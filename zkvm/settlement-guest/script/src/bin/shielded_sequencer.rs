//! Blind sequencer — runs INSIDE the enclave. The browser seals its order to this service's key
//! (see /pubkey); only this enclave decrypts it, executes the trade, generates the SP1 proof, and
//! returns proof + public values + attestation. The operator/backend relays ciphertext and never
//! sees the plaintext order — that's how the TEE actually enforces order privacy (dark-pool style).
//!
//! Honest scope: the SP1 network still receives the witness while proving (a separate trust domain
//! from the operator). Fully removing that needs in-enclave STARK proving; here proving is initiated
//! from inside the enclave so the operator is blind.

use std::net::SocketAddr;
use std::sync::Arc;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use revm::primitives::U256;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};
use zstable_settlement_executor::{
    apply_batch_with_overlay, compute_quoted_price, compute_sigma, derive_withdrawals, keccak256,
    BatchContext, MockChainStateProvider, OraclePrice, OverlayState, Trade, MAX_FEE_BPS,
};
use zstable_settlement_guest_lib::{encode_public_values, BatchWitness};

const REVM_ELF: Elf = include_elf!("zstable-settlement-guest-program");
const SALT: &[u8] = b"zstable-salt-v1";
const INFO: &[u8] = b"zstable-sealed-order-v1";

struct WorkerKey {
    secret: SecretKey,
    public_hex: String,
}

impl WorkerKey {
    fn generate() -> Self {
        let secret = SecretKey::random(&mut rand_core::OsRng);
        let public_hex = hex::encode(secret.public_key().to_encoded_point(false).as_bytes());
        Self { secret, public_hex }
    }

    fn open(&self, eph_pub: &str, iv: &str, ct: &str) -> Result<Vec<u8>, String> {
        let eph = PublicKey::from_sec1_bytes(
            &hex::decode(eph_pub.trim_start_matches("0x")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let shared = diffie_hellman(self.secret.to_nonzero_scalar(), eph.as_affine());
        let hk = Hkdf::<Sha256>::new(Some(SALT), shared.raw_secret_bytes());
        let mut key = [0u8; 32];
        hk.expand(INFO, &mut key).map_err(|e| e.to_string())?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let iv = hex::decode(iv.trim_start_matches("0x")).map_err(|e| e.to_string())?;
        let ct = hex::decode(ct.trim_start_matches("0x")).map_err(|e| e.to_string())?;
        cipher
            .decrypt(Nonce::from_slice(&iv), ct.as_ref())
            .map_err(|_| "sealed order decrypt failed".to_string())
    }
}

/// Seals `plaintext` to `compliance_pubkey` (a STABLE, externally-generated key — never this
/// enclave's own ephemeral `WorkerKey`, see AppState::compliance_pubkey doc). Same ECDH->HKDF->
/// AES-256-GCM construction as `WorkerKey::open`, just encrypting outward with a fresh ephemeral
/// key instead of decrypting inward — a distinct HKDF `info` label keeps the two uses' derived
/// keys independent even if the same code/library primitives are reused.
fn seal_to_compliance_key(compliance_pubkey: &[u8], plaintext: &[u8]) -> Result<String, String> {
    const COMPLIANCE_INFO: &[u8] = b"zstable-compliance-record-v1";
    let recipient = PublicKey::from_sec1_bytes(compliance_pubkey).map_err(|e| e.to_string())?;
    let eph_secret = SecretKey::random(&mut rand_core::OsRng);
    let eph_pub = hex::encode(eph_secret.public_key().to_encoded_point(false).as_bytes());
    let shared = diffie_hellman(eph_secret.to_nonzero_scalar(), recipient.as_affine());
    let hk = Hkdf::<Sha256>::new(Some(SALT), shared.raw_secret_bytes());
    let mut key = [0u8; 32];
    hk.expand(COMPLIANCE_INFO, &mut key).map_err(|e| e.to_string())?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let mut iv = [0u8; 12];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut iv);
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext)
        .map_err(|e| e.to_string())?;
    Ok(format!("{}:{}:{}", eph_pub, hex::encode(iv), hex::encode(ct)))
}

#[derive(Clone)]
struct AppState {
    key: Arc<WorkerKey>,
    attestation_endpoint: String,
    seal_pubkey: Arc<Vec<u8>>,
    /// Basis points of gross output retained as a fee (same output asset), credited to the Vault's
    /// LP line for that asset — see `FEE_BPS` env var. Never chosen by the client/order.
    fee_bps: u16,
    /// Stable, externally-generated P-256 pubkey (COMPLIANCE_PUBKEY env, hex SEC1 uncompressed) a
    /// deposit<->recipient compliance record is sealed to per trade — NOT this enclave's own
    /// ephemeral `key`, which is regenerated (and would lose everything sealed to it) on every
    /// restart. None disables the feature entirely (no record produced).
    compliance_pubkey: Option<Arc<Vec<u8>>>,
}

#[derive(Deserialize)]
struct SealedOrder {
    eph_pub: String,
    iv: String,
    ct: String,
}

#[derive(Deserialize)]
struct OracleJson {
    token: String,
    price: String,
    /// ERC20 decimals of this token; absent -> 18 (unchanged 18↔18 behavior).
    #[serde(default)]
    decimals: Option<u8>,
    /// Pricing-formula/market-state inputs, same shape `generate-oracle-file.ts` emits. All
    /// optional/defaulted so older callers passing only {token, price} still price at the flat
    /// oracle price (see `verify_quoted_price`'s zero-params collapse).
    #[serde(default)]
    base_spread_bps: u16,
    #[serde(default)]
    vol_coeff_bps: u16,
    #[serde(default)]
    skew_coeff_bps: u16,
    #[serde(default)]
    sigma_min_1e18: String,
    #[serde(default)]
    sigma_max_1e18: String,
    #[serde(default)]
    utilization_1e18: String,
    #[serde(default)]
    price_history: Vec<String>,
}

#[derive(Deserialize)]
struct BlindRequest {
    sealed: SealedOrder,
    batch_number: u64,
    chain_id: u64,
    rollup_id: String,
    oracle: Vec<OracleJson>,
    #[serde(default)]
    overlay: OverlayState,
}

/// The plaintext order — visible ONLY inside the enclave after decryption.
#[derive(Deserialize)]
struct OrderPlaintext {
    side: u8,
    stock: String,
    quote: String,
    input: String,
    recipient: String,
    secret: String,
    /// noteCommitment of the on-chain `Vault.deposit` funding this order's input, so the proof can
    /// bind `input_amount` to a real, unspent deposit instead of trusting the order alone. Defaults
    /// to the zero commitment for callers not yet passing one (fails on-chain, not silently).
    #[serde(default)]
    deposit_commitment: String,
}

#[derive(Serialize)]
struct WithdrawalJson {
    nullifier: String,
    stock_token: String,
    amount: String,
    recipient: String,
}

#[derive(Serialize)]
struct FeeJson {
    asset: String,
    amount: String,
}

#[derive(Serialize)]
struct DepositJson {
    note_commitment: String,
    asset: String,
    amount: String,
}


#[derive(Serialize)]
struct BlindResponse {
    public_values: String,
    proof: String,
    vkey: String,
    tee_agree: bool,
    withdrawals: Vec<WithdrawalJson>,
    /// Disclosed per-asset fee totals matching `public_values.feesRoot` (see `compute_fee_entries`).
    /// Empty when no trade in the batch had a non-zero fee.
    fees: Vec<FeeJson>,
    /// Disclosed per-deposit consumption totals matching `public_values.depositsRoot` (see
    /// `compute_deposit_entries`). The submitter passes this straight through to
    /// `ZstableRollup.settleBatch`, which calls `Vault.consumeDeposit` for each entry.
    deposits: Vec<DepositJson>,
    new_overlay: OverlayState,
    attestation_hash: Option<String>,
    attestation_status: String,
    /// The full attestation document (hex). Clients decode this to verify the sealing key is bound.
    attestation_hex: Option<String>,
    /// True when the document's user_data/public_key equals this enclave's sealing key.
    attestation_bound: bool,
    /// `{deposit_commitment, recipient, batch_number, timestamp}` sealed to COMPLIANCE_PUBKEY (see
    /// AppState::compliance_pubkey) — None when that env var is unset. The caller (server.js) must
    /// append this, unmodified, to durable storage OUTSIDE the enclave: this enclave is stateless
    /// and this is the only moment this record exists before the process may restart.
    compliance_record: Option<String>,
}

fn addr20(s: &str) -> [u8; 20] {
    let b = hex::decode(s.trim_start_matches("0x")).expect("bad 20-byte hex");
    let mut o = [0u8; 20];
    o.copy_from_slice(&b);
    o
}
fn u256_be(v: u128) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[16..].copy_from_slice(&v.to_be_bytes());
    o
}
fn secret32(s: &str) -> [u8; 32] {
    let b = hex::decode(s.trim_start_matches("0x")).expect("bad 32-byte secret");
    let mut o = [0u8; 32];
    o.copy_from_slice(&b);
    o
}

fn attestation_hash_of(doc: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(doc)))
}

fn u64_field(s: &str) -> u64 {
    if s.is_empty() {
        0
    } else {
        s.parse().expect("bad 1e18-scale field (want decimal string)")
    }
}

/// Ask the Nitro Security Module (/dev/nsm) for an attestation document that BINDS `seal_pubkey`
/// into both the `public_key` and `user_data` fields. Only reachable inside a real Nitro enclave.
fn nsm_attestation(seal_pubkey: &[u8]) -> Option<Vec<u8>> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
    let fd = nsm_init();
    if fd < 0 {
        return None;
    }
    let req = Request::Attestation {
        user_data: Some(serde_bytes::ByteBuf::from(seal_pubkey.to_vec())),
        nonce: None,
        public_key: Some(serde_bytes::ByteBuf::from(seal_pubkey.to_vec())),
    };
    let resp = nsm_process_request(fd, req);
    nsm_exit(fd);
    match resp {
        Response::Attestation { document } => Some(document),
        _ => None,
    }
}

struct Attestation {
    hash: Option<String>,
    status: String,
    hex: Option<String>,
    bound: bool,
}

/// Prefer an NSM document bound to the sealing key; fall back to the (unbound) Oyster endpoint so
/// the enclave still reports a real attestation even where /dev/nsm is not exposed to the workload.
fn fetch_attestation(endpoint: &str, seal_pubkey: &[u8]) -> Attestation {
    if let Some(doc) = nsm_attestation(seal_pubkey) {
        return Attestation {
            hash: Some(attestation_hash_of(&doc)),
            status: "attestation bound to sealing key via /dev/nsm".to_string(),
            hex: Some(format!("0x{}", hex::encode(&doc))),
            bound: true,
        };
    }
    match reqwest::blocking::Client::new().get(endpoint).send().and_then(|r| r.bytes()) {
        Ok(b) => Attestation {
            hash: Some(attestation_hash_of(&b)),
            status: "attestation from Oyster endpoint (sealing key NOT bound: /dev/nsm unavailable)".to_string(),
            hex: Some(format!("0x{}", hex::encode(&b))),
            bound: false,
        },
        Err(e) => Attestation { hash: None, status: format!("attestation unavailable: {e}"), hex: None, bound: false },
    }
}

/// The whole blind pipeline (decrypt -> execute -> prove -> attest). Blocking (SP1 proving).
fn run_blind(st: AppState, req: BlindRequest) -> Result<BlindResponse, String> {
    let pt = st.key.open(&req.sealed.eph_pub, &req.sealed.iv, &req.sealed.ct)?;
    let order: OrderPlaintext = serde_json::from_slice(&pt).map_err(|e| e.to_string())?;

    let stock = addr20(&order.stock);
    let quote = addr20(&order.quote);
    let input: u128 = order.input.parse().map_err(|_| "bad input amount".to_string())?;
    let recipient = addr20(&order.recipient);
    let secret = secret32(&order.secret);

    let oracle: Vec<OraclePrice> = req
        .oracle
        .iter()
        .map(|o| OraclePrice {
            token: addr20(&o.token),
            price: u256_be(o.price.parse::<u128>().expect("bad oracle price")),
            decimals: o.decimals.unwrap_or(18),
            base_spread_bps: o.base_spread_bps,
            vol_coeff_bps: o.vol_coeff_bps,
            skew_coeff_bps: o.skew_coeff_bps,
            sigma_min_1e18: u64_field(&o.sigma_min_1e18),
            sigma_max_1e18: u64_field(&o.sigma_max_1e18),
            utilization_1e18: u64_field(&o.utilization_1e18),
            price_history: o
                .price_history
                .iter()
                .map(|p| u256_be(p.parse::<u128>().expect("bad price_history entry")))
                .collect(),
        })
        .collect();
    // Base price is taken from the on-chain oracle, not the client — the client cannot forge it.
    let stock_oracle = oracle.iter().find(|o| o.token == stock).ok_or("stock not in oracle")?;
    let oracle_price = U256::from_be_bytes::<32>(stock_oracle.price);
    // Must match EXACTLY what the guest's `verify_quoted_price` recomputes from the same committed
    // oracle/pricing-params/price-history, or the proof would fail (see compute_quoted_price docs).
    let sigma = compute_sigma(&stock_oracle.price_history, stock_oracle.sigma_min_1e18, stock_oracle.sigma_max_1e18);
    let quoted_price = compute_quoted_price(
        oracle_price,
        order.side,
        stock_oracle.base_spread_bps,
        stock_oracle.vol_coeff_bps,
        stock_oracle.skew_coeff_bps,
        sigma,
        U256::from(stock_oracle.utilization_1e18),
    );
    let price = quoted_price.to_be_bytes::<32>();
    let (input_token, output_token) = if order.side == 0 { (quote, stock) } else { (stock, quote) };
    let deposit_commitment = if order.deposit_commitment.is_empty() {
        [0u8; 32]
    } else {
        secret32(&order.deposit_commitment)
    };
    let trade = Trade {
        account: recipient,
        input_token,
        input_amount: u256_be(input),
        output_token,
        price,
        side: order.side,
        secret,
        fee_bps: st.fee_bps,
        deposit_commitment,
    };

    let ctx = BatchContext {
        chain_id: req.chain_id,
        rollup_address: addr20(&req.rollup_id),
        batch_number: req.batch_number,
        tee_batch_nonce: req.batch_number,
        withdrawals: vec![],
        trades: vec![trade],
        oracle,
    };

    // TEE fast path: execute natively (a trade-only batch; the withdrawal is derived from the trade).
    let (_out, public_values, new_overlay) =
        apply_batch_with_overlay(MockChainStateProvider::new(), req.overlay.clone(), &ctx, vec![])
            .map_err(|e| format!("execution failed: {e:?}"))?;

    // ZK finality: prove the identical batch, initiated from INSIDE the enclave.
    let client = ProverClient::from_env();
    let pk = client.setup(REVM_ELF).map_err(|e| e.to_string())?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&BatchWitness { ctx: ctx.clone(), overlay: req.overlay.clone(), txs: vec![], provider: MockChainStateProvider::new() });
    let proof = client.prove(&pk, stdin).groth16().run().map_err(|e| e.to_string())?;
    let proof_pv = proof.public_values.as_slice();
    let tee_agree = proof_pv == encode_public_values(&public_values).as_slice();

    let withdrawals = derive_withdrawals(&ctx)
        .iter()
        .map(|w| WithdrawalJson {
            nullifier: format!("0x{}", hex::encode(w.nullifier)),
            stock_token: format!("0x{}", hex::encode(w.stock_token)),
            amount: format!("0x{}", hex::encode(w.amount)),
            recipient: format!("0x{}", hex::encode(w.recipient)),
        })
        .collect();
    let fees = zstable_settlement_executor::compute_fee_entries(&ctx)
        .into_iter()
        .map(|(asset, amount)| FeeJson {
            asset: format!("0x{}", hex::encode(asset)),
            amount: format!("0x{}", hex::encode(amount)),
        })
        .collect();
    let deposits = zstable_settlement_executor::compute_deposit_entries(&ctx)
        .into_iter()
        .map(|(commitment, asset, amount)| DepositJson {
            note_commitment: format!("0x{}", hex::encode(commitment)),
            asset: format!("0x{}", hex::encode(asset)),
            amount: format!("0x{}", hex::encode(amount)),
        })
        .collect();
    let att = fetch_attestation(&st.attestation_endpoint, &st.seal_pubkey);

    // Compliance record: seals {deposit_commitment, recipient, batch_number, timestamp} to the
    // stable COMPLIANCE_PUBKEY, if configured — never to this enclave's own ephemeral `st.key`.
    // Failure here must not fail the trade itself (compliance is additive, not a settlement gate).
    let compliance_record = st.compliance_pubkey.as_ref().and_then(|pk| {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let record = serde_json::json!({
            "deposit_commitment": format!("0x{}", hex::encode(deposit_commitment)),
            "recipient": format!("0x{}", hex::encode(recipient)),
            "batch_number": req.batch_number,
            "timestamp": ts,
        });
        seal_to_compliance_key(pk, record.to_string().as_bytes()).ok()
    });

    Ok(BlindResponse {
        public_values: format!("0x{}", hex::encode(proof_pv)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
        vkey: pk.verifying_key().bytes32().to_string(),
        tee_agree,
        withdrawals,
        fees,
        deposits,
        new_overlay,
        attestation_hash: att.hash,
        attestation_status: att.status,
        attestation_hex: att.hex,
        attestation_bound: att.bound,
        compliance_record,
    })
}

async fn execute_blind(State(st): State<AppState>, Json(req): Json<BlindRequest>) -> (StatusCode, Json<serde_json::Value>) {
    match tokio::task::spawn_blocking(move || run_blind(st, req)).await {
        Ok(Ok(resp)) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "service": "zstable-shielded-sequencer", "status": "ok" }))
}
async fn pubkey(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "pubkey": st.key.public_hex,
        "curve": "P-256",
        "scheme": "ECDH-HKDF-SHA256-AES256GCM",
        "salt": "zstable-salt-v1",
        "info": "zstable-sealed-order-v1",
    }))
}
async fn attestation_raw(State(st): State<AppState>) -> (StatusCode, [(axum::http::HeaderName, &'static str); 1], Vec<u8>) {
    let att = tokio::task::spawn_blocking(move || fetch_attestation(&st.attestation_endpoint, &st.seal_pubkey))
        .await
        .unwrap_or(Attestation { hash: None, status: "unavailable".into(), hex: None, bound: false });
    let ct = [(axum::http::header::CONTENT_TYPE, "application/octet-stream")];
    match att.hex {
        Some(h) => (StatusCode::OK, ct, hex::decode(h.trim_start_matches("0x")).unwrap_or_default()),
        None => (StatusCode::SERVICE_UNAVAILABLE, ct, Vec::new()),
    }
}
async fn attestation(State(st): State<AppState>) -> Json<serde_json::Value> {
    let att = tokio::task::spawn_blocking(move || fetch_attestation(&st.attestation_endpoint, &st.seal_pubkey))
        .await
        .unwrap_or(Attestation { hash: None, status: "unavailable".into(), hex: None, bound: false });
    Json(serde_json::json!({
        "available": att.hash.is_some(),
        "attestation_hash": att.hash,
        "attestation_hex": att.hex,
        "bound": att.bound,
        "status": att.status,
    }))
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    sp1_sdk::utils::setup_logger();
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(4000);
    let attestation_endpoint = std::env::var("ATTESTATION_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:1300/attestation/raw".to_string());
    let fee_bps: u16 = std::env::var("FEE_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(30);
    assert!(fee_bps <= MAX_FEE_BPS, "FEE_BPS {fee_bps} exceeds protocol MAX_FEE_BPS {MAX_FEE_BPS}");
    let key = Arc::new(WorkerKey::generate());
    let seal_pubkey = Arc::new(hex::decode(&key.public_hex).expect("sealing pubkey hex"));
    // Optional: stable compliance-record recipient key, generated OFFLINE by the operator (never
    // by this process) — see docs/roadmap-tee-compliance.md. Unset = feature disabled entirely.
    let compliance_pubkey = std::env::var("COMPLIANCE_PUBKEY")
        .ok()
        .and_then(|h| hex::decode(h.trim_start_matches("0x")).ok())
        .map(Arc::new);
    let state = AppState { key: key.clone(), attestation_endpoint, seal_pubkey, fee_bps, compliance_pubkey: compliance_pubkey.clone() };
    println!("shielded-sequencer pubkey (seal orders to this): {}", key.public_hex);
    println!("fee_bps: {fee_bps} ({:.2}% retained per trade, credited to the LP line)", fee_bps as f64 / 100.0);
    println!("compliance record sealing: {}", if compliance_pubkey.is_some() { "ENABLED (COMPLIANCE_PUBKEY set)" } else { "disabled (no COMPLIANCE_PUBKEY)" });

    let app = Router::new()
        .route("/health", get(health))
        .route("/pubkey", get(pubkey))
        .route("/attestation", get(attestation))
        .route("/attestation/raw", get(attestation_raw))
        .route("/execute-blind", post(execute_blind))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("shielded-sequencer listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
