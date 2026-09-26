//! Sequencer: the connective tissue of "TEE for speed, ZK for finality".
//!
//! For one batch it:
//!   1. builds a batch on top of the sequencer-owned overlay,
//!   2. has the Oyster TEE execute it (`/execute-batch`) and reads its attestation (`/attestation`),
//!   3. proves the *identical* execution on the SP1 network (mock if configured),
//!   4. asserts the TEE's public values equal the proof's (TEE == ZK),
//!   5. writes an on-chain-ready settlement bundle (`publicValues`, `proof`, `withdrawals`) and
//!      persists the new overlay so the next batch chains.
//!
//! The on-chain submit (`ZstableRollup.settleBatch`) is done by the TS submitter, which reads the
//! bundle this writes. Config is entirely env-driven (see the consts below).

use std::fs;

use alloy_sol_types::SolType;
use revm::context::TxEnv;
use revm::primitives::{Address, TxKind, U256};
use revm::state::AccountInfo;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};
use zstable_settlement_executor::{
    derive_withdrawals, keccak256, BatchContext, MockChainStateProvider, OraclePrice, OverlayState,
    PublicValues, Trade, Withdrawal,
};
use zstable_settlement_guest_lib::{encode_public_values, BatchWitness, PublicValuesStruct};

const REVM_ELF: Elf = include_elf!("zstable-settlement-guest-program");

/// Mirror of tee-worker `AccountAccess` (accounts/slots the enclave verifies against real L2 state).
#[derive(Serialize, Clone)]
struct AccountAccess {
    address: Address,
    slots: Vec<U256>,
}

/// Mirror of tee-worker `ExecuteBatchRequest` (field names must match its serde).
#[derive(Serialize)]
struct OysterExecuteRequest {
    ctx: BatchContext,
    txs: Vec<TxEnv>,
    overlay: OverlayState,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    access_list: Vec<AccountAccess>,
    mock_state: Option<MockChainStateProvider>,
}

/// Mirror of tee-worker `ExecuteBatchResponse`. `new_overlay` is tolerated as optional so a batch
/// still runs against a worker image that predates sequencer-owned state (batch 1 starts empty).
#[derive(Deserialize)]
struct OysterExecuteResponse {
    public_values: PublicValues,
    #[allow(dead_code)]
    tx_count: u32,
    #[serde(default)]
    new_overlay: OverlayState,
    /// Verified base state the enclave read (verified mode only); the prover replays it.
    #[serde(default)]
    base_state: Option<MockChainStateProvider>,
}

/// Mirror of tee-worker `AttestationInfo`.
#[derive(Deserialize)]
struct AttestationInfo {
    available: bool,
    attestation_hex: Option<String>,
    status: String,
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

/// The on-chain-ready bundle the TS submitter feeds to `ZstableRollup.settleBatch`.
#[derive(Serialize)]
struct SettlementBundle {
    batch_number: u64,
    public_values: String,
    proof: String,
    withdrawals: Vec<WithdrawalJson>,
    /// Disclosed per-asset fee totals matching `public_values.feesRoot`. Empty when no trade in
    /// the batch had a non-zero fee.
    fees: Vec<FeeJson>,
    /// Disclosed per-deposit consumption totals matching `public_values.depositsRoot`, passed
    /// straight through to `ZstableRollup.settleBatch`.
    deposits: Vec<DepositJson>,
    vkey: String,
    attestation_hash: Option<String>,
    attestation_status: String,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn addr20_from_hex(s: &str) -> [u8; 20] {
    let bytes = hex::decode(s.trim_start_matches("0x")).expect("bad 20-byte hex");
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    out
}

fn u256_be_bytes(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

/// Builds the demo batch: one funded sender making a value transfer, optionally releasing a
/// withdrawal (set WITHDRAW_* env to bind an on-chain payout to this batch). Both the TEE and the
/// prover run this exact batch on top of `overlay`.
fn build_batch(
    chain_id: u64,
    rollup_address: [u8; 20],
    batch_number: u64,
) -> (BatchContext, Vec<TxEnv>, MockChainStateProvider, Vec<Withdrawal>, Vec<AccountAccess>) {
    // Verified mode: real accounts that exist on-chain (sender must have balance). Mock defaults otherwise.
    let sender = Address::from(addr20_from_hex(&env_or("ZSTABLE_SENDER", "0x1111111111111111111111111111111111111111")));
    let recipient = Address::from(addr20_from_hex(&env_or("ZSTABLE_RECIPIENT", "0x3333333333333333333333333333333333333333")));
    let amount: u128 = env_or("ZSTABLE_AMOUNT", "1000").parse().expect("bad ZSTABLE_AMOUNT");
    // Must equal the sender's real nonce in verified mode (use a fresh funded account => 0).
    let nonce: u64 = env_or("ZSTABLE_NONCE", "0").parse().expect("bad ZSTABLE_NONCE");

    // Base state: either REAL verified chain state exported by an external bridge (if wired)
    // (ZSTABLE_STATE_FILE, produced locally via Helios+archive+MPT), or a funded mock for dev.
    let provider: MockChainStateProvider = if let Ok(path) = std::env::var("ZSTABLE_STATE_FILE") {
        serde_json::from_slice(&std::fs::read(&path).expect("read ZSTABLE_STATE_FILE"))
            .expect("parse ZSTABLE_STATE_FILE")
    } else {
        let mut p = MockChainStateProvider::new();
        p.set_account(
            sender,
            AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u128),
                nonce,
                ..Default::default()
            },
        );
        p
    };

    let tx = TxEnv {
        caller: sender,
        kind: TxKind::Call(recipient),
        value: U256::from(amount),
        gas_limit: 21_000,
        gas_price: 0,
        chain_id: Some(chain_id),
        nonce,
        ..Default::default()
    };

    let mut withdrawals = Vec::new();
    if let (Ok(token), Ok(wamount), Ok(wrecipient)) = (
        std::env::var("WITHDRAW_TOKEN"),
        std::env::var("WITHDRAW_AMOUNT"),
        std::env::var("WITHDRAW_RECIPIENT"),
    ) {
        withdrawals.push(Withdrawal {
            nullifier: keccak256(format!("zstable-withdrawal-{batch_number}").as_bytes()),
            stock_token: addr20_from_hex(&token),
            amount: u256_be_bytes(wamount.parse().expect("WITHDRAW_AMOUNT must be an integer")),
            recipient: addr20_from_hex(&wrecipient),
        });
    }

    // Trade mode: a priced buy/sell whose fill the guest DERIVES from price (proof-bound).
    //   ZSTABLE_TRADE_SIDE=buy|sell, ZSTABLE_TRADE_STOCK, ZSTABLE_TRADE_QUOTE (tUSD), ZSTABLE_TRADE_INPUT,
    //   ZSTABLE_TRADE_PRICE (1e18 tUSD per whole stock), ZSTABLE_TRADE_ACCOUNT (defaults to sender).
    let mut trades = Vec::new();
    if let Ok(side_str) = std::env::var("ZSTABLE_TRADE_SIDE") {
        let side: u8 = if side_str.eq_ignore_ascii_case("sell") { 1 } else { 0 };
        let stock = addr20_from_hex(&std::env::var("ZSTABLE_TRADE_STOCK").expect("ZSTABLE_TRADE_STOCK"));
        let quote = addr20_from_hex(&std::env::var("ZSTABLE_TRADE_QUOTE").expect("ZSTABLE_TRADE_QUOTE"));
        let account = std::env::var("ZSTABLE_TRADE_ACCOUNT")
            .map(|s| addr20_from_hex(&s))
            .unwrap_or_else(|_| sender.into_array());
        let input: u128 = std::env::var("ZSTABLE_TRADE_INPUT").expect("ZSTABLE_TRADE_INPUT").parse().expect("bad ZSTABLE_TRADE_INPUT");
        let price: u128 = std::env::var("ZSTABLE_TRADE_PRICE").expect("ZSTABLE_TRADE_PRICE").parse().expect("bad ZSTABLE_TRADE_PRICE");
        let (input_token, output_token) = if side == 0 { (quote, stock) } else { (stock, quote) };
        // Private nullifier seed: from the caller's random secret (unlinkable), or a deterministic
        // fallback for dev. The withdrawal's nullifier = keccak(domain|secret), never the account.
        let secret: [u8; 32] = match std::env::var("ZSTABLE_TRADE_SECRET") {
            Ok(h) => {
                let b = hex::decode(h.trim_start_matches("0x")).expect("bad ZSTABLE_TRADE_SECRET");
                let mut s = [0u8; 32];
                s.copy_from_slice(&b);
                s
            }
            Err(_) => keccak256(&[&account[..], &batch_number.to_be_bytes()].concat()),
        };
        // noteCommitment of the real on-chain deposit funding this trade's input (see Vault.sol);
        // defaults to zero, which `Vault.consumeDeposit` will reject on-chain if actually used.
        let deposit_commitment: [u8; 32] = match std::env::var("ZSTABLE_TRADE_DEPOSIT_COMMITMENT") {
            Ok(h) => {
                let b = hex::decode(h.trim_start_matches("0x")).expect("bad ZSTABLE_TRADE_DEPOSIT_COMMITMENT");
                let mut c = [0u8; 32];
                c.copy_from_slice(&b);
                c
            }
            Err(_) => [0u8; 32],
        };
        let fee_bps: u16 = std::env::var("ZSTABLE_TRADE_FEE_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
        trades.push(Trade {
            account,
            input_token,
            input_amount: u256_be_bytes(input),
            output_token,
            price: u256_be_bytes(price),
            side,
            secret,
            fee_bps,
            deposit_commitment,
        });
    }

    let ctx = BatchContext {
        chain_id,
        rollup_address,
        batch_number,
        tee_batch_nonce: batch_number,
        withdrawals: withdrawals.clone(),
        trades: trades.clone(),
        oracle: load_oracle(),
    };
    // On-chain withdrawal list = explicit + trade-derived; must match the committed root.
    let all_withdrawals = derive_withdrawals(&ctx);
    let access_list = vec![
        AccountAccess { address: sender, slots: Vec::new() },
        AccountAccess { address: recipient, slots: Vec::new() },
    ];
    (ctx, vec![tx], provider, all_withdrawals, access_list)
}

/// Loads the on-chain price oracle the guest checks trade prices/formula against, from
/// ORACLE_FILE (JSON array, in AssetRegistry assetId order; see `scripts/generate-oracle-file.ts`
/// for how to produce it from live on-chain state). Only `token`/`price` are required so older,
/// spread-less oracle files still work unchanged (every other field defaults to "no formula
/// applied" -> `verify_quoted_price` reduces to the plain `trade.price == oracle.price` check).
/// Empty if unset (no trades).
fn load_oracle() -> Vec<OraclePrice> {
    let path = match std::env::var("ORACLE_FILE") {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    #[derive(serde::Deserialize)]
    struct O {
        token: String,
        price: String,
        /// ERC20 decimals of this token; absent -> 18 (unchanged 18↔18 behavior).
        #[serde(default)]
        decimals: Option<u8>,
        #[serde(default)]
        base_spread_bps: u16,
        #[serde(default)]
        vol_coeff_bps: u16,
        #[serde(default)]
        skew_coeff_bps: u16,
        /// Decimal strings, not JSON numbers: at 1e18 scale these routinely exceed what a JS
        /// `number` (or any tool round-tripping through one) can represent exactly, same reason
        /// `price`/`price_history` are strings.
        #[serde(default)]
        sigma_min_1e18: String,
        #[serde(default)]
        sigma_max_1e18: String,
        #[serde(default)]
        utilization_1e18: String,
        /// Oldest -> newest recent oracle prices (same decimal-string format as `price`); see
        /// `AssetRegistry.oracleRoot()`'s embedded historyRoot for why this must come from the
        /// SAME on-chain oracle as `price` (e.g. `UniswapV3TwapOracle.priceHistory`), not a
        /// separately-trusted series.
        #[serde(default)]
        price_history: Vec<String>,
    }
    let items: Vec<O> = serde_json::from_slice(&std::fs::read(&path).expect("read ORACLE_FILE"))
        .expect("parse ORACLE_FILE");
    items
        .into_iter()
        .map(|o| OraclePrice {
            token: addr20_from_hex(&o.token),
            price: u256_be_bytes(o.price.parse().expect("bad oracle price")),
            decimals: o.decimals.unwrap_or(18),
            base_spread_bps: o.base_spread_bps,
            vol_coeff_bps: o.vol_coeff_bps,
            skew_coeff_bps: o.skew_coeff_bps,
            sigma_min_1e18: parse_u64_or_zero(&o.sigma_min_1e18),
            sigma_max_1e18: parse_u64_or_zero(&o.sigma_max_1e18),
            utilization_1e18: parse_u64_or_zero(&o.utilization_1e18),
            price_history: o
                .price_history
                .iter()
                .map(|p| u256_be_bytes(p.parse().expect("bad oracle price_history entry")))
                .collect(),
        })
        .collect()
}

fn parse_u64_or_zero(s: &str) -> u64 {
    if s.is_empty() {
        0
    } else {
        s.parse().expect("bad u64 field in ORACLE_FILE")
    }
}

fn main() {
    dotenv::dotenv().ok();
    sp1_sdk::utils::setup_logger();

    let oyster_url = std::env::var("OYSTER_URL").expect("set OYSTER_URL, e.g. http://<enclave-ip>:4000");
    let overlay_path = env_or("OVERLAY_PATH", "overlay.json");
    let output_path = env_or("OUTPUT", "settlement.json");
    let chain_id: u64 = env_or("CHAIN_ID", "46630").parse().expect("bad CHAIN_ID");
    let rollup_address = addr20_from_hex(&env_or("ROLLUP_ID", "0x00000000000000000000000000000000000000AA"));
    let batch_number: u64 = env_or("BATCH_NUMBER", "1").parse().expect("bad BATCH_NUMBER");

    // Sequencer-owned overlay: load the prior state so batches chain, empty for the first batch.
    let overlay: OverlayState = fs::read(&overlay_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();

    let verified = env_or("ZSTABLE_STATE_MODE", "mock") == "verified";
    let (ctx, txs, provider, withdrawals, access_list) = build_batch(chain_id, rollup_address, batch_number);
    println!("state mode: {}", if verified { "verified (real on-chain state)" } else { "mock" });

    // 1) Oyster TEE executes the batch on top of the overlay.
    let http = reqwest::blocking::Client::new();
    let exec_req = OysterExecuteRequest {
        ctx: ctx.clone(),
        txs: txs.clone(),
        overlay: overlay.clone(),
        access_list: if verified { access_list } else { Vec::new() },
        mock_state: if verified { None } else { Some(provider.clone()) },
    };
    let resp = http
        .post(format!("{oyster_url}/execute-batch"))
        .json(&exec_req)
        .send()
        .expect("Oyster /execute-batch request failed");
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        panic!("Oyster /execute-batch failed: {status}: {body}");
    }
    let tee: OysterExecuteResponse = resp.json().expect("decode Oyster execute response");
    println!("TEE executed batch {batch_number}: new_state_commitment = 0x{}", hex::encode(tee.public_values.new_state_commitment));

    // 2) Oyster attestation (real SGX quote inside the enclave; dev reports unavailable).
    let att: AttestationInfo = http
        .get(format!("{oyster_url}/attestation"))
        .send()
        .expect("Oyster /attestation request failed")
        .json()
        .expect("decode attestation");
    let attestation_hash = att
        .attestation_hex
        .as_ref()
        .filter(|_| att.available)
        .map(|hex_str| format!("0x{}", hex::encode(keccak256(&hex::decode(hex_str.trim_start_matches("0x")).unwrap_or_default()))));
    println!("TEE attestation: {} ({})", if att.available { "present" } else { "unavailable" }, att.status);

    // 3) Prove the identical execution on the SP1 network.
    let client = ProverClient::from_env();
    let pk = client.setup(REVM_ELF).expect("failed to setup ELF");
    // In verified mode the guest must replay the EXACT state the enclave verified; use the base
    // state the TEE returned. In mock mode the local provider is already that base state.
    let guest_provider = if verified {
        tee.base_state
            .clone()
            .expect("verified mode: enclave returned no base_state (rebuild the worker image)")
    } else {
        provider
    };
    let mut stdin = SP1Stdin::new();
    // Clone: `ctx` is still needed below (compute_fee_entries/compute_deposit_entries) after the
    // witness moves its own copy into the proving request.
    stdin.write(&BatchWitness { ctx: ctx.clone(), overlay, txs, provider: guest_provider });
    println!("requesting SP1 proof (this can take minutes on the network)...");
    // `from_env` selects the prover via SP1_PROVER (mock/cpu/network); on the mainnet network the
    // SDK applies the auction fulfillment strategy by default.
    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .expect("failed to generate proof");

    // 4) TEE == ZK: the proof's committed public values must equal the TEE's.
    let proof_pv = proof.public_values.as_slice();
    let tee_pv = encode_public_values(&tee.public_values);
    assert_eq!(proof_pv, tee_pv.as_slice(), "FATAL: TEE public values != proof public values");
    let _decoded = PublicValuesStruct::abi_decode(proof_pv).expect("decode public values");
    println!("TEE and SP1 proof agree on public values ✓");

    // 5) Write the on-chain-ready settlement bundle + persist the new overlay.
    let bundle = SettlementBundle {
        batch_number,
        public_values: format!("0x{}", hex::encode(proof_pv)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
        withdrawals: withdrawals
            .iter()
            .map(|w| WithdrawalJson {
                nullifier: format!("0x{}", hex::encode(w.nullifier)),
                stock_token: format!("0x{}", hex::encode(w.stock_token)),
                amount: format!("0x{}", hex::encode(w.amount)),
                recipient: format!("0x{}", hex::encode(w.recipient)),
            })
            .collect(),
        fees: zstable_settlement_executor::compute_fee_entries(&ctx)
            .into_iter()
            .map(|(asset, amount)| FeeJson {
                asset: format!("0x{}", hex::encode(asset)),
                amount: format!("0x{}", hex::encode(amount)),
            })
            .collect(),
        deposits: zstable_settlement_executor::compute_deposit_entries(&ctx)
            .into_iter()
            .map(|(commitment, asset, amount)| DepositJson {
                note_commitment: format!("0x{}", hex::encode(commitment)),
                asset: format!("0x{}", hex::encode(asset)),
                amount: format!("0x{}", hex::encode(amount)),
            })
            .collect(),
        vkey: pk.verifying_key().bytes32().to_string(),
        attestation_hash,
        attestation_status: att.status,
    };
    fs::write(&output_path, serde_json::to_string_pretty(&bundle).unwrap()).expect("write settlement bundle");
    fs::write(&overlay_path, serde_json::to_string_pretty(&tee.new_overlay).unwrap()).expect("write overlay");
    println!("wrote {output_path} (submit with the TS submitter) and persisted overlay to {overlay_path}");
}
