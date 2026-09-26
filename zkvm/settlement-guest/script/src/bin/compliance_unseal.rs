//! Compliance-unseal CLI — single one-shot command, run only by whoever holds both the
//! compliance-logger signing key (via the hardhat script it shells out to) and COMPLIANCE_PRIVATE_KEY
//! (see roadmap-tee-compliance.md: single-custodian, offline seed backup, NOT Shamir).
//!
//! The property this enforces: decryption is REFUSED unless a matching entry already exists on
//! chain in `ComplianceLog` — checked by THIS process, by independently reading the chain itself,
//! never trusted from the on-chain submission step it just performed. Anyone can independently
//! verify non-access by checking `ComplianceLog` is empty (or that its entries match only
//! legitimate, documented requests) — see verify-privacy.js/verify-kit for the same "don't trust
//! us, check yourself" pattern already used for trade privacy.
//!
//! Flow, all in this one invocation:
//!   1. Submits ComplianceLog.logUnseal(record_hash, reason) on-chain by shelling out to
//!      scripts/request-compliance-unseal.ts (which signs with the configured hardhat network
//!      account and blocks until mined).
//!   2. Independently re-fetches that tx's receipt from RPC_URL and confirms: it succeeded, it was
//!      sent to COMPLIANCE_LOG_ADDRESS, and one of its logs is UnsealRequested(record_hash, ...)
//!      with record_hash matching keccak256(sealed_record) computed right here — step 1 succeeding
//!      is never itself treated as sufficient.
//!   3. Only if that holds: decrypt sealed_record with COMPLIANCE_PRIVATE_KEY and print plaintext.
//!   4. Otherwise: refuse (nonzero exit, no plaintext ever produced).
use std::process::Command;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use zstable_settlement_executor::keccak256;

const SALT: &[u8] = b"zstable-salt-v1";
const COMPLIANCE_INFO: &[u8] = b"zstable-compliance-record-v1";
const UNSEAL_EVENT_SIG: &str = "UnsealRequested(bytes32,string,address,uint256)";

fn json_rpc(rpc_url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp: serde_json::Value = reqwest::blocking::Client::new()
        .post(rpc_url)
        .json(&body)
        .send()
        .map_err(|e| e.to_string())?
        .json()
        .map_err(|e| e.to_string())?;
    if let Some(err) = resp.get("error") {
        return Err(format!("RPC error: {err}"));
    }
    resp.get("result").cloned().ok_or_else(|| "no result in RPC response".to_string())
}

/// Confirms a real, successful `ComplianceLog.logUnseal(record_hash, ...)` already happened
/// on-chain for `record_hash`, by independently reading the transaction's own receipt/logs —
/// never trusting the caller's claim about what the tx did.
fn verify_unseal_logged(rpc_url: &str, compliance_log_address: &str, log_tx_hash: &str, record_hash: &[u8; 32]) -> Result<(), String> {
    let receipt = json_rpc(rpc_url, "eth_getTransactionReceipt", serde_json::json!([log_tx_hash]))?;
    if receipt.is_null() {
        return Err("log_tx_hash not found (not yet mined?)".to_string());
    }
    let status = receipt.get("status").and_then(|s| s.as_str()).unwrap_or("0x0");
    if status != "0x1" {
        return Err("log tx did not succeed".to_string());
    }
    let to = receipt.get("to").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();
    if to != compliance_log_address.to_lowercase() {
        return Err("log tx was not sent to ComplianceLog".to_string());
    }
    let topic0 = format!("0x{}", hex::encode(keccak256(UNSEAL_EVENT_SIG.as_bytes())));
    let want_topic1 = format!("0x{}", hex::encode(record_hash));
    let logs = receipt.get("logs").and_then(|l| l.as_array()).cloned().unwrap_or_default();
    let matched = logs.iter().any(|log| {
        let topics = log.get("topics").and_then(|t| t.as_array()).cloned().unwrap_or_default();
        let t0 = topics.first().and_then(|t| t.as_str()).unwrap_or("").to_lowercase();
        let t1 = topics.get(1).and_then(|t| t.as_str()).unwrap_or("").to_lowercase();
        t0 == topic0.to_lowercase() && t1 == want_topic1.to_lowercase()
    });
    if !matched {
        return Err("no matching UnsealRequested(record_hash,...) log found in that tx".to_string());
    }
    Ok(())
}

fn decrypt_with_compliance_key(secret: &SecretKey, sealed_record: &str) -> Result<Vec<u8>, String> {
    let mut parts = sealed_record.splitn(3, ':');
    let eph_pub_hex = parts.next().ok_or("bad sealed_record format")?;
    let iv_hex = parts.next().ok_or("bad sealed_record format")?;
    let ct_hex = parts.next().ok_or("bad sealed_record format")?;

    let eph = PublicKey::from_sec1_bytes(&hex::decode(eph_pub_hex).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), eph.as_affine());
    let hk = Hkdf::<Sha256>::new(Some(SALT), shared.raw_secret_bytes());
    let mut key = [0u8; 32];
    hk.expand(COMPLIANCE_INFO, &mut key).map_err(|e| e.to_string())?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let iv = hex::decode(iv_hex).map_err(|e| e.to_string())?;
    let ct = hex::decode(ct_hex).map_err(|e| e.to_string())?;
    cipher.decrypt(Nonce::from_slice(&iv), ct.as_ref()).map_err(|_| "decrypt failed".to_string())
}

/// Runs scripts/request-compliance-unseal.ts (signs + submits ComplianceLog.logUnseal, blocks
/// until mined) and returns the tx hash it printed. This is only "step 1" of the guarantee: its
/// success is never itself trusted, `main` always re-verifies independently afterward.
fn submit_unseal_request(contracts_dir: &str, hardhat_network: &str, compliance_log_address: &str, sealed_record: &str, reason: &str) -> Result<String, String> {
    let output = Command::new("npx")
        .args(["hardhat", "run", "scripts/request-compliance-unseal.ts", "--network", hardhat_network])
        .current_dir(contracts_dir)
        .env("COMPLIANCE_LOG", compliance_log_address)
        .env("SEALED_RECORD", sealed_record)
        .env("REASON", reason)
        .output()
        .map_err(|e| format!("failed to run request-compliance-unseal.ts: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        return Err(format!("logUnseal submission failed: {stdout}{}", String::from_utf8_lossy(&output.stderr)));
    }
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("log_tx_hash: "))
        .map(|s| s.split_whitespace().next().unwrap_or(s).to_string())
        .ok_or_else(|| format!("couldn't find log_tx_hash in script output: {stdout}"))
}

/// One-shot CLI: submits the on-chain unseal request, independently re-verifies it landed, and
/// only then decrypts — refuses (nonzero exit) at the first sign anything didn't go through the
/// chain first, no matter how the submission step reported itself.
fn main() {
    dotenv::dotenv().ok();
    let rpc_url = std::env::var("RPC_URL").expect("set RPC_URL");
    let compliance_log_address = std::env::var("COMPLIANCE_LOG_ADDRESS").expect("set COMPLIANCE_LOG_ADDRESS");
    let compliance_secret_hex = std::env::var("COMPLIANCE_PRIVATE_KEY").expect(
        "set COMPLIANCE_PRIVATE_KEY (generated OFFLINE — see /memories/repo/roadmap-tee-compliance.md)",
    );
    let compliance_secret = SecretKey::from_slice(&hex::decode(compliance_secret_hex.trim_start_matches("0x")).expect("bad hex"))
        .expect("bad COMPLIANCE_PRIVATE_KEY");
    let sealed_record = std::env::var("SEALED_RECORD").expect("set SEALED_RECORD (the eph_pub:iv:ct line from the compliance-records jsonl)");
    let reason = std::env::var("REASON").expect("set REASON (goes on-chain permanently and publicly)");
    let contracts_dir = std::env::var("CONTRACTS_DIR").expect("set CONTRACTS_DIR (path to packages/contracts)");
    let hardhat_network = std::env::var("HARDHAT_NETWORK").expect("set HARDHAT_NETWORK (e.g. arc)");

    println!("submitting ComplianceLog.logUnseal on-chain...");
    let log_tx_hash = submit_unseal_request(&contracts_dir, &hardhat_network, &compliance_log_address, &sealed_record, &reason)
        .unwrap_or_else(|e| { eprintln!("refused: {e}"); std::process::exit(1); });
    println!("log_tx_hash: {log_tx_hash}");

    let record_hash = keccak256(sealed_record.as_bytes());
    if let Err(e) = verify_unseal_logged(&rpc_url, &compliance_log_address, &log_tx_hash, &record_hash) {
        // No independently-confirmed log entry -> no plaintext, ever. This is the whole point.
        eprintln!("refused, not logged: {e}");
        std::process::exit(1);
    }

    match decrypt_with_compliance_key(&compliance_secret, &sealed_record) {
        Ok(pt) => println!("plaintext: {}", String::from_utf8_lossy(&pt)),
        Err(e) => { eprintln!("decrypt failed: {e}"); std::process::exit(1); }
    }
}
