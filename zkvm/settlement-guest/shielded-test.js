// End-to-end test of the shielded-sequencer: seal an order to its /pubkey, POST /execute-blind, and
// print the proof result. This is exactly what the dApp browser + blind relay will do.
const { webcrypto } = require("crypto");
const fs = require("fs");
const subtle = webcrypto.subtle;
const enc = new TextEncoder();
const SALT = enc.encode("zstable-salt-v1");
const INFO = enc.encode("zstable-sealed-order-v1");
const BASE = process.env.BLIND_URL || "http://127.0.0.1:4100";

async function seal(pubHex, plaintext) {
  const pubRaw = Buffer.from(pubHex.replace(/^0x/, ""), "hex");
  const workerPub = await subtle.importKey("raw", pubRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const eph = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const shared = await subtle.deriveBits({ name: "ECDH", public: workerPub }, eph.privateKey, 256);
  const hk = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const keyBits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: SALT, info: INFO }, hk, 256);
  const aesKey = await subtle.importKey("raw", keyBits, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(plaintext));
  const ephRaw = await subtle.exportKey("raw", eph.publicKey);
  return { eph_pub: Buffer.from(ephRaw).toString("hex"), iv: Buffer.from(iv).toString("hex"), ct: Buffer.from(ct).toString("hex") };
}

(async () => {
  const market = JSON.parse(fs.readFileSync("/root/zstable/contracts/deployments/market.arcTestnet.json", "utf8"));
  const oracle = [{ token: market.quote.address, price: market.quote.price }, ...market.stocks.map((s) => ({ token: s.address, price: s.price }))];
  const stock = market.stocks[0]; // zAAPL

  const pub = (await (await fetch(`${BASE}/pubkey`)).json()).pubkey;
  console.log("blind pubkey:", pub.slice(0, 24) + "…");

  const secret = "0x" + Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString("hex");
  // Must match a REAL, unspent Vault.deposit noteCommitment or settleBatch reverts ("asset
  // mismatch"/"insufficient deposit") — see DEPOSIT_COMMITMENT env override below.
  const deposit_commitment = process.env.DEPOSIT_COMMITMENT || "0x" + "00".repeat(32);
  const order = {
    side: 0,
    stock: stock.address,
    quote: market.quote.address,
    input: "180000000000000000000",
    recipient: "0x593bB363C07E6Bd22561BeE78847A72ABBC51716",
    secret,
    deposit_commitment,
  };
  console.log("ORDER (only the enclave will see this):", JSON.stringify(order));

  const sealed = await seal(pub, JSON.stringify(order));
  const req = { sealed, batch_number: 1, chain_id: 46630, rollup_id: "0x00000000000000000000000000000000000000AA", oracle };
  console.log("posting sealed order (operator sees only ciphertext) …");

  const res = await fetch(`${BASE}/execute-blind`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(req) });
  const out = await res.json();
  if (out.error) { console.log("ERROR:", out.error); process.exit(1); }
  console.log("tee_agree      :", out.tee_agree);
  console.log("proof selector :", out.proof.slice(0, 10), "len", (out.proof.length - 2) / 2, "B");
  console.log("vkey           :", out.vkey);
  console.log("attestation    :", out.attestation_hash, `(${out.attestation_status})`);
  for (const w of out.withdrawals) console.log("withdrawal     : token", w.stock_token, "amount", BigInt(w.amount).toString(), "-> ", w.recipient, "nullifier", w.nullifier.slice(0, 14) + "…");

  // Field names already match ZstableRollup.settleBatch's shape (see submit-settlement.ts); only
  // batch_number is missing from the response since it's an input, not something the enclave echoes.
  const settlementPath = process.env.SETTLEMENT_PATH || "settlement.json";
  fs.writeFileSync(settlementPath, JSON.stringify({ batch_number: req.batch_number, ...out }, null, 2));
  console.log("wrote", settlementPath);
})();
