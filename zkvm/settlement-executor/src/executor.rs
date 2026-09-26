//! Executes an ordered batch of transactions with real REVM semantics against a database that
//! layers rollup-private state over verified on-chain settlement state.
//!
//! The TEE worker calls this natively for the fast/private path; the SP1 guest program calls
//! the exact same function to produce a proof of the identical execution. Both must produce
//! byte-identical [`BatchResult`]s for the same inputs.

use revm::context::result::{ExecutionResult, HaltReason};
use revm::context::TxEnv;
use revm::database::{CacheDB, DatabaseRef};
use revm::primitives::U256;
use revm::state::EvmState;
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

use crate::commitment::{keccak256, state_commitment, Hash};
use crate::overlay::OverlayState;

/// Everything both the TEE and the SP1 guest must commit to identically for a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicValues {
    pub chain_id: u64,
    pub rollup_address: [u8; 20],
    pub batch_number: u64,
    pub tee_batch_nonce: u64,
    pub old_state_commitment: Hash,
    pub new_state_commitment: Hash,
    pub tx_commitment: Hash,
    pub withdrawals_root: Hash,
    /// Commitment to the price table the batch's trades were checked against (keccak over the
    /// on-chain oracle). The guest verifies each trade's price against this table IN-ZK, so trades
    /// never need to be published on-chain for the settlement to trust their prices. Zero if none.
    pub oracle_root: Hash,
    /// Commitment to the total fee retained per output asset this batch (see `compute_fees_root`).
    /// Fees are never withdrawn separately: they simply reduce the trader's payout below the
    /// gross oracle-derived output, so the retained amount stays in the vault's physical balance
    /// for that asset. Zero if no trade in the batch had a non-zero fee.
    pub fees_root: Hash,
    /// Commitment to how much of each real on-chain deposit (identified by its `noteCommitment`)
    /// this batch's trades consumed as input (see `compute_deposits_root`). This is what ties a
    /// trade's `input_amount` to a genuine, unspent deposit instead of a self-reported number in
    /// the witness — the settlement contract calls `Vault.consumeDeposit` for each disclosed entry,
    /// which reverts if the deposit does not actually have that much `remaining`. Zero if no trade
    /// had a non-zero input (e.g. a batch with only explicit `ctx.withdrawals`).
    pub deposits_root: Hash,
    /// Commitment to the per-asset pricing formula parameters every trade's price was checked
    /// against (see `compute_pricing_params_root`), matching `AssetRegistry.pricingParamsRoot()`.
    /// Lets `settleBatch` bind the batch to a specific, governance-set spread/vol/skew
    /// parameterization instead of trusting whatever the sequencer claims it used.
    pub pricing_params_root: Hash,
    pub tx_count: u32,
}

/// A rollup-private withdrawal a batch authorizes: releases `amount` of `stock_token` to
/// `recipient` on-chain, single-use via `nullifier`. The guest commits the list's root so the
/// settlement contract can trust exactly these withdrawals.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Withdrawal {
    pub nullifier: Hash,
    pub stock_token: [u8; 20],
    /// Big-endian U256.
    pub amount: [u8; 32],
    pub recipient: [u8; 20],
}

/// A priced buy/sell intent executed privately in the batch. The output amount (how much of
/// `output_token` the trader receives) is DERIVED here by both the TEE and the SP1 guest from
/// `input_amount` and `price`, so the proof binds the trade math — the sequencer cannot forge it.
///   side 0 (buy):  input=quote(tUSD), output=stock; output = input * 1e18 / price
///   side 1 (sell): input=stock,       output=quote; output = input * price / 1e18
/// `price` is tUSD (1e18) per 1 whole stock token. `fee_bps` (basis points, capped at
/// `MAX_FEE_BPS`) is taken from that gross output, in the SAME output asset — never converted,
/// never a separate token — and is what the trader actually receives (`compute_trade_net_output`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Trade {
    pub account: [u8; 20],
    pub input_token: [u8; 20],
    /// Big-endian U256.
    pub input_amount: [u8; 32],
    pub output_token: [u8; 20],
    /// Big-endian U256, tUSD (1e18) per 1 whole stock token.
    pub price: [u8; 32],
    pub side: u8,
    /// Private nullifier seed: the withdrawal's nullifier is keccak(domain|secret), NOT derived
    /// from the account, so an on-chain withdrawal cannot be linked back to the depositor.
    #[serde(default)]
    pub secret: [u8; 32],
    /// Basis points of the gross output retained as a fee (0 = no fee). Rejected outright above
    /// `MAX_FEE_BPS`, regardless of who set it.
    #[serde(default)]
    pub fee_bps: u16,
    /// The `noteCommitment` of the on-chain `Vault.deposit` this trade's `input_amount` is drawn
    /// from. Aggregated per commitment into `deposits_root` and enforced on-chain by
    /// `Vault.consumeDeposit`, which reverts if that deposit does not have enough `remaining` —
    /// so a trade cannot spend more than was genuinely deposited. Zero (never deposited under that
    /// commitment) will fail on-chain, not here: the guest only proves the aggregation, not the
    /// deposit's existence (only the Vault's storage is authoritative for that).
    #[serde(default)]
    pub deposit_commitment: Hash,
}

/// Default ERC20 decimals assumed when an oracle entry (or an older oracle file) omits it: 18,
/// which keeps every pre-existing 18-decimal asset behaving exactly as before.
fn default_decimals() -> u8 {
    18
}

/// One asset's committed pricing inputs the guest checks trades against: the on-chain oracle base
/// price (matching `AssetRegistry.oracleRoot()`), that asset's pricing-formula parameters
/// (matching `AssetRegistry.pricingParamsRoot()`), and the live inputs the formula also needs —
/// current credit-line utilization and a recent price history to derive realized volatility from
/// (see `compute_sigma`). Bundled in one entry (rather than three parallel lists) so there is a
/// single per-token lookup and a single list the sequencer must keep in AssetRegistry assetId
/// order for both roots to match on-chain.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OraclePrice {
    pub token: [u8; 20],
    /// Big-endian U256, tUSD (1e18) per 1 whole stock token.
    pub price: [u8; 32],
    /// ERC20 decimals of THIS token, so the guest scales trade amounts between assets with
    /// different decimals (e.g. a 6-decimal USDG quote vs an 18-decimal stock) instead of assuming
    /// 18. Defaults to 18 so pre-existing 18↔18 callers/oracle files stay byte-identical.
    #[serde(default = "default_decimals")]
    pub decimals: u8,
    #[serde(default)]
    pub base_spread_bps: u16,
    #[serde(default)]
    pub vol_coeff_bps: u16,
    #[serde(default)]
    pub skew_coeff_bps: u16,
    #[serde(default)]
    pub sigma_min_1e18: u64,
    #[serde(default)]
    pub sigma_max_1e18: u64,
    /// Fraction (1e18) of this asset's credit line currently deployed; 0 if not tracked/unused.
    #[serde(default)]
    pub utilization_1e18: u64,
    /// Oldest -> newest recent oracle prices (same 1e18 scale as `price`), used to derive realized
    /// volatility. Fewer than 2 entries (including empty, the default) is a cold start: sigma is
    /// conservatively taken as `sigma_max_1e18` rather than assumed calm.
    #[serde(default)]
    pub price_history: Vec<[u8; 32]>,
}

/// Chain/rollup/batch identity a batch is bound to, plus the withdrawals it authorizes
/// (committed via [`PublicValues::withdrawals_root`]) and the priced trades those withdrawals
/// derive from (committed via [`PublicValues::trades_commitment`]).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BatchContext {
    pub chain_id: u64,
    pub rollup_address: [u8; 20],
    pub batch_number: u64,
    pub tee_batch_nonce: u64,
    #[serde(default)]
    pub withdrawals: Vec<Withdrawal>,
    #[serde(default)]
    pub trades: Vec<Trade>,
    /// The on-chain price oracle (token -> price) the guest checks trade prices against, in the
    /// same order the settlement contract recomputes its `oracleRoot` (AssetRegistry assetId order).
    #[serde(default)]
    pub oracle: Vec<OraclePrice>,
}

/// One transaction's REVM execution outcome, kept alongside the raw `ExecutionResult` for the
/// caller to inspect gas usage, logs, or revert reasons.
pub struct TxOutcome {
    pub result: ExecutionResult<HaltReason>,
}

#[derive(Debug)]
pub enum BatchError<DbError> {
    Database(DbError),
    Execution(String),
}

/// Runs `txs` in order against `provider` (verified settlement-chain state) with a
/// rollup-private overlay (deposits, freshly created rollup-only accounts, etc. all live in the
/// overlay via the same `CacheDB`). Returns the per-tx outcomes and the batch's public values.
///
/// `old_state_commitment` must be the commitment of the overlay's state *before* this batch;
/// the caller is responsible for persisting the overlay across batches (the TEE worker keeps it
/// durably; the SP1 guest receives it as part of its witness).
pub fn apply_batch<P>(
    provider: P,
    ctx: &BatchContext,
    old_state_commitment: Hash,
    txs: Vec<TxEnv>,
) -> Result<(Vec<TxOutcome>, PublicValues), BatchError<<P as DatabaseRef>::Error>>
where
    P: DatabaseRef,
{
    let (outcomes, public_values, _state) =
        apply_batch_stateful(provider, ctx, old_state_commitment, txs)?;
    Ok((outcomes, public_values))
}

/// Same as [`apply_batch`] but also returns the raw [`EvmState`] REVM produced, so a stateful
/// caller (the TEE worker) can merge those changes into a durable overlay that persists across
/// batches. The SP1 guest uses [`apply_batch`] (it does not carry state between proofs).
pub fn apply_batch_stateful<P>(
    provider: P,
    ctx: &BatchContext,
    old_state_commitment: Hash,
    txs: Vec<TxEnv>,
) -> Result<(Vec<TxOutcome>, PublicValues, EvmState), BatchError<<P as DatabaseRef>::Error>>
where
    P: DatabaseRef,
{
    let db = CacheDB::new(provider);
    // Configure the EVM for the settlement chain (not Ethereum mainnet) so tx chain-id checks pass.
    let mut evm = Context::mainnet()
        .modify_cfg_chained(|cfg| cfg.chain_id = ctx.chain_id)
        .with_db(db)
        .build_mainnet();

    let mut outcomes = Vec::with_capacity(txs.len());
    let mut tx_hashes = Vec::with_capacity(txs.len());

    for tx in txs {
        let tx_hash = tx_commitment_entry(&tx);
        // `transact_one` accumulates state in the journal; `transact` would finalize (and clear)
        // after every tx, so the single `finalize()` below would then see an empty state.
        let result = evm
            .transact_one(tx)
            .map_err(|_| BatchError::Execution("revm transaction failed".into()))?;
        outcomes.push(TxOutcome { result });
        tx_hashes.push(tx_hash);
    }

    let state = evm.finalize();
    let new_state_commitment = state_commitment(&state);
    let tx_commitment = keccak256_concat_hashes(&tx_hashes);

    // Privacy + trustlessness: the guest recomputes each trade's price from the committed on-chain
    // oracle + pricing formula IN-ZK, so the settlement never needs the plaintext trades to trust
    // the prices, and the operator cannot widen a trade's price beyond what the formula allows.
    verify_quoted_price(ctx).map_err(BatchError::Execution)?;
    verify_trade_fees(ctx).map_err(BatchError::Execution)?;
    verify_trade_deposits(ctx).map_err(BatchError::Execution)?;

    let public_values = PublicValues {
        chain_id: ctx.chain_id,
        rollup_address: ctx.rollup_address,
        batch_number: ctx.batch_number,
        tee_batch_nonce: ctx.tee_batch_nonce,
        old_state_commitment,
        new_state_commitment,
        tx_commitment,
        withdrawals_root: compute_withdrawals_root(&derive_withdrawals(ctx)),
        oracle_root: compute_oracle_root(&ctx.oracle),
        fees_root: compute_fees_root(ctx),
        deposits_root: compute_deposits_root(ctx),
        pricing_params_root: compute_pricing_params_root(&ctx.oracle),
        tx_count: outcomes.len() as u32,
    };

    Ok((outcomes, public_values, state))
}

/// Executes a batch on top of a durable rollup [`OverlayState`]: the overlay is layered over the
/// verified base state (so prior rollup writes persist), the batch runs, and its changes are
/// merged back into the overlay. Chains the state commitment (`old` = the overlay's running
/// commitment, `new` = this batch's diff commitment). Returns the updated overlay for the caller
/// to persist. This is what the TEE worker uses to keep real rollup balances across batches.
pub fn apply_batch_with_overlay<P>(
    base: P,
    mut overlay: OverlayState,
    ctx: &BatchContext,
    txs: Vec<TxEnv>,
) -> Result<(Vec<TxOutcome>, PublicValues, OverlayState), BatchError<<P as DatabaseRef>::Error>>
where
    P: DatabaseRef,
{
    let old_state_commitment = overlay.commitment();
    let (outcomes, public_values, state) = {
        let layered = overlay.layer_over(base);
        apply_batch_stateful(layered, ctx, old_state_commitment, txs)?
    };
    overlay.apply_evm_state(&state);
    overlay.set_commitment(public_values.new_state_commitment);
    Ok((outcomes, public_values, overlay))
}

fn tx_commitment_entry(tx: &TxEnv) -> Hash {
    keccak256(format!("{tx:?}").as_bytes())
}

/// Deterministic commitment to a batch's withdrawals, matching `ZstableRollup`'s on-chain
/// recomputation: keccak256 over each entry packed as
/// nullifier(32) | stockToken(20) | amount(32) | recipient(20), in list order. An empty list
/// commits to the zero hash so "no withdrawals" is unambiguous and cheap to check on-chain.
pub fn compute_withdrawals_root(withdrawals: &[Withdrawal]) -> Hash {
    if withdrawals.is_empty() {
        return [0u8; 32];
    }
    let mut buf = Vec::with_capacity(withdrawals.len() * 104);
    for w in withdrawals {
        buf.extend_from_slice(&w.nullifier);
        buf.extend_from_slice(&w.stock_token);
        buf.extend_from_slice(&w.amount);
        buf.extend_from_slice(&w.recipient);
    }
    keccak256(&buf)
}

fn keccak256_concat_hashes(hashes: &[Hash]) -> Hash {
    let mut buf = Vec::with_capacity(hashes.len() * 32);
    for h in hashes {
        buf.extend_from_slice(h);
    }
    keccak256(&buf)
}

/// 1e18 fixed-point scale for prices (tUSD per 1 whole stock token).
const PRICE_SCALE: u128 = 1_000_000_000_000_000_000;

/// This token's ERC20 decimals as committed in the oracle table (18 if it's not listed, matching
/// the pre-decimals behavior). The quote asset is always in the oracle table alongside the stocks,
/// so both sides of a trade resolve here.
fn decimals_of(oracle: &[OraclePrice], token: &[u8; 20]) -> u32 {
    oracle
        .iter()
        .find(|o| &o.token == token)
        .map(|o| o.decimals as u32)
        .unwrap_or(18)
}

/// Derives a trade's output amount from its input and price. Both the TEE and the SP1 guest call
/// this, so the proof binds `output == f(input, price, side)` — the sequencer cannot forge fills.
///
/// `price` is 1e18-scaled quote-per-1-whole-stock, but token AMOUNTS live in each token's own
/// decimals, which need NOT match (mainnet's USDG quote is 6, stocks are 18). So the raw
/// `input * 1e18 / price` (which silently assumes input.decimals == output.decimals) is scaled by
/// `10^output_decimals / 10^input_decimals`. When both are 18 that factor is 1 and this collapses
/// EXACTLY to the previous formula, so 18↔18 (testnet) output is byte-identical.
pub fn compute_trade_output(trade: &Trade, oracle: &[OraclePrice]) -> [u8; 32] {
    let input = U256::from_be_bytes::<32>(trade.input_amount);
    let price = U256::from_be_bytes::<32>(trade.price);
    let scale = U256::from(PRICE_SCALE);
    let pow_in = U256::from(10u64).pow(U256::from(decimals_of(oracle, &trade.input_token)));
    let pow_out = U256::from(10u64).pow(U256::from(decimals_of(oracle, &trade.output_token)));
    let out = if price.is_zero() {
        U256::ZERO
    } else if trade.side == 0 {
        // buy: stock_out = quote_in * 10^stockDec * 1e18 / (10^quoteDec * price)
        input.saturating_mul(pow_out).saturating_mul(scale) / pow_in.saturating_mul(price)
    } else {
        // sell: quote_out = stock_in * price * 10^quoteDec / (10^stockDec * 1e18)
        input.saturating_mul(price).saturating_mul(pow_out) / pow_in.saturating_mul(scale)
    };
    out.to_be_bytes::<32>()
}

/// The nullifier binding a trade's derived withdrawal: keccak(domain | secret). Derived only from
/// the user's private secret, so an on-chain withdrawal reveals no link to the depositor/account.
fn trade_nullifier(trade: &Trade) -> Hash {
    let mut buf = Vec::with_capacity(16 + 32);
    buf.extend_from_slice(b"zstable-nullifier");
    buf.extend_from_slice(&trade.secret);
    keccak256(&buf)
}

/// The full withdrawal set a batch authorizes: any explicit `ctx.withdrawals`, then one derived
/// per trade (releasing the priced NET output token/amount to the trader, i.e. gross minus fee —
/// see `compute_trade_net_output`). Both the executor (for the committed root) and the sequencer
/// (for the on-chain withdrawals list) call this, so they agree.
pub fn derive_withdrawals(ctx: &BatchContext) -> Vec<Withdrawal> {
    let mut out = ctx.withdrawals.clone();
    for trade in ctx.trades.iter() {
        out.push(Withdrawal {
            nullifier: trade_nullifier(trade),
            stock_token: trade.output_token,
            amount: compute_trade_net_output(trade, &ctx.oracle),
            recipient: trade.account,
        });
    }
    out
}

/// Deterministic commitment to the price oracle, matching `AssetRegistry.oracleRoot()` on-chain:
/// keccak256 over each entry packed as token(20) | price(32) | historyRoot(32), in list order.
/// `historyRoot` is `compute_price_history_hash(&o.price_history)` when the witness carries any
/// history samples, or the zero hash when it carries none — matching `AssetRegistry.oracleRoot()`
/// exactly: a statically-priced asset (`priceOracleRef`, no `IPriceOracle` set) always commits
/// `bytes32(0)` there, and never has real samples to offer here either. A real
/// `UniswapV3TwapOracle` never returns an empty history (its constructor requires
/// `historyLength > 0`), so "empty" unambiguously means "no history source", not "cold start with
/// zero samples". This is what binds the guest's realized-volatility input (`o.price_history`) to
/// the same trustless on-chain source as the price itself, instead of a self-reported witness
/// value. Empty oracle list -> zero hash.
pub fn compute_oracle_root(oracle: &[OraclePrice]) -> Hash {
    if oracle.is_empty() {
        return [0u8; 32];
    }
    let mut buf = Vec::with_capacity(oracle.len() * 84);
    for o in oracle {
        buf.extend_from_slice(&o.token);
        buf.extend_from_slice(&o.price);
        let history_root = if o.price_history.is_empty() {
            [0u8; 32]
        } else {
            compute_price_history_hash(&o.price_history)
        };
        buf.extend_from_slice(&history_root);
    }
    keccak256(&buf)
}

/// keccak256 over the price history packed as price_1(32) | price_2(32) | ... | price_N(32),
/// oldest first, matching `UniswapV3TwapOracle._historyRoot()`.
pub fn compute_price_history_hash(price_history: &[[u8; 32]]) -> Hash {
    let mut buf = Vec::with_capacity(price_history.len() * 32);
    for p in price_history {
        buf.extend_from_slice(p);
    }
    keccak256(&buf)
}

/// Deterministic commitment to the pricing formula parameters, matching
/// `AssetRegistry.pricingParamsRoot()` on-chain: keccak256 over each oracle entry packed as
/// token(20) | baseSpreadBps(2) | volCoeffBps(2) | skewCoeffBps(2) | sigmaMin(8) | sigmaMax(8), in
/// the same list order `compute_oracle_root` uses. Empty -> zero hash.
pub fn compute_pricing_params_root(oracle: &[OraclePrice]) -> Hash {
    if oracle.is_empty() {
        return [0u8; 32];
    }
    let mut buf = Vec::with_capacity(oracle.len() * 42);
    for o in oracle {
        buf.extend_from_slice(&o.token);
        buf.extend_from_slice(&o.base_spread_bps.to_be_bytes());
        buf.extend_from_slice(&o.vol_coeff_bps.to_be_bytes());
        buf.extend_from_slice(&o.skew_coeff_bps.to_be_bytes());
        buf.extend_from_slice(&o.sigma_min_1e18.to_be_bytes());
        buf.extend_from_slice(&o.sigma_max_1e18.to_be_bytes());
    }
    keccak256(&buf)
}

/// sqrt(pi/2) as a 1e18 fixed-point constant: for i.i.d. normally-distributed returns,
/// E[|r|] = sqrt(2/pi)*sigma, so sigma = mean-absolute-deviation * sqrt(pi/2). Using MAD instead of
/// a variance+sqrt estimator avoids squaring/rooting entirely, which is materially cheaper inside
/// the guest (see the sigma spec in ZSTABLE_MAINNET_VAULT_LIQUIDITA_E_REBALANCING.md).
const SIGMA_FROM_MAD_1E18: u128 = 1_253_314_137_315_500_251;

/// 1 basis point as a 1e18 fixed-point fraction (1 bps = 1e-4 = 1e14 / 1e18).
const BPS_TO_1E18: u128 = 100_000_000_000_000;

/// Realized volatility from `price_history` (oldest -> newest, 1e18-scale prices): mean absolute
/// value of simple returns between consecutive entries, scaled by `SIGMA_FROM_MAD_1E18`, then
/// clamped to `[sigma_min_1e18, sigma_max_1e18]`. A history with fewer than 2 usable prices (cold
/// start, or all only differ from a zero entry which is skipped to avoid a div-by-zero) cannot
/// produce a single return, and is treated as maximally uncertain: `sigma_max_1e18`, the
/// conservative bound that protects LPs rather than assuming a calm market with no data.
pub fn compute_sigma(price_history: &[[u8; 32]], sigma_min_1e18: u64, sigma_max_1e18: u64) -> U256 {
    let sigma_min = U256::from(sigma_min_1e18);
    let sigma_max = U256::from(sigma_max_1e18);
    let scale = U256::from(PRICE_SCALE);

    let mut sum_abs_return = U256::ZERO;
    let mut count: u64 = 0;
    for pair in price_history.windows(2) {
        let prev = U256::from_be_bytes::<32>(pair[0]);
        let curr = U256::from_be_bytes::<32>(pair[1]);
        if prev.is_zero() {
            continue;
        }
        let diff = if curr >= prev { curr - prev } else { prev - curr };
        let abs_return = diff.saturating_mul(scale) / prev;
        sum_abs_return = sum_abs_return.saturating_add(abs_return);
        count += 1;
    }
    if count == 0 {
        return sigma_max;
    }
    let mad = sum_abs_return / U256::from(count);
    let sigma = mad.saturating_mul(U256::from(SIGMA_FROM_MAD_1E18)) / scale;
    if sigma < sigma_min {
        sigma_min
    } else if sigma > sigma_max {
        sigma_max
    } else {
        sigma
    }
}

/// Applies the market-maker formula to `oracle_price` for one trade's direction:
/// `P_quote = P_oracle * (1e18 +/- (baseSpread + volCoeff*sigma + skewCoeff*utilization)) / 1e18`.
/// The spread always widens AGAINST the trader: buy pays a higher price (+), sell receives a
/// lower one (-). `base/vol/skew_coeff_bps` are first converted from basis points to a 1e18
/// fraction, then `vol`/`skew` are applied as a coefficient against `sigma`/`utilization` (also
/// 1e18 fractions), so every term is a 1e18 fraction of the oracle price before being summed.
pub fn compute_quoted_price(
    oracle_price: U256,
    side: u8,
    base_spread_bps: u16,
    vol_coeff_bps: u16,
    skew_coeff_bps: u16,
    sigma_1e18: U256,
    utilization_1e18: U256,
) -> U256 {
    let scale = U256::from(PRICE_SCALE);
    let bps_scale = U256::from(BPS_TO_1E18);

    let base_frac = U256::from(base_spread_bps).saturating_mul(bps_scale);
    let vol_frac = U256::from(vol_coeff_bps).saturating_mul(bps_scale).saturating_mul(sigma_1e18) / scale;
    let skew_frac =
        U256::from(skew_coeff_bps).saturating_mul(bps_scale).saturating_mul(utilization_1e18) / scale;
    let total_spread_frac = base_frac.saturating_add(vol_frac).saturating_add(skew_frac);

    if side == 0 {
        oracle_price.saturating_mul(scale.saturating_add(total_spread_frac)) / scale
    } else {
        let multiplier = scale.saturating_sub(total_spread_frac);
        oracle_price.saturating_mul(multiplier) / scale
    }
}

/// Recomputes each trade's expected price from the committed oracle base price and that asset's
/// pricing formula (spread + realized volatility + utilization skew), and requires the trade's
/// price to match EXACTLY. This is what stops the operator from ever widening a trader's price:
/// the formula, its parameters, and the data it runs on (oracle price, price history, utilization)
/// are all committed on-chain, so there is no free variable left for the sequencer to choose.
/// Replaces the older, spread-less `trade.price == oracle.price` check as a strict superset of it:
/// an asset with no pricing params/market state configured (all fields default to zero) yields
/// `total_spread_frac == 0`, so `P_quote == oracle_price` exactly, same as before.
fn verify_quoted_price(ctx: &BatchContext) -> Result<(), String> {
    for t in &ctx.trades {
        let stock = if t.side == 0 { t.output_token } else { t.input_token };
        let entry = ctx
            .oracle
            .iter()
            .find(|o| o.token == stock)
            .ok_or_else(|| "trade token is not in the on-chain oracle".to_string())?;
        let oracle_price = U256::from_be_bytes::<32>(entry.price);
        let sigma = compute_sigma(&entry.price_history, entry.sigma_min_1e18, entry.sigma_max_1e18);
        let utilization = U256::from(entry.utilization_1e18);
        let expected = compute_quoted_price(
            oracle_price,
            t.side,
            entry.base_spread_bps,
            entry.vol_coeff_bps,
            entry.skew_coeff_bps,
            sigma,
            utilization,
        );
        if U256::from_be_bytes::<32>(t.price) != expected {
            return Err("trade price does not match the pricing formula".into());
        }
    }
    Ok(())
}

/// Protocol-wide hard cap on any single trade's fee, in basis points of its gross derived output.
/// This is a safety rail only: the actual fee RATE charged, how it is split between the LP whose
/// asset backed the trade and the protocol, and any interest/spread on top, are still-open
/// economic decisions (see ZSTABLE_MAINNET_VAULT_LIQUIDITA_E_REBALANCING.md) — not made here.
pub const MAX_FEE_BPS: u16 = 500; // 5%

/// Rejects any trade whose fee rate exceeds `MAX_FEE_BPS`. Independent of price verification: a
/// trade can have a correct oracle price and still be rejected for an out-of-bounds fee.
fn verify_trade_fees(ctx: &BatchContext) -> Result<(), String> {
    for t in &ctx.trades {
        if t.fee_bps > MAX_FEE_BPS {
            return Err("trade fee exceeds the protocol maximum".into());
        }
    }
    Ok(())
}

/// Fee taken from a trade's gross derived output, in the SAME (output) asset — never a separate
/// token or currency, never converted via the oracle. `trade.fee_bps` is basis points of the
/// gross output; 0 means no fee.
pub fn compute_trade_fee(trade: &Trade, oracle: &[OraclePrice]) -> [u8; 32] {
    let gross = U256::from_be_bytes::<32>(compute_trade_output(trade, oracle));
    let bps = U256::from(trade.fee_bps);
    (gross.saturating_mul(bps) / U256::from(10_000u64)).to_be_bytes::<32>()
}

/// What the trader actually receives: gross oracle-derived output minus the fee. Both are
/// deterministic functions of `trade`, so the sequencer cannot inflate the fee or under-report
/// the payout without changing the trade itself (and thus the committed roots).
pub fn compute_trade_net_output(trade: &Trade, oracle: &[OraclePrice]) -> [u8; 32] {
    let gross = U256::from_be_bytes::<32>(compute_trade_output(trade, oracle));
    let fee = U256::from_be_bytes::<32>(compute_trade_fee(trade, oracle));
    gross.saturating_sub(fee).to_be_bytes::<32>()
}

/// Deterministic commitment to the total fee retained per output asset this batch, address-sorted:
/// keccak256 over each entry packed as token(20) | totalFeeAmount(32). This does not move or
/// create value — the fee simply stays in the vault's existing physical balance for that asset
/// instead of being paid out to the trader — it only makes the retained amount independently
/// auditable (e.g. by `verify-privacy.js` or an LP monitoring tool) without publishing individual
/// trades. Empty (no trade had a non-zero fee) -> zero hash.
pub fn compute_fees_root(ctx: &BatchContext) -> Hash {
    let totals = fee_totals_by_asset(ctx);
    if totals.is_empty() {
        return [0u8; 32];
    }
    let mut buf = Vec::with_capacity(totals.len() * 52);
    for (token, amount) in &totals {
        buf.extend_from_slice(token);
        buf.extend_from_slice(&amount.to_be_bytes::<32>());
    }
    keccak256(&buf)
}

/// The same per-asset fee totals as `compute_fees_root`, but as an explicit list rather than a
/// hash — this is what a settlement submitter (e.g. `submit-settlement.ts`) discloses on-chain as
/// `ZstableRollup.FeeEntry[]`; hashing it with the same packing must reproduce `compute_fees_root`.
pub fn compute_fee_entries(ctx: &BatchContext) -> Vec<([u8; 20], [u8; 32])> {
    fee_totals_by_asset(ctx)
        .into_iter()
        .map(|(token, amount)| (token, amount.to_be_bytes::<32>()))
        .collect()
}

fn fee_totals_by_asset(ctx: &BatchContext) -> std::collections::BTreeMap<[u8; 20], U256> {
    use std::collections::BTreeMap;
    let mut totals: BTreeMap<[u8; 20], U256> = BTreeMap::new();
    for trade in &ctx.trades {
        let fee = U256::from_be_bytes::<32>(compute_trade_fee(trade, &ctx.oracle));
        if fee.is_zero() {
            continue;
        }
        *totals.entry(trade.output_token).or_insert(U256::ZERO) += fee;
    }
    totals
}

/// Rejects a batch where the same deposit commitment is referenced by trades with different
/// `input_token`s (which would be nonsensical — one deposit is denominated in one asset). This is
/// a cheap sanity check; the authoritative check is on-chain in `Vault.consumeDeposit`, which
/// knows the deposit's real asset and would revert the whole batch anyway.
fn verify_trade_deposits(ctx: &BatchContext) -> Result<(), String> {
    use std::collections::HashMap;
    let mut asset_by_commitment: HashMap<Hash, [u8; 20]> = HashMap::new();
    for t in &ctx.trades {
        match asset_by_commitment.get(&t.deposit_commitment) {
            Some(existing) if *existing != t.input_token => {
                return Err("deposit commitment referenced with inconsistent input asset".into());
            }
            _ => {
                asset_by_commitment.insert(t.deposit_commitment, t.input_token);
            }
        }
    }
    Ok(())
}

/// Deterministic commitment to how much of each real deposit this batch's trades consumed as
/// input, commitment-sorted: keccak256 over each entry packed as
/// noteCommitment(32) | asset(20) | totalAmount(32). Multiple trades may draw on the same deposit
/// within a batch; their `input_amount`s are summed here, and `Vault.consumeDeposit` enforces
/// on-chain that the sum never exceeds that deposit's real `remaining`. Empty -> zero hash.
pub fn compute_deposits_root(ctx: &BatchContext) -> Hash {
    let totals = deposit_totals_by_commitment(ctx);
    if totals.is_empty() {
        return [0u8; 32];
    }
    let mut buf = Vec::with_capacity(totals.len() * 84);
    for ((commitment, asset), amount) in &totals {
        buf.extend_from_slice(commitment);
        buf.extend_from_slice(asset);
        buf.extend_from_slice(&amount.to_be_bytes::<32>());
    }
    keccak256(&buf)
}

/// The same per-deposit consumption totals as `compute_deposits_root`, but as an explicit list —
/// this is what a settlement submitter discloses on-chain as `ZstableRollup.DepositConsumption[]`;
/// hashing it with the same packing must reproduce `compute_deposits_root`.
pub fn compute_deposit_entries(ctx: &BatchContext) -> Vec<(Hash, [u8; 20], [u8; 32])> {
    deposit_totals_by_commitment(ctx)
        .into_iter()
        .map(|((commitment, asset), amount)| (commitment, asset, amount.to_be_bytes::<32>()))
        .collect()
}

fn deposit_totals_by_commitment(ctx: &BatchContext) -> std::collections::BTreeMap<(Hash, [u8; 20]), U256> {
    use std::collections::BTreeMap;
    let mut totals: BTreeMap<(Hash, [u8; 20]), U256> = BTreeMap::new();
    for trade in &ctx.trades {
        let input = U256::from_be_bytes::<32>(trade.input_amount);
        if input.is_zero() {
            continue;
        }
        *totals
            .entry((trade.deposit_commitment, trade.input_token))
            .or_insert(U256::ZERO) += input;
    }
    totals
}
