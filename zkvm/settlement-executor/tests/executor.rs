//! Validates real REVM execution (not a custom ledger): a simple value transfer, and the core
//! safety property that running the same batch against the same starting state twice produces
//! identical public values.

use revm::context::TxEnv;
use revm::context_interface::result::ExecutionResult;
use revm::primitives::{TxKind, U256};
use revm::state::AccountInfo;
use zstable_settlement_executor::{
    apply_batch, compute_deposits_root, compute_fees_root, compute_oracle_root,
    compute_price_history_hash, compute_pricing_params_root, compute_quoted_price, compute_sigma,
    compute_trade_fee, compute_trade_net_output, compute_trade_output, compute_withdrawals_root,
    keccak256, BatchContext, MockChainStateProvider, OraclePrice, Trade, Withdrawal,
    MAX_FEE_BPS,
};

const CHAIN_ID: u64 = 1;
const ROLLUP_ADDRESS: [u8; 20] = [0x22; 20];

fn default_ctx() -> BatchContext {
    BatchContext {
        chain_id: CHAIN_ID,
        rollup_address: ROLLUP_ADDRESS,
        batch_number: 1,
        tee_batch_nonce: 1,
        withdrawals: Vec::new(),
        trades: Vec::new(),
        oracle: Vec::new(),
    }
}

fn funded_provider(sender: revm::primitives::Address, balance: u128) -> MockChainStateProvider {
    let mut provider = MockChainStateProvider::new();
    provider.set_account(
        sender,
        AccountInfo {
            balance: U256::from(balance),
            nonce: 0,
            ..Default::default()
        },
    );
    provider
}

fn simple_transfer_tx(sender: revm::primitives::Address, recipient: revm::primitives::Address, value: u128) -> TxEnv {
    TxEnv {
        caller: sender,
        kind: TxKind::Call(recipient),
        value: U256::from(value),
        gas_limit: 21_000,
        gas_price: 0,
        chain_id: Some(CHAIN_ID),
        nonce: 0,
        ..Default::default()
    }
}

#[test]
fn simple_value_transfer_succeeds() {
    let sender = revm::primitives::Address::from([0x11u8; 20]);
    let recipient = revm::primitives::Address::from([0x33u8; 20]);
    let provider = funded_provider(sender, 1_000_000_000_000_000_000);
    let old_commitment = keccak256(b"genesis");

    let tx = simple_transfer_tx(sender, recipient, 1_000);
    let (outcomes, public_values) =
        apply_batch(provider, &default_ctx(), old_commitment, vec![tx]).expect("batch applies");

    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0].result, ExecutionResult::Success { .. }));
    assert_eq!(public_values.tx_count, 1);
    assert_ne!(public_values.old_state_commitment, public_values.new_state_commitment);
}

#[test]
fn same_batch_from_same_state_is_deterministic() {
    let sender = revm::primitives::Address::from([0x11u8; 20]);
    let recipient = revm::primitives::Address::from([0x33u8; 20]);
    let old_commitment = keccak256(b"genesis");

    let provider_a = funded_provider(sender, 1_000_000_000_000_000_000);
    let provider_b = funded_provider(sender, 1_000_000_000_000_000_000);

    let tx_a = simple_transfer_tx(sender, recipient, 1_000);
    let tx_b = simple_transfer_tx(sender, recipient, 1_000);

    let (_, public_values_a) =
        apply_batch(provider_a, &default_ctx(), old_commitment, vec![tx_a]).expect("batch applies");
    let (_, public_values_b) =
        apply_batch(provider_b, &default_ctx(), old_commitment, vec![tx_b]).expect("batch applies");

    // The whole point of the TEE+ZK design: independent runs of the same batch against the
    // same starting state must agree byte-for-byte on the resulting public values.
    assert_eq!(public_values_a, public_values_b);
}

#[test]
fn insufficient_balance_transfer_fails() {
    let sender = revm::primitives::Address::from([0x44u8; 20]);
    let recipient = revm::primitives::Address::from([0x55u8; 20]);
    let provider = funded_provider(sender, 10);
    let old_commitment = keccak256(b"genesis");

    let tx = simple_transfer_tx(sender, recipient, 1_000);
    // revm may reject this outright as an invalid transaction (insufficient funds check before
    // execution), or execute it and halt/revert — either is an acceptable rejection here.
    match apply_batch(provider, &default_ctx(), old_commitment, vec![tx]) {
        Ok((outcomes, _)) => assert!(!matches!(outcomes[0].result, ExecutionResult::Success { .. })),
        Err(_) => {}
    }
}

#[test]
fn withdrawals_root_matches_solidity_packing() {
    // Reference computed with ethers (mirrors ZstableRollup._withdrawalsRoot) for the vector
    // nullifier=0x11*32, stockToken=0x22*20, amount=1000, recipient=0x33*20. If this drifts, the
    // guest's committed root would no longer match the settlement contract's recomputation.
    let mut amount = [0u8; 32];
    amount[30] = 0x03;
    amount[31] = 0xE8; // 1000
    let w = Withdrawal {
        nullifier: [0x11u8; 32],
        stock_token: [0x22u8; 20],
        amount,
        recipient: [0x33u8; 20],
    };
    let root = compute_withdrawals_root(&[w]);
    let expected =
        hex_literal_32("94754cf29ca93dd3ea7b3169e4011cfa3b1d412b2737cf61fb61755097dc5a28");
    assert_eq!(root, expected);
    assert_eq!(compute_withdrawals_root(&[]), [0u8; 32]);
}

fn hex_literal_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn sample_trade(input_amount: u128, price: u128, side: u8, fee_bps: u16) -> Trade {
    Trade {
        account: [0x11u8; 20],
        input_token: [0x22u8; 20],
        input_amount: U256::from(input_amount).to_be_bytes::<32>(),
        output_token: [0x33u8; 20],
        price: U256::from(price).to_be_bytes::<32>(),
        side,
        secret: [0x44u8; 32],
        fee_bps,
        deposit_commitment: [0u8; 32],
    }
}

#[test]
fn trade_fee_is_deducted_from_gross_output_in_the_output_asset() {
    // buy: input 100 tUSD (1e18-scaled) at price 2 (1e18-scaled) -> gross output 50 stock.
    let trade = sample_trade(100_000_000_000_000_000_000, 2_000_000_000_000_000_000, 0, 250); // 2.5%
    // Empty oracle -> both tokens default to 18 decimals, so the 18↔18 math is unchanged.
    let gross = U256::from_be_bytes::<32>(compute_trade_output(&trade, &[]));
    let fee = U256::from_be_bytes::<32>(compute_trade_fee(&trade, &[]));
    let net = U256::from_be_bytes::<32>(compute_trade_net_output(&trade, &[]));

    assert_eq!(gross, U256::from(50_000_000_000_000_000_000u128));
    assert_eq!(fee, gross * U256::from(250u64) / U256::from(10_000u64));
    assert_eq!(net, gross - fee);
    assert!(fee > U256::ZERO);
}

#[test]
fn zero_fee_bps_yields_zero_fee_and_net_equal_to_gross() {
    let trade = sample_trade(100_000_000_000_000_000_000, 2_000_000_000_000_000_000, 0, 0);
    let gross = U256::from_be_bytes::<32>(compute_trade_output(&trade, &[]));
    let net = U256::from_be_bytes::<32>(compute_trade_net_output(&trade, &[]));
    assert_eq!(U256::from_be_bytes::<32>(compute_trade_fee(&trade, &[])), U256::ZERO);
    assert_eq!(net, gross);
}

#[test]
fn fees_root_aggregates_per_output_asset_and_is_zero_without_fees() {
    let trade_a = sample_trade(100_000_000_000_000_000_000, 2_000_000_000_000_000_000, 0, 100);
    let mut trade_b = sample_trade(50_000_000_000_000_000_000, 2_000_000_000_000_000_000, 0, 100);
    trade_b.output_token = trade_a.output_token; // same output asset -> fees must aggregate

    let base_ctx = BatchContext {
        chain_id: 1,
        rollup_address: [0u8; 20],
        batch_number: 1,
        tee_batch_nonce: 1,
        withdrawals: Vec::new(),
        trades: vec![trade_a, trade_b],
        oracle: Vec::new(),
    };
    let root = compute_fees_root(&base_ctx);
    assert_ne!(root, [0u8; 32]);

    let no_fee_trade = sample_trade(10_000_000_000_000_000_000, 2_000_000_000_000_000_000, 0, 0);
    let empty_ctx = BatchContext {
        trades: vec![no_fee_trade],
        ..base_ctx
    };
    assert_eq!(compute_fees_root(&empty_ctx), [0u8; 32]);
}

#[test]
fn batch_rejects_a_trade_whose_fee_exceeds_the_protocol_cap() {
    let sender = revm::primitives::Address::from([0x11u8; 20]);
    let provider = funded_provider(sender, 1_000_000_000_000_000_000);
    let old_commitment = keccak256(b"genesis");

    let mut ctx = default_ctx();
    ctx.trades.push(sample_trade(
        10_000_000_000_000_000_000,
        2_000_000_000_000_000_000,
        0,
        MAX_FEE_BPS + 1,
    ));

    let result = apply_batch(provider, &ctx, old_commitment, Vec::new());
    assert!(result.is_err(), "a trade above MAX_FEE_BPS must be rejected");
}

#[test]
fn fees_root_matches_solidity_packing() {
    // Reference computed with ethers (mirrors ZstableRollup._feesRoot) for the vector
    // asset=0x22*20, amount=1000. If this drifts, the guest's committed feesRoot would no longer
    // match the settlement contract's recomputation. fee_bps=10000 (100%) here only to make this
    // pure hashing test produce fee==gross==1000; verify_trade_fees would reject that ratio
    // outside a unit test that calls compute_fees_root directly.
    let mut trade = sample_trade(1000, 1_000_000_000_000_000_000, 0, 10_000);
    trade.output_token = [0x22u8; 20];
    let ctx = BatchContext {
        chain_id: 1,
        rollup_address: [0u8; 20],
        batch_number: 1,
        tee_batch_nonce: 1,
        withdrawals: Vec::new(),
        trades: vec![trade],
        oracle: Vec::new(),
    };
    let root = compute_fees_root(&ctx);
    let expected =
        hex_literal_32("7b1597fbb410e5215c34a21268251d3f114a2b5196fb86ef45d0336acc8ae302");
    assert_eq!(root, expected);
}

#[test]
fn deposits_root_aggregates_per_commitment_and_is_zero_without_input() {
    let mut trade_a = sample_trade(100_000_000_000_000_000_000, 2_000_000_000_000_000_000, 0, 0);
    trade_a.deposit_commitment = [0x55u8; 32];
    let mut trade_b = sample_trade(50_000_000_000_000_000_000, 2_000_000_000_000_000_000, 0, 0);
    trade_b.deposit_commitment = [0x55u8; 32]; // same deposit, second trade drawing on it
    trade_b.input_token = trade_a.input_token; // must match: same asset for the same commitment

    let base_ctx = BatchContext {
        chain_id: 1,
        rollup_address: [0u8; 20],
        batch_number: 1,
        tee_batch_nonce: 1,
        withdrawals: Vec::new(),
        trades: vec![trade_a, trade_b],
        oracle: Vec::new(),
    };
    let root = compute_deposits_root(&base_ctx);
    assert_ne!(root, [0u8; 32]);

    let zero_input_trade = sample_trade(0, 2_000_000_000_000_000_000, 0, 0);
    let empty_ctx = BatchContext {
        trades: vec![zero_input_trade],
        ..base_ctx
    };
    assert_eq!(compute_deposits_root(&empty_ctx), [0u8; 32]);
}

#[test]
fn deposits_root_matches_solidity_packing() {
    // Reference computed with ethers (mirrors ZstableRollup._depositsRoot) for the vector
    // noteCommitment=0x55*32, asset=0x22*20, amount=1000.
    let mut trade = sample_trade(1000, 1_000_000_000_000_000_000, 0, 0);
    trade.input_token = [0x22u8; 20];
    trade.deposit_commitment = [0x55u8; 32];
    let ctx = BatchContext {
        chain_id: 1,
        rollup_address: [0u8; 20],
        batch_number: 1,
        tee_batch_nonce: 1,
        withdrawals: Vec::new(),
        trades: vec![trade],
        oracle: Vec::new(),
    };
    let root = compute_deposits_root(&ctx);
    let expected =
        hex_literal_32("7d940611462495ba749bb1fe386f5f1f7a7682ae1cf9b87f31926b55e45396ed");
    assert_eq!(root, expected);
}

#[test]
fn batch_rejects_a_deposit_commitment_used_with_inconsistent_input_assets() {
    let sender = revm::primitives::Address::from([0x11u8; 20]);
    let provider = funded_provider(sender, 1_000_000_000_000_000_000);
    let old_commitment = keccak256(b"genesis");

    let mut trade_a = sample_trade(10_000_000_000_000_000_000, 2_000_000_000_000_000_000, 0, 0);
    trade_a.deposit_commitment = [0x66u8; 32];
    let mut trade_b = sample_trade(5_000_000_000_000_000_000, 2_000_000_000_000_000_000, 0, 0);
    trade_b.deposit_commitment = [0x66u8; 32];
    trade_b.input_token = [0x99u8; 20]; // different asset, same commitment -> inconsistent

    let mut ctx = default_ctx();
    ctx.trades.push(trade_a);
    ctx.trades.push(trade_b);

    let result = apply_batch(provider, &ctx, old_commitment, Vec::new());
    assert!(result.is_err(), "inconsistent deposit-commitment/asset pairing must be rejected");
}

fn sample_oracle_entry(
    token: [u8; 20],
    price: u128,
    base_spread_bps: u16,
    vol_coeff_bps: u16,
    skew_coeff_bps: u16,
    sigma_min_1e18: u64,
    sigma_max_1e18: u64,
) -> OraclePrice {
    OraclePrice {
        token,
        price: U256::from(price).to_be_bytes::<32>(),
        decimals: 18,
        base_spread_bps,
        vol_coeff_bps,
        skew_coeff_bps,
        sigma_min_1e18,
        sigma_max_1e18,
        utilization_1e18: 0,
        price_history: Vec::new(),
    }
}

#[test]
fn compute_sigma_cold_start_returns_sigma_max() {
    // No history at all, and a single price (no return computable) are both a cold start.
    assert_eq!(compute_sigma(&[], 1_000, 500_000_000_000_000_000), U256::from(500_000_000_000_000_000u128));
    let one = [U256::from(100u128).to_be_bytes::<32>()];
    assert_eq!(compute_sigma(&one, 1_000, 500_000_000_000_000_000), U256::from(500_000_000_000_000_000u128));
}

#[test]
fn compute_sigma_computes_mad_scaled_estimate_and_clamps() {
    // Prices 100 -> 101 -> 99 (1e18-scaled): returns are +1% then ~-1.9802%, MAD = mean(|r|).
    let p0 = U256::from(100_000_000_000_000_000_000u128).to_be_bytes::<32>();
    let p1 = U256::from(101_000_000_000_000_000_000u128).to_be_bytes::<32>();
    let p2 = U256::from(99_000_000_000_000_000_000u128).to_be_bytes::<32>();
    let history = [p0, p1, p2];

    // Unclamped: sigma should land between the two returns' magnitudes once scaled by sqrt(pi/2).
    let sigma = compute_sigma(&history, 0, u64::MAX);
    assert!(sigma > U256::from(10_000_000_000_000_000u128)); // > 1%
    assert!(sigma < U256::from(30_000_000_000_000_000u128)); // < 3%

    // A tight clamp above the computed value pins it to sigma_max.
    let clamped_high = compute_sigma(&history, 0, 1_000_000_000_000_000); // 0.1% ceiling
    assert_eq!(clamped_high, U256::from(1_000_000_000_000_000u128));

    // A floor above the computed value pins it to sigma_min.
    let clamped_low = compute_sigma(&history, 900_000_000_000_000_000, u64::MAX); // 90% floor
    assert_eq!(clamped_low, U256::from(900_000_000_000_000_000u128));
}

#[test]
fn compute_quoted_price_with_zero_params_equals_oracle_price_both_sides() {
    let oracle_price = U256::from(2_000_000_000_000_000_000u128);
    let zero = U256::ZERO;
    assert_eq!(compute_quoted_price(oracle_price, 0, 0, 0, 0, zero, zero), oracle_price);
    assert_eq!(compute_quoted_price(oracle_price, 1, 0, 0, 0, zero, zero), oracle_price);
}

#[test]
fn compute_quoted_price_base_spread_widens_against_the_trader() {
    let oracle_price = U256::from(1_000_000_000_000_000_000u128); // 1.0
    let zero = U256::ZERO;
    // 100 bps = 1%: buy pays 1.01, sell receives 0.99, both exact (no sigma/utilization involved).
    let buy = compute_quoted_price(oracle_price, 0, 100, 0, 0, zero, zero);
    let sell = compute_quoted_price(oracle_price, 1, 100, 0, 0, zero, zero);
    assert_eq!(buy, U256::from(1_010_000_000_000_000_000u128));
    assert_eq!(sell, U256::from(990_000_000_000_000_000u128));
}

#[test]
fn compute_quoted_price_vol_and_skew_terms_scale_the_spread() {
    let oracle_price = U256::from(1_000_000_000_000_000_000u128);
    let sigma = U256::from(20_000_000_000_000_000u128); // 2%
    let utilization = U256::from(500_000_000_000_000_000u128); // 50%
    // volCoeffBps=50 (0.5% per unit sigma) * sigma(2%) = 0.01% ; skewCoeffBps=200 (2% per unit
    // utilization) * utilization(50%) = 1%. Total extra spread = 1.01%, plus 0 base.
    let buy = compute_quoted_price(oracle_price, 0, 0, 50, 200, sigma, utilization);
    assert_eq!(buy, U256::from(1_010_100_000_000_000_000u128));
}

#[test]
fn verify_quoted_price_accepts_the_formula_price_and_rejects_an_operator_widened_one() {
    let sender = revm::primitives::Address::from([0x11u8; 20]);
    let stock = [0x33u8; 20];
    let oracle_price: u128 = 2_000_000_000_000_000_000;

    // baseSpreadBps=100 (1%): a buy at the CORRECT formula price (oracle * 1.01) must be accepted.
    let mut ctx = default_ctx();
    ctx.oracle.push(sample_oracle_entry(stock, oracle_price, 100, 0, 0, 0, 0));
    let correct_price: u128 = 2_020_000_000_000_000_000; // 2.0 * 1.01
    ctx.trades.push(Trade {
        account: [0x11u8; 20],
        input_token: [0x22u8; 20],
        input_amount: U256::from(1u128).to_be_bytes::<32>(),
        output_token: stock,
        price: U256::from(correct_price).to_be_bytes::<32>(),
        side: 0,
        secret: [0x44u8; 32],
        fee_bps: 0,
        deposit_commitment: [0u8; 32],
    });
    let provider = funded_provider(sender, 1_000_000_000_000_000_000);
    let old_commitment = keccak256(b"genesis");
    assert!(apply_batch(provider, &ctx, old_commitment, Vec::new()).is_ok());

    // The operator tries to widen the price beyond what the committed formula allows.
    let mut widened_ctx = ctx.clone();
    widened_ctx.trades[0].price = U256::from(correct_price + 1).to_be_bytes::<32>();
    let provider2 = funded_provider(sender, 1_000_000_000_000_000_000);
    let result = apply_batch(provider2, &widened_ctx, old_commitment, Vec::new());
    assert!(result.is_err(), "a price above the committed formula's result must be rejected");
}

#[test]
fn pricing_params_root_is_zero_for_empty_oracle() {
    assert_eq!(compute_pricing_params_root(&[]), [0u8; 32]);
}

#[test]
fn pricing_params_root_matches_solidity_packing() {
    // Reference computed with ethers (mirrors AssetRegistry.pricingParamsRoot) for the vector
    // token=0x22*20, baseSpreadBps=50, volCoeffBps=200, skewCoeffBps=100, sigmaMin=1e15,
    // sigmaMax=5e17. If this drifts, the guest's committed pricingParamsRoot would no longer
    // match the registry's on-chain recomputation.
    let entry = sample_oracle_entry(
        [0x22u8; 20],
        1_000_000_000_000_000_000,
        50,
        200,
        100,
        1_000_000_000_000_000,
        500_000_000_000_000_000,
    );
    let root = compute_pricing_params_root(&[entry]);
    let expected =
        hex_literal_32("2347fec9176fde85699054888ffd232b1e4386d739b7de31ae3450311e31adac");
    assert_eq!(root, expected);
}

#[test]
fn oracle_root_treats_empty_history_as_no_source_not_as_zero_samples() {
    // A statically-priced asset (no IPriceOracle set) has no history source and commits the ZERO
    // hash for it (see AssetRegistry.oracleRoot()'s static-ref branch) -- NOT keccak256(""), which
    // is what a naive "just hash whatever bytes are there" implementation would produce for an
    // empty Vec. This is the exact bug that would silently desync the guest from the contract for
    // every asset priced via the legacy static path.
    let mut entry = sample_oracle_entry([0x22u8; 20], 2_000_000_000_000_000_000, 0, 0, 0, 0, 0);
    entry.price_history = Vec::new();
    let root = compute_oracle_root(&[entry.clone()]);

    let naive_wrong = {
        let mut buf = Vec::new();
        buf.extend_from_slice(&entry.token);
        buf.extend_from_slice(&entry.price);
        buf.extend_from_slice(&compute_price_history_hash(&[])); // keccak256(""), NOT zero
        keccak256(&buf)
    };
    assert_ne!(root, naive_wrong, "an empty history must not hash as keccak256(\"\")");

    let mut expected_buf = Vec::new();
    expected_buf.extend_from_slice(&entry.token);
    expected_buf.extend_from_slice(&entry.price);
    expected_buf.extend_from_slice(&[0u8; 32]); // the zero hash, matching AssetRegistry's static branch
    assert_eq!(root, keccak256(&expected_buf));
}

#[test]
fn oracle_root_matches_solidity_packing_with_a_nonempty_price_history() {
    // Reference computed with ethers (mirrors AssetRegistry.oracleRoot with an oracle-backed
    // asset) for token=0x22*20, price=2e18, history=[1e18, 1.1e18].
    let mut entry = sample_oracle_entry([0x22u8; 20], 2_000_000_000_000_000_000, 0, 0, 0, 0, 0);
    entry.price_history = vec![
        U256::from(1_000_000_000_000_000_000u128).to_be_bytes::<32>(),
        U256::from(1_100_000_000_000_000_000u128).to_be_bytes::<32>(),
    ];
    let root = compute_oracle_root(&[entry]);
    let expected =
        hex_literal_32("09200973919d5df121fcff7ab3880a6f4b1daac785d2dffdba640fea6c0d3e1e");
    assert_eq!(root, expected);
}
