//! Shared REVM batch execution: the TEE worker runs this natively for the fast/private path,
//! and the SP1 guest program runs the identical code to produce a validity proof of the same
//! execution. Both must produce byte-identical [`executor::PublicValues`] for the same inputs.

pub mod commitment;
pub mod executor;
pub mod overlay;
pub mod state_provider;

pub use commitment::{keccak256, state_commitment, Hash};
pub use executor::{
    apply_batch, apply_batch_stateful, apply_batch_with_overlay, compute_deposit_entries,
    compute_deposits_root, compute_fee_entries, compute_fees_root, compute_oracle_root,
    compute_price_history_hash, compute_pricing_params_root, compute_quoted_price, compute_sigma,
    compute_trade_fee, compute_trade_net_output, compute_trade_output, compute_withdrawals_root,
    derive_withdrawals, BatchContext, BatchError, OraclePrice, PublicValues, Trade, TxOutcome,
    Withdrawal, MAX_FEE_BPS,
};
pub use overlay::{OverlayDb, OverlayState};
pub use state_provider::{MockChainStateProvider, VerifiedChainStateProvider};
