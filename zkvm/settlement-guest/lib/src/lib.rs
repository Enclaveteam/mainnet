use alloy_sol_types::sol;
use revm::context::TxEnv;
use serde::{Deserialize, Serialize};
use zstable_settlement_executor::{
    apply_batch_with_overlay, BatchContext, MockChainStateProvider, OverlayState, PublicValues,
};

sol! {
    /// Solidity-ABI mirror of `zstable_settlement_executor::PublicValues`. `Rollup.sol` will decode
    /// this from the SP1 proof's public values and check it against on-chain state before
    /// finalizing a batch.
    struct PublicValuesStruct {
        uint64 chainId;
        address rollupAddress;
        uint64 batchNumber;
        uint64 teeBatchNonce;
        bytes32 oldStateCommitment;
        bytes32 newStateCommitment;
        bytes32 txCommitment;
        bytes32 withdrawalsRoot;
        bytes32 oracleRoot;
        bytes32 feesRoot;
        bytes32 depositsRoot;
        bytes32 pricingParamsRoot;
        uint32 txCount;
    }
}

/// Everything the guest program needs to reproduce a batch's REVM execution.
///
/// `provider` is the mock, verifies-nothing chain-state stand-in (see
/// `zstable_settlement_executor::state_provider`) until the real Helios-anchored light-client bridge
/// exists — the guest proves whatever `provider` claims, so a real deployment must not use this.
#[derive(Serialize, Deserialize)]
pub struct BatchWitness {
    pub ctx: BatchContext,
    pub overlay: OverlayState,
    pub txs: Vec<TxEnv>,
    pub provider: MockChainStateProvider,
}

/// Runs the shared REVM batch executor and returns its public values, ready to be committed via
/// `sp1_zkvm::io::commit_slice`. The TEE worker's fast-path receipt must commit to the same
/// [`PublicValues`] fields using the same encoding so the two paths stay comparable.
pub fn run_batch(witness: BatchWitness) -> PublicValues {
    let (_outcomes, public_values, _new_overlay) = apply_batch_with_overlay(
        witness.provider,
        witness.overlay,
        &witness.ctx,
        witness.txs,
    )
    .expect("batch must be valid");
    public_values
}

pub fn encode_public_values(pv: &PublicValues) -> Vec<u8> {
    use alloy_sol_types::SolType;
    let encoded = PublicValuesStruct {
        chainId: pv.chain_id,
        rollupAddress: pv.rollup_address.into(),
        batchNumber: pv.batch_number,
        teeBatchNonce: pv.tee_batch_nonce,
        oldStateCommitment: pv.old_state_commitment.into(),
        newStateCommitment: pv.new_state_commitment.into(),
        txCommitment: pv.tx_commitment.into(),
        withdrawalsRoot: pv.withdrawals_root.into(),
        oracleRoot: pv.oracle_root.into(),
        feesRoot: pv.fees_root.into(),
        depositsRoot: pv.deposits_root.into(),
        pricingParamsRoot: pv.pricing_params_root.into(),
        txCount: pv.tx_count,
    };
    PublicValuesStruct::abi_encode(&encoded)
}
