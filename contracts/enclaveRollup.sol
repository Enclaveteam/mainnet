// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./ISP1Verifier.sol";
import "./ZstablePublicValues.sol";
import "./StakingGate.sol";
import "./NullifierRegistry.sol";
import "./IWithdrawalRollup.sol";

/// @notice SP1-based settlement for the Zstable rollup (Option A: TEE for speed, ZK for finality).
///
/// The TEE fast-path executes a batch and returns public values; an SP1 proof of that same REVM
/// execution is generated asynchronously and settled here. This contract verifies the SP1 proof,
/// decodes the committed public values, and — only if the proof is valid and chains correctly onto
/// the current state — advances the settled state commitment. It is the on-chain "ZK for finality"
/// half; nothing is trusted from the submitter beyond a valid proof.
/// Minimal view into the on-chain price oracle (AssetRegistry) the guest checks trades against.
interface IAssetOracle {
    function oracleRoot() external view returns (bytes32);
    function pricingParamsRoot() external view returns (bytes32);
}

/// Callback into the vault's per-asset LP credit-line accounting (see Vault.sol). Lets the vault
/// track claims it has already authorized so LP redemptions cannot spend the same funds.
interface IVaultTraderClaims {
    function reserveTraderClaim(address asset, uint256 amount) external;
}

/// Callback that makes the vault a pure pass-through: for each trade it converts the deposited
/// input into exactly the withdrawal output via its rebalancer, atomically, BEFORE the withdrawal
/// can be released (see Vault.rebalanceTrade), so the vault never holds a directional position.
interface IVaultRebalance {
    function rebalanceTrade(
        address inputAsset,
        address outputAsset,
        uint256 inputAmount,
        uint256 withdrawalAmount,
        uint256 feeAmount
    ) external;
}

/// Callback into the vault's per-deposit ledger (see Vault.sol). Ties a batch's trade inputs to
/// real, unspent on-chain deposits — the sequencer cannot authorize a trade whose input was never
/// actually deposited.
interface IVaultDeposits {
    function consumeDeposit(bytes32 noteCommitment, address asset, uint256 amount) external;
}

contract ZstableRollup is Ownable, IWithdrawalRollup {
    using ZstablePublicValuesLib for bytes;

    /// A proven withdrawal awaiting release by the vault.
    struct WithdrawalIntent {
        address stockToken;
        uint256 amount;
        address recipient;
    }

    /// One withdrawal a settled batch authorizes; the batch's proof commits to the list via
    /// `withdrawalsRoot`, so the sequencer cannot inject or alter entries.
    struct WithdrawalEntry {
        bytes32 nullifier;
        address stockToken;
        uint256 amount;
        address recipient;
    }

    /// Total fee retained for LPs in one output asset this batch. It is bound to `feesRoot` and
    /// physically acquired by the vault in addition to the net trader withdrawal.
    struct FeeEntry {
        address asset;
        uint256 amount;
    }

    /// Total amount of one on-chain deposit (identified by its `noteCommitment`) that this batch's
    /// trades consumed as input. The proof commits to this via `depositsRoot`, so the sequencer
    /// cannot claim a trade was funded beyond what a real deposit actually has `remaining`.
    struct DepositConsumption {
        bytes32 noteCommitment;
        address asset;
        uint256 amount;
    }

    ISP1Verifier public verifier;
    /// Verifying key of the pinned SP1 guest program; only proofs of that exact program are accepted.
    bytes32 public programVKey;

    /// Chain id and rollup identity the guest must have committed to (binds proofs to this rollup).
    uint64 public immutable expectedChainId;
    address public immutable expectedRollupAddress;

    /// Optional staking gate; if set, only eligible sequencers may settle. address(0) disables it.
    StakingGate public stakingGate;

    /// Spent-nullifier tracker; this rollup must be its authorized writer (via setRollup).
    NullifierRegistry public immutable nullifierRegistry;

    /// On-chain price oracle; settlement binds the proof's oracleRoot to this so trades stay private.
    IAssetOracle public immutable assetOracle;

    /// Custody contract allowed to consume proven withdrawals.
    address public vault;

    /// Withdrawals proven by settled batches, awaiting release by the vault (single-use per nullifier).
    mapping(bytes32 => WithdrawalIntent) public pendingWithdrawals;

    /// Latest settled state commitment and batch number.
    bytes32 public stateCommitment;
    uint64 public batchNumber;

    event BatchSettled(
        uint64 indexed batchNumber,
        bytes32 oldStateCommitment,
        bytes32 newStateCommitment,
        bytes32 txCommitment,
        uint32 txCount
    );
    event VerifierUpdated(address verifier);
    event ProgramVKeyUpdated(bytes32 programVKey);
    event StakingGateUpdated(address stakingGate);
    event VaultSet(address vault);
    event WithdrawalQueued(bytes32 indexed nullifier, address stockToken, uint256 amount, address recipient);
    event WithdrawalConsumed(bytes32 indexed nullifier);
    event FeeAccrued(uint64 indexed batchNumber, address indexed asset, uint256 amount);

    constructor(
        address verifier_,
        bytes32 programVKey_,
        uint64 expectedChainId_,
        address expectedRollupAddress_,
        bytes32 genesisStateCommitment,
        address stakingGate_,
        address nullifierRegistry_,
        address assetRegistry_,
        address initialOwner
    ) Ownable(initialOwner) {
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        expectedChainId = expectedChainId_;
        expectedRollupAddress = expectedRollupAddress_;
        stateCommitment = genesisStateCommitment;
        stakingGate = StakingGate(stakingGate_);
        nullifierRegistry = NullifierRegistry(nullifierRegistry_);
        assetOracle = IAssetOracle(assetRegistry_);
    }

    function setVerifier(address verifier_) external onlyOwner {
        verifier = ISP1Verifier(verifier_);
        emit VerifierUpdated(verifier_);
    }

    /// Pin the SP1 guest verifying key. Only settable by the owner (e.g. after a program upgrade).
    function setProgramVKey(bytes32 programVKey_) external onlyOwner {
        programVKey = programVKey_;
        emit ProgramVKeyUpdated(programVKey_);
    }

    function setStakingGate(address stakingGate_) external onlyOwner {
        stakingGate = StakingGate(stakingGate_);
        emit StakingGateUpdated(stakingGate_);
    }

    /// Wire the custody vault allowed to consume proven withdrawals. Set once.
    function setVault(address vault_) external onlyOwner {
        require(vault == address(0), "vault already set");
        require(vault_ != address(0), "zero address");
        vault = vault_;
        emit VaultSet(vault_);
    }

    /// Verifies an SP1 proof of a batch's REVM execution and, if it chains onto the current state,
    /// advances the settled commitment and queues the withdrawals the proof authorized. Reverts
    /// (via the verifier) on an invalid proof. `fees` discloses, per output asset, the total fee
    /// retained this batch (see `FeeEntry`). Each total is physically included in one matching
    /// output-asset rebalance and remains unreserved in the vault for that asset's LPs.
    /// `deposits` discloses, per on-chain deposit, how much of it this batch's trades consumed as
    /// input (see `DepositConsumption`); bound to `pv.depositsRoot` and applied via
    /// `Vault.consumeDeposit`, which reverts if a deposit does not have that much `remaining`.
    function settleBatch(
        bytes calldata publicValues,
        WithdrawalEntry[] calldata withdrawals,
        FeeEntry[] calldata fees,
        DepositConsumption[] calldata deposits,
        bytes calldata proofBytes
    ) external {
        if (address(stakingGate) != address(0)) {
            require(stakingGate.isEligible(msg.sender), "sequencer not staked");
        }

        // Reverts if the proof is not a valid proof of `programVKey` over these public values.
        verifier.verifyProof(programVKey, publicValues, proofBytes);

        ZstablePublicValues memory pv = publicValues.decode();
        require(pv.chainId == expectedChainId, "chain mismatch");
        require(pv.rollupAddress == expectedRollupAddress, "rollup mismatch");
        require(pv.oldStateCommitment == stateCommitment, "stale batch");
        require(pv.batchNumber == batchNumber + 1, "wrong batch number");
        // Bind the withdrawal list to the proof: the sequencer cannot add/alter withdrawals.
        require(_withdrawalsRoot(withdrawals) == pv.withdrawalsRoot, "withdrawals mismatch");
        // Bind the prices to the on-chain oracle: the guest verified every trade against exactly
        // this table IN-ZK, so trades never need to be revealed on-chain to trust their prices.
        require(pv.oracleRoot == assetOracle.oracleRoot(), "oracle mismatch");
        // Bind the pricing formula parameters (spread/vol/skew) the guest used to the live,
        // governance-set values: the sequencer cannot settle a batch priced against a formula
        // different from the one AssetRegistry currently commits to.
        require(pv.pricingParamsRoot == assetOracle.pricingParamsRoot(), "pricing params mismatch");
        // Bind the disclosed fee breakdown to the proof, same pattern as withdrawals: the guest
        // committed the total fee retained per output asset, so the sequencer cannot under/over
        // report it here.
        require(_feesRoot(fees) == pv.feesRoot, "fees mismatch");
        // Bind the disclosed deposit consumption to the proof: the guest committed exactly how
        // much of each real deposit its trades' inputs drew from, so the sequencer cannot
        // authorize a trade whose input was never actually deposited.
        require(_depositsRoot(deposits) == pv.depositsRoot, "deposits mismatch");

        stateCommitment = pv.newStateCommitment;
        batchNumber = pv.batchNumber;

        // Consume deposits BEFORE reserving withdrawals: this frees each input asset's principal as
        // spendable liquidity in THIS same transaction, so the auto-rebalance a withdrawal's
        // `reserveTraderClaim` may trigger prefers the batch's own just-freed capital over reaching
        // for the external rebalancer.
        for (uint256 i = 0; i < deposits.length; i++) {
            DepositConsumption calldata d = deposits[i];
            if (vault != address(0)) {
                // Reverts if `d.noteCommitment` doesn't exist, is the wrong asset, or lacks enough
                // `remaining` — the whole batch fails to settle rather than partially applying.
                IVaultDeposits(vault).consumeDeposit(d.noteCommitment, d.asset, d.amount);
            }
        }

        bool[] memory feeApplied = new bool[](fees.length);
        for (uint256 i = 0; i < withdrawals.length; i++) {
            WithdrawalEntry calldata w = withdrawals[i];
            nullifierRegistry.markSpent(w.nullifier); // reverts on double-spend
            pendingWithdrawals[w.nullifier] = WithdrawalIntent(w.stockToken, w.amount, w.recipient);
            if (vault != address(0)) {
                // Acquire the output from the deposited input FIRST (paired 1:1 with this batch's
                // deposits, as the blind sequencer emits them), so the payout is fully backed before
                // the withdrawal can ever be released; then mirror the reservation. A trade with no
                // paired deposit passes address(0) -> rebalanceTrade is a no-op for it.
                address inputAsset = i < deposits.length ? deposits[i].asset : address(0);
                uint256 inputAmount = i < deposits.length ? deposits[i].amount : 0;
                uint256 feeAmount;
                for (uint256 j = 0; j < fees.length; j++) {
                    if (!feeApplied[j] && fees[j].asset == w.stockToken) {
                        feeAmount = fees[j].amount;
                        feeApplied[j] = true;
                        break;
                    }
                }
                require(feeAmount == 0 || inputAsset != address(0), "fee has no paired input");
                IVaultRebalance(vault).rebalanceTrade(inputAsset, w.stockToken, inputAmount, w.amount, feeAmount);
                IVaultTraderClaims(vault).reserveTraderClaim(w.stockToken, w.amount);
            }
            emit WithdrawalQueued(w.nullifier, w.stockToken, w.amount, w.recipient);
        }

        for (uint256 i = 0; i < fees.length; i++) {
            require(vault == address(0) || feeApplied[i], "fee has no matching withdrawal");
            emit FeeAccrued(pv.batchNumber, fees[i].asset, fees[i].amount);
        }

        emit BatchSettled(
            pv.batchNumber,
            pv.oldStateCommitment,
            pv.newStateCommitment,
            pv.txCommitment,
            pv.txCount
        );
    }

    /// Releases a proven withdrawal to the vault (single-use). Only the wired vault may call.
    function consumeWithdrawal(bytes32 nullifier)
        external
        returns (address stockToken, uint256 amount, address recipient)
    {
        require(msg.sender == vault, "not vault");
        WithdrawalIntent memory intent = pendingWithdrawals[nullifier];
        require(intent.recipient != address(0), "no pending withdrawal");
        delete pendingWithdrawals[nullifier];
        emit WithdrawalConsumed(nullifier);
        return (intent.stockToken, intent.amount, intent.recipient);
    }

    /// Recompute the withdrawals commitment exactly as the guest does off-chain: keccak256 over each
    /// entry packed as nullifier(32)|stockToken(20)|amount(32)|recipient(20), in list order. Empty
    /// list commits to the zero hash.
    function _withdrawalsRoot(WithdrawalEntry[] calldata withdrawals) internal pure returns (bytes32) {
        if (withdrawals.length == 0) return bytes32(0);
        bytes memory buf;
        for (uint256 i = 0; i < withdrawals.length; i++) {
            WithdrawalEntry calldata w = withdrawals[i];
            buf = abi.encodePacked(buf, w.nullifier, w.stockToken, w.amount, w.recipient);
        }
        return keccak256(buf);
    }

    /// Recompute the fees commitment exactly as the executor's `compute_fees_root` does off-chain:
    /// keccak256 over each entry packed as asset(20)|amount(32), in list order (the guest sorts by
    /// asset address ascending; the caller must supply entries in that same order). Empty list
    /// commits to the zero hash.
    function _feesRoot(FeeEntry[] calldata fees) internal pure returns (bytes32) {
        if (fees.length == 0) return bytes32(0);
        bytes memory buf;
        for (uint256 i = 0; i < fees.length; i++) {
            FeeEntry calldata f = fees[i];
            buf = abi.encodePacked(buf, f.asset, f.amount);
        }
        return keccak256(buf);
    }

    /// Recompute the deposits commitment exactly as the executor's `compute_deposits_root` does
    /// off-chain: keccak256 over each entry packed as noteCommitment(32)|asset(20)|amount(32), in
    /// list order (the guest sorts by commitment ascending; the caller must supply the same order).
    /// Empty list commits to the zero hash.
    function _depositsRoot(DepositConsumption[] calldata deposits) internal pure returns (bytes32) {
        if (deposits.length == 0) return bytes32(0);
        bytes memory buf;
        for (uint256 i = 0; i < deposits.length; i++) {
            DepositConsumption calldata d = deposits[i];
            buf = abi.encodePacked(buf, d.noteCommitment, d.asset, d.amount);
        }
        return keccak256(buf);
    }
}
