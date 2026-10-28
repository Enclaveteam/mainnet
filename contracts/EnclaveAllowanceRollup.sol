// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./ISP1Verifier.sol";
import "./EnclaveAllowancePublicValues.sol";
import "./EnclaveAllowanceRegistry.sol";
import "./IWithdrawalRollup.sol";

interface IEnclaveAllowanceVault {
    function consumeDeposit(bytes32 noteCommitment, address asset, uint256 amount) external;
    function payFee(address asset, uint256 amount) external;
}

/// @notice SP1-based settlement for Enclave Allowance: ONE proven deposit funds ONE registered target.
/// A separate, minimal stack from Trade, Invoice and Payroll — no REVM, no oracle, no LP accounting.
/// The proof binds the deposit to the funder's secret and to the target; on-chain, the target's
/// recipient, asset, cap and active flag are read LIVE from the registry, and the amounts, fee cap and
/// minimum are re-checked, so none of it rests on the proof alone — an enclave (even a compromised one)
/// cannot pay a recipient other than the one registered, exceed the cap, or fund an inactive target.
contract EnclaveAllowanceRollup is Ownable, IWithdrawalRollup {
    using EnclaveAllowancePublicValuesLib for bytes;

    /// Mirror of the guest's MAX_ALLOWANCE_FEE_BPS.
    uint16 public constant MAX_FEE_BPS = 200;

    struct WithdrawalIntent {
        address asset;
        uint256 amount;
        address recipient;
    }

    /// Same packing as the guest's withdrawals root: nullifier | asset | amount | recipient.
    struct WithdrawalEntry {
        bytes32 nullifier;
        address asset;
        uint256 amount;
        address recipient;
    }

    struct DepositConsumption {
        bytes32 noteCommitment;
        address asset;
        uint256 amount;
    }

    struct FeeEntry {
        address asset;
        uint256 amount;
    }

    ISP1Verifier public verifier;
    bytes32 public programVKey;
    uint64 public immutable expectedChainId;
    address public immutable expectedRollupAddress;
    EnclaveAllowanceRegistry public immutable registry;
    address public vault;

    mapping(bytes32 => WithdrawalIntent) public pendingWithdrawals;
    mapping(bytes32 => bool) private _spent;

    /// The per-funding receipt: public, but it names only the target and the recipient — never the funder.
    event AllowanceFunded(bytes32 indexed targetId, address indexed recipient, address asset, uint256 amount, uint256 fee, bytes32 nullifier);
    event VerifierUpdated(address verifier);
    event ProgramVKeyUpdated(bytes32 programVKey);
    event VaultSet(address vault);
    event WithdrawalQueued(bytes32 indexed nullifier, address asset, uint256 amount, address recipient);
    event WithdrawalConsumed(bytes32 indexed nullifier);

    constructor(
        address verifier_,
        bytes32 programVKey_,
        uint64 expectedChainId_,
        address expectedRollupAddress_,
        address registry_,
        address initialOwner
    ) Ownable(initialOwner) {
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        expectedChainId = expectedChainId_;
        expectedRollupAddress = expectedRollupAddress_;
        registry = EnclaveAllowanceRegistry(registry_);
    }

    function setVerifier(address verifier_) external onlyOwner {
        verifier = ISP1Verifier(verifier_);
        emit VerifierUpdated(verifier_);
    }

    function setProgramVKey(bytes32 programVKey_) external onlyOwner {
        programVKey = programVKey_;
        emit ProgramVKeyUpdated(programVKey_);
    }

    /// Wire the custody vault. Set once.
    function setVault(address vault_) external onlyOwner {
        require(vault == address(0), "vault already set");
        require(vault_ != address(0), "zero address");
        vault = vault_;
        emit VaultSet(vault_);
    }

    function isSpent(bytes32 nullifier) external view returns (bool) {
        return _spent[nullifier];
    }

    /// Verifies the proof, then checks the funding against the target's live on-chain terms, queues the
    /// recipient's withdrawal, consumes the funding deposit and pays the fee. Anyone may submit.
    function settleBatch(
        bytes calldata publicValues,
        WithdrawalEntry calldata w,
        DepositConsumption calldata depositUsed,
        FeeEntry calldata fee,
        bytes calldata proofBytes
    ) external {
        require(vault != address(0), "vault not set");

        verifier.verifyProof(programVKey, publicValues, proofBytes);

        EnclaveAllowancePublicValues memory pv = publicValues.decode();
        require(pv.chainId == expectedChainId, "chain mismatch");
        require(pv.rollupAddress == expectedRollupAddress, "rollup mismatch");
        require(keccak256(abi.encodePacked(w.nullifier, w.asset, w.amount, w.recipient)) == pv.withdrawalsRoot, "withdrawal mismatch");
        require(keccak256(abi.encodePacked(depositUsed.noteCommitment, depositUsed.asset, depositUsed.amount)) == pv.depositsRoot, "deposit mismatch");
        require(keccak256(abi.encodePacked(fee.asset, fee.amount)) == pv.feesRoot, "fee mismatch");

        // The target's terms come from the registry, never from the proof or the submitter.
        (, address recipient, address asset, uint256 cap, bool active) = registry.targets(pv.targetId);
        require(recipient != address(0), "no such target");
        require(active, "target inactive");
        require(w.recipient == recipient, "recipient mismatch");
        require(w.asset == asset && depositUsed.asset == asset && fee.asset == asset, "asset mismatch");
        require(w.amount >= registry.MIN_FUNDING(), "funding below minimum");
        require(cap == 0 || w.amount <= cap, "funding above cap");

        // Defense in depth on the money, so it does not rest on the proof alone.
        require(pv.feeBps <= MAX_FEE_BPS, "fee above cap");
        require(fee.amount == (w.amount * pv.feeBps) / 10_000, "fee != amount * feeBps");
        require(w.amount + fee.amount == depositUsed.amount, "amount + fee != deposit");

        require(!_spent[w.nullifier], "already spent");
        _spent[w.nullifier] = true;
        pendingWithdrawals[w.nullifier] = WithdrawalIntent(w.asset, w.amount, w.recipient);
        emit WithdrawalQueued(w.nullifier, w.asset, w.amount, w.recipient);

        IEnclaveAllowanceVault(vault).consumeDeposit(depositUsed.noteCommitment, depositUsed.asset, depositUsed.amount);
        IEnclaveAllowanceVault(vault).payFee(fee.asset, fee.amount);

        emit AllowanceFunded(pv.targetId, w.recipient, w.asset, w.amount, fee.amount, w.nullifier);
    }

    /// Releases a proven withdrawal to the vault (single-use). Only the wired vault may call.
    function consumeWithdrawal(bytes32 nullifier)
        external
        returns (address asset, uint256 amount, address recipient)
    {
        require(msg.sender == vault, "not vault");
        WithdrawalIntent memory intent = pendingWithdrawals[nullifier];
        require(intent.recipient != address(0), "no pending withdrawal");
        delete pendingWithdrawals[nullifier];
        emit WithdrawalConsumed(nullifier);
        return (intent.asset, intent.amount, intent.recipient);
    }
}
