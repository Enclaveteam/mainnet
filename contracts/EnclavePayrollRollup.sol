// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./ISP1Verifier.sol";
import "./EnclavePayrollPublicValues.sol";
import "./IWithdrawalRollup.sol";

interface IEnclavePayrollVault {
    function consumeDeposit(bytes32 noteCommitment, address asset, uint256 amount) external;
    function payFee(address asset, uint256 amount) external;
}

/// @notice SP1-based settlement for Enclave Payroll: ONE proven deposit pays a whole recipient list.
/// A separate, minimal stack from the Trade and Invoice contracts — no REVM, no oracle, no LP
/// accounting; the deposit consumed always equals recipients' total plus fee, so the vault never
/// pays out of anyone else's funds. The proof binds the deposit to the employer's secret and to
/// this exact list; on-chain, the sums, fee cap, single-asset rule and payroll id are re-checked so
/// they do not rest on the proof alone.
contract EnclavePayrollRollup is Ownable, IWithdrawalRollup {
    using EnclavePayrollPublicValuesLib for bytes;

    /// Keeps one settlement (a nullifier write and two events per recipient) inside block gas.
    uint256 public constant MAX_RECIPIENTS = 50;
    /// Mirror of the guest's MAX_PAYROLL_FEE_BPS.
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
    address public vault;

    mapping(bytes32 => WithdrawalIntent) public pendingWithdrawals;
    mapping(bytes32 => bool) private _spent;
    /// A payroll id (asset + salt + fee + ordered list) settles at most once.
    mapping(bytes32 => bool) public payrollSettled;

    /// One per settled payroll. `salt` + `feeBps` + the `PayrollPaid` events of the same
    /// transaction are everything needed to recompute `payrollId` publicly.
    event PayrollSettled(
        bytes32 indexed payrollId,
        address indexed asset,
        bytes32 salt,
        uint16 feeBps,
        uint256 recipientCount,
        uint256 total,
        uint256 fee
    );
    /// The per-recipient receipt.
    event PayrollPaid(bytes32 indexed payrollId, uint256 index, address indexed recipient, uint256 amount);
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
        address initialOwner
    ) Ownable(initialOwner) {
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        expectedChainId = expectedChainId_;
        expectedRollupAddress = expectedRollupAddress_;
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

    /// Verifies the proof, then queues every recipient's withdrawal, consumes the single funding
    /// deposit and pays the fee. Anyone may submit; nothing is trusted from the submitter beyond a
    /// valid proof of the committed roots.
    function settleBatch(
        bytes calldata publicValues,
        WithdrawalEntry[] calldata withdrawals,
        DepositConsumption calldata depositUsed,
        FeeEntry calldata fee,
        bytes calldata proofBytes
    ) external {
        require(vault != address(0), "vault not set");
        require(withdrawals.length > 0 && withdrawals.length <= MAX_RECIPIENTS, "bad recipient count");

        verifier.verifyProof(programVKey, publicValues, proofBytes);

        EnclavePayrollPublicValues memory pv = publicValues.decode();
        require(pv.chainId == expectedChainId, "chain mismatch");
        require(pv.rollupAddress == expectedRollupAddress, "rollup mismatch");
        require(_withdrawalsRoot(withdrawals) == pv.withdrawalsRoot, "withdrawals mismatch");
        require(keccak256(abi.encodePacked(depositUsed.noteCommitment, depositUsed.asset, depositUsed.amount)) == pv.depositsRoot, "deposit mismatch");
        require(keccak256(abi.encodePacked(fee.asset, fee.amount)) == pv.feesRoot, "fee mismatch");

        // Defense in depth: re-derive the payroll id from the disclosed list, and re-check the money.
        require(_payrollId(depositUsed.asset, pv.salt, pv.feeBps, withdrawals) == pv.payrollId, "payroll id mismatch");
        require(!payrollSettled[pv.payrollId], "payroll already settled");
        require(pv.feeBps <= MAX_FEE_BPS, "fee above cap");
        require(fee.asset == depositUsed.asset, "fee/deposit asset mismatch");

        uint256 total;
        for (uint256 i = 0; i < withdrawals.length; i++) {
            WithdrawalEntry calldata w = withdrawals[i];
            require(w.asset == depositUsed.asset, "mixed assets");
            require(w.amount > 0, "zero amount");
            require(w.recipient != address(0), "zero recipient");
            total += w.amount;
        }
        require(fee.amount == (total * pv.feeBps) / 10_000, "fee != total * feeBps");
        require(total + fee.amount == depositUsed.amount, "withdrawals + fee != deposit");

        payrollSettled[pv.payrollId] = true;
        for (uint256 i = 0; i < withdrawals.length; i++) {
            WithdrawalEntry calldata w = withdrawals[i];
            require(!_spent[w.nullifier], "already spent");
            _spent[w.nullifier] = true;
            pendingWithdrawals[w.nullifier] = WithdrawalIntent(w.asset, w.amount, w.recipient);
            emit WithdrawalQueued(w.nullifier, w.asset, w.amount, w.recipient);
            emit PayrollPaid(pv.payrollId, i, w.recipient, w.amount);
        }

        IEnclavePayrollVault(vault).consumeDeposit(depositUsed.noteCommitment, depositUsed.asset, depositUsed.amount);
        IEnclavePayrollVault(vault).payFee(fee.asset, fee.amount);

        emit PayrollSettled(pv.payrollId, depositUsed.asset, pv.salt, pv.feeBps, withdrawals.length, total, fee.amount);
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

    /// keccak("enclave-payroll-id-v1" | asset | salt | feeBps(uint16) | N x (recipient | amount)),
    /// exactly the guest's `payroll_id`.
    function _payrollId(address asset, bytes32 salt, uint16 feeBps, WithdrawalEntry[] calldata withdrawals)
        internal
        pure
        returns (bytes32)
    {
        bytes memory buf = abi.encodePacked("enclave-payroll-id-v1", asset, salt, feeBps);
        for (uint256 i = 0; i < withdrawals.length; i++) {
            buf = abi.encodePacked(buf, withdrawals[i].recipient, withdrawals[i].amount);
        }
        return keccak256(buf);
    }

    function _withdrawalsRoot(WithdrawalEntry[] calldata withdrawals) internal pure returns (bytes32) {
        bytes memory buf;
        for (uint256 i = 0; i < withdrawals.length; i++) {
            WithdrawalEntry calldata w = withdrawals[i];
            buf = abi.encodePacked(buf, w.nullifier, w.asset, w.amount, w.recipient);
        }
        return keccak256(buf);
    }
}
