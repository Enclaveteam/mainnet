// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./ISP1Verifier.sol";
import "./EnclaveEscrowPublicValues.sol";
import "./IWithdrawalRollup.sol";

interface IEnclaveEscrowVault {
    function consumeDeposit(bytes32 noteCommitment, address asset, uint256 amount) external;
    function payFee(address asset, uint256 amount) external;
    function isOpen(bytes32 noteCommitment) external view returns (bool);
}

/// @notice SP1-based settlement for Enclave Escrow. The deal (parties, payout addresses, deadlines, arbiter)
/// never appears on-chain: a proof opens it inside the enclave and discloses only the note commitment it
/// acts on, the step taken, and the time / dispute gates to check against the chain, which this contract
/// does here (a proof cannot know the time or whether a dispute was filed). A compromised enclave still
/// cannot pay more than the deposit, pay twice, release before a deadline, or rule without a dispute.
///
/// Steps (the guest decides which role may take which; this contract enforces the chain-side conditions):
///   release / refund        gate 0   the buyer / the seller says so
///   autoRelease             gate 1   after the release deadline, and only if never disputed
///   ruleSeller / ruleBuyer  gate 2   the arbiter rules on a disputed escrow
///   autoRefund              gate 3   the arbiter never ruled within the dispute timeout
///   dispute                 recordDispute, before the release deadline
contract EnclaveEscrowRollup is Ownable, IWithdrawalRollup {
    using EnclaveEscrowPublicValuesLib for bytes;

    /// Mirror of the guest's MAX_ESCROW_FEE_BPS.
    uint16 public constant MAX_FEE_BPS = 200;
    uint8 public constant KIND_PAYOUT = 1;
    uint8 public constant KIND_DISPUTE = 2;
    uint8 public constant GATE_NONE = 0;
    uint8 public constant GATE_NOT_DISPUTED = 1;
    uint8 public constant GATE_DISPUTED = 2;
    uint8 public constant GATE_DISPUTE_TIMEOUT = 3;

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
    /// Fee rate the enclave charges, on top of the escrow amount. Must equal the enclave's ESCROW_FEE_BPS.
    uint16 public feeBps;

    mapping(bytes32 => WithdrawalIntent) public pendingWithdrawals;
    mapping(bytes32 => bool) private _spent;
    /// noteCommitment -> when a dispute was recorded (0 = never disputed).
    mapping(bytes32 => uint64) public disputedAt;

    /// Receipts: public, and they name no party and no deal.
    event EscrowPaidOut(bytes32 indexed nullifier, address indexed recipient, address asset, uint256 amount, uint256 fee);
    event EscrowDisputed(bytes32 indexed noteCommitment);
    event VerifierUpdated(address verifier);
    event ProgramVKeyUpdated(bytes32 programVKey);
    event FeeBpsSet(uint16 feeBps);
    event VaultSet(address vault);
    event WithdrawalQueued(bytes32 indexed nullifier, address asset, uint256 amount, address recipient);
    event WithdrawalConsumed(bytes32 indexed nullifier);

    constructor(
        address verifier_,
        bytes32 programVKey_,
        uint64 expectedChainId_,
        address expectedRollupAddress_,
        uint16 feeBps_,
        address initialOwner
    ) Ownable(initialOwner) {
        require(feeBps_ <= MAX_FEE_BPS, "fee above cap");
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        expectedChainId = expectedChainId_;
        expectedRollupAddress = expectedRollupAddress_;
        feeBps = feeBps_;
    }

    function setVerifier(address verifier_) external onlyOwner {
        verifier = ISP1Verifier(verifier_);
        emit VerifierUpdated(verifier_);
    }

    function setProgramVKey(bytes32 programVKey_) external onlyOwner {
        programVKey = programVKey_;
        emit ProgramVKeyUpdated(programVKey_);
    }

    /// Must equal the enclave's ESCROW_FEE_BPS: the enclave refuses any order with another rate.
    function setFeeBps(uint16 feeBps_) external onlyOwner {
        require(feeBps_ <= MAX_FEE_BPS, "fee above cap");
        feeBps = feeBps_;
        emit FeeBpsSet(feeBps_);
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

    /// Verifies the proof, checks the chain-side gates, queues the payout withdrawal, consumes the escrow's
    /// deposit and pays the fee. Anyone may submit.
    function settleBatch(
        bytes calldata publicValues,
        WithdrawalEntry calldata w,
        DepositConsumption calldata depositUsed,
        FeeEntry calldata fee,
        bytes calldata proofBytes
    ) external {
        require(vault != address(0), "vault not set");

        verifier.verifyProof(programVKey, publicValues, proofBytes);

        EnclaveEscrowPublicValues memory pv = publicValues.decode();
        require(pv.chainId == expectedChainId, "chain mismatch");
        require(pv.rollupAddress == expectedRollupAddress, "rollup mismatch");
        require(pv.kind == KIND_PAYOUT, "not a payout");
        require(keccak256(abi.encodePacked(w.nullifier, w.asset, w.amount, w.recipient)) == pv.withdrawalsRoot, "withdrawal mismatch");
        require(keccak256(abi.encodePacked(depositUsed.noteCommitment, depositUsed.asset, depositUsed.amount)) == pv.depositsRoot, "deposit mismatch");
        require(keccak256(abi.encodePacked(fee.asset, fee.amount)) == pv.feesRoot, "fee mismatch");
        require(depositUsed.noteCommitment == pv.noteCommitment, "commitment mismatch");

        _checkGates(pv);

        // Defense in depth on the money, so it does not rest on the proof alone.
        require(w.asset == depositUsed.asset && fee.asset == depositUsed.asset, "asset mismatch");
        require(pv.feeBps <= MAX_FEE_BPS, "fee above cap");
        require(pv.feeBps == feeBps, "fee rate mismatch");
        require(fee.amount == (w.amount * pv.feeBps) / 10_000, "fee != amount * feeBps");
        require(w.amount + fee.amount == depositUsed.amount, "amount + fee != deposit");

        require(!_spent[w.nullifier], "already spent");
        _spent[w.nullifier] = true;
        pendingWithdrawals[w.nullifier] = WithdrawalIntent(w.asset, w.amount, w.recipient);
        emit WithdrawalQueued(w.nullifier, w.asset, w.amount, w.recipient);

        IEnclaveEscrowVault(vault).consumeDeposit(depositUsed.noteCommitment, depositUsed.asset, depositUsed.amount);
        IEnclaveEscrowVault(vault).payFee(fee.asset, fee.amount);

        emit EscrowPaidOut(w.nullifier, w.recipient, w.asset, w.amount, fee.amount);
    }

    /// Records that a party disputed the escrow before its release deadline. The proof shows a buyer or a
    /// seller key was presented for a deal that has an arbiter, without saying which one.
    function recordDispute(bytes calldata publicValues, bytes calldata proofBytes) external {
        require(vault != address(0), "vault not set");

        verifier.verifyProof(programVKey, publicValues, proofBytes);

        EnclaveEscrowPublicValues memory pv = publicValues.decode();
        require(pv.chainId == expectedChainId, "chain mismatch");
        require(pv.rollupAddress == expectedRollupAddress, "rollup mismatch");
        require(pv.kind == KIND_DISPUTE, "not a dispute");
        require(pv.notAfter != 0 && block.timestamp < pv.notAfter, "deadline passed");
        require(IEnclaveEscrowVault(vault).isOpen(pv.noteCommitment), "no open deposit");
        require(disputedAt[pv.noteCommitment] == 0, "already disputed");
        disputedAt[pv.noteCommitment] = uint64(block.timestamp);
        emit EscrowDisputed(pv.noteCommitment);
    }

    function _checkGates(EnclaveEscrowPublicValues memory pv) internal view {
        require(block.timestamp >= pv.notBefore, "too early");
        require(pv.notAfter == 0 || block.timestamp < pv.notAfter, "too late");
        uint64 at = disputedAt[pv.noteCommitment];
        if (pv.gate == GATE_NONE) {
            return;
        } else if (pv.gate == GATE_NOT_DISPUTED) {
            require(at == 0, "disputed");
        } else if (pv.gate == GATE_DISPUTED) {
            require(at != 0, "not disputed");
        } else if (pv.gate == GATE_DISPUTE_TIMEOUT) {
            require(at != 0, "not disputed");
            require(block.timestamp >= uint256(at) + pv.disputeTimeout, "dispute timeout not reached");
        } else {
            revert("bad gate");
        }
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
