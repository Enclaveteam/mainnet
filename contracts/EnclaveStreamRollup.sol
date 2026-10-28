// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./ISP1Verifier.sol";
import "./EnclaveStreamPublicValues.sol";
import "./IWithdrawalRollup.sol";

interface IEnclaveStreamVault {
    function consumePartial(bytes32 noteCommitment, address asset, uint256 amount) external;
    function isOpen(bytes32 noteCommitment) external view returns (bool);
}

/// @notice SP1-based settlement for Enclave Stream. The schedule, the parties and the payout addresses never
/// appear on-chain: a proof opens them inside the enclave and discloses only the note commitment, the step, and
/// two timestamps. A proof cannot know the time or what was claimed before, so THIS contract keeps that state and
/// enforces it: per commitment it stores how far the recipient has claimed (`claimedUntil`), whether and when the
/// sender revoked (`revokedAt`) and whether the unvested rest was refunded.
///
///   claim    kind 1   claimedUntil == fromTime, toTime <= now, and toTime <= revokedAt once revoked
///   revoke   kind 2   the sender's key on a revocable stream: records `revokedAt` (the vested part stays claimable)
///   refund   kind 3   after a revocation: the unvested rest goes back to the sender, once
contract EnclaveStreamRollup is Ownable, IWithdrawalRollup {
    using EnclaveStreamPublicValuesLib for bytes;

    uint8 public constant KIND_CLAIM = 1;
    uint8 public constant KIND_REVOKE = 2;
    uint8 public constant KIND_REFUND = 3;

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

    ISP1Verifier public verifier;
    bytes32 public programVKey;
    uint64 public immutable expectedChainId;
    address public immutable expectedRollupAddress;
    address public vault;

    mapping(bytes32 => WithdrawalIntent) public pendingWithdrawals;
    mapping(bytes32 => bool) private _spent;
    /// noteCommitment -> the time the recipient has claimed up to (0 = nothing claimed yet).
    mapping(bytes32 => uint64) public claimedUntil;
    /// noteCommitment -> when the sender revoked (0 = never).
    mapping(bytes32 => uint64) public revokedAt;
    mapping(bytes32 => bool) public refunded;

    /// Receipts: public, and they name no party and no schedule.
    event StreamClaimed(bytes32 indexed nullifier, address indexed recipient, address asset, uint256 amount);
    event StreamRefunded(bytes32 indexed nullifier, address indexed recipient, address asset, uint256 amount);
    event StreamRevoked(bytes32 indexed noteCommitment);
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

    /// A claim (kind 1) or the refund of the unvested rest (kind 3): verifies the proof, checks the chain-side
    /// state, queues the payout, spends that part of the deposit. Anyone may submit.
    function settleBatch(
        bytes calldata publicValues,
        WithdrawalEntry calldata w,
        DepositConsumption calldata depositUsed,
        bytes calldata proofBytes
    ) external {
        require(vault != address(0), "vault not set");

        verifier.verifyProof(programVKey, publicValues, proofBytes);

        EnclaveStreamPublicValues memory pv = publicValues.decode();
        require(pv.chainId == expectedChainId, "chain mismatch");
        require(pv.rollupAddress == expectedRollupAddress, "rollup mismatch");
        require(pv.kind == KIND_CLAIM || pv.kind == KIND_REFUND, "not a payout");
        require(keccak256(abi.encodePacked(w.nullifier, w.asset, w.amount, w.recipient)) == pv.withdrawalsRoot, "withdrawal mismatch");
        require(keccak256(abi.encodePacked(depositUsed.noteCommitment, depositUsed.asset, depositUsed.amount)) == pv.depositsRoot, "deposit mismatch");
        require(depositUsed.noteCommitment == pv.noteCommitment, "commitment mismatch");
        require(w.asset == depositUsed.asset && w.amount == depositUsed.amount && w.amount > 0, "amount mismatch");
        require(w.recipient != address(0), "zero recipient");

        bytes32 c = pv.noteCommitment;
        if (pv.kind == KIND_CLAIM) {
            require(claimedUntil[c] == pv.fromTime, "claim does not continue from the last one");
            require(pv.toTime > pv.fromTime, "empty period");
            require(pv.toTime <= block.timestamp, "not vested yet");
            uint64 rev = revokedAt[c];
            require(rev == 0 || pv.toTime <= rev, "stream was revoked earlier");
            claimedUntil[c] = pv.toTime;
        } else {
            require(pv.fromTime == 0, "bad refund");
            require(revokedAt[c] != 0 && pv.toTime == revokedAt[c], "not revoked at that time");
            require(!refunded[c], "already refunded");
            refunded[c] = true;
        }

        require(!_spent[w.nullifier], "already spent");
        _spent[w.nullifier] = true;
        pendingWithdrawals[w.nullifier] = WithdrawalIntent(w.asset, w.amount, w.recipient);
        emit WithdrawalQueued(w.nullifier, w.asset, w.amount, w.recipient);

        IEnclaveStreamVault(vault).consumePartial(c, depositUsed.asset, depositUsed.amount);

        if (pv.kind == KIND_CLAIM) emit StreamClaimed(w.nullifier, w.recipient, w.asset, w.amount);
        else emit StreamRefunded(w.nullifier, w.recipient, w.asset, w.amount);
    }

    /// Records that the sender revoked a (revocable) stream. From now on the recipient can claim only what vested
    /// up to this block, and the sender can take the unvested rest back with a refund proof.
    function recordRevoke(bytes calldata publicValues, bytes calldata proofBytes) external {
        require(vault != address(0), "vault not set");

        verifier.verifyProof(programVKey, publicValues, proofBytes);

        EnclaveStreamPublicValues memory pv = publicValues.decode();
        require(pv.chainId == expectedChainId, "chain mismatch");
        require(pv.rollupAddress == expectedRollupAddress, "rollup mismatch");
        require(pv.kind == KIND_REVOKE, "not a revocation");
        require(IEnclaveStreamVault(vault).isOpen(pv.noteCommitment), "no open deposit");
        require(revokedAt[pv.noteCommitment] == 0, "already revoked");
        revokedAt[pv.noteCommitment] = uint64(block.timestamp);
        emit StreamRevoked(pv.noteCommitment);
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
