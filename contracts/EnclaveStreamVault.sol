// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./AssetRegistry.sol";
import "./IWithdrawalRollup.sol";

/// @notice Custody for Enclave Stream. There is no registry of streams and no party is named on-chain: a stream is
/// one deposit under a note commitment, keccak("enclave-stream-deposit-v1" | secret | termsHash), where the terms
/// (the parties' key hashes, the vesting schedule, whether it can be revoked) stay off-chain and are only ever
/// opened inside the enclave and the zero-knowledge proof.
///
/// Unlike the single-payout vaults, the deposit is spent in several parts: `consumePartial` is called by the
/// rollup once per claim (and once for a revocation refund). The sender has NO unilateral exit while the stream can
/// still be running: `exit` opens only at `exitAfter`, chosen at deposit time and checked by the recipient against
/// the schedule before it relies on the stream.
///
/// The fee is taken ONCE, at deposit, on top of the principal and paid straight to the fee recipient, so no
/// fee-rate has to match anything in the enclave and a later change of the rate never touches a live stream.
contract EnclaveStreamVault is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    AssetRegistry public immutable assetRegistry;
    IWithdrawalRollup public immutable rollup;

    /// Receives the fee of every deposit. `deposit` reverts while it is unset and the fee is not zero.
    address public feeRecipient;
    /// Fee in basis points of the principal, charged on top of it at deposit. Owner-set, capped.
    uint16 public feeBps;
    uint16 public constant MAX_FEE_BPS = 200;

    uint64 public constant MIN_EXIT_DELAY = 3 days;
    /// Long enough for multi-year vesting plus the claim window; short enough that a typo cannot lock funds for decades.
    uint64 public constant MAX_EXIT_DELAY = 2190 days;

    struct DepositRecord {
        address asset;
        address depositor;
        uint256 remaining;
        uint64 exitAfter;
    }

    mapping(bytes32 => DepositRecord) public deposits;

    event DepositQueued(address indexed depositor, address indexed asset, uint256 amount, uint256 fee, bytes32 noteCommitment, uint64 exitAfter);
    event DepositConsumed(bytes32 indexed noteCommitment, address indexed asset, uint256 amount);
    event Exited(bytes32 indexed noteCommitment, address indexed depositor, address indexed asset, uint256 amount);
    event Withdrawn(bytes32 indexed nullifier, address indexed asset, uint256 amount, address indexed recipient);
    event FeeRecipientSet(address feeRecipient);
    event FeeBpsSet(uint16 feeBps);
    event FeePaid(address indexed asset, uint256 amount, address indexed feeRecipient);

    constructor(address assetRegistry_, address rollup_, uint16 feeBps_, address initialOwner) Ownable(initialOwner) {
        require(feeBps_ <= MAX_FEE_BPS, "fee above cap");
        assetRegistry = AssetRegistry(assetRegistry_);
        rollup = IWithdrawalRollup(rollup_);
        feeBps = feeBps_;
    }

    function setFeeRecipient(address feeRecipient_) external onlyOwner {
        require(feeRecipient_ != address(0), "zero address");
        feeRecipient = feeRecipient_;
        emit FeeRecipientSet(feeRecipient_);
    }

    /// Applies to NEW deposits only; a stream already funded keeps what it paid.
    function setFeeBps(uint16 feeBps_) external onlyOwner {
        require(feeBps_ <= MAX_FEE_BPS, "fee above cap");
        feeBps = feeBps_;
        emit FeeBpsSet(feeBps_);
    }

    /// True while the deposit exists and still holds something.
    function isOpen(bytes32 noteCommitment) external view returns (bool) {
        return deposits[noteCommitment].remaining > 0;
    }

    /// The amount a depositor must have approved for `principal`: the principal plus the fee.
    function totalFor(uint256 principal) public view returns (uint256) {
        return principal + (principal * feeBps) / 10_000;
    }

    /// `noteCommitment` MUST be keccak("enclave-stream-deposit-v1" | secret | termsHash): the guest refuses to act
    /// on a deposit under any other commitment. `principal` is what the stream vests; the fee is added on top.
    /// The depositor cannot take the deposit back before `exitAfter`; the recipient checks this value on-chain,
    /// together with the amount, before relying on the stream.
    function deposit(address asset, uint256 principal, bytes32 noteCommitment, uint64 exitAfter) external nonReentrant {
        require(assetRegistry.isSupported(asset), "asset not supported");
        require(principal > 0, "amount=0");
        require(noteCommitment != bytes32(0), "zero commitment");
        require(deposits[noteCommitment].asset == address(0), "commitment already used");
        require(exitAfter >= block.timestamp + MIN_EXIT_DELAY, "exit too early");
        require(exitAfter <= block.timestamp + MAX_EXIT_DELAY, "exit too late");
        uint256 fee = (principal * feeBps) / 10_000;
        if (fee > 0) require(feeRecipient != address(0), "fee recipient not set");
        deposits[noteCommitment] = DepositRecord(asset, msg.sender, principal, exitAfter);
        IERC20(asset).safeTransferFrom(msg.sender, address(this), principal + fee);
        if (fee > 0) {
            IERC20(asset).safeTransfer(feeRecipient, fee);
            emit FeePaid(asset, fee, feeRecipient);
        }
        emit DepositQueued(msg.sender, asset, principal, fee, noteCommitment, exitAfter);
    }

    /// Spends part of the deposit (a claim, or the refund of the unvested rest after a revocation).
    function consumePartial(bytes32 noteCommitment, address asset, uint256 amount) external {
        require(msg.sender == address(rollup), "not rollup");
        DepositRecord storage rec = deposits[noteCommitment];
        require(rec.asset == asset, "asset mismatch");
        require(amount > 0 && rec.remaining >= amount, "insufficient deposit");
        rec.remaining -= amount;
        emit DepositConsumed(noteCommitment, asset, amount);
    }

    /// The depositor takes what is left back, but only from `exitAfter` on. There is no earlier exit.
    function exit(bytes32 noteCommitment) external nonReentrant {
        DepositRecord storage rec = deposits[noteCommitment];
        require(rec.asset != address(0), "no such deposit");
        require(msg.sender == rec.depositor, "not depositor");
        require(block.timestamp >= rec.exitAfter, "too early");
        uint256 amount = rec.remaining;
        require(amount > 0, "nothing left");
        rec.remaining = 0;
        IERC20(rec.asset).safeTransfer(msg.sender, amount);
        emit Exited(noteCommitment, msg.sender, rec.asset, amount);
    }

    /// Permissionless: pays the proven recipient, so a relayer (not the sender or the recipient) can submit it.
    function withdraw(bytes32 nullifier) external nonReentrant {
        (address asset, uint256 amount, address recipient) = rollup.consumeWithdrawal(nullifier);
        IERC20(asset).safeTransfer(recipient, amount);
        emit Withdrawn(nullifier, asset, amount, recipient);
    }
}
