// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./AssetRegistry.sol";
import "./IWithdrawalRollup.sol";

/// @notice Custody for Enclave Escrow. There is no registry of escrows and no party is ever named on-chain:
/// an escrow is just a deposit under a note commitment, keccak("enclave-escrow-deposit-v1" | secret |
/// termsHash), where the terms (parties' key hashes, payout addresses, deadlines, arbiter) stay off-chain
/// and are only ever opened inside the enclave and the zero-knowledge proof.
///
/// The buyer has NO unilateral exit while the deal can still be running: `exit` opens only at `exitAfter`,
/// chosen at deposit time and checked by the seller against the deal's deadlines before delivering. Until
/// then the deposit can only leave through a proven settlement in `EnclaveEscrowRollup`, to the payout
/// address the terms name. Pure passthrough (no LP accounting). Separate stack: nothing here touches Trade,
/// Invoice, Payroll or Allowance.
contract EnclaveEscrowVault is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    AssetRegistry public immutable assetRegistry;
    IWithdrawalRollup public immutable rollup;

    /// Receives each escrow's fee at settlement. `payFee` reverts while it is unset, so a settlement can
    /// never leave its fee stranded in the vault.
    address public feeRecipient;

    /// The earliest `exitAfter` a deposit may choose, counted from the deposit. Fixed, not owner-settable.
    uint64 public constant MIN_EXIT_DELAY = 3 days;
    /// The latest `exitAfter` a deposit may choose, so a typo cannot lock funds for years.
    uint64 public constant MAX_EXIT_DELAY = 400 days;

    struct DepositRecord {
        address asset;
        address depositor;
        uint256 remaining;
        uint64 exitAfter;
    }

    mapping(bytes32 => DepositRecord) public deposits;

    event DepositQueued(address indexed depositor, address indexed asset, uint256 amount, bytes32 noteCommitment, uint64 exitAfter);
    event DepositConsumed(bytes32 indexed noteCommitment, address indexed asset, uint256 amount);
    event Exited(bytes32 indexed noteCommitment, address indexed depositor, address indexed asset, uint256 amount);
    event Withdrawn(bytes32 indexed nullifier, address indexed asset, uint256 amount, address indexed recipient);
    event FeeRecipientSet(address feeRecipient);
    event FeePaid(address indexed asset, uint256 amount, address indexed feeRecipient);

    constructor(address assetRegistry_, address rollup_, address initialOwner) Ownable(initialOwner) {
        assetRegistry = AssetRegistry(assetRegistry_);
        rollup = IWithdrawalRollup(rollup_);
    }

    function setFeeRecipient(address feeRecipient_) external onlyOwner {
        require(feeRecipient_ != address(0), "zero address");
        feeRecipient = feeRecipient_;
        emit FeeRecipientSet(feeRecipient_);
    }

    /// True while the deposit exists and has not been consumed or exited.
    function isOpen(bytes32 noteCommitment) external view returns (bool) {
        return deposits[noteCommitment].remaining > 0;
    }

    /// `noteCommitment` MUST be keccak("enclave-escrow-deposit-v1" | secret | termsHash): the guest refuses
    /// to act on a deposit under any other commitment. `amount` is the escrow amount plus the fee. The
    /// buyer cannot take the deposit back before `exitAfter`; the seller checks this value on-chain, together
    /// with the amount, before delivering.
    function deposit(address asset, uint256 amount, bytes32 noteCommitment, uint64 exitAfter) external nonReentrant {
        require(assetRegistry.isSupported(asset), "asset not supported");
        require(amount > 0, "amount=0");
        require(noteCommitment != bytes32(0), "zero commitment");
        require(deposits[noteCommitment].asset == address(0), "commitment already used");
        require(exitAfter >= block.timestamp + MIN_EXIT_DELAY, "exit too early");
        require(exitAfter <= block.timestamp + MAX_EXIT_DELAY, "exit too late");
        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
        deposits[noteCommitment] = DepositRecord(asset, msg.sender, amount, exitAfter);
        emit DepositQueued(msg.sender, asset, amount, noteCommitment, exitAfter);
    }

    /// Consumes the WHOLE deposit (amount + fee) of a settled escrow.
    function consumeDeposit(bytes32 noteCommitment, address asset, uint256 amount) external {
        require(msg.sender == address(rollup), "not rollup");
        DepositRecord storage rec = deposits[noteCommitment];
        require(rec.asset == asset, "asset mismatch");
        require(amount > 0 && rec.remaining == amount, "deposit mismatch");
        rec.remaining = 0;
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

    /// Permissionless: pays the proven recipient, so a relayer (not the buyer or the seller) can submit it.
    function withdraw(bytes32 nullifier) external nonReentrant {
        (address asset, uint256 amount, address recipient) = rollup.consumeWithdrawal(nullifier);
        IERC20(asset).safeTransfer(recipient, amount);
        emit Withdrawn(nullifier, asset, amount, recipient);
    }

    function payFee(address asset, uint256 amount) external nonReentrant {
        require(msg.sender == address(rollup), "not rollup");
        if (amount == 0) return;
        require(feeRecipient != address(0), "fee recipient not set");
        IERC20(asset).safeTransfer(feeRecipient, amount);
        emit FeePaid(asset, amount, feeRecipient);
    }
}
