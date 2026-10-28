// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./AssetRegistry.sol";
import "./IWithdrawalRollup.sol";

/// @notice Custody for Enclave Allowance: a funder makes one deposit per funding under a note
/// commitment, and a proven settlement consumes it to pay the target's recipient. Pure passthrough (no
/// LP accounting) with a depositor-only 7-day forced exit. Separate stack: nothing here touches the
/// Trade, Invoice or Payroll contracts.
contract EnclaveAllowanceVault is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    AssetRegistry public immutable assetRegistry;
    IWithdrawalRollup public immutable rollup;

    /// Receives each funding's fee at settlement. `payFee` reverts while it is unset, so a funding can
    /// never settle with its fee stranded in the vault.
    address public feeRecipient;

    /// Fixed (not owner-settable), so no admin key can extend it to grief a user trying to exit.
    uint64 public constant FORCED_EXIT_DELAY = 7 days;

    struct DepositRecord {
        address asset;
        address depositor;
        uint256 remaining;
        uint64 depositedAt;
    }

    mapping(bytes32 => DepositRecord) public deposits;

    event DepositQueued(address indexed depositor, address indexed asset, uint256 amount, bytes32 noteCommitment);
    event DepositConsumed(bytes32 indexed noteCommitment, address indexed asset, uint256 amount);
    event ForcedExit(bytes32 indexed noteCommitment, address indexed depositor, address indexed asset, uint256 amount);
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

    /// `noteCommitment` MUST be keccak("enclave-allowance-deposit-v1" | secret | targetId): the guest
    /// refuses to spend a deposit under any other commitment, so a wrongly formed one is only
    /// recoverable through `forceExit`.
    function deposit(address asset, uint256 amount, bytes32 noteCommitment) external nonReentrant {
        require(assetRegistry.isSupported(asset), "asset not supported");
        require(amount > 0, "amount=0");
        require(deposits[noteCommitment].asset == address(0), "commitment already used");
        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
        deposits[noteCommitment] = DepositRecord(asset, msg.sender, amount, uint64(block.timestamp));
        emit DepositQueued(msg.sender, asset, amount, noteCommitment);
    }

    function consumeDeposit(bytes32 noteCommitment, address asset, uint256 amount) external {
        require(msg.sender == address(rollup), "not rollup");
        DepositRecord storage rec = deposits[noteCommitment];
        require(rec.asset == asset, "asset mismatch");
        require(rec.remaining >= amount, "insufficient deposit");
        rec.remaining -= amount;
        emit DepositConsumed(noteCommitment, asset, amount);
    }

    function forceExit(bytes32 noteCommitment) external nonReentrant {
        DepositRecord storage rec = deposits[noteCommitment];
        require(rec.asset != address(0), "no such deposit");
        require(msg.sender == rec.depositor, "not depositor");
        require(block.timestamp >= rec.depositedAt + FORCED_EXIT_DELAY, "too early");
        uint256 amount = rec.remaining;
        require(amount > 0, "nothing left");
        address asset = rec.asset;
        rec.remaining = 0;
        IERC20(asset).safeTransfer(msg.sender, amount);
        emit ForcedExit(noteCommitment, msg.sender, asset, amount);
    }

    /// Permissionless: pays the proven recipient, so a relayer (not the funder or the recipient) can
    /// submit it without linking anyone on-chain.
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
