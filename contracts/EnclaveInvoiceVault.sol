// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./AssetRegistry.sol";
import "./IWithdrawalRollup.sol";

/// @notice Minimal escrow custody for fixed-amount invoice payments — deliberately much smaller
/// than Vault.sol: no LP shares, no redemptions, no rebalancing, no oracle. Every invoice payment
/// is a 1:1 passthrough (a payer's deposit funds only that same payment's own withdrawal), so this
/// vault never holds or risks pooled capital and needs no solvency accounting beyond the deposit
/// ledger itself.
contract EnclaveInvoiceVault is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    AssetRegistry public immutable assetRegistry;
    IWithdrawalRollup public immutable rollup;

    /// Where the (optional, lower-than-trade) invoice fee is forwarded at settlement time. No
    /// pooled LP value here to credit fees into, so they are paid out directly instead.
    address public feeRecipient;

    /// Same forced-exit safety net as Vault.sol: a depositor can always recover an un-consumed
    /// deposit after this delay, with no rollup/enclave/admin action required.
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
        feeRecipient = feeRecipient_;
        emit FeeRecipientSet(feeRecipient_);
    }

    function deposit(address asset, uint256 amount, bytes32 noteCommitment) external nonReentrant {
        require(assetRegistry.isSupported(asset), "asset not supported");
        require(amount > 0, "amount=0");
        require(deposits[noteCommitment].asset == address(0), "commitment already used");
        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
        deposits[noteCommitment] = DepositRecord(asset, msg.sender, amount, uint64(block.timestamp));
        emit DepositQueued(msg.sender, asset, amount, noteCommitment);
    }

    /// Called by the Rollup during `settleBatch`. Ties the invoice payment's input to a real,
    /// unspent on-chain deposit — reverts if the deposit does not have that much `remaining`.
    function consumeDeposit(bytes32 noteCommitment, address asset, uint256 amount) external {
        require(msg.sender == address(rollup), "not rollup");
        DepositRecord storage rec = deposits[noteCommitment];
        require(rec.asset == asset, "asset mismatch");
        require(rec.remaining >= amount, "insufficient deposit");
        rec.remaining -= amount;
        emit DepositConsumed(noteCommitment, asset, amount);
    }

    /// Recovers whatever is left of a deposit directly to its original depositor once
    /// `FORCED_EXIT_DELAY` has passed — e.g. an invoice that never got paid/proven. No rollup,
    /// enclave, or admin action of any kind is involved.
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

    function withdraw(bytes32 nullifier) external nonReentrant {
        (address asset, uint256 amount, address recipient) = rollup.consumeWithdrawal(nullifier);
        IERC20(asset).safeTransfer(recipient, amount);
        emit Withdrawn(nullifier, asset, amount, recipient);
    }

    /// Called by the Rollup during `settleBatch`, once per disclosed invoice fee. Forwards the fee
    /// straight to `feeRecipient` (no pooled LP value here to credit it into). A no-op if
    /// `feeRecipient` is unset, so an owner can disable fees entirely by leaving it at address(0)
    /// (funds then simply stay in the vault instead of reverting the whole batch).
    function payFee(address asset, uint256 amount) external nonReentrant {
        require(msg.sender == address(rollup), "not rollup");
        if (amount == 0 || feeRecipient == address(0)) return;
        IERC20(asset).safeTransfer(feeRecipient, amount);
        emit FeePaid(asset, amount, feeRecipient);
    }
}
