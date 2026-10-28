// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./AssetRegistry.sol";

/// @notice Standalone registry of fixed-amount payment requests ("invoices"), isolated from the
/// Trade system (no Vault/Rollup dependency injection — same isolation principle as ComplianceLog).
/// A merchant creates an invoice on-chain; a payer settles it 1:1 through EnclaveInvoiceRollup,
/// which is the only address ever allowed to call `markPaid` (see `setRollup`).
contract EnclaveInvoiceRegistry is Ownable {
    struct Invoice {
        address asset;
        uint256 amount;
        address recipient;
        uint64 expiry; // 0 = no expiry
        bool paid;
    }

    AssetRegistry public immutable assetRegistry;

    /// The only settlement contract allowed to call `markPaid`. Set once, like NullifierRegistry.setRollup.
    address public rollup;

    mapping(bytes32 => Invoice) public invoices;
    uint256 private _nonce;

    event RollupSet(address rollup);
    event InvoiceCreated(
        bytes32 indexed invoiceId,
        address indexed asset,
        uint256 amount,
        address indexed recipient,
        uint64 expiry
    );
    event InvoicePaid(bytes32 indexed invoiceId);

    constructor(address assetRegistry_, address initialOwner) Ownable(initialOwner) {
        assetRegistry = AssetRegistry(assetRegistry_);
    }

    function setRollup(address rollup_) external onlyOwner {
        require(rollup == address(0), "rollup already set");
        require(rollup_ != address(0), "zero address");
        rollup = rollup_;
        emit RollupSet(rollup_);
    }

    /// Permissionless: any address may create an invoice payable to itself. `recipient` is always
    /// `msg.sender` — an invoice can never redirect payout to an address the creator does not
    /// control, removing an entire class of foot-gun/scam invoice.
    function createInvoice(address asset, uint256 amount, uint64 expiry) external returns (bytes32 invoiceId) {
        require(assetRegistry.isSupported(asset), "asset not supported");
        require(amount > 0, "amount=0");
        require(expiry == 0 || expiry > block.timestamp, "expiry in the past");

        invoiceId = keccak256(abi.encodePacked(msg.sender, asset, amount, expiry, _nonce++));
        invoices[invoiceId] = Invoice(asset, amount, msg.sender, expiry, false);
        emit InvoiceCreated(invoiceId, asset, amount, msg.sender, expiry);
    }

    function isPaid(bytes32 invoiceId) external view returns (bool) {
        return invoices[invoiceId].paid;
    }

    /// Called by EnclaveInvoiceRollup during `settleBatch`, once per proven invoice payment. Reverts
    /// if the invoice does not exist, was already paid, or has expired — the whole batch fails to
    /// settle rather than silently skipping a bad entry.
    function markPaid(bytes32 invoiceId) external {
        require(msg.sender == rollup, "not rollup");
        Invoice storage inv = invoices[invoiceId];
        require(inv.recipient != address(0), "no such invoice");
        require(!inv.paid, "already paid");
        require(inv.expiry == 0 || block.timestamp <= inv.expiry, "invoice expired");
        inv.paid = true;
        emit InvoicePaid(invoiceId);
    }
}
