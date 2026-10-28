// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./ISP1Verifier.sol";
import "./EnclaveInvoicePublicValues.sol";
import "./EnclaveInvoiceRegistry.sol";
import "./IWithdrawalRollup.sol";

/// Callback into the invoice vault's deposit ledger (see EnclaveInvoiceVault.sol). Ties a batch's
/// invoice payment to a real, unspent on-chain deposit — mirrors IVaultDeposits from ZstableRollup.
interface IEnclaveInvoiceVaultDeposits {
    function consumeDeposit(bytes32 noteCommitment, address asset, uint256 amount) external;
}

/// Callback that immediately forwards a batch's disclosed invoice fee to the vault's configured
/// fee recipient. Unlike Trade fees (which stay in the Vault as LP-credited value), an invoice fee
/// has no LP pool to credit, so it is paid out directly at settlement time.
interface IEnclaveInvoiceVaultFee {
    function payFee(address asset, uint256 amount) external;
}

/// @notice SP1-based settlement for fixed-amount invoice payments — a separate, minimal stack from
/// ZstableRollup/Vault so the Trade system's already-audited, production contracts are never
/// touched by this feature. No REVM re-execution, no oracle, no LP/liquidity accounting: every
/// invoice payment is a 1:1 passthrough (deposit funds its own withdrawal), so nothing here ever
/// draws on pooled capital.
contract EnclaveInvoiceRollup is Ownable, IWithdrawalRollup {
    using EnclaveInvoicePublicValuesLib for bytes;

    struct WithdrawalIntent {
        address asset;
        uint256 amount;
        address recipient;
    }

    /// One withdrawal a settled batch authorizes; bound to `withdrawalsRoot` (same packing as
    /// ZstableRollup.WithdrawalEntry, field-for-field).
    struct WithdrawalEntry {
        bytes32 nullifier;
        address asset;
        uint256 amount;
        address recipient;
    }

    /// Real on-chain deposit this batch's invoice payment consumed as input (same shape/packing as
    /// ZstableRollup.DepositConsumption).
    struct DepositConsumption {
        bytes32 noteCommitment;
        address asset;
        uint256 amount;
    }

    /// One proven invoice payment. Bound to `invoicesRoot` AND cross-checked live against
    /// `invoiceRegistry`'s current on-chain state — an enclave (even if compromised) cannot
    /// authorize a payout to a recipient/amount other than what the invoice actually specifies.
    struct InvoicePayment {
        bytes32 invoiceId;
        address asset;
        uint256 amount;
        address recipient;
    }

    /// Fee retained on one invoice payment, paired by index with `invoicePayments`. Bound to
    /// `feesRoot` and physically forwarded to the vault's fee recipient at settlement time.
    struct FeeEntry {
        address asset;
        uint256 amount;
    }

    ISP1Verifier public verifier;
    bytes32 public programVKey;

    uint64 public immutable expectedChainId;
    address public immutable expectedRollupAddress;

    /// Isolated nullifier domain: this rollup is the sole writer of its own spent-set, so an
    /// invoice-derived nullifier can never collide with (or be confused for) a Trade nullifier.
    mapping(bytes32 => bool) private _spent;

    EnclaveInvoiceRegistry public immutable invoiceRegistry;

    address public vault;

    mapping(bytes32 => WithdrawalIntent) public pendingWithdrawals;

    event BatchSettled(bytes32 withdrawalsRoot, bytes32 depositsRoot, bytes32 invoicesRoot);
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
        address invoiceRegistry_,
        address initialOwner
    ) Ownable(initialOwner) {
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        expectedChainId = expectedChainId_;
        expectedRollupAddress = expectedRollupAddress_;
        invoiceRegistry = EnclaveInvoiceRegistry(invoiceRegistry_);
    }

    function setVerifier(address verifier_) external onlyOwner {
        verifier = ISP1Verifier(verifier_);
        emit VerifierUpdated(verifier_);
    }

    function setProgramVKey(bytes32 programVKey_) external onlyOwner {
        programVKey = programVKey_;
        emit ProgramVKeyUpdated(programVKey_);
    }

    function setVault(address vault_) external onlyOwner {
        require(vault == address(0), "vault already set");
        require(vault_ != address(0), "zero address");
        vault = vault_;
        emit VaultSet(vault_);
    }

    function isSpent(bytes32 nullifier) external view returns (bool) {
        return _spent[nullifier];
    }

    /// Verifies an SP1 proof that a batch's deposits fund its withdrawals 1:1, each matching a real
    /// on-chain invoice, then queues the withdrawals and marks the invoices paid. `withdrawals`,
    /// `deposits` and `invoicePayments` are paired by index (entry i's deposit funds entry i's
    /// invoice, released via entry i's withdrawal) — same pairing convention as ZstableRollup.
    function settleBatch(
        bytes calldata publicValues,
        WithdrawalEntry[] calldata withdrawals,
        DepositConsumption[] calldata deposits,
        InvoicePayment[] calldata invoicePayments,
        FeeEntry[] calldata fees,
        bytes calldata proofBytes
    ) external {
        require(withdrawals.length == invoicePayments.length, "withdrawals/invoices length mismatch");
        require(deposits.length == invoicePayments.length, "deposits/invoices length mismatch");
        require(fees.length == invoicePayments.length, "fees/invoices length mismatch");

        // Reverts if the proof is not a valid proof of `programVKey` over these public values.
        verifier.verifyProof(programVKey, publicValues, proofBytes);

        EnclaveInvoicePublicValues memory pv = publicValues.decode();
        require(pv.chainId == expectedChainId, "chain mismatch");
        require(pv.rollupAddress == expectedRollupAddress, "rollup mismatch");
        require(_withdrawalsRoot(withdrawals) == pv.withdrawalsRoot, "withdrawals mismatch");
        require(_depositsRoot(deposits) == pv.depositsRoot, "deposits mismatch");
        require(_invoicesRoot(invoicePayments) == pv.invoicesRoot, "invoices mismatch");
        require(_feesRoot(fees) == pv.feesRoot, "fees mismatch");

        // Live cross-check against the REAL on-chain invoice state (not just internal consistency
        // between the proof and calldata): a stale, already-paid, expired, or tampered invoice is
        // rejected here even if the proof itself was validly generated against old/wrong data.
        for (uint256 i = 0; i < invoicePayments.length; i++) {
            _settleInvoicePayment(invoicePayments[i], withdrawals[i], fees[i]);
        }

        for (uint256 i = 0; i < deposits.length; i++) {
            DepositConsumption calldata d = deposits[i];
            if (vault != address(0)) {
                IEnclaveInvoiceVaultDeposits(vault).consumeDeposit(d.noteCommitment, d.asset, d.amount);
            }
        }

        for (uint256 i = 0; i < fees.length; i++) {
            FeeEntry calldata f = fees[i];
            if (vault != address(0) && f.amount > 0) {
                IEnclaveInvoiceVaultFee(vault).payFee(f.asset, f.amount);
            }
        }

        for (uint256 i = 0; i < withdrawals.length; i++) {
            WithdrawalEntry calldata w = withdrawals[i];
            require(!_spent[w.nullifier], "already spent");
            _spent[w.nullifier] = true;
            pendingWithdrawals[w.nullifier] = WithdrawalIntent(w.asset, w.amount, w.recipient);
            emit WithdrawalQueued(w.nullifier, w.asset, w.amount, w.recipient);
        }

        emit BatchSettled(pv.withdrawalsRoot, pv.depositsRoot, pv.invoicesRoot);
    }

    /// Split out of settleBatch purely to stay under the EVM stack limit. Validates one invoice
    /// payment against live on-chain state AND against its paired withdrawal/fee, then marks it paid.
    /// `withdrawal.amount + fee.amount` must equal the invoice's full (gross) amount: the recipient
    /// gets the net, the fee recipient gets the rest — the sequencer cannot under/over-report either.
    function _settleInvoicePayment(InvoicePayment calldata p, WithdrawalEntry calldata w, FeeEntry calldata f) internal {
        (address asset, uint256 amount, address recipient, uint64 expiry, bool paid) = invoiceRegistry.invoices(p.invoiceId);
        require(recipient != address(0), "no such invoice");
        require(!paid, "invoice already paid");
        require(expiry == 0 || block.timestamp <= expiry, "invoice expired");
        require(asset == p.asset && amount == p.amount && recipient == p.recipient, "invoice data mismatch");
        // Bind the paired withdrawal to THIS SAME invoice's data: the sequencer cannot supply a
        // correct invoicePayments entry while routing the actual withdrawals[i] payout elsewhere.
        require(w.asset == p.asset && w.recipient == p.recipient, "withdrawal/invoice mismatch");
        require(f.asset == p.asset, "fee/invoice asset mismatch");
        require(w.amount + f.amount == p.amount, "withdrawal+fee != invoice amount");
        invoiceRegistry.markPaid(p.invoiceId);
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

    /// keccak256 over nullifier(32)|asset(20)|amount(32)|recipient(20), in list order. Empty list
    /// commits to the zero hash — same convention as ZstableRollup._withdrawalsRoot.
    function _withdrawalsRoot(WithdrawalEntry[] calldata withdrawals) internal pure returns (bytes32) {
        if (withdrawals.length == 0) return bytes32(0);
        bytes memory buf;
        for (uint256 i = 0; i < withdrawals.length; i++) {
            WithdrawalEntry calldata w = withdrawals[i];
            buf = abi.encodePacked(buf, w.nullifier, w.asset, w.amount, w.recipient);
        }
        return keccak256(buf);
    }

    /// keccak256 over noteCommitment(32)|asset(20)|amount(32), in list order. Empty list commits to
    /// the zero hash — same convention as ZstableRollup._depositsRoot.
    function _depositsRoot(DepositConsumption[] calldata deposits) internal pure returns (bytes32) {
        if (deposits.length == 0) return bytes32(0);
        bytes memory buf;
        for (uint256 i = 0; i < deposits.length; i++) {
            DepositConsumption calldata d = deposits[i];
            buf = abi.encodePacked(buf, d.noteCommitment, d.asset, d.amount);
        }
        return keccak256(buf);
    }

    /// keccak256 over invoiceId(32)|asset(20)|amount(32)|recipient(20), in list order. Empty list
    /// commits to the zero hash.
    function _invoicesRoot(InvoicePayment[] calldata invoicePayments) internal pure returns (bytes32) {
        if (invoicePayments.length == 0) return bytes32(0);
        bytes memory buf;
        for (uint256 i = 0; i < invoicePayments.length; i++) {
            InvoicePayment calldata p = invoicePayments[i];
            buf = abi.encodePacked(buf, p.invoiceId, p.asset, p.amount, p.recipient);
        }
        return keccak256(buf);
    }

    /// keccak256 over asset(20)|amount(32), in list order. Empty list commits to the zero hash —
    /// same packing convention as ZstableRollup._feesRoot.
    function _feesRoot(FeeEntry[] calldata fees) internal pure returns (bytes32) {
        if (fees.length == 0) return bytes32(0);
        bytes memory buf;
        for (uint256 i = 0; i < fees.length; i++) {
            FeeEntry calldata f = fees[i];
            buf = abi.encodePacked(buf, f.asset, f.amount);
        }
        return keccak256(buf);
    }
}
