// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./AssetRegistry.sol";

/// @notice Registry of Enclave Allowance targets: a standing, reusable funding channel. A target is
/// registered once (recipient + asset + optional per-funding cap) and can then be funded any number of
/// times, privately, with free amounts. Unlike an invoice there is no fixed amount, no `paid` flag and
/// no expiry — only the owner can switch a target off or change its cap.
///
/// Registration is permissionless: the registrant becomes the target's owner and may name any recipient
/// (typically an agent wallet). The owner is separate from the recipient on purpose: if the recipient's
/// key is compromised, the owner can still stop further funding. Deactivating only stops FUTURE
/// fundings; it cannot recall money already paid out.
contract EnclaveAllowanceRegistry {
    struct Target {
        address owner;
        address recipient;
        address asset;
        /// Maximum amount a single funding may pay the recipient, in `asset` units; 0 = no cap. This is
        /// a per-funding limit, NOT a spending budget: a target can be funded any number of times.
        uint256 cap;
        bool active;
    }

    /// Smallest funding (and smallest non-zero cap), in base units; every funding costs a paid proof.
    /// Sized for 6-decimal assets (0.01). Must equal the guest's `MIN_ALLOWANCE_AMOUNT`.
    uint256 public constant MIN_FUNDING = 10_000;

    AssetRegistry public immutable assetRegistry;

    mapping(bytes32 => Target) public targets;
    uint256 private _nonce;

    event TargetRegistered(bytes32 indexed targetId, address indexed owner, address indexed recipient, address asset, uint256 cap);
    event TargetCapUpdated(bytes32 indexed targetId, uint256 cap);
    event TargetActiveSet(bytes32 indexed targetId, bool active);

    constructor(address assetRegistry_) {
        assetRegistry = AssetRegistry(assetRegistry_);
    }

    function registerTarget(address asset, address recipient, uint256 cap) external returns (bytes32 targetId) {
        require(assetRegistry.isSupported(asset), "asset not supported");
        require(recipient != address(0), "zero recipient");
        require(cap == 0 || cap >= MIN_FUNDING, "cap below minimum funding");
        targetId = keccak256(abi.encodePacked(msg.sender, recipient, asset, _nonce++));
        targets[targetId] = Target(msg.sender, recipient, asset, cap, true);
        emit TargetRegistered(targetId, msg.sender, recipient, asset, cap);
    }

    function setCap(bytes32 targetId, uint256 cap) external {
        Target storage t = _owned(targetId);
        require(cap == 0 || cap >= MIN_FUNDING, "cap below minimum funding");
        t.cap = cap;
        emit TargetCapUpdated(targetId, cap);
    }

    function deactivateTarget(bytes32 targetId) external {
        Target storage t = _owned(targetId);
        require(t.active, "already inactive");
        t.active = false;
        emit TargetActiveSet(targetId, false);
    }

    function reactivateTarget(bytes32 targetId) external {
        Target storage t = _owned(targetId);
        require(!t.active, "already active");
        t.active = true;
        emit TargetActiveSet(targetId, true);
    }

    function _owned(bytes32 targetId) internal view returns (Target storage t) {
        t = targets[targetId];
        require(t.owner != address(0), "no such target");
        require(msg.sender == t.owner, "not target owner");
    }
}
