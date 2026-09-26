// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./IPriceOracle.sol";

/// @notice IPriceOracle bridge for an asset whose real market lives on a different chain than this
/// registry (e.g. a token's live Uniswap V3 pool on one chain, while settlement runs
/// on a testnet). A relayer (owner) periodically pushes the price + trailing history it read
/// directly off an on-chain source oracle on that other chain — this contract does not trust the
/// relayer's math, only that the pushed history is what the guest independently hashes into
/// `historyRoot`, exactly like `UniswapV3TwapOracle`. The relayer is a liveness/freshness
/// assumption, not a price-integrity one: a stale or absent push degrades to `updatedAt` going
/// stale, it cannot fabricate a history that still hashes to a plausible root.
contract PushOracle is IPriceOracle, Ownable {
    struct Entry {
        uint256 price1e18;
        uint64 updatedAt;
        uint256[] history;
    }

    mapping(address => Entry) private entries;

    /// Ceiling on price() staleness; a dead relay makes trades fail-safe instead of silently
    /// settling against a frozen price. Owner-adjustable, not a fixed constant, since relay cadence
    /// may vary per deployment. Bounded so it can never be set so low a normal relay cadence trips
    /// it constantly, nor so high it defeats the whole point of the check.
    uint256 public constant MIN_STALENESS = 1 minutes;
    uint256 public constant MAX_STALENESS_CAP = 1 days;
    uint256 public maxStaleness = 10 minutes;

    event PricePushed(address indexed asset, uint256 price1e18, uint64 updatedAt, uint256 historyLength);
    event MaxStalenessUpdated(uint256 maxStaleness);

    constructor(address owner_) Ownable(owner_) {}

    function setMaxStaleness(uint256 maxStaleness_) external onlyOwner {
        require(maxStaleness_ >= MIN_STALENESS && maxStaleness_ <= MAX_STALENESS_CAP, "staleness out of bounds");
        maxStaleness = maxStaleness_;
        emit MaxStalenessUpdated(maxStaleness_);
    }

    /// `history` is oldest-first, matching `UniswapV3TwapOracle.priceHistory` ordering so the same
    /// guest-side `historyRoot` hashing applies unchanged.
    function pushPrice(address asset, uint256 price1e18, uint256[] calldata history) external onlyOwner {
        require(asset != address(0), "zero address");
        Entry storage e = entries[asset];
        e.price1e18 = price1e18;
        e.updatedAt = uint64(block.timestamp);
        e.history = history;
        emit PricePushed(asset, price1e18, e.updatedAt, history.length);
    }

    function price(address asset) external view override returns (uint256 price1e18, uint64 updatedAt, bytes32 historyRoot) {
        Entry storage e = entries[asset];
        require(e.updatedAt != 0, "no price pushed");
        require(block.timestamp - e.updatedAt <= maxStaleness, "stale price");
        price1e18 = e.price1e18;
        updatedAt = e.updatedAt;
        historyRoot = _historyRoot(e.history);
    }

    function priceHistory(address asset) external view returns (uint256[] memory) {
        return entries[asset].history;
    }

    /// keccak256 over price_1(32) | price_2(32) | ... | price_N(32), oldest first — identical
    /// packing to `UniswapV3TwapOracle._historyRoot` so the guest's recomputation matches either
    /// source without special-casing.
    function _historyRoot(uint256[] memory history) internal pure returns (bytes32) {
        bytes memory buf;
        for (uint256 i = 0; i < history.length; i++) {
            buf = abi.encodePacked(buf, history[i]);
        }
        return keccak256(buf);
    }
}
