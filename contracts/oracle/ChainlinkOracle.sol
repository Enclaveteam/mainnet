// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./IPriceOracle.sol";

/// @notice Minimal slice of Chainlink's AggregatorV3Interface this oracle needs.
interface IChainlinkAggregator {
    function decimals() external view returns (uint8);
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

/// @notice Reads a real, decentralized Chainlink price feed for a single asset (one instance per
/// feed, mirroring UniswapV3TwapOracle's one-instance-per-pool pattern). Offers no price history
/// (historyRoot is always bytes32(0)) -- IPriceOracle documents this as a valid "cold start", which
/// the guest treats as maximally conservative sigma (widest allowed volatility spread). This only
/// ever makes a trade's spread WIDER (more conservative), never understates risk from a missing
/// history, so it is not a price-integrity weakening versus a source that does offer history.
contract ChainlinkOracle is IPriceOracle {
    IChainlinkAggregator public immutable feed;
    address public immutable asset;
    uint8 public immutable feedDecimals;
    /// Ceiling on price() staleness vs. the feed's own reported updatedAt. Chainlink feeds already
    /// enforce their own heartbeat/deviation thresholds upstream; this is a second, independent
    /// backstop so a feed that stops updating fails trades safely instead of settling against a
    /// frozen price. Set to comfortably exceed the specific feed's published heartbeat.
    uint256 public immutable maxStaleness;

    constructor(address feed_, address asset_, uint256 maxStaleness_) {
        require(feed_ != address(0) && asset_ != address(0), "zero address");
        require(maxStaleness_ > 0, "zero staleness");
        feed = IChainlinkAggregator(feed_);
        asset = asset_;
        uint8 dec = IChainlinkAggregator(feed_).decimals();
        require(dec <= 18, "unsupported feed decimals");
        feedDecimals = dec;
        maxStaleness = maxStaleness_;
    }

    function price(address asset_) external view override returns (uint256 price1e18, uint64 updatedAt, bytes32 historyRoot) {
        require(asset_ == asset, "wrong asset");
        (, int256 answer, , uint256 updatedAt_, ) = feed.latestRoundData();
        require(answer > 0, "bad answer");
        require(block.timestamp - updatedAt_ <= maxStaleness, "stale price");
        price1e18 = uint256(answer) * (10 ** (18 - feedDecimals));
        updatedAt = uint64(updatedAt_);
        historyRoot = bytes32(0);
    }
}
