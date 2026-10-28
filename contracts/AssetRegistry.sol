// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./oracle/IPriceOracle.sol";

/// @notice Admin allowlist of Stock Token contracts supported by the rollup; metadata only, no funds.
contract AssetRegistry is Ownable {
    struct AssetInfo {
        uint32 assetId;
        uint8 decimals;
        bytes32 priceOracleRef;
        bool supported;
    }

    /// The market-maker pricing formula's per-asset knobs: P_quote = P_oracle * (1e18 + baseSpreadBps
    /// + volCoeffBps*sigma + skewCoeffBps*utilization) / 1e18, all bps fields in the SAME 1e18-fraction
    /// units as sigma/utilization so they can be summed directly. `sigmaMin1e18`/`sigmaMax1e18` clamp
    /// the guest-computed realized volatility before it enters that formula; governance controls only
    /// the clamp bounds, never the observed value itself.
    struct PricingParams {
        uint16 baseSpreadBps;
        uint16 volCoeffBps;
        uint16 skewCoeffBps;
        uint64 sigmaMin1e18;
        uint64 sigmaMax1e18;
    }

    /// Hard cap on any single bps coefficient above: a safety rail against an accidental
    /// owner input locking in an absurd spread, not the final economic parameterization.
    uint16 public constant MAX_PRICING_BPS = 5000; // 50%

    mapping(address => AssetInfo) private _assets;
    mapping(uint32 => address) public assetIdToToken;
    /// Optional live price source per asset (e.g. a Uniswap V3 TWAP); falls back to the static
    /// `priceOracleRef` when unset, so existing callers that never set one see no behavior change.
    mapping(address => IPriceOracle) public oracleOf;
    mapping(address => PricingParams) private _pricingParams;
    uint32 public nextAssetId = 1;

    event AssetRegistered(address indexed stockToken, uint32 indexed assetId, uint8 decimals, bytes32 priceOracleRef);
    event AssetUpdated(address indexed stockToken, bytes32 priceOracleRef);
    event AssetRemoved(address indexed stockToken);
    event AssetOracleSet(address indexed stockToken, address oracle);
    event PricingParamsSet(
        address indexed stockToken,
        uint16 baseSpreadBps,
        uint16 volCoeffBps,
        uint16 skewCoeffBps,
        uint64 sigmaMin1e18,
        uint64 sigmaMax1e18
    );

    constructor(address initialOwner) Ownable(initialOwner) {}

    function registerAsset(address stockToken, uint8 decimals, bytes32 priceOracleRef) external onlyOwner {
        require(stockToken != address(0), "zero address");
        require(!_assets[stockToken].supported, "already registered");
        uint32 assetId = nextAssetId++;
        _assets[stockToken] = AssetInfo(assetId, decimals, priceOracleRef, true);
        assetIdToToken[assetId] = stockToken;
        emit AssetRegistered(stockToken, assetId, decimals, priceOracleRef);
    }

    function updatePriceOracleRef(address stockToken, bytes32 priceOracleRef) external onlyOwner {
        require(_assets[stockToken].supported, "not registered");
        _assets[stockToken].priceOracleRef = priceOracleRef;
        emit AssetUpdated(stockToken, priceOracleRef);
    }

    function removeAsset(address stockToken) external onlyOwner {
        require(_assets[stockToken].supported, "not registered");
        _assets[stockToken].supported = false;
        emit AssetRemoved(stockToken);
    }

    /// Points `stockToken` at a live `IPriceOracle` (e.g. a Uniswap V3 TWAP); pass the zero address
    /// to revert to the static `priceOracleRef` set via `registerAsset`/`updatePriceOracleRef`.
    function setOracle(address stockToken, IPriceOracle oracle) external onlyOwner {
        require(_assets[stockToken].supported, "not registered");
        oracleOf[stockToken] = oracle;
        emit AssetOracleSet(stockToken, address(oracle));
    }

    function setPricingParams(address stockToken, PricingParams calldata params) external onlyOwner {
        require(_assets[stockToken].supported, "not registered");
        require(
            params.baseSpreadBps <= MAX_PRICING_BPS &&
                params.volCoeffBps <= MAX_PRICING_BPS &&
                params.skewCoeffBps <= MAX_PRICING_BPS,
            "bps exceeds protocol max"
        );
        require(params.sigmaMin1e18 <= params.sigmaMax1e18, "bad sigma clamp");
        _pricingParams[stockToken] = params;
        emit PricingParamsSet(
            stockToken,
            params.baseSpreadBps,
            params.volCoeffBps,
            params.skewCoeffBps,
            params.sigmaMin1e18,
            params.sigmaMax1e18
        );
    }

    function pricingParamsOf(address stockToken) external view returns (PricingParams memory) {
        return _pricingParams[stockToken];
    }

    /// The price the rollup guest must check trades against right now: the registered live oracle
    /// if one is set, otherwise the static `priceOracleRef`.
    function currentPrice(address stockToken) public view returns (uint256) {
        IPriceOracle oracle = oracleOf[stockToken];
        if (address(oracle) != address(0)) {
            (uint256 price1e18, , ) = oracle.price(stockToken);
            return price1e18;
        }
        return uint256(_assets[stockToken].priceOracleRef);
    }

    function isSupported(address stockToken) external view returns (bool) {
        return _assets[stockToken].supported;
    }

    function assetInfo(address stockToken) external view returns (AssetInfo memory) {
        return _assets[stockToken];
    }

    /// Deterministic commitment to the price table the rollup guest checks trades against:
    /// keccak256 over each supported asset packed as token(20) | price(32) | historyRoot(32), in
    /// assetId order. `historyRoot` is the oracle's own commitment to a recent, independently
    /// verifiable price history (bytes32(0) for a static `priceOracleRef`, which has none) — this is
    /// how the guest's realized-volatility input stays bound to the same trustless source as the
    /// price itself, with no separate history feed to trust. Empty -> zero hash. Must match the
    /// guest's compute_oracle_root.
    function oracleRoot() external view returns (bytes32) {
        bytes memory buf;
        for (uint32 id = 1; id < nextAssetId; id++) {
            address token = assetIdToToken[id];
            AssetInfo memory info = _assets[token];
            if (!info.supported) continue;
            IPriceOracle oracle = oracleOf[token];
            uint256 tokenPrice;
            bytes32 historyRoot;
            if (address(oracle) != address(0)) {
                (tokenPrice, , historyRoot) = oracle.price(token);
            } else {
                tokenPrice = uint256(info.priceOracleRef);
                historyRoot = bytes32(0);
            }
            buf = abi.encodePacked(buf, token, tokenPrice, historyRoot);
        }
        if (buf.length == 0) return bytes32(0);
        return keccak256(buf);
    }

    /// Deterministic commitment to the pricing formula parameters the guest must use per asset,
    /// same shape/order as `oracleRoot()` so both can be recomputed and checked the same way in
    /// `settleBatch`. An asset with no params set still contributes its (zeroed) entry, so the
    /// guest can never treat "unconfigured" as "configured with a zero spread" by omission.
    function pricingParamsRoot() external view returns (bytes32) {
        bytes memory buf;
        for (uint32 id = 1; id < nextAssetId; id++) {
            address token = assetIdToToken[id];
            AssetInfo memory info = _assets[token];
            if (!info.supported) continue;
            PricingParams memory p = _pricingParams[token];
            buf = abi.encodePacked(
                buf,
                token,
                p.baseSpreadBps,
                p.volCoeffBps,
                p.skewCoeffBps,
                p.sigmaMin1e18,
                p.sigmaMax1e18
            );
        }
        if (buf.length == 0) return bytes32(0);
        return keccak256(buf);
    }
}
