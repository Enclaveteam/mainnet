// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "./AssetRegistry.sol";
import "./IWithdrawalRollup.sol";

/// Minimal slice of IUniswapV3Pool this vault needs to sell one asset for another at the pool's
/// live market price — the SAME real on-chain pool `UniswapV3TwapOracle` reads for the price feed
/// (see `setTradingPool`). No router: swapping directly against the pool avoids depending on a
/// router deployment that may not exist on this chain.
interface IUniswapV3PoolSwap {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96, bytes calldata data)
        external
        returns (int256 amount0, int256 amount1);
}

/// @notice Custody contract: locks real assets on trader deposit, releases them on a proven
/// withdrawal, AND accounts for liquidity-provider credit lines used to back that settlement.
/// LP accounting is additive to the original trader deposit/withdraw path. `settleBatch` reserves
/// each authorized trader claim here (see `reserveTraderClaim`) and consumes trader deposits
/// against a real on-chain record (see `consumeDeposit`) so a trade's input cannot be fabricated.
/// If the deposit is never consumed by a settled batch, the depositor can recover it directly via
/// `forceExit` after a timeout, with no key/server/admin belonging to the operator involved.
/// `rebalanceTrade` pays each trade's withdrawal out of the SAME asset's LP-deposited liquidity
/// (see AssetCreditState) — that stays the direct backing for `withdraw`. To replenish what a
    /// trade draws down (so LPs of the OUTPUT asset can eventually redeem), it also swaps the trader's
/// just-deposited input asset for the output asset on the real Uniswap V3 pool (see
/// `setTradingPool`) — no external wallet, no internal-only bookkeeping trick: a genuine on-chain
/// swap, exactly what an external rebalancer wallet would have done, executed by the Vault itself.
contract Vault is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using Math for uint256;

    AssetRegistry public immutable assetRegistry;
    IWithdrawalRollup public immutable rollup;

    /// After this delay from deposit, an un-consumed deposit becomes recoverable by its original
    /// depositor via `forceExit`, with no rollup/TEE/admin action required. Fixed (not owner-settable)
    /// so no admin key can extend it to grief a user trying to exit.
    uint64 public constant FORCED_EXIT_DELAY = 7 days;

    // Depositor address is still visible on-chain via the ERC20 Transfer event regardless of
    // noteCommitment privacy — full deposit-time unlinkability is a known open item, not solved here.
    event DepositQueued(
        address indexed depositor,
        address indexed stockToken,
        uint256 amount,
        bytes32 noteCommitment
    );
    event Withdrawn(bytes32 indexed nullifier, address indexed stockToken, uint256 amount, address indexed recipient);

    /// A trader deposit tracked on-chain by its `noteCommitment` (chosen by the depositor at
    /// deposit time). `remaining` starts at the full deposited amount and is only ever reduced by
    /// a proven `consumeDeposit` (a settled batch actually spending it as trade input) or by the
    /// depositor's own `forceExit`. Never increased, never reassigned to another depositor.
    struct DepositRecord {
        address stockToken;
        address depositor;
        uint256 remaining;
        uint64 depositedAt;
    }

    mapping(bytes32 => DepositRecord) public deposits;

    event DepositConsumed(bytes32 indexed noteCommitment, address indexed asset, uint256 amount);
    event ForcedExit(bytes32 indexed noteCommitment, address indexed depositor, address indexed asset, uint256 amount);

    // ---------------------------------------------------------------------------------------
    // Liquidity-provider credit lines (per asset, denominated in that same asset — no shared
    // multi-asset share, no oracle-based NAV). See design doc for the full rationale.
    // ---------------------------------------------------------------------------------------

    /// Per-asset LP accounting. `reservedLPClaims` is the sum of all requested-but-not-yet-claimed
    /// redemption amounts, already fixed in asset terms at request time (see `requestRedeem`).
    /// `reservedTraderClaims` mirrors the Rollup's own `pendingWithdrawals` for that asset: it is
    /// incremented when `settleBatch` authorizes a withdrawal and decremented when `withdraw`
    /// consumes it, so LP redemptions can never spend funds already owed to a proven trader claim.
    /// `unconsumedDepositPrincipal` is the sum of all `deposits[...].remaining` for this asset: raw
    /// trader principal sitting in the vault that has NOT yet been consumed by a trade. It is not
    /// LP-backing value and must be excluded from LP accounting too, or a trader's own un-consumed
    /// deposit would silently inflate (and later, on forceExit, silently deflate) LP share price.
    struct AssetCreditState {
        uint256 totalShares;
        uint256 reservedLPClaims;
        uint256 reservedTraderClaims;
        uint256 unconsumedDepositPrincipal;
        uint256 minimumBuffer;
    }

    /// A redemption request whose payout amount was fixed at request time (not re-priced later).
    /// `convAssets`/`convAmounts` are the pro-rata slices of the pool's converted holdings (assets
    /// acquired by trades that drained this pool, at the trades' real executed prices) owed to this
    /// redeemer in-kind alongside the own-asset `amount`.
    struct PendingRedemption {
        address asset;
        address receiver;
        uint256 amount;
        bool claimed;
        address[] convAssets;
        uint256[] convAmounts;
        // For cancelRedeem: the exact state requestRedeem removed, so a cancel is a true inverse.
        address requester;
        uint256 sharesBurned;
        uint256 principalReduction;
    }

    // Virtual shares/assets (OZ ERC4626-style decimals offset) applied to every conversion to
    // dampen the classic first-depositor share-price inflation issue. This mitigates but does not
    // fully eliminate it; see ZSTABLE_MAINNET_VAULT_IMPLEMENTAZIONE_TECNICA.md §5.3 / §12.
    uint256 private constant VIRTUAL_SHARES = 1e3;
    uint256 private constant VIRTUAL_ASSETS = 1;

    mapping(address => AssetCreditState) private _creditState;
    mapping(address => mapping(address => uint256)) public lpShares; // asset => holder => shares
    mapping(address => mapping(address => uint256)) public lpPrincipal; // asset => holder => remaining supplied capital
    mapping(bytes32 => PendingRedemption) public pendingRedemptions;
    uint256 private _redemptionNonce;

    /// Trade-conversion ledger: convertedHoldings[pool][held] = amount of `held` owned by `pool`'s
    /// LPs, acquired when trades drained `pool`'s asset and paid in `held` (at the trades' REAL
    /// executed prices — spread and fees included, no oracle). This balance physically sits in the
    /// vault under `held`'s ERC-20 balance but belongs to `pool`'s LPs, so `held`'s own accounting
    /// must treat it as reserved (see `_convertedOwedIn`). Redeemed pro-rata in-kind by LP exits.
    mapping(address => mapping(address => uint256)) public convertedHoldings;
    /// Sum over all pools of convertedHoldings[pool][held], indexed by `held`: what `held`'s own
    /// balance owes to OTHER pools' LPs. Kept in lockstep with `convertedHoldings`.
    mapping(address => uint256) private _convertedOwedIn;
    /// Every pool address that ever had a nonzero conversion against `asset` — bounded in practice
    /// by the registered-asset count (2 today), only iterated at redeem time.
    mapping(address => address[]) private _convertedCounterAssets;
    mapping(address => mapping(address => bool)) private _isCounterAsset;

    /// Real Uniswap V3 pool `rebalanceTrade` swaps against for this stock token (vs. the quote
    /// asset) — typically the SAME pool `UniswapV3TwapOracle` reads for the price feed. Zero
    /// disables real-swap rebalancing for that token (rebalanceTrade then just checks LP solvency).
    mapping(address => address) public tradingPool;
    /// Every pool address ever wired via `setTradingPool` (never cleared, even if a stock is later
    /// re-pointed at a different pool — the old pool remains a genuine, owner-vetted Uniswap V3
    /// pool, so trusting it forever does not weaken this check). `uniswapV3SwapCallback` checks
    /// `msg.sender` against THIS, never against a value decoded from the callback's own calldata —
    /// calldata on a direct external call is fully controlled by the caller, so it can never be
    /// used to authorize a token transfer out of the vault; only this owner-maintained set can.
    mapping(address => bool) public isKnownTradingPool;

    event LiquidityDeposited(
        address indexed asset,
        address indexed provider,
        address indexed receiver,
        uint256 amount,
        uint256 shares
    );
    event RedemptionRequested(
        bytes32 indexed requestId,
        address indexed asset,
        address indexed receiver,
        uint256 shares,
        uint256 amount
    );
    event RedemptionClaimed(bytes32 indexed requestId, address indexed asset, address indexed receiver, uint256 amount);
    event RedemptionCancelled(bytes32 indexed requestId, address indexed asset, address indexed requester, uint256 shares);
    event MinimumBufferUpdated(address indexed asset, uint256 minimumBuffer);
    event TradingPoolUpdated(address indexed stockToken, address indexed pool);
    /// Emitted once per trade the vault settled. If `pool` is non-zero, the vault sold `paidInput`
    /// of the input asset for `swappedOut` of `outputAsset` on that real Uniswap V3 pool (the same
    /// swap an external rebalancer wallet used to perform) before `withdrawalAmount` was verified
    /// free and reserved for the trader by `reserveTraderClaim`. `feeAmount` is never reserved, so
    /// whatever `swappedOut` exceeds `withdrawalAmount` stays free/LP-owned value for `outputAsset`'s
    /// providers. `pool == address(0)` means no trading pool was configured for this pair — the
    /// withdrawal was still paid straight out of `outputAsset`'s own LP-deposited liquidity.
    event AutoRebalanced(address indexed outputAsset, uint256 withdrawalAmount, uint256 feeAmount, address indexed pool, uint256 paidInput, uint256 swappedOut);

    constructor(address assetRegistry_, address rollup_, address initialOwner) Ownable(initialOwner) {
        assetRegistry = AssetRegistry(assetRegistry_);
        rollup = IWithdrawalRollup(rollup_);
    }

    function deposit(address stockToken, uint256 amount, bytes32 noteCommitment) external nonReentrant {
        require(assetRegistry.isSupported(stockToken), "asset not supported");
        require(amount > 0, "amount=0");
        require(deposits[noteCommitment].stockToken == address(0), "commitment already used");
        IERC20(stockToken).safeTransferFrom(msg.sender, address(this), amount);
        deposits[noteCommitment] = DepositRecord(stockToken, msg.sender, amount, uint64(block.timestamp));
        _creditState[stockToken].unconsumedDepositPrincipal += amount;
        emit DepositQueued(msg.sender, stockToken, amount, noteCommitment);
    }

    /// Called by the Rollup during `settleBatch`, once per disclosed `DepositConsumption` entry
    /// (aggregated per deposit across the batch's trades and bound to the proof via `depositsRoot`
    /// — see ZstableRollup.sol). This is what ties a trade's input to a real, unspent deposit: the
    /// sequencer cannot claim a trade was funded by more than a deposit's actual `remaining`.
    function consumeDeposit(bytes32 noteCommitment, address asset, uint256 amount) external {
        require(msg.sender == address(rollup), "not rollup");
        DepositRecord storage rec = deposits[noteCommitment];
        require(rec.stockToken == asset, "asset mismatch");
        require(rec.remaining >= amount, "insufficient deposit");
        rec.remaining -= amount;
        _creditState[asset].unconsumedDepositPrincipal -= amount;
        emit DepositConsumed(noteCommitment, asset, amount);
    }

    /// Recovers whatever is left of a deposit directly to its original depositor, once
    /// `FORCED_EXIT_DELAY` has passed since it was made — with no rollup, TEE, or admin action of
    /// any kind. If the deposit was already (partially) consumed by a genuine settled trade, only
    /// the un-consumed `remaining` is recoverable here; the consumed portion became a trader claim
    /// elsewhere, already recoverable independently via the existing permissionless `withdraw`.
    function forceExit(bytes32 noteCommitment) external nonReentrant {
        DepositRecord storage rec = deposits[noteCommitment];
        require(rec.stockToken != address(0), "no such deposit");
        require(msg.sender == rec.depositor, "not depositor");
        require(block.timestamp >= rec.depositedAt + FORCED_EXIT_DELAY, "too early");
        uint256 amount = rec.remaining;
        require(amount > 0, "nothing left");
        address asset = rec.stockToken;
        rec.remaining = 0;
        _creditState[asset].unconsumedDepositPrincipal -= amount;
        IERC20(asset).safeTransfer(msg.sender, amount);
        emit ForcedExit(noteCommitment, msg.sender, asset, amount);
    }

    function withdraw(bytes32 nullifier) external nonReentrant {
        (address stockToken, uint256 amount, address recipient) = rollup.consumeWithdrawal(nullifier);
        _creditState[stockToken].reservedTraderClaims -= amount;
        IERC20(stockToken).safeTransfer(recipient, amount);
        emit Withdrawn(nullifier, stockToken, amount, recipient);
    }

    /// Called by the Rollup, once per authorized withdrawal, in the same `settleBatch` transaction
    /// that queues it. Pure bookkeeping mirror of `pendingWithdrawals`; the actual inventory that
    /// backs the payout is acquired separately by `rebalanceTrade`, which the Rollup calls first.
    function reserveTraderClaim(address asset, uint256 amount) external {
        require(msg.sender == address(rollup), "not rollup");
        _creditState[asset].reservedTraderClaims += amount;
    }

    /// Real on-chain rebalance, called by the Rollup for each trade during `settleBatch` BEFORE
    /// `reserveTraderClaim` commits the reservation. If a Uniswap V3 pool is wired (see
    /// `setTradingPool`) it sells the trader's just-deposited input asset for the output asset on
    /// that real pool. When NO pool exists (e.g. Arc mainnet today has no permissionless DEX),
    /// it instead records the conversion in the trade-conversion ledger: the output pool's LPs
    /// become the owners of the trade's real input (`inputAmount`, already consumed and sitting in
    /// this vault), at the trade's REAL executed price — fees/spread included, no oracle involved.
    /// A later trade in the opposite direction first unwinds the standing claim (the drained pool
    /// takes back its own asset and releases the held one), so balanced two-way flow nets to zero.
    /// The final solvency check always runs, for every call, with no early-exit path around it.
    function rebalanceTrade(
        address inputAsset,
        address outputAsset,
        uint256 inputAmount,
        uint256 withdrawalAmount,
        uint256 feeAmount
    ) external {
        require(msg.sender == address(rollup), "not rollup");

        if (inputAsset != address(0) && inputAsset != outputAsset) {
            address pool = tradingPool[inputAsset] != address(0) ? tradingPool[inputAsset] : tradingPool[outputAsset];
            if (pool != address(0)) {
                uint256 paidInput = _fairValue(withdrawalAmount + feeAmount, outputAsset, inputAsset);
                AssetCreditState storage inState = _creditState[inputAsset];
                uint256 inBalance = IERC20(inputAsset).balanceOf(address(this));
                uint256 inReserved = inState.reservedLPClaims + inState.reservedTraderClaims
                    + inState.unconsumedDepositPrincipal + inState.minimumBuffer + _convertedOwedIn[inputAsset];
                require(inBalance >= inReserved && inBalance - inReserved >= paidInput, "insufficient input liquidity to rebalance");
                uint256 amountOut = _swapExactInput(pool, inputAsset, outputAsset, paidInput);
                emit AutoRebalanced(outputAsset, withdrawalAmount, feeAmount, pool, paidInput, amountOut);
            } else {
                _recordConversion(inputAsset, outputAsset, inputAmount, withdrawalAmount + feeAmount);
                emit AutoRebalanced(outputAsset, withdrawalAmount, feeAmount, address(0), inputAmount, 0);
            }
        }

        AssetCreditState storage outState = _creditState[outputAsset];
        uint256 balance = IERC20(outputAsset).balanceOf(address(this));
        uint256 reserved = outState.reservedLPClaims + outState.reservedTraderClaims
            + outState.unconsumedDepositPrincipal + outState.minimumBuffer + _convertedOwedIn[outputAsset];
        require(balance >= reserved && balance - reserved >= withdrawalAmount, "insufficient output liquidity for trade");
    }

    /// Ledger update for one no-pool trade: `outputAsset`'s pool sold `outputSold` of its own asset
    /// and received `inputAmount` of `inputAsset`. First unwinds any standing opposite claim
    /// (outputAsset held by inputAsset's pool) 1:1 in output-asset units — the incoming output-side
    /// flow simply hands back what the other pool was holding — then records the (remaining)
    /// conversion as a new holding for `outputAsset`'s LPs. Proportional split keeps both legs at
    /// the trade's own executed price.
    function _recordConversion(address inputAsset, address outputAsset, uint256 inputAmount, uint256 outputSold) internal {
        if (inputAmount == 0 || outputSold == 0) return;

        // Opposite standing claim: inputAsset's pool holds outputAsset from earlier reverse trades.
        uint256 oppositeHeld = convertedHoldings[inputAsset][outputAsset];
        if (oppositeHeld > 0) {
            uint256 unwoundOutput = outputSold <= oppositeHeld ? outputSold : oppositeHeld;
            // Input share pertaining to the unwound slice, at this trade's own price.
            uint256 unwoundInput = inputAmount.mulDiv(unwoundOutput, outputSold, Math.Rounding.Floor);
            convertedHoldings[inputAsset][outputAsset] = oppositeHeld - unwoundOutput;
            _convertedOwedIn[outputAsset] -= unwoundOutput;
            inputAmount -= unwoundInput;
            outputSold -= unwoundOutput;
            if (inputAmount == 0 || outputSold == 0) return;
        }

        convertedHoldings[outputAsset][inputAsset] += inputAmount;
        _convertedOwedIn[inputAsset] += inputAmount;
        if (!_isCounterAsset[outputAsset][inputAsset]) {
            _isCounterAsset[outputAsset][inputAsset] = true;
            _convertedCounterAssets[outputAsset].push(inputAsset);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Liquidity-provider entry/exit
    // ---------------------------------------------------------------------------------------

    /// Deposits `amount` of `asset` as LP credit, minting shares denominated in that same asset
    /// (no conversion, no oracle). `receiver` gets the shares; `msg.sender` pays the transfer.
    function depositLiquidity(address asset, uint256 amount, address receiver)
        external
        nonReentrant
        returns (uint256 shares)
    {
        require(assetRegistry.isSupported(asset), "asset not supported");
        require(amount > 0, "amount=0");
        require(receiver != address(0), "zero receiver");

        AssetCreditState storage state = _creditState[asset];
        // Full pool value (own + converted holdings at oracle price): a new LP entering after a
        // conversion must pay for the converted holdings too, or they'd dilute existing LPs.
        uint256 assetsBefore = _poolValue(asset, state);
        uint256 sharesBefore = state.totalShares;

        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);

        shares = amount.mulDiv(sharesBefore + VIRTUAL_SHARES, assetsBefore + VIRTUAL_ASSETS, Math.Rounding.Floor);
        require(shares > 0, "deposit too small");

        state.totalShares = sharesBefore + shares;
        lpShares[asset][receiver] += shares;
        lpPrincipal[asset][receiver] += amount;

        emit LiquidityDeposited(asset, msg.sender, receiver, amount, shares);
    }

    /// Burns `shares` immediately and fixes the payout at the current pro-rata slice of the pool's
    /// REAL basket: own asset + any converted holdings (assets trades paid in when they drained
    /// this pool, at the trades' executed prices — the "7 dollars and 3 euros" exit). No oracle is
    /// involved in the split. Paying out still depends on free liquidity (see `claimRedeem`).
    function requestRedeem(address asset, uint256 shares, address receiver)
        external
        nonReentrant
        returns (bytes32 requestId)
    {
        require(shares > 0, "shares=0");
        require(receiver != address(0), "zero receiver");
        require(lpShares[asset][msg.sender] >= shares, "insufficient shares");

        AssetCreditState storage state = _creditState[asset];
        uint256 assetsBefore = _totalAssets(asset, state);
        uint256 sharesBefore = state.totalShares;
        uint256 holderSharesBefore = lpShares[asset][msg.sender];

        uint256 amount = shares.mulDiv(assetsBefore + VIRTUAL_ASSETS, sharesBefore + VIRTUAL_SHARES, Math.Rounding.Floor);
        uint256 principalBefore = lpPrincipal[asset][msg.sender];
        uint256 principalReduction = shares == holderSharesBefore
            ? principalBefore
            : principalBefore.mulDiv(shares, holderSharesBefore, Math.Rounding.Floor);

        lpShares[asset][msg.sender] -= shares;
        lpPrincipal[asset][msg.sender] = principalBefore - principalReduction;
        state.totalShares = sharesBefore - shares;
        state.reservedLPClaims += amount;

        requestId = keccak256(abi.encode(asset, msg.sender, receiver, shares, amount, _redemptionNonce++));
        _storeRedemption(requestId, asset, receiver, amount, shares, sharesBefore, principalReduction);

        emit RedemptionRequested(requestId, asset, receiver, shares, amount);
    }

    /// Split out of requestRedeem purely to stay under the EVM stack limit.
    function _storeRedemption(
        bytes32 requestId,
        address asset,
        address receiver,
        uint256 amount,
        uint256 shares,
        uint256 sharesBefore,
        uint256 principalReduction
    ) internal {
        (address[] memory convAssets, uint256[] memory convAmounts) = _sliceConversions(asset, shares, sharesBefore);
        PendingRedemption storage req = pendingRedemptions[requestId];
        req.asset = asset;
        req.receiver = receiver;
        req.amount = amount;
        req.convAssets = convAssets;
        req.convAmounts = convAmounts;
        req.requester = msg.sender;
        req.sharesBurned = shares;
        req.principalReduction = principalReduction;
    }

    /// Cancels an unclaimed redemption, exactly reversing its request: shares are re-minted to the
    /// requester, the reserved own-asset amount backs shares again, and the in-kind conversion
    /// slices return to the pool's ledger. Value re-enters together with the shares, so the share
    /// price other LPs see is unchanged. Lets a requester recover from a redemption whose own-asset
    /// side stays uncoverable (see claimRedeem) instead of locking the slices forever.
    function cancelRedeem(bytes32 requestId) external nonReentrant {
        PendingRedemption storage req = pendingRedemptions[requestId];
        require(req.receiver != address(0), "no such redemption");
        require(!req.claimed, "already claimed");
        require(msg.sender == req.requester, "not requester");

        req.claimed = true;
        address asset = req.asset;
        AssetCreditState storage state = _creditState[asset];
        state.reservedLPClaims -= req.amount;
        state.totalShares += req.sharesBurned;
        lpShares[asset][req.requester] += req.sharesBurned;
        lpPrincipal[asset][req.requester] += req.principalReduction;
        for (uint256 i = 0; i < req.convAssets.length; i++) {
            if (req.convAssets[i] == address(0) || req.convAmounts[i] == 0) continue;
            convertedHoldings[asset][req.convAssets[i]] += req.convAmounts[i]; // _convertedOwedIn never moved at request time
        }

        emit RedemptionCancelled(requestId, asset, req.requester, req.sharesBurned);
    }

    /// Pro-rata in-kind slices of every converted holding, moved out of the pool's ledger and into
    /// the redemption (their physical reservation via _convertedOwedIn is released only at claim
    /// time, when the tokens actually leave the vault).
    function _sliceConversions(address asset, uint256 shares, uint256 sharesBefore)
        internal
        returns (address[] memory convAssets, uint256[] memory convAmounts)
    {
        address[] storage counters = _convertedCounterAssets[asset];
        convAssets = new address[](counters.length);
        convAmounts = new uint256[](counters.length);
        for (uint256 i = 0; i < counters.length; i++) {
            uint256 held = convertedHoldings[asset][counters[i]];
            if (held == 0) continue;
            uint256 slice = held.mulDiv(shares, sharesBefore, Math.Rounding.Floor);
            if (slice == 0) continue;
            convertedHoldings[asset][counters[i]] = held - slice;
            convAssets[i] = counters[i];
            convAmounts[i] = slice;
        }
    }

    /// Pays out a previously requested redemption once the asset's free liquidity covers it.
    /// Free liquidity here excludes both the minimum buffer and any outstanding trader claims
    /// reserved via `reserveTraderClaim` — an LP redemption can never spend funds already owed to a
    /// proven withdrawal. Reverts (retriable later) otherwise. Not FIFO/pro-rata yet — first
    /// request that is coverable wins; a fair queue policy is an open design question (see design
    /// doc §16 / "Opzioni aperte").
    function claimRedeem(bytes32 requestId) external nonReentrant returns (uint256 amount) {
        PendingRedemption storage req = pendingRedemptions[requestId];
        require(req.receiver != address(0), "no such redemption");
        require(!req.claimed, "already claimed");

        address asset = req.asset;
        amount = req.amount;
        AssetCreditState storage state = _creditState[asset];
        uint256 balance = IERC20(asset).balanceOf(address(this));
        // Un-consumed trader-deposit principal is never LP-owned value and must be excluded here
        // too, or a redemption could pay out funds reserved for a depositor's forceExit. Converted
        // holdings owed to OTHER pools' LPs (_convertedOwedIn) share this asset's physical balance
        // and are equally untouchable — same exclusion set as `_totalAssets`/`freeLiquidity`.
        uint256 reservedForOthers = state.reservedTraderClaims + state.minimumBuffer
            + state.unconsumedDepositPrincipal + _convertedOwedIn[asset];
        require(balance >= reservedForOthers && balance - reservedForOthers >= amount, "insufficient free liquidity");

        req.claimed = true;
        state.reservedLPClaims -= amount;
        IERC20(asset).safeTransfer(req.receiver, amount);

        // Converted-holdings slices: paid straight out of their _convertedOwedIn reservation (the
        // physical balance was never spendable by anyone else), so no extra liquidity check needed.
        for (uint256 i = 0; i < req.convAssets.length; i++) {
            if (req.convAssets[i] == address(0) || req.convAmounts[i] == 0) continue;
            _convertedOwedIn[req.convAssets[i]] -= req.convAmounts[i];
            IERC20(req.convAssets[i]).safeTransfer(req.receiver, req.convAmounts[i]);
        }

        emit RedemptionClaimed(requestId, asset, req.receiver, amount);
    }

    /// Governance-configured floor below which `claimRedeem` will not pay out `asset`. Zero by
    /// default (no buffer reserved) until explicitly configured.
    function setMinimumBuffer(address asset, uint256 minimumBuffer_) external onlyOwner {
        _creditState[asset].minimumBuffer = minimumBuffer_;
        emit MinimumBufferUpdated(asset, minimumBuffer_);
    }

    /// Wires `stockToken` to the real Uniswap V3 pool `rebalanceTrade` swaps against (see
    /// AutoRebalanced). Pass the zero address to disable real-swap rebalancing for that token —
    /// `rebalanceTrade` then falls back to the plain LP-solvency check with no swap. A non-zero
    /// pool is permanently marked trusted for `uniswapV3SwapCallback` (see `isKnownTradingPool`).
    function setTradingPool(address stockToken, address pool) external onlyOwner {
        tradingPool[stockToken] = pool;
        if (pool != address(0)) isKnownTradingPool[pool] = true;
        emit TradingPoolUpdated(stockToken, pool);
    }

    // ---------------------------------------------------------------------------------------
    // Real on-chain rebalancing (Uniswap V3 direct pool swap, no router)
    // ---------------------------------------------------------------------------------------

    // Standard Uniswap V3 sqrt-price bounds (well-known constants, same values used by the
    // official periphery libraries) +/- 1: the widest price limit a swap can specify, i.e. "accept
    // any execution price the pool's current liquidity allows".
    uint160 private constant MIN_SQRT_RATIO_PLUS_ONE = 4295128740;
    uint160 private constant MAX_SQRT_RATIO_MINUS_ONE = 1461446703485210103287273052203988822378723970341;

    /// Oracle value of `amount` of `fromAsset`, expressed in `toAsset` units, using
    /// `AssetRegistry.currentPrice` for both, normalized by each asset's own decimals. Rounded UP
    /// so the vault never undersizes the input it sells relative to the fair value it computed.
    function _fairValue(uint256 amount, address fromAsset, address toAsset) internal view returns (uint256) {
        uint256 priceFrom = assetRegistry.currentPrice(fromAsset);
        uint256 priceTo = assetRegistry.currentPrice(toAsset);
        require(priceFrom > 0 && priceTo > 0, "no price for asset");

        uint8 decimalsFrom = assetRegistry.assetInfo(fromAsset).decimals;
        uint8 decimalsTo = assetRegistry.assetInfo(toAsset).decimals;

        uint256 valueInQuote = amount.mulDiv(priceFrom, 10 ** decimalsFrom, Math.Rounding.Ceil);
        return valueInQuote.mulDiv(10 ** decimalsTo, priceTo, Math.Rounding.Ceil);
    }

    /// Sells exactly `amountIn` of `tokenIn` for `tokenOut` on `pool`, no price limit beyond the
    /// pool's own liquidity curve. `rebalanceTrade`'s post-swap solvency check is the backstop
    /// against bad execution (e.g. thin liquidity/slippage): it reverts the whole settlement rather
    /// than let an under-filled swap create an unfunded withdrawal.
    function _swapExactInput(address pool, address tokenIn, address tokenOut, uint256 amountIn) internal returns (uint256 amountOut) {
        bool zeroForOne = tokenIn == IUniswapV3PoolSwap(pool).token0();
        (int256 amount0, int256 amount1) = IUniswapV3PoolSwap(pool).swap(
            address(this),
            zeroForOne,
            int256(amountIn),
            zeroForOne ? MIN_SQRT_RATIO_PLUS_ONE : MAX_SQRT_RATIO_MINUS_ONE,
            abi.encode(tokenIn)
        );
        amountOut = uint256(zeroForOne ? -amount1 : -amount0);
        require(tokenOut == (zeroForOne ? IUniswapV3PoolSwap(pool).token1() : IUniswapV3PoolSwap(pool).token0()), "pool token mismatch");
    }

    /// Uniswap V3 swap callback: the pool calls this on the initiator (`address(this)` in
    /// `_swapExactInput`) mid-swap to collect payment. Authorization comes ONLY from
    /// `isKnownTradingPool[msg.sender]` (a set this contract's owner populated) — `data` is
    /// caller-controlled on any direct call to this externally-callable function, so it can
    /// never be trusted for authorization, only for the (already-vault-chosen) token identity.
    /// Exactly one of the two deltas is positive (owed to the pool); pays it in the token that's
    /// actually owed, straight from the vault's own balance (the trader's just-consumed deposit,
    /// already physically here).
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        require(isKnownTradingPool[msg.sender], "callback not from a known pool");
        address tokenIn = abi.decode(data, (address));
        uint256 amountToPay = amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta);
        IERC20(tokenIn).safeTransfer(msg.sender, amountToPay);
    }

    // ---------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------

    /// LP-owned value of `asset`: physical balance minus amounts already fixed for pending LP
    /// redemptions and minus trader claims already authorized by `settleBatch`.
    function totalAssets(address asset) external view returns (uint256) {
        return _totalAssets(asset, _creditState[asset]);
    }

    function totalSharesOf(address asset) external view returns (uint256) {
        return _creditState[asset].totalShares;
    }

    function reservedLPClaims(address asset) external view returns (uint256) {
        return _creditState[asset].reservedLPClaims;
    }

    function reservedTraderClaims(address asset) external view returns (uint256) {
        return _creditState[asset].reservedTraderClaims;
    }

    function unconsumedDepositPrincipal(address asset) external view returns (uint256) {
        return _creditState[asset].unconsumedDepositPrincipal;
    }

    function minimumBufferOf(address asset) external view returns (uint256) {
        return _creditState[asset].minimumBuffer;
    }

    /// Current redemption value of `shares` of `asset` in own-asset units, converted holdings
    /// included at oracle price. The actual exit is in-kind (see `requestRedeem`) — this view is
    /// for frontends showing a single-number position value.
    function previewShareValue(address asset, uint256 shares) external view returns (uint256) {
        AssetCreditState storage state = _creditState[asset];
        uint256 assets = _poolValue(asset, state);
        return shares.mulDiv(assets + VIRTUAL_ASSETS, state.totalShares + VIRTUAL_SHARES, Math.Rounding.Floor);
    }

    /// Spendable-above-buffer balance of `asset`, after pending LP redemptions, converted holdings
    /// owed to other pools, and trader claims are set aside. Floors at zero.
    function freeLiquidity(address asset) external view returns (uint256) {
        AssetCreditState storage state = _creditState[asset];
        uint256 balance = IERC20(asset).balanceOf(address(this));
        uint256 reserved = state.reservedLPClaims + state.reservedTraderClaims + state.unconsumedDepositPrincipal
            + state.minimumBuffer + _convertedOwedIn[asset];
        if (balance <= reserved) return 0;
        return balance - reserved;
    }

    /// LP-owned value only; nets out pending LP redemptions, trader claims already authorized
    /// against this asset, un-consumed trader-deposit principal, and balances of THIS asset that
    /// the trade-conversion ledger assigned to other pools' LPs — none of that is this pool's
    /// capital, even though it shares the same physical ERC-20 balance.
    function _totalAssets(address asset, AssetCreditState storage state) internal view returns (uint256) {
        uint256 balance = IERC20(asset).balanceOf(address(this));
        uint256 reserved = state.reservedLPClaims + state.reservedTraderClaims + state.unconsumedDepositPrincipal
            + _convertedOwedIn[asset];
        if (balance <= reserved) return 0;
        return balance - reserved;
    }

    /// Full value of `asset`'s pool in own-asset units: own assets + converted holdings priced at
    /// the on-chain oracle. Used ONLY to price share mints/views — LP exits never need it (they
    /// are paid pro-rata in-kind, at the trades' already-executed prices).
    function _poolValue(address asset, AssetCreditState storage state) internal view returns (uint256) {
        uint256 value = _totalAssets(asset, state);
        address[] storage counters = _convertedCounterAssets[asset];
        for (uint256 i = 0; i < counters.length; i++) {
            uint256 held = convertedHoldings[asset][counters[i]];
            if (held > 0) value += _fairValue(held, counters[i], asset);
        }
        return value;
    }
}
