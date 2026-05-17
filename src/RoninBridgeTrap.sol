// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Trap} from "drosera-contracts/Trap.sol";
import {EventLog, EventFilter, EventFilterLib} from "drosera-contracts/libraries/Events.sol";

import {TrapDeployConfig} from "./TrapDeployConfig.sol";

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
}

interface IBaselineFeederLike {
    struct BridgePolicy {
        address bridge;
        uint256 outlierThresholdWeth;
        uint256 outlierThresholdUsdc;
        uint256 windowCapWeth;
        uint256 windowCapUsdc;
        uint256 tvlDropBps;
        uint256 wethPerUsdc;
        bool    configured;
    }
    function getBridgePolicy(address bridge) external view returns (BridgePolicy memory);
}

/// @title RoninBridgeTrap
/// @notice Drosera trap covering the Ronin Bridge $625M hack (Mar 23 2022,
///         Lazarus). Four severity-ordered detection vectors observe bridge
///         token balances, the largest single withdrawal per block, the
///         cumulative withdrawal volume over the sample window, and the
///         loss-of-visibility surface. None of them depend on validator
///         signature validity — the attacker held real keys.
///
///         EXPLOIT MAPPING (detection logic mapped to the attack txs):
///         • Block 14442835: `withdrawERC20For(20000002, attacker, WETH,
///           173600e18, sig)` → bridge WETH balance collapses; `TokenWithdrew`
///           event emits. Vectors 2 (OutlierWithdrawal) and 3 (BridgeTVLDrain)
///           both fire from a single snapshot.
///         • Block 14442840 (+5 blocks): `withdrawERC20For(...USDC...)` →
///           Vector 4 (CumulativeWithdrawal) already fires from a 10-block
///           window — the bridge would have been paused well before this tx.
///
///         AUDITOR ENDORSEMENT: Verichains' V2 audit (Jun 2022) explicitly
///         recommended "incident response protocols implemented by smart
///         contracts which help quickly respond and limit loss." This trap
///         is what that recommendation looks like, implemented three years
///         retroactively for V1.
contract RoninBridgeTrap is Trap {
    using EventFilterLib for EventFilter;

    // ────────────────────────────────────────────────────────────────────────
    // Types
    // ────────────────────────────────────────────────────────────────────────

    enum ThreatType {
        None,
        MonitoringDegraded,
        OutlierWithdrawal,
        BridgeTVLDrain,
        CumulativeWithdrawal
    }

    struct Snapshot {
        // Binding + ordering
        address bridge;                  //  0
        uint256 blockNumber;             //  1
        // Read-status flags (explicit, no sentinel ambiguity)
        bool    balancesReadOk;          //  2
        bool    baselineReadOk;          //  3
        bool    baselineConfigured;      //  4
        bool    eventReadOk;             //  5
        // Bridge balances
        uint256 wethBalance;             //  6
        uint256 usdcBalance;             //  7
        uint256 aggregateValueTU;        //  8  WETH-equivalent value across both tokens
        // Per-block withdrawal observations (event-derived)
        uint256 largestWithdrawalWeth;   //  9  max single WETH TokenWithdrew this block
        uint256 largestWithdrawalUsdc;   // 10  max single USDC TokenWithdrew this block
        uint256 blockWithdrawalSumWeth;  // 11  sum of WETH withdrawals this block
        uint256 blockWithdrawalSumUsdc;  // 12  sum of USDC withdrawals this block
        // Embedded baseline (from feeder)
        uint256 outlierThresholdWeth;    // 13
        uint256 outlierThresholdUsdc;    // 14
        uint256 windowCapWeth;           // 15
        uint256 windowCapUsdc;           // 16
        uint256 tvlDropBps;              // 17
        // Diagnostics
        uint256 withdrawalEventCount;    // 18
    }

    struct IncidentPayload {
        ThreatType threatType;
        address    bridge;
        uint256    currentBlockNumber;
        uint256    previousBlockNumber;
        bytes      details;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Constants
    // ────────────────────────────────────────────────────────────────────────

    uint256 internal constant SNAPSHOT_FIELDS = 19;
    uint256 internal constant ENCODED_SNAPSHOT_LEN = SNAPSHOT_FIELDS * 32; // 608
    uint256 internal constant BPS = 10_000;

    // ────────────────────────────────────────────────────────────────────────
    // Pure config accessors (constructorless deployment)
    // ────────────────────────────────────────────────────────────────────────

    function BRIDGE_GATEWAY() public pure returns (address) {
        return TrapDeployConfig.BRIDGE_GATEWAY;
    }
    function BASELINE_FEEDER() public pure returns (address) {
        return TrapDeployConfig.BASELINE_FEEDER;
    }
    function WETH() public pure returns (address) {
        return TrapDeployConfig.WETH;
    }
    function USDC() public pure returns (address) {
        return TrapDeployConfig.USDC;
    }

    constructor() {}

    // ────────────────────────────────────────────────────────────────────────
    // Event filter
    // ────────────────────────────────────────────────────────────────────────

    function eventLogFilters() public pure override returns (EventFilter[] memory) {
        EventFilter[] memory filters = new EventFilter[](1);
        filters[0] = EventFilter({
            contractAddress: TrapDeployConfig.BRIDGE_GATEWAY,
            // Indexed: _withdrawId, _owner, _tokenAddress. Non-indexed: _tokenNumber (uint256).
            signature: "TokenWithdrew(uint256,address,address,uint256)"
        });
        return filters;
    }

    // ────────────────────────────────────────────────────────────────────────
    // collect()
    // ────────────────────────────────────────────────────────────────────────

    function collect() external view override returns (bytes memory) {
        Snapshot memory s;
        s.bridge      = BRIDGE_GATEWAY();
        s.blockNumber = block.number;

        // Guard: if the bridge has no code at this block (e.g. pre-deployment
        // or fork that has rolled back), short-circuit with safe defaults.
        uint256 bridgeSize;
        address bridge = s.bridge;
        assembly { bridgeSize := extcodesize(bridge) }
        if (bridgeSize == 0) {
            return abi.encode(s);
        }

        // 1. Token balances on the bridge.
        (bool wethOk, uint256 wethBal) = _safeBalanceOf(WETH(), s.bridge);
        (bool usdcOk, uint256 usdcBal) = _safeBalanceOf(USDC(), s.bridge);
        s.wethBalance     = wethBal;
        s.usdcBalance     = usdcBal;
        s.balancesReadOk  = wethOk && usdcOk;

        // 2. Governance baseline.
        (bool baselineOk, IBaselineFeederLike.BridgePolicy memory p) =
            _readBaseline(s.bridge);
        s.baselineReadOk        = baselineOk;
        s.baselineConfigured    = baselineOk && p.configured;
        s.outlierThresholdWeth  = p.outlierThresholdWeth;
        s.outlierThresholdUsdc  = p.outlierThresholdUsdc;
        s.windowCapWeth         = p.windowCapWeth;
        s.windowCapUsdc         = p.windowCapUsdc;
        s.tvlDropBps            = p.tvlDropBps;

        // 3. Aggregate value in WETH-equivalent units, used by the TVLDrain
        //    vector. If wethPerUsdc is zero (no baseline / governance not yet
        //    rotated) we fall back to summing raw balances — coarse but
        //    monotonic enough for relative-drop detection.
        s.aggregateValueTU = _aggregateValue(s.wethBalance, s.usdcBalance, p.wethPerUsdc);

        // 4. In-block TokenWithdrew events.
        (
            bool eventOk,
            uint256 maxW,
            uint256 maxU,
            uint256 sumW,
            uint256 sumU,
            uint256 count
        ) = _scanWithdrawals();
        s.eventReadOk             = eventOk;
        s.largestWithdrawalWeth   = maxW;
        s.largestWithdrawalUsdc   = maxU;
        s.blockWithdrawalSumWeth  = sumW;
        s.blockWithdrawalSumUsdc  = sumU;
        s.withdrawalEventCount    = count;

        return abi.encode(s);
    }

    // ────────────────────────────────────────────────────────────────────────
    // shouldRespond()
    // ────────────────────────────────────────────────────────────────────────

    function shouldRespond(bytes[] calldata data)
        external
        pure
        override
        returns (bool, bytes memory)
    {
        // Guard: minimum samples and per-sample length.
        if (data.length < 2) return (false, "");

        Snapshot memory current  = _decodeSnapshot(data[0]);
        Snapshot memory previous = _decodeSnapshot(data[1]);

        // Bind to a non-zero target and require every sample to refer to it.
        if (current.bridge == address(0)) return (false, "");
        if (previous.bridge != current.bridge) return (false, "");

        // Strict newest→oldest contiguous ordering across the full window.
        // Use a local copy so we don't reuse `previous` semantics.
        Snapshot memory newer = current;
        for (uint256 i = 1; i < data.length; i++) {
            Snapshot memory older = _decodeSnapshot(data[i]);
            if (
                newer.blockNumber == 0 ||
                older.blockNumber == 0 ||
                newer.blockNumber != older.blockNumber + 1 ||
                older.bridge != current.bridge
            ) {
                return (false, "");
            }
            newer = older;
        }

        // VECTOR 1 — MonitoringDegraded (debounced 2 samples).
        //   EXPLOIT: An attacker who can disrupt the trap's read path (RPC
        //            degradation, feeder removal, malicious event-log
        //            tampering) silently disables detection — a precursor to
        //            many sophisticated attacks.
        //   DETECTION: Any `xxxReadOk = false` across two consecutive
        //              samples surfaces as MonitoringDegraded. Two-sample
        //              debounce prevents single-block
        //              RPC blips from auto-pausing the protocol.
        if (_degraded(current) && _degraded(previous)) {
            return _emit(
                ThreatType.MonitoringDegraded,
                current,
                previous,
                abi.encode(
                    current.balancesReadOk,  current.baselineReadOk,  current.eventReadOk,
                    previous.balancesReadOk, previous.baselineReadOk, previous.eventReadOk
                )
            );
        }

        // VECTOR 2 — OutlierWithdrawal (single-snapshot, baseline-gated).
        //   At block 14442835: largestWithdrawalWeth = 173,600e18 ≫ Tier-3
        //   threshold (4,000e18) → FIRES on a SINGLE snapshot.
        if (current.baselineConfigured && current.eventReadOk) {
            if (
                current.outlierThresholdWeth > 0 &&
                current.largestWithdrawalWeth >= current.outlierThresholdWeth
            ) {
                return _emit(
                    ThreatType.OutlierWithdrawal,
                    current,
                    previous,
                    abi.encode(
                        WETH_TOKEN_TAG,
                        current.largestWithdrawalWeth,
                        current.outlierThresholdWeth
                    )
                );
            }
            if (
                current.outlierThresholdUsdc > 0 &&
                current.largestWithdrawalUsdc >= current.outlierThresholdUsdc
            ) {
                return _emit(
                    ThreatType.OutlierWithdrawal,
                    current,
                    previous,
                    abi.encode(
                        USDC_TOKEN_TAG,
                        current.largestWithdrawalUsdc,
                        current.outlierThresholdUsdc
                    )
                );
            }
        }

        // VECTOR 3 — BridgeTVLDrain (block-over-block aggregate diff).
        //   EXPLOIT: At block 14442835 the bridge's WETH balance collapsed
        //            by 173,600 WETH in a single block — a ~50% drop in
        //            aggregate bridge value. Any future drain that
        //            sidesteps the OutlierWithdrawal event path (e.g.
        //            an attack that doesn't emit TokenWithdrew) still
        //            shows up as a balance state change here.
        //   DETECTION: Compare aggregate value (WETH-equivalent units)
        //              current vs previous; fire when drop exceeds the
        //              governance-attested basis-point threshold.
        //   Gated on previous.balancesReadOk so a recovering RPC after a
        //   degraded window cannot look like a drain.
        if (
            current.balancesReadOk &&
            previous.balancesReadOk &&
            previous.aggregateValueTU > 0 &&
            current.aggregateValueTU < previous.aggregateValueTU &&
            current.tvlDropBps > 0
        ) {
            uint256 drop = previous.aggregateValueTU - current.aggregateValueTU;
            uint256 dropBps = (drop * BPS) / previous.aggregateValueTU;
            if (dropBps >= current.tvlDropBps) {
                return _emit(
                    ThreatType.BridgeTVLDrain,
                    current,
                    previous,
                    abi.encode(
                        previous.aggregateValueTU,
                        current.aggregateValueTU,
                        dropBps,
                        current.tvlDropBps
                    )
                );
            }
        }

        // VECTOR 4 — CumulativeWithdrawal (window aggregation).
        //   EXPLOIT: Tx 1 (173,600 WETH, block 14442835) + Tx 2 (25.5M USDC,
        //            block 14442840) → cumulative outflow over the 10-block
        //            window is orders of magnitude beyond the V2-audited
        //            $50M-daily cap pro-rated to a 10-block window
        //            (~69k USDC equivalent). Drosera consensus on tx 1
        //            would have paused the bridge 5 blocks before tx 2.
        //   DETECTION: Sum `blockWithdrawalSum*` across all samples,
        //              compare to the per-token window caps embedded from
        //              the governance feeder. Each snapshot carries the
        //              same `windowCap*` (governance policy), so we read
        //              from `current`.
        if (current.baselineConfigured) {
            uint256 sumW = current.blockWithdrawalSumWeth;
            uint256 sumU = current.blockWithdrawalSumUsdc;
            for (uint256 i = 1; i < data.length; i++) {
                Snapshot memory s = _decodeSnapshot(data[i]);
                sumW += s.blockWithdrawalSumWeth;
                sumU += s.blockWithdrawalSumUsdc;
            }
            if (
                (current.windowCapWeth > 0 && sumW >= current.windowCapWeth) ||
                (current.windowCapUsdc > 0 && sumU >= current.windowCapUsdc)
            ) {
                return _emit(
                    ThreatType.CumulativeWithdrawal,
                    current,
                    previous,
                    abi.encode(
                        sumW, sumU,
                        current.windowCapWeth, current.windowCapUsdc,
                        data.length
                    )
                );
            }
        }

        return (false, "");
    }

    // ────────────────────────────────────────────────────────────────────────
    // Token tags for incident details
    // ────────────────────────────────────────────────────────────────────────

    bytes32 internal constant WETH_TOKEN_TAG =
        bytes32(uint256(uint160(TrapDeployConfig.WETH)));
    bytes32 internal constant USDC_TOKEN_TAG =
        bytes32(uint256(uint160(TrapDeployConfig.USDC)));

    // ────────────────────────────────────────────────────────────────────────
    // Internals — collect() helpers
    // ────────────────────────────────────────────────────────────────────────

    /// @dev `_safeBalanceOf` returns an explicit ok flag so a failed read
    ///      never masquerades as a legitimate zero balance and never
    ///      contaminates aggregate-drop checks.
    function _safeBalanceOf(address token, address account)
        internal
        view
        returns (bool ok, uint256 bal)
    {
        if (token == address(0)) return (true, 0);
        uint256 size;
        assembly { size := extcodesize(token) }
        if (size == 0) return (false, 0);

        try IERC20Like(token).balanceOf(account) returns (uint256 b) {
            return (true, b);
        } catch {
            return (false, 0);
        }
    }

    function _readBaseline(address bridge)
        internal
        view
        returns (bool ok, IBaselineFeederLike.BridgePolicy memory p)
    {
        address feeder = BASELINE_FEEDER();
        uint256 size;
        assembly { size := extcodesize(feeder) }
        if (size == 0) return (false, p);

        try IBaselineFeederLike(feeder).getBridgePolicy(bridge) returns (
            IBaselineFeederLike.BridgePolicy memory out
        ) {
            return (true, out);
        } catch {
            return (false, p);
        }
    }

    /// @dev Coarse but monotonic: aggregate WETH-equivalent value used for
    ///      the BridgeTVLDrain relative-drop check. If `wethPerUsdc` is zero
    ///      (governance hasn't rotated yet), fall back to raw-sum which is
    ///      still monotonic for relative-drop math even if the magnitudes
    ///      aren't directly meaningful.
    function _aggregateValue(uint256 wethBal, uint256 usdcBal, uint256 wethPerUsdc)
        internal
        pure
        returns (uint256)
    {
        if (wethPerUsdc == 0) {
            // Best-effort fallback. Both balances contribute proportionally
            // (USDC normalised to its own units; the trap simply tracks
            // relative drop, so a uniform fallback is acceptable).
            return wethBal + usdcBal;
        }
        // wethPerUsdc is a Q-fixed-point ratio scaled by 1e18; converting
        // USDC (6 decimals) to WETH (18 decimals) preserves precision.
        return wethBal + (usdcBal * wethPerUsdc) / 1e6;
    }

    /// @dev Scan the operator-supplied event-log buffer for matching
    ///      `TokenWithdrew` events from the bridge. Parses topics + data with
    ///      defensive length checks; any malformed log flips `eventReadOk` to
    ///      false but never reverts.
    function _scanWithdrawals()
        internal
        view
        returns (
            bool ok,
            uint256 maxWeth,
            uint256 maxUsdc,
            uint256 sumWeth,
            uint256 sumUsdc,
            uint256 count
        )
    {
        EventLog[] memory logs   = getEventLogs();
        EventFilter[] memory fs  = eventLogFilters();
        if (fs.length == 0) {
            // Trap misconfigured at compile time — treat as visibility loss.
            return (false, 0, 0, 0, 0, 0);
        }
        EventFilter memory filter = fs[0];
        bytes32 expectedTopic0 = EventFilterLib.topic0(filter);
        address wethAddr = WETH();
        address usdcAddr = USDC();
        bool allParsed = true;

        for (uint256 i = 0; i < logs.length; i++) {
            EventLog memory log = logs[i];

            // Filter by emitter + topic0.
            if (log.emitter != filter.contractAddress) continue;
            if (log.topics.length == 0 || log.topics[0] != expectedTopic0) continue;

            // Defensive shape check — TokenWithdrew has 4 topics (incl. sig)
            // and 32 bytes of data (single uint256).
            if (log.topics.length != 4 || log.data.length != 32) {
                allParsed = false;
                continue;
            }

            address token = address(uint160(uint256(log.topics[3])));
            uint256 amount;
            // Parse non-indexed amount.
            bytes memory d = log.data;
            assembly {
                amount := mload(add(d, 0x20))
            }

            if (token == wethAddr) {
                sumWeth += amount;
                if (amount > maxWeth) maxWeth = amount;
                count += 1;
            } else if (token == usdcAddr) {
                sumUsdc += amount;
                if (amount > maxUsdc) maxUsdc = amount;
                count += 1;
            }
            // Other tokens are ignored — outside the trap's scope.
        }

        ok = allParsed;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Internals — shouldRespond() helpers
    // ────────────────────────────────────────────────────────────────────────

    /// @dev `_degraded` does NOT include `baselineConfigured` because that
    ///      is a deliberate operator choice (governance hasn't opted in yet),
    ///      not a visibility failure.
    function _degraded(Snapshot memory s) internal pure returns (bool) {
        return (!s.balancesReadOk || !s.baselineReadOk || !s.eventReadOk);
    }

    function _emit(
        ThreatType threatType,
        Snapshot memory current,
        Snapshot memory previous,
        bytes memory details
    ) internal pure returns (bool, bytes memory) {
        return (
            true,
            abi.encode(
                IncidentPayload({
                    threatType:          threatType,
                    bridge:              current.bridge,
                    currentBlockNumber:  current.blockNumber,
                    previousBlockNumber: previous.blockNumber,
                    details:             details
                })
            )
        );
    }

    /// @dev Malformed-bytes-safe decode. Snapshot has no
    ///      dynamic fields so its encoding length is fixed; any other length
    ///      yields a zero snapshot rather than a revert.
    function _decodeSnapshot(bytes calldata raw)
        internal
        pure
        returns (Snapshot memory s)
    {
        if (raw.length != ENCODED_SNAPSHOT_LEN) return s;

        assembly {
            let p := raw.offset
            // 0  bridge
            mstore(s,                       calldataload(add(p, 0x000)))
            // 1  blockNumber
            mstore(add(s, 0x020),           calldataload(add(p, 0x020)))
            // 2  balancesReadOk
            mstore(add(s, 0x040), iszero(iszero(calldataload(add(p, 0x040)))))
            // 3  baselineReadOk
            mstore(add(s, 0x060), iszero(iszero(calldataload(add(p, 0x060)))))
            // 4  baselineConfigured
            mstore(add(s, 0x080), iszero(iszero(calldataload(add(p, 0x080)))))
            // 5  eventReadOk
            mstore(add(s, 0x0a0), iszero(iszero(calldataload(add(p, 0x0a0)))))
            // 6  wethBalance
            mstore(add(s, 0x0c0),           calldataload(add(p, 0x0c0)))
            // 7  usdcBalance
            mstore(add(s, 0x0e0),           calldataload(add(p, 0x0e0)))
            // 8  aggregateValueTU
            mstore(add(s, 0x100),           calldataload(add(p, 0x100)))
            // 9  largestWithdrawalWeth
            mstore(add(s, 0x120),           calldataload(add(p, 0x120)))
            // 10 largestWithdrawalUsdc
            mstore(add(s, 0x140),           calldataload(add(p, 0x140)))
            // 11 blockWithdrawalSumWeth
            mstore(add(s, 0x160),           calldataload(add(p, 0x160)))
            // 12 blockWithdrawalSumUsdc
            mstore(add(s, 0x180),           calldataload(add(p, 0x180)))
            // 13 outlierThresholdWeth
            mstore(add(s, 0x1a0),           calldataload(add(p, 0x1a0)))
            // 14 outlierThresholdUsdc
            mstore(add(s, 0x1c0),           calldataload(add(p, 0x1c0)))
            // 15 windowCapWeth
            mstore(add(s, 0x1e0),           calldataload(add(p, 0x1e0)))
            // 16 windowCapUsdc
            mstore(add(s, 0x200),           calldataload(add(p, 0x200)))
            // 17 tvlDropBps
            mstore(add(s, 0x220),           calldataload(add(p, 0x220)))
            // 18 withdrawalEventCount
            mstore(add(s, 0x240),           calldataload(add(p, 0x240)))
        }
    }
}
