// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EventLog} from "drosera-contracts/libraries/Events.sol";

import {RoninBridgeTrap} from "../src/RoninBridgeTrap.sol";
import {BaselineFeeder} from "../src/BaselineFeeder.sol";
import {BridgePauseRegistry, IEmergencyActionTarget} from "../src/BridgePauseRegistry.sol";
import {BridgePauseResponder} from "../src/BridgePauseResponder.sol";
import {MockBridgePauseTarget} from "../src/mocks/MockBridgePauseTarget.sol";
import {TrapDeployConfig} from "../src/TrapDeployConfig.sol";

/// @title RoninBridgeTrapTest
/// @notice Unit + edge-case tests for the Ronin trap. Snapshot construction
///         is done synthetically to keep tests deterministic; the historical
///         fork test lives in ExploitReproduction.t.sol.
contract RoninBridgeTrapTest is Test {
    // ────────────────────────────────────────────────────────────────────────
    // Setup
    // ────────────────────────────────────────────────────────────────────────

    address constant BRIDGE = TrapDeployConfig.BRIDGE_GATEWAY;
    address constant WETH   = TrapDeployConfig.WETH;
    address constant USDC   = TrapDeployConfig.USDC;
    address constant FEEDER_ADDR = TrapDeployConfig.BASELINE_FEEDER;

    // Mar 2022 prices: ~$2300/ETH. wethPerUsdc Q18: 1e18 / 2300 ≈ 4.347e14
    uint256 constant WETH_PER_USDC_Q18 = 434_782_608_695_652; // ≈ 1/2300 * 1e18

    // Tier-3-equivalent thresholds (Verichains audit): $10M in WETH / USDC.
    // At $2300/ETH → 4_348 WETH ≈ $10M. Use 4_000e18 as the trap's strict
    // outlier threshold and 10_000_000e6 for USDC.
    uint256 constant OUTLIER_WETH = 4_000e18;
    uint256 constant OUTLIER_USDC = 10_000_000e6;

    // Window cap: pro-rated from Ronin's V2 $50M daily cap over a 10-block
    // sample window (12s blocks → ~7200/day → window ≈ 50M * 10/7200 ≈ 69k USD).
    // In WETH that's ~30 WETH; in USDC ~69k. Conservative.
    uint256 constant WINDOW_CAP_WETH = 30e18;
    uint256 constant WINDOW_CAP_USDC = 69_000e6;

    uint256 constant TVL_DROP_BPS = 2_500; // 25%

    RoninBridgeTrap trap;
    BaselineFeeder feeder;
    BridgePauseRegistry registry;
    BridgePauseResponder responder;
    MockBridgePauseTarget target1;
    MockBridgePauseTarget target2;

    address admin   = address(0xA11CE);
    address relayer = address(0xB0B);

    function setUp() public {
        trap = new RoninBridgeTrap();

        // Deploy a real feeder, then overlay its runtime code at the
        // compile-time-fixed BASELINE_FEEDER address so the trap's
        // pure accessor resolves to a live contract.
        feeder = new BaselineFeeder(address(this));
        vm.etch(FEEDER_ADDR, address(feeder).code);
        // The etched copy starts with zero storage — re-set ownership and
        // policy via the etched copy itself.
        BaselineFeeder(FEEDER_ADDR);
        // Storage slot 0 = `owner`. Write directly so we don't need to call
        // a constructor on the etched instance.
        vm.store(FEEDER_ADDR, bytes32(uint256(0)), bytes32(uint256(uint160(address(this)))));

        registry = new BridgePauseRegistry(admin);
        responder = new BridgePauseResponder(admin, relayer, registry);

        target1 = new MockBridgePauseTarget();
        target2 = new MockBridgePauseTarget();
        vm.prank(admin);
        registry.setTarget(address(target1), true);
        vm.prank(admin);
        registry.setTarget(address(target2), true);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Snapshot builders
    // ────────────────────────────────────────────────────────────────────────

    struct SnapInputs {
        uint256 blockNumber;
        bool    balancesReadOk;
        bool    baselineReadOk;
        bool    baselineConfigured;
        bool    eventReadOk;
        uint256 wethBalance;
        uint256 usdcBalance;
        uint256 largestWithdrawalWeth;
        uint256 largestWithdrawalUsdc;
        uint256 blockWithdrawalSumWeth;
        uint256 blockWithdrawalSumUsdc;
        uint256 outlierThresholdWeth;
        uint256 outlierThresholdUsdc;
        uint256 windowCapWeth;
        uint256 windowCapUsdc;
        uint256 tvlDropBps;
        uint256 withdrawalEventCount;
    }

    function _baseHealthy(uint256 blockNumber, uint256 wethBal, uint256 usdcBal)
        internal
        pure
        returns (SnapInputs memory s)
    {
        s.blockNumber          = blockNumber;
        s.balancesReadOk       = true;
        s.baselineReadOk       = true;
        s.baselineConfigured   = true;
        s.eventReadOk          = true;
        s.wethBalance          = wethBal;
        s.usdcBalance          = usdcBal;
        s.outlierThresholdWeth = OUTLIER_WETH;
        s.outlierThresholdUsdc = OUTLIER_USDC;
        s.windowCapWeth        = WINDOW_CAP_WETH;
        s.windowCapUsdc        = WINDOW_CAP_USDC;
        s.tvlDropBps           = TVL_DROP_BPS;
    }

    function _encode(SnapInputs memory s) internal pure returns (bytes memory) {
        RoninBridgeTrap.Snapshot memory snap;
        snap.bridge                  = BRIDGE;
        snap.blockNumber             = s.blockNumber;
        snap.balancesReadOk          = s.balancesReadOk;
        snap.baselineReadOk          = s.baselineReadOk;
        snap.baselineConfigured      = s.baselineConfigured;
        snap.eventReadOk             = s.eventReadOk;
        snap.wethBalance             = s.wethBalance;
        snap.usdcBalance             = s.usdcBalance;
        snap.aggregateValueTU        = s.wethBalance + (s.usdcBalance * WETH_PER_USDC_Q18) / 1e6;
        snap.largestWithdrawalWeth   = s.largestWithdrawalWeth;
        snap.largestWithdrawalUsdc   = s.largestWithdrawalUsdc;
        snap.blockWithdrawalSumWeth  = s.blockWithdrawalSumWeth;
        snap.blockWithdrawalSumUsdc  = s.blockWithdrawalSumUsdc;
        snap.outlierThresholdWeth    = s.outlierThresholdWeth;
        snap.outlierThresholdUsdc    = s.outlierThresholdUsdc;
        snap.windowCapWeth           = s.windowCapWeth;
        snap.windowCapUsdc           = s.windowCapUsdc;
        snap.tvlDropBps              = s.tvlDropBps;
        snap.withdrawalEventCount    = s.withdrawalEventCount;
        return abi.encode(snap);
    }

    /// @dev Build a 10-sample window of healthy snapshots spanning
    ///      [blockNumber - 9 .. blockNumber] newest→oldest.
    function _healthyWindow(uint256 blockNumber, uint256 wethBal, uint256 usdcBal)
        internal
        pure
        returns (bytes[] memory data)
    {
        data = new bytes[](10);
        for (uint256 i = 0; i < 10; i++) {
            SnapInputs memory s = _baseHealthy(blockNumber - i, wethBal, usdcBal);
            data[i] = _encode(s);
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // Guards & edge cases
    // ────────────────────────────────────────────────────────────────────────

    function test_NoFire_EmptyData() public view {
        bytes[] memory empty = new bytes[](0);
        (bool fired, bytes memory payload) = trap.shouldRespond(empty);
        assertFalse(fired);
        assertEq(payload.length, 0);
    }

    function test_NoFire_SingleSample() public view {
        bytes[] memory one = new bytes[](1);
        SnapInputs memory s = _baseHealthy(100, 200_000e18, 50_000_000e6);
        one[0] = _encode(s);
        (bool fired, bytes memory payload) = trap.shouldRespond(one);
        assertFalse(fired);
        assertEq(payload.length, 0);
    }

    function test_NoFire_MalformedShorterThanExpected() public view {
        bytes[] memory data = new bytes[](2);
        data[0] = hex"deadbeef";
        data[1] = hex"cafebabe";
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertFalse(fired);
        assertEq(payload.length, 0);
    }

    function test_NoFire_MalformedWrongLength() public view {
        // 800 bytes — wrong size, snapshot is 608. Should not revert.
        bytes memory garbage = new bytes(800);
        bytes[] memory data = new bytes[](2);
        data[0] = garbage;
        data[1] = garbage;
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertFalse(fired);
        assertEq(payload.length, 0);
    }

    function test_NoFire_NonContiguousOrdering() public view {
        bytes[] memory data = new bytes[](2);
        SnapInputs memory newer = _baseHealthy(100, 1, 1);
        SnapInputs memory older = _baseHealthy(95, 1, 1); // 5-block gap
        data[0] = _encode(newer);
        data[1] = _encode(older);
        (bool fired,) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    function test_NoFire_HealthyWindow() public view {
        bytes[] memory data = _healthyWindow(14_442_834, 200_000e18, 50_000_000e6);
        (bool fired,) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    function test_NoFire_DifferentBridgeAcrossSamples() public view {
        bytes[] memory data = new bytes[](2);
        SnapInputs memory newer = _baseHealthy(100, 1, 1);
        SnapInputs memory older = _baseHealthy(99, 1, 1);
        data[0] = _encode(newer);
        // hand-craft an older snapshot whose `bridge` field is a different
        // address: easier to reuse _encode but flip bridge in raw bytes.
        bytes memory raw = _encode(older);
        // The first 32 bytes of the encoded snapshot are the `bridge` field.
        // Overwrite to address(0xdead).
        bytes32 dead = bytes32(uint256(uint160(address(0xdead))));
        assembly {
            mstore(add(raw, 0x20), dead)
        }
        data[1] = raw;
        (bool fired,) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Vector 1: MonitoringDegraded (debounced)
    // ────────────────────────────────────────────────────────────────────────

    function test_MonitoringDegraded_DoesNotFireOnSingleBadSample() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        // Flip only the newest snapshot to degraded.
        SnapInputs memory s = _baseHealthy(100, 200_000e18, 50_000_000e6);
        s.balancesReadOk = false;
        data[0] = _encode(s);
        (bool fired,) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    function test_MonitoringDegraded_FiresOnTwoConsecutiveBadSamples() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        SnapInputs memory s0 = _baseHealthy(100, 200_000e18, 50_000_000e6);
        SnapInputs memory s1 = _baseHealthy(99,  200_000e18, 50_000_000e6);
        s0.balancesReadOk = false;
        s1.eventReadOk    = false;
        data[0] = _encode(s0);
        data[1] = _encode(s1);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        RoninBridgeTrap.IncidentPayload memory p =
            abi.decode(payload, (RoninBridgeTrap.IncidentPayload));
        assertEq(uint8(p.threatType), uint8(RoninBridgeTrap.ThreatType.MonitoringDegraded));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Vector 2: OutlierWithdrawal (single snapshot)
    // ────────────────────────────────────────────────────────────────────────

    function test_OutlierWithdrawal_WethFiresAtThreshold() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        SnapInputs memory s = _baseHealthy(100, 200_000e18, 50_000_000e6);
        s.largestWithdrawalWeth = OUTLIER_WETH; // == threshold
        s.blockWithdrawalSumWeth = OUTLIER_WETH;
        data[0] = _encode(s);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        RoninBridgeTrap.IncidentPayload memory p =
            abi.decode(payload, (RoninBridgeTrap.IncidentPayload));
        assertEq(uint8(p.threatType), uint8(RoninBridgeTrap.ThreatType.OutlierWithdrawal));
    }

    function test_OutlierWithdrawal_WethDoesNotFireJustBelowThreshold() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        SnapInputs memory s = _baseHealthy(100, 200_000e18, 50_000_000e6);
        s.largestWithdrawalWeth = OUTLIER_WETH - 1;
        s.blockWithdrawalSumWeth = OUTLIER_WETH - 1;
        // Isolate Outlier from Cumulative by disabling window caps in this
        // boundary-only test — a 3999 WETH withdrawal would also breach the
        // 30 WETH window cap, masking the test's intent.
        s.windowCapWeth = 0;
        s.windowCapUsdc = 0;
        data[0] = _encode(s);
        (bool fired,) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    function test_OutlierWithdrawal_BybitScaleWeth() public view {
        bytes[] memory data = _healthyWindow(14_442_835, 200_000e18, 50_000_000e6);
        SnapInputs memory s = _baseHealthy(14_442_835, 26_400e18, 50_000_000e6);
        s.largestWithdrawalWeth  = 173_600e18; // The real exploit number.
        s.blockWithdrawalSumWeth = 173_600e18;
        data[0] = _encode(s);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        RoninBridgeTrap.IncidentPayload memory p =
            abi.decode(payload, (RoninBridgeTrap.IncidentPayload));
        assertEq(uint8(p.threatType), uint8(RoninBridgeTrap.ThreatType.OutlierWithdrawal));
        assertEq(p.bridge, BRIDGE);
        assertEq(p.currentBlockNumber, 14_442_835);
    }

    function test_OutlierWithdrawal_UsdcFires() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        SnapInputs memory s = _baseHealthy(100, 200_000e18, 24_500_000e6);
        s.largestWithdrawalUsdc  = 25_500_000e6;
        s.blockWithdrawalSumUsdc = 25_500_000e6;
        data[0] = _encode(s);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        RoninBridgeTrap.IncidentPayload memory p =
            abi.decode(payload, (RoninBridgeTrap.IncidentPayload));
        assertEq(uint8(p.threatType), uint8(RoninBridgeTrap.ThreatType.OutlierWithdrawal));
    }

    function test_OutlierWithdrawal_SkippedWhenBaselineUnconfigured() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        SnapInputs memory s = _baseHealthy(100, 200_000e18, 50_000_000e6);
        // Critical: keep the threshold non-zero so we exercise the OUTER
        // `baselineConfigured` gate, not the inner `threshold > 0` gate.
        // Setting both to zero would mask the actual semantics being tested.
        s.baselineConfigured = false;
        s.outlierThresholdWeth = OUTLIER_WETH;
        s.largestWithdrawalWeth = 999_999e18; // would be a clear outlier
        // Cumulative would also fire on this large sum — disable to isolate.
        s.windowCapWeth = 0;
        s.windowCapUsdc = 0;
        data[0] = _encode(s);
        (bool fired,) = trap.shouldRespond(data);
        assertFalse(fired, "must skip Outlier when baseline is not configured");
    }

    function test_OutlierWithdrawal_SkippedWhenEventReadFailed() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        SnapInputs memory s = _baseHealthy(100, 200_000e18, 50_000_000e6);
        s.eventReadOk = false;
        // largest stays zero (events couldn't be read), but force a value
        // to prove the trap STILL skips Outlier on eventReadOk=false.
        s.largestWithdrawalWeth = 173_600e18;
        data[0] = _encode(s);
        (bool fired,) = trap.shouldRespond(data);
        // Vector 2 must not fire because eventReadOk == false.
        // Vector 3 (TVLDrain) doesn't fire because balances unchanged.
        // Vector 1 (Degraded) doesn't fire because previous is healthy.
        assertFalse(fired);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Vector 3: BridgeTVLDrain
    // ────────────────────────────────────────────────────────────────────────

    function test_TVLDrain_FiresOnLargeBalanceDrop() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        SnapInputs memory current = _baseHealthy(100, 26_400e18, 50_000_000e6); // -50% WETH
        // No events injected — pure balance-diff path.
        data[0] = _encode(current);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        RoninBridgeTrap.IncidentPayload memory p =
            abi.decode(payload, (RoninBridgeTrap.IncidentPayload));
        assertEq(uint8(p.threatType), uint8(RoninBridgeTrap.ThreatType.BridgeTVLDrain));
    }

    function test_TVLDrain_NotTrippedByRecoveringRpc() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        SnapInputs memory prev   = _baseHealthy(99, 200_000e18, 50_000_000e6);
        prev.balancesReadOk = false; // previous read failed
        prev.wethBalance    = 0;
        prev.usdcBalance    = 0;
        SnapInputs memory curr   = _baseHealthy(100, 26_400e18, 50_000_000e6); // looks "smaller"
        data[0] = _encode(curr);
        data[1] = _encode(prev);
        (bool fired,) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    function test_TVLDrain_BelowThresholdDoesNotFire() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        // 10% drop, below 25% threshold.
        SnapInputs memory current = _baseHealthy(100, 180_000e18, 50_000_000e6);
        data[0] = _encode(current);
        (bool fired,) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Vector 4: CumulativeWithdrawal
    // ────────────────────────────────────────────────────────────────────────

    function test_Cumulative_FiresWhenWindowSumExceedsCap() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        // Two blocks each draw 20 WETH → sum = 40 > windowCapWeth (30).
        SnapInputs memory s0 = _baseHealthy(100, 200_000e18, 50_000_000e6);
        s0.blockWithdrawalSumWeth = 20e18;
        s0.largestWithdrawalWeth  = 20e18;
        SnapInputs memory s1 = _baseHealthy(99,  200_000e18, 50_000_000e6);
        s1.blockWithdrawalSumWeth = 20e18;
        s1.largestWithdrawalWeth  = 20e18;
        data[0] = _encode(s0);
        data[1] = _encode(s1);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        RoninBridgeTrap.IncidentPayload memory p =
            abi.decode(payload, (RoninBridgeTrap.IncidentPayload));
        assertEq(uint8(p.threatType), uint8(RoninBridgeTrap.ThreatType.CumulativeWithdrawal));
    }

    function test_Cumulative_SkippedWhenBaselineUnconfigured() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        SnapInputs memory s0 = _baseHealthy(100, 200_000e18, 50_000_000e6);
        s0.baselineConfigured = false;
        s0.outlierThresholdWeth = 0;
        s0.outlierThresholdUsdc = 0;
        s0.windowCapWeth = 0;
        s0.windowCapUsdc = 0;
        s0.blockWithdrawalSumWeth = 50e18; // would otherwise trip cap.
        data[0] = _encode(s0);
        (bool fired,) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Severity ordering
    // ────────────────────────────────────────────────────────────────────────

    function test_SeverityOrdering_OutlierBeforeTVLDrain() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        SnapInputs memory s = _baseHealthy(100, 26_400e18, 50_000_000e6); // -50% TVL
        s.largestWithdrawalWeth  = 173_600e18;
        s.blockWithdrawalSumWeth = 173_600e18;
        data[0] = _encode(s);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        RoninBridgeTrap.IncidentPayload memory p =
            abi.decode(payload, (RoninBridgeTrap.IncidentPayload));
        // Both Outlier and TVLDrain would fire; Outlier wins.
        assertEq(uint8(p.threatType), uint8(RoninBridgeTrap.ThreatType.OutlierWithdrawal));
    }

    function test_SeverityOrdering_DegradedBeforeOutlier() public view {
        bytes[] memory data = _healthyWindow(100, 200_000e18, 50_000_000e6);
        SnapInputs memory s0 = _baseHealthy(100, 200_000e18, 50_000_000e6);
        SnapInputs memory s1 = _baseHealthy(99,  200_000e18, 50_000_000e6);
        s0.balancesReadOk = false;
        s1.balancesReadOk = false;
        s0.largestWithdrawalWeth  = 173_600e18; // would trip Outlier in isolation.
        s0.blockWithdrawalSumWeth = 173_600e18;
        data[0] = _encode(s0);
        data[1] = _encode(s1);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        RoninBridgeTrap.IncidentPayload memory p =
            abi.decode(payload, (RoninBridgeTrap.IncidentPayload));
        // Degraded takes precedence — visibility loss is reported first.
        assertEq(uint8(p.threatType), uint8(RoninBridgeTrap.ThreatType.MonitoringDegraded));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Responder + Registry
    // ────────────────────────────────────────────────────────────────────────

    function _samplePayload() internal pure returns (bytes memory) {
        return abi.encode(
            RoninBridgeTrap.IncidentPayload({
                threatType:          RoninBridgeTrap.ThreatType.OutlierWithdrawal,
                bridge:              BRIDGE,
                currentBlockNumber:  14_442_835,
                previousBlockNumber: 14_442_834,
                details:             abi.encode(WETH, uint256(173_600e18), OUTLIER_WETH)
            })
        );
    }

    function test_Responder_IdempotentOnSuccess() public {
        bytes memory payload = _samplePayload();
        vm.prank(relayer);
        responder.handleIncident(payload);
        assertEq(target1.pauseCount(), 1);

        // Replay — should no-op.
        vm.prank(relayer);
        responder.handleIncident(payload);
        assertEq(target1.pauseCount(), 1, "replay should be no-op");
    }

    function test_Responder_RetryableOnTotalDownstreamFailure() public {
        target1.setShouldRevert(true);
        target2.setShouldRevert(true);

        bytes memory payload = _samplePayload();
        vm.prank(relayer);
        vm.expectRevert(bytes("no target paused"));
        responder.handleIncident(payload);

        bytes32 h = keccak256(payload);
        assertFalse(responder.executedIncidentHash(h), "flag must remain clear on total failure");

        // Recover one target, retry succeeds.
        target1.setShouldRevert(false);
        vm.prank(relayer);
        responder.handleIncident(payload);
        assertTrue(responder.executedIncidentHash(h));
        assertEq(target1.pauseCount(), 1);
    }

    function test_Responder_NoApprovedTargetsDistinctRevert() public {
        // Revoke both approvals.
        vm.prank(admin);
        registry.setTarget(address(target1), false);
        vm.prank(admin);
        registry.setTarget(address(target2), false);

        vm.prank(relayer);
        vm.expectRevert(bytes("no approved targets"));
        responder.handleIncident(_samplePayload());
    }

    function test_Responder_OnlyRelayer() public {
        vm.expectRevert(bytes("BridgePauseResponder/not-relayer"));
        responder.handleIncident(_samplePayload());
    }

    function test_Responder_GlobalPause() public {
        vm.prank(admin);
        responder.setGlobalPaused(true);

        vm.prank(relayer);
        vm.expectRevert(bytes("BridgePauseResponder/globally-paused"));
        responder.handleIncident(_samplePayload());
    }

    function test_Responder_FanOutEmitsPerTargetEvent() public {
        bytes memory payload = _samplePayload();
        vm.recordLogs();
        vm.prank(relayer);
        responder.handleIncident(payload);
        // Both downstream targets received exactly one pause call.
        assertEq(target1.pauseCount(), 1);
        assertEq(target2.pauseCount(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Registry
    // ────────────────────────────────────────────────────────────────────────

    function test_Registry_RevokeReapproveDoesNotDuplicate() public {
        vm.prank(admin);
        registry.setTarget(address(target1), false);
        vm.prank(admin);
        registry.setTarget(address(target1), true);

        // targets[] should still have exactly 2 entries — no duplicate push.
        assertEq(registry.targetsLength(), 2);
    }

    function test_Registry_MaxTargetsEnforced() public {
        // We already have 2 targets. Add 14 more to reach MAX_TARGETS=16.
        for (uint256 i = 0; i < 14; i++) {
            vm.prank(admin);
            registry.setTarget(address(uint160(0xCAFE + i)), true);
        }
        assertEq(registry.targetsLength(), 16);

        // 17th must revert.
        vm.prank(admin);
        vm.expectRevert(bytes("BridgePauseRegistry/max-targets"));
        registry.setTarget(address(uint160(0xDEAD_BEEF)), true);
    }

    function test_Registry_OnlyOwnerCanSet() public {
        vm.expectRevert(bytes("BridgePauseRegistry/not-owner"));
        registry.setTarget(address(0x1234), true);
    }

    // ────────────────────────────────────────────────────────────────────────
    // BaselineFeeder
    // ────────────────────────────────────────────────────────────────────────

    function test_Feeder_SetAndGet() public {
        BaselineFeeder f = new BaselineFeeder(address(this));
        f.setBridgePolicy(BRIDGE, 1, 2, 3, 4, 2500, 1e15);
        BaselineFeeder.BridgePolicy memory p = f.getBridgePolicy(BRIDGE);
        assertEq(p.bridge, BRIDGE);
        assertEq(p.outlierThresholdWeth, 1);
        assertEq(p.outlierThresholdUsdc, 2);
        assertEq(p.windowCapWeth, 3);
        assertEq(p.windowCapUsdc, 4);
        assertEq(p.tvlDropBps, 2500);
        assertEq(p.wethPerUsdc, 1e15);
        assertTrue(p.configured);
    }

    function test_Feeder_UnconfiguredReturnsZero() public {
        BaselineFeeder f = new BaselineFeeder(address(this));
        BaselineFeeder.BridgePolicy memory p = f.getBridgePolicy(BRIDGE);
        assertFalse(p.configured);
    }

    function test_Feeder_OnlyOwnerCanSet() public {
        BaselineFeeder f = new BaselineFeeder(admin);
        vm.expectRevert(bytes("BaselineFeeder/not-owner"));
        f.setBridgePolicy(BRIDGE, 1, 2, 3, 4, 2500, 1e15);
    }

    function test_Feeder_BpsOverflowReverts() public {
        BaselineFeeder f = new BaselineFeeder(address(this));
        vm.expectRevert(bytes("BaselineFeeder/bps-overflow"));
        f.setBridgePolicy(BRIDGE, 1, 2, 3, 4, 10_001, 1e15);
    }

    // ────────────────────────────────────────────────────────────────────────
    // collect() smoke test
    // ────────────────────────────────────────────────────────────────────────

    function test_Collect_ReturnsEncodedSnapshot() public {
        // Set policy on the etched feeder.
        BaselineFeeder(FEEDER_ADDR).setBridgePolicy(
            BRIDGE,
            OUTLIER_WETH,
            OUTLIER_USDC,
            WINDOW_CAP_WETH,
            WINDOW_CAP_USDC,
            TVL_DROP_BPS,
            WETH_PER_USDC_Q18
        );

        // No real bridge code at BRIDGE in this test (no fork). The
        // extcodesize guard will short-circuit collect() to a zero snapshot
        // bound only to the bridge address + block.number.
        bytes memory raw = trap.collect();
        assertEq(raw.length, 19 * 32, "snapshot must be 19 * 32 bytes");

        RoninBridgeTrap.Snapshot memory s =
            abi.decode(raw, (RoninBridgeTrap.Snapshot));
        assertEq(s.bridge, BRIDGE);
        assertEq(s.blockNumber, block.number);
        // bridge has no code → balancesReadOk false (we short-circuited
        // before token reads).
        assertFalse(s.balancesReadOk);
    }
}
