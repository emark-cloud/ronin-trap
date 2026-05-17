// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BaselineFeeder
/// @notice Governance-owned bridge policy registry. Stores per-bridge
///         withdrawal limits, TVL-drop thresholds, and a token-price ratio
///         used to normalise multi-asset bridge value into a single token
///         unit for TVL-drop comparisons.
/// @dev    Exists because `pure shouldRespond` cannot read contract state.
///         The trap reads this in `collect()` and embeds the policy values
///         into every Snapshot so `shouldRespond` can consume them from the
///         sample bytes (BaselineFeeder pattern).
///
///         Rotation happens via `setBridgePolicy(...)` behind a governance
///         multisig + timelock. No trap redeploy is required to roll
///         thresholds as token prices move.
contract BaselineFeeder {
    // ────────────────────────────────────────────────────────────────────────
    // Types
    // ────────────────────────────────────────────────────────────────────────

    struct BridgePolicy {
        address bridge;                  // sanity binding — the bridge this policy applies to
        uint256 outlierThresholdWeth;    // single-tx outlier (token units, 1e18)
        uint256 outlierThresholdUsdc;    // single-tx outlier (token units, 1e6)
        uint256 windowCapWeth;           // cumulative cap across the trap's sample window
        uint256 windowCapUsdc;           // cumulative cap across the trap's sample window
        uint256 tvlDropBps;              // basis points; e.g. 2500 = 25%
        uint256 wethPerUsdc;             // Q18 fixed-point — WETH per 1 USDC unit
        bool    configured;              // governance must opt-in before absolute checks fire
    }

    // ────────────────────────────────────────────────────────────────────────
    // Storage
    // ────────────────────────────────────────────────────────────────────────

    address public owner;
    mapping(address bridge => BridgePolicy) internal _policies;

    // ────────────────────────────────────────────────────────────────────────
    // Events
    // ────────────────────────────────────────────────────────────────────────

    event OwnerTransferred(address indexed previousOwner, address indexed newOwner);
    event BridgePolicySet(
        address indexed bridge,
        uint256 outlierThresholdWeth,
        uint256 outlierThresholdUsdc,
        uint256 windowCapWeth,
        uint256 windowCapUsdc,
        uint256 tvlDropBps,
        uint256 wethPerUsdc
    );
    event BridgePolicyCleared(address indexed bridge);

    // ────────────────────────────────────────────────────────────────────────
    // Modifiers
    // ────────────────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "BaselineFeeder/not-owner");
        _;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Construction
    // ────────────────────────────────────────────────────────────────────────

    constructor(address initialOwner) {
        require(initialOwner != address(0), "BaselineFeeder/zero-owner");
        owner = initialOwner;
        emit OwnerTransferred(address(0), initialOwner);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Admin
    // ────────────────────────────────────────────────────────────────────────

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "BaselineFeeder/zero-owner");
        emit OwnerTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Set or update the policy for a bridge. Marks it as configured.
    /// @dev    All non-zero numeric inputs are accepted as-is; governance owns
    ///         the responsibility for sensible thresholds. `wethPerUsdc` must
    ///         be > 0 to avoid division-style traps downstream (the trap
    ///         tolerates zero gracefully but absolute TVL checks would be
    ///         useless).
    function setBridgePolicy(
        address bridge,
        uint256 outlierThresholdWeth,
        uint256 outlierThresholdUsdc,
        uint256 windowCapWeth,
        uint256 windowCapUsdc,
        uint256 tvlDropBps,
        uint256 wethPerUsdc
    ) external onlyOwner {
        require(bridge != address(0), "BaselineFeeder/zero-bridge");
        require(tvlDropBps <= 10_000, "BaselineFeeder/bps-overflow");

        _policies[bridge] = BridgePolicy({
            bridge:                 bridge,
            outlierThresholdWeth:   outlierThresholdWeth,
            outlierThresholdUsdc:   outlierThresholdUsdc,
            windowCapWeth:          windowCapWeth,
            windowCapUsdc:          windowCapUsdc,
            tvlDropBps:             tvlDropBps,
            wethPerUsdc:            wethPerUsdc,
            configured:             true
        });

        emit BridgePolicySet(
            bridge,
            outlierThresholdWeth,
            outlierThresholdUsdc,
            windowCapWeth,
            windowCapUsdc,
            tvlDropBps,
            wethPerUsdc
        );
    }

    /// @notice Clear a bridge policy. Absolute checks will skip; relative
    ///         checks (block-over-block diffs) still operate via the trap.
    function clearBridgePolicy(address bridge) external onlyOwner {
        delete _policies[bridge];
        emit BridgePolicyCleared(bridge);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Reads
    // ────────────────────────────────────────────────────────────────────────

    /// @notice Read the policy for a bridge. Returns a zero-initialised
    ///         struct with `configured == false` if no policy is set.
    function getBridgePolicy(address bridge)
        external
        view
        returns (BridgePolicy memory)
    {
        return _policies[bridge];
    }
}
