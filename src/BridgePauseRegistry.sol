// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IEmergencyActionTarget
/// @notice Interface every downstream emergency-pause guardian must implement.
/// @dev    The responder calls `emergencyPause(rawPayload)` via try/catch so
///         a single misbehaving target cannot prevent fan-out to the others.
interface IEmergencyActionTarget {
    function emergencyPause(bytes calldata incidentPayload) external;
}

/// @title BridgePauseRegistry
/// @notice Governance-owned bounded allowlist of approved emergency-pause
///         targets. The responder fans incidents out to every approved
///         target up to a hard cap.
/// @dev    Guardian-registry pattern, renamed for the bridge domain. Two
///         subtleties carried over:
///
///         1. `MAX_TARGETS` bounds fan-out gas so an unbounded list cannot
///            become gas-fragile at the exact moment of an incident.
///         2. The `_seen` insertion flag prevents a `revoke → re-approve`
///            cycle from pushing the same address into `targets[]` twice,
///            which would cause duplicate downstream calls.
contract BridgePauseRegistry {
    uint256 public constant MAX_TARGETS = 16;

    address public owner;
    mapping(address target => bool) public approvedTargets;
    mapping(address target => bool) internal _seen;
    address[] public targets;

    event OwnerTransferred(address indexed previousOwner, address indexed newOwner);
    event TargetSet(address indexed target, bool approved);

    modifier onlyOwner() {
        require(msg.sender == owner, "BridgePauseRegistry/not-owner");
        _;
    }

    constructor(address initialOwner) {
        require(initialOwner != address(0), "BridgePauseRegistry/zero-owner");
        owner = initialOwner;
        emit OwnerTransferred(address(0), initialOwner);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "BridgePauseRegistry/zero-owner");
        emit OwnerTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Approve or revoke a target. First-time approvals are appended
    ///         to `targets[]` and gated by `MAX_TARGETS`. A re-approval after
    ///         revoke flips the `approvedTargets` flag without re-pushing.
    function setTarget(address target, bool approved) external onlyOwner {
        require(target != address(0), "BridgePauseRegistry/zero-target");

        if (!_seen[target]) {
            require(targets.length < MAX_TARGETS, "BridgePauseRegistry/max-targets");
            _seen[target] = true;
            targets.push(target);
        }
        approvedTargets[target] = approved;
        emit TargetSet(target, approved);
    }

    function targetsLength() external view returns (uint256) {
        return targets.length;
    }

    function getTargets() external view returns (address[] memory) {
        return targets;
    }
}
