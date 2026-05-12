// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IEmergencyActionTarget} from "../BridgePauseRegistry.sol";

/// @title MockBridgePauseTarget
/// @notice Test double for a downstream emergency-pause guardian.
///         Records every call and exposes a revert switch so retry/idempotency
///         tests can simulate downstream failure → recovery.
contract MockBridgePauseTarget is IEmergencyActionTarget {
    bool public shouldRevert;
    uint256 public pauseCount;
    bytes public lastPayload;

    event Paused(bytes payload);

    function setShouldRevert(bool v) external {
        shouldRevert = v;
    }

    function emergencyPause(bytes calldata incidentPayload) external override {
        if (shouldRevert) {
            revert("MockBridgePauseTarget/forced-revert");
        }
        pauseCount += 1;
        lastPayload = incidentPayload;
        emit Paused(incidentPayload);
    }
}
