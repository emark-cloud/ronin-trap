// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BridgePauseRegistry, IEmergencyActionTarget} from "./BridgePauseRegistry.sol";

/// @title BridgePauseResponder
/// @notice Idempotent on-chain incident handler. The Drosera relayer calls
///         `handleIncident(rawPayload)` once 2/3 BLS consensus is achieved on
///         a triggering `shouldRespond` result. The responder dedupes by
///         payload hash and fans out to every approved emergency-pause
///         target in the registry.
/// @dev    Idempotent execution, retryable on total
///         downstream failure, distinct revert reasons for misconfiguration
///         vs downstream brokenness.
///
///         CAVEAT (documented in README): the responder cannot directly call
///         `pause()` on Ronin's V1 MainchainGateway because Drosera holds no
///         role on that contract. The registry's approved targets are
///         governance-pre-deployed pause proxies that DO hold the role. For
///         tests we ship MockBridgePauseTarget.
contract BridgePauseResponder {
    // ────────────────────────────────────────────────────────────────────────
    // Roles
    // ────────────────────────────────────────────────────────────────────────

    address public admin;
    address public relayer;
    BridgePauseRegistry public immutable registry;

    bool    public globalPaused;
    mapping(bytes32 incidentHash => bool) public executedIncidentHash;
    uint256 public incidentCount;

    // ────────────────────────────────────────────────────────────────────────
    // Events
    // ────────────────────────────────────────────────────────────────────────

    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);
    event RelayerSet(address indexed previousRelayer, address indexed newRelayer);
    event GlobalPauseSet(bool paused);
    event DownstreamPauseAttempt(address indexed target, bool success);
    event IncidentHandled(
        bytes32 indexed incidentHash,
        uint8 threatType,
        address bridge,
        uint256 currentBlockNumber,
        uint256 previousBlockNumber,
        uint256 attemptedCount,
        uint256 successCount
    );

    // ────────────────────────────────────────────────────────────────────────
    // Modifiers
    // ────────────────────────────────────────────────────────────────────────

    modifier onlyAdmin() {
        require(msg.sender == admin, "BridgePauseResponder/not-admin");
        _;
    }

    modifier onlyRelayer() {
        require(msg.sender == relayer, "BridgePauseResponder/not-relayer");
        _;
    }

    modifier whenNotGlobalPaused() {
        require(!globalPaused, "BridgePauseResponder/globally-paused");
        _;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Construction
    // ────────────────────────────────────────────────────────────────────────

    constructor(address initialAdmin, address initialRelayer, BridgePauseRegistry registry_) {
        require(initialAdmin != address(0), "BridgePauseResponder/zero-admin");
        require(initialRelayer != address(0), "BridgePauseResponder/zero-relayer");
        require(address(registry_) != address(0), "BridgePauseResponder/zero-registry");

        admin    = initialAdmin;
        relayer  = initialRelayer;
        registry = registry_;

        emit AdminTransferred(address(0), initialAdmin);
        emit RelayerSet(address(0), initialRelayer);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Admin
    // ────────────────────────────────────────────────────────────────────────

    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "BridgePauseResponder/zero-admin");
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    function setRelayer(address newRelayer) external onlyAdmin {
        require(newRelayer != address(0), "BridgePauseResponder/zero-relayer");
        emit RelayerSet(relayer, newRelayer);
        relayer = newRelayer;
    }

    /// @notice Kill-switch for false-positive storms. When `globalPaused`,
    ///         further incidents are rejected outright.
    function setGlobalPaused(bool paused) external onlyAdmin {
        globalPaused = paused;
        emit GlobalPauseSet(paused);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Incident handling
    // ────────────────────────────────────────────────────────────────────────

    /// @notice Drosera-facing entry. Idempotent on success; retryable on
    ///         total downstream failure. Decodes the trap's IncidentPayload
    ///         envelope for event logging only — the raw bytes are forwarded
    ///         unmodified to downstream targets.
    function handleIncident(bytes calldata rawPayload)
        external
        onlyRelayer
        whenNotGlobalPaused
    {
        require(rawPayload.length >= 32, "BridgePauseResponder/short-payload");

        bytes32 incidentHash = keccak256(rawPayload);

        // Replay of a previously-succeeded incident: cheap no-op (idempotency).
        if (executedIncidentHash[incidentHash]) return;

        // Decode the envelope only for event metadata. If the trap and
        // responder ABIs ever drift, the bytes still reach downstream targets
        // intact — they decode according to their own schemas.
        (uint8 threatType, address bridge, uint256 currentBN, uint256 previousBN) =
            _peekEnvelope(rawPayload);

        // Fan out.
        address[] memory ts = registry.getTargets();
        uint256 attemptedCount;
        uint256 successCount;

        for (uint256 i = 0; i < ts.length; i++) {
            address t = ts[i];
            if (!registry.approvedTargets(t)) continue;
            attemptedCount++;

            try IEmergencyActionTarget(t).emergencyPause(rawPayload) {
                emit DownstreamPauseAttempt(t, true);
                successCount++;
            } catch {
                emit DownstreamPauseAttempt(t, false);
            }
        }

        // Distinct revert reasons so operators can diagnose the failure mode.
        require(attemptedCount > 0, "no approved targets");
        require(successCount > 0,   "no target paused");

        // Only NOW is the incident truly handled. Flipping the flag earlier
        // would brick the incident forever if every downstream call reverted.
        executedIncidentHash[incidentHash] = true;
        incidentCount += 1;

        emit IncidentHandled(
            incidentHash,
            threatType,
            bridge,
            currentBN,
            previousBN,
            attemptedCount,
            successCount
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Internal
    // ────────────────────────────────────────────────────────────────────────

    /// @dev Safely peek the first four fields of the IncidentPayload envelope
    ///      for event metadata. Tolerates short or malformed payloads by
    ///      returning zeros — never reverts here.
    function _peekEnvelope(bytes calldata raw)
        private
        pure
        returns (uint8 threatType, address bridge, uint256 currentBN, uint256 previousBN)
    {
        // IncidentPayload encoding (abi.encode of a struct with a trailing
        // bytes field) lays out:
        //   [0x00 .. 0x20)  uint256  threatType (zero-padded enum)
        //   [0x20 .. 0x40)  address  bridge     (right-padded in word)
        //   [0x40 .. 0x60)  uint256  currentBlockNumber
        //   [0x60 .. 0x80)  uint256  previousBlockNumber
        //   [0x80 .. 0xa0)  uint256  offset to bytes details
        //   ...             details
        if (raw.length < 0x80) {
            return (0, address(0), 0, 0);
        }
        bytes32 w0;
        bytes32 w1;
        bytes32 w2;
        bytes32 w3;
        assembly {
            w0 := calldataload(raw.offset)
            w1 := calldataload(add(raw.offset, 0x20))
            w2 := calldataload(add(raw.offset, 0x40))
            w3 := calldataload(add(raw.offset, 0x60))
        }
        threatType  = uint8(uint256(w0));
        bridge      = address(uint160(uint256(w1)));
        currentBN   = uint256(w2);
        previousBN  = uint256(w3);
    }
}
