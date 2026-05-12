// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title TrapDeployConfig
/// @notice Compile-time constants for the Ronin Bridge trap deployment.
/// @dev Drosera deploys traps with NO constructor arguments (GUIDELINES.md §2).
///      All monitored addresses live here as `internal constant` and are
///      surfaced through `pure` accessors on the trap so call sites read like
///      fields. Baseline values themselves live in the BaselineFeeder so
///      governance can rotate them on-chain without a trap rebuild — only the
///      feeder ADDRESS is compile-time fixed.
library TrapDeployConfig {
    /// @notice MainchainGateway V1 — the Ronin bridge contract drained on
    ///         2022-03-23 in blocks 14442835 + 14442840.
    address internal constant BRIDGE_GATEWAY =
        0x1A2a1c938CE3eC39b6D47113c7955bAa9DD454F2;

    /// @notice BaselineFeeder address. Replace with the real deployment
    ///         before mainnet activation; tests overlay this via vm.etch
    ///         to a deployed mock feeder.
    address internal constant BASELINE_FEEDER =
        0x1111111111111111111111111111111111111111;

    /// @notice Canonical WETH (mainnet).
    address internal constant WETH =
        0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    /// @notice Canonical USDC (mainnet, Circle).
    address internal constant USDC =
        0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
}
