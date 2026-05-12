# Ronin Bridge Exploit Trap

**Operation Flytrap PoC — Ronin Network Bridge $625M Hack (March 23, 2022)**

Production-grade Drosera trap demonstrating how the protocol would have detected and contained the second-largest cryptocurrency theft in history. Four severity-ordered detection vectors observe bridge token balances, the largest single withdrawal per block, the cumulative withdrawal volume across the sample window, and the loss-of-visibility surface. None of them depend on validator signature validity — the attacker held real keys.

39/39 tests passing, including a fork-based exploit reproduction at the historical block.

## The Attack

On March 23, 2022, the Ronin Network bridge was drained of **$625M** in WETH and USDC. The Lazarus Group compromised 5 of 9 validator private keys — four from Sky Mavis (the Axie Infinity studio) and one from the Axie DAO, accessed via an allowlist that had never been revoked after a temporary delegation in late 2021. The attacker forged two withdrawal signatures that passed the 5/9 quorum check on the MainchainGateway and walked out with the funds.

### How It Happened

1. **Nov 2021**: Sky Mavis received temporary allowlist access to sign on Axie DAO's behalf for gas-free transactions during a load incident.
2. **Dec 2021**: That delegation was no longer needed — **but the allowlist was never revoked**.
3. **Early 2022**: An employee was spear-phished, exposing Sky Mavis infrastructure. The attacker obtained 4 Sky Mavis validator keys and used the unrevoked Axie DAO allowlist to produce the 5th signature.
4. **Mar 23, 2022 — Block 14,442,835** (13:29 UTC): `withdrawERC20For(20000002, attacker, WETH, 173600e18, signatures)` drains **173,600 WETH** (~$400M).
5. **Block 14,442,840** (+5 blocks, 13:31 UTC): A second `withdrawERC20For` drains **25,500,000 USDC** (~$225M).
6. **Mar 29, 2022**: Discovered **6 days later** when a user reported a failed 5,000 ETH withdrawal.

**5 blocks separate the two attack transactions** — a 60-second window during which a Drosera consensus could have triggered an emergency pause and contained the USDC drain entirely.

### Stolen Assets

173,600 WETH (~$400M) · 25.5M USDC (~$225M)

### Key Addresses

| Role | Address |
|---|---|
| Victim (MainchainGateway V1) | `0x1A2a1c938CE3eC39b6D47113c7955bAa9DD454F2` |
| Attacker EOA | `0x098B716B8Aaf21512996dC57EB0615e2383E2f96` |
| WETH drain tx | `0xc28fad5e8d5e0ce6a2eaf67b6687be5d58113e16be590824d6cfa1a94467d0b7` |
| USDC drain tx | `0xed2c72ef1a552ddaec6dd1f5cddf0b59a8f37f82bdda5257d9c7c37db7bb9b08` |

## Why Drosera

The Verichains audit of Ronin Bridge V2 (June 28, 2022 — `/home/emark/drosera/Ronin.pdf`) explicitly recommended:

> *"The current risk controls focus on delaying attackers (by hard cap) but unclear how to react against them. The incident response protocols should be implemented by smart contracts which help quickly respond and limit loss."*

This trap is that incident-response layer, implemented three years retroactively for the V1 bridge that was drained.

The wider claim — and the marketable headline of this trap — is that **Drosera does not require the trap author to predict the attack vector**. The Ronin root cause was off-chain (compromised dev infrastructure plus an unrevoked allowlist). The trap catches it anyway because **bridge state diverged from a sanctioned baseline**.

## Threat Model

| Aspect | Detail |
|---|---|
| **Target** | Cross-chain bridge contracts holding ERC-20 / native treasury |
| **Attack** | Signature-quorum compromise enabling forged withdrawals; or any other vector that results in anomalous bridge outflow |
| **Scope** | Bridge balance state, per-block withdrawal events, cumulative withdrawal velocity, monitoring health |
| **Not in scope** | Validator key custody, signature cryptography, off-chain compromise of operator infrastructure (Ronin's root cause), social engineering |

## Detection Vectors

Severity-ordered, short-circuiting on first match.

| Order | Vector | Shape | What it catches in this exploit |
|---|---|---|---|
| 1 | `MonitoringDegraded` (debounced 2 samples) | Visibility | Bridge/feeder/event reads failing for ≥2 consecutive blocks. |
| 2 | `OutlierWithdrawal` (single snapshot) | Statistical-threshold | Tx 1 (173,600 WETH ≫ 4,000 WETH Tier-3 threshold). **Headline vector.** |
| 3 | `BridgeTVLDrain` (block-over-block diff) | State-diff | Tx 1 → ~50% drop in aggregated bridge value. |
| 4 | `CumulativeWithdrawal` (window aggregation) | Velocity / multi-block | Tx 1 + Tx 2 over 10-block window vastly exceeds pro-rated $50M daily cap (Ronin's own V2 audit number). |

Vector 2 is the marketable headline — it uses Ronin's V2-audit Tier-3 threshold (`$10M`, `~4,000 WETH`) **enforced three years earlier** by Drosera.

## Architecture

The system is split into six contracts:

```
src/
  interfaces/ITrap.sol            Local Drosera trap interface
  RoninBridgeTrap.sol             Trap: collect + shouldRespond (pure)
  BaselineFeeder.sol              Governance-owned per-bridge policy
  BridgePauseResponder.sol        Responder: idempotent, allowlisted, pausable
  BridgePauseRegistry.sol         Governance-owned bounded allowlist (MAX_TARGETS=16)
  TrapDeployConfig.sol            Compile-time addresses (constructorless deployment)
  mocks/MockBridgePauseTarget.sol Downstream pause target used by tests
```

### Data flow

```
governance → feeder.setBridgePolicy(bridge, outlierThresh*, windowCap*, tvlDropBps, wethPerUsdc)
operator   → trap.collect()                          (every block, view)
operator   → trap.shouldRespond(data[])              (pure, 10-sample window)
             ↓ returns abi.encode(IncidentPayload)
consensus  → responder.handleIncident(payload)       (idempotent, dedupes by keccak256)
             ↓ fans out to every approved target (bounded ≤ 16)
registry   → target.emergencyPause(payload)          (try/catch per target)
```

### BaselineFeeder

`pure shouldRespond()` cannot read state — so the trap reads the governance-approved bridge policy in `collect()` and embeds it in every snapshot. Rotating thresholds as WETH price moves is one governance transaction, no trap redeploy.

Stored values are denominated in **token units, not USD**. This eliminates a live oracle dependency in `collect()` and lets `MonitoringDegraded` cleanly attribute visibility loss to bridge reads or event-log reads, not to a third-party price feed.

### Snapshot (19 fields, 608 bytes encoded)

`collect()` emits a snapshot bound to both a block and a bridge. Every fallible read returns a status flag so `shouldRespond()` can tell loss-of-visibility from a legitimately zero value:

| Slot | Field | Purpose |
|---|---|---|
| 0 | `bridge` | Monitored target binding |
| 1 | `blockNumber` | Sample ordering |
| 2 | `balancesReadOk` | Both WETH+USDC `balanceOf` succeeded |
| 3 | `baselineReadOk` | Feeder call succeeded |
| 4 | `baselineConfigured` | Feeder has policy for this bridge |
| 5 | `eventReadOk` | `getEventLogs()` parse succeeded |
| 6 | `wethBalance` | Bridge WETH balance |
| 7 | `usdcBalance` | Bridge USDC balance |
| 8 | `aggregateValueTU` | WETH-equivalent value across both tokens |
| 9 | `largestWithdrawalWeth` | Max single `TokenWithdrew(WETH,…)` event this block |
| 10 | `largestWithdrawalUsdc` | Max single `TokenWithdrew(USDC,…)` event this block |
| 11 | `blockWithdrawalSumWeth` | Sum of WETH withdrawals this block |
| 12 | `blockWithdrawalSumUsdc` | Sum of USDC withdrawals this block |
| 13–16 | thresholds + caps | Embedded from feeder |
| 17 | `tvlDropBps` | TVL-drop threshold (basis points) |
| 18 | `withdrawalEventCount` | Diagnostics |

### Event filter

The trap subscribes to `TokenWithdrew(uint256,address,address,uint256)` from the MainchainGateway. The token is indexed (topic[3]), the amount is in non-indexed data. The parser is defensive against malformed logs and any unrecognised tokens are silently ignored.

### Responder

- `handleIncident(bytes)` — Drosera relayer-facing entry. Idempotent on success (replay no-op), retryable on total downstream failure (the `executedIncidentHash` flag is flipped *after* at least one downstream target accepts the pause).
- Distinct revert reasons: `"no approved targets"` (registry misconfig) vs `"no target paused"` (downstream broken). Operators can diagnose the failure mode.
- Global pause kill-switch for false-positive storms.

### CAVEAT — Downstream pause permission

The responder cannot directly call `pause()` on Ronin's MainchainGateway V1 — Drosera holds no role on that contract, and V1 may not even expose a pause function callable by an outsider. The registry's approved targets are **governance-pre-deployed pause proxies** that hold the bridge role. In production deployments, a protocol team would (a) deploy such a proxy with the bridge's `WITHDRAWAL_UNLOCKER_ROLE` (or equivalent), (b) approve it in the registry. The shipped `MockBridgePauseTarget` is for tests only.

## Deployment Sequence

1. `BaselineFeeder(governance)`
2. `BridgePauseRegistry(governance)`
3. `RoninBridgeTrap()` (no constructor args — compile-time config via `TrapDeployConfig.sol`)
4. `BridgePauseResponder(admin, relayer = 0x01C344b8406c3237a6b9dbd06ef2832142866d87, registry)`
5. `feeder.setBridgePolicy(...)` + `registry.setTarget(...)` (governance multisig + timelock)

Replace `TrapDeployConfig.BASELINE_FEEDER` with the deployed feeder address, then `forge build` and deploy the trap. Privileged roles (`feeder.owner`, `registry.owner`, `responder.admin`) are deployed behind a governance multisig + timelock — the source is governance-*compatible*; the deployment makes it governance-*managed*.

## Building and Testing

```bash
bun install
forge build
forge test
```

Archive RPC: `https://eth-mainnet.public.blastapi.io` (verified to hold state for block 14,442,834 — see `LESSONS.md` for the RPC selection rationale).

## Response Window

5 blocks separated tx 1 from tx 2 — a 60-second window at 12s blocks. With `block_sample_size = 10`, Drosera operators would have run `collect()` immediately following tx 1, the trap's `OutlierWithdrawal` vector would have fired on the first sample, and 2/3 BLS consensus could have submitted a pause transaction multiple blocks before tx 2. The $25.5M USDC drain would have been contained.

## Assumptions

The trap is correct only when these hold:

- **`BaselineFeeder` is reachable and configured.** `OutlierWithdrawal` and `CumulativeWithdrawal` are absolute-threshold vectors gated on `baselineConfigured == true`. Without governance opt-in, only `BridgeTVLDrain` and `MonitoringDegraded` are active.
- **Governance rotates `wethPerUsdc` as WETH price moves.** The aggregate value math uses a Q18 fixed-point ratio stored in the feeder. A stale ratio doesn't break the trap, but `BridgeTVLDrain` will compute drop-bps in units that no longer match real USD value.
- **A pre-deployed pause proxy holds the bridge role.** The shipped `BridgePauseResponder` cannot directly call `pause()` on the Ronin V1 MainchainGateway — Drosera has no role on it. In production, governance deploys an emergency-pause proxy with `WITHDRAWAL_UNLOCKER_ROLE` (or the bridge-specific equivalent) and adds its address to `BridgePauseRegistry`.
- **Privileged roles are governance-managed.** The source is governance-*compatible* (admin/owner/relayer fields exist on all three peripheral contracts). The deployment makes it governance-*managed* by placing those roles behind a multisig + timelock.
- **The Drosera operator network surfaces in-block event logs to `collect()` via `getEventLogs()`.** Event-log read failures fold into `MonitoringDegraded` (debounced); a sustained event-stream outage would defeat `OutlierWithdrawal` specifically until visibility recovers.

## Limitations

What this trap does **not** protect against:

- **Validator key custody** and off-chain compromise of operator infrastructure (Ronin's actual root cause). Drosera observes on-chain results, not key management or social engineering.
- **Forged signatures that fall under all detection thresholds.** A patient attacker could siphon below `OutlierWithdrawal`, below the window cap, and below `tvlDropBps` per block. Governance must size thresholds against the bridge's normal-traffic envelope, not theoretical maximums.
- **Tokens beyond WETH and USDC.** The trap scopes to the two assets that comprised the historical exploit (and are the largest bridge balances). The bridge also holds AXS, SLP, and other ERC-20s — the event-scanner ignores them, and the aggregate-value math only sums WETH + USDC. Add `BridgePolicy` entries per additional token to extend coverage.
- **USDC-only drains while `wethPerUsdc == 0`.** The aggregate-value fallback when no price ratio is set sums WETH (18 dec) + USDC (6 dec) raw, which makes USDC contribution dimensionally negligible. `BridgeTVLDrain` would miss a pure USDC drain in that mode; the other three vectors still cover it. Governance is expected to set `wethPerUsdc > 0` on first policy write.
- **In-flight transactions in the same block as the trigger.** Drosera responds at the *next* block after consensus, not atomically with the offending tx. The protective claim is "would have caught tx 2 5 blocks later," not "would have prevented tx 1 itself."
- **Bridges other than MainchainGateway V1.** The trap is bound at compile time to one bridge address. The `BridgePolicy` schema is per-bridge so the pattern templates across other bridges, but each deployment monitors exactly one target.

## Documentation

- `LESSONS.md` — Flytrap strategy scorecard, design rationale (BaselineFeeder, token-unit thresholds, severity ordering, etc.).
- The Solidity source carries inline "show your work" comments mapping each detection vector to the exploit step it catches.

## Sources

- [SlowMist Ronin Network exploit & AML analysis](https://slowmist.medium.com/report-on-the-ronin-network-exploit-and-aml-analysis-of-stolen-funds-692b2a589a96)
- [Merkle Science: Hack Track — Ronin Network Exploit](https://www.merklescience.com/blog/hack-track-analysis-of-ronin-network-exploit)
- [Halborn: Explained — The Ronin Hack (March 2022)](https://www.halborn.com/blog/post/explained-the-ronin-hack-march-2022)
- [Ronin official postmortem — "Back to Building"](https://roninchain.com/blog/posts/back-to-building-ronin-security-breach-6513cc78a5edc1001b03c364)
- [Three Sigma: Ronin Bridge $625M Exploit Analysis](https://threesigma.xyz/blog/exploit/ronin-network-12m-exploit-analysis)
- Verichains Security Audit of Ronin Bridge Smart Contracts (June 28, 2022) — `/home/emark/drosera/Ronin.pdf`
