# Lessons from Trap #2 — Ronin Bridge $625M Exploit

What building this trap taught us about applying Drosera to a flow-based, multi-asset bridge exploit. Written for future Operation Flytrap traps and for anyone using this folder as a reference template.

This is the second entry in the Operation Flytrap series. Trap #1 (Bybit Safe{Wallet}) covered the **state-diff** detection-pattern shape on the **multisig hygiene** sector. Trap #2 deliberately probes different shapes (statistical-threshold, velocity, visibility) on the **bridges** sector — directly serving the Flytrap goal of mapping where Drosera is strongest.

---

## 1. Core thesis still holds — and is the strongest pitch we've earned

The Ronin root cause was entirely off-chain: a compromised Sky Mavis employee, an unrevoked allowlist, and forged-but-cryptographically-valid signatures. **No amount of on-chain signature validation would have caught this.**

The trap catches it anyway because the *result* of the attack — a 173,600 WETH withdrawal in a single transaction — is unambiguously outside the Ronin V2 auditor's own recommended Tier-3 threshold of $10M. The trap does not model the attacker. It models the bridge.

Pitch this as:

> **Drosera doesn't require you to predict the attack. It requires you to define what normal looks like.**

Ronin's own Verichains audit even wrote the pitch for us:

> *"The incident response protocols should be implemented by smart contracts which help quickly respond and limit loss."*

That is Drosera's mission statement, written by a third-party auditor about Ronin specifically. Use this quote in every piece of marketing about this trap.

---

## 2. Detection-pattern shape: bridges are a flow problem, not an identity problem

Bybit was an identity problem — "this Safe must look like THIS." Ronin is a flow problem — "no single withdrawal exceeds X, no cumulative window withdrawal exceeds Y, no aggregate balance drops Z%." Building Trap #2 forced the snapshot to carry **per-block event-derived deltas** that `shouldRespond` sums across the sample window. This is a fundamentally different snapshot shape than Bybit's, and gives us a working blueprint for the next bridge / DEX / lending-protocol trap.

Status of the detection-pattern axis after Trap #2:

| Shape | Covered by | Notes |
|---|---|---|
| State-diff detection | Bybit, Ronin (vector 3) | Easy mode. Two data points. |
| Statistical / threshold | **Ronin (vector 2)** | New shape. `OutlierWithdrawal`. Single-snapshot fire. |
| Multi-block / velocity | **Ronin (vector 4)** | New shape. `CumulativeWithdrawal`. Per-block delta summed across window. |
| Visibility (debounced) | Bybit, Ronin (vector 1) | Standard hygiene per GUIDELINES.md §7. |
| Cross-protocol correlation | Open | Future trap. |

Three shapes covered in two traps. Trap #3 should aim at cross-protocol correlation (cascade liquidations, governance attacks) or oracle-deviation patterns to fill the matrix.

---

## 3. Bridges are a horizontal lane — the trap templates across the sector

Ronin's design (signature quorum + multi-token gateway + per-token thresholds) is structurally similar to Wormhole, Multichain, Synapse, LayerZero, Polygon PoS, and most cross-chain bridges. The `OutlierWithdrawal` + `CumulativeWithdrawal` + `BridgeTVLDrain` vectors are mechanically applicable to any of them — only the addresses and thresholds change. The `BaselineFeeder` schema is intentionally per-bridge so a single trap deployment can monitor multiple bridges by setting per-bridge policy.

This is exactly what `project_flytrap_strategy.md` §5 calls a horizontal trap — toward Flytrap's 100–200 deployment target, bridges are the most efficient sector.

---

## 4. Architectural friction surfaced — feedback for the Drosera team

Three protocol-level frictions came up. Each is the kind of "what more could Drosera do if you did X" deliverable that Flytrap goal #2 explicitly values.

### a. Snapshot-as-state-buffer is awkward for cumulative analysis

`pure shouldRespond` cannot maintain a running total across calls. The workaround is to embed per-block deltas in every snapshot and sum across the sample window inside `shouldRespond`. This works, but every cumulative trap will rebuild this pattern by hand. **A first-class "running-sum" primitive (or a sanctioned `cumulativeWindow` helper in `drosera-contracts`) would remove this boilerplate from every velocity-style trap.**

### b. Event-log reliability is implicit, not documented

The trap relies on `getEventLogs()` (the Drosera-supplied operator-injected log buffer) to detect single-block withdrawals. The semantics of an empty/lagged log stream are not documented in GUIDELINES.md, so we conservatively folded `eventReadOk=false` into `MonitoringDegraded`. **Clearer documentation of `getEventLogs()` failure modes (or a `getEventLogsWithStatus()` returning an explicit success flag) would let event-driven traps make cleaner decisions.**

### c. Per-token aggregation needs a token-unit ratio, which is governance overhead

Bridges hold multiple assets at heterogeneous prices. The `BridgeTVLDrain` vector needs an aggregate value to compute "drop bps" — which forces us to store a `wethPerUsdc` ratio in the feeder and rely on governance to rotate it weekly. This is the pragmatic choice (an oracle would be a worse attack surface), but it's a real ergonomic tax. **A blessed pattern for "passive price-snapshot feeders that don't introduce attack surface" would lift this tax for every multi-asset trap.**

---

## 5. RPC selection is now a known recurring tax

drpc.org free tier 408s on storage queries to overlay addresses (e.g. `vm.etch`'d feeders). publicnode.com is fast but **not archive-capable** below the recent ~tens-of-thousands of blocks. `eth-mainnet.public.blastapi.io` worked for Mar 2022 archive state. Recording this here because the Bybit `feedback_trap_dev` memory got it wrong — drpc.org was archive-capable but rate-limited, not always-usable.

**Rule of thumb:** for new fork tests, probe with `cast call <known-contract> --block <historical-block> --rpc-url <candidate>` before committing to an RPC in `foundry.toml`. Two minutes of verification saves an hour of "why does setUp revert?"

---

## 6. Surfacing technical pedigree — the readme is the marketing surface

The `RoninBridgeTrap.sol` source includes inline "show your work" comments mapping each detection vector to the historical attack step it catches. The `README.md` quotes the Verichains audit directly. The `LESSONS.md` (this file) explains the *why* behind every design decision — feeder schema, token-unit thresholds, severity ordering, debounce categorisation.

If a reviewer can't read Solidity, they can still extract the value: 39 tests, 4 detection vectors, real exploit reproduced at the historical block, third-party auditor endorsement. That's the stigma-removal pitch from `project_flytrap_strategy.md` §6 — make the craft visible, not just functional.

---

## How this trap scores on the six Flytrap-strategy axes

| Axis | Ronin |
|---|---|
| Crisp "normal" definable | ✓ (per-token outlier thresholds, daily cap pro-rated) |
| Detection-pattern shape | **Three shapes**: state-diff (TVLDrain), statistical-threshold (Outlier), velocity (Cumulative) |
| State diff present | ✓ (bridge balance collapse) |
| Time window | ✓✓ (5 blocks between tx1 and tx2 — strong response-window pitch) |
| Attestable baseline | ✓ (Verichains audit even wrote the cap for us: $50M daily) |
| Protocol friction surfaced | ✓ (snapshot-as-buffer, event-log reliability, per-token ratios) |
| Horizontal applicability | **Very high** (every multi-validator bridge is in audience) |
| Design rationale visible | ✓ (this file + README + inline comments) |

This trap scores higher than Bybit on time-window pitch (5 blocks of contained damage), horizontal applicability (bridges > one specific multisig), and protocol-friction yield (three concrete feedback items for the Drosera team). It scores lower on the "is it the single most expensive hack" axis — Bybit was $1.46B vs Ronin's $625M — but Flytrap's goal is sector mapping, not loss-amount maximisation.
