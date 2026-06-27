# Security & Critical Incidents — Bug Audit

**Scope:** Cross-cutting security label (43 issues), non-finality label, keyword searches for consensus splits, crashes, outages, hotfixes, and CVEs across the full lifetime of sigp/lighthouse. Complements per-subsystem audits by building incident timelines and mapping root causes to subsystems.

**Queries run:**
- `gh issue list --repo sigp/lighthouse --label "security" --state all --limit 100`
- `gh issue list --repo sigp/lighthouse --label "non-finality" --state all --limit 100`
- `gh search issues --repo sigp/lighthouse "<keyword>" --state all --limit 50` for: "consensus split", "non-finality", "did not finalize", "crash loop", "panic on mainnet", "post-mortem", "postmortem", "incident", "hotfix", "emergency release", "CVE", "RUSTSEC", "DoS", "out of memory", "Holesky", "Goerli", "fork choice", "deadlock", "slashing", "invalid block", "database corruption", "race condition"
- `gh release list --repo sigp/lighthouse --limit 100` + individual `gh release view` for all patch releases
- `gh issue view <N> --repo sigp/lighthouse --comments` for all major incidents
- `gh pr view / gh pr diff` for key fixes

---

## 2. Bug Table

| # | Title | State | Class | Severity | How-found | One-line root cause | Fix PR | Subsystem |
|---|-------|-------|-------|----------|-----------|---------------------|--------|-----------|
| [#485](https://github.com/sigp/lighthouse/issues/485) | DoS vector: blocks with big slot skips | Closed | `protocol-networking` | critical | internal-testing | State advancement required before sig verification; O(epochs) CPU, anyone could exploit | Spec change added `proposer_index` to blocks (closed 2020-08-28) | networking |
| [#800](https://github.com/sigp/lighthouse/issues/800) | Memory exhaustion via skip-slot state accumulation | Closed | `resource` | high | code-review | ~5MB intermediate states stored per skip slot during block processing | Rate-limiting / max-skip enforcement | consensus |
| [#845](https://github.com/sigp/lighthouse/issues/845) | Cross-fork attestations invalidate blocks | Closed | `spec-correctness` | high | internal-testing | PR #820 disabled attestation sig checks in op pool; cross-fork committees diverge after 2 epochs | PR #869 — filter op pool attestations by target root | consensus |
| [#891](https://github.com/sigp/lighthouse/issues/891) | Prune forks from database | Closed | `persistence` | medium | code-review | Unbounded DB growth from unfinalized fork retention | Fork pruning feature | database |
| [#945](https://github.com/sigp/lighthouse/issues/945) | Block import conflicting with finalized chain | Closed | `spec-correctness` | critical | code-review | `check_block_against_finalized_slot` checked slot not chain; parent pre-finality could be accepted | Fixed finality check to verify parent root | consensus |
| [#1031](https://github.com/sigp/lighthouse/issues/1031) | Fuzzing — Arbitrary trait derivation | Closed | `logic-other` | medium | code-review | Missing fuzz coverage | Added Arbitrary trait impls | consensus |
| [#1130](https://github.com/sigp/lighthouse/issues/1130) | bip39 crate doesn't use zeroize | Closed | `logic-other` | medium | static-analysis | Key material not zeroed from memory | Dependency upgrade | validator-client |
| [#1152](https://github.com/sigp/lighthouse/issues/1152) | Limit incoming attestation processing | Closed | `protocol-networking` | high | code-review | No rate limit on attestation ingestion (DoS vector) | Rate-limiter added | networking |
| [#1160](https://github.com/sigp/lighthouse/issues/1160) | Remove legacy keypair support | Closed | `logic-other` | low | code-review | Unmaintained code path | Removal | validator-client |
| [#1175](https://github.com/sigp/lighthouse/issues/1175) | Strip line endings from .pass files | Closed | `config-cli` | low | user-report | Password files with trailing newlines failed auth | Strip whitespace | validator-client |
| [#1194](https://github.com/sigp/lighthouse/issues/1194) | Cargo audit fail: rusqlite | Closed | `logic-other` | low | static-analysis | RUSTSEC advisory in dependency | Dep update | slasher-crypto-misc |
| [#1245](https://github.com/sigp/lighthouse/issues/1245) | Replace rust-crypto | Closed | `logic-other` | medium | code-review | Unmaintained crypto library | Replaced with maintained crates | slasher-crypto-misc |
| [#1255](https://github.com/sigp/lighthouse/issues/1255) | Fork handling in op pool | Closed | `spec-correctness` | medium | code-review | Attestations across fork boundary not properly filtered | Op pool fork handling revamp | consensus |
| [#1333](https://github.com/sigp/lighthouse/issues/1333) | Deposit signature subgroup check missing | Closed | `serialization` | high | audit | `verify_deposit_signature()` used aggregate verify (no pubkey subgroup check) | PR #1935 — use `Signature::verify()` directly | slasher-crypto-misc |
| [#1584](https://github.com/sigp/lighthouse/issues/1584) | Validators registered with slashing-protection on startup | Closed | `logic-other` | high | code-review | Auto-registration could reset slashing protection on accidental DB misplace | Register only at creation/import | validator-client |
| [#1669](https://github.com/sigp/lighthouse/issues/1669) | Cargo audit: RUSTSEC-2020-0043 | Closed | `logic-other` | low | static-analysis | Ignored RUSTSEC advisory | Dep update | slasher-crypto-misc |
| [#1707](https://github.com/sigp/lighthouse/issues/1707) | Update BLST/Milagro to BLS draft v4 | Closed | `serialization` | high | spec-test | BLS library not on final spec draft | Dep update | slasher-crypto-misc |
| [#1709](https://github.com/sigp/lighthouse/issues/1709) | Parasitic voluntary exits (far-future epoch) | Closed | `resource` | medium | user-report | Exits with far-future epochs never pruned; 43MB RAM per 1M validators at 1/3 attacker | Added epoch validity window to exit pruning | consensus |
| [#1712](https://github.com/sigp/lighthouse/issues/1712) | Out-of-date dependencies | Closed | `logic-other` | low | static-analysis | Stale dependency tree | Dep updates | slasher-crypto-misc |
| [#1773](https://github.com/sigp/lighthouse/issues/1773) | Fork choice timing attack | Closed | `spec-correctness` | medium | code-review | Theoretical protocol-level timing attack on fork choice | Superseded by proposer boost | consensus |
| [#1873](https://github.com/sigp/lighthouse/issues/1873) | Slashing protection import epoch gap | Closed | `persistence` | critical | internal-testing | Importing disjoint interchange files left signing gap between covered ranges | PR — prune DB on import to fill gap | validator-client |
| [#1880](https://github.com/sigp/lighthouse/issues/1880) | Password length check counts bytes not chars | Closed | `config-cli` | low | user-report | Multi-byte emoji chars miscounted as long enough | Fix char counting | validator-client |
| [#2086](https://github.com/sigp/lighthouse/issues/2086) | Resolve RUSTSEC-2020-0091 | Closed | `logic-other` | low | static-analysis | RUSTSEC dep advisory | Dep update | slasher-crypto-misc |
| [#2276](https://github.com/sigp/lighthouse/issues/2276) | VC logs scrub beacon endpoint data | Closed | `config-cli` | medium | code-review | Auth tokens logged in plaintext | Strip sensitive data from logs | validator-client |
| [#2437](https://github.com/sigp/lighthouse/issues/2437) | Validator API key files have 644 permissions | Closed | `config-cli` | high | audit | Secret key files world-readable (644 instead of 600) | Enforce 600 permissions on key files | validator-client |
| [#2438](https://github.com/sigp/lighthouse/issues/2438) | API token readable from log file | Closed | `config-cli` | high | audit | API token logged in plaintext to 644-permission log file | Restrict log file permissions | validator-client |
| [#2443](https://github.com/sigp/lighthouse/issues/2443) | Vulnerability in prost (libp2p dep) | Closed | `logic-other` | medium | static-analysis | RUSTSEC in protobuf library | Dep update | networking |
| [#2512](https://github.com/sigp/lighthouse/issues/2512) | VC API: POST/PATCH require no auth token | Closed | `api-correctness` | critical | audit | Write API endpoints not checking Authorization header | PR #2517 — add auth check to POST/PATCH | validator-client |
| [#2727](https://github.com/sigp/lighthouse/issues/2727) | Cargo audit: `time` crate | Closed | `logic-other` | low | static-analysis | RUSTSEC advisory in `time` | Dep update | slasher-crypto-misc |
| [#2778](https://github.com/sigp/lighthouse/issues/2778) | Docker image OS vulnerabilities | Closed | `logic-other` | medium | static-analysis | Base OS outdated | Image rebuild | slasher-crypto-misc |
| [#3093](https://github.com/sigp/lighthouse/issues/3093) | Docker image vulns in v2.1.4 | Closed | `logic-other` | medium | static-analysis | Base OS outdated | Image rebuild | slasher-crypto-misc |
| [#3947](https://github.com/sigp/lighthouse/issues/3947) | Update `warp` to upstream (OPEN) | Open | `logic-other` | medium | static-analysis | Forked/stale warp HTTP library | Dep update (v9001 partial) | http-api |
| [#4293](https://github.com/sigp/lighthouse/issues/4293) | Implement broadcast_validation API | Closed | `api-correctness` | high | spec-test | No validation before block broadcast (builder safety) | PR implementing broadcast_validation | http-api |
| [#4725](https://github.com/sigp/lighthouse/issues/4725) | broadcast_validation for blobs context | Closed | `availability-da` | medium | code-review | Blobs complicate safe broadcast validation | Updated blob handling | data-availability |
| [#4773](https://github.com/sigp/lighthouse/issues/4773) | HeadTracker race condition / DB corruption | Closed | `concurrency` | critical | user-report | Race between block import and pruning: blocks in DB but absent from HeadTracker, 5× disk growth | PR #5084 — lock HeadTracker before write | database |
| [#4918](https://github.com/sigp/lighthouse/issues/4918) | Gossipsub OOM: unbounded send queues | Closed | `resource` | critical | mainnet-incident | Slow peers accumulate unlimited gossip message queues; 16GB+ spikes on mainnet | Bounded queues + message prioritization in gossipsub fork (v4.6.0) | networking |
| [#6262](https://github.com/sigp/lighthouse/issues/6262) | serde_yaml unmaintained (OPEN) | Open | `logic-other` | low | static-analysis | Unmaintained dep | Replace dep | slasher-crypto-misc |
| [#6393](https://github.com/sigp/lighthouse/issues/6393) | Reproducible builds | Closed | `logic-other` | medium | code-review | Supply-chain security gap | Reproducible build infra | slasher-crypto-misc |
| [#6477](https://github.com/sigp/lighthouse/issues/6477) | Broadcast blobs early: security tradeoff | Closed | `availability-da` | medium | code-review | Early blob broadcast could leak KZG data to block unbundlers | Added engine_getBlobsV1 alternative | data-availability |
| [#6692](https://github.com/sigp/lighthouse/issues/6692) | Check tx lengths during optimistic sync | Closed | `el-integration` | medium | spec-test | Spec change: invalid-length txs accepted during optimistic sync | PR implementing spec check | execution-layer |
| [#6875](https://github.com/sigp/lighthouse/issues/6875) | Arithmetic lint in rate-limiter | Closed | `resource` | medium | static-analysis | Integer overflow risk in rate limiter | Enable overflow lint | networking |
| [#7090](https://github.com/sigp/lighthouse/issues/7090) | RUSTSEC-2025-0009 in `ring` crate | Closed | `logic-other` | medium | static-analysis | RUSTSEC in ring crypto (via libp2p) | Dep update for v7.0.0 | slasher-crypto-misc |
| [#7091](https://github.com/sigp/lighthouse/issues/7091) | RUSTSEC-2024-0437 in protobuf | Closed | `logic-other` | medium | static-analysis | RUSTSEC in protobuf | Dep update for v7.0.0 | slasher-crypto-misc |
| [#7170](https://github.com/sigp/lighthouse/issues/7170) | Log rotation resets permissions to 644 | Closed | `config-cli` | high | code-review | Log rotation creates new file without restricting permissions | Fix rotation to maintain 600 on new file (v7.1.0) | validator-client |
| [#7171](https://github.com/sigp/lighthouse/issues/7171) | libp2p/discv5 logfiles not restricted | Closed | `config-cli` | high | code-review | `is_restricted=true` config not applied to discv5/libp2p loggers | Apply restriction to sub-loggers (v7.1.0) | networking |
| [#8101](https://github.com/sigp/lighthouse/issues/8101) | Proposer calculation bug post-Fulu | Closed | `spec-correctness` | critical | audit | Proposer shuffling decision roots not fork-aware after Fulu; wrong proposer index computed | PR #8101 — fork-aware beacon proposer cache | consensus |
| [#8437](https://github.com/sigp/lighthouse/issues/8437) | ENR update loop → 117GB OOM | Closed | `resource` | critical | user-report | discv5 v10.1 in v8.0.0 missing Docker SNAT port-fix; ENR toggled 500×/sec until OOM | PR #8443 — update discv5 with fix (v8.1.0) | networking |
| [#8955](https://github.com/sigp/lighthouse/issues/8955) | Crash: overflow in gossipsub backoff time arithmetic | Closed | `panic-crash` | high | user-report | libp2p gossipsub `Instant::add()` overflow in backoff calculation (RUSTSEC-2026-0009) | v8.1.2 — update gossipsub fork | networking |
| [#9090](https://github.com/sigp/lighthouse/issues/9090) | O(n²) find_head + stack overflow at ~30k blocks | Closed | `resource` | critical | code-review | PR #9025 removed best_child/best_descendant caching; O(n²) + recursive stack overflow | PR #9090 — O(n) iterative algorithms with children index | consensus |
| [#9106](https://github.com/sigp/lighthouse/issues/9106) | Consensus fault: total_effective_balance=0 in PreEpochCache | Closed | `spec-correctness` | high | audit | Floor not applied when converting PreEpochCache→EpochCache; balance=0 only on dead network | PR #9106 — add floor in EpochCache conversion | consensus |
| [#9358](https://github.com/sigp/lighthouse/issues/9358) | HTTP API: no Content-Length limit (wont-fix) | Closed | `api-correctness` | low | static-analysis | Automated tool flag; not a real threat (API not internet-exposed) | Closed wont-fix | http-api |
| v4.0.0 retraction | Fork choice bug (v4.0.0 retracted) | — | `spec-correctness` | critical | internal-testing | Fuzzer-found fork choice bug causing slot-level downtime; exact root cause not public | PR #4122 + #3962 (v4.0.1) | consensus |
| v4.4.0 killed | Double-lock deadlock in HTTP API | — | `concurrency` | critical | internal-testing | PR #4236 acquired `parking_lot::RwLock` read lock twice on same thread; deadlock | PR #4687 — restructure to avoid reentrant lock (v4.4.1) | http-api |
| v5.1.0 hotfix | Messages not published to peers | — | `protocol-networking` | critical | testnet-incident | Gossip mesh peer count bug: no mesh peers → all published messages silently dropped | PR #5357 (v5.1.1) | networking |
| v7.0.1 hotfix | State cache size 128→32 caused cache misses | — | `perf-regression` | high | user-report | v7.0.0 set default state cache to 32; massive cache miss rate on mainnet | PR #7364 — restore to 128 (v7.0.1) | consensus |
| v8.1.1 security | Yamux flow-control overflow/underflow panics | — | `panic-crash` | critical | audit | `increase_send_window_by()` and `consume_receive_window()` panicked on crafted peer input | sigp/rust-yamux patch (v8.1.1) | networking |
| v8.1.2 security | Yamux drop panic, Quinn QUIC `.unwrap()`, gossipsub backoff | — | `panic-crash` | critical | audit | `on_drop_stream` expect-panic; Quinn QUIC transport param `.unwrap()` on crafted data | sigp/rust-yamux + sigp/quinn + sigp/rust-libp2p patches (v8.1.2) | networking |
| GHSA-wm9c | Electra epoch processing double-applies consolidations | — | `spec-correctness` | critical | audit | Single-pass epoch processing ran `process_effective_balance_updates` twice for consolidation-affected validators | PR #7209 (v7.0.0-beta.5) | consensus |
| Holesky 2025 | Holesky testnet chain outage (Feb 2025) | — | `fork-upgrade` | critical | mainnet-incident | Nethermind/Geth/Besu EL config bug at Electra upgrade justified invalid block; chain split; OOM under non-finality | v7.0.0-beta.1 banned invalid block; OOM mitigations in v7.x | execution-layer |

---

## 3. Incident Timelines

### Incident 1: DoS via Skip-Slot State Advancement (2019–2020)

**Issue:** [#485](https://github.com/sigp/lighthouse/issues/485)  
**Subsystem:** networking  
**Severity:** critical

**Trigger:** Anyone on the p2p network could craft a BeaconBlock with a very old parent reference, forcing the receiving node to advance state through many epochs (O(skip distance) CPU/time) before any signature check was possible.

**Blast radius:** Complete CPU DoS against any Lighthouse node. No authentication required — any peer could send the crafted block. Identified pre-mainnet during protocol review.

**Root cause:** The spec at the time had no `proposer_index` field on `BeaconBlock`. Without it, the node had to compute the proposer shuffling by advancing state to the block's slot before verifying the block's signature. There was no way to reject the block cheaply.

**Timeline:**
- 2019-08-02: paulhauner opens #485; multiple solutions discussed with protolambda, arnetheduck, prestonvanloon (EF)
- 2019-08-06: Vitalik posts analysis of lightweight skip options
- 2020-08-28: Closed — the Ethereum consensus spec added `proposer_index` to `BeaconBlock`, enabling quick signature verification on the parent state without any slot advancement

**Fix:** Ethereum spec change (EIP/spec PR). With `proposer_index`, the node can verify the block signature against the parent state and reject bad blocks cheaply.

**Why not caught earlier:** Protocol-design limitation known to researchers; addressed at spec level, not just implementation.

---

### Incident 2: Cross-Fork Attestation Blocks (2020)

**Issue:** [#845](https://github.com/sigp/lighthouse/issues/845)  
**Subsystem:** consensus  
**Severity:** high

**Trigger:** PR #820 disabled attestation signature checks in the op pool for performance. On a network with a fork lasting more than 2 epochs, attestations from the other fork would be included in blocks without valid signatures — producing blocks other nodes would reject.

**Blast radius:** Block proposal failures on forked chains. Not triggered on mainnet (pre-launch) but would have caused liveness issues.

**Root cause:** Op pool attestations were not filtered by fork-safe target root. Committee shufflings diverge after >2 epochs of forking. Without the sig check, cross-fork attestations with mismatched committees were treated as valid inclusions.

**Timeline:**
- 2020-02-11: michaelsproul discovers and reports #845
- 2020-02-12: paulhauner and michaelsproul discuss target-root filtering approach
- 2020-03-05: michaelsproul begins fix
- 2020-04-20: Closed (fix merged)

**Fix:** Filter op pool attestations by matching target epoch roots against the producing state, ensuring only same-fork attestations are included.

**Why not caught earlier:** Performance optimization (PR #820) that disabled a correctness check without accounting for the multi-epoch fork-divergence edge case.

---

### Incident 3: VC API Authentication Bypass (2021)

**Issue:** [#2512](https://github.com/sigp/lighthouse/issues/2512)  
**Subsystem:** validator-client  
**Severity:** critical

**Trigger:** The validator client HTTP API implemented authentication for GET requests but NOT for POST and PATCH requests. Any process that could reach the API port could issue write commands (add/remove validators, change settings) without credentials.

**Blast radius:** Full write access to the validator client for any host-local or network-adjacent attacker. Could add/remove validators, modify keystore settings.

**Root cause:** Authentication middleware was only wired up to GET request handlers. The POST and PATCH handlers bypassed the authorization check.

**Timeline:**
- 2021-07-07: dnkolegov (external researcher) reports #2512 alongside #2437 (wrong file permissions) and #2438 (token in logs)
- 2021-08-18: Fixed via PR #2517 — authorization header check added to all write endpoint handlers

**Fix:** PR #2517 — apply Authorization header verification to all HTTP method handlers, not just GET.

**Why not caught earlier:** Authentication applied per-handler rather than as a middleware on all routes. File permissions issues (#2437, #2438) reported by same researcher — suggests a pattern of insufficient security review of the VC API layer.

---

### Incident 4: Slashing Protection Import Epoch Gap (2020)

**Issue:** [#1873](https://github.com/sigp/lighthouse/issues/1873)  
**Subsystem:** validator-client  
**Severity:** critical

**Trigger:** Importing two slashing protection interchange files covering non-overlapping epoch ranges (e.g., 0–50 and 100–150) would leave a gap (51–99) where signing was not blocked, violating the minimum-bound safety guarantee.

**Blast radius:** A validator key migrated using multiple interchange exports could be made to sign attestations/blocks in the gap epoch range, risking a slashable offense.

**Root cause:** The import logic did not enforce a continuous coverage requirement. File 2's minimum bound did not cause File 1's records to fill in or block the gap.

**Timeline:**
- 2020-11-09: michaelsproul identifies and reports #1873
- 2020-11-24: Fixed — import now prunes/clears old DB records so the imported file's minimum bound takes effect from the last known-signed slot

**Fix:** Clear existing slashing protection records on import (or use a stricter minimum-bound column), so no epoch gap is possible.

**Why not caught earlier:** Slashing protection correctness is subtle; this edge case requires importing multiple partially-overlapping files, which wasn't covered by existing import tests.

---

### Incident 5: HeadTracker Race Condition → DB Corruption (2023–2024)

**Issue:** [#4773](https://github.com/sigp/lighthouse/issues/4773)  
**Fix PR:** [#5084](https://github.com/sigp/lighthouse/pull/5084)  
**Subsystem:** database  
**Severity:** critical

**Trigger:** A race condition between the block import thread and the background pruning thread: blocks could be written to the RocksDB database before the HeadTracker in-memory index was updated. The pruning thread could then see the block as an orphan and delete it, even though it was actually canonical.

**Blast radius:** Silent data loss in the beacon database. Users observed 5× disk growth and mysterious missing blocks. In severe cases the node would need to resync. Affected real mainnet users.

**Root cause:** The HeadTracker write was not atomic with the database write. Two threads could interleave such that the pruner observed an inconsistent state.

**Timeline:**
- 2023: Multiple user reports of unexpected disk growth
- 2023: Root cause identified as HeadTracker/pruner race
- 2024 (v4.6.0): Fixed via PR #5084 — HeadTracker write lock acquired before database write; atomicity enforced

**Fix:** PR #5084 — take HeadTracker write lock before committing block to DB, preventing pruner from seeing the block as orphaned.

**Why not caught earlier:** The race required specific timing between import and pruning threads; not easily caught by unit tests. Needed an integration test with concurrent block import + pruning under load.

---

### Incident 6: Gossipsub OOM — Unbounded Send Queues (2023–2024)

**Issue:** [#4918](https://github.com/sigp/lighthouse/issues/4918)  
**Subsystem:** networking  
**Severity:** critical (mainnet-incident)

**Trigger:** On the mainnet p2p network, slow peers would accumulate unlimited outbound message queues in gossipsub. When a slow peer eventually disconnected, freeing its queue caused memory to spike then drop — but during accumulation nodes would reach 16GB+ RSS and be OOM-killed.

**Blast radius:** Mainnet Lighthouse nodes crashing periodically due to OOM. Missed attestations and proposals during crash and restart.

**Root cause:** gossipsub send queues had no size bound. The upstream libp2p gossipsub implementation provided no backpressure and no dropping mechanism for slow peers.

**Timeline:**
- 2023-11-09: AgeManning opens #4918 after identifying root cause
- 2023-12: Fork of rust-libp2p developed with: message priorities (publish > forward > control), time-based dropping for non-critical messages, gossipsub scoring for slow peers
- 2024-01-23: Fixed in v4.6.0 — memory stays stable at 2–4GB post-fix vs. spikes to 16GB+ pre-fix

**Fix:** Custom gossipsub fork with bounded queues, message prioritization, and time-based dropping of lower-priority stale messages.

**Why not caught earlier:** Only manifested at mainnet scale with many slow/heterogeneous peers. Not reproducible in small test networks.

---

### Incident 7: v4.0.0 Retraction — Fuzzer-Found Fork Choice Bug (2023)

**Subsystem:** consensus  
**Severity:** critical

**Trigger:** A fuzzer-discovered bug in fork choice logic introduced in v4.0.0, which could cause "temporary periods of effective downtime of several slots" if triggered.

**Blast radius:** Not triggered on any networks before the retraction. If triggered: several slots of consensus failure for affected node.

**Root cause:** Not fully disclosed publicly. The associated fix PRs (#4122, #3962) indicate changes to fork choice state tracking and removal of `CountRealizedFull` concept. The `best_justified_checkpoint` migration was handled by stubbing with junk values rather than a proper DB migration (tech debt).

**Timeline:**
- 2023-03-22: v4.0.0 published
- 2023-03-23 (~1 day later): v4.0.0 retracted; hotfix v4.0.1-rc.0 published with statement "bug found by our fuzzers and has not been triggered on any networks"
- 2023-03-27: v4.0.1 published as the stable fix release

**Fix:** PRs #4122 + #3962 — fork choice corrections plus resilience improvements per consensus-specs#3290.

**Why not caught earlier:** Fuzzer found it pre-deployment. Credit to the active fuzzing infrastructure. The specific trigger scenario was not exercised by integration tests.

---

### Incident 8: v4.4.0 Killed by HTTP API Deadlock (2023)

**Subsystem:** http-api  
**Severity:** critical

**Trigger:** PR #4236 introduced a reentrant `parking_lot::RwLock` read-lock on the fork choice state within the HTTP API. `parking_lot::RwLock` explicitly does not support recursive locking — calling `.read()` while already holding a read lock on the same thread causes a deadlock.

**Blast radius:** Complete deadlock of the HTTP API and any thread waiting on the fork choice lock. Caught during release testing (not in production). No v4.4.0 was ever released.

**Root cause:** Two separate code paths both acquired a fork choice read lock. When one path called into the other (via a helper function that also locked), the same thread would attempt to acquire the lock twice.

**Timeline:**
- 2023 (release cycle): v4.4.0 release candidate tested
- Bug found via `gdb` during release testing by paulhauner
- PR #4687 filed and merged
- v4.4.1 released instead — release notes explicitly state "there is no v4.4.0 release"

**Fix:** PR #4687 — restructure HTTP API to extract needed data while holding the first lock, eliminating the second lock acquisition entirely.

**Why not caught earlier:** Reentrant lock bugs require the two lock acquisitions to be in different code paths (not obviously nested). The specific HTTP API call chain was not covered by the existing test suite.

---

### Incident 9: Gossipsub "No Mesh Peers" — Silent Message Drop (2024)

**Subsystem:** networking  
**Severity:** critical (testnet-incident → mainnet concern)

**Trigger:** A bug in v5.1.0 caused Lighthouse nodes to have zero gossip mesh peers, meaning all published messages (attestations, blocks, etc.) were silently dropped — never reaching the network.

**Blast radius:** Complete gossip silence. Any affected node would appear online but contribute nothing to the network. Found in v5.1.0 shortly after release.

**Timeline:**
- 2024-03-12: v5.1.0 released with the bug
- v5.1.1 released same day or next with PR #5357 fix

**Fix:** PR #5357 — fix the mesh peer selection/management bug ensuring at least `mesh_n` peers are populated.

**Why not caught earlier:** The mesh peer count bug may have depended on a specific network state or peer count that only manifested on real networks, not small test networks.

---

### Incident 10: Holesky Testnet Outage — Electra Upgrade (Feb 2025)

**Issue:** [#7040](https://github.com/sigp/lighthouse/issues/7040)  
**Subsystem:** execution-layer (root cause in ELs); networking + consensus (Lighthouse impact)  
**Severity:** critical (mainnet-incident on Holesky)

**Trigger:** A configuration bug in Nethermind, Geth, and Besu execution layer clients during the Holesky Electra upgrade caused an invalid block to be justified. This split the chain — the majority of validators (running affected ELs) were on the invalid chain.

**Blast radius:** Complete Holesky testnet outage. Validators on the honest chain could not attest (slashing protection blocked double-votes). Validators on the invalid chain were building on the wrong fork. The chain did not finalize for 12+ hours. Memory usage exploded during non-finality (issue #7053).

**Root cause (Lighthouse-specific):**
1. The Lighthouse BN was importing both the valid and invalid forks, with ~200GB of side chain data accumulated overnight
2. The state cache (128 epoch boundary states × 180MB each ≈ 24GB) caused OOM under non-finality
3. The `balances` and `inactivity_scores` state diffs were 180MB+ per epoch under inactivity leak (changing every epoch)

**Timeline:**
- 2025-02-xx: Holesky Electra upgrade attempted; EL config bug causes invalid block to be justified
- 2025-02-26: paulhauner releases v7.0.0-beta.1 banning the invalid block
- 2025-02-26: #7040 opened as informational "front page" for rescue efforts
- 2025-02-28: Coordinated slashing organized at slot 3737760 (15:12 UTC)
- 2025-03-01: michaelsproul releases holesky-rescue branch with OOM mitigations (#7041)
- 2025-04-08: OOM issues tracked in #7053 resolved with v7.0.0 changes
- 2025-05-15: #7040 closed as incident over

**Fix (Lighthouse):** 
- v7.0.0-beta.1: ban the invalid block
- PR #7054: remove block root lookups from status processing (major OOM contributor)  
- PR #7066: fix `BlocksByRange` to avoid state lookups across finalized epoch boundary
- PR #7069: more intelligent state cache pruning
- State cache size reduced from 128 default

**Why not caught earlier:** EL config bug was a multi-client failure, not purely a Lighthouse issue. However, Lighthouse's OOM profile during non-finality was a known structural weakness (issue #5112 for PromiseCache, #6532 for size-based pruning) that was not addressed before a real non-finality event.

---

### Incident 11: Yamux Flow-Control Panics — v8.1.1/v8.1.2 (2026)

**Subsystem:** networking  
**Severity:** critical

**Trigger:** The yamux multiplexing layer (used for all libp2p connections) contained two panic-inducing bugs:
1. `increase_send_window_by()` would panic on integer overflow if a peer sent a crafted window-update frame
2. `consume_receive_window()` would panic on underflow if a peer sent more data than the declared window allowed

A second set of bugs in v8.1.2:
3. `on_drop_stream` would `expect`-panic if a stream was dropped after already being removed from the streams map
4. Quinn QUIC transport parameter parsing used `.unwrap()` on externally-controlled data

**Blast radius:** Any peer on the p2p network could crash a Lighthouse beacon node by sending crafted yamux/QUIC frames. Mandatory upgrade issued; "all prior releases affected."

**Root cause:** `parking_lot` panics / Rust integer overflow in externally-controlled numeric inputs within the networking multiplexer. No input validation on peer-supplied window sizes.

**Timeline:**
- 2026-02-27: v8.1.1 released as mandatory security upgrade (yamux overflow/underflow fix)
- 2026-03-09: v8.1.2 released as mandatory security upgrade (additional yamux, QUIC, gossipsub fixes)
- CVEs promised but not yet public as of research date (RUSTSEC-2026-0009 linked)

**Fix:** sigp/rust-yamux and sigp/quinn patches replacing panics with proper `Err(ConnectionError::InvalidWindowUpdate)` returns; sigp/rust-libp2p gossipsub fix for invalid backoff values on PRUNE.

**Why not caught earlier:** Third-party networking library code not owned by Lighthouse. Needed explicit audit of all externally-supplied numeric operations in the networking stack.

---

### Incident 12: GHSA-wm9c — Electra Epoch Processing Double-Application (2025)

**GHSA:** GHSA-wm9c-xvqq-5c28  
**Issue/PR:** [#7209](https://github.com/sigp/lighthouse/pull/7209)  
**Subsystem:** consensus  
**Severity:** critical

**Trigger:** In v7.0.0-beta.0 through v7.0.0-beta.4, single-pass epoch processing ran `process_effective_balance_updates` twice for validators affected by consolidations. The first run updates effective balances and resets pending consolidations; the second run re-applies the hysteresis check on the already-consolidated balances, producing wrong effective balances.

**Blast radius:** Any validator affected by an Electra consolidation would have an incorrect effective balance recorded in the beacon state. This is a consensus fault — Lighthouse nodes would compute different state roots from other clients for any epoch containing consolidations.

**Root cause:** The single-pass epoch processing loop (introduced for Electra) incorrectly called `process_effective_balance_updates` as a side effect during consolidation processing, in addition to the main epoch processing call.

**Timeline:**
- 2025 pre-Electra: Bug introduced during Electra/Pectra single-pass epoch processing implementation
- Discovered by @alexfilippov314 during the Cantina/EF Pectra security competition
- 2025: Fixed in v7.0.0-beta.5 via PR #7209

**Fix:** PR #7209 — restructure single-pass epoch processing to call `process_effective_balance_updates` exactly once, correctly handling consolidation-affected validators without double-application.

**Why not caught earlier:** The bug only manifested with Electra consolidations (a new feature), and the single-pass epoch processing was itself new code. Spec conformance tests for this specific combination were missing or insufficient.

---

### Incident 13: O(n²) find_head + Stack Overflow Under Non-Finality (2026)

**Issue:** [#9090](https://github.com/sigp/lighthouse/issues/9090)  
**Subsystem:** consensus  
**Severity:** critical (under non-finality)

**Trigger:** PR #9025 removed `best_child`/`best_descendant` caching from proto-array for spec clarity. This made `find_head` and `filter_block_tree` O(n²) in the number of unfinalized blocks (each node scanned all nodes to find children). Additionally, `filter_block_tree` was recursive — it would stack-overflow at approximately 30k unfinalized blocks.

**Blast radius:** Under extended non-finality with >30k unfinalized blocks, Lighthouse would crash with a stack overflow. Even before overflow, the O(n²) algorithm would make block processing increasingly slow, potentially causing missed duties.

**Root cause:** The "refactor for spec clarity" (PR #9025) removed a performance-critical caching layer without adding an equivalent replacement. The recursive implementation was never tested at the scale required to survive a real non-finality event.

**Timeline:**
- 2026 (post PR #9025): O(n²) regression introduced
- 2026-04-04: PR #9090 opened after the regression is identified
- 2026-06-05: PR #9090 merged (iterative O(n) children index built per find_head call)

**Fix:** PR #9090 — build a parent→children index map in O(n) once per `find_head` call; convert `filter_block_tree` from recursive to iterative reverse-order traversal (natural in proto-array insertion order).

**Why not caught earlier:** Performance tests were not run at the scale of non-finality scenarios (10k–500k unfinalized blocks). The Holesky 2025 incident should have prompted this kind of scale testing.

---

### Incident 14: Proposer Index Calculation Bug Post-Fulu (2025)

**Issue/PR:** [#8101](https://github.com/sigp/lighthouse/pull/8101)  
**Subsystem:** consensus  
**Severity:** critical

**Trigger:** After the Fulu fork, the code computing proposer indices was not lookahead-aware and did not use fork-aware proposer shuffling decision roots. This could result in validators being assigned incorrect slot proposals or proposing blocks with wrong proposer indices.

**Blast radius:** Potential consensus failure at the Fulu fork boundary. Found during the Fusaka security competition — if not caught, this would have caused divergent proposer assignments between Lighthouse and other clients.

**Root cause:** The `beacon_proposer_cache` and `proposer_shuffling_root_for_child_block` logic were not updated to be fork-aware during the Fulu implementation. The decision root used for shuffling lookup did not account for the fork boundary.

**Timeline:**
- 2025-09-22: Discovered by external researcher during Fusaka security competition
- 2025-09-26: PR #8101 merged — fork-aware proposer cache with end-to-end regression tests

**Fix:** PR #8101 — rework beacon proposer cache to be fork-aware; use correct lookahead decision roots; add unit tests for `ProtoBlock::proposer_shuffling_root_for_child_block`.

**Why not caught earlier:** Fork-upgrade boundary logic requires fork-specific test scenarios. The Fusaka security competition was the mechanism that caught it — suggesting that security competitions around fork boundaries are high-value.

---

### Incident 15: discv5 Docker SNAT ENR Loop → OOM (2025)

**Issue:** [#8437](https://github.com/sigp/lighthouse/issues/8437)  
**Subsystem:** networking  
**Severity:** critical

**Trigger:** When Lighthouse runs inside Docker alongside another container using the same UDP port, Docker's SNAT changes the externally-visible port. A bug in discv5 v10.1 (the version in v8.0.0) caused the node to rapidly toggle its ENR between two port values at ~500 updates/second. Each update allocated memory; 117GB RSS was reached within 14 minutes before OOM-kill.

**Blast radius:** Any Lighthouse node in a Docker environment with port conflicts crashes with OOM within minutes of starting. Affects home stakers with common Docker setups.

**Root cause:** discv5 v10.1 was missing a commit (`42d6ac55de3c779e78bfbfeca3d0da1bb9adbf11`) that fixed the SNAT-induced ENR loop. The fix existed in discv5's repository but was not included in the version Lighthouse v8.0.0 pinned.

**Timeline:**
- 2025-11-18: User OOM crash with 117GB RSS; "Address updated" log spam
- 2025-11-19: Issue #8437 filed
- 2025-11-24: Fixed via PR #8443 — pin discv5 to version including the SNAT fix
- v8.1.0: Included in release

**Fix:** PR #8443 — update discv5 dependency to version containing the SNAT port-flip fix.

**Why not caught earlier:** The fix existed upstream but was missed when pinning discv5 v10.1 for v8.0.0. No integration test for Docker SNAT environments.

---

## 4. Synthesis

### 4a. Counts by Class and Severity

**By bug class:**

| Class | Count |
|-------|-------|
| `protocol-networking` | 8 |
| `spec-correctness` | 8 |
| `resource` | 6 |
| `config-cli` | 6 |
| `logic-other` (RUSTSEC/dep) | 12 |
| `panic-crash` | 3 |
| `concurrency` | 2 |
| `persistence` | 2 |
| `api-correctness` | 3 |
| `fork-upgrade` | 2 |
| `el-integration` | 1 |
| `availability-da` | 2 |
| `perf-regression` | 1 |
| `serialization` | 2 |

**By severity:**

| Severity | Count |
|----------|-------|
| critical | 18 |
| high | 14 |
| medium | 15 |
| low | 9 |

### 4b. Subsystem by Severity

| Subsystem | Critical | High | Total |
|-----------|----------|------|-------|
| networking | 7 | 4 | ~18 |
| consensus | 7 | 4 | ~15 |
| validator-client | 2 | 3 | ~8 |
| database | 1 | 1 | 3 |
| execution-layer | 1 | 1 | 2 |
| http-api | 2 | 1 | 4 |
| slasher-crypto-misc | 0 | 2 | ~12 (mostly RUSTSEC) |
| data-availability | 0 | 0 | 2 |

### 4c. Recurring Root-Cause Themes

1. **Externally-controlled numeric inputs in networking code cause panics/OOM.** The yamux overflow/underflow bugs (v8.1.1/v8.1.2), gossipsub backoff panic (v8.1.2), and gossipsub unbounded queue OOM (#4918) are all networking-layer resource exhaustion bugs caused by insufficient bounds on peer-supplied numeric values. Lighthouse forks networking libraries and is responsible for their security; this has repeatedly been the critical vulnerability path.

2. **Performance optimizations break correctness.** PR #820 disabling attestation sig checks (#845), PR #9025 removing best_child/best_descendant caching (#9090), PR #3658 validator lookup optimization (#3660 revert), and the state cache size change in v7.0.0 (#7364 revert) all show a pattern of performance work that removed or weakened correctness invariants. The v4.4.0 deadlock (#4687) shows a similar "wrong direction" pattern where a new feature introduced a concurrency bug.

3. **Non-finality robustness lags.** The Holesky 2025 incident (#7040, #7053) revealed that Lighthouse's state cache design (128 × 180MB states) was catastrophic under the inactivity leak scenario. The O(n²) find_head bug (#9090) shows that even in 2026, non-finality scale testing was insufficient. This is a structural gap: the system has not been designed and tested to the full non-finality stress scenario.

4. **File permissions and auth are repeatedly missed in the VC layer.** Four separate issues (#2437, #2438, #7170, #7171) cover file permissions and log token exposure. Issue #2512 is an authentication bypass. All were found by external audit/researcher rather than internal review. The validator client security model (auth tokens, key file permissions) lacks systematic review.

5. **Fork-upgrade boundary code is a consistent source of critical bugs.** GHSA-wm9c (Electra epoch processing double-application), #8101 (Fulu proposer index), v4.0.0 retraction (fork choice at Capella), #1707 (BLS spec update), and the Holesky Electra outage all cluster around fork boundaries. New fork code is high-risk and insufficiently covered by cross-client conformance testing.

### 4d. Highest-Leverage Prevention Measures

1. **Mandatory panic/arithmetic audit for all externally-controlled numeric inputs in networking code.** Yamux, QUIC, gossipsub: any arithmetic on peer-supplied values (window sizes, backoff durations, sequence numbers) must use checked/saturating arithmetic or return graceful errors. This alone would have prevented the v8.1.1/v8.1.2 mandatory-upgrade incidents and the gossipsub backoff crash (#8955).

2. **Non-finality chaos tests at realistic scale (50k–500k unfinalized blocks).** The O(n²) find_head bug (#9090) would have been caught by a benchmark at 30k blocks. The Holesky OOM profile (#7053) would have been caught by running under inactivity-leak conditions with a realistic validator set. Neither was part of CI. Add a dedicated non-finality scenario in the test harness.

3. **Security competitions before every major fork upgrade.** The Fusaka competition caught #8101 (Fulu proposer index). The Cantina/EF Pectra competition caught GHSA-wm9c. Manual audit before fork launches (Capella, Deneb, Electra, Fulu) should be standard practice — the pattern of fork-boundary critical bugs is unambiguous.

4. **Correctness coverage for all performance-optimization PRs that remove/weaken checks.** A review checklist item: "does this PR remove or weaken any correctness-critical check?" — with required companion tests that directly exercise the removed check. PR #820 (#845), PR #9025 (#9090), and state-cache size changes all lacked this discipline.

5. **VC API security model review and automated auth penetration testing.** Issues #2437, #2438, #2512, #7170, #7171 were all found by an external researcher and a single internal code review, not by systematic security testing. A lightweight automated test that attempts unauthenticated write requests and checks file permissions would have caught all five.

**Dominant subsystems by severity:** Networking (7 critical) and Consensus (7 critical) are equally dominant in critical bugs — but for different reasons. Networking bugs are mostly panic-inducing peer-controlled arithmetic. Consensus bugs are mostly spec-correctness failures at fork boundaries or under unusual network conditions (forks, non-finality).
