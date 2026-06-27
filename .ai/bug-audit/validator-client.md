# Validator Client — Bug Audit

## Scope

This audit covers bugs in Lighthouse's validator client subsystem: attestation/proposal/sync-committee duties, slashing protection DB, doppelganger detection, web3signer/remote signer, keymanager API, fee recipient, graffiti, VC-to-BN fallback/multi-BN, attestation aggregation duties, and keystore/import.

Does NOT cover: beacon-node-side block production internals, generic HTTP API, EL/engine API internals (though fee-recipient and payload-attr bugs that cross into VC behavior are included).

**Queries run:**
- `gh issue list --repo sigp/lighthouse --label val-client --label bug --state all --limit 300`
- `gh issue list --repo sigp/lighthouse --label val-client --state all --limit 300`
- `gh issue list --repo sigp/lighthouse --label dvt --state all --limit 300`
- `gh search issues/prs` for: "slashing protection", "doppelganger", "web3signer", "remote signer", "keymanager", "fee recipient", "missed attestation", "missed proposal", "sync committee duty", "attestation aggregation", "validator duties", "fallback beacon node", "validator definitions", "keystore", "validator client" (merged PRs)
- Deep dives: `gh issue view <N> --comments`, `gh pr diff <N>`, and timeline API for closing PRs

---

## 2. Bug Table

| # | Title | State | Class | Severity | How-found | One-line root cause | Fix PR |
|---|-------|-------|-------|----------|-----------|---------------------|--------|
| [#1873](https://github.com/sigp/lighthouse/issues/1873) | Fix bug in slashing protection import | CLOSED | persistence | critical | code-review | Sequential interchange file imports don't update min-epoch bound; gap epochs become signable | (pre-mainnet fix) |
| [#3617](https://github.com/sigp/lighthouse/issues/3617) | Block with an incorrect fee recipient | CLOSED | config-cli | critical | mainnet-incident | Fallback BN had no fee recipient configured; real mainnet rewards went to junk address | [#3529](https://github.com/sigp/lighthouse/pull/3529) / follow-up |
| [#7403](https://github.com/sigp/lighthouse/issues/7403) | VC intermittently freezes on Linux kernel 6.14.4–6.14.7 | CLOSED | concurrency | critical | user-report | Linux kernel eventpoll bug froze Tokio runtime; all VC duties silently stopped | kernel 6.14.8+ / workaround |
| [#5687](https://github.com/sigp/lighthouse/issues/5687) | `InvalidSignature` errors from race between duties & attestation data | OPEN | concurrency | high | user-report | TOCTOU: BN re-orgs between duty fetch and attestation-data fetch; wrong shuffling used | — |
| [#4984](https://github.com/sigp/lighthouse/issues/4984) | Atomicity bug while adding validators using VC API | OPEN | persistence | high | user-report | Web3signer key added to in-memory store before full init; failed init leaves key stuck; re-add fails with DuplicatePublicKey | — |
| [#8667](https://github.com/sigp/lighthouse/issues/8667) | Sync committee messages have to wait for full block import | CLOSED | sync-logic | high | internal-testing | Sync committee `/beacon/head/root` blocked on full block import; near-certain epoch-boundary failures | (merged 2026-02-02) |
| [#8381](https://github.com/sigp/lighthouse/issues/8381) | Update VC to submit beacon committee selections once per epoch | CLOSED | spec-correctness | high | user-report | Selections submitted per-slot not per-epoch; broke mixed-client DVT clusters | (merged 2026-02-03) |
| [#6732](https://github.com/sigp/lighthouse/issues/6732) | Lighthouse under-subscribes attestation subnets for aggregation | CLOSED | logic-other | high | user-report | Off-by-one: unsubscription set to `duty.slot`, happening exactly when duty fires | [#6890](https://github.com/sigp/lighthouse/pull/6890) |
| [PR #5863](https://github.com/sigp/lighthouse/pull/5863) | Fix attestations not getting added to aggregation pool | CLOSED | logic-other | high | internal-testing | Delay-map entry expired before attestation arrived after subscription-spam optimization; aggregation gate rejected all attestations | — (is the fix) |
| [#5691](https://github.com/sigp/lighthouse/issues/5691) | web3signer doesn't set `Accept: application/json` header | CLOSED | protocol-networking | high | user-report | `Accept: */*` allows server to respond `text/plain`; Lighthouse fails to deserialize | [#5692](https://github.com/sigp/lighthouse/pull/5692) |
| [#5365](https://github.com/sigp/lighthouse/issues/5365) | SSV proposal block miss with Lighthouse v5.0.0 | CLOSED | concurrency | high | user-report | Global mutex on `block_production_state` serialized concurrent DVT requests; 4th request arrived ~2-3s late | (merged 2024-03-08) |
| [#3614](https://github.com/sigp/lighthouse/issues/3614) | VC should publish proposer prep and registrations to all BNs | CLOSED | protocol-networking | high | user-report | Proposer prep only sent to primary BN; fallback had no payload hint, producing 0-tx blocks | [#3529](https://github.com/sigp/lighthouse/pull/3529) |
| [#3302](https://github.com/sigp/lighthouse/issues/3302) | VC using excessive memory when using Web3Signer | CLOSED | resource | high | user-report | Each Web3Signer validator got its own `reqwest::Client`; 1000 validators = 1000 HTTP clients; OOM at scale | (merged 2022-09-08) |
| [#3141](https://github.com/sigp/lighthouse/issues/3141) | VC trips slashing protection when publishing blocks via fallback | CLOSED | logic-other | high | user-report | Signed block recorded before publish; timeout during publish → fallback sees a "different block same slot" → DoubleBlockProposal rejection | [#3188](https://github.com/sigp/lighthouse/pull/3188) |
| [#2926](https://github.com/sigp/lighthouse/issues/2926) | High inclusion lag and missed attestations with fallback BN | CLOSED | protocol-networking | high | user-report | VC still retried primary BN (causing 8s+ timeouts per slot) before falling back; health check not integrated into duty path | [#4393](https://github.com/sigp/lighthouse/pull/4393) |
| [#2409](https://github.com/sigp/lighthouse/issues/2409) | Add file locking for `validator_definitions.yml` | OPEN | concurrency | high | code-review | Account manager and HTTP API can both write definitions file concurrently; one write clobbers the other | — |
| [#2394](https://github.com/sigp/lighthouse/issues/2394) | VC blocks on `SlashingDatabase::open` when running with NSSM on Windows | OPEN | concurrency | high | user-report | Async runtime / blocking I/O interaction hangs indefinitely when started as Windows NSSM service | — |
| [#1973](https://github.com/sigp/lighthouse/issues/1973) | Validator fails to start after hard reboot due to json.lock files | CLOSED | persistence | high | user-report | Keystore lock files not cleaned on SIGKILL; VC treats them as active locks and refuses to start | (merged 2020-11-25) |
| [PR #6748](https://github.com/sigp/lighthouse/pull/6748) | Fix incorrect VC default HTTP token path with `--datadir` | CLOSED | config-cli | high | user-report | Regression: `--datadir` changed token path to `$HOME/.lighthouse/...` instead of `<datadir>/...`; "Permission denied" crash in containers | — (is the fix) |
| [PR #8846](https://github.com/sigp/lighthouse/pull/8846) | VC head monitor SSE connection timeout | CLOSED | config-cli | high | user-report | Default HTTP timeout applied to SSE stream; stream timed out and retried continuously in v8.1.0 | — (is the fix) |
| [#4550](https://github.com/sigp/lighthouse/issues/4550) | Teku VC cannot use Lighthouse BN | CLOSED | api-correctness | high | user-report | Lighthouse BN missing fields from consensus-specs #3375 in `/eth/v1/config/spec`; Teku `--network=auto` fails | (merged 2024-04-03) |
| [#6983](https://github.com/sigp/lighthouse/issues/6983) | v2 aggregate_attestation returns 404 for Deneb nodes | CLOSED | api-correctness | high | user-report | `/eth/v2/validator/aggregate_attestation` only handled post-Electra; returned 404 on Deneb | [#6984](https://github.com/sigp/lighthouse/pull/6984) |
| [PR #4703](https://github.com/sigp/lighthouse/pull/4703) | Wrong `parent_beacon_block_root` in proposer prep payload attrs | CLOSED | el-integration | high | user-report | Sent root of head's *parent* instead of head itself for EIP-4788; payload ID cache miss every slot; Besu incompatible | — (is the fix) |
| [#4802](https://github.com/sigp/lighthouse/issues/4802) | Re-org feature does not work with Vouch blinded proposals | CLOSED | protocol-networking | high | user-report | Vouch rejects Lighthouse's locally-built payload when re-org suppresses original; fallback produces 0-tx block past 1s cutoff | (merged 2024-11-12) |
| [#1537](https://github.com/sigp/lighthouse/issues/1537) | Improve atomicity of slashing protection DB creation | OPEN | persistence | medium | code-review | SQLite file created but tables never written if process killed mid-init; next startup fails on missing schema | — |
| [#4635](https://github.com/sigp/lighthouse/issues/4635) | keymanager API `voluntary_exit` spec compliance | CLOSED | api-correctness | medium | user-report | GET response returned bare `{message, signature}` without the required `{data: ...}` wrapper | (merged 2023-09-22) |
| [#6925](https://github.com/sigp/lighthouse/issues/6925) | Electra `aggregate_attestation` missing version header | CLOSED | api-correctness | medium | user-report | v2 endpoint missing `Eth-Consensus-Version` header post-Electra as required by spec | (merged 2025-02-10) |
| [#4717](https://github.com/sigp/lighthouse/issues/4717) | Historic sync duties fail for recently-activated validators | OPEN | logic-other | medium | user-report | Optimization loads older state; recently-activated validator not in it; returns 500 `UnknownValidator` | — |
| [#3507](https://github.com/sigp/lighthouse/issues/3507) | GET `/eth/v1/validator/{pubkey}/feerecipient` returns 500 when fee recipient not set | OPEN | api-correctness | medium | user-report | No fee recipient configured → 500 Internal Server Error instead of 404 | — |
| [#3442](https://github.com/sigp/lighthouse/issues/3442) | Fee recipient GET returns 405 instead of 404 for unknown key | CLOSED | api-correctness | medium | user-report | Unknown pubkey routed to wrong method handler, returning 405 | (merged 2022-11-03) |
| [#3421](https://github.com/sigp/lighthouse/issues/3421) | Doppelganger false positive with Teku | OPEN | protocol-networking | medium | user-report | Teku timing behavior creates apparent attestation duplicates; triggers Lighthouse doppelganger logic incorrectly | — |
| [#3085](https://github.com/sigp/lighthouse/issues/3085) | VC CRIT spam waiting for sync committee duties with 0 validators | CLOSED | logic-other | medium | user-report | PR #2999 skipped duty poll with 0 validators but left sync duties map empty; service then logged CRIT repeatedly | (merged 2022-03-15) |
| [#2012](https://github.com/sigp/lighthouse/issues/2012) | Insecure filesystem permissions on validator key files | CLOSED | config-cli | medium | code-review | Keystores created with permission `777`; any local user could overwrite or delete them | (merged 2020-11-29) |
| [#5600](https://github.com/sigp/lighthouse/issues/5600) | `secrets-dir` flag does not work as intended | OPEN | config-cli | medium | user-report | Flag ignored when `validator_definitions.yml` already has explicit password paths; also create path mismatch | — |
| [#5044](https://github.com/sigp/lighthouse/issues/5044) | BN reporting as "available" when it isn't | OPEN | protocol-networking | medium | user-report | Health check returns available even when BN is in a non-useful state for VC duties | — |
| [PR #7892](https://github.com/sigp/lighthouse/pull/7892) | VC always waits 4s to attest; misses early-block window | CLOSED | spec-correctness | medium | internal-testing | Spec says attest "4s into slot OR on receiving valid head, whichever first"; Lighthouse always waited 4s | — (is the fix) |
| [#4359](https://github.com/sigp/lighthouse/issues/4359) | Proposer-nodes not preferred over beacon-nodes | OPEN | logic-other | medium | user-report | Block publishing path used non-proposer BN despite `--proposer-nodes` config | — |
| [#5288](https://github.com/sigp/lighthouse/issues/5288) | VC logs "Successfully published attestations" even when count=0 | CLOSED | logic-other | low | user-report | Empty attestation list POSTed to BN; success logged at INFO while failures logged at CRIT elsewhere | (merged 2024-03-08) |
| [#5880](https://github.com/sigp/lighthouse/issues/5880) | Blank line at end of graffiti-file causes error | OPEN | config-cli | low | user-report | Parser rejects blank lines (common trailing newline) as `InvalidLine("Missing delimiter")`; entire file ignored | [#6635](https://github.com/sigp/lighthouse/pull/6635) |
| [#4341](https://github.com/sigp/lighthouse/issues/4341) | VC performing all duties 1 second early | CLOSED | logic-other | low | user-report | System timing/clock issue caused duties to fire at 3s instead of 4s into slot | (merged 2023-05-26) |
| [#3985](https://github.com/sigp/lighthouse/issues/3985) | `first_success` swallows intermediate errors | CLOSED | logic-other | low | user-report | `first_success` returned early on success without propagating prior errors; made diagnoses very hard | (merged 2023-03-11) |
| [#3634](https://github.com/sigp/lighthouse/issues/3634) | Doppelganger waits unnecessarily on clean restart | CLOSED | logic-other | low | user-report | No mechanism to tell doppelganger detection that recent missed attestations were from self (clean shutdown) | (merged 2023-01-16) |
| [#3432](https://github.com/sigp/lighthouse/issues/3432) | Error in VC when fee recipient only set in BN | CLOSED | config-cli | low | user-report | VC emits misleading error if fee recipient not set in VC even if BN default is present | (merged 2025-05-13) |
| [#3422](https://github.com/sigp/lighthouse/issues/3422) | Subnet subscriptions not sent to all connected BNs | CLOSED | protocol-networking | medium | user-report | Subnet subscriptions and aggregation duties only sent to primary BN; fallback BNs unaware of duties | (merged 2022-09-29) |
| [#8080](https://github.com/sigp/lighthouse/issues/8080) | False positives in validator monitor missed block logging | OPEN | logic-other | low | user-report | Validator monitor logs missed blocks as false positives in certain edge cases | — |
| [#2656](https://github.com/sigp/lighthouse/issues/2656) | Doppelganger protection test script false success | OPEN | logic-other | low | internal-testing | Test script can exit 0 when doppelganger protection actually failed to trigger | — |

---

## 3. Deep Dives

### Bug #1873 — Slashing protection import allows signing in epoch gaps

**Root cause:** EIP-3076 interchange import records `min_attestation_source` and `min_attestation_target` per validator. When two files are imported sequentially (epochs 0–50 then 100–150), the second import's minimum of 100 did not overwrite the first file's maximum of 50. The DB therefore still permitted signing in epochs 50–100, violating the guarantee that the interchange file's epoch is a safe lower bound.

**How discovered:** Code review during development; issue was filed and fixed before mainnet launch.

**How fixed:** The import logic was corrected to take the maximum observed epoch across all imports as the safe lower bound, not replace.

**Why it wasn't caught earlier:** The sequential-import scenario was not covered by tests. Single-file import was tested but not multi-file with a gap.

**Could-have-been-caught-by:** Property-based test asserting that after importing any sequence of interchange files, no previously-seen epoch is ever signable again (import monotonicity invariant).

---

### Bug #3617 — Block produced with incorrect (junk) fee recipient on mainnet

**Root cause:** A real user configured: VC with `--suggested-fee-recipient`, primary BN (Teku) with its own default, and a Lighthouse fallback BN with no fee recipient. When the primary BN disconnected mid-proposal cycle, the VC fell back to Lighthouse BN, which had no fee recipient and used a zero/junk address. The block was produced and published with rewards going to that address.

**How discovered:** Mainnet incident; user reported lost block rewards.

**How fixed:** PR #3529 made VC broadcast proposer preparation (with fee recipient) to ALL connected BNs at epoch start. Follow-up PRs extended this to validator registrations. The root architectural issue was that BN-specific state (fee recipient hint) was not synchronized across all registered BNs.

**Why it wasn't caught earlier:** Multi-BN failover testing didn't cover the case where only *some* BNs had fee recipients configured. The "happy path" always had primary BN with correct config.

**Could-have-been-caught-by:** Integration test simulating primary BN disconnect during block proposal; assertion that the produced block's fee recipient matches VC config. Also: a startup validation warning if `--suggested-fee-recipient` is not set and VC has fallback BNs configured.

---

### Bug #7403 — VC silently freezes on Linux kernel 6.14.4–6.14.7

**Root cause:** A regression in Linux kernel 6.14.4's `eventpoll` code (filed upstream as tokio/tokio#7335) caused the epoll-based I/O reactor to stall indefinitely when no I/O events arrived. Tokio's runtime simply stopped scheduling tasks. The VC process was alive (not crashed), but no duties were executed and no errors were emitted.

**How discovered:** User reports that VC "appeared healthy" but produced no attestations for extended periods. Correlated with specific kernel version range.

**How fixed:** Fixed in Linux kernel 6.14.8. Lighthouse-side workaround: poll a local VC API endpoint every few seconds to keep Tokio awake.

**Why it wasn't caught earlier:** External kernel regression; no Lighthouse code change required. CI runs on stable kernels. The failure mode (silent stall with no error) made it especially hard to detect.

**Could-have-been-caught-by:** A VC liveness monitor that alerts if no attestation duty has been executed for >1 epoch (independent of log monitoring). This would catch *any* silent freeze regardless of cause.

---

### Bug #5687 — TOCTOU race between duties and attestation data (OPEN)

**Root cause:** When a BN re-orgs between the VC's `GET /eth/v1/validator/duties/attester/{epoch}` call and its `POST /eth/v1/validator/attestation_data` call, the attestation data is for the post-reorg head but the committee assignments are from pre-reorg state. The BN correctly rejects the signature as `InvalidSignature`. This is a classic time-of-check/time-of-use (TOCTOU) race.

**How discovered:** Became more observable after PR #5500 made re-orgs more likely to produce this window. User-reported on mainnet.

**How fixed:** Not yet fixed. One approach: re-request duties after fetching attestation data and compare; another is to include the epoch's committee root in the attestation data response and verify before signing.

**Why it wasn't caught earlier:** Re-orgs are rare on mainnet; the race window is millisecond-scale. Under load testing or re-org simulation it would be observable.

**Could-have-been-caught-by:** Chaos/fault-injection test that injects a re-org between the two VC HTTP requests and checks for missed attestations. An invariant could be: attestation data's shuffling must be consistent with the committee assignment used.

---

### Bug #4984 — Atomicity bug in web3signer validator add via API (OPEN)

**Root cause:** The `POST /lighthouse/validators/web3signer` handler adds the key to the in-memory `ValidatorStore` before all initialization (TLS handshake, key derivation, disk write) completes. If any of these steps fail, the in-memory store is in an inconsistent state: it has the key but disk does not. A subsequent re-add attempt fails with `DuplicatePublicKey`. VC restart is required to clear the bad state.

**How discovered:** User-reported when adding a validator with an invalid TLS certificate.

**How fixed:** Not yet fixed. Correct approach: complete all initialization steps (disk write + connectivity check) before inserting into the in-memory store, and roll back disk changes if the store insertion fails.

**Why it wasn't caught earlier:** Error paths in validator addition were not integration-tested. The success path was well-tested.

**Could-have-been-caught-by:** Error-path integration test: attempt to add a validator with invalid config, verify that the re-add succeeds without restarting VC. This would expose the bad in-memory state.

---

### Bug #8667 — Sync committee messages blocked on full block import

**Root cause:** The attestation service uses `early_attester_cache` to serve attestation data from a partially-imported block. No equivalent existed for sync committee messages; these required the full block import to complete before `/beacon/head/root` returned the new head. At epoch boundaries, a new block is produced and imported while sync committee messages for that slot are due; the import delay means messages arrive late or not at all.

**How discovered:** Internal testing / code review comparing attestation vs. sync committee paths.

**How fixed:** The BN was modified to expose the head root earlier for sync committee duty purposes, analogous to the early attester cache.

**Why it wasn't caught earlier:** The attestation path was optimized (early attester cache) in isolation; the sync committee path was overlooked. No monitoring alert for "sync committee message not submitted on time" vs "attestation late."

**Could-have-been-caught-by:** Test asserting that sync committee messages are submitted within X ms of block arrival, measured at epoch boundaries specifically.

---

### Bug #8381 — DVT beacon committee selections submitted per-slot instead of per-epoch

**Root cause:** The Ethereum spec requires VC to submit `BeaconCommitteeSelection` aggregates once per epoch (at epoch start, for current+next epoch). Lighthouse was submitting them once per slot (for the current slot). This worked in single-VC setups but broke mixed-client DVT clusters (e.g., Lighthouse VC + Teku VC) where middleware required consistent epoch-level submissions.

**How discovered:** User-reported DVT cluster aggregation failures in mixed-client setups.

**How fixed:** Changed submission to per-epoch schedule, aligned with spec.

**Why it wasn't caught earlier:** Single-client setups don't expose the mismatch. DVT interoperability testing requires running actual multi-client clusters, which was not part of CI.

**Could-have-been-caught-by:** Spec compliance test that checks submission frequency matches the spec schedule. DVT-specific CI that exercises a mixed Lighthouse+Teku cluster.

---

### Bug #6732+PR#6890 — Off-by-one in subnet unsubscription causes aggregation failures in v6.x

**Root cause:** The subnet subscription logic computed unsubscription time as `subscription.slot + 1` (correct intent: stay subscribed until the duty slot completes). But the subscription itself was scheduled at `duty.slot - 1`. The combination meant the effective window was `[duty.slot - 1, duty.slot)` — the node unsubscribed at the start of the duty slot, exactly when it needed to be subscribed. All aggregation failed for the duration of v6.x.

**How discovered:** User-reported massive decrease in aggregate quality after v6.0.0 upgrade.

**How fixed:** PR #6890 — unsubscription set to `duty.slot + 1`.

**Why it wasn't caught earlier:** The regression was introduced when a subscription optimization PR (reducing subnet spam) shifted the subscription time from `duty.slot` to `duty.slot - 1` but did not adjust the unsubscription counter. The two PRs were authored separately and the interaction was not tested.

**Could-have-been-caught-by:** An integration test measuring aggregate quality (number of validators covered per aggregate) before/after each subscription-related change. A CI alert on "aggregation rate" would have flagged the regression immediately.

---

### PR #5863 — Attestations not added to aggregation pool after subscription optimization

**Root cause:** PR #4806 reduced subnet subscription spam by not subscribing before every slot. This optimization removed the entry from a delay map that `should_process` used to determine whether an attestation should be aggregated. With no delay map entry, `should_process` returned `false` and attestations were forwarded but not aggregated. Default configuration affected.

**How discovered:** Internal testing after observing low aggregate quality in CI.

**How fixed:** PR #5863 — fixed the aggregation gate to not depend on the delay map entry from subscription.

**Why it wasn't caught earlier:** Two independent optimizations interacted badly. The subscription change (PR #4806) removed a side-effect that the aggregation gate depended on, but neither PR author noticed the dependency.

**Could-have-been-caught-by:** Integration test with assertion that `--import-all-attestations` is NOT needed for normal aggregation (i.e., default config produces equivalent aggregate quality). Measuring aggregate coverage per subnet per slot in CI.

---

### Bug #5691 — Web3Signer wrong `Accept` header

**Root cause:** Lighthouse sent `Accept: */*` to Web3Signer. The Web3Signer reference implementation is allowed to respond with `Content-Type: text/plain` when `application/json` is not explicitly requested. Lighthouse's JSON deserializer then failed on the plain-text response body.

**How discovered:** User-reported that remote signing failed with certain Web3Signer server configurations.

**How fixed:** PR #5692 — added `Accept: application/json` to all requests to Web3Signer.

**Why it wasn't caught earlier:** No integration test ran against a real Web3Signer instance that tested content negotiation. All tests used a mock that always returned JSON.

**Could-have-been-caught-by:** Integration test against actual Web3Signer binary with content negotiation verification.

---

### Bug #5365 — SSV concurrent block requests serialized by global lock

**Root cause:** Lighthouse v5.0.0 added a global mutex on `block_production_state` (PR #4925) for an unrelated correctness reason. DVT setups (e.g., SSV with 4 operators) send 4 concurrent requests to `GET /eth/v1/validator/blinded_blocks/{slot}`. All 4 were serialized by this lock, each taking ~700ms, so the 4th arrived ~2.8s later than the first. By the time SSV completed consensus, the block was past the broadcast deadline.

**How discovered:** User-reported DVT missed block proposals after upgrade to v5.0.0.

**How fixed:** Lock scope was narrowed or the lock was removed from the hot path.

**Why it wasn't caught earlier:** The global lock was added for single-validator correctness; multi-concurrent-request DVT scenarios were not tested.

**Could-have-been-caught-by:** Benchmark test measuring p99 latency for N concurrent block requests; alert if any request takes >1s in a 4-concurrent scenario.

---

### Bug #3141 — Slashing protection false positive blocks fallback BN after primary timeout

**Root cause:** The block production flow at the time of this bug was: (1) produce block from BN, (2) sign block and record in slashing DB, (3) publish block to BN. If step 3 timed out on the primary BN, the VC retried on a fallback BN. But the fallback BN built a *different* block for the same slot (different transactions, different state root). When VC tried to sign *that* block, the slashing DB correctly flagged it as a double block proposal and rejected it — even though no actual double proposal had occurred.

**How discovered:** User-reported that primary BN timeout caused block proposals to permanently fail for that slot.

**How fixed:** PR #3188 restructured the flow: (1) produce block from first responsive BN, (2) sign once, (3) publish to first responsive BN. The sign-and-record step happens only once regardless of how many BNs are tried for publication.

**Why it wasn't caught earlier:** Multi-BN setups were not common in early Lighthouse deployments. Single-BN users never hit this path.

**Could-have-been-caught-by:** Integration test: two BNs configured, primary times out during publish, assert fallback BN publishes block successfully without slashing protection rejection.

---

### Bug #2926 — Missed attestations during primary BN downtime

**Root cause:** When the primary BN was marked as offline, the VC health check happened on a separate timer. On each attestation duty, the VC still tried the primary BN first, waited the full 8-second HTTP timeout, then fell back. With a 12-second slot time, this consumed most of the inclusion window.

**How discovered:** User-reported high inclusion delays and missed attestations during primary BN downtime.

**How fixed:** PR #4393 reworked the fallback mechanism to mark BNs as unhealthy and immediately route to healthy BNs without attempting unhealthy ones on each duty cycle.

**Why it wasn't caught earlier:** Primary BN downtime was not simulated in integration tests. The timeout behavior was only observable in production environments.

**Could-have-been-caught-by:** Integration test: kill primary BN, verify next attestation duty completes within 2s (not 10s). Monitor: alert if attestation inclusion slot exceeds duty slot + 2.

---

### Bug #3614 — Proposer prep and validator registrations only sent to primary BN

**Root cause:** The VC broadcast proposer preparation hints (for `engine_forkchoiceUpdated` payload attributes) only to the current primary BN. If the primary failed between epoch start (when prep was sent) and the actual proposal slot, the fallback BN had no payload hint. Result: fallback BN would request a payload from EL without attributes, resulting in a block with zero transactions.

**How discovered:** User-reported zero-tx blocks when primary BN failed.

**How fixed:** PR #3529 changed proposer prep to broadcast to ALL registered BNs. A follow-up PR extended this to validator registrations (builder API).

**Why it wasn't caught earlier:** Single-BN testing never exposed this. The "broadcast to all" pattern was not the default design choice.

**Could-have-been-caught-by:** Integration test: register validator with 2 BNs; disconnect primary before proposal slot; assert produced block has non-zero transactions.

---

### Bug #1973 — VC fails to start after hard reboot due to stale lock files

**Root cause:** When the VC opens a keystore, it creates a `.lock` file to prevent concurrent access. If the process is killed uncleanly (SIGKILL, power loss), these lock files are not deleted. On next startup, the VC treats the lock file as evidence of a live process and refuses to open the keystore, leaving the validator unable to start without manual `rm *.lock`.

**How discovered:** User-reported after power outage.

**How fixed:** Lock file handling was improved to check if the owning PID is still alive (on Unix) and remove stale locks.

**Why it wasn't caught earlier:** Clean shutdown always cleaned up locks. Crash/kill scenario not in CI.

**Could-have-been-caught-by:** Test that SIGKILL's VC mid-operation and verifies it restarts cleanly without manual intervention.

---

### PR #6748 — Incorrect default HTTP token path with `--datadir`

**Root cause:** A refactoring PR (#6577) introduced a regression: when `--datadir` was specified, the VC computed the API token file path as `$HOME/.lighthouse/mainnet/validators/api-token.txt` instead of `<datadir>/validators/api-token.txt`. In containerized deployments (e.g., eth-docker), the home directory was not writable, causing a "Permission denied" CRIT error and VC startup failure.

**How discovered:** User-reported in eth-docker issue tracker.

**How fixed:** PR #6748 — corrected the path resolution logic.

**Why it wasn't caught earlier:** The regression was in a rarely-tested code path (non-default `--datadir` with non-standard HOME). No test covered the case where `--datadir` differs from the default.

**Could-have-been-caught-by:** Parameterized test of VC startup with `--datadir=/some/path`, asserting the token is written to `/some/path/validators/api-token.txt`.

---

## 4. Synthesis

### Counts by class

| Class | Count |
|-------|-------|
| logic-other | 13 |
| api-correctness | 8 |
| concurrency | 6 |
| config-cli | 7 |
| persistence | 4 |
| protocol-networking | 6 |
| spec-correctness | 3 |
| el-integration | 2 |
| resource | 1 |
| sync-logic | 1 |

### Counts by severity

| Severity | Count |
|----------|-------|
| critical | 3 |
| high | 22 |
| medium | 12 |
| low | 9 |

**Total bugs cataloged: 46**

---

### Recurring root-cause themes

**1. Multi-BN state not synchronized (cluster of 4–5 bugs)**
Issues #3617, #3614, #3422, #2926, #3141 all share the same architectural deficiency: the VC maintained "per-primary-BN" state (fee recipient hints, subnet subscriptions, proposer prep, validator registrations) that was not broadcast to all registered BNs. When the primary failed, fallbacks were unprepared. This was a fundamental design choice that required systematic remediation across multiple PRs.

**2. Aggregation gate fragility (2–3 bugs, high reward impact)**
Issues #6732, PR #5863, and #3422 all caused large-scale degradation in attestation aggregation quality — one of the highest-reward activities for validators. In each case, an independent optimization (subscription timing, delay map, subnet announcement) interacted badly with the aggregation gate. The gate was not independently monitored, so regressions weren't caught until user reports.

**3. Slashing protection correctness at boundaries (3 bugs)**
Issues #1873 (sequential import gaps), #3141 (fallback-BN false positive), and #1537 (non-atomic DB init) all represent edge cases in the slashing protection subsystem that were either not tested or only hit under unusual conditions (two imports, primary BN timeout, process kill during init). The first caused a real safety risk; the others caused false positives or startup failures.

**4. DVT/concurrent-request assumptions (2 bugs)**
Issues #5365 and #8381 both reveal that the VC was implicitly designed for single-operator use. A global lock serialized concurrent block requests; committee selections were submitted per-slot not per-epoch. DVT setups exposed concurrency and protocol assumptions that single-VC testing never exercised.

**5. HTTP client/API integration with remote signers (3 bugs)**
Issues #5691 (wrong Accept header), #3302 (per-validator HTTP clients), and #4984 (atomicity in web3signer add) all point to insufficient integration testing of the web3signer HTTP path. Each was caught only when real deployments hit edge cases.

**6. Config/path regressions in containerized deployments (3 bugs)**
PR #6748 (API token path), #8846 (SSE timeout), and #5600 (secrets-dir) show that configuration handling regresses frequently when refactoring. Container environments (eth-docker, Kubernetes) expose non-standard paths and service models that are rarely tested.

---

### Highest-leverage early-detection investments

**1. Aggregation quality integration test (catches #6732, PR #5863, #3422)**
After every PR touching subscription, aggregation, or subnet code: run a local network, produce blocks for 10 epochs, assert that aggregation coverage per subnet exceeds a threshold (e.g., >80% of attesting validators covered per aggregate). This would have caught both v6.x off-by-one and the delay-map regression immediately.

**2. Multi-BN failover integration harness (catches #3617, #3614, #2926, #3141)**
A standardized test: start VC with 2 BNs, kill primary at various points in the proposal cycle (before produce, after produce, during publish), assert correct block produced with correct fee recipient and zero missed attestations. This scenario is too complex for unit tests but straightforward with a local testnet.

**3. Slashing protection property-based tests (catches #1873, #3141)**
Fuzz the interchange import path with arbitrary sequences of interchange files. Assert monotonicity: no epoch that appeared in any previously-imported file is ever signable after import. Additionally, property test the multi-BN produce/sign/publish flow: signing may occur exactly once per slot regardless of how many BNs are tried.

**4. DVT concurrent-request latency test (catches #5365, #8381)**
Benchmark: send N concurrent block requests to a single VC, assert p99 latency < 500ms for N up to 8. Run this in CI against every release. Additionally: spec-compliance test asserting committee selections are submitted exactly once per epoch, not once per slot.

**5. VC restart liveness test (catches #7403, #1973, PR #6748)**
After SIGKILL or simulated kernel-level stall: assert VC restarts cleanly, all validators are operational within 2 epochs, and no manual intervention (lock file deletion, config override) is required. For the kernel-freeze scenario: deploy a canary that emits a metric every epoch; alert if no metrics for >2 epochs.

---

### Structural / architectural smells

- **`beacon_node_fallback.rs` is a hotspot**: Five separate bugs required changes to the multi-BN routing and fallback logic. The module has accumulated correctness constraints (health tracking, per-duty routing, broadcast vs. first-success) that are tested only ad-hoc. A formal "BN selector" abstraction with explicit invariants (all BNs have proposer prep, subnet subscriptions sent to all) would help.

- **Aggregation gate has implicit dependencies**: The aggregation gate (`should_process`) implicitly depends on subscription state tracked in another module. This coupling has caused bugs twice (PR #5863, #6732). Decoupling or making the dependency explicit would reduce this risk.

- **Web3Signer path undertested**: The remote signing path consistently produces bugs when hit by real deployments. This code path needs a mandatory integration test suite against a real (or realistic mock) Web3Signer binary.

- **Slashing protection lacks atomicity guarantees at multiple levels**: From DB creation (#1537) to import sequencing (#1873) to the sign-then-publish interaction (#3141), the slashing protection subsystem has repeatedly had atomicity problems. A formal review of "what are all the atomic operations we need" and corresponding test coverage would close this gap.
