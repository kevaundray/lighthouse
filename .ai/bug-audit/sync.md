# Sync — Bug Audit

## Scope

This audit covers bugs in Lighthouse's sync subsystem: range sync, backfill sync, block/blob/data-column lookup sync, sync stalls, batch handling, and head tracking. The source code lives primarily in `beacon_node/network/src/sync/`. The audit does **not** cover gossip/discovery/RPC transport bugs (networking agent scope), DB/checkpoint-store internals, or DA verification logic itself — overlaps are flagged inline.

## Queries Run

```
gh issue list --repo sigp/lighthouse --label "syncing" --label "bug" --state all --limit 300
gh issue list --repo sigp/lighthouse --label "syncing" --state all --limit 300
gh search issues --repo sigp/lighthouse "range sync" --state {open,closed}
gh search issues --repo sigp/lighthouse "backfill sync" --state {open,closed}
gh search issues --repo sigp/lighthouse "parent lookup" --state {open,closed}
gh search issues --repo sigp/lighthouse "single block lookup" --state {open,closed}
gh search issues --repo sigp/lighthouse "optimistic sync" --state {open,closed}
gh search issues --repo sigp/lighthouse "checkpoint sync" --state {open,closed}
gh search issues --repo sigp/lighthouse "data column by root" --state {open,closed}
gh search issues --repo sigp/lighthouse "custody by root" --state {open,closed}
gh search issues --repo sigp/lighthouse "not syncing" --state {open,closed}
gh search issues --repo sigp/lighthouse "lookup stuck" --state {open,closed}
```

PRs and their diffs were checked for root cause confirmation.

---

## 2. Bug Table

| # | Title | State | Class | Severity | How-found | One-line root cause | Fix PR |
|---|-------|-------|-------|----------|-----------|---------------------|--------|
| [#7360](https://github.com/sigp/lighthouse/issues/7360) | Range sync process_completed_batches assumes processing_target exists | CLOSED | sync-logic | high | testnet-incident | `process_completed_batches` unconditionally tries to find the batch at `processing_target` even when the batch was never requested (no idle peers or no sampling peers) — removes the chain with WrongChainState | [#7391](https://github.com/sigp/lighthouse/pull/7391) |
| [#6895](https://github.com/sigp/lighthouse/issues/6895) | Range sync stuck due to insufficient peers on data column subnets when triggered | CLOSED | sync-logic | high | testnet-incident | Head chain sync starts before peer metadata (custody counts) is known; `good_peers_on_sampling_subnets` returns false, blocking batch dispatch with no re-trigger on metadata arrival | — (workaround + #6258) |
| [#6989](https://github.com/sigp/lighthouse/issues/6989) | Supernode unable to progress range sync due to unknown RPC error | CLOSED | sync-logic | high | testnet-incident | RPC error on column stream was not logged; batch failed silently with "RPC Error" due to missing columns, causing repeated retries with no progress | [#6990](https://github.com/sigp/lighthouse/pull/6990) |
| [#7980](https://github.com/sigp/lighthouse/issues/7980) | Lighthouse repeatedly sending DataColumnsByRoot requests for same block | CLOSED | sync-logic | high | testnet-incident (cross-client report) | Empty RPC responses were not counted as peer failures, allowing infinite retries to the same unresponsive peers; random peer selection also caused fragmented single-column requests | [#8005](https://github.com/sigp/lighthouse/pull/8005) |
| [#8104](https://github.com/sigp/lighthouse/issues/8104) | Stuck block lookup on nodes running latest `unstable` | CLOSED | sync-logic | high | internal-testing | Block in processing cache causes new lookup to return `Pending` on block request; processing result arrives for old lookup ID and is ignored, leaving new lookup permanently stuck in `AwaitingDownload` | [#8111](https://github.com/sigp/lighthouse/pull/8111) (+others) |
| [#5694](https://github.com/sigp/lighthouse/issues/5694) | single_block_lookups leak | OPEN (fixed in PRs) | resource | medium | internal-testing | Lookups created for blocks already in the DA checker skip the block request; no completion event is ever received so the lookup is never removed (100k–150k leaked lookups observed) | [#5583](https://github.com/sigp/lighthouse/pull/5583), [#5681](https://github.com/sigp/lighthouse/pull/5681) |
| [#5833](https://github.com/sigp/lighthouse/issues/5833) | Stuck lookup reports (collection) | OPEN | sync-logic | medium | internal-testing | Multiple root causes: race where processing result returns for an obsolete lookup ID; blob request fails with no peers and drops the lookup, causing re-creation that misses the completed processing event | TBD |
| [#6703](https://github.com/sigp/lighthouse/issues/6703) | Stuck lookups involving block requests that never time out | CLOSED | sync-logic / protocol-networking | medium | user-report | Dial negotiation counter could saturate on repeated IO errors, stopping further dials; RPC requests queued but never sent, lookup never timed out | [#6711](https://github.com/sigp/lighthouse/pull/6711) |
| [#4817](https://github.com/sigp/lighthouse/issues/4817) | State reconstruction broken on Holesky due to backfill bug for skipped slots | CLOSED | persistence | critical | internal-testing | Block backfill did not fill in block roots for slots between genesis and the first non-skipped block (e.g. slot 1 on Holesky), breaking the forwards block roots iterator and state reconstruction | [#4820](https://github.com/sigp/lighthouse/pull/4820) |
| [#4346](https://github.com/sigp/lighthouse/issues/4346) | Backfill stuck on target 171444 | CLOSED | sync-logic | high | user-report | `InvalidSyncState("Batch not found for current processing target")` on backfill — same class of bug as #7360; processing pointer advances without a batch being available | — (self-resolved or related fix) |
| [#7818](https://github.com/sigp/lighthouse/issues/7818) | Unexpected batch state when `--genesis-backfill` flag is used | OPEN | sync-logic | high | internal-testing | When all epochs near genesis have 0 imported blocks, `advance_chain` never removes completed batches; `saturating_sub` prevents `current_start` reaching 0, so `check_completed` never fires and backfill loop hits AwaitingValidation CRIT | — |
| [#9455](https://github.com/sigp/lighthouse/issues/9455) | Range sync cannot retry downloading a batch if the blocks were already imported | OPEN | sync-logic | high | internal-testing | Faulty peer serves blocks but 0 envelopes; on retry, `filter_chain_segment` raises `DuplicateFullyImported` for the already-stored blocks, discarding the new batch and preventing envelope import — permanent stall | — |
| [#5474](https://github.com/sigp/lighthouse/issues/5474) | Fork choice should run after RPC blob processing | CLOSED | sync-logic | high | internal-testing | When blobs were fetched via RPC to complete a block import, `recompute_head_at_current_slot` was not called; head stayed stale for 8+ seconds, missed attestations, snapshot cache miss on next slot | [#5475](https://github.com/sigp/lighthouse/pull/5475) |
| [#7204](https://github.com/sigp/lighthouse/issues/7204) | Lighthouse sending excessive redundant data column by root requests to same peer | CLOSED | sync-logic | medium | testnet-incident (cross-client report) | DataColumn custody lookups queried any custodial peer from the global peer list rather than from the lookup's known peers; batching by peer_id was also ineffective causing single-column requests | — (partial: #8005 addresses retry; lookup peer attribution in #7733) |
| [#4667](https://github.com/sigp/lighthouse/issues/4667) | Single lookups should consider processed/processing blocks/blobs | CLOSED | sync-logic | medium | internal-testing | Delayed lookup could fire even after block was fully imported via gossip; DA checker was not queried for "processing" state, causing redundant RPC requests and spurious peer penalties | [#4732](https://github.com/sigp/lighthouse/pull/4732) |
| [#5707](https://github.com/sigp/lighthouse/issues/5707) | Sync lookup requests blocks from peers that may not have it | CLOSED | sync-logic | medium | code-review | Child lookup created with the peer from an `UnknownParentBlock` event; that peer cannot be expected to have the block, causing `NoResponseReturned` downscoring of an innocent peer | [#5724](https://github.com/sigp/lighthouse/pull/5724) |
| [#5095](https://github.com/sigp/lighthouse/issues/5095) | Stop needlessly penalizing peers in SingleBlockLookup post-deneb | CLOSED | sync-logic | medium | code-review | Post-Deneb: blob request was sent twice and peer was penalized for the first (completed) attempt; state machine logic error caused double request with incorrect failure accounting | — |
| [#7577](https://github.com/sigp/lighthouse/issues/7577) | Lookup sync: don't penalize peers that extend children of long chains | CLOSED | sync-logic | medium | code-review | `failed_chains` cache stored long-chain roots (OOM protection) and then incorrectly penalized peers that extended those chains, even though the behavior was not malicious | [#8042](https://github.com/sigp/lighthouse/pull/8042) |
| [#6879](https://github.com/sigp/lighthouse/issues/6879) | Optimistic batch range sync failure penalizes innocent peer | OPEN | sync-logic | medium | code-review | Optimistic start batch tries the last epoch only and expects failure on mismatch — but the peer that served that "failed" batch is downscored with `faulty_batch` | — |
| [#6880](https://github.com/sigp/lighthouse/issues/6880) | Lighthouse can propose a block that would revert finality | CLOSED | sync-logic | high | testnet-incident | On slow (PeerDAS) networks a node can be within the 8-epoch "close enough to head" window but behind peers' finalized checkpoint; it proposes on its stale fork which all nodes reject, then gets banned and isolated | [#7044](https://github.com/sigp/lighthouse/pull/7044) |
| [#3612](https://github.com/sigp/lighthouse/issues/3612) | VC does not fallback for sync sigs when primary BN is optimistic | CLOSED | sync-logic | high | code-review | VC `first_success` used the first BN that returned any head root, ignoring whether it was optimistic; sync committee sigs could be submitted to an optimistic head | [#3624](https://github.com/sigp/lighthouse/pull/3624) |
| [#4831](https://github.com/sigp/lighthouse/issues/4831) | Validate Versioned Hashes During Optimistic Sync | CLOSED | spec-correctness | high | code-review | Spec requires CL to verify `versioned_hashes` before `engine_newPayload` during optimistic sync (to guard against syncing EL); Lighthouse only verified `block_hash` | [#4832](https://github.com/sigp/lighthouse/pull/4832) |
| [#7866](https://github.com/sigp/lighthouse/issues/7866) | Slow batch KZG verification during range sync | CLOSED | perf-regression | medium | internal-testing | Range sync KZG verification was single-threaded; at 48 blobs/slot and 32 slots/batch this was 16+ seconds per batch; also only first 128 columns were being verified (bug) | [#7921](https://github.com/sigp/lighthouse/pull/7921), [#7924](https://github.com/sigp/lighthouse/pull/7924) |
| [#5058](https://github.com/sigp/lighthouse/issues/5058) | Slow backfill during checkpoint sync post-deneb | CLOSED | perf-regression | medium | user-report | Post-Deneb backfill rate-limited to ~8 slots/sec; `--disable-backfill-rate-limiting` produced 500+ slots/sec; rate limiter was too aggressive for the combined block+blob workload | — |
| [#4508](https://github.com/sigp/lighthouse/issues/4508) | Investigate backfill sync slowness | CLOSED | perf-regression | medium | testnet-incident | Backfill batch download taking ~30s on devnet-7; likely I/O bound or rate-limiting interaction with combined block+blob processing | — |
| [#7526](https://github.com/sigp/lighthouse/issues/7526) | Data column reconstruction taking 5+ seconds on devnets with high blob count | CLOSED | perf-regression | medium | testnet-incident | Column reconstruction blocking sync path; not flagged as blocking but caused visible stall | — (blocked on other work) |
| [#6106](https://github.com/sigp/lighthouse/issues/6106) | Node gets instantly banned by peers on restart due to excessive concurrent requests | CLOSED | sync-logic | high | testnet-incident | On restart, block lookups caused burst of DataColumnsByRoot requests exceeding per-peer `MAX_INBOUND_SUBSTREAMS` (32); peer banned us for `HandlerRejected` | [#6209](https://github.com/sigp/lighthouse/pull/6209) (disable sampling by default) |
| [#4943](https://github.com/sigp/lighthouse/issues/4943) | Lighthouse sends genesis block twice in BlocksByRange response | CLOSED | protocol-networking | low | user-report | Backfill block retrieval returned genesis block twice when slot 0 and the first non-skip slot both mapped to genesis | [#4985](https://github.com/sigp/lighthouse/pull/4985) (schema heal) |
| [#6440](https://github.com/sigp/lighthouse/issues/6440) | Invalid data columns with 0 blobs not rejected | CLOSED | availability-da | medium | testnet-incident (cross-client report) | Gossip verification for data columns skipped the case where `kzg_commitments` is empty; invalid columns for 0-blob blocks passed verification | [#6454](https://github.com/sigp/lighthouse/pull/6454) |
| [#7747](https://github.com/sigp/lighthouse/issues/7747) | "Not all columns consumed for block" on fusaka-devnet-2 | CLOSED | sync-logic | medium | testnet-incident | Sync was requesting extra columns or peer was returning extras; not blocking but indicates bookkeeping mismatch in column-by-root accounting | — |
| [#7186](https://github.com/sigp/lighthouse/issues/7186) | Backfill errors when node is restarted while backfilling (PeerDAS) | CLOSED | sync-logic | high | testnet-incident | On restart, backfill immediately fires many batches before custody peers are known; every batch fails `NoCustodyPeers` causing `BackfillSync` to mark itself failed and stop | — |
| [#1557](https://github.com/sigp/lighthouse/issues/1557) | Head tracker has unsafe API wrt concurrency | CLOSED | concurrency | medium | code-review | `head()`, `heads()`, `head_info()` returned copies of data while fork pruning ran in a separate thread; race condition where a head could be removed while being used | [#1771](https://github.com/sigp/lighthouse/pull/1771) |
| [#8289](https://github.com/sigp/lighthouse/issues/8289) | Slow head sync in tiny devnet | OPEN | sync-logic / perf-regression | medium | internal-testing | Chain rotation when peers get re-statused drops in-flight buffered batches (101 dropped blocks observed); batch await queue growing to 90s wait times; `sync_range_chains_dropped_blocks_total` counter | — |
| [#6100](https://github.com/sigp/lighthouse/issues/6100) | Syncing chain drops blocks when rolling over to new chain | OPEN | sync-logic | medium | code-review | When range sync chain rotates on peer re-status, all buffered not-yet-processed batches are dropped and re-requested; no "draining" state to consume in-flight work | — |
| [#3344](https://github.com/sigp/lighthouse/issues/3344) | Unexpected behavior on hive optimistic sync tests | OPEN | sync-logic | high | ci-test | After `SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY` elapses, Lighthouse does not initiate sync to alternative chain on hive | — |
| [#5732](https://github.com/sigp/lighthouse/issues/5732) | Sync Stall on Lighthouse v5.1.3 | OPEN | sync-logic | high | internal-testing | Batch 280494 downloaded and awaiting but never sent for processing after batch 280493 completed | — |
| [#6113](https://github.com/sigp/lighthouse/issues/6113) | Stuck/slow range sync on PeerDAS networks | CLOSED | sync-logic | high | testnet-incident | Batch failed silently (missing column error not logged); combined with #6108 DataColumnsByRange serving issue caused range sync to stall repeatedly | [#6990](https://github.com/sigp/lighthouse/pull/6990) (logging), [#6209](https://github.com/sigp/lighthouse/pull/6209) |
| [#8268](https://github.com/sigp/lighthouse/issues/8268) | Custody backfill sync shows incorrect estimated time to completion | OPEN | sync-logic | low | user-report | ETA calculation for custody backfill is wrong | — |
| [#4321](https://github.com/sigp/lighthouse/issues/4321) | Enforce BATCH_BUFFER_SIZE when handling failed batches in range sync | OPEN | resource | medium | code-review | On batch failure, all prior unvalidated batches are re-requested; this can be an unbounded number of batches if they are all empty | — |
| [#3730](https://github.com/sigp/lighthouse/issues/3730) | Memory issues during genesis sync | OPEN | resource | high | user-report | Genesis sync uses significantly more memory (10GB observed); not reproduced to root cause; workaround is checkpoint sync | — |
| [#9159](https://github.com/sigp/lighthouse/issues/9159) | Unable to sync complete blob history (mainnet) | OPEN | sync-logic | medium | user-report | Backfill fails with `BatchDownloadFailed` when trying to download blobs pre-Deneb boundary; likely peer availability or EIP-4844 retention window issue | — |
| [#8928](https://github.com/sigp/lighthouse/issues/8928) | Lighthouse syncs slowly with huge blobs_db (Sepolia) | OPEN | perf-regression | medium | user-report | Very slow / intermittent sync when `blobs_db` is large; likely I/O saturation from blob DB reads slowing batch processing | — |
| [#5660](https://github.com/sigp/lighthouse/issues/5660) | Trigger unknown parent lookups from RPC blob processing | CLOSED | sync-logic | medium | code-review | RPC blob responses did not trigger parent lookups for unknown parent blocks; blocks could stay unimportable | — |
| [#5602](https://github.com/sigp/lighthouse/issues/5602) | Scoring issue (single lookups) | CLOSED | sync-logic | low | code-review | Peers were scored incorrectly in single lookup failure paths | — |
| [#5662](https://github.com/sigp/lighthouse/issues/5662) | Key single lookups by block root instead of id | CLOSED | sync-logic | medium | code-review | Lookups keyed by auto-increment ID allowed duplicate lookups for the same block root; root-keying eliminates the class | — |

---

## 3. Deep Dives

### #7360 — Range sync process_completed_batches assumes processing_target exists

**Root cause:** In `chain.rs`, `process_completed_batches()` uses `self.processing_target` as an index into `self.batches` without checking that the batch at that epoch was ever created. There are two valid conditions where the batch is never created: (1) no idle peers to dispatch to, (2) in optimistic start with no `good_peers_on_sampling_subnets`. Under either condition, the chain calls `process_completed_batches` based purely on the pointer advancing, finds no batch, and removes the chain with `WrongChainState("Batch not found for current processing target")`.

**How discovered:** Pawan reported `CRIT Chain removed` logs with this message on peerdas-devnet; dapplion analyzed the logs and identified the code path.

**How fixed:** PR #7391 removed the error guard — the missing-batch state is now simply allowed, so the chain is not removed prematurely. The next event (peer reconnect, new status) re-triggers batch dispatch.

**Why it wasn't caught earlier:** The condition only arises with PeerDAS's additional check for sampling subnet peers, which is a new code path with no unit test coverage. Pre-PeerDAS, idle-peer stalls were transient and the window was narrow.

**Could-have-been-caught-by:** A unit test that creates a chain with no idle peers and then calls `process_completed_batches`; a state-machine invariant check that `processing_target` has a corresponding batch before asserting it must exist.

---

### #6895 — Range sync stuck: metadata not known when head chain starts

**Root cause:** Head chain sync starts upon receiving status messages from advanced peers. At that moment, PeerDAS metadata (custody group counts) may not have been received yet, so `good_peers_on_sampling_subnets` returns false. The batch-dispatch loop is guarded by this check and emits a log but does nothing. Crucially, obtaining peer metadata later does not re-trigger `request_blocks()` on the chain.

**How discovered:** jimmygchen observed the stall pattern on peerdas-devnet-4 during fresh sync testing.

**How fixed:** Workaround — proposal to use the minimum custody count (every peer must serve at least that many columns) even before metadata is confirmed, so some peers pass the check. Longer-term fix is decoupled range requests (#6258).

**Why it wasn't caught earlier:** The metadata/status ordering is a race condition specific to PeerDAS; pre-PeerDAS block-only range sync never checked custody subnet membership.

**Could-have-been-caught-by:** A simulation test that starts chain sync before metadata handshake completes; an invariant that re-triggers sync on any metadata update; monitoring `sync_range_chains_awaiting_peers` metric with a stuck alarm.

---

### #6989 — Range sync batch silently fails due to unlogged RPC error

**Root cause:** When all constituent RPC requests for a batch completed but returned columns for different blocks than expected, the batch was marked `Failed: RPC Error` — but the actual root cause (a column assertion failure inside `convert_range_response_to_block`) was not logged. The batch would indefinitely retry with no indication of why it was failing.

**How discovered:** jimmygchen attached full debug logs while investigating a supernode that repeatedly retried the same batch. PR #6990 added the missing error log, which immediately revealed "No column for block … index …".

**How fixed:** PR #6990 added the missing `DEBG` log before returning the error. This revealed the actual underlying bug (columns delivered but not matching the requested block) was a separate serve-side issue addressed later.

**Why it wasn't caught earlier:** Error propagation through `?` discarded the inner error message before it could reach a log call; the visible symptom (`Batch failed. RPC Error`) was misleading.

**Could-have-been-caught-by:** A linting rule that all `Result::Err` branches in sync code must log before returning; integration tests that assert all batch failures produce a diagnostic log with the root cause.

---

### #7980 / #8005 — DataColumnsByRoot retry loops to same unresponsive peers

**Root cause:** In data column custody lookups (`network_context/custody.rs`), when a peer returned an empty response for a column request, this was not recorded as a peer failure — the `failed_peers` set was only updated on protocol errors, not empty responses. The retry logic therefore kept sending to the same peers indefinitely. Additionally, peer selection was random per-column rather than hashed-per-block, splitting each lookup into many tiny single-column requests.

**How discovered:** Prysm and Teku teams observed on fusaka-devnet-3 that a Lighthouse peer (lighthouse-reth-2) was spamming single-column requests with exact repeats of the same `(root, index)` pair.

**How fixed:** PR #8005 introduced per-peer attempt tracking (`MAX_CUSTODY_PEER_ATTEMPTS = 3`), counted empty responses as failures, and replaced random with hash-based peer selection to enable batching.

**Why it wasn't caught earlier:** The failure was only observable from the receiving peer's side. Lighthouse's own logs for empty responses were silent. Hive/e2e tests at the time did not simulate unresponsive peers returning empty streams.

**Could-have-been-caught-by:** A mock peer that always returns empty; a metric for `custody_lookup_attempts_per_peer` with an alarm at 3+; review checklist item: "all stream-completion paths check for empty response as potential peer failure."

---

### #8104 — Stuck block lookup: processing result arrives for obsolete lookup ID

**Root cause:** The sequence: (1) block arrives, lookup ID=55 is created; (2) lookup 55 sends a blob request which fails (no peers), is dropped; (3) block processing from lookup 55's block request completes asynchronously; (4) an unknown-block-hash message creates new lookup ID=56 for the same root while the block is in the processing cache — the block request returns `Pending`; (5) the processing completion event fires for lookup ID=55, which no longer exists, so it's dropped; (6) lookup 56 is permanently stuck in `AwaitingDownload(block in processing cache)`.

**How discovered:** jimmygchen observed the `WARN Notify the devs a sync lookup is stuck` warning after deploying a fix (#8005) that inadvertently introduced new edge cases.

**How fixed:** Partial — PR #8111 added more logging. The underlying ID-based lookup state tracking needed a redesign to handle the case where a processing result arrives for a lookup that has been superseded by a new lookup for the same root.

**Why it wasn't caught earlier:** The lookup system's state machine uses auto-increment IDs rather than block roots as keys; once #5662 keyed lookups by root this partially mitigated the problem, but state transitions that span multiple IDs (e.g., processing result from old ID, new lookup at same root) remained racy.

**Could-have-been-caught-by:** A unit test simulating exactly this sequence (blob fail → block processing result → root re-queued); a property: "a block root should never have a stuck lookup if its block has reached the processing stage."

---

### #4817 — State reconstruction broken on Holesky: backfill genesis skip slots

**Root cause:** Block backfill (`historical_blocks.rs`) wrote block roots into the freezer's linear array starting at the slot of the earliest block. If slots 0 and 1 were skipped (as on Holesky where slot 1 is skipped), the entries for those slots were left as zero hashes rather than the genesis block root. This broke the forwards block roots iterator used by state reconstruction.

**How discovered:** michaelsproul identified it when implementing state reconstruction testing on Holesky, noticing that the reconstruction panicked on tree-states.

**How fixed:** PR #4820 added `heal_freezer_block_roots_at_genesis()` which fills slots 0..first_block with the genesis block root, plus a schema migration (v18) to apply the heal retroactively. Existing Holesky databases were declared corrupt; users had to re-sync.

**Why it wasn't caught earlier:** Holesky was a new network (launched late 2023); no prior network had genesis skip slots. The forwards-iterator code path was not exercised in tests with skip slots at genesis.

**Could-have-been-caught-by:** A test with `harness.advance_slot()` before the first block (exactly what PR #4820 added); a genesis invariant: "every slot in [0, first_block_slot] must have a non-zero block root."

---

### #5474 — Fork choice not run after RPC blob import

**Root cause:** Three code paths complete block import: (1) gossip block with no blobs — fork choice called; (2) gossip blob completes a block — fork choice called; (3) RPC blobs complete a block — fork choice **not** called. The omission in path 3 meant the head could remain stale for the entire slot until the periodic fork choice tick (8+ seconds), causing snapshot cache misses for state advance and missed attestation windows.

**How discovered:** michaelsproul observed in debug logs that a block with all components arrived 3.1s into a slot but the head was not updated until 8.5s later, triggering a state advance cache miss.

**How fixed:** PR #5475 — one-line fix: call `recompute_head_at_current_slot` in the RPC blob import completion path.

**Why it wasn't caught earlier:** The three import paths were in different files (`sync_methods.rs` vs `gossip_methods.rs`); the fork choice call was added to gossip paths but missed the RPC path during Deneb integration. No test checked head update latency after RPC blob completion.

**Could-have-been-caught-by:** A test that imports a block + blobs via RPC and asserts `beacon_chain.head()` updates within 100ms; a review checklist item: "all block-completion paths call fork choice."

---

### #6880 — Node proposes block that reverts finality

**Root cause:** The sync state machine considers a node "close enough to head" to propose if it is within 8 epochs of clock. However, on PeerDAS devnets with slow sync speeds, a node can be within that window yet behind the network's finalized checkpoint. In that state, the node proposes a block building on a pre-finality parent; all other nodes reject this block, the proposer gets heavily penalized, and is eventually banned and isolated.

**How discovered:** dapplion observed the issue on small PeerDAS devnets where sync is inherently slow due to the column-fetching overhead and the 8-epoch window is too large.

**How fixed:** PR #7044 plumbed the existing `--sync-tolerance-epochs` flag through to the proposer prep routines so operators can tighten the window on smaller networks. The fundamental tension (attack resistance vs. liveness) is noted as unresolved.

**Why it wasn't caught earlier:** The 8-epoch heuristic was designed for fast-syncing mainnet; PeerDAS introduced a new regime where sync can legitimately be much slower.

**Could-have-been-caught-by:** A simulation test with a slow-sync node assigned a proposal duty; checking whether our finalized epoch is at least as recent as the network's before allowing proposals; a metric that alerts when proposing despite a large finality gap.

---

### #3612 — VC sync sigs use optimistic BN head

**Root cause:** `sync_committee_service.rs` used `first_success` to get the head block root from the first BN that responded, without checking the `execution_optimistic` flag. If the BN had an optimistic head (EL syncing), the VC would sign sync committee messages for an unverified block, which could be invalid.

**How discovered:** paulhauner noticed the omission in code review.

**How fixed:** PR #3624 passed the `execution_optimistic` check inside the `first_success` function so it prefers a non-optimistic BN.

**Could-have-been-caught-by:** A test with a mock BN returning optimistic status; a CI hive test for optimistic sync VC behavior.

---

### #4831 — Versioned hashes not validated during optimistic sync

**Root cause:** The Ethereum spec requires the CL to verify `versioned_hashes` from a block's KZG commitments before sending `engine_newPayload` when in optimistic sync mode, as a defense against a compromised/syncing EL. Lighthouse verified `block_hash` but not `versioned_hashes`.

**How discovered:** ethDreamer noticed the gap while reviewing the Deneb spec compliance checklist.

**How fixed:** PR #4832 added versioned hash computation and comparison using `alloy-consensus`, alongside refactoring of execution payload handling.

**Could-have-been-caught-by:** A spec-compliance test matrix comparing every "MUST" in the optimistic sync spec against code paths; the Ethereum consensus spec tests (if the relevant test vector existed).

---

### #7866 — Single-threaded KZG verification stalls range/backfill sync

**Root cause:** `process_chain_segment` called KZG batch verification for data columns sequentially rather than using rayon. At 48 blobs × 32 slots/batch with 508ms/batch on a single core, each batch took 16+ seconds of pure verification. Additionally, a bug caused only the first 128 columns to be verified (the others silently accepted).

**How discovered:** jimmygchen noticed the absence of rayon usage while analyzing sync speed on high-blob-count devnets.

**How fixed:** PR #7921 added rayon for range sync KZG verification and fixed the 128-column limit bug. PR #7924 added a dedicated low-priority rayon pool for backfill to avoid competing with the global beacon processor pool.

**Why it wasn't caught earlier:** KZG verification performance was acceptable on mainnet (6 blobs/slot maximum); PeerDAS with up to 32 blobs/slot exposed an 8× throughput gap.

**Could-have-been-caught-by:** A benchmark test that measures batch verification time at max blob count and alerts if > 1s/batch; a code review checklist noting "all CPU-heavy loops in sync paths should use rayon or spawn_blocking."

---

### #5694 / #5833 — single_block_lookups memory leak

**Root cause:** A lookup is created for block A which is already in the DA checker. The block request state returns `Pending` (block in processing), so no actual RPC request is sent. No subsequent event ever triggers lookup completion because the block's processing result is routed to the old ID. The lookup accumulates in `single_block_lookups` indefinitely. At scale, 100k–150k leaked entries were observed.

**How discovered:** dapplion noticed the `sync_single_block_lookups` Prometheus metric climbing abnormally on production nodes.

**How fixed:** PRs #5583 and #5681 — added completion events for the DA-checker fast-path and tightened state machine transitions.

**Why it wasn't caught earlier:** The metric was newly added; the leak was extremely slow (small per-lookup) so it wasn't noticed until long-running nodes were examined.

**Could-have-been-caught-by:** A test that checks `single_block_lookups` count does not grow monotonically over a long run; a periodic audit that logs lookup ages > N slots.

---

## 4. Synthesis

### Counts by class

| Class | Count |
|-------|-------|
| sync-logic | 26 |
| perf-regression | 5 |
| resource | 3 |
| persistence | 1 |
| concurrency | 1 |
| spec-correctness | 1 |
| availability-da | 1 |
| protocol-networking | 1 (overlap) |

### Counts by severity

| Severity | Count |
|----------|-------|
| critical | 1 |
| high | 15 |
| medium | 16 |
| low | 2 |

### Recurring root-cause themes

1. **Pointer/index assumption without guard.** Multiple bugs (#7360, #4346, #7818) share the exact same pattern: a processing-target pointer is advanced, then the code assumes the batch at that pointer exists. The backfill and range sync codebases each replicated this mistake independently.

2. **Lookup state machine reentrancy / ID mismatch.** The block lookup system (#5694, #5833, #8104, #4667, #5662) repeatedly suffers from processing results arriving for obsolete lookup IDs, or new lookups being created while old ones are still in-flight for the same root. The fundamental issue is using auto-increment IDs as keys while block roots are the actual identity.

3. **Empty RPC responses not treated as failures.** Seen in #7980 (DataColumnsByRoot) and #6989 (batch RPC error not logged): the sync code did not consistently treat "peer responded with empty" as an actionable failure for retry-tracking and peer scoring purposes.

4. **PeerDAS metadata race at sync start.** #6895 and #7186 both stem from range or backfill sync starting before peer custody metadata is available, and there being no re-trigger when metadata later arrives.

5. **Missing fork-choice / head-update calls on non-gossip import paths.** #5474 shows that the 3 block-completion paths (gossip-no-blobs, gossip-blob-completion, RPC-blob-completion) were not kept in sync with each other; only one path was missing the fork choice call, but that was enough to cause 8-second head delays.

6. **Peer penalty logic not matched to sync state.** Recurs in #5095, #5707, #6879, #7577 — peers are penalized for expected or innocent behavior during optimistic start, parent-lookup bootstrapping, or long-chain OOM protection.

7. **Rayon/CPU usage not considered in new data paths.** #7866 and related PRs show that adding KZG verification to sync paths without rayon parallelism created unacceptable per-batch latency at PeerDAS scale. This connects to the broader theme that each new DA feature (blobs, columns) introduced a new CPU-bound path that needed independent parallelism analysis.

### 3–6 highest-leverage early-detection ideas

1. **State-machine invariant: processing_target must have a matching batch.** An `assert` or `debug_assert` at the top of `process_completed_batches` and its backfill equivalent that the batch at `processing_target` exists (or that the pointer was not advanced) would have caught #7360, #4346, and #7818 in CI before they reached devnets.

2. **Property test for lookup lifecycle: every created lookup must eventually be removed.** A test harness that drives random sequences of block/blob/column arrival and departure events and asserts that `single_block_lookups.len()` returns to zero would catch #5694, #5833, and #8104. The existing "stuck lookup" warning is reactive; a property-based test is proactive.

3. **Empty RPC response as a tracked metric and peer failure.** A review checklist item / lint: "every `stream terminated` event in a sync RPC handler must either (a) confirm all expected items were received or (b) record a peer failure." Pair this with a `sync_rpc_empty_responses_total` counter alerted on sustained elevation — catches #7980 and #6989.

4. **Benchmark: single-threaded KZG time at max blob count.** A CI benchmark that processes a batch of blocks at the maximum blob-per-slot count (48+ for PeerDAS) and asserts the verification time is < 2s/batch. This would have caught #7866 before the devnet. Pair with a code review rule: "any loop over DA objects in a sync path must be reviewed for rayon parallelism."

5. **Re-trigger sync on peer state changes.** An invariant: if a sync chain is in `AwaitingPeers` state, any peer event (metadata received, peer connected, peer status updated) must trigger a re-attempt. This would fix the class of bugs represented by #6895 and #7186 structurally. A test: start a chain, block all peer dispatch, then deliver a metadata event, and assert a batch is sent.

6. **Fork-choice call checklist for all block import completion paths.** A documented invariant (and matching test) that every code path that results in a block being imported into the fork choice store must call `recompute_head`. A test that counts fork choice calls after simulating each of the three import paths (gossip-no-blobs, gossip-blob, RPC-blob) would have caught #5474 immediately.

### Structural / architectural observations

- **`chain.rs` range sync and `backfill_sync/mod.rs` are structurally isomorphic but not shared.** The same `processing_target` batch-pointer bug appeared in both. Any fix applied to one should be cross-checked against the other. Consider extracting the common "batch queue with pointer" abstraction.

- **The lookup system's dual-key problem (ID vs. root) is a persistent source of bugs.** Issues #5662, #5694, #5833, #8104 all relate to this. The system was partially fixed by keying on root (#5662) but the state machine still creates new lookup objects that can coexist with in-flight events from old objects for the same root. Tree sync (#7678) is meant to replace this, but until then, the lookup module is the most fragile module in the sync stack.

- **PeerDAS introduced a new "metadata dependency" for sync that is not modeled in the sync state machine.** Pre-PeerDAS, range sync only needed peer status (head slot/epoch). PeerDAS adds a third dependency (custody metadata) that must be available before batch dispatch. This dependency is currently checked inline as a condition, not modeled as a state. Making it an explicit `SyncState::AwaitingMetadata` transition with a re-trigger handler would make the logic auditable.
