# Data Availability (Blobs/KZG/PeerDAS/Custody) — Bug Audit

## Scope

Covers issues and PRs in the sigp/lighthouse repo related to:
- Blob sidecars (Deneb / EIP-4844): gossip/RPC verification, blob pool, pruning, storage
- KZG commitments and proofs: batch verification, inclusion proofs, c-kzg / rust-eth-kzg library bugs
- PeerDAS / data columns (Fulu / EIP-7594): custody, gossip verification, sampling, reconstruction
- Data availability boundary / pruning / checkpoint sync
- Availability cache and DA checker

**Not covered:** generic RPC transport, generic libp2p, validator duties. Sync/networking issues caused by DA bugs are noted.

## Queries run

```
gh issue list --repo sigp/lighthouse --label "das" --label "bug" --state all --limit 300
gh issue list --repo sigp/lighthouse --label "deneb" --label "bug" --state all --limit 300
gh issue list --repo sigp/lighthouse --label "das" --state all --limit 300
gh issue list --repo sigp/lighthouse --label "deneb" --state all --limit 100
gh issue list --repo sigp/lighthouse --label "fulu" --state all --limit 100
gh search issues --repo sigp/lighthouse "blob" --state {open,closed} --limit 50
gh search issues --repo sigp/lighthouse "kzg" --state closed --limit 50
gh search issues --repo sigp/lighthouse "data availability" --state closed --limit 50
Per-issue: gh issue view <N> --comments + gh api .../timeline to find fix PRs
Per-fix PR: gh pr view <N> + gh pr diff <N>
```

---

## 2. Bug Table

| # | Title | State | Class | Severity | How-found | One-line root cause | Fix PR |
|---|-------|-------|-------|----------|-----------|---------------------|--------|
| [#5114](https://github.com/sigp/lighthouse/issues/5114) | Backfill mistakenly stores blobs in the hot DB | CLOSED | `persistence` | high | internal-testing | Backfill used wrong DB handle; blobs went to hot DB instead of blobs_db | [#5119](https://github.com/sigp/lighthouse/pull/5119) |
| [#5474](https://github.com/sigp/lighthouse/issues/5474) | Fork choice should run after RPC blob processing | CLOSED | `sync-logic` | high | user-report | `recompute_head` missing on the RPC-blob-complete import code path, causing stale head | [#5475](https://github.com/sigp/lighthouse/pull/5475) |
| [#5251](https://github.com/sigp/lighthouse/issues/5251) | Download checkpoint block's blob when checkpoint syncing | CLOSED | `availability-da` | high | code-review | Checkpoint sync didn't fetch blobs for the anchor block, violating DB invariant | [#5252](https://github.com/sigp/lighthouse/pull/5252) |
| [#5107](https://github.com/sigp/lighthouse/issues/5107) | Blob sidecar indices-filter does not work | CLOSED | `api-correctness` | medium | user-report | Query-string deserialization used wrong method; `?indices=0,1` yielded empty result | [#5118](https://github.com/sigp/lighthouse/pull/5118) |
| [#5092](https://github.com/sigp/lighthouse/issues/5092) | `blobs pruned within boundary` on non-mainnet config | CLOSED | `config-cli` | medium | user-report | `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` not loaded from network config; hardcoded mainnet value used | — |
| [#5095](https://github.com/sigp/lighthouse/issues/5095) | Needlessly penalizing peers in SingleBlockLookup post-Deneb | CLOSED | `sync-logic` | medium | internal-testing | `component_downloaded`/`component_processed` flags not reset on retry; peers scored negatively for correct behaviour | [#5096](https://github.com/sigp/lighthouse/pull/5096) |
| [#5134](https://github.com/sigp/lighthouse/issues/5134) | `SlotTooLow` errors from observed aggregates | CLOSED | `spec-correctness` | medium | user-report | Attestation observation cache too small (1× epoch) after Deneb extended the validity window to 2 epochs | [#5135](https://github.com/sigp/lighthouse/pull/5135) |
| [#4876](https://github.com/sigp/lighthouse/issues/4876) | RPC lookups for blobs on local block production | CLOSED | `sync-logic` | medium | internal-testing | Locally produced block not found in availability cache; triggered redundant BlobsByRoot RPC | — |
| [#4667](https://github.com/sigp/lighthouse/issues/4667) | Single lookups should consider processed/processing blocks/blobs | CLOSED | `sync-logic` | medium | internal-testing | Delayed lookup fires after block is fully imported; DA checker unaware of already-imported state | — |
| [#4446](https://github.com/sigp/lighthouse/issues/4446) | Batch KZG proof verification with batch size 1 failing | CLOSED | `availability-da` | high | ci-test | c-kzg library returned false for single-blob batch verify on minimal spec | [#4404](https://github.com/sigp/lighthouse/pull/4404) |
| [#5058](https://github.com/sigp/lighthouse/issues/5058) | Slow backfill during checkpoint sync post-Deneb | CLOSED | `perf-regression` | medium | user-report | Rate-limiting applied to blob backfill path without accounting for blob fetch overhead | — |
| [#6059](https://github.com/sigp/lighthouse/issues/6059) | Excessive sampling requests sent to peer(s) | CLOSED | `sync-logic` | high | testnet-incident | No tracking of failed sampling peers; node retried same peer 419k times | [#6084](https://github.com/sigp/lighthouse/pull/6084) |
| [#6105](https://github.com/sigp/lighthouse/issues/6105) | PeerDAS KZG library stack overflow during block production | CLOSED | `panic-crash` | critical | testnet-incident | Switch from c-kzg to peerdas-kzg library introduced stack overflow in recursive FFT for commitment computation | [#6125](https://github.com/sigp/lighthouse/pull/6125) (lib switch), [#6107](https://github.com/sigp/lighthouse/issues/6107) |
| [#6106](https://github.com/sigp/lighthouse/issues/6106) | Node instantly banned by peers on restart (excessive concurrent requests) | CLOSED | `protocol-networking` | high | testnet-incident | On restart, block lookups fanned out too many concurrent `DataColumnsByRoot` requests, exceeding peer `inbound_substreams` limit | [#6209](https://github.com/sigp/lighthouse/pull/6209) (disable sampling), [#6256](https://github.com/sigp/lighthouse/pull/6256) |
| [#6108](https://github.com/sigp/lighthouse/issues/6108) | Unable to reliably serve `DataColumnsByRange` | CLOSED | `sync-logic` | high | internal-testing | Columns stored during live sync were not indexed by slot for range queries; serving 0 columns to peers | — |
| [#6113](https://github.com/sigp/lighthouse/issues/6113) | Stuck/slow range sync on PeerDAS networks | CLOSED | `sync-logic` | high | internal-testing | Combination of #6108 and peer management issues causing range sync to stall | [#6113](https://github.com/sigp/lighthouse/issues/6113) |
| [#6111](https://github.com/sigp/lighthouse/issues/6111) | Missing `kzg_commitments_inclusion_proof` verification on DataColumnsByRange | CLOSED | `availability-da` | high | code-review | RPC range path skipped verification of KZG inclusion proof in `DataColumnSidecar`; only added for gossip path | [#6044](https://github.com/sigp/lighthouse/pull/6044) |
| [#6240](https://github.com/sigp/lighthouse/issues/6240) | Wrong DA config constants used for data columns | CLOSED | `spec-correctness` | high | code-review | Deneb blob constants reused for PeerDAS data columns; `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` missing | — |
| [#6319](https://github.com/sigp/lighthouse/issues/6319) | Flaky sampling tests (race condition) | CLOSED | `concurrency` | medium | ci-test | Race in `sampling_with_retries` test caused by non-deterministic async ordering | [#6326](https://github.com/sigp/lighthouse/pull/6326) |
| [#6440](https://github.com/sigp/lighthouse/issues/6440) | Invalid data columns with 0 blobs not rejected | CLOSED | `availability-da` | critical | testnet-incident (Prysm cross-report) | Missing guard: empty `kzg_commitments` block produces a "valid" inclusion proof; columns accepted and broke devnet-2 consensus | [#6454](https://github.com/sigp/lighthouse/pull/6454) |
| [#6559](https://github.com/sigp/lighthouse/issues/6559) | Prune blobs can OOM | CLOSED | `resource` | critical | user-report | New pruning algorithm read all blobs in memory to partition; 77 GB RAM spike when enabling pruning | [#6571](https://github.com/sigp/lighthouse/pull/6571) (alt approach) |
| [#7100](https://github.com/sigp/lighthouse/issues/7100) | High read IO due to blob pruning | CLOSED | `resource` | high | user-report | Blob prune ran every epoch and iterated entire blobs DB; 250 MB/s read IO spikes | — (freq tuning) |
| [#7203](https://github.com/sigp/lighthouse/issues/7203) | Data column gossip verification >4s when blob count >20 | CLOSED | `perf-regression` | high | testnet-incident (Sunnyside Lab) | Proposer shuffling cache computed redundantly on every verification thread; no deduplication | [#7304](https://github.com/sigp/lighthouse/pull/7304) |
| [#7204](https://github.com/sigp/lighthouse/issues/7204) | Excessive redundant DataColumnsByRoot requests per peer | CLOSED | `sync-logic` | high | testnet-incident (Prysm report) | Column lookup fanned one request per column index instead of batching; no tracking of failed peers | [#8005](https://github.com/sigp/lighthouse/pull/8005) |
| [#7305](https://github.com/sigp/lighthouse/issues/7305) | Backfill doesn't verify header signature in blobs/data columns | OPEN | `availability-da` | high | code-review | Backfill path only verifies block signature, not that blob/column header matches | — (open) |
| [#7526](https://github.com/sigp/lighthouse/issues/7526) | Data column reconstruction taking 5+ seconds on high-blob devnets | CLOSED | `perf-regression` | high | testnet-incident | No rayon parallelism in KZG batch verify; plus race where RPC columns arrived after reconstruct, causing lookup drop | [#7921](https://github.com/sigp/lighthouse/pull/7921) |
| [#7719](https://github.com/sigp/lighthouse/issues/7719) | CPU oversubscription in BeaconProcessor due to unscoped rayon | CLOSED | `resource` | high | code-review | `ColumnReconstruction` task used global rayon pool while BeaconProcessor also sized to `num_cpus` | [#7924](https://github.com/sigp/lighthouse/pull/7924) |
| [#7866](https://github.com/sigp/lighthouse/issues/7866) | Slow batch KZG verification during range sync (no rayon) | CLOSED | `perf-regression` | high | internal-testing | Range/backfill sync KZG verify loop was sequential; each epoch took seconds per supernode | [#7921](https://github.com/sigp/lighthouse/pull/7921) |
| [#7921 bug](https://github.com/sigp/lighthouse/pull/7921) | (Hidden bug in #7921) Only first 128 columns in a chain segment batch were being KZG-verified | CLOSED | `availability-da` | high | code-review (during fix) | Off-by-one in batch chunking silently skipped verification of remaining columns in large epochs | [#7921](https://github.com/sigp/lighthouse/pull/7921) |
| [#7980](https://github.com/sigp/lighthouse/issues/7980) | Repeated DataColumnsByRoot requests for same block | CLOSED | `sync-logic` | high | testnet-incident (Prysm/Teku report) | Empty RPC responses not counted as failures; retry loop kept hitting same unresponsive peers | [#8005](https://github.com/sigp/lighthouse/pull/8005) |
| [#7991](https://github.com/sigp/lighthouse/issues/7991) | `CellIndicesNotUnique` error during data column reconstruction | CLOSED | `availability-da` | high | testnet-incident | DA checker could insert duplicate column indices; reconstruction passed unsorted/duplicated indices to KZG library | [#7998](https://github.com/sigp/lighthouse/pull/7998) |
| [#8035](https://github.com/sigp/lighthouse/issues/8035) | Fork choice write lock held 4+ seconds during data column processing | CLOSED | `concurrency` | high | testnet-incident | Data column gossip verification acquired fork-choice write lock while waiting on KZG batch verify | — |
| [#8268](https://github.com/sigp/lighthouse/issues/8268) | Custody backfill sync shows incorrect ETA | OPEN | `logic-other` | low | user-report | Slot count used for ETA doesn't account for multi-column nature of backfill | — |
| [#8400](https://github.com/sigp/lighthouse/issues/8400) | Missing uniqueness validation for blob schedule epochs | OPEN | `config-cli` | medium | code-review (audit) | `blob_schedule` list accepts duplicate epoch entries; could cause ambiguous lookups | — |
| [#8509](https://github.com/sigp/lighthouse/issues/8509) | `reconstruct_blobs` passes cell indices out of order | CLOSED | `availability-da` | high | user-report + code-review | KZG library v0.9.0 added ascending-order assertion; `reconstruct_blobs` iterated columns in arbitrary order unlike `reconstruct_data_columns` | [#8510](https://github.com/sigp/lighthouse/pull/8510) |
| [#8569](https://github.com/sigp/lighthouse/issues/8569) | 500 error: insufficient data columns to reconstruct blobs | CLOSED | `api-correctness` | medium | user-report | Node in custody-only mode (4 columns) received HTTP request to reconstruct all blobs (needs 64); surfaced as 500 | — |
| [#8775](https://github.com/sigp/lighthouse/issues/8775) | `blob_delay_ms` always "unknown" in head block logs post-Fulu | CLOSED | `logic-other` | low | internal-testing | Fork upgrade: data columns replaced blobs but timestamp tracking was not migrated to the data-column code path | [#9024](https://github.com/sigp/lighthouse/pull/9024) |
| [#8842](https://github.com/sigp/lighthouse/issues/8842) | Regression: `DataColumnsByRange` includes duplicate columns | CLOSED | `protocol-networking` | high | testnet-incident | Return type changed from `Vec<Hash256>` to `Vec<(Hash256, Slot)>`; `.unique()` on tuples didn't deduplicate skip-slot duplicates | [#8843](https://github.com/sigp/lighthouse/pull/8843) |
| [#6372](https://github.com/sigp/lighthouse/issues/6372) | No slashability check for data columns on publish | CLOSED | `availability-da` | medium | code-review | Block publish path checks blobs for slashability but data column equivalent was missing | — |
| [#7186](https://github.com/sigp/lighthouse/issues/7186) | Backfill errors on restart during PeerDAS custody backfill | CLOSED | `sync-logic` | high | testnet-incident | `NoCustodyPeers` on startup; peer reconnection state not re-established before backfill resumed | — |
| [#5391](https://github.com/sigp/lighthouse/issues/5391) | Import expired blobs (no mechanism for archival nodes) | OPEN | `availability-da` | medium | code-review | No import path for out-of-window blobs; archive nodes can't bootstrap blob history without changes | — |
| [#8160](https://github.com/sigp/lighthouse/issues/8160) | `/blob_sidecars` returns `kzg_proof: 0xc0` after Fusaka upgrade | CLOSED | `fork-upgrade` | medium | user-report | Post-Fulu, the API returns data-column-derived KZG proofs which are infinity points; not explained in API docs | — |

---

## 3. Deep Dives

### #6440 — Invalid data columns with 0 blobs accepted
**Root cause:** The gossip `verify_inclusion_proof()` function on `DataColumnSidecar` passes for a block with zero KZG commitments because the proof over an empty list is technically valid. Lighthouse accepted these sidecars without checking that `kzg_commitments.is_empty()` → reject. The columns propagated and peers reacted differently, breaking devnet-2 consensus.

**How discovered:** Prysm team observed inconsistent behaviour on peer-das-devnet-2 and cross-reported to the Lighthouse team.

**How fixed:** PR #6454 added a `verify_data_column_sidecar()` guard called at the top of gossip validation: reject if `kzg_commitments.is_empty()`, if `column.len() != kzg_commitments.len()`, or if index >= `NUMBER_OF_COLUMNS`. A regression test was added.

**Why not caught earlier:** No explicit unit test covered the zero-blob edge case. The inclusion-proof math itself was correct; the semantic invariant ("a block with no blobs must have no data columns") was not encoded anywhere.

**Could-have-been-caught-by:** Fuzz testing the gossip validation path with empty commitment lists. A checklist item in code-review: "does every new validity check cover the empty case?" A property-based test: `∀ block_with_n_blobs, n=0 ⟹ no valid DataColumnSidecar exists`.

---

### #5114 — Backfill stores blobs in hot DB
**Root cause:** `import_historical_block_batch` committed its ops directly to the hot DB via a plain `StoreOp` batch rather than using `do_atomically_with_block_and_blobs_cache`, which routes blob ops to `blobs_db`. Pre-existing nodes on Goerli had their backfilled blobs in the wrong column family.

**How discovered:** Internal testing on Goerli during v4.6.0-rc preparation; cross-checking blob query results against expected DB.

**How fixed:** PR #5119 rewrote backfill storage to write blobs → blobs_db first, then hot, then cold. Schema migrated to v19; a migration copied and deleted misplaced blobs from hot DB.

**Why not caught earlier:** The three-DB atomicity pattern is non-obvious; the abstraction (`do_atomically_with_block_and_blobs_cache`) was added later as blobs were introduced. Regression test coverage for backfill's storage routing did not exist.

**Could-have-been-caught-by:** An invariant assertion or test that verifies "all blobs in the hot DB must have been written via blobs_db first." A `#[cfg(test)]` consistency check after any store operation during backfill.

---

### #5474 — Fork choice not run after RPC blob import
**Root cause:** There are three code paths that complete block import: (a) no blobs, (b) gossip blobs complete the block, (c) RPC blobs complete the block. Only path (c) was missing the `recompute_head_at_current_slot` call. This caused the head to remain stale after blobs arrived via RPC, leading to a snapshot cache miss several seconds later.

**How discovered:** User report on mainnet (v5.1.2): head was delayed >8s into the slot after RPC blob delivery at 3.1s, causing a snapshot cache miss for the old head.

**How fixed:** PR #5475: added `recompute_head_at_current_slot` to the RPC-blob-complete import path.

**Why not caught earlier:** The three import paths diverged during Deneb development. The gossip path was correctly updated (it goes through a different function), but the RPC path was not. No integration test exercised the RPC path's fork-choice update.

**Could-have-been-caught-by:** A simulator test that measures head latency specifically when blobs are fetched via RPC rather than gossip. An invariant: "head timestamp must advance within N ms of a fully-available block regardless of acquisition path."

---

### #6105 — KZG library stack overflow during block production
**Root cause:** Switching from the `c-kzg` library to `peerdas-kzg` (a Rust implementation) introduced a stack overflow in the recursive FFT routine during commitment computation. The stack frame was too large for the default OS thread stack.

**How discovered:** Testnet-incident on das-devnet-2 interop session; block production panicked with "thread has overflowed its stack".

**How fixed:** The `peerdas-kzg` library was identified as the source; the team reverted to `c-kzg` for the immediate release and opened a tracking issue (#6107) to choose the KZG library carefully. Later `rust-eth-kzg` (a safer Rust wrapper) was adopted instead.

**Why not caught earlier:** The stack overflow only manifested under production-scale computation (multiple blobs, full FFT). CI tests ran with small blob counts on smaller stacks. No stress test exercised block production under high blob count.

**Could-have-been-caught-by:** A dedicated stress test that produces a block with the maximum allowed blob count in a CI job, ideally on a thread with a tight stack limit. A `RUST_MIN_STACK` environment variable in CI for KZG-intensive tests. Vendor changelog review before switching libraries.

---

### #6559 — Prune blobs causes OOM (77 GB RAM)
**Root cause:** The revised blob pruning algorithm (added to support partial blob storage by removing `oldest_blob_slot`) called `get_blobs()` on every block inside `do_atomically_with_block_and_blobs_cache` in order to partition blobs for deletion. On a node with months of blobs, this loaded the entire blobs database into memory at once.

**How discovered:** User report (AllNodes) with a jemalloc memory dump pinpointing the call site.

**How fixed:** PR #6571 replaced the partitioning approach with a `delete_while` iterator that processes records one by one from the DB, never materialising the full set.

**Why not caught earlier:** The bug only triggered when `--prune-blobs` was toggled from `false` to `true` on a node that had accumulated many months of blobs. Test environments used small, short-lived datasets.

**Could-have-been-caught-by:** A benchmark test of `try_prune` on a simulated large blobs DB. Heap profiling in a staging environment with realistic blob counts. A hard upper bound on the number of blobs loaded in a single pruning pass.

---

### #6440 (see above deep-dive) — Note: also covered by the zero-blob issue.

---

### #7991 / #8509 — Duplicate or unsorted cell indices crash reconstruction
**#7991 root cause:** The DA checker could accumulate duplicate column entries for a block (race between gossip and RPC paths). When reconstruction was triggered, the duplicate indices were passed to `recover_cells_and_compute_kzg_proofs`, which as of rust-eth-kzg v0.9.0 enforces `assert!(cell_indices == sorted(cell_indices))` — crashing with `CellIndicesNotUnique`.

**#8509 root cause:** `reconstruct_blobs` passed `cell_ids` in arbitrary insertion order, violating the ascending-order precondition introduced in rust-eth-kzg v0.9.0. The parallel function `reconstruct_data_columns` already sorted its input (coincidentally, from an earlier fix), but `reconstruct_blobs` did not.

**How discovered:** Both observed as errors on devnets after the rust-eth-kzg library was bumped to v0.9.0, which turned a silent incorrect-result into a hard panic.

**How fixed:** #7998 deduplicates columns before passing to the library. #8510 adds `sort_by_key(|col| col.index)` at the top of `reconstruct_blobs`.

**Why not caught earlier:** The preconditions existed conceptually in the spec but the Rust library previously silently accepted out-of-order/duplicate input. When the library tightened validation, it exposed latent bugs in Lighthouse's coordination layer.

**Could-have-been-caught-by:** Property-based tests for `reconstruct_blobs` that shuffle input ordering. A wrapper function that enforces sorting before calling into the KZG library. Reviewing library changelogs for new preconditions before bumping.

---

### #7203 — Data column gossip verification >4s for >20 blobs
**Root cause:** Each gossip data column verification thread independently computed the proposer shuffling when the cache was cold. On a burst of 128 columns arriving simultaneously, all threads raced to compute the same shuffling, with each computation taking ~200ms at high blob count, stacking to multi-second verification times.

**How discovered:** Sunnyside Lab devnet testing report showing network degradation above 20 blobs per block; Lighthouse-specific column verification latency confirmed via metrics.

**How fixed:** PR #7304 introduced a `OnceCell` per shuffling key in the data column gossip verification path so only one thread computes the shuffling; others wait and reuse the cached result.

**Why not caught earlier:** The bug is latent at low blob counts (shuffling compute is fast). It only becomes critical at the high blob counts targeted by PeerDAS devnets.

**Could-have-been-caught-by:** A benchmark test for `validate_data_column_sidecar_for_gossip` under 128 simultaneous columns with cold shuffling cache. A metric threshold alert for gossip verification latency.

---

### #8842 — Regression: `DataColumnsByRange` serves duplicate columns
**Root cause:** PR #8682 changed `get_block_roots_from_store` to return `Vec<(Hash256, Slot)>` instead of `Vec<Hash256>` for richer information. A `.unique()` call that previously worked on `Hash256` values now operated on `(Hash256, Slot)` tuples. For skip slots, the same block root appears with multiple distinct slot values, so `.unique()` no longer deduplicated them; duplicate columns were served per request.

**How discovered:** Testnet-incident: peers (Prysm/Teku) downscored the Lighthouse node with `DuplicatedData` errors. This was a v8.1.0-only regression.

**How fixed:** PR #8843: changed to `.unique_by(|(root, _)| *root)` to key uniqueness only on block root, ignoring slot.

**Why not caught earlier:** The test for `get_block_roots_from_store` did not include skip slots (which are common). The return-type change was mechanical and appeared safe; the semantic breakage in the uniqueness operation was invisible without skip-slot test vectors.

**Could-have-been-caught-by:** A unit test for `DataColumnsByRange` response generation that includes skip slots. A review checklist item: "does changing a return type preserve all downstream invariants?"

---

### #5474 — Fork choice missing on RPC blob path (see above)

---

### #6106 — Instant ban on restart from excessive concurrent requests
**Root cause:** After a restart, the block lookup system fanned out many `DataColumnsByRoot` requests simultaneously. This exceeded the per-peer `MAX_INBOUND_SUBSTREAMS` limit (32), causing peers to reject with `HandlerRejected` and then immediately ban the restarting node.

**How discovered:** Local testnet reproduction; node effectively isolated after restart.

**How fixed:** PR #6209 temporarily disabled sampling by default behind `--enable-sampling`, and PR #6256 added rate limiting. Proper fix came later with #8005 (smarter peer selection, retry capping).

**Why not caught earlier:** Rate limiting was present for blob requests but not for the newly added data column request types. Integration tests did not cover the restart path at PeerDAS scale.

**Could-have-been-caught-by:** A simulator test that restarts one node and checks it does not get banned. Request-rate validation in CI using the local testnet scripts.

---

### #7526 / #7719 / #7866 — CPU oversubscription and slow KZG during reconstruction
**Root cause (combined):** Reconstruction spawned a `BeaconProcessor` blocking task that internally called the global rayon thread pool. The processor also sized its worker pool to `num_cpus`. The combination caused 2× CPU oversubscription during reconstruction bursts on supernodes. Separately, the KZG batch-verify loop for range/backfill sync was entirely sequential (no rayon), so an epoch with 48 blobs on a supernode took ~16 seconds.

Additionally, a hidden bug inside the #7921 fix: the chunking logic for batch KZG verification only iterated the first 128 columns in a chain segment, silently skipping the rest.

**How discovered:** Sunnyside Lab testnet report + internal investigation; the hidden skip-verification bug was found by code review while writing the fix.

**How fixed:** PR #7921 parallelised KZG batch verify with rayon for range/backfill; PR #7924 introduced scoped rayon pools in BeaconProcessor.

**Could-have-been-caught-by:** A benchmark for reconstruction CPU usage at simulated peak blob/column counts. A test that verifies all columns in a large epoch batch are individually verified.

---

## 4. Synthesis

### Counts by class

| Class | Count |
|-------|-------|
| `availability-da` | 10 |
| `sync-logic` | 8 |
| `perf-regression` | 5 |
| `resource` | 3 |
| `persistence` | 1 |
| `protocol-networking` | 2 |
| `api-correctness` | 2 |
| `spec-correctness` | 2 |
| `panic-crash` | 1 |
| `concurrency` | 2 |
| `config-cli` | 2 |
| `fork-upgrade` | 1 |
| `logic-other` | 2 |

### Counts by severity

| Severity | Count |
|----------|-------|
| critical | 3 (#6105, #6440, #6559) |
| high | 22 |
| medium | 11 |
| low | 2 |

### Recurring root-cause themes

1. **Missing edge-case guards in DA verification.** Multiple bugs (#6440, #6111, #7305) share the pattern: a new verification step is added to one path (gossip) but not another (RPC range, backfill), or a boundary condition (empty blobs, duplicate columns, unsorted indices) is not validated. The KZG math is correct but the semantic/structural preconditions around it are not enforced.

2. **Library upgrade silently exposes latent bugs.** Both the KZG stack overflow (#6105) and the unsorted-indices crashes (#7991, #8509) were caused by upgrading the KZG library. The first tightened stack usage; the second tightened a precondition. Lighthouse had bugs that only became visible when the library stopped tolerating them. This pattern recurs whenever the rust-eth-kzg crate bumps.

3. **Code-path asymmetry between gossip and RPC.** Many bugs arise because a feature is implemented correctly for the gossip path and then partially (or not at all) for the RPC path: fork-choice not run after RPC blob import (#5474), inclusion proofs not verified on RPC range (#6111), blobs not fetched during checkpoint sync (#5251).

4. **Sync and peer management under PeerDAS scale.** The PeerDAS retry/lookup system repeatedly sent excessive requests to the same peers (#6059, #6106, #7204, #7980). Each fix patched one aspect (track failed peers, cap retries, batch requests), but the fundamental design—optimistic fanout without back-pressure—continued to cause issues across devnets.

5. **Pruning and storage operations not tested at realistic scale.** The OOM during blob pruning (#6559) and the high IO from epoch-granularity pruning (#7100) were both invisible at test scale. Storage and pruning operations for blobs accumulate very large datasets over time.

6. **Fork-upgrade transitions break existing instrumentation.** After Fulu, `blob_delay_ms` stopped updating because the code that tracked blob timestamps was not extended to track data-column timestamps (#8775). Similar patterns are expected in any metric, cache, or API that was written for Deneb and not updated for Fulu.

### Highest-leverage early-detection ideas

1. **Fuzz the DA verification layer with adversarial KZG inputs.** Target `validate_data_column_sidecar_for_gossip` and `validate_blob_sidecar_for_gossip` with: empty commitment lists, out-of-order columns, duplicate indices, `index >= NUMBER_OF_COLUMNS`, and mismatched lengths. This would have caught #6440, #7991, and #8509 before testnet.

2. **Symmetric test coverage for gossip vs RPC vs backfill verification paths.** For every check added to one path, CI should enforce the same check on other paths. A `#[test]` matrix that runs each verification scenario (zero blobs, max blobs, empty column list) through gossip, RPC range, RPC root, and backfill simultaneously.

3. **Library-bump integration test harness.** When rust-eth-kzg or c-kzg is bumped, automatically run a suite that exercises all preconditions documented in the library's changelog (sorted indices, non-duplicate cells, non-empty inputs). A small test fixture file (`kzg_preconditions.rs`) that imports and stresses the library boundary.

4. **Realistic-scale storage and pruning benchmarks in CI.** A nightly or weekly job that populates the blobs/columns DB with a simulated year of data and benchmarks the pruning pass, measuring peak RAM and IO. Threshold alerts for >2 GB peak RSS during pruning.

5. **Testnet-incident replay tests.** For each past devnet/mainnet incident (e.g., devnet-2 invalid columns, restart-ban scenario, reconstruction timeout), add a deterministic simulator test that would reproduce it. These serve as regression guards for entire classes of bugs, not just the specific fix.

### Structural / architectural smells

- **`data_column_verification.rs` and `blob_verification.rs` are nearly parallel but diverge silently.** Every time one is updated, the other must be manually checked. A shared trait or macro that enforces symmetric validation would eliminate an entire class of bugs.

- **The DA checker (`data_availability_checker/`) accumulates components from multiple async paths (gossip, RPC, reconstruction) without strong ordering guarantees.** This has caused duplicate-index bugs (#7991) and race conditions (#6319). A design review of the DA checker's concurrency model would be high leverage.

- **`BeaconProcessor` task granularity conflicts with rayon.** Reconstruction tasks are heavyweight but allocated only one BeaconProcessor slot; they then try to claim more threads through rayon's global pool. The architectural mismatch between the cooperative-task model and rayon's fork-join model needs a principled solution (scoped pools in #7924 is a step, but not complete).
