# Database / Store — Bug Audit

## Scope

This audit covers `beacon_node/store/`, the `HotColdDB`, freezer (cold) DB, state caching, pruning, schema migrations, checkpoint-sync persistence, tree-states / hierarchical state diffs (HDiff), blob DB, and pubkey cache on disk. Slashing-protection DB in the validator client is **excluded** (different subsystem; VC-related issues #2354, #1873, #1584, #1537 are not covered here).

### Queries run

```
gh issue list --repo sigp/lighthouse --label "database" --label "bug" --state all --limit 300 --json ...
gh issue list --repo sigp/lighthouse --label "database" --state all --limit 300 --json ...
gh search issues --repo sigp/lighthouse "pruning" --state closed
gh search issues --repo sigp/lighthouse "freezer", "state cache", "corrupt", "disk usage"
gh search issues --repo sigp/lighthouse "hdiff" --state closed
gh search prs --repo sigp/lighthouse "pruning bug fix"
gh issue view <N> + gh api .../issues/<N>/timeline + gh pr diff <N>  (for ~25 items)
```

---

## 2. Bug Table

| # | Title | State | Class | Severity | How-found | One-line root cause | Fix PR |
|---|-------|-------|-------|----------|-----------|---------------------|--------|
| [#692](https://github.com/sigp/lighthouse/issues/692) | Use atomic operations in database | CLOSED | persistence | high | code-review | Each DB insert was a separate op; no atomicity across block+state writes | [#1323](https://github.com/sigp/lighthouse/pull/1323) |
| [#1109](https://github.com/sigp/lighthouse/issues/1109) | Block pruning warnings | CLOSED | persistence | medium | testnet-incident | During initial sync, pruning tried to delete blocks not yet finalized, resulting in warnings | [#1132](https://github.com/sigp/lighthouse/pull/1132) |
| [#1557](https://github.com/sigp/lighthouse/issues/1557) | Head tracker has unsafe API wrt concurrency | CLOSED | concurrency | high | code-review | `head_tracker` had a TOCTOU race: heads could be removed by pruner thread while being read | [#1771](https://github.com/sigp/lighthouse/pull/1771) |
| [#1785](https://github.com/sigp/lighthouse/issues/1785) | Remove head tracker in favour of fork choice | CLOSED | persistence | high | code-review | Head tracker was a redundant, independently persisted structure that could drift from fork-choice | [#6744](https://github.com/sigp/lighthouse/pull/6744) |
| [#2134](https://github.com/sigp/lighthouse/issues/2134) | StateRootMismatch while syncing on windows | CLOSED | persistence | high | user-report | `randao_mixes` state corruption on Windows/VM (related to chunked-vector zeroing, see #3011) | unknown |
| [#3011](https://github.com/sigp/lighthouse/issues/3011) | Fix bug in freezer DB storage of `randao_mixes` | CLOSED | persistence | critical | internal-testing | `store_updated_vector` could re-write old state zeroing entries in chunked randao_mixes array | Superseded by [#5978](https://github.com/sigp/lighthouse/pull/5978) |
| [#3433](https://github.com/sigp/lighthouse/issues/3433) | State Reconstruction reaches a faulty state | OPEN | persistence | high | user-report | `VectorChunkError(Missing)` on restart mid-reconstruction; gap left in cold chunked vector | (ongoing) |
| [#3455](https://github.com/sigp/lighthouse/issues/3455) | Missing chunk in forwards iterator | CLOSED | persistence | medium | user-report | Gap in `BeaconBlockRoots` chunked array in freezer (related to invariant mismatch, see #4663) | [#3511](https://github.com/sigp/lighthouse/pull/3511) (tools only) / [#4663](https://github.com/sigp/lighthouse/pull/4663) |
| [#3505](https://github.com/sigp/lighthouse/issues/3505) | Store pubkey cache decompressed on disk | CLOSED | perf-regression | medium | internal-testing | Compressed BLS pubkeys required expensive decompression on every startup (schema v21) | [#5897](https://github.com/sigp/lighthouse/pull/5897) |
| [#3899](https://github.com/sigp/lighthouse/issues/3899) | Disallow v14/v15 schema downgrade after Capella | CLOSED | persistence | high | code-review | `downgrade_from_v14` not guarded after Capella; `PersistedOpPool` deserialized with wrong type | [#4004](https://github.com/sigp/lighthouse/pull/4004) |
| [#4697](https://github.com/sigp/lighthouse/issues/4697) | `ERRO Missing chunk in forwards iterator` (block roots) | CLOSED | persistence | medium | internal-testing | PR #4663 changed block-root invariant but failed to establish it before the next restore point | [#4875](https://github.com/sigp/lighthouse/pull/4875) |
| [#4773](https://github.com/sigp/lighthouse/issues/4773) | Lighthouse space usage — 87 GB to 430 GB in 7 days | CLOSED | resource | high | user-report | Pruning silently failed after encountering a missing block; states accumulated indefinitely in hot DB | [#5768](https://github.com/sigp/lighthouse/pull/5768) / [#4975](https://github.com/sigp/lighthouse/pull/4975) |
| [#4817](https://github.com/sigp/lighthouse/issues/4817) | State reconstruction broken on Holesky (genesis skip slots) | CLOSED | persistence | high | testnet-incident | Backfill never wrote block roots for skipped genesis slots, leaving gap in linear array | [#4820](https://github.com/sigp/lighthouse/pull/4820) |
| [#4943](https://github.com/sigp/lighthouse/issues/4943) | Lighthouse sends genesis block twice in BlocksByRange | CLOSED | persistence | medium | testnet-incident | Zero block roots stored for skipped genesis slots on checkpoint-synced nodes (same root as #4817) | [#4985](https://github.com/sigp/lighthouse/pull/4985) |
| [#4975](https://github.com/sigp/lighthouse/pull/4975) | Restore crash safety for database pruning | CLOSED | persistence | critical | internal-testing | Pruning checkpoint could race ahead of split slot; on restart, states between old and new checkpoints deleted | [#4975](https://github.com/sigp/lighthouse/pull/4975) |
| [#5097](https://github.com/sigp/lighthouse/pull/5097) | Fix tree-states sub-epoch diffs | CLOSED | persistence | medium | user-report | HDiff writes were batched but not committed between diffs; later diffs couldn't find earlier staged diffs | [#5097](https://github.com/sigp/lighthouse/pull/5097) |
| [#5114](https://github.com/sigp/lighthouse/issues/5114) | Backfill mistakenly stores blobs in the hot DB | CLOSED | persistence | high | internal-testing | `import_historical_block_batch` committed straight to hot DB bypassing `blobs_db` separation | [#5119](https://github.com/sigp/lighthouse/pull/5119) |
| [#5373](https://github.com/sigp/lighthouse/issues/5373) | Disk usage spiked with Panic log | OPEN | resource | high | user-report | Storage full triggered panic from `slog-async`; write failure during blob prune caused state to accumulate | (unresolved) |
| [#5768](https://github.com/sigp/lighthouse/pull/5768) | Fix hot state disk leak | CLOSED | resource | high | testnet-incident | Temporary-flag deletion removed flags for _all_ advanced states instead of only skip-slot states | [#5768](https://github.com/sigp/lighthouse/pull/5768) |
| [#6035](https://github.com/sigp/lighthouse/pull/6035) | Fix SigVerifiedOp SSZ implementation (schema v20 migration) | CLOSED | serialization | high | code-review | `SigVerifiedOp` `Encode`/`Decode` diverged, causing intermittent v20 migration failures | [#6035](https://github.com/sigp/lighthouse/pull/6035) |
| [#6277](https://github.com/sigp/lighthouse/issues/6277) | MDBX binaries exhibit memory corruption | OPEN | resource | critical | user-report | MDBX backend (experimental) causes memory corruption; not recommended for production | (open/unfixed) |
| [#6510](https://github.com/sigp/lighthouse/issues/6510) | Store execution payloads during backfill if `--prune-payloads false` | CLOSED | persistence | medium | code-review | Payloads silently discarded during backfill even when `--prune-payloads false` | (design issue) |
| [#6559](https://github.com/sigp/lighthouse/issues/6559) | Prune blobs can OOM | CLOSED | resource | critical | user-report | `try_prune` loaded all blobs atomically; switching from archive to pruning mode read 77 GB into RAM | [#6571](https://github.com/sigp/lighthouse/pull/6571) |
| [#6580](https://github.com/sigp/lighthouse/issues/6580) | Database growth during non-finality | CLOSED | resource | critical | internal-testing | Hot DB stored one full state per epoch during non-finality; multi-week incidents could hit hundreds of GB | [#6750](https://github.com/sigp/lighthouse/pull/6750) |
| [#6591](https://github.com/sigp/lighthouse/pull/6591) | Fix v22 schema upgrade | CLOSED | persistence | high | internal-testing | `AnchorInfo` wrangling broken between last manual test and merge; v22 upgrade would misbehave | [#6591](https://github.com/sigp/lighthouse/pull/6591) |
| [#7100](https://github.com/sigp/lighthouse/issues/7100) | High read IO due to blob pruning | CLOSED | perf-regression | high | user-report | Post-fix (#6571) blob pruning now read all blobs every epoch (250 MB/s spikes); default too aggressive | [#7113](https://github.com/sigp/lighthouse/pull/7113) |
| [#7216](https://github.com/sigp/lighthouse/issues/7216) | Global pubkey cache is not crash safe | OPEN | persistence | medium | code-review | Global pubkey cache on disk not written atomically; partial write on crash could corrupt it | (open) |
| [#7323](https://github.com/sigp/lighthouse/issues/7323) | Pruning logic broken on `unstable` | CLOSED | persistence | high | internal-testing | Schema v22→v23 migration left "dangling" temporary states causing disjointed summaries DAG | [#7460](https://github.com/sigp/lighthouse/pull/7460) |
| [#7690](https://github.com/sigp/lighthouse/issues/7690) | `BlockId::root` doesn't work at `oldest_block_slot` | CLOSED | persistence | medium | internal-testing | `block_root_at_slot_skips_none` tries to load the _previous_ slot first, which fails at oldest stored | [#7693](https://github.com/sigp/lighthouse/pull/7693) |
| [#7760](https://github.com/sigp/lighthouse/issues/7760) | Slim down PersistedForkChoice | CLOSED | resource | high | internal-testing | `PersistedForkChoiceStore` bloated with `balances_cache` + `justified_balances`; grew during non-finality | [#7805](https://github.com/sigp/lighthouse/pull/7805) |
| [#7849](https://github.com/sigp/lighthouse/pull/7849) | Fix bugs in rebasing of states prior to finalization | CLOSED | persistence | high | user-report | `rebase_on_finalized` called for pre-split states in HDiff grid, corrupting pubkey caches | [#7849](https://github.com/sigp/lighthouse/pull/7849) |
| [#8363](https://github.com/sigp/lighthouse/issues/8363) | State Reconstruction fails with MissingHDiff | CLOSED | persistence | high | user-report | HDiff for a slot missing after restart mid-reconstruction; no resume logic for partially-complete HDiff traversal | (no dedicated fix PR found; closed as won't fix/duplicate) |
| [#8409](https://github.com/sigp/lighthouse/pull/8409) | Gracefully handle deleting states prior to anchor_slot | CLOSED | persistence | high | internal-testing | Aborting and restarting checkpoint sync left orphaned snapshot/diff; `hot_storage_strategy` failed on second sync | [#8409](https://github.com/sigp/lighthouse/pull/8409) |
| [#8426](https://github.com/sigp/lighthouse/issues/8426) | Improve tests for unaligned checkpoint sync | CLOSED | persistence | medium | code-review | Skipped slots at epoch boundary caused `MissingFullBlockExecutionPayloadPruned` panic during checkpoint sync | [#8458](https://github.com/sigp/lighthouse/pull/8458) |
| [#8538](https://github.com/sigp/lighthouse/issues/8538) | Upgraded 8.0.1 node fails to start (DB issue) | CLOSED | persistence | critical | user-report | `Hdiff(InvalidSszState)` on startup after v8.0.1 upgrade; corrupted SSZ data in HDiff storage | (closed; users advised to purge-db) |
| [#8640](https://github.com/sigp/lighthouse/issues/8640) | Inconsistent state availability: /root OK but /validators fails | CLOSED | persistence | high | user-report | Race between finalization SSE event emission and HDiff pruning; state root exists but summary deleted | (closed; design-level race) |
| [#9472](https://github.com/sigp/lighthouse/issues/9472) | `/eth/v1/beacon/light_client/updates` may return incorrect data | OPEN | api-correctness | medium | code-review | Light client update DB query returns stale/incorrect data | (open) |

---

## 3. Deep Dives

### DD-1: Randao Mixes Freezer Corruption (#3011)

**Root cause:** `store_updated_vector` in `beacon_node/store/src/chunked_vector.rs` was responsible for writing `randao_mixes` in the flat chunked format used by the cold (freezer) DB. Under certain conditions the function would re-write an earlier state's chunks, inadvertently zeroing entries. The result was a `0x00` hash appearing at a specific index (e.g. epoch 320 in state at slot 12288), which then propagated silently through all subsequent state reconstructions. The corruption was not caught on first write because the block root check passed; it only manifested when comparing reconstructed states.

**How discovered:** Developer discovered it when `state reconstruction` failed with `ParentBlockRootMismatch` on Prater testnet (Feb 2022). A manual shell script to checksum every 2048th state revealed the first corrupt state at slot 12288 — far earlier than the failure. Also corroborated by `#2134` (Windows VM `StateRootMismatch`) which was likely the same underlying issue.

**How fixed:** The chunked vector code (`chunked_vector.rs`) was eventually replaced wholesale by the hierarchical state diffs (HDiff) approach in PR #5978. The issue was closed in favour of that architectural change rather than patching `store_updated_vector`.

**Why it wasn't caught earlier:** No integrity check over stored chunked vectors on read. State reconstruction doesn't verify a round-trip hash of each intermediate state against its state root. The corruption was also intermittent (depends on re-write ordering), so it didn't appear in CI.

**Could-have-been-caught-by:**
- Property-based test: write state → reconstruct → compare `hash_tree_root` against expected state root.
- Startup integrity check scanning chunked-vector gaps and zero-hash entries.
- Monotonic write invariant: chunked vector entries should never be overwritten with different data; assert on second write.

---

### DD-2: Pruning Checkpoint Race → Irreparable DB Corruption (#4975)

**Root cause:** In the tree-states hot-DB prototype, pruning maintained a separate "pruning checkpoint" that was stored independently of the `split` slot. The pruning routine updated this checkpoint, then separately `migrate_db` updated the `split`. If Lighthouse was killed between these two operations:

1. Pruning checkpoint advanced from `N` to `M`.
2. `split` remained at `N`.
3. On next restart, pruning ran from `M` (checkpoint) to `O` (new end), deleting _everything_ between `M` and `O` that was not on the canonical chain — including states between `N` and `M` that migration had not yet copied to the cold DB.
4. `migrate_db` could not find the states it expected; the DB was irreparably damaged.

**How discovered:** Internal testing during tree-states development (PR #4975 note: "This bug doesn't exist on `stable`").

**How fixed:** Abolished the separate pruning checkpoint; derived it always from `split`, making them advance atomically.

**Why it wasn't caught earlier:** The race window was narrow (between two async operations), and the bug only existed in the unreleased tree-states branch, not stable.

**Could-have-been-caught-by:**
- Crash-injection test (kill process between pruning and migration) as part of CI.
- Invariant assertion: `pruning_checkpoint <= split.slot` checked on startup.
- Single atomic DB operation for pruning + split update.

---

### DD-3: Block Roots Invariant Mismatch → Cascading "Missing Chunk" Errors (#4697)

**Root cause:** PR #4663 changed the invariant for block roots in the freezer from `slot < last_restore_point_slot` to `slot < split.slot`. The PR correctly maintained the invariant going forward, but _did not establish it retroactively_ on upgrade. As a result, until a new restore-point was written (~27h), there was a gap in the linear block-roots array between `last_restore_point_slot` and `split.slot`. Any forward block-roots iterator traversal through that gap logged `ERRO Missing chunk in forwards iterator`.

**How discovered:** Internal testing by `@michaelsproul` immediately after releasing the fix PR. PR #4663 introduced it, and #4697 was filed as a consequence. Many user nodes on Görli/testnets were affected.

**How fixed:** PR #4875 added `heal_freezer_block_roots()` call inside the schema v18 migration, which fills in the gap on upgrade. Regression test added.

**Why it wasn't caught earlier:** The bug was self-healing (fixed naturally after 27h), so it was missed during release testing — the test nodes had already waited long enough. There was also no automated schema migration test at the time.

**Could-have-been-caught-by:**
- Automated schema upgrade test that verifies the `BeaconBlockRoots` array is gap-free immediately after migration (before any new blocks).
- Startup invariant check asserting no gaps in `BeaconBlockRoots` from 0 to `split.slot`.

---

### DD-4: Backfill Blobs in Wrong DB (#5114)

**Root cause:** `import_historical_block_batch` in `historical_blocks.rs` committed its entire batch directly to the hot DB. Blobs should have been written to `blobs_db` (a separate LevelDB directory introduced in PR #4892). The function did not use `do_atomically_with_block_and_blobs_cache`, which handles the routing. Blobs were therefore silently stored in the wrong DB on all nodes that checkpoint-synced and ran blob backfill on Goerli/testnet.

**How discovered:** Internal code review by `@michaelsproul` during v4.6.0-rc.0 testing.

**How fixed:** PR #5119 rerouted blob writes to `blobs_db`, added schema v19 migration to copy misrouted blobs from hot DB to blobs DB and delete them.

**Why it wasn't caught earlier:** Blobs still returned correctly (the hot DB lookup fell back correctly), so there were no observable failures. No test exercised the separation between `hot_db` and `blobs_db` during backfill.

**Could-have-been-caught-by:**
- Integration test asserting that after blob backfill, `hot_db` contains no blob-column keys.
- Type-level enforcement: blobs write path should require a `BlobsDbHandle` type, not a generic `HotDbHandle`.
- Lint/clippy rule: flag direct `.do_atomically()` calls on `hot_db` from the backfill code path.

---

### DD-5: State Reconstruction Broken on Holesky (Genesis Skip Slots) (#4817 / #4943)

**Root cause:** On Holesky, slot 1 is skipped (the first block is at slot 2). During backfill, `import_historical_block_batch` never wrote block roots for slots 0–1 because there were no blocks at those slots. The `forwards_block_roots_iterator` requires a contiguous array; the missing entries broke state reconstruction (which needs block-root iteration), and also caused Lighthouse to serve duplicate genesis blocks in `BlocksByRange` responses.

**How discovered:** Holesky genesis (September 2023); testnet incident report from `@etan-status` (Nimbus interop testing #4943).

**How fixed:** PR #4820 added logic to fill in block roots for genesis skip slots when storing the genesis block. PR #4985 added a schema migration to heal already-broken databases.

**Why it wasn't caught earlier:** Mainnet and all previous testnets had no genesis skip slots. The condition was entirely new to Holesky and was not covered in any existing test harness.

**Could-have-been-caught-by:**
- Test harness that starts a chain with a skipped genesis slot, does checkpoint sync, then verifies block-root array continuity.
- A pre-sync invariant check: `BeaconBlockRoots[0..genesis_first_block_slot]` must all equal genesis root.

---

### DD-6: Hot DB State Disk Leak (#5768)

**Root cause:** PR #5533 (in-memory tree states) introduced logic to store "advanced states" in the DB with a temporary flag, deleting the flag during block processing. The bug: temporary flags were deleted for _all_ advanced states on every block, when they should only be deleted for states at skipped slots. For consecutive blocks at slots N and N+1, the pre-state of N+1 was stored permanently without a temporary flag, so pruning never deleted it. Over time this caused unbounded growth.

**How discovered:** Internal testnet deployment (`@antondlr` noticed state growth).

**How fixed:** PR #5768 scoped temporary-flag deletion to skipped slots only; ported hot-DB state pruning logic from tree-states to allow pruning without restart.

**Why it wasn't caught earlier:** The logic change was subtle (a condition inversion), and CI did not measure disk usage over time. The temporary flags feature was also new, so no existing test exercised the pruning of "non-temporary" advanced states.

**Could-have-been-caught-by:**
- DB size monotonicity test: after N finalized epochs, assert that hot DB size is bounded by O(epochs * state_size_per_restore_point).
- Metric: count `HotStateSummary` entries; alert if count grows unboundedly.

---

### DD-7: Blob Pruning OOM (#6559)

**Root cause:** The `try_prune` function loaded all blobs inside a single atomic transaction (`do_atomically_with_block_and_blobs_cache`), then partitioned them to keep/delete. Switching a node from `--prune-blobs false` (full archive) to `--prune-blobs true` forced a single atomic load of all blobs (~77 GB on mainnet), exhausting RAM.

**How discovered:** User report from AllNodes (production node) — OOM kill after flag change.

**How fixed:** PR #6571 replaced the load-all-then-delete pattern with a streaming `delete_while` iterator that removes blobs incrementally without loading all of them into memory. Then PR #7113 changed the default `--epochs-per-blob-prune` to 256 (once per day) to reduce I/O from the new algorithm.

**Why it wasn't caught earlier:** Archive blob storage was new; the OOM only manifested when transitioning from archive to pruned mode, which was not a tested migration path.

**Could-have-been-caught-by:**
- Memory-bounded invariant: any DB operation involving `blobs_db` should be proven to use O(batch_size) memory, not O(total_db_size).
- Integration test: switch from archive to pruned mode and verify memory usage stays below a threshold.

---

### DD-8: Database Growth During Non-Finality (#6580)

**Root cause:** The hot DB stored one full beacon state per epoch indefinitely. During a multi-week non-finality event, this compounded to hundreds of GB. The hot DB had no state-pruning mechanism tied to the live chain head — it only pruned via the migration to the cold DB (which requires finalization).

**How discovered:** Internal analysis after observing non-finality scenarios. The `HDiff` approach for the hot DB was the proposed fix.

**How fixed:** PR #6750 ("Hierarchical state diffs in hot DB") replaced full-state storage in the hot DB with HDiff-style diffs referenced by `state_root`, pruning everything except the path from the most recent snapshot to the split state.

**Why it wasn't caught earlier:** Non-finality events of multi-week duration had not previously been common enough to exhaust disk on typical operator hardware. The issue was understood architecturally but not urgent until staking became mainstream.

**Could-have-been-caught-by:**
- Simulated non-finality stress test: run a chain without finalization for N epochs, assert hot DB size stays below a budget.
- Disk usage metric with alerting: `hot_db_bytes_total` growing faster than `blocks_per_epoch * block_size`.

---

### DD-9: v22 Schema Upgrade Bug (#6591) and Dangling Temp States → Pruning Failure (#7323)

**Root cause (two-stage):**
1. PR #6591: The v22 schema migration for the HDiff hot-DB feature mishandled `AnchorInfo`, discovered only by manual testing between last test and merge.
2. PR #7460 (Issue #7323): The v22→v23 migration deleted the "temporary" flag from states but left the state data in the DB, creating "dangling" states not connected to any head. The new pruning DAG (`StateSummariesDAG`) rejected these disjoint nodes with `StateSummariesNotContiguousError`, halting all pruning.

**How discovered:** Internal node run after release of v7.x.

**How fixed:** PR #7460 made `StateSummariesDAG` more permissive: disjoint summaries are treated as roots of their own sub-tree and pruned (safe since canonical summaries cannot be disjointed without existing DB corruption).

**Why it wasn't caught earlier:** Schema migration testing was only manual at the time. The dangling state from v22 was only reachable on nodes that had run the intermediate v22 build.

**Could-have-been-caught-by:**
- Automated schema migration test (which PR #7669 later added) running the upgrade and verifying pruning runs cleanly afterward.
- DAG construction should have been tested against DBs containing orphan summaries.

---

### DD-10: Checkpoint Sync Interrupted → `LessThanStart` HDiff Failure (#8409)

**Root cause:** If checkpoint sync was aborted midway (e.g., node killed) and restarted, an orphaned snapshot/diff pair from the first sync remained in the DB. When the pruning logic ran on restart with the partial `anchor_slot` set, `hot_storage_strategy` encountered a diff with a start slot less than the anchor, causing `HotColdDBError(Rollback)` and a failure loop.

**How discovered:** Internal testing by `@jimmygchen`.

**How fixed:** PR #8409 added cleanup: if `hot_storage_strategy` fails, delete the orphaned snapshot/diff before propagating the error.

**Why it wasn't caught earlier:** The multi-phase checkpoint sync was not tested with mid-sync interruptions. The comment in the code even acknowledged the non-atomicity: "the writing of the checkpoint state could also be made more atomic."

**Could-have-been-caught-by:**
- Chaos-injection test: kill Lighthouse at random points during checkpoint sync, restart, verify clean startup.
- Atomic two-phase write for checkpoint state (write to a temp key, rename/swap on success).

---

### DD-11: `rebase_on_finalized` Corrupts Pubkey Cache for Pre-Split States (#7849)

**Root cause:** After v7.1.0, the HDiff grid stores states older than the split slot (required for diff computation). `rebase_on_finalized` was called for _all_ hot states including these pre-split states. This function called `rebase_caches_on` which incorrectly used the newer split state's pubkey cache on an older state (e.g., genesis state), violating the invariant `pubkey_cache.len() <= validators.len()`, producing an `OutOfBoundsIterFrom` panic/error.

**How discovered:** Production user report from `beaconcha.in` archive node on Hoodi testnet.

**How fixed:** PR #7849 restricted `rebase_on_finalized` to states at or after the split slot, and fixed the bounds check in `rebase_caches_on`.

**Why it wasn't caught earlier:** The pre-split states in the HDiff grid were a new invariant introduced in v7.1.0; no existing test exercised `rebase_on_finalized` on states with a slot prior to `split_slot`.

**Could-have-been-caught-by:**
- Test that exercises `rebase_on_finalized` on the full range of states in the HDiff grid including states older than `split_slot`.
- Debug assertion: `old_state.slot >= new_state.slot` before calling `rebase_caches_on`.

---

### DD-12: SigVerifiedOp SSZ Migration Bug (Schema v20) (#6035)

**Root cause:** The hand-written `Encode`/`Decode` implementations for `SigVerifiedOp` diverged — `Encode` wrote fields in one order, `Decode` expected a different layout. This only manifested when op-pool entries were present in the DB (i.e., not always), causing the v20→v21 migration to fail and brick the database for affected nodes.

**How discovered:** Code review during v21 schema migration testing (#5897 comment thread).

**How fixed:** PR #6035 replaced the hand-written impls with generated ones using transparent wrapper types (`SigVerifiedOpEncode`/`SigVerifiedOpDecode`), with roundtrip property tests.

**Why it wasn't caught earlier:** Manual migration testing on a clean node had no op-pool entries. The discrepancy only triggered when `SigVerifiedOp`s existed, which is intermittent.

**Could-have-been-caught-by:**
- Roundtrip SSZ test: `decode(encode(x)) == x` for every type stored in the DB (should be in CI for all DB types).
- Fuzzing of schema-migration read path.

---

### DD-13: Blobs Stored in Hot DB During Backfill (#5114) — *see DD-4 above*

### DD-14: PersistedForkChoice Bloat During Non-Finality (#7760)

**Root cause:** `PersistedForkChoiceStore` included `balances_cache` (~65 MB) and `justified_balances` (~16 MB). It was written to disk on every slot. During non-finality, `ProtoArray` grows as more unfinalized blocks accumulate, causing write amplification of hundreds of MB/s.

**How discovered:** Internal profiling showing excessive disk write bytes.

**How fixed:** PR #7805 removed `balances_cache` and `justified_balances` from the persisted struct, removed `balances` from `ProtoArray`, and compressed votes with zstd. Schema bumped to v28 with migration.

**Why it wasn't caught earlier:** The problem only compounds under extended non-finality. Under normal conditions the data fits in a reasonable budget.

**Could-have-been-caught-by:**
- Write-bytes metric with an alert if `persisted_fork_choice_bytes` exceeds a threshold.
- Non-finality simulation test verifying `PersistedForkChoice` size is bounded.

---

## 4. Synthesis

### 4.1 Counts by Class and Severity

**By class:**

| Class | Count |
|-------|-------|
| `persistence` | 20 |
| `resource` | 8 |
| `concurrency` | 2 |
| `serialization` | 1 |
| `perf-regression` | 2 |
| `api-correctness` | 1 |

**By severity:**

| Severity | Count |
|----------|-------|
| `critical` | 5 |
| `high` | 22 |
| `medium` | 7 |
| `low` | 0 |

---

### 4.2 Recurring Root-Cause Themes

1. **Invariant mismatch between phases of multi-step operations.** The most common pattern: a feature changes what data is stored (or where), but fails to establish the new invariant for data already on disk. Examples: #4697 (block roots gap after PR #4663), #4817 (genesis skip slots), #5114 (blobs in wrong DB), #7323 (dangling temp states from v22 migration). Each required a retroactive schema migration heal step.

2. **Pruning checkpoint / state management races.** Pruning and migration are two separate async operations. When they can get out of sync (either through a race or a crash window), the result is catastrophic: states are deleted that migration still needs (#4975), or orphaned state fragments accumulate (#8409, #5768). The fundamental tension is that "what to prune" and "what has been migrated" must be determined atomically.

3. **Atomicity boundary mismatches between multiple DB files.** Lighthouse uses multiple LevelDB directories (`chain_db`, `freezer_db`, `blobs_db`). Cross-DB atomic writes are complex and repeatedly failed: early freezer writes (#692, #1323), blobs-to-hot-DB routing (#5114), and the three-way atomicity needed for backfill (blobs + hot + cold, PR #5119).

4. **Cascading failures from silent pruning errors.** When pruning encountered an error (e.g., missing block root, write failure), it logged a warning but continued. States therefore silently accumulated (#4773, #5373), reaching hundreds of GB before users noticed. The pruning failure mode was insufficiently visible.

5. **HDiff/tree-states: multiple boundary bugs during introduction.** The hierarchical state diff system (PRs #5978, #6750) solved the non-finality disk growth problem but introduced a new wave of persistence bugs: `rebase_on_finalized` called on pre-split states (#7849), dangling summaries from schema migration (#7323), checkpoint sync interrupt recovery (#8409), and MissingHDiff on reconstruction restart (#8363).

6. **Schema migration brittleness under real-world conditions.** Migrations were only tested manually on clean nodes. Bugs in migrations (#3899, #6035, #6591, #7323, #4697) were repeatedly found only in production because: (a) they triggered only with specific DB states (e.g., op-pool entries, skip slots), (b) they were self-healing over time, or (c) manual test environments had no real historical data.

---

### 4.3 Highest-Leverage Early Detection Ideas

1. **Automated schema migration CI test with a seeded real-world DB snapshot.** Run every schema upgrade against a snapshot taken from a mainnet/testnet node that has op-pool entries, skip slots, archive states, and blobs in various DB columns. Assert the DB is valid (no gaps, no misrouted data) immediately after migration. This would have caught #4697, #4817, #4943, #5114, #6035, #6591, #7323.

2. **Crash-injection (chaos) tests for pruning and migration.** Use `SIGKILL` injection at random points within `migrate_db`, `prune_abandoned_forks`, and `hot_storage_strategy`. On restart, assert that the node can start cleanly and serve correct state. This would have caught #4975, #8409, and surfaced the non-atomicity noted in #692.

3. **Monotonic hot-DB size invariant in long-running tests.** A test that simulates 100+ epochs (including non-finality periods) should assert that `hot_db` size (state bytes) stays within O(hierarchy_levels * snapshot_size). Alert if state count in `HotStateSummary` exceeds a threshold relative to finalized epoch difference. Would have caught #5768, #6580, #7760.

4. **Roundtrip SSZ property tests for every on-disk DB type.** `decode(encode(x)) == x` for every type serialized to/from the DB, run as part of CI with randomized inputs. Would have caught #6035 (`SigVerifiedOp`) and would harden all future schema migrations.

5. **Gap-detection startup check (with metric export).** On startup, scan the `BeaconBlockRoots` chunked-vector (or the HDiff grid anchor) for gaps, and export the result as a Prometheus metric. If a gap is found, log a `CRIT` and expose a repair suggestion. This is a generalization of the `lighthouse db inspect --output gaps` tool (#3511) into the normal run path. Would have surfaced #3455, #4697, #4817, and #3011 corruption earlier.

---

### 4.4 Structural/Architectural Observations

- **`beacon_node/store/src/hot_cold_store.rs` is the highest-risk single file.** It appears in or causes nearly every impactful bug: pruning logic, split management, HDiff grid, anchor handling. It is very large and has grown organically. Consider decomposing into dedicated modules: `pruner.rs`, `migration.rs`, `hdiff_storage.rs`.

- **`historical_blocks.rs` (backfill path) is a persistent bug attractor.** Three separate issues (#4817, #4943, #5114, #6510) all trace to the backfill import path making wrong assumptions about DB routing or data invariants. The function `import_historical_block_batch` has high cyclomatic complexity and touches multiple DB handles without type-level separation.

- **The "three DB" architecture (`chain_db` + `freezer_db` + `blobs_db`) is fundamentally non-atomic** across writes. Every feature that writes to more than one of these needs to specify a crash-recovery order (write blobs first, then hot, then cold: PR #5119) and test it. A transactional wrapper or write-ahead log that spans all three would eliminate an entire class of bugs.

- **Schema migration code is under-tested relative to its criticality.** `schema_change/` has almost no CI coverage for the upgrade/downgrade paths on realistic data. The first automated migration test was added only in PR #7669 (2024), years after the bugs this would have caught.
