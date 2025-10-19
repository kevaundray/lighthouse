# Data Availability Checker Overview

Lighthouse keeps a dedicated cache that tracks every block whose availability is still in flux.
This document explains how the checker works today, which APIs other components rely on, and the
assumptions you must preserve when extending it (e.g. when adding execution proofs).

## High-level Architecture

The public surface lives in `beacon_node/beacon_chain/src/data_availability_checker.rs`. At its
core is `DataAvailabilityChecker<T>`, which wraps:

- `DataAvailabilityCheckerInner<T>` (in `overflow_lru_cache.rs`): maintains an LRU map from block
  root to `PendingComponents`. Each entry tracks the cached block, any KZG-verified blobs and custody
  columns, and whether reconstruction has started.
- `StateLRUCache<T>` (in `state_lru_cache.rs`): holds the executed state for pending blocks. When the
  cache overflows, it replays the block from its parent state (assuming the parent is already
  imported).
- `CustodyContext`: exposes which custody columns this node must sample for each epoch.

The cache is intentionally configured to stay “full” and only evict via LRU to avoid race
conditions—other code assumes entries persist until finality-driven pruning runs.

## Block Lifecycle Inside the Checker

1. **Pre-execution insert** – `BeaconChain::process_block` calls
   `put_pre_execution_block` before the block is executed. The entry is stored as
   `CachedBlock::PreExecution`. During this phase the checker **accepts** new blobs/columns, but
   `make_available` always returns `None`: availability decisions are deferred until the block is
   executed.

2. **Component ingestion** – gossip, RPC, engine backfills, or reconstruction code call one of:

   - `put_gossip_verified_blobs`, `put_rpc_blobs`, or `put_kzg_verified_blobs`
   - `put_gossip_verified_data_columns`, `put_rpc_custody_columns`, or
     `put_kzg_verified_custody_data_columns`

   Each helper KZG-verifies inputs, filters them to the custody requirement, then merges them into
   the cached `PendingComponents`. If the executed block is not yet cached, the call returns
   `Availability::MissingComponents` and the block remains pending. Once a block is executed,
   `make_available` will re-check all cached data against the block commitments.

3. **Execution success** – `put_executed_block` upgrades the entry to
   `CachedBlock::Executed`. This triggers a re-validation of cached blobs/columns and, if all
   required components are present, `Availability::Available` is returned. Otherwise the block
   continues to surface as `Availability::MissingComponents`.

4. **Import** – `BeaconChain::process_availability` consumes the `Availability` result:

   - `Available` → run `import_available_block`, persist data, recompute head.
   - `MissingComponents` → propagate `AvailabilityProcessingStatus::MissingComponents(slot,
     block_root)`. Downstream code reacts by requesting blobs/columns from peers or the execution
     layer, logging warnings, and scheduling retries.

5. **Execution failure** – if execution fails, `remove_block_on_execution_error` removes the
   pre-execution placeholder so rangesync/lookup can retry. Executed entries remain in the cache so
   a late-arriving component can still complete availability.

## Public API and Call Sites

`DataAvailabilityChecker` exposes the following groups of methods:

### Block Registration

- `put_pre_execution_block`, `put_executed_block`, `remove_block_on_execution_error`
- `get_cached_block` – returns `BlockProcessStatus::NotValidated` for pre-execution entries and
  `ExecutionValidated` once executed.

Consumers: `BeaconChain::process_block`, `[network]/sync` lookups, and test harnesses.

### Component Ingestion

- Gossip and RPC ingestion for blobs and custody columns (`put_{gossip,rpc}_*`)
- Engine-path ingestion (`put_kzg_verified_blobs`, `put_kzg_verified_custody_data_columns`)

Consumers: gossip handlers (`network_beacon_processor/gossip_methods.rs`), RPC handlers
(`network_beacon_processor/sync_methods.rs`), execution-layer fetch service
(`network_beacon_processor/mod.rs`), and reconstruction.

### Reconstruction

- `reconstruct_data_columns` – drives `check_and_set_reconstruction_started` and
  `KzgVerifiedCustodyDataColumn::reconstruct_columns`. Successful reconstruction re-inserts the
  newly simulated columns and returns them for publication.

Consumers: beacon processor’s reconstruction queue (`network_beacon_processor/mod.rs:816-838`).

### Inspection & Helpers

- `get_blob`, `get_data_columns`, `cached_{blob,data_column}_indexes`
- Custody utilities: `custody_context`, `sampling_columns_for_epoch`
- Policy helpers: `data_availability_boundary`, `blobs_required_for_epoch`,
  `data_columns_required_for_epoch`, `metrics`

Consumers: fetch service, RPC responders, metrics, gossip log annotations, custody scheduling, and
network initialisation (for custody group counts).

## Behaviour of `Availability::MissingComponents`

`check_availability_and_cache_components` converts any `Ok(None)` from `make_available` into
`Availability::MissingComponents`. The status is **widely** used:

- `BeaconChain::process_block` returns it to the caller and logs “awaiting blobs”.
- Range sync treats it as a hard error for that segment (`MissingBlobs`).
- Gossip and RPC handlers use it to trigger follow-up actions (e.g. fetch from EL,
  schedule reconstruction) while keeping the block cached.
- Block lookup tests assert that returning `MissingComponents` after all components were processed
  is a bug (`MissingComponentsAfterAllProcessed`).

Any new availability path must respect this signal and ensure it is never emitted after the block
is both executed and fully supplied with the required components.

## Key Assumptions and Invariants

- **Custody context initialisation** – The client builder **must** call
  `custody_context().init_ordered_data_columns_from_custody_groups`. Sampling decisions and CGC
  filtering rely on this ordered list.
- **Cache persistence** – Entries should not be manually removed except when execution fails. Other
  components rely on being able to query cached data long after the block becomes available.
- **Parent state availability** – State reconstruction assumes the parent block is already in fork
  choice. If you store new data (e.g. execution proofs), ensure you do not break this assumption.
- **Slot clock access** – `put_rpc_blobs` and `data_availability_boundary` expect the slot clock to
  be readable; callers should observe that pre-condition.
- **Commitment matching** – Any cached blob or column must be verified against the commitments in
  the executed block. `merge_block` evicts mismatched blobs; new data sources must follow the same
  pattern.

## Edge Cases To Consider When Adding Execution Proofs

Adding a new component type (e.g. execution proofs) will require all of the following:

1. **Ingestion path** – Decide which interfaces receive proofs (gossip, RPC, EL, reconstruction) and
   add corresponding `put_*` helpers. Proofs should be verified (or at least validated) before being
   cached.
2. **Caching model** – Extend `PendingComponents` and `AvailableBlockData` to hold the new component
   type. Ensure `make_available` checks the proofs are present whenever the block’s availability
   requires them.
3. **Filtering** – If proofs are only relevant to specific custody groups or slots, reuse or extend
   `CustodyContext` to determine which proofs to retain.
4. **Availability signal** – Update `check_availability_and_cache_components` so `MissingComponents`
   accurately captures “waiting for proof” states, and make sure ingestion paths pass the slot/root
   along so sync/gossip can log meaningful messages.
5. **Serving and inspection** – Expose read APIs if other peers will request the proofs (similar to
   `get_blob` / `get_data_columns`). Update RPC routing to serve them.
6. **Persistence** – Decide whether proofs need to be persisted alongside blobs/data columns in
   `AvailableBlockData::deconstruct` and the hot store.
7. **Maintenance** – Update metrics and the overflow maintenance service if proof caching affects
   per-epoch pruning or memory limits.

## Quick Reference

- `DataAvailabilityChecker<T>` – public API (beacon_node/beacon_chain/src/data_availability_checker.rs)
- `DataAvailabilityCheckerInner<T>` & `PendingComponents` – storage and availability logic
  (…/overflow_lru_cache.rs)
- `StateLRUCache<T>` – executed state caching (…/state_lru_cache.rs)
- Beacon chain integration points – `beacon_node/beacon_chain/src/beacon_chain.rs`
- Network integration – `beacon_node/network/src/network_beacon_processor/{gossip_methods,sync_methods,mod}.rs`
- Fetch service – `beacon_node/beacon_chain/src/fetch_blobs/fetch_blobs_beacon_adapter.rs`

Keep this document up to date as new component types or flows are added—the checker is a central
piece of the availability story, and small changes ripple throughout the client.
