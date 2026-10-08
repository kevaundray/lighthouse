# Deterministic component simulation

## Scope and decision

Implement deterministic RPC flow-control and consensus fork-choice simulations. These are real Lighthouse component tests, not whole-node simulation. The existing `testing/simulator` remains a real-time integration network.

Determinism means identical ordered semantic results for the same seed, scenario, code and locked dependencies. It does not mean identical wall-clock metrics, logs, cryptographic execution timing or portability of seeds across code/dependency changes. Failures must identify the seed and event context. Record the expanded event/observation trace when replaying a failure.

## Research

- [FoundationDB simulation](https://github.com/apple/foundationdb/blob/main/documentation/sphinx/source/client-testing.rst): control every source of nondeterminism inside the simulated boundary; replay failures with the same workload and seed.
- [Turmoil](https://docs.rs/turmoil/latest/turmoil/): single-thread hosts, simulated Tokio-compatible TCP/UDP, seeded faults, partitions and repair. Existing sockets must be replaced explicitly.
- [Shuttle](https://docs.rs/shuttle/latest/shuttle/): randomized, replayable thread scheduling using substituted synchronization primitives.
- [Loom](https://docs.rs/loom/latest/loom/): systematic exploration of instrumented concurrency and memory-ordering behaviors, not a distributed network simulator.
- [Workers.io testing skill](https://github.com/workersio/skills): workload, fault-injection and mutation-testing guidance informs test selection. Require a meaningful failure mechanism, bounded recovery and an assertion that catches a plausible regression. No plugin installation is required.

Use Tokio virtual time for asynchronous RPC limiters and a synchronous logical event scheduler for fork choice. Neither boundary needs simulated sockets, so adding Turmoil here would add a dependency without exercising its transport model.

## Architecture review

| Boundary | Existing seam | Required change or limitation |
| --- | --- | --- |
| RPC flow control | `SelfRateLimiter`, `ResponseLimiter`, `RPCRateLimiter` accept requests and expose poll-driven output | Token replenishment uses `std::time::Instant` while wakeups use Tokio timers. Align those clocks; control identities, arrivals and completions in tests. |
| Fork choice | `ForkChoice` accepts explicit slot and block-delay inputs; `ForkChoiceStore` separates storage | Drive real instances synchronously with valid production-generated artifacts. Reuse production store semantics, not an invented consensus algorithm. |
| Beacon chain harness | Seeded keys, manual slot clock, memory store, real block generation | Fixture preparation uses runtime/worker machinery. Keep it outside the deterministic replay boundary and document that distinction. |
| Existing simulator | Real nodes and validator clients | Uses wall-clock genesis, real ports and asynchronous workers; not a deterministic runtime. |
| Sync test rig | Real sync manager and event queues | Production randomness, unordered peer selection, standard clocks and bypassed maintenance timers prevent a full determinism claim. |
| Whole node | Tokio task executor and libp2p transport construction | Would require controlled transport/discovery/DNS/QUIC, execution-layer HTTP, clocks, entropy, storage and blocking/Rayon scheduling. Out of this implementation scope. |

## Implementation plan

### RPC flow control

1. Add a focused virtual-time regression for quota replenishment before changing production clocks; observe it fail with the old clock and pass after alignment.
2. Align the rate limiter's monotonic clock with Tokio timers. Preserve production quota semantics and public APIs. Queue residence metrics may remain outside the semantic trace if they do not affect decisions.
3. Add a current-thread, paused-time simulation using deterministic peer identities and a named seeded RNG. Drive production poll APIs and actual timer expiry, not private timer callbacks.
4. Exercise burst traffic, delayed completions, per-peer independence, disconnect cancellation, stale timer events and recovery with fresh request IDs; exercise response queue release and disconnect cleanup.
5. Check quota/concurrency boundaries, ordering where promised, exactly-once terminal outcomes for queued work, no cancelled-work resurrection, unaffected-peer progress and bounded recovery.
6. Compare full semantic traces across independent replays and run a fixed seed corpus. Keep active transport cancellation outside the limiter contract.

### Consensus fork choice

1. Generate a valid competing-branch corpus with Lighthouse production block/state/attestation helpers using an explicit fork/spec, deterministic keys and fixed genesis. Fixture generation is not claimed to be simulated.
2. Construct independent real `ForkChoice` instances backed by production memory-store semantics. Replay runs must not share mutable clock, votes or checkpoint state.
3. Order logical events by `(time, insertion sequence)` and use a seeded RNG for varied delivery timing. Model partition drops and explicit recovery deliveries; do not imply fork choice implements network retries.
4. Exercise partition divergence and recovery, delayed/reordered/duplicate messages, unknown-parent rejection and parent-first recovery, current-slot vote deferral, and proposer-boost expiry/boundaries where supported by the corpus.
5. Assert exact scenario-specific heads, finalized ancestry and nondecreasing finalized checkpoints. Do not require transient agreement during partitions or claim finality progress from a short corpus without the requisite valid votes/epochs.
6. Provide a runnable replay example plus automated integration tests. Replay equality supplements semantic assertions; it is not itself a correctness oracle.

### Integration and verification

- Add a focused Make target. Existing CI already runs network unit tests in `release-tests-ubuntu` and fork-choice integration tests in `fork-choice-tests`; keep that coverage rather than add a duplicate job.
- Keep dependencies test-only and use the repository's existing RNG/Tokio conventions.
- Run targeted simulation tests and relevant existing limiter/consensus tests, `cargo check`, formatting and dependency sorting checks.
- Run the consensus replay example as a real smoke scenario and compare independent outputs.
- Demonstrate test sensitivity with a focused reverted behavioral mutation or failing-before/passing-after regression, not a coverage count.
- Review each scenario against the Workers.io quality bar: protected behavior, plausible bug, failing invariant, and explicit excluded behavior.

## Running and replaying

```bash
# Fixed corpus: three RPC tests and three consensus tests.
make test-deterministic-simulation

# Use existing debug artifacts instead of a release build.
make test-deterministic-simulation PROFILE=dev

# Replay RPC faults, printing the semantic trace for both independent runs.
LIGHTHOUSE_SIMULATION_SEED=42 cargo test -p lighthouse_network --lib \
  rpc::deterministic_simulation::seeded_rpc_lifecycle_replays -- --exact --nocapture

# Replay consensus delivery, vote and block-boundary scenarios.
# RUST_LOG removes nondeterministic fixture debug logs, not the semantic trace.
RUST_LOG=error cargo run -p fork_choice --example deterministic_simulation -- 42
```

Both fixed campaigns use seeds `0`, `1`, `7`, `42`, `0x5eed` and `u64::MAX`. Explicit replay arguments use decimal `u64`. Preserve the code revision and `Cargo.lock` with a failure trace; seed stability across generator changes is not guaranteed.

### Implemented workload and oracle

| Component | Adversarial sequence | Observable invariant |
| --- | --- | --- |
| RPC requests | Seeded bursts, delayed completions, disconnect and reconnect before stale timers expire | Quota spacing, concurrency bound, unaffected-peer progress, exactly-once queued cancellation, no resurrection, bounded completion of the new generation |
| RPC responses | Bursts, disconnect while queued, queue drain and reuse | Per-peer FIFO, correct stream/connection identity, no disconnected response release, new traffic accepted after drain |
| RPC ready buffer | Disconnect with both admitted-but-unemitted and delayed work | Exact cancellation set and no duplicate failures after another disconnect |
| Fork choice | Competing valid branches, in-flight partition drops, reordered child, explicit parent-first recovery, delayed/duplicate votes | Known divergent heads, exact weighted convergence, finalized ancestry and nonregression |
| Fork-choice votes | Same-slot delivery, duplicate votes before and after the next slot | No early head change; exact effective-balance weight after deferral, without duplicate inflation |
| Fork-choice blocks | Arrival immediately before/at the boost cutoff, next-slot tick, future/unknown-parent blocks and redelivery | Strict boost cutoff, expiry, no duplicate resurrection, rejected blocks absent until explicit valid import |

The RPC simulation uses ChaCha20 and a 3-second virtual horizon; fork-choice delivery uses ChaCha8 and a 128-event budget. Ordered semantic traces are compared between fresh instances. Assertions check known outcomes as well as replay equality.

### Coverage limits

- RPC simulations drive production poll APIs and timers, but do not test sockets, codecs, peer management or the executor's wakeup scheduling. Queue-residence wall-clock metrics are excluded.
- Active requests belong to the transport. The RPC model explicitly detaches old active requests and withholds old-connection completion callbacks; it does not prove callback ownership or active cancellation. General multi-token request FIFO is not asserted.
- Consensus fixtures use the Base/phase-0 fork, Mainnet preset, 64 deterministic validators and fixed genesis. Production helpers generate signed blocks and signature-verified committee votes before synchronous replay.
- Each replay allocates independent production fork-choice and memory-store state. Proposals are a fixed corpus, not adaptive validator behavior; recovery redelivery is simulator policy, not a sync implementation.
- The short consensus scenario retains genesis finality. It tests ancestry/nonregression, not finalization progress, modern-fork execution payloads, storage crashes or whole-node determinism.

## Clock compatibility fix

`RPCRateLimiter` now uses `tokio::time::Instant` for token accounting, matching its Tokio pruning timer and the caller's delayed-request timers. Ordinary execution still uses a monotonic clock; paused-time execution now replenishes quota when the timer fires.

The new quota regression failed with the previous `std::time::Instant` after advancing 60 virtual seconds. A separate throwaway executable exercised the public `RPC` behaviour after the change: request 1 was emitted immediately, request 2 queued, and request 2 was emitted after 60 virtual seconds. That executable was removed after verification.

This demonstrates a simulation-clock incompatibility and its correction, not a previously established failure of normal wall-clock production traffic.

## Verification and test value

- `make test-deterministic-simulation PROFILE=dev`: six tests passed, including the fixed seed campaigns and independent in-process replay comparisons.
- `cargo nextest run -p lighthouse_network --lib rpc::`: 24 tests passed.
- Independent consensus CLI processes with seed `42` produced identical 62-line semantic traces; seed `7` changed the event schedule after excluding the seed label itself.
- A temporary mutation of the production proposer-boost cutoff from `<` to `<=` failed the boundary test with `wrong boost at delay=3999`. The original production guard was restored.
- `cargo check`, `cargo fmt --all -- --check`, and dependency sorting checks passed.

Applying the Workers.io review criteria: keep these scenarios because they test actual quota release, cancellation, vote weight and head selection under adverse event sequences. The clock regression and cutoff mutation demonstrate assertion sensitivity. Replay equality alone, transport mocks, and claims of whole-node or finality coverage would not meet that bar.

## Publication

Any PR must target `kevaundray/lighthouse`, not `sigp/lighthouse`. The configured `origin` points at the user's fork. Do not publish upstream issues or PRs as part of this work.
