# Whole-node deterministic simulation

## Goal

Run actual Lighthouse beacon-node services together under a controlled execution environment, inject seeded failures, and reproduce the same semantic execution from the same inputs. Component tests and a repeatable final head alone do not meet this goal.

This extends the component work in [deterministic_simulation.md](deterministic_simulation.md). The guarded whole-node baseline and partition/execution-recovery workloads have passed with byte-identical independent-process replay.

## Running and replaying

```sh
# Build, run 17 independent processes, compare complete semantic traces.
# The output directory must be new; failures retain all evidence.
python3 testing/simulation/whole_node_replay.py \
  --output /tmp/lighthouse-whole-node-replay --jobs 2

# Equivalent serial Make entrypoint.
make test-whole-node-simulation \
  WHOLE_NODE_REPLAY_OUTPUT=/tmp/lighthouse-whole-node-replay-serial

# Build and reproduce one scenario.
cargo build --config .cargo/config-simulation.toml --release \
  -p simulator --features spec-minimal --bin deterministic-simulation
target/x86_64-unknown-linux-gnu/release/deterministic-simulation 42 faults
target/x86_64-unknown-linux-gnu/release/deterministic-simulation 42 baseline
target/x86_64-unknown-linux-gnu/release/deterministic-simulation 42 discovery
target/x86_64-unknown-linux-gnu/release/deterministic-simulation 42 restart
target/x86_64-unknown-linux-gnu/release/deterministic-simulation 42 storage
target/x86_64-unknown-linux-gnu/release/deterministic-simulation 42 forks

# Qualify only selected scenarios, with the same replay and invariant checks.
python3 testing/simulation/whole_node_replay.py \
  --output /tmp/lighthouse-restarts --scenarios restart storage --jobs 2

# Persistent-store boundaries and actual encrypted discovery PING/PONG/ban isolation.
cargo test --config .cargo/config-simulation.toml --release \
  -p store --lib simulation_store::tests
cargo test --config .cargo/config-simulation.toml --release \
  -p simulator --features spec-minimal --test discovery_simulation

# Prove unsupported native effects terminate the child with SIGSYS.
cargo test --config .cargo/config-simulation.toml --release \
  -p simulator --features spec-minimal --bin deterministic-simulation \
  simulation_guard::tests::rejects_uncontrolled_effects
```

The replay command runs each of `baseline`, `faults`, `discovery`, `restart`, `storage`, and `forks` at seed 42 twice, and each non-baseline scenario at seed 7 once. It requires successful process exits and terminal `passed`/`stopped` events, compares the complete ordered semantic JSONL records, and checks that different seeds change actual injected fault events. It validates crash/restart evidence against the manifest and retains separate stdout/stderr, per-run status and trace hashes, executable/lock/config hashes, exact commands and source revision/dirty status. Runtime children have isolated temporary fixture directories. A wall-clock timeout kills the complete process group; the driver also has a virtual-time bound. `RUST_LOG` can select diagnostic targets; comparisons must use the same logging configuration because enabled tracing can change the simulated execution schedule.

The `faults` scenario partitions the initial pair for 16 slots, restores connectivity, reports Engine API `SYNCING` for eight slots while the execution model learns payloads, restores `VALID`, and starts a third node at slot 80. Fault timing is seeded independently of runtime scheduling. The driver requires actual head divergence and execution optimism, monotonic per-process and non-conflicting global finality, convergence of all three nodes, fresh heads and finality, no remaining optimism, and accepted post-recovery proposals from **both** validator groups on the converged chain. Each final checkpoint must match its canonical head state's historical block root at the checkpoint slot; actual Beacon HTTP heads must agree with local observations. It never injects beacon blocks, votes, head state or finalized checkpoints directly.

Additional scenarios:

- `discovery`: real Discv5 protocol over simulated IPv4 UDP, ENR bootstrap, ordinary untrusted peer scoring, and the same partition/Engine faults. No trusted-peer admin calls. The trace records real UDP sessions and HTTP peer scores/status and rejects any trusted peer. Recovery has a separate slot-512 bound because the production score half-life is 600 seconds, independent of the accelerated three-second slots. Production score thresholds are unchanged.
- `restart`: the third node first syncs, then crashes at seeded slot 94–96 and restarts two slots later. Its execution service stays alive on a separate virtual host. A fresh production client opens retained storage and network identity; the first restored head must be a non-genesis root in the pre-crash canonical ancestry, before network catch-up.
- `storage`: the third node's next real block batch fails. The driver requires an actually returned storage error, poisoned fork choice, and the production database-failure shutdown reason, then models power loss and fresh startup two slots later. The model never syncs on crash or reopen. A recovered checkpoint may be older than the lost process's last observation; the trace records that transition, resets only that process's monotonicity baseline, and preserves the global conflicting-finality oracle.
- `forks`: Fulu at genesis, Gloas at epoch 12/slot 96, after the partition/Engine recovery and late join. Actual head blocks **and states** must match the scheduled fork; the trace must observe Fulu then Gloas, continued proposals, finalized ancestry and all-node convergence. This is a current live-operation transition, not a claim to run historical Bellatrix/Capella/Deneb networks: current production attestation/blob services deliberately no longer support parts of those old live paths.

Non-discovery scenarios finish at slot 128. Every scenario requires a head at least `end - 1` and finalized epoch at least `end / 8 - 4`.

Original PR #28 qualification at commit `227051605d9931152616a154abb83d86273d94f6`:

| Run | Partition / heal / SYNCING / VALID | Result | Full stdout SHA256 |
| --- | --- | --- | --- |
| baseline/42, twice | none | identical slot-128 heads, epoch-14 finality, both proposers resumed | `8acd4068fcf70bd38c4fec001ec821b6182b7c4a13a76082c18da411f710ba5e` |
| faults/42, twice | 41 / 57 / 65 / 73 | identical slot-128 heads, epoch-14 finality, both faults observed and proposers resumed | `5b5e6b20c206cd75f7c04394abe0e025d81c724135a7df64d0f2c57359fa3df3` |
| faults/7 | 40 / 56 / 64 / 72 | slot-128 convergence, epoch-14 finality, both faults observed and proposers resumed | `28bba4464dc7dece75777be3196e158487b834e89df6af91d5d860455cfece7e` |

These are recorded qualification results, not golden roots required of future protocol changes. Expected diagnostics during the injected `SYNCING` window remain visible on stderr.

Native compatibility was also exercised after integration: `cargo run --release -p simulator --features spec-minimal -- basic-sim --nodes 2 --proposer-nodes 0 --validators-per-node 32 --speed-up-factor 2 --log-dir /tmp/lighthouse-native-after-dst` completed with `Simulation exited successfully`. Targeted native checks passed for simulator, beacon chain, execution layer and validator HTTP API tests/examples; the simulation configuration also passed `cargo check`. The integrated suite passed 24 RPC tests, three consensus simulations and 42 execution-layer tests. Earlier focused native checks passed three fork-choice signal tests, 43 slashing-protection tests, and the real validator-management HD-creation and enabling HTTP tests. Formatting and workspace dependency sorting checks passed. Vendored upstream warnings and simulation-only unused/deprecated-path warnings remain visible; they are not suppressed.

## Required production coverage

The simulated node must execute the real libp2p swarm and RPC/gossip protocols, network service, router, sync manager, beacon processor and reprocessing timers, block/signature/state validation, fork choice, slot services and storage. The post-Merge scenario must also execute the real Engine API HTTP client against a controlled execution-layer test service. Validator duties should use production validator-client code rather than a driver inventing votes or writing fork-choice state.

A test execution layer is an explicit external-system model, not a replacement for Lighthouse's production Engine API client or beacon-chain processing. Slasher, monitoring/exporters, UPnP, QUIC and discovery coverage must be individually stated; disabling an optional surface does not prove that surface deterministic.

## Effect inventory

| Source | Evidence | Requirement |
| --- | --- | --- |
| Async scheduling | `common/task_executor/src/lib.rs`; multi-thread environment runtime | Control runnable task ordering, cancellation, timers and panics. |
| CPU and blocking work | TaskExecutor Tokio/Rayon paths; global parallel iterators; migration thread | Control native workers too. A current-thread outer runtime does not suffice. |
| Blocking waits | `fork_choice_signal.rs`, shuffling promises, oneshot-broadcast condition variables, slasher receive loop | Preserve wait semantics; do not inline these into a FIFO executor that deadlocks producers. |
| Logical and wall time | SystemTimeSlotClock, sync lookup/custody ages, peer scoring, LRU TTLs | Route semantic clocks through the controlled environment, not only metrics or outer sleeps. |
| Entropy | ClientBuilder OsRng; BLS batch verification; peer selection; Noise/gossip | Seed every decision-affecting source and keep deterministic test entropy out of ordinary production builds. |
| Collections/globals | RandomState peer ranking; hash iteration; discv5 global ban state; libp2p IDs | Control ordering and per-node/per-run isolation. |
| Transitive timers | Pinned libp2p futures-timer threads and web_time clocks | Control dependency timers, not just direct Tokio timers. |
| Transport | `lighthouse_network/src/service/utils.rs` constructs Tokio TCP/QUIC/DNS | A transport replacement must preserve production upgrades/protocols and explicitly implement faults. |
| Storage | Production disk backend and migration/compaction; MemoryStore atomic/durability limitations | State the crash model; an in-memory live run does not prove crash consistency. |
| HTTP/external services | Concrete reqwest Engine API client, validator API traffic, JWT/config files | Keep all peers/services inside the controlled boundary; prohibit live external dependencies. |

## Execution strategy and qualification evidence

### Selected: in-process simulation

After the native-runner qualification below, the user selected in-process simulation rather than host hardware changes. The implementation uses [MadSim](https://github.com/madsim-rs/madsim) pinned at `519950efb4711464f300ed7edf2967ed62d5f502`. Turmoil offers virtual TCP/UDP, but MadSim also intercepts standard-library clocks and entropy. Neither tool alone makes Lighthouse deterministic: transitive timers, native workers, HTTP transports and process globals need integration.

An independent-process probe now reproduces identical standard-library clock values, hash iteration, rand 0.8/0.9 output, getrandom 0.3/0.4 output and virtual TCP round trips for seed 42; seed 7 changes the trace. The initially unpatched rand 0.8 path escaped through getrandom 0.2's raw Linux syscall. The pinned 0.2.17 adaptation selects its existing libc backend only under `cfg(madsim)`, allowing MadSim interception without changing ordinary builds.
 
`ClientBuilder::simulation_store` assembles the real node services over `SimulationStore`. `SystemTimeSlotClock` remains the production implementation; its standard-library clock is controlled by the simulator. Rayon and BLS execute real computation without native worker pools. Fork-choice notifications are awaitable; migration and CPU jobs run through controlled tasks. Each beacon node has an independent shutdown channel so a storage failure stops the affected process rather than silently terminating or being ignored by the entire harness.

The configuration is Linux x86-64, minimal spec, 64 real signing validators, Fulu plus a scheduled Gloas transition, IPv4/TCP Noise/Yamux peers, IPv4 UDP discovery, and plaintext Engine/Beacon HTTP. QUIC, IPv6 discovery, UPnP, host metrics/monitoring, slasher, native TLS, kernel TCP tuning and the optional validator-management HTTP API remain outside this configuration. Discovery-disabled scenarios use the production `POST /lighthouse/add_peer` API for the initial pair: bootstrap addresses alone are one-shot dials, not a reconnection policy. Those scenarios do not qualify untrusted scoring; `discovery` does not use that trust bypass. CPU jobs execute atomically; instruction-level races and parallel Rayon execution are not modeled.

The persistent KV model separates accepted bytes from durable bytes for hot, cold and blob stores. Atomic batches either apply completely or return the injected failure without mutation. A process crash retains accepted bytes; modeled power loss restores each database's last sync image. Generation fencing precedes task cancellation and destructor execution, preventing old handles from writing a graceful-shutdown checkpoint after a crash. `HotColdDB::open_simulated` reloads metadata into new caches, and normal startup uses the persisted chain/fork choice. Boundary tests cover atomic failure, independent durability including deletion, write/sync failure, stale handles/iterators, and retry. This does **not** qualify LevelDB/Redb/WAL/filesystem crash consistency, torn physical sectors, or validator-client/SQLite restart durability.

The dedicated simulation process installs a seccomp guard that traps unexpected native network, reactor, clock, timer, entropy, thread-creation and blocking-futex syscalls. Subprocess regression probes for native TCP, contended `parking_lot` locks, worker threads, raw entropy and raw clocks all terminate with `SIGSYS`; the actual whole-node workload completes under the same guard. Host build tools remain native: `.cargo/config-simulation.toml` uses an explicit target so simulation cfg flags do not change build-script HTTP clients. Standard-library clock interception and each entropy generation are separately qualified; seccomp is not a claim to virtualize arbitrary C-library or vDSO behavior.

The ordinary build uses the facade's native Tokio re-export. Simulation-only transport/runtime adaptations are selected by `cfg(madsim)`, not ordinary Cargo feature unification. Pinned source adaptations live under `testing/simulation/deps`: the Tokio consumers in delay_map, HTTP and timer crates must agree on the facade's I/O/time types; getrandom 0.2 must reach the intercepted libc entrypoint; MadSim needs the separately published TCP/timer fixes. MadSim's native RPC helper retains a private, unmodified native tokio-util dependency to avoid a facade dependency cycle. Upstream licenses and pinned manifests remain with the vendored source.

### Rejected on this host: whole-process execution

A Linux deterministic runtime may control native threads, syscalls, clocks and randomness without rewriting consensus/network algorithms. Hermit's ptrace backend is a candidate, subject to an actual compatibility experiment. Its strict-mode documentation does not make arbitrary external networks or changing filesystem inputs deterministic. Namespace isolation, socket readiness, child threads/processes, entropy and time must be tested before using this route for claims about Lighthouse.

The local environment rejected a user/PID/mount namespace probe with `Operation not permitted`. Hermit's documented no-namespace mode changes the isolation contract and must not silently replace the required isolated runner. Native development libraries can be extracted locally without changing host packages. Build success or `--version` is not sufficient qualification.

The user initially selected a capability-enabled Docker runner. With `SYS_PTRACE`, `SYS_ADMIN`, `PERFMON`, and unconfined seccomp/AppArmor, the ptrace qualification reached a different fail-closed check: this host's AMD Ryzen 7950X3D has SpecLockMap enabled, and Reverie's retired-conditional-branch counter validation failed. No host MSR or hardware setting was changed; dropping `--strict` was not accepted as a fix.

Hermit `3c8a5157e630139ed2407a9653c10bcf836ebb84`, using Reverie `7142ff8c0a78b275c94e796bf10053fabde35748`, was also built with its DBT backend. A real Rust probe exercised wall/monotonic clocks, OS entropy, randomized hash iteration, a native thread/barrier, a timer, TCP and UDP round trips inside a network-isolated Docker container. Both executions exited successfully with identical stdout and identical software branch totals (162096), but **strict verification failed**: raw thread IDs differed in `sched_getaffinity` syscall records (`43` versus `49`). The structured verdict was `verified=false`, `bitwise_parity=false`, `verdict=diverged`. Matching application output must not conceal this failed qualification.

Source inspection also found that the stock DBT adapter disables native maximum-timeslice preemption. Its optional native branch-budget mechanism is not wired into the CLI, and loaded-library preemption has explicit safety limitations. KVM is not a software-clock alternative: its actual execution also requires a hardware branch counter. Neither backend is currently qualified for this whole-node plan.

The [rr AMD Zen guide](https://github.com/rr-debugger/rr/wiki/Zen) documents the SpecLockMap workaround, including this CPU model, and warns that kernel SSB mitigation transitions may reset it. Host MSR changes, kernel modules, boot configuration changes and disabling security mitigations are outside the granted container-capability authorization. A counter-qualified host or separately authorized hardware workaround is required for the ptrace route.

The existing real-node `basic-sim` workload was also exercised without a deterministic runner: two nodes, 64 validators, minimal spec, one-second slots, development build. It failed because the Beacon API had no block for slot 112 when the sync-aggregate check queried it. The optimized baseline then passed with three-second slots and node logs: `cargo run --release -p simulator --features spec-minimal -- basic-sim --nodes 2 --proposer-nodes 0 --validators-per-node 32 --speed-up-factor 2 --log-dir /tmp/lighthouse-whole-node-baseline`. It reached `Simulation exited successfully`, including the existing finalization, block production, sync-aggregate, blob, light-client and late-node sync checks. These runs do not establish a protocol defect or deterministic replay; no bug PR is justified by the aggressive-deadline failure alone.

## Acceptance gates

1. **Backend qualification:** repeated execution of clock, entropy, controlled-worker, timer and selected-transport probes; precise runner/version/config and environmental assumptions recorded. The selected workload supports TCP and IPv4 UDP discovery, not QUIC. No unsupported path silently falls back to native uncontrolled execution.
2. **Whole-node baseline:** at least two actual beacon nodes and production validator duties, deterministic genesis/config/keys, controlled post-Merge execution service, real block gossip/import and RPC sync. Verify exact heads and checkpoints, accepted block ancestry and explicit shutdown.
3. **Fault and recovery workload:** seeded finite partitions or connection failures, delayed traffic/completions, a late joining node, execution-layer unavailability/recovery and bounded progress after healing. The fault must occur at the tested boundary, not be simulated by directly replacing final state.
4. **Replay:** compare ordered semantic inputs and observations across independent processes, including heads, payload status, checkpoints and failure/recovery outcomes. Keep executable revision, dependency lock, runner version/config and expanded schedule. Different seeds must alter actual fault/scheduling decisions, not just labels.
5. **Bug sensitivity:** every confirmed failure gets a minimized regression before its fix. Synthetic mutation failures validate tests but are not reported as discovered Lighthouse bugs.
6. **Publication:** fork-only PRs. The first commit reproduces the bug and fails for the intended assertion; the immediately following commit fixes it. Test infrastructure changes stay separate when practical. Include observed red/green commands and limits in each PR.

## Publication established so far

- [PR #23](https://github.com/kevaundray/lighthouse/pull/23): RPC virtual-clock mismatch. Reproducer `ee1574c20`, next-commit fix `aeea1b9aa`.
- [PR #24](https://github.com/kevaundray/lighthouse/pull/24): verified RPC and consensus component simulations, built on #23. No whole-node claim.
- [PR #25](https://github.com/kevaundray/lighthouse/pull/25): MadSim TCP listener ownership and half-close defects. Reproducer `e93e4ad02`, next-commit fix `7eb87c1a0`; executable listener-drop/rebind and request-half-close cases.
- [PR #26](https://github.com/kevaundray/lighthouse/pull/26): MadSim overflow on the unbounded sleep used by the real event-source HTTP client. Reproducer `3d0c91682`, next-commit fix `0098d1143`; executable pending/reset and finite-timeout cases. Stacked on #25. These are simulator compatibility defects, not production Lighthouse protocol bugs.
- [PR #27](https://github.com/kevaundray/lighthouse/pull/27): Lighthouse's execution test model discarded usable ancestry until each parent became canonical. Reproducer `de91c84c6`, next-commit fix `1b3fd21c0`. The regression sends a valid payload chain without intermediate forkchoice updates and requires subsequent payload production; all 42 execution-layer library tests passed after the fix. This is a test-model bug, not a production consensus bug.

The user's fork `unstable` was fast-forwarded to the existing checkout base `03ce8c89c` with explicit approval; no upstream branch was modified.
