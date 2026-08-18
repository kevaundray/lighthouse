# PQ Devnet Findings and Decisions

This is the living engineering record for replacing Lighthouse validator BLS signatures with an
experimental leanMultisig/XMSS signature scheme on a devnet. Update it whenever implementation,
testing, or devnet operation changes an assumption below.

## Scope

- Target: a private, genesis-started Lighthouse devnet.
- Mainnet interoperability is not required for the PQ build.
- KZG remains unchanged. Its use of BLS12-381 is not a validator-signature dependency.
- The first devnet may intentionally omit post-genesis deposits, Web3Signer, external builders,
  distributed-validator signing, voluntary exits, offline exit signing, Gloas, and
  BLS-to-execution-change operations. These exclusions must be explicit in configuration and must
  not silently fall back to BLS validator signatures.
- A working result requires at least two nodes to start from the same genesis, connect, propose
  blocks, exchange attestations, verify PQ signing evidence, and advance/finalize the chain.

## Repository Baseline

- Lighthouse worktree: `/home/kev/work/lighthouse`
- Lighthouse branch at investigation start: `kw/leanvm`
- Lighthouse commit at investigation start: `e423a66763bb1bd780492d635123f208d80c3538`
  (`Release v8.2.2`)
- The worktree was clean before implementation.
- `make install-hooks` was run on 2026-08-18.

## Upstream Versions Inspected

- `ethereum/lean-multisig-bindings` main:
  `c0ef8e621556581b2beb0c4f72f99c001a026fe6` (2026-08-16).
- The Rust binding is an intentionally thin re-export of `lean_multisig_api`.
- The binding pins `kevaundray/leanVM` at
  `aed646200cf5ae3199c25c61f2bfe094582678ae`.
- The pinned facade exposes `Claim`, `SecretKey`, `Signature`, `aggregate`, `verify`, and `setup`.
- Aggregate wire encodings omit the claim and signer set. The outer protocol must supply both
  when decoding and verifying an aggregate.
- The API caps one aggregate at 32,768 distinct XMSS signers and one multi-claim proof at 16
  claims in the inspected revision.
- A clean external consumer successfully compiled the exact pins with Rust 1.88, Lighthouse's
  current MSRV. The dependency has no Lean, Lake, Python, C compiler, or `build.rs` requirement;
  the zkDSL program is embedded and compiled by Rust code at runtime.
- The bindings package is named `lean-multisig` version 0.1.0, is unpublished, and has no Cargo
  features in the inspected revision.

## Cryptographic and Wire Findings

- The inspected pinned XMSS parameter set uses 32-byte public keys and 1,208-byte raw
  signatures.
- Lighthouse BLS types assume 48-byte public keys and 96-byte signatures.
- The pinned scheme uses a `u32` slot directly as the XMSS leaf/tweak identifier.
- Signing two different messages with one XMSS leaf is forbidden. Re-signing the identical
  `(leaf, message)` pair is deterministic and safe.
- A Lighthouse validator signs several different duties in one Ethereum slot. Therefore the
  Ethereum slot cannot be used directly as the XMSS leaf identifier.
- Initial leaf-allocation direction: reserve a stable number of leaves per Ethereum slot and map
  `(slot, duty_tag)` to one `u32` leaf. The exact duty table and devnet lifetime bound must be
  specified and tested before validator signing is enabled.
- Durable leaf-use state is part of cryptographic safety, not merely ordinary slashing
  protection. The signer must durably record `(leaf_id, signing_root)` before publication. A
  repeated identical root may be returned; a different root for an occupied leaf must fail hard.
- Individual-signature fields and same-message evidence are different consensus concepts.
  `SingleAttestation` must use a cheap promotable same-message evidence container: BLS stores its
  existing aggregate point, while PQ may store either a tagged raw signature or recursive proof.
  Converting a single attestation to indexed form must never invoke the prover.
- PQ aggregate proof bytes must be length-bounded before allocation or parsing. The initial
  candidate limit is 512 KiB, subject to measurements with the exact pinned backend.

## Performance Evidence

The public `leanEthereum/leanBench` data is indicative rather than proof for the exact binding
revision. On recorded Google C4 machines using leanVM main and inverse-rate exponent 2:

- 125 raw signatures: approximately 0.32 to 1.20 seconds median proving time and a 179 KiB
  proof.
- 1,000 raw signatures: approximately 2.15 to 10.3 seconds median proving time and a 219 KiB
  proof.
- 1,000-signature proving peaked at approximately 5.4 to 6.0 GiB RSS.

Consequences:

- Proof generation must never run on a Tokio worker.
- Proving concurrency needs an explicit limit; start at one job per process.
- Aggregation may require a dedicated process after the in-process devnet path works.
- The devnet must record proving latency, verification latency, proof size, queue depth, and peak
  resident memory.

An exact-pin local dependency probe on 2026-08-18 added stronger operational evidence:

- Calling `setup()` on an ordinary Rust test thread reproducibly aborted with stack overflow.
- A dedicated 64 MiB-stack thread completed setup, a one-signer proof, contextual decode, and
  verification. Upstream config requests a conservative 512 MiB minimum stack.
- The debug probe took about 31.5 seconds and reached roughly 776 MiB process RSS for that one
  aggregate.
- Dependency-local `.cargo/config.toml` settings are not inherited by Lighthouse. The binding
  requests AVX2 on x86 because its scalar fallback is documented as silently breaking
  aggregation. The first devnet launcher must validate host AVX2 before starting the globally
  AVX2-compiled experimental binary. In-binary runtime detection is too late because compiler-
  generated AVX2 may execute before the check. A later prover sidecar can keep the main binary
  portable, or a fork can supply a correct runtime-dispatched path.

Initial implementation consequence: use one long-lived dedicated PQ worker with an explicitly
large stack, initialize it before networking, and serialize setup/proving jobs. Do not set a large
global `RUST_MIN_STACK`, which would reserve that stack policy for unrelated Lighthouse threads.

## Security/Maturity Findings

- The pinned leanVM security policy says it is not production software.
- The inspected parameter-set documentation estimates about 124 bits of classical security and
  about 62 bits of quantum security in the QROM, with a complete proof still listed as TODO.
- This implementation must be labelled experimental. Encodings must include a parameter-set or
  protocol version so test data cannot be mistaken for a future production scheme.
- The bindings and safe Rust facade are very recent and unpublished as a standalone crates.io
  dependency. All git dependencies must be pinned by commit.
- The bindings manifest declares `MIT OR Apache-2.0` but the inspected repository has no license
  files. leanVM has an Apache-2.0 root license, while internal package manifests omit license
  metadata. A Lighthouse fork should add the missing license files/metadata and document both git
  sources for supply-chain review.

## Binding Adaptation Findings

A narrow fork is justified for the first devnet; the recursive circuit itself does not need to
change initially. The fork should:

1. expose distinct raw-signature and aggregate-proof decoding instead of one opaque `Signature`;
2. rename the claim's `slot` field to a one-time-use or leaf identifier to prevent accidental
   Ethereum-slot reuse;
3. expose an explicit large-stack startup/worker contract and improve setup failure reporting;
4. expose representation-specific limits and bounded decode entry points;
5. add the missing license files and package metadata.

The Lighthouse adapter must still apply its own protocol limits before calling the backend and
must classify decode/invalid-proof errors separately from local setup/prover failures.

## Lighthouse Coupling Found During Investigation

- 198 Rust files directly import or refer to the `bls` crate.
- 31 public consensus fields are named `signature` or `pubkey`.
- 42 Rust files outside `crypto/bls` depend on aggregate-signature or batch-verification
  semantics.
- `crypto/bls` is an abstraction across BLS implementations, not across signature families. It
  fixes byte lengths, point-at-infinity semantics, context-free decoding, point addition, and
  fast aggregate verification.
- The useful abstraction boundary is at consensus operations:
  verification requests, aggregation jobs, and validator signing authority.
- Consensus wire types remain explicit and selected for a specific build/network. They should
  not be erased behind unbounded byte vectors or a runtime BLS/PQ union for the first devnet.

## Architecture Decisions

1. Use branch-by-abstraction: introduce a BLS-backed boundary and prove no wire or behavioural
   change before adding PQ.
2. Prefer compile-time `bls-consensus` versus `pq-devnet` selection. A runtime dual-format node is
   not required initially.
3. Keep verification, aggregation, and signing authority as separate deep modules. They have
   different dependencies, scheduling, and failure modes.
4. Do not extend `crypto/bls` traits into a universal signature abstraction.
5. Keep SSZ wire bytes separate from parsed/verified cryptographic objects. Contextual PQ parsing
   occurs only after the signer set and signing claim have been reconstructed.
6. Start PQ validators at genesis instead of attempting an in-place BLS-to-PQ validator registry
   migration.
7. Preserve BLS as a regression backend during development. Existing consensus vectors are the
   oracle for the branch-by-abstraction refactor.
8. Start the first PQ profile at Electra and keep Gloas disabled. Enabled sync-committee duties
   use PQ evidence; they are not silently skipped or signed with BLS.
9. Use the versioned `LeanPqDevnetV1` one-time-use layout below. Any added duty creates a new
   profile and regenerated validator keys rather than silently changing offsets.

## LeanPqDevnetV1 Signing-Duty Layout

The initial Electra profile reserves 14 dense XMSS leaves per Ethereum slot:

| Offset | Duty |
| ---: | --- |
| 0 | RANDAO reveal for the containing proposal slot |
| 1 | Beacon block proposal |
| 2 | Attestation |
| 3 | Attestation selection proof |
| 4 | Aggregate and proof |
| 5 | Sync committee message |
| 6–9 | Sync selection proof for subcommittee 0–3 |
| 10–13 | Sync contribution and proof for subcommittee 0–3 |

The checked mapping is `ethereum_slot * 14 + duty_offset`. Subcommittee indices at least four are
rejected before conversion. The arithmetic maximum is slot 306,783,377; practical validator key
ranges are much smaller and fixed by the devnet configuration before genesis. The initial smoke
network should provision at least the planned runtime plus the 16-slot sync-duty lookahead. For a
64-slot run this is 80 slot rows, or 1,120 leaves per validator.

The semantic slot comes from the object being signed, never wall-clock time: proposal slot for
RANDAO and blocks, attestation data slot, selection slot, aggregate data slot, sync message slot,
and contribution slot plus subcommittee. RANDAO therefore needs its containing proposal slot added
to the local signing request even though its BLS signing root contains only the epoch.

The journal provides fail-closed at-most-one-publication semantics per duty instance. An identical
root may be retried; a different root for the same duty and slot is refused. Supporting multiple
aggregate attempts would require an explicit protocol attempt identifier and is outside V1.

No one-time-use leaf is allocated for an empty sync aggregate or a Gloas self-build placeholder.
Those require explicit absent/empty evidence rules rather than fake infinity signatures in PQ.

## Open Questions

- Exact XMSS parameter set for the first devnet: inspected 32-byte/1,208-byte configuration or a
  newer higher-security configuration.
- Whether validator proposal and attestation duties use one tree with disjoint leaves or distinct
  keys/trees.
- Whether the first block format carries one proof per aggregate or bounded multi-claim proof
  groups.
- Required validator count and target hardware for the acceptance devnet.
- Whether an external proving service is needed after initial end-to-end measurements.
- Whether to require AVX2 for the entire first-devnet binary or patch leanVM for correct runtime
  dispatch before the initial network launch.

## Findings Log

### 2026-08-18: Initial architecture investigation

- Confirmed that replacing BLS is not a backend-only change because leanMultisig aggregation
  requires claims and signer context and produces large variable-sized proofs.
- Confirmed that a devnet from genesis makes the project feasible without mainnet wire
  compatibility or validator-state migration.
- Chose semantic branch-by-abstraction over generalizing Lighthouse's BLS point traits.

### 2026-08-18: Exact dependency build and runtime probe

- Confirmed the exact git pins compile on Rust 1.88 without a Lean toolchain.
- Reproduced stack overflow when backend setup runs on an ordinary Rust test thread.
- Completed setup and a one-signer aggregate on a dedicated large-stack thread, confirming that
  worker ownership is a correctness requirement rather than an optional optimization.
- Confirmed that an XMSS public key commits to its complete inclusive activation range. Genesis
  key generation therefore requires a frozen duty-ID layout and advertised devnet lifetime; the
  range cannot be extended without changing validator public keys.
- Identified strict evidence-kind decoding, setup ergonomics, limits, and license metadata as the
  minimal binding-fork delta.

### 2026-08-18: Validator signing-duty inventory

- Confirmed that production validator-client signing converges on
  `validator_client/signing_method`, while account-manager offline exits bypass it.
- Identified every same-slot collision, including proposal plus RANDAO, attester/aggregator duties,
  and per-subcommittee sync selection/contribution duties.
- Chose the dense 14-leaf `LeanPqDevnetV1` Electra layout and explicit initial exclusions above.
- Confirmed validator registrations have no consensus slot and remote/distributed signers cannot
  own the required local XMSS journal; PQ startup must reject those configurations.

### 2026-08-18: Lighthouse exact-pin dependency integration

- Added `ethereum/lean-multisig-bindings` commit
  `c0ef8e621556581b2beb0c4f72f99c001a026fe6` as the optional `pq-devnet` dependency of
  `consensus_signature`. `Cargo.lock` confirms its transitive leanVM/API source is exactly
  `aed646200cf5ae3199c25c61f2bfe094582678ae`.
- The RED command
  `cargo nextest run -p consensus_signature --features pq-devnet pq_dependency_smoke` failed in
  0.39 seconds because the feature and dependency did not yet exist.
- Integrating the exact graph required two patch-only lockfile updates compatible with existing
  Lighthouse constraints: `objc2` 0.6.3 to 0.6.4 and `tracing-subscriber` 0.3.22 to 0.3.23.
- The GREEN command used the upstream-required x86 setting:
  `RUSTFLAGS='-C target-feature=+avx2' cargo nextest run -p consensus_signature --features
  pq-devnet pq_dependency_smoke`. The one test passed in 33.206 seconds; the timed command took
  45.93 seconds including incremental compilation and peaked at 802,648 KiB RSS.
- A post-format repeat passed in 32.929 seconds; the command took 34.18 seconds and peaked at
  771,424 KiB RSS. The default BLS compatibility test, default package check, PQ-only package
  check, package `--all-features` check, and full default workspace `cargo check` also passed.
- The owned-worker two-signer smoke passed in 36.838 seconds; the timed command took 37.98
  seconds and peaked at 787,380 KiB RSS. It verifies the exact two-key set and rejects missing,
  extra, substituted, and wrong-claim signer contexts during contextual decode/verification.
- `cargo check --workspace --all-features` is not a valid Lighthouse baseline: independently of
  this adapter, it enables both existing `bls` features `supranational-portable` and
  `supranational-force-adx`, and BLST rejects the mutually exclusive `portable` and `force-adx`
  combination in its build script. All-feature evidence for this task is therefore scoped to
  `cargo check -p consensus_signature --all-features`.
- The smoke runs deterministic key generation, raw encoding/contextual decoding/verification,
  setup, two-signer proving, aggregate contextual decoding/verification, and signer-context
  rejection through one process-singleton `PqProver`. That object alone invokes upstream setup
  and aggregation on its named 512 MiB-stack worker and serial command queue; the test no longer
  supplies its own thread or mutex.
- The adapter does not re-export upstream `setup` or `aggregate`. A normal scalar `pq-devnet`
  build compiles, but `PqProver::new` returns compile-time-mode unavailable without invoking the
  backend. The working experimental binary is wholly AVX2-only and relies on launcher preflight.
- Aggregate errors classify invalid raw/child evidence, message mismatch, malformed signer
  context, empty/over-limit requests, stopped or panicked workers, and local/internal backend
  failures separately. Because the upstream error is non-exhaustive, unknown future variants
  default to internal and must never trigger peer penalties.
- The singleton lifecycle is explicit: idle, active, or permanently poisoned. A caught setup or
  aggregation panic poisons the process-global upstream state; dropping that worker cannot change
  poisoned back to idle, and later construction reports poison separately from an active worker.
- No fork was needed to compile and exercise this smoke boundary. A binding fork remains required
  before treating the dependency as distributable devnet infrastructure: the bindings manifest
  declares `MIT OR Apache-2.0` but the pinned repository contains no corresponding license files.
  The same fork should implement the representation-specific decoding, bounded inputs, leaf-ID
  naming, and worker/setup contract listed above; license provenance must be resolved and tracked
  before binaries are distributed outside the experiment.
