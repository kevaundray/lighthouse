# PQ Consensus Signature Devnet Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Produce and verify a multi-node Lighthouse devnet whose validator proposals and votes use
leanMultisig/XMSS signing evidence instead of BLS signatures.

**Architecture:** Introduce scheme-neutral consensus-operation boundaries while keeping wire types
explicit and compile-time selected. Preserve BLS behaviour first, then add an experimental PQ build
with stateful signing protection, raw XMSS gossip signatures, recursive aggregate proofs, bounded
wire encodings, and devnet-specific genesis/configuration.

**Tech Stack:** Rust 2024, Lighthouse workspace crates, SSZ/tree-hash, Tokio plus scoped Rayon,
lean-multisig Rust bindings, leanVM/XMSS, cargo-nextest, Lighthouse local-testnet tooling.

**Required workflows:** Use `@superpowers:test-driven-development` for every behaviour change,
`@superpowers:systematic-debugging` for failures, `@superpowers:verification-before-completion`
before completion claims, and `@superpowers:requesting-code-review` at milestone boundaries.

## Definition of Done

The project is complete only when all of the following are evidenced in the worktree:

1. The architecture plan and `docs/pq-devnet-findings.md` reflect the implemented design.
2. A default BLS Lighthouse build still compiles and passes the affected existing tests.
3. A separately selected PQ devnet build contains no validator-signature fallback to BLS.
4. PQ validator keys can be generated, stored, loaded, and used without unsafe XMSS leaf reuse.
5. PQ proposer signatures and individual attestations are produced and verified.
6. Attestation aggregation produces and verifies leanMultisig aggregate proofs.
7. Any enabled sync-committee path uses PQ evidence; otherwise the feature is explicitly disabled
   by the PQ devnet preset rather than silently using BLS.
8. SSZ, tree-hash, gossip, RPC, storage, and allocation limits are explicit and tested for PQ
   objects.
9. At least two beacon nodes and the required validator clients run from the same PQ genesis,
   connect, propose blocks, exchange attestations, advance epochs, and finalize.
10. The exact launch command, version pins, validator count, observed proving/verification latency,
    proof sizes, and peak RSS are recorded.
11. `cargo check` succeeds after all code changes, as required by `CLAUDE.md`.

## Milestone 0: Preserve the Investigation

### Task 0.1: Record the design and implementation evidence

**Files:**

- Create: `docs/plans/2026-08-18-pq-devnet-implementation.md`
- Create: `docs/plans/2026-08-18-pq-consensus-signatures-design.md`
- Create: `docs/pq-devnet-findings.md`

**Step 1: Write the documents**

Record scope, alternatives, the chosen branch-by-abstraction architecture, version pins,
performance/security findings, milestones, acceptance evidence, and open questions.

**Step 2: Validate internal links and referenced paths**

Run:

```bash
rg -n "TODO|TBD|OPEN QUESTION" docs/plans/2026-08-18-pq-* docs/pq-devnet-findings.md
git diff --check
```

Expected: only intentional open questions are present; `git diff --check` exits successfully.

**Step 3: Commit**

```bash
git add docs/plans/2026-08-18-pq-devnet-implementation.md \
  docs/plans/2026-08-18-pq-consensus-signatures-design.md \
  docs/pq-devnet-findings.md
git commit -m "docs: plan PQ consensus signature devnet"
```

## Milestone 1: Introduce a BLS-Compatible Boundary

### Task 1.1: Add the consensus-signature facade with BLS wire aliases

**Files:**

- Create: `crypto/consensus_signature/Cargo.toml`
- Create: `crypto/consensus_signature/src/lib.rs`
- Create: `crypto/consensus_signature/src/bls.rs`
- Create: `crypto/consensus_signature/tests/bls_compatibility.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`

**Step 1: Write a failing public-boundary test**

The test must express these behaviours through `consensus_signature`, not `bls`:

```rust
#[test]
fn bls_backend_verifies_raw_and_aggregate_evidence() {
    // Generate two deterministic BLS keypairs.
    // Verify one Raw request.
    // Aggregate both signatures and verify one Aggregate request.
    // Change the message and assert verification fails.
}
```

**Step 2: Run the test and verify RED**

Run:

```bash
cargo nextest run -p consensus_signature --test bls_compatibility
```

Expected: compilation fails because the new facade API is not implemented.

**Step 3: Implement only the BLS facade**

The facade owns semantic names for:

- validator public-key bytes;
- raw signature evidence;
- aggregate signature evidence;
- signing claim;
- raw and aggregate verification requests;
- single and batch verification entry points.

It delegates cryptographic operations to `crypto/bls`. Do not add PQ code, runtime enums, or new
wire encodings in this task.

**Step 4: Verify GREEN**

Run:

```bash
cargo nextest run -p consensus_signature --test bls_compatibility
cargo check -p consensus_signature
```

Expected: all tests pass and the crate checks successfully.

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crypto/consensus_signature
git commit -m "feat: add consensus signature facade"
```

### Task 1.2: Route state-transition batch verification through the facade

**Files:**

- Modify: `consensus/state_processing/Cargo.toml`
- Modify: `consensus/state_processing/src/per_block_processing/block_signature_verifier.rs`
- Modify: `consensus/state_processing/src/per_block_processing/signature_sets.rs`
- Modify: `consensus/state_processing/src/lib.rs`
- Test: `consensus/state_processing/src/per_block_processing/tests.rs`

**Step 1: Write a failing boundary regression test**

Add a test that builds a valid block-signature verification workload through the state-processing
API, verifies it, then corrupts one signature and observes rejection. The test must not call
`bls::verify_signature_sets` directly.

**Step 2: Run the targeted test and verify RED**

```bash
cargo nextest run --release -p state_processing <new_test_name>
```

Expected: the test fails because state processing still bypasses the facade.

**Step 3: Replace the verification call boundary**

Keep all BLS signing-root construction and wire types unchanged. Move backend selection and batch
algorithm invocation behind the consensus-signature facade.

**Step 4: Verify GREEN and regression coverage**

```bash
cargo nextest run --release -p state_processing <new_test_name>
cargo nextest run --release -p state_processing
cargo check -p state_processing
```

Expected: all affected tests pass with unchanged BLS results.

**Step 5: Commit**

```bash
git add consensus/state_processing crypto/consensus_signature
git commit -m "refactor: route consensus verification through signature facade"
```

### Task 1.3: Separate individual and same-message semantic types while retaining BLS bytes

**Files:**

- Modify: `crypto/consensus_signature/src/bls.rs`
- Modify: `consensus/types/src/attestation/attestation.rs`
- Modify: `consensus/types/src/sync_committee/sync_committee_message.rs`
- Modify: relevant signing constructors under `consensus/types/src/`
- Test: `consensus/types/tests/`

**Step 1: Add schema and round-trip tests first**

Assert that the BLS build's SSZ bytes and tree roots are identical before and after replacing
ambiguous type names with explicit raw/aggregate names.

**Step 2: Run and verify RED**

```bash
cargo nextest run -p types <new_schema_test_name>
```

Expected: compilation fails until the semantic types exist at the requested fields.

**Step 3: Introduce BLS-backed newtypes or aliases**

One-signer proposal, sync-message, and wrapper fields use `IndividualSignature`.
`SingleAttestation`, indexed/aggregate attestations, contributions, and sync aggregates use
`SameMessageEvidence`, whose PQ representation may contain a tagged raw signature or proof.
Promotion of individual evidence into same-message evidence must be cheap and must not prove.
Preserve exact BLS SSZ encodings.

**Step 4: Verify GREEN**

```bash
cargo nextest run -p types <new_schema_test_name>
cargo nextest run -p types
cargo check -p types
```

Expected: schema and existing type tests pass.

**Step 5: Commit**

```bash
git add crypto/consensus_signature consensus/types
git commit -m "refactor: name consensus signing evidence semantically"
```

## Milestone 2: Pin and Adapt leanMultisig

### Task 2.1: Vendor or fork-pin the Rust PQ dependency

**Files:**

- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create or modify: `crypto/consensus_signature/src/pq.rs`
- Create: `crypto/consensus_signature/tests/pq_dependency_smoke.rs`
- Create: `crypto/consensus_signature/tests/pq_error_classification.rs`
- Create: `crypto/consensus_signature/tests/pq_prover_guard.rs`
- Modify: `docs/plans/2026-08-18-pq-devnet-implementation.md`
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Add a failing dependency smoke test**

The heavy smoke imports only the stable API surface required by Lighthouse: guarded setup, two
deterministic keys, raw sign, raw verify, guarded aggregate, contextual aggregate decode, and
aggregate verify. It must prove the exact two-signer set and reject missing, extra, wrong, and
wrong-claim contexts. The test constructs one owned `PqProver`; that object must run all setup and
proving inside its own named, serial-command `std::thread` with an explicit 512 MiB stack. A second
live prover in the process must be rejected.

Separate fast tests require a scalar build to reject prover construction without invoking the
backend and classify known upstream evidence/request failures separately from local/internal
failures. Unknown variants of the non-exhaustive upstream error must default to local/internal.

**Step 2: Verify RED**

```bash
cargo nextest run -p consensus_signature --features pq-devnet --test pq_prover_guard
cargo nextest run -p consensus_signature --features pq-devnet --test pq_error_classification
RUSTFLAGS='-C target-feature=+avx2' cargo nextest run -p consensus_signature \
  --features pq-devnet pq_dependency_smoke
```

Expected: compilation fails because the pinned dependency, feature, guarded adapter errors, and
operations are absent.

**Step 3: Pin exact commits and expose a minimal adapter**

Pin both the binding and its leanVM/API dependency. Do not publicly re-export upstream `setup` or
`aggregate`. An owned process-singleton `PqProver` is the only proving entry point. Its constructor
starts one named 512 MiB-stack OS worker, initializes upstream setup there, and then services owned
aggregate jobs through one serial command queue. Report spawn, setup panic, worker stop, worker
panic, peer-invalid evidence, invalid request/limit, and internal backend errors distinctly.
Track the process-global backend lifecycle as idle, active, or poisoned. A caught setup or
aggregation panic permanently poisons the process: dropping the worker must not reopen upstream
state, and later constructors must distinguish poison from an already-active worker.

The experimental PQ binary is x86-64 AVX2-only. A global `-C target-feature=+avx2` binary cannot
safely perform its own host compatibility test after startup, so the launcher must preflight AVX2
before executing it. Ordinary scalar `pq-devnet` and package `--all-features` builds must compile,
but `PqProver::new` returns compile-time-mode unavailable without invoking upstream code. A later
prover sidecar can keep the main Lighthouse binary portable.

This task pins and probes the dependency and enforces the worker/AVX availability boundary only.
The semantic `OneTimeUseId` mapping remains Task 2.2; representation-specific raw/aggregate
evidence wrappers and bounded contextual decoding remain Task 2.3. A narrow binding fork is not
required for this internal smoke, but is required before external binary distribution to resolve
license files and harden those later evidence boundaries.

**Step 4: Verify GREEN**

```bash
cargo nextest run -p consensus_signature --features pq-devnet --test pq_prover_guard
cargo nextest run -p consensus_signature --features pq-devnet --test pq_error_classification
RUSTFLAGS='-C target-feature=+avx2' cargo nextest run -p consensus_signature \
  --features pq-devnet pq_dependency_smoke
RUSTFLAGS='-C target-feature=+avx2' cargo check -p consensus_signature \
  --no-default-features --features pq-devnet
RUSTFLAGS='-C target-feature=+avx2' cargo check -p consensus_signature --all-features
```

Expected: the fast refusal and error-classification tests, two-signer smoke, PQ-only check, and
package all-feature check pass. Run the default BLS facade tests and full default workspace
`cargo check` as regressions.

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crypto/consensus_signature \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "build: pin lean multisig backend"
```

### Task 2.2: Define signing identifiers and the duty allocation table

**Files:**

- Create: `crypto/consensus_signature/src/signing_id.rs`
- Create: `crypto/consensus_signature/tests/signing_id.rs`
- Modify: `validator_client/signing_method/src/lib.rs`
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write failing allocation tests**

Tests must cover:

- all 14 `LeanPqDevnetV1` duty instances map to offsets `0..=13` exactly;
- two different duties in one Ethereum slot receive different XMSS leaves;
- the same duty and slot reproduce the same leaf;
- adjacent slots cannot collide;
- sync subcommittees `0..=3` succeed while `4` and `u64::MAX` are rejected;
- maximum slot 306,783,377 succeeds and the next slot is rejected without panicking;
- every enabled `SignableMessage` arm extracts its semantic object slot and expected duty;
- RANDAO uses the containing proposal slot rather than epoch start;
- validator registration, voluntary exits, and Gloas `SignableMessage` arms return explicit V1
  unsupported errors;
- remote/distributed signing and account-manager offline exits are documented exclusions in this
  allocation task; their startup/invocation enforcement and tests belong to Tasks 3.3 and 6.2
  rather than a fake signing-duty API;
- empty sync aggregates and self-build placeholders allocate no leaf.

**Step 2: Verify RED**

```bash
cargo nextest run -p consensus_signature --test signing_id
```

Expected: compilation fails because `SigningId` and the allocation table do not exist.

**Step 3: Implement the minimal checked mapping**

Implement the versioned Electra V1 table from `docs/pq-devnet-findings.md` with
`LEAVES_PER_SLOT = 14` and checked `slot * 14 + duty_offset` arithmetic. Keep every assigned duty
tag explicit; do not hash duty names or cast unchecked enum discriminants into leaf IDs. Add the
containing proposal slot to RANDAO signing intent even though its signing root is epoch-bound.

**Step 4: Verify GREEN**

```bash
cargo nextest run -p consensus_signature --test signing_id
cargo check -p consensus_signature --no-default-features --features pq-devnet
```

Expected: all allocation tests pass.

**Step 5: Commit**

```bash
git add crypto/consensus_signature validator_client/signing_method docs/pq-devnet-findings.md
git commit -m "feat: allocate XMSS leaves by validator duty"
```

### Task 2.3: Implement PQ raw signing and verification

**Files:**

- Modify: `crypto/consensus_signature/src/pq.rs`
- Create: `crypto/consensus_signature/src/pq/backend.rs`
- Create: `crypto/consensus_signature/src/pq/wire.rs`
- Create: `crypto/consensus_signature/tests/pq_wire.rs`
- Modify: `crypto/consensus_signature/tests/pq_error_classification.rs`
- Remove: `crypto/consensus_signature/tests/pq_dependency_smoke.rs` after moving it into private
  unit coverage

**Step 1: Write failing raw-signature tests**

Start with fast framing tests. Freeze a Lighthouse-owned `LHPQ` envelope with independent wire
version, parameter-set, and evidence-kind bytes. Cover the exact 1,215-byte raw form; bad magic;
unknown version, parameter set, and evidence kind; short/long payloads; and strict rejection of
aggregate or absent evidence in an individual-signature field.

Then cover deterministic raw-signature retries, wrong root, wrong public key, wrong signing ID,
malformed/non-canonical payloads, signing outside the key range, and a canonical empty placeholder
that never verifies. Raw verification must not initialize the aggregate prover.

**Step 2: Verify RED**

```bash
cargo nextest run -p consensus_signature --no-default-features --features pq-devnet \
  --test pq_wire
cargo nextest run -p consensus_signature --no-default-features --features pq-devnet \
  --lib 'pq::tests'
cargo test -p consensus_signature --no-default-features --features pq-devnet --doc
```

Expected: tests fail because the PQ backend is incomplete.

**Step 3: Implement raw signing and contextual verification**

Keep wire bytes opaque until verification context is present. The Lighthouse envelope is:

```text
"LHPQ" | wire_version=1 | parameter_set=1 | evidence_kind | backend_payload
```

For the exact pinned backend, strip its private six-byte `LMSI` envelope on output and reconstruct
the required raw header only inside `pq/backend.rs` after the Lighthouse envelope has selected the
semantic kind. Enforce every length/version/kind check before invoking leanMultisig. Do not expose
raw upstream `Claim`, `Signature`, `SecretKey`, or `verify`; expose a semantic claim requiring
`OneTimeUseId` and a strict raw wrapper. The raw sign primitive and unreserved key handle are
crate-private and test-only in this task. Task 3.3 must co-locate that primitive with the
journal-owning signing authority, or otherwise provide one non-bypassable reserve-and-sign
operation; it must not re-export the unreserved primitive. Unknown non-exhaustive backend errors
remain local/internal by default.

Freeze the V1 contribution/signer cap at 32,768. Reject empty or oversized proving requests before
decoding contributions or allocating a second vector, and reject oversized expected-signer slices
before collecting backend keys. Empty expected-signer slices are rejected at the same boundary.
Public errors carry only semantic request/failure categories; the
opaque backend diagnostic terminates `Error::source`. The private exact-pin bridge classifies raw
input failures separately from owned-prover failures, including `LocallyGeneratedProof`.

This exact-pin bridge is acceptable for internal raw devnet work. Do not treat hostile aggregate
decoding as hardened or distribute binaries until a narrow fork exposes representation-specific,
bounded decoding and resolves license metadata. Task 4.1 owns SSZ/TreeHash/serde integration and
the bounded same-message evidence union.

**Step 4: Verify GREEN**

Run the same commands, then run the real worker smoke:

```bash
RUSTFLAGS='-C target-feature=+avx2' cargo nextest run -p consensus_signature \
  --no-default-features --features pq-devnet --lib pq_dependency_smoke
```

Expected: all framing/private raw tests and the two-signer worker smoke pass.

**Step 5: Commit**

```bash
git add crypto/consensus_signature
git commit -m "feat: add PQ raw signature backend"
```

## Milestone 3: PQ Validator State and Signing Safety

### Task 3.1: Add a crash-safe XMSS leaf journal

**Files:**

- Create: `validator_client/signing_method/src/xmss_journal.rs`
- Modify: `validator_client/signing_method/src/lib.rs`
- Modify: `validator_client/signing_method/Cargo.toml`

**Step 1: Write failing filesystem tests**

Use a temporary directory and crate-internal module tests so the reservation primitive remains
inaccessible outside the journal-owning authority. Test:

- reserve a fresh `(leaf, root)`;
- identical retry succeeds;
- different root at the same leaf fails;
- restart preserves reservations;
- committed reservation is reopenably durable before the signing callback runs;
- failure after insert but before commit persists no row and invokes no signer;
- failure after commit but before/during sign leaves the row burned and permits only same-root
  retry;
- truncated/corrupt/missing/wrong-version journal fails closed without recreation;
- key/profile/genesis/allocation/range mismatch fails startup and reservation;
- concurrent attempts cannot reserve conflicting roots;
- a second process cannot acquire the journal lock;
- validator key-file bytes and permissions are unchanged by journal activity.

**Step 2: Verify RED**

```bash
cargo nextest run -p signing_method --no-default-features --features pq-devnet \
  'xmss_journal::tests'
```

Expected: compilation fails because the journal does not exist.

**Step 3: Implement the minimal durable journal**

Create the separate global `validators_dir/xmss_usage.sqlite` design recorded in
`docs/pq-devnet-findings.md`. Isolate SQLite and filesystem-lock dependencies behind the
`signing_method/pq-devnet` feature. Use SQLite DELETE rollback-journal mode,
`synchronous=EXTRA`, exclusive locking, one serialized connection, fixed application/schema
versions, and a persistent 0600 OS lockfile that is never unlinked by its guard. Provisioning alone
creates and directory-syncs the database and lock; normal startup performs a non-creating,
non-symlink open and validates exact schema, integrity, permissions, and the active binding subset
while permitting extra historical keys. Derive the stable key ID solely from canonical public-key
bytes, freeze the 32-byte V1 profile ID and allocation version, never prune rows, and release the
transaction/DB mutex before the signing callback. Keep raw `reserve` private; production sibling
modules may only use the crate-private combined durable callback operation until Task 3.3 seals it
behind the signing authority. The first PQ devnet journal is Unix-only and fails startup explicitly
on unsupported platforms instead of weakening its permission contract.

**Step 4: Verify GREEN**

```bash
cargo nextest run -p signing_method --no-default-features --features pq-devnet \
  'xmss_journal::tests'
cargo test -p signing_method --no-default-features --features pq-devnet --doc
cargo check -p signing_method --no-default-features --features pq-devnet
cargo check -p signing_method
```

Expected: all journal tests pass.

**Step 5: Commit**

```bash
git add Cargo.lock validator_client/signing_method \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "feat: persist XMSS leaf reservations"
```

### Task 3.2: Add PQ validator key storage

**Files:**

- Modify or create: `crypto/eth2_keystore/` PQ key storage modules
- Modify: `common/validator_dir/`
- Create: targeted key round-trip tests in each changed package
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write failing key round-trip tests**

Cover generation, encrypted persistence, reload, public-key identity, malformed/trailing secret
bytes, wrong password, hostile KDF parameters, unsupported outer/scheme/backend versions, and
one-time-use range preservation. On reload, require the derived public key and upstream inclusive
range to match the authenticated metadata exactly. Normal unit tests use a small 8--16-leaf range;
the real 1,120-leaf measurement is explicit/ignored.

Add validator-directory tests for the distinct PQ filename and definition variant, 0600 modes,
collision refusal, and discovery.

**Step 2: Verify RED using the narrowest affected package test**

Expected: failure because no PQ keystore format exists.

**Step 3: Implement an explicitly versioned experimental format**

Do not claim EIP-2335 compatibility if the payload is not an EIP-2333-derived BLS scalar. Add a
separate `PqKeystore`/`PqValidatorDirBuilder` and `pq-voting-keystore.json`; reuse only the existing
`eth2_keystore::Crypto` encryption primitives. The authenticated outer schema independently pins
format version, scheme/parameter set, exact backend revision, 32-byte public key, and inclusive
`one_time_use_range`. Usage state remains exclusively in `xmss_usage.sqlite`.

Generate keys sequentially in tests and future callers; do not outer-parallelize upstream key
generation or scrypt. This task stops at the reusable encrypted-key and validator-directory
boundary and does not add an `lcli` command. Do not add padded or shadow BLS keys: the current
validator registry still has a 48-byte BLS wire type, so provisioning and direct PQ genesis must
follow Task 4.1's compile-time PQ public-key schema.

**Step 4: Verify GREEN and measure key size/load time**

Record measurements in `docs/pq-devnet-findings.md`.

**Step 5: Commit**

```bash
git add Cargo.lock crypto/eth2_keystore common/validator_dir \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "feat: add experimental PQ validator keys"
```

**Execution dependency:** after this storage task, execute Task 4.1 before Task 3.3. Then execute
Task 4.1b to create the direct-registry genesis and provisioned validator set. Task 3.3 can only
route real duties once those compile-time PQ wire types exist.

### Task 3.3: Route validator duties through PQ signing authority

**Prerequisites:** Tasks 3.2, 4.1, and 4.1b.

**Files:**

- Modify: `validator_client/signing_method/src/lib.rs`
- Modify: `validator_client/initialized_validators/src/lib.rs`
- Modify: `validator_client/lighthouse_validator_store/src/lib.rs`
- Modify: `validator_client/validator_store/src/lib.rs`
- Create: PQ signing integration tests

**Step 1: Write failing duty-signing tests**

Cover proposer and attester duties first, including identical retry and conflicting-root refusal.
Add PQ startup tests that reject Web3Signer and any other remote/distributed signing method before
duties begin.

**Step 2: Verify RED**

Run the targeted signing-method/validator-store tests. Expected: PQ signing is unavailable.

**Step 3: Implement PQ local signing**

Reserve the leaf durably, sign in a blocking/scoped worker, and return the explicit raw wire type.
Accept only the local journal-owning PQ signing method in PQ mode; reject Web3Signer and other
remote/distributed signing configurations with a clear startup error.
Co-locate the upstream raw-sign primitive with this authority (or expose only one combined
reserve-and-sign operation across a private boundary). Do not make the Task 2.3 test-only
unreserved key/sign operation public or re-export it from `consensus_signature`.

**Step 4: Verify GREEN**

Run targeted tests and `cargo check` for the changed packages.

**Step 5: Commit**

```bash
git add validator_client
git commit -m "feat: sign validator duties with PQ keys"
```

## Milestone 4: PQ Consensus Wire Types

### Task 4.1: Add PQ public key and raw-signature SSZ types

**Files:**

- Modify: `crypto/consensus_signature/src/pq.rs`
- Modify: `consensus/types/src/validator/validator.rs`
- Modify: individual signed containers under `consensus/types/src/`
- Create: PQ SSZ/tree-hash tests
- Modify: `beacon_node/beacon_chain/tests/schema_stability.rs`

**Step 1: Write failing PQ schema tests**

Pin byte lengths, JSON form, SSZ round trips, tree roots, malformed lengths, and parameter-set
version rejection.

**Step 2: Verify RED under PQ-only features**

Expected: current BLS-sized fields do not satisfy the PQ schema.

**Step 3: Implement compile-time-selected PQ types**

Do not introduce runtime BLS/PQ unions. Keep default BLS schema unchanged.

**Step 4: Verify both configurations**

```bash
cargo nextest run -p types
cargo nextest run -p types --no-default-features --features pq-devnet
cargo check -p types
cargo check -p types --no-default-features --features pq-devnet
```

Expected: both suites pass with their own pinned schemas.

**Step 5: Commit**

```bash
git add crypto/consensus_signature consensus/types beacon_node/beacon_chain/tests/schema_stability.rs
git commit -m "feat: add PQ consensus wire types"
```

### Task 4.1b: Provision PQ validators and build a direct-registry genesis

**Prerequisites:** Tasks 3.2 and 4.1.

**Files:**

- Modify: relevant PQ-gated `lcli` account/genesis commands
- Modify or create: PQ validator provisioning helpers under `common/validator_dir/`
- Modify: the genesis/state-initialization path under `beacon_node/` or `consensus/state_processing/`
- Create: deterministic direct-registry genesis tests
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write failing provisioning and genesis tests**

Generate a small fixed validator set from a fixed seed/configuration and require:

- registry public keys are the generated 32-byte PQ keys in deterministic order;
- every validator is active at genesis, with deterministic execution withdrawal credentials;
- no deposit signatures or BLS shadow keys are generated or checked;
- the generated validator directories use `pq-voting-keystore.json` and the usage journal is
  provisioned and bound to every key, range, allocation version, parameter profile, and genesis
  validators root;
- generating twice yields identical public configuration and genesis state bytes.

Use small key ranges in ordinary tests. Add an ignored/measured test for the initial devnet range
`0..=1119` only after the validator count and lifetime are frozen.

**Step 2: Verify RED**

Run the narrow PQ-only `lcli`, genesis, and validator-directory tests. Expected: the direct PQ
registry/provisioning path does not exist.

**Step 3: Implement the PQ-only provisioning command and genesis path**

Generate and encrypt PQ keys sequentially, create their validator directories, and construct the
genesis validator registry directly from their PQ public keys. Reuse/refactor only the
post-registry state-finalization and fork-upgrade tail from the deposit genesis path. Never create
dummy deposits, unchecked deposit signatures, padded public keys, shadow BLS keys, or consume XMSS
leaves during genesis.

Create and bind the usage journal as part of provisioning, then reopen and cross-check every
keystore, registry entry, range, and journal binding before reporting success. Reject collisions
and partial pre-existing output rather than overwriting it.

**Step 4: Verify GREEN**

Run the targeted PQ tests, regenerate twice and compare public outputs/state bytes, then run the
default BLS genesis regressions and the mandatory full workspace `cargo check`.

**Step 5: Commit**

```bash
git add Cargo.lock lcli common/validator_dir beacon_node consensus/state_processing \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "feat: provision PQ validator genesis"
```

### Task 4.2: Define bounded aggregate-proof evidence

**Files:**

- Modify: `crypto/consensus_signature/src/pq.rs`
- Modify: `consensus/types/src/attestation/attestation.rs`
- Modify: `consensus/types/src/sync_committee/sync_aggregate.rs`
- Create: aggregate-proof SSZ and adversarial decoding tests

**Step 1: Write failing bounds tests**

Cover empty proof, maximum accepted proof, one byte over the limit, invalid envelope version,
trailing bytes, and allocation-before-length-check regressions.

**Step 2: Verify RED**

Expected: no bounded PQ aggregate evidence exists.

**Step 3: Implement the bounded opaque wire type**

Parsing remains contextual and occurs during verification, not generic SSZ decoding.

**Step 4: Verify GREEN in BLS and PQ configurations**

Run targeted type tests and checks.

**Step 5: Commit**

```bash
git add crypto/consensus_signature consensus/types
git commit -m "feat: add bounded PQ aggregate proof evidence"
```

## Milestone 5: PQ Aggregation and Consensus Verification

### Task 5.1: Implement the aggregation job boundary

**Files:**

- Create: `crypto/consensus_signature/src/aggregation.rs`
- Create: `crypto/consensus_signature/tests/aggregation.rs`
- Modify: `crypto/consensus_signature/src/bls.rs`
- Modify: `crypto/consensus_signature/src/pq.rs`

**Step 1: Write failing cross-backend contract tests**

The same test cases must run against both backends: one raw contribution, multiple raw
contributions, duplicate signer handling, child aggregate reuse, wrong claim, wrong signer set,
empty input, and size limits.

**Step 2: Verify RED for both backends**

Expected: the aggregation job interface does not exist.

**Step 3: Implement one-shot aggregation**

BLS uses point aggregation internally. PQ invokes the prover. Do not expose incremental mutation
in the shared interface.

**Step 4: Verify GREEN and record measurements**

Run both backends. Record PQ time, proof bytes, and peak RSS for the chosen devnet committee sizes
in `docs/pq-devnet-findings.md`.

**Step 5: Commit**

```bash
git add crypto/consensus_signature docs/pq-devnet-findings.md
git commit -m "feat: add signature aggregation jobs"
```

### Task 5.2: Replace attestation point mutation with aggregation jobs

**Files:**

- Modify: `consensus/types/src/attestation/attestation.rs`
- Modify: `beacon_node/operation_pool/src/attestation_storage.rs`
- Modify: `beacon_node/operation_pool/src/lib.rs`
- Modify: `beacon_node/beacon_chain/src/single_attestation.rs`
- Modify: related attestation tests

**Step 1: Write a failing end-to-end aggregation test**

Build several valid single attestations, aggregate them, assert the participant union, verify the
result, and reject a proof paired with altered participant bits.

**Step 2: Verify RED under PQ mode**

Expected: current synchronous `add_assign` aggregation cannot produce PQ evidence.

**Step 3: Submit aggregation jobs through a resource-limited service**

Use a scoped blocking/Rayon execution path and an explicit one-job concurrency limit. Preserve a
fast synchronous BLS implementation behind the same caller boundary.

**Step 4: Verify GREEN under both backends**

Run operation-pool, types, and beacon-chain attestation tests.

**Step 5: Commit**

```bash
git add consensus/types beacon_node/operation_pool beacon_node/beacon_chain
git commit -m "feat: aggregate attestations through signature service"
```

### Task 5.3: Verify PQ block and gossip evidence

**Files:**

- Modify: `consensus/state_processing/src/per_block_processing/signature_sets.rs`
- Modify: `consensus/state_processing/src/per_block_processing/block_signature_verifier.rs`
- Modify: `beacon_node/beacon_chain/src/attestation_verification.rs`
- Modify: `beacon_node/beacon_chain/src/attestation_verification/batch.rs`
- Modify: `beacon_node/beacon_chain/src/sync_committee_verification.rs`
- Create: PQ block/gossip adversarial tests

**Step 1: Write failing verification tests**

Cover valid proposer/raw attestation/aggregate proof, wrong leaf, wrong root, wrong signer bits,
malformed proof, proof over size limit, and mixed valid/invalid batch behaviour.

**Step 2: Verify RED under PQ mode**

Expected: BLS `SignatureSet` construction or batch verification is still reached.

**Step 3: Reconstruct PQ context and invoke the verification engine**

Resolve signer keys from state only after validating attacker-controlled indices. Ensure expensive
verification executes outside async workers and has admission limits.

**Step 4: Verify GREEN under both backends**

Run targeted state-processing and beacon-chain tests.

**Step 5: Commit**

```bash
git add consensus/state_processing beacon_node/beacon_chain
git commit -m "feat: verify PQ consensus signing evidence"
```

## Milestone 6: Networking, APIs, and Resource Limits

### Task 6.1: Update gossip and RPC codecs for PQ bounds

**Files:**

- Modify: `beacon_node/lighthouse_network/src/types/pubsub.rs`
- Modify: `beacon_node/lighthouse_network/src/rpc/codec.rs`
- Modify: `beacon_node/lighthouse_network/src/rpc/protocol.rs`
- Modify: networking rate-limit and scoring configuration
- Create: oversized/malformed gossip and RPC tests

**Step 1: Write failing codec/admission tests**

Prove valid PQ objects round-trip and oversized objects are rejected before expensive decoding or
verification.

**Step 2: Verify RED**

Run the narrow network tests. Expected: current size assumptions reject valid PQ data or admit
unbounded input.

**Step 3: Implement PQ-specific bounded limits**

Avoid globally raising limits for ordinary BLS networks.

**Step 4: Verify GREEN**

Run lighthouse-network and network package tests in both configurations.

**Step 5: Commit**

```bash
git add beacon_node/lighthouse_network beacon_node/network
git commit -m "feat: support bounded PQ network messages"
```

### Task 6.2: Update HTTP APIs and explicitly reject unsupported integrations

**Files:**

- Modify: `beacon_node/http_api/`
- Modify: `validator_client/http_api/`
- Modify: `validator_client/signing_method/src/web3signer.rs`
- Modify: `account_manager/`
- Modify: builder configuration/startup validation
- Create: API serialization and startup-validation tests

**Step 1: Write failing tests**

Cover PQ JSON round trips plus explicit startup/configuration errors for external builder modes and
an explicit unsupported error from account-manager offline-exit signing in the first PQ devnet.

**Step 2: Verify RED**

Expected: APIs assume BLS hex lengths or unsupported modes start silently.

**Step 3: Implement explicit PQ serialization and validation**

Do not silently fall back to BLS.

**Step 4: Verify GREEN**

Run targeted HTTP API, signing-method, and CLI tests.

**Step 5: Commit**

```bash
git add beacon_node/http_api validator_client
git commit -m "feat: expose PQ devnet APIs safely"
```

## Milestone 7: Devnet Genesis and End-to-End Operation

### Task 7.1: Add a reproducible PQ devnet preset and launcher

**Files:**

- Create: `scripts/local_testnet/pq/` configuration and launch assets
- Modify: `scripts/local_testnet/README.md`
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write a failing configuration smoke test**

The test invokes the Task 4.1b provisioning command, validates that every registry key and enabled
signature field uses the PQ parameter set, and checks that launcher arguments select only the PQ
binary/profile.

**Step 2: Verify RED**

Expected: no reproducible multi-process PQ launcher/preset exists.

**Step 3: Implement the smallest useful preset**

Start with a measured validator count and one committee. Disable unsupported protocol features
explicitly. Pin all timing and proof-size limits. Reuse the already-tested Task 4.1b key/genesis
command; do not duplicate provisioning logic in shell.

**Step 4: Verify GREEN**

Generate the devnet twice and assert deterministic public configuration/genesis outputs for the
same seed.

**Step 5: Commit**

```bash
git add scripts/local_testnet docs/pq-devnet-findings.md
git commit -m "feat: add reproducible PQ devnet"
```

### Task 7.2: Run a two-node PQ devnet to finality

**Files:**

- Modify: `docs/pq-devnet-findings.md`
- Create: a checked-in smoke-test script under `scripts/local_testnet/pq/`

**Step 1: Write the automated smoke-test assertions**

The script must fail unless:

- two beacon nodes report healthy;
- peers connect;
- validator clients load PQ keys;
- blocks are proposed and imported;
- attestations and aggregate proofs are observed;
- at least two epochs advance;
- finalized checkpoint advances beyond genesis;
- logs contain no BLS validator-signature fallback;
- processes shut down cleanly.

**Step 2: Run and verify RED**

Run the smoke test. Expected: it fails until the end-to-end integration is complete.

**Step 3: Fix only observed end-to-end defects using TDD**

For every code defect, first add a focused failing regression test, then implement the fix.

**Step 4: Run and verify GREEN**

Capture commands, commit IDs, validator count, timing, proof sizes, RSS, finality evidence, and log
locations in `docs/pq-devnet-findings.md`.

**Step 5: Commit**

```bash
git add scripts/local_testnet/pq docs/pq-devnet-findings.md
git commit -m "test: verify PQ devnet reaches finality"
```

## Milestone 8: Completion Audit

### Task 8.1: Run required verification

**Files:**

- Modify as necessary: `docs/pq-devnet-findings.md`

**Step 1: Format and lint changed code**

```bash
cargo fmt --all -- --check
make lint
```

Expected: success with no new warnings.

**Step 2: Run BLS and PQ targeted suites**

Run every package suite named in prior tasks in its relevant configuration. Expected: all pass.

**Step 3: Run the repository-required compilation gate**

```bash
cargo check
```

Expected: success.

Also run the PQ workspace check command established by the feature wiring. Expected: success.

**Step 4: Re-run the PQ devnet smoke test from a clean data directory**

Expected: two-node finality succeeds without reusing prior state.

**Step 5: Audit the Definition of Done against direct evidence**

Update `docs/pq-devnet-findings.md` with an evidence table. Do not infer completion from narrow
unit tests.

**Step 6: Commit**

```bash
git add docs/pq-devnet-findings.md
git commit -m "docs: record verified PQ devnet results"
```
