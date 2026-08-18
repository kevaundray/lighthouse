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
Record hash-chain/hash-onion RANDAO as a future profile option that could eliminate this signature
duty, but do not alter the frozen V1 allocation or first-devnet consensus rules in this task.

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

For the exact pinned backend's fixed-size raw form, strip its private six-byte `LMSI` envelope on
output and reconstruct the required raw header only inside `pq/backend.rs` after the Lighthouse
envelope has selected the semantic kind. Aggregate evidence is different: Task 4.2 preserves its
complete upstream `Signature::to_bytes()` envelope inside the Lighthouse aggregate payload because
the pinned private representation has no public aggregate-payload codec. Enforce every
length/version/kind check before invoking leanMultisig. Do not expose
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

- Modify: root `Cargo.toml` for the feature-isolated `rustix` workspace dependency
- Modify or create: `crypto/eth2_keystore/` PQ key storage modules
- Modify: `common/validator_dir/`
- Create: targeted key round-trip tests in each changed package
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write failing key round-trip tests**

Cover generation, encrypted persistence, reload, public-key identity, malformed/trailing secret
bytes, wrong password, hostile KDF parameters, unsupported outer/scheme/backend versions, and
one-time-use range preservation. On reload, require the derived public key and upstream inclusive
range to match the authenticated metadata exactly. Normal unit tests use a small 8--16-leaf range;
the real 1,120-leaf `0..=1119` measurement has a separate manual ignored test and must not run in
ordinary verification.

Add validator-directory tests for the distinct PQ filename and directory-local definition, exact
0700/0600 modes, collision refusal, canonical identity, and fail-closed immediate-child discovery.
Do not add an account-utils/validator-client definition while its key type is still BLS-only.

**Step 2: Verify RED using the narrowest affected package test**

Expected: failure because no PQ keystore format exists.

**Step 3: Implement an explicitly versioned experimental format**

Do not claim EIP-2335 compatibility if the payload is not an EIP-2333-derived BLS scalar. Add a
separate `PqKeystore`/`PqValidatorDirBuilder` and `pq-voting-keystore.json`; reuse only the existing
`eth2_keystore::Crypto` encryption primitives. The outer schema pins format/version,
scheme/parameter set, both exact bindings and backend revisions, canonical 32-byte public key, and
inclusive `one_time_use_range`. Since `Crypto` authenticates ciphertext rather than arbitrary outer
JSON, duplicate every security-relevant outer field in a canonical encrypted inner envelope and
require byte-for-byte inner/outer equality after decrypt. Also require exact canonical upstream
reserialization and derived public-key/range equality. Preflight one exact bounded KDF/cipher/
checksum profile before running the KDF, and cap JSON/ciphertext input before allocation or crypto.
Reject invalid UTF-8, raw empty passwords, passwords over 4,096 bytes, and passwords that become
empty after the exact EIP-2335 NFKD normalization and Unicode control-character removal before key
generation, KDF work, or storage mutation. V1 accepts any nonempty contiguous inclusive range of at
most 1,120 IDs; validate its checked span before entropy/upstream key construction and again on
metadata load. Usage state remains exclusively in `xmss_usage.sqlite`.

Keep live upstream keys private to the storage implementation in this task: public production APIs
may validate metadata/passwords but must not return a sign-capable key. The combined journal-owned
decrypt/reserve/sign authority is introduced only in Task 3.3.

Generate keys sequentially in tests and future callers; use a cross-process test lock and do not
outer-parallelize upstream key generation or scrypt. Create PQ child directories at 0700 and files
with descriptor-relative create-new 0600/no-follow/fd checks and durability syncs. Retain opened
base/password directory descriptors across the KDF and use `mkdirat`/`openat` for every provisioning
mutation, with final descriptor/entry/path identity checks. Perform read-only collision preflight
before the KDF and retain exclusive creation enforcement afterward. Fail closed on partial,
symlinked, mixed BLS/PQ, non-canonical, and replaced identities. Never perform pathname cleanup
after a successful create: handled failures leave tombstones exactly like crashes, and retries
collide until explicit provisioning recovery removes them. Document that the directory and
external password file cannot be made one atomic transaction. This task stops at the reusable
encrypted-key and validator-directory boundary and does not add an `lcli` command. Do not add
padded or shadow BLS keys: the current
validator registry still has a 48-byte BLS wire type, so provisioning and direct PQ genesis must
follow Task 4.1's compile-time PQ public-key schema.

**Step 4: Verify GREEN and measure key size/load time**

Record measurements in `docs/pq-devnet-findings.md`.

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crypto/eth2_keystore common/validator_dir \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "feat: add experimental PQ validator keys"
```

**Execution dependency:** after this storage task, execute Task 4.1, then Task 3.3a. Task 3.3a
deepens the provisional storage/journal modules into one non-bypassable authority before Task 4.1b
uses its provisioning facade. Route real duties only in Task 3.3b after the direct PQ genesis and
validator set exist.

### Task 3.3a: Consolidate PQ storage and the journal into one signing authority

**Prerequisites:** Tasks 3.1, 3.2, and 4.1.

**Implementation status (2026-08-18):** implemented and under final workspace verification. The
concrete private layout is `crypto/pq_signing/src/authority/{mod,keystore,journal}.rs`, with
external keystore/authority coverage in `crypto/pq_signing/tests/`. The old
`eth2_keystore::pq_keystore` and `signing_method::xmss_journal` modules are removed. The public
facade has no live-key, raw-reservation, callback, or unreserved-signing escape hatch.

**Files:**

- Create: `crypto/pq_signing/Cargo.toml`
- Create: `crypto/pq_signing/src/authority/{mod,keystore,journal}.rs`
- Move/adapt: PQ keystore code/tests from `crypto/eth2_keystore/`
- Move/adapt: XMSS journal code/tests from `validator_client/signing_method/`
- Modify: `crypto/eth2_keystore/` to expose only reusable encryption/password-normalization
  primitives, with no leanMultisig dependency
- Modify: `common/validator_dir/` to use `pq_signing::PqKeystore`
- Modify: `validator_client/signing_method/` to depend on the new facade but not own SQLite/XMSS
  internals
- Create: `crypto/pq_signing/tests/{authority,keystore}.rs` plus private authority/journal unit and
  subprocess crash tests
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write failing authority/privacy tests**

Require one crate to own encrypted PQ-key decoding, the live upstream key, durable reservations,
and raw signing. Add compile-fail tests proving public callers cannot obtain a live key, decrypted
key bytes, raw reservation API, reservation result, caller-supplied post-reservation callback, or
unreserved signing primitive.

At the public boundary require:

- bounded/versioned `PqKeystore` generation, parsing, metadata, and password authentication;
- `AuthenticatedPqKeyMetadata`, containing only the validated public key/profile/range;
- `provision_usage_journal(...) -> Result<(), _>` and
  `validate_usage_journal(...) -> Result<(), _>`, which never return a journal/reservation handle;
- one global `PqSigningAuthority` owning the journal and all loaded local PQ keys;
- lightweight bound `PqSigner` handles whose only cryptographic operation is
  `sign(PqSigningClaim) -> PqRawSignature`.

Cover successful encrypted-key-to-signature verification, identical retry returning byte-identical
evidence, conflicting root and out-of-range ID never reaching the backend, duplicate/mismatched
keys failing startup, missing journal failing startup, and a second process being refused by the
persistent lock. Retain subprocess crash cases before commit, after commit/before sign, and after
sign/before return.

**Step 2: Verify RED**

Run the new crate's doc/privacy, keystore, journal, and authority tests. Expected: the consolidated
crate and safe facade do not exist; the current cross-crate private pieces cannot be connected
without exposing a bypass.

**Step 3: Implement the deep `pq_signing` boundary**

Move the experimental non-EIP-2335 PQ keystore and the complete XMSS journal under private sibling
modules in `pq_signing`. `eth2_keystore` returns to owning BLS/EIP-2335 encryption primitives and a
narrow shared NFKD/control-removal helper only. Remove the public builder that accepts an upstream
`lean_multisig::SecretKey`.

Use `pub(in crate::authority)` for keystore decryption, live-key construction, raw upstream signing,
journal open/reserve, and reservation outcomes. No cross-crate `pub` decrypted-key, upstream-key,
generic backend, raw reserve, or callback API is permitted. Construct the frozen Lighthouse raw
envelope internally and validate it through `PqRawSignature` before return.

The authority is synchronous and explicitly blocking. Startup acquires the one global journal,
validates all bindings, then decrypts/reconstructs keys sequentially. Each signing operation:

1. acquires the per-key operation gate and rejects a previously poisoned signer;
2. validates the bound key/profile/range;
3. commits `(key, one_time_use_id, signing_root)` durably and releases the DB mutex;
4. acquires a separate live-key mutex;
5. contains any backend unwind, permanently poisoning that in-memory key on panic, or produces the
   deterministic raw signature.

The operation gate spans the poison check, reservation, and backend operation to prevent an
in-flight call from racing a poison check. It is not the live-key mutex: never hold the SQLite and
live-key mutexes together. Any error, contained panic, cancellation, or abort after commit burns
the leaf; same-root retry remains valid and different-root retry never calls the backend. Task
3.3b, not this crate, dispatches the entire blocking operation through Lighthouse's scoped
executor.

Change `validator_dir/pq-devnet` and `signing_method/pq-devnet` to depend on `pq_signing`; remove
their direct PQ SQLite/lean ownership. Keep `types/pq-devnet` dependent only on
`consensus_signature/pq-wire`.

**Step 4: Verify GREEN**

```bash
cargo test -p pq_signing --no-default-features --features pq-devnet --doc
cargo nextest run -p pq_signing --no-default-features --features pq-devnet
cargo check -p eth2_keystore
cargo check -p validator_dir --no-default-features --features pq-devnet
cargo check -p signing_method --no-default-features --features pq-devnet
cargo tree -p types --no-default-features --features pq-devnet -e normal,build | \
  rg 'lean-multisig|lean_multisig_api|lean_vm|rec_aggregation'
cargo check
```

The graph command must produce no matches. Run heavy real-key tests serially and preserve Rust 1.88
coverage, feature isolation, clippy, formatting, dependency sorting, and the full workspace check.

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crypto/pq_signing crypto/eth2_keystore common/validator_dir \
  validator_client/signing_method docs/plans/2026-08-18-pq-devnet-implementation.md \
  docs/pq-devnet-findings.md
git commit -m "feat: add journal-owned PQ signing authority"
```

### Task 3.3b: Implement the validator signing/slashing core

**Prerequisites:** Tasks 3.3a and 4.1b.

**Files:**

- Modify: `validator_client/signing_method/src/lib.rs`
- Modify: `common/validator_dir/src/pq_validator_dir.rs`
- Create: a bounded shared PQ-devnet bundle/manifest module under `common/validator_dir/`; the
  runtime validator client must not depend on `testing/pq_devnet`
- Modify: `validator_client/initialized_validators/src/lib.rs`
- Modify: `validator_client/lighthouse_validator_store/src/lib.rs`
- Modify: `validator_client/validator_store/src/lib.rs`
- Modify: the active validator-identity transport surface under `common/eth2/` and the required
  feature forwarding in `validator_client/doppelganger_service/`
- Modify: `crypto/pq_signing/` only to add the descriptor-anchored authority-open and
  journal-before-decryption boundary used by runtime bundle startup
- Modify: `testing/pq_devnet/` to consume the shared manifest schema instead of defining a runtime
  schema in the provisioning package
- Modify: `validator_client/slashing_protection/src/lib.rs` and
  `validator_client/slashing_protection/src/slashing_database.rs`
- Modify: `consensus/types/src/attestation/attestation.rs`
- Modify: the relevant Cargo features for every package above
- Create: PQ signing integration tests, including an isolated validator-store test harness whose
  fixture dependency cannot enter the runtime feature graph

**Step 1: Write failing duty-signing tests**

Cover the first finalizing-devnet duties: RANDAO reveal, block proposal, attestation, attestation
selection proof, and aggregate-and-proof. Require real signatures to verify against the bound key,
identical retries to return byte-identical evidence, and conflicting roots to fail without creating
another journal reservation.

Pin the safety ordering with tests for an unsafe attestation, concurrent same-root and conflicting
attestations, and cancellation after the slashing-protection commit. An unsafe attestation must not
burn an XMSS leaf. A same-data retry after either database commit must succeed deterministically.

Add bundle/authority construction tests for wrong manifest/network root, journal binding mismatch,
missing/extra/duplicate keys, a parent-directory swap, and a second journal owner. Gate EIP-3076
import/export and remote key mutation from the compiling PQ core surface. Default BLS behavior
remains covered by its existing tests. Actual validator-client process startup and its complete set
of profile guards belong to Task 3.3c and are not claimed by this task.

**Step 2: Verify RED**

Run the targeted signing-method/validator-store tests. Expected: PQ signing is unavailable.

**Step 3: Implement PQ local signing**

Keep `SignableMessage`/`SigningMethod` as the semantic abstraction; do not introduce a universal
signature-scheme trait. In PQ mode `SigningMethod` contains a lightweight signer only behind an
opaque holder and controlled constructor; public callers cannot extract or clone it. Before
computing a root, validate that the supplied `SigningContext` domain and epoch match the semantic
message. It computes the signing root and frozen V1 `OneTimeUseId`, then dispatches exactly one combined
`PqSigner::sign` call through Lighthouse's high-priority scoped blocking/Rayon executor. Journal
reservation and signing must remain one non-bypassable blocking operation. Preserve
`PqSigningError` as an error source and do not reintroduce an upstream key, raw reservation,
callback, or unreserved signing escape hatch.

Own exactly one `PqSigningAuthority` per validator-client process on `InitializedValidators`, then
place one lightweight signer handle in each initialized validator. Do not open an authority per
validator because the journal lock and binding validation are process-global.

Move the bounded PQ-devnet manifest/layout schema out of the provisioning package into a shared
runtime module. Its authority-construction API takes the actual beacon/network
`genesis_validators_root` as the root of trust, validates the manifest only as consistency data,
requires an exact key set and exact per-keystore one-time-use range, and retains one root directory
descriptor across manifest/key/secret reads and the anchored authority journal open. It returns one
authority plus lightweight signer handles; Task 3.3c wires that API into the actual process after
the network root is known and opens fresh slashing protection in the required order.

Bundle loading performs only bounded outer-metadata validation and assembles `PqKeyUnlock` values.
The authority must lock and validate the journal before performing exactly one authenticated
KDF/decryption and derived-key identity/range cross-check per key. Non-Linux PQ builds must compile
and return an explicit `UnsupportedPlatform`; the first journal-backed profile remains Linux-only.

Use active `ValidatorPublicKeyBytes` in core slashing-protection APIs, but gate the BLS-shaped
EIP-3076 interchange in PQ builds. Never create a BLS shadow identity.

Blocks already commit slashing protection before signing; in PQ mode allow `Safe::SameData` to
reach the authority for deterministic retry. Reorder attestations from
`sign -> batch slashing check` to:

```text
batch slashing-protection transaction
    -> retain Safe::Valid and PQ Safe::SameData
    -> combined journal-reserve-and-sign on the scoped executor
    -> attach/promote the individual evidence
```

Preserve successful attestation siblings when one signer fails, and record exactly one final
`SUCCESS` or `SAME_DATA` metric only after successful evidence attachment. Likewise, block
`SUCCESS`/`SAME_DATA` metrics are recorded only after signature production and signed-block
construction.

Add a scheme-neutral one-participant attestation attachment helper. In PQ Electra it sets the
participant bit and cheaply promotes `PqRawSignature` to `PqSameMessageEvidence`; it must never
prove or combine multiple signatures. Task 4.2 owns beacon-node aggregate evidence.

The compiling core accepts only the local journal-owning PQ signing method and exposes explicit
unsupported-duty errors. Task 3.3c owns process-level rejection of remote/distributed signing and
the remaining unsupported workflows before duties begin.

Keep RANDAO as a semantic duty and retain its frozen V1 leaf: its signing root is epoch-bound but
its one-time-use ID is proposal-slot-bound. A hash-chain/hash-onion RANDAO remains a future,
versioned profile that changes consensus/state-transition rules; it must not silently renumber or
remove the V1 RANDAO leaf.

**Step 4: Verify GREEN**

Run targeted signing, initialized-validator, slashing-protection, validator-store, and bundle
construction tests in both PQ and default configurations. Prove the normal
`lighthouse_validator_store/pq-devnet` graph excludes the fixture crate and `state_processing`.
Verify Rust 1.88, non-Linux cfg completeness when an appropriate target is available, feature
isolation, clippy with warnings denied, formatting, dependency sorting, and the mandatory full
workspace `cargo check`.

Also preserve the default EIP-3076 fixture-generator workflow while keeping runtime interchange
unavailable in PQ mode:

```bash
make -C validator_client/slashing_protection generate GENERATE_DIR="$(mktemp -d)/generated-tests"
cargo check -p slashing_protection --all-features --all-targets
```

**Step 5: Commit**

```bash
git add Cargo.lock common/eth2 common/validator_dir consensus/types crypto/pq_signing \
  testing/pq_devnet validator_client \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "feat: sign validator duties with PQ keys"
```

### Task 3.3c: Integrate PQ startup into the validator-client process

**Prerequisites:** Task 3.3b and the PQ state-processing/verification feature-spine migration from
Tasks 4.2 and 5.1-5.3. This task must not be started by feature-unifying `types/pq-devnet` into the
current BLS-only state-processing graph.

**Files:**

- Modify: `validator_client/src/lib.rs`, `config.rs`, and `cli.rs`
- Modify: the validator-client/runtime feature forwarding needed after the verification spine is PQ
  compatible
- Create: full-process PQ startup and unsupported-profile tests

**Step 1: Write failing process-startup tests**

Start the actual validator-client process far enough to obtain the beacon/network
`genesis_validators_root`. Cover wrong manifest/network root, journal mismatch,
missing/extra/duplicate keys, a second journal owner, and cancellation/restart after ordinary
slashing protection commits. Require explicit startup/profile rejection of Web3Signer,
distributed signing and distributed selections, builder registration, remote key mutation APIs,
online voluntary exits, and EIP-3076 import/export.

**Step 2: Verify RED**

Run the validator-client PQ feature check and the new process tests. Until the prerequisite
state-processing/verification feature spine lands, the expected RED is the documented BLS-shaped
state-processing graph; do not weaken the startup contract to make it compile.

**Step 3: Wire the process in the fail-closed order**

After the actual network root is known:

1. validate the bounded frozen-profile manifest and match it to the actual root;
2. validate the exact directory identity set and reject mixed, missing, extra, or duplicate keys;
3. unlock every bounded keystore and match its exact one-time-use range to the manifest;
4. open one descriptor-anchored authority with the actual root;
5. bind lightweight signer handles;
6. only then create/register a fresh PQ slashing-protection database; and
7. enable duties only after all unsupported workflows have been rejected.

Do not add BLS shadow identities or expose a caller-supplied signing-root path in PQ mode.

**Step 4: Verify GREEN**

Run full-process PQ startup/restart tests, all unsupported-profile tests, the first useful duty
tests through the process boundary, default BLS regressions, Rust 1.88 checks, feature graphs,
clippy with warnings denied, formatting, dependency sorting, and the mandatory full workspace
`cargo check`.

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock validator_client docs/plans/2026-08-18-pq-devnet-implementation.md \
  docs/pq-devnet-findings.md
git commit -m "feat: start the validator client with PQ signing"
```

## Milestone 4: PQ Consensus Wire Types

### Task 4.1: Add PQ public key and raw-signature SSZ types

**Files:**

- Modify: `crypto/consensus_signature/Cargo.toml`
- Create: `crypto/consensus_signature/src/pq_wire.rs`
- Modify: `crypto/consensus_signature/src/lib.rs` and `src/pq.rs`
- Create: `crypto/consensus_signature/tests/pq_wire_schema.rs`
- Modify: `consensus/types/Cargo.toml`
- Modify: validator-identity fields and helpers under `consensus/types/src/validator/`,
  `state/`, `sync_committee/`, `withdrawal/`, `consolidation/`, and `deposit/pending_deposit.rs`
- Gate BLS-only signing, point-mutation, and direct-verification helpers under
  `consensus/types/src/attestation/`, `block/`, `exit/`, and `sync_committee/`
- Create: focused PQ schema tests under `consensus/types/tests/`, including the isolated
  `pq_schema_harness/Cargo.toml` and committed `pq_schema_harness/Cargo.lock`
- Modify: `validator_client/signing_method/Cargo.toml` to forward both PQ feature halves
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write failing PQ schema tests**

In `consensus_signature`, pin the following independent wire contracts before enabling them in
`types`:

- `PqPublicKey`: exact 32-byte fixed SSZ, canonical lowercase `0x` JSON, stable tree root,
  byte/string round trips, and exact-length rejection;
- `PqRawSignature`: exact 1,215-byte fixed SSZ with `LHPQ`, wire version 1, parameter set 1, and raw
  evidence kind; pin JSON/tree root and reject wrong length, magic, version, parameter set, and kind;
- `PqSameMessageEvidence`: a distinct bounded **variable-size** SSZ byte-list from its first
  version, capped at 512 KiB. Pin raw promotion without proving, canonical seven-byte absent
  evidence, structurally framed aggregate evidence, variable-length SSZ offsets/tree roots, and
  one-byte-over-cap rejection.

The same-message type must use its final variable-size SSZ shape now. A temporary fixed raw-only
type would change every containing SSZ offset and tree root when recursive proofs arrive in Task
4.2. Generic decoding validates only the Lighthouse envelope and bound; contextual aggregate-proof
decoding remains Task 4.2.

Add default BLS regression assertions that the existing aliases, fixed bytes, JSON, SSZ, and tree
roots remain exactly unchanged.

**Step 2: Verify RED under PQ-only features**

Run the narrow wire tests first. Expected: `pq-wire`, the three PQ wire types, and their trait
implementations do not yet exist. Then add focused `types` schema tests and capture the current
BLS-sized validator/signature fields failing those expectations.

**Step 3: Implement compile-time-selected PQ types**

Split features so consensus serialization never pulls the prover into the types graph:

```toml
# crypto/consensus_signature
pq-wire = []
pq-devnet = ["pq-wire", "dep:lean-multisig"]

# consensus/types
pq-devnet = ["consensus_signature/pq-wire"]
```

Cargo feature unification requires every PQ entry-point package that contains both `types` and
`consensus_signature` to select both halves of the profile. Such a package must forward
`types/pq-devnet` whenever it enables either `consensus_signature/pq-devnet` or
`consensus_signature/pq-wire`; enabling only the signature crate leaves `types` compiling BLS-only
helpers against PQ aliases.

Keep the wire implementation in `pq_wire.rs`, with no leanMultisig dependency. The backend-heavy
`pq` module remains gated by `pq-devnet` and reuses/re-exports those wire types. Use additive,
all-features-safe selection: `feature = "pq-wire"` selects PQ aliases, while its absence selects
the exact existing BLS aliases. Do not introduce a runtime BLS/PQ union or a universal `BlsLike`
trait. Forward the optional arbitrary feature so PQ types remain usable by derived test objects.

The active aliases are:

- `ValidatorPublicKeyBytes` and `VerificationKey` -> `PqPublicKey`;
- `IndividualSignature` and `RawSignature` -> `PqRawSignature`;
- `SameMessageEvidence` and `AggregateSignature` -> `PqSameMessageEvidence`.

Migrate the validator registry, state pubkey cache, sync-committee identities/duties,
withdrawal/consolidation request validator keys, and `PendingDeposit.pubkey` to the active validator
identity type. Keep deposit ingress messages/signature bytes, builder/relay objects, and
BLS-to-execution changes explicitly BLS. In PQ mode, deposit processing is disabled later; the
pending-deposit queue still needs the active key type so state transitions remain type-coherent.

For the legacy sync-committee `aggregate_pubkey` field, preserve the field in the PQ schema but use
the canonical zero PQ key; PQ verification must never consume it. Gate BLS point aggregation,
`infinity`, direct `.verify`, decompression, and `SecretKey` convenience constructors instead of
emulating them on PQ types. Retain data-only constructors that accept semantic signature values.
Use canonical absent evidence only for genuinely empty aggregate placeholders; `SingleAttestation`
promotion must remain a cheap raw-envelope conversion and never invoke proving.

**Step 4: Verify both configurations**

```bash
cargo nextest run -p consensus_signature --test bls_compatibility
cargo nextest run -p consensus_signature --no-default-features --features pq-wire \
  --test pq_wire_schema
cargo test -p consensus_signature --all-features --all-targets --no-run
cargo check -p consensus_signature
cargo check -p consensus_signature --no-default-features --features pq-wire
cargo check -p consensus_signature --all-features

cargo check -p signing_method
cargo check -p signing_method --features pq-devnet

cargo nextest run -p types --test consensus_signature_schema
cargo test --manifest-path consensus/types/tests/pq_schema_harness/Cargo.toml --locked --lib
cargo check -p types --lib
cargo check -p types --lib --no-default-features --features pq-devnet
cargo check -p types --lib --all-features

cargo tree -p types --no-default-features --features pq-devnet -e normal,build | \
  rg 'lean-multisig|lean_multisig_api|lean_vm|rec_aggregation'
```

The standalone schema-harness command and its committed `Cargo.lock` are mandatory because its
nested workspace intentionally prevents root-workspace dev-dependencies from enabling BLS-only
downstream crates. The final graph command must produce no matches. Confirm separately that
`consensus_signature --features pq-devnet` still resolves the exact pinned backend.

Do **not** use the old full `cargo nextest run -p types --features pq-devnet` as the Task 4.1 gate.
The package's dev-dependencies unify `types` into BLS-only `beacon_chain` and `state_processing`
paths that are intentionally migrated in later verification milestones. At this slice, use focused
normal-dependency PQ schema tests plus `types --lib` checks. Continue to run the complete default
types suite and the mandatory default workspace check:

```bash
cargo nextest run -p types
cargo check
```

Expected: BLS goldens are byte-for-byte unchanged, PQ wire/schema tests pass, PQ `types --lib`
compiles without leanMultisig in its normal/build graph, and the default workspace compiles.

**Step 5: Commit**

```bash
git add Cargo.lock consensus/types/tests/pq_schema_harness/Cargo.lock \
  crypto/consensus_signature consensus/types validator_client/signing_method/Cargo.toml \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "feat: add PQ consensus wire types"
```

### Task 4.1b: Provision PQ validators and build a direct-registry genesis

**Prerequisites:** Tasks 4.1 and 3.3a.

**Implementation status (2026-08-18):** implemented and locally verified; pending maintainer review. The
feature-isolated `lcli-pq-devnet` package, narrow `state_processing/pq-genesis` surface,
direct-registry Electra constructor, anchored staging publisher, validator provisioning, and bound
journal cross-check are present. The production `16 × 0..=1119` path remains an ignored/manual
measurement, as required; ordinary coverage uses synthetic genesis keys and a one-validator small
range.

**Files:**

- Create: a feature-isolated minimal package/binary such as `testing/pq_devnet/` with binary name
  `lcli-pq-devnet`; do not add the first PQ command to the dependency-heavy existing `lcli`
- Modify or create: PQ validator provisioning helpers under `common/validator_dir/`
- Modify: `consensus/state_processing/` to expose a temporary genesis-only PQ compilation surface
  without per-block/signature modules
- Modify: the genesis/state-initialization path to share the post-registry fork-upgrade tail
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
- generating twice yields identical public configuration, registry ordering, directory identities,
  journal bindings, and genesis state bytes. Keystore ciphertext JSON is intentionally randomized
  by fresh salt and IV and is not compared byte-for-byte.

Use small key ranges in ordinary tests. Add an ignored/measured test for the initial devnet range
`0..=1119` only after the validator count and lifetime are frozen.

**Step 2: Verify RED**

Run the narrow PQ-only standalone-tool, genesis-only state-processing, authority-provisioning, and
validator-directory tests. Expected: the direct PQ registry/provisioning path does not exist.

**Step 3: Implement the PQ-only provisioning command and genesis path**

The existing `lcli` package unconditionally depends on BLS-heavy beacon/state/network crates; a PQ
subcommand there would feature-unify PQ `types` through callers that are not migrated yet. Add a
minimal package whose default feature set is empty and whose PQ binary target requires
`pq-devnet`. Similarly, add a temporary `state_processing/pq-genesis` surface that compiles only
genesis, fork upgrades, and their minimal dependencies; default `state_processing` continues to
compile its full unchanged path.

Generate and encrypt PQ keys sequentially, create their validator directories, and construct the
genesis validator registry directly from their PQ public keys. Refactor the existing deposit-based
genesis function so both entry points share one post-registry activation/fork-upgrade/cache/root
tail. Never create dummy deposits, unchecked deposit signatures, padded public keys, shadow BLS
keys, or consume XMSS leaves during genesis. Use Electra at epoch zero, an empty deposit root/count/
index and pending-deposit queue, deterministic execution withdrawal credentials, and canonical
zero sync-committee aggregate-key placeholders.

Use the frozen V1 profile: minimal preset, 16 validators, `0..=1119`, sequential construction, and
domain-separated validator seeds
`SHA256("lighthouse/pq-devnet/validator-seed/v1" || master_seed || index_be_u64)`. Read the exact
32-byte master seed and bounded password from files into zeroizing storage; never accept either on
the process command line.

Build under a deterministic sibling staging path, reject existing final/staging paths before KDF
work, and never clean partial output automatically. After all files are durable, use an atomic
no-replace publish and sync the parent. A crash leaves a named tombstone for explicit inspection.

Obtain `genesis_validators_root` from the constructed state, then call only the authority's
non-signing journal provisioning facade. Reopen and cross-check every keystore, registry entry,
range, and journal binding before and after publication. Discovery order is lexical by public key;
cross-check by key map while separately preserving derivation-index registry order.

**Step 4: Verify GREEN**

Run fast pure direct-genesis tests with synthetic keys, authority facade tests, and one-validator
small-range end-to-end provisioning. Regenerate into two fresh destinations and compare public
outputs/state. Keep the full 16-validator `0..=1119` run ignored/manual and measure it separately.
Then run default BLS genesis regressions and the mandatory full workspace `cargo check`.

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock testing/pq_devnet common/validator_dir consensus/state_processing \
  crypto/pq_signing \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "feat: provision PQ validator genesis"
```

### Task 4.2: Define bounded aggregate-proof evidence

**Files:**

- Modify: `crypto/consensus_signature/src/pq.rs`
- Modify: `crypto/consensus_signature/src/pq/backend.rs`
- Modify: `crypto/consensus_signature/src/pq_wire.rs`
- Modify: `crypto/consensus_signature/tests/pq_wire_schema.rs`
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write failing contextual-boundary tests**

Task 4.1 already introduced bounded variable-size SSZ, Lighthouse framing, raw promotion, and
absent evidence. Preserve those tests and add the missing boundary: opaque locally generated
aggregate construction plus contextual hostile decode/verify. Cover a real two-signer proof,
wrong root and one-time-use ID, missing/extra/substituted/duplicate/permuted signers, raw/absent
kinds, malformed/truncated/trailing upstream envelopes, maximum and one-byte-over-limit evidence,
allocation-before-bound regressions, and local-versus-peer proof-error classification.

**Step 2: Verify RED**

Expected: the wire type exists, but no backend-owned conversion or contextual aggregate verifier
exists. Do not describe the already-implemented generic SSZ bound as missing.

**Step 3: Implement backend-owned construction and contextual verification**

Task 4.2 initially routed local construction through opaque `PqAggregateSignature`. Task 5.1
removed that interim wrapper, its in-memory verifier, and their backend-specific public errors:
only the crate-private prover worker behind public `AggregationService` may create local aggregate
evidence. Retain the complete pinned upstream `LMSI/version/aggregate` envelope inside the
Lighthouse aggregate payload. Check the 512 KiB full-evidence cap before constructing the wire
value and report `AggregationError::OutputTooLarge` through the operation-level boundary.

Generic SSZ/wire decoding continues to validate only the Lighthouse envelope, semantic kind, and
outer byte limit. Contextual verification accepts `PqSameMessageEvidence`, `PqSigningClaim`, and
the exact expected `PqPublicKey` list. Require the list to be duplicate-free and strictly ordered
by canonical public-key bytes. Check evidence and signer bounds before collecting keys or entering
backend parsing/setup, reject raw and absent kinds, and map malformed bytes, claim/signer mismatch,
and peer `Error::Proof(_)` to `InvalidEvidence`. Locally generated prover/proof failures remain
local/internal; unknown non-exhaustive backend errors fail closed as internal. Keep backend
diagnostics opaque.

No `consensus/types` dependency or container change is required: Task 4.1 already gave attestation
and sync aggregate fields their final variable-size PQ shape. A fork is not required for this
controlled exact-pin devnet slice. Before public or broadly untrusted deployment, fork the binding
to expose representation-specific bounded decoding/serialization so nested backend allocations
are enforced internally rather than only by Lighthouse's outer 512 KiB cap.

**Step 4: Verify GREEN in BLS and PQ configurations**

Run fast scalar framing/classification tests, the serialized AVX2 two-signer proof test, default BLS
compatibility, Rust 1.88 scalar/AVX2 checks, the `types/pq-devnet` Lean-free graph check, Clippy with
warnings denied, formatting, dependency sorting, diff checks, and the mandatory workspace
`cargo check`.

**Step 5: Commit**

```bash
git add Cargo.lock crypto/consensus_signature docs/plans/2026-08-18-pq-devnet-implementation.md \
  docs/pq-devnet-findings.md
git commit -m "feat: add bounded PQ aggregate proof evidence"
```

## Milestone 5: PQ Aggregation and Consensus Verification

### Task 5.1: Implement the aggregation job boundary

**Files:**

- Create: `crypto/consensus_signature/src/aggregation.rs`
- Create: `crypto/consensus_signature/tests/aggregation.rs`
- Modify: `crypto/consensus_signature/src/lib.rs`
- Modify: `crypto/consensus_signature/src/bls.rs`
- Modify: `crypto/consensus_signature/src/pq.rs`
- Modify: `crypto/consensus_signature/src/pq/backend.rs`
- Modify: `crypto/consensus_signature/src/pq_wire.rs`
- Modify: `crypto/consensus_signature/Cargo.toml`
- Modify: `crypto/consensus_signature/tests/pq_wire_schema.rs`
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write failing cross-backend contract tests**

The same structural contract must run against both backends: one raw contribution, multiple raw
contributions, raw plus child aggregate, aggregate plus aggregate, wrong claim/evidence, empty
input, non-canonical or duplicate signer/index mappings, overlap between contributions, expected
signer-union mismatch, and signer/contribution/total-input/output size limits. One contribution is
validated and returned without proving; multiple contributions use backend aggregation.

Add PQ worker tests for bounded non-blocking submission, one active plus at most one queued job,
queue saturation, cancellation before backend entry, worker shutdown/panic/poisoning, and local
output overflow. Prove that waiting for a result is async-compatible and never performs setup,
decode, verification, or proving on a Tokio/beacon-processor worker.

**Step 2: Verify RED for both backends**

Expected: the aggregation job interface does not exist.

**Step 3: Implement one-shot owned aggregation**

Expose one operation-level job rather than a `BlsLike` trait or incremental mutation:

```rust
pub struct SameMessageClaim {
    pub signing_root: [u8; 32],
    pub one_time_use_id: OneTimeUseId,
}

pub struct AggregationSigner {
    pub validator_index: u64,
    pub public_key: ValidatorPublicKeyBytes,
}

pub struct AggregationContribution {
    pub signers: Vec<AggregationSigner>,
    pub evidence: SameMessageEvidence,
}

pub struct AggregationJob {
    pub claim: SameMessageClaim,
    pub expected_signers: Vec<AggregationSigner>,
    pub contributions: Vec<AggregationContribution>,
}
```

Require strictly increasing unique validator indices, canonically encoded unique public keys, no
overlap between contributions, no public key mapped to multiple indices, and exact equality between the
contribution signer union and `expected_signers`. Bound signer count, contribution count, total
input evidence bytes, and output evidence bytes before backend work. Participant bits remain owned
by consensus/pool callers and must be committed atomically with the returned evidence later.
Freeze the pinned KoalaBear public-key canonicality check in the Lean-free wire layer: each of the
eight little-endian `u32` limbs must be strictly below `0x7f000001`. Reject a malformed key before
job construction/backend entry, and retain a local `InvalidJob` defense-in-depth classification.

The domain lists remain ordered by validator index. Before entering leanMultisig, project each
domain list to a separate public-key list sorted strictly by canonical key bytes, retaining the
index-to-key association for union/overlap checks. Do not require validator-index order to coincide
with public-key byte order.

BLS uses point aggregation internally behind this owned job. PQ decodes and verifies every raw or
child aggregate against the common claim and its exact child signer set, then supports raw+raw,
raw+aggregate, and aggregate+aggregate recursion. Child aggregate payloads contain the complete
upstream LMSI envelope defined in Task 4.2. After all inputs are verified, a backend proof failure
is local/internal; malformed child evidence is `InvalidEvidence`. Structural caller errors are
`InvalidJob`, not peer blame.

Refactor `PqProver` submission so it remains one long-lived named 512 MiB-stack OS worker but does
not synchronously wait on a channel from async callers. Use non-blocking bounded submission and an
async-compatible oneshot result, with one active job and at most one queued job. Check cancellation
before entering the backend; do not attempt unsafe mid-proof cancellation. Preserve permanent
process poisoning after a caught backend panic. Setup may remain synchronous during builder startup
before networking begins. Keep `PqProver` and its constructor crate-private; public downstream
ownership and startup must go exclusively through `AggregationService`, so another caller cannot
reserve the process singleton and starve consensus aggregation.

Classify queue saturation and configured limits as `ResourceExhausted`, missing/poisoned/stopped
workers as local unavailability, locally oversized output as `OutputTooLarge`, and unknown
post-verification backend failures as `Internal`. Dropping an aggregation future is silent
cancellation: the worker skips a queued job before backend entry, and no receiver remains to
observe a result. The first V1 runtime uses a stricter 16-validator cap even though the pinned
backend supports 32,768.

**Step 4: Verify GREEN and record measurements**

Run both backends. Record PQ time, proof bytes, and peak RSS for the chosen devnet committee sizes
in `docs/pq-devnet-findings.md`. Keep the real recursive proof cases serialized under AVX2. Verify
Rust 1.88, default BLS compatibility, types graph isolation, clippy with warnings denied,
formatting, dependency sorting, diff checks, and the mandatory full workspace `cargo check`.

**Step 5: Commit**

```bash
git add crypto/consensus_signature docs/plans/2026-08-18-pq-devnet-implementation.md \
  docs/pq-devnet-findings.md
git commit -m "feat: add signature aggregation jobs"
```

### Task 5.1a: Build the PQ attestation key/request prerequisite

**Prerequisites:** Tasks 4.2 and 5.1.

**Files:**

- Modify: `consensus/state_processing/Cargo.toml`
- Modify: `consensus/state_processing/src/lib.rs`
- Create: `consensus/state_processing/src/pq_attestation.rs`
- Modify: `testing/pq_devnet/Cargo.toml`
- Create: `testing/pq_devnet/tests/pq_attestation.rs`
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write failing isolated cache/request tests**

Use an isolated normal-dependency PQ harness, not the root `state_processing` dev-dependency graph.
Cover deterministic cache construction from the validator registry, index/key lookup, duplicate
key and out-of-range rejection, exact signing-root/leaf derivation, a valid promoted raw single,
valid one- and two-participant same-message evidence, and wrong root/leaf/key/participant bits.

Reject nonzero Electra `AttestationData.index`, claimed signer slices that differ from a well-formed
participant bitfield, cross-contribution signer overlap, over-16 contributions, and empty,
duplicate, unordered, out-of-range, or over-16 signer indices before allocation, evidence clone, or
backend work. A `SingleAttestation` must contain individual/raw evidence; a one-signer recursive
proof is not valid in that field. Pin local-versus-peer error classification and prove structural
failures never submit to the aggregation worker.

**Step 2: Verify RED on the minimal feature surface**

Add a `state_processing/pq-attestation` feature that compiles only the new module and its minimal
dependencies. Expected: no PQ registry cache or scheme-neutral attestation job builder exists. Do
not enable the full BLS-only per-block, deposit, sync, or Gloas module graph.

**Step 3: Implement the compile-time PQ cache and request builder**

Keep the default `ValidatorPubkeyCache`, parallel BLS decompression, and persisted `pkc` database
bytes completely unchanged. For the frozen 16-validator, deposit-disabled V1 profile, add a
concrete `PqValidatorKeyCache` containing the registry-order `Vec<PqPublicKey>` plus a reverse map.
Rebuild it from the head-state registry on startup; do not write PQ keys to `pkc`. If persistence is
ever required, it must use a distinct column/profile marker rather than reinterpret BLS records.

Before cloning evidence or submitting work:

- require the Electra V1 profile and `AttestationData.index == 0`;
- require at most sixteen contributions before reserving or iterating contribution-owned vectors;
- checked-convert attacker-controlled indices and validate registry/cache bounds;
- locally derive committees and validate committee/aggregation bit lengths and membership;
- require one through sixteen strictly increasing unique validator indices with no overlap across
  contributions;
- resolve exact keys and treat duplicate registry keys/cache incompleteness as local state errors;
- derive `DOMAIN_BEACON_ATTESTER` at `data.target.epoch`; and
- derive the XMSS ID from `data.slot` and `SigningDuty::Attestation` (never the target epoch,
  inclusion slot, or aggregate-and-proof slot).

For aggregate inputs, use a borrowed contribution view pairing each Electra attestation with the
caller's reconstructed signer-index slice. Validate each supplied slice first, then independently
derive the indices from state committees and participant bits and require exact equality. This
keeps large evidence borrowed until every structural, bounds, membership, and cache check passes.

Build one owned `AggregationJob`. For verification, a single contribution must be contextually
verified by `AggregationService` and returned byte-identically without proving. Keep signer lists
ordered by validator index; the service separately sorts keys for leanMultisig. Release state,
cache, and shuffling locks before awaiting the worker.

Map malformed bitfields/indices and invalid evidence to peer/consensus invalid. Map an
`InvalidJob` after local construction, cache invariant failures, queue exhaustion, unavailable or
poisoned worker, output overflow, and internal backend failure to local errors. Do not mutate
observed-attester or pool state until verification succeeds.

**Step 4: Verify the isolated PQ and unchanged BLS paths**

```bash
cargo check -p state_processing --lib --features pq-attestation
cargo check -p state_processing --lib --features pq-genesis,pq-attestation
RUSTFLAGS='-C target-feature=+avx2' cargo test -p pq_devnet --features pq-devnet \
  --test pq_attestation -- --test-threads=1
cargo check -p types --lib --no-default-features --features pq-devnet
cargo check
```

Confirm the `types/pq-devnet` graph remains free of leanMultisig/futures. Preserve default BLS cache
and attestation tests. Verify Rust 1.88, clippy with warnings denied, formatting, dependency sorting,
diff checks, and the mandatory full workspace check.

**Step 5: Commit**

```bash
git add Cargo.lock consensus/state_processing testing/pq_devnet \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "feat: verify PQ attestation evidence"
```

### Task 5.2a: Add an isolated, failure-atomic attestation aggregation coordinator

**Status (2026-08-18): implemented and awaiting review.** The isolated coordinator and opaque
verification transition compile without enabling either existing beacon-node pool. Fast state
machine coverage is 15/15. The serialized journal-backed AVX2 integration test is 1/1 and completed
in 137.36 seconds of test time (137.66 seconds command wall time, 794,400 KiB command-tree peak
RSS) on this host. The Minimal preset produces a two-validator slot committee at the V1
sixteen-validator registry cap, so a three-signer raw-plus-child catch-up case is not constructible
in this harness; raw-plus-child backend recursion remains covered by Task 5.1.

**Prerequisites:** Tasks 5.1 and 5.1a.

The current `operation_pool` package cannot honestly enable the PQ profile yet. It unconditionally
imports the full BLS `state_processing` surface, performs point mutation in
`attestation_storage.rs`, and has a development dependency cycle through `beacon_chain`. There is
also a second independent mutation path in `beacon_chain::naive_aggregation_pool`. Do not mass-gate
either package merely to make a narrow test compile.

**Files:**

- Modify: root `Cargo.toml` and `Cargo.lock`
- Create: `beacon_node/attestation_aggregation/Cargo.toml`
- Create: `beacon_node/attestation_aggregation/src/lib.rs`
- Modify: `consensus/state_processing/src/pq_attestation.rs`
- Modify: `consensus/state_processing/src/lib.rs`
- Modify: `testing/pq_devnet/Cargo.toml`
- Create: `testing/pq_devnet/tests/pq_attestation_aggregation.rs`
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write failing sealed-candidate and state-machine tests**

Add an opaque `VerifiedPqAttestation<E>` produced only after the Task 5.1a contextual job succeeds.
It owns the Electra attestation, its exact sorted signer indices, and the verified claim. Callers may
inspect it but may not construct it or replace its evidence. This prevents the coordinator's
`insert_verified` entry point from becoming an unauthenticated storage bypass.

In the isolated normal-dependency harness cover:

- exact duplicate, subset, strict-superset, and overlapping-incomparable candidates;
- deterministic largest-first disjoint selection with stable tie-breaking;
- one through sixteen candidates/signers and cap-plus-one rejection before allocation;
- same data but different single committee keys never combine;
- singleton retrieval returns verified evidence without proving;
- only one in-flight proof per bucket;
- an arrival during an awaited proof remains stored;
- unrelated arrivals do not invalidate a snapshot, while removal/pruning of a selected candidate
  makes the commit stale and never resurrects it;
- queue/backend/output failure clears in-flight state and preserves every source for retry;
- a fake executor that re-enters the coordinator proves no pool lock crosses job construction or
  `.await`; and
- generation overflow fails closed;
- the 64th distinct bucket and exact 8 MiB retained-evidence total are accepted, while cap-plus-one
  is rejected without a map entry or large evidence allocation; and
- slot pruning releases both bucket and byte capacity, preserves current buckets, and makes a
  removed in-flight bucket stale without resurrection.

**Step 2: Verify RED on an optional, isolated feature surface**

Create a workspace member `attestation_aggregation` whose default build is PQ-free. Its optional
`pq-attestation` feature may enable only `consensus_signature/pq-devnet`,
`state_processing/pq-attestation`, `types/pq-devnet`, and the lock/container dependencies it owns.
Do not feature-unify `operation_pool` or `beacon_chain` in this slice.

Expected RED: no sealed verified candidate, candidate coordinator, prepared snapshot, or atomic
commit API exists.

**Step 3: Implement the deep coordinator boundary**

Expose four actions under the PQ feature:

1. `PqAttestationAggregationCoordinator::new(Arc<AggregationService>)`;
2. synchronous `insert_verified(VerifiedPqAttestation<E>) -> InsertOutcome`; and
3. synchronous `prepare_aggregate(bucket, state, key_cache, spec) -> PreparedAggregate`, followed
   by `PreparedAggregate::execute().await -> AggregateOutcome`; and
4. synchronous `prune_before_slot(cutoff) -> PruneOutcome`.

Use a bucket key containing the full `AttestationData` plus exactly one Electra committee index.
V1 rejects Base and multi-committee candidates and never combines committees. Store bounded
candidate records with monotonic IDs. Equal/subset candidates are dominated, strict supersets
atomically replace their subsets, and overlapping incomparable candidates remain. Candidate-only
operation-pool use may retain verified aggregate gossip and drop dominated duplicates without
proving.

Apply two coordinator-wide bounds under the same mutex before cloning/inserting candidate storage:
at most 64 distinct buckets, and at most `V1_MAX_AGGREGATION_INPUT_BYTES` (8 MiB) of actual retained
`SameMessageEvidence` bytes. The bucket cap is four times the Minimal preset's honest two-epoch,
sixteen-slot window. Existing-bucket inserts also obey the byte cap. Strict-superset replacement,
aggregate commit, concurrent-dominated-arrival removal, and slot pruning must debit/release exact
checked byte counts. Exact cap is accepted; overflow and cap-plus-one return a specific local
capacity outcome without partial mutation. Pruning removes only buckets with `data.slot < cutoff`.

Under the coordinator lock, select and mark one deterministic bounded snapshot in flight, then
clone only bounded handles/IDs and release the lock. Build the Task 5.1a owned job and await the
existing `AggregationService` outside all coordinator, state, cache, shuffling, and async-runtime
locks. Do not add Rayon or another blocking layer: the service already owns the named 512 MiB OS
worker, singleton setup, and one-active/one-queued admission.

After success, reacquire one write lock and commit participant-bit union plus returned evidence as
one atomic update only if every selected ID/value is still present and the final retained-byte
total is within cap. Preserve unrelated arrivals.
If a selected candidate was removed or pruned, return `StaleSnapshot` and install nothing. On every
failure, clear in-flight state and preserve all candidates for retry. Treat post-verification
`InvalidEvidence` as a local invariant failure, never as peer blame.

**Step 4: Verify real proof construction and unchanged default builds**

Use a serialized AVX2 integration test with two journal-backed raw singles. Assert union bits and
contextual verification, reject altered bits/root/leaf/key, contextually verify the installed child
as a singleton without reproving, and prove failure leaves sources unchanged. Require real
raw-plus-child recursion at the Task 5.1 backend boundary, not in this coordinator harness: the
frozen V1 registry cap of sixteen and Minimal preset's eight slots per epoch mathematically limit
the one allowed slot committee to two validators, so a non-overlapping two-signer child plus third
raw signer cannot exist. Do not weaken state-derived committee validation, combine committees, or
add a test-only consensus profile. Also run fast fake-executor concurrency/state-machine tests,
Rust 1.88 checks, warnings-denied Clippy, default BLS operation-pool/types tests, graph isolation,
formatting, sorting, diff checks, and the mandatory full workspace `cargo check`.

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock beacon_node/attestation_aggregation consensus/state_processing \
  testing/pq_devnet docs/plans/2026-08-18-pq-devnet-implementation.md \
  docs/pq-devnet-findings.md
git commit -m "feat: coordinate PQ attestation aggregation"
```

### Task 5.3a: Add reserved priority admission to the singleton PQ worker

**Prerequisites:** Task 5.1.

Verification and recursive proving currently share one capacity-one queue. A local proof can fill
that queue and turn valid block or attestation gossip into a local `QueueSaturated` failure. Never
create a second prover owner: leanMultisig setup and process-global proving state are singleton.

**Files:**

- Modify: `crypto/consensus_signature/Cargo.toml`
- Modify: `crypto/consensus_signature/src/aggregation.rs`
- Modify: `crypto/consensus_signature/src/pq.rs`
- Modify: `crypto/consensus_signature/tests/aggregation.rs`
- Modify: PQ worker/privacy tests and `docs/pq-devnet-findings.md`

**Step 1: Write failing scheduler tests**

Cover three explicit work classes in this order: block/import verification, attestation-gossip
verification, and local aggregation proving. Prove that a full aggregation queue cannot reject a
reserved block request, block work runs before queued gossip/proving, each class is FIFO, all queues
and total queued evidence bytes are bounded before admission while the active job remains
separately per-job bounded, dropped queued receivers are skipped,
shutdown drains admitted work without blocking Drop, and a caught worker panic permanently poisons
the lifecycle and resolves every queued receiver.

**Step 2: Verify RED**

Expected: `AggregationService` has only one undifferentiated `aggregate` entry point backed by a
single `sync_channel(1)`.

**Step 3: Implement one bounded priority scheduler**

Keep `aggregate(job)` as the low-priority proving API. Add an explicit verification API accepting
only `Block` or `Gossip` admission classes; do not expose arbitrary numeric priority. Default BLS
executes immediately and ignores scheduling. PQ validates and owns each job before enqueueing it.

Replace the single channel with one private mutex/condition-variable scheduler owned by the same
512 MiB worker. Give block verification reserved capacity, gossip bounded capacity, and aggregation
one queued slot. Also cap total queued encoded evidence bytes with checked accounting so count
bounds cannot retain many maximum-size jobs. The worker always pops block, then gossip, then local
proof, checking receiver cancellation at the last safe point. Once backend work begins it remains
non-cancellable. On panic, poison the process lifecycle, return `WorkerPanicked` to the active
request, and resolve or drop every queued response as `WorkerStopped`.

Freeze the first conservative queued-only budgets at two block jobs/1 MiB, four gossip jobs/2 MiB,
and one local aggregation job/8 MiB, with an 11 MiB checked global sum. Each verification slot can
therefore hold one maximum 512 KiB evidence envelope and every class owns its byte budget: lower
classes cannot consume block reservation. An active job is no longer queued and is separately
bounded by the existing 8 MiB per-job cap, so the maximum retained evidence is 19 MiB plus bounded
job metadata. Admission must opportunistically purge cancelled queued receivers before applying
these limits, while the worker repeats the cancellation check at the last safe point.

Process all jobs for one imported block sequentially in later tasks; fan-out would self-saturate the
bounded scheduler. Priority does not pre-empt an already-running proof. Record that limitation and
start the devnet with 120-second slots unless release-build measurements show that another setting
has sufficient margin. This is an initial test setting, not a latency or liveness guarantee.

**Step 4: Verify and commit**

Run deterministic fake-worker scheduler tests, the real AVX2 recursive proof smoke, scalar and AVX2
Rust 1.88/Clippy checks, all-feature checks, default BLS compatibility, formatting/sorting/diff, and
the mandatory workspace check.

```bash
git add crypto/consensus_signature Cargo.lock \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "feat: prioritize PQ signature verification"
```

### Task 5.3b: Add narrow prepared and verified PQ consensus requests

**Prerequisites:** Tasks 5.1a, 5.2a, and 5.3a.

Do not retrofit PQ into BLS `SignatureSet` or `BlockSignatureVerifier` in this slice. They are
synchronous, decompressed-key-oriented, and batch-oriented; the PQ boundary is contextual,
asynchronous, bounded, and one-time-ID-aware.

**Files:**

- Modify: `consensus/state_processing/Cargo.toml`
- Create: `consensus/state_processing/src/pq_profile.rs`
- Create: `consensus/state_processing/src/pq_verification.rs`
- Modify: `consensus/state_processing/src/lib.rs`
- Modify: `testing/pq_devnet/Cargo.toml`
- Create: `testing/pq_devnet/tests/pq_consensus_verification.rs`
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write failing owned-request and adversarial tests**

Add domain-specific owned transitions, not a public `(domain, duty, root)` crypto escape hatch:

- `PreparedPqBlockProposal -> VerifiedPqBlockProposal` for gossip;
- `PreparedPqBlock -> VerifiedPqBlock` for proposal, RANDAO, and every included attestation;
- `PreparedPqAggregateAndProof -> VerifiedPqAggregateAndProof` for selection proof, outer signature,
  and the sealed inner `VerifiedPqAttestation`.

The verified wrapper owns the exact object (or an `Arc` to it), so it cannot be paired with another
block/aggregate after verification. Assert prepared values are owned, `Send`, and contain no state
or cache reference. Their fields and constructors must remain private.

Cover valid proposal, RANDAO, raw single, recursive aggregate, selection proof, and outer aggregate
signature; wrong root, leaf, proposer/aggregator key, signer bits/set, malformed/truncated/oversized
evidence; structural failure before unavailable backend submission; mixed valid/invalid request
ordering; and stable peer-invalid versus local failure classification.

**Step 2: Implement a feature-isolated verification module**

Add `state_processing/pq-verification`, implying `pq-attestation` but still excluding the normal
BLS transition/deposit/sync/Gloas graph. Reuse one immutable `PqValidatorKeyCache`. Validate every
attacker-controlled index, committee, bitfield, profile, and cap before cloning evidence. Derive
each semantic claim centrally:

- proposal domain and proposal-slot `BeaconBlockProposal` leaf;
- epoch-bound RANDAO signing root with the proposal-slot `RandaoReveal` leaf;
- target-epoch attester domain with the attestation data-slot leaf;
- selection-proof and aggregate-and-proof roots with the aggregate data slot and their distinct
  duty IDs.

Submit jobs sequentially through the reserved Block/Gossip scheduler classes, release state/cache
locks first, and mutate observed/pool state only after the sealed transition succeeds.

Keep hash-chain/hash-onion RANDAO as a future versioned profile. V1 retains the frozen RANDAO duty
and 14-leaf layout. A hash-chain profile needs a genesis commitment, transition and wire rules,
rollback/backup policy, and must not silently renumber V1 leaves.

**Step 3: Verify and commit**

Implementation evidence: RED first failed on the absent owned proposal API, then on the absent
full-block/aggregate transitions, unselected-aggregator admission, and target/slot epoch mismatch.
The final scalar isolated suite passed 12/12. The serialized journal-backed AVX2 test passed 1/1 in
300.83 seconds with 1,284,288 KiB peak command-tree RSS and zero swaps; it covers the complete valid
claim set plus wrong root/leaf/key/signer-set and deterministic mixed-request ordering. Direct
`state_processing` feature tests are not an isolation signal because its unconditional dev
dependencies feature-unify the BLS graph; use the `pq_devnet` normal-dependency harness and
`cargo check --lib`/normal-edge graph checks for this profile.

Review follow-up RED/GREEN evidence: an absent dedicated proposal-epoch variant failed to compile,
then production preparation mapped it peer-invalid; absent evidence-work and error-mapper seams
failed to compile, then whole-object preflight reported zero evidence work and the real mapper
covered every backend class. Temporary RANDAO-first and outer-first mutations failed the real AVX2
precedence assertions with the wrong components; restored proposal/RANDAO/attestation and
selection/inner/outer order passed. The test-only seams require the separate
`pq-verification-testing` harness feature and cannot construct jobs or tokens.

Final preflight RED/GREEN: once the counter included `BeaconState::is_aggregator`'s PQ selection
proof SSZ serialization, the malformed-inner test failed with one evidence touch. Moving
eligibility/hash after the independent inner and outer structural preflights restored zero without
adding a borrowed public signature accessor.

Final quality RED/GREEN split proposal structural validation from its complete-block tree hash: the
malformed-final-attestation case first observed one evidence-work unit and now observes zero. It
also moved the outer aggregate root behind selection eligibility: a structurally valid unselected
aggregate first observed two units and now observes exactly one selection-proof serialization.
`PqConsensusError::source` now exposes direct and attestation-nested `SigningIdError` and
`AggregationError` causes, while peer-invalid and plain local terminal errors have no source; its
RED first returned `None` for `SlotOutOfRange`. The all-features library and compile-fail privacy
audits retain private constructors, fields, and evidence replacement.

Run the isolated AVX2 harness, default BLS state-processing regressions, Rust 1.88, warnings-denied
Clippy, graph isolation, formatting/sorting/diff, and the mandatory workspace check.

```bash
git add consensus/state_processing testing/pq_devnet Cargo.lock \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "feat: verify PQ consensus signing requests"
```

### Task 5.3c: Require a sealed verified block at the PQ transition boundary

**Prerequisites:** Task 5.3b.

Add a `state_processing/pq-transition` feature that reuses the ordinary unsigned transition logic
behind a `VerifiedPqBlock` entry point. Do not copy the state transition and do not expose a public
PQ `NoVerification` flag.

The first V1 profile is Electra from genesis with a fixed 16-validator registry. Explicitly reject
deposits/deposit requests, proposer and attester slashings, voluntary exits, BLS-to-execution
changes, withdrawal/consolidation requests, Fulu/Gloas, and non-empty blob commitments before
backend work. Require stable zero-deposit `eth1_data`. Preserve normal execution-payload validation,
slot/epoch processing, fork choice inputs, justification/finalization, and forward range-sync block
verification.

For sync committees, accept exactly zero participant bits plus canonical absent PQ evidence. Reject
zero bits with raw/aggregate evidence and any set bit with absent/raw/aggregate evidence. Then run
the ordinary sync reward/penalty accounting for all false positions without invoking PQ crypto or
consuming a leaf.

Implemented behind `pq-transition`, which strictly depends on `pq-verification`. The public block
entry point consumes `VerifiedPqBlock` and accepts no raw block, caller spec, block-root switch, or
consensus context. Full-block preparation first rejects the frozen-profile and unsupported body
shapes, then binds the capability to a canonical pre-state root and an owned clone of the exact
`ChainSpec` before materializing evidence. Transition recomputes the state root, repeats preflight,
constructs a fresh context, and hardcodes parent-root verification before entering the private
shared unsigned block core. The ordinary BLS wrapper and its public strategies are unchanged; PQ
does not compile or re-export the BLS block verifier, signature-set modules, or a public
`NoVerification` route.

The shared profile now requires exactly 16 validators, Electra at genesis, no Fulu/Gloas schedule,
zero deposit root/count/index, and empty Electra pending deposit/partial-withdrawal/consolidation
queues. Peer-controlled unsupported body fields and every noncanonical sync bit/evidence pairing
are rejected before evidence work. A profile-checked PQ slot wrapper reuses normal slot and epoch
processing; the PQ epoch branch makes the impossible pending-deposit path fail before mutation but
retains ordinary justification/finalization, rewards, resets, cache rotation, and sync committee
rotation. Canonical empty sync input reaches the ordinary accounting function with all false
positions and no sync verification job.

TDD began with an unresolved `per_block_processing_pq` import. Scalar tests cover exact-slot and
16-validator bounds, Fulu/Gloas schedules, every unsupported operation, all sync pairings, all
zero-deposit/pending-state invariants, and epoch-boundary processing. Compile-fail tests prove that
raw blocks, BLS `NoVerification`, and caller-substituted spec/root/context inputs cannot cross the
boundary. The real AVX2 test binds a token to its exact same-slot state, rejects a changed RANDAO
pre-state before mutation, preserves the typed wrong-parent and invalid-timestamp errors, applies a
valid timely attestation, installs the ordinary temporary block header, and charges every false
sync position including duplicates and the proposer. An early execution RED
(`expected: 324, found: 24`) confirmed that the reused payload timestamp check was active before
the fixture added genesis time. A spec-binding sensitivity mutation then replaced the sealed
17-second-slot spec with a fresh default Electra spec and failed the otherwise-valid transition
with `expected: 324, found: 368`; restoring the token-owned spec accepted that block and preserved
the later typed `expected: 385, found: 384` mismatch. The final expanded run passed 1/1 in 462.75
seconds (7:43.06 command wall), peaked at 789,688 KiB RSS, and used no swap.

This slice preserves the existing in-state execution payload checks (parent hash, `prev_randao`,
timestamp, withdrawals, and blob limits). Calling Engine API `newPayload` remains Task 5.3e. The
hash-chain/hash-onion RANDAO remains a future versioned profile proposal; V1 still authenticates
the frozen signature-derived RANDAO duty and leaf.

Final review hardening removed the crate-wide PQ `dead_code` exemption. Default-only, Gloas-only,
and slow test helpers are now cfg-scoped individually, while the supported `pq-attestation`-only
feature omits `pq_pre_state_root` until `pq-verification` enables its consumers. Warning-denied
Rust 1.88 checks cover attestation-only, verification, transition, genesis, and all-feature builds.

```bash
git add consensus/state_processing testing/pq_devnet \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "feat: process sealed PQ blocks"
```

### Task 5.3d: Migrate RANDAO HTTP transport to the active individual signature

**Prerequisites:** Tasks 5.3b and 5.3c.

Introduce an active-backend serialized individual-signature transport: BLS remains exactly
`bls::SignatureBytes`, PQ uses strict `PqRawSignature`. Migrate `common/eth2`, block-production HTTP,
and validator block-service callers. Keep builder/relay registration keys BLS-specific. In PQ mode
reject `skip_randao_verification`; never substitute an empty PQ signature for BLS infinity.

### Task 5.3e: Integrate sealed PQ verification into BeaconChain

**Prerequisites:** Tasks 5.3b-d and the top-level PQ feature spine.

Rebuild an immutable `Arc<PqValidatorKeyCache>` from the 16-validator registry at startup; never
reinterpret or write the BLS `pkc` record. Add the singleton signature service to `BeaconChain`,
route block gossip/import/range sync and single/aggregate gossip through the prepared/verified
domain APIs, and preserve local failures as no-peer-penalty retryable outcomes. Explicitly disable
sync duty polling/gossip/contribution pools, slasher, light-client, checkpoint sync/backfill,
external builders/registrations, and unsupported APIs. Only after this slice is green wire both
attestation pools in Task 5.2b.

### Task 5.2b: Wire verified candidates into both beacon-node attestation pools

**Prerequisites:** Tasks 5.2a and 5.3e, including the compiling top-level PQ feature spine for the
affected beacon-node packages.

**Files:**

- Modify: `beacon_node/operation_pool/src/attestation_storage.rs`
- Modify: `beacon_node/operation_pool/src/lib.rs`
- Modify: `beacon_node/beacon_chain/src/naive_aggregation_pool.rs`
- Modify: `beacon_node/beacon_chain/src/beacon_chain.rs`
- Modify: beacon-chain startup/configuration and aggregate retrieval call sites
- Modify: related operation-pool, naive-pool, and block-production tests

**Step 1: Write failing real-caller tests**

Cover verified single and aggregate gossip insertion, candidate dominance, on-demand local aggregate
retrieval, block-selection retrieval, a concurrent arrival during proof construction, retry after
resource failure, pruning during proof, and restart with an intentionally ephemeral candidate pool.
Assert no method performs proving while holding an operation-pool or naive-pool lock.

**Step 2: Verify RED through the real PQ feature spine**

Expected: both pools still attempt synchronous BLS point mutation. Do not treat a narrow unit target
that omits either real pool as completion.

**Step 3: Replace both mutation paths with the coordinator**

Embed one shared coordinator/key-cache/service owner in `BeaconChain`. Route only the sealed
`VerifiedPqAttestation` returned by the Task 5.3e BeaconChain gossip path, using the domain
verification transition introduced in Task 5.3b, into candidate storage. Make PQ aggregate
retrieval async and on-demand; snapshot under locks, release them, await `PreparedAggregate`, and
then commit through the coordinator. Keep the default BLS pool and persisted `pkc` representation
byte-for-byte unchanged.

For the first V1 operation pool, use candidate-only policy: retain verified aggregate gossip, drop
dominated duplicates, and select maximal candidates for blocks. Do not synthesize cross-committee
proofs, do not prove during synchronous insert/get paths, and do not re-prove persisted candidates
during startup. Candidate state may remain ephemeral for the first devnet; restart recovery means
the signing journal remains safe and the pool refills from gossip.

**Step 4: Explicitly disable sync aggregation in V1**

Disable validator sync duties and beacon-node sync contribution gossip/aggregation at startup.
Block production must emit `SyncAggregate::empty()`: zero participant bits plus canonical absent PQ
evidence, consuming no XMSS leaf. Verification must accept exactly that pair, reject absent evidence
with any set bit, and reject raw/aggregate evidence with zero bits. Never emulate BLS infinity or
silently run the BLS sync path.

**Step 5: Verify both profiles and commit**

Run the real operation-pool, naive-pool, beacon-chain, and block-production suites in PQ and default
BLS configurations, plus networking-size and restart smoke tests affected by larger aggregate
evidence.

```bash
git add beacon_node/operation_pool beacon_node/beacon_chain \
  docs/plans/2026-08-18-pq-devnet-implementation.md docs/pq-devnet-findings.md
git commit -m "feat: aggregate PQ attestations in beacon pools"
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
