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
