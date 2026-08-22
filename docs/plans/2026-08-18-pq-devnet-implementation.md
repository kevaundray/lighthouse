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

Use backend-owned serialize/decode/skip-placeholder functions rather than a signature trait or
runtime backend enum. Centralize the v2/v3/v4/blinded query policy so default BLS URL ordering and
empty-parameter spelling stay byte-compatible, while PQ rejects verification skipping before URL
construction or network I/O. The HTTP server must use the same decoded-query policy at one source
boundary. If the full validator-services or BeaconChain PQ feature graph exposes deferred,
unrelated BLS-only services, verify this slice through the isolated normal-dependency `pq_devnet`
RANDAO transport harness and record the blockers; do not gate unrelated production modules merely
to manufacture a package-level green build.

### Task 5.3e: Integrate sealed PQ verification into BeaconChain

**Prerequisites:** Tasks 5.3b-d and the top-level PQ feature spine.

Rebuild an immutable `Arc<PqValidatorKeyCache>` from the 16-validator registry at startup; never
reinterpret or write the BLS `pkc` record. Add the singleton signature service to `BeaconChain`,
route block gossip/import/range sync and single/aggregate gossip through the prepared/verified
domain APIs, and preserve local failures as no-peer-penalty retryable outcomes. Explicitly disable
sync duty polling/gossip/contribution pools, slasher, light-client, checkpoint sync/backfill,
external builders/registrations, and unsupported APIs. Only after this slice is green wire both
attestation pools in Task 5.2b.

Local block production must use a separate sealed local-production RANDAO capability together with
sealed verified included attestations. It must never manufacture or reuse `VerifiedPqBlock`, which
authenticates a complete externally supplied signed block, and it must never enter the legacy
`NoVerification` path. The local capability binds the exact proposal slot, proposer, epoch-bound
RANDAO claim, V1 proposal-slot RANDAO leaf, signature, key cache, and spec needed by block assembly;
included attestations retain their own contextual verification tokens. The ordinary BLS
`ProduceBlockVerification` behavior remains unchanged outside the PQ profile.

#### Task 5.3e-b: Establish the PQ startup ownership spine

The first BeaconChain slice is intentionally startup-only. Add a real top-level
`lighthouse/pq-devnet` beacon-node profile, but stop it at a typed
`DeferredRuntimeIntegration` boundary before filesystem, database, network, HTTP, timer, execution
layer, or proof-worker side effects. Reject compile-time combinations with the ordinary full CLI,
full beacon-node runtime, or slasher backends. Validator-client support remains Task 5.3e-e.

The lower-level startup core must load or persist one exact canonical snapshot, strictly validate
the frozen 16-validator Electra-from-genesis profile, rebuild one immutable
`Arc<PqValidatorKeyCache>`, and accept the process's sole `Arc<AggregationService>`. Restart binds
the metadata, state, and block by slot and by recomputed canonical roots. It uses hierarchy `[0]`
(a full snapshot every slot), never invokes BLS block replay, and neither reads nor writes the
legacy `pkc` and `opo` records.

Programmatic `ClientConfig` preflight is required before all startup side effects. Only
`GenesisState` and `FromStore` are accepted; reject builders, weak-subjectivity/checkpoint modes,
archive/backfills, light-client service flags, optimistic finalized sync, validator monitoring,
slasher, Fulu/Gloas, and any store hierarchy other than `[0]`.

For this bounded slice, compile-time omit the ordinary BeaconChain gossip/import/production,
fork-choice, payload/builder/Gloas, sync-duty, slashing, monitoring, persistence, historical,
light-client, and worker modules; omit the network service/router/sync/subnet processors; and omit
HTTP API/metrics/timers and non-beacon-node CLI subcommands. The PQ operation pool is an ephemeral
ownership root only and exposes no fabricated insertion/retrieval behavior. Task 5.3e-c restores
network block-gossip and import callers, Task 5.3e-d restores external attestation gossip through
sealed verification, and later slices restore pool insertion, local production/APIs, and
validator-client duties. Default BLS module selection and behavior remain unchanged.

#### Task 5.3e-a: Seal local production before BeaconChain wiring

Implement `PreparedPqRandao -> VerifiedPqRandao` with block-class verification and owned immutable
cache/spec bindings. Derive the proposer from the bound state and slot; do not accept it from the
caller. A local block seal consumes a unique zero-state-root `BeaconBlock`, the verified RANDAO,
and exact-order `Arc<VerifiedPqAttestation>` values. Retain the attestation tokens' expected
`(validator index, public key)` signers so the seal can re-derive and compare bytes, claim, indices,
and keys without doing cryptographic work.

The consuming transition accepts no cache, spec, context, outer signature, or root-mode arguments.
It installs the active empty proposal placeholder internally, repeats pre-state and frozen-profile
preflight, uses the shared private unsigned core with parent-root checking, and returns the unique
block plus fresh context for post-state-root installation. Keep imported `VerifiedPqBlock`
unchanged and independently verify the subsequently signed imported block in the real AVX2 test.
Hash-chain/hash-onion RANDAO remains a future versioned proposal and must not change the V1 claim or
14-leaf numbering.

```bash
git add consensus/state_processing testing/pq_devnet docs/pq-devnet-findings.md \
  docs/plans/2026-08-18-pq-devnet-implementation.md
git commit -m "feat: seal PQ local block production"
```

#### Task 5.3e-c: Import external blocks through one sealed PQ boundary

Keep the ordinary BLS router, batch verifier, backfill, and historical-replay modules omitted.
Restore a PQ-only block processor whose gossip, RPC, lookup, and forward-range ingress all construct
an explicit source request and enter the same complete verification path. Advance an owned clone of
the exact canonical parent state, run deterministic execution-payload checks, prepare and verify the
full block (proposal, RANDAO, and every included attestation) with the process-owned aggregation
service, and consume `VerifiedPqBlock` in a transition that owns the advanced state and internally
checks the signed post-state root. No observed or canonical state changes before this output exists.
Acquire one of two chain-owned import admissions with a non-waiting `try_acquire` before any of
that work. Keep the admission alive through proof, Engine, and persistence, including any detached
blocking phase after async cancellation. Run skipped-slot advancement, payload/job preparation,
post-proof transition/root hashing, range hashing, and atomic database persistence on the required
process-owned blocking executor. A forward range holds one admission, is capped at eight raw
blocks, and never verifies more than one block at a time.

For gossip, begin a generation-bound `(slot, proposer) -> block root` lifecycle only after the
sealed output exists. The unique first capability is pending propagation; concurrent duplicates
cannot commit. Dropping it permits a new propagation claim, while only a failure after propagation
permits a commit-only retry. A different root is an equivocation and is not propagated in V1. Call
the chain-owned Engine notifier after an accepted gossip block has been forwarded. Under the same
single-writer gate, every gossip/RPC/lookup/range commit rechecks exact root/generation authority;
external roots reserve bounded observation capacity before Engine, without evicting terminal
evidence. Only `VALID` can commit. `INVALID` and `INVALID_BLOCK_HASH` are exact-root terminal without
peer downscore, while `SYNCING`, `ACCEPTED`, transport, and database failures are retryable local
outcomes. Successful commits install the current root as committed and prune older slots while
retaining the current-slot equivocation boundary. Atomically persist the sealed block, exact state
snapshot, and head metadata before swapping the in-memory canonical head. Forward ranges preflight
their entire parent/slot chain, then verify, execute, and commit blocks strictly sequentially and
return the exact imported prefix on failure.

After Engine returns `VALID`, transfer the import gate, admission, exact observation authority, and
sealed output into one owned blocking completion. That completion must finish the atomic database
write, in-memory head publication, and committed-observation pruning even if its awaiting network
caller is canceled. A database failure performs no head swap and restores retryable observation
state before releasing either permit.

The selected top-level binary remains at its explicit deferred-runtime boundary until the remaining
network-service, local-production/API, and validator-duty slices are assembled. This task provides
the real consuming BeaconChain and PQ network-processor call chains without exposing raw transition,
raw persistence, `NoVerification`, per-call Engine substitution, BLS batch verification, checkpoint
sync, backfill, or historical reconstruction.

#### Task 5.3e-d: Verify external attestation gossip through sealed PQ boundaries

Keep the ordinary BLS attestation verifier, batch verifier, pool insertion, fork choice, local
aggregation, production, HTTP API, and validator-client duties unchanged or omitted under the PQ
runtime graph. Extend only the PQ network processor with awaited unaggregated-attestation and signed
aggregate-and-proof gossip entry points.

The unaggregated wire boundary must use a private-field
`PreparedPqSingleAttestation -> VerifiedPqSingleAttestation` transition. The prepared value owns the
exact `SingleAttestation`, its derived Electra attestation, signer/claim bindings, and verification
job; callers cannot pair a generic prepared job with different raw wire bytes. Signed
aggregate-and-proof gossip continues to use the existing private-field
`PreparedPqAggregateAndProof -> VerifiedPqAggregateAndProof` transition. Both paths submit only
`VerificationClass::Gossip` work to the process-owned priority `AggregationService`; they never
invoke aggregate proving or create another service.

Acquire one of a small, fixed number of chain-owned gossip admissions without waiting before
snapshot or preparation work, and retain it through proof and observation. Perform a prune-aware
key/subset duplicate precheck before loading a block, state, job, or evidence. Then clone the exact
canonical head and run propagation-slot, canonical-root/target, subnet, committee, cache, bounded
referenced-head-to-attestation-slot advancement, and owned-job preparation on the chain-owned
blocking executor. Release all head, cache, and observation borrows before awaiting the aggregation
service. After proof, repeat timeliness, bounded canonical ancestry, and duplicate checks before
observation; a canonical head advance is accepted while a lineage change or proof that outlives its
gossip window is a local ignore without peer blame. Receipt-time future/past ambiguity is also a
local ignore rather than a peer penalty; future work remains retryable while expired work does not.
Invalid structure, context, or evidence is peer-attributable; unavailable head/clock/executor and
proof-service resource failures are local and unpenalized.

After successful proof verification, atomically transition the exact attestation identity from
unseen to pending with a fresh generation and return a generation-bound propagation capability.
Only that first capability can be marked propagated and consumed into sealed provenance for the
later Task 5.2b coordinator. Dropping it before propagation rolls pending back to unseen and releases
its admission; concurrent duplicates cannot propagate or consume it. Aggregate reservation updates
the aggregator-per-target-epoch and attestation subset/superset boundaries together under one mutex,
so finalization or rollback cannot expose a partial observation. Transfer the non-waiting ingress
permit into the capability and retain it until propagation finalization or rollback. Bound the
observation map from the exact 16-validator registry and the propagation-slot window, prune expired
entries, and never evict current evidence. No observation changes occur before proof success, and no
lock is held across blocking work or an await. Stale-entry pruning may occur during the cheap
precheck, but no live pending/observed claim is created or replaced before proof success. Generation
allocation is checked and fails closed on exhaustion.

This slice ends at `Accept`/`Ignore`/`Reject` plus the sealed verified provenance required by the
later coordinator. It does not insert into either attestation pool, claim fork-choice processing,
or fabricate successful downstream work. Exercise the real awaited network entry points for
unaggregated and aggregate gossip with valid and invalid AVX evidence, pending duplicates,
propagation-capability cancellation/retry, and consuming sealed provenance. Run the prune,
generation, timing, target-root, bounded-advancement, canonical-lineage, single-conflict, and atomic
aggregate-index lifecycle checks in the runnable `pq_devnet` route. Local service errors retain
typed no-peer-penalty mapping; this slice does not claim an operation-pool/fork-choice insertion or
local production/API result.

#### Task 5.3e-e1: Produce a sealed local full block from the chain-owned execution layer

Restore only the BeaconChain local-production core in this slice. Do not enable the ordinary HTTP
API, validator-services, validator-client process, network service, builders, registration, sync
duties, or the top-level runtime. Those graphs remain intentionally deferred to e-e2 through e-e4.

Acquire one chain-owned non-waiting production admission before cloning the canonical snapshot or
doing proof work. On the process-owned blocking executor, clone the exact head state, advance it
sequentially to the requested proposal slot with `per_slot_processing_pq`, derive the proposer, and
call `prepare_pq_randao`. Reject a past/future or excessively distant request without touching the
execution layer. Await `PreparedPqRandao::verify` on the process-owned `AggregationService`; this is
the only RANDAO verifier and it submits at `VerificationClass::Block`. An invalid reveal is a typed
request error, while proof-service, executor, clock, or admission failures are local and retryable.
No state, head, cache, or admission borrow is held across the proof await.

Only after RANDAO verification succeeds may production request payload/body data. Extend the one
execution capability injected into `BeaconChainBuilder` so production uses its immutable
`Arc<ExecutionLayer>` to request a **local full** Electra payload. It must not consult a builder or
accept a per-call payload strategy. A deterministic fake may be injected only through the existing
`pq-startup-testing` builder seam. Derive timestamp, previous RANDAO, parent execution hash/gas
limit, withdrawals, proposer fee-recipient/gas-limit lookup, and fork-choice parameters from the
owned advanced state and exact canonical parent. The execution-layer entry point must force the
local `engine_forkchoiceUpdated`/`engine_getPayload` path and return full payload contents; blinded,
builder, Gloas, and wrong-fork contents are rejected.

On the blocking executor, assemble one unique Electra `BeaconBlock` with zero `state_root`, the
exact verified RANDAO, exact canonical parent, requested graffiti, unchanged zero-deposit eth1 data,
canonical empty sync aggregate, empty unsupported operations, and only attestations accompanied by
their sealed `Arc<VerifiedPqAttestation>` provenance. The initial slice passes zero attestations.
Consume the block, `VerifiedPqRandao`, and provenance in `prepare_pq_local_block`, then consume the
result in `per_block_processing_pq_local` against the owned advanced state. Compute the post-state
root, install it into the unique returned block, and return full V3-compatible block contents with
the exact empty blob/proof lists from the local payload. Do not sign, persist, publish, or mutate the
canonical head. Recheck the exact canonical parent before returning so a head change during proof
or Engine work produces a terminal stale-production result rather than a misleading proposal.

Write RED tests before each production change. Pin RANDAO-Block-priority-before-payload ordering,
invalid RANDAO failures with zero payload calls, unique zero-root sealing, canonical empty
sync, zero-attestation provenance, full local payload only, post-state-root correctness, stale-head
recheck, admission release on cancellation, blocking-executor heartbeat behavior, and a real AVX
round trip in which the returned unsigned block is proposal-signed and accepted by the existing
Task 5.3e-c imported-block path. Preserve all default BLS tests and feature selection.

Review follow-up evidence (2026-08-19): RED tests exposed a caller-thread state clone, a nonzero
`blob_gas_used` payload accepted after recomputing its execution hash, ambiguous initial/late slot
outcomes, missing exact-request response binding, and a wrong-fork response admitted by the common
payload validator. The production branch now uses the real `Arc<ExecutionLayer>` local FCU/getPayload
path with a test-only adjacent input observer; the MockEngine sees the exact parent while a configured
builder sees zero calls. The scalar focused command passed 1/1. The AVX2 focused
`pq_block_production` test file passed 16/16 in 541.92 seconds, including the real Engine path,
blocking heartbeat, cancellation/admission, typed slot outcomes, pure mutation matrix, and sealed RPC
import. A final warning-denied AVX2 `--no-run` compile of that same target completed successfully in
47.98 seconds. Parent verification additionally passed warning-denied default state-processing,
execution-layer, and BeaconChain checks; scalar and AVX2 top-level PQ checks; the default
state-processing tests; the execution-layer generator regression; focused BeaconChain and
execution-layer Clippy with only documented baseline allowances; formatting, dependency sorting,
diff hygiene, and the PQ graph-exclusion audit. The final Rust 1.88 warning-denied workspace check
passed after this documentation update.

Final re-review sensitivity (2026-08-19): the test-only observer is constructed only after the real
`PayloadParameters` exists and reads the fork, FCU, payload attributes, and gas inputs from that
object. Temporarily changing the actual parameter fork to Fulu made the observer's Electra assertion
fail before Engine handling; restoring Electra passed the exact real-Engine test 1/1. Invalid RANDAO
and stale-head behavior tests now explicitly assert terminal classification; a temporary retryable
mutation failed the shared classifier test. Those two exact behavior tests passed 1/1 each, and the
focused warning-denied AVX2 `--no-run` compile passed. The full 16-test file was not rerun because
neither final change alters the proof or Engine behavior already covered above.

#### Task 5.3e-e2a: Seal local HTTP publication and add an acknowledged broadcaster

Do not route locally submitted validator blocks through either the RPC importer or the inbound-gossip
source. Add an honest `Publish` source to the existing e-c verification boundary and preserve the
exact immutable signed block inside a publish-specific propagation capability. Reuse the complete
proposal/RANDAO/attestation proof and owned post-state transition, but distinguish an already
committed root from an Engine-rejected or otherwise terminal root at the public publication seam.
Committed duplicate publication is idempotent success; a prior terminal rejection is conflict.
Because the canonical block root excludes the proposal signature, restart idempotence requires full
signed-block equality with the exact current persisted head. Linear V1 retains no historical signed
identity index: an older pruned committed block follows the ordinary stale/parent-unavailable policy.

Add one bounded, process-owned block-broadcast command channel. Each command owns the exact block
from the sealed capability and a one-shot acknowledgment. A positive acknowledgment means that the
network worker accepted that exact immutable block for gossipsub publication; enqueueing an ordinary
unbounded `NetworkMessage::Publish` is not sufficient. The real network adapter remains deferred to
e-e4, while the isolated test actor returns deterministic acknowledgments through the same bounded
channel. Do not expose a per-request broadcaster strategy.

After non-waiting admission, move the raw block, admission, sealed propagation capability,
broadcaster request, Engine notification, and atomic database/head commit into one detached
process-owned task. Await broadcast acknowledgment before consuming `after_propagation`; only then
run the existing chain-owned Engine and persistence path. Caller cancellation never cancels this
owned operation or releases its admission early. A dropped/negative broadcaster acknowledgment
drops the unpromoted capability and restores propagation retryability; Engine `SYNCING`, transport,
or store failure after successful broadcast retries commit without rebroadcast. Once Engine returns
`VALID`, database/head completion retains the existing cancellation-independent guarantee. Add
non-waiting HTTP publication admission before body buffering, a bounded broadcaster queue, and
checked body limits so neither raw requests nor verified post-states accumulate waiters.
If an RPC/lookup import resolves the same observation while publication awaits its acknowledgment,
promotion reconciles the current state: exact signed current head is committed, exact-root Engine
rejection is terminal, and a current different root is equivocation. Configuration-time body-limit
overflow is a distinct nonretryable startup error, never task unavailability.

Exercise the source/capability and broadcaster lifecycle before adding routes: exact block ownership,
pending and committed duplicates, terminal rejection, equivocation, queue/admission cap and cap+1,
failed acknowledgment and rebroadcast retry, post-broadcast Engine/store retry without rebroadcast,
caller cancellation at broadcaster and Engine barriers, event ordering, and restart-visible commit.

Focused implementation evidence (2026-08-19): warning-denied scalar publication tests passed 8/8
and the existing import lifecycle tests passed 20/20. The warning-denied AVX2 production target
compiled, and exact behavior tests passed for acknowledged broadcast-before-Engine plus committed
duplicate (1/1), `SYNCING` then `VALID` commit retry without rebroadcast (1/1), dropped and rejected
broadcast retry (1/1), Engine terminal rejection without retry (1/1), caller cancellation with exact
admission bounds through a pending Engine call and restart-visible commit (1/1), canceled atomic
persistence failure followed by commit retry without rebroadcast (1/1), and a proposal-signed wrong
post-state root rejected before broadcast/Engine (1/1). The full AVX2 file and broad workspace gates
were intentionally not run in this staged e-e2a cycle.

Review remediation evidence (2026-08-19): exact signed persisted-head publication after restart was
RED as stale and GREEN as committed (1/1, 79.11s), while a mutated proposal signature with the same
canonical message root was not committed. Same-root RPC commit during the broadcast-ack barrier was
RED as local invariant and GREEN as committed (1/1, 78.99s); same-root Lookup Engine rejection was
RED as local invariant and GREEN as terminal (1/1, 79.02s), both with exactly one Engine call. Two
fully proposal-signed different-root publications from the same slot/proposer produced equivocation
before a second broadcast or Engine call (1/1, 130.65s); temporarily mapping equivocation to pending
made that exact test fail (1/1 expected RED, 131.07s) before restoration. Body-limit overflow and
cross-root promotion reconciliation had focused scalar REDs, then passed in the 8/8 publication
suite. A final deterministic gate race held RPC inside Engine, acknowledged and promoted Publish
behind it, then let RPC persist first: the pre-fix Publish result was terminal, while the fixed path
returned committed with exactly one Engine call (1/1, 79.20s). The three exact same-root
acknowledgment-race tests passed serially (3/3, 236.32s). Warning-denied AVX2 no-run compilation
passed after these changes; broad gates remain deferred.

#### Task 5.3e-e2b: Expose the isolated PQ full-V3 HTTP production and publish routes

Create a feature-empty-by-default `beacon_node/pq_http_api` crate instead of enabling the ordinary
`http_api` crate, whose monolithic BLS/slasher/router graph remains incompatible and exposes many
unsupported endpoints. The narrow crate owns an immutable `Arc<BeaconChain>`, the e-e2a publication
facade, and its process `TaskExecutor`; e-e4 supplies the real broadcaster receiver and server
binding. Do not add this crate to `beacon_node`, `client`, or `lighthouse` until e-e4.

Expose only `GET /eth/v3/validator/blocks/{slot}` for local full production and
`POST /eth/v2/beacon/blocks` for full signed-block publication. Decode the active PQ RANDAO transport
and always verify it; reject `skip_randao_verification`, V2/V4 production, blinded endpoints,
builder boost/selection, Gloas, registration, sync, duties, and unknown query fields by absence or
typed rejection. Return the normal full V3 JSON/SSZ shape with Electra consensus version,
`execution_payload_blinded = false`, exact execution value, and zero consensus value for the
zero-attestation slice.

The current devnet continues to use its slot-bound PQ RANDAO transport. A hashchain RANDAO proposal
exists as a possible follow-up design, but e-e2b neither selects nor implements that alternative.

Acquire publication admission and enforce content-length limits before buffering. Retain at most
4,096 bounded transport chunk objects while streaming, reject a checked next length as soon as it
exceeds either the declaration or media cap, then fallibly allocate and coalesce the contiguous body
only on the blocking executor. The retained-memory bound covers both raw chunks and the temporary
contiguous decode copy, bounded chunk metadata, and fixed bookkeeping across both admissions. Decode
JSON/SSZ on that blocking executor, require Electra plus the supported content type/version headers,
require full `BlockContents` with explicit empty blob/proof lists, and reject block-only, blinded,
Fulu/Gloas, or nonempty sidecar inputs before verification/broadcast. Match every
production/publication error explicitly: malformed/profile/PQ-invalid input is 400;
stale/past/expired/equivocation/terminal conflict is 409; admission or broadcast capacity is 429;
oversized/unsupported media is 413/415; retryable proof/clock/Engine/broadcast/store/task failures are
503; successful and already-committed publication is 200; an exact pending root is 202. Do not
collapse this table through a broad `is_retryable` fallback.

Cover actual awaited Warp filters and `BeaconNodeHttpClient` JSON/SSZ round trips, standard headers
and metadata, every unsupported route/option/version, body/query/admission cap and cap+1, signed and
root/context mutations before broadcast, successful publication ordering, cancellation and retry
mapping, committed versus terminal duplicates, and one serialized real AVX route through restart.

Focused implementation evidence (2026-08-19): the new `pq_http_api` crate is feature-empty by
default and remains absent from `beacon_node`, `client`, and `lighthouse`. Its warning-denied scalar
suite passed 15/15, covering native Warp 411/413 recovery, raw-query cap/cap+1, contextual JSON
trailing data, actual media-specific body-length recheck, full-Electra JSON/SSZ decoding with explicit
empty sidecars, exhaustive production/publication status classes, SSZ V3 headers, bounded streamed
body collection, single-large-chunk blocking/heartbeat sensitivity inside the shared coalescer,
deterministic allocation-failure-to-503 mapping, raw-plus-copy retained-memory accounting, and
response permits retained through body clones and the exact two-response cap.
Warning-denied default and `pq-devnet` crate checks, focused Clippy, formatting, and the warning-denied
AVX2 production-target no-run compile passed. The strict query/header/version/body policy route passed
1/1 in 79.81 seconds, including malformed/overflow slots and duplicate queries without payload or
Engine calls. The incomplete-body ephemeral-server route held two streaming clients until the
testing-only two-second timeout, rejected cap+1 with 429 before polling its body, returned 408 for the
stalled requests, and immediately recovered its permits (1/1 in 82.01 seconds). The serialized
real-chain route passed 1/1 in 133.43 seconds: `BeaconNodeHttpClient` completed full V3 JSON and SSZ
production; block-only, invalid-signature, and proposal-signed wrong-state-root publications failed
before broadcast/Engine; a padded two-megabyte Warp request reached the shared blocking coalescer,
preserved an async heartbeat, and survived HTTP caller cancellation; and the exact
broadcast preceded the detached Engine/database/head commit. Client JSON/SSZ duplicates and a restart
SSZ duplicate were idempotent. Awaited route tests additionally covered live equivocation plus
SYNCING-to-VALID retry without rebroadcast (1/1 in 132.56 seconds), and terminal Engine rejection with
no duplicate Engine call. Broad workspace gates and the real network/server adapter remain deferred
pending review and e-e4.

#### Task 5.3e-e3: Add a proposer-only PQ validator-client service

Compile a dedicated PQ proposer service instead of the ordinary validator-services duty graph. Do
not accept a caller-supplied slot, public key, validator index, or assignment capability: those
values could cause an untrusted caller to consume a journal-backed one-time RANDAO or proposal leaf.
Extend the isolated PQ HTTP facade with the standard bounded
`GET /eth/v1/validator/duties/proposer/{epoch}` route. It serves only the current or next epoch,
derives every `(slot, validator_index, pubkey)` tuple from one exact canonical PQ snapshot on the
chain-owned blocking executor, reports Electra and `execution_optimistic = false`, binds the
dependent root to that snapshot, and rechecks the head before returning. A changed head or local
clock/state failure is a retryable `503`; malformed, past, or too-far-future requests are rejected
without state work.

The proposer service owns one configured `BeaconNodeHttpClient`, an immutable provisioning-derived
map of local `(pubkey, validator_index)` pairs, its slot clock, validator store, task executor, and a
nonwaiting capacity-one admission. Its only scheduling entry point is
`try_propose_current_slot()`: it reads the current slot itself, fetches fresh standard duties, and
intersects an exact current-slot duty against the immutable local map. Repeated same-slot calls
coalesce; no caller can select a signing identity and no admission waiter queue is permitted. The
admitted operation is detached and retains its permit across all proof, HTTP, signing, and publish
work, so dropping the caller cannot free capacity or abandon an in-flight journal operation.

The production profile requires a 300-second slot and uses one absolute deadline at 285 seconds
after slot start, leaving a 15-second safety margin. Duty fetch, journal-backed RANDAO signing, and
SSZ-first/full-V3 production share a 120-second phase budget; slashing-protected block signing has a
second 120-second phase budget; exact signed publication retries use the remaining time, capped at
45 seconds. The journal-backed RANDAO and proposal-signing futures are never wrapped in cancelling
timeouts: check the phase/global deadline before starting, await them non-cancellably in the detached
operation, record an overrun, and do not start the next phase after expiry. Production HTTP calls are
bounded, but JSON fallback is initially allowlisted only after a completed successful response whose
SSZ or response decoding is incompatible, plus a connection failure proven to precede request
transmission. Never fall back after a timeout, ambiguous transport failure, semantic metadata/body
error, or any HTTP status including 400, 406, 409, 415, 429, and 503. Require
Electra/full/unblinded/zero-consensus metadata and the exact duty proposer index, sign through the
existing slashing-protected PQ full-block path with its database transaction offloaded to a
PQ-owned blocking task, then publish the same signed contents through V2 SSZ with an allowlisted JSON
fallback. Do not compile or start builder registration, remote signing, distributed selection,
attestation, aggregation, sync-committee, preparation, payload-attestation, or proposer-preference
services in this slice.

Exercise the real `BeaconNodeHttpClient` against the e-e2 ephemeral server. Cover truthful
current/next duties and stale-head suppression; a caller's inability to select slot/key/index;
capacity-one cancellation and same-slot coalescing; deadline expiry at every stateful boundary;
byte-identical RANDAO and signed-block fallback/retry; invalid, wrong-version, blinded, nonzero
consensus-value, and wrong-proposer responses; publication retry/disposition mapping; and a complete
propose/sign/publish import. The current V1 profile continues to use the signature-derived,
proposal-slot-bound RANDAO leaf. A hash-chain/hash-onion RANDAO remains a future versioned proposal
that would require a committed seed and new state/wire transition.

Focused implementation evidence (2026-08-19): the warning-denied proposer-service suite passed
37/37 unit tests plus the downstream typed-error visibility test. The real current-thread
store/client tracer passed 1/1 in 143.24 seconds and exercised
SSZ-invalid-to-JSON V3 production, exact RANDAO and proposal signing, direct intended-URL connection
fallback from V2 SSZ to one retained JSON encoding, byte-identical `202` to `200` JSON retries,
and the no-reproduce/no-resign boundary. The same tracer paused inside the real blocking publication
encoder, observed an unrelated async heartbeat, retained cap-one admission, and rejected HTTP work
after the already-captured 45-second deadline expired. Redirects are disabled for the service-owned
client constructed from the caller's configured builder, so a redirect cannot turn a transmitted
request into purported pre-send fallback evidence. Endpoint-specific duties and V3 response paths
bound declared bytes, streamed bytes, and fragment count before coalescing and contextual decoding
on the owned blocking executor; JSON body metadata must agree exactly with independent response
headers. A real authenticated 16-validator composition passed 1/1 in 2288.49 seconds through the
actual PQ HTTP GET/POST routes, acknowledged broadcaster, sealed verification, Engine `VALID`,
atomic database/head commit, exact signed restart restoration, and idempotent restart publication
without a second broadcast or Engine call. Publication now uses closed strict-client raw POSTs,
classifies only the actual HTTP status, and drops the untrusted response body without generic
`ErrorMessage` parsing. Preparation timeouts cover only bounded HTTP streaming; coalescing and
decode are awaited non-cancellably while the detached operation retains cap-one admission, then the
same slot-clock deadline classifies any overrun. Signing-method shutdown/join failures remain typed
transient executor failures, while context, signing-ID, and invalid-signing-request failures are
typed terminal errors nameable from the crate root. The PQ proposer dependency graph excludes
`beacon_node_fallback`, while the default validator-store graph continues to include ordinary
doppelganger polling. Warning-denied PQ-production, default-validator-store, and default `eth2`
checks passed; broad workspace gates remain deferred until independent review.

#### Task 5.3e-e4: Assemble the PQ network, HTTP, and proposer runtime

Replace the top-level `DeferredRuntimeIntegration` boundary only after e-e1, e-e2a, e-e2b, and e-e3
are green. Do not re-enable `client::builder`, the ordinary network service/router/sync/subnet
manager, `http_api`, validator services, or the full CLI to obtain a superficially complete graph.
Assemble the already sealed components through a PQ-only runtime owner in the following vertical
slices.

##### Task 5.3e-e4a: Add a result-bearing live-block PQ network worker

Add a narrow `network::PqNetworkService` which owns one `lighthouse_network::Network`, one
`PqNetworkBlockProcessor`, the sole `PqBlockBroadcastReceiver`, and bounded non-waiting ingress and
completion channels. Construct the libp2p service directly; do not restore the ordinary router,
sync manager, backfill, subnet service, notifier, or unbounded `NetworkMessage` channel. The worker
must perform only the minimum status handshake required to keep a same-genesis live peer connected,
subscribe to the Electra beacon-block topic, and reject unsupported RPC requests. It does not claim
late-join or historical catch-up support.

Add a production-shared exact-block publish primitive to `lighthouse_network::Network` which
returns the actual gossipsub result instead of using the existing `publish(Vec<_>)` method that logs
and discards `PublishError`. A successful publish and `PublishError::Duplicate` acknowledge the
e-e2a command: the latter is idempotent evidence that the exact encoded message is already known.
`NoPeersSubscribedToTopic` and every other publish failure return a negative acknowledgment; an
enqueue alone must never promote the publication capability or permit Engine/DB work. Pin all four
cases and the exact block/topic bytes.

For inbound blocks, take a bounded permit before spawning verification, run the existing full
sealed verifier off the mutable libp2p event loop, and return the owned disposition through a
bounded completion channel. Only the network owner may call gossipsub validation. `Accept` calls
the result-bearing validation API first and consumes `after_propagation` only when gossipsub still
holds and accepts that exact `(message id, peer)`; `Reject` reports Reject and the frozen peer
penalty; `Ignore`, unknown parent, capacity, and local proof/service failures report Ignore with no
penalty. A `Retry` token may commit without re-propagation. Engine notification and import remain
detached from the mutable network loop and continue to use the chain-owned import gate. No network,
observation, state, or cache lock may cross proof, Engine, or persistence awaits.

Implemented e4a evidence: the PQ-only worker owns the lower network, exact-block broadcaster,
cap-two proof admission, cap-two completion channel, Status/control RPC profile, and block-topic
subscription. PQ network construction rejects any slot duration other than exactly 300 seconds
before constructing gossipsub history or deadline state; checked 299/300/301-second tests pin this
precondition while the ordinary/default profile remains unchanged. A narrow vendored
`libp2p-gossipsub` patch is selected through an exact source patch, excluded from workspace
membership, and disabled by default. Its provenance, update procedure, focused tests, and retained
upstream MIT license are recorded beside the vendored crate.

In the PQ profile the admission hook runs after transform/message-ID derivation but before the
ordinary duplicate cache and mcache: at most two exact raw messages are pending globally and one per
compatible peer, each for at most one 300-second slot. Overflow and incompatible peers are ignored
without caching. The compatible set is hard-capped at 16. A phase-shifted 300-second window can
intersect two slots containing one block plus two single attestations each, so the checked retained
allowance is six local IDs and six remote IDs per peer. The remote global allowance is
`16 * 6 = 96`; 17 windows retain at most `(96 + 6) * 17 = 1,734` unique reservations. Retryable
Ignore/expiry releases the pending guard and exact per-peer count. Accept moves the exact raw
message into ordinary canonical history and returns a sealed commit reservation;
commit-without-propagation returns the same reservation without forwarding. The network owner
retains that reservation across detached Engine/DB work.
Only a genuinely retryable local commit failure removes the exact duplicate-cache, mcache map,
every matching heartbeat-history entry, and bounded-history entry so the exact block can re-enter;
terminal failure or successful commit retains them. Terminal Ignore, Reject, Equivocation, and
Pending also retain only their bounded exact IDs. Exact local publication while the same ID is
pending is negative `PendingValidation`, never a positive Duplicate. With bounded PQ admission
configured, local publish commits its duplicate-cache and mcache/history entries only after at least
one eligible lower peer queue accepts. If every queue is full, it releases only the exact unique
reservation; repeated failures leave zero heartbeat entries, so expiry of the failed attempt's
bucket cannot evict a later successful retry. With admission disabled, the exact upstream/default
cache-before-queue behavior remains intact and an `AllQueuesFull` retry is Duplicate.

The separate pending map, not mcache, keeps a slow proof alive for the 300-second deadline. Accepted
canonical messages use checked `L = ceil(slot_duration / heartbeat_interval) + 2` mcache history
(302 heartbeats at the frozen one-second profile); the full/default profile remains 12. A fast
simulated test proves a pending block is expired by the old 12-second policy but retained at 13
seconds by the 300-second policy. The accepted raw mcache lifetime intersects at most three
admission windows, so its checked ID inventory bound is `3 * (96 + 6) = 306`; this is distinct from
the per-RPC publish-message limit. This distinction avoids claiming that increasing accepted
history alone protects an unverified block.

Tests prove that validated Status is required before inbound proof admission or outbound publication,
that the 17th compatible peer is rejected, and that disconnect removes compatibility. Recipient
selection applies the same exact Status-compatible set inside gossipsub queue selection: a compatible
but unsubscribed peer plus an incompatible subscribed peer yields `NoPeers`, and publication reaches
only a peer that is both compatible and subscribed. Real peers prove positive publish and exact
Duplicate acknowledgment; no-peer and every other publish failure are negative and are not inserted
in the ordinary retry cache. Full SSZ block encoding runs on the chain-owned blocking executor behind
cap-two admission and compatibility is rechecked after encoding. The lower snappy transform remains
synchronous, bounded by the configured maximum gossip message size, and is not described as off-loop.
Tests pin the received topic/fork digest and decoded block bytes, cap/cap-plus-one ownership, shutdown
acknowledgment, bounded commit-completion cleanup, and network-loop heartbeat while a large block is
encoded.

A production-shared private lifecycle harness pins Accept/report-success ordering, report-false
capability rollback, Retry-without-repropagation, Reject/penalty, Ignore/no penalty, non-waiting
cap/cap-plus-one admission, and full/closed completion RAII cleanup. Incompatible fork digest or
finalized epoch/root maps to `IrrelevantNetwork` with zero proof starts. Lower network construction
errors retain their exact String detail, and dropping the sole broadcaster receiver makes an
already-pending acknowledgment resolve `WorkerUnavailable`.

The AVX real-worker gate produces and signs an authenticated block, performs the compatible Status
handshake, admits it on the receiving worker, and then blocks receiver import preparation for 13
seconds. During that pending proof, submitting the exact block through the receiver's own broadcaster
returns prompt negative `PendingValidation`, proving the mutable receiver loop remains live rather
than observing an unrelated publisher loop. Releasing the barrier completes the full sealed proof,
Engine VALID notification, atomic DB/head publication, exact stored block lookup, and restart at the
same signed root (1/1 in 93.86 seconds). Independent-store two-node convergence and direct
publisher `PqBlockPublicationService` ordering are covered by e4b rather than this receiver-only
gate; this is not an HTTP-route test.

##### Task 5.3e-e4b: Prove the bounded two-node live-block boundary

Build a two-node in-process harness from the real PQ network worker, real gossipsub encoding, two
independent stores/Engine adapters, and the existing e-e2a publication service. Start both nodes
from the same exact genesis before the proposal slot, establish the status handshake and topic
subscription, then publish one signed block. Assert publisher gossipsub acceptance precedes its
Engine/DB commit, the peer performs full sealed verification before Accept and its own Engine/DB
commit, and both durable heads restore as the exact signed block. Exercise negative acknowledgment
with zero subscribed peers, idempotent Duplicate, invalid evidence Reject/penalty, local service
failure Ignore/no penalty/retry, bounded overload, caller cancellation, and shutdown while a
command is pending.

This slice is deliberately a live-gossip/non-finality proof. V1 has no fork choice or finalized
checkpoint advancement, and a node that starts behind is not synchronized. Do not advertise range
sync, lookup, finality, or late-join support. Complete this evidence before adding the attestation
topics or top-level proposer assembly so failures remain attributable.

Implemented evidence uses two independent `HotColdDB` instances, chain heads, and deterministic
Engine adapters, with the one process-owned `AggregationService` shared by both nodes. The publisher
uses the real bounded publication service and the live network worker as its sole broadcaster. A
blocking encoding barrier proves that neither Engine is notified and neither head changes before the
real gossipsub acknowledgment. Releasing it yields a `Publish`-source publisher commit followed by
the receiver's independent admitted proof, validation report, Engine VALID notification, and atomic
DB/head commit. Both stores contain the exact signed block and both chains rebuild from their own DB
at that signed root only after their network-owner shutdown receipts resolve; each finalized
checkpoint remains exactly its captured genesis checkpoint, including epoch and root. The
warning-denied AVX gate passed 1/1 in 80.03 seconds.

The live zero-peer gate returns a negative acknowledgment while leaving the publisher head at
genesis with no retained gossip admission. Existing bounded lifecycle tests pin owner shutdown while
an acknowledgment is pending, and the publication cancellation gate pins detached completion and
restart after the caller is dropped. Exact duplicate, invalid evidence, local retry, and bounded
overload behavior remain covered by the e4a/e-e2a lifecycle gates rather than repeating their full
proof work here. Late join, range synchronization, and finality remain deliberately unsupported.

##### Task 5.3e-e4c: Add a PQ-only disk-chain and process owner

Add a deep `client::pq_runtime` module, compiled only by `client/pq-devnet`, which owns construction
order and returns the existing `Client` facade. It must preflight all configuration before I/O,
open the supported disk store with the existing BeaconChain schema migrator, load exact genesis or
resume the persisted PQ head, construct one process-wide `AggregationService` on the owned blocking
executor, construct one production `ExecutionLayer`, install both once in
`BeaconChainBuilder::pq_new`, and start the e4a network worker. Determine resume from the PQ persisted
head/initialized anchor rather than blindly replaying `GenesisState`; missing or partially bound
PQ metadata fails closed. Do not call or cfg-enable the ordinary `ClientBuilder`.

The PQ runtime owner retains the chain, network globals, bound addresses, and closed service
capabilities. The long-lived network loop uses a TaskExecutor-owned, panic-monitored result task
which observes the environment exit signal itself, closes ingress, and drains its admitted
encoding/proof/commit owners before returning. HTTP uses its own graceful-shutdown future and
`spawn_without_exit`, matching Warp ownership. Dropping/ending the network worker drops the sole
broadcast receiver so every pending acknowledgment resolves `WorkerUnavailable`; no caller may
retain a receiver or mutable libp2p handle. Startup failure after a component is launched must fire
shutdown and must not leave a detached listener or proof worker accepting new work.

Implemented e4c adds the isolated `client::pq_runtime` disk/process owner without changing the
top-level binary boundary. Pure planning seals Minimal's exact 300-second profile, GenesisState or
FromStore mode, disk/network/JWT paths, the real Engine endpoint, narrow HTTP settings, and optional
proposer paths before any filesystem query or write. The disk classifier accepts only the exact
PQ-head/frozen-anchor empty-or-resume pairs, rejects the ordinary beacon-chain sentinel and partial
or corrupt metadata, and dispatches only the current PQ schema without ordinary fork-choice
migration.

JWT validation uses the ExecutionLayer's production parser. GenesisState reads, context-decodes,
and profile-validates `genesis.ssz` before directory creation; FromStore never requires or reads the
genesis file. One owned blocking closure retains every provisional disk, aggregation, Engine, and
chain owner across caller cancellation. After it completes, the real PQ network is the last
fallible startup step. Its result-bearing start awaits a first-poll live acknowledgment; an executor
exit that wins before that acknowledgment returns `TaskUnavailable`, never a client. The existing
`Client` privately owns the PQ disk/network owner and sender. The PQ runtime module, raw owner,
broadcaster, receiver, and mutable lower network are not production API. Shutdown uses a
process-owned, non-clone stop trigger: it closes the sole receiver, waits for all admitted encoding,
proof, and commit tasks to release their exact owners, then resolves queued and future requests from
retained sender clones as `WorkerUnavailable` before its receipt completes. Worker panic is reported
through the TaskExecutor shutdown channel, and both panic and abnormal task loss map to the typed
`TaskUnavailable` startup/receipt outcome rather than detaching an unmonitored Tokio owner.

Pure planning derives store paths lexically from the configured data directory and validates the
PQ store configuration without consulting legacy-directory existence. Fresh GenesisState input is
validated before directory creation. An existing store is classified first; exact Resume never
reads an absent or corrupt genesis candidate, while Empty consults that candidate. Focused evidence
also covers empty/partial/ordinary/corrupt store rejection, blocking-construction cancellation
ownership, real network construction failure cleanup, fixed-port shutdown/rebind, and exact
signed-head disk restart. A proposer-configured e4c start leaves the sealed bundle and slashing
paths unopened, and the PQ client dependency graph contains no validator-store, signer,
proposer-service, or slashing crate. HTTP binding, proposer resource construction, top-level
`DeferredRuntimeIntegration` replacement, CLI provisioning, and slot scheduling remain e4d/e work.

##### Task 5.3e-e4d: Make provisioning and configuration launchable and unambiguous

Extend the PQ provisioner with one atomically published container. Its distributable, key-free
`testnet/` directory contains the frozen Minimal Electra `config.yaml`,
`deposit_contract_block.txt`, empty bootstrap list, and exact `genesis.ssz`; its private `bundle/`
directory contains the authenticated validator bundle, passwords, and journal. Stage the whole
container privately, publish it with one rename, then expose only the final public directory and
files as 0755/0644 while retaining every private directory/file as 0700/0600. Bounded loaders reject
missing, unexpected, symlink, non-regular, over-count, over-size, or permission-incompatible entries
before authentication. The public loader seals exact genesis bytes, validators root, genesis time,
and the canonical validator-index/public-key/withdrawal-credential registry. Bundle identity
validation checks both the validators root and the checked frozen relation
`eth1_timestamp + 300 == genesis_time`, then binds every authenticated manifest entry to that exact
registry position; a bundle may own a canonical prefix without inventing its own indices.

Add an additive `pq-proposer` feature over `pq-devnet`, so the verifier-only normal/build graph has
no validator-store, signer, or slashing dependency. Make the PQ launch parser require the generated
testnet directory and accept one optional authenticated validator-bundle root only with that
feature. Absence means verifier-only. Presence enables exactly one local proposer authority and
derives its SQLite slashing database lexically as
`<node-datadir>/pq-proposer/slashing_protection.sqlite`. Parsing is allowlisted and pure: it neither
probes nor creates any supplied path. Never discover or load validator keys from the public network
directory.

Reject, before filesystem or network side effects, TLS/CORS/metrics/UI, checkpoint/history modes,
builders, monitoring, ordinary validator options, an execution layer without a real endpoint, a
bundle whose manifest identity or validator registry differs from the selected public network, and
an HTTP-disabled proposer. Every fresh or resumed launch bounded-loads and seals the selected public
network exactly once. Disk chains compare their exact root/time identity with that sealed input
before AggregationService, Engine, network, or proposer resources; the inner store/resume path never
rereads `genesis.ssz`. A verifier-only node must not construct `InitializedValidators`,
`LighthouseValidatorStore`, a slashing database, strict HTTP client, or proposer service. A proposer
node loads the authenticated bundle on a detached process-executor task which retains the already
opened and identity-bound store across caller cancellation. It opens or resumes and atomically
registers the exact sealed canonical identity sequence in slashing protection on the blocking
executor, and constructs a sealed non-clone validator-store owner with builder, doppelganger, and
remote signing disabled.
Task e4d stops at that resource. Task e4e constructs `PqProposerService` only after Warp is bound and
the actual strict loopback beacon-node URL is known.

##### Task 5.3e-e4e: Bind the narrow HTTP server and drive the proposer

Bind only `PqHttpApi::new(chain, executor, broadcast_sender).routes()` with Warp graceful shutdown.
Start it after the network receiver is live and before the proposer. If the configured listener is
wildcard, derive the strict local client URL from loopback plus the actual bound port; never send
the proposer through an advertised wildcard address. Bound accepted HTTP connections with separate
nonwaiting loopback and remote admissions retained for each connection lifetime, so idle and
partial-header clients cannot make shutdown or memory retention unbounded. Construct the strict
local client from the actual URL with redirects and proxies disabled, HTTP/1 only, and the frozen
285-second transport ceiling.

The proposer scheduler is a process-owned, exit-aware slot loop which calls only
`try_propose_current_slot`; it does not accept caller duties, keys, indices, or slots, and it never
retains more than the service's cap-one detached receipt. Fresh startup attempts the current
non-genesis slot immediately. Resume samples the clock only after the acknowledged ready gate is
released, marks that observed startup slot skipped, and waits for the next checked boundary. The
loop recomputes each later boundary, coalesces a completed same-slot result, and boundedly retries
every closed-policy nonfatal synchronous outcome (including capacity, unavailable clock, and a
stale-slot admission race) after a one-second backoff. Immediately before every admission it uses
a biased stop/executor-exit gate, so an already-ready or same-poll stop cannot start new
non-cancellable work. Executor/task loss and configuration/signing invariants terminate the
process. Malformed local response headers/JSON/SSZ, protocol violations, and impossible
bounded-body/resource outcomes are fatal, while allowlisted transport/status and block/publication
conflict outcomes remain slot-local. Shutdown stops new slots and
non-cancellably awaits any retained receipt before closing HTTP/network ingress and releasing the
sealed store; a fatal retained completion is still propagated after the resource drain.

Replace both synchronous PQ `new_from_cli`/`DeferredRuntimeIntegration` branches with the ordinary
environment sequence: parse and programmatically validate config, honor dump/immediate-shutdown,
then spawn asynchronous `ProductionBeaconNode::new(context, config)`. Remove the pre-runtime
hard-exit path. Keep non-beacon-node commands compile-omitted. The top-level supervisor must own
startup immediately: a signal received during construction queues stop without canceling the
startup future, then drains the constructed `Client` before firing the environment executor exit.
Every failure after HTTP bind must similarly stop and await HTTP, drop the sole broadcaster, await
network shutdown, and return the original construction error rather than a cleanup artifact.

##### Task 5.3e-e4f: Wire the remaining PQ gossip topics and run the launch harness

After live block propagation and proposer assembly are independently green, subscribe to
aggregate-and-proof and the fixed bounded set of Electra attestation subnets (the ordinary dynamic
subnet service remains absent). Route them through the e-d full proof boundary, call gossipsub
Accept before consuming `mark_propagated`, and then drop the sealed post-propagation provenance
honestly until Task 5.2b supplies pool/coordinator consumers. Invalid evidence is Reject/peer
penalty; duplicate, aged, stale-lineage, capacity, and local service failure are Ignore/no penalty.

Add a process-launch harness using the actual PQ Lighthouse binary, generated public testnet, two
distinct data/network directories and ports, one proposer-enabled node, one verifier-only node, and
a mock Engine per node. Launch both before the first proposal slot, wait for libp2p and HTTP
readiness, observe multiple consecutive 300-second slots without overlapping proof jobs, terminate
through the real shutdown signal, restart both stores, and assert exact signed heads and publication
idempotence. This is the final e4 evidence for local V3 production, journal-backed signing, V2
publication, acknowledged gossipsub, full e-c import, Engine VALID, atomic persistence, and restart.
It must explicitly assert that finalized epoch/root remain the frozen genesis values and that a
late-starting node is unsupported rather than presenting this as a sync-capable devnet.

Implemented e4f evidence currently closes the block-launch portion of this task, not the remaining
attestation topics. The actual `CARGO_BIN_EXE_lighthouse` starts one proposer and one verifier as
separate OS processes with separate disk/network identities and independent authenticated,
stateful Engines. Exact bounded operational events prove compatible Status before proposals and
three consecutive slot-1/2/3 lifecycles. For each slot, the proposer and verifier agree on the
canonical block root and SHA-256 digest of the full signed SSZ, independently execute `newPayload`
and a no-attributes FCU, and converge on the same persisted head. The proposer alone performs the
corresponding attributes FCU and `getPayload`; all payload bundles contain zero blobs.

After graceful SIGINT, both processes restart from the same respective data directories against
the retained Engines. Startup replays exactly one no-attributes FCU to the slot-3 execution hash
and reports the exact resumed root/signed digest before any proposal event. A resumed proposer does
not immediately admit the slot observed when its ready gate is released: it marks that startup
slot skipped and waits for the next checked boundary. The tracer stops both resumed
processes before that boundary, observes no additional payload/import lifecycle, then proves TCP,
UDP, proposer SQLite, and all six LevelDB owners are released. The finalized checkpoint remains
exactly genesis before and after restart.

The warning-denied AVX2 process test passed 1/1 in 2386.88 seconds. This evidence makes no
attestation, justification/finalization advancement, late-join, or range-sync claim. Attestation
subnet and aggregate-and-proof wiring described at the start of this task remains future work.

### Task 5.2b: Wire verified candidates into both beacon-node attestation pools

**Prerequisites:** Tasks 5.2a and 5.3e, including the compiling top-level PQ feature spine for the
affected beacon-node packages.

**Cycle 1 checkpoint (implemented, fresh-only):** `BeaconChain` now owns the minimal
scheme-neutral fork choice initialized from exact genesis. The sealed single-attestation gossip
capability transfers its original nonwaiting admission and shutdown activity across propagation
into a monitored, cancellation-safe consumer. That consumer coalesces on Pending execution
reconciliation, applies `on_attestation` exactly once on the blocking executor, and resolves the
observation as Applied or Terminal. The chain-owned tick path uses the same bounded ownership,
requires exact clock agreement, rejects rollback, and caps one request at eight forward slots.

The block continuation keeps reconciliation Pending across DB publication, no-attributes FCU, and
blocking fork-choice `on_block`. Only successful insertion atomically promotes Reconciled and
Committed; panic, join loss, or post-FCU clock loss fails terminally and closes ingress before
releasing ownership. Pre-propagation cancellation alone may reopen an observation. Once propagation
is marked, the exact identity is ConsumptionPending, survives bounded pruning, suppresses duplicate
or conflicting propagation, and resolves only Applied or Terminal.

**Cycle 2 checkpoint (implemented, live single routing):** the PQ network owns exactly the beacon
block topic plus Minimal/Electra unaggregated attestation subnets 0 through 7 and ignores all caller
configured topics during PQ lower-network construction. An admitted single is verified under the
shared nonwaiting two-item proof cap, reported `Accept`, atomically promoted, and consumed by the
cycle-1 chain-owned continuation. Failed reporting rolls the pre-propagation observation back;
post-propagation ownership survives cancellation/executor exit and is included in network drain.
Only retryable local verifier failures release history; duplicate, aged/stale, shutdown,
generation-exhausted, and terminal outcomes retain it without peer penalty.

The authentic two-worker AVX2 tracer passed a real signed single over its exact subnet topic after
compatible Status, proved a queued slot-1 vote and exact latest message after the checked slot-2
tick, kept the receiver network loop responsive during proof work, and applied neither proof nor
vote twice on exact redelivery. The outbound attestation injection seam is bounded and entirely
`pq-startup-testing`-only.

**Cycle 3 Slice A checkpoint (implemented, local context only):** the private native
`BeaconChain` path derives current-slot contexts only for Minimal/Electra with exact 300-second
slots. It accepts an immutable, sorted, unique validator identity snapshot capped at 16 and binds
every public key to its exact canonical registry index; callers cannot supply a slot, committee,
subnet, or attestation data. The owned blocking derivation clones the canonical state and rebuilds
the Current committee cache, so a cache-empty Resume snapshot produces the same exact duties
without mutating persisted state.

Real execution-VALID slot-1 import evidence binds the resulting data and duties to the imported
canonical root. Independent frozen committee membership, position, and subnet vectors cover the
full 16-validator profile, while an epoch-2 fixture pins distinct non-default justified source,
target, and Current-dependent roots. The context path has a nonwaiting cap of two and retains its
shutdown activity across blocking work, cancellation, late validation, and returned ownership.
Initial, late, and consume-time clock/head/reconciliation samples use short nonwaiting acquisitions
of the canonical PQ import gate and release it before exposing the coherent candidate snapshot.
That snapshot is explicitly not signing authorization; a later signer and pre-publication/local
application path must revalidate under their own safety boundary.

**Cycle 3 Slice B1 checkpoint (implemented, local proof provenance only):** consuming an exact
Slice-A candidate now seals a private, non-`Clone` provenance object. It binds the immutable
validator public key and registry index, committee index/position/length/count, trusted subnet,
slot, bound and dependent roots, signing root, exact attestation data and bitfields, individual
signature framing, and SHA-256 of the complete signed single-attestation SSZ bytes. The returned
locally verified token is likewise private and non-`Clone` and retains the original proof admission
and PQ import activity through late-lineage blocking work, caller cancellation, and its own
lifetime. Local verification uses an independent cap-two proof-admission domain; inbound single and
aggregate gossip retain the existing remote cap-two domain. The bounded combined proof ownership
is therefore two local plus two remote, not one global cap-two semaphore.

Preparation, proof, and late-lineage validation are shared production stages for remote and local
singles without an `is_local` mode. The remote route preserves its original single-snapshot
semantics: the snapshot that supplies the bound root is the snapshot passed into preparation even
if the canonical head changes between those operations. Signing-ID and aggregation error sources
remain delegated identically. The local route does not touch remote observations, mark propagation,
apply fork choice, or publish; authentic slot-1 evidence pins observations exactly `0 -> 0`, and
structurally valid but cryptographically invalid evidence becomes a typed local contextual
invariant.

**Cycle 3 Slice B2 A+B checkpoint (implemented, guarded batch and precheck ownership only):** a
coherent Slice-A snapshot transfers its candidates plus original admission and shutdown activity
into a private, non-`Clone` owned signing batch. The planning boundary returns `NoDuty` without
store work for an empty batch and caps nonempty batches at 16. It classifies every store-output
shape before sealing: requested/returned capacity, empty, missing, extra, duplicate index,
order/index mismatch, and exact candidate/data/bitfield association. Production exposes no
reusable `AttestationToSign` request vector and no raw validation bypass.

The one-shot `sign_once` operation consumes the guarded batch, creates its exact requests only
inside a TaskExecutor-monitored without-exit task, awaits exactly one real validator-store stream
result, and returns only an atomically sealed batch through a non-`Clone` receipt. Dropping that
receipt cannot cancel signing or release the original guards. A two-candidate test pins request
order, distinct keys/indices/data, committee positions 0 and 1, exact full attestations, one signer
invocation, and ordered returned output; committee-index substitution and reversed iteration are
mutation-sensitive.

The real PQ `ValidatorStore::sign_attestations` call now gives its SQLite slashing precheck
without-exit blocking ownership. Caller abort and executor exit cannot orphan the operation, and a
panic returns typed `ExecutorError` while signaling process failure. The actual-call mutation back
to the cancellable helper loses that signal and fails. Ordinary BLS signing and PQ block slashing
remain unchanged. A production imported-slot context-transfer proof also pins that batch ownership,
not a synthetic fixture, retains admission and keeps chain drain pending until batch drop.

**Cycle 3 Slice B2 C1-C3 checkpoint (implemented, direct service without scheduling or
publication):** the signer-only `pq-proposer` graph now contains a concrete
`PqAttesterService<MinimalEthSpec, SystemTimeSlotClock>`. Its constructor takes the real chain,
validator store, and executor and internally seals the store-derived, exact sorted/unique identity
snapshot capped at 16. The zero-argument current-slot operation supplies no caller-selected signing
semantics. The `pq-devnet` verifier graph remains free of the validator store, keys, and service.

The cap-one state machine coalesces same-slot callers in one `InFlight` receipt and caches
`CompletedNoDuty`, service-owned `CompletedVerified`, or `CompletedTerminal`. A verified batch is
non-`Clone` and blocks a different slot with `PreviousUnconsumed` until a future publisher consumes
it. The independent monotonic no-duty watermark preserves `NoDuty(N)` across an admitted
`N+1` retryable pre-sign failure: `N` remains cached, `N-1` is rollback, and `N+1` may retry. One
monitored without-exit supervisor owns the entire context, consume, signing, and proof operation;
pre-sign retryable failures restore `Idle`, while the stateful boundary records exact
validator/index/target-epoch/data/signing-root attempts and makes later partial, empty, panic, or
proof failure terminal without alternate signing. Nested typed errors retain their source chains.

The service never separates provenance from its guards. It consumes the signed batch through the
chain's atomic whole-batch verifier, checks the exact proof cap of two before stateful work, and
collects at most two real local proofs all-or-none. The resulting batch owns the original candidate
guard and all real proof tokens; cloneable receipts expose only exact bounded metadata and full
signed-SSZ digests. Shutdown closes admission, drains the supervisor, rechecks completion, and drops
any batch completed during close before chain drain, fixing the close/completion race. The authentic
fixture's ordered owner wrapper also drops service/store/chain/executor ownership before its private
temporary root on both normal and unwind teardown.

The final warning-denied AVX2 direct-service tracer passed 1/1 in 460.39 seconds using the validated
private 16-key fixture clone and a real execution-VALID reconciled slot-1 Minimal/Electra/300 head.
It produced two duties through the zero-argument service, observed exactly one SQLite precheck and
one whole-batch local verification, retained two real tokens, returned byte-identical cached
same-slot metadata, and kept the remote observation cardinality at `0 -> 0`. The exact command was
`RUSTFLAGS='-D warnings -C target-feature=+avx2' cargo +1.88 test -p lighthouse
--no-default-features --features pq-proposer --test pq_e4f_launch
direct_pq_attester_service_authentically_signs_and_proves_slot_once -- --exact --nocapture`.
Removing the service-owned batch failed with `AtomicBatchMissing` in 459.80 seconds; the restored
GREEN run recorded clone/authentication/RANDAO/import/complete phases at 0.172/279.315/306.991/
459.396/460.382 seconds.

**Publication admission prerequisite checkpoint (historical lower prerequisite):** the PQ
gossipsub admission profile now checked-derives six retained local IDs and six retained remote IDs
per peer from two phase-intersecting slots of one block plus two singles. With the hard 16-peer
compatibility cap, remote global retained capacity is 96. Pending work remains exactly two globally
and one per peer. Seventeen windows retain at most 1,734 IDs, while the accepted raw mcache can
intersect three windows and is bounded by 306 IDs. Zero/invalid relationships and checked capacity
overflow reject configuration.

Tests pin local 6/7, sequential per-peer 6/7 after pending resolution, global 96/97 across peers,
peer churn without history release, retryable decrement versus terminal retention, exact N rather
than N+1 rollover, and the full 1,734-entry inventory. The expiry test fills five terminal IDs,
expires a sixth pending exact ID at 300 seconds, and requires identical redelivery; removing exact
history release fails. The ordinary no-admission path is unchanged. At this prerequisite boundary,
the production publisher, service-owned batch consumption, and local fork-choice application had
not yet landed; the completed convergence checkpoint below supersedes those limitations.

**Source-aware lower publication checkpoint (historical lower boundary):** the
signer-only `lighthouse_network/pq-proposer` graph now owns a sealed, private-field, non-`Clone`
preencoded single-attestation request. Its synchronous lower publish method requires a unique
mutable borrow, preserving the same capability across retryable `NoPeers`, `AllQueuesFull`,
`ValidationAdmissionFull`, and `PendingRemote` outcomes while preventing safe concurrent reuse
through distinct networks. The request binds exact SSZ bytes, subnet topic, and fork digest before
lower entry. Existing bounded Snappy compression still runs synchronously in gossipsub.

The result-bearing contract preserves exact anonymous `MessageId` identity and distinguishes
Published, local duplicate, remote pending, remote retained duplicate, unknown duplicate, no peers,
all queues full, validation admission full, message too large, and transform failure. A mismatched
success ID and a provenance-less generic duplicate are terminal rather than reported as published
or guessed local. The bounded vendor history derives provenance from its existing local and remote
sets; no unbounded side map was added. Failed local queue/peer attempts release reservation,
duplicate-cache, and mcache state, retryable remote resolution releases the exact remote identity,
and successful publication remains retained.

Compile and behavioral mutations pin the unique-borrow API, same-object retry, ID mismatch,
unknown duplicate, source collapse, admission and transform mapping, anonymous-ID eligibility, and
reservation rollback. At this lower-only boundary, no upper network command, attester-service
batch handoff, or local consume/apply coalescer existed; the completed convergence checkpoint below
supersedes those limitations. Scheduler, HTTP, pools, aggregation, persistence, justification, and
finalization remain separate work.

**Network whole-batch command checkpoint (historical command boundary):** the
signer-only `network/pq-proposer` graph now owns one cap-one, result-bearing command whose only
production input is the complete non-`Clone` verified local batch. The command and its opaque
progress owner retain all candidate guards and real proof tokens; no raw single, encoded request,
or token escapes. Admission/closed errors return exact ownership. A monitored without-exit blocking
operation encodes every member in deterministic order away from the mutable network loop, hashes
the one exact signed-SSZ buffer against the sealed digest, derives the attestation topic from the
trusted subnet and slot-specific fork digest, and moves that same buffer into generic anonymous
gossipsub publication. The specialized lower encoded-request API is consequently removed; only the
source-aware classifier and generic lower publish remain.

Progress distinguishes verified, published/local-duplicate, remote pending/retained unresolved,
retryable, and terminal members with exact `MessageId` identity. Retry consumes the opaque owner,
skips the irreversible prefix, and reuses the failed member's exact encoded buffer. Encoding
unavailability/panic is terminal and process-fatal while preserving ownership. One bounded
service-owned completion slot survives receipt cancellation. Production close wakes live queued,
blocked-encoding, and completed receipts without taking their shared progress; abandoned receipts
release naturally when the final service/command owner drops, and shutdown drain remains bounded.

The read-only count/topic/ID trace is available only through additive
`lighthouse/pq-startup-testing`; `pq-proposer` alone does not enable it. Fast tests pin exact
two-member encoding, subnet/fork topics, no truncation, cursor retry, remote provenance, task
failure, receipt cancellation, and all three close races. The final authentic warning-denied AVX2
run passed in 461.00 seconds through real journal signing, whole-batch local proof, and actual
no-peer `PqNetworkService`, independently matching both encoded members and member-zero's exact
topic/anonymous ID. That command-only tracer did not apply a vote; its missing service handoff,
remote-outcome coalescence, local application, and two-worker upper wire proof are completed below.

**Publication/coalescing convergence checkpoint (completed):** the production lower result carries
non-forgeable evidence for every locally published member, and an irreversible published prefix
remains owned by the network service across retry, remote wait, shutdown, and caller loss. Remote
observations are keyed by exact signed identity plus canonical anonymous wire `MessageId`; a
bounded active admission bridge covers only the interval before the chain claim exists. Local
application starts only after every member is either locally published or authoritatively consumed
by the remote chain. Watch loss, bridge loss, identity conflict, and already-signalled terminal
consumption remain distinct typed outcomes, with exactly one process-failure owner.

The last authentic blocker proved to be source coupling in proof admission. The real two-member
local verified batch retained both permits from the remote gossip semaphore, so inbound member one
necessarily returned `IngressCapacity`, the active bridge emitted `Released`, and publication
retried it locally. The correction did not raise that cap: remote single/aggregate gossip keeps its
existing capacity two, while local attestation proof verification has a separate private capacity
two. Thus retained proof work is explicitly bounded at two local plus two remote, with the
whole-batch publisher still cap one. The local atomic collector and attester service both consume
the chain-owned local constant. Production-sensitive tests pin local and remote cap-plus-one
independently; mutating the local verifier back onto the remote semaphore leaves zero remote permits
instead of two and fails, while changing the remote constant no longer changes the local collector
bound. The restored imported-slot local-context regression passed 1/1 in 131.90 seconds with remote
capacity intact and local proof/activity ownership retained through drop.

The completed acceptance tracer uses two independent `BeaconChain`, validator-store, fork-choice,
and network instances with identical genesis and execution-VALID slot-1 heads; the intentionally
process-singleton aggregation service is shared. A real two-member batch is journal-signed and
whole-batch verified once by the direct attester service, transferred through its sealed bounded
production handoff, and published by `PqNetworkService`. The independent peer supplies member one
as the external source while member zero follows the local publication path. Exact signed-SSZ
digests, subnet/fork topics, and anonymous message IDs are checked independently, and neither member
is re-signed, re-proved, re-encoded, or re-applied.

A commit-blocking review found that the first publication preflight could become stale while a
mixed batch awaited its remote member. The final post-wire route first settles every remote member
without holding the import gate. It then acquires the import gate, coherently rechecks the current
clock, canonical head/state slots, cached validated state root, and execution reconciliation, and
retains that gate into the blocking fork-choice continuation. The continuation acquires the
fork-choice mutex exactly once, resamples the actual clock while holding that mutex, validates
fork-choice time and bound-root ancestry under the same guard, and applies each local member with
that freshly sampled current slot. No import gate or fork-choice lock crosses the remote wait or a
network operation. Mutating application back to the signed slot made the focused test observe slot
1 instead of the advanced current slot 2. Removing the under-fork-choice resample made the clock
advance from slot 2 to slot 3 while waiting for the mutex incorrectly complete as
`[Applied, Queued]` instead of the typed
`ClockChanged { sampled: Slot(2), current: Slot(3) }`; restoring the shared production/harness route
returned the exact typed error with zero local fork-choice calls and one fail-close.

The exact warning-denied AVX2 command was
`RUSTFLAGS='-D warnings -C target-feature=+avx2' cargo +1.88 test -p lighthouse
--no-default-features --features pq-proposer,pq-startup-testing --test pq_e4f_launch
direct_pq_attester_service_converges_two_independent_workers_exactly_once -- --exact --nocapture`.
The final rerun passed 1/1 in 460.39 seconds, with cache preparation at 0.241 seconds, authority
preparation at 279.806 seconds, RANDAO at 307.448 seconds, concurrent imports at 459.274 seconds,
service completion at 460.233 seconds, and complete drain at 460.383 seconds. The chain task
executor failure receiver and both independent network task-executor failure receivers were all
retained, live, and empty immediately before explicit service/network stop and chain drain.

Before the inbound barrier is released, sender progress is exactly member zero
`Published { duplicate: false }` and member one `WaitingRemote { retained: false }`. The false
provenance is deliberate: lower admission still reports pending-not-yet-retained while the bounded
active bridge covers the chain-claim gap. Final sender progress is exact and ordered: member zero is
`Consumed { duplicate: false, result: Queued }`, and member one is
`Consumed { duplicate: true, result: Queued }`, each bound to its independently derived exact
`MessageId`. The sender makes exactly two fork-choice calls, once per identity across the local and
remote sources; the receiver makes one call for wire-delivered member zero. The sender observation
cache intentionally retains two source-neutral exact-once records: locally published member zero
transitions through `LocalWireSuccess` and `ConsumptionPending` to `Consumed(Queued)`, while remote
member one is already `Consumed(Queued)` and coalesces without a second sender application. Exact
epoch/index queries return `Queued` for both identities. Receipt, batch guards, proof admissions,
and observation ownership remain live through remote waiting and clean drain.

This closes Task 5.2b's direct signing, sealed production handoff, real two-worker publication,
cross-source coalescence, and exact-once local fork-choice application boundary. It does not claim
operation-pool or naive-aggregation-pool insertion, aggregation or block inclusion, or
justification/finality beyond genesis. A monitored duty scheduler and persisted attester,
pool/fork-choice, and finality recovery across restart also remain subsequent vertical slices.

**Cycle 4 implementation design (next):** the file list below supersedes the earlier proposal to
revive both BLS attestation mutation paths. Under `pq-devnet`, `operation_pool::attestation_storage`
and `BeaconChain::naive_aggregation_pool` are deliberately not compiled. Reintroducing them would
create two new mutation authorities beside the already failure-atomic
`PqAttestationAggregationCoordinator`. Instead, the PQ `OperationPool` becomes the single deep
facade over that coordinator. Its default/BLS build and persisted `opo` representation remain
unchanged.

Cycle 4 is split into dependency-ordered tracer bullets:

1. The PQ `OperationPool` owns one coordinator constructed from the chain's existing process-wide
   `AggregationService`. Both the inbound-single continuation and the post-wire local-batch
   continuation move their already sealed `VerifiedPqAttestation` values into this pool only after
   successful fork-choice disposition. Exact cross-source duplicates are dominated. Ordinary
   bounded cache/resource rejection drops only the pool candidate and does not roll back a valid
   fork-choice vote; impossible sealed-input or generation invariants fail closed.
2. A deterministic selection API snapshots no more than 64 buckets and returns no more than the
   Electra block maximum of eight sealed `Arc<VerifiedPqAttestation>` values. It validates each
   candidate against the authoritative block-inclusion rules and the exact advanced pre-block
   state. Slot-2 production passes the identical ordered sealed values into
   `prepare_pq_local_block`; failed production leaves candidates retryable. A maximal aggregate is
   preferred when already committed, otherwise verified raw singles are a liveness-preserving
   fallback. This first inclusion tracer must advance participation for the exact included slot-1
   validators before it claims progress toward finality.
3. When a bucket gains a second disjoint candidate, chain-owned background work schedules at most
   one active and one queued aggregation attempt. Snapshotting and commit remain under the
   coordinator lock, while recursive proof work holds no pool lock. Backend/resource failure keeps
   every source candidate available. Do not start a fresh proof after `getPayload`: the block
   production budget is 120 seconds and authentic aggregation can exceed it.
4. Live aggregate gossip follows only after it gains the single-attestation lifecycle:
   post-propagation import activity, `ConsumptionPending`, a monitored non-cancellable chain
   continuation, terminal failure ownership, and exact pool/fork-choice disposition. The current
   `Observed`-at-propagation token is not sufficient because cancellation after `Accept` can
   suppress a valid aggregate without storing it.

The authentic Cycle-4 tracer extends the current two-worker E4F fixture through slot 2. It requires
sender pool cardinality two and receiver cardinality one after slot-1 publication, exact aggregate
union bits/signers when background proof is ready, deterministic raw-single fallback otherwise,
actual V3 production/publication/import on both independent chains, and exact post-state
participation changes. Wrong bit, evidence, key, data root, token order, or token count must fail
before Engine, database, or head mutation. Restart retains the included block/state participation
but deliberately starts with an empty ephemeral candidate pool. This checkpoint still does not
claim justification or finality.

**Files:**

- Modify: `beacon_node/operation_pool/Cargo.toml`
- Modify: `beacon_node/operation_pool/src/pq_runtime.rs`
- Modify: `beacon_node/beacon_chain/src/pq_runtime/beacon_chain.rs`
- Modify: `beacon_node/beacon_chain/src/pq_runtime/attestation_gossip.rs`
- Modify: `beacon_node/beacon_chain/src/pq_runtime/production.rs`
- Modify: `beacon_node/attestation_aggregation/src/pq.rs` only for bounded selection/background
  scheduling capabilities missing from the existing coordinator
- Modify: `testing/pq_devnet/tests/pq_attestation_aggregation.rs`
- Modify or create focused PQ pool/production tests under `testing/pq_devnet/tests/`
- Extend: `lighthouse/tests/pq_e4f_launch.rs`

**Step 1: Write a failing real-consumer pool-insertion test**

Drive one inbound verified single and one post-wire local batch through the actual chain consumers.
Require sealed candidate insertion, exact cross-source dominance, bounded capacity behavior, and
zero extra proof/fork-choice calls. The RED must fail because PQ `OperationPool` is currently empty
and both consumers discard the sealed candidates after fork-choice application.

**Step 2: Verify RED through the real PQ feature spine**

Run the focused `pq_devnet` target with `RUSTFLAGS='-D warnings -C target-feature=+avx2'` and the
smallest feature set that compiles the actual consumers. Expected: compile failure for the missing
PQ pool ownership/insertion surface. Also prove the default operation-pool feature tree remains
free of `attestation_aggregation`.

**Step 3: Implement the single PQ OperationPool facade**

Add the coordinator as an optional `operation_pool/pq-devnet` dependency and construct exactly one
PQ pool from the existing chain-owned `AggregationService`. Add crate-private consuming conversions
from verified gossip/local singles to `VerifiedPqAttestation`; expose no raw constructor or clone.
Insert only after successful fork-choice disposition. Keep default BLS modules and persistence
byte-for-byte unchanged.

**Step 4: Add deterministic block selection before background aggregation**

Write REDs for bounded deterministic order, canonical inclusion validation, failed-production
retry, pruning, and slot-2 raw-single inclusion. Snapshot under pool locks, release them, then pass
the exact sealed values to `prepare_pq_local_block`. Candidate state remains ephemeral; startup does
not interpret BLS `opo` bytes or re-prove candidates.

**Step 5: Add bounded background aggregation**

Reuse `PreparedAggregate` and the coordinator's generation-bound in-flight RAII. REDs cover one
active plus one queued attempt, concurrent arrival, prune during proof, backend/queue failure retry,
cap-plus-one, heartbeat/no-lock-across-await, and caller/executor cancellation. Selection uses the
committed maximal aggregate when available and raw singles otherwise.

**Step 6: Retain explicit empty sync aggregation in V1**

Disable validator sync duties and beacon-node sync contribution gossip/aggregation at startup.
Block production must emit `SyncAggregate::empty()`: zero participant bits plus canonical absent PQ
evidence, consuming no XMSS leaf. Verification must accept exactly that pair, reject absent evidence
with any set bit, and reject raw/aggregate evidence with zero bits. Never emulate BLS infinity or
silently run the BLS sync path.

**Step 7: Verify both profiles, the slot-2 tracer, restart semantics, and commit**

Run the PQ operation-pool, coordinator, beacon-chain, and block-production suites; default BLS
operation-pool/state-processing suites; warning-denied verifier/proposer feature checks; and the
authentic two-worker slot-2 production/import/restart tracer. Record proof latency and raw-fallback
behavior in the findings document.

```bash
git add beacon_node/operation_pool beacon_node/attestation_aggregation beacon_node/beacon_chain \
  testing/pq_devnet lighthouse/tests/pq_e4f_launch.rs \
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

The completed Task 5.2b cycle-1 checkpoint supplies only a fresh in-memory receiver/fork-choice
foundation. It does not satisfy this task: real attestation gossip and aggregation routing, pool
selection, persisted restart behavior, two-thirds epoch participation, justification, and a
finalized checkpoint beyond genesis remain required. Until those slices are complete, the existing
two-process evidence must continue to assert finalized checkpoint exactly equal to genesis.

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
