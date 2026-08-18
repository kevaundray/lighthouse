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
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Add a failing dependency smoke test**

The test imports only the stable API surface required by Lighthouse: setup, deterministic key
creation, raw sign, raw verify, aggregate, aggregate decode, and aggregate verify.

**Step 2: Verify RED**

```bash
cargo nextest run -p consensus_signature --features pq-devnet pq_dependency_smoke
```

Expected: failure because the pinned dependency and feature are absent.

**Step 3: Pin exact commits and expose a minimal adapter**

Pin both the binding and its leanVM/API dependency. If the upstream facade cannot express the
required leaf identifier, bounded decoding, or fallible setup, fork it and record the fork commit
in `docs/pq-devnet-findings.md`.

**Step 4: Verify GREEN**

```bash
cargo nextest run -p consensus_signature --features pq-devnet pq_dependency_smoke
cargo check -p consensus_signature --no-default-features --features pq-devnet
```

Expected: smoke test and PQ-only check pass.

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crypto/consensus_signature docs/pq-devnet-findings.md
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

- every enabled `SignableMessage` variant maps to a stable duty tag;
- two different duties in one Ethereum slot receive different XMSS leaves;
- the same duty and slot reproduce the same leaf;
- overflow and devnet-lifetime violations return errors without panicking;
- no duty tag is reused.

**Step 2: Verify RED**

```bash
cargo nextest run -p consensus_signature --test signing_id
```

Expected: compilation fails because `SigningId` and the allocation table do not exist.

**Step 3: Implement the minimal checked mapping**

Use checked arithmetic. Keep the number of leaves per slot and every assigned duty tag explicit.
Do not hash duty names into leaf IDs.

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
- Create: `crypto/consensus_signature/tests/pq_raw.rs`

**Step 1: Write failing raw-signature tests**

Cover deterministic retries, wrong root, wrong public key, wrong signing ID, malformed bytes,
out-of-range signing ID, and parameter-set/version mismatch.

**Step 2: Verify RED**

```bash
cargo nextest run -p consensus_signature --no-default-features --features pq-devnet \
  --test pq_raw
```

Expected: tests fail because the PQ backend is incomplete.

**Step 3: Implement raw signing and contextual verification**

Keep wire bytes opaque until verification context is present. Enforce all length/version checks
before invoking leanMultisig.

**Step 4: Verify GREEN**

Run the same command. Expected: all raw PQ tests pass.

**Step 5: Commit**

```bash
git add crypto/consensus_signature
git commit -m "feat: add PQ raw signature backend"
```

## Milestone 3: PQ Validator State and Signing Safety

### Task 3.1: Add a crash-safe XMSS leaf journal

**Files:**

- Create: `validator_client/signing_method/src/xmss_journal.rs`
- Create: `validator_client/signing_method/tests/xmss_journal.rs`
- Modify: `validator_client/signing_method/Cargo.toml`

**Step 1: Write failing filesystem tests**

Use a temporary directory and test:

- reserve a fresh `(leaf, root)`;
- identical retry succeeds;
- different root at the same leaf fails;
- restart preserves reservations;
- truncated/corrupt journal fails closed;
- concurrent attempts cannot reserve conflicting roots;
- reservation is durable before the signing callback returns.

**Step 2: Verify RED**

```bash
cargo nextest run -p signing_method --test xmss_journal
```

Expected: compilation fails because the journal does not exist.

**Step 3: Implement the minimal durable journal**

Use an atomic, recoverable local persistence strategy and avoid runtime panics. Document lock
ordering and durability assumptions.

**Step 4: Verify GREEN**

```bash
cargo nextest run -p signing_method --test xmss_journal
cargo check -p signing_method
```

Expected: all journal tests pass.

**Step 5: Commit**

```bash
git add validator_client/signing_method
git commit -m "feat: persist XMSS leaf reservations"
```

### Task 3.2: Add PQ validator key storage and genesis generation

**Files:**

- Modify or create: `crypto/eth2_keystore/` PQ key storage modules
- Modify: `common/validator_dir/`
- Modify: `account_manager/`
- Modify: `lcli/`
- Create: targeted key round-trip tests in each changed package
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write failing key round-trip tests**

Cover generation, encrypted persistence, reload, public-key identity, malformed key rejection, and
activation/signing range preservation.

**Step 2: Verify RED using the narrowest affected package test**

Expected: failure because no PQ keystore format exists.

**Step 3: Implement an explicitly versioned experimental format**

Do not claim EIP-2335 compatibility if the payload is not an EIP-2333-derived BLS scalar. Keep PQ
files distinguishable from BLS keystores.

**Step 4: Verify GREEN and measure key size/load time**

Record measurements in `docs/pq-devnet-findings.md`.

**Step 5: Commit**

```bash
git add crypto/eth2_keystore common/validator_dir account_manager lcli \
  docs/pq-devnet-findings.md
git commit -m "feat: add experimental PQ validator keys"
```

### Task 3.3: Route validator duties through PQ signing authority

**Files:**

- Modify: `validator_client/signing_method/src/lib.rs`
- Modify: `validator_client/initialized_validators/src/lib.rs`
- Modify: `validator_client/lighthouse_validator_store/src/lib.rs`
- Modify: `validator_client/validator_store/src/lib.rs`
- Create: PQ signing integration tests

**Step 1: Write failing duty-signing tests**

Cover proposer and attester duties first, including identical retry and conflicting-root refusal.

**Step 2: Verify RED**

Run the targeted signing-method/validator-store tests. Expected: PQ signing is unavailable.

**Step 3: Implement PQ local signing**

Reserve the leaf durably, sign in a blocking/scoped worker, and return the explicit raw wire type.
Reject Web3Signer configuration in PQ mode with a clear startup error.

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
- Modify: builder configuration/startup validation
- Create: API serialization and startup-validation tests

**Step 1: Write failing tests**

Cover PQ JSON round trips plus explicit startup errors for Web3Signer and external builder modes in
the first PQ devnet.

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
- Modify: relevant `lcli` genesis commands
- Modify: `docs/pq-devnet-findings.md`

**Step 1: Write a failing configuration smoke test**

The test generates PQ keys/genesis and validates that every registry key and enabled signature
field uses the PQ parameter set.

**Step 2: Verify RED**

Expected: no reproducible PQ genesis path exists.

**Step 3: Implement the smallest useful preset**

Start with a measured validator count and one committee. Disable unsupported protocol features
explicitly. Pin all timing and proof-size limits.

**Step 4: Verify GREEN**

Generate the devnet twice and assert deterministic public configuration/genesis outputs for the
same seed.

**Step 5: Commit**

```bash
git add scripts/local_testnet lcli docs/pq-devnet-findings.md
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
