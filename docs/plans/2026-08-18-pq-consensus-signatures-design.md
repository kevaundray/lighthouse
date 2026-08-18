# PQ Consensus Signatures Design

**Status:** Accepted for implementation on the experimental PQ devnet

**Decision:** Introduce compile-time-selected consensus signature wire types and three deep
operation boundaries: verification, aggregation, and validator signing authority. Do not turn
Lighthouse's existing BLS traits into a general signature-scheme abstraction.

## Context

Lighthouse currently treats validator signatures as BLS points. This works because BLS signatures
have fixed-size context-free encodings, aggregate by point addition, and support fast randomized
batch verification. These properties are visible well beyond `crypto/bls`: consensus types mutate
aggregate points in place, pools aggregate while holding data structures, state processing builds
BLS `SignatureSet`s, and validator signing is stateless at the crypto layer.

The inspected leanMultisig binding has different semantics:

- an XMSS raw signature is bound to both a 32-byte signing root and a `u32` one-time-use index;
- the same one-time-use index must never sign two different roots;
- aggregate evidence is a large recursive proof, not an algebraic point;
- producing a proof is expensive and memory-intensive;
- decoding a proof requires the claim and exact signer set, which are not carried in its bytes;
- raw signatures and recursive aggregate proofs are distinct kinds of evidence;
- signer and proof sizes must be bounded before allocation and parsing.

The target is a separate, genesis-started private devnet. Mainnet wire compatibility and a node
that dynamically switches an existing chain between BLS and PQ are not requirements.

## Design Forces and Invariants

1. The default BLS build must retain its current SSZ bytes, tree roots, and validation behaviour.
2. A PQ build must not silently use BLS for validator proposals, attestations, or any enabled
   consensus duty.
3. Consensus objects need concrete bounded wire types. Runtime type erasure is not acceptable at
   the SSZ boundary.
4. Verification must reconstruct the signing root, one-time-use identifier, and exact authorized
   signer set before parsing PQ aggregate evidence.
5. Proof generation must not run on a Tokio worker or while a pool lock is held.
6. Validator signing must reserve one-time-use state durably before returning publishable bytes.
7. Invalid peer evidence must be distinguishable from a local setup, resource, or prover failure.
8. The first abstraction should be small enough to migrate incrementally and deep enough that PQ
   mechanics do not leak back into every caller.

## Alternatives Considered

### Alternative A: Generalize `crypto/bls` into `SignatureScheme`

This would retain the existing public shape: fixed byte constants, point-like decoded signatures,
an infinity value, context-free decoding, `add_assign`, and fast aggregate verification.

This alternative is rejected. Those are BLS properties, not validator-signature properties.
Emulating `add_assign` would either hide multi-second proving behind a cheap-looking method or
produce an object that is not yet valid wire evidence. Context-free decoding is impossible for the
inspected PQ proof. Extending the existing traits would make an unsound abstraction convenient.

### Alternative B: Make consensus types generic over a rich `SignatureProfile`

This is the maximal static-typing design. `BeaconState`, `Validator`, attestations, blocks, API
objects, caches, and stores would carry a profile parameter whose associated types define public
keys and every signature form.

It is theoretically clean but rejected for the first devnet. Lighthouse's consensus graph is
already parameterized by `EthSpec`; adding another pervasive parameter would touch most persisted
and API-facing types before producing a vertical PQ path. A runtime BLS/PQ enum has the same
problem in another form and intentionally changes every SSZ container by adding tags.

The useful part of this alternative is retained internally: the active build has explicit
scheme-specific wire types and backend adapters. The profile does not become a public generic
parameter threaded throughout Lighthouse.

### Alternative C: One minimal `ConsensusSignatureEngine`

This design exposes a concrete compile-time-selected engine with two operations:
`verify_all(requests)` and `aggregate(owned_job)`. It is the smallest viable operational seam and
correctly excludes point addition from the interface.

This is close to the chosen design. It is insufficient by itself because XMSS signing owns durable
state, async I/O, and a stronger safety contract than either verification or aggregation. Folding
signing into the engine would couple nodes that only verify to key storage and journals.

### Alternative D: Caller-first domain services

This design preserves high-level Lighthouse APIs and hides signature mechanics behind block/gossip
verification, aggregation finalization, and signing services. It avoids exposing a universal public
crypto trait and moves expensive proof generation out of consensus value types.

This is also close to the chosen design. A purely domain-level implementation still needs one
small reusable crypto boundary so block processing and gossip cannot independently recreate
backend dispatch, error classification, limits, and proof parsing.

## Chosen Architecture

Use a hybrid of the minimal-engine and caller-first designs:

```text
concrete active wire types (compile-time BLS or PQ)
                  |
          consensus signature verifier
                  |
       state-processing request builders
          /                       \
 block verification          gossip verification

aggregation pools --snapshot--> aggregation service --owned job--> backend prover

validator duties --> signing authority --> durable use journal --> backend signer
```

The wire boundary is static. The operation boundaries are deep modules whose private backend may
evolve from in-process code to an owned worker process without changing consensus callers.

### 1. Concrete active wire types

The signature crate exports semantic types selected for the build:

```rust
pub struct PublicKeyBytes(/* active bounded representation */);
pub struct IndividualSignature(/* active bounded representation */);
pub struct SameMessageEvidence(/* active bounded representation */);
pub struct OneTimeUseId(u32);

pub struct SigningClaim {
    pub signing_root: Hash256,
    pub one_time_use: OneTimeUseId,
}
```

`IndividualSignature` and `SameMessageEvidence` remain distinct concepts even if the BLS build
uses identical underlying primitives. The PQ same-message container may carry the binding's tagged
raw-or-proof encoding so promoting a single attestation is cheap. Promotion must never invoke the
prover; proof generation occurs only when contributions are combined.

BLS remains the default profile and preserves its current fixed-size encodings. The PQ build uses
bounded variable-size proof bytes and an explicit algorithm/parameter/wire version where needed.
Features must be arranged so ordinary workspace `--all-features` use is not made uncompilable;
the implementation may use a distinct PQ package/binary if mutually exclusive active aliases prove
too fragile.

### 2. Verification boundary

State processing owns consensus facts: domain computation, signing-root construction, duty-derived
one-time-use ID, validator-index resolution, and canonical signer ordering. It produces requests;
the verifier owns cryptographic parsing, batching, limits, and backend error translation.

```rust
pub enum EvidenceRef<'a> {
    Individual(&'a IndividualSignature),
    SameMessage(&'a SameMessageEvidence),
}

pub struct VerificationRequest<'a> {
    pub claim: SigningClaim,
    pub evidence: EvidenceRef<'a>,
    pub expected_signers: &'a [VerificationKey],
}

impl ConsensusSignatureVerifier {
    pub fn verify_all(
        &self,
        requests: &[VerificationRequest<'_>],
    ) -> Result<(), VerifyError>;

    pub fn verify_each(
        &self,
        requests: &[VerificationRequest<'_>],
    ) -> Vec<Result<(), VerifyError>>;
}
```

Resolved verification-key handles preserve Lighthouse's decompressed BLS key cache. Each handle
must also expose canonical bytes for exact PQ signer-set authorization. `verify_all` supports the
all-or-nothing block path; `verify_each` centralizes the current gossip batch-and-fallback policy.

`VerifyError` separates invalid or malformed consensus evidence from local unavailable,
resource-exhausted, and internal failures. Callers must not penalize peers for the latter group.

### 3. Aggregation boundary

Consensus pools store verified contributions and participant identity cheaply. They snapshot the
inputs under their existing lock, release it, and submit an owned job. Bits and evidence are
committed together only after successful finalization.

```rust
pub enum Contribution {
    Individual {
        signer: VerificationKey,
        signature: IndividualSignature,
    },
    SameMessage {
        signers: Vec<VerificationKey>,
        evidence: SameMessageEvidence,
    },
}

pub struct AggregationJob {
    pub claim: SigningClaim,
    pub expected_signers: Vec<VerificationKey>,
    pub contributions: Vec<Contribution>,
}

impl SignatureAggregationService {
    pub async fn aggregate(
        &self,
        job: AggregationJob,
    ) -> Result<SameMessageEvidence, AggregateError>;
}
```

The owned request can cross a dedicated thread or process boundary. The first PQ implementation
uses bounded concurrency of one, explicit input and output limits, and no work on Tokio workers.
The service validates duplicate/overlapping signer subsets and exact canonical signer union before
proving. BLS follows the same service path but performs cheap point addition internally.

Multi-claim proof construction is a later capability, not overloaded into same-message aggregate.
The inspected backend permits at most 16 claims and any use must preserve that explicit bound.

### 4. Stateful signing authority

Signing is a separate validator-client concern:

```rust
pub struct SignIntent {
    pub signing_root: Hash256,
    pub duty: SigningDuty,
}

impl SigningAuthority {
    pub async fn sign(
        &self,
        intent: SignIntent,
    ) -> Result<IndividualSignature, SignError>;
}
```

`SigningDuty` is an exhaustive semantic enum, not a raw caller-provided integer. A centralized,
checked mapping assigns distinct one-time-use IDs to all potentially different messages within an
Ethereum slot, including indexed subcommittee duties. The initial layout is
`slot * LEAVES_PER_SLOT + duty_offset`, with checked conversion to `u32`, an advertised maximum
devnet lifetime, and uniqueness tests covering every enabled duty.

Before returning signature bytes, the authority durably reserves
`(validator_key, one_time_use_id, signing_root)`. Retrying the identical root is allowed and must be
deterministic. Attempting a different root at an occupied ID fails closed. Concurrent requests for
one key serialize through the journal. This mechanism complements but does not replace ordinary
slashing protection.

## Ownership and Dependency Direction

- `crypto/bls` remains the low-level BLS implementation and keeps its primitive/vector tests.
- `crypto/consensus_signature` owns semantic requests, errors, active wire types, validation
  limits, the verifier facade, and private backend adapters.
- `consensus/state_processing` owns domain request construction and signer resolution.
- `beacon_chain` owns the asynchronous aggregation service and pool finalization policy.
- `crypto/pq_signing` owns encrypted PQ keys, live XMSS keys, and the crash-safe one-time-use
  journal behind a non-bypassable synchronous authority. `validator_client/signing_method` owns
  semantic duty routing and dispatches each complete reserve-and-sign call through Lighthouse's
  scoped blocking executor.
- `consensus/types` depends only on active wire types; it must not depend on leanVM or a prover.

PQ verification remains in-process. PQ proving begins in-process on a dedicated bounded executor,
but the owned job interface deliberately permits a future process adapter. External signing,
builders, deposits, and BLS-to-execution-change are separate integrations and may be explicitly
disabled in the first preset rather than absorbed into this abstraction.

## Wire and Protocol Rules

- Begin the PQ chain at an Electra-or-later fork so gossip uses `SingleAttestation`; a legacy
  one-bit aggregate should not force one-signer proof generation.
- Parse an aggregate only after its outer claim and exact expected signer list are known.
- Fork or wrap the binding to enforce strict individual-versus-aggregate kind checks. A costly
  recursive proof must not be accepted in a field designated as an individual signature.
- Apply proof byte, signer count, recursion/input, and allocation bounds before backend parsing.
- Do not put a runtime BLS/PQ tag into existing mainnet containers. The PQ devnet is a distinct
  compile-time-selected wire schema from genesis.
- Keep KZG and non-validator cryptography outside this abstraction.

## Error Handling and Scheduling

Verification errors have two top-level meanings:

- `Invalid`: malformed bytes, bad signature/proof, wrong claim, unauthorized or non-canonical
  signer set. This is consensus-invalid evidence.
- `Local`: setup unavailable, resource limit temporarily exhausted, worker/process failure, or an
  internal invariant failure. This must not be converted into peer misbehaviour.

Aggregation errors additionally report invalid contribution structure, overlap, claim mismatch,
cancellation, and output-limit failure. A failed aggregation leaves the pool snapshot retryable and
does not mutate the advertised participant bits.

Setup is explicit and idempotent. Proving is scheduled on a dedicated resource with queue bounds,
cancellation, latency/proof-size metrics, and initially one concurrent job. Verification may use
backend-specific batching while retaining stable request/result ordering.

## Test Strategy

The migration proceeds by branch-by-abstraction:

1. Add the boundary backed only by BLS and assert raw, aggregate, wrong-root, and wrong-key cases.
2. Route block and gossip verification through it while retaining existing BLS vectors.
3. Split semantic individual and same-message evidence with golden SSZ/tree-root regressions.
4. Add the pinned PQ adapter and shared boundary conformance tests.
5. Add exhaustive duty-ID and crash-safe journal tests before enabling PQ signing.
6. Move attestation aggregation to owned jobs, with failure-atomic pool tests.
7. Add bounded wire/network tests and a multi-node devnet smoke harness.

Important boundary cases include exact signer-set ordering; missing, extra, duplicate, and
overlapping signers; malformed, truncated, and oversized evidence; wrong root and one-time-use ID;
raw-plus-child and child-plus-child aggregation; cancellation/resource exhaustion; stable
`verify_each` ordering; journal restart/crash/concurrency/replay; and proof finalization outside
locks.

Completion requires the default BLS build to keep its golden bytes and the PQ build to finalize a
multi-node chain across a validator/node restart without validator-signature BLS fallback.

## Consequences

The abstraction is intentionally not universal. Wire representation, SSZ/tree hashing, key-cache
storage, secret keys, BLS batch algorithms, PQ setup/proof topology, and one-time-use persistence
remain scheme-specific. What becomes common is the stable language spoken by consensus callers:
verify this claimed evidence from these signers, finalize these contributions, or sign this duty
safely.

This keeps the first vertical path tractable and makes the expensive/stateful differences visible
in the API. It also preserves room for another PQ backend later without pretending that all
signature schemes are interchangeable points.
