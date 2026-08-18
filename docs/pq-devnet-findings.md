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
10. Store permanent XMSS-use tombstones in a separate global
    `validators_dir/xmss_usage.sqlite`, not in validator key directories or the EIP-3076 slashing
    database. A key, its XMSS journal, and ordinary slashing state form one non-rollbackable backup
    unit.

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

A hash-chain (historically, "hash onion") RANDAO reveal is a relevant alternative for a future PQ
profile. It could replace the signature-derived RANDAO contribution and therefore remove RANDAO
from the XMSS duty table, saving one one-time-use leaf and avoiding a large PQ signature in every
proposed block. It also introduces its own stateful commitment, backup/rollback, migration, and
distributed-validator constraints. `LeanPqDevnetV1` deliberately keeps the current signature-shaped
RANDAO rule for the first controlled devnet. Adopting a hash chain must create a new versioned
profile and genesis/wire transition; it must not change the frozen 14-leaf stride in place, because
that would remap every later XMSS leaf for existing keys.

The journal provides fail-closed at-most-one-publication semantics per duty instance. An identical
root may be retried; a different root for the same duty and slot is refused. Supporting multiple
aggregate attempts would require an explicit protocol attempt identifier and is outside V1.

No one-time-use leaf is allocated for an empty sync aggregate or a Gloas self-build placeholder.
Those require explicit absent/empty evidence rules rather than fake infinity signatures in PQ.

## XMSS Usage Journal

The journal is owned by the local signing authority and uses SQLite DELETE rollback-journal mode
with `synchronous=EXTRA`, exclusive database locking, one serialized connection, explicit
application and schema versions, and fail-closed integrity checks. `EXTRA` is required because in
rollback mode it additionally syncs the containing directory after journal unlink, closing the
last-commit power-loss gap left by `FULL`, as documented by
[SQLite's synchronous pragma](https://www.sqlite.org/pragma.html#pragma_synchronous). Provisioning
alone creates and directory-syncs the
database plus a persistent 0600 OS lockfile; normal validator startup opens existing regular files
without creation or symlink following and refuses missing, corrupt, truncated, wrong-version,
wrong-mode, insecure-permission, or mismatched state. The persistent lock guard never removes its
pathname, avoiding an unlink-before-close inode race.
The implementation rejects non-Unix PQ journal startup until an equivalent ACL/permission contract
is implemented there; Unix lock and database opens reject symlinks and verify opened-file metadata.

The logical tables bind each stable XMSS key identity, derived solely from its canonical 32-byte
public key, to a fixed 32-byte profile ID, allocation version, genesis validators root, public key,
and inclusive leaf range, then store permanent
`(key_id, one_time_use_id) -> signing_root` reservations. Profile changes do not create a namespace
escape: one underlying XMSS key can never reuse the same leaf under another profile. Reservations
are never pruned and survive validator deletion/reimport.

Reservation runs in an exclusive transaction and commits before signing. It returns `Fresh` for a
new row, `SameRoot` for an identical retry, and `ConflictingRoot` otherwise. A signer failure or
cancellation after commit leaves the leaf burned. The database transaction and mutex are released
before entering the upstream secret-key cache or expensive signing code.

This state does not belong in `slashing_protection.sqlite`: EIP-3076 import/export and pruning know
only block and attestation records, existing slashing operations commit in separate transactions,
and placing the tables together would not make the two safety checks atomic. For PQ attestations,
Lighthouse's current sign-before-batch-slashing-check order must be reversed. The safe sequence is
ordinary slashing-protection commit, XMSS reservation commit, then signature generation. Exact-data
retries must remain eligible so crashes between these steps can recover deterministically.

An append-only flat file is rejected because torn-record recovery, fsync, interprocess locking, and
compaction duplicate SQLite functionality. Journal rows must not live in the recoverable validator
cache or per-validator directory because current key deletion removes those paths.

EIP-3076 interchange alone is not a safe PQ migration or backup. A stopped-validator backup must
bundle immutable encrypted key material, this journal, and ordinary slashing state. Restoring a
stale journal after later signatures is unsafe; key rotation is the safe recovery boundary.

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

### 2026-08-18: XMSS journal architecture

- Chose a separate global SQLite journal with permanent per-key leaf tombstones and strict startup
  validation.
- Confirmed journal durability must precede signing and ordinary slashing protection must precede
  journal reservation.
- Confirmed current concurrent attestation signing happens before its batch slashing check and must
  be reordered for PQ.
- Confirmed validator deletion, EIP-3076 export, and recoverable-cache repair cannot delete,
  recreate, or substitute for XMSS usage state.

### 2026-08-18: Crash-safe XMSS journal implemented

- Added the feature-isolated `signing_method` journal with STRICT, WITHOUT ROWID key and
  reservation tables, fixed application/schema/profile/allocation versions, key identity derived
  from public-key bytes, exact active-binding validation, and permanent leaf tombstones.
- Normal startup is non-creating and fail-closed across missing/corrupt/truncated/wrong-version
  databases, non-DELETE mode, insecure permissions, symlinks, schema/integrity/foreign-key errors,
  and key/profile/genesis/allocation/range mismatch. Extra historical key registrations remain
  valid so validator deletion cannot erase state. Canonical `sqlite_schema` validation rejects
  weakened constraints and every executable/extra schema object, including a trigger that could
  delete a committed tombstone. Local SQLite and filesystem diagnostics are retained for startup
  operability without changing fail-closed behavior.
- Reservation uses one exclusive transaction with `ON CONFLICT DO NOTHING`; identical roots are
  retryable and conflicting roots are refused. The transaction and connection mutex are released
  before the callback. Callback error, panic, and process abort burn the committed leaf, while an
  injected or process-abort failure before commit rolls back without invoking signing.
- The targeted PQ journal matrix passes 25 tests, including conflicting and identical concurrent
  attempts, a real second-process lock refusal, restart recovery, abort-before/after-commit
  recovery, non-mutation of validator key files, and 0600 database/lock permissions.

### 2026-08-18: Frozen duty allocation implemented

- Added semantic `SigningDuty` and `OneTimeUseId` types with the frozen 14-leaf
  `LeanPqDevnetV1` mapping. Every duty offset is explicit; slot multiplication, offset addition,
  and `u32` conversion are checked.
- Enforced sync subcommittee indices `0..=3` and the maximum complete duty-row slot
  `306,783,377`. Slot `306,783,378` is rejected for every duty even though its first four leaf
  values would individually fit, so every accepted slot has a complete stable row.
- Production `SignableMessage` extraction now obtains the slot from the signed object for all
  enabled Electra duties. Validator registration, voluntary exit, execution-payload envelope,
  payload attestation, and proposer preferences return typed V1-unsupported errors.
- Changed the validator-store RANDAO API to accept the containing proposal slot. The validator
  store and Web3Signer adapter derive the epoch from that slot, preserving the existing BLS
  signing root while retaining the distinct V1 RANDAO leaf.
- Remote/distributed signing and account-manager offline exits remain outside this local mapping;
  they do not get invented `SignableMessage` variants. Tasks 3.3 and 6.2 own their explicit
  startup/invocation rejection tests. Empty sync aggregates and Gloas self-build placeholders are
  not `SignableMessage` signing requests and allocate no leaf.

### 2026-08-18: PQ evidence envelope and strict raw boundary

- Chose a Lighthouse-owned envelope: `LHPQ`, one-byte wire version, one-byte parameter-set ID,
  one-byte semantic evidence kind, then the backend payload. The exact pinned raw form is 1,215
  bytes: seven Lighthouse header bytes plus the 1,208-byte XMSS signature payload.
- The fixed-size raw adapter does not preserve the upstream private `LMSI` representation tag on
  the network: it strips the raw tag locally and reconstructs it only after the Lighthouse envelope
  has selected the raw field kind. Aggregate evidence cannot use that shortcut because the pinned
  backend exposes only the complete private `Signature::to_bytes()` representation. Task 4.2
  therefore preserves the full `LMSI/version/aggregate` envelope inside the Lighthouse aggregate
  payload and checks that inner representation before contextual decoding.
- Raw verification can proceed without prover setup. A PQ individual-signature field accepts only
  the exact raw form. Same-message evidence will later admit raw promotion, aggregate proof, or a
  canonical seven-byte absent value; aggregate evidence is capped at 512 KiB for V1.
- A narrow fork is still required before hostile aggregate inputs or external distribution. The
  current aggregate decoder contains nested variable-length allocations, and the pin exposes no
  public representation-specific decoder or constants. The fork must add bounded raw/aggregate
  APIs, parameter identity, one-time-use terminology, and complete license metadata.
- The implemented raw boundary accepts exactly 1,215 bytes, checks the Lighthouse header before
  touching the backend, and leaves the 1,208-byte payload opaque until claim and public-key context
  are present. Scalar tests confirm deterministic same-claim retries and raw verification without
  creating a prover; wrong root, key, or one-time-use ID, non-canonical field elements, out-of-range
  signing, and the canonical empty raw placeholder all fail closed.
- Upstream `Claim`, `Signature`, `SecretKey`, and `verify` are no longer re-exported. The temporary
  `PqUnreservedSigningKey` and raw sign operation are crate-private and compiled only for unit
  tests, with a compile-fail API regression. Task 3.3 must co-locate the upstream sign primitive
  with the durable journal-owning authority (or provide another non-bypassable combined
  reserve-and-sign operation); simply re-exporting the unreserved type would recreate unsafe XMSS
  leaf reuse. `PqProver` accepts semantic raw contributions and returns an opaque in-memory
  aggregate, leaving aggregate wire bytes and hostile bounded decoding to Task 4.1.
- The V1 semantic signer/contribution limit is frozen at 32,768. Empty and oversized proving jobs
  fail before contextual decode or allocation of the backend-signature vector; empty and oversized
  expected signer sets fail before backend-key collection. Boundary errors are backend-independent. The
  opaque backend diagnostic deliberately terminates `Error::source`, and the private bridge maps
  raw-input failures separately from owned-prover failures. In particular, recursive proof errors
  on the raw-only worker path are `LocallyGeneratedProof` and therefore local/internal, while
  unknown or impossible upstream variants also default local.
- The final refactored semantic two-signer AVX2 smoke passed in 36.604 seconds on the same development
  host. It still verifies the exact signer set and rejects missing, extra, substituted, and
  wrong-claim contexts. No new peak-RSS measurement was taken in this slice.

### 2026-08-18: PQ key storage implemented

- Chose a distinct `PqKeystore` and `pq-voting-keystore.json`, reusing only Lighthouse's existing
  EIP-2335 `Crypto` encryption primitives. The payload is an XMSS key, not an EIP-2333 BLS scalar,
  so the file is explicitly not advertised as EIP-2335 and is never discovered as
  `voting-keystore.json`.
- The outer schema pins the Lighthouse format/version, scheme, parameter set, exact bindings
  revision `c0ef8e621556581b2beb0c4f72f99c001a026fe6`, exact leanVM backend revision
  `aed646200cf5ae3199c25c61f2bfe094582678ae`, canonical lowercase 32-byte public key, and inclusive
  one-time-use range. `Crypto` alone does not authenticate arbitrary outer JSON fields, so the
  encrypted plaintext contains a canonical duplicate of every security-relevant field. Reload
  requires an exact inner/outer match, exact canonical upstream reserialization, and rederived
  public-key/range equality.
- The controlled format accepts only scrypt `n=262144,r=8,p=1,dklen=32` with a 32-byte salt,
  AES-128-CTR with a 16-byte IV, and SHA-256 with a 32-byte checksum. These checks happen before
  the KDF, avoiding the generic envelope's much broader cost range. Public JSON input is capped at
  16 MiB and ciphertext at 4 MiB before expensive processing. `PqKeystore` deliberately does not
  implement public `Deserialize`; callers must use the bounded string/reader constructors.
- V1 accepts raw passwords of 1--4,096 bytes only when they are valid UTF-8 and remain nonempty
  after the exact EIP-2335 NFKD normalization and Unicode control-character removal shared with
  encryption/decryption. Checked range/password preflight runs before entropy, upstream key
  construction, scrypt, or provisioning mutation. Any nonempty contiguous inclusive one-time-use
  range containing at most 1,120 IDs is accepted, and the range cap is rechecked on metadata load.
- Upstream secret serialization persists the seed, range, precomputed top tree, version, and
  checksum but no used-leaf state. Reload must rederive and compare the public key/range; the
  separate SQLite journal remains mandatory. The live upstream key is not zeroized on drop, which
  remains an experimental limitation.
- No public storage API returns a live sign-capable upstream key. Task 3.2 only provides validated
  metadata/password checks; Task 3.3 must introduce the narrow combined journal-owning authority.
- `PqValidatorDirBuilder` retains rustix directory descriptors for existing base/password roots or
  their parents, performs cheap descriptor-relative collision preflight before scrypt, and uses
  only `mkdirat`/`openat` beneath those descriptors for provisioning mutations. Canonical
  `0x<64-lower-hex>` validator directories are 0700; keystore/password files use exclusive create,
  0600, no-follow, descriptor metadata/entry identity checks, and file/directory `fsync`. Final
  validation rereads the keystore through the retained child descriptor and rejects path/descriptor
  replacement. Directory-local discovery is deterministic, immediate-child-only, and rejects
  symlinked, locally partial or malformed, mixed BLS/PQ, non-canonical, and post-open
  identity-replacement cases. It cannot detect a missing external password file; password
  validation or the startup provisioning cross-check reports that failure.
  Password ingress is capped and reads directly into a fully preallocated zeroizing buffer, so
  partial reads, oversize inputs, and read errors do not leave an ordinary secret `Vec`. It
  deliberately does not create an account-utils/validator-client `ValidatorDefinition`: that type
  remains BLS-keyed until Task 4.1.
- The directory and external password file cannot be committed atomically. Pathname cleanup after a
  successful create is deliberately forbidden because it can unlink an attacker-substituted inode.
  Handled errors and process/power loss therefore leave fail-closed tombstone files/directories;
  retries collide until provisioning explicitly inspects and removes the leftovers. Discovery fails
  closed on a partial PQ directory. Descriptor-relative mutation prevents ancestor-path swaps from
  redirecting writes, but an actor already able to mutate the retained directory can still race
  same-inode content changes or hard links; provisioning roots must not be shared with such an actor.
- Debug-profile measurement for an 8-leaf inclusive `0..=7` key on Linux 7.0.0-28-generic,
  x86_64, AMD Ryzen 9 7950X3D (16 cores/32 threads), 62 GiB RAM, rustc 1.94.0: upstream bytes 730,
  JSON bytes 2,631, deterministic key generation 56.503 ms, scrypt encryption 17.304 s, and
  decrypt/reconstruct/validate 17.071 s. After the final review fixes, the serial 12-test active
  hostile-input suite took 189.86 s and the 7-test validator-directory suite took 189.13 s. A
  manual ignored measurement target now covers the real inclusive `0..=1119` range, but it was
  deliberately not run in this slice: upstream key generation is linear and that measurement is
  not practical during ordinary tests.

### 2026-08-18: Direct PQ genesis decisions deferred to Task 4.1b

- The initial 64-slot run plus 16-slot lookahead is planned to provision IDs `0..=1119`. Generate
  validators sequentially and do not add outer keygen/scrypt parallelism.
- The first devnet uses 16 validators so minimal-preset committees exercise real aggregation. Its
  future genesis registry will be initialized directly from PQ public keys with deterministic
  execution withdrawal credentials and zero deposits. BLS shadow keys, dummy deposit evidence,
  and weakened deposit verification remain forbidden.
- Provisioning belongs in one PQ-only `lcli` command that derives keys deterministically, creates
  genesis, writes distinct validator directories, creates the bound XMSS journal, then reopens and
  cross-checks every key, registry entry, and journal registration. This is Task 4.1b, after Task
  4.1 replaces the BLS-sized registry/wire fields.

### 2026-08-18: PQ wire-schema preflight

- The wire/profile boundary is compile-time selected. `consensus_signature/pq-wire` contains only
  serialization types; `pq-devnet` adds the pinned leanMultisig backend. `types/pq-devnet` forwards
  only `pq-wire`, so consensus objects and schema tooling do not pull the prover, Lean VM runtime,
  or its large setup graph into their dependency closure. With all package features enabled,
  `pq-wire` deterministically selects the PQ aliases; mutually exclusive Cargo features are
  avoided.
- PQ validator public keys are fixed 32-byte values and individual signatures are fixed 1,215-byte
  Lighthouse `LHPQ/v1/parameter1/raw` envelopes. Same-message evidence is a distinct bounded
  variable-size SSZ byte-list from the first PQ schema, capped at 512 KiB. It supports canonical
  raw promotion and absent evidence in Task 4.1; Task 4.2 adds hostile aggregate-proof validation
  and construction without changing container offsets or tree roots.
- Active validator identity fields include the registry, state pubkey cache, sync committees,
  validator withdrawal/consolidation requests, and pending-deposit queues. Deposit ingress,
  builder/relay messages, and BLS-to-execution changes remain explicitly BLS and are disabled or
  kept out of the initial PQ devnet path. The legacy sync-committee aggregate-public-key field uses
  a canonical zero PQ placeholder and is never a PQ verification input.
- PQ types deliberately do not imitate BLS point mechanics. Point addition, infinity semantics,
  decompression, direct BLS verification, and secret-key convenience constructors are gated out;
  signing, verification, and aggregation remain separate deep service boundaries.
- A full PQ-feature `types` test invocation is not a valid Task 4.1-local gate because dev-dependency
  feature unification pulls the same PQ `types` instance into still-BLS-only beacon-chain and
  state-processing code. Task 4.1 uses focused wire/schema tests and PQ `types --lib` checks, while
  preserving the complete default BLS suite. Full PQ downstream checks become mandatory as those
  callers migrate.

### 2026-08-18: PQ wire schema implemented

- Implemented `consensus_signature/pq-wire` as a serialization-only feature and made
  `pq-devnet` add the exact-pinned backend on top. The 32-byte public key, 1,215-byte raw envelope,
  and bounded same-message type implement canonical lowercase `0x` JSON, SSZ, tree hash, and
  optional arbitrary construction without importing leanMultisig. Package `--all-features`
  deterministically selects the PQ aliases.
- The raw parser checks the exact 1,215-byte length before examining attacker-controlled header
  fields, then requires `LHPQ`, wire version 1, parameter set 1, and evidence kind 0. Its all-zero
  backend payload is a structurally canonical construction placeholder, not valid evidence.
  Public-key strings reject uppercase/non-canonical hex.
- `PqSameMessageEvidence` is variable-size SSZ from its first release and uses the list limit in
  its tree root. Raw promotion only copies the frozen raw envelope. Absent evidence is exactly
  `LHPQ/v1/parameter1/kind2` (seven bytes). Aggregate evidence is structurally framed as
  `LHPQ/v1/parameter1/kind1` plus at least one opaque payload byte and is capped at 512 KiB;
  contextual proof parsing remains Task 4.2.
- Active validator identity now covers `Validator`, the state pubkey cache and registry APIs, sync
  committees/duties, withdrawal and consolidation requests, and `PendingDeposit`. Deposit ingress,
  builders/relays, validator registration, and BLS-to-execution objects retain explicit BLS keys.
  The PQ sync-committee aggregate-key field is always the canonical zero key. No PQ code consumes
  it as a verification input.
- BLS-only point aggregation, infinity seeding, decompression, direct verification, and
  `SecretKey` convenience constructors in `types` are compile-time absent in the PQ profile.
  Data-only construction and raw-to-same-message promotion remain available. The Gloas helper that
  chooses between a self-build validator key and a builder BLS key is also absent because those
  key types intentionally differ.
- The isolated normal-dependency schema harness under `consensus/types/tests/pq_schema_harness`
  avoids `types` dev-dependency feature unification and pins PQ registry/request/pending-deposit,
  signed-header, and `SingleAttestation` sizes, offsets, and roots. Invoking a PQ integration test
  through the `types` package itself still reaches the expected later-milestone blockers in
  `state_processing` and `slasher`, including BLS deposit ingress conversion and BLS batch
  verification. This is not a Task 4.1 `types --lib` failure. Run its mandatory entry point with
  `cargo test --manifest-path consensus/types/tests/pq_schema_harness/Cargo.toml --locked --lib`;
  its lockfile is committed for reproducibility, while normal root workspace test commands
  intentionally cannot discover the nested harness.
- Cargo feature unification makes PQ selection a two-part invariant for packages containing
  `types`: they must forward the matching `types/pq-devnet` profile whenever they directly enable
  `consensus_signature/pq-devnet` or `pq-wire`. `signing_method/pq-devnet` therefore selects both
  crates; selecting only the signature crate mixes PQ aliases with BLS-only `types` helpers.

### 2026-08-18: Signing-authority and provisioning boundary correction

- Rust has no cross-crate private or friend visibility. Keeping encrypted-key decryption in
  `eth2_keystore` and the XMSS journal in `signing_method` would require a public live key, secret
  bytes, raw reservation, or callback bridge. Any of those recreates an unjournaled signing path.
  The accepted correction is a new feature-isolated `pq_signing` crate that privately owns the PQ
  keystore decoder, upstream live keys, SQLite journal, per-key signing locks, and the only raw
  signing operation.
- Public `pq_signing` APIs expose encrypted keystores, authenticated public metadata, a
  journal-provision/validate facade returning no handle, one global authority, bound signer handles,
  and a combined blocking `sign(claim)` operation. Live upstream keys, decrypted bytes, raw reserve
  calls/results, generic backends, callbacks, and unreserved signing remain crate-private.
- `eth2_keystore` returns to BLS/EIP-2335 primitives plus shared exact password normalization. PQ
  storage moves beside the authority. `validator_dir` and `signing_method` depend on that facade;
  `types` continues to depend only on lean-free `consensus_signature/pq-wire`.
- The implementation order is now Task 4.1 wire schema, Task 3.3a authority/provisioning boundary,
  Task 4.1b direct genesis/provisioning, then Task 3.3b duty routing. This lets the provisioning tool
  bind the journal without ever receiving reservation authority and lets the validator client load
  only an already-provisioned journal.
- Existing `lcli` is not a viable first PQ command boundary: it unconditionally pulls beacon,
  state-processing, networking, store, and execution crates, which feature-unifies PQ `types` into
  still-BLS-only callers. Task 4.1b therefore uses a minimal feature-isolated provisioning binary
  and a temporary genesis-only state-processing feature surface. Neither boundary is evidence that
  ordinary PQ block processing is complete.
- Direct-genesis ordering has no journal cycle: deterministic seeds produce encrypted keys/public
  keys; those keys produce the direct registry and `genesis_validators_root`; that root then binds
  the journal. The journal uses the validators root, never the state or block root. Staging output is
  published atomically without cleanup; public artifacts are deterministic, while encrypted
  keystore JSON intentionally differs because salts and IVs use fresh entropy.

### 2026-08-18: Task 3.3a signing-authority implementation findings

- Co-locating the encrypted key and SQLite journal was necessary in practice, not only in the
  design: Rust sibling crates cannot share a sign-capable value without making the bypass public.
  The new `pq_signing` crate keeps `SecretKey`, decryption, raw reservation, reservation outcomes,
  and backend-envelope conversion below `authority`; only authenticated public metadata,
  provision/validate operations returning `()`, authority construction, bound signer lookup, and
  `PqSigner::sign` cross the public boundary.
- Startup can reject unsupported profiles, duplicate public keys, missing/locked journals,
  genesis-root mismatches, and range/binding mismatches before scrypt. Only after one existing
  journal is locked and all candidate bindings validate are passwords processed and live keys
  reconstructed sequentially.
- The lock order uses one per-key operation gate across poison check, journal reservation, and
  backend completion. The journal mutex is acquired and released under that gate; only afterward
  is the separate live-key mutex acquired, so SQLite and live-key mutexes never overlap. A caught
  backend panic returns `BackendPanicked`, permanently poisons that in-memory key, and causes later
  calls to return `SignerPoisoned` before reservation. The operation gate prevents concurrent calls
  from passing the poison check while a backend call is in flight. Private injection tests prove
  panic containment, durable leaf burning, restart recovery, and concurrent no-reservation after
  poison. Subprocess tests cover rollback before commit, abort after commit/before signing, and
  abort after a real backend signature/before return.
- The leanMultisig raw encoding is not exposed through `consensus_signature`. The authority checks
  the pinned `LMSI` raw header, replaces it with the frozen `LHPQ` V1 raw header, and reparses via
  `PqRawSignature::from_bytes` before returning. The end-to-end test verifies that result through
  `consensus_signature::pq::verify_raw`, including byte-identical same-root retry and restart.
- `eth2_keystore` is lean-free again. Its only new shared surface is the exact zeroizing EIP-2335
  NFKD/control-removal helper already used by its own encrypt/decrypt paths. `validator_dir` now
  stores `pq_signing::PqKeystore`; `signing_method` no longer owns SQLite, filesystem locking, or
  XMSS reservation code.
- Because `pq_signing/pq-devnet` activates `consensus_signature/pq-devnet`, every dependent crate
  that also contains `types` must forward `types/pq-devnet`. The migrated `validator_dir` feature
  now does so, just like `signing_method`; otherwise Cargo feature unification selects PQ signature
  aliases inside a BLS-profile `types` build.
- The migrated full-feature `pq_signing` suite currently contains 55 runnable tests plus two
  ignored manual measurements; an independent run took about 463 seconds on this host because
  real-key cases intentionally retain fixed-profile scrypt and XMSS work.
- The `pq_signing` facade is deliberately synchronous and explicitly documents its blocking
  contract. Key generation, KDF authentication, durable journal operations, authority startup,
  and signing must not run on Tokio async workers. Task 3.3b must dispatch each complete authority
  operation through Lighthouse's scoped blocking executor, keeping reservation and backend signing
  in the same dispatched call.

### 2026-08-18: Direct PQ genesis and provisioning implemented

- Added the feature-isolated `testing/pq_devnet` package and `lcli-pq-devnet` binary instead of
  extending dependency-heavy `lcli`. Its default feature set is empty. The production command
  accepts only output, master-seed-file, password-file, and Eth1 timestamp paths/metadata; secret
  bytes are never command-line arguments. The frozen production constructor selects the minimal
  preset, 16 validators, and inclusive range `0..=1119`; its expensive end-to-end test is ignored.
- `state_processing/pq-genesis` compiles only genesis and the Base-to-Electra upgrade modules. The
  deposit initializer and direct-registry initializer share the same post-registry upgrade/cache/
  validators-root tail. The direct entry point fails closed unless Base, Altair, Bellatrix,
  Capella, Deneb, and Electra are all configured at epoch zero and neither Fulu nor Gloas is also at
  epoch zero. It creates no deposits, deposit signatures, pending deposits, or BLS shadow keys.
  Validators are active at genesis and the PQ sync-committee aggregate-key placeholder is the
  canonical zero key.
- The genesis-only Altair transform skips pending-attestation translation because a new genesis
  state has none. It also skips the progressive-balances cache helper to avoid pulling metrics and
  per-block modules into the narrow surface. That cache is explicitly excluded from SSZ and tree
  hashing, so state bytes/roots are unchanged; normal per-block processing initializes it before
  processing the first block.
- Validator seeds are exactly
  `SHA256("lighthouse/pq-devnet/validator-seed/v1" || master_seed || index_be_u64)`.
  Execution withdrawal credentials are `0x01 || 11 zero bytes || digest[12..32]`, where the digest
  is `SHA256("lighthouse/pq-devnet/withdrawal-credentials/v1" || master_seed || index_be_u64)`.
  Registry order follows the derivation index even though directory discovery remains lexical by
  public key. The manifest records and revalidates its format/version, preset/fork, validator
  count, range, Eth1 timestamp, validators root, every derivation index, every public key, and
  every withdrawal credential.
- Configuration, including Eth1 timestamp/genesis-delay overflow, final-path, and deterministic
  sibling-staging collisions are rejected before secret reads or KDF work. Validator count is
  capped at 16 and the key range at 1,120 IDs before key generation. The master seed must be an
  exact 32-byte private regular file; the password is a
  private regular file capped at 4,096 bytes. Both require mode 0600 and no-follow opens. Each
  secret reader makes one `maximum + 1` allocation inside `Zeroizing`; public genesis/manifest
  reads use a separate actual-length allocation and never reserve the 128 MiB bound eagerly.
- Provisioning retains the destination parent and staging directory descriptors. Staging creation,
  child-directory creation, validator/password writes, public-file writes, collision checks,
  no-replace publication, parent `fsync`, and final inode checks are descriptor-relative.
  `PqValidatorDirBuilder` now accepts held private-directory anchors; a path-swap regression proves
  writes remain in the held directories and never reach replacements. The journal remains behind
  non-signing `pq_signing` provision/validate facades; its Linux anchored variants derive the only
  SQLite path from the held staging descriptor. Because SQLite rejects `SQLITE_OPEN_NOFOLLOW` when
  an intermediate `/proc/self/fd` component is used, only this validated 0700-directory facade
  omits that SQLite flag; exclusive 0600 database/lock creation and the public reservation boundary
  are unchanged. A malicious process running as the same UID remains outside this filesystem threat
  model: it can mutate owner-writable directory entries despite the descriptor anchor, so operators
  must isolate the validator client from untrusted same-UID processes. Provisioning validation
  requires the exact registered-key set and zero existing
  reservations; the ordinary authority-open path still permits valid historical keys as designed.
- Files are durable before publication, publication is `RENAME_NOREPLACE`, and the destination
  parent is synced afterward. No failure path removes output. A pre-rename failure leaves the named
  `.pq-staging` tombstone. An injected post-rename parent-sync failure leaves the final directory as
  a tombstone and returns an error; operators must inspect/remove it explicitly rather than retrying
  or cleaning automatically. The provisioning command is Linux-only and rejects other platforms
  before opening secret files or doing KDF work.
- The deterministic one-validator `0..=3` test provisions two destinations, authenticates every
  reopened keystore, compares registry order/state bytes/public manifest data, checks both journal
  bindings before and after publication, and confirms fresh salt/IV make encrypted keystore JSON
  differ. One debug-profile run completed in 275.19 seconds on the existing development host. The
  full 16-validator `0..=1119` production run remains unmeasured/manual because its sequential KDF
  and linear XMSS construction cost is intentionally outside ordinary tests.
- The previously recorded hash-chain/hash-onion RANDAO proposal remains a future profile option.
  Task 4.1b does not change the V1 duty layout or replace signature-derived RANDAO.

### 2026-08-18: Task 3.3b validator signing/slashing core implemented

- `SignableMessage` and `SigningMethod` remain the semantic boundary; no universal crypto trait was
  added. In the PQ feature graph `SigningMethod` contains only a lightweight `PqSigner`, derives the
  frozen V1 leaf from the semantic duty, and submits exactly one combined `PqSigner::sign` call to
  the high-priority scoped blocking executor. RANDAO retains its epoch-bound signing root and
  proposal-slot-bound V1 leaf so a later hash-chain profile can remain a versioned consensus change.
  The caller-supplied signing-root helper is absent from PQ builds; PQ callers can enter only through
  the semantic-message API that derives both the signing root and frozen signing ID internally.
  The authority-bound signer is held behind an opaque signing-method wrapper and cannot be
  extracted through the public enum. Domain and epoch consistency are validated before root
  computation or reservation; wrong-context regressions subsequently sign the correct same leaves,
  proving that rejection did not burn them.
- The bounded manifest schema now lives in `validator_dir` and is shared by provisioning and the
  runtime-side bundle construction boundary. Bundle loading treats the caller-provided, actual
  network genesis validators root as the
  authority and the manifest root as a consistency check, rejects a non-canonical profile or key
  set, compares the manifest range to every cheaply validated outer keystore range, and reads
  bounded keystores/passwords through one held root directory descriptor. The same descriptor
  anchors the authority journal open, so replacing the parent path cannot redirect reservation
  history. Only after locking and validating that journal does the authority perform exactly one
  authenticated KDF/decryption and derived-key identity/range cross-check per key. A second
  authority owner is rejected before any KDF. Non-Linux builds have an explicit
  `UnsupportedPlatform` fallback; this host has no installed non-Linux Rust target with `std`, so
  only cfg-complete structure and Linux host compilation were verified here.
- Core slashing-protection APIs now use the active `ValidatorPublicKeyBytes`. PQ builds have no BLS
  shadow identity and compile without EIP-3076 import/export. Blocks retain commit-before-sign and
  allow PQ `Safe::SameData`; attestations commit their batch first, retain `Safe::Valid` plus PQ
  `Safe::SameData`, and only then reserve/sign and attach one-participant evidence. Attachment sets
  the participant bit and promotes the raw envelope without proving or combining it.
- The real-PQ duty test verifies RANDAO, block proposal, attestation, selection proof, and
  aggregate-and-proof signatures. The store integration test simulates cancellation after the
  ordinary slashing commit, recovers the same vote, produces byte-identical concurrent same-root
  evidence, rejects a conflicting vote, and observes exactly two journal reservations. It also
  proves that a post-slashing signer failure increments neither success category, while successful
  `Safe::Valid` and `Safe::SameData` outcomes increment exactly one final status after attachment;
  unregistered and slashable prechecks retain their own counters. A mixed batch preserves its
  successfully signed sibling when another signer fails. Block `SUCCESS` and `SAME_DATA` are also
  delayed until signature and signed-block construction, so either signer failure increments
  neither. The integration fixture now lives
  in a nested, isolated Cargo test harness, and the normal
  `lighthouse_validator_store/pq-devnet` graph contains neither `pq_devnet` nor `state_processing`.
  Its final debug run took 148.82 seconds on this host. The poisoned-password/locked-journal startup
  regression took 85.60 seconds and the focused authentication counter test took 34.06 seconds.
- Default EIP-3076 APIs and the fixture generator remain available when PQ is disabled, while PQ
  runtime interchange stays gated. The unchanged `make generate` workflow produced fixtures in a
  temporary directory, and `cargo check -p slashing_protection --all-features --all-targets`
  succeeds with the PQ profile selecting an explicit generator stub.
- A runnable full `validator_client/pq-devnet` feature is blocked at the package graph, rather than
  at the signing or slashing boundary. A temporary feature-forwarding check (removed after the
  diagnostic) made Cargo unify `types/pq-devnet` into `state_processing` through
  `eth2_network_config`/`environment` and produced 33 compile errors: BLS batch-verification APIs,
  aggregate-attestation and sync-committee verification, deposit/request public keys, and Gloas
  upgrade logic remain BLS-specific. Consequently the full-process startup ordering and startup
  rejection of distributed selections, builder registration, HTTP key mutation, and online exit
  cannot honestly be marked GREEN until the state-processing/network migration lands. It is now
  tracked separately as Task 3.3c, explicitly dependent on the PQ state-processing/verification
  feature-spine migration. Task 3.3b claims only the compiling signing/slashing and bounded
  bundle/authority construction core. The
  compiling boundary rejects Web3Signer by construction, gates remote mutation and EIP-3076 APIs,
  and returns explicit errors for unsupported signing duties; it does not claim an executable PQ
  validator client yet.

### 2026-08-18: Bounded contextual aggregate evidence implemented

- Task 4.1 already supplied the final 512 KiB variable-size SSZ type and Lighthouse raw,
  aggregate, and absent framing. Task 4.2's actual RED was the missing backend-owned aggregate
  construction and contextual hostile decode/verify boundary; no `types` container or tree-root
  change was needed.
- Task 4.2 initially made `PqAggregateSignature::into_same_message_evidence` the only local
  aggregate-output path. Task 5.1 removed that interim wrapper, `verify_aggregate`, and their
  backend-specific public error surface. Local construction is now confined to the crate-private
  prover worker behind public `AggregationService`. It retains the complete pinned upstream
  `LMSI/version1/aggregate` envelope inside `LHPQ/version1/parameter1/aggregate`, checks the full
  outer length against 512 KiB before constructing the wire value, and reports
  `AggregationError::OutputTooLarge` through the operation-level boundary.
- `verify_aggregate_evidence` requires the bounded evidence, exact semantic `PqSigningClaim`, and
  expected public keys in strictly ascending canonical byte order. It rejects empty/over-limit,
  duplicate, or permuted local signer contexts before allocating the backend key vector or entering
  backend parsing/setup. Raw and absent outer kinds are invalid aggregate evidence. Missing, extra,
  substituted, wrong-root, and wrong-one-time-ID contexts fail cryptographic verification.
- Generic SSZ decoding remains intentionally non-cryptographic: it checks only the Lighthouse
  envelope/kind and 512 KiB cap, leaving the aggregate payload opaque. Contextual verification
  separately requires the exact inner `LMSI/version1/aggregate` envelope and rejects malformed,
  truncated, trailing, or cryptographically invalid proofs. A mutated real two-signer proof was
  confirmed to reach upstream `Error::Proof(_)` and is classified as peer `InvalidEvidence`;
  locally generated proof errors on the owned prover path remain `Internal`. Unknown upstream
  variants remain internal, and backend sources are not exposed through the public verification
  error chain.
- The exact outer cap is accepted and max-plus-one is rejected before copying into the bounded wire
  value. The pinned upstream serializer and aggregate decoder still allocate their private nested
  representation internally. This is acceptable for the controlled exact-pin devnet because the
  Lighthouse outer cap is enforced first, but a public/untrusted hardening fork must add
  representation-specific bounded serialization/decoding APIs and resolve the already-recorded
  license provenance. No fork is required to continue this private devnet slice.
- Final focused evidence on this host: the scalar PQ suite passed 35/35 in 0.276 seconds; the
  AVX2-only real two-signer encode/decode/verify and adversarial proof test passed in 35.381 seconds;
  the default BLS suite passed 7/7. Scalar and AVX2 Rust 1.88 checks, scalar and AVX2 Clippy with
  warnings denied, the Lean-free `types/pq-devnet` normal dependency graph check, Cargo formatting
  and sorting, doc tests, diff checks, and the mandatory default workspace `cargo check` all passed.

### 2026-08-18: Owned aggregation jobs and bounded async proving implemented

- Consensus aggregation now crosses one operation-level `AggregationJob` boundary. The common
  validator requires validator-index-ordered, unique index/key mappings; disjoint non-empty
  contributions; an exact contribution/expected-signer union; and the V1 limits of 16 signers, 16
  contributions, and 8 MiB total input. Participant bits remain caller-owned so a later pool
  migration can commit bits and returned evidence atomically. BLS point addition is private to its
  backend. A single contribution is still cryptographically verified but returned byte-for-byte
  without aggregate work.
- Validator-index order is deliberately independent from backend key order. The domain structures
  remain index ordered while every PQ contribution and final signer set is separately projected to
  strictly key-sorted bytes before entering leanMultisig. Tests force the two orders to disagree.
  `PqPublicKey` now also enforces the pinned XMSS SSZ canonical encoding without a Lean dependency:
  all eight little-endian `u32` limbs must be below the KoalaBear modulus `0x7f000001`. Boundary
  tests accept `p - 1` and reject `p` and `u32::MAX` in both the first and last limb.
- PQ raw and child-aggregate evidence is decoded and verified against its exact child signers and
  common `(signing_root, one_time_use_id)` only on the named 512 MiB-stack prover worker. Recursive
  input and output retain the complete upstream `LMSI/version1/aggregate` envelope. Raw+raw,
  raw+child, and child+child jobs work; peer proof/decode mismatches are `InvalidEvidence`, while
  structural caller errors and post-verification proving failures stay local.
- `PqProver` and its constructor are crate-private; `AggregationService` is the sole public owner
  that can synchronously initialize or reserve the process singleton. Its original capacity-one
  submission channel was replaced in Task 5.3a by the reserved scheduler described below.
  Wire-only `types/pq-devnet` builds do not compile this execution service, scheduler, parking-lot,
  or futures dependency.
- The unavailable-build cfg now has one complete fallback for every target other than an
  AVX2-compiled x86-64 binary. Its target mapping returns `UnsupportedTarget` on non-x86-64 and
  `Avx2NotEnabledAtCompileTime` on scalar x86-64; host unit tests cover both mappings and the native
  scalar path. An AArch64 Rust standard library is installed, but a direct cross-target Cargo check
  cannot reach this crate because the environment lacks `aarch64-linux-gnu-gcc`, which `ring` and
  `blst` require. This is an environment limitation, not a claimed cross-target pass.
- Exact local AVX2 debug evidence used the warm-cache command
  `RUSTFLAGS='-C target-feature=+avx2' cargo test -p consensus_signature --features pq-devnet
  pq::tests::pq_dependency_smoke -- --exact --nocapture --test-threads=1`, wrapped in GNU
  `/usr/bin/time -v`. There were no concurrent Lean/Lake workers; 51 GiB memory was available and
  the run performed four serialized real proofs. Two raw+raw jobs took 7.758 s and 7.401 s and
  produced 106,895-byte and 106,546-byte evidence. Raw+child took 85.618 s and produced 164,420
  bytes; child+child took 76.112 s and produced 159,551 bytes. The test completed in 206.10 s; the
  timed command tree peaked at 2,663,836 KiB RSS and reported zero swaps. These are host/debug-build
  measurements, not production latency claims.

### 2026-08-18: PQ attestation cache and owned request prerequisite implemented

- `state_processing/pq-attestation` is a deliberately narrow compile profile. It contains only the
  PQ attestation cache/request boundary and composes with `pq-genesis`; it does not feature-unify
  the existing BLS per-block, deposit, sync-committee, epoch-processing, or Gloas graph. The
  default `ValidatorPubkeyCache`, its parallel BLS decompression, and persisted `pkc` bytes are
  unchanged.
- `PqValidatorKeyCache` is rebuilt deterministically from registry order on startup, keeps a
  registry vector plus reverse map, rechecks the Lean-free KoalaBear canonical encoding, and
  rejects empty, duplicate, or greater-than-16 registries. It has no serialization or database
  path; rebuilding it leaves the state SSZ bytes unchanged. The real backend-generated keys used
  by the integration test pass the same wire canonicality boundary.
- The pure Electra V1 builders validate the deposit-disabled/future-fork-disabled profile, checked
  validator indices, exact cache/state keys, committee membership, committee and aggregation bit
  lengths, `AttestationData.index == 0`, and one through sixteen signer indices before cloning
  evidence. The aggregate contribution count is capped at sixteen before reserving or iterating
  internal contribution vectors. Aggregate callers pass borrowed `(attestation, signer_indices)`
  views: each index list must be non-empty, strictly increasing, unique, in bounds, and exactly
  equal to the independently committee-derived list. Cross-contribution signer overlap is also
  rejected by the builder. The output is one fully owned `AggregationJob`, allowing state, cache,
  and shuffling locks to be released before any asynchronous worker wait.
- The attester domain is derived at `AttestationData.target.epoch`; the signing root covers the
  complete attestation data, and the XMSS leaf is derived only from `AttestationData.slot` plus
  `SigningDuty::Attestation`. No outer aggregate-and-proof slot or duty enters the inner claim.
  `SingleAttestation` accepts only the promotable raw envelope. Even a valid one-child recursive
  proof is rejected in that field.
- Every request, including a single contribution, is contextually verified by
  `AggregationService`. A valid singleton is returned byte-for-byte without proving. Bad evidence
  is peer/consensus-invalid; a post-construction `InvalidJob`, cache invariant, queue/resource
  limit, unavailable or poisoned worker, output overflow, and internal prover failure remain local.
  This boundary does not mutate observed-attester or pool state.
- The isolated real-key AVX2 test uses journal-backed authority signatures. It verifies raw
  pass-through, produces and then verifies a two-signer recursive proof as a single child without
  reproving, and rejects wrong signing root, XMSS leaf, key, participant bits, and recursive
  evidence in `SingleAttestation`. The final focused real-key run completed in 135.62 seconds on
  this host; a malformed-single contextual verification run completed in 23.89 seconds. After
  adding direct nonzero-data-index, bitfield/claimed-signer mismatch, and cross-contribution overlap
  regressions, the final serialized isolated suite passed 13/13 in 138.00 seconds.

### 2026-08-18: Failure-atomic PQ attestation aggregation coordinator implemented

- `attestation_aggregation` is a new optional workspace crate whose default build has no normal
  dependencies. Its `pq-attestation` feature enables only the consensus-signature PQ backend, the
  narrow state-processing attestation surface, PQ wire types, and its own `parking_lot` mutex. It
  does not enable `operation_pool` or `beacon_chain`; those integrations remain Task 5.2b.
- State processing now offers an owned prepare/verify transition. It releases every state, registry,
  and committee-cache borrow before awaiting `AggregationService`, and only successful contextual
  verification can construct the opaque `VerifiedPqAttestation`. Callers have read-only views of
  the owned Electra attestation, exact sorted signer indices, and claim. A compile-fail test guards
  the private constructor/evidence fields.
- Candidate buckets contain the full `AttestationData` and exactly one Electra committee index.
  The bounded state machine uses monotonic IDs, rejects equal/subset candidates, replaces strict
  subsets, retains overlapping incomparable candidates, and selects largest-first disjoint sets
  with insertion-ID tie-breaking. Both candidate and signer unions stop at sixteen, and generation
  overflow fails before mutation.
- Coordinator-wide retention is also bounded under that mutex: at most 64 distinct buckets and at
  most 8 MiB (`V1_MAX_AGGREGATION_INPUT_BYTES`) of actual `SameMessageEvidence` bytes. Sixty-four is
  four times the Minimal preset's honest two-epoch, sixteen-slot window. New-bucket and byte
  capacity are checked before cloning/inserting candidate storage; exact caps are accepted and
  cap-plus-one returns a specific outcome without mutation. Existing-bucket insert, dominance
  replacement, aggregate commit, and concurrent-dominated-arrival cleanup all maintain checked
  byte accounting.
- Snapshot selection, ID/handle cloning, and the in-flight mark occur under one mutex. Owned job
  construction and `.await` occur after releasing it. Commit rechecks every selected ID and `Arc`
  identity, then replaces selected sources and any concurrent candidate dominated by the finished
  signer union with union bits plus evidence in one lock hold. Genuinely incomparable/unrelated
  arrivals survive. Pruned selections return `StaleSnapshot`; construction, queue,
  backend, invalid-evidence, and dropped-preparation paths clear the in-flight marker and preserve
  sources for retry. Invalid evidence after insertion is classified as a local invariant failure,
  not peer blame.
- `prune_before_slot` atomically removes buckets whose attestation slot is below the caller cutoff
  and releases their candidate/evidence accounting. Current and future buckets are untouched. If
  pruning removes an in-flight bucket, the shared prepared execution becomes `StaleSnapshot`; a
  later commit, failure, or drop cannot recreate the bucket.
- Fifteen fast tests cover dominance, including concurrent-arrival dominance at commit, stable
  disjoint selection, one-through-sixteen limits and
  cap-plus-one, exact/max-plus-one global bucket and byte caps without large allocations, pruning
  capacity reuse, in-flight prune staleness on success and backend failure, replacement-token
  isolation after prune/recreate, committee isolation, singleton/no-proof selection,
  one in-flight snapshot,
  unrelated arrival preservation, stale selected pruning, retry preservation, lock re-entry, and
  generation exhaustion. The fake executor and real verifier now use the same private prepared
  execution owner for unlocked await, failure/drop cleanup, stale checking, and atomic commit. The
  real serialized AVX2 test uses two journal-backed raw signatures, verifies dropped preparation
  and synchronous job-construction failure both permit retry, forces a wrong-key contextual
  execution failure and successful retry, enforces one in-flight proof, commits and re-verifies the
  two-bit recursive child, and rejects altered bits, root, leaf, and key. It passed 1/1 in 137.36
  seconds (137.66 seconds command wall time) with a 794,400 KiB
  command-tree peak RSS and zero swaps.
- Raw-plus-child catch-up needs at least three distinct validators in one committee. With the V1
  registry capped at sixteen, Minimal preset slot committees contain only two validators, so that
  coordinator case is not constructible without changing the frozen profile or introducing a
  test-only consensus preset. Task 5.1 already exercises real raw-plus-child recursion; this slice
  records the coordinator limitation rather than weakening state-derived committee validation.

### 2026-08-18: Reserved PQ verification admission implemented

- `AggregationService::verify` exposes only the semantic `Block` and `Gossip` classes. It requires
  exactly one contribution before queue admission, so callers can contextually verify either raw
  evidence or an existing recursive child but cannot promote multi-contribution proving into a
  high-priority class. `aggregate` remains the only local recursive-proving API and maps to a
  private lowest-priority class. Default BLS verifies immediately and returns the same evidence as
  its aggregation boundary; the class has no scheduling effect and BLS wire behavior is unchanged.
- One private parking-lot mutex/condition-variable scheduler feeds the existing named 512 MiB
  singleton worker and process-global backend owner. It pops Block, then Gossip, then Aggregate,
  FIFO within each class. Frozen queued-only limits are two block jobs/1 MiB, four gossip jobs/2
  MiB, and one aggregation job/8 MiB. The independently owned class budgets sum to an 11 MiB global
  checked queued-evidence cap, so filling gossip and aggregation cannot consume the block reserve.
  The active job is accounted separately and remains bounded by the existing 8 MiB job-input cap;
  maximum retained evidence is therefore 19 MiB plus bounded signer/job metadata.
- Admission bounded-scans the seven possible queued entries and purges dropped result receivers
  before checking counts or bytes. Each command's cancellation state is observed exactly once in a
  one-pass stable partition, and the checked removed-byte sum covers that exact removed identity
  set; a receiver dropping concurrently after its live decision remains queued and accounted until
  the next admission or worker pop. Removed commands are accumulated while the queue and accounting
  change atomically, then destroyed only after releasing the scheduler lock, because job `Drop`
  implementations and response machinery may re-enter the scheduler. The worker releases queued
  accounting on pop and checks cancellation again immediately before backend entry. Once backend
  work starts it remains non-cancellable. Dropping the service closes admissions and detaches
  without joining; admitted jobs drain by priority and the worker retains the lifecycle guard until
  it exits.
- Queue releases use checked subtraction. Cancellation scans use checked addition, and shutdown
  first validates each class sum and the global sum against the queued commands. Any underflow,
  overflow, or mismatch permanently marks scheduler accounting poisoned, closes admission, and
  resolves retained work as `WorkerStopped`; counters are reset only after the poisoned scheduler
  has drained every queue. Normal and poisoned shutdown both finish draining under the scheduler
  lock, release that lock, and only then wake response futures, so a custom waker may safely
  re-enter scheduler admission without deadlock.
- A caught active backend panic returns `WorkerPanicked`, permanently poisons the singleton
  lifecycle, closes admissions, and explicitly resolves every queued response as `WorkerStopped`.
  Count, class-byte, and global-byte admission failures all remain local
  `ResourceExhausted(QueueSaturated)` results and must never become peer-invalid attribution.
- Priority is cooperative, not pre-emptive: a block request arriving during an active recursive
  proof waits for that proof to finish. Later block callers must submit their signature jobs
  sequentially rather than fan out into the bounded queue. Start the first devnet with 120-second
  slots and treat that only as a conservative test setting pending release-build end-to-end
  measurements; lengthen it if active-proof and sequential block verification lack margin.
- Deterministic tests cover lower-class saturation with maximum block admission still available,
  strict priority/FIFO order, exact count/class/global byte caps and cap-plus-one without evidence
  allocation, distinct admission-time and last-safe worker-time cancellation, notification of a
  worker already waiting on admission, close notification and lifecycle release, nonblocking owner
  Drop with draining, panic fan-out/poisoning, local queue-error classification, the single public
  backend owner, and default BLS equivalence. The real AVX2 recursion smoke continues to exercise
  the same singleton worker and local proving entry point. The final-tree AVX2 debug run passed 1/1
  in 206.19 seconds of test time (3:27.38 command wall including compilation): raw+raw took 7.723
  and 7.405 seconds and emitted 106,895 and 106,546 bytes, raw+child took 85.838 seconds and emitted
  164,420 bytes, and child+child took 76.066 seconds and emitted 159,551 bytes. The timed command
  tree peaked at 2,615,112 KiB RSS with zero swaps; this is not a worker-thread-only memory
  measurement.

### 2026-08-18: Owned PQ consensus verification transitions implemented

- `state_processing/pq-verification` is a narrow compile profile layered on `pq-attestation`.
  It adds no dependency on the synchronous BLS `SignatureSet` or `BlockSignatureVerifier` graph.
  The shared `pq_profile` predicate freezes Electra-from-genesis, the deposit-disabled state, and
  the no-Fulu/no-Gloas schedule in one place. A normal-edge graph audit remains the authoritative
  isolation check: invoking `cargo test -p state_processing --features pq-verification` also pulls
  that package's unconditional BLS-oriented dev dependencies and feature-unifies incompatible wire
  profiles, so behavioral tests live in the normal-dependency `pq_devnet` harness.
- Three private-constructor transitions own the exact object they authenticate:
  `PreparedPqBlockProposal -> VerifiedPqBlockProposal`,
  `PreparedPqBlock -> VerifiedPqBlock`, and
  `PreparedPqAggregateAndProof -> VerifiedPqAggregateAndProof`. Blocks are held in one `Arc` from
  preparation through sealing. The aggregate token owns its exact signed aggregate plus a sealed
  `VerifiedPqAttestation`. Prepared values retain no state, cache, committee, or shuffling borrow;
  compile-fail examples pin private fields and inner-evidence opacity.
- Preparation validates the profile, fork shape, expected proposer, registry/cache identity,
  validator and aggregator indices, committee membership, selection eligibility, Electra
  bitfields, signer union, evidence framing/caps, and `target.epoch == data.slot.epoch()` before
  submitting backend work. Individual PQ fields are promoted to one-contribution
  `SameMessageEvidence` only inside a private job helper. The full block prepares proposal, RANDAO,
  and every included attestation job synchronously, then verifies them sequentially through the
  reserved `Block` class. Aggregate gossip prepares selection, inner attestation, and outer jobs,
  then verifies them sequentially through `Gossip`. No verified token is returned on an
  intermediate success.
- Claim derivation is domain-specific and centralized: proposal uses the block epoch/domain and
  proposal-slot `BeaconBlockProposal` leaf; RANDAO signs the proposal epoch with the RANDAO domain
  but consumes the proposal-slot `RandaoReveal` leaf; inner attestation uses its target epoch for
  the attester domain and data slot for the attestation leaf; selection and outer
  aggregate-and-proof both use the aggregate data slot and distinct V1 duty leaves. The outer
  domain deliberately follows the slot epoch, and mismatched attestation target/slot epochs are
  rejected structurally. V1 still uses this epoch-bound RANDAO claim. A hash-chain/hash-onion
  RANDAO remains a future versioned profile requiring a genesis commitment, state/wire transition,
  rollback and backup policy, and no silent renumbering of the frozen V1 14-leaf layout.
- Attestation execution now makes admission intent explicit. Contextual verification requires a
  `VerificationClass`, while the aggregation coordinator calls the separate local `aggregate`
  method. This prevents one-contribution block/gossip verification from accidentally entering the
  low-priority proving class and prevents local multi-contribution proving from claiming a reserved
  verification slot.
- Fast isolated tests cover owned/`Send` prepared values, base and unselected-aggregator shapes,
  target/slot mismatch, malformed/truncated and cap-plus-one evidence, structural rejection on a
  scalar build before unavailable backend use, and stable peer-invalid versus unavailable,
  resource, panic, and internal local failures. The scalar suite passed 12/12 in 0.17 seconds. The
  serialized journal-backed AVX2 integration generates one real two-signer recursive proof and
  verifies valid proposal, RANDAO, raw block attestation, selection proof, recursive inner
  evidence, and outer signature. It rejects wrong root, proposal leaf, proposer key, aggregator
  key, and recursive signer bits/set, and proves a mixed block returns the RANDAO component only
  after its valid proposal. The final focused run passed 1/1 in 300.83 seconds (321.75 seconds
  command wall including an AVX2 rebuild), peaked at 1,284,288 KiB RSS, and reported zero swaps.
- Spec-review follow-up split compound preparation into borrow-only whole-object preflight and a
  later materialization phase. A harness-only, `#[doc(hidden)]` counter seam proves malformed final
  block and aggregate inputs cause zero evidence work; it counts owned clones, claim tree hashes,
  and the PQ selection proof's transient SSZ serialization. Aggregator eligibility and hashing are
  deferred until inner and outer structural preflight succeeds. Ordinary `pq-verification` and
  `pq-devnet` do not enable the seam. Out-of-current-epoch proposal slots now have a dedicated
  peer-invalid result, while genuine state/cache failures remain local. The production aggregation
  error mapper is directly covered for invalid evidence and every local error class. Real AVX2
  precedence checks are mutation-sensitive: RANDAO-first produced `RandaoReveal` instead of
  `BlockProposal`, and outer-first produced `AggregateAndProof` instead of both `SelectionProof`
  and `AggregateAttestation`; restored production order passed all checks.
- Final quality review made the whole-object preflight sensitivity non-tautological. With the old
  ordering, a malformed final block attestation observed one proposal-root hash instead of zero,
  and a structurally valid unselected aggregate observed selection serialization plus an outer-root
  hash (two units) instead of selection alone (one unit). Both focused tests now pass with the
  intended counts. `PqConsensusError::source` directly exposes its four nested local cause shapes
  (direct or attestation-nested signing-ID and aggregation failures); its peer-invalid and plain
  local terminal variants deliberately return no source. The source test's RED was `None` instead
  of the expected `SlotOutOfRange` cause.
