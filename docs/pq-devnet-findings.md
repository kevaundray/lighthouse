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
- The adapter will not preserve the upstream private `LMSI` representation tag on the network.
  Instead, one narrow exact-pin bridge strips it from locally produced evidence and reconstructs a
  raw or aggregate backend header only after the Lighthouse envelope has selected the field kind.
  This prevents conflicting attacker-controlled inner and outer kinds and lets a later fork replace
  the bridge without changing devnet SSZ bytes.
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
