# PQ Devnet Findings and Decisions

This is the living engineering record for replacing Lighthouse validator BLS signatures with an
experimental leanMultisig/XMSS signature scheme on a devnet. Update it whenever implementation,
testing, or devnet operation changes an assumption below.

## Scope

- Target: a private, genesis-started Lighthouse devnet.
- Mainnet interoperability is not required for the PQ build.
- KZG remains unchanged. Its use of BLS12-381 is not a validator-signature dependency.
- The first devnet may intentionally omit post-genesis deposits, Web3Signer, external builders,
  and BLS-to-execution-change operations. These exclusions must be explicit in configuration and
  must not silently fall back to BLS validator signatures.
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
- Raw signatures and recursive aggregate proofs are different consensus types. In particular,
  Lighthouse's current use of `AggregateSignature` inside `SingleAttestation` must be split.
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
  aggregation. The first devnet must require and validate AVX2, or use a fork that supplies a
  correct portable/runtime-dispatched path.

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

## Open Questions

- Exact XMSS parameter set for the first devnet: inspected 32-byte/1,208-byte configuration or a
  newer higher-security configuration.
- Exact duty-tag allocation and the number of XMSS leaves reserved per Ethereum slot.
- Whether validator proposal and attestation duties use one tree with disjoint leaves or distinct
  keys/trees.
- Whether the first block format carries one proof per aggregate or bounded multi-claim proof
  groups.
- Whether sync committee signatures are included in milestone one or enabled after attestation
  aggregation.
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
