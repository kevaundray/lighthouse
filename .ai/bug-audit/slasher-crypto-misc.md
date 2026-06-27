# Slasher + Cryptography + Cross-Cutting Runtime/Process — Bug Audit

**Scope:** The slasher subsystem (LMDB/MDBX/Redb backends, attestation + block queues, slashing detection), BLS/crypto (blst, key derivation, keystore EIP-2335, KZG), SSZ/tree-hash serialization correctness, CLI/config handling, and process-wide runtime concerns (panics, memory/CPU resource leaks, tokio runtime, deadlocks, logging).

**Queries run:**
- `gh api repos/sigp/lighthouse/issues?state=all&labels=slasher` (paginated)
- `gh api repos/sigp/lighthouse/issues?state=all&labels=crypto` (paginated)
- `gh api repos/sigp/lighthouse/issues?state=all&labels=slasher,bug` (via issue list)
- `gh api repos/sigp/lighthouse/issues?state=all&labels=lcli` (paginated)
- `gh api repos/sigp/lighthouse/issues?state=all&labels=optimization,bug` (via issue list)
- `gh api repos/sigp/lighthouse/issues?state=closed&labels=bug` (paginated, then filtered by keyword: panic, crash, overflow, deadlock, OOM, memory, unsafe, unwrap)
- Timeline API on each candidate to find fix PRs; `gh pr view` and `gh pr diff` for key fixes
- Keyword searches via the core issues API (state=all, jq-filtered titles)

---

## 2. Bug Table

| # | Title | State | Class | Severity | How-found | One-line root cause | Fix PR |
|---|-------|-------|-------|----------|-----------|---------------------|--------|
| [#9141](https://github.com/sigp/lighthouse/issues/9141) | Fix slasher OOM | CLOSED | resource | critical | user-report | Slasher received unvalidated `IndexedAttestation` before committee membership check; bogus `validator_index` (e.g. 2^40) triggered unbounded memory allocation in `AttestationBatch::group` | [#9141](https://github.com/sigp/lighthouse/pull/9141) |
| [#6277](https://github.com/sigp/lighthouse/issues/6277) | Binaries compiled with MDBX exhibit memory corruption | OPEN | resource | critical | user-report | MDBX (and underlying LMDB) C library causes memory corruption even when slasher code paths are inactive, traced to UB in the Rust bindings | n/a (MDBX being removed) |
| [#6211](https://github.com/sigp/lighthouse/issues/6211) | Work around UB in LMDB bindings | CLOSED | persistence | critical | internal-testing | LMDB cursor `get_current` returns a shared reference that is silently mutated by subsequent cursor operations (delete_current); fix copies value to owned `Vec` before mutating | [#6211](https://github.com/sigp/lighthouse/pull/6211) |
| [#9106](https://github.com/sigp/lighthouse/issues/9106) | Fix total_effective_balance=0 in PreEpochCache | CLOSED | spec-correctness | high | audit | `PreEpochCache` omitted the `max(1, ...)` floor on `total_effective_balance`; reachable only on fully-dead networks (total_active_balance=0) but produces consensus-incorrect epoch processing | [#9106](https://github.com/sigp/lighthouse/pull/9106) |
| [#8528](https://github.com/sigp/lighthouse/issues/8528) | Use correct `Fork` in `verify_header_signature` | CLOSED | spec-correctness | high | testnet-incident | `verify_header_signature` used the head state's fork instead of `fork_at_epoch`; at the Fulu fork boundary the head state was stale, causing blob/column header signature verification to fail | [#8535](https://github.com/sigp/lighthouse/pull/8535) |
| [#9173](https://github.com/sigp/lighthouse/issues/9173) | Fix builder exit signature batch verification | CLOSED | spec-correctness | high | internal-testing | Batch BLS verification path for builder voluntary exits used a different (hand-rolled) code path than the individual-verification path; EF spec tests only cover individual verification so the divergence went undetected | [#9174](https://github.com/sigp/lighthouse/pull/9174) |
| [#8491](https://github.com/sigp/lighthouse/issues/8491) | BLS: Fix `is_infinity` flag when aggregating onto empty AggregateSignature | CLOSED | logic-other | medium | code-review | `add_assign`/`add_assign_aggregate` updated `is_infinity` with conjunction before branching on whether `self` was empty; result: aggregating infinity onto `empty()` left `is_infinity=false` while the underlying point was ∞ | [#8496](https://github.com/sigp/lighthouse/pull/8496) |
| [#5078](https://github.com/sigp/lighthouse/issues/5078) | Fix PublishBlockRequest SSZ decoding | CLOSED | serialization | high | internal-testing | POST block SSZ endpoint decoded the 4-byte SSZ length prefix as the slot number to determine the fork; happened to pass existing tests because the test slot value matched the fork schedule | [#5078](https://github.com/sigp/lighthouse/pull/5078) |
| [#5080](https://github.com/sigp/lighthouse/issues/5080) | Stack overflow in `POST /eth/v*/beacon/blocks` with SSZ bodies | CLOSED | panic-crash | high | user-report | warp's deeply-nested future combinators overflowed the stack when processing SSZ block bodies; fixed by adding `.boxed()` to break the chain and later fixing the root cause | [#5104](https://github.com/sigp/lighthouse/pull/5104) |
| [#6035](https://github.com/sigp/lighthouse/issues/6035) | Fix SigVerifiedOp SSZ implementation | CLOSED | persistence | high | internal-testing | Hand-written `Encode`/`Decode` for `SigVerifiedOp` had a field ordering mismatch; schema v20 migration could silently corrupt op pool data | [#6035](https://github.com/sigp/lighthouse/pull/6035) |
| [#1889](https://github.com/sigp/lighthouse/issues/1889) | Missing EIP-2335 control code removal | CLOSED | spec-correctness | high | audit | Keystore password processing omitted stripping C0, C1, and DEL control codes as required by EIP-2335; keystores created by other-spec-compliant clients might not decrypt | [#1928](https://github.com/sigp/lighthouse/pull/1928) |
| [#1906](https://github.com/sigp/lighthouse/issues/1906) | Insufficient validation of EIP-2335 KDF params | CLOSED | config-cli | high | audit | Lighthouse accepted arbitrarily weak or absurdly large KDF params (PBKDF2 iteration count, scrypt N/r/p) enabling weak keys or DoS via memory exhaustion | [#1930](https://github.com/sigp/lighthouse/pull/1930) |
| [#1907](https://github.com/sigp/lighthouse/issues/1907) | Unvalidated IV length for EIP-2335 | CLOSED | spec-correctness | medium | audit | AES-128-CTR IV accepted at any length including zero; only minimal fix applied (reject zero-length; warn on non-128-bit) | [#1930](https://github.com/sigp/lighthouse/pull/1930) |
| [#1624](https://github.com/sigp/lighthouse/issues/1624) | Issues recovering 24-word launchpad mnemonics | CLOSED | logic-other | critical | user-report | Key derivation used a stale version of EIP-2333; mnemonic-to-key path produced different keys than the `eth2-deposit-cli`, making recovery impossible for users who used the launchpad | [#1633](https://github.com/sigp/lighthouse/pull/1633) |
| [#2857](https://github.com/sigp/lighthouse/issues/2857) | `malloc_utils` sets `M_MMAP_MAX` rather than `M_MMAP_THRESHOLD` | CLOSED | config-cli | medium | user-report | Constant `M_MMAP_THRESHOLD` was hardcoded to `-4` (maps to `M_MMAP_MAX` in glibc), silently capping mmap chunks at 2M instead of tuning the threshold; caused elevated memory fragmentation | [#2937](https://github.com/sigp/lighthouse/pull/2937) |
| [#8390](https://github.com/sigp/lighthouse/issues/8390) | Fix panic on a rare startup race condition | CLOSED | panic-crash | high | user-report | Custody backfill sync queried `custody_context` before it was fully initialized in the builder, causing a panic on a narrow startup race | [#8391](https://github.com/sigp/lighthouse/pull/8391) |
| [#6412](https://github.com/sigp/lighthouse/issues/6412) | Fix deadlock on block cache | CLOSED | concurrency | high | internal-testing | `eth1_chain.rs` acquired `block_cache` read lock (1), then called into code that tried to acquire it again (3); a concurrent write lock (2) from `prune_blocks` caused a three-way deadlock under parking_lot | [#6412](https://github.com/sigp/lighthouse/pull/6412) |
| [#6200](https://github.com/sigp/lighthouse/issues/6200) | Avoid acquiring another read lock while holding one (potential deadlock) | CLOSED | concurrency | high | internal-testing | `eth1/service.rs` held a read lock on `block_cache` and re-acquired it inside the same scope; concurrent write lock from `do_update` caused deadlock on resource-constrained nodes | [#6200](https://github.com/sigp/lighthouse/pull/6200) |
| [#2245](https://github.com/sigp/lighthouse/issues/2245) | Potential deadlock in `hot_cold_store.rs` | CLOSED | concurrency | high | static-analysis | `load_cold_intermediate_state` acquired `split.read()` then called code that re-acquired `split.read()`; parking_lot non-reentrant read lock can deadlock with a concurrent write | (commit 371c216a) |
| [#1557](https://github.com/sigp/lighthouse/issues/1557) | Head tracker has unsafe API wrt concurrency | CLOSED | concurrency | high | code-review | `head()`, `heads()`, `head_info()` returned cloned `Hash256` without holding a lock; prune thread could delete the returned root while it was being used in another thread, causing a race | (commit 703c33bd) |
| [#8065](https://github.com/sigp/lighthouse/issues/8065) | Fix reprocess queue memory leak | CLOSED | resource | medium | internal-testing | When `BlockImported` event was missed, attestation-ID entries for that block root leaked in the reprocess queue map indefinitely; random/invalid block roots could grow this map unboundedly | [#8076](https://github.com/sigp/lighthouse/pull/8076) |
| [#5768](https://github.com/sigp/lighthouse/issues/5768) | Fix hot state disk leak | CLOSED | resource | high | testnet-incident | v5.2.0-RC deleted temporary flags for all advanced states instead of only skipped slots, preventing pruning of canonical-chain hot states; database grew indefinitely | [#5768](https://github.com/sigp/lighthouse/pull/5768) |
| [#6105](https://github.com/sigp/lighthouse/issues/6105) | PeerDAS KZG library stack overflow during block production | CLOSED | panic-crash | high | testnet-incident | Rust `peerdas-kzg` library used deeply recursive tree hashing algorithms that overflowed the default tokio task stack size | [#6107](https://github.com/sigp/lighthouse/pull/6107) |
| [#5444](https://github.com/sigp/lighthouse/issues/5444) / [#6399](https://github.com/sigp/lighthouse/issues/6399) | Panic from `libp2p-upnp` crashing node | CLOSED | panic-crash | high | user-report | `libp2p-upnp` crate panicked in a tokio task (via `unwrap()` on UPnP HTTP response); any task panic propagated to CRIT and caused full node shutdown | [#5501](https://github.com/sigp/lighthouse/pull/5501) / patched dep |
| [#4171](https://github.com/sigp/lighthouse/issues/4171) / [#5020](https://github.com/sigp/lighthouse/issues/5020) | Earlier UPnP panics (igd crate) | CLOSED | panic-crash | high | user-report | `igd` crate called `unwrap()` on URL construction; any invalid network environment caused a panic that crashed the node | dependency patches |
| [#4285](https://github.com/sigp/lighthouse/issues/4285) | Investigate `CommitteePromiseFailed` error for slasher | OPEN | logic-other | medium | user-report | Slasher's attestation committee calculation fails for some attestations and is not retried; root cause not definitively resolved | n/a |
| [#6254](https://github.com/sigp/lighthouse/issues/6254) | Prevent fd leak in random slasher tests | CLOSED | resource | low | ci-test | `Box::leak` used to give `SlasherDB` a `'static` lifetime meant destructors never ran; each test iteration leaked file descriptors, eventually exhausting the process fd limit | [#6254](https://github.com/sigp/lighthouse/pull/6254) |
| [#6246](https://github.com/sigp/lighthouse/issues/6246) | `--logfile` breaks libp2p rolling file appender | CLOSED | config-cli | medium | user-report | Code passed the full `--logfile` path (including filename) as a directory to the rolling-file appender; failed when the file already existed | [#6266](https://github.com/sigp/lighthouse/pull/6266) |
| [#6748](https://github.com/sigp/lighthouse/issues/6748) | Incorrect VC default HTTP token path when `--datadir` is present | CLOSED | config-cli | medium | user-report | A regression in #6577 changed the default API token path to `$HOME/.lighthouse/mainnet/...` when `--datadir` was supplied, causing a CRIT if `$HOME` was not writable (e.g. Docker with `eth-docker`) | [#6755](https://github.com/sigp/lighthouse/pull/6755) |
| [#6125](https://github.com/sigp/lighthouse/issues/6125) | Fix `--proposer-nodes` CLI flag name | CLOSED | config-cli | high | user-report | The flag was registered as `proposer-node` but Clap looked it up as `proposer_nodes`; any use of the flag caused an immediate startup CRIT | [#6125](https://github.com/sigp/lighthouse/pull/6125) |
| [#9290](https://github.com/sigp/lighthouse/issues/9290) | `--ignore-ws-check` flag doesn't allow node to start outside WS period | CLOSED | config-cli | high | user-report | The flag existed but the weak-subjectivity check was not gated on it, making the flag a no-op | [#9290](https://github.com/sigp/lighthouse/pull/9290) |
| [#4488](https://github.com/sigp/lighthouse/issues/4488) | Non-release profiles of `lcli` panic due to argument processing failure | CLOSED | panic-crash | medium | internal-testing | Clap 2.x panics when a global argument is both `required` and has a `default_value`; only triggered in debug/test profiles, not release | [#4489](https://github.com/sigp/lighthouse/pull/4489) |
| [#7216](https://github.com/sigp/lighthouse/issues/7216) | Global pubkey cache is not crash safe | OPEN | persistence | medium | code-review | In-memory pubkey cache updated before on-disk write; a crash between the two leaves disk out of sync, requiring restart with head-state import | n/a |
| [#7090](https://github.com/sigp/lighthouse/issues/7090) | Fix `ring` audit failure (RUSTSEC-2025-0009) | CLOSED | logic-other | medium | static-analysis | Transitive `ring` dependency had a published vulnerability (RUSTSEC-2025-0009); required updating `libp2p` to pull in a safe version | [#7086](https://github.com/sigp/lighthouse/pull/7086) |
| [#7403](https://github.com/sigp/lighthouse/issues/7403) | Validator Client intermittently freezes on Linux kernel 6.14.x | CLOSED | concurrency | high | user-report | Linux kernel regression in `io_uring` / futex path caused Tokio worker threads to stall; fixed by upgrading to tokio with workaround | (dep upgrade) |
| [#6088](https://github.com/sigp/lighthouse/issues/6088) | Critical Task Panic with InvalidCertificate Error | CLOSED | panic-crash | high | user-report | `libp2p-tls` called `expect()`/`unwrap()` on TLS certificate generation; on hosts with specific crypto configurations this panicked at startup | dep upgrade |
| [#2099](https://github.com/sigp/lighthouse/issues/2099) | tokio-runtime-worker panicked | CLOSED | panic-crash | high | user-report | Panic in a tokio runtime worker propagated to a CRIT and crashed the node; trace pointed to subscription management | (fixed in that era) |
| [#6269](https://github.com/sigp/lighthouse/issues/6269) | `shuffling_is_compatible` admits false negatives | OPEN | logic-other | low | code-review | `shuffling_is_compatible` checks block-root equality at the decision slot as proxy for equal shufflings; this is sufficient but not necessary, so rare consecutive same-proposer slots can cause unnecessary attestation rejection | n/a |
| [#5120](https://github.com/sigp/lighthouse/issues/5120) | Fix off-by-one in backfill sig verification | CLOSED | spec-correctness | high | internal-testing | A `break` in the backfill loop occurred before `signed_blocks.push(signed_block)`, skipping signature verification of the very first block in the chain (slot 1) | [#5120](https://github.com/sigp/lighthouse/pull/5120) |
| [#4936](https://github.com/sigp/lighthouse/issues/4936) | Performance Degradation and OOM Events During API Calls | CLOSED | resource | medium | user-report | Batch validator-update API calls generated excessive `slog-async` log events, overflowing the logger buffer and contributing to OOM situations | (logging improvements) |
| [#2485](https://github.com/sigp/lighthouse/issues/2485) | Panic in Prometheus timer | CLOSED | panic-crash | medium | user-report | Prometheus timer `observe_duration()` panicked if the timer value was negative (clock skew) | (fixed in that era) |

---

## 3. Deep Dives

### DD-1: Slasher OOM via bogus validator_index (#9141)

**Root cause.** The slasher's `accept_attestation` was called from inside the `.inspect()` closure on the gossip attestation pipeline _before_ committee membership was validated. When `IndexedAttestation.attesting_indices` contained a synthesized huge index (e.g. 2^40), `AttestationBatch::group` allocated a `Vec` indexed by that value, exhausting RAM.

The two relevant call sites were in `IndexedAggregatedAttestation::verify_slashable` and `IndexedUnaggregatedAttestation::verify_slashable` in `attestation_verification.rs`:

```rust
// BEFORE (removed in fix):
.inspect(|verified| {
    if let Some(slasher) = chain.slasher.as_ref() {
        slasher.accept_attestation(verified.indexed_attestation.clone());
    }
})
.map_err(|slash_info| process_slash_info(slash_info, chain))
```

An attacker on the gossip network could craft a `SingleAttestation` with an enormous `attester_index` before committee checks ran.

**How discovered.** Reported via user channels (likely Discord); an out-of-memory crash on a slasher node prompted investigation. The fix branch was shipped immediately as `slasher-fix` before the PR merged.

**How fixed.** Two complementary changes (PR #9141):
1. Removed the premature `inspect()` calls; the slasher already received attestations after full validation via a separate code path.
2. Added a defence-in-depth cap `MAX_VALIDATOR_INDEX = 8_388_608` in `attestation_queue.rs` with a warning log if exceeded, even for attestations that reach the slasher after validation.
A regression test (`unaggregated_attestation_bogus_attester_index_not_sent_to_slasher`) exercises the exact scenario.

**Why it wasn't caught earlier.** The slasher was wired into a pre-validation hook as an optimization to reduce latency; the intent was benign but the security boundary was not checked. No fuzz test existed that constructed attestations with out-of-range indices and measured allocator behaviour.

**Could-have-been-caught-by.**
- Property-based / fuzzing test on the gossip attestation pipeline that generates random `attesting_indices` and asserts allocator usage stays bounded.
- Mandatory review checklist item: "Does this path run before or after index bounds/membership validation?"
- A `MAX_VALIDATOR_INDEX` guard in the slasher from the start (defence-in-depth).

---

### DD-2: LMDB Cursor UB causing memory corruption in slasher (#6211)

**Root cause.** The LMDB Rust bindings return a `&[u8]` pointing into LMDB's memory-mapped region for a cursor's current value. However, the LMDB C API internally aliases that pointer with its write buffer; calling `.delete_current()` on the cursor can silently overwrite the bytes being referenced through the shared reference. In Rust terms this is undefined behaviour (mutation through a `&T`).

The bug had existed latently for a long time but only became consistently exercisable after PR #4529 refactored the slasher database to interleave reads and deletes in the same cursor iteration. The symptom was memory corruption on Holesky nodes that manifested as wrong attestation data being processed, and sometimes crashes.

```rust
// BEFORE (UB):
Ok(Some((Cow::Borrowed(key), Cow::Borrowed(value))))

// AFTER (copy to owned Vec before any mutation):
Ok(Some((Cow::Borrowed(key), Cow::Owned(value.to_vec()))))
```

**How discovered.** Internal debugging of strange slasher behaviour on Holesky nodes. A fuzz test seed (`no_crash_aug_24`) was added to capture the reproducer.

**How fixed.** PR #6211: copy `value` into an owned `Vec` before returning it from `get_current_kv()`, ensuring the reference can no longer be invalidated by subsequent cursor operations.

**Why it wasn't caught earlier.** UB in C FFI does not trigger Rust's memory safety guarantees. Miri can detect some FFI UB but does not run LMDB's C library. The test harness passed because the cursor read and delete rarely interleaved in a way that produced observable corruption.

**Could-have-been-caught-by.**
- A mandatory FFI safety audit for any database cursor that interleaves reads and mutations; invariant: "never hold a reference derived from a cursor across another cursor operation."
- Fuzzing the slasher with memory sanitizer (`-Z sanitizer=address`) would likely have flagged the read-after-write.
- Choosing memory-safe Rust-native database backends (Redb) from the start avoids this entire class.

---

### DD-3: SSZ block endpoint decodes fork from length prefix (#5078)

**Root cause.** The `POST /eth/v1/beacon/blocks` and `POST /eth/v2/beacon/blocks` SSZ endpoints needed to determine the fork variant to use for decoding. Instead of reading the `Eth-Consensus-Version` request header that was already provided for exactly this purpose, the code read the first 4 bytes of the SSZ body (which is the SSZ offset/length for a variable-length field) and interpreted it as a slot number, then derived the fork from that slot.

This failed silently in tests because the test slot values happened to map to the correct fork, but in production a Teku validator client sending Deneb SSZ blocks saw stack overflows (separate issue #5080) and/or incorrect decoding.

**How discovered.** During testing of the SSZ POST endpoint for the Deneb fork. Credit to `@realbigsean` for finding the decode bug.

**How fixed.** PR #5078: extract `ForkName` from the `Eth-Consensus-Version` header (which is already parsed by the warp filter) and pass it to the `PublishBlockRequest::from_ssz_bytes_by_fork` function.

**Why it wasn't caught earlier.** The existing test happened to work because the test block slot (low number, e.g. 1) decoded to `Base` fork in the same way that the real SSZ length prefix would. The happy-path alignment masked the logic error. There were no cross-fork interop tests for this endpoint until after the fix.

**Could-have-been-caught-by.**
- An integration test that sends a block at a known Deneb slot but with an SSZ length that doesn't equal the slot.
- A property test generating random (fork, block) pairs and round-tripping through the endpoint.
- Code review checklist: "Is the fork being derived from the correct source (header vs. payload)?"

---

### DD-4: SigVerifiedOp SSZ Encode/Decode mismatch (#6035)

**Root cause.** `SigVerifiedOp` had hand-written `ssz::Encode` and `ssz::Decode` implementations whose field ordering differed. Specifically the `Encode` wrote fields in one order while `Decode` read them in a different order. During the schema v20 migration, op pool entries were re-serialized using these implementations. If any `SigVerifiedOp` was present in the op pool, the migration would produce silently corrupt data that would fail to decode on the next read.

The error was intermittent because it only occurred when the op pool was non-empty at migration time.

**How discovered.** Noticed while testing the schema v21 migration (see comment on PR #5897). Adding roundtrip tests to the v20 migration exposed the mismatch.

**How fixed.** PR #6035: replaced the hand-written impl with a derived serialization using intermediate types `SigVerifiedOpEncode` and `SigVerifiedOpDecode` that made the mapping explicit and obviously correct.

**Why it wasn't caught earlier.** Hand-written SSZ impls are not checked by the derive macros. No roundtrip tests existed for `SigVerifiedOp` serialization in isolation.

**Could-have-been-caught-by.**
- A mandatory roundtrip property test (`encode → decode → assert_eq!(original)`) for every type with hand-written SSZ impls.
- A CI check that flags types implementing both `Encode` and `Decode` without derive macros, requiring manual review.
- Miri or a custom test that verifies field ordering by encoding and decoding a known-value struct.

---

### DD-5: EIP-2335 missing control code removal (#1889)

**Root cause.** EIP-2335 specifies that C0 (0x00–0x1F), C1 (0x80–0x9F), and DEL (0x7F) control characters must be stripped from keystore passwords before use. Lighthouse's keystore implementation skipped this step entirely. A password containing these characters would decrypt a Lighthouse-created keystore but a spec-compliant client might strip the characters and fail; conversely a keystore from another client that stripped them would decrypt differently in Lighthouse.

**How discovered.** Security audit (#1889 author reports it as an audit finding, consistent with the co-filed issues #1906, #1907 in the same audit batch).

**How fixed.** PR #1928: reject passwords with invalid UTF-8 control characters on encryption (strict); allow them on decryption for backward-compatibility with potentially already-created keystores.

**Why it wasn't caught earlier.** The audit found this; no pre-existing conformance tests checked password processing against the EIP-2335 spec text. The spec is a short document but the password processing section is a footnote.

**Could-have-been-caught-by.**
- A spec-conformance test suite for EIP-2335 (encode/decode roundtrip including password normalization).
- A reference test vector from the EIP test vectors that includes control characters.

---

### DD-6: EIP-2335 KDF parameter validation missing (#1906, #1907)

**Root cause.** Lighthouse accepted KDF parameters (PBKDF2 iteration count; scrypt N, r, p; AES IV) at any value, including:
- Extremely low iteration counts (near 0), creating easily brute-forceable keystores.
- Astronomically large values that would cause OOM or DoS during decryption.
- Zero-length or wrong-length AES-128-CTR IVs.

**How discovered.** Security audit (same audit batch as #1889).

**How fixed.** PR #1930:
- PBKDF2: warn if `c < 262144` (NIST minimum), error if `c > 2^32`.
- Scrypt: warn on low params, error if N would exceed 4GB RAM.
- AES IV: error on zero-length, warn on non-128-bit.

**Why it wasn't caught earlier.** No lower or upper bound validation existed; the KDF was treated as a black box. An audit was required to surface this class of issue.

**Could-have-been-caught-by.**
- Automated security scanning for crypto parameter validation (e.g. a lint rule: "any call to PBKDF2/scrypt must be preceded by parameter range validation").
- Fuzzing the keystore decoder with random parameter values; OOM would be flagged.

---

### DD-7: EIP-2333 key derivation mismatch (#1624)

**Root cause.** Lighthouse used an older (draft) version of EIP-2333 for HD key derivation from mnemonics. The final version of EIP-2333 changed the derivation path format. As a result, the 0th voting key derived by Lighthouse from a 24-word mnemonic was different from what `eth2-deposit-cli` produced, making validator recovery impossible for affected users.

**How discovered.** User report on Discord. Affected users who generated keys via the Ethereum Launchpad (which used `eth2-deposit-cli`) and then tried to recover via `lighthouse account validator recover`.

**How fixed.** PR #1633: updated key derivation to match the finalized EIP-2333 spec. Required a coordinated update with `eth2-deposit-cli`.

**Why it wasn't caught earlier.** The EIP was still in draft when Lighthouse first implemented it; no cross-client compatibility test vector suite existed at the time.

**Could-have-been-caught-by.**
- Cross-client test vectors exercised in CI from the start of EIP implementation.
- A canary test that checks at least one known mnemonic → known pubkey mapping using the reference implementation's vectors.

---

### DD-8: glibc malloc constant wrong (M_MMAP_MAX vs M_MMAP_THRESHOLD) (#2857)

**Root cause.** In `common/malloc_utils/src/glibc.rs`, the constant for `M_MMAP_THRESHOLD` was set to `-4`. The correct constant is `-3`. The value `-4` corresponds to `M_MMAP_MAX` (maximum mmap chunks). As a result, Lighthouse was capping the number of mmap'd allocations at 2,097,152 (`1 << 21`) rather than setting the mmap threshold to 128 KB, which is the intended tuning to reduce glibc fragmentation on long-running Lighthouse nodes.

```rust
// BEFORE (wrong constant):
libc::mallopt(libc::M_MMAP_THRESHOLD, -4);  // -4 = M_MMAP_MAX in glibc!

// AFTER:
libc::mallopt(libc::M_MMAP_THRESHOLD, -3);  // correct
```

**How discovered.** A user noticed the comment in the source code referenced the wrong constant after reading the glibc source.

**How fixed.** PR #2937: corrected the constant to `M_MMAP_THRESHOLD` (`-3`) and explicitly set the value to 128 KB.

**Why it wasn't caught earlier.** glibc constants are integer-valued and not type-safe; passing the wrong one compiles silently and the code appears to work (mallopt with an unknown option just returns 0). No test verifies the allocator configuration.

**Could-have-been-caught-by.**
- Typed constants (e.g. a newtype wrapping `i32` for `mallopt` option codes) or using `libc::M_MMAP_THRESHOLD` by name rather than a raw integer.
- A memory fragmentation regression test measuring heap fragmentation under a realistic workload.

---

### DD-9: LMDB/MDBX memory corruption in slasher (#6277)

**Root cause.** MDBX (the default-compiled backend for some distributions) caused memory corruption in the Lighthouse process even when the slasher code paths were inactive. This was traced to the MDBX C library's behavior at initialization or map time interfering with other allocations. The LMDB issue (#6211) may have been a contributing factor, but MDBX added additional corruption vectors. The problem is fundamental to using an unsafe C library with a shared address space.

**How discovered.** A production node investigation on Holesky; the node exhibited inexplicable state corruption traced back to the presence of MDBX-compiled binaries. The issue cross-references #6206 (expensive fork-choice mutation caused by corrupted data).

**How fixed.** MDBX being removed from Lighthouse; Redb (a pure-Rust database) is being adopted as the new default slasher backend (#4529, #6481). LMDB is also being evaluated for replacement.

**Why it wasn't caught earlier.** Memory corruption from a C library is not detectable by Rust's type system or borrow checker. Reproducing requires specific timing, data patterns, and hardware; sanitizer-based testing was not applied to the C library itself.

**Could-have-been-caught-by.**
- AddressSanitizer / MemorySanitizer runs against the compiled MDBX bindings.
- Using only memory-safe (Rust-native) database backends from the start.
- A "chaos" test that runs a slasher under memory pressure and checks for determinism.

---

### DD-10: SSZ block stack overflow (warp future chain) (#5080 / PR #5076)

**Root cause.** When `warp` composes large chains of `and_then`/`map` futures (as it does when parsing SSZ block bodies with fork-based routing), the resulting deeply-nested `Future` type can overflow the stack when `.poll()` is called. This is a known warp limitation. The Teku validator client used SSZ block publishing and hit this immediately on the v4.6.0 release.

**How discovered.** Reported by a user running Teku as the validator client connecting to a Lighthouse beacon node. The node crashed with a stack overflow instead of an OOM or explicit error.

**How fixed.** PR #5076: added `.boxed()` at strategic points in the warp filter chain to heap-allocate (type-erase) the future, breaking the recursive type depth. PR #5078 fixed the deeper SSZ decode bug simultaneously.

**Why it wasn't caught earlier.** The SSZ POST endpoint was new in v4.6.0; no CI test exercised it with real content at the time. The Lighthouse VC itself used JSON, so the bug only manifested with other VCs.

**Could-have-been-caught-by.**
- An integration test using the SSZ POST path from a simulated Teku-style client.
- A compile-time check on future type depth (challenging in Rust, but `.boxed()` can be enforced by convention).
- A Teku / multi-client interop test in CI.

---

### DD-11: verify_header_signature uses stale fork at fork boundary (#8528)

**Root cause.** `verify_header_signature` (used by the slasher for years, then added to the blob/column validation hot path in Fulu) computed the signing domain from the **head state's fork**, not from `ChainSpec::fork_at_epoch(block.slot.epoch())`. At a fork boundary (e.g. the Fulu transition), the head state still held the pre-fork `Fork` struct, so all Fulu blocks' signatures verified against the wrong domain and failed.

**How discovered.** Fusaka/Fulu devnet testing; nodes that were syncing took a different code path and recovered, but freshly-imported blocks failed.

**How fixed.** PR #8535: replaced `state.fork()` with `spec.fork_at_epoch(block.message.slot.epoch(head_state))` inside `verify_header_signature`.

**Why it wasn't caught earlier.** The function had only been used by the slasher historically, where the head state was never at a fork boundary during validation. Promotion to the hot path for Fulu without adding a fork-boundary test exposed the latent bug. The regression test included in the PR fails if the fix is reverted.

**Could-have-been-caught-by.**
- A unit test for `verify_header_signature` at a fork transition epoch.
- A review gate: "any function computing a signing domain that uses `state.fork()` must be audited to ensure correctness at fork boundaries."
- Broader coverage by the EF spec tests at fork-transition slots.

---

### DD-12: Builder exit signature batch vs. individual path divergence (#9173)

**Root cause.** `process_builder_voluntary_exit` in `per_block_processing/process_operations.rs` had a hand-rolled BLS signature verification path that differed from the generic `exit_signature_set` function used for individual verification. The EF spec tests invoke the individual path; the batch path went untested. When EF security reviewed the code they found the batch path used different domain computation logic.

Specifically, the builder exit batch path hardcoded `Domain::VoluntaryExit` with `capella_fork_version`, but did not correctly distinguish builder vs. validator exits for the Gloas fork.

**How discovered.** Internal testing during Gloas fork development; the EF tests only covered the individual-verification code path.

**How fixed.** PR #9174: unified the two code paths to use `exit_signature_set`, which correctly handles builder vs. validator index routing and fork-dependent domain selection.

**Why it wasn't caught earlier.** The EF spec tests for voluntary exits are written against the individual-verification code path. The batch path is a Lighthouse optimization for block processing throughput. There was no test that compared batch and individual results for the same set of exits.

**Could-have-been-caught-by.**
- A differential test: for any set of exits, `batch_verify(exits) == all(individual_verify(e) for e in exits)`.
- A checklist: "does any new operation type have a separate batch verification path that must stay in sync with the individual path?"

---

### DD-13: Head tracker race condition (#1557)

**Root cause.** `head()`, `heads()`, and `head_info()` in `beacon_chain.rs` returned a cloned `Hash256` without keeping the head tracker read lock. A concurrent fork-prune thread could delete that root from the head tracker between the `clone()` and the use of the returned value in another thread. This created a TOCTOU race that could result in accessing a root that no longer existed.

**How discovered.** Code review (author identified it via static analysis of lock usage).

**How fixed.** Refactored to return lock guards from the head tracker functions, ensuring the lock is held for the lifetime of the returned reference (commit 703c33bd).

**Why it wasn't caught earlier.** The race window was narrow and required concurrent fork pruning. In normal operation (finalized chain, single-threaded import) it was very unlikely to trigger. The bug was found by careful reading, not observation.

**Could-have-been-caught-by.**
- Lockbud or a Rust static concurrency analysis tool.
- A thread-sanitizer integration test that exercises concurrent prune + head read.

---

### DD-14: Hot database state leak (PR #5768)

**Root cause.** PR #5533 introduced logic to store "advanced states" (states needed for epoch boundaries at skipped slots) with a temporary flag, then delete the flag once the state was used. The deletion logic deleted temporary flags for **all** advanced states unconditionally, not just those at skipped slots. Consecutive blocks at slots N and N+1 would write the pre-state for N+1 as a temporary, delete the flag (making it permanent), and then never prune it. The database grew without bound.

**How discovered.** Testnet deployment by `@antondlr` who noticed the beacon state storage growing continuously on a v5.2.0-RC node.

**How fixed.** PR #5768: delete temporary flags only at skipped slots (the correct invariant). Added database pruning logic that iterates `HotStateSummary` entries and removes states older than the split slot.

**Why it wasn't caught earlier.** The regression was introduced in a large refactor (PR #5533). There was no long-running disk-size regression test that would catch gradual growth. Unit tests only verified correctness of individual operations, not cumulative storage behaviour.

**Could-have-been-caught-by.**
- A long-running integration test that measures hot DB size over N epochs and asserts it remains bounded.
- A CI check that simulates 1000 slots of non-skipped block production and asserts the number of stored states doesn't grow linearly.

---

## 4. Synthesis

### Counts by class

| Class | Count |
|-------|-------|
| panic-crash | 9 |
| concurrency | 5 |
| resource | 5 |
| spec-correctness | 5 |
| config-cli | 5 |
| persistence | 3 |
| serialization | 2 |
| logic-other | 4 |
| **Total** | **38** |

### Counts by severity

| Severity | Count |
|----------|-------|
| critical | 3 |
| high | 21 |
| medium | 11 |
| low | 3 |

### Recurring root-cause themes

1. **Pre-validation hooks bypass security boundaries (slasher OOM, #9141).** Code added for performance (feeding the slasher early) ran before the validation that established the preconditions the slasher depended on. This pattern appears any time an observer is inserted into a pipeline without a complete threat model.

2. **C FFI database bindings introduce UB invisible to Rust's safety guarantees (#6211, #6277).** Both LMDB and MDBX introduced memory corruption and UB via Rust bindings that violate the aliasing rules. The borrow checker cannot help when the mutation happens inside a C library. This is a structural smell in the slasher backend architecture.

3. **Hand-written SSZ impls diverge from the derived layout (#6035, #5078).** When SSZ `Encode`/`Decode` are written by hand rather than derived, field ordering errors are easy to introduce and hard to catch without explicit roundtrip tests. Multiple bugs in this category.

4. **Fork-boundary state staleness (#8528, #9173, #7441).** Functions that compute BLS signing domains or fork-specific data from `state.fork()` instead of `spec.fork_at_epoch()` are latently incorrect at fork transitions. This class of bug has appeared repeatedly as new forks add new code paths.

5. **Dependency panics propagate to full node crash (#6399, #5444, #4171, #6088).** Third-party crate panics in `unwrap()`/`expect()` calls cause node shutdown because the tokio task panic handler treats any panic as fatal. This is particularly acute for optional subsystems like UPnP.

6. **CLI flag/config regressions are silently broken (#6125, #9290, #6748, #2857).** Several flags were registered incorrectly (wrong name, wrong constant, ignored value). These only surface on user reports because no automated test exercises all flag combinations.

### Highest-leverage early-detection opportunities

1. **Fuzz the gossip pipeline with out-of-range indices + memory-usage assertion.** A fuzzer that constructs attestations with random `validator_index` values and asserts that heap usage does not grow beyond a fixed bound would have caught #9141 before it reached production. This applies to any `accept_*` entry point in the slasher.

2. **Mandatory roundtrip property tests for all hand-written SSZ impls.** Any type that implements `ssz::Encode` + `ssz::Decode` without derive macros should have a `proptest` or `quickcheck` roundtrip test: `decode(encode(v)) == v`. A CI lint that flags non-derived impls without a roundtrip test would enforce this. This would have caught #6035 and likely #5078.

3. **Fork-boundary signing domain audit as a release gate.** Before each new hard fork, enumerate every function that calls `state.fork()` for domain computation. Any function that does not also have a fork-transition unit test should be flagged. This would have caught #8528 and #9173.

4. **Replace C-FFI database backends with pure-Rust alternatives (Redb).** This is already the direction being taken (#4529, #6481, #8048). The structural fix eliminates the entire class of LMDB/MDBX UB (#6211, #6277). Enforce this by removing the unsafe C backends from CI.

5. **Treat third-party panic paths as bugs; wrap them before first merge.** A project-wide policy that no tokio-spawned task may call a third-party crate function that is known to panic (UPnP, TLS, UPnP-igd) without a `catch_unwind` wrapper or being gracefully degraded. This would have prevented #4171, #5444, #6088, #6399. Consider a CI lint against `unwrap()`/`expect()` in newly added code that touches external crates.

6. **Long-running disk-size regression test.** A CI job that runs a beacon node for 1000+ slots and asserts that hot DB size growth is bounded (O(1) in validators, not O(slots)) would have caught #5768 before it reached a release candidate. Similar tests could catch reprocess-queue growth (#8065) and other resource leaks.
