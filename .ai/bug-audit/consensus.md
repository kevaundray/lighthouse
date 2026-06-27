# Consensus Core — Bug Audit

## Scope

This audit covers the **consensus core** of sigp/lighthouse: state transition, fork choice (proto-array), block/attestation verification, epoch processing, rewards, and non-finality. Source areas include `consensus/`, `beacon_node/beacon_chain/` (state processing), `consensus/fork_choice/`, attestation & block verification, epoch processing, and the rewards subsystem.

**Out of scope:** networking/gossip transport, sync pipeline, execution-layer/engine-API, database, HTTP API (except where those surface consensus bugs), blobs/DAS. Overlapping items are flagged.

### Queries run

```
gh issue list --repo sigp/lighthouse --label "consensus" --label "bug" --state all --limit 300
gh issue list --repo sigp/lighthouse --label "non-finality" --state all --limit 100
gh issue list --repo sigp/lighthouse --label "consensus" --state all --limit 300
gh search issues --repo sigp/lighthouse "fork choice" --limit 60
gh search issues --repo sigp/lighthouse "proto-array" --limit 30
gh search issues --repo sigp/lighthouse "epoch processing" --limit 30
gh search issues --repo sigp/lighthouse "attestation verification" --limit 30
gh search issues --repo sigp/lighthouse "shuffling committee" --limit 20
gh search issues --repo sigp/lighthouse "weak subjectivity" --limit 20
gh search issues --repo sigp/lighthouse "reorg" --limit 20
gh search issues --repo sigp/lighthouse "slashing" --limit 30
gh search issues --repo sigp/lighthouse "invalid block" --limit 20
gh search issues --repo sigp/lighthouse "progressive balances" --limit 10
gh search issues --repo sigp/lighthouse "non-finality" --limit 20
gh search prs --repo sigp/lighthouse "fork choice" --state closed --limit 30
```

---

## 2. Bug Table

| # | Title | State | Class | Severity | How-found | One-line root cause | Fix PR |
|---|-------|-------|-------|----------|-----------|---------------------|--------|
| [#3](https://github.com/sigp/lighthouse/issues/3) | Attestation BLS verification is bypassed | CLOSED | `spec-correctness` | critical | code-review | BLS signature check entirely absent in early attestation path | Early internal fix |
| [#485](https://github.com/sigp/lighthouse/issues/485) | DoS vector when processing blocks with big skips | CLOSED | `resource` | high | code-review | No limit on slot distance between block and parent; unbounded state advance CPU/memory | Internal fix |
| [#800](https://github.com/sigp/lighthouse/issues/800) | Potential memory exhaustion vector | CLOSED | `resource` | high | code-review | Intermediate states cached during skip-slot replay without bound; enables OOM | Internal fix |
| [#845](https://github.com/sigp/lighthouse/issues/845) | Forks longer than two epochs cause invalid blocks to be produced | CLOSED | `spec-correctness` | critical | internal-testing | Op pool skipped signature re-check; attestations from diverged-committee forks silently included | [#900](https://github.com/sigp/lighthouse/pull/900) |
| [#1098](https://github.com/sigp/lighthouse/issues/1098) | Rules for using `SafeArith` | CLOSED | `spec-correctness` | high | code-review | No enforcement of checked arithmetic in consensus crates; silent saturation masked invalid states | [#1644](https://github.com/sigp/lighthouse/pull/1644) |
| [#1100](https://github.com/sigp/lighthouse/issues/1100) | Saturating arith on Slot/Epoch should fail state transition | CLOSED | `spec-correctness` | high | code-review | `Slot`/`Epoch` arithmetic was saturating; spec requires overflow to invalidate transition | [#1644](https://github.com/sigp/lighthouse/pull/1644) |
| [#1255](https://github.com/sigp/lighthouse/issues/1255) | Rethink and test fork handling in op pool | CLOSED | `logic-other` | medium | code-review | Op pool attestation fork handling lacked tests and relied on fragile `AttestationId` struct | Internal fix |
| [#1333](https://github.com/sigp/lighthouse/issues/1333) | Deposit Signature Subgroup Check | CLOSED | `spec-correctness` | critical | audit | Deposit verification called aggregate-verify path; skipped public key subgroup check | [#1935](https://github.com/sigp/lighthouse/pull/1935) |
| [#1557](https://github.com/sigp/lighthouse/issues/1557) | Head tracker has unsafe API wrt concurrency | CLOSED | `concurrency` | high | code-review | `head()`, `heads()`, `head_info()` returned copies while fork pruning deleted entries concurrently | Internal fix |
| [#1709](https://github.com/sigp/lighthouse/issues/1709) | Parasitic voluntary exits | CLOSED | `resource` | medium | user-report | Voluntary exits with far-future `exit.epoch` never pruned; potential DoS / memory bloat | Internal fix |
| [#1719](https://github.com/sigp/lighthouse/issues/1719) | Racy seen caches | CLOSED | `concurrency` | high | code-review | `Observed*` structs held internal `RwLock`/`Mutex`; TOCTOU races on seen-block/attestation caches | [#1937](https://github.com/sigp/lighthouse/pull/1937) |
| [#1773](https://github.com/sigp/lighthouse/issues/1773) | Fork choice timing attack | CLOSED | `spec-correctness` | medium | code-review | Spec-described ex-ante reorg timing attack not mitigated | Internal fix |
| [#2741](https://github.com/sigp/lighthouse/issues/2741) | Check justified checkpoint root in fork choice | CLOSED | `spec-correctness` | critical | code-review | `filter_block_tree` checked checkpoint **epoch** only; spec requires checking `(epoch, root)` pair | [#2822](https://github.com/sigp/lighthouse/pull/2822) |
| [#3266](https://github.com/sigp/lighthouse/issues/3266) | Invalid "Failure verifying attestation for gossip" | CLOSED | `logic-other` | low | user-report | Duplicate attestation logged as ERROR rather than DEBUG; misleading operator output | Internal fix |
| [#4184](https://github.com/sigp/lighthouse/issues/4184) | Fix exit verification at fork boundaries | CLOSED | `fork-upgrade` | medium | code-review | Exit verification for epoch E+1 when head is in epoch E crossed fork boundary without fork upgrade | [#4183](https://github.com/sigp/lighthouse/pull/4183) |
| [#4234](https://github.com/sigp/lighthouse/issues/4234) | Withdrawals root on "inconsistent" attestation verification states | CLOSED | `spec-correctness` | high | mainnet-incident | "Inconsistent" state replay for attestation shuffling corrupted block_roots, producing wrong withdrawal amounts | [#4249](https://github.com/sigp/lighthouse/pull/4249) |
| [#4238](https://github.com/sigp/lighthouse/issues/4238) | Attestation verification uses head state fork | CLOSED | `fork-upgrade` | critical | mainnet-incident | Batch attestation sig-verify used the head state's `Fork` struct; at Capella boundary pre-fork head caused rejection of valid post-fork attestations (and acceptance of stale ones), leading to invalid block | [#4263](https://github.com/sigp/lighthouse/pull/4263) |
| [#4264](https://github.com/sigp/lighthouse/issues/4264) | No gossip validation before block broadcast | CLOSED | `spec-correctness` | medium | code-review | Blocks published via HTTP API bypassed all gossip validation before broadcast | Internal fix |
| [#4332](https://github.com/sigp/lighthouse/issues/4332) | Beacon node failing to recover after SIGINT (fork choice store corruption) | CLOSED | `concurrency` | critical | user-report | SIGINT mid-flight left fork choice partially mutated in memory; shutdown handler persisted this corrupt state | [#4357](https://github.com/sigp/lighthouse/pull/4357) |
| [#4826](https://github.com/sigp/lighthouse/issues/4826) | Progressive balances optimisation incorrect with slashed validators | CLOSED | `spec-correctness` | high | internal-testing | After `on_slashing` removed a balance, `on_effective_balance_change` re-applied a delta for the same (slashed) validator; double-counted removal | [#4834](https://github.com/sigp/lighthouse/pull/4834) |
| [#4856](https://github.com/sigp/lighthouse/issues/4856) | Rewards API: proposer rewards incorrectly included in phase0 attestation rewards | CLOSED | `api-correctness` | medium | internal-testing | Phase0 rewards API reused op pool delta function that mixed proposer rewards into attestation `inclusion_delay` | [#4882](https://github.com/sigp/lighthouse/pull/4882) |
| [#4929](https://github.com/sigp/lighthouse/issues/4929) | Incorrect phase0 block rewards in rewards API | CLOSED | `api-correctness` | medium | internal-testing | Phase0 block reward path ignored slashed validator attestation dedup; rewarded proposer based on first-seen instead of best flags | Internal fix |
| [#6269](https://github.com/sigp/lighthouse/issues/6269) | `shuffling_is_compatible` admits false negatives | OPEN | `spec-correctness` | medium | code-review | Assumes equal block root at decision slot ↔ equal shuffling; `<-` direction is false (RANDAO can alias) | Not fixed yet |
| [#6606](https://github.com/sigp/lighthouse/issues/6606) | Block verification checks for pre-finalized blocks are flaky | OPEN | `persistence` | high | code-review | `pre_finalization_cache` assumes block on-disk-but-not-in-fork-choice means pruned; false after unclean shutdown | Not fixed yet |
| [#7083](https://github.com/sigp/lighthouse/issues/7083) | Reject attestations to blocks prior to the split | CLOSED | `logic-other` | medium | internal-testing | Attestations pointing to pre-split blocks triggered noisy cache-miss logs and unnecessary state loads | Internal fix |
| [#7448](https://github.com/sigp/lighthouse/issues/7448) | Pubkey cache not rebuilt at skipped slots | OPEN | `spec-correctness` | medium | internal-testing | Validators inducted at epoch boundary during skipped slots not added to pubkey cache; block/attestation verification fails for those validators | Not fixed yet |
| [#7839](https://github.com/sigp/lighthouse/issues/7839) | Attestation verification access of `fork_choice` lock is racey | OPEN | `concurrency` | medium | internal-testing | Attestation verification reads fork choice lock 4 separate times; pruning can run between reads 1 and 3, producing `MissingBeaconBlock` error | Not fixed yet |
| [#9090](https://github.com/sigp/lighthouse/pull/9090) | O(n²) `find_head` and stack overflow in `filter_block_tree` | CLOSED | `resource` | critical | internal-testing | After removing best_child/best_descendant caching in #9025, `find_head` became O(n²) and `filter_block_tree` recursive (stack overflow at ~30k blocks) | [#9090](https://github.com/sigp/lighthouse/pull/9090) |
| [#9191](https://github.com/sigp/lighthouse/pull/9191) | Spurious re-org logs on ePBS payload status changes | CLOSED | `logic-other` | low | internal-testing | `after_new_head` fired on every payload status update (Empty→Full), not just actual head changes; false reorg metrics/SSE | [#9191](https://github.com/sigp/lighthouse/pull/9191) |
| [#9305](https://github.com/sigp/lighthouse/pull/9305) | Non-canonical payload attestation processing | CLOSED | `spec-correctness` | high | ci-test (EF compliance) | Payload attestation (PTC) verification always used head state, failing for non-canonical chain attestations | [#9305](https://github.com/sigp/lighthouse/pull/9305) |
| [#9364](https://github.com/sigp/lighthouse/pull/9364) | Bogus `InvalidBestNode` error prevents Lighthouse from starting | CLOSED | `spec-correctness` | critical | testnet-incident | Over-strict sanity check in `find_head` returned error when all leaves were ineligible (valid in extreme non-finality); blocked node startup | [#9364](https://github.com/sigp/lighthouse/pull/9364) |
| [#9359](https://github.com/sigp/lighthouse/issues/9359) | Proposer reorg strat uses unrealized finalization incorrectly | OPEN | `spec-correctness` | medium | code-review | `get_proposer_head_info` reads head node's `unrealized_finalized_checkpoint` instead of `store.finalized_checkpoint`; also checks finalization in FFG-competitive check where spec only checks justification | Not fixed yet |
| [#9471](https://github.com/sigp/lighthouse/pull/9471) | Unrealized justification incorrect for blocks with slashings | CLOSED | `spec-correctness` | high | internal-testing | Optimisation reused parent block's unrealized checkpoints for child in same epoch; failed to account for slashings which can change justification within an epoch | [#9471](https://github.com/sigp/lighthouse/pull/9471) |
| [#9524](https://github.com/sigp/lighthouse/pull/9524) | Transient bug in `dequeue_attestation` | CLOSED | `spec-correctness` | high | internal-testing | `dequeue_attestations` split queue at first `slot >= current_slot` assuming sorted order; queue is arrival-ordered so future-slot votes could block already-due votes from being applied to fork choice | [#9524](https://github.com/sigp/lighthouse/pull/9524) |
| [#9544](https://github.com/sigp/lighthouse/issues/9544) | GLOAS `PENDING` head causes proposer to miss slot | OPEN | `spec-correctness` | high | testnet-incident | In deep non-finality, `find_head` returned justified checkpoint node with `PayloadStatus::Pending`; block production aborted on `PENDING` parent, proposer misses slot | Not fixed yet |

---

## 3. Deep Dives

---

### DD-1: Attestation BLS verification bypassed (#3)

**Root cause:** In the very earliest implementation of Lighthouse, the BLS signature check for incoming attestations was a stub — the verification call was present in the code but the actual cryptographic verification was never performed (blocked on a dependency).

**How discovered:** Code review during early development (pre-mainnet).

**How fixed:** Wired up the actual BLS verification library once the dependency was available.

**Why it wasn't caught earlier:** The codebase was pre-testnet; no running network existed to generate realistic gossip traffic with valid/invalid signatures.

**Could-have-been-caught-by:** An integration test that submits an attestation with a deliberately wrong signature and asserts rejection. This is now a standard EF gossip-validation test case.

---

### DD-2: Forks >2 epochs produce invalid blocks (#845, fix #900)

**Root cause:** PR #820 disabled signature re-verification when drawing attestations from the op pool (to save CPU). This introduced a bug: after 2 epochs of forking the committee shufflings on the two chains diverge, so attestations inserted into the op pool on chain A have signatures that are invalid on chain B. Without re-checking, the block producer silently included those cross-chain attestations, producing a block that other clients (and the spec) would reject.

**How discovered:** Internal testing using a 4-node devnet with a simulated fork.

**How fixed:** PR #900 added `attestation_shuffling_is_compatible` — a fork-choice ancestry check that confirms the attestation's implied shuffling (decided by the block root at the decision slot) is the same as the state being produced on.

**Why it wasn't caught earlier:** The optimization was added without a corresponding test for multi-epoch forks. Single-epoch forks remain in the same shuffling epoch.

**Could-have-been-caught-by:** A property-based test: "for any two states with divergent RANDAO after 2 epochs, attestations from one are rejected when packing blocks on the other." An EF test for op-pool correctness across forks would also catch this.

---

### DD-3: Deposit signature subgroup check missing (#1333, fix #1935)

**Root cause:** `verify_deposit_signature()` called `fast_aggregate_verify_pre_aggregated()`, which is designed for aggregated BLS verification and does NOT check public key subgroup membership. The spec requires full individual verification for deposits, including subgroup checks. A malformed public key (not in the correct subgroup) could pass verification silently.

**How discovered:** External security audit (Kirk Baird, Sigma Prime's own team, labelled A0 = highest priority).

**How fixed:** PR #1935 changed `verify_deposit_signature()` to call `Signature::verify()`, which performs a proper individual BLS verification including subgroup checks.

**Why it wasn't caught earlier:** The aggregate verification path and the individual verification path look syntactically similar. The distinction is subtle and lies in the BLS spec, not the Rust type system.

**Could-have-been-caught-by:** A spec-test vector for deposits with intentionally subgroup-invalid public keys. Type-level distinction between "aggregate-verified signature" and "individually-verified signature" would make incorrect usage a compile error.

---

### DD-4: Saturating arithmetic masks invalid state transitions (#1098, #1100, fix #1644)

**Root cause:** `Slot` and `Epoch` implemented `Add`/`Sub` with saturating semantics (a design decision from 2018 to avoid panics). The spec later clarified: arithmetic overflow/underflow during state transition renders the block invalid. With saturating arithmetic, Lighthouse silently accepted states/blocks it should have rejected.

**How discovered:** Code review / spec clarification (issue opened by @paulhauner after reading spec update).

**How fixed:** PR #1644 introduced the `SafeArith` trait with explicit `safe_add`, `safe_sub`, etc. methods. The `+`/`-` operators were gated behind a `legacy-arith` feature that CI builds `consensus/` and `state_processing/` **without**, guaranteeing only checked arithmetic reaches consensus code.

**Why it wasn't caught earlier:** The saturating behaviour predated the spec clarification; it was a deliberate choice at the time.

**Could-have-been-caught-by:** An EF spec test with a block whose arithmetic would wrap on u64. The CI feature-flag trick used in the fix is itself an excellent prevention mechanism.

---

### DD-5: Justified checkpoint compared by epoch only (#2741, fix #2822)

**Root cause:** `filter_block_tree` in proto-array compared `justified_epoch` and `finalized_epoch` to determine block viability. The spec checks full `Checkpoint` equality: `(epoch, root)`. Comparing only epochs means that a block on a different fork that happened to justify the same epoch number (but a different root) would be incorrectly treated as viable.

**How discovered:** Externally flagged by @hwwhww (Ethereum Foundation); linked to a spec PR. Labelled A0.

**How fixed:** PR #2822 stored full `Checkpoint` (including root) in `ProtoNode` and `ProtoArray`, added a database migration to populate the roots from existing data, and changed `filter_block_tree` to compare full checkpoints. Also bundled proposer boosting implementation.

**Why it wasn't caught earlier:** The spec had historically underspecified this; the bug predated the formal spec clarification. No EF fork-choice test covered cross-fork epoch collision at the time.

**Could-have-been-caught-by:** EF consensus-spec fork-choice test `new_finalized_slot_is_justified_checkpoint_ancestor` (which was added around the same time). Running EF fork-choice spec tests as part of CI earlier would have caught this.

---

### DD-6: Attestation batch verification uses wrong fork at upgrade boundary (#4238, fix #4263)

**Root cause:** The batch attestation signature verification path read `state.fork` from the **head state** to determine the domain for signature verification. At a hard-fork boundary (Capella in this case), when the head state was still pre-fork (last block of the old epoch), attestations created by validators who had advanced their local state into the new epoch would use the new fork's domain. Lighthouse verified those with the old fork's domain → rejected valid attestations. Conversely, stale attestations signed with the old domain were accepted and packed into the block, producing an invalid block (rejected by other clients due to batch signature failure).

**How discovered:** Mainnet incident — DSRV (Lido operator) reported a missed block at slot 6,209,557, the first slot of the Capella epoch. Prysm logs confirmed three invalid attestation signatures.

**How fixed:** PR #4263 updated batch verification to detect if the attestation slot crosses a fork boundary and, if so, temporarily upgrade the `Fork` struct before verifying.

**Why it wasn't caught earlier:** Fork-boundary attestation verification was never tested end-to-end. The bug only manifests in the brief window at fork epoch boundaries (affects only the first slot of a fork epoch if the head is still in the prior epoch).

**Could-have-been-caught-by:** An integration test that: (a) sets up a fork at epoch N, (b) collects attestations from validators who have advanced past the boundary, (c) attempts to include them in a block proposal at epoch N boundary, (d) verifies the block is accepted by another client. This scenario is now part of EF consensus tests for fork upgrades.

---

### DD-7: Inconsistent state replay corrupts block_roots, wrong withdrawal amounts (#4234, fix #4249)

**Root cause:** To efficiently get attester shufflings for old attestations, Lighthouse used an "inconsistent" state replay that skipped computing state roots (expensive). A side effect: `block_roots` in the state stores `hash_tree_root(block, state_root)`, so without real state roots, `block_roots` contained wrong values. During replay, attestation inclusion rewards were computed against these corrupt roots (essentially zero rewards for everyone). Capella added withdrawals that depend on current balances; the wrong proposer reward credit led to a wrong withdrawal amount, causing a `WithdrawalsRootMismatch` error.

**How discovered:** Mainnet ERRO log observed across SigP fleet on April 24, 2023, shortly after Capella activation.

**How fixed:** PR #4249 skipped all withdrawals processing when doing an "inconsistent" state replay (since the shuffling needed is determined by the epoch boundary, not mid-epoch state).

**Why it wasn't caught earlier:** Pre-Capella, withdrawals didn't exist; the inconsistent state replay was harmless. The bug was latent and only triggered by the new withdrawal processing code added for Capella.

**Could-have-been-caught-by:** A property test: "inconsistent state replay must produce the same attester shuffling as a consistent replay." Testing the new withdrawal path against inconsistent replays before Capella deployment.

---

### DD-8: Fork choice store corrupted by partial mutation on SIGINT (#4332, fix #4357)

**Root cause:** Fork choice processing (block import, pruning after finalization) mutates multiple in-memory data structures non-atomically. When a SIGINT arrived mid-mutation and cancelled the async task, the fork choice was in a partially-updated state. The shutdown handler persisted this in-memory fork choice to disk. On restart, `find_head` failed the `InvalidBestNode` sanity check because the persisted state was internally inconsistent.

**How discovered:** User report on Discord — beacon node crashed to the `CRIT` error on restart after a SIGINT during sync.

**How fixed:** PR #4357 removed the `CountUnrealized` optimization that made fork choice processing conditional and non-idempotent. With `CountUnrealized` always enabled, re-importing the same block to fork choice produces the same result, making the system self-healing on restart.

**Why it wasn't caught earlier:** Race between async task cancellation and the shutdown handler's fork-choice persistence was not tested. Crash-safety testing (SIGKILL/SIGINT mid-operation) was absent.

**Could-have-been-caught-by:** Crash-injection tests: start a node, kill it with SIGKILL at various random points during block import/pruning, verify it restarts cleanly. This is analogous to filesystem crash-consistency testing.

---

### DD-9: Progressive balances cache double-counts balance removal for slashed validators (#4826, fix #4834)

**Root cause:** The progressive balances optimization maintains a running sum of unslashed participating balances. `on_slashing()` removed the validator's balance from the total. Later, `on_effective_balance_change()` applied a delta for any validators whose effective balance changed at epoch transition — **including slashed validators**. For a slashed validator whose effective balance was reduced as a result of slashing, both the removal and the delta were applied, effectively double-removing their contribution.

**How discovered:** Internal testing during Deneb + tree-states development by @michaelsproul.

**How fixed:** PR #4834 guarded `on_effective_balance_change` with `!validator.slashed()`. Added defensive checks and a regression test.

**Why it wasn't caught earlier:** The optimisation was behind a feature flag (disabled by default); this limited exposure. The bug required a specific sequence: validator slashed, effective balance reduced in same epoch transition.

**Could-have-been-caught-by:** A property test: "progressive balances total must equal the total computed by the naive full-scan, for any sequence of slashings and balance changes." Differential testing between the optimized and naive paths.

---

### DD-10: `InvalidBestNode` over-strict sanity check prevents node startup (#9364, fix #9364)

**Root cause:** `find_head` in proto-array contained an `InvalidBestNode` error path that fired when the head traversal reached a node where all descendants in the fork-choice tree were ineligible. The assumption was that this "should never happen." Under extreme non-finality (Gloas devnets) or after payload invalidation, the justified checkpoint itself could be the head, with all its descendant subtrees non-viable. This is perfectly valid per spec — `get_head` should return the starting node in that case — but the Lighthouse error prevented the node from starting at all.

**How discovered:** Glamsterdam devnet — Lighthouse nodes unable to start after extended periods of non-finality.

**How fixed:** PR #9364 completely removed the `InvalidBestNode` error path. In all cases where all leaf nodes are ineligible, `find_head` now returns the starting node (the justified checkpoint block), matching spec behaviour.

**Why it wasn't caught earlier:** The condition requires all descendant subtrees to simultaneously be non-viable, which doesn't happen on healthy mainnets. Devnet stress testing (extreme non-finality, new ePBS semantics) was needed to trigger it.

**Could-have-been-caught-by:** EF fork-choice compliance tests for non-finality scenarios; the wiring of EF fork-choice tests (PR #9185) would have caught this.

---

### DD-11: O(n²) `find_head` and stack overflow in `filter_block_tree` (#9090, fix #9090)

**Root cause:** PR #9025 removed the `best_child`/`best_descendant` cache from proto-array nodes for spec clarity. This left `find_head` scanning all nodes to find children at each step — O(n²) overall. Additionally, `filter_block_tree` used recursion; at ~30k unfinalized blocks (non-finality scenario) it stack-overflowed.

**How discovered:** Internal testing / follow-up from the Gloas fork-choice refactor (#9025).

**How fixed:** PR #9090 added `build_children_index()` (O(n) pre-pass to build a parent→children map) and converted `filter_block_tree` to iterative reverse traversal (proto-array nodes are insertion-ordered, so reverse iteration processes children before parents).

**Why it wasn't caught earlier:** The refactor that removed the cache (#9025) didn't include performance benchmarks or tests for large fork-choice trees. The stack overflow threshold (~30k) is only reachable during extended non-finality.

**Could-have-been-caught-by:** A benchmark test for `find_head` with N=50,000 blocks run as part of CI on the PR that removed the cache. A stack-overflow smoke test for `filter_block_tree` with deep chains.

---

### DD-12: Dequeue attestations unsorted queue causes stuck votes (#9524, fix #9524)

**Root cause:** `dequeue_attestations` released queued votes by splitting the queue at the first entry where `slot >= current_slot`, assuming the queue was sorted by slot. The queue (`Vec<QueuedAttestation>`) is appended in arrival order and never sorted. A future-slot attestation arriving early would sit before already-due attestations; the split would exclude the due attestations, leaving them permanently stuck behind the future-slot entry.

**How discovered:** Internal testing on Gloas devnets.

**How fixed:** PR #9524 replaced the sorted-split approach with a `BTreeMap<Slot, Vec<QueuedAttestation>>` for natural ordering, plus regression tests.

**Why it wasn't caught earlier:** Normal network operation tends to deliver attestations close to their slot time; out-of-order delivery from future slots is unusual on mainnet. No unit test exercised out-of-order queuing.

**Could-have-been-caught-by:** A unit test inserting attestations from slot N+2 before slot N, then dequeueing at slot N, and asserting the slot-N attestations were applied.

---

### DD-13: Unrealized justification reuse incorrect when block contains slashings (#9471, fix #9471)

**Root cause:** An optimization reused the parent block's unrealized justified/finalized checkpoints for a child block in the same epoch (to avoid recomputing the full FFG progression). The optimization was valid in general but failed to account for slashings: a slashing in the child block can change balances, which can push the unrealized justification forward or back. Using the parent's checkpoints in the presence of slashings could give wrong unrealized checkpoints.

**How discovered:** Internal testing / code review while working on Gloas.

**How fixed:** PR #9471 added a `has_slashings` guard: when the block being imported contains slashings, the optimization is bypassed and unrealized checkpoints are recomputed from scratch. Three regression tests confirm behavior.

**Why it wasn't caught earlier:** Slashings are rare on mainnet; the optimization had been in place for a long time without issue. The Gloas development brought deeper scrutiny to fork-choice correctness.

**Could-have-been-caught-by:** A fork-choice EF test with a block that contains slashings and then verifies the subsequent unrealized justified checkpoint. Differential testing: "unrealized checkpoint computed with optimization must equal that computed without optimization."

---

### DD-14: Proposer reorg strategy uses wrong finalization source (#9359, open)

**Root cause:** `get_proposer_head_info` computes `epochs_since_finalization` from `head_node.unrealized_finalized_checkpoint` rather than `store.finalized_checkpoint` as the spec requires. It also checks both unrealized justification and unrealized finalization for FFG-competitiveness, whereas the spec only checks unrealized justification. This can cause the proposer to choose a different parent than expected by the spec's reorg helper.

**How discovered:** Flagged via vulnerability report (de-escalated by @michaelsproul to a spec deviation, not a security issue).

**How fixed:** Not yet fixed (open as of audit date).

**Why it wasn't caught earlier:** The proposer reorg feature is optional and rarely used on mainnet; deviations only manifest in edge-case network conditions.

**Could-have-been-caught-by:** Direct comparison of Lighthouse's `get_proposer_head_info` output against a Python reference implementation of the spec helper for a range of fork-choice states.

---

### DD-15: Non-canonical payload attestation (PTC) always uses head state (#9305, fix #9305)

**Root cause:** In the Gloas/ePBS fork, payload attestations (from the Payload Timeliness Committee) needed to be verified for any chain tip, not just the canonical head. The verification function always looked up the PTC using the head block's state, silently failing for non-canonical chains. EF fork-choice compliance tests caught this.

**How discovered:** EF fork-choice compliance tests wired in PR #9185 and #9256.

**How fixed:** PR #9305 stored PTC data in the existing attester shuffling cache (indexed by epoch + decision block root) and added a fallback that loads the correct state for non-canonical chain verification.

**Why it wasn't caught earlier:** The ePBS feature was new (Gloas fork) and the EF compliance test suite for it was being wired simultaneously.

**Could-have-been-caught-by:** Running EF fork-choice compliance tests from the beginning of Gloas development.

---

## 4. Synthesis

### Counts by class

| Class | Count |
|-------|-------|
| `spec-correctness` | 16 |
| `concurrency` | 4 |
| `resource` | 3 |
| `fork-upgrade` | 2 |
| `api-correctness` | 2 |
| `logic-other` | 3 |
| `persistence` | 1 |

### Counts by severity

| Severity | Count |
|----------|-------|
| critical | 7 |
| high | 12 |
| medium | 9 |
| low | 3 |

### Recurring root-cause themes

1. **Spec deviation in edge-case branches.** The most common class. Many bugs exist in code that runs correctly 99.9% of the time (normal finality, single chain, no slashings, no fork boundaries) but breaks in rare combinations: at upgrade epochs (#4238), with slashings (#4826, #9471), with non-finality (#9090, #9364), or with out-of-order events (#9524). The spec covers all of these; Lighthouse code historically didn't.

2. **Incorrect checkpoint comparison.** Both #2741 (checked epoch but not root in `filter_block_tree`) and #9359 (uses `unrealized_finalized` vs. `store.finalized`) represent the same class of error: using a coarser equality test than the spec requires. This has appeared twice across a 5-year codebase, suggesting the pattern will recur.

3. **Stale/wrong state used in attestation/block verification.** Three separate bugs (#4238, #4234, #9305) all involve looking up an incorrect `BeaconState` (head state instead of slot-appropriate state) for signature verification or shuffling retrieval. The root cause is that the "right" state is expensive to compute and the code reused the nearest available state.

4. **Fork-choice non-atomicity / crash unsafety.** #4332 (SIGINT corruption) and #6606 (pre-finalization cache false assumption after unclean shutdown) both arise because the invariant "if block is in DB it is finalized or in fork choice" is only one-directional. Crash recovery was not systematically tested.

5. **Optimization introduces spec divergence.** Recurring theme: a performance optimization (#820 removed sig re-check → #845, #9025 removed best_child cache → #9090, unrealized checkpoint reuse → #9471, progressive balances incremental update → #4826) introduced a spec violation. Each optimization was added without a differential correctness test against the naive path.

6. **Race conditions on "seen" caches and fork-choice locks.** #1719, #1557, and #7839 are all variations of the same pattern: a multi-step operation reads fork-choice or a seen-cache multiple times without holding the lock across all reads.

### Highest-leverage early-detection ideas

1. **EF fork-choice compliance tests wired in CI from day one.** Issues #2741, #9364, #9305, and #9359 would all have been caught. The EF test suite covers justified/finalized checkpoint root checks, `filter_block_tree` with non-finality, and non-canonical attestation verification. PR #9185 only wired these in recently — much of this should have been in CI from v1.0.

2. **Differential "optimization vs. naive" property tests for every state-processing optimization.** Progressive balances (#4826), op-pool attestation reuse (#845), unrealized checkpoint caching (#9471) — each was an optimization that silently diverged from the reference implementation. A property test asserting `optimized_result == naive_result` for random inputs would catch this class immediately.

3. **Crash-injection / crash-recovery CI.** Two critical bugs (#4332, #6606) only manifested after an unclean shutdown. A CI job that: imports N blocks, kills the node with SIGKILL at a random block, restarts, and verifies the node starts cleanly and produces correct fork-choice state — would have caught both.

4. **Fork-upgrade attestation/block production end-to-end test.** #4238 was a critical mainnet incident that only surfaces in the ~4-second window between the last slot of one fork epoch and the first received block of the next. A harness test that explicitly exercises batch attestation verification at a fork boundary (head still in old epoch, attestations signed with new-epoch domain) would have caught this before Capella mainnet.

5. **Stack-depth / complexity benchmarks for non-finality scenarios in proto-array.** #9090 introduced a stack overflow at ~30k blocks and O(n²) find_head. A criterion benchmark tracking `find_head` time for N=10k, 50k, 100k unfinalized blocks, run as part of the PR that removed `best_child` caching, would have immediately flagged the regression.

6. **Type-level enforcement of checkpoint equality.** The recurring "checked epoch but forgot root" pattern (#2741, #9359) could be addressed by a newtype that wraps `Checkpoint` and implements `PartialEq` only via a library function that forces consideration of both fields — or, more pragmatically, a lint that flags any comparison of `.epoch` fields extracted from a `Checkpoint` struct.

### Architectural smells

- **`proto_array.rs` / fork-choice core.** Shows up in 7+ bugs (#2741, #4332, #9090, #9364, #9471, #9524, #9359). This module is high-complexity, performance-critical, and spec-sensitive — a prime candidate for differential fuzz testing against the Python reference implementation.
- **`attestation_verification/` and state-context mismatch.** Three independent bugs (#4238, #4234, #9305) arose from using the wrong `BeaconState` for verification. The abstraction for "get the right state for this attestation" is clearly fragile. A session-typed approach where the `BeaconState` required for a given attestation is part of the type signature would help.
- **Optimization + correctness divergence.** The progressive balances cache (`progressive_balances_cache.rs`) and the unrealized-checkpoint reuse path in `fork_choice.rs` both had bugs introduced by optimizations. Both modules need differential property tests as a standing requirement for any future modifications.
