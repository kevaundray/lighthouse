# Lighthouse Historical Bug Audit — Master Synthesis

*Aggregated from 10 parallel subsystem audits of sigp/lighthouse issues + PRs (open & closed),
their conversations, and the actual fix diffs. ~370 distinct bugs catalogued. Detail files per
subsystem live alongside this one.*

---

## 1. Executive summary

Lighthouse's bugs cluster far more by **failure pattern** than by subsystem. The same handful of
structural mistakes recur across consensus, networking, sync, DA, DB, VC, EL, and HTTP — separated
sometimes by years and four releases. The single most important finding:

> **Most of the worst bugs were not novel. They were the *same class of mistake* reappearing in a
> new module because the codebase has no standing mechanism to catch that class.**

The two subsystems that produce the most *critical* bugs are **consensus** (spec-correctness at
fork boundaries / under non-finality) and **networking** (panics & OOM from peer-controlled
inputs), for opposite reasons — one is "too clever," the other is "trusts the peer too much."

The good news for "catch them earlier": because the bugs are patterned, a small number of
**standing test/lint harnesses** (≈8) would have caught a large majority of the critical history.
They are listed in §5, prioritized.

---

## 2. Coverage & method

| Subsystem (agent) | Bugs catalogued | Critical | File |
|---|---|---|---|
| Consensus / fork choice / state transition | 35 | 7 | `consensus.md` |
| Networking / P2P (gossip, discv5, RPC, peers) | ~38 | 2* | `networking.md` |
| Sync (range / backfill / lookups) | 34 | 1 | `sync.md` |
| Execution layer / Engine API / builder | 28 | 2 | `execution-layer.md` |
| Database / store / migrations | 37 | 5 | `database.md` |
| Validator client | 46 | 3 | `validator-client.md` |
| HTTP API | 35 | 0 | `http-api.md` |
| Data availability (blobs / PeerDAS / KZG) | 43 | 3 | `data-availability.md` |
| Slasher / crypto / runtime / CLI | 38 | 3 | `slasher-crypto-misc.md` |
| **Cross-cutting: security label + incidents** | ~51 rows | 18 | `critical-incidents-security.md` |

\* The networking agent rated severity conservatively; the incidents agent independently rated
networking as the joint-highest critical subsystem (7 criticals: yamux, gossipsub OOM, mesh-peer
drop, discv5 OOM, etc.). Treat networking as a top-tier critical source.

Each agent: enumerated all bug-labeled items in scope, keyword-searched unlabeled ones, read the
conversations, followed the fixing PR's diff, and classified by a shared taxonomy (bug-class,
how-found, severity). Method file: `SCHEMA.md`.

---

## 3. Distribution

### 3a. By bug class (approx. aggregate across the 10 reports; some cross-subsystem overlap)

| Class | ~Count | Where it concentrates |
|---|---|---|
| `spec-correctness` | ~40 | consensus, http-api (rewards/LC), slasher (fork domain) |
| `api-correctness` | ~39 | http-api, validator-client, execution-layer |
| `sync-logic` | ~35 | sync, data-availability |
| `persistence` | ~30 | **database**, validator-client (slashing protection) |
| `protocol-networking` | ~30 | networking, VC (multi-BN), DA (custody requests) |
| `resource` | ~26 | database, DA, slasher, networking, sync |
| `concurrency` | ~21 | VC, slasher, consensus, database |
| `logic-other` | ~20 | mostly RUSTSEC/dep advisories + misc |
| `panic-crash` | ~18 | **networking** (peer input), slasher (unwrap) |
| `config-cli` | ~16 | VC, slasher, networking (permissions/flags) |
| `el-integration` | ~14 | execution-layer |
| `perf-regression` | ~12 | sync, DA, database |
| `serialization` | ~8 | execution-layer (JSON), slasher/db (SSZ) |
| `availability-da` | ~10 | data-availability |
| `fork-upgrade` | ~5 explicit | (under-counts — fork-boundary is really a *cross-class* driver, see §4.3) |

### 3b. By severity (critical concentration)

Critical bugs are dominated by: **consensus** (fork-boundary + non-finality), **networking**
(peer-controlled panics/OOM), **database** (pruning/migration corruption), **DA** (devnet consensus
breaks), and **validator-client** (slashing-protection gap + auth bypass). HTTP API produced *zero*
criticals (worst case: wrong-but-recoverable responses) — a useful signal about where blast radius
actually lives.

---

## 4. The cross-cutting root-cause patterns (the core finding)

These are ordered by how many subsystems they appear in × severity. Each is a *structural* problem,
not a one-off. Issue numbers cite occurrences in **different** subsystems to prove recurrence.

### 4.1 — Code-path asymmetry: "the alternate path is untested dead code that rots"
The bug that recurs in the most subsystems. A check/behavior is added on the *common* path and
silently missing on a parallel path that runs rarely.
- **DA:** verification added for gossip, missing on RPC range path & backfill — missing fork-choice
  call (#5474), missing KZG inclusion proof (#6111), missing checkpoint-sync blob fetch (#5251),
  missing backfill header-sig check (#7305, still open).
- **Execution layer:** SSZ engine-API path is tested; the JSON path is effectively dead code that
  accumulated 3 separate fork-unaware deserialization bugs (#3314, #7277, #8224).
- **Sync:** three block-import code paths, only two called `recompute_head`; the RPC-blob path
  silently didn't (#5474).
- **Consensus:** op-pool attestation path skipped the sig re-check the gossip path did (#845).

**Structural fix posture:** a *symmetric test matrix* — every DA/import/verify check must be exercised
through **every** ingress path (gossip · RPC · backfill · HTTP · checkpoint-sync), ideally by sharing
one verification function rather than parallel copies.

### 4.2 — Optimization removes or weakens a correctness check
Performance work is the single most productive *source* of critical consensus bugs. Each optimization
diverged silently from the naive/spec path because no differential test pinned them together.
- Disabled op-pool sig re-check → cross-fork invalid blocks (#845).
- Removed `best_child`/`best_descendant` cache → O(n²) `find_head` + stack overflow at ~30k blocks
  (#9090).
- Incremental progressive-balances cache → double-counts slashed validators (#4826).
- Reused parent's unrealized checkpoints → wrong with in-epoch slashings (#9471).
- State-cache default 128→32 → mainnet cache-miss storm, hotfixed (v7.0.1 / #7364).

**Structural fix posture:** review-gate — *"does this PR remove/weaken a correctness check or a
cache an invariant depends on?"* → require a companion differential property test
`optimized_result == naive_result` over randomized inputs.

### 4.3 — Fork-boundary state staleness (`state.fork()` vs `spec.fork_at_epoch()`)
A latent bug at **every** hard fork. Using the head/current state's fork or constants instead of the
slot-appropriate ones. This is really a *driver* that manifests as spec-correctness, api, or
el-integration depending on where it lands.
- **Consensus:** batch attestation verify used head-state `Fork` at Capella boundary → Capella
  mainnet missed block (#4238); Electra epoch processing double-applied consolidations, GHSA-wm9c
  (#7209); Fulu proposer shuffling not fork-aware (#8101).
- **Slasher/crypto:** `state.fork()` for signing domain (#8528, #9173, #7441).
- **HTTP API:** every fork (Altair/Dencun/Electra) shipped a non-additive endpoint regression
  (#6818, #6983, #8252, #5016).
- **Execution layer:** fork-unaware Fork computation (#8528).

**Structural fix posture:** lint/audit that flags `head_state.fork()` (and per-fork constants read
from the wrong state) in signing-domain / verification code; a release-gate fork-transition test
harness; **security competitions before each fork** (which already caught GHSA-wm9c and #8101).

### 4.4 — Trusting peer-controlled numeric inputs → panic / OOM (networking)
Lighthouse forks its networking libraries (libp2p/gossipsub, discv5, yamux, quinn) and therefore
*owns their security*. Repeatedly, arithmetic on peer-supplied values panicked or grew unbounded.
- yamux window over/underflow panics — mandatory upgrades v8.1.1/v8.1.2 (any peer could crash node).
- gossipsub backoff `Instant::add` overflow crash (#8955, RUSTSEC-2026-0009).
- gossipsub unbounded send queues → 16GB+ OOM on mainnet (#4918).
- discv5 SNAT ENR loop → 117GB RSS in 14 min (#8437).
- igd / libp2p-upnp / rustls `unwrap()` in tokio tasks → full-node crash (#4171, #5444, #6088, #6399).

**Structural fix posture:** mandatory checked/saturating arithmetic + graceful `Err` (never panic)
on *all* externally-controlled numeric inputs in the networking stack; a `cargo-deny`/RUSTSEC CI
gate; a fuzz harness feeding crafted frames; an unpinned-`cargo update` nightly build to surface
dependency panics before users do.

### 4.5 — Non-finality / scale never tested at realistic size
A standing structural blind spot. The system is designed and tested for healthy finalizing networks;
real non-finality (inactivity leak, tens of thousands of unfinalized blocks) repeatedly broke it.
- O(n²) `find_head` + stack overflow at ~30k blocks (#9090).
- Holesky 2025: 128×180MB state cache → OOM; 200GB side-chain growth overnight (#7040, #7053).
- Hot-DB unbounded `HotStateSummary` growth under non-finality (#5768, #6580).
- DA blob pruning OOM (77GB spike, #6559) and high IO (#7100).

**Structural fix posture:** a dedicated **non-finality chaos scenario** in CI/sim — 50k–500k
unfinalized blocks under inactivity-leak conditions — with assertions on memory, stack depth, DB
growth, and `find_head` latency.

### 4.6 — Invariant not re-established retroactively on feature/schema rollout (persistence)
A change alters *what* is stored or *where*, but doesn't backfill the new invariant for existing
data — so it works on fresh nodes and corrupts upgraded ones. Each needed a "heal" migration.
- block-roots gap after invariant change (#4697), genesis skip-slot (#4817), blobs in wrong DB
  (#5114), dangling temp states after v22→v23 (#7323).
- Pruning vs `migrate_db` run asynchronously and desync on crash → corruption (#4975, #8409).
- Three LevelDB directories (chain/freezer/blobs) with **no cross-directory atomic write** (#692,
  #1323, #5114, #8409).

**Structural fix posture:** schema-migration CI against a *seeded real-world DB snapshot* (with op-pool
entries, skip slots, blobs, archive states); crash-injection within `migrate_db`; a startup
gap-detection check exported as a Prometheus metric.

### 4.7 — Wrong/coarser comparison or wrong state object in verification
- **Consensus:** checkpoint compared by *epoch only*, ignoring root — the **same logical error in
  #2741 (2021) and #9359 (2026)**, 5 years apart. Wrong `BeaconState` used for verify/shuffling
  (#4238, #4234, #9305).
- **Sync:** lookup state-machine ID/root mismatch — results applied to an obsolete lookup ID while a
  new lookup for the same root exists (#5694, #5833, #8104).

**Structural fix posture:** newtype/`PartialEq` discipline forcing full-`Checkpoint` comparison;
differential check of `get_proposer_head_info` / fork-choice helpers against the Python spec
reference; property test "every created lookup is eventually removed."

### 4.8 — State-machine lifecycle bugs in sync lookups (the single most fragile module)
`single_block_lookups` and the range/backfill `processing_target` logic repeatedly assume a batch /
lookup exists when it doesn't, or process results for a stale ID.
- `processing_target` assumes batch exists — *independently* in range (#7360, #4346) and backfill
  (#7818) because the two are structurally isomorphic but **not shared code**.
- empty RPC responses not counted as peer failures → unlimited retries / infinite loops (#7980, #6989).

**Structural fix posture:** unify range/backfill batch logic; `debug_assert` the batch-exists
invariant; event-sequence property tests; "empty stream = peer failure, always" review rule + metric.

### 4.9 — Multi-target state not synchronized
The code updates one target and forgets the others it's supposed to keep in lockstep.
- **VC:** fee recipient / proposer prep / subnet subs / validator registration sent only to the
  primary beacon node, not fallbacks → zero-tx blocks & missed duties on failover (#3617, #3614,
  #2926, #3141, #3422).
- **DB:** the three-directory non-atomicity above (#692, #5114, #8409).

### 4.10 — Peer scoring penalizes honest behavior
False-positive downscoring recurs across networking, sync, and DA.
- `BlockIsAlreadyKnown` from RPC-before-gossip race (#5602), P3 deficit on old-fork topics (#3237),
  attestations for unseen heads (#2902), excessive substream rejections under PeerDAS load (#6106),
  innocent peers penalized in sync (#5095, #5707, #6879, #7577).

### 4.11 — Security/permissions/auth in the VC found only by external researchers
Never caught internally. Suggests the VC's security surface lacks systematic review.
- world-readable key files 644 (#2437), token in logs (#2438), **POST/PATCH auth bypass** (#2512),
  log rotation resets perms (#7170), sub-logger files unrestricted (#7171).

### 4.12 — Hand-written serialization diverges from derived
- manual `Encode`/`Decode` field-order mistakes → silent DB corruption on migration (#6035) and wrong
  deserialization (#5078); fork-unaware JSON deserialization in the builder path (#3314/#7277/#8224).

---

## 5. The "catch them earlier" toolkit — prioritized

Each item lists the patterns (§4) and example bugs it would have caught. Ordered by
(historical-criticals-prevented × breadth × feasibility).

| # | Investment | Catches patterns | Example bugs it would've caught |
|---|---|---|---|
| 1 | **EF spec + fork-choice compliance tests in CI, from day one** (only wired recently via #9185) | 4.3, 4.7 | #2741, #9305, #9359, #9364, GHSA-wm9c |
| 2 | **Non-finality chaos scenario** (50k–500k unfinalized blocks, inactivity leak) in sim/CI | 4.2, 4.5 | #9090, Holesky #7053, #5768/#6580, #6559 |
| 3 | **Differential "optimized == naive" property tests** as a standing requirement for any cache/optimization | 4.2, 4.7 | #845, #4826, #9471, #9090 |
| 4 | **Checked-arithmetic + no-panic lint on peer-controlled inputs** in networking, plus `cargo-deny`/RUSTSEC gate + nightly unpinned `cargo update` build | 4.4, 4.12 | yamux v8.1.1/.2, #8955, #4918, #8437, #4171/#5444/#6088 |
| 5 | **Symmetric ingress-path test matrix** (run every verify/import check through gossip · RPC · backfill · HTTP · checkpoint-sync); prefer one shared verification fn over parallel copies | 4.1, 4.8 | #5474, #6111, #5251, #7305, #8224 |
| 6 | **Crash-injection / chaos tests** (SIGKILL at random block-import & mid-`migrate_db` points; assert clean restart) | 4.6 (and consensus 4332/6606) | #4332, #6606, #4975, #8409, #4773 |
| 7 | **Schema-migration CI on a seeded real-world DB snapshot** + startup gap-detection metric | 4.6 | #4697, #4817, #5114, #6035, #7323 |
| 8 | **Per-fork cross-client API conformance matrix** (LH BN ↔ Teku/Prysm/Nimbus VC each devnet) + OpenAPI response validation + light-client Merkle-proof verification in tests | 4.1, 4.3 | #5080, #6818, #8252, #7441, #7536, #7434/#7440 |
| 9 | **Security competition before every fork** + automated VC auth/permission regression tests | 4.3, 4.11 | #8101, GHSA-wm9c, #2512, #2437/#2438/#7170/#7171 |
| 10 | **Multi-BN failover harness** (kill primary mid-proposal-cycle; assert fee recipient, non-zero txs, no slashing false positives) | 4.9 | #3617, #3614, #2926, #3141 |
| 11 | **SSZ roundtrip property tests for every non-derived `Encode`/`Decode`** (CI lint flagging manual impls without a proptest) | 4.12 | #6035, #5078 |
| 12 | **Dependency-bump integration harness** (test preconditions in a new KZG/networking crate's changelog before merging the bump) | 4.4 | #6105, #7991, #8509 |

Items 1–4 are the highest leverage: between them they cover the large majority of *critical* history.

---

## 6. Architectural / structural smells (modules that recur)

- **`proto_array.rs` / fork-choice core** — appears in 7+ bugs (#2741, #4332, #9090, #9364, #9471,
  #9524, #9359). High-complexity, perf-critical, spec-sensitive. Prime candidate for **differential
  fuzzing against the Python spec reference**.
- **`attestation_verification` state-context selection** — 3 independent "wrong `BeaconState`" bugs
  (#4238, #4234, #9305). The "get the right state for this message" abstraction is fragile; a
  type-/session-typed approach would help.
- **`single_block_lookups` (sync)** — the most fragile state machine; ID/root lifecycle bugs recur.
- **Builder-API JSON path (execution_layer)** — untested parallel path; a fork-unaware-deserialization
  bug magnet.
- **Three-directory DB (chain/freezer/blobs)** — no cross-directory atomic write primitive; root of
  multiple corruption bugs. A structural fix (single transactional boundary) would retire a class.
- **Forked networking stack (gossipsub/discv5/yamux/quinn)** — Lighthouse owns security of code it
  doesn't fully author; every mandatory-upgrade incident lives here.
- **Pruning ↔ migration concurrency** — asynchronous, desyncs on crash; repeatedly corrupts.

---

## 7. Suggested next steps (for the "what do we do about it" phase)

1. Treat §4 as the **bug-taxonomy backbone**. Validate the 12 patterns against the per-subsystem
   tables, then weight by severity × recency to pick the top 3–4 to attack first.
2. Convert §5 items 1–4 into concrete CI/harness tickets — these are the highest ROI and mostly
   tooling, not redesign.
3. For the structural smells in §6, decide which warrant a redesign (e.g. DB atomic boundary,
   fork-choice differential fuzzing) vs. which are adequately covered by adding the §5 harnesses.
4. Consider an **invariant ledger**: for each pattern, the explicit invariant + where it's enforced +
   the test that proves it. The recurring "same bug 5 years later" (#2741→#9359) is the cost of not
   having one.

---

*Per-subsystem detail (full bug tables, deep dives, per-area synthesis) is in the sibling files:
`consensus.md`, `networking.md`, `sync.md`, `execution-layer.md`, `database.md`,
`validator-client.md`, `http-api.md`, `data-availability.md`, `slasher-crypto-misc.md`,
`critical-incidents-security.md`. Shared method: `SCHEMA.md`.*
