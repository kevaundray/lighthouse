# Lighthouse — Structural-Problem Analysis

*Phase 2 of the bug audit. Takes the 12 recurring patterns from [MASTER-REPORT.md](MASTER-REPORT.md)
§4 and asks the question that actually matters: **is there a structural problem, or just a backlog of
fixed instances?** To answer it honestly, the patterns were re-verified against the **current**
`unstable` tree — because a historical audit over-counts: many of these classes have already been
closed reactively.*

---

## 0. TL;DR

**There is not one big structural problem. There is one genuine architectural debt, one architectural
*shape* that needs enforcing, and a process gap — "we fix instances, we don't install class-level
guards" — that is itself the meta-structural problem.**

Re-verification against current code matters a lot. Several of the scariest historical patterns are
**already addressed**:

- **Fork-choice spec compliance** (patterns 4.3/4.7): EF `fork_choice` suite is now fully wired and in
  the merge-queue gate (`testing/ef_tests`, `ForkChoiceHandler`). The exact class behind #2741, #9305,
  #9359, #9364 now has a standing guard.
- **Non-finality `find_head` blow-up** (4.2/4.5, the #9090 stack overflow): there is now a Criterion
  bench at **518k blocks** (`consensus/proto_array/benches/find_head.rs`) explicitly sized for "1 month
  of non-finality." The lesson was internalized.
- **Sync lookup fragility** (4.8): `single_block_lookups` is now hardened — fallible "batch exists"
  paths (no more `.expect`), `UnexpectedRequestId` guard, lifecycle tests asserting `created == removed`,
  and an `UpdatedPeerCgc` re-trigger for PeerDAS metadata. Range/backfill now share `BatchInfo`.
- **Pruning vs migration race** (4.6 DB-side): now serialized on a single background migrator thread.
- **Fork-boundary `state.fork()`** (4.3): patched in #9342 + `verify_header_signature`; remaining
  `state.fork()` sites are spec-correct; `beacon_proposer_cache` explicitly uses `fork_at_epoch`.

So the "structural problem" is **not** that these areas are broken today. It is that *each guard was
added only after a production incident in that specific area*. The classes with **no** standing guard
yet are where the next incidents will come from. Those are enumerated below.

---

## 1. How to read this

Each structural problem is classified on three axes:

- **Live?** — verified state of the *current* `unstable` tree: `STILL-LIVE` / `PARTIAL` / `ADDRESSED`.
- **Type** — `redesign` (architecture change), `harness` (standing test/fuzz/bench), or `process`
  (lint/review-gate/competition).
- **Weight** = historical severity × recency (how bad were the bugs, and are they still happening). This
  is what should drive ordering, per the request.

A problem that is `ADDRESSED` is listed only to record *why* it's no longer a priority.

---

## 2. Tier 1 — Genuine architectural problems (redesign-class)

### S1. Cross-database non-atomicity (chain DB ↔ freezer DB ↔ blobs DB)
**Live?** STILL-LIVE · **Type:** redesign · **Weight:** HIGH severity × HIGH recency (#8409 is v8-era)

The store still opens **three physically independent databases** (`chain_db`, `freezer_db`, `blobs_db`;
`hot_cold_store.rs:279,289-291`) and there is **no write primitive that spans them**. `do_atomically`
is per-backend (a LevelDB `WriteBatch` or redb txn) and touches exactly one directory. The code says so
itself (`hot_cold_store.rs:3662`):

> *"Since it is pretty much impossible to be atomic across more than one database, we trade potentially
> re-doing the migration … for consistency."*

`do_atomically_with_block_and_blobs_cache` writes blobs first, then hot state, with a **software
rollback** on failure — which is *not* crash-safe (a process death between the two commits leaves blobs
persisted, hot DB not). This is the **root cause shape** behind the persistence-corruption class
(#692, #1323, #5114, #8409, and the HeadTracker/pruner corruption #4773). It is the single most
"structural" item in the whole audit: not a missing test, but a foundational invariant the architecture
cannot currently express.

**Recommendation (redesign, staged):**
1. *Short term (harness):* a crash-injection test (S5) that SIGKILLs between the blob-commit and
   hot-commit and asserts clean recovery — this at least makes the current risk *visible and bounded*.
2. *Medium term (redesign):* introduce an explicit cross-DB **intent/journal** (write-ahead a small
   "operation N in progress" record so recovery is deterministic rather than "re-run and hope it's
   idempotent"), or collapse blobs into the hot DB so the only remaining boundary is the
   deliberately-idempotent hot→cold migration. The hot↔cold boundary is *designed* to be re-runnable;
   the hot↔blobs boundary is the unguarded one and the better redesign target.

### S2. Verification-path asymmetry as an architectural shape
**Live?** PARTIAL · **Type:** redesign (enforce a shape) · **Weight:** HIGH severity × HIGH recency

This was the **most widespread pattern** historically (§4.1: #5474, #6111, #5251, #7305, #8224). Good
news: **block** verification now funnels all ingress paths through
`SignatureVerifiedBlock → ExecutionPendingBlock` — the right architecture. **Bad news: data-column
verification has not converged.** Verified live asymmetry:

| data-column path | inclusion proof | proposer sig | KZG |
|---|---|---|---|
| gossip (Fulu) | ✅ | ✅ | ✅ |
| **RPC custody** | ❌ | ❌ | ✅ |
| block-publishing local | ❌ | ❌ | bypassed |

The RPC path substitutes a *weaker* gate ("parent block known to fork choice", `beacon_chain.rs:3543`)
for the gossip path's full header+inclusion-proof+proposer-sig — the **same shape** as the still-noted
#4546 (`block_verification.rs:304`). (The Gloas-gossip omission is legitimate — that struct carries no
header — so it's not a bug, but it shows the checks are per-path, not centralized.)

**Recommendation (redesign, focused):** make data-column verification **ingress-agnostic** — one
`verify_data_column(column, trust: TrustLevel)` funnel where the difference between paths is an *explicit
trust parameter*, never an omitted check. The architectural rule worth adopting repo-wide:
*"a verification difference between ingress paths must be a named, reviewed parameter — not the absence
of a call."* This is the durable fix for §4.1 generally; block verification already demonstrates the
pattern works.

---

## 3. Tier 2 — Missing class-level guards (harness-class)

These are the patterns that recur *because nothing tests the class*. The infrastructure for most already
half-exists; the gap is wiring + running it.

### S3. No differential "optimized == naive" tests
**Live?** STILL-LIVE (gap) · **Type:** harness · **Weight:** HIGH severity × HIGH recency

The §4.2 class — optimization silently diverges from spec — produced #845, #4826, #9471, and the Electra
consolidation double-apply **GHSA-wm9c**. Verified: there is **no** test comparing
`ProgressiveBalancesCache` to a naive recompute, and **no** test comparing `single_pass.rs` epoch
processing to the Altair multi-pass path. The two existing progressive-balances tests check "does the
chain advance," not arithmetic equivalence. This is the **cheapest high-value item in the report**: the
naive paths already exist; a property test asserting `optimized == naive` over randomized
slash/balance-change sequences would have caught three criticals.

**Recommendation:** standing requirement — every cache / single-pass optimization ships with a
`proptest`/EF-driven differential test against the naive path. Start with progressive balances and
single-pass epoch processing.

### S4. No fuzzing execution harness
**Live?** STILL-LIVE (gap) · **Type:** harness · **Weight:** HIGH severity × MEDIUM recency

The `arbitrary` feature exists on `types`/`state_processing`/`slashing_protection` but **only compiles**
(`make arbitrary-fuzz` is a `cargo check`); there is **no fuzz target, no `fuzz/` dir, nothing run**.
Historically a fuzzer caught the **v4.0.0 fork-choice bug** before release — that capability is no longer
exercised in-repo. Highest-value targets: RPC/gossip SSZ decoders (directly relevant to the peer-input
panic class §4.4) and fork-choice op sequences.

**Recommendation:** stand up `cargo-fuzz` targets on the existing `Arbitrary` impls (SSZ decode, then
fork-choice `on_block`/`on_attestation`), run continuously (OSS-Fuzz or a nightly job), not in the PR gate.

### S5. No crash-injection / chaos tests
**Live?** STILL-LIVE (gap) · **Type:** harness · **Weight:** CRITICAL severity × HIGH recency

Verified: only graceful close/reopen tests + lockbud static deadlock analysis exist. **No** SIGKILL,
mid-migration kill, or mid-write corruption test. This is the direct validator for **S1** (and for the
consensus crash-recovery bugs #4332, #6606, and the HeadTracker corruption #4773). Filesystem crash-
consistency testing is a solved discipline; Lighthouse has none.

**Recommendation:** a test that runs a node, SIGKILLs at randomized points during block import / blob
commit / `migrate_db`, restarts, and asserts a consistent DB + clean startup. Pairs with and de-risks S1.

### S6. No full-stack non-finality scenario
**Live?** PARTIAL · **Type:** harness · **Weight:** CRITICAL severity × HIGH recency (Holesky 2025)

The `find_head` Criterion bench (518k blocks) is excellent but is a **microbench** — it does not exercise
gossip, sync, or the DB. The Holesky OOM (#7040/#7053) lived at the *full-stack* level (state cache ×
180MB diffs, side-chain accumulation). The simulator (`testing/simulator`) runs only happy-path; grep for
`inactivity`/`non_final` returns nothing.

**Recommendation:** add an inactivity-leak / non-finality scenario to the simulator that runs the full
stack for an extended unfinalized period and asserts bounds on memory, DB growth, and duty performance.

### S7. Arithmetic / no-panic lint only covers one file
**Live?** STILL-LIVE (gap) · **Type:** harness/lint · **Weight:** CRITICAL severity (mandatory upgrades) × HIGH recency

`#![deny(clippy::arithmetic_side_effects)]` exists in **exactly one file**
(`rpc/rate_limiter.rs`). `unwrap_used`/`panic` is denied **nowhere**. The §4.4 peer-input panics
(yamux v8.1.1/.2, gossipsub backoff #8955) were in forked deps, but Lighthouse *owns* those forks and
its own networking arithmetic is unguarded. `cargo-audit` + `cargo-deny` (bans/sources only) are wired,
which is good, but they don't catch a panic Lighthouse introduces.

**Recommendation:** extend `arithmetic_side_effects` (and ideally `unwrap_used`) to the
`lighthouse_network` crate and the forked networking libs; add a nightly *unpinned* `cargo update` build
to surface upstream dependency panics before users hit them.

---

## 4. Tier 3 — Process guards

### S8. Fork-upgrade safety is convention + luck, not enforced
**Live?** PARTIAL · **Type:** process · **Weight:** CRITICAL severity × HIGH recency

Every fork has shipped a boundary bug (§4.3). The recent fixes are real but **convention-based**: nothing
*prevents* the next `state.fork()`-in-domain mistake. What demonstrably *works* is the **pre-fork
security competition** — it caught GHSA-wm9c (Pectra) and #8101 (Fusaka). That should be standing policy,
plus a clippy `disallowed-methods` entry flagging `state.fork()` / `head_state.fork()` in signing-domain
code (steering devs to `spec.fork_at_epoch`).

### S9. VC security surface reviewed only by outsiders
**Live?** Likely STILL-LIVE · **Type:** process · **Weight:** CRITICAL severity (auth bypass) × MEDIUM recency

Every VC auth/permission bug (#2437, #2438, #2512, #7170, #7171) was found by an **external** researcher.
A lightweight automated regression test (attempt unauthenticated POST/PATCH; assert key/log file perms
== 600) closes the whole class and is trivial relative to its blast radius.

---

## 5. Priority order (severity × recency × feasibility)

| Rank | Item | Type | Why first |
|---|---|---|---|
| 1 | **S3** differential optimized-vs-naive tests | harness | Cheapest; naive paths exist; would've caught 3 criticals incl. GHSA-wm9c |
| 2 | **S5** crash-injection tests | harness | Directly de-risks S1 and the consensus crash-recovery class; makes S1 risk visible |
| 3 | **S7** arithmetic/no-panic lint on networking | lint | One-line denies per crate; the mandatory-upgrade class lives here |
| 4 | **S6** full-stack non-finality sim scenario | harness | Holesky-class; the microbench is not enough |
| 5 | **S2** unify data-column verification funnel | redesign | Live asymmetry, high severity; block-verification proves the shape works |
| 6 | **S4** fuzzing execution harness | harness | Infra (`arbitrary`) already present; restores a capability that once caught a release-blocker |
| 7 | **S1** cross-DB atomicity redesign | redesign | Deepest debt, but biggest effort; do after S5 makes its risk measurable |
| 8 | **S8** fork competition + `state.fork()` lint | process | Standardize what already works |
| 9 | **S9** VC auth/permission regression test | process | Trivial; closes an externally-found class |

---

## 6. The meta-structural finding

The recurring-bug data tells one organizational story: **Lighthouse reliably fixes the *instance* and
reliably adds a *guard for that exact spot* — but historically only after an incident, and rarely a guard
for the *class*.** EF fork-choice tests, the 518k `find_head` bench, sync-lookup lifecycle assertions,
and the `fork_at_epoch` fixes are all *reactive, spot guards added post-incident*. They are good — but the
pattern means the *next* incident is in whichever class doesn't yet have its spot guard.

The leverage move is to flip three of these from spot-guard to **class-guard**, because the class-guards
are cheap and don't yet exist:
- **S3** turns "test this optimization" into "every optimization is differentially tested."
- **S2** turns "add the missing check on this path" into "verification is a single ingress-agnostic funnel."
- **S7** turns "fix this overflow" into "peer-input arithmetic cannot compile if it can panic."

Those three, plus the **crash-injection harness (S5)** that finally makes the one true architectural debt
(**S1**, cross-DB atomicity) measurable, are the highest-leverage structural work. Everything else in the
master report is already either guarded or a known instance.

---

*Current-code claims in this document were verified by direct inspection of the `unstable` tree
(file/line evidence retained in the audit working notes). Historical bug references trace to the
per-subsystem files in this directory.*
