# Lighthouse Historical Bug Audit — Shared Schema & Method

**Goal of the overall project:** Categorize bugs Lighthouse (sigp/lighthouse, an Ethereum
consensus client in Rust) has hit over its lifetime, by (a) which part of the stack they came
from and (b) what *class* of bug they are — so we can put detection in place earlier and spot
structural problems. Your slice is one part of the stack.

## Environment
- `gh` CLI is authenticated. Repo is `sigp/lighthouse`.
- You have Bash, Read, Write. Do NOT modify the lighthouse repo. Only write to the output file you're given.

## Method — DO NOT BE LAZY
You must look at BOTH issues AND pull requests, and BOTH open AND closed. The richest signal is
in closed items and their conversations + the actual fix.

For each candidate bug:
1. Read the issue/PR body and the **conversation/comments** (use `--comments`).
2. **Follow the fix**: find the PR that closed the issue and look at what actually changed.
   - Timeline / closing PR: `gh api repos/sigp/lighthouse/issues/<N>/timeline --jq '.[] | select(.event=="closed" or .event=="cross-referenced") | {event, commit_id, source: .source.issue.number}'`
   - Or just search: `gh search prs --repo sigp/lighthouse "<keywords>" --state merged`
   - View the diff to understand root cause: `gh pr diff <N> --repo sigp/lighthouse` (skim; focus on the core change, not lockfiles).
3. Determine: what was the actual root cause, how was it discovered (user report on mainnet/testnet, fuzzing, code review, CI, internal testing, spec test), and how was it fixed.

### Useful query recipes
```
gh issue list --repo sigp/lighthouse --label "<LABEL>" --label bug --state all --limit 300 \
  --json number,title,state,labels,createdAt,closedAt,url
gh search issues --repo sigp/lighthouse "<keyword>" --state all --limit 100 \
  --json number,title,state,url
gh issue view <N> --repo sigp/lighthouse --comments
gh pr view <N>   --repo sigp/lighthouse --comments
gh pr diff <N>   --repo sigp/lighthouse
```
Component labels exist: consensus, Networking, database, HTTP-API, val-client, slasher, crypto,
"builder API", das, deneb, syncing, optimization, non-finality, security. Many bugs are NOT
component-labeled, so also keyword-search your subsystem's source paths and concepts.

## Depth budget
- Enumerate ALL bug-labeled items in your scope (could be 20–50). List every one in the table.
- Deep-dive the ~12–20 most impactful (consensus failure, crash, non-finality, stall, fund loss,
  DB corruption, security). For those fill every field.
- For trivial ones, a one-line table row with a best-effort class is fine.
- Prefer thoroughness over speed, but you must finish and write the file.

## Bug-class taxonomy (pick the best-fit primary class; note secondary if relevant)
- `spec-correctness` — wrong state transition / fork-choice / reward / spec-noncompliance
- `concurrency` — deadlock, race condition, lock-ordering, async-blocking
- `resource` — memory leak, unbounded growth, OOM, CPU oversubscription, disk
- `panic-crash` — unwrap/expect, index OOB, arithmetic overflow/underflow, assertion
- `persistence` — DB corruption, migration bug, pruning bug, schema, atomicity
- `protocol-networking` — gossip, req/resp, discovery, peer scoring/management, ENR
- `sync-logic` — range/backfill/lookup stalls, bad batch handling, finalized-chain handling
- `serialization` — SSZ, JSON, type/encoding mismatch, deserialization
- `api-correctness` — wrong/missing API response, status codes, schema mismatch
- `config-cli` — flag handling, defaults, migration of config
- `availability-da` — blobs / data-availability / KZG / PeerDAS custody
- `el-integration` — engine API, payload handling, fork-choice-updated, builder/MEV
- `perf-regression` — slowdown, latency, throughput regression
- `fork-upgrade` — bugs tied to a hard-fork transition / version upgrade boundary
- `logic-other` — anything else; describe it

## How-found taxonomy
`mainnet-incident`, `testnet-incident`, `user-report`, `internal-testing`, `code-review`,
`ci-test`, `spec-test`, `fuzzing`, `audit`, `static-analysis`, `unknown`

## Severity
`critical` (consensus split / non-finality / fund loss / crash-loop / DB loss),
`high` (degraded duties, missed attestations/proposals, partial outage),
`medium` (incorrect-but-recoverable, API wrongness), `low` (cosmetic, edge).

## OUTPUT — write to the given file path as Markdown with these sections:

### 1. Header
`# <Area> — Bug Audit` and a 2–3 sentence scope note + the queries you ran.

### 2. Bug table
A Markdown table, one row per bug:
`| # | Title | State | Class | Severity | How-found | One-line root cause | Fix PR |`
Link numbers as `[#1234](url)`.

### 3. Deep dives
For each impactful bug (~12–20): a short block with **Root cause**, **How discovered**,
**How fixed**, **Why it wasn't caught earlier**, and **Could-have-been-caught-by** (test type,
invariant, lint, fuzzing, monitoring, type-level guarantee, review checklist...).

### 4. Synthesis for this area
- Counts by class and by severity (a small table).
- Recurring root-cause themes specific to this subsystem.
- The 3–6 highest-leverage things that would have caught the most/worst bugs earlier.
- Any structural/architectural smell you noticed (e.g. a module that shows up repeatedly).

Be concrete and cite issue/PR numbers throughout.
