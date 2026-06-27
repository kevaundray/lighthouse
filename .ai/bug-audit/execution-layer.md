# Execution Layer Integration — Bug Audit

## Scope

Covers the EL integration stack in Lighthouse: Engine API (`forkchoiceUpdated` / `newPayload` / `getPayload`), execution payload handling, optimistic sync (EL side), Bellatrix/merge transition, Builder API / MEV-Boost / relay interaction, and the builder circuit-breaker / health checks. Primary source: `beacon_node/execution_layer/`, `beacon_node/builder_client/`, `beacon_node/beacon_chain/src/execution_payload.rs`.

Does **not** cover: consensus state-transition validity rules, blobs/KZG internals (except EL payload/blob bundle plumbing). Overlaps with consensus or networking layer are flagged inline.

## Queries Run

```bash
gh issue list --repo sigp/lighthouse --label "builder API" --label "bug" --state all --limit 300
gh issue list --repo sigp/lighthouse --label "builder API" --state all --limit 300
gh issue list --repo sigp/lighthouse --label "bellatrix" --state all --limit 300
gh issue list --repo sigp/lighthouse --label "bellatrix" --label "bug" --state all --limit 50
gh issue list --repo sigp/lighthouse --label "bug" --state all --limit 300   # filtered for EL keywords
gh issue list --repo sigp/lighthouse --state all --limit 500                 # keyword-filtered
gh pr list   --repo sigp/lighthouse --state merged --limit 1000              # keyword-filtered
gh pr list   --repo sigp/lighthouse --label "builder API" --state all
# Individual issue/PR reads + timeline/fix lookups for each candidate
gh issue view <N> --repo sigp/lighthouse --comments
gh api repos/sigp/lighthouse/issues/<N>/timeline --jq ...
gh pr diff <N> --repo sigp/lighthouse
```

---

## 2. Bug Table

| # | Title | State | Class | Severity | How-found | One-line root cause | Fix PR |
|---|-------|-------|-------|----------|-----------|---------------------|--------|
| [#3314](https://github.com/sigp/lighthouse/issues/3314) | `baseFeePerGas` field in ExecutionPayloadV1 is too permissive | CLOSED | serialization | high | testnet-incident (hive) | `baseFeePerGas` / `totalDifficulty` U256 fields accepted non-spec hex encoding (missing `0x`, leading zeros) | [#3321](https://github.com/sigp/lighthouse/pull/3321) |
| [#3316](https://github.com/sigp/lighthouse/issues/3316) | Transition payload production might fail if TTD block timestamp coincides with slot time | CLOSED | el-integration | high | testnet-incident (hive) | `forkchoiceUpdated` sent with `timestamp == terminal_block.timestamp`; EL rejects equal-timestamp payload attributes | [#3331](https://github.com/sigp/lighthouse/pull/3331) |
| [#3390](https://github.com/sigp/lighthouse/issues/3390) | Sync stuck on execution engine delayed restart | CLOSED | sync-logic | high | user-report | Range-sync chain wrongly blacklisted after EL downtime; forkchoice update sent only once on EL reconnect, which was a no-op; sync never progressed | [#3439](https://github.com/sigp/lighthouse/pull/3439) |
| [#3189](https://github.com/sigp/lighthouse/issues/3189) | Set `safe_block_hash` to the justified block hash | CLOSED | spec-correctness | medium | code-review | `safe_block_hash` was computed using a stale/wrong approach not matching the updated spec | [#3347](https://github.com/sigp/lighthouse/pull/3347) |
| [#3394](https://github.com/sigp/lighthouse/issues/3394) | Don't use a builder with an optimistic head | CLOSED | el-integration | high | code-review | Builder API was used even when the head was optimistically imported (EL not yet verified) — risk of using unverified payload as parent | [#3412](https://github.com/sigp/lighthouse/pull/3412) |
| [#3432](https://github.com/sigp/lighthouse/issues/3432) | Error in VC when fee recipient is only set in the BN | CLOSED | api-correctness | medium | user-report | VC logged an error about missing fee recipient even when BN flag covered it; UX issue not a correctness bug | closed via UX fix |
| [#3550](https://github.com/sigp/lighthouse/issues/3550) | Strict fee recipient fails all block proposals before TTD is reached | CLOSED | el-integration | high | code-review | Pre-merge blocks have `0x0` fee recipient; `--strict-fee-recipient` equality check fired on every pre-merge block proposal | fixed in v3.1.x |
| [#3556](https://github.com/sigp/lighthouse/issues/3556) | Finalized execution payloads not deleted from disk | CLOSED | resource | medium | code-review | Payload-separation PR omitted the pruning call in `migrate_database`; payloads accumulated unboundedly post-merge | [#3565](https://github.com/sigp/lighthouse/pull/3565) |
| [#3176](https://github.com/sigp/lighthouse/issues/3176) | Don't mark EL as offline if non-essential API call fails | CLOSED | el-integration | high | testnet-incident | `getBlockByHash` failures (ethereumjs compat) caused EL to be marked offline, halting all forkchoice/newPayload calls | [#3324](https://github.com/sigp/lighthouse/pull/3324) |
| [#4473](https://github.com/sigp/lighthouse/issues/4473) | Spurious `Error whilst producing block` when using block relays | CLOSED | api-correctness | medium | user-report | Relay pre-publishes block to gossip; Lighthouse's gossip-validity duplicate-block check returned 400 causing false VC error | [#4655](https://github.com/sigp/lighthouse/pull/4655) |
| [#4802](https://github.com/sigp/lighthouse/issues/4802) | Re-org feature does not work with Vouch blinded proposals | CLOSED | el-integration | high | user-report (mainnet) | Late-block re-org suppressed payload attributes; Vouch rejected re-org payload; Geth had no time to build payload, returned 0-tx block | closed after v3 endpoint (#4629) |
| [#5405](https://github.com/sigp/lighthouse/issues/5405) | POST to `eth/v1/builder/blinded_blocks` missing header | CLOSED | api-correctness | medium | user-report | Missing `Eth-Consensus-Version` header on builder `submitBlindedBlock` call; spec non-compliance | [#5407](https://github.com/sigp/lighthouse/pull/5407) |
| [#6937](https://github.com/sigp/lighthouse/issues/6937) / [#7050](https://github.com/sigp/lighthouse/pull/7050) | `totalDifficulty` field removed from reth broke EL reconnect | CLOSED | serialization | high | testnet-incident | `ExecutionBlock::total_difficulty` was non-optional; reth 1.14.11 removed the field; `forkchoiceUpdated` called during proposer prep hit deserialization error | [#7050](https://github.com/sigp/lighthouse/pull/7050) |
| [#7277](https://github.com/sigp/lighthouse/issues/7277) | Fix deserialization of Electra JSON responses from builders | CLOSED | serialization | high | code-review | `ForkVersionDeserialize` used `serde_json::from_value` without fork hint; `ExecutionPayloadAndBlobs` deserialized as wrong variant (Deneb instead of Electra) | [#7285](https://github.com/sigp/lighthouse/pull/7285) |
| [#6971](https://github.com/sigp/lighthouse/issues/6971) | Plumbing for execution requests from `BuilderBid`s missing | CLOSED | el-integration | high | code-review | Electra `execution_requests` from builder bids were not plumbed through to payload construction; builder proposals on Electra missing EL requests | [#7500](https://github.com/sigp/lighthouse/pull/7500) via pre-v7.0.0 work |
| [#7000](https://github.com/sigp/lighthouse/issues/7000) / [#7009](https://github.com/sigp/lighthouse/pull/7009) | SSZ builder: Accept header set to wrong value | CLOSED | api-correctness | medium | testnet-incident | SSZ builder path sent wrong `Accept` header; SSZ content not negotiated correctly | [#7009](https://github.com/sigp/lighthouse/pull/7009) |
| [#8224](https://github.com/sigp/lighthouse/issues/8224) | `getHeader` fails to deserialize JSON responses | CLOSED | serialization | high | user-report | `BuilderHttpClient::get_builder_header` parsed `SignedBuilderBid` directly from body; real body is a `ForkVersionedResponse` wrapper; JSON path was never tested (default is SSZ) | [#8228](https://github.com/sigp/lighthouse/pull/8228) |
| [#8957](https://github.com/sigp/lighthouse/issues/8957) / [#9102](https://github.com/sigp/lighthouse/pull/9102) | Gloas: `get_expected_withdrawals`/fcU interaction incorrect for Full/Empty blocks | CLOSED | el-integration | high | code-review | `get_expected_withdrawals` blind to block `Full`/`Empty` payload status; fcU cache not invalidated when payload status changed; wrong withdrawals in payload attributes | [#9102](https://github.com/sigp/lighthouse/pull/9102) |
| [#9167](https://github.com/sigp/lighthouse/issues/9167) | Gloas genesis: `head_block_hash=0x00` sent to EL | CLOSED | el-integration | high | testnet-incident | At Gloas genesis, block's bid block hash was `0x0`; fcU sent with zero head hash; EL couldn't find genesis block | fixed in subsequent Gloas prep work |
| [#9173](https://github.com/sigp/lighthouse/pull/9173) | Builder exit signature batch verification logic wrong | CLOSED | spec-correctness | high | code-review (EF tests) | Batch vs individual sig verification used separate code paths; batch path had a logic bug; only individual path was covered by EF tests | [#9173](https://github.com/sigp/lighthouse/pull/9173) |
| [#9191](https://github.com/sigp/lighthouse/pull/9191) | Spurious re-org logs on ePBS payload status changes | CLOSED | logic-other | medium | code-review | `after_new_head` fired on every payload status transition (Empty→Full) even with unchanged head root; false reorg SSE events emitted | [#9191](https://github.com/sigp/lighthouse/pull/9191) |
| [#9225](https://github.com/sigp/lighthouse/pull/9225) | `payload_attestation_data` returns 400 for no-block slot | CLOSED | api-correctness | medium | user-report | Endpoint returned 400 (error) when no block seen for slot; spec says validators should simply skip; VC logged CRIT | [#9225](https://github.com/sigp/lighthouse/pull/9225) |
| [#9226](https://github.com/sigp/lighthouse/pull/9226) | Execution payload envelope not imported locally on HTTP API publish | CLOSED | el-integration | high | code-review | Proposer published payload envelope to network but never imported it locally; proposer voted its own payload as missing | [#9226](https://github.com/sigp/lighthouse/pull/9226) |
| [#9231](https://github.com/sigp/lighthouse/pull/9231) | PTC votes produced locally not submitted to local op pool | CLOSED | logic-other | high | code-review | Proposer's own PTC votes were broadcast but never added to local op pool; blocks built by the proposer omitted their own PTC votes | [#9231](https://github.com/sigp/lighthouse/pull/9231) |
| [#9305](https://github.com/sigp/lighthouse/pull/9305) | Non-canonical payload attestation processing always used head | CLOSED | el-integration | high | code-review / spec-test | Payload attestation verification always fetched PTC from head state; non-canonical chain verification was incorrect | [#9305](https://github.com/sigp/lighthouse/pull/9305) |
| [#9364](https://github.com/sigp/lighthouse/pull/9364) | Bogus `InvalidBestNode` sanity check prevents node startup | CLOSED | el-integration / fork-upgrade | critical | testnet-incident | Overly strict sanity check in `find_head` failed when all subtree nodes were ineligible (e.g. Gloas PENDING heads); node couldn't start | [#9364](https://github.com/sigp/lighthouse/pull/9364) |
| [#9544](https://github.com/sigp/lighthouse/issues/9544) | GLOAS PENDING head causes proposer to miss slot | OPEN | el-integration | critical | testnet-incident | Extended non-finality returns justified checkpoint as head with `PayloadStatus::Pending`; block production path rejects Pending status and returns 400; all scheduled proposers miss slot | open |
| [#8528](https://github.com/sigp/lighthouse/pull/8528) | Wrong `Fork` used in `verify_header_signature` at fork boundary | CLOSED | fork-upgrade | high | testnet-incident (Fusaka mainnet) | `verify_header_signature` used head state's fork; at a fork boundary head state fork is stale; signature verification failed for transition blocks | [#8528](https://github.com/sigp/lighthouse/pull/8528) |
| [#3355](https://github.com/sigp/lighthouse/issues/3355) / [#3356](https://github.com/sigp/lighthouse/pull/3356) | No circuit-breaker before using builder API | CLOSED | el-integration | high | code-review | No checks on chain health before using builder; if network was degraded (skipped slots) builder use could hurt the chain | [#3356](https://github.com/sigp/lighthouse/pull/3356) |

---

## 3. Deep Dives

### Bug 1 — `baseFeePerGas` / U256 QUANTITY encoding too permissive (#3314, fixed #3321)

**Root cause:** The Engine API spec requires all `QUANTITY` fields (including `baseFeePerGas` and `terminal_total_difficulty`) to be hex-encoded big-endian without leading zeros and with a `0x` prefix. Lighthouse's serde deserialization simply called `U256::from_str` without validating the format, so malformed or spoofed values were silently accepted into the payload.

**How discovered:** hive simulation (`eth2/engine` suite) with `marioevz/hive` branch that injected malformed hex strings.

**How fixed:** Added a new `u256_hex_be` serde module that enforces the exact QUANTITY encoding spec (must start with `0x`, no leading zeros except `"0x0"`). Applied the module to `base_fee_per_gas` in both `JsonExecutionPayloadV1` and `JsonExecutionPayloadHeaderV1`, and to `terminal_total_difficulty`.

**Why it wasn't caught earlier:** There were no spec-compliance serialization tests for these numeric fields; the default `U256` serde was used without reviewing the EL spec encoding rules.

**Could-have-been-caught-by:** A property-based (quickcheck/proptest) round-trip test checking that the QUANTITY encoding rejects leading zeros and missing prefixes. Or a dedicated hive conformance suite running before release.

---

### Bug 2 — Transition payload timestamp equal to terminal block timestamp (#3316, fixed #3331)

**Root cause:** When the terminal PoW block was mined exactly at a slot boundary, its `timestamp` equaled the slot's timestamp. Lighthouse constructed `payloadAttributes` with `timestamp = terminal_block.timestamp` (same value). The EL rejected the attributes with "invalid timestamp: parent X given X." The probability was 1/12 on mainnet.

**How discovered:** hive `equal-timestamp-terminal-transition-block` test by @marioevz.

**How fixed:** Changed `get_terminal_pow_block_hash` to accept and propagate the proposal slot's computed timestamp, and verified the timestamp is strictly greater than the terminal block's.

**Why it wasn't caught earlier:** The existing merge unit tests used a fixed, pre-set terminal block whose timestamp never coincided with a slot boundary. No fuzz/randomized harness tested the full space of terminal timestamps.

**Could-have-been-caught-by:** A targeted test that constructs a terminal block with `timestamp == slot_timestamp` and asserts a valid payload is still produced; hive integration tests (which did catch it).

---

### Bug 3 — Sync stuck on EL delayed restart (#3390, fixed #3439)

**Root cause:** When the EL went offline for several hours and came back, Lighthouse had accumulated batch download failures during the outage. The sync algorithm didn't properly distinguish "batch failed because EL was offline (not the peer's fault)" from "batch failed because the peer is bad." Result: chains were wrongly blacklisted. When the EL came back, Lighthouse issued a single `forkchoiceUpdated` to a block the EL already knew, which was a no-op. The sync state machine stalled indefinitely.

**How discovered:** User report from @karalabe testing Sepolia — node required a full restart to recover.

**How fixed:** PR #3439 added logic to avoid blacklisting a chain when batch failures are attributable to a local EL issue, not the remote peer. Also fixed a missing return in batch-failure reporting.

**Why it wasn't caught earlier:** The failure mode required an unusually long EL downtime; most tests simulated brief outages. The race between sync recovering and EL reconnection was not modeled.

**Could-have-been-caught-by:** Integration test that simulates EL downtime of several hours (slot-equivalent) and verifies sync resumes without a restart; monitoring alert for "sync stalled with EL online."

---

### Bug 4 — Using builder with an optimistic head (#3394, fixed #3412)

**Root cause:** The builder API path did not check whether the current head was in an optimistic state (EL payload not yet verified). Using an unverified block as the parent for a builder request could have caused the proposer to build on a chain that the EL might later mark as INVALID.

**How discovered:** Code review during Bellatrix preparation.

**How fixed:** Added an `is_optimistic` check inside `is_healthy` for the builder API selection. If the head is optimistic, the builder path is skipped.

**Why it wasn't caught earlier:** Safety properties around optimistic sync and builder interaction were complex and new; there was no checklist coupling these two features.

**Could-have-been-caught-by:** A test that puts the head into optimistic mode and verifies builder proposals are rejected. Or a formal safety requirement matrix for builder API prerequisites.

---

### Bug 5 — Strict fee recipient fails all block proposals before TTD (#3550)

**Root cause:** `--strict-fee-recipient` compared the block's `fee_recipient` field against the configured value. Before the TTD transition, all execution payloads are the default zero payload with `fee_recipient = 0x0000...`. The check fired every proposal pre-merge, causing proposal failures.

**How discovered:** Code review by @michaelsproul.

**How fixed:** Check was guarded to skip when the payload is the default (empty) payload.

**Why it wasn't caught earlier:** Flag was added during Bellatrix development without testing the pre-merge path; the feature was rarely tested end-to-end pre-merge.

**Could-have-been-caught-by:** An integration test that runs `--strict-fee-recipient` on a pre-merge chain and asserts proposals succeed.

---

### Bug 6 — Finalized execution payloads not deleted from disk (#3556, fixed #3565)

**Root cause:** When execution payloads were separated from beacon states (PR #3157), the code path in `migrate_database` that should have deleted finalized payloads was missing. Payloads accumulated on disk post-merge indefinitely.

**How discovered:** Code review audit of the payload-separation PR by @michaelsproul.

**How fixed:** PR #3565 added two pruning paths: (1) on each finalization migration, delete payloads between old and new split points; (2) a one-shot startup scan via `try_prune_execution_payloads` for users upgrading from a version without the fix.

**Why it wasn't caught earlier:** The PR that introduced payload separation didn't include a storage-growth test. The bug only became visible after accumulating blocks post-merge (weeks-scale).

**Could-have-been-caught-by:** A unit/integration test asserting that finalized payloads are absent from the DB after enough finalization epochs. Or a disk-size regression test.

---

### Bug 7 — EL wrongly marked offline on non-essential API failure (#3176, fixed #3324)

**Root cause:** When non-critical calls (e.g. `eth_getBlockByHash` for payload reconstruction) failed (e.g. due to ethereumjs incompatibility), Lighthouse's multi-engine abstraction propagated the error and marked the EL as offline. This halted all `forkchoiceUpdated` and `notifyNewPayload` calls, stalling both the EL and CL.

**How discovered:** Testnet incompatibility with ethereumjs during merge shadow fork testing.

**How fixed:** PR #3324 removed the `broadcast`/`first_success` multi-engine machinery (now single EL) and stopped using the cached `EngineState` to gate requests — every request is tried immediately regardless of cached state.

**Why it wasn't caught earlier:** The multi-engine abstraction was designed for multiple ELs and carried over complexity that didn't translate cleanly to the single-EL post-merge world.

**Could-have-been-caught-by:** A test that injects a failing `getBlockByHash` while the EL is otherwise healthy, and verifies `forkchoiceUpdated` is still called.

---

### Bug 8 — Builder relay duplicate-block 400 causing VC error (#4473, fixed #4655)

**Root cause:** In v4.3.0, Lighthouse added proper gossip-validity checks before publishing, which included rejecting duplicate blocks (400 `BlockIsAlreadyKnown`). Builder relays publish blocks _before_ returning them to the proposer, so when the proposer called the publish endpoint, Lighthouse saw the block as a known duplicate and returned 400. The VC logged `ERRO Error whilst producing block` even though the block was actually on-chain. Additionally, HTTP error body was lost in the forwarding path (#3404), obscuring the real error.

**How discovered:** User report after v4.3.0 deployment.

**How fixed:** PR #4655 changed duplicate-block HTTP response to 202 (published but not validated), with a flag `--http-duplicate-block-status` for users needing strict control. VC updated to treat 202 as success.

**Why it wasn't caught earlier:** The interaction between the new gossip-validity gating (v4.3.0 feature) and the builder relay publish-before-return pattern was not anticipated in the feature design.

**Could-have-been-caught-by:** Integration test simulating the relay flow (relay pre-publishes, then calls the BN endpoint); or explicit design review of the interaction before shipping the gossip-validity feature.

---

### Bug 9 — Re-org feature breaks Vouch blinded proposals (#4802)

**Root cause:** When Lighthouse tried a late-block re-org, it suppressed payload attributes to Geth. Vouch (an external VC) expected a specific payload that it had already selected; Lighthouse's re-org payload was built on a different parent. Vouch rejected the blinded re-org payload and requested a full block. At that point, Lighthouse sent payload attributes to Geth too late (< 1s before slot), and Geth returned an almost-empty payload (0 transactions). Net effect: proposer built a 0-tx block.

**How discovered:** Observed in the wild on mainnet; reported by @michaelsproul.

**How fixed:** The issue resolved itself once the v3 block production endpoint (PR #4629) was supported by both sides, as it no longer requires Vouch to accept a specific pre-negotiated payload.

**Why it wasn't caught earlier:** The re-org feature was built and tested with Lighthouse's own VC in mind; external VC interaction (especially Vouch's stricter payload-matching) was not modeled.

**Could-have-been-caught-by:** A test harness that simulates an external VC that rejects unexpected payload headers; or a design review note that the re-org feature must be compatible with arbitrary external VCs.

---

### Bug 10 — Missing `Eth-Consensus-Version` header on `submitBlindedBlock` (#5405, fixed #5407)

**Root cause:** Lighthouse's `BuilderHttpClient::post_with_raw_response` did not add the `Eth-Consensus-Version` header when calling `eth/v1/builder/blinded_blocks`. The spec requires this header so the relay can parse the fork-specific block type correctly.

**How discovered:** External user report from @mcdee; confirmed by reading the builder spec.

**How fixed:** PR #5407 adds a `HeaderMap` parameter to `post_with_raw_response`, populated with the `Eth-Consensus-Version` value derived from `fork_name_unchecked()` of the blinded block.

**Why it wasn't caught earlier:** The mock builder in tests didn't validate the `Eth-Consensus-Version` header; some relays were permissive. Only strictly compliant relays or middleware (like Vouch) surfaced the issue.

**Could-have-been-caught-by:** Mock builder test that asserts the presence and correct value of `Eth-Consensus-Version`. A builder spec conformance suite would catch this class of missing-header bugs.

---

### Bug 11 — `totalDifficulty` removed from reth breaks fcU proposer prep (#6937 / #7050)

**Root cause:** `ExecutionBlock::total_difficulty` was a non-optional `Uint256`. Reth v1.14.11 removed the `totalDifficulty` field from JSON RPC responses (post-merge it's meaningless). When `update_execution_engine_forkchoice` called `get_block_by_hash` during proposer preparation, deserialization of the missing field panicked/errored, causing the entire `forkchoiceUpdated` call to fail intermittently (only when the proposer lookahead window aligned).

**How discovered:** User report from builder-playground testing with reth 1.2.0; CI failures with latest geth; @ryanschneider traced the root cause.

**How fixed:** PR #7050 makes `total_difficulty` an `Option<Uint256>` and treats `None` as "post-merge."

**Why it wasn't caught earlier:** The field had always been present in older EL clients; Lighthouse's CI used pinned older geth versions; the failure was intermittent based on timing.

**Could-have-been-caught-by:** Integration tests using latest (unpinned) EL client versions; schema-evolution testing that checks optional/removed fields; CI running against reth as well as geth.

---

### Bug 12 — Electra builder response deserialized as wrong fork (#7277, fixed #7285)

**Root cause:** `ForkVersionDeserialize` for `ExecutionPayloadAndBlobs` called `serde_json::from_value(value)` without passing the fork name context. The plain Deserialize impl would pick the first matching variant (Deneb), producing a type mismatch when the builder returned an Electra payload. The JSON path was the fallback when SSZ wasn't available.

**How discovered:** Code review by @michaelsproul ahead of Electra release.

**How fixed:** PR #7285 implements a proper `ForkVersionDeserialize` for `ExecutionPayloadAndBlobs` that deserializes each field with fork-awareness, and adds round-trip tests for each fork.

**Why it wasn't caught earlier:** The default path (SSZ) worked correctly. The JSON path was dead code in practice (mev-boost uses SSZ by default) and had no dedicated tests.

**Could-have-been-caught-by:** A unit test that exercises the JSON deserialization path for each fork (Deneb, Electra) and asserts the correct variant is produced. The fix includes exactly such tests.

---

### Bug 13 — `getHeader` JSON path completely broken for non-SSZ builders (#8224, fixed #8228)

**Root cause:** `BuilderHttpClient::get_builder_header` attempted to deserialize `SignedBuilderBid` directly from the response body. The actual response format is `ForkVersionedResponse<SignedBuilderBid>` — a wrapper with a `version` field and a `data` field. The code looked for `message` at the top level, while it was nested under `data`. Because mev-boost defaults to SSZ, this JSON path was never exercised.

**How discovered:** User report from a Lighthouse+Vouch user (Vouch uses JSON, not SSZ).

**How fixed:** PR #8228 changes the deserialization to use `serde_json::from_slice::<ForkVersionedResponse>`, which properly unwraps the version/data envelope. A comprehensive mock-server test suite was added covering SSZ, JSON, and no-version-header fallback cases.

**Why it wasn't caught earlier:** The entire builder JSON path was untested — no mocked server tests existed. The assumption was that all builders speak SSZ.

**Could-have-been-caught-by:** A mock-server integration test with JSON content type (the fix adds exactly this); or a CI job that runs against a Vouch-style JSON-only relay.

---

### Bug 14 — Gloas: Wrong withdrawals in payload attributes due to Full/Empty blindness (#8957, fixed #9102)

**Root cause:** In the Gloas/ePBS fork, blocks are divided into "Full" (execution payload present) and "Empty" (payload envelope only, no execution). `get_expected_withdrawals` was called without knowing the head block's `PayloadStatus`, so it always computed withdrawals as if the head was Full. Also, the proposer cache (`ProposerKey`) didn't include `PayloadStatus`, so when a block transitioned from Empty to Full (after envelope import), the cache wasn't invalidated and no new `forkchoiceUpdated` was sent.

**How discovered:** Code review by @michaelsproul and @pawanjay176 during Gloas devnet preparation.

**How fixed:** PR #9102 adds `PayloadStatus` to `ProposerKey` (causing cache miss on status change → new fcU), and propagates the bid block hash to compute the correct `parent_payload_status` when preparing payload attributes.

**Why it wasn't caught earlier:** The Gloas spec was new and the withdrawal-computation interaction with Full/Empty payload status was a newly introduced invariant not yet covered by tests.

**Could-have-been-caught-by:** Gloas spec tests that exercise the withdrawal list for Empty-head followed by Full-head; property: "expected_withdrawals must be consistent with head payload status."

---

### Bug 15 — `InvalidBestNode` panics prevent node startup on Gloas devnets (#9364)

**Root cause:** `find_head` had an overly strict sanity check `InvalidBestNode` that asserted the returned head must match the expected head. Under extreme non-finality (or after Gloas PENDING payload status propagation), all subtree nodes could be ineligible, causing `find_head` to return the justified checkpoint. This triggered the `InvalidBestNode` assertion and prevented nodes from loading fork choice from disk at startup.

**How discovered:** Glamsterdam devnet-5 — multiple Lighthouse nodes failed to start with `CRIT: Unable to load fork choice from disk`.

**How fixed:** PR #9364 completely removes the `InvalidBestNode` failure path. The spec's `get_head` always returns _something_; returning the justified checkpoint is correct behavior in this case.

**Why it wasn't caught earlier:** The check was inherited from before Gloas and worked fine on pre-Gloas networks. Gloas introduced new reachable states (PENDING payload status) that violated its assumptions.

**Could-have-been-caught-by:** A regression test that populates fork choice under extreme non-finality with PENDING nodes and verifies a node can restart; running Gloas spec fork-choice tests.

---

### Bug 16 — GLOAS PENDING head causes proposer to miss slot (#9544, OPEN)

**Root cause:** Under extended non-finality, `find_head` returns the justified checkpoint with `PayloadStatus::Pending`. This cached status propagates to the block production path as `parent_payload_status`. `should_build_on_full` returns `Err(InvalidPayloadStatus)` for Pending, causing the HTTP block production endpoint to return 400. Every proposer scheduled during this window misses its slot.

**How discovered:** Glamsterdam devnet-6 testing; deep analysis by @gitToki.

**How fixed:** Not yet fixed (open issue). Suggested fix: skip viable-node filtering for PENDING nodes in `find_head_walk` so the virtual EMPTY children are always returned.

**Why it wasn't caught earlier:** New Gloas invariant where PENDING can legitimately be the head under non-finality; not covered by existing devnet-scale tests.

**Could-have-been-caught-by:** A devnet-scale test that induces extended non-finality and verifies proposers still produce (or gracefully skip) slots.

---

### Bug 17 — Wrong `Fork` in `verify_header_signature` at Fusaka boundary (#8528)

**Root cause:** `verify_header_signature` computed the `Fork` from the head state's fork field. At a fork boundary, the head state's fork is stale (it holds the pre-fork fork data). Blocks at the transition slot use the new fork's signing domain. The signature verification failed for all transition blocks, blocking import via the normal path. Nodes recovered only via sync (different code path).

**How discovered:** Observed at Fusaka mainnet fork transition; @eserilev quickly diagnosed it.

**How fixed:** PR #8528 uses `ChainSpec::fork_at_epoch(slot.epoch())` to compute the `Fork` instead of the head state's fork field, ensuring correctness at fork boundaries.

**Why it wasn't caught earlier:** `verify_header_signature` was previously only on the slasher path; it entered the critical blob/column verification path for the first time with Fulu. The function's head-state-fork assumption was latent.

**Could-have-been-caught-by:** A regression test that exercises `verify_header_signature` at a fork transition slot (the fix includes one). More broadly: a policy that all functions referencing head state fork are audited when entering a new code path.

---

### Bug 18 — Execution payload envelope not imported locally after HTTP API publish (#9226)

**Root cause:** When a proposer submitted a payload envelope via the HTTP API, Lighthouse published it to the network peers but did not import it locally. The proposer subsequently voted that it had seen no payload for its own block, degrading its own attestation effectiveness.

**How discovered:** Code review during Gloas development.

**How fixed:** PR #9226 adds gossip verification and local import of the payload envelope on HTTP API publication.

**Why it wasn't caught earlier:** The publish-only-to-network behavior was correct pre-Gloas; local import of an _envelope_ (separate from the block itself) was a new Gloas invariant not previously required.

**Could-have-been-caught-by:** A test that publishes a payload via HTTP API and asserts the proposer's own PTC vote matches the published payload.

---

### Bug 19 — PTC votes not submitted to local op pool (#9231)

**Root cause:** When a validator produced a PTC (payload-timeliness committee) vote, it was broadcast to the network but not inserted into the local beacon node's PTC op pool. When that same node was the block proposer, its own PTC votes were absent from the aggregated set, reducing the vote count in produced blocks.

**How discovered:** Code review during Gloas devnet work.

**How fixed:** PR #9231 adds the locally-produced PTC vote to the local op pool alongside the network broadcast.

**Why it wasn't caught earlier:** Attestation committee votes follow the same pattern (gossip + local op pool insert), but the PTC path was implemented from scratch and this step was omitted.

**Could-have-been-caught-by:** A test that produces PTC votes and checks the local op pool contains them before block production.

---

### Bug 20 — Builder exit signature batch verification wrong (#9173)

**Root cause:** Batch builder exit signature verification used a different code path from individual verification. The batch path had incorrect aggregation/message binding logic. EF spec tests only exercised the individual path.

**How discovered:** Code review; not caught by EF tests because they only call individual verification.

**How fixed:** PR #9173 unifies batch and individual verification code paths.

**Why it wasn't caught earlier:** Two independent implementations of "the same" verification; EF tests only cover one path.

**Could-have-been-caught-by:** A unit test that runs both individual and batch verification on the same set of exits and compares results; explicitly testing the batch path with EF test vectors.

---

## 4. Synthesis

### 4.1 Counts by Class and Severity

| Class | Count |
|-------|-------|
| `el-integration` | 12 |
| `serialization` | 4 |
| `api-correctness` | 4 |
| `logic-other` | 2 |
| `spec-correctness` | 2 |
| `resource` | 1 |
| `sync-logic` | 1 |
| `fork-upgrade` | 1 |

| Severity | Count |
|----------|-------|
| critical | 2 |
| high | 15 |
| medium | 6 |
| low | 0 |

### 4.2 Recurring Root-Cause Themes

1. **Fork-unaware deserialization of EL/builder JSON responses.** Three separate bugs (#3314, #7277, #8224) stem from the same pattern: serde deserialization of multi-fork types without propagating the fork name. The JSON path is implicitly trusted to deserialize the right variant, but there is no fork hint. The SSZ path (which uses a tag byte or builder `fork_name` header) is usually correct. The JSON path is a latent bug magnet.

2. **Dead code paths never exercised in tests.** #8224 (JSON builder path), #7277 (JSON for Electra), and the batch vs individual sig path (#9173) are all cases where an alternate code path existed but had zero test coverage because the default (SSZ, individual) worked. Bugs in alternate paths survived indefinitely.

3. **New Gloas/ePBS invariants introduced but not plumbed through existing code.** Four bugs (#8957, #9102, #9167, #9226, #9231, #9544) all trace to the same root: the Gloas fork introduced new state (Full/Empty payload status, payload envelopes, PTC op pool) that existing code paths (withdrawals, proposer cache, op pool, head walk) were not updated to handle. The codebase had "TODO(gloas): …" markers that turned into devnet bugs.

4. **External client API spec drift.** Two bugs (#3314, #7050) arose because EL clients (geth, reth) silently changed their JSON encoding (removed `totalDifficulty`, changed QUANTITY format). Lighthouse's deserialization was strict in some places and too loose in others, with no contract tests against real client outputs.

5. **Builder API under-specified and under-tested.** The builder API has the highest bug density in this area (8+ bugs). The JSON vs SSZ content negotiation, missing headers, wrong fork-version deserialization, and missing execution-requests plumbing are all builder-specific. The builder test fixtures use SSZ by default, leaving the JSON path dangerously untested.

6. **Interaction between features not modeled at design time.** The re-org / Vouch blinded proposal incompatibility (#4802), the duplicate-block / relay pre-publish clash (#4473), and the builder-with-optimistic-head risk (#3394) all result from two features interacting in a way neither considered the other's behavior.

### 4.3 Highest-Leverage Detection Ideas

1. **Mock-server tests for _every_ builder API content type on _every_ fork.** The JSON path for `getHeader`, `submitBlindedBlock`, and `getPayload` needs mock-server round-trip tests for Bellatrix/Capella/Deneb/Electra/Fulu using JSON (not SSZ). PR #8228 established the pattern; it should be systematically applied. This would have caught #8224, #7277, #5405, and #7009.

2. **Rotate CI execution client (geth + reth + nethermind).** Pinning to old geth versions hid #7050 until a user hit it in production. Running CI integration tests against the latest stable of at least two different EL clients catches EL API changes (removed fields, encoding changes) before they reach mainnet.

3. **Invariant test for "no alternate code path without tests."** For any `match fork_name { ... }` arm or `if ssz ... else json ...` branch in builder/EL serialization code, require a test exercising that arm. A static lint or review checklist item: "alternate content-type/fork-name branch covered?" This directly addresses the dead-path problem.

4. **Gloas/ePBS integration test harness covering all new state transitions.** A structured test suite that exercises: Full→Empty→Full head transitions and withdrawal list consistency; proposer-misses-slot under non-finality with PENDING status; local PTC vote included in proposer's own block; payload-envelope locally imported after HTTP publish. The Glamsterdam devnet bugs (#9102, #9167, #9226, #9231, #9544, #9364) are a cluster that could have been caught earlier with a dedicated Gloas protocol test harness.

5. **Review checklist for `fork_at_epoch` vs head-state fork.** `verify_header_signature` (#8528) is the second case (after attestation domain selection) where "use the slot's epoch, not the head state's fork" is required. A code-review item: "any function that computes a Fork or signing domain should use `ChainSpec::fork_at_epoch`, not `head_state.fork()`" would prevent this class of fork-upgrade bugs recurring.

### 4.4 Structural / Architectural Observations

- **`beacon_node/builder_client/src/lib.rs`** is the module with the highest bug density: #8224, #7277, #7009, #5405 all live there. It handles JSON/SSZ content negotiation, fork-versioned response parsing, and header construction. The lack of a mock-server test infrastructure until PR #8228 left this module's alternate paths dark.

- **The builder JSON path is essentially a secondary implementation** that diverges from SSZ at almost every step and is exercised only when SSZ negotiation fails (rare in production). Consider making the JSON path a first-class citizen with the same test coverage as SSZ, or eliminating it and requiring all builders to support SSZ.

- **Gloas (ePBS) integration** shows a pattern where a single new concept (Full/Empty payload status) must be threaded through many independent call sites (withdrawal calculation, proposer cache key, op pool submission, local import, fork-choice head walk). Each missed site becomes a devnet bug. A more systematic approach — e.g., a "Gloas invariant audit" checklist that lists every site that must be aware of payload status — would reduce this scatter.

- **The `find_head` / `InvalidBestNode` saga** (#9364) shows that over-asserting internal consistency under adversarial or degenerate network conditions is harmful. The fix (removing the assertion entirely) is the right call; but the lesson is: internal sanity checks in fork-choice that prevent startup should be extremely conservative or replaced with metrics/warnings.
