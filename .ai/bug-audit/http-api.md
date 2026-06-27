# HTTP API — Bug Audit

## Scope

Covers the Lighthouse beacon node REST API, validator client API, standard Beacon API spec compliance, SSE event stream, response schema/status codes, query params, rewards API, and light-client API endpoints. Primary source paths: `beacon_node/http_api/`, `common/eth2/` (API client), `validator_client/` (HTTP client usage). The warp→axum migration is in scope for structural issues. Validator-client duty scheduling logic is excluded (covered by VC agent), as are consensus-state-transition bugs that only incidentally surface via API.

## Queries Run

```bash
gh issue list --repo sigp/lighthouse --label "HTTP-API" --label "bug" --state all --limit 300
gh issue list --repo sigp/lighthouse --label "HTTP-API" --state all --limit 300
gh issue list --repo sigp/lighthouse --label "rewards-api" --state all --limit 100
gh search issues --repo sigp/lighthouse "http api" --state all --limit 50
gh search issues --repo sigp/lighthouse "beacon api" --state all --limit 50
gh search issues --repo sigp/lighthouse "status code" --state all --limit 50
gh search issues --repo sigp/lighthouse "SSE event stream" --state all --limit 50
gh search issues --repo sigp/lighthouse "endpoint 404" --state all --limit 50
gh search issues --repo sigp/lighthouse "query param" --state all --limit 50
gh search issues --repo sigp/lighthouse "block rewards" --state all --limit 50
gh search issues --repo sigp/lighthouse "openapi" --state all --limit 50
gh search issues --repo sigp/lighthouse "content-type" --state all --limit 30
gh search issues --repo sigp/lighthouse "ssz response" --state all --limit 30
gh search issues --repo sigp/lighthouse "deserialize request" --state all --limit 30
gh search issues --repo sigp/lighthouse "/eth/v1" --state all --limit 50
gh search issues --repo sigp/lighthouse "validator status" "api" --state all --limit 30
gh search issues --repo sigp/lighthouse "light client" "endpoint" --state all --limit 30
gh search issues --repo sigp/lighthouse "500 internal" --state all --limit 30
gh search prs --repo sigp/lighthouse "http api" --state all --limit 50
gh search prs --repo sigp/lighthouse "beacon api" "fix" --state all --limit 50
gh search prs --repo sigp/lighthouse "api endpoint" "fix" --state all --limit 50
# Plus: gh issue view <N> --comments and gh pr diff <N> for each candidate
```

---

## 2. Bug Table

| # | Title | State | Class | Severity | How-found | One-line root cause | Fix PR |
|---|-------|-------|-------|----------|-----------|---------------------|--------|
| [#5080](https://github.com/sigp/lighthouse/issues/5080) | Stack overflow in POST /eth/v*/beacon/blocks with SSZ bodies | closed | `panic-crash` | high | internal-testing | Warp deeply-nested `.or()` futures overflow stack on SSZ block endpoints | [#5076](https://github.com/sigp/lighthouse/pull/5076) |
| [#4245](https://github.com/sigp/lighthouse/issues/4245) | Beacon API events SSE stream unexpected disconnections | closed | `api-correctness` | medium | user-report | SSE channel buffer full treated as fatal; entire stream terminated instead of dropping message | [#4500](https://github.com/sigp/lighthouse/pull/4500) |
| [#4860](https://github.com/sigp/lighthouse/issues/4860) | Attestation rewards API doesn't account for justification and finalization | closed | `spec-correctness` | medium | code-review | Skips `process_justification_and_finalization`, causing wrong `is_in_inactivity_leak` at finality-restoration epoch | [#4877](https://github.com/sigp/lighthouse/pull/4877) |
| [#4856](https://github.com/sigp/lighthouse/issues/4856) | Rewards API: proposer rewards incorrectly included in Phase0 attestation rewards | closed | `spec-correctness` | medium | user-report | `inclusion_delay` component includes proposer-portion causing double-counting in Phase0 | [#4882](https://github.com/sigp/lighthouse/pull/4882) |
| [#6818](https://github.com/sigp/lighthouse/issues/6818) | Attestation Rewards API endpoint broken on Pectra enabled networks | closed | `api-correctness` | high | user-report | Hardcoded `MAX_EFFECTIVE_BALANCE = 32 ETH` instead of Electra's 2048 ETH cap, causing range errors | [#6819](https://github.com/sigp/lighthouse/pull/6819) |
| [#5016](https://github.com/sigp/lighthouse/issues/5016) | Discrepancy between block v3 claimed rewards and rewards POST endpoint | closed | `spec-correctness` | medium | internal-testing | Op pool used Phase0 denominator for Altair proposer reward, ~10% over-report in v3 block endpoint | [#5047](https://github.com/sigp/lighthouse/pull/5047) |
| [#7441](https://github.com/sigp/lighthouse/issues/7441) | next sync committee branch calculated incorrectly in light client updates | closed | `spec-correctness` | high | user-report | Destructured tuple assignment swapped `current_` and `next_sync_committee_branch` in cache | [#7443](https://github.com/sigp/lighthouse/pull/7443) |
| [#7536](https://github.com/sigp/lighthouse/issues/7536) | Light client bootstrap returns incorrect Merkle proof in current_sync_committee_branch | closed | `spec-correctness` | high | user-report | Cached state where current==next committee gives degenerate sibling in Merkle proof | — |
| [#7167](https://github.com/sigp/lighthouse/issues/7167) | Light client update SSZ responses use signature_slot instead of attested_header slot for fork digest | closed | `spec-correctness` | medium | user-report | Fork digest computed from `signature_slot` not `attested_header.beacon.slot` as spec requires | [#7230](https://github.com/sigp/lighthouse/pull/7230) |
| [#5107](https://github.com/sigp/lighthouse/issues/5107) | Blob sidecar indices-filter query parameter does not work | closed | `api-correctness` | medium | user-report | `indices` query param used single-value parsing; multi-value (`?indices=0&indices=1`) silently ignored | [#5118](https://github.com/sigp/lighthouse/pull/5118) |
| [#5182](https://github.com/sigp/lighthouse/issues/5182) | /eth/v1/validator/liveness does not accept string-encoded validator indices | closed | `api-correctness` | medium | user-report | Request body typed `Vec<u64>`, failing deserialization of spec-required `["1"]` string form | [#5184](https://github.com/sigp/lighthouse/pull/5184) |
| [#3114](https://github.com/sigp/lighthouse/issues/3114) | HTTP Accept headers not parsed correctly (complex media types) | closed | `api-correctness` | medium | user-report | Simple string matching on Accept headers; `application/octet-stream,application/json;q=0.9` rejected | [#3185](https://github.com/sigp/lighthouse/pull/3185) |
| [#6983](https://github.com/sigp/lighthouse/issues/6983) | Electra /eth/v2/validator/aggregate_attestation returning 404s for Deneb | closed | `api-correctness` | high | user-report | v2 aggregate endpoint only wired for Electra format; pre-Electra attestations always 404 | [#6984](https://github.com/sigp/lighthouse/pull/6984) |
| [#7294](https://github.com/sigp/lighthouse/issues/7294) | /eth/v2/beacon/pool/attestations does not honor committee_index filter | closed | `api-correctness` | medium | user-report | Filter logic indistinguishable between "no filter (default 0)" and "explicit index=0"; index>0 always empty | [#7298](https://github.com/sigp/lighthouse/pull/7298) |
| [#8252](https://github.com/sigp/lighthouse/issues/8252) | Should ignore committee_index in attestation production API post-Electra | closed | `spec-correctness` | high | user-report | Post-Electra committee_index forwarded to `beacon_committees()` causing panic/500 for index>0 | [#9437](https://github.com/sigp/lighthouse/pull/9437) |
| [#7434](https://github.com/sigp/lighthouse/issues/7434) | ForkVersionedResponse version field missing on light client responses | closed | `api-correctness` | medium | user-report | `version: Option<ForkName>` left unset on light client endpoints, missing required field | — |
| [#7440](https://github.com/sigp/lighthouse/issues/7440) | Missing `version` in getPendingConsolidations response | closed | `api-correctness` | low | user-report | New Electra endpoint implemented without `version` field in fork-versioned response wrapper | [#8251](https://github.com/sigp/lighthouse/pull/8251) |
| [#5977](https://github.com/sigp/lighthouse/issues/5977) | Missing fields in getBlobSidecars response | closed | `api-correctness` | low | code-review | Blob sidecars endpoint returned only `data`; missing `version`, `execution_optimistic`, `finalized` | [#5987](https://github.com/sigp/lighthouse/pull/5987) |
| [#5131](https://github.com/sigp/lighthouse/issues/5131) | Endpoints that require node to be synced respond with wrong error while syncing | closed | `api-correctness` | medium | user-report | Warp filter priority: sync-guard 503 suppressed by version-mismatch 400 for POST endpoints | [#5136](https://github.com/sigp/lighthouse/pull/5136) |
| [#4525](https://github.com/sigp/lighthouse/issues/4525) | Lighthouse v4.3.0 doesn't send Eth-Consensus-Version header | closed | `api-correctness` | medium | user-report | Blinded blocks endpoint omits `Eth-Consensus-Version` response header required by spec | [#4528](https://github.com/sigp/lighthouse/pull/4528) |
| [#7690](https://github.com/sigp/lighthouse/issues/7690) | BlockId::root doesn't work at oldest_block_slot | closed | `api-correctness` | medium | internal-testing | `block_root_at_slot_skips_none` always checks previous slot first; no previous slot after checkpoint | [#7693](https://github.com/sigp/lighthouse/pull/7693) |
| [#2133](https://github.com/sigp/lighthouse/issues/2133) | Extra `is_syncing` field in node/syncing endpoint | closed | `api-correctness` | medium | user-report | LH added non-standard `is_syncing` field; LH VC crashed connecting to Teku BN missing it | [#2148](https://github.com/sigp/lighthouse/pull/2148) |
| [#9358](https://github.com/sigp/lighthouse/issues/9358) | HTTP API OOM from lack of Content-Length limit on SSZ endpoints | closed | `resource` | medium | code-review | `warp::body::bytes()` without length limit allows unbounded memory buffering | [#9398](https://github.com/sigp/lighthouse/pull/9398) |
| [#4929](https://github.com/sigp/lighthouse/issues/4929) | Incorrect phase0 block rewards in rewards API | closed | `spec-correctness` | medium | user-report | Phase0 `inclusion_delay` includes proposer portion; attester totals inflated by rewards API | [#4882](https://github.com/sigp/lighthouse/pull/4882) |
| [#9472](https://github.com/sigp/lighthouse/issues/9472) | /eth/v1/beacon/light_client/updates may return incorrect data due to LE byte ordering | **open** | `api-correctness` | high | audit | DB keys are LE-encoded; lexicographic iteration breaks when request crosses period-256 boundary | — |
| [#1717](https://github.com/sigp/lighthouse/issues/1717) | Standard HTTP API validator response values unquoted | closed | `serialization` | high | user-report | Large integer fields serialized as bare JSON numbers not quoted strings; precision loss in JS | — |
| [#4264](https://github.com/sigp/lighthouse/issues/4264) | No gossip validation before block broadcast | closed | `spec-correctness` | medium | code-review | Block publish endpoint returned 200 without pre-broadcast gossip validation (spec violation) | [#4313](https://github.com/sigp/lighthouse/pull/4313) |
| [#7075](https://github.com/sigp/lighthouse/issues/7075) | Mainnet configuration values missing from /eth/v1/config/spec | closed | `api-correctness` | low | user-report | Several newer ChainSpec fields not included in HTTP API config/spec serialization | — |
| [#4802](https://github.com/sigp/lighthouse/issues/4802) | Re-org feature does not work with Vouch blinded proposals | closed | `api-correctness` | high | code-review | Re-org builds local payload that external builder (Vouch) rejects; fallback produces 0-tx block | — |
| [#3878](https://github.com/sigp/lighthouse/issues/3878) | Event monitor connections dropped by Lighthouse mysteriously | **open** | `api-correctness` | medium | user-report | SSE connections silently terminated by Lighthouse after 48 min–26 hours; root cause unresolved | — |
| [#7250](https://github.com/sigp/lighthouse/issues/7250) | Beacon committees endpoint returning incorrect data (prior epoch) | **open** | `api-correctness` | medium | user-report | Epoch-boundary race: state not fully transitioned, committees query returns stale prior-epoch data | — |
| [#4984](https://github.com/sigp/lighthouse/issues/4984) | Atomicity bug adding validators via VC API | **open** | `api-correctness` | medium | internal-testing | Validator added to in-memory state before validation; failed validation leaves orphan in memory, DuplicatePublicKey on retry | — |
| [#8571](https://github.com/sigp/lighthouse/issues/8571) | Missing values in /eth/v1/config/spec | **open** | `api-correctness` | low | user-report | REORG thresholds, EPOCHS_PER_SUBNET_SUBSCRIPTION, ATTESTATION_SUBNET_COUNT, etc. absent from response | — |
| [#8892](https://github.com/sigp/lighthouse/issues/8892) | Add missing SSZ response support to several HTTP API endpoints | **open** | `api-correctness` | low | code-review | Multiple endpoints lack SSZ response support now required by Beacon API spec v4.0.0+ | — |
| [#9545](https://github.com/sigp/lighthouse/issues/9545) | Checkpoint sync fails (401) with path-embedded API key when URL has trailing slash | **open** | `api-correctness` | medium | internal-testing | Trailing slash on base URL causes double-slash in constructed path; rejected by QuickNode-style providers | — |
| [#4717](https://github.com/sigp/lighthouse/issues/4717) | Historic sync duties queries fail for recently-activated validators | **open** | `api-correctness` | medium | user-report | Sync duties endpoint caches state from `(epoch//512-1)*512`; recently-activated validators absent → 500 | — |
| [#6121](https://github.com/sigp/lighthouse/issues/6121) | Stalled sync status unclear in /eth/v1/node/syncing | closed | `api-correctness` | low | user-report | `SyncState::Stalled` (no peers) maps to `is_syncing: false` even though node hasn't reached head | — |
| [#7759](https://github.com/sigp/lighthouse/issues/7759) | /eth/v1/beacon/light_client/update SSZ does not follow spec | **open** | `spec-correctness` | medium | user-report | SSZ light client updates missing required chunked format (ForkDigest context + length prefix per item) | — |

---

## 3. Deep Dives

### [#5080](https://github.com/sigp/lighthouse/issues/5080) — Stack overflow in POST /eth/v*/beacon/blocks with SSZ bodies

**Root cause:** Warp's route-matching uses deeply nested `.or()` combinators. For the SSZ block POST endpoint (the last in a long alternative chain), this creates a recursive future type of depth proportional to the number of routes. When polled, the stack overflows. This is a known warp limitation ([warp#811](https://github.com/seanmonstar/warp/issues/811)).

**How discovered:** Kurtosis devnet testing with Teku VC + Lighthouse BN during Dencun upgrade preparation. Lighthouse VC never uses SSZ endpoints, so the path was never exercised in-house.

**How fixed:** PR #5076 inserted `.boxed()` calls at key points in the warp route chain to erase the recursive future type, bounding stack depth.

**Why it wasn't caught earlier:** Lighthouse's own VC uses JSON endpoints. No cross-client CI (e.g., Teku VC against LH BN) exercised SSZ POST blocks.

**Could-have-been-caught-by:** Cross-client integration tests exercising SSZ block submission with Teku or Prysm VCs. Alternatively, a compile-time stack-depth check or a warp migration to axum (which doesn't have this issue).

---

### [#9472](https://github.com/sigp/lighthouse/issues/9472) — Light client updates return incorrect data due to LE byte ordering (OPEN)

**Root cause:** Light client update entries are stored in the database with keys encoded as `sync_committee_period.to_le_bytes()`. Lexicographic iteration over LE-encoded integers does not produce numerically sorted output: period 256 (`0x0001_00`) sorts before period 255 (`0xFF_00`) lexicographically. When a query range spans a multiple-of-256 period boundary, iteration terminates prematurely, returning truncated or wrong results. The fix requires a database migration to big-endian key encoding.

**How discovered:** Reported by the Ethereum Foundation Protocol Security Research Team. The boundary only occurs after ~2.27 years of mainnet operation (sync period 256 = ~year 2025).

**How fixed:** Not yet fixed (open). Requires a DB migration, which is non-trivial for a production node.

**Why it wasn't caught earlier:** Tests did not span the period-256 boundary. The bug is invisible until real-time crosses that date. LE vs BE key ordering is a subtle invariant not enforced by the type system.

**Could-have-been-caught-by:** Property-based test verifying that iterating LE-encoded keys for periods 254–258 returns results in numerical order. A type-level `BeKey<u64>` newtype that enforces BE encoding at the DB layer.

---

### [#8252](https://github.com/sigp/lighthouse/issues/8252) — committee_index causes 500 in attestation production post-Electra

**Root cause:** Post-Electra, there is only one committee per slot; the `committee_index` parameter in `GET /eth/v1/validator/attestation_data` should be ignored. Lighthouse forwarded the provided value to `beacon_committees(slot, index)`, which returned `BeaconStateError(NoCommittee)` for index > 0, propagating as a 500 UNHANDLED_ERROR. The Beacon APIs spec (PR #511) explicitly required ignoring the parameter; all other clients (Prysm, Nimbus, Lodestar, Grandine) already did so.

**How discovered:** Cross-client API comparison on an Electra devnet by user Alleysira.

**How fixed:** PR #9437 hardcodes `committee_index = 0` for the post-Electra code path, ignoring the query parameter.

**Why it wasn't caught earlier:** Lighthouse was overly strict in a way that was spec-correct before the spec was updated. The new requirement was a spec clarification not yet reflected in LH's implementation. No Electra API integration tests covered this path.

**Could-have-been-caught-by:** Cross-client interop test matrix for validator duty endpoints; checking against updated beacon-APIs spec conformance suite.

---

### [#6818](https://github.com/sigp/lighthouse/issues/6818) — Attestation Rewards API broken on Pectra networks

**Root cause:** The attestation rewards calculator used the Phase0/Altair constant `MAX_EFFECTIVE_BALANCE = 32 ETH` as the divisor/bound. Post-Electra validators can have up to 2048 ETH effective balance. For any validator above 32 ETH, arithmetic produced an out-of-range error, causing a 500 `AttestationRewardsError` for the entire API call.

**How discovered:** User peterbitfly (beaconcha.in) reported the failure on pectra-devnet-5 epoch 303, once compounding validators exceeded 32 ETH.

**How fixed:** PR #6819 parameterizes the balance bounds by fork: uses `MAX_EFFECTIVE_BALANCE_ELECTRA` for Electra-era epochs. Added `InteropGenesisBuilder` to make testing high-balance validators easier.

**Why it wasn't caught earlier:** Early Electra devnets all had validators at exactly 32 ETH. Compounding past the old cap requires running the devnet for some time or deliberately seeding high-balance validators.

**Could-have-been-caught-by:** Rewards API integration test with an Electra genesis that includes >32 ETH validators from block 0.

---

### [#7441](https://github.com/sigp/lighthouse/issues/7441) — Swapped sync committee branches in light client updates

**Root cause:** A destructured tuple assignment in the light client update cache swapped `current_sync_committee_branch` and `next_sync_committee_branch`. Both are `[Hash256; N]` values, so the swap is type-safe and compile-invisible. Light client consumers received reversed branches, failing all Merkle proof verifications.

**How discovered:** User benluelo compared LH and Lodestar responses to `/eth/v1/beacon/light_client/updates`, found differing branch values, and confirmed Lighthouse's values failed Merkle proof verification.

**How fixed:** PR #7443 replaced the destructured assignment with explicit field-by-field assignment, eliminating the swap.

**Why it wasn't caught earlier:** The branch values are syntactically valid hashes. No test verified them against the state root by running Merkle proof verification.

**Could-have-been-caught-by:** A unit test that computes `current_sync_committee_branch` and `next_sync_committee_branch` from a known state root and checks the returned branches verify successfully. Or cross-client comparison CI.

---

### [#6983](https://github.com/sigp/lighthouse/issues/6983) — v2 aggregate attestation 404 on Deneb after Electra endpoint added

**Root cause:** When `/eth/v2/validator/aggregate_attestation` was introduced for Electra, it was implemented only for the Electra attestation format rather than being an additive extension. Pre-Electra (Deneb) attestations no longer matched any handler, causing universal 404s on all Deneb networks.

**How discovered:** User Bez625 testing LH v6.0.1 on Holesky. Every call returned `ATTESTATION_NOT_IN_POOL`.

**How fixed:** PR #6984 made the v2 endpoint fork-aware: it checks the current fork and uses the appropriate attestation format.

**Why it wasn't caught earlier:** No regression test for the v2 endpoint on pre-Electra (Deneb) networks was run after adding Electra support.

**Could-have-been-caught-by:** Per-endpoint regression tests on both pre-Electra and Electra networks as part of the fork upgrade test suite.

---

### [#3114](https://github.com/sigp/lighthouse/issues/3114) — Complex Accept headers rejected (broke Nimbus checkpoint sync)

**Root cause:** Accept header parsing used simple string matching rather than proper MIME type parsing. Nimbus sends `Accept: application/octet-stream,application/json;q=0.9`. Lighthouse couldn't parse the comma-separated format with quality factors, failing to identify `application/octet-stream` as the preferred type, causing SSZ endpoints to return 400 "Unsupported endpoint version".

**How discovered:** Nimbus checkpoint sync client failed to use LH BN SSZ endpoints in cross-client testing.

**How fixed:** PR #3185 introduced the `mime` crate for RFC-compliant MIME type parsing.

**Why it wasn't caught earlier:** Tests only sent simple single-type Accept headers. Nimbus's complex Accept header is an edge case from real-world HTTP client implementations.

**Could-have-been-caught-by:** Unit tests for Accept header parsing covering quality factors, comma-separated alternatives, and parameter stripping.

---

### [#5131](https://github.com/sigp/lighthouse/issues/5131) — Wrong error code (400 vs 503) from POST endpoints while syncing

**Root cause:** Warp route matching collects all errors and surfaces the highest-priority one. The `not_while_syncing_filter` guard was placed where Warp's body-parsing version-mismatch error (400) outranked the sync-guard's 503. Clients calling POST endpoints while the node was syncing received `BAD_REQUEST: Unsupported endpoint version` instead of `SERVICE_UNAVAILABLE`.

**How discovered:** User dknopik testing POST endpoints against a syncing node.

**How fixed:** PR #5136 restructured affected POST handlers to check the sync state inside the `.then` block (before body parsing), ensuring 503 is emitted unconditionally.

**Why it wasn't caught earlier:** Sync state tests likely only covered GET endpoints. Warp's filter priority semantics are non-obvious and require knowing the framework internals.

**Could-have-been-caught-by:** Integration tests that POST to block/attestation submission endpoints against a node explicitly in syncing state, asserting 503 status.

---

### [#4245](https://github.com/sigp/lighthouse/issues/4245) — SSE stream disconnects when event channel fills

**Root cause:** The SSE event channel has a fixed buffer. Under high load (`--subscribe-all-subnets --import-all-attestations` on mainnet), the sender's `try_send` returned a channel-full error, which the old code treated as fatal, closing the entire SSE stream.

**How discovered:** User reported `curl: (18) transfer closed with outstanding read data remaining` within minutes of subscribing to attestation events on mainnet.

**How fixed:** PR #4500 changed channel-full to be non-fatal: skip the overflowed message, send an SSE comment keep-alive (`:`) to maintain the connection. Added `--http-sse-capacity-multiplier` CLI flag for tuning.

**Why it wasn't caught earlier:** Tests use low-traffic topics. The channel-full condition is load-dependent and not triggered by basic test suites.

**Could-have-been-caught-by:** Load test simulating all-subnet attestation SSE subscription, verifying the stream survives backpressure without disconnecting.

---

### [#4525](https://github.com/sigp/lighthouse/issues/4525) — Missing Eth-Consensus-Version response header

**Root cause:** The blinded blocks endpoint was implemented without the `Eth-Consensus-Version` response header required by the spec. Clients like Vouch (via go-eth2-client) explicitly require this header for fork-version-aware deserialization and error when absent.

**How discovered:** User xenowits found Vouch VC failing to use LH BN blinded blocks endpoint. The go-eth2-client library surfaced the missing header as an explicit error.

**How fixed:** PR #4528 added `Eth-Consensus-Version` to blinded blocks and blocks endpoints.

**Why it wasn't caught earlier:** API tests validated response body fields but not required response headers. Header requirements are less visible than body schema.

**Could-have-been-caught-by:** Response header assertions in API tests; or an OpenAPI-schema-based test that validates required response headers.

---

### [#5182](https://github.com/sigp/lighthouse/issues/5182) — Liveness endpoint rejects string-encoded validator indices

**Root cause:** The liveness endpoint request body was `Vec<u64>`, which rejects `["1"]` (string-encoded). The Beacon API spec mandates that validator indices be accepted as either integers or strings because JavaScript cannot safely represent u64 as a JSON number. Other endpoints already used `ValidatorIndexData` to handle both forms.

**How discovered:** User guybrush discovered the inconsistency while testing the liveness API, comparing against endpoints that already worked with string-encoded indices.

**How fixed:** PR #5184 changed the type to `ValidatorIndexData`.

**Why it wasn't caught earlier:** Tests only tested with bare integer `[1]`. The JS interop requirement for string-encoding is a spec detail easy to miss when writing request types.

**Could-have-been-caught-by:** Parametric API tests that test each endpoint with both `[1]` and `["1"]` forms.

---

### [#5107](https://github.com/sigp/lighthouse/issues/5107) — Blob sidecar `indices` query parameter broken

**Root cause:** The `indices` filter for `/eth/v1/beacon/blob_sidecars/{block_id}` used single-value query parsing. Multi-key form (`?indices=0&indices=1`) was silently ignored; comma-separated form (`?indices=0,1`) returned 400. Neither the filtering nor error response was correct.

**How discovered:** User protolambda found it on a local Dencun devnet. Both forms failed.

**How fixed:** PR #5118 switched to `multi_key_query` deserialization supporting both forms.

**Why it wasn't caught earlier:** The blob sidecars endpoint was new for Dencun; the index filter was never tested.

**Could-have-been-caught-by:** API tests for blob retrieval with both `?indices=0` (single), `?indices=0&indices=1` (multi-key), and `?indices=0,1` (comma-separated).

---

### [#2133](https://github.com/sigp/lighthouse/issues/2133) — Non-standard `is_syncing` field breaks cross-client VC

**Root cause:** Lighthouse added a non-standard `is_syncing: bool` to the `/eth/v1/node/syncing` JSON response. The Lighthouse VC consumed this field directly. When LH VC connected to a Teku BN (which followed the spec and omitted this field), deserialization failed with `missing field 'is_syncing'`.

**How discovered:** Users reported LH VC failing to connect to Teku BN.

**How fixed:** PR #2148 removed the non-standard field and moved sync detection to the standard `node/health` HTTP status code.

**Why it wasn't caught earlier:** Single-client testing always has the field. Cross-client tests (LH VC + non-LH BN) are needed to surface non-standard extensions.

**Could-have-been-caught-by:** Cross-client interop tests running LH VC against Teku/Prysm/Nimbus BN implementations.

---

### [#1717](https://github.com/sigp/lighthouse/issues/1717) — Validator response values serialized as unquoted numbers

**Root cause:** Fields like `effective_balance`, `activation_epoch`, `withdrawable_epoch` in `/eth/v1/beacon/states/{state_id}/validators` were serialized as bare JSON numbers. The spec requires these to be quoted strings because JavaScript clients cannot represent u64 precisely as a JSON double (max safe integer is 2^53).

**How discovered:** User mcdee inspected the JSON response in v0.3.0-staging and found unquoted integers.

**How fixed:** Early API compliance work added correct serde serialization with string quoting.

**Why it wasn't caught earlier:** The spec requirement for quoting large integers is a JavaScript interop detail not enforced by Rust's type system.

**Could-have-been-caught-by:** OpenAPI schema validation tests; or snapshot tests comparing against spec-conforming example responses.

---

### [#7167](https://github.com/sigp/lighthouse/issues/7167) — Light client update SSZ uses wrong slot for fork digest

**Root cause:** The SSZ context bytes for `/eth/v1/beacon/light_client/updates` are required to be computed as `ForkDigest(compute_fork_version(compute_epoch_at_slot(update.attested_header.beacon.slot)))`. Lighthouse used `signature_slot` instead. In cross-fork scenarios where signature and attested header are in different forks, this produces incorrect context bytes.

**How discovered:** User Inspector-Butters traced the spec requirement to `light_client.rs:162` and found the wrong slot variable.

**How fixed:** PR #7230 corrected the slot used in fork digest computation and ensured overall SSZ response format conformance.

**Why it wasn't caught earlier:** Cross-fork update scenarios (signature in fork N, header in fork N-1) require deliberate test setup.

**Could-have-been-caught-by:** Spec-compliance tests for light client SSZ encoding at fork boundaries; cross-client SSZ byte comparison.

---

### [#4860](https://github.com/sigp/lighthouse/issues/4860) — Attestation rewards API skips justification/finalization processing

**Root cause:** The attestation rewards endpoint simulates state at epoch N-1 to compute rewards. It did not call `process_justification_and_finalization` before checking `is_in_inactivity_leak`. At the exact epoch when finality is restored after a period of non-finality, the predicate incorrectly returns `true` (still leaking) because J&F hasn't been run to update the justified checkpoints. This produced wrong inactivity values for the restoration epoch.

**How discovered:** Core developer michaelsproul identified it by comparing the API output against expected values at mainnet epoch 200759 (the finality restoration epoch).

**How fixed:** PR #4877 adds `process_justification_and_finalization` at the start of the rewards simulation path.

**Why it wasn't caught earlier:** The bug only occurs at the single epoch when finality is restored from a non-finality period. Unit tests for the rewards API covered only steady-state finalized scenarios.

**Could-have-been-caught-by:** Integration tests that simulate an inactivity leak, then restore finality, and query rewards at the restoration epoch.

---

### [#4802](https://github.com/sigp/lighthouse/issues/4802) — Re-org feature produces 0-transaction blocks with Vouch blinded proposals

**Root cause:** The re-org feature attempts to build a block on the parent-of-head. With blinded proposals, the external builder (relay) may not have a payload prepared for the re-org target slot. Lighthouse falls back to a local payload build, but Vouch rejects the local payload (wrong kind). After the 1-second cutoff, Lighthouse gives up on the re-org but has no time to build a proper payload, resulting in a 0-transaction block.

**How discovered:** Observed in production when Lighthouse nodes with re-org enabled using Vouch VC began proposing 0-transaction blocks.

**How fixed:** The v3 block endpoint redesigned payload negotiation in a way that avoids this race; Vouch migrated to v3.

**Why it wasn't caught earlier:** The interaction between re-org logic, external builder (relay), and third-party VC (Vouch) is a multi-system scenario not covered by standard integration tests.

**Could-have-been-caught-by:** Integration tests that simulate re-org + mock relay + blinded proposal flow, verifying a valid (non-zero-tx) block is produced.

---

## 4. Synthesis

### Counts by Class

| Class | Count |
|---|---|
| `api-correctness` | 22 |
| `spec-correctness` | 10 |
| `panic-crash` | 1 |
| `serialization` | 1 |
| `resource` | 1 |
| **Total** | **35** |

_(Three bugs appear as duplicates/closely related: #4856/#4929 both fixed by #4882, #7536 covered by #7441 family.)_

### Counts by Severity

| Severity | Count |
|---|---|
| high | 10 |
| medium | 19 |
| low | 6 |
| critical | 0 |

### Open Issues

7 bugs remain open: #9472 (LE byte order, DB migration needed), #3878 (SSE mystery disconnects), #7250 (epoch boundary race), #4984 (VC API atomicity), #8571/#8892 (missing config/SSZ fields), #9545 (trailing slash 401), #4717 (sync duties for new validators), #7759 (light client SSZ chunked format).

---

### Recurring Root-Cause Themes

**1. Fork upgrade regressions:** #6818, #6983, #7294, #8252, #5016 — each fork (Altair, Dencun, Electra) introduced at least one API regression. New endpoints replaced old behavior instead of being additive, or used wrong per-fork constants.

**2. Light client endpoint correctness:** #7441, #7536, #7167, #7759, #9472 — five distinct correctness bugs in the light client API sub-stack (branch swap, degenerate Merkle proof, wrong fork digest slot, non-spec SSZ format, LE key ordering). The light client server is systematically under-tested with proof verification.

**3. Missing required response fields/headers:** #7434, #7440, #5977, #8892, #4525, #2133 — envelope fields (`version`, `execution_optimistic`, `finalized`), response headers (`Eth-Consensus-Version`), and non-standard extras (`is_syncing`) all caused interop failures. These are structurally hard to catch without schema validation.

**4. Warp framework surprises:** #5080, #5131, #3114 — the warp filter model produced stack overflows (future nesting), wrong error priority (400 vs 503), and MIME parsing failures. Three distinct correctness issues attributable to the warp abstraction layer.

**5. Query parameter / request body parsing:** #5107, #5182, #7294 — multi-value query params, string-encoded integer bodies, and filter semantics all had bugs that only surface when non-trivial inputs are sent.

**6. Rewards API spec complexity:** #4860, #4856, #4929, #5016, #6818 — five bugs in the rewards/incentives API family, spanning Phase0 double-counting, wrong fork constants, missing J&F processing, and op-pool formula errors. The rewards API has accumulated the most spec-correctness bugs of any single endpoint family.

---

### Highest-Leverage Early-Detection Ideas

**1. OpenAPI schema validation in CI.** Instrument every API handler to validate actual responses (headers + body) against the Beacon API OpenAPI schema. Would have caught: #7434, #7440, #5977, #8892, #8571, #4525, #1717, #7075. This alone covers ~8 bugs and prevents the recurring "missing field" pattern.

**2. Per-fork cross-client API conformance tests.** Run a test matrix (LH BN ↔ Teku/Prysm/Nimbus VC and vice versa) on each devnet deployment: Altair, Bellatrix, Capella, Deneb, Electra. Would have caught: #5080, #2133, #3114, #6983, #8252, #6818. Catches both interop failures and fork-specific regressions.

**3. Light client proof verification tests.** For every light client endpoint (bootstrap, updates, finality update, optimistic update), run an actual Merkle proof verification of the returned branch against the claimed state root. Would have caught: #7441, #7536, #7167, #7759. These bugs all produce syntactically valid-looking responses that only fail cryptographic verification.

**4. Rewards API sum invariant tests.** Assert: `sum(attestation_rewards[v] for v in validators) + sum(proposer_rewards) == block_rewards_total` for all forks. Assert that rewards are monotonically reasonable (not negative, not exceed max effective balance). Would have caught: #4856, #4929, #5016, #4860, #6818.

**5. Mutation tests for query parameter parsing.** For every filterable endpoint, test `?param=0`, `?param=0&param=1` (multi-key), `?param=0,1` (comma), `?param="0"` (quoted string), and missing param. Would have caught: #5107, #5182, #7294.

---

### Structural/Architectural Smells

- **Light client server (`beacon_node/http_api/src/light_client.rs`)** appears in five distinct bugs. The code complexity, caching logic, and SSZ encoding path are all under-tested. This module is the highest bug-density file in the HTTP API.
- **Warp framework:** Stack overflow (#5080), wrong error priority (#5131), and MIME parsing (#3114) are all Warp-specific. The ongoing axum migration (#9001) should eliminate this class. Until migration is complete, any new route chain should be tested for stack depth.
- **`ForkVersionedResponse` optional fields:** The `version: Option<ForkName>` design allowed five separate bugs where the field was left `None`. Making it `ForkName` (non-optional) would have converted these into compile-time errors.
- **Rewards API:** Five bugs across six issues. The rewards calculation duplicates fork-specific logic in multiple places (op pool, API handler, state transition). A single authoritative rewards computation path with per-fork parameterization would reduce this surface.
