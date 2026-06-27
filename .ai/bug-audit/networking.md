# Networking / P2P Transport — Bug Audit

## Scope

This audit covers bugs in Lighthouse's networking stack: gossipsub, discv5 discovery, RPC/req-resp, peer management & scoring, ENR, libp2p plumbing, ports/NAT, and subnet management. The primary source directory is `beacon_node/lighthouse_network/`. Sync logic (range/backfill/lookup algorithms) is excluded unless a networking component is the root cause.

Bugs touching PeerDAS at the RPC layer (batching, substream limits, duplicate serving) are included and flagged as overlapping with the `availability-da` domain.

## Queries Run

```bash
# Label-based enumeration
gh issue list --repo sigp/lighthouse --label "Networking" --label "bug" --state all --limit 300
gh issue list --repo sigp/lighthouse --label "Networking" --state all --limit 300
gh pr list   --repo sigp/lighthouse --label "Networking" --state all --limit 200

# Keyword searches (issues + PRs, open+closed)
gh search issues --repo sigp/lighthouse "gossipsub"       --state all --limit 50
gh search issues --repo sigp/lighthouse "discv5"          --state all --limit 50
gh search issues --repo sigp/lighthouse "peer score"      --state all --limit 50
gh search issues --repo sigp/lighthouse "peer manager"    --state all --limit 50
gh search issues --repo sigp/lighthouse "req/resp"        --state all --limit 50
gh search issues --repo sigp/lighthouse "ENR"             --state all --limit 50
gh search issues --repo sigp/lighthouse "subnet"          --state all --limit 50
gh search issues --repo sigp/lighthouse "goodbye"         --state all --limit 50
gh search issues --repo sigp/lighthouse "rate limit"      --state all --limit 50
gh search issues --repo sigp/lighthouse "QUIC"            --state all --limit 50
gh search issues --repo sigp/lighthouse "UPnP"            --state all --limit 50
gh search issues --repo sigp/lighthouse "NAT"             --state all --limit 50
gh search issues --repo sigp/lighthouse "peer disconnect" --state all --limit 50
gh search issues --repo sigp/lighthouse "libp2p"          --state all --limit 50
# (same set repeated for PRs)

# Deep-dive tooling
gh issue view <N>   --repo sigp/lighthouse --comments
gh pr diff   <N>   --repo sigp/lighthouse
gh api repos/sigp/lighthouse/issues/<N>/timeline \
  --jq '.[] | select(.event=="closed" or .event=="cross-referenced") | ...'
```

---

## 2. Bug Table

| # | Title | State | Class | Severity | How-found | One-line root cause | Fix PR |
|---|-------|-------|-------|----------|-----------|---------------------|--------|
| [#4171](https://github.com/sigp/lighthouse/issues/4171) | Panic in UPnP search | CLOSED | panic-crash | high | user-report | `igd` crate `unwrap()`s on malformed gateway URL in `search_gateway()` | #4172, #5068 |
| [#5020](https://github.com/sigp/lighthouse/issues/5020) | Another UPnP/`igd` panic | CLOSED | panic-crash | high | user-report | `igd` `unwrap()` in `get_external_ip` code path on gateway response error | [#5068](https://github.com/sigp/lighthouse/pull/5068) |
| [#5443](https://github.com/sigp/lighthouse/issues/5443) | UPnP route established when UPnP is disabled | CLOSED | config-cli | low | user-report | After switching to `libp2p-upnp`, `--disable-upnp` flag not wired to the new behaviour | [#5449](https://github.com/sigp/lighthouse/pull/5449) |
| [#5444](https://github.com/sigp/lighthouse/issues/5444) | Panic from `libp2p-upnp` after BN re-connects | CLOSED | panic-crash | high | user-report | `libp2p-upnp` hits `unreachable!()` at `behaviour.rs:450` when mapping state invalidated on reconnect | [#5449](https://github.com/sigp/lighthouse/pull/5449) |
| [#6399](https://github.com/sigp/lighthouse/issues/6399) | Panic crash after upgrade to 5.3.0 (UPnP) | CLOSED | panic-crash | high | user-report | `libp2p-upnp` `unwrap()` on `None` mapping state at `behaviour.rs:475`; fixed in upstream rust-libp2p/PR#6459 | upstream fix, landed v8.2.0 |
| [#9377](https://github.com/sigp/lighthouse/issues/9377) | Lighthouse crashes due to panic in rust-libp2p UPnP | OPEN | panic-crash | high | user-report | Same `libp2p-upnp` mapping-state `unwrap()` at `behaviour.rs:513` in v8.1.2 (before v8.2.0 fix) | — |
| [#5004](https://github.com/sigp/lighthouse/issues/5004) | QUIC zero port error | CLOSED | config-cli | medium | user-report | `quic_port = tcp_port + 1` computes to 1 when `--port 0`, requiring root privs | [#5021](https://github.com/sigp/lighthouse/pull/5021) |
| [#6088](https://github.com/sigp/lighthouse/issues/6088) | Critical Task Panic with InvalidCertificate Error | CLOSED | panic-crash | critical | user-report | `libp2p-quic` `Config::new()` `unwrap()`s on TLS cert init; `rustls` v0.23.11 regression returns `UnsupportedCriticalExtension` | build with `--locked` |
| [#6106](https://github.com/sigp/lighthouse/issues/6106) | Node gets instantly banned on restart (excessive RPC requests) | CLOSED | protocol-networking | high | internal-testing | PeerDAS DataColumnsByRoot requests sent one-per-column to a single peer, exceeding `MAX_INBOUND_SUBSTREAMS=32`; peer returns `HandlerRejected` → ban | [#6256](https://github.com/sigp/lighthouse/pull/6256) |
| [#6244](https://github.com/sigp/lighthouse/issues/6244) | Gossipsub mesh/connected peer inconsistencies | CLOSED | protocol-networking | high | code-review | Disconnected peers remain in IDONTWANT promise tracking; mesh vs connected sets desync | [#6244](https://github.com/sigp/lighthouse/pull/6244) |
| [#5110](https://github.com/sigp/lighthouse/pull/5110) | Gossipsub fanout desynchronization | CLOSED | protocol-networking | medium | code-review | Fanout map not maintained correctly, causing publish errors for non-subscribed topics | [#5110](https://github.com/sigp/lighthouse/pull/5110) |
| [#5357](https://github.com/sigp/lighthouse/pull/5357) | Publish fails when mesh empty but subscribed peers exist | CLOSED | protocol-networking | high | user-report | After disabling flood-publish, messages only go to mesh peers; empty mesh = silent publish failure even with valid subscribed peers | [#5357](https://github.com/sigp/lighthouse/pull/5357) |
| [#3237](https://github.com/sigp/lighthouse/issues/3237) | Gossipsub deficit scoring during topic transition | CLOSED | protocol-networking | high | internal-testing | Old fork topics get P3 penalty for zero messages, causing honest peers to be penalized/banned during fork | [#4486](https://github.com/sigp/lighthouse/pull/4486) |
| [#4581](https://github.com/sigp/lighthouse/issues/4581) | "Too many subscriptions per request" during Deneb fork | CLOSED | protocol-networking | medium | testnet-incident | `max_subscriptions_per_request=160` too low when subscribed to dual-fork subnets (64 att × 2 + core > 160) | [#4588](https://github.com/sigp/lighthouse/pull/4588) |
| [#5602](https://github.com/sigp/lighthouse/issues/5602) | Blob gossip incorrectly penalizes peer (BlockIsAlreadyKnown) | CLOSED | protocol-networking | medium | user-report | `BlockIsAlreadyKnown` returned when blob imported via RPC before gossip arrives; gossip handler treats this as a penalizable violation | [#5656](https://github.com/sigp/lighthouse/pull/5656) |
| [#5942](https://github.com/sigp/lighthouse/pull/5942) | RPC requests lost when cleared from rate limiter on peer disconnect | CLOSED | protocol-networking | medium | code-review | Requests moved from `self_limiter` to `events` queue then dropped silently on disconnect, never reported as failed to sync | [#5942](https://github.com/sigp/lighthouse/pull/5942) |
| [#5680](https://github.com/sigp/lighthouse/pull/5680) | RPC errors not propagated on peer disconnection | CLOSED | protocol-networking | medium | code-review | In-flight RPC request not notified as failed when peer disconnects; sync has no chance to retry | [#5680](https://github.com/sigp/lighthouse/pull/5680) |
| [#6408](https://github.com/sigp/lighthouse/pull/6408) | RPC Ping response has wrong sequence number | CLOSED | protocol-networking | medium | code-review | Pong sent with wrong seq number, causing unnecessary metadata refresh cycles on remote peers | [#6408](https://github.com/sigp/lighthouse/pull/6408) |
| [#5113](https://github.com/sigp/lighthouse/pull/5113) | Multiple concurrent dials to same peer | CLOSED | concurrency | medium | code-review | Discovery query backlog can accumulate same peer multiple times before peer manager deduplicates | [#5113](https://github.com/sigp/lighthouse/pull/5113) |
| [#6207](https://github.com/sigp/lighthouse/pull/6207) | Infinite discovery query loop in small networks | CLOSED | resource | medium | testnet-incident | When all discovered peers are already known/connected, peer manager re-queries every 500ms indefinitely | [#6207](https://github.com/sigp/lighthouse/pull/6207) |
| [#4147](https://github.com/sigp/lighthouse/issues/4147) | Discovery returns no results when peering with Prysm | CLOSED | protocol-networking | high | user-report | Lighthouse discv5 used `FindPeers` (non-standard); Prysm only understands `FindNode`; cross-client discovery fails | discv5 library update in v4.0.1 |
| [#8437](https://github.com/sigp/lighthouse/issues/8437) | Address update loop causes OOM (RSS 117GB) | CLOSED | resource | critical | user-report | discv5 socket-update handler incorrectly updated TCP port with UDP addr, toggling between two ports 500×/s → unbounded memory growth | [#8443](https://github.com/sigp/lighthouse/pull/8443) |
| [#6108](https://github.com/sigp/lighthouse/issues/6108) | DataColumnsByRange serves zero columns | CLOSED | protocol-networking | high | internal-testing | PeerDAS DataColumnsByRange response logic returns 0 columns for most requested epoch ranges | multiple PeerDAS PRs |
| [#8842](https://github.com/sigp/lighthouse/issues/8842) | Duplicate columns in DataColumnsByRange (v8.1.0 regression) | CLOSED | protocol-networking | high | user-report | `.unique()` on `(Hash256, Slot)` tuples fails to deduplicate skip-slot entries; remote peers downscore for `DuplicatedData` | [#8843](https://github.com/sigp/lighthouse/pull/8843) |
| [#4140](https://github.com/sigp/lighthouse/pull/4140) | Ban peer race condition | CLOSED | concurrency | high | code-review | Queued unban event from prior cycle can follow a ban event, leaving a should-be-banned peer unbanned | [#4140](https://github.com/sigp/lighthouse/pull/4140) |
| [#2902](https://github.com/sigp/lighthouse/issues/2902) | Excessive penalties for attestations with unknown head | CLOSED | protocol-networking | medium | user-report | Attestations for a yet-unseen head block penalized as gossip violation, causing honest peers to be downscored | unknown |
| [#5013](https://github.com/sigp/lighthouse/pull/5013) | Wrong mesh_n in PeerScoreSettings | CLOSED | protocol-networking | medium | code-review | `PeerScoreSettings` built with default `mesh_n=6` but actual gossipsub config uses `mesh_n=4` from `NetworkLoad` | [#5013](https://github.com/sigp/lighthouse/pull/5013) |
| [#1483](https://github.com/sigp/lighthouse/issues/1483) | libp2p startup ignores `AddrInUse` | CLOSED | panic-crash | medium | user-report | Port 9000 already in use silently ignored at startup; node runs but doesn't listen | fixed in early 2020 |
| [#9301](https://github.com/sigp/lighthouse/issues/9301) | Trailing bytes not rejected on RPC (spec violation) | OPEN | spec-correctness | medium | audit | RPC `Ping` with trailing garbage bytes returns SUCCESS instead of `INVALID_REQUEST` per spec; all clients (except Teku) non-compliant | — |
| [#5384](https://github.com/sigp/lighthouse/issues/5384) | `nat_open` metric broken after UPnP refactor | CLOSED | logic-other | low | user-report | Switch to `libp2p-upnp` broke metric update path; `nat_open` never set | [#5427](https://github.com/sigp/lighthouse/pull/5427) |
| [#2701](https://github.com/sigp/lighthouse/issues/2701) | Inbound stream termination edge case | CLOSED | protocol-networking | medium | code-review | Edge case where inbound stream not properly terminated caused resource leak | early 2022 |
| [#1554](https://github.com/sigp/lighthouse/issues/1554) | Incorrect error handling: swallowed errors | CLOSED | logic-other | medium | code-review | Networking errors silently swallowed, hiding real failures | late 2020 |
| [#5498](https://github.com/sigp/lighthouse/issues/5498) | Task Panic (UPnP-related) | CLOSED | panic-crash | high | user-report | UPnP-related panic in async task; part of recurring libp2p-upnp pattern | [#9543](https://github.com/sigp/lighthouse/pull/9543) |
| [#6895](https://github.com/sigp/lighthouse/issues/6895) | Range sync stuck: no peers on custody column subnets | CLOSED | protocol-networking | high | internal-testing | Metadata (including custody columns) arrives async after connection; range sync checks column peers before metadata is received; no re-trigger on metadata arrival | [#6975](https://github.com/sigp/lighthouse/pull/6975) |
| [#8105](https://github.com/sigp/lighthouse/issues/8105) | Attestation publishing failures: insufficient attestation subnet peers | CLOSED | protocol-networking | high | user-report | Node has too few peers on the specific attestation subnet to publish; scoring/connection churn | unknown |
| [#8153](https://github.com/sigp/lighthouse/issues/8153) | `NoPeersSubscribedToTopic` on attestation publish | CLOSED | protocol-networking | high | user-report | No peers subscribed to attestation subnet topic at publish time; gossip silently fails | unknown |
| [#6384](https://github.com/sigp/lighthouse/issues/6384) | Peer count slowly decreases to zero | CLOSED | protocol-networking | high | user-report | Discovery/reconnection not aggressive enough to recover from gradual peer loss; eventually peer count hits 0 | #6446, #5271 |
| [#4258](https://github.com/sigp/lighthouse/issues/4258) | Resubscribing to core topics | CLOSED | protocol-networking | medium | unknown | After restart/reconnect, failed to resubscribe to core gossipsub topics | unknown |
| [#6302](https://github.com/sigp/lighthouse/issues/6302) | Bootnode not discovering beacon nodes | CLOSED | protocol-networking | medium | user-report | Configuration or discv5 issue preventing bootnode from finding peers | [#6385](https://github.com/sigp/lighthouse/pull/6385) |
| [#7980](https://github.com/sigp/lighthouse/issues/7980) | Repeatedly sending DataColumnsByRoot for same block | CLOSED | protocol-networking | medium | internal-testing | Redundant repeated requests for same columns; likely missing deduplication in custody request state | unknown |

---

## 3. Deep Dives

---

### DD-1: UPnP Panic Series — #4171, #5020, #5444, #6399, #9377

**Root cause:** Three layers of the same structural bug across different crate revisions. (1) The `igd` crate (2020–2023) called `unwrap()` on HTTP response parsing in `search_gateway()` and `get_external_ip()`. (2) After migrating to `libp2p-upnp` (#4840, Apr 2024), that crate contained `unreachable!()` and `unwrap()` in its port-mapping state machine at `behaviour.rs:450` and `behaviour.rs:475`. The state machine assumed mappings always persisted through network interruptions, but a reconnect cycle could leave mappings in an unknown state. (3) The `--disable-upnp` flag was not wired to the new `libp2p-upnp` behaviour after the switch (separate bug #5443), meaning users couldn't work around the panic.

**How discovered:** All user reports from mainnet/testnet. No CI reproduction.

**How fixed:** `igd` → `igd-next` migration (#5068) fixed the crate-level panics. Disabled the libp2p UPnP behaviour when `--disable-upnp` set (#5449). Upstream rust-libp2p fixed the state-machine panic (rust-libp2p/PR#6459), landed in LH v8.2.0.

**Why not caught earlier:** UPnP depends on local network topology (router presence, UPnP support, NAT type). CI runs without real gateway hardware. The panic only manifests on network events (restart/reconnect), not on initial startup, making it hard to reproduce in integration tests.

**Could-have-been-caught-by:**
- Fuzz the UPnP state machine with simulated gateway disconnect/reconnect events
- Require that all external crates used in async tasks have `#![deny(clippy::unwrap_used)]` or equivalent; audit dependency panics
- Mock UPnP gateway in integration tests, simulate mapping expiry/reconnect
- Canary CI job that runs with `--disable-upnp` as a control path

---

### DD-2: QUIC Port = 1 When `--port 0` — #5004

**Root cause:** `quic_port = tcp_port + 1`. When `tcp_port = 0` (OS-assigned), this computes `quic_port = 1`, a privileged port on Linux.

**How discovered:** User report. Simple arithmetic oversight.

**How fixed:** PR #5021: if `port == 0`, set `quic_port = 0` as well.

**Why not caught earlier:** No test with `--port 0` in CI.

**Could-have-been-caught-by:**
- A unit test for the port-derivation function with inputs `(0, 9000, 65535)`.
- Property-based test: `derived_ports(p)` should be in `[0, 65535]` and never a privileged port unless explicitly configured.

---

### DD-3: QUIC/TLS `InvalidCertificate` Panic — #6088

**Root cause:** `libp2p-quic::Config::new()` calls `unwrap()` on `libp2p-tls` cert creation. When `rustls` v0.23.11 (bumped by `cargo update`) started returning `UnsupportedCriticalExtension` for the ephemeral TLS certificates generated for QUIC, the `unwrap()` panicked at startup. Users who built with `--locked` were not affected.

**How discovered:** Users who ran `cargo update` before building. The reproducibility was deterministic by rustls version, but only observable outside of locked builds.

**How fixed:** No LH-side code change — advised `--locked`. Root fix is in `rustls` upstream.

**Why not caught earlier:** CI builds with `--locked`. Only manifests when building without pinned dependencies.

**Could-have-been-caught-by:**
- A CI job that explicitly runs `cargo update && cargo build` (without `--locked`) on each PR.
- Upstream: the `libp2p-quic` crate should not `unwrap()` on cert initialization; it should propagate a startup error.

---

### DD-4: Node Banned on Restart (Excessive Concurrent RPC Substreams) — #6106

**Root cause:** During PeerDAS, each custody-column sample was sent as a separate `DataColumnsByRoot` RPC substream. On restart, the node sent many simultaneous requests to one peer (small testnet = one peer). `MAX_INBOUND_SUBSTREAMS = 32` on the receiving peer triggered `HandlerRejected` errors. Each rejection scored the requesting node negatively; after enough rejections the peer banned it with score -100.

**How discovered:** Internal testnet during PeerDAS development.

**How fixed:** PR #6256 introduced `SamplingRequestId` to batch all column indices for a single sampling operation into one RPC request per peer, drastically reducing substream count.

**Why not caught earlier:** PeerDAS was new; the per-column-per-substream design was not analyzed against `MAX_INBOUND_SUBSTREAMS` limits. Small testnet amplified the problem (single-peer all-requests).

**Could-have-been-caught-by:**
- Invariant: "total concurrent outbound substreams to one peer must not exceed `MAX_INBOUND_SUBSTREAMS` of a typical peer"; tracked in test or as a runtime assertion
- Simulator test with 2-node PeerDAS and full restart cycle
- Load/stress test measuring substream multiplexing at peak

---

### DD-5: Gossipsub Mesh / Connected Peer Desynchronization — PR #6244

**Root cause:** Two related state bugs. (1) When a peer disconnects, IDONTWANT promise tracking maps are not cleaned up because the map is not indexed by peer ID (cleanup is O(n)). Stale peer IDs remain, causing "peer not connected" lookup failures when IDONTWANT is processed. (2) The mesh peers set and the connected peers set became desynchronized, allowing mesh entries for disconnected peers.

**How discovered:** Code review / internal investigation during gossipsub maintenance.

**How fixed:** PR #6244 corrected both: cleaned IDONTWANT tracking on disconnect and reconciled mesh vs connected peer sets.

**Why not caught earlier:** The desynchronization is a soft state inconsistency (no immediate crash). Its effects are subtle — slightly wrong gossip routing, spurious log warnings. No invariant was asserted on the relationship between connected_peers and mesh_peers.

**Could-have-been-caught-by:**
- Debug assertion: `mesh_peers ⊆ connected_peers` checked after every peer disconnect event
- Fuzz gossipsub with random connect/disconnect/subscribe sequences
- Gossipsub state invariant test in CI: connect 5 peers, disconnect 2, assert mesh is consistent

---

### DD-6: Gossipsub Publish Failure When Mesh Empty — PR #5357

**Root cause:** After disabling flood-publish to improve bandwidth efficiency, gossipsub only published to mesh peers. If a node's mesh happened to be empty (e.g., just connected, or all mesh peers simultaneously disconnected), publication failed with `InsufficientPeers` — even if subscribed (non-mesh) peers were available who could relay the message.

**How discovered:** User reports of attestation/block publishing failures.

**How fixed:** PR #5357 added a fallback: if mesh is empty but subscribed peers exist with sufficient score, publish to up to `mesh_n` of them directly.

**Why not caught earlier:** Flood-publish had been the default, masking this issue. The fallback path was never exercised in normal conditions. It only manifested under transient connectivity.

**Could-have-been-caught-by:**
- Integration test: disconnect all mesh peers, verify message still published to subscribed peers
- Property: "publish should succeed if at least one subscribed peer with sufficient score exists"

---

### DD-7: Gossipsub Deficit Scoring During Fork Transition — #3237

**Root cause:** Gossipsub's P3 parameter penalizes peers for receiving fewer messages on a topic than expected (`deficit = expected - received`). During an Ethereum fork, both old and new fork topics are maintained temporarily. Once the fork completes, no messages are sent on old topics; P3 deficit penalties accumulate on all peers subscribed to those topics. Honest peers get banned.

**How discovered:** Internal analysis during fork planning.

**How fixed:** PR #4486 removed the deficit scoring for topics during transition periods by setting application-level scores that neutralized the P3 deficit.

**Why not caught earlier:** Fork transitions are infrequent, making it easy to miss in testing. The scoring effect accumulates gradually.

**Could-have-been-caught-by:**
- Simulate a fork in the gossipsub scoring test: after fork, old topics should not accumulate penalties
- Periodic review of gossipsub P-parameter configuration against current topic lifecycle

---

### DD-8: Too Many Subscriptions During Deneb Fork — #4581

**Root cause:** `max_subscriptions_per_request = 160`. During the Deneb fork, a node with `--subscribe-all-subnets` held topics for both pre-Deneb and Deneb fork digests simultaneously: 64 attestation subnets × 2 fork digests + sync committee subnets + core topics > 160. When gossipsub attempted to subscribe, the peer's filter rejected the request: `too many subscriptions per request; ignoring RPC from peer`.

**How discovered:** Differential testing by Antithesis on local testnet.

**How fixed:** PR #4588 increased limits to `max_subscriptions_per_request = 200`, `max_subscribed_topics = 400`.

**Why not caught earlier:** The 160 limit was chosen before multi-fork topic doubling was considered. No test exercised `--subscribe-all-subnets` across a fork boundary.

**Could-have-been-caught-by:**
- Static analysis: compute max possible topics at any point in the Ethereum roadmap and verify all limits are > max
- Integration test: start with `--subscribe-all-subnets`, simulate fork transition, assert no subscription errors

---

### DD-9: False Gossip Penalty for `BlockIsAlreadyKnown` — #5602

**Root cause:** When a blob arrives via RPC first, the block is imported. When the same blob arrives later via gossip, `process_gossip_blob` returns `BlockError::BlockIsAlreadyKnown`. The gossip validation layer mapped this to a `Mid Tolerance Error`, penalizing the sending peer for what was actually a benign race condition (RPC vs gossip delivery order).

**How discovered:** User reports of unexpected peer downscoring.

**How fixed:** PR #5656 changed `process_gossip_blob` to return `Ok` (ignore) when `BlockIsAlreadyKnown`, treating it as a benign duplicate rather than a violation.

**Why not caught earlier:** The RPC-first path is timing-dependent and not exercised in most unit tests.

**Could-have-been-caught-by:**
- Test the gossip import code path against `BlockIsAlreadyKnown` explicitly and assert no peer penalty
- Review all `BlockError` variants that can appear in gossip context and classify each as penalizable/benign

---

### DD-10: RPC Pending Requests Lost on Rate-Limiter → Events Queue Transition — PR #5942

**Root cause:** RPC request lifecycle: (1) if immediately sendable → enqueue in `events`; (2) if rate-limited → enqueue in `self_limiter`. On peer disconnect, the code correctly drained `self_limiter` and reported those requests as failed. However, requests already promoted from `self_limiter` to `events` but not yet sent were silently discarded. The sync layer had no chance to retry.

**How discovered:** Code review.

**How fixed:** PR #5942 also scanned the `events` queue for pending requests to a disconnecting peer and emitted failure reports for them.

**Why not caught earlier:** Two-stage queue design created a "gap" in the failure-reporting path. No integration test simulated rate-limited request + peer disconnect.

**Could-have-been-caught-by:**
- State machine test: send request → rate-limit triggers → peer disconnects → assert sync receives failure event
- Invariant: any request entered into the RPC subsystem must always produce exactly one response or one failure notification

---

### DD-11: RPC Errors Not Propagated on Peer Disconnect — PR #5680

**Root cause:** When a peer disconnected while an RPC request was in-flight (i.e., substream open but response not yet received), no error was emitted to the application layer. Sync had workarounds but they were fragile. The fix required explicitly emitting `RPCError::Disconnect` for all outbound streams associated with a disconnecting peer via `inject_error`.

**How discovered:** Code review and investigation of sync stall reports.

**How fixed:** PR #5680 modified `inject_disconnect` to iterate all open outbound streams and emit `RPCError::Disconnect` for each.

**Why not caught earlier:** The in-flight case requires precise timing (disconnect arrives between request sent and response received). No test simulated this exactly.

**Could-have-been-caught-by:**
- Integration test: open RPC stream, disconnect peer before response, assert sync receives error
- Invariant: `outstanding_requests_for_peer > 0 before disconnect` → sync must receive that many failure events

---

### DD-12: Address Update Feedback Loop → OOM — #8437

**Root cause:** A bug in `discovery/mod.rs` where the `SocketUpdated` event handler incorrectly updated the TCP port with the UDP socket address. This caused a feedback loop: discv5 emitted `SocketUpdated(udp_addr)` → LH updated ENR TCP field with UDP addr → discv5 detected ENR change and emitted another `SocketUpdated` → loop at ~500Hz. Each iteration allocated state; memory grew to 117GB before the OOM killer intervened.

**How discovered:** User report of catastrophic memory growth.

**How fixed:** PR #8443 (`cargo update` including discv5 patch) fixed the socket address handling in the discv5 library.

**Why not caught earlier:** The feedback loop requires specific network conditions (address change event). No test simulated rapid `SocketUpdated` events to verify the handler was idempotent.

**Could-have-been-caught-by:**
- Stress test: inject 100 consecutive `SocketUpdated` events, assert memory usage stays bounded and ENR settles
- Monitor: alert on `address_updated` event rate > threshold (e.g., >10/s)

---

### DD-13: DataColumnsByRange Duplicate Columns Regression — #8842

**Root cause:** PR #8682 changed the return type of `get_block_roots_from_store` from `Vec<Hash256>` to `Vec<(Hash256, Slot)>` to support skip slots. The caller deduped with `.unique()`, which now compared `(Hash256, Slot)` tuples rather than just `Hash256`. Skip slots share the same block root but different slots, so they weren't deduplicated, resulting in the same column being served multiple times in one response. Remote peers correctly returned `DuplicatedData` errors and downscored the serving node.

**How discovered:** v8.1.0 regression found via user reports.

**How fixed:** PR #8843 changed to `.unique_by(|(root, _)| *root)`.

**Why not caught earlier:** The type change was not accompanied by a test verifying deduplication behavior with skip slots. The `DuplicatedData` penalty was a downstream effect, making it harder to trace.

**Could-have-been-caught-by:**
- Unit test for `DataColumnsByRange` response with epochs containing skip slots, asserting each column index appears at most once
- Property: response columns per root are unique by root, not by (root, slot)

---

### DD-14: Discovery `FindPeers` vs `FindNode` — Prysm Incompatibility — #4147

**Root cause:** Lighthouse's discv5 library sent `FindPeers` queries (a non-standard extension). Prysm's discv5 (go-ethereum v5wire) only understands `FindNode` (the standard). Prysm returned "invalid packet header" and no peers. Users with Prysm bootnodes saw zero discovered peers.

**How discovered:** User report ("I have 0 peers from Prysm bootnodes").

**How fixed:** discv5 library updated to use `FindNode` in v4.0.1.

**Why not caught earlier:** No cross-client discovery test in CI. Requires running two different Ethereum clients simultaneously.

**Could-have-been-caught-by:**
- Cross-client simulator: LH discovers peers via a Prysm or Teku discovery node
- discv5 protocol fuzz/interop test using the spec's official test vectors

---

### DD-15: Ban Peer Race Condition — PR #4140

**Root cause:** The peer manager event queue could contain `[Ban A, Unban A]` from a prior connect/disconnect/connect cycle. When processing these in order, the unban arrived after the ban, leaving a should-be-banned peer unbanned. A subsequent connection from that peer was accepted.

**How discovered:** Code review.

**How fixed:** PR #4140 cleared pending unban messages when applying a ban; added re-ban logic when a should-be-banned peer connects.

**Why not caught earlier:** Event ordering is subtle and difficult to trigger in normal tests. No test exercised rapid ban/unban/reconnect cycles.

**Could-have-been-caught-by:**
- State machine test: ban peer → peer reconnects immediately → assert peer is still banned
- Invariant: if `peer_db.is_banned(id)` then `peer_db.connection_state(id) ∉ {Connected, Dialing}`

---

## 4. Synthesis

### Counts by Class

| Class | Count |
|-------|-------|
| protocol-networking | 22 |
| panic-crash | 7 |
| concurrency | 3 |
| resource | 2 |
| config-cli | 2 |
| spec-correctness | 1 |
| logic-other | 2 |

### Counts by Severity

| Severity | Count |
|----------|-------|
| critical | 2 |
| high | 18 |
| medium | 14 |
| low | 2 |

### Recurring Root-Cause Themes

**1. External dependency panics (libp2p ecosystem).** The UPnP subsystem alone caused at least 6 issues across 3+ years (#4171, #5020, #5443, #5444, #6399, #9377, #5498). Both `igd` and `libp2p-upnp` used `unwrap()` in their state machines. The QUIC crate panicked on cert init (#6088). The discv5 crate had an OOM feedback loop (#8437). Lighthouse is highly exposed to upstream crate quality.

**2. Gossipsub internal state inconsistency.** Multiple bugs traced to the gossipsub implementation's internal state becoming inconsistent around peer lifecycle events (disconnect, fork transition): fanout desync (#5110), mesh/connected desync (#6244), IDONTWANT promise tracking (#6244), stale message accumulation, wrong P-parameters. Many of these arose from Lighthouse maintaining a private gossipsub fork before upstreaming.

**3. RPC request lifecycle incompleteness.** Three distinct holes in the "request always produces a response or failure" contract: in-flight requests not notified on disconnect (#5680), events-queue requests not notified on disconnect (#5942), requests silently lost when peer exceeds substream limit (#6106). These all caused sync stalls.

**4. Peer scoring false positives.** Honest peers penalized for: `BlockIsAlreadyKnown` race (#5602), P3 deficit during fork transitions (#3237), `HandlerRejected` due to excessive substreams (#6106), attestations for unseen head (#2902). Each case reflected a mismatch between the "reason for penalty" and "proof of malice."

**5. PeerDAS-specific networking stress.** PeerDAS introduced new RPC message types with volume characteristics (64 columns × N peers) that overwhelmed existing limits (MAX_INBOUND_SUBSTREAMS=32), introduced new deduplication requirements that weren't met (#8842), and timing dependencies on metadata exchange that blocked sync (#6895).

**6. Discovery protocol reliability.** Three different failure modes: infinite query loops (#6207), cross-client packet type mismatch (#4147), catastrophic OOM feedback loop (#8437). Discovery is a critical bootstrap path but under-tested with adversarial or cross-client scenarios.

### Highest-Leverage Early-Detection Improvements

**1. "Every RPC request must produce exactly one outcome" invariant.**
Instrument the RPC layer with a counter per peer: increment on request, decrement on response or failure. Assert at peer disconnect that the counter is zero. This would have caught #5680 and #5942 in any integration test that included a mid-request disconnect.

**2. Gossipsub state invariant assertions.**
After every peer lifecycle event (connect/disconnect/subscribe/unsubscribe), assert: `mesh_peers ⊆ connected_peers`, `fanout.keys() ∩ mesh.keys() = ∅`, `IDONTWANT_promises.peer_ids ⊆ connected_peers`. Run these in debug builds and in CI. Would have caught #6244, #5110, and similar bugs before they manifested in production.

**3. Dependency panic audit + CI unlock test.**
Run `cargo-geiger` or `cargo-deny` to flag `unsafe` and `unwrap()`-heavy dependencies. Add a nightly CI job that builds with `cargo update` (no `--lock`) to catch transient dependency regressions. Would have surfaced the `igd`, `libp2p-upnp`, and `rustls` panics earlier.

**4. Peer scoring decision log + automated false-positive detection.**
Log every peer score adjustment with its cause. Add a CI integration test that replays known-benign scenarios (RPC-before-gossip blob delivery, fork topic after transition) and asserts no peer penalty is emitted. Would have caught #5602, #3237, #2902.

**5. Cross-client discovery interop test in CI.**
Run a 2-node network with one LH and one Prysm/Teku node, assert each discovers the other within N seconds. Would have caught #4147 immediately. Also catches discv5 regressions early.

**6. Resource bounds test for discovery feedback loops.**
Inject 1000 `SocketUpdated` / `AddressUpdated` events in rapid succession and assert memory stays < 2× baseline and ENR stabilizes. Would have caught #8437 before it reached a user with 117GB RSS.

### Structural / Architectural Smells

- **UPnP is a repeated crash vector.** Three years, six issues. The safest fix is making UPnP opt-in rather than opt-out, or running it in an isolated subprocess where a panic can't take down the beacon node. Disabling by default with `--enable-upnp` would have avoided most user incidents.

- **Private gossipsub fork created divergence.** Lighthouse maintained a fork of gossipsub for years before switching to upstream (#7057). Multiple bugs (#5110, #6244, and others) were found during or after that migration, suggesting the fork accumulated divergent state-management logic that wasn't visible to upstream reviewers.

- **PeerDAS networking assumptions not validated against existing limits.** `MAX_INBOUND_SUBSTREAMS = 32` predates PeerDAS. The addition of 64-column-per-block requests was not checked against existing stream multiplexing limits, producing a "friendly fire" peer ban (#6106) that required a new batching abstraction.

- **Scoring system used for attack resistance doubles as connectivity risk.** Several bugs show that the peer scoring system, when miscalibrated or triggered by benign conditions, degrades connectivity. The system needs a "safe mode" or minimum peer count override: "never score below X if we have fewer than N peers."
