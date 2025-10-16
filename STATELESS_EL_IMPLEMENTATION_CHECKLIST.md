# Stateless Execution Layer Implementation Checklist

This checklist tracks the implementation of the Stateless Execution Layer architecture as described in `STATELESS_EXECUTION_LAYER_DESIGN.md`.

## Phase 1: Core Stateless-EL Crate (Foundation) ✅ COMPLETE

**Goal:** Create the stateless-EL crate with basic structure and dummy implementations.

- [x] Create `stateless_execution_layer/` crate with Cargo.toml
- [x] Implement `StatelessExecutionLayer` struct with core fields
- [x] Implement `ProofVerifier` and `ProofGenerator` traits
- [x] Create `DummyVerifier` implementation (simulate delay, return success)
- [x] Create `DummyGenerator` implementation (simulate delay, create dummy proof)
- [x] Implement `VerifierRegistry` and `GeneratorRegistry`
- [x] Implement proof cache with LRU eviction (`ProofCache`)
- [x] Implement basic `new_payload()` method with proof checking logic
- [x] Implement `forkchoice_updated()` method (minimal for stateless)
- [x] Create `StatelessExecutionLayerConfig` struct
- [x] Add configuration parsing and validation
- [x] Write unit tests for:
  - [x] Proof cache operations
  - [x] Config validation
  - [x] Dummy verifier/generator
  - [x] has_required_proofs() logic

**Exit Criteria:** Stateless-EL crate compiles and unit tests pass. ✅

**Completion Date:** 2025-10-15
**Test Results:** 38 tests passed, 0 failed

---

## Phase 2: Network Integration

**Goal:** Wire up stateless-EL to the network layer for proof gossip.

### 2.1 ExecutionLayer Backend Abstraction

- [ ] Modify `beacon_node/execution_layer/src/lib.rs`:
  - [ ] Create `ExecutionBackend` enum (Full, Stateless)
  - [ ] Update `ExecutionLayer` to use backend
  - [ ] Implement `new_payload()` dispatch to backend
  - [ ] Implement `forkchoice_updated()` dispatch to backend
  - [ ] Add constructor for stateless backend

### 2.2 Network Message Channels

- [ ] Create channels for proof message flow:
  - [ ] Network → Stateless-EL: `mpsc::channel<(SubnetId, Arc<ExecutionProof>)>`
  - [ ] Stateless-EL → Network: `mpsc::channel<(SubnetId, Arc<ExecutionProof>)>`
  - [ ] Stateless-EL → Network (RPC): `mpsc::channel<RpcRequest>`

### 2.3 Router Modifications

- [ ] Modify `beacon_node/network/src/router/mod.rs`:
  - [ ] Add `stateless_el_proof_tx` field
  - [ ] Route `ExecutionProofMessage` to stateless-EL (not beacon processor)
  - [ ] Remove old execution proof routing to beacon processor

### 2.4 ENR Advertisement

- [ ] Modify `beacon_node/lighthouse_network/src/discovery/enr.rs`:
  - [ ] Add `EXECUTION_PROOF_SUBNETS_ENR_KEY` constant
  - [ ] Implement `build_execution_proof_subnets()` (bitfield encoding)
  - [ ] Implement `execution_proof_subnets()` ENR extension method
  - [ ] Update ENR builder to include proof subnets

### 2.5 Peer Tracking

- [ ] Modify `beacon_node/lighthouse_network/src/peer_manager/peerdb.rs`:
  - [ ] Add `execution_proof_subnets` field to `PeerInfo`
  - [ ] Update peer metadata handling to extract proof subnets from ENR

### 2.6 Gossip Subscription

- [ ] Verify gossip topics exist (should already be in codebase):
  - [ ] `GossipKind::ExecutionProof(subnet_id)` in `topics.rs`
  - [ ] Subscription logic in `core_topics_to_subscribe()`
- [ ] Update `TopicConfig` to include `execution_proof_subnets`

### 2.7 Proof Reception in Stateless-EL

- [ ] Implement `on_gossip_proof_received()`:
  - [ ] Validate subnet ID matches
  - [ ] Check subscription
  - [ ] Store in proof cache
  - [ ] Check if threshold reached
  - [ ] Trigger callback if available

### 2.8 Proof Publishing from Stateless-EL

- [ ] Implement proof generation flow:
  - [ ] Detect when to generate (new_payload called with generation enabled)
  - [ ] Spawn background task per subnet
  - [ ] Generate proof (dummy for now)
  - [ ] Verify locally
  - [ ] Publish via network channel

### 2.9 CLI Flags

- [ ] Add CLI flags in `beacon_node/src/cli.rs`:
  - [ ] `--stateless-execution-layer`
  - [ ] `--verify-execution-proof-subnets=<list>`
  - [ ] `--min-proofs-required=<n>`
  - [ ] `--generate-execution-proofs=<list>`
- [ ] Parse flags in `beacon_node/src/config.rs`

### 2.10 Beacon Node Initialization

- [ ] Modify `beacon_node/src/lib.rs`:
  - [ ] Parse stateless-EL config from CLI
  - [ ] Create channels
  - [ ] Instantiate `StatelessExecutionLayer` if configured
  - [ ] Create `ExecutionLayer` with appropriate backend
  - [ ] Wire up proof channel to router
  - [ ] Spawn proof publishing task

### 2.11 Testing

- [ ] Test gossip proof flow end-to-end
- [ ] Test proof generation and publishing
- [ ] Test ENR advertisement
- [ ] Test peer discovery with proof subnets

**Exit Criteria:** Beacon node starts with `--stateless-execution-layer`, proofs flow through gossip, ENR advertises participation.

---

## Phase 3: Data Availability Integration

**Goal:** Coordinate proof availability with the DA checker.

### 3.1 DA Checker Modifications

- [ ] Modify `beacon_node/beacon_chain/src/data_availability_checker/overflow_lru_cache.rs`:
  - [ ] Add `stateless_el: Option<Arc<StatelessExecutionLayer>>` field
  - [ ] Update `check_availability()` to query `stateless_el.has_required_proofs()`
  - [ ] Implement `on_execution_proofs_ready()` callback handler

### 3.2 Stateless-EL Query Interface

- [ ] Implement `has_required_proofs()`:
  - [ ] Non-blocking check against proof cache
  - [ ] Return true if >= min_proofs_required
- [ ] Implement `register_proof_ready_callback()`:
  - [ ] Store callback function
  - [ ] Call when proofs reach threshold

### 3.3 Callback Wiring

- [ ] Wire callback from stateless-EL to DA checker:
  - [ ] After stateless-EL creation, register callback
  - [ ] Callback triggers DA checker's `on_execution_proofs_ready()`
  - [ ] DA checker re-checks availability and releases block if ready

### 3.4 Testing

- [ ] Test block waits for proofs before import
- [ ] Test callback triggers when proofs arrive
- [ ] Test availability logic with missing/arriving proofs
- [ ] Test timeout behavior for missing proofs

**Exit Criteria:** Blocks only import when proofs are available, DA checker coordinates blob + proof availability.

---

## Phase 4: RPC Proof Fetching

**Goal:** Add resilience by fetching missing proofs via RPC.

### 4.1 RPC Protocol

- [ ] Add RPC method in `beacon_node/lighthouse_network/src/rpc/methods.rs`:
  - [ ] `ExecutionProofsByRootRequest` struct
  - [ ] `RPCRequest::ExecutionProofsByRoot` variant
  - [ ] `RPCResponse::ExecutionProofsByRoot` variant
  - [ ] Request/response encoding

### 4.2 RPC Handler

- [ ] Implement RPC request handler:
  - [ ] Look up proofs in local cache
  - [ ] Return proofs if available
  - [ ] Peer scoring for successful/failed requests

### 4.3 Request Missing Proofs

- [ ] Implement `request_missing_proofs()` in stateless-EL:
  - [ ] Wait for gossip grace period (200ms)
  - [ ] Check if proofs arrived via gossip
  - [ ] If not, send RPC request via channel
  - [ ] Select peers with matching subnets in ENR

### 4.4 RPC Request Processing

- [ ] Spawn task in beacon node to handle RPC requests from stateless-EL:
  - [ ] Receive requests from channel
  - [ ] Select appropriate peer
  - [ ] Make RPC call
  - [ ] Forward response to stateless-EL

### 4.5 Testing

- [ ] Test RPC fallback when gossip fails
- [ ] Test peer selection based on ENR
- [ ] Test timeout and retry logic
- [ ] Test proof arrival via RPC

**Exit Criteria:** Stateless-EL actively fetches missing proofs via RPC when gossip fails.

---

## Phase 5: Real zkVM Integration (Future Work)

**Goal:** Replace dummy implementations with real zkVM proof generation/verification.

- [ ] Choose zkVM system (RISC Zero, SP1, or both)
- [ ] Implement execution witness fetching:
  - [ ] Add `debug_executionWitness` RPC call to EL
  - [ ] Parse witness format
- [ ] Implement real `RiscZeroVerifier`:
  - [ ] Integrate RISC Zero SDK
  - [ ] Implement proof verification
  - [ ] Handle verification errors
- [ ] Implement real `RiscZeroGenerator`:
  - [ ] Integrate RISC Zero SDK
  - [ ] Write zkVM guest program for execution
  - [ ] Generate real proofs
- [ ] Optimize proof size:
  - [ ] Add compression (zstd/snappy)
  - [ ] Consider recursive proofs
- [ ] Add metrics:
  - [ ] Proof generation latency
  - [ ] Proof verification time
  - [ ] Proof size distribution
  - [ ] Success/failure rates

**Exit Criteria:** Real cryptographic proofs working end-to-end.

---

## Phase 6: Testing and Hardening

**Goal:** Comprehensive testing and production readiness.

### 6.1 Unit Tests

- [ ] All stateless-EL components have unit tests
- [ ] All error paths tested
- [ ] Edge cases covered

### 6.2 Integration Tests

- [ ] BeaconChainHarness tests with stateless-EL
- [ ] Multi-node proof propagation
- [ ] Block import with proofs

### 6.3 End-to-End Tests

- [ ] Local testnet with Kurtosis:
  - [ ] Proof generator nodes
  - [ ] Stateless validator nodes
  - [ ] Block production and validation
- [ ] Byzantine behavior testing:
  - [ ] Invalid proofs
  - [ ] Proof withholding
  - [ ] Proof replay

### 6.4 Performance Testing

- [ ] Benchmark proof generation
- [ ] Benchmark proof verification
- [ ] Measure network overhead
- [ ] Profile hot paths

### 6.5 Documentation

- [ ] API documentation for stateless-EL
- [ ] User guide for running stateless nodes
- [ ] Operator guide for proof generation
- [ ] Architecture documentation

### 6.6 Security Review

- [ ] Code review by team
- [ ] Security audit (external)
- [ ] Threat model documentation

**Exit Criteria:** Comprehensive test coverage, documentation complete, security reviewed.

---

## Code Cleanup Checklist

Once new implementation is working, remove old execution proof code:

- [ ] Delete `beacon_node/beacon_chain/src/execution_proof_generation.rs`
- [ ] Delete `beacon_node/beacon_chain/src/execution_proof_verification.rs`
- [ ] Delete `beacon_node/beacon_chain/src/execution_proof_network.rs`
- [ ] Remove execution proof tracking from DA checker `PendingComponents`
- [ ] Remove `GossipExecutionProof` work type from beacon processor
- [ ] Clean up old CLI flags (if any changed)
- [ ] Update CLAUDE.md if needed

Keep these files (they're reused):
- ✅ `consensus/types/src/execution_proof.rs`
- ✅ `consensus/types/src/execution_proof_subnet_id.rs`
- ✅ Gossip topic definitions in `lighthouse_network/src/types/topics.rs`
- ✅ PubsubMessage variant in `lighthouse_network/src/types/pubsub.rs`

---

## Notes

- Work can proceed incrementally - each phase builds on the previous
- Tests should be written alongside implementation
- Refer to `STATELESS_EXECUTION_LAYER_DESIGN.md` for detailed code examples
- Follow patterns in `CLAUDE.md` for Lighthouse conventions
- When in doubt, look at how blobs/data columns are handled - very similar patterns

## Current Status

**Phase:** Phase 1 Complete ✅
**Branch:** kw/exec-proofs-stateless-el
**Last Updated:** 2025-10-15

### Phase 1 Summary

Phase 1 is complete with all components implemented and tested:

#### Files Created:
- `consensus/types/src/execution_proof.rs` - Core ExecutionProof type with SSZ/TreeHash
- `consensus/types/src/execution_proof_subnet_id.rs` - Type-safe subnet ID (0-7)
- `stateless_execution_layer/Cargo.toml` - Crate dependencies
- `stateless_execution_layer/src/config.rs` - Configuration with builder pattern
- `stateless_execution_layer/src/proof_verification.rs` - ProofVerifier trait
- `stateless_execution_layer/src/proof_generation.rs` - ProofGenerator trait
- `stateless_execution_layer/src/dummy_verifier.rs` - Dummy verifier for testing
- `stateless_execution_layer/src/dummy_generator.rs` - Dummy generator for testing
- `stateless_execution_layer/src/verifier_registry.rs` - Registry for verifiers
- `stateless_execution_layer/src/generator_registry.rs` - Registry for generators
- `stateless_execution_layer/src/proof_cache.rs` - LRU cache for proofs
- `stateless_execution_layer/src/lib.rs` - Main StatelessExecutionLayer implementation

#### Test Coverage:
All 38 unit tests passing:
- Config validation (5 tests)
- Dummy verifier/generator (8 tests)
- Verifier/Generator registries (8 tests)
- Proof cache operations (9 tests)
- Error handling (2 tests)
- Main StatelessExecutionLayer (3 tests)
- Integration tests (3 tests)

Ready to proceed to Phase 2: Network Integration
