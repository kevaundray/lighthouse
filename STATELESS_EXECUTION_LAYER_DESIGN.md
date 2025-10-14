# Stateless Execution Layer Architecture Design

## Overview

This document describes the architectural design for implementing execution proof support in Lighthouse through a new **Stateless Execution Layer** crate. This approach encapsulates all execution proof logic (generation, verification, caching, networking) into a self-contained module that implements the Engine API, allowing the consensus layer to remain focused on consensus logic.

## Background & Motivation

The goal is to enable **stateless validation** where nodes can validate execution payloads without running a full execution client by:
1. Generating cryptographic proofs (zkVM-based) of execution payload validity
2. Distributing proofs via dedicated gossip subnets
3. Verifying proofs instead of re-executing transactions
4. Supporting multiple proof systems (different zkVMs) on different subnets

### Key Architectural Principle

**The stateless-EL is a drop-in replacement for a full execution layer**, implementing the same Engine API interface. The consensus layer doesn't need to know about proof internals - it just calls the same Engine API methods (`newPayload`, `forkchoiceUpdated`, etc.).

## High-Level Architecture

```
┌─────────────────────────────────────────────────────┐
│ Beacon Node Binary                                  │
│                                                     │
│  ┌──────────────────────────────────────────────┐  │
│  │ Consensus Layer (BeaconChain)                │  │
│  │                                              │  │
│  │  - Block import logic                        │  │
│  │  - Fork choice                               │  │
│  │  - Validator duties                          │  │
│  └──────────────┬───────────────────────────────┘  │
│                 │ Engine API calls                  │
│                 │ (newPayload, forkchoiceUpdated)   │
│                 ▼                                   │
│  ┌──────────────────────────────────────────────┐  │
│  │ Stateless Execution Layer (NEW CRATE)        │  │
│  │                                              │  │
│  │  - Engine API server (in-process)           │  │
│  │  - Proof verification (zkVM)                │  │
│  │  - Proof generation (zkVM, optional)        │  │
│  │  - Proof cache (LRU)                        │  │
│  │  - Peer tracking (exec-proof-capable)       │  │
│  └──────────────┬───────────────────────────────┘  │
│                 │ Proof messages (channels)         │
│                 ▼                                   │
│  ┌──────────────────────────────────────────────┐  │
│  │ Lighthouse Network (lighthouse_network)      │  │
│  │                                              │  │
│  │  - libp2p / gossipsub                       │  │
│  │  - Discovery (ENR with exec_proof_subnets)  │  │
│  │  - Peers & scoring                          │  │
│  │  - RPC protocols                            │  │
│  └──────────────────────────────────────────────┘  │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Core Design Decisions

### 1. Stateless-EL as Embedded Library

- **Deployment**: Single binary - the beacon node pulls in stateless-EL as a library
- **Integration**: CL creates a `StatelessExecutionLayer` instance and calls it like any Engine API client
- **Not** a separate process or external service

### 2. P2P Network Sharing (Recommended Approach)

**Strategy: Peer List Sharing with Message Forwarding**

The stateless-EL piggybacks on the CL's libp2p/discovery infrastructure:

1. **CL Discovery**: The beacon node's ENR advertises execution proof subnet participation
2. **Peer Discovery**: When CL discovers peers with `exec_proof_subnets` in their ENR, it tracks them
3. **Gossip Forwarding**: CL receives `execution_proof` gossip messages and forwards them to stateless-EL via channels
4. **Proof Publishing**: Stateless-EL publishes generated proofs by sending them back to CL network layer via channels
5. **RPC Capability**: Stateless-EL can request the CL network layer to fetch missing proofs via RPC

**Benefits:**
- Clean separation: stateless-EL doesn't directly import `lighthouse_network`
- Single ENR, single peer set, efficient connection management
- Stateless-EL is focused on proof logic, not networking primitives

### 3. Data Availability Checker Integration

**Strategy: DA Checker Queries Stateless-EL for Proof Availability**

The DA checker coordinates both blob/data column availability AND execution proof availability:

```rust
// A block is "available" when:
// 1. We have the block itself
// 2. We have all required blobs/data columns
// 3. We have minimum required execution proofs (if using stateless-EL)
```

**Implementation:**
- DA checker holds an `Option<Arc<StatelessExecutionLayer>>` reference
- When checking availability, DA checker calls `stateless_el.has_required_proofs(payload)`
- When proofs arrive, stateless-EL triggers a callback to DA checker to re-check availability
- Block only proceeds to import when both blobs AND proofs are available

**Benefits:**
- Centralized availability logic
- Event-driven (no polling)
- Reuses existing DA checker retry/timeout mechanisms

### 4. Proof Request Strategy (Hybrid Approach)

**Strategy: Gossip-first with RPC Fallback**

When `newPayload` is called but proofs are missing:

1. Return `PayloadStatus::Syncing` immediately (non-blocking)
2. Wait 100-500ms for proofs to arrive via gossip (fast path)
3. If still missing, actively request proofs via RPC (resilient path)
4. CL will retry `newPayload` later (standard Engine API flow)

**Benefits:**
- Matches how full ELs handle missing parent blocks
- Fast when gossip works (majority of cases)
- Resilient when gossip fails (peer withholding, network partitions)
- Prevents validator stalls

**Implementation Requirements:**
- New RPC method: `ExecutionProofsByRoot` (similar to `BlobsByRoot`)
- Stateless-EL requests CL network layer to fetch proofs from peers

### 5. Multiple Proof Systems (M-of-N Security)

**Strategy: Subscribe to N Subnets, Require M Valid Proofs from Different Subnets**

- **Subnets**: Each of 8 subnets can represent a different zkVM or proof system
  - Subnet 0: RISC Zero proofs
  - Subnet 1: SP1 proofs
  - Subnet 2-7: Future proof systems
- **M-of-N**: Require proofs from M different subnets (e.g., `min_proofs_required = 2` means need both RISC Zero AND SP1)
- **Subscription Strategy**: Subscribe to N > M subnets for redundancy (e.g., subscribe to 4, require 2)

**Benefits:**
- Security through diversity: single zkVM compromise doesn't break validation
- Flexibility: network can experiment with multiple proof systems
- Gradual rollout: start with 1 subnet, expand over time

### 6. Proof Generation + Verification Support

**Strategy: Separate Configuration for Generation and Verification**

A single node can:
- Generate proofs for specific subnets (requires zkVM guest binary + resources)
- Verify proofs from different subnets (requires verifier implementations)

**Example Use Case:**
```bash
# Node generates RISC Zero proofs, verifies both RISC Zero + SP1
lighthouse bn \
  --stateless-execution-layer \
  --generate-execution-proofs=0 \
  --verify-execution-proof-subnets=0,1 \
  --min-proofs-required=2
```

**Benefits:**
- Flexibility: nodes can specialize based on hardware/capabilities
- Redundancy: generator nodes can verify their own proofs + others for security

## Detailed Component Design

### New Crate: `stateless_execution_layer/`

```
stateless_execution_layer/
├── Cargo.toml
├── src/
│   ├── lib.rs                    // Main StatelessExecutionLayer struct
│   ├── engine_api.rs             // Engine API implementation (newPayload, etc.)
│   ├── proof_generation.rs       // zkVM proof generation interface
│   ├── proof_verification.rs     // zkVM proof verification interface
│   ├── proof_cache.rs            // LRU cache for received proofs
│   ├── network_interface.rs      // Channels to/from lighthouse_network
│   ├── peer_manager.rs           // Track execution-proof-capable peers
│   ├── verifier_registry.rs      // Map subnet_id -> ProofVerifier
│   ├── generator_registry.rs     // Map subnet_id -> ProofGenerator
│   └── config.rs                 // Configuration struct
```

### Main Struct: `StatelessExecutionLayer`

```rust
pub struct StatelessExecutionLayer {
    /// Configuration (subnets, min_proofs, etc.)
    config: StatelessExecutionLayerConfig,

    /// Proof cache: block_hash -> Vec<ExecutionProof>
    proof_cache: Arc<RwLock<LruCache<ExecutionBlockHash, Vec<ExecutionProof>>>>,

    /// Verifier registry: subnet_id -> verifier implementation
    verifiers: Arc<VerifierRegistry>,

    /// Optional generator registry (only if generating proofs)
    generators: Option<Arc<GeneratorRegistry>>,

    /// Channel to send proofs to network layer for publishing
    network_tx: mpsc::Sender<(ExecutionProofSubnetId, Arc<ExecutionProof>)>,

    /// Channel to send RPC requests to network layer
    rpc_request_tx: mpsc::Sender<RpcRequest>,

    /// Callback to notify DA checker when proofs become available
    proof_ready_callback: Option<Arc<dyn Fn(ExecutionBlockHash) + Send + Sync>>,

    /// Logger
    log: Logger,
}
```

### Configuration

```rust
pub struct StatelessExecutionLayerConfig {
    /// Which subnets to subscribe to for verification
    pub subscribed_subnets: HashSet<ExecutionProofSubnetId>,

    /// Minimum proofs required from DIFFERENT subnets
    pub min_proofs_required: usize,

    /// Which subnets to generate proofs for (empty if not generating)
    pub generation_subnets: HashSet<ExecutionProofSubnetId>,

    /// Proof cache size
    pub proof_cache_size: usize,

    /// Timeout for proof requests
    pub proof_request_timeout: Duration,

    /// Delay before falling back to RPC (gossip grace period)
    pub gossip_grace_period: Duration,
}
```

### Engine API Implementation

```rust
impl StatelessExecutionLayer {
    /// Main Engine API method: validate execution payload
    pub async fn new_payload(
        &self,
        payload: ExecutionPayload,
    ) -> Result<PayloadStatus> {
        let block_hash = payload.block_hash();

        // 1. If we generate proofs, spawn generation task
        if let Some(generators) = &self.generators {
            self.spawn_proof_generation(payload.clone(), generators);
        }

        // 2. Check if we have enough proofs to verify
        let proofs = self.proof_cache.read().await.get(&block_hash);

        match proofs {
            Some(proofs) if proofs.len() >= self.config.min_proofs_required => {
                // Have enough proofs, verify them
                self.verify_proofs(&payload, proofs).await?;
                Ok(PayloadStatus::Valid)
            }
            _ => {
                // Missing proofs, trigger fetching and return SYNCING
                self.request_missing_proofs(block_hash, payload.block_root());
                Ok(PayloadStatus::Syncing)
            }
        }
    }

    pub async fn forkchoice_updated(
        &self,
        state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse> {
        // For stateless-EL, we don't build payloads
        // This method is primarily used for head updates
        Ok(ForkchoiceUpdatedResponse {
            payload_status: PayloadStatus::Valid,
            payload_id: None,
        })
    }
}
```

### Proof Verification Logic

```rust
impl StatelessExecutionLayer {
    async fn verify_proofs(
        &self,
        payload: &ExecutionPayload,
        proofs: &[ExecutionProof],
    ) -> Result<()> {
        let mut verified_subnets = HashSet::new();
        let mut errors = Vec::new();

        for proof in proofs {
            // Get verifier for this subnet's zkVM
            let verifier = self.verifiers.get_verifier(proof.subnet_id)
                .ok_or(UnknownSubnet(proof.subnet_id))?;

            // Verify proof
            match verifier.verify(payload, proof).await {
                Ok(true) => {
                    verified_subnets.insert(proof.subnet_id);

                    // Early exit if we have enough
                    if verified_subnets.len() >= self.config.min_proofs_required {
                        return Ok(());
                    }
                }
                Ok(false) => {
                    errors.push(format!("Proof from subnet {} failed verification", proof.subnet_id));
                }
                Err(e) => {
                    errors.push(format!("Error verifying proof from subnet {}: {}", proof.subnet_id, e));
                }
            }
        }

        // Not enough valid proofs from different subnets
        Err(InsufficientProofs {
            required: self.config.min_proofs_required,
            verified: verified_subnets.len(),
            errors,
        })
    }
}
```

### Proof Request Logic (Hybrid Gossip + RPC)

```rust
impl StatelessExecutionLayer {
    fn request_missing_proofs(&self, block_hash: ExecutionBlockHash, block_root: Hash256) {
        let proof_cache = self.proof_cache.clone();
        let rpc_request_tx = self.rpc_request_tx.clone();
        let config = self.config.clone();
        let log = self.log.clone();

        tokio::spawn(async move {
            // Wait for gossip grace period (100-500ms)
            tokio::time::sleep(config.gossip_grace_period).await;

            // Check if proofs arrived via gossip
            let has_proofs = proof_cache.read().await
                .get(&block_hash)
                .map(|p| p.len() >= config.min_proofs_required)
                .unwrap_or(false);

            if !has_proofs {
                // Gossip didn't deliver, request via RPC
                debug!(log, "Requesting proofs via RPC"; "block_hash" => ?block_hash);

                let request = RpcRequest::ExecutionProofsByRoot {
                    block_hash,
                    block_root,
                    subnet_ids: config.subscribed_subnets.clone(),
                };

                let _ = rpc_request_tx.send(request).await;
            }
        });
    }
}
```

### Proof Generation Logic

```rust
impl StatelessExecutionLayer {
    fn spawn_proof_generation(
        &self,
        payload: ExecutionPayload,
        generators: &Arc<GeneratorRegistry>,
    ) {
        for subnet_id in &self.config.generation_subnets {
            let generator = match generators.get_generator(*subnet_id) {
                Some(g) => g,
                None => {
                    warn!(self.log, "No generator for subnet"; "subnet_id" => ?subnet_id);
                    continue;
                }
            };

            let payload = payload.clone();
            let network_tx = self.network_tx.clone();
            let proof_cache = self.proof_cache.clone();
            let log = self.log.clone();
            let subnet_id = *subnet_id;

            tokio::spawn(async move {
                debug!(log, "Generating proof"; "subnet_id" => ?subnet_id, "block_hash" => ?payload.block_hash());

                // Generate proof (expensive operation)
                match generator.generate(&payload).await {
                    Ok(proof) => {
                        // Store in local cache
                        proof_cache.write().await
                            .insert(payload.block_hash(), vec![proof.clone()]);

                        // Publish to gossip
                        if let Err(e) = network_tx.send((subnet_id, Arc::new(proof))).await {
                            warn!(log, "Failed to publish proof"; "error" => ?e);
                        }
                    }
                    Err(e) => {
                        error!(log, "Proof generation failed"; "error" => ?e);
                    }
                }
            });
        }
    }
}
```

### Proof Reception from Gossip

```rust
impl StatelessExecutionLayer {
    /// Handle proof received from gossip (called via channel from network layer)
    pub async fn on_gossip_proof_received(
        &self,
        subnet_id: ExecutionProofSubnetId,
        proof: Arc<ExecutionProof>,
    ) -> Result<()> {
        // Validate subnet ID matches
        if proof.subnet_id != subnet_id {
            return Err(SubnetMismatch);
        }

        // Check if subscribed to this subnet
        if !self.config.subscribed_subnets.contains(&subnet_id) {
            return Err(UnsubscribedSubnet);
        }

        // Store in cache
        let block_hash = proof.block_hash;
        let mut cache = self.proof_cache.write().await;
        cache.entry(block_hash)
            .or_insert_with(Vec::new)
            .push((*proof).clone());

        // Check if we now have enough proofs for any pending payloads
        let proof_count = cache.get(&block_hash).map(|p| p.len()).unwrap_or(0);
        if proof_count >= self.config.min_proofs_required {
            // Notify DA checker that proofs are available
            if let Some(callback) = &self.proof_ready_callback {
                callback(block_hash);
            }
        }

        Ok(())
    }
}
```

### Verifier and Generator Traits

```rust
/// Trait for proof verification (one implementation per zkVM)
pub trait ProofVerifier: Send + Sync {
    /// Verify that the proof is valid for the given execution payload
    async fn verify(
        &self,
        payload: &ExecutionPayload,
        proof: &ExecutionProof,
    ) -> Result<bool>;

    /// Get the subnet ID this verifier handles
    fn subnet_id(&self) -> ExecutionProofSubnetId;
}

/// Trait for proof generation (one implementation per zkVM)
pub trait ProofGenerator: Send + Sync {
    /// Generate a proof for the given execution payload
    /// This is computationally expensive and should be run in a background task
    async fn generate(
        &self,
        payload: &ExecutionPayload,
    ) -> Result<ExecutionProof>;

    /// Get the subnet ID this generator produces proofs for
    fn subnet_id(&self) -> ExecutionProofSubnetId;
}

/// Registry mapping subnet IDs to verifiers
pub struct VerifierRegistry {
    verifiers: HashMap<ExecutionProofSubnetId, Arc<dyn ProofVerifier>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        let mut verifiers = HashMap::new();

        // Register verifiers for each subnet
        // Subnet 0: RISC Zero (placeholder for now)
        verifiers.insert(
            ExecutionProofSubnetId::new(0).unwrap(),
            Arc::new(DummyVerifier::new(0)) as Arc<dyn ProofVerifier>
        );

        // Subnet 1: SP1 (placeholder for now)
        verifiers.insert(
            ExecutionProofSubnetId::new(1).unwrap(),
            Arc::new(DummyVerifier::new(1)) as Arc<dyn ProofVerifier>
        );

        // More subnets can be added here

        Self { verifiers }
    }

    pub fn get_verifier(&self, subnet_id: ExecutionProofSubnetId) -> Option<Arc<dyn ProofVerifier>> {
        self.verifiers.get(&subnet_id).cloned()
    }
}

/// Registry mapping subnet IDs to generators
pub struct GeneratorRegistry {
    generators: HashMap<ExecutionProofSubnetId, Arc<dyn ProofGenerator>>,
}

impl GeneratorRegistry {
    pub fn new(enabled_subnets: HashSet<ExecutionProofSubnetId>) -> Self {
        let mut generators = HashMap::new();

        for subnet_id in enabled_subnets {
            // Create generator for this subnet
            // For now, use dummy generators
            generators.insert(
                subnet_id,
                Arc::new(DummyGenerator::new(subnet_id)) as Arc<dyn ProofGenerator>
            );
        }

        Self { generators }
    }

    pub fn get_generator(&self, subnet_id: ExecutionProofSubnetId) -> Option<Arc<dyn ProofGenerator>> {
        self.generators.get(&subnet_id).cloned()
    }
}
```

## Integration with Existing Lighthouse Code

### 1. ExecutionLayer Abstraction

Modify `beacon_node/execution_layer/src/lib.rs` to support multiple backends:

```rust
pub enum ExecutionBackend {
    /// External execution engine (geth, nethermind, etc.)
    Full(EngineApiClient),

    /// In-process stateless execution layer
    Stateless(Arc<StatelessExecutionLayer>),
}

pub struct ExecutionLayer<T: EthSpec> {
    backend: ExecutionBackend,
    // ... existing fields
}

impl<T: EthSpec> ExecutionLayer<T> {
    pub async fn new_payload(&self, payload: ExecutionPayload) -> Result<PayloadStatus> {
        match &self.backend {
            ExecutionBackend::Full(client) => {
                client.new_payload_v4(payload).await
            }
            ExecutionBackend::Stateless(stateless_el) => {
                stateless_el.new_payload(payload).await
            }
        }
    }

    pub async fn forkchoice_updated(
        &self,
        state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse> {
        match &self.backend {
            ExecutionBackend::Full(client) => {
                client.forkchoice_updated_v3(state, payload_attributes).await
            }
            ExecutionBackend::Stateless(stateless_el) => {
                stateless_el.forkchoice_updated(state, payload_attributes).await
            }
        }
    }

    // Similar for other Engine API methods...
}
```

### 2. Network Layer Changes

#### A. Gossip Topic Subscription

In `beacon_node/lighthouse_network/src/types/topics.rs`, the execution proof topics already exist in current code. Keep them:

```rust
pub enum GossipKind {
    // ... existing variants
    ExecutionProof(ExecutionProofSubnetId), // subnet_id 0-7
}

// Topic generation
pub fn core_topics_to_subscribe(opts: &TopicConfig) -> Vec<GossipKind> {
    let mut topics = vec![/* ... existing topics */];

    // Subscribe to configured execution proof subnets
    for subnet_id in &opts.execution_proof_subnets {
        topics.push(GossipKind::ExecutionProof(*subnet_id));
    }

    topics
}
```

#### B. Message Routing

In `beacon_node/network/src/router/mod.rs`, route execution proof messages to stateless-EL:

```rust
pub struct Router<T: EthSpec> {
    // Channel to send proofs to stateless-EL
    stateless_el_proof_tx: Option<mpsc::Sender<(ExecutionProofSubnetId, Arc<ExecutionProof>)>>,
    // ... existing fields
}

impl<T: EthSpec> Router<T> {
    fn handle_gossip_message(&mut self, message: PubsubMessage<T>) {
        match message {
            PubsubMessage::ExecutionProofMessage(subnet_id, proof) => {
                // Forward to stateless-EL if configured
                if let Some(tx) = &self.stateless_el_proof_tx {
                    let _ = tx.try_send((*subnet_id, proof));
                }
                // No longer goes through beacon processor
            }
            // ... other message types go to beacon processor as before
        }
    }
}
```

#### C. RPC Protocol for Proof Requests

Add new RPC method in `beacon_node/lighthouse_network/src/rpc/methods.rs`:

```rust
pub enum RPCRequest {
    // ... existing variants
    ExecutionProofsByRoot(ExecutionProofsByRootRequest),
}

pub struct ExecutionProofsByRootRequest {
    /// Block hash to get proofs for
    pub block_hash: ExecutionBlockHash,
    /// Block root (for validation)
    pub block_root: Hash256,
    /// Which subnets to request proofs from
    pub subnet_ids: Vec<ExecutionProofSubnetId>,
}

pub enum RPCResponse<T: EthSpec> {
    // ... existing variants
    ExecutionProofsByRoot(Option<Arc<ExecutionProof>>),
}
```

The RPC handler would look up proofs from its local cache and return them.

### 3. Data Availability Checker Integration

Modify `beacon_node/beacon_chain/src/data_availability_checker/overflow_lru_cache.rs`:

```rust
pub struct AvailabilityCheckingCache<T: EthSpec> {
    /// Reference to stateless-EL for proof availability checks
    stateless_el: Option<Arc<StatelessExecutionLayer>>,
    // ... existing fields
}

impl<T: EthSpec> AvailabilityCheckingCache<T> {
    pub fn check_availability(&self, block: &Arc<SignedBeaconBlock<T>>) -> Availability {
        // 1. Check blobs/data columns (existing logic)
        let has_data_columns = self.has_all_data_columns(block);

        // 2. Check execution proofs (new logic)
        let has_execution_proofs = if let Some(el) = &self.stateless_el {
            if let Ok(Some(payload)) = block.message().body().execution_payload() {
                el.has_required_proofs(payload)
            } else {
                true // No execution payload, skip check
            }
        } else {
            true // Not using stateless-EL, skip check
        };

        // 3. Determine availability
        if has_data_columns && has_execution_proofs {
            Availability::Available
        } else {
            Availability::MissingComponents
        }
    }

    /// Called by stateless-EL when proofs become available
    pub fn on_execution_proofs_ready(&self, block_hash: ExecutionBlockHash) {
        // Find pending block with this execution payload hash
        // Re-check availability
        // If now available, trigger block processing
        // (implementation details depend on existing DA checker logic)
    }
}
```

Add method to stateless-EL for querying proof availability:

```rust
impl StatelessExecutionLayer {
    /// Non-blocking check: do we have minimum required proofs for this payload?
    pub fn has_required_proofs(&self, payload: &ExecutionPayload) -> bool {
        let cache = self.proof_cache.blocking_read(); // or use try_read()
        cache.get(&payload.block_hash())
            .map(|proofs| proofs.len() >= self.config.min_proofs_required)
            .unwrap_or(false)
    }

    /// Register callback for when proofs become available
    pub fn register_proof_ready_callback(
        &mut self,
        callback: Arc<dyn Fn(ExecutionBlockHash) + Send + Sync>,
    ) {
        self.proof_ready_callback = Some(callback);
    }
}
```

### 4. Beacon Node Initialization

In `beacon_node/src/lib.rs`, initialize stateless-EL when configured:

```rust
// Parse CLI config
let stateless_config = if client_config.chain.stateless_execution_layer {
    Some(StatelessExecutionLayerConfig {
        subscribed_subnets: client_config.chain.verify_execution_proof_subnets.clone(),
        min_proofs_required: client_config.chain.min_proofs_required,
        generation_subnets: client_config.chain.generate_execution_proof_subnets.clone(),
        proof_cache_size: 1024,
        proof_request_timeout: Duration::from_secs(5),
        gossip_grace_period: Duration::from_millis(200),
    })
} else {
    None
};

// Create channels for stateless-EL <-> network communication
let (proof_tx, proof_rx) = mpsc::channel(1024);
let (rpc_request_tx, rpc_request_rx) = mpsc::channel(256);

// Create stateless-EL instance
let stateless_el = if let Some(config) = stateless_config {
    let el = StatelessExecutionLayer::new(
        config,
        proof_rx,
        proof_tx.clone(),
        rpc_request_tx,
        context.log.clone(),
    );
    Some(Arc::new(el))
} else {
    None
};

// Create ExecutionLayer with appropriate backend
let execution_layer = if let Some(sel) = stateless_el.clone() {
    ExecutionLayer::new_stateless(sel, context.log.clone())
} else {
    ExecutionLayer::new_full(client_config.execution_endpoint, /* ... */)
};

// Pass stateless-EL to DA checker
let da_checker = DataAvailabilityChecker::new(
    /* ... existing params */,
    stateless_el.clone(),
)?;

// Register callback from stateless-EL to DA checker
if let Some(sel) = &stateless_el {
    let da_checker_clone = da_checker.clone();
    sel.register_proof_ready_callback(Arc::new(move |block_hash| {
        da_checker_clone.on_execution_proofs_ready(block_hash);
    }));
}

// Pass proof channel sender to network router
network_router.set_stateless_el_proof_tx(proof_tx);

// Spawn task to handle RPC requests from stateless-EL
spawn_rpc_request_handler(rpc_request_rx, network_globals.clone());
```

### 5. ENR Advertisement

In `beacon_node/lighthouse_network/src/discovery/enr.rs`, add execution proof subnet advertisement:

```rust
pub const EXECUTION_PROOF_SUBNETS_ENR_KEY: &str = "exproofs";

impl EnrBuilder {
    pub fn build_execution_proof_subnets(&mut self, subnets: &HashSet<ExecutionProofSubnetId>) {
        // Encode as bitfield (8 bits for 8 subnets)
        let mut bitfield: u8 = 0;
        for subnet_id in subnets {
            bitfield |= 1 << subnet_id.as_u8();
        }

        self.enr.insert(
            EXECUTION_PROOF_SUBNETS_ENR_KEY,
            &bitfield.to_be_bytes(),
        );
    }
}

impl EnrExt for Enr {
    fn execution_proof_subnets(&self) -> Option<HashSet<ExecutionProofSubnetId>> {
        let bytes = self.get(EXECUTION_PROOF_SUBNETS_ENR_KEY)?;
        let bitfield = u8::from_be_bytes([bytes[0]]);

        let mut subnets = HashSet::new();
        for i in 0..8 {
            if bitfield & (1 << i) != 0 {
                subnets.insert(ExecutionProofSubnetId::new(i).ok()?);
            }
        }

        Some(subnets)
    }
}
```

In peer manager, track execution proof capabilities:

```rust
// beacon_node/lighthouse_network/src/peer_manager/peerdb.rs

pub struct PeerInfo {
    /// Execution proof subnets this peer supports
    pub execution_proof_subnets: HashSet<ExecutionProofSubnetId>,
    // ... existing fields
}

// When peer discovered or metadata received:
impl PeerManager {
    fn handle_peer_metadata(&mut self, peer_id: PeerId, enr: &Enr) {
        if let Some(subnets) = enr.execution_proof_subnets() {
            if let Some(peer_info) = self.peers.get_mut(&peer_id) {
                peer_info.execution_proof_subnets = subnets;
            }
        }
    }
}
```

### 6. CLI Configuration

In `beacon_node/src/cli.rs`, add new flags:

```rust
pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("beacon_node")
        // ... existing flags
        .arg(
            Arg::with_name("stateless-execution-layer")
                .long("stateless-execution-layer")
                .help("Use stateless execution layer instead of full execution client")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("verify-execution-proof-subnets")
                .long("verify-execution-proof-subnets")
                .value_name("SUBNETS")
                .help("Comma-separated list of execution proof subnets to verify (0-7)")
                .takes_value(true)
                .requires("stateless-execution-layer")
        )
        .arg(
            Arg::with_name("min-proofs-required")
                .long("min-proofs-required")
                .value_name("COUNT")
                .help("Minimum number of proofs required from different subnets")
                .takes_value(true)
                .default_value("1")
                .requires("stateless-execution-layer")
        )
        .arg(
            Arg::with_name("generate-execution-proofs")
                .long("generate-execution-proofs")
                .value_name("SUBNETS")
                .help("Comma-separated list of subnets to generate proofs for (0-7)")
                .takes_value(true)
                .requires("stateless-execution-layer")
        )
}
```

In `beacon_node/src/config.rs`, parse these into `ChainConfig`:

```rust
pub struct ChainConfig {
    /// Enable stateless execution layer
    pub stateless_execution_layer: bool,

    /// Which subnets to verify proofs from
    pub verify_execution_proof_subnets: HashSet<ExecutionProofSubnetId>,

    /// Minimum proofs required from different subnets
    pub min_proofs_required: usize,

    /// Which subnets to generate proofs for (empty if not generating)
    pub generate_execution_proof_subnets: HashSet<ExecutionProofSubnetId>,

    // ... existing fields
}
```

## Code Removal and Simplification

With this new architecture, the following files from the current execution proofs implementation can be **removed**:

- ❌ `beacon_node/beacon_chain/src/execution_proof_generation.rs` → replaced by stateless-EL crate
- ❌ `beacon_node/beacon_chain/src/execution_proof_verification.rs` → replaced by stateless-EL crate
- ❌ `beacon_node/beacon_chain/src/execution_proof_network.rs` → replaced by stateless-EL crate
- ❌ Execution proof tracking in `data_availability_checker/overflow_lru_cache.rs` → replaced by stateless-EL query interface

The following can be **kept and reused**:

- ✅ `consensus/types/src/execution_proof.rs` - Core ExecutionProof type
- ✅ `consensus/types/src/execution_proof_subnet_id.rs` - ExecutionProofSubnetId type
- ✅ Gossip topic definitions in `lighthouse_network/src/types/topics.rs`
- ✅ PubsubMessage variant in `lighthouse_network/src/types/pubsub.rs`

## Implementation Phases

### Phase 1: Core Stateless-EL Crate (Foundation)

**Goal:** Create the stateless-EL crate with basic structure and dummy implementations.

**Tasks:**
1. Create `stateless_execution_layer/` crate with basic structure
2. Implement `StatelessExecutionLayer` struct with core fields
3. Implement `ProofVerifier` and `ProofGenerator` traits
4. Create `DummyVerifier` and `DummyGenerator` implementations (simulate delay, return success)
5. Implement proof cache with LRU eviction
6. Implement basic `new_payload()` method with proof checking logic
7. Add configuration struct and parsing
8. Write unit tests for core logic

**Deliverables:**
- Working stateless-EL crate that can be imported
- Basic Engine API implementation (dummy proofs)
- Unit tests passing

### Phase 2: Network Integration

**Goal:** Wire up stateless-EL to the network layer for proof gossip.

**Tasks:**
1. Modify `ExecutionLayer` to support `ExecutionBackend` enum
2. Add channels for proof forwarding (network → stateless-EL)
3. Modify router to send execution proof gossip to stateless-EL
4. Implement proof reception in stateless-EL (`on_gossip_proof_received`)
5. Implement proof publishing (stateless-EL → network)
6. Add ENR field for execution proof subnets
7. Update peer manager to track execution proof capabilities
8. Add CLI flags and configuration parsing
9. Wire up initialization in `beacon_node/src/lib.rs`

**Deliverables:**
- Beacon node can start with `--stateless-execution-layer`
- Proofs flow from gossip to stateless-EL
- Generated proofs published to gossip
- ENR advertises participation

### Phase 3: Data Availability Integration

**Goal:** Coordinate proof availability with the DA checker.

**Tasks:**
1. Add `stateless_el: Option<Arc<StatelessExecutionLayer>>` to DA checker
2. Implement `has_required_proofs()` query method
3. Modify `check_availability()` to consider execution proofs
4. Implement callback mechanism (stateless-EL → DA checker)
5. Handle `on_execution_proofs_ready()` in DA checker
6. Test availability logic with missing/arriving proofs

**Deliverables:**
- Blocks wait for proofs before import
- DA checker coordinates blob + proof availability
- Callbacks trigger availability re-checks

### Phase 4: RPC Proof Fetching

**Goal:** Add resilience by fetching missing proofs via RPC.

**Tasks:**
1. Add `ExecutionProofsByRoot` RPC method
2. Implement RPC request channel (stateless-EL → network)
3. Implement `request_missing_proofs()` with gossip grace period
4. Add RPC handler to serve proofs from local cache
5. Add peer selection logic (prefer peers with matching subnets in ENR)
6. Add timeout and retry logic
7. Test RPC fallback when gossip fails

**Deliverables:**
- Stateless-EL actively fetches missing proofs
- RPC fallback works when gossip fails
- Robust against peer withholding

### Phase 5: Real zkVM Integration (Future)

**Goal:** Replace dummy implementations with real zkVM proof generation/verification.

**Tasks:**
1. Implement `RiscZeroVerifier` using RISC Zero SDK
2. Implement `RiscZeroGenerator` using RISC Zero SDK
3. Fetch execution witness from EL via `debug_executionWitness`
4. Implement zkVM guest program for execution verification
5. Optimize proof size (compression, recursion)
6. Add metrics for generation/verification performance
7. Benchmark and optimize hot paths

**Deliverables:**
- Real cryptographic proofs
- Integration with RISC Zero or SP1
- Production-ready performance

### Phase 6: Testing and Hardening

**Goal:** Comprehensive testing and production readiness.

**Tasks:**
1. Unit tests for all stateless-EL components
2. Integration tests with BeaconChainHarness
3. Multi-node testnet with proof generation and stateless validation
4. Byzantine proof testing (invalid proofs, proof withholding)
5. Performance benchmarks
6. Security audit
7. Documentation

**Deliverables:**
- Comprehensive test coverage
- Multi-node testnet working
- Documentation complete
- Ready for mainnet consideration

## Example Usage Scenarios

### Scenario 1: Proof Generator Node

```bash
# Node with full EL that generates RISC Zero proofs (subnet 0)
lighthouse bn \
  --execution-endpoint http://localhost:8551 \
  --stateless-execution-layer \
  --generate-execution-proofs=0
```

**Behavior:**
- Runs full EL for normal execution
- Also generates RISC Zero proofs for locally built blocks
- Publishes proofs to gossip subnet 0
- Other stateless nodes can use these proofs

### Scenario 2: Stateless Validator (Single Proof System)

```bash
# Stateless node that only verifies RISC Zero proofs
lighthouse bn \
  --stateless-execution-layer \
  --verify-execution-proof-subnets=0 \
  --min-proofs-required=1
```

**Behavior:**
- No full EL required
- Subscribes to execution proof gossip subnet 0
- Validates blocks using RISC Zero proofs
- Lower resource requirements than full node

### Scenario 3: Stateless Validator (Multi-Proof Security)

```bash
# Stateless node requiring proofs from 2 different zkVMs
lighthouse bn \
  --stateless-execution-layer \
  --verify-execution-proof-subnets=0,1,2,3 \
  --min-proofs-required=2
```

**Behavior:**
- Subscribes to 4 proof subnets (RISC Zero, SP1, and 2 others)
- Requires proofs from at least 2 different systems
- Higher security through diversity
- More bandwidth usage

### Scenario 4: Hybrid Node (Generate + Verify)

```bash
# Node that generates RISC Zero proofs and verifies multiple systems
lighthouse bn \
  --stateless-execution-layer \
  --generate-execution-proofs=0 \
  --verify-execution-proof-subnets=0,1 \
  --min-proofs-required=2
```

**Behavior:**
- Generates RISC Zero proofs for its blocks
- Also verifies both RISC Zero and SP1 proofs
- Contributes to proof diversity
- High resource usage

## Key Invariants and Assumptions

### Invariants

1. **A block is only available when both blobs AND proofs are present** (if using stateless-EL)
2. **Proofs from M different subnets are required** (configurable M)
3. **Each subnet represents a distinct proof system** (different zkVM)
4. **Stateless-EL never blocks the CL** - returns SYNCING immediately if proofs missing
5. **Proof generation is asynchronous** - doesn't block block import

### Assumptions

1. **At least one zkVM/proof system is sound** (cryptographic assumption)
2. **Sufficient honest nodes generate proofs** (liveness assumption)
3. **Execution witness data is available from EL** (for proof generation)
4. **Gossip delivers proofs within reasonable time** (~200ms) or RPC fallback works
5. **Proof verification is deterministic** - same proof always produces same result

## Security Considerations

### Attack Vectors and Mitigations

1. **Invalid Proof DoS**
   - Attack: Flood network with invalid proofs
   - Mitigation: Rate limiting, peer scoring, early structural validation

2. **Proof Withholding**
   - Attack: Validators don't publish generated proofs
   - Mitigation: Monitor proof availability, peer scoring, RPC fallback

3. **Single zkVM Compromise**
   - Attack: One proof system is broken (unsound)
   - Mitigation: Require M-of-N proofs from different systems, diversity

4. **Replay Attacks**
   - Attack: Reuse old proofs for new blocks
   - Mitigation: Proof includes block_root and block_hash, strict validation

5. **Proof Verification DoS**
   - Attack: Send proofs that are expensive to verify
   - Mitigation: Timeout verification, rate limiting, structural pre-checks

### Trust Assumptions

- **Cryptographic**: At least M of N zkVM proof systems are sound
- **Liveness**: Sufficient honest nodes generate and distribute proofs
- **Network**: Gossip or RPC can deliver proofs within reasonable time
- **Execution**: Witness data from EL is correct and available

## Performance Targets

### Proof Generation (Real zkVMs)

- **Target**: 10-60 seconds per block (zkVM dependent)
- **Parallelization**: Multiple proofs generated concurrently
- **Resource**: High CPU/memory during generation

### Proof Verification

- **Target**: 1-10 seconds per proof
- **Parallelization**: Verify multiple proofs concurrently
- **Early exit**: Stop after M valid proofs

### Proof Size

- **Current (dummy)**: ~100 bytes
- **Target (real)**: 100KB - 1MB (with compression)
- **Optimization**: Proof compression, recursion, aggregation

### Network Overhead

- **Gossip bandwidth**: ~1-8 MB per block (1 proof per subnet)
- **RPC fallback**: Occasional, not常态
- **Subscription strategy**: Subscribe to N > M subnets for redundancy

## Open Questions and Future Work

### Research Questions

1. **Optimal M-of-N parameters**: How many proofs needed for security vs. performance?
2. **Subnet allocation**: How to assign zkVM systems to subnets? Governance?
3. **Proof versioning**: How to handle zkVM upgrades without breaking compatibility?
4. **Economic incentives**: Should proof generators be rewarded? How?
5. **Proof aggregation**: Can multiple proofs be aggregated for efficiency?

### Future Enhancements

1. **Proof Compression**: Apply zstd/snappy compression to proof data
2. **Batch Verification**: Verify multiple proofs in one zkVM call
3. **Proof Caching**: Long-term storage of proofs for historical sync
4. **Dynamic Subscription**: Adjust subnet subscriptions based on peer availability
5. **Proof Marketplace**: Economic layer for proof generation incentives
6. **Hybrid Mode**: Use proofs for old blocks, full EL for recent blocks
7. **Checkpoint Sync with Proofs**: Sync from checkpoint using only proofs

## References

### Code Patterns

- **Blob Verification**: Similar gossip verification pattern
- **Data Column Verification**: Similar M-of-N availability pattern
- **Engine API**: Standard interface for execution engines

### Specifications

- **Engine API**: https://github.com/ethereum/execution-apis/tree/main/src/engine
- **RISC Zero**: https://dev.risczero.com/
- **SP1**: https://docs.succinct.xyz/

### Related Work

- **Ethereum Stateless Validation**: Research on witness formats and proof systems
- **PeerDAS**: Similar subnet-based gossip architecture

---

**Document Status**: Design specification for implementation
**Target Version**: Lighthouse post-current-implementation (fresh branch)
**Last Updated**: 2025-10-14
