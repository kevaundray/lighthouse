# ExecutionProofs Implementation Milestones

A step-by-step implementation plan for adding ExecutionProofs support to Ethereum consensus clients, with testable milestones using Kurtosis.

## Overview

This implementation plan breaks down ExecutionProofs into 6 major milestones, each building on the previous one and providing a testable checkpoint. Each milestone can be validated using Kurtosis to ensure the implementation is working correctly before proceeding.

## Milestone 1: Core Data Types and Foundations

### Duration: 1-2 weeks

### Scope
Implement the basic data structures and type definitions without any network or verification logic.

### Deliverables

#### 1.1 Core Type Definitions
```rust
// consensus/types/src/execution_proof.rs
#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct ExecutionProof {
    #[serde(with = "serde_utils::quoted_u8")]
    pub version: u8,
    #[serde(with = "serde_utils::hex_vec")]
    pub data: Vec<u8>,
}

impl ExecutionProof {
    pub fn new(version: u8, data: Vec<u8>) -> Self {
        Self { version, data }
    }
    
    pub fn mock_sp1_proof(payload_hash: Hash256) -> Self {
        Self::new(0, payload_hash.as_bytes().to_vec())
    }
    
    pub fn mock_risc0_proof(payload_hash: Hash256) -> Self {
        Self::new(1, payload_hash.as_bytes().to_vec())
    }
    
    pub fn mock_execution_witness(payload_hash: Hash256) -> Self {
        Self::new(2, payload_hash.as_bytes().to_vec())
    }
}
```

#### 1.2 Proof Subnet IDs
```rust
// consensus/types/src/proof_subnet_id.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofSubnetId(u8);

impl ProofSubnetId {
    pub const PROOF_SUBNET_COUNT: usize = 8;
    
    pub fn new(id: u8) -> Result<Self, String> {
        if id < Self::PROOF_SUBNET_COUNT as u8 {
            Ok(Self(id))
        } else {
            Err(format!("Invalid proof subnet ID: {}", id))
        }
    }
    
    pub fn as_u8(&self) -> u8 { self.0 }
    pub fn sp1() -> Self { Self(0) }
    pub fn risc0() -> Self { Self(1) }
    pub fn execution_witness() -> Self { Self(2) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofType {
    SP1Proof = 0,
    Risc0Proof = 1,
    ExecutionWitness = 2,
}

impl ProofType {
    pub fn subnet_id(&self) -> ProofSubnetId {
        ProofSubnetId(*self as u8)
    }
}
```

#### 1.3 Basic Configuration
```rust
// beacon_node/beacon_chain/src/proof_config.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofConfig {
    pub enabled: bool,
    pub optimistic_acceptance: bool,
    pub fallback_to_execution: bool,
    pub verification_timeout_ms: u64,
    pub max_cache_size: usize,
    pub cache_ttl_seconds: u64,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            enabled: false,  // Start disabled
            optimistic_acceptance: true,
            fallback_to_execution: true,
            verification_timeout_ms: 5000,
            max_cache_size: 1000,
            cache_ttl_seconds: 300,
        }
    }
}
```

### Testing with Kurtosis

#### Test Scenario 1.1: Type Serialization
```yaml
# kurtosis-config/milestone1/test-types.yaml
participants:
  - el_type: geth
    el_image: ethereum/client-go:latest
    cl_type: lighthouse
    cl_image: sigp/lighthouse:latest
    count: 2

network_params:
  network_id: "3151908"
  deposit_contract_address: "0x4242424242424242424242424242424242424242"
  seconds_per_slot: 12
  slots_per_epoch: 32
```

**Test Commands:**
```bash
# Test 1: Verify ExecutionProof SSZ encoding/decoding
kurtosis run github.com/ethpandaops/ethereum-package --args-file milestone1/test-types.yaml

# Inside the enclave, test proof serialization
lighthouse --datadir /data/lighthouse \
  --network custom \
  test-utils execution-proof-serialization \
  --proof-type sp1 \
  --payload-hash 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

# Expected: Successfully serialize and deserialize ExecutionProof
# Expected: Proof subnet ID mappings work correctly
# Expected: Type conversions are working
```

#### Test Scenario 1.2: Configuration Loading
```bash
# Test 2: Verify configuration parsing
lighthouse beacon_node \
  --datadir /data/lighthouse \
  --network custom \
  --execution-proofs-enabled false \
  --execution-proofs-optimistic-acceptance true \
  --execution-proofs-fallback-to-execution true \
  --testnet-dir /data/custom-testnet \
  --config-file /data/proof-config.yaml

# Expected: Configuration loads without errors
# Expected: Default values are applied correctly
# Expected: CLI overrides work
```

### Success Criteria
- [ ] All ExecutionProof types serialize/deserialize correctly
- [ ] ProofSubnetId mapping functions work
- [ ] Configuration system loads without errors
- [ ] Unit tests pass for all new types
- [ ] Integration with existing SSZ types works
- [ ] Kurtosis can start nodes with ExecutionProofs types available

---

## Milestone 2: Network Layer - Gossip Topics

### Duration: 2-3 weeks

### Scope
Add gossip topic support for ExecutionProofs without verification logic.

### Deliverables

#### 2.1 Gossip Topic Integration
```rust
// beacon_node/lighthouse_network/src/types/topics.rs
pub fn execution_proof_topic(
    fork_digest: [u8; 4], 
    subnet_id: ProofSubnetId, 
    spec: &ChainSpec
) -> String {
    format!(
        "/eth2/{}/execution_proof_{}/ssz_snappy",
        hex::encode(fork_digest),
        subnet_id.as_u8()
    )
}

pub fn execution_proof_topic_name(subnet_id: ProofSubnetId) -> String {
    format!("execution_proof_{}", subnet_id.as_u8())
}
```

#### 2.2 PubSub Message Support
```rust
// beacon_node/lighthouse_network/src/types/pubsub.rs
#[derive(Debug, Clone, PartialEq)]
pub enum PubsubMessage<E: EthSpec> {
    // ... existing variants
    ExecutionProof(Box<(ProofSubnetId, ExecutionProof)>),
}

impl<E: EthSpec> PubsubMessage<E> {
    pub fn decode(topic: &TopicHash, data: &[u8], spec: &ChainSpec) -> Result<Self, String> {
        // Add ExecutionProof decoding logic
        if let Some(subnet_id) = extract_execution_proof_subnet(topic, spec) {
            let proof = ExecutionProof::from_ssz_bytes(data)
                .map_err(|e| format!("Failed to decode ExecutionProof: {}", e))?;
            return Ok(PubsubMessage::ExecutionProof(Box::new((subnet_id, proof))));
        }
        // ... existing logic
    }
}
```

#### 2.3 Subnet Management
```rust
// beacon_node/lighthouse_network/src/types/subnet.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Subnet {
    Attestation(AttestationSubnetId),
    SyncCommittee(SyncSubnetId),
    Proof(ProofSubnetId),  // New variant
}

impl Subnet {
    pub fn proof_subnets() -> impl Iterator<Item = Subnet> {
        (0..ProofSubnetId::PROOF_SUBNET_COUNT)
            .map(|i| Subnet::Proof(ProofSubnetId::new(i as u8).unwrap()))
    }
}
```

#### 2.4 ENR Metadata Support
```rust
// beacon_node/lighthouse_network/src/discovery/enr.rs
pub fn update_enr_proof_subnets(
    enr: &mut Enr<CombinedKey>,
    proof_subnets: &BitVec<u8>,
    log: &Logger,
) -> Result<(), String> {
    let proofnets_bytes = proof_subnets.clone().into_vec();
    enr.insert(PROOFNETS_ENR_KEY, &proofnets_bytes)
        .map_err(|e| format!("Failed to update ENR proof subnets: {}", e))?;
    Ok(())
}
```

### Testing with Kurtosis

#### Test Scenario 2.1: Topic Registration
```yaml
# kurtosis-config/milestone2/test-gossip.yaml
participants:
  - el_type: geth
    cl_type: lighthouse
    count: 3
    
network_params:
  seconds_per_slot: 12
  slots_per_epoch: 32

additional_services:
  - prometheus_grafana
  - tx_spammer
```

**Test Commands:**
```bash
# Test 1: Verify gossip topic registration
kurtosis run github.com/ethpandaops/ethereum-package --args-file milestone2/test-gossip.yaml

# Inside the enclave, verify topics are registered
curl -s http://lighthouse-node-0:5052/lighthouse/health | jq '.network_libp2p'

# Expected: execution_proof_0, execution_proof_1, execution_proof_2 topics registered
# Expected: ENR contains proofnets field
# Expected: Peer discovery includes proof subnet information
```

#### Test Scenario 2.2: Message Encoding/Decoding
```bash
# Test 2: Test message publication without verification
lighthouse debug execution-proof \
  --network-dir /data/custom-testnet \
  --datadir /data/lighthouse \
  publish-mock-proof \
  --proof-type sp1 \
  --payload-hash 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
  --target-peers 2

# Expected: Mock proof published to subnet 0
# Expected: Other nodes receive and decode the proof message
# Expected: No verification occurs (just message passing)
```

#### Test Scenario 2.3: Subnet Subscription
```bash
# Test 3: Verify subnet subscription behavior
lighthouse beacon_node \
  --datadir /data/lighthouse \
  --network custom \
  --execution-proofs-enabled true \
  --execution-proofs-subscribe-subnets 0,1,2 \
  --metrics \
  --metrics-address 0.0.0.0

# Check metrics for subnet subscriptions
curl -s http://lighthouse-node-0:5054/metrics | grep "proof_subnet_subscription"

# Expected: Metrics show subscriptions to proof subnets 0, 1, 2
# Expected: Peer count includes proof subnet peers
```

### Success Criteria
- [ ] ExecutionProof gossip topics are registered correctly
- [ ] Messages can be published and received across the network
- [ ] ENR metadata includes proof subnet information
- [ ] Peers can discover each other based on proof subnet subscriptions
- [ ] Message encoding/decoding works properly
- [ ] Network metrics show proof-related gossip activity
- [ ] No verification logic is triggered (messages are just passed through)

---

## Milestone 3: Proof Cache and Basic Verification Interface

### Duration: 2-3 weeks

### Scope
Implement the proof caching system and verification interfaces with mock implementations.

### Deliverables

#### 3.1 ExecutionProof Cache
```rust
// beacon_node/beacon_chain/src/execution_proof_cache.rs
pub struct ExecutionProofCache<E: EthSpec> {
    cache: Arc<TimeoutRwLock<LruCache<Hash256, CachedProof>>>,
    verifiers: ProofVerifierRegistry,
    config: ProofConfig,
}

#[derive(Debug, Clone)]
pub struct CachedProof {
    pub proof: ExecutionProof,
    pub is_valid: bool,
    pub timestamp: Instant,
    pub verification_time_ms: u64,
}

impl<E: EthSpec> ExecutionProofCache<E> {
    pub fn new(config: ProofConfig) -> Self {
        Self {
            cache: Arc::new(TimeoutRwLock::new(
                LruCache::new(NonZeroUsize::new(config.max_cache_size).unwrap()),
                Duration::from_secs(config.cache_ttl_seconds),
            )),
            verifiers: ProofVerifierRegistry::new(),
            config,
        }
    }
    
    pub async fn cache_proof(&self, payload_hash: Hash256, proof: ExecutionProof) {
        let cached = CachedProof {
            proof: proof.clone(),
            is_valid: false,  // Will be verified later
            timestamp: Instant::now(),
            verification_time_ms: 0,
        };
        self.cache.write().await.put(payload_hash, cached);
    }
    
    pub async fn get_proof(&self, payload_hash: &Hash256) -> Option<CachedProof> {
        self.cache.read().await.get(payload_hash).cloned()
    }
    
    pub async fn verify_proof(&self, payload_hash: Hash256, proof: &ExecutionProof) -> Result<bool, ProofError> {
        let start_time = Instant::now();
        
        // Mock verification for now
        let is_valid = self.mock_verify_proof(proof).await?;
        
        // Update cache with verification result
        if let Some(mut cached) = self.cache.write().await.get_mut(&payload_hash) {
            cached.is_valid = is_valid;
            cached.verification_time_ms = start_time.elapsed().as_millis() as u64;
        }
        
        Ok(is_valid)
    }
    
    async fn mock_verify_proof(&self, proof: &ExecutionProof) -> Result<bool, ProofError> {
        // Mock verification - always succeed for valid-looking proofs
        tokio::time::sleep(Duration::from_millis(10)).await;  // Simulate verification time
        Ok(proof.data.len() >= 32)  // Simple mock validation
    }
}
```

#### 3.2 Global Cache Instance
```rust
// Global singleton for easy access
pub struct GlobalExecutionProofCache;

impl GlobalExecutionProofCache {
    pub fn instance() -> &'static ExecutionProofCache<MainnetEthSpec> {
        static INSTANCE: OnceLock<ExecutionProofCache<MainnetEthSpec>> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            ExecutionProofCache::new(ProofConfig::default())
        })
    }
    
    pub async fn cache_proof(payload_hash: Hash256, proof: ExecutionProof) {
        Self::instance().cache_proof(payload_hash, proof).await;
    }
    
    pub async fn get_verification_result(payload_hash: &Hash256) -> Option<bool> {
        Self::instance().get_proof(payload_hash).await.map(|p| p.is_valid)
    }
}
```

#### 3.3 Proof Verifier Interface
```rust
#[async_trait]
pub trait ProofVerifier: Send + Sync {
    async fn verify(&self, proof: &ExecutionProof) -> Result<bool, ProofError>;
    fn extract_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, ProofError>;
    fn proof_type(&self) -> ProofType;
    fn version(&self) -> u8;
}

// Mock implementations for testing
pub struct MockSP1Verifier;

#[async_trait]
impl ProofVerifier for MockSP1Verifier {
    async fn verify(&self, proof: &ExecutionProof) -> Result<bool, ProofError> {
        // Mock SP1 verification - check basic structure
        if proof.version != 0 {
            return Err(ProofError::UnsupportedVersion(proof.version));
        }
        if proof.data.len() < 32 {
            return Err(ProofError::InvalidProofData);
        }
        
        // Simulate verification delay
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(true)
    }
    
    fn extract_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, ProofError> {
        if proof.data.len() < 32 {
            return Err(ProofError::InvalidProofData);
        }
        Ok(Hash256::from_slice(&proof.data[0..32]))
    }
    
    fn proof_type(&self) -> ProofType { ProofType::SP1Proof }
    fn version(&self) -> u8 { 0 }
}
```

#### 3.4 Network Message Processing
```rust
// beacon_node/network/src/network_beacon_processor/gossip_methods.rs
impl<T: BeaconChainTypes> NetworkBeaconProcessor<T> {
    pub async fn process_execution_proof(
        &self,
        subnet_id: ProofSubnetId,
        proof: ExecutionProof,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        // Extract payload hash from proof
        let payload_hash = self.extract_payload_hash_from_proof(&proof).await?;
        
        // Cache the proof
        GlobalExecutionProofCache::cache_proof(payload_hash, proof.clone()).await;
        
        // If we have a pending payload for this hash, trigger verification
        if let Some(pending_payload) = self.get_pending_payload(&payload_hash).await {
            self.trigger_payload_verification(payload_hash, proof).await?;
        }
        
        // Propagate to peers (if not duplicate)
        self.propagate_execution_proof(subnet_id, proof, peer_id).await?;
        
        Ok(())
    }
    
    async fn extract_payload_hash_from_proof(&self, proof: &ExecutionProof) -> Result<Hash256, Error> {
        // For now, extract from the proof data directly (mock)
        if proof.data.len() >= 32 {
            Ok(Hash256::from_slice(&proof.data[0..32]))
        } else {
            Err(Error::InvalidProofData)
        }
    }
}
```

### Testing with Kurtosis

#### Test Scenario 3.1: Cache Functionality
```yaml
# kurtosis-config/milestone3/test-cache.yaml
participants:
  - el_type: geth
    cl_type: lighthouse
    count: 3

snooper_enabled: true
```

**Test Commands:**
```bash
# Test 1: Cache basic operations
kurtosis run github.com/ethpandaops/ethereum-package --args-file milestone3/test-cache.yaml

# Test cache operations via debug API
curl -X POST http://lighthouse-node-0:5052/lighthouse/debug/execution_proof/cache \
  -H "Content-Type: application/json" \
  -d '{
    "payload_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "proof": {
      "version": 0,
      "data": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    }
  }'

# Verify proof is cached
curl http://lighthouse-node-0:5052/lighthouse/debug/execution_proof/cache/0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

# Expected: Proof is stored and retrievable from cache
# Expected: Cache metrics show hits/misses
# Expected: TTL expiration works correctly
```

#### Test Scenario 3.2: Mock Verification
```bash
# Test 2: Mock proof verification
curl -X POST http://lighthouse-node-0:5052/lighthouse/debug/execution_proof/verify \
  -H "Content-Type: application/json" \
  -d '{
    "payload_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "proof": {
      "version": 0,
      "data": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef0000000000000000"
    }
  }'

# Expected: Mock verification succeeds
# Expected: Verification time is recorded
# Expected: Cache is updated with verification result
```

#### Test Scenario 3.3: Network Message Processing
```bash
# Test 3: End-to-end message processing
lighthouse debug execution-proof \
  --network-dir /data/custom-testnet \
  --datadir /data/lighthouse \
  publish-proof \
  --proof-type sp1 \
  --payload-hash 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
  --proof-data 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef0000000000000000

# Wait for propagation and check all nodes received it
for i in {0..2}; do
  echo "Checking node $i:"
  curl http://lighthouse-node-$i:5052/lighthouse/debug/execution_proof/cache/0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
done

# Expected: All nodes have the proof in cache
# Expected: Proof verification status is consistent across nodes
# Expected: Network metrics show successful propagation
```

### Success Criteria
- [ ] Proof cache stores and retrieves proofs correctly
- [ ] TTL expiration removes old proofs from cache
- [ ] Mock verification interface works
- [ ] Network messages are processed and cached
- [ ] Global cache singleton is accessible
- [ ] Metrics show cache hits, misses, and verification times
- [ ] Proof propagation works across all nodes in the network

---

## Milestone 4: Payload Verification Integration

### Duration: 3-4 weeks

### Scope
Integrate ExecutionProofs with the existing payload verification system, supporting optimistic acceptance and fallback mechanisms.

### Deliverables

#### 4.1 Enhanced Payload Verification
```rust
// beacon_node/beacon_chain/src/execution_payload.rs
pub async fn verify_and_notify_new_payload_with_proofs<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    payload: &ExecutionPayload<T::EthSpec>,
    // ... other existing parameters
) -> Result<PayloadVerificationStatus, ExecutionPayloadError> {
    let payload_hash = payload.block_hash();
    
    // If ExecutionProofs are enabled, try proof-based verification first
    if chain.config.proof_config.enabled {
        match try_proof_verification(chain, &payload_hash).await {
            Ok(PayloadVerificationStatus::Verified) => {
                info!(chain.log, "Payload verified via ExecutionProof"; "hash" => %payload_hash);
                return Ok(PayloadVerificationStatus::Verified);
            }
            Ok(PayloadVerificationStatus::Invalid) => {
                warn!(chain.log, "Payload invalid via ExecutionProof"; "hash" => %payload_hash);
                return Err(ExecutionPayloadError::InvalidProof);
            }
            Err(ProofError::ProofNotAvailable) => {
                // Handle based on configuration
                if chain.config.proof_config.optimistic_acceptance {
                    info!(chain.log, "Accepting payload optimistically, proof not available"; "hash" => %payload_hash);
                    spawn_async_proof_validation(chain.clone(), payload_hash);
                    return Ok(PayloadVerificationStatus::Optimistic);
                } else if chain.config.proof_config.fallback_to_execution {
                    info!(chain.log, "Falling back to EL verification"; "hash" => %payload_hash);
                    // Continue to EL verification below
                } else {
                    return Err(ExecutionPayloadError::ProofRequired);
                }
            }
            Err(e) => {
                warn!(chain.log, "Proof verification error"; "error" => %e, "hash" => %payload_hash);
                if chain.config.proof_config.fallback_to_execution {
                    // Continue to EL verification
                } else {
                    return Err(e.into());
                }
            }
        }
    }
    
    // Standard EL verification (existing logic)
    verify_and_notify_new_payload_el_only(chain, payload).await
}

async fn try_proof_verification<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    payload_hash: &Hash256,
) -> Result<PayloadVerificationStatus, ProofError> {
    let cache = GlobalExecutionProofCache::instance();
    
    // Check if we have a cached verification result
    if let Some(cached_result) = cache.get_verification_result(payload_hash).await {
        return Ok(if cached_result {
            PayloadVerificationStatus::Verified
        } else {
            PayloadVerificationStatus::Invalid
        });
    }
    
    // Check if we have the proof but haven't verified it yet
    if let Some(cached_proof) = cache.get_proof(payload_hash).await {
        let is_valid = cache.verify_proof(*payload_hash, &cached_proof.proof).await?;
        return Ok(if is_valid {
            PayloadVerificationStatus::Verified
        } else {
            PayloadVerificationStatus::Invalid
        });
    }
    
    // No proof available
    Err(ProofError::ProofNotAvailable)
}

fn spawn_async_proof_validation<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    payload_hash: Hash256,
) {
    let chain_clone = chain.clone();
    tokio::spawn(async move {
        let timeout = Duration::from_millis(chain_clone.config.proof_config.verification_timeout_ms);
        
        // Wait for proof to arrive
        let result = tokio::time::timeout(timeout, async {
            loop {
                if let Some(cached_result) = GlobalExecutionProofCache::instance()
                    .get_verification_result(&payload_hash).await 
                {
                    return Ok(cached_result);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await;
        
        match result {
            Ok(Ok(true)) => {
                info!(chain_clone.log, "Async proof verification succeeded"; "hash" => %payload_hash);
                // Update fork choice to mark as verified
                if let Err(e) = update_payload_status_to_verified(&chain_clone, payload_hash).await {
                    warn!(chain_clone.log, "Failed to update payload status"; "error" => %e);
                }
            }
            Ok(Ok(false)) => {
                warn!(chain_clone.log, "Async proof verification failed"; "hash" => %payload_hash);
                // Trigger invalidation
                if let Err(e) = invalidate_payload(&chain_clone, payload_hash).await {
                    warn!(chain_clone.log, "Failed to invalidate payload"; "error" => %e);
                }
            }
            Err(_) => {
                warn!(chain_clone.log, "Async proof verification timeout"; "hash" => %payload_hash);
                // Continue with optimistic status, no action needed
            }
            Ok(Err(e)) => {
                warn!(chain_clone.log, "Async proof verification error"; "error" => %e);
            }
        }
    });
}
```

#### 4.2 Fork Choice Integration
```rust
// Integration with existing fork choice for status transitions
async fn update_payload_status_to_verified<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    payload_hash: Hash256,
) -> Result<(), Error> {
    // Find the block with this payload hash
    if let Some(block_root) = chain.store.get_block_root_by_execution_hash(&payload_hash).await? {
        // Update fork choice to mark as verified
        chain.fork_choice.write().on_payload_verified(block_root)?;
        
        // Trigger any pending attestations or other operations
        chain.recompute_head_at_current_slot().await?;
    }
    
    Ok(())
}

async fn invalidate_payload<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    payload_hash: Hash256,
) -> Result<(), Error> {
    // Find and invalidate the block
    if let Some(block_root) = chain.store.get_block_root_by_execution_hash(&payload_hash).await? {
        let invalid_ancestor = InvalidationOperation::InvalidateOne { block_root };
        chain.fork_choice.write().on_invalid_execution_payload(invalid_ancestor)?;
        
        // Trigger re-org if this was on the canonical chain
        chain.recompute_head_at_current_slot().await?;
    }
    
    Ok(())
}
```

#### 4.3 Configuration Integration
```rust
// beacon_node/beacon_chain/src/builder.rs
impl<T: BeaconChainTypes> BeaconChainBuilder<T> {
    pub fn proof_config(mut self, config: ProofConfig) -> Self {
        self.proof_config = Some(config);
        self
    }
}

// CLI integration
impl TryFrom<&ArgMatches> for BeaconChainConfig {
    fn try_from(matches: &ArgMatches) -> Result<Self, String> {
        // ... existing configuration
        
        let proof_config = ProofConfig {
            enabled: matches.is_present("execution-proofs-enabled"),
            optimistic_acceptance: matches.is_present("execution-proofs-optimistic-acceptance"),
            fallback_to_execution: matches.is_present("execution-proofs-fallback-to-execution"),
            verification_timeout_ms: matches.value_of("execution-proofs-verification-timeout")
                .map(|s| s.parse().map_err(|_| "Invalid verification timeout"))
                .unwrap_or(Ok(5000))?,
            max_cache_size: matches.value_of("execution-proofs-cache-size")
                .map(|s| s.parse().map_err(|_| "Invalid cache size"))
                .unwrap_or(Ok(1000))?,
            cache_ttl_seconds: matches.value_of("execution-proofs-cache-ttl")
                .map(|s| s.parse().map_err(|_| "Invalid cache TTL"))
                .unwrap_or(Ok(300))?,
        };
        
        // ... apply proof_config to BeaconChainConfig
    }
}
```

### Testing with Kurtosis

#### Test Scenario 4.1: Optimistic Acceptance
```yaml
# kurtosis-config/milestone4/test-optimistic.yaml
participants:
  - el_type: geth
    cl_type: lighthouse
    cl_extra_params: 
      - "--execution-proofs-enabled"
      - "--execution-proofs-optimistic-acceptance"
      - "--execution-proofs-fallback-to-execution"
    count: 4

network_params:
  seconds_per_slot: 12
  slots_per_epoch: 32
  capella_fork_epoch: 0
  deneb_fork_epoch: 0
```

**Test Commands:**
```bash
# Test 1: Verify optimistic acceptance works
kurtosis run github.com/ethpandaops/ethereum-package --args-file milestone4/test-optimistic.yaml

# Start the network and let it produce blocks
sleep 60

# Check that blocks are being accepted optimistically
for i in {0..3}; do
  echo "Node $i payload status:"
  curl -s http://lighthouse-node-$i:5052/eth/v1/beacon/blocks/head | jq '.data.message.body.execution_payload.block_hash'
  curl -s http://lighthouse-node-$i:5052/lighthouse/debug/execution_payload_status | jq '.'
done

# Expected: Blocks are imported with Optimistic status initially
# Expected: No proof verification errors
# Expected: Network continues to finalize blocks
```

#### Test Scenario 4.2: Proof-Based Verification
```bash
# Test 2: Test proof-based verification path
# Publish a proof for a known payload
PAYLOAD_HASH=$(curl -s http://lighthouse-node-0:5052/eth/v1/beacon/blocks/head | jq -r '.data.message.body.execution_payload.block_hash')

lighthouse debug execution-proof \
  --network-dir /data/custom-testnet \
  --datadir /data/lighthouse \
  publish-proof \
  --proof-type sp1 \
  --payload-hash $PAYLOAD_HASH \
  --proof-data $(echo -n $PAYLOAD_HASH | xxd -p -c 64)

# Wait for proof propagation
sleep 10

# Trigger a new payload with the same hash
curl -X POST http://lighthouse-node-0:5052/lighthouse/debug/trigger_payload_verification \
  -H "Content-Type: application/json" \
  -d "{\"payload_hash\": \"$PAYLOAD_HASH\"}"

# Expected: Payload is verified via proof, not EL
# Expected: Status transitions from Optimistic to Verified
# Expected: Verification metrics show proof-based verification
```

#### Test Scenario 4.3: Fallback Behavior
```bash
# Test 3: Test fallback to EL when proofs unavailable
lighthouse beacon_node \
  --datadir /data/lighthouse-fallback \
  --network custom \
  --execution-proofs-enabled \
  --execution-proofs-optimistic-acceptance false \
  --execution-proofs-fallback-to-execution true \
  --testnet-dir /data/custom-testnet

# Generate blocks and verify they're processed via EL
sleep 30

# Check verification paths
curl -s http://lighthouse-fallback:5052/lighthouse/metrics | grep "execution_proof_fallback_to_el_total"

# Expected: Blocks are verified via EL when no proofs available
# Expected: No optimistic acceptance occurs
# Expected: Fallback metrics increment
```

#### Test Scenario 4.4: Invalid Proof Handling
```bash
# Test 4: Test invalid proof rejection
PAYLOAD_HASH=$(curl -s http://lighthouse-node-0:5052/eth/v1/beacon/blocks/head | jq -r '.data.message.body.execution_payload.block_hash')

# Publish an invalid proof (wrong data)
lighthouse debug execution-proof \
  --network-dir /data/custom-testnet \
  --datadir /data/lighthouse \
  publish-proof \
  --proof-type sp1 \
  --payload-hash $PAYLOAD_HASH \
  --proof-data 0xdeadbeefdeadbeefdeadbeef  # Invalid/insufficient data

# Check that invalid proof is rejected
curl -s http://lighthouse-node-0:5052/lighthouse/debug/execution_proof/cache/$PAYLOAD_HASH

# Expected: Proof verification fails
# Expected: Payload status remains Optimistic or falls back to EL
# Expected: Invalid proof metrics increment
```

### Success Criteria
- [ ] Payloads are accepted optimistically when proofs are not available
- [ ] Proof-based verification works when proofs are available
- [ ] Fork choice correctly transitions from Optimistic to Verified
- [ ] Invalid proof detection and handling works
- [ ] Fallback to EL verification works when configured
- [ ] Async proof validation updates payload status correctly
- [ ] Configuration options control behavior as expected
- [ ] Network continues to operate normally with ExecutionProofs enabled

---

## Milestone 5: End-to-End Integration and Real Proof Types

### Duration: 4-5 weeks

### Scope
Replace mock implementations with real proof verification logic and test complete end-to-end workflows.

### Deliverables

#### 5.1 Real Proof Verifier Implementations
```rust
// Integration with actual zkVM libraries
pub struct SP1ProofVerifier {
    verifier: SP1Verifier,
    vkey: SP1VerifyingKey,
}

#[async_trait]
impl ProofVerifier for SP1ProofVerifier {
    async fn verify(&self, proof: &ExecutionProof) -> Result<bool, ProofError> {
        if proof.version != 0 {
            return Err(ProofError::UnsupportedVersion(proof.version));
        }
        
        // Deserialize SP1 proof from data
        let sp1_proof: SP1Proof = bincode::deserialize(&proof.data)
            .map_err(|_| ProofError::InvalidProofData)?;
        
        // Extract public inputs (payload hash, state root, etc.)
        let public_inputs: PublicInputs = sp1_proof.public_values.read();
        
        // Verify the SP1 proof
        self.verifier.verify(&sp1_proof, &self.vkey)
            .map_err(|e| ProofError::VerificationFailed(e.to_string()))?;
        
        Ok(true)
    }
    
    fn extract_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, ProofError> {
        let sp1_proof: SP1Proof = bincode::deserialize(&proof.data)
            .map_err(|_| ProofError::InvalidProofData)?;
        
        let public_inputs: PublicInputs = sp1_proof.public_values.read();
        Ok(Hash256::from_slice(&public_inputs.payload_hash))
    }
    
    fn proof_type(&self) -> ProofType { ProofType::SP1Proof }
    fn version(&self) -> u8 { 0 }
}

pub struct ExecutionWitnessVerifier {
    // MPT verification logic
}

#[async_trait]
impl ProofVerifier for ExecutionWitnessVerifier {
    async fn verify(&self, proof: &ExecutionProof) -> Result<bool, ProofError> {
        if proof.version != 0 {
            return Err(ProofError::UnsupportedVersion(proof.version));
        }
        
        // Deserialize execution witness
        let witness: ExecutionWitness = rlp::decode(&proof.data)
            .map_err(|_| ProofError::InvalidProofData)?;
        
        // Verify state root transitions using MPT proofs
        self.verify_state_transition(&witness).await
            .map_err(|e| ProofError::VerificationFailed(e.to_string()))
    }
    
    async fn verify_state_transition(&self, witness: &ExecutionWitness) -> Result<bool, Error> {
        // Implement stateless execution verification
        // This involves:
        // 1. Verifying account proofs against pre-state root
        // 2. Executing transactions
        // 3. Verifying resulting state root matches post-state root
        todo!("Implement stateless execution verification")
    }
    
    fn extract_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, ProofError> {
        let witness: ExecutionWitness = rlp::decode(&proof.data)
            .map_err(|_| ProofError::InvalidProofData)?;
        Ok(witness.block_hash)
    }
    
    fn proof_type(&self) -> ProofType { ProofType::ExecutionWitness }
    fn version(&self) -> u8 { 0 }
}
```

#### 5.2 Proof Producer Service
```rust
// External proof producer service
pub struct ExecutionProofProducer {
    execution_client: Arc<ExecutionClient>,
    beacon_client: Arc<BeaconNodeClient>,
    sp1_prover: Option<SP1Prover>,
    risc0_prover: Option<Risc0Prover>,
    witness_generator: Option<WitnessGenerator>,
    network_client: Arc<NetworkClient>,
    config: ProofProducerConfig,
}

impl ExecutionProofProducer {
    pub async fn run(&self) -> Result<(), Error> {
        let mut block_stream = self.beacon_client.subscribe_head_events().await?;
        
        while let Some(head_event) = block_stream.next().await {
            let block = self.beacon_client.get_block(&head_event.block_root).await?;
            
            if let Some(execution_payload) = block.message.body.execution_payload() {
                self.process_execution_payload(execution_payload).await?;
            }
        }
        
        Ok(())
    }
    
    async fn process_execution_payload(&self, payload: &ExecutionPayload) -> Result<(), Error> {
        let payload_hash = payload.block_hash();
        
        // Generate proofs for enabled types
        let mut proof_tasks = Vec::new();
        
        if self.config.sp1_enabled {
            if let Some(prover) = &self.sp1_prover {
                let task = self.generate_sp1_proof(prover.clone(), payload.clone());
                proof_tasks.push(tokio::spawn(task));
            }
        }
        
        if self.config.execution_witness_enabled {
            if let Some(generator) = &self.witness_generator {
                let task = self.generate_execution_witness(generator.clone(), payload.clone());
                proof_tasks.push(tokio::spawn(task));
            }
        }
        
        // Wait for proof generation and publish results
        for task in proof_tasks {
            if let Ok(Ok(proof)) = task.await {
                self.publish_proof(proof).await?;
            }
        }
        
        Ok(())
    }
    
    async fn generate_sp1_proof(&self, prover: SP1Prover, payload: ExecutionPayload) -> Result<ExecutionProof, Error> {
        // Get block data and state
        let block_data = self.execution_client.get_block_data(&payload.block_hash()).await?;
        let pre_state = self.execution_client.get_state_data(&payload.parent_hash()).await?;
        
        // Generate SP1 proof for state transition
        let stdin = SP1Stdin::new();
        stdin.write(&block_data);
        stdin.write(&pre_state);
        
        let proof = prover.prove(&stdin).await?;
        let proof_bytes = bincode::serialize(&proof)?;
        
        Ok(ExecutionProof::new(0, proof_bytes))
    }
    
    async fn generate_execution_witness(&self, generator: WitnessGenerator, payload: ExecutionPayload) -> Result<ExecutionProof, Error> {
        // Generate execution witness with state proofs
        let witness = generator.generate_witness(&payload).await?;
        let witness_bytes = rlp::encode(&witness);
        
        Ok(ExecutionProof::new(0, witness_bytes))
    }
    
    async fn publish_proof(&self, proof: ExecutionProof) -> Result<(), Error> {
        let proof_type = ProofType::from_version(proof.version)?;
        let subnet_id = proof_type.subnet_id();
        
        self.network_client.publish_execution_proof(proof, subnet_id).await
    }
}
```

#### 5.3 Integration Testing Framework
```rust
// Test utilities for end-to-end testing
pub struct ExecutionProofTestHarness {
    beacon_chain_harness: BeaconChainHarness,
    proof_producer: ExecutionProofProducer,
    network_context: NetworkContext,
}

impl ExecutionProofTestHarness {
    pub async fn new() -> Self {
        let mut builder = BeaconChainHarness::builder()
            .proof_config(ProofConfig {
                enabled: true,
                optimistic_acceptance: true,
                fallback_to_execution: true,
                verification_timeout_ms: 10000,
                max_cache_size: 100,
                cache_ttl_seconds: 60,
            });
        
        let harness = builder.build();
        
        Self {
            beacon_chain_harness: harness,
            proof_producer: ExecutionProofProducer::new_test_instance(),
            network_context: NetworkContext::new_test(),
        }
    }
    
    pub async fn test_end_to_end_proof_flow(&mut self) -> Result<(), Error> {
        // 1. Generate a block
        let (block, post_state) = self.beacon_chain_harness.make_block().await?;
        
        // 2. Generate proof for the execution payload
        let execution_payload = block.message().body().execution_payload().unwrap();
        let proof = self.proof_producer.generate_sp1_proof(execution_payload).await?;
        
        // 3. Publish proof to network
        self.network_context.publish_execution_proof(proof.clone(), ProofSubnetId::sp1()).await?;
        
        // 4. Import block (should use proof for verification)
        let result = self.beacon_chain_harness.process_block(block.clone()).await?;
        
        // 5. Verify the block was verified via proof
        assert_eq!(result.payload_verification_status, PayloadVerificationStatus::Verified);
        
        Ok(())
    }
}
```

### Testing with Kurtosis

#### Test Scenario 5.1: Real SP1 Proof Generation and Verification
```yaml
# kurtosis-config/milestone5/test-sp1-proofs.yaml
participants:
  - el_type: geth
    cl_type: lighthouse
    cl_extra_params:
      - "--execution-proofs-enabled"
      - "--execution-proofs-sp1-verifier-enabled"
    count: 3

additional_services:
  - proof_producer:
      image: "custom/sp1-proof-producer:latest"
      config:
        sp1_enabled: true
        beacon_node_url: "http://lighthouse-node-0:5052"
        execution_node_url: "http://geth-node-0:8545"
```

**Test Commands:**
```bash
# Test 1: End-to-end SP1 proof workflow
kurtosis run github.com/ethpandaops/ethereum-package --args-file milestone5/test-sp1-proofs.yaml

# Wait for network to start producing blocks
sleep 60

# Check that SP1 proofs are being generated and verified
curl -s http://lighthouse-node-0:5052/lighthouse/metrics | grep "execution_proofs_verified_total{result=\"sp1_success\"}"

# Verify proof cache contains SP1 proofs
curl -s http://lighthouse-node-0:5052/lighthouse/debug/execution_proof/cache | jq '.sp1_proofs | length'

# Expected: SP1 proofs are generated for new blocks
# Expected: Proofs are successfully verified by all nodes
# Expected: Blocks are marked as Verified via SP1 proofs
```

#### Test Scenario 5.2: Execution Witness Verification
```bash
# Test 2: Execution witness generation and verification
kurtosis service exec proof-producer "generate-execution-witness --block-hash $LATEST_BLOCK_HASH"

# Check that execution witness is generated and propagated
sleep 10

curl -s http://lighthouse-node-0:5052/lighthouse/debug/execution_proof/cache | jq '.execution_witness_proofs'

# Expected: Execution witness is generated
# Expected: Stateless verification succeeds
# Expected: All nodes can verify the witness independently
```

#### Test Scenario 5.3: Performance Under Load
```yaml
# kurtosis-config/milestone5/test-performance.yaml
participants:
  - el_type: geth
    cl_type: lighthouse
    cl_extra_params:
      - "--execution-proofs-enabled"
      - "--execution-proofs-cache-size=10000"
    count: 5

network_params:
  seconds_per_slot: 12  # Normal timing
  num_validator_keys_per_node: 32

additional_services:
  - proof_producer:
      replicas: 2  # Multiple proof producers
  - tx_spammer:
      transactions_per_second: 100
```

**Test Commands:**
```bash
# Test 3: Performance under load
kurtosis run github.com/ethpandaops/ethereum-package --args-file milestone5/test-performance.yaml

# Let the network run for 10 minutes under load
sleep 600

# Check performance metrics
for i in {0..4}; do
  echo "Node $i metrics:"
  curl -s http://lighthouse-node-$i:5052/lighthouse/metrics | grep -E "(execution_proof|block_production|payload_verification)" 
done

# Expected: Block production latency remains normal
# Expected: Proof verification doesn't cause delays
# Expected: Cache hit rate is high (>80%)
# Expected: Network continues to finalize under load
```

#### Test Scenario 5.4: Mixed Proof Types
```bash
# Test 4: Multiple proof types working together
# Configure different nodes to prefer different proof types
curl -X POST http://lighthouse-node-0:5052/lighthouse/config/proof_preferences \
  -H "Content-Type: application/json" \
  -d '{"preferred_types": ["sp1", "execution_witness"]}'

curl -X POST http://lighthouse-node-1:5052/lighthouse/config/proof_preferences \
  -H "Content-Type: application/json" \
  -d '{"preferred_types": ["risc0", "execution_witness"]}'

# Generate blocks and verify different proof types are used
sleep 120

# Check proof type distribution
curl -s http://lighthouse-node-0:5052/lighthouse/metrics | grep "execution_proofs_verified_total"

# Expected: Different proof types are generated and verified
# Expected: Nodes can verify proofs from different zkVM systems
# Expected: Fallback between proof types works correctly
```

### Success Criteria
- [ ] Real SP1 proofs can be generated and verified
- [ ] Execution witnesses work for stateless verification
- [ ] RISC0 proof integration works (if implemented)
- [ ] Performance under load meets requirements (<1s additional latency)
- [ ] Multiple proof types can coexist
- [ ] Proof generation doesn't impact block production timing
- [ ] Cache performance is acceptable (>80% hit rate)
- [ ] End-to-end workflows complete successfully
- [ ] Error handling works for all failure modes

---

## Milestone 6: Production Readiness and Optimization

### Duration: 3-4 weeks

### Scope
Production-ready optimizations, monitoring, security hardening, and comprehensive documentation.

### Deliverables

#### 6.1 Production Configuration and Security
```rust
// Production-ready configuration with security considerations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionProofConfig {
    // Core settings
    pub enabled: bool,
    pub proof_types: Vec<ProofType>,
    
    // Security settings
    pub max_proof_size_bytes: usize,           // DoS protection
    pub max_verification_time_ms: u64,         // Resource limits
    pub rate_limit_proofs_per_second: u32,     // Rate limiting
    pub trusted_proof_producers: Vec<PeerId>,  // Optional allowlist
    
    // Performance settings
    pub verification_parallelism: usize,       // Concurrent verifications
    pub cache_size_mb: usize,                 // Memory-based cache sizing
    pub cache_ttl_seconds: u64,
    pub proof_priority_by_type: HashMap<ProofType, u8>,  // Verification priority
    
    // Fallback and reliability
    pub optimistic_acceptance: bool,
    pub fallback_to_execution: bool,
    pub max_optimistic_blocks: u32,           // Limit optimistic chain length
    pub proof_required_for_finalization: bool, // Require proofs for finality
    
    // Monitoring and alerts
    pub metrics_enabled: bool,
    pub alert_on_verification_failures: bool,
    pub slow_verification_threshold_ms: u64,
}

impl ProductionProofConfig {
    pub fn mainnet_default() -> Self {
        Self {
            enabled: true,
            proof_types: vec![ProofType::ExecutionWitness], // Conservative start
            max_proof_size_bytes: 50 * 1024 * 1024, // 50MB max
            max_verification_time_ms: 30000, // 30s max
            rate_limit_proofs_per_second: 10,
            trusted_proof_producers: vec![], // Open network
            verification_parallelism: 4,
            cache_size_mb: 1024, // 1GB cache
            cache_ttl_seconds: 3600, // 1 hour
            proof_priority_by_type: HashMap::from([
                (ProofType::ExecutionWitness, 1), // Highest priority
                (ProofType::SP1Proof, 2),
                (ProofType::Risc0Proof, 3),
            ]),
            optimistic_acceptance: true,
            fallback_to_execution: true,
            max_optimistic_blocks: 8, // ~1.6 minutes
            proof_required_for_finalization: false, // Don't break finality
            metrics_enabled: true,
            alert_on_verification_failures: true,
            slow_verification_threshold_ms: 10000,
        }
    }
}
```

#### 6.2 Advanced Caching and Performance
```rust
// High-performance cache implementation
pub struct TieredExecutionProofCache<E: EthSpec> {
    // L1: In-memory LRU cache for recent proofs
    l1_cache: Arc<Mutex<LruCache<Hash256, CachedProof>>>,
    
    // L2: Disk-based cache for historical proofs
    l2_cache: Arc<DiskCache>,
    
    // L3: Network cache for peer-assisted retrieval
    network_cache: Arc<NetworkCache>,
    
    // Verification workers
    verification_pool: ThreadPool,
    
    config: ProductionProofConfig,
    metrics: ProofCacheMetrics,
}

impl<E: EthSpec> TieredExecutionProofCache<E> {
    pub async fn get_proof_with_priority(&self, payload_hash: &Hash256, priority: u8) -> Option<CachedProof> {
        // L1 cache check
        if let Some(proof) = self.l1_cache.lock().get(payload_hash) {
            self.metrics.l1_hits.inc();
            return Some(proof.clone());
        }
        
        // L2 cache check (async)
        if let Ok(Some(proof)) = self.l2_cache.get(payload_hash).await {
            self.metrics.l2_hits.inc();
            // Promote to L1
            self.l1_cache.lock().put(*payload_hash, proof.clone());
            return Some(proof);
        }
        
        // L3 network cache check (if enabled)
        if priority >= 5 {  // Only for high-priority requests
            if let Ok(Some(proof)) = self.network_cache.request_proof(payload_hash).await {
                self.metrics.l3_hits.inc();
                // Cache in L1 and L2
                self.cache_proof_all_levels(payload_hash, &proof).await;
                return Some(proof);
            }
        }
        
        self.metrics.cache_misses.inc();
        None
    }
    
    pub async fn verify_proof_with_timeout(
        &self, 
        payload_hash: Hash256, 
        proof: ExecutionProof,
        timeout: Duration
    ) -> Result<bool, ProofError> {
        let verification_future = self.verify_proof_internal(proof);
        
        match tokio::time::timeout(timeout, verification_future).await {
            Ok(result) => result,
            Err(_) => {
                self.metrics.verification_timeouts.inc();
                Err(ProofError::VerificationTimeout)
            }
        }
    }
    
    async fn verify_proof_internal(&self, proof: ExecutionProof) -> Result<bool, ProofError> {
        let verifier = self.get_verifier_for_proof(&proof)?;
        
        // Use thread pool for CPU-intensive verification
        let (tx, rx) = oneshot::channel();
        
        self.verification_pool.execute(move || {
            let start = Instant::now();
            let result = block_on(verifier.verify(&proof));
            let duration = start.elapsed();
            
            let _ = tx.send((result, duration));
        });
        
        let (result, duration) = rx.await.map_err(|_| ProofError::VerificationFailed("Worker panic".to_string()))?;
        
        // Record metrics
        self.metrics.verification_duration.observe(duration.as_secs_f64());
        if duration > Duration::from_millis(self.config.slow_verification_threshold_ms) {
            self.metrics.slow_verifications.inc();
        }
        
        result
    }
}
```

#### 6.3 Comprehensive Monitoring and Alerting
```rust
// Production monitoring and metrics
#[derive(Clone)]
pub struct ExecutionProofMetrics {
    // Cache metrics
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub cache_size: Gauge,
    pub cache_memory_usage: Gauge,
    
    // Verification metrics
    pub proofs_received: CounterVec,  // by type, subnet
    pub proofs_verified: CounterVec,  // by type, result
    pub verification_duration: HistogramVec, // by type
    pub verification_queue_size: Gauge,
    
    // Network metrics
    pub gossip_messages_sent: CounterVec,
    pub gossip_messages_received: CounterVec,
    pub peer_proof_requests: Counter,
    pub network_errors: CounterVec,
    
    // Performance metrics
    pub block_verification_duration: Histogram,
    pub optimistic_blocks: Gauge,
    pub proof_availability_rate: Histogram,
    
    // Error metrics
    pub verification_failures: CounterVec,  // by type, reason
    pub invalid_proofs: CounterVec,
    pub timeout_errors: Counter,
    pub resource_limit_errors: Counter,
}

impl ExecutionProofMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            cache_hits: Counter::new("execution_proof_cache_hits_total", "Total cache hits")?,
            cache_misses: Counter::new("execution_proof_cache_misses_total", "Total cache misses")?,
            // ... initialize all metrics
        })
    }
    
    pub fn register_with_prometheus(&self, registry: &Registry) -> Result<(), prometheus::Error> {
        registry.register(Box::new(self.cache_hits.clone()))?;
        registry.register(Box::new(self.cache_misses.clone()))?;
        // ... register all metrics
        Ok(())
    }
}

// Alerting rules (Prometheus/Grafana configuration)
pub const ALERTING_RULES: &str = r#"
groups:
  - name: execution_proofs
    rules:
      - alert: ExecutionProofVerificationFailureRate
        expr: rate(execution_proof_verification_failures_total[5m]) > 0.1
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "High execution proof verification failure rate"
          
      - alert: ExecutionProofCacheMissRate
        expr: rate(execution_proof_cache_misses_total[5m]) / rate(execution_proof_cache_requests_total[5m]) > 0.5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High execution proof cache miss rate"
          
      - alert: ExecutionProofVerificationTimeout
        expr: rate(execution_proof_verification_timeouts_total[5m]) > 0.01
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Execution proof verification timeouts occurring"
"#;
```

#### 6.4 Documentation and Migration Guide
```markdown
# Production Deployment Guide

## Pre-deployment Checklist

### System Requirements
- [ ] CPU: 8+ cores recommended for proof verification
- [ ] RAM: 16GB+ (additional 4GB for proof cache)
- [ ] Disk: 100GB+ additional space for proof storage
- [ ] Network: Bandwidth for proof gossip (~10MB/hour additional)

### Configuration Review
- [ ] Proof types enabled match your verification capabilities
- [ ] Cache size appropriate for available memory
- [ ] Rate limits configured for your network
- [ ] Monitoring and alerting set up
- [ ] Backup and recovery procedures in place

### Security Considerations
- [ ] Proof size limits configured to prevent DoS
- [ ] Verification timeouts set appropriately
- [ ] Network isolation for proof verification (if required)
- [ ] Audit logs enabled for proof verification events

## Migration Strategy

### Phase 1: Shadow Mode (2 weeks)
```bash
# Enable ExecutionProofs in shadow mode (no verification)
lighthouse beacon_node \
  --execution-proofs-enabled true \
  --execution-proofs-verification-mode shadow \
  --execution-proofs-fallback-to-execution true
```

### Phase 2: Optimistic Mode (2 weeks)
```bash
# Enable optimistic acceptance with fallback
lighthouse beacon_node \
  --execution-proofs-enabled true \
  --execution-proofs-optimistic-acceptance true \
  --execution-proofs-fallback-to-execution true
```

### Phase 3: Full Production (ongoing)
```bash
# Full ExecutionProofs with all optimizations
lighthouse beacon_node \
  --execution-proofs-enabled true \
  --execution-proofs-config production-config.yaml \
  --execution-proofs-cache-size-mb 1024 \
  --execution-proofs-verification-parallelism 4
```
```

### Testing with Kurtosis

#### Test Scenario 6.1: Production Load Testing
```yaml
# kurtosis-config/milestone6/test-production-load.yaml
participants:
  - el_type: geth
    cl_type: lighthouse
    cl_extra_params:
      - "--execution-proofs-config=/data/production-config.yaml"
    count: 10  # Large network

network_params:
  num_validator_keys_per_node: 64
  seconds_per_slot: 12

snooper_enabled: true
prometheus_grafana_enabled: true

additional_services:
  - proof_producer:
      replicas: 3
      config:
        high_performance_mode: true
  - tx_spammer:
      transactions_per_second: 200
  - network_chaos:  # Introduce network issues
      chaos_type: partition
      frequency: "every 10m"
      duration: "30s"
```

**Test Commands:**
```bash
# Test 1: Long-running production simulation
kurtosis run github.com/ethpandaops/ethereum-package --args-file milestone6/test-production-load.yaml

# Run for 24 hours
sleep 86400

# Check performance metrics after 24 hours
curl -s http://grafana:3000/api/dashboards/uid/execution-proofs/snapshot

# Expected: Network remains stable over 24 hours
# Expected: Memory usage stays within bounds
# Expected: Verification performance remains consistent
# Expected: No resource leaks or degradation
```

#### Test Scenario 6.2: Security and DoS Testing
```bash
# Test 2: Security testing
# Generate oversized proofs to test limits
lighthouse debug execution-proof generate-invalid \
  --proof-type sp1 \
  --size-mb 100 \  # Above configured limit
  --target-node lighthouse-node-0

# Generate high-frequency proof spam
for i in {1..1000}; do
  lighthouse debug execution-proof publish-proof \
    --proof-type sp1 \
    --payload-hash $(openssl rand -hex 32) \
    --proof-data $(openssl rand -hex 1000) &
done

# Check that rate limiting and size limits work
curl -s http://lighthouse-node-0:5052/lighthouse/metrics | grep "execution_proof_rate_limit_hits"

# Expected: Oversized proofs are rejected
# Expected: Rate limiting prevents spam
# Expected: System remains stable under attack
# Expected: Legitimate proofs still processed
```

#### Test Scenario 6.3: Disaster Recovery Testing
```bash
# Test 3: Cache recovery and data persistence
# Stop all nodes
kurtosis service stop lighthouse-node-0 lighthouse-node-1 lighthouse-node-2

# Corrupt cache data
kurtosis service exec lighthouse-node-0 "rm -rf /data/lighthouse/proof_cache/*"

# Restart nodes
kurtosis service start lighthouse-node-0 lighthouse-node-1 lighthouse-node-2

# Verify network recovers and proof cache rebuilds
sleep 300

curl -s http://lighthouse-node-0:5052/lighthouse/metrics | grep "execution_proof_cache_size"

# Expected: Nodes restart successfully
# Expected: Cache rebuilds from network and disk
# Expected: No data corruption or loss
# Expected: Network continues normal operation
```

#### Test Scenario 6.4: Performance Regression Testing
```bash
# Test 4: Performance comparison with baseline
# Run baseline without ExecutionProofs
kurtosis run ethereum-package --args-file baseline-config.yaml &
BASELINE_PID=$!

sleep 1800  # 30 minutes

# Get baseline metrics
curl -s http://lighthouse-node-0:5052/lighthouse/metrics > baseline-metrics.txt

kill $BASELINE_PID

# Run with ExecutionProofs
kurtosis run ethereum-package --args-file milestone6/test-production-load.yaml &
PROOF_PID=$!

sleep 1800  # 30 minutes

# Get ExecutionProofs metrics
curl -s http://lighthouse-node-0:5052/lighthouse/metrics > proof-metrics.txt

# Compare performance
python3 compare-performance.py baseline-metrics.txt proof-metrics.txt

# Expected: Block production latency increase <5%
# Expected: Memory usage increase <20%
# Expected: CPU usage increase <15%
# Expected: Network bandwidth increase <10%
```

### Success Criteria
- [ ] 24+ hour stability test passes
- [ ] Performance regression within acceptable limits (<5% latency)
- [ ] Security measures protect against DoS attacks
- [ ] Monitoring and alerting work correctly
- [ ] Cache persistence and recovery work
- [ ] Production configuration is well-documented
- [ ] Migration procedures are tested and verified
- [ ] Error handling covers all edge cases
- [ ] Resource usage is predictable and bounded
- [ ] Network effects are minimal under normal operation

---

## Summary

This milestone-based implementation plan provides:

### **Incremental Development**
- Each milestone builds on the previous one
- Clear deliverables and testable outcomes
- Ability to pause and assess at each stage

### **Comprehensive Testing**
- Kurtosis integration at every milestone
- Real-world network conditions testing
- Performance and security validation

### **Production Readiness**
- Security considerations from early milestones
- Performance optimization throughout
- Comprehensive monitoring and alerting

### **Risk Mitigation**
- Fallback mechanisms maintained throughout
- Compatibility with existing systems
- Graceful degradation under failure conditions

The total implementation timeline is approximately **15-20 weeks**, with each milestone providing a stable checkpoint that can be deployed and tested independently. This approach ensures that ExecutionProofs can be implemented incrementally with confidence in system stability at each stage.