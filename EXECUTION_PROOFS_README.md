# ExecutionProofs Implementation Guide

A comprehensive guide for implementing ExecutionProofs support in Ethereum consensus clients, based on the Lighthouse implementation.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Workflow Comparison](#workflow-comparison)
4. [Implementation Guide](#implementation-guide)
5. [Network Protocol](#network-protocol)
6. [Configuration](#configuration)
7. [Testing](#testing)
8. [Production Considerations](#production-considerations)

## Overview

ExecutionProofs is an enhancement to the Ethereum consensus layer that enables **cryptographic verification of execution payloads** through zkVM proofs and execution witnesses. It provides an alternative to traditional execution layer (EL) verification while maintaining full compatibility with existing optimistic sync mechanisms.

### Key Benefits

- **Cryptographic Assurance**: Mathematical proofs instead of trust-based EL verification
- **Decentralized Verification**: Multiple proof systems reduce single points of failure
- **Faster Finality**: Proofs can arrive faster than EL sync completion
- **Graceful Degradation**: Falls back to standard EL verification when proofs unavailable

### Supported Proof Types

| Proof Type | Subnet ID | Description | Use Case |
|------------|-----------|-------------|----------|
| **SP1Proof** | 0 | SP1 zkVM proofs | State transition verification |
| **Risc0Proof** | 1 | Risc0 zkVM proofs | State transition verification |
| **ExecutionWitness** | 2 | MPT proofs + block data | Stateless execution |
| *Future* | 3-7 | Reserved for additional zkVMs | Jolt, Nexus, etc. |

## Architecture

### Core Components

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Consensus     │◄──►│ ExecutionProof   │◄──►│    Network      │
│   Validation    │    │     Cache        │    │   (Gossip)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Payload Status  │    │   Proof          │    │   Subnet        │
│   Management    │    │  Verifiers       │    │  Management     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Data Structures

#### ExecutionProof Type

```rust
pub struct ExecutionProof {
    pub version: u8,        // Proof format version
    pub data: Vec<u8>,      // Opaque proof data (SSZ encoded)
}
```

#### ProofSubnetId Mapping

```rust
pub enum ProofType {
    SP1Proof,           // Subnet 0
    Risc0Proof,         // Subnet 1  
    ExecutionWitness,   // Subnet 2
    // Subnets 3+ reserved for future expansion
}

pub const PROOF_SUBNET_COUNT: usize = 8;
```

## Workflow Comparison

### Traditional Optimistic Sync

```
Block Received → Basic Validation → EL Available?
├─ Yes: EL Verification → Verified/Invalid
└─ No: Optimistic Import → Later EL Verification
```

### ExecutionProofs Enhanced Flow

```
Block Received → Basic Validation → Proof Available?
├─ Yes: Proof Verification → Verified/Invalid
├─ No + Optimistic: Optimistic Import → Async Proof Validation  
└─ No + Fallback: EL Verification → Verified/Invalid
```

### Key Analogies

| Optimistic Sync | ExecutionProofs | Purpose |
|----------------|-----------------|---------|
| EL unavailable | Proof unavailable | Accept payload optimistically |
| EL verification | Proof verification | Validate execution correctness |
| EL sync wait | Proof gossip wait | Await verification data |
| `PayloadVerificationStatus` | Same enum reused | Track validation state |

## Implementation Guide

### 1. Core Data Types

**Step 1: Define ExecutionProof Structure**

```rust
// consensus/types/src/execution_proof.rs
#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
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
}
```

**Step 2: Define ProofSubnetId**

```rust
// consensus/types/src/proof_subnet_id.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofSubnetId(u8);

impl ProofSubnetId {
    pub const PROOF_SUBNET_COUNT: usize = 8;
    
    pub fn sp1() -> Self { Self(0) }
    pub fn risc0() -> Self { Self(1) }  
    pub fn execution_witness() -> Self { Self(2) }
    
    pub fn from_proof_type(proof_type: ProofType) -> Self {
        match proof_type {
            ProofType::SP1Proof => Self::sp1(),
            ProofType::Risc0Proof => Self::risc0(),
            ProofType::ExecutionWitness => Self::execution_witness(),
        }
    }
}
```

### 2. Caching Layer

**Step 3: Implement ExecutionProofCache**

```rust
// beacon_node/beacon_chain/src/execution_proof_cache.rs
pub struct ExecutionProofCache<E: EthSpec> {
    // LRU cache with TTL
    cache: TimeoutRwLock<LruCache<Hash256, CachedProof>>,
    // Registry of proof verifiers
    verifiers: ProofVerifierRegistry,
}

impl<E: EthSpec> ExecutionProofCache<E> {
    pub fn new(config: ProofConfig) -> Self {
        Self {
            cache: TimeoutRwLock::new(
                LruCache::new(NonZeroUsize::new(config.max_cache_size).unwrap()),
                Duration::from_secs(config.cache_ttl_seconds),
            ),
            verifiers: ProofVerifierRegistry::new(),
        }
    }
    
    pub async fn verify_proof(&self, proof: &ExecutionProof, payload_hash: Hash256) -> Result<bool, ProofError> {
        // 1. Check cache for existing verification result
        if let Some(cached) = self.cache.read().await.get(&payload_hash) {
            return Ok(cached.is_valid);
        }
        
        // 2. Extract payload hash from proof data
        let extracted_hash = self.extract_payload_hash(proof)?;
        if extracted_hash != payload_hash {
            return Err(ProofError::PayloadHashMismatch);
        }
        
        // 3. Verify proof using appropriate verifier
        let verifier = self.verifiers.get_verifier(proof.version)?;
        let is_valid = verifier.verify(proof).await?;
        
        // 4. Cache result
        self.cache.write().await.put(payload_hash, CachedProof { 
            is_valid, 
            timestamp: Instant::now() 
        });
        
        Ok(is_valid)
    }
}
```

### 3. Network Integration

**Step 4: Gossip Topic Support**

```rust
// beacon_node/lighthouse_network/src/types/topics.rs
pub fn execution_proof_topic(fork_digest: [u8; 4], subnet_id: ProofSubnetId, spec: &ChainSpec) -> String {
    format!(
        "/eth2/{}/execution_proof_{}/ssz_snappy",
        hex::encode(fork_digest),
        subnet_id.as_u8()
    )
}

// Examples:
// SP1: /eth2/0x12345678/execution_proof_0/ssz_snappy
// Risc0: /eth2/0x12345678/execution_proof_1/ssz_snappy  
// ExecutionWitness: /eth2/0x12345678/execution_proof_2/ssz_snappy
```

**Step 5: PubSub Message Handling**

```rust
// beacon_node/lighthouse_network/src/types/pubsub.rs
#[derive(Debug, Clone, PartialEq)]
pub enum PubsubMessage<E: EthSpec> {
    // ... existing variants
    ExecutionProof(Box<(ProofSubnetId, ExecutionProof)>),
}

impl<E: EthSpec> PubsubMessage<E> {
    pub fn decode(topic: &TopicHash, data: &[u8], spec: &ChainSpec) -> Result<Self, String> {
        match get_topic_name(topic, spec.fork_context.as_ref()) {
            // ... existing cases
            EXECUTION_PROOF_TOPIC => {
                let subnet_id = extract_subnet_from_topic(topic)?;
                let proof: ExecutionProof = ExecutionProof::from_ssz_bytes(data)?;
                Ok(PubsubMessage::ExecutionProof(Box::new((subnet_id, proof))))
            }
        }
    }
}
```

### 4. Beacon Chain Integration

**Step 6: Payload Verification Enhancement**

```rust
// beacon_node/beacon_chain/src/execution_payload.rs

pub async fn verify_and_notify_new_payload<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    payload: &ExecutionPayload<T::EthSpec>,
    // ... other params
) -> Result<PayloadVerificationStatus, ExecutionPayloadError> {
    
    // 1. Basic validation (existing logic)
    // ...
    
    // 2. Check if ExecutionProofs are enabled
    if chain.config.proof_config.enabled {
        // Try proof-based verification first
        match try_proof_verification(chain, payload).await {
            Ok(status) => return Ok(status),
            Err(ProofError::ProofNotAvailable) if chain.config.proof_config.optimistic_acceptance => {
                // Accept optimistically and spawn async proof validation
                spawn_proof_validation_handler(chain.clone(), payload_hash, proof_receiver);
                return Ok(PayloadVerificationStatus::Optimistic);
            },
            Err(ProofError::ProofNotAvailable) if chain.config.proof_config.fallback_to_execution => {
                // Fall back to EL verification
                return try_execution_layer_verification(chain, payload).await;
            },
            Err(e) => return Err(e.into()),
        }
    }
    
    // 3. Standard EL verification (existing optimistic sync logic)  
    try_execution_layer_verification(chain, payload).await
}

async fn try_proof_verification<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    payload: &ExecutionPayload<T::EthSpec>,
) -> Result<PayloadVerificationStatus, ProofError> {
    let payload_hash = payload.block_hash();
    
    // Check global proof cache
    let cache = GlobalExecutionProofCache::instance();
    
    match cache.get_verification_result(&payload_hash).await {
        Some(true) => Ok(PayloadVerificationStatus::Verified),
        Some(false) => Err(ProofError::ProofInvalid),
        None => Err(ProofError::ProofNotAvailable),
    }
}
```

### 5. Configuration System

**Step 7: Configuration Management**

```rust
// beacon_node/beacon_chain/src/proof_config.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofConfig {
    /// Enable ExecutionProofs verification
    pub enabled: bool,
    
    /// Accept payloads optimistically when proofs not available
    pub optimistic_acceptance: bool,
    
    /// Fall back to EL verification when proofs not available  
    pub fallback_to_execution: bool,
    
    /// Timeout for proof verification (milliseconds)
    pub verification_timeout_ms: u64,
    
    /// Maximum number of cached proofs
    pub max_cache_size: usize,
    
    /// TTL for cached proofs (seconds)
    pub cache_ttl_seconds: u64,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            enabled: false,                    // Opt-in feature
            optimistic_acceptance: true,       // Safe fallback
            fallback_to_execution: true,       // Compatibility
            verification_timeout_ms: 5000,     // 5 second timeout
            max_cache_size: 1000,             // Reasonable cache size
            cache_ttl_seconds: 300,           // 5 minute TTL
        }
    }
}
```

### 6. Proof Verifier Interface

**Step 8: Proof Verification Trait**

```rust
// beacon_node/beacon_chain/src/execution_proof_cache.rs
#[async_trait]
pub trait ProofVerifier: Send + Sync {
    async fn verify(&self, proof: &ExecutionProof) -> Result<bool, ProofError>;
    fn extract_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, ProofError>;
}

// Example implementations (placeholder)
pub struct SP1ProofVerifier;
pub struct Risc0ProofVerifier;  
pub struct ExecutionWitnessVerifier;

#[async_trait]
impl ProofVerifier for SP1ProofVerifier {
    async fn verify(&self, proof: &ExecutionProof) -> Result<bool, ProofError> {
        // TODO: Implement SP1 proof verification
        // This would integrate with SP1 verifier library
        todo!("SP1 proof verification")
    }
    
    fn extract_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, ProofError> {
        // TODO: Extract payload hash from SP1 proof data
        todo!("SP1 payload hash extraction")
    }
}
```

## Block Production and ExecutionProofs

### Overview

ExecutionProofs enhances the block production workflow by enabling cryptographic verification of execution payloads through zkVM proofs and execution witnesses. The system is designed to support both **synchronous** and **asynchronous** proof generation patterns while maintaining backward compatibility with existing block production flows.

### Traditional vs ExecutionProofs Block Production

#### Traditional Block Production Flow
```
Validator Duty → Generate Block → Sign Block → Publish Block → Network Propagation
```

#### ExecutionProofs Enhanced Flow
```
Validator Duty → Generate Block → Sign Block → Publish Block → Network Propagation
                      ↓              ↓            ↓
                 [Proof Generation] → [Proof Gossip] → [Proof Verification]
```

### Current Implementation Status

The current Lighthouse implementation focuses on **proof consumption and verification** rather than **proof generation during block production**. This design choice provides several benefits:

- **Non-blocking**: Block production latency is unaffected by proof generation
- **Decoupled**: Proof generation can be handled by specialized external services
- **Flexible**: Supports multiple proof generation strategies and timing models

### Block Production Integration Points

#### 1. Payload Verification Enhancement

The core integration happens in the payload verification flow (`execution_payload.rs`):

```rust
pub async fn verify_and_notify_new_payload<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    payload: &ExecutionPayload<T::EthSpec>,
) -> Result<PayloadVerificationStatus, ExecutionPayloadError> {
    
    // Enhanced verification flow with ExecutionProofs
    if chain.config.proof_config.enabled {
        // 1. Try proof-based verification first
        match try_proof_verification(chain, payload).await {
            Ok(PayloadVerificationStatus::Verified) => return Ok(PayloadVerificationStatus::Verified),
            Ok(PayloadVerificationStatus::Invalid) => return Err(ExecutionPayloadError::InvalidProof),
            Err(ProofError::ProofNotAvailable) => {
                // 2. Handle missing proofs based on config
                if chain.config.proof_config.optimistic_acceptance {
                    spawn_async_proof_validation(chain.clone(), payload.block_hash());
                    return Ok(PayloadVerificationStatus::Optimistic);
                } else if chain.config.proof_config.fallback_to_execution {
                    // Fall through to EL verification
                } else {
                    return Err(ExecutionPayloadError::ProofRequired);
                }
            }
        }
    }
    
    // 3. Standard EL verification (existing optimistic sync logic)
    execute_payload_verification_el(chain, payload).await
}
```

#### 2. Proof Cache Integration

Block production leverages the global proof cache:

```rust
// Global cache accessible during block production
let cache = GlobalExecutionProofCache::instance();

// Check for available proofs during payload verification
if let Some(proof_result) = cache.get_verification_result(&payload_hash).await {
    return match proof_result {
        true => Ok(PayloadVerificationStatus::Verified),
        false => Err(ExecutionPayloadError::InvalidProof),
    };
}
```

### Proof Generation Patterns

#### Pattern 1: External Proof Producers (Current)

**Architecture:**
```
Block Producer (Validator) ← → Beacon Node ← → Proof Producer (External)
                                    ↓
                               Proof Cache ← → Gossip Network
```

**Workflow:**
1. **Block Producer**: Generates and publishes blocks normally
2. **Proof Producer**: Monitors execution payloads independently
3. **Proof Producer**: Generates proofs asynchronously
4. **Proof Producer**: Publishes proofs to gossip subnets
5. **Beacon Nodes**: Receive and cache proofs for validation

**Benefits:**
- No block production latency impact
- Specialized proof generation services
- Horizontal scaling of proof generation
- Independent proof producer development

**Example External Proof Producer:**
```rust
pub struct ExternalProofProducer {
    execution_client: Arc<ExecutionClient>,
    proof_generator: Box<dyn ProofGenerator>,
    network_client: Arc<NetworkClient>,
}

impl ExternalProofProducer {
    pub async fn run(&self) {
        let mut payload_stream = self.execution_client.subscribe_new_payloads().await;
        
        while let Some(payload) = payload_stream.next().await {
            // Generate proof asynchronously
            let proof_generation = self.generate_proof_for_payload(payload.clone());
            
            tokio::spawn(async move {
                match proof_generation.await {
                    Ok(proof) => {
                        // Publish to appropriate subnet
                        let subnet_id = ProofSubnetId::from_proof_type(proof.get_type());
                        self.network_client.publish_execution_proof(proof, subnet_id).await;
                    }
                    Err(e) => warn!("Proof generation failed: {}", e),
                }
            });
        }
    }
    
    async fn generate_proof_for_payload(&self, payload: ExecutionPayload) -> Result<ExecutionProof, ProofError> {
        // 1. Extract necessary data from payload
        let block_data = self.execution_client.get_block_data(&payload.block_hash()).await?;
        let state_data = self.execution_client.get_state_data(&payload.parent_hash()).await?;
        
        // 2. Generate proof using zkVM or witness generation
        let proof_data = self.proof_generator.generate(block_data, state_data).await?;
        
        // 3. Create ExecutionProof
        Ok(ExecutionProof::new(self.proof_generator.version(), proof_data))
    }
}
```

#### Pattern 2: Integrated Proof Generation (Future Enhancement)

**Architecture for Future Enhancement:**
```rust
pub async fn produce_block_with_proof_generation<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    proof_generator: Option<Box<dyn ProofGenerator>>,
    // ... other params
) -> Result<(BeaconBlockResponseWrapper<T::EthSpec>, Option<ProofHandle>), BlockProductionError> {
    
    // 1. Generate block normally
    let block_response = chain.produce_block_with_verification(/* ... */).await?;
    
    // 2. If proof generation requested, spawn async proof generation
    let proof_handle = if let Some(generator) = proof_generator {
        let payload = block_response.execution_payload().clone();
        let handle = tokio::spawn(async move {
            generator.generate_proof(&payload).await
        });
        Some(ProofHandle::new(handle))
    } else {
        None
    };
    
    // 3. Return block immediately, proof generation continues async
    Ok((block_response, proof_handle))
}
```

### Proof Producer Interfaces

#### Current Interface Design

**Proof Verifier Trait:**
```rust
#[async_trait]
pub trait ProofVerifier: Send + Sync {
    async fn verify(&self, proof: &ExecutionProof) -> Result<bool, ProofError>;
    fn extract_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, ProofError>;
    fn proof_type(&self) -> ProofType;
}
```

**Global Cache Interface:**
```rust
impl GlobalExecutionProofCache {
    // For proof producers
    pub async fn cache_proof(&self, payload_hash: Hash256, proof: ExecutionProof);
    
    // For proof consumers  
    pub async fn get_verification_result(&self, payload_hash: &Hash256) -> Option<bool>;
    
    // For async validation
    pub async fn add_pending_validation(&self, payload_hash: Hash256) 
        -> mpsc::UnboundedReceiver<ProofValidationResult>;
}
```

#### Future Producer Interface (Proposed)

**Proof Generator Trait:**
```rust
#[async_trait]
pub trait ProofGenerator: Send + Sync {
    async fn generate_proof(&self, payload: &ExecutionPayload) -> Result<ExecutionProof, ProofError>;
    fn proof_type(&self) -> ProofType;
    fn version(&self) -> u8;
    async fn can_generate_for(&self, payload: &ExecutionPayload) -> bool;
}

// Example implementations
pub struct SP1ProofGenerator {
    sp1_prover: SP1Prover,
    execution_client: Arc<ExecutionClient>,
}

pub struct ExecutionWitnessGenerator {
    witness_builder: WitnessBuilder,
    execution_client: Arc<ExecutionClient>,
}
```

### Timing and Performance Considerations

#### Proof Generation Timing Models

**Model 1: Post-Block Generation (Current)**
```
Block Production: [0ms -------- 100ms] → Block Published
Proof Generation:         [50ms -------- 2000ms] → Proof Published
Proof Verification:                [100ms - 150ms] → Payload Verified
```

**Model 2: Parallel Generation (Future)**
```
Block Production: [0ms -------- 100ms] → Block Published
Proof Generation: [0ms -------- 2000ms] → Proof Published  
Proof Verification:                [100ms - 150ms] → Payload Verified
```

**Model 3: Pre-Generation (Advanced)**
```
Proof Pre-gen:    [Pre-computed proofs for common state transitions]
Block Production: [0ms ---- 50ms] → Block + Proof Published
Proof Verification:        [50ms - 100ms] → Payload Verified
```

#### Performance Metrics

**Block Production Impact:**
- Current implementation: **0ms additional latency**
- With integrated generation: **0-50ms** (async spawn overhead)
- With synchronous generation: **500-5000ms** (proof generation time)

**Network Efficiency:**
- Proof size: **100KB - 10MB** (depending on proof type)
- Gossip propagation: **100-500ms** additional latency
- Cache hit rate: **>90%** expected in steady state

### Configuration for Block Production

#### Producer Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofProductionConfig {
    /// Enable proof generation during block production
    pub enabled: bool,
    
    /// Proof generation strategy
    pub strategy: ProofGenerationStrategy,
    
    /// Proof types to generate
    pub proof_types: Vec<ProofType>,
    
    /// Maximum time to wait for proof generation (ms)
    pub generation_timeout_ms: u64,
    
    /// Whether to publish block without waiting for proof
    pub non_blocking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofGenerationStrategy {
    External,           // Use external proof producers
    Integrated,         // Generate proofs in block producer
    Hybrid,            // Try integrated, fallback to external
}
```

#### CLI Integration

```bash
# For block producers
lighthouse validator_client \
  --proof-generation-enabled \
  --proof-generation-strategy integrated \
  --proof-types sp1,risc0 \
  --proof-generation-timeout 5000 \
  --proof-generation-non-blocking

# For beacon nodes  
lighthouse beacon_node \
  --execution-proofs-enabled \
  --execution-proofs-producer-mode \
  --execution-proofs-subscribe-subnets 0,1,2
```

### Integration with Existing Systems

#### Builder API Integration

**MEV-Boost Compatibility:**
```rust
// ExecutionProofs can work alongside MEV-Boost
pub async fn get_payload_with_proofs(
    &self,
    payload_id: PayloadId,
    proof_requirements: Option<ProofRequirements>,
) -> Result<(ExecutionPayload, Option<ExecutionProof>), Error> {
    
    // 1. Get payload from builder/EL
    let payload = self.get_payload(payload_id).await?;
    
    // 2. If proofs required, check cache or generate
    let proof = if let Some(req) = proof_requirements {
        self.get_or_generate_proof(&payload, req).await?
    } else {
        None
    };
    
    Ok((payload, proof))
}
```

#### Validator Client Integration

**Block Production Service Enhancement:**
```rust
impl<T: SlotClock + 'static, E: EthSpec> BlockService<T, E> {
    async fn produce_block_with_proofs(
        &self,
        slot: Slot,
        randao_reveal: Signature,
        proof_config: Option<ProofProductionConfig>,
    ) -> Result<SignedBeaconBlock<E>, BlockError> {
        
        // 1. Standard block production
        let unsigned_block = self.beacon_node
            .get_validator_blocks(slot, randao_reveal, None)
            .await?;
        
        // 2. Sign block
        let signed_block = self.sign_block(unsigned_block).await?;
        
        // 3. If proof generation enabled, start async proof generation
        if let Some(config) = proof_config {
            self.start_proof_generation(&signed_block, config).await;
        }
        
        // 4. Publish block (non-blocking)
        self.publish_block(signed_block.clone()).await?;
        
        Ok(signed_block)
    }
}
```

### Monitoring and Observability

#### Block Production Metrics

```
# Block production with ExecutionProofs
execution_proofs_block_production_duration_seconds{stage}
execution_proofs_proof_generation_requests_total{type}
execution_proofs_proof_generation_successes_total{type}
execution_proofs_proof_generation_failures_total{type,reason}
execution_proofs_proof_generation_duration_seconds{type}
```

#### Proof Producer Metrics

```
# External proof producers
execution_proofs_payloads_monitored_total
execution_proofs_proofs_generated_total{type}
execution_proofs_proofs_published_total{type,subnet}
execution_proofs_generation_queue_size{type}
execution_proofs_network_publish_duration_seconds{subnet}
```

### Best Practices

#### For Block Producers

1. **Use non-blocking proof generation** to avoid impacting block production latency
2. **Configure appropriate timeouts** for proof generation
3. **Monitor proof success rates** and adjust strategies accordingly
4. **Implement fallback mechanisms** when proof generation fails
5. **Consider proof pre-generation** for common state transitions

#### For Proof Producers

1. **Monitor execution payload sources** for new blocks requiring proofs
2. **Implement efficient proof generation** with appropriate parallelization
3. **Use subnet-specific publishing** based on proof types
4. **Implement retry logic** for failed proof generations
5. **Cache intermediate proof data** to optimize generation speed

#### For Network Operators

1. **Subscribe to relevant proof subnets** based on verification needs
2. **Configure appropriate cache sizes** for expected proof volumes
3. **Monitor proof verification success rates** 
4. **Implement DoS protection** for proof processing
5. **Plan capacity** for proof storage and verification

## Network Protocol

### Gossip Subnet Architecture

ExecutionProofs uses a dedicated gossip subnet system with 8 total subnets:

```
Subnet 0: SP1 Proofs           (/eth2/{fork_digest}/execution_proof_0/ssz_snappy)
Subnet 1: Risc0 Proofs         (/eth2/{fork_digest}/execution_proof_1/ssz_snappy)  
Subnet 2: Execution Witnesses  (/eth2/{fork_digest}/execution_proof_2/ssz_snappy)
Subnet 3-7: Reserved           (Future zkVM systems)
```

### Message Flow

```
1. Proof Producer → Generate ExecutionProof for payload
2. Proof Producer → Publish to appropriate subnet (based on proof type)
3. Network → Gossip proof to interested peers
4. Consensus Client → Receive proof via gossip
5. Consensus Client → Verify proof and update payload status
6. Consensus Client → Continue consensus with verified payload
```

### Peer Discovery

Peers advertise their supported proof subnets in their ENR metadata:

```
proofnets: <8-bit bitfield indicating subscribed proof subnets>
```

## Configuration

### CLI Flags (Example for Lighthouse)

```bash
lighthouse beacon_node \
  --execution-proofs-enabled \
  --execution-proofs-optimistic-acceptance \
  --execution-proofs-fallback-to-execution \
  --execution-proofs-verification-timeout 5000 \
  --execution-proofs-cache-size 1000 \
  --execution-proofs-cache-ttl 300
```

### Configuration File

```yaml
# beacon_node.yaml
execution_proofs:
  enabled: true
  optimistic_acceptance: true
  fallback_to_execution: true
  verification_timeout_ms: 5000
  max_cache_size: 1000
  cache_ttl_seconds: 300
```

### Environment Variables

```bash
EXECUTION_PROOFS_ENABLED=true
EXECUTION_PROOFS_OPTIMISTIC_ACCEPTANCE=true
EXECUTION_PROOFS_FALLBACK_TO_EXECUTION=true
```

## Testing

### Unit Tests

**Test Proof Subnet Mapping**

```rust
#[test]
fn test_proof_subnet_mapping() {
    assert_eq!(ProofSubnetId::sp1(), ProofSubnetId(0));
    assert_eq!(ProofSubnetId::risc0(), ProofSubnetId(1));
    assert_eq!(ProofSubnetId::execution_witness(), ProofSubnetId(2));
}
```

**Test Cache Behavior**

```rust
#[tokio::test]
async fn test_execution_proof_cache() {
    let config = ProofConfig::default();
    let cache = ExecutionProofCache::new(config);
    
    let proof = ExecutionProof::new(0, vec![1, 2, 3, 4]);
    let payload_hash = Hash256::random();
    
    // Verify proof gets cached
    let result = cache.verify_proof(&proof, payload_hash).await.unwrap();
    assert!(result);
    
    // Verify cache hit
    let cached_result = cache.get_verification_result(&payload_hash).await;
    assert_eq!(cached_result, Some(true));
}
```

### Integration Tests

**Test End-to-End Proof Flow**

```rust
#[tokio::test]
async fn test_proof_validation_integration() {
    let mut chain = BeaconChainHarness::builder()
        .proof_config(ProofConfig { enabled: true, ..Default::default() })
        .build();
    
    // Create payload with proof
    let payload = generate_test_payload();
    let proof = generate_test_proof_for_payload(&payload);
    
    // Simulate proof arrival via gossip
    chain.process_execution_proof(proof).await;
    
    // Verify payload is accepted and verified
    let status = chain.get_payload_status(&payload.block_hash()).await;
    assert_eq!(status, PayloadVerificationStatus::Verified);
}
```

## Production Considerations

### Performance

- **Cache Size**: Configure based on expected proof volume and memory constraints
- **Verification Timeout**: Balance between thoroughness and block import speed
- **Subnet Selection**: Consider proof generation capabilities when subscribing to subnets

### Security

- **Proof Validation**: Ensure robust verification logic to prevent invalid proof acceptance
- **Resource Limits**: Implement DoS protection for proof processing
- **Fallback Safety**: Always maintain EL verification as a fallback option

### Monitoring

**Key Metrics to Track:**

```
execution_proofs_received_total{subnet_id}
execution_proofs_verified_total{result}
execution_proofs_cache_hits_total
execution_proofs_cache_misses_total
execution_proofs_verification_duration_seconds
execution_proofs_fallback_to_el_total
```

### Migration Strategy

1. **Phase 1**: Deploy with `enabled: false` (infrastructure only)
2. **Phase 2**: Enable proof reception and caching (`enabled: true, optimistic_acceptance: true`)
3. **Phase 3**: Gradual transition from EL-first to proof-first verification
4. **Phase 4**: Production deployment with proof generation

### Compatibility

- **Backward Compatible**: Full compatibility with non-ExecutionProofs clients
- **Graceful Degradation**: Automatic fallback to standard optimistic sync
- **Network Agnostic**: Works with any Ethereum network (mainnet, testnets)

## Conclusion

ExecutionProofs represents a significant advancement in Ethereum consensus client architecture, providing cryptographic assurance for execution payload verification while maintaining full backward compatibility. The implementation leverages existing optimistic sync infrastructure, making it a natural evolution rather than a complete redesign.

Key implementation success factors:

1. **Reuse existing patterns** (PayloadVerificationStatus, optimistic acceptance)
2. **Maintain fallback mechanisms** (EL verification when proofs unavailable)  
3. **Implement robust caching** (LRU + TTL for performance)
4. **Design for extensibility** (multiple proof types, configurable timeouts)
5. **Follow Ethereum standards** (SSZ encoding, gossip protocol compliance)

This implementation guide provides the blueprint for adding ExecutionProofs support to any Ethereum consensus client while maintaining production reliability and performance standards.
