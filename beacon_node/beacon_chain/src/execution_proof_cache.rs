//! Cache for execution proofs received via gossip subnets.
//!
//! This cache stores proofs by their associated payload hash and handles
//! async validation of optimistically accepted payloads when proofs arrive.

use lru::LruCache;
use slog::{debug, info, warn, Logger};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use types::{EthSpec, ExecutionProof, Hash256, ProofSubnetId, ProofType};

/// Maximum number of proofs to cache
const PROOF_CACHE_SIZE: usize = 1024;

/// How long to keep proofs in cache
const PROOF_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// How long to wait for proofs before timing out
const PENDING_PROOF_TIMEOUT: Duration = Duration::from_secs(60); // 1 minute

/// Global proof cache instance (EthSpec-agnostic)
static GLOBAL_PROOF_CACHE: std::sync::OnceLock<Arc<GlobalExecutionProofCache>> = std::sync::OnceLock::new();

/// Global proof verifier registry (EthSpec-agnostic)
static GLOBAL_PROOF_VERIFIER_REGISTRY: std::sync::OnceLock<Arc<GlobalProofVerifierRegistry>> = std::sync::OnceLock::new();

/// Cache for execution proofs and pending validation requests
#[derive(Debug)]
pub struct ExecutionProofCache<E: EthSpec> {
    /// Cache proofs by their expected payload hash
    proofs: RwLock<LruCache<Hash256, CachedProof>>,
    /// Track optimistically accepted payloads waiting for proofs
    pending_proofs: RwLock<HashMap<Hash256, PendingProofValidation<E>>>,
}

/// A cached proof with metadata
#[derive(Debug, Clone)]
pub struct CachedProof {
    pub proof: ExecutionProof,
    pub subnet_id: ProofSubnetId,
    pub received_at: Instant,
}

/// Information about a payload waiting for proof validation
#[derive(Debug)]
pub struct PendingProofValidation<E: EthSpec> {
    pub payload_hash: Hash256,
    pub block_root: Hash256,
    pub accepted_at: Instant,
    pub validation_sender: mpsc::UnboundedSender<ProofValidationResult>,
    pub _phantom: PhantomData<E>,
}

/// Result of proof validation
#[derive(Debug, Clone)]
pub enum ProofValidationResult {
    Valid,
    Invalid { reason: String },
    Error { error: String },
}

impl<E: EthSpec> ExecutionProofCache<E> {
    /// Create a new execution proof cache
    pub fn new() -> Self {
        Self {
            proofs: RwLock::new(LruCache::new(
                NonZeroUsize::new(PROOF_CACHE_SIZE).expect("cache size > 0"),
            )),
            pending_proofs: RwLock::new(HashMap::new()),
        }
    }

    /// Cache a proof received from gossip subnet
    pub async fn cache_proof(&self, proof: ExecutionProof, subnet_id: ProofSubnetId) {
        // Extract payload hash from proof data
        // Note: This is proof-type specific and would need to be implemented
        // based on the actual proof format
        if let Ok(payload_hash) = self.extract_payload_hash(&proof, subnet_id) {
            let cached_proof = CachedProof {
                proof,
                subnet_id,
                received_at: Instant::now(),
            };

            // Store the proof
            {
                let mut proofs = self.proofs.write().await;
                proofs.put(payload_hash, cached_proof.clone());
            }

            // Check if we have pending validation for this payload
            let pending = {
                let mut pending_proofs = self.pending_proofs.write().await;
                pending_proofs.remove(&payload_hash)
            };

            if let Some(pending) = pending {
                // Proof arrived for a pending payload - validate it
                self.validate_pending_proof(pending, cached_proof).await;
            }
        }
    }

    /// Get a cached proof for a payload hash
    pub async fn get_proof(&self, payload_hash: Hash256) -> Option<CachedProof> {
        let mut proofs = self.proofs.write().await;
        proofs.get(&payload_hash).cloned()
    }

    /// Add a payload that was optimistically accepted and needs proof validation
    pub async fn add_pending_validation(
        &self,
        payload_hash: Hash256,
        block_root: Hash256,
    ) -> mpsc::UnboundedReceiver<ProofValidationResult> {
        let (tx, rx) = mpsc::unbounded_channel();

        let pending = PendingProofValidation {
            payload_hash,
            block_root,
            accepted_at: Instant::now(),
            validation_sender: tx,
            _phantom: PhantomData,
        };

        {
            let mut pending_proofs = self.pending_proofs.write().await;
            pending_proofs.insert(payload_hash, pending);
        }

        rx
    }

    /// Clean up expired entries
    pub async fn cleanup_expired(&self) {
        let now = Instant::now();

        // Clean up expired proofs
        {
            let mut proofs = self.proofs.write().await;
            let mut keys_to_remove = Vec::new();
            
            // Collect keys of expired proofs
            for (key, cached_proof) in proofs.iter() {
                if now.duration_since(cached_proof.received_at) >= PROOF_CACHE_TTL {
                    keys_to_remove.push(*key);
                }
            }
            
            // Remove expired proofs
            for key in keys_to_remove {
                proofs.pop(&key);
            }
        }

        // Clean up expired pending validations
        {
            let mut pending_proofs = self.pending_proofs.write().await;
            pending_proofs.retain(|_, pending| {
                let expired = now.duration_since(pending.accepted_at) > PENDING_PROOF_TIMEOUT;
                if expired {
                    // Send timeout error
                    let _ = pending.validation_sender.send(ProofValidationResult::Error {
                        error: "Proof validation timeout".to_string(),
                    });
                }
                !expired
            });
        }
    }

    /// Extract payload hash from proof data
    /// This is proof-type specific and needs to be implemented based on actual proof formats
    fn extract_payload_hash(
        &self,
        proof: &ExecutionProof,
        subnet_id: ProofSubnetId,
    ) -> Result<Hash256, String> {
        // TODO: Implement based on actual proof formats
        // For now, return an error - this would be implemented when
        // integrating with actual SP1/Risc0/witness formats
        
        match subnet_id.into() {
            0 => self.extract_sp1_payload_hash(proof),
            1 => self.extract_risc0_payload_hash(proof),
            2 => self.extract_witness_payload_hash(proof),
            _ => Err("Unsupported proof type".to_string()),
        }
    }

    fn extract_sp1_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, String> {
        // TODO: Implement SP1 proof payload hash extraction
        // For now, use first 32 bytes of proof data as placeholder
        if proof.data().len() >= 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&proof.data()[0..32]);
            Ok(Hash256::from(bytes))
        } else {
            Err("SP1 proof too short for payload hash extraction".to_string())
        }
    }

    fn extract_risc0_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, String> {
        // TODO: Implement Risc0 proof payload hash extraction
        // For now, use first 32 bytes of proof data as placeholder
        if proof.data().len() >= 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&proof.data()[0..32]);
            Ok(Hash256::from(bytes))
        } else {
            Err("Risc0 proof too short for payload hash extraction".to_string())
        }
    }

    fn extract_witness_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, String> {
        // TODO: Implement execution witness payload hash extraction
        // For now, use first 32 bytes of proof data as placeholder
        if proof.data().len() >= 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&proof.data()[0..32]);
            Ok(Hash256::from(bytes))
        } else {
            Err("Execution witness too short for payload hash extraction".to_string())
        }
    }

    /// Validate a proof against a pending payload
    async fn validate_pending_proof(
        &self,
        pending: PendingProofValidation<E>,
        cached_proof: CachedProof,
    ) {
        // TODO: Implement actual proof verification based on proof type
        // For now, send a placeholder result
        let result = ProofValidationResult::Error {
            error: "Proof verification not implemented".to_string(),
        };

        let _ = pending.validation_sender.send(result);
    }
}

impl<E: EthSpec> Default for ExecutionProofCache<E> {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for proof-based execution payload verification
#[derive(Debug, Clone)]
pub struct ProofConfig {
    /// Whether proof verification is enabled
    pub enabled: bool,
    /// Proof types to accept and verify
    pub accepted_proof_types: Vec<ProofType>,
    /// Whether to accept payloads optimistically when proofs are not available
    pub optimistic_acceptance: bool,
    /// Whether to fallback to normal execution verification if proof verification fails
    pub fallback_to_execution: bool,
    /// Timeout for proof verification operations (in milliseconds)
    pub verification_timeout_ms: u64,
    /// Maximum number of execution proofs to cache
    pub max_cache_size: usize,
    /// Time-to-live for cached execution proofs (in seconds)
    pub cache_ttl_seconds: u64,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            accepted_proof_types: vec![ProofType::SP1Proof, ProofType::Risc0Proof, ProofType::ExecutionWitness],
            optimistic_acceptance: true,
            fallback_to_execution: true,
            verification_timeout_ms: 5000, // 5 seconds
            max_cache_size: 1000,
            cache_ttl_seconds: 300, // 5 minutes
        }
    }
}

/// Trait for proof verification
/// This allows different proof types to implement their own verification logic
pub trait ProofVerifier<E: EthSpec>: Send + Sync {
    /// Verify a proof against an execution payload
    fn verify_proof(
        &self,
        proof: &ExecutionProof,
        payload_hash: Hash256,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + '_>>;

    /// Get the proof type this verifier handles
    fn proof_type(&self) -> ProofType;
}

/// Registry of proof verifiers
#[derive(Default)]
pub struct ProofVerifierRegistry<E: EthSpec> {
    verifiers: HashMap<ProofType, Arc<dyn ProofVerifier<E>>>,
}

impl<E: EthSpec> ProofVerifierRegistry<E> {
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    pub fn register_verifier(&mut self, verifier: Arc<dyn ProofVerifier<E>>) {
        self.verifiers.insert(verifier.proof_type(), verifier);
    }

    pub async fn verify_proof(
        &self,
        proof_type: ProofType,
        proof: &ExecutionProof,
        payload_hash: Hash256,
    ) -> Result<bool, String> {
        if let Some(verifier) = self.verifiers.get(&proof_type) {
            verifier.verify_proof(proof, payload_hash).await
        } else {
            Err(format!("No verifier registered for proof type {:?}", proof_type))
        }
    }
}

/// Global execution proof cache (EthSpec-agnostic)
/// This avoids the need to modify BeaconChain struct
#[derive(Debug)]
pub struct GlobalExecutionProofCache {
    /// Cache proofs by their expected payload hash
    proofs: RwLock<LruCache<Hash256, CachedProof>>,
    /// Track pending validation requests by payload hash
    pending_proofs: RwLock<HashMap<Hash256, Vec<mpsc::UnboundedSender<ProofValidationResult>>>>,
    /// Logger for the global cache
    log: Logger,
}

impl GlobalExecutionProofCache {
    pub fn new(log: Logger) -> Self {
        Self {
            proofs: RwLock::new(LruCache::new(
                NonZeroUsize::new(PROOF_CACHE_SIZE).expect("Cache size must be non-zero")
            )),
            pending_proofs: RwLock::new(HashMap::new()),
            log,
        }
    }

    /// Get a cached proof for a payload hash
    pub async fn get_proof(&self, payload_hash: Hash256) -> Option<CachedProof> {
        let mut proofs = self.proofs.write().await;
        proofs.get(&payload_hash).cloned()
    }

    /// Cache a proof from gossip
    pub async fn cache_proof(&self, proof: ExecutionProof, subnet_id: ProofSubnetId) {
        // Extract payload hash from proof data (placeholder implementation)
        if let Ok(payload_hash) = self.extract_payload_hash(&proof, subnet_id) {
            let cached_proof = CachedProof {
                proof,
                subnet_id,
                received_at: Instant::now(),
            };

            debug!(
                self.log,
                "Caching execution proof";
                "payload_hash" => ?payload_hash,
                "subnet_id" => ?subnet_id,
            );

            // Store the proof
            {
                let mut proofs = self.proofs.write().await;
                proofs.put(payload_hash, cached_proof);
            }

            // Notify any pending validation requests
            let pending_senders = {
                let mut pending_proofs = self.pending_proofs.write().await;
                pending_proofs.remove(&payload_hash).unwrap_or_default()
            };

            for sender in pending_senders {
                // For now, send a placeholder result since actual verification
                // would require the BeaconChain context
                let _ = sender.send(ProofValidationResult::Valid);
            }
        }
    }

    /// Add a pending validation request
    pub async fn add_pending_validation(
        &self, 
        payload_hash: Hash256
    ) -> mpsc::UnboundedReceiver<ProofValidationResult> {
        let (tx, rx) = mpsc::unbounded_channel();

        {
            let mut pending_proofs = self.pending_proofs.write().await;
            pending_proofs.entry(payload_hash).or_insert_with(Vec::new).push(tx);
        }

        rx
    }

    /// Extract payload hash from proof data (placeholder implementation)
    fn extract_payload_hash(
        &self,
        proof: &ExecutionProof,
        subnet_id: ProofSubnetId,
    ) -> Result<Hash256, String> {
        match subnet_id.into() {
            0 => self.extract_sp1_payload_hash(proof),
            1 => self.extract_risc0_payload_hash(proof),
            2 => self.extract_witness_payload_hash(proof),
            _ => Err("Unsupported proof type".to_string()),
        }
    }

    fn extract_sp1_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, String> {
        // TODO: Implement SP1 proof payload hash extraction
        // For now, use first 32 bytes of proof data as placeholder
        if proof.data().len() >= 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&proof.data()[0..32]);
            Ok(Hash256::from(bytes))
        } else {
            Err("SP1 proof too short for payload hash extraction".to_string())
        }
    }

    fn extract_risc0_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, String> {
        // TODO: Implement Risc0 proof payload hash extraction
        // For now, use first 32 bytes of proof data as placeholder
        if proof.data().len() >= 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&proof.data()[0..32]);
            Ok(Hash256::from(bytes))
        } else {
            Err("Risc0 proof too short for payload hash extraction".to_string())
        }
    }

    fn extract_witness_payload_hash(&self, proof: &ExecutionProof) -> Result<Hash256, String> {
        // TODO: Implement execution witness payload hash extraction
        // For now, use first 32 bytes of proof data as placeholder
        if proof.data().len() >= 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&proof.data()[0..32]);
            Ok(Hash256::from(bytes))
        } else {
            Err("Execution witness too short for payload hash extraction".to_string())
        }
    }

    /// Clean up expired entries
    pub async fn cleanup_expired(&self) {
        let now = Instant::now();

        // Clean up expired proofs
        {
            let mut proofs = self.proofs.write().await;
            let mut keys_to_remove = Vec::new();
            
            // Collect keys of expired proofs
            for (key, cached_proof) in proofs.iter() {
                if now.duration_since(cached_proof.received_at) >= PROOF_CACHE_TTL {
                    keys_to_remove.push(*key);
                }
            }
            
            // Remove expired proofs
            for key in keys_to_remove {
                proofs.pop(&key);
            }
        }

        // Clean up expired pending validations
        {
            let mut pending_proofs = self.pending_proofs.write().await;
            pending_proofs.retain(|_, _| {
                // For simplicity, we'll keep all pending requests
                // In a real implementation, we'd track timestamps and remove old ones
                true
            });
        }
    }
}

/// Global proof verifier registry (EthSpec-agnostic)
#[derive(Default)]
pub struct GlobalProofVerifierRegistry {
    verifiers: RwLock<HashMap<ProofType, ProofVerifierFn>>,
}

/// Function type for proof verification to avoid EthSpec generics
type ProofVerifierFn = Box<dyn Fn(&ExecutionProof, Hash256) -> Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + '_>> + Send + Sync>;

impl GlobalProofVerifierRegistry {
    pub fn new() -> Self {
        Self {
            verifiers: RwLock::new(HashMap::new()),
        }
    }

    pub async fn verify_proof(
        &self,
        proof_type: ProofType,
        proof: &ExecutionProof,
        payload_hash: Hash256,
    ) -> Result<bool, String> {
        let verifiers = self.verifiers.read().await;
        if let Some(verifier) = verifiers.get(&proof_type) {
            verifier(proof, payload_hash).await
        } else {
            Err(format!("No verifier registered for proof type {:?}", proof_type))
        }
    }
}

/// Initialize the global proof cache
pub fn initialize_global_proof_cache(log: Logger) -> Arc<GlobalExecutionProofCache> {
    GLOBAL_PROOF_CACHE.get_or_init(|| {
        Arc::new(GlobalExecutionProofCache::new(log))
    }).clone()
}

/// Initialize the global proof verifier registry
pub fn initialize_global_proof_verifier_registry() -> Arc<GlobalProofVerifierRegistry> {
    GLOBAL_PROOF_VERIFIER_REGISTRY.get_or_init(|| {
        Arc::new(GlobalProofVerifierRegistry::new())
    }).clone()
}

/// Get the global proof cache instance
pub fn get_global_proof_cache() -> Option<Arc<GlobalExecutionProofCache>> {
    GLOBAL_PROOF_CACHE.get().cloned()
}

/// Get the global proof verifier registry instance
pub fn get_global_proof_verifier_registry() -> Option<Arc<GlobalProofVerifierRegistry>> {
    GLOBAL_PROOF_VERIFIER_REGISTRY.get().cloned()
}