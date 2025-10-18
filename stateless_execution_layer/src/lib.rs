mod config;
mod dummy_generator;
mod dummy_verifier;
mod generator_registry;
mod proof_cache;
mod proof_generation;
mod proof_verification;
mod verifier_registry;

pub use config::{StatelessExecutionLayerConfig, StatelessExecutionLayerConfigBuilder};
pub use dummy_generator::DummyGenerator;
pub use dummy_verifier::DummyVerifier;
pub use generator_registry::GeneratorRegistry;
pub use proof_cache::ProofCache;
pub use proof_generation::{GenerationError, GenerationResult, ProofGenerator};
pub use proof_verification::{ProofVerifier, VerificationError, VerificationResult};
pub use verifier_registry::VerifierRegistry;

use slog::{debug, error, info, warn, Logger};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use types::{ExecutionBlockHash, ExecutionProof, ExecutionProofSubnetId, Hash256};

/// Type for the callback function when proofs become available
pub type ProofReadyCallback = Arc<dyn Fn(ExecutionBlockHash) + Send + Sync>;

/// Request to fetch missing proofs from peers via RPC
#[derive(Debug, Clone)]
pub struct ProofRequest {
    /// The beacon block root to request proofs for
    pub block_root: Hash256,
    /// The execution block hash
    pub payload_hash: ExecutionBlockHash,
    /// Subnet IDs to request proofs from
    pub subnet_ids: Vec<ExecutionProofSubnetId>,
}

/// Result type for StatelessExecutionLayer operations
pub type Result<T> = std::result::Result<T, StatelessExecutionLayerError>;

/// Errors that can occur in the StatelessExecutionLayer
#[derive(Debug, thiserror::Error)]
pub enum StatelessExecutionLayerError {
    #[error("Insufficient proofs: required {required}, verified {verified}")]
    InsufficientProofs { required: usize, verified: usize },

    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Payload status returned from Engine API methods
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadStatus {
    /// Payload is valid
    Valid,

    /// Payload validation is in progress (waiting for proofs)
    Syncing,

    /// Payload is invalid
    Invalid { error: String },
}

/// Response from forkchoice_updated
#[derive(Debug, Clone)]
pub struct ForkchoiceUpdatedResponse {
    pub payload_status: PayloadStatus,
}

/// Main StatelessExecutionLayer struct
///
/// This struct implements the Engine API interface for stateless execution
/// validation using cryptographic proofs instead of re-executing transactions.
pub struct StatelessExecutionLayer {
    /// Configuration (subnets, min_proofs, etc.)
    config: StatelessExecutionLayerConfig,

    /// Proof cache: block_hash -> Vec<ExecutionProof>
    proof_cache: ProofCache,

    /// Verifier registry: subnet_id -> verifier implementation
    verifiers: Arc<VerifierRegistry>,

    /// Optional generator registry (only if generating proofs)
    generators: Option<Arc<GeneratorRegistry>>,

    /// Channel to send proofs to network layer for publishing
    /// Format: (subnet_id, proof)
    network_tx: Option<mpsc::UnboundedSender<(ExecutionProofSubnetId, Arc<ExecutionProof>)>>,

    /// Channel to request missing proofs from network layer
    /// Format: ProofRequest containing block_root, payload_hash, and subnet_ids to request
    /// Uses RwLock for interior mutability to allow setting after Arc creation
    proof_request_tx: Arc<RwLock<Option<mpsc::UnboundedSender<ProofRequest>>>>,

    /// Callback to notify when required proofs become available for a block
    proof_ready_callback: Arc<RwLock<Option<ProofReadyCallback>>>,

    /// Logger
    log: Logger,
}

impl StatelessExecutionLayer {
    /// Create a new StatelessExecutionLayer
    pub fn new(config: StatelessExecutionLayerConfig, log: Logger) -> Result<Self> {
        // Validate configuration
        config
            .validate()
            .map_err(|e| StatelessExecutionLayerError::ConfigError(e))?;

        // Create proof cache
        let proof_cache = ProofCache::new(config.proof_cache_size);

        // Create verifier registry with dummy verifiers for Phase 1
        let verifiers = Arc::new(VerifierRegistry::new_with_dummy_verifiers());

        // Create generator registry if needed
        let generators = if !config.generation_subnets.is_empty() {
            Some(Arc::new(GeneratorRegistry::new_with_dummy_generators(
                config.generation_subnets.clone(),
            )))
        } else {
            None
        };

        info!(
            log,
            "StatelessExecutionLayer created";
            "subscribed_subnets" => config.subscribed_subnets.len(),
            "generation_subnets" => config.generation_subnets.len(),
            "min_proofs_required" => config.min_proofs_required,
        );

        Ok(Self {
            config,
            proof_cache,
            verifiers,
            generators,
            network_tx: None,
            proof_request_tx: Arc::new(RwLock::new(None)),
            proof_ready_callback: Arc::new(RwLock::new(None)),
            log,
        })
    }

    /// Set the network transmitter for publishing proofs
    pub fn set_network_tx(
        &mut self,
        tx: mpsc::UnboundedSender<(ExecutionProofSubnetId, Arc<ExecutionProof>)>,
    ) {
        self.network_tx = Some(tx);
    }

    /// Set the proof request transmitter for requesting missing proofs
    ///
    /// This method uses interior mutability to allow setting the channel
    /// after the StatelessExecutionLayer has been wrapped in an Arc.
    pub async fn set_proof_request_tx(&self, tx: mpsc::UnboundedSender<ProofRequest>) {
        let mut request_tx = self.proof_request_tx.write().await;
        *request_tx = Some(tx);
    }

    /// Register a callback to be notified when required proofs become available for a block
    pub async fn register_proof_ready_callback(&self, callback: ProofReadyCallback) {
        let mut cb = self.proof_ready_callback.write().await;
        *cb = Some(callback);
    }

    /// Main Engine API method: validate execution payload
    ///
    /// This is called by the consensus layer to validate an execution payload.
    /// Returns Valid if we have enough valid proofs, Syncing if we're waiting
    /// for proofs, or Invalid if verification fails.
    pub async fn new_payload(
        &self,
        payload_hash: ExecutionBlockHash,
        block_root: Hash256,
    ) -> Result<PayloadStatus> {
        debug!(
            self.log,
            "new_payload called";
            "payload_hash" => ?payload_hash,
            "block_root" => ?block_root,
        );

        // 1. If we generate proofs, spawn generation tasks
        if let Some(generators) = &self.generators {
            self.spawn_proof_generation(payload_hash, block_root, generators);
        }

        // 2. Check if we have enough proofs to verify
        if self
            .proof_cache
            .has_required_proofs(&payload_hash, self.config.min_proofs_required)
            .await
        {
            // Have enough proofs, verify them
            match self.verify_proofs(&payload_hash).await {
                Ok(()) => {
                    info!(
                        self.log,
                        "Payload verified successfully";
                        "payload_hash" => ?payload_hash,
                    );
                    Ok(PayloadStatus::Valid)
                }
                Err(e) => {
                    error!(
                        self.log,
                        "Payload verification failed";
                        "payload_hash" => ?payload_hash,
                        "error" => ?e,
                    );
                    Ok(PayloadStatus::Invalid {
                        error: e.to_string(),
                    })
                }
            }
        } else {
            // Missing proofs, return SYNCING and request missing proofs
            let current_count = self.proof_cache.subnet_count(&payload_hash).await;
            debug!(
                self.log,
                "Waiting for proofs";
                "payload_hash" => ?payload_hash,
                "current_proofs" => current_count,
                "required" => self.config.min_proofs_required,
            );

            // Request missing proofs from peers
            self.request_missing_proofs(payload_hash, block_root).await;

            Ok(PayloadStatus::Syncing)
        }
    }

    /// Engine API method: update fork choice
    ///
    /// For stateless-EL, we don't build payloads, so this is minimal.
    /// This method is primarily used for head updates.
    pub async fn forkchoice_updated(
        &self,
        _head_block_hash: ExecutionBlockHash,
    ) -> Result<ForkchoiceUpdatedResponse> {
        Ok(ForkchoiceUpdatedResponse {
            payload_status: PayloadStatus::Valid,
        })
    }

    /// Handle proof received from gossip (called via channel from network layer)
    pub async fn on_gossip_proof_received(
        &self,
        subnet_id: ExecutionProofSubnetId,
        proof: Arc<ExecutionProof>,
    ) -> Result<()> {
        // Validate subnet ID matches
        if proof.subnet_id != subnet_id {
            warn!(
                self.log,
                "Proof subnet_id mismatch";
                "expected" => ?subnet_id,
                "actual" => ?proof.subnet_id,
                "block_hash" => ?proof.block_hash,
            );
            return Err(StatelessExecutionLayerError::Internal(
                "Proof subnet_id mismatch".to_string(),
            ));
        }

        // Check if subscribed to this subnet
        if !self.config.subscribed_subnets.contains(&subnet_id) {
            debug!(
                self.log,
                "Ignoring proof from unsubscribed subnet";
                "subnet_id" => ?subnet_id,
                "block_hash" => ?proof.block_hash,
            );
            return Err(StatelessExecutionLayerError::Internal(
                "Unsubscribed subnet".to_string(),
            ));
        }

        let block_hash = proof.block_hash;
        let slot = proof.slot();

        debug!(
            self.log,
            "Received execution proof from gossip";
            "subnet_id" => ?subnet_id,
            "block_hash" => ?block_hash,
            "slot" => slot.as_u64(),
        );

        // Store in cache
        self.proof_cache.insert((*proof).clone()).await;

        // Get current count of proofs for logging
        let proof_count = self.proof_cache.subnet_count(&block_hash).await;

        info!(
            self.log,
            "Execution proof cached";
            "block_hash" => ?block_hash,
            "subnet_id" => ?subnet_id,
            "slot" => slot.as_u64(),
            "proof_count" => proof_count,
            "min_required" => self.config.min_proofs_required,
        );

        // Check if we now have enough proofs for this block
        if self.has_required_proofs(&block_hash).await {
            info!(
                self.log,
                "Block verification threshold reached";
                "block_hash" => ?block_hash,
                "proof_count" => proof_count,
                "min_required" => self.config.min_proofs_required,
            );

            // Trigger callback if available
            if let Some(callback) = self.proof_ready_callback.read().await.as_ref() {
                debug!(
                    self.log,
                    "Triggering proof-ready callback";
                    "block_hash" => ?block_hash,
                );
                callback(block_hash);
            }
        }

        Ok(())
    }

    /// Non-blocking check: do we have minimum required proofs for this payload?
    pub async fn has_required_proofs(&self, payload_hash: &ExecutionBlockHash) -> bool {
        self.proof_cache
            .has_required_proofs(payload_hash, self.config.min_proofs_required)
            .await
    }

    /// Get a specific proof by its identifier (block_root + subnet_id)
    ///
    /// This method is used by the RPC handler to serve ExecutionProofsByRoot requests.
    /// Note: This is currently O(n) as it searches through all cached proofs.
    /// TODO: Add a secondary index by block_root for better performance.
    pub async fn get_proof_by_identifier(
        &self,
        block_root: &Hash256,
        subnet_id: ExecutionProofSubnetId,
    ) -> Option<ExecutionProof> {
        // Unfortunately, the cache is keyed by ExecutionBlockHash (payload hash),
        // but RPC requests use beacon block_root. We need to search through all cached proofs.
        // This is inefficient but works for Phase 4. A production implementation should add
        // a secondary index.
        self.proof_cache
            .find_by_block_root(block_root, subnet_id)
            .await
    }

    /// Request missing proofs from peers via RPC fallback
    ///
    /// This method is called when we have insufficient proofs for a payload.
    /// It determines which subnets we're missing proofs from and sends a request
    /// to the network layer to fetch them from peers.
    async fn request_missing_proofs(&self, payload_hash: ExecutionBlockHash, block_root: Hash256) {
        // Only request if we have a proof request channel configured
        let request_tx_guard = self.proof_request_tx.read().await;
        let request_tx = match request_tx_guard.as_ref() {
            Some(tx) => tx,
            None => {
                debug!(
                    self.log,
                    "Cannot request missing proofs - no request channel configured";
                    "payload_hash" => ?payload_hash,
                );
                return;
            }
        };

        // Get currently cached proofs for this block
        let cached_proofs = self
            .proof_cache
            .get(&payload_hash)
            .await
            .unwrap_or_default();
        let cached_subnet_ids: HashSet<ExecutionProofSubnetId> =
            cached_proofs.iter().map(|p| p.subnet_id).collect();

        // Determine which subscribed subnets we're missing proofs from
        let missing_subnet_ids: Vec<ExecutionProofSubnetId> = self
            .config
            .subscribed_subnets
            .iter()
            .filter(|subnet_id| !cached_subnet_ids.contains(subnet_id))
            .copied()
            .collect();

        if missing_subnet_ids.is_empty() {
            debug!(
                self.log,
                "No missing subnets to request";
                "payload_hash" => ?payload_hash,
                "cached_count" => cached_subnet_ids.len(),
            );
            return;
        }

        // Limit the number of subnets to request to avoid excessive RPC traffic
        // Request up to (min_required - cached) subnets
        let needed_count = self
            .config
            .min_proofs_required
            .saturating_sub(cached_subnet_ids.len());
        let subnets_to_request: Vec<ExecutionProofSubnetId> =
            missing_subnet_ids.into_iter().take(needed_count).collect();

        if subnets_to_request.is_empty() {
            return;
        }

        debug!(
            self.log,
            "Requesting missing proofs from peers";
            "payload_hash" => ?payload_hash,
            "block_root" => ?block_root,
            "subnets_to_request" => ?subnets_to_request,
            "cached_count" => cached_subnet_ids.len(),
            "min_required" => self.config.min_proofs_required,
        );

        // Send request to network layer
        let request = ProofRequest {
            block_root,
            payload_hash,
            subnet_ids: subnets_to_request,
        };

        if let Err(e) = request_tx.send(request) {
            warn!(
                self.log,
                "Failed to send proof request";
                "error" => ?e,
                "payload_hash" => ?payload_hash,
            );
        }
    }

    /// Verify proofs for a payload
    async fn verify_proofs(&self, payload_hash: &ExecutionBlockHash) -> Result<()> {
        let proofs = self.proof_cache.get(payload_hash).await.ok_or(
            StatelessExecutionLayerError::InsufficientProofs {
                required: self.config.min_proofs_required,
                verified: 0,
            },
        )?;

        let mut verified_subnets = HashSet::new();
        let mut errors = Vec::new();

        for proof in &proofs {
            // Get verifier for this subnet's zkVM
            let verifier = match self.verifiers.get_verifier(proof.subnet_id) {
                Some(v) => v,
                None => {
                    errors.push(format!("No verifier for subnet {}", proof.subnet_id));
                    continue;
                }
            };

            // Verify proof
            match verifier.verify(payload_hash, proof).await {
                Ok(true) => {
                    verified_subnets.insert(proof.subnet_id);

                    // Early exit if we have enough
                    if verified_subnets.len() >= self.config.min_proofs_required {
                        return Ok(());
                    }
                }
                Ok(false) => {
                    errors.push(format!(
                        "Proof from subnet {} failed verification",
                        proof.subnet_id
                    ));
                }
                Err(e) => {
                    errors.push(format!(
                        "Error verifying proof from subnet {}: {}",
                        proof.subnet_id, e
                    ));
                }
            }
        }

        // Not enough valid proofs from different subnets
        Err(StatelessExecutionLayerError::InsufficientProofs {
            required: self.config.min_proofs_required,
            verified: verified_subnets.len(),
        })
    }

    /// Spawn proof generation tasks
    fn spawn_proof_generation(
        &self,
        payload_hash: ExecutionBlockHash,
        block_root: Hash256,
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

            let network_tx = self.network_tx.clone();
            let proof_cache = self.proof_cache.clone();
            let log = self.log.clone();
            let subnet_id = *subnet_id;

            tokio::spawn(async move {
                debug!(log, "Generating proof"; "subnet_id" => ?subnet_id, "payload_hash" => ?payload_hash);

                // Generate proof (expensive operation)
                match generator.generate(&payload_hash, &block_root).await {
                    Ok(proof) => {
                        // Store in local cache
                        proof_cache.insert(proof.clone()).await;

                        // Publish to gossip if network channel available
                        if let Some(tx) = network_tx {
                            if let Err(e) = tx.send((subnet_id, Arc::new(proof))) {
                                warn!(log, "Failed to publish proof"; "error" => ?e);
                            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use slog::o;

    fn test_logger() -> Logger {
        slog::Logger::root(slog::Discard, o!())
    }

    #[tokio::test]
    async fn test_stateless_el_creation() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .min_proofs_required(1)
            .build()
            .unwrap();

        let el = StatelessExecutionLayer::new(config, test_logger());
        assert!(el.is_ok());
    }

    #[tokio::test]
    async fn test_new_payload_without_proofs() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .min_proofs_required(1)
            .build()
            .unwrap();

        let el = StatelessExecutionLayer::new(config, test_logger()).unwrap();
        let payload_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        let status = el.new_payload(payload_hash, block_root).await.unwrap();
        assert_eq!(status, PayloadStatus::Syncing);
    }

    #[tokio::test]
    async fn test_new_payload_with_proofs() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .min_proofs_required(1)
            .build()
            .unwrap();

        let el = StatelessExecutionLayer::new(config, test_logger()).unwrap();
        let payload_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        // Insert a proof
        let proof =
            ExecutionProof::new_for_testing(subnet_0, payload_hash, block_root, vec![1, 2, 3])
                .unwrap();
        el.proof_cache.insert(proof).await;

        let status = el.new_payload(payload_hash, block_root).await.unwrap();
        assert_eq!(status, PayloadStatus::Valid);
    }

    #[tokio::test]
    async fn test_forkchoice_updated() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .build()
            .unwrap();

        let el = StatelessExecutionLayer::new(config, test_logger()).unwrap();
        let head = ExecutionBlockHash::repeat_byte(1);

        let response = el.forkchoice_updated(head).await.unwrap();
        assert_eq!(response.payload_status, PayloadStatus::Valid);
    }

    #[tokio::test]
    async fn test_proof_generation_and_publishing() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();

        // Configure to generate proofs for two subnets
        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .add_subscribed_subnet(subnet_1)
            .add_generation_subnet(subnet_0)
            .add_generation_subnet(subnet_1)
            .min_proofs_required(2)
            .build()
            .unwrap();

        let mut el = StatelessExecutionLayer::new(config, test_logger()).unwrap();

        // Set up network channel to receive published proofs
        let (tx, mut rx) = mpsc::unbounded_channel();
        el.set_network_tx(tx);

        let payload_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        // Call new_payload which should trigger proof generation
        let status = el.new_payload(payload_hash, block_root).await.unwrap();
        // Should return SYNCING since we don't have proofs yet
        assert_eq!(status, PayloadStatus::Syncing);

        // Wait for generated proofs to be published via channel
        // Dummy generator is instant, so proofs should arrive quickly
        let mut received_proofs = Vec::new();
        for _ in 0..2 {
            if let Ok(Some((subnet_id, proof))) =
                tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await
            {
                received_proofs.push((subnet_id, proof));
            }
        }

        // Should have received 2 proofs (one for each generation subnet)
        assert_eq!(received_proofs.len(), 2);

        // Verify proof metadata
        for (subnet_id, proof) in received_proofs {
            assert_eq!(proof.block_hash, payload_hash);
            // Note: block_root() is computed from tree hash of signed header,
            // not from the block_root parameter passed to new_for_testing
            assert!(subnet_id == subnet_0 || subnet_id == subnet_1);
        }

        // Now that proofs have been generated and cached, new_payload should return Valid
        let status = el.new_payload(payload_hash, block_root).await.unwrap();
        assert_eq!(status, PayloadStatus::Valid);
    }

    #[tokio::test]
    async fn test_gossip_proof_reception() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();

        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .add_subscribed_subnet(subnet_1)
            .min_proofs_required(2)
            .build()
            .unwrap();

        let el = StatelessExecutionLayer::new(config, test_logger()).unwrap();
        let payload_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        // Initially should return SYNCING (no proofs)
        let status = el.new_payload(payload_hash, block_root).await.unwrap();
        assert_eq!(status, PayloadStatus::Syncing);

        // Simulate receiving first proof via gossip
        let proof_0 =
            ExecutionProof::new_for_testing(subnet_0, payload_hash, block_root, vec![1, 2, 3])
                .unwrap();
        el.on_gossip_proof_received(subnet_0, Arc::new(proof_0))
            .await
            .unwrap();

        // Still should return SYNCING (need 2 proofs from different subnets)
        let status = el.new_payload(payload_hash, block_root).await.unwrap();
        assert_eq!(status, PayloadStatus::Syncing);

        // Simulate receiving second proof from different subnet
        let proof_1 =
            ExecutionProof::new_for_testing(subnet_1, payload_hash, block_root, vec![4, 5, 6])
                .unwrap();
        el.on_gossip_proof_received(subnet_1, Arc::new(proof_1))
            .await
            .unwrap();

        // Now should return VALID (have 2 proofs from different subnets)
        let status = el.new_payload(payload_hash, block_root).await.unwrap();
        assert_eq!(status, PayloadStatus::Valid);
    }

    #[tokio::test]
    async fn test_proof_ready_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .min_proofs_required(1)
            .build()
            .unwrap();

        let el = StatelessExecutionLayer::new(config, test_logger()).unwrap();
        let payload_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        // Register callback
        let callback_triggered = Arc::new(AtomicBool::new(false));
        let callback_triggered_clone = callback_triggered.clone();
        let callback = Arc::new(move |_hash: ExecutionBlockHash| {
            callback_triggered_clone.store(true, Ordering::SeqCst);
        });
        el.register_proof_ready_callback(callback).await;

        // Initially callback not triggered
        assert!(!callback_triggered.load(Ordering::SeqCst));

        // Receive proof via gossip
        let proof =
            ExecutionProof::new_for_testing(subnet_0, payload_hash, block_root, vec![1, 2, 3])
                .unwrap();
        el.on_gossip_proof_received(subnet_0, Arc::new(proof))
            .await
            .unwrap();

        // Callback should have been triggered
        assert!(callback_triggered.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_gossip_proof_validation() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();

        // Only subscribe to subnet_0
        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .min_proofs_required(1)
            .build()
            .unwrap();

        let el = StatelessExecutionLayer::new(config, test_logger()).unwrap();
        let payload_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        // Should reject proof from unsubscribed subnet
        let proof_1 =
            ExecutionProof::new_for_testing(subnet_1, payload_hash, block_root, vec![1, 2, 3])
                .unwrap();
        let result = el
            .on_gossip_proof_received(subnet_1, Arc::new(proof_1))
            .await;
        assert!(result.is_err());

        // Should reject proof with mismatched subnet_id
        let mut proof_0 =
            ExecutionProof::new_for_testing(subnet_0, payload_hash, block_root, vec![4, 5, 6])
                .unwrap();
        proof_0.subnet_id = subnet_1; // Mismatch: claim subnet_0 but actually subnet_1
        let result = el
            .on_gossip_proof_received(subnet_0, Arc::new(proof_0))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_request_missing_proofs() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();
        let subnet_2 = ExecutionProofSubnetId::new(2).unwrap();

        // Configure to subscribe to 3 subnets but require 2 proofs
        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .add_subscribed_subnet(subnet_1)
            .add_subscribed_subnet(subnet_2)
            .min_proofs_required(2)
            .build()
            .unwrap();

        let el = StatelessExecutionLayer::new(config, test_logger()).unwrap();

        // Set up proof request channel
        let (tx, mut rx) = mpsc::unbounded_channel();
        el.set_proof_request_tx(tx).await;

        let payload_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        // Insert one proof from subnet_0
        let proof_0 =
            ExecutionProof::new_for_testing(subnet_0, payload_hash, block_root, vec![1, 2, 3])
                .unwrap();
        el.proof_cache.insert(proof_0).await;

        // Call new_payload - should return SYNCING and request missing proofs
        let status = el.new_payload(payload_hash, block_root).await.unwrap();
        assert_eq!(status, PayloadStatus::Syncing);

        // Should have received a proof request for missing subnets
        let request = rx.try_recv().expect("Should have received proof request");
        assert_eq!(request.block_root, block_root);
        assert_eq!(request.payload_hash, payload_hash);

        // Should request exactly 1 subnet (need 2 total, have 1)
        assert_eq!(request.subnet_ids.len(), 1);

        // Should request either subnet_1 or subnet_2 (not subnet_0 which we already have)
        assert!(!request.subnet_ids.contains(&subnet_0));
        assert!(request.subnet_ids.contains(&subnet_1) || request.subnet_ids.contains(&subnet_2));
    }

    #[tokio::test]
    async fn test_no_request_when_sufficient_proofs() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();

        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .add_subscribed_subnet(subnet_1)
            .min_proofs_required(2)
            .build()
            .unwrap();

        let el = StatelessExecutionLayer::new(config, test_logger()).unwrap();

        // Set up proof request channel
        let (tx, mut rx) = mpsc::unbounded_channel();
        el.set_proof_request_tx(tx).await;

        let payload_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        // Insert two proofs (sufficient)
        let proof_0 =
            ExecutionProof::new_for_testing(subnet_0, payload_hash, block_root, vec![1, 2, 3])
                .unwrap();
        let proof_1 =
            ExecutionProof::new_for_testing(subnet_1, payload_hash, block_root, vec![4, 5, 6])
                .unwrap();
        el.proof_cache.insert(proof_0).await;
        el.proof_cache.insert(proof_1).await;

        // Call new_payload - should return VALID and NOT send proof request
        let status = el.new_payload(payload_hash, block_root).await.unwrap();
        assert_eq!(status, PayloadStatus::Valid);

        // Should NOT have received any proof request
        assert!(
            rx.try_recv().is_err(),
            "Should not request proofs when we have enough"
        );
    }

    #[tokio::test]
    async fn test_request_without_channel_configured() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();

        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .add_subscribed_subnet(subnet_1)
            .min_proofs_required(2)
            .build()
            .unwrap();

        // Don't set proof_request_tx - should handle gracefully
        let el = StatelessExecutionLayer::new(config, test_logger()).unwrap();

        let payload_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        // Call new_payload with no proofs - should return SYNCING but not panic
        let status = el.new_payload(payload_hash, block_root).await.unwrap();
        assert_eq!(status, PayloadStatus::Syncing);
        // Test passes if no panic occurs
    }
}
