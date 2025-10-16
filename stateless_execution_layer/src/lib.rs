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
use tokio::sync::mpsc;
use types::{ExecutionBlockHash, ExecutionProof, ExecutionProofSubnetId, Hash256};

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
            // Missing proofs, return SYNCING
            debug!(
                self.log,
                "Waiting for proofs";
                "payload_hash" => ?payload_hash,
                "required" => self.config.min_proofs_required,
            );
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
            return Err(StatelessExecutionLayerError::Internal(
                "Proof subnet_id mismatch".to_string(),
            ));
        }

        // Check if subscribed to this subnet
        if !self.config.subscribed_subnets.contains(&subnet_id) {
            return Err(StatelessExecutionLayerError::Internal(
                "Unsubscribed subnet".to_string(),
            ));
        }

        debug!(
            self.log,
            "Received proof from gossip";
            "subnet_id" => ?subnet_id,
            "block_hash" => ?proof.block_hash,
        );

        // Store in cache
        self.proof_cache.insert((*proof).clone()).await;

        Ok(())
    }

    /// Non-blocking check: do we have minimum required proofs for this payload?
    pub async fn has_required_proofs(&self, payload_hash: &ExecutionBlockHash) -> bool {
        self.proof_cache
            .has_required_proofs(payload_hash, self.config.min_proofs_required)
            .await
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
        let proof = ExecutionProof::new(subnet_0, payload_hash, block_root, vec![1, 2, 3]).unwrap();
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
}
