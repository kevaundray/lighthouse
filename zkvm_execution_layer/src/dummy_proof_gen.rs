use crate::ethproofs_demo::{
    download_proof_binary, fetch_proofs_list, validate_proof, VERIFIER_STORE,
};
use crate::proof_generation::{ProofGenerationError, ProofGenerationResult, ProofGenerator};
use async_trait::async_trait;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, warn};
use types::{ExecutionBlockHash, ExecutionProof, ExecutionProofId, Hash256, Slot};

/// TODO(ethproofs): Implementation of proof generation for demo.
///
/// Dummy proof generator for testing
///
/// This generator simulates the proof generation process with a configurable delay
/// and creates dummy proofs.
pub struct DummyProofGenerator {
    proof_id: ExecutionProofId,
    generation_delay: Duration,
}

impl DummyProofGenerator {
    /// Create a new dummy generator for the specified proof ID
    pub fn new(proof_id: ExecutionProofId) -> Self {
        Self {
            proof_id,
            generation_delay: Duration::from_millis(0),
        }
    }

    /// Create a new dummy generator with custom generation delay
    pub fn with_delay(proof_id: ExecutionProofId, delay: Duration) -> Self {
        Self {
            proof_id,
            generation_delay: delay,
        }
    }

    /// TODO(ethproofs): Used when Ethproofs API fails or verification fails.
    ///
    /// Create a fallback dummy proof
    fn create_dummy_proof(
        &self,
        slot: Slot,
        payload_hash: &ExecutionBlockHash,
        block_root: &Hash256,
    ) -> ProofGenerationResult<ExecutionProof> {
        let dummy_data = format!(
            "ethproofs_fallback_subnet_{:?}_slot_{:?}_hash_{:?}",
            self.proof_id, slot, payload_hash
        )
        .into_bytes();

        ExecutionProof::new(self.proof_id, slot, *payload_hash, *block_root, dummy_data)
            .map_err(ProofGenerationError::ProofGenerationFailed)
    }
}

#[async_trait]
impl ProofGenerator for DummyProofGenerator {
    async fn generate(
        &self,
        slot: Slot,
        payload_hash: &ExecutionBlockHash,
        block_root: &Hash256,
    ) -> ProofGenerationResult<ExecutionProof> {
        // Simulate proof generation work
        if !self.generation_delay.is_zero() {
            sleep(self.generation_delay).await;
        }

        debug!(
            proof_id = %self.proof_id,
            block_hash = %payload_hash,
            "[Ethproofs] Starting proof generation"
        );

        // Get the Ethproofs prover UUID corresponding to this proof_id
        let prover_uuid = match VERIFIER_STORE.get_prover_uuid_for_proof_id(self.proof_id) {
            Some(uuid) => uuid,
            None => {
                warn!(
                    proof_id = %self.proof_id,
                    "[Ethproofs] No prover UUID mapping found, cannot query API"
                );
                return self.create_dummy_proof(slot, payload_hash, block_root);
            }
        };

        let cluster = prover_uuid.to_string();

        debug!(
            proof_id = %self.proof_id,
            prover_uuid = %prover_uuid,
            "[Ethproofs] Querying API"
        );

        // Fetch proofs from Ethproofs API for this proof_id's cluster
        match fetch_proofs_list(*payload_hash, cluster).await {
            Ok(proofs) => {
                debug!(
                    proof_id = %self.proof_id,
                    block_hash = %payload_hash,
                    count = proofs.len(),
                    "[Ethproofs] Fetched proofs"
                );

                // Try to download and verify the proof
                if let Some(proof_entry) = proofs.first() {
                    // Download the proof binary
                    match download_proof_binary(proof_entry.proof_id).await {
                        Ok(proof_binary) => {
                            // Create proof for verification
                            match ExecutionProof::new(
                                self.proof_id,
                                slot,
                                *payload_hash,
                                *block_root,
                                proof_binary,
                            ) {
                                Ok(proof) => {
                                    // Verify the proof
                                    if validate_proof(&proof) {
                                        debug!(
                                            proof_id = proof_entry.proof_id,
                                            cluster_id = %proof_entry.cluster_id,
                                            "[Ethproofs] Proof verification succeeded"
                                        );
                                        return Ok(proof);
                                    } else {
                                        debug!(
                                            proof_id = proof_entry.proof_id,
                                            "[Ethproofs] Proof verification failed"
                                        );
                                    }
                                }
                                Err(e) => {
                                    debug!(
                                        proof_id = proof_entry.proof_id,
                                        error = %e,
                                        "[Ethproofs] Failed to create proof structure"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            debug!(
                                proof_id = proof_entry.proof_id,
                                error = %e,
                                "[Ethproofs] Failed to download proof"
                            );
                        }
                    }
                } else {
                    warn!(
                        proof_id = %self.proof_id,
                        "[Ethproofs] No proofs returned from API"
                    );
                }

                // Fall back to dummy proof if we get here
                warn!(
                    proof_id = %self.proof_id,
                    block_hash = %payload_hash,
                    "[Ethproofs] Proof verification failed, falling back to dummy"
                );
                self.create_dummy_proof(slot, payload_hash, block_root)
            }
            Err(e) => {
                debug!(
                    proof_id = %self.proof_id,
                    block_hash = %payload_hash,
                    error = %e,
                    "[Ethproofs] Failed to fetch proofs, using dummy fallback"
                );
                self.create_dummy_proof(slot, payload_hash, block_root)
            }
        }
    }

    fn proof_id(&self) -> ExecutionProofId {
        self.proof_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dummy_generator_success() {
        let subnet = ExecutionProofId::new(0).unwrap();
        let generator = DummyProofGenerator::new(subnet);
        let slot = Slot::new(100);
        let block_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        let result = generator.generate(slot, &block_hash, &block_root).await;
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(proof.proof_id, subnet);
        assert_eq!(proof.slot, slot);
        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.block_root, block_root);
        assert!(proof.proof_data_size() > 0);
    }

    #[tokio::test]
    async fn test_dummy_generator_deterministic() {
        let subnet = ExecutionProofId::new(1).unwrap();
        let generator = DummyProofGenerator::new(subnet);
        let slot = Slot::new(200);
        let block_hash = ExecutionBlockHash::repeat_byte(42);
        let block_root = Hash256::repeat_byte(99);

        // Generate twice
        let proof1 = generator
            // TODO(ethproofs): Changed so we don't make API calls here.
            .create_dummy_proof(slot, &block_hash, &block_root)
            .unwrap();
        let proof2 = generator
            // TODO(ethproofs): Changed so we don't make API calls here.
            .create_dummy_proof(slot, &block_hash, &block_root)
            .unwrap();

        // Should be identical
        assert_eq!(proof1.proof_data_slice(), proof2.proof_data_slice());
    }

    #[tokio::test]
    async fn test_dummy_generator_custom_delay() {
        // TODO(zkproofs): Maybe remove, mainly need it as a temp check
        let subnet = ExecutionProofId::new(0).unwrap();
        let delay = Duration::from_millis(1);
        let generator = DummyProofGenerator::with_delay(subnet, delay);
        let slot = Slot::new(100);
        let block_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        let start = tokio::time::Instant::now();
        let result = generator.generate(slot, &block_hash, &block_root).await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(elapsed >= delay);
    }
}
