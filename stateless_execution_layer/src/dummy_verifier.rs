use crate::proof_verification::{ProofVerifier, VerificationError, VerificationResult};
use async_trait::async_trait;
use std::time::Duration;
use tokio::time::sleep;
use types::{ExecutionBlockHash, ExecutionProof, ExecutionProofSubnetId};

/// Dummy proof verifier for testing and Phase 1 implementation
///
/// This verifier simulates the verification process with a configurable delay
/// and always returns successful verification. It's useful for:
/// - Testing the stateless-EL architecture without real zkVM dependencies
/// - Benchmarking the proof flow without verification overhead
/// - Development and integration testing
pub struct DummyVerifier {
    subnet_id: ExecutionProofSubnetId,
    verification_delay: Duration,
}

impl DummyVerifier {
    /// Create a new dummy verifier for the specified subnet
    pub fn new(subnet_id: ExecutionProofSubnetId) -> Self {
        Self {
            subnet_id,
            verification_delay: Duration::from_millis(10), // Simulate some work
        }
    }

    /// Create a new dummy verifier with custom verification delay
    pub fn with_delay(subnet_id: ExecutionProofSubnetId, delay: Duration) -> Self {
        Self {
            subnet_id,
            verification_delay: delay,
        }
    }
}

#[async_trait]
impl ProofVerifier for DummyVerifier {
    async fn verify(
        &self,
        payload_hash: &ExecutionBlockHash,
        proof: &ExecutionProof,
    ) -> VerificationResult<bool> {
        // Check that the proof is for the correct subnet
        if proof.subnet_id != self.subnet_id {
            return Err(VerificationError::UnsupportedSubnet(proof.subnet_id));
        }

        // Check that the proof is for the correct payload
        if &proof.block_hash != payload_hash {
            return Err(VerificationError::VerificationFailed(format!(
                "Proof block hash mismatch: expected {}, got {}",
                payload_hash, proof.block_hash
            )));
        }

        // Simulate verification work
        if !self.verification_delay.is_zero() {
            sleep(self.verification_delay).await;
        }

        // Dummy verifier always succeeds
        Ok(true)
    }

    fn subnet_id(&self) -> ExecutionProofSubnetId {
        self.subnet_id
    }

    fn name(&self) -> &str {
        "DummyVerifier"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{FixedBytesExtended, Hash256};

    fn create_test_proof(
        subnet_id: ExecutionProofSubnetId,
        block_hash: ExecutionBlockHash,
    ) -> ExecutionProof {
        ExecutionProof::new(subnet_id, block_hash, Hash256::zero(), vec![1, 2, 3, 4]).unwrap()
    }

    #[tokio::test]
    async fn test_dummy_verifier_success() {
        let subnet = ExecutionProofSubnetId::new(0).unwrap();
        let verifier = DummyVerifier::new(subnet);
        let block_hash = ExecutionBlockHash::zero();
        let proof = create_test_proof(subnet, block_hash);

        let result = verifier.verify(&block_hash, &proof).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[tokio::test]
    async fn test_dummy_verifier_wrong_subnet() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();
        let verifier = DummyVerifier::new(subnet_0);
        let block_hash = ExecutionBlockHash::zero();
        let proof = create_test_proof(subnet_1, block_hash);

        let result = verifier.verify(&block_hash, &proof).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerificationError::UnsupportedSubnet(_)
        ));
    }

    #[tokio::test]
    async fn test_dummy_verifier_wrong_block_hash() {
        let subnet = ExecutionProofSubnetId::new(0).unwrap();
        let verifier = DummyVerifier::new(subnet);
        let block_hash_1 = ExecutionBlockHash::repeat_byte(1);
        let block_hash_2 = ExecutionBlockHash::repeat_byte(2);
        let proof = create_test_proof(subnet, block_hash_1);

        let result = verifier.verify(&block_hash_2, &proof).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerificationError::VerificationFailed(_)
        ));
    }

    #[test]
    fn test_verifier_properties() {
        let subnet = ExecutionProofSubnetId::new(0).unwrap();
        let verifier = DummyVerifier::new(subnet);

        assert_eq!(verifier.subnet_id(), subnet);
        assert_eq!(verifier.name(), "DummyVerifier");
    }
}
