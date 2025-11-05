use crate::ethproofs_demo::{EthproofsValidator, ProofValidator};
use crate::proof_verification::{ProofVerificationResult, ProofVerifier, VerificationError};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;
use types::{ExecutionProof, ExecutionProofId};

/// TODO(ethproofs): Ethproofs demo implementation of proof verification.
///
/// Dummy proof verifier for testing
///
/// This verifier simulates the verification process with a configurable delay.
pub struct DummyVerifier {
    proof_id: ExecutionProofId,
    verification_delay: Duration,
    validator: Arc<dyn ProofValidator>,
}

impl DummyVerifier {
    /// Create a new dummy verifier for the specified proof ID
    pub fn new(proof_id: ExecutionProofId) -> Self {
        Self {
            proof_id,
            verification_delay: Duration::from_millis(0),
            validator: Arc::new(EthproofsValidator),
        }
    }

    /// Create a new dummy verifier with custom verification delay
    pub fn with_delay(proof_id: ExecutionProofId, delay: Duration) -> Self {
        Self {
            proof_id,
            verification_delay: delay,
            validator: Arc::new(EthproofsValidator),
        }
    }

    /// Create a new dummy verifier with a custom validator (for testing)
    #[cfg(test)]
    fn with_validator(
        proof_id: ExecutionProofId,
        validator: Arc<dyn ProofValidator>,
    ) -> Self {
        Self {
            proof_id,
            verification_delay: Duration::from_millis(0),
            validator,
        }
    }
}

impl ProofVerifier for DummyVerifier {
    fn verify(&self, proof: &ExecutionProof) -> ProofVerificationResult<bool> {
        // Check that the proof is for the correct subnet
        if proof.proof_id != self.proof_id {
            return Err(VerificationError::UnsupportedProofID(proof.proof_id));
        }

        // Simulate verification work
        if !self.verification_delay.is_zero() {
            std::thread::sleep(self.verification_delay);
        }

        debug!(
            proof_id = %self.proof_id,
            block_hash = %proof.block_hash,
            "[Ethproofs] Verifying proof"
        );

        // Perform cryptographic verification using the injected validator
        Ok(self.validator.validate(proof))
    }

    fn proof_id(&self) -> ExecutionProofId {
        self.proof_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use types::{ExecutionBlockHash, FixedBytesExtended, Hash256, Slot};

    mock! {
        TestValidator {}
        impl ProofValidator for TestValidator {
            fn validate(&self, proof: &ExecutionProof) -> bool;
        }
    }

    fn create_test_proof(
        subnet_id: ExecutionProofId,
        block_hash: types::ExecutionBlockHash,
    ) -> ExecutionProof {
        ExecutionProof::new(
            subnet_id,
            Slot::new(100),
            block_hash,
            Hash256::zero(),
            vec![1, 2, 3, 4],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_dummy_verifier_success() {
        let subnet = ExecutionProofId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let proof = create_test_proof(subnet, block_hash);

        let mut mock_validator = MockTestValidator::new();
        mock_validator
            .expect_validate()
            .withf(move |p| p.proof_id == subnet)
            .returning(|_| true);

        let verifier = DummyVerifier::with_validator(subnet, Arc::new(mock_validator));

        let result = verifier.verify(&proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_dummy_verifier_wrong_subnet() {
        let subnet_0 = ExecutionProofId::new(0).unwrap();
        let subnet_1 = ExecutionProofId::new(1).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let proof = create_test_proof(subnet_1, block_hash);

        let mock_validator = MockTestValidator::new();
        let verifier = DummyVerifier::with_validator(subnet_0, Arc::new(mock_validator));

        let result = verifier.verify(&proof);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerificationError::UnsupportedProofID(_)
        ));
    }
}
