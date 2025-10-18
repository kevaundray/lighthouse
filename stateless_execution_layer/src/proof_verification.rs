use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;
use types::{ExecutionProof, ExecutionProofSubnetId};

/// Result type for proof verification operations
pub type VerificationResult<T> = Result<T, VerificationError>;

/// Errors that can occur during proof verification
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),

    #[error("Unsupported subnet: {0}")]
    UnsupportedSubnet(ExecutionProofSubnetId),

    #[error("Proof size mismatch: expected {expected}, got {actual}")]
    ProofSizeMismatch { expected: usize, actual: usize },

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Trait for proof verification (one implementation per zkVM)
///
/// Each proof system (RISC Zero, SP1, etc.) implements this trait
/// to provide verification for proofs from their subnet.
#[async_trait]
pub trait ProofVerifier: Send + Sync {
    /// Verify that the proof is valid for the given execution payload
    ///
    /// This method checks that the proof cryptographically validates
    /// the execution of the payload. Returns Ok(true) if valid,
    /// Ok(false) if invalid (but well-formed), or Err if the proof
    /// is malformed or verification cannot be performed.
    async fn verify(
        &self,
        payload_hash: &types::ExecutionBlockHash,
        proof: &ExecutionProof,
    ) -> VerificationResult<bool>;

    /// Get the subnet ID this verifier handles
    fn subnet_id(&self) -> ExecutionProofSubnetId;

    /// Get a human-readable name for this verifier
    fn name(&self) -> &str;
}

/// Type-erased proof verifier
pub type DynProofVerifier = Arc<dyn ProofVerifier>;

#[cfg(test)]
mod tests {
    use super::*;
    use types::FixedBytesExtended;

    // Helper to create a test proof
    #[allow(dead_code)]
    fn create_test_proof(subnet_id: ExecutionProofSubnetId) -> ExecutionProof {
        ExecutionProof::new_for_testing(
            subnet_id,
            types::ExecutionBlockHash::zero(),
            types::Hash256::zero(),
            vec![1, 2, 3, 4],
        )
        .unwrap()
    }

    #[test]
    fn test_verification_error_display() {
        let err = VerificationError::VerificationFailed("test error".to_string());
        assert!(err.to_string().contains("test error"));

        let subnet = ExecutionProofSubnetId::new(0).unwrap();
        let err = VerificationError::UnsupportedSubnet(subnet);
        assert!(err.to_string().contains("Unsupported subnet"));
    }
}
