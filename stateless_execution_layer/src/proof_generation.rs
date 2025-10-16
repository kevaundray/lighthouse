use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;
use types::{ExecutionProof, ExecutionProofSubnetId};

/// Result type for proof generation operations
pub type GenerationResult<T> = Result<T, GenerationError>;

/// Errors that can occur during proof generation
#[derive(Debug, Error)]
pub enum GenerationError {
    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),

    #[error("Missing execution witness data: {0}")]
    MissingWitnessData(String),

    #[error("Invalid execution witness: {0}")]
    InvalidWitness(String),

    #[error("Proof generation timeout")]
    Timeout,

    #[error("Insufficient resources: {0}")]
    InsufficientResources(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Trait for proof generation (one implementation per zkVM)
///
/// Each proof system (RISC Zero, SP1, etc.) implements this trait
/// to generate proofs for execution payloads from their subnet.
#[async_trait]
pub trait ProofGenerator: Send + Sync {
    /// Generate a proof for the given execution payload
    ///
    /// This is a computationally expensive operation and should be run
    /// in a background task. The generated proof validates that the
    /// execution payload was correctly executed.
    ///
    /// # Arguments
    /// * `payload_hash` - Hash of the execution payload to prove
    /// * `block_root` - Beacon block root (for proof binding)
    ///
    /// # Returns
    /// A cryptographic proof that the payload is valid
    async fn generate(
        &self,
        payload_hash: &types::ExecutionBlockHash,
        block_root: &types::Hash256,
    ) -> GenerationResult<ExecutionProof>;

    /// Get the subnet ID this generator produces proofs for
    fn subnet_id(&self) -> ExecutionProofSubnetId;

    /// Get a human-readable name for this generator
    fn name(&self) -> &str;
}

/// Type-erased proof generator
pub type DynProofGenerator = Arc<dyn ProofGenerator>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generation_error_display() {
        let err = GenerationError::GenerationFailed("test error".to_string());
        assert!(err.to_string().contains("test error"));

        let err = GenerationError::Timeout;
        assert!(err.to_string().contains("timeout"));
    }
}
