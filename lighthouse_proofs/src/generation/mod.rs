//! Proof generation implementations

mod dummy;

pub use dummy::DummyProofGenerator;

use crate::types::{ErasedExecutionPayload, ExecutionPayloadProof, ProofId};
use crate::Result;
use async_trait::async_trait;

/// Trait for proof generation implementations
#[async_trait]
pub trait ProofGenerator: Send + Sync {
    /// Generate a proof for an execution payload
    async fn generate_proof(
        &self,
        payload: &ErasedExecutionPayload,
        witness: &[u8],
        proof_id: ProofId,
    ) -> Result<ExecutionPayloadProof>;

    /// Get the proof types this generator supports
    fn supported_proof_types(&self) -> Vec<ProofId>;

    /// Check if this generator supports a specific proof type
    fn supports_proof_type(&self, proof_id: ProofId) -> bool {
        self.supported_proof_types().contains(&proof_id)
    }

    /// Get the expected resource usage for generating a proof
    fn resource_estimate(&self, _proof_id: ProofId) -> ResourceEstimate {
        ResourceEstimate::default()
    }
}

/// Resource usage estimate for proof generation
#[derive(Debug, Clone, Default)]
pub struct ResourceEstimate {
    /// Estimated CPU cores needed
    pub cpu_cores: f32,
    /// Estimated memory in MB
    pub memory_mb: u64,
    /// Estimated time in seconds
    pub time_seconds: u64,
}