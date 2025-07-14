//! Proof validation implementations

mod basic;

pub use basic::BasicProofValidator;

use crate::types::{ErasedExecutionPayload, ExecutionPayloadProof};
use crate::Result;
use async_trait::async_trait;

/// Trait for proof validation implementations
#[async_trait]
pub trait ProofValidator: Send + Sync {
    /// Validate a proof against an execution payload
    async fn validate_proof(
        &self,
        proof: &ExecutionPayloadProof,
        payload: &ErasedExecutionPayload,
    ) -> Result<bool>;

    /// Validate proof structure without payload
    async fn validate_proof_structure(&self, proof: &ExecutionPayloadProof) -> Result<bool>;

    /// Get supported proof versions
    fn supported_versions(&self) -> Vec<u32>;
}