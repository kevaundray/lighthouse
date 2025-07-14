//! Proof storage implementations

mod memory;
mod metrics;

pub use memory::MemoryProofStore;
pub use metrics::ProofStoreMetrics;

use crate::types::{ExecutionBlockHash, ExecutionPayloadProof, ProofId};
use crate::Result;
use async_trait::async_trait;

/// Trait for proof storage implementations
#[async_trait]
pub trait ProofStore: Send + Sync {
    /// Store a proof after validation
    async fn store_proof(&self, proof: ExecutionPayloadProof) -> Result<()>;

    /// Store a proof without validation (assumes already validated)
    async fn store_validated_proof(&self, proof: ExecutionPayloadProof) -> Result<()>;

    /// Get a specific proof
    async fn get_proof(
        &self,
        block_hash: &ExecutionBlockHash,
        proof_id: ProofId,
    ) -> Option<ExecutionPayloadProof>;

    /// Get all proofs for a block
    async fn get_proofs(&self, block_hash: &ExecutionBlockHash) -> Vec<ExecutionPayloadProof>;

    /// Check if we have any valid proof for a block
    async fn has_valid_proof(&self, block_hash: &ExecutionBlockHash) -> bool;

    /// Check if we have a specific proof
    async fn has_valid_proof_for_id(
        &self,
        block_hash: &ExecutionBlockHash,
        proof_id: ProofId,
    ) -> bool;

    /// Get the number of proofs for a block
    async fn proof_count_for_payload(&self, block_hash: &ExecutionBlockHash) -> usize;

    /// Check if we have sufficient proofs
    async fn has_sufficient_proofs(
        &self,
        block_hash: &ExecutionBlockHash,
        min_required: usize,
    ) -> bool {
        self.proof_count_for_payload(block_hash).await >= min_required
    }

    /// Get total number of stored proofs
    async fn len(&self) -> usize;

    /// Check if store is empty
    async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Get number of unique payloads with proofs
    async fn unique_payload_count(&self) -> usize;

    /// Clear all stored proofs
    async fn clear(&self) -> Result<()>;

    /// Remove proofs older than the given timestamp
    async fn prune_old_proofs(&self, cutoff_timestamp: u64) -> Result<usize>;

    /// Get metrics about the store
    async fn metrics(&self) -> ProofStoreMetrics;
    
    /// Clean up finalized blocks
    async fn cleanup_finalized_blocks(&self, finalized_roots: Vec<types::Hash256>) -> usize;
}