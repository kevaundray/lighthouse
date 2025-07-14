//! Dummy proof generator for testing and development

use super::{ProofGenerator, ResourceEstimate};
use crate::types::{ErasedExecutionPayload, ExecutionPayloadProof, ProofId};
use crate::Result;
use async_trait::async_trait;
use rand::{thread_rng, Rng};
use std::time::Duration;
use tracing::debug;

/// Dummy proof generator that creates placeholder proofs
pub struct DummyProofGenerator {
    /// Delay range for simulating proof generation time
    delay_range: (u64, u64),
}

impl DummyProofGenerator {
    /// Create a new dummy proof generator
    pub fn new() -> Self {
        Self {
            delay_range: (1000, 3000), // 1-3 seconds default
        }
    }

    /// Create with custom delay range
    pub fn with_delay_range(min_ms: u64, max_ms: u64) -> Self {
        Self {
            delay_range: (min_ms, max_ms),
        }
    }
}

impl Default for DummyProofGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProofGenerator for DummyProofGenerator {
    async fn generate_proof(
        &self,
        payload: &ErasedExecutionPayload,
        witness: &[u8],
        proof_id: ProofId,
    ) -> Result<ExecutionPayloadProof> {
        let execution_block_hash = payload.block_hash;
        let block_number = payload.block_number;

        // Simulate proof generation delay
        let delay_ms = thread_rng().gen_range(self.delay_range.0..=self.delay_range.1);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;

        debug!(
            "Generated dummy proof for block {:?} (number {}) on subnet {} after {}ms",
            execution_block_hash,
            block_number,
            proof_id.subnet_id(),
            delay_ms
        );

        // Create dummy proof data
        let dummy_data = format!(
            "dummy_proof_subnet_{}_block_{:?}_number_{}_witness_len_{}_timestamp_{}",
            proof_id.subnet_id(),
            execution_block_hash,
            block_number,
            witness.len(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        )
        .into_bytes();

        Ok(ExecutionPayloadProof::new_v1(
            execution_block_hash,
            proof_id,
            dummy_data,
        ))
    }

    fn supported_proof_types(&self) -> Vec<ProofId> {
        // Dummy generator supports all proof types
        vec![
            ProofId::EXECUTION_WITNESS,
            ProofId::custom(1),
            ProofId::custom(2),
            ProofId::custom(3),
            ProofId::custom(4),
            ProofId::custom(5),
            ProofId::custom(6),
            ProofId::custom(7),
        ]
    }

    fn resource_estimate(&self, _proof_id: ProofId) -> ResourceEstimate {
        ResourceEstimate {
            cpu_cores: 0.1,
            memory_mb: 10,
            time_seconds: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExecutionBlockHash, Hash256};

    #[tokio::test]
    async fn test_dummy_proof_generation() {
        let generator = DummyProofGenerator::new();
        
        // Create a test payload
        let payload = ErasedExecutionPayload {
            block_hash: ExecutionBlockHash::from(Hash256::random()),
            block_number: 123,
            parent_hash: ExecutionBlockHash::from(Hash256::random()),
            timestamp: 1000,
            payload_bytes: vec![],
        };
        
        let witness = b"test_witness";
        let proof_id = ProofId::custom(1);
        
        // Generate proof
        let proof = generator
            .generate_proof(&payload, witness, proof_id)
            .await
            .unwrap();
        
        // Verify proof
        assert_eq!(proof.block_hash, payload.block_hash);
        assert_eq!(proof.proof_id, proof_id);
        assert!(!proof.proof_data.is_empty());
        
        // Check that proof data contains expected info
        let proof_str = String::from_utf8_lossy(&proof.proof_data);
        assert!(proof_str.contains("dummy_proof"));
        assert!(proof_str.contains("subnet_1"));
        assert!(proof_str.contains("number_123"));
    }
}