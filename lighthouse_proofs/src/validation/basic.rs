//! Basic proof validation implementation

use super::ProofValidator;
use crate::types::{ErasedExecutionPayload, ExecutionPayloadProof};
use crate::{Error, Result};
use async_trait::async_trait;
use tracing::debug;

/// Basic proof validator that performs structural validation
pub struct BasicProofValidator {
    /// Minimum proof data size in bytes
    min_proof_size: usize,
    /// Maximum proof data size in bytes
    max_proof_size: usize,
}

impl BasicProofValidator {
    /// Create a new basic proof validator
    pub fn new() -> Self {
        Self {
            min_proof_size: 1,
            max_proof_size: 10 * 1024 * 1024, // 10MB
        }
    }

    /// Create with custom size limits
    pub fn with_size_limits(min_size: usize, max_size: usize) -> Self {
        Self {
            min_proof_size: min_size,
            max_proof_size: max_size,
        }
    }
}

impl Default for BasicProofValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProofValidator for BasicProofValidator {
    async fn validate_proof(
        &self,
        proof: &ExecutionPayloadProof,
        payload: &ErasedExecutionPayload,
    ) -> Result<bool> {
        // First validate structure
        self.validate_proof_structure(proof).await?;

        // Verify proof matches payload
        if proof.block_hash != payload.block_hash {
            return Err(Error::ValidationFailed(format!(
                "Proof block hash {:?} doesn't match payload hash {:?}",
                proof.block_hash,
                payload.block_hash
            )));
        }

        debug!(
            "Validated proof for block {:?} on subnet {}",
            proof.block_hash,
            proof.proof_id.id()
        );

        // In a real implementation, this would perform cryptographic validation
        // For now, we just check basic properties
        Ok(true)
    }

    async fn validate_proof_structure(&self, proof: &ExecutionPayloadProof) -> Result<bool> {
        // Check proof data size
        if proof.proof_data.len() < self.min_proof_size {
            return Err(Error::ValidationFailed(format!(
                "Proof data too small: {} bytes (minimum: {})",
                proof.proof_data.len(),
                self.min_proof_size
            )));
        }

        if proof.proof_data.len() > self.max_proof_size {
            return Err(Error::ValidationFailed(format!(
                "Proof data too large: {} bytes (maximum: {})",
                proof.proof_data.len(),
                self.max_proof_size
            )));
        }

        // Check version support
        if !proof.is_version_supported() {
            return Err(Error::ValidationFailed(format!(
                "Unsupported proof version: {}",
                proof.version
            )));
        }

        Ok(true)
    }

    fn supported_versions(&self) -> Vec<u32> {
        vec![1] // Currently only support version 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExecutionBlockHash, Hash256, ProofId};

    #[tokio::test]
    async fn test_basic_validation() {
        let validator = BasicProofValidator::new();
        
        // Create matching payload and proof
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let payload = ErasedExecutionPayload {
            block_hash,
            block_number: 100,
            parent_hash: ExecutionBlockHash::from(Hash256::random()),
            timestamp: 1000,
            payload_bytes: vec![],
        };
        
        let proof = ExecutionPayloadProof::new_v1(
            block_hash,
            ProofId::EXECUTION_WITNESS,
            vec![1, 2, 3],
        );
        
        // Should validate successfully
        assert!(validator.validate_proof(&proof, &payload).await.unwrap());
    }

    #[tokio::test]
    async fn test_validation_failures() {
        let validator = BasicProofValidator::new();
        
        let block_hash1 = ExecutionBlockHash::from(Hash256::random());
        let block_hash2 = ExecutionBlockHash::from(Hash256::random());
        
        let payload = ErasedExecutionPayload {
            block_hash: block_hash1,
            block_number: 100,
            parent_hash: ExecutionBlockHash::from(Hash256::random()),
            timestamp: 1000,
            payload_bytes: vec![],
        };
        
        // Mismatched block hash
        let bad_proof = ExecutionPayloadProof::new_v1(
            block_hash2,
            ProofId::EXECUTION_WITNESS,
            vec![1, 2, 3],
        );
        
        assert!(validator.validate_proof(&bad_proof, &payload).await.is_err());
        
        // Empty proof data
        let empty_proof = ExecutionPayloadProof::new_v1(
            block_hash1,
            ProofId::EXECUTION_WITNESS,
            vec![],
        );
        
        assert!(validator.validate_proof_structure(&empty_proof).await.is_err());
    }
}