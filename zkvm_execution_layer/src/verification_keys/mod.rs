//! Execution proof verification key data structures
//!
//! This module defines the data structures for handling verification keys used
//! in execution proof verification. Verification keys are loaded dynamically from
//! the Ethproofs API via the active_provers_loader module.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents a verification key for validating execution proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionProofVerificationKey {
    /// Unique identifier for the prover that generated this key
    pub prover_id: Uuid,
    /// The binary verification key data
    pub vk: Vec<u8>,
}

impl ExecutionProofVerificationKey {
    /// Create a new verification key
    pub fn new(prover_id: Uuid, vk: Vec<u8>) -> Self {
        Self { prover_id, vk }
    }

    /// Get the size of the verification key in bytes
    pub fn size(&self) -> usize {
        self.vk.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_key_creation() {
        let prover_id = Uuid::new_v4();
        let vk_data = vec![1, 2, 3, 4, 5];
        let vk = ExecutionProofVerificationKey::new(prover_id, vk_data.clone());

        assert_eq!(vk.prover_id, prover_id);
        assert_eq!(vk.vk, vk_data);
        assert_eq!(vk.size(), 5);
    }
}
