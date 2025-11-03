//! Execution proof verifiers
//!
//! This module manages different proof verification systems based on prover type.
//! Each verifier implements cryptographic proof verification for a specific zkVM or proof system.

pub mod pico;
pub mod zisk;
pub mod zkm;

use std::collections::HashMap;
use types::ExecutionProofId;
use uuid::Uuid;

/// Result type for proof verification
pub type VerificationResult = Result<bool, String>;

/// Ethproofs demo prover UUIDs - hardcoded mapping for demo testing
/// These constants define the relationship between internal proof_ids (0, 1, 2, etc.)
/// and Ethproofs prover UUIDs.
pub mod ethproofs_ids {
    use uuid::Uuid;

    /// Brevis/Pico Prism verifier UUID (proof_id = 0)
    pub const BREVIS_UUID: &str = "79041a5b-ee8d-49b3-8207-86c7debf8e13";

    /// ZisK verifier UUID (proof_id = 1)
    pub const ZISK_UUID: &str = "33f14a82-47b7-42d7-9bc1-b81a46eea4fe";

    /// ZKCloud verifier UUID (proof_id = 2)
    pub const ZKCLOUD_UUID: &str = "884fcc21-d522-4b4a-b535-7cfde199485c";

    /// ZKM verifier UUID (proof_id = 3)
    pub const ZKM_UUID: &str = "84a01f4b-8078-44cf-b463-90ddcd124960";

    /// Parse a Brevis UUID
    pub fn brevis() -> Uuid {
        Uuid::parse_str(BREVIS_UUID).expect("Valid UUID")
    }

    /// Parse a ZisK UUID
    pub fn zisk() -> Uuid {
        Uuid::parse_str(ZISK_UUID).expect("Valid UUID")
    }

    /// Parse a ZKCloud UUID
    pub fn zkcloud() -> Uuid {
        Uuid::parse_str(ZKCLOUD_UUID).expect("Valid UUID")
    }

    /// Parse a ZKM UUID
    pub fn zkm() -> Uuid {
        Uuid::parse_str(ZKM_UUID).expect("Valid UUID")
    }
}

/// Trait for proof verifiers
pub trait ProofVerifier: Send + Sync {
    /// Verify a proof given the proof data and verification key
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult
    where
        Self: Sized;

    /// Get the name of this verifier
    fn name() -> &'static str
    where
        Self: Sized;
}

/// Type for verifier function
pub type VerifierFn = fn(&[u8], &[u8]) -> VerificationResult;

/// Verifier entry with name and verification function
pub struct VerifierEntry {
    pub name: &'static str,
    pub verify_fn: VerifierFn,
}

/// Manager for multiple proof verifiers, keyed by prover UUID
#[derive(Default)]
pub struct VerifierStore {
    /// Map of prover_id to verifier function
    verifiers: HashMap<Uuid, VerifierEntry>,
}

impl VerifierStore {
    /// Create a new empty verifier store
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    /// Register a verifier for a specific prover UUID
    pub fn register(&mut self, prover_id: Uuid, name: &'static str, verify_fn: VerifierFn) {
        self.verifiers
            .insert(prover_id, VerifierEntry { name, verify_fn });
    }

    /// Get a verifier entry for a specific prover UUID
    pub fn get(&self, prover_id: &Uuid) -> Option<&VerifierEntry> {
        self.verifiers.get(prover_id)
    }

    /// Check if a verifier exists for a prover
    pub fn contains(&self, prover_id: &Uuid) -> bool {
        self.verifiers.contains_key(prover_id)
    }

    /// Get the number of registered verifiers
    pub fn len(&self) -> usize {
        self.verifiers.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.verifiers.is_empty()
    }

    /// Get all registered prover IDs
    pub fn prover_ids(&self) -> Vec<Uuid> {
        self.verifiers.keys().copied().collect()
    }

    /// Get the prover UUID corresponding to a proof_id (Ethproofs demo mapping)
    ///
    /// For Ethproofs demo testing, this provides a hardcoded mapping of proof_ids to prover UUIDs:
    /// - proof_id 0 → brevis (Pico verifier)
    /// - proof_id 1 → zisk (ZisK verifier)
    /// - proof_id 2 → zkcloud (ZisK verifier)
    /// - proof_id 3 → zkm (ZKM verifier)
    pub fn get_prover_uuid_for_proof_id(&self, proof_id: ExecutionProofId) -> Option<Uuid> {
        let id = proof_id.as_u8() as u32;
        match id {
            0 => Some(ethproofs_ids::brevis()),
            1 => Some(ethproofs_ids::zisk()),
            2 => Some(ethproofs_ids::zkcloud()),
            3 => Some(ethproofs_ids::zkm()),
            _ => None,
        }
    }

    /// Create a store with default verifiers registered
    ///
    /// This registers verifiers for known Ethproofs prover UUIDs
    pub fn with_defaults() -> Self {
        let mut store = Self::new();

        // Register Pico verifier for brevis
        store.register(
            ethproofs_ids::brevis(),
            pico::PicoVerifier::name(),
            pico::PicoVerifier::verify,
        );

        // Register ZisK verifier
        store.register(
            ethproofs_ids::zisk(),
            zisk::ZiskVerifier::name(),
            zisk::ZiskVerifier::verify,
        );

        // Register ZKCloud verifier (uses ZisK verifier)
        store.register(
            ethproofs_ids::zkcloud(),
            zisk::ZiskVerifier::name(),
            zisk::ZiskVerifier::verify,
        );

        // Register ZKM verifier
        store.register(
            ethproofs_ids::zkm(),
            zkm::ZkmVerifier::name(),
            zkm::ZkmVerifier::verify,
        );

        store
    }
}
