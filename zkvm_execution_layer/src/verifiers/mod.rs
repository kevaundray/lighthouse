//! Execution proof verifiers
//!
//! This module manages different proof verification systems based on prover type.
//! Each verifier implements cryptographic proof verification for a specific zkVM or proof system.

pub mod airbender;
pub mod fallback;
pub mod openvm;
pub mod pico;
pub mod sp1_hypercube;
pub mod zisk;
pub mod zkcloud;

use std::collections::HashMap;
use types::ExecutionProofId;
use uuid::Uuid;

/// Result type for proof verification
pub type VerificationResult = Result<bool, String>;

/// Ethproofs demo prover UUIDs - hardcoded mapping for demo testing
/// These constants define the relationship between internal proof_ids (0, 1, 2, etc.)
/// and Ethproofs prover UUIDs.
///
/// Proof ID Mapping (alphabetical order, Fallback first, Airbender reserved):
/// - proof_id 0 → Fallback verifier (used when Ethproofs API fails/times out)
/// - proof_id 1 → Airbender verifier (reserved for future use)
/// - proof_id 2 → OpenVM verifier
/// - proof_id 3 → Pico Prism verifier
/// - proof_id 4 → SP1-Hypercube verifier
/// - proof_id 5 → ZisK 1 (Girona) verifier
/// - proof_id 6 → ZisK 2 (Sevilla) verifier
/// - proof_id 7 → ZisK-ZkCloud verifier
pub mod ethproofs_ids {
    use uuid::Uuid;

    /// Fallback verifier UUID (proof_id = 0)
    /// Used for dummy proofs when Ethproofs API fails or times out
    pub const FALLBACK_UUID: &str = "00000000-0000-0000-0000-000000000000";

    /// Airbender verifier UUID (proof_id = 1)
    pub const AIRBENDER_UUID: &str = "b18507c4-50f3-4638-854a-ed625c7e685a";

    /// OpenVM verifier UUID (proof_id = 2)
    pub const OPENVM_UUID: &str = "9b6768c0-831d-488c-ba72-05f93975a3be";

    /// Pico Prism verifier UUID (proof_id = 3)
    pub const PICO_UUID: &str = "f404c187-88d6-4927-963c-61760a639900";

    /// SP1-Hypercube verifier UUID (proof_id = 4)
    pub const SP1_HYPERCUBE_UUID: &str = "fbef2553-8cd0-4f45-b328-570b5c8688b2";

    /// ZisK 1 (Girona) verifier UUID (proof_id = 5)
    pub const ZISK_1_GIRONA_UUID: &str = "817bbf03-07b4-466d-879b-e476322bd080";

    /// ZisK 2 (Sevilla) verifier UUID (proof_id = 6)
    pub const ZISK_2_SEVILLA_UUID: &str = "534e6cf4-3dfe-47de-bba2-a0b11d544557";

    /// ZisK-ZkCloud verifier UUID (proof_id = 7)
    pub const ZISK_ZKCLOUD_UUID: &str = "884fcc21-d522-4b4a-b535-7cfde199485c";

    /// Parse a Fallback UUID
    pub fn fallback() -> Uuid {
        Uuid::parse_str(FALLBACK_UUID).expect("Valid UUID")
    }

    /// Parse an Airbender UUID
    pub fn airbender() -> Uuid {
        Uuid::parse_str(AIRBENDER_UUID).expect("Valid UUID")
    }

    /// Parse an OpenVM UUID
    pub fn openvm() -> Uuid {
        Uuid::parse_str(OPENVM_UUID).expect("Valid UUID")
    }

    /// Parse a Pico UUID
    pub fn pico() -> Uuid {
        Uuid::parse_str(PICO_UUID).expect("Valid UUID")
    }

    /// Parse a SP1-Hypercube UUID
    pub fn sp1_hypercube() -> Uuid {
        Uuid::parse_str(SP1_HYPERCUBE_UUID).expect("Valid UUID")
    }

    /// Parse a ZisK 1 (Girona) UUID
    pub fn zisk_1_girona() -> Uuid {
        Uuid::parse_str(ZISK_1_GIRONA_UUID).expect("Valid UUID")
    }

    /// Parse a ZisK 2 (Sevilla) UUID
    pub fn zisk_2_sevilla() -> Uuid {
        Uuid::parse_str(ZISK_2_SEVILLA_UUID).expect("Valid UUID")
    }

    /// Parse a ZisK-ZkCloud UUID
    pub fn zisk_zkcloud() -> Uuid {
        Uuid::parse_str(ZISK_ZKCLOUD_UUID).expect("Valid UUID")
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
    /// - proof_id 0 → fallback
    /// - proof_id 1 → airbender
    /// - proof_id 2 → openvm
    /// - proof_id 3 → pico
    /// - proof_id 4 → sp1_hypercube
    /// - proof_id 5 → zisk_1_girona
    /// - proof_id 6 → zisk_2_sevilla
    /// - proof_id 7 → zisk_zkcloud
    pub fn get_prover_uuid_for_proof_id(&self, proof_id: ExecutionProofId) -> Option<Uuid> {
        let id = proof_id.as_u8() as u32;
        match id {
            0 => Some(ethproofs_ids::fallback()),
            1 => Some(ethproofs_ids::airbender()),
            2 => Some(ethproofs_ids::openvm()),
            3 => Some(ethproofs_ids::pico()),
            4 => Some(ethproofs_ids::sp1_hypercube()),
            5 => Some(ethproofs_ids::zisk_1_girona()),
            6 => Some(ethproofs_ids::zisk_2_sevilla()),
            7 => Some(ethproofs_ids::zisk_zkcloud()),
            _ => None,
        }
    }

    /// Create a store with default verifiers registered
    ///
    /// This registers verifiers for known Ethproofs prover UUIDs
    pub fn with_defaults() -> Self {
        let mut store = Self::new();

        // Register Fallback verifier (proof_id 0)
        store.register(
            ethproofs_ids::fallback(),
            fallback::FallbackVerifier::name(),
            fallback::FallbackVerifier::verify,
        );

        // Register Airbender verifier (proof_id 1)
        store.register(
            ethproofs_ids::airbender(),
            airbender::AirbenderVerifier::name(),
            airbender::AirbenderVerifier::verify,
        );

        // Register OpenVM verifier (proof_id 2)
        store.register(
            ethproofs_ids::openvm(),
            openvm::OpenVmVerifier::name(),
            openvm::OpenVmVerifier::verify,
        );

        // Register Pico verifier (proof_id 3)
        store.register(
            ethproofs_ids::pico(),
            pico::PicoVerifier::name(),
            pico::PicoVerifier::verify,
        );

        // Register SP1-Hypercube verifier (proof_id 4)
        store.register(
            ethproofs_ids::sp1_hypercube(),
            sp1_hypercube::Sp1HypercubeVerifier::name(),
            sp1_hypercube::Sp1HypercubeVerifier::verify,
        );

        // Register ZisK 1 (Girona) verifier (proof_id 5)
        store.register(
            ethproofs_ids::zisk_1_girona(),
            zisk::ZiskVerifier::name(),
            zisk::ZiskVerifier::verify,
        );

        // Register ZisK 2 (Sevilla) verifier (proof_id 6)
        store.register(
            ethproofs_ids::zisk_2_sevilla(),
            zisk::ZiskVerifier::name(),
            zisk::ZiskVerifier::verify,
        );

        // Register ZisK-ZkCloud verifier (proof_id 7)
        store.register(
            ethproofs_ids::zisk_zkcloud(),
            zkcloud::ZkCloudVerifier::name(),
            zkcloud::ZkCloudVerifier::verify,
        );

        store
    }
}
