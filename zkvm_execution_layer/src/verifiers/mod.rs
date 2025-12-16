//! Execution proof verifiers
//!
//! This module manages different proof verification systems based on prover type.
//! Each verifier implements cryptographic proof verification for a specific zkVM or proof system.

pub mod airbender;
pub mod fallback;
pub mod openvm;
pub mod panic_safe;
pub mod pico;
pub mod sp1_hypercube;
pub mod zisk;

use std::collections::HashMap;

/// Result type for proof verification
pub type VerificationResult = Result<bool, String>;

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

/// Manager for proof verifiers, keyed by zkvm_slug
///
/// Verifiers are registered by zkvm_slug (e.g., "sp1-hypercube", "zisk") and looked up
/// based on the proof system specified by the prover. This supports dynamic prover loading
/// where verification keys and provers come from the Ethproofs API.
#[derive(Default)]
pub struct VerifierStore {
    /// Map of zkvm_slug to verifier function (for dynamic prover loading)
    verifiers_by_slug: HashMap<String, VerifierEntry>,
}

impl VerifierStore {
    /// Create a new empty verifier store
    pub fn new() -> Self {
        Self {
            verifiers_by_slug: HashMap::new(),
        }
    }

    /// Register a verifier for a specific zkvm_slug
    pub fn register_by_slug(
        &mut self,
        zkvm_slug: String,
        name: &'static str,
        verify_fn: VerifierFn,
    ) {
        self.verifiers_by_slug
            .insert(zkvm_slug, VerifierEntry { name, verify_fn });
    }

    /// Get a verifier entry for a specific zkvm_slug
    pub fn get_by_slug(&self, zkvm_slug: &str) -> Option<&VerifierEntry> {
        self.verifiers_by_slug.get(zkvm_slug)
    }

    /// Check if a verifier exists for a zkvm_slug
    pub fn contains_slug(&self, zkvm_slug: &str) -> bool {
        self.verifiers_by_slug.contains_key(zkvm_slug)
    }

    /// Get the number of registered verifiers
    pub fn len(&self) -> usize {
        self.verifiers_by_slug.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.verifiers_by_slug.is_empty()
    }

    /// Get all registered zkvm slugs
    pub fn zkvm_slugs(&self) -> Vec<String> {
        self.verifiers_by_slug.keys().cloned().collect()
    }

    /// Register all verifiers by their zkvm_slug
    ///
    /// This is used for dynamic prover loading where verification keys and provers
    /// come from the Ethproofs API. All verifiers are registered once by their slug,
    /// and then can be looked up based on the prover's zkvm_slug.
    pub fn register_all_by_slug(&mut self) {
        // Register Fallback verifier
        self.register_by_slug(
            "fallback".to_string(),
            fallback::FallbackVerifier::name(),
            fallback::FallbackVerifier::verify,
        );

        // Register Airbender verifier
        self.register_by_slug(
            "airbender".to_string(),
            airbender::AirbenderVerifier::name(),
            airbender::AirbenderVerifier::verify,
        );

        // Register OpenVM verifier
        self.register_by_slug(
            "openvm".to_string(),
            openvm::OpenVmVerifier::name(),
            openvm::OpenVmVerifier::verify,
        );

        // Register Pico verifier
        self.register_by_slug(
            "pico".to_string(),
            pico::PicoVerifier::name(),
            pico::PicoVerifier::verify,
        );

        // Register SP1-Hypercube verifier
        self.register_by_slug(
            "sp1-hypercube".to_string(),
            sp1_hypercube::Sp1HypercubeVerifier::name(),
            sp1_hypercube::Sp1HypercubeVerifier::verify,
        );

        // Register ZisK verifier
        self.register_by_slug(
            "zisk".to_string(),
            zisk::ZiskVerifier::name(),
            zisk::ZiskVerifier::verify,
        );
    }
}
