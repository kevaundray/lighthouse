pub mod config;

pub mod proof_generation;
pub mod proof_verification;

pub mod registry_proof_gen;
pub mod registry_proof_verification;

pub mod dummy_proof_gen;
pub mod dummy_proof_verifier;

/// Engine API implementation for ZK-VM execution
pub mod engine_api;

pub use config::ZKVMExecutionLayerConfig;
/// Re-export the main ZK-VM engine API and config
pub use engine_api::ZKVMEngineApi;
pub use registry_proof_gen::GeneratorRegistry;

/// TODO(ethproofs): Used for Ethproofs demo testing.
pub mod ethproofs_demo;
pub mod verification_keys;
pub mod verifiers;
