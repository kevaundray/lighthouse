//! Error types for the lighthouse_proofs crate

use thiserror::Error;
use types::ExecutionBlockHash;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid proof for block {block_hash:?} on subnet {subnet_id}: {reason}")]
    InvalidProof {
        block_hash: ExecutionBlockHash,
        subnet_id: u64,
        reason: String,
    },

    #[error("Proof validation failed: {0}")]
    ValidationFailed(String),

    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Proof not found for block {0:?}")]
    ProofNotFound(ExecutionBlockHash),

    #[error("Insufficient proofs: {available}/{required} for block {block_hash:?}")]
    InsufficientProofs {
        block_hash: ExecutionBlockHash,
        available: usize,
        required: usize,
    },

    #[error("Invalid subnet ID: {0}")]
    InvalidSubnetId(u64),

    #[error("Broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("Chain tracking error: {0}")]
    ChainTrackingError(String),

    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    #[error("Internal error: {0}")]
    Internal(String),
    
    #[error("Proof system not initialized")]
    SystemNotInitialized,
}