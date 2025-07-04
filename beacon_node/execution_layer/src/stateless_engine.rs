//! Stateless execution engine implementation.
//!
//! This module provides a stateless implementation of the ExecutionEngine trait,
//! which validates execution payloads using cryptographic proofs instead of
//! running a full execution client.

use crate::engine_api::NewPayloadRequest;
use crate::engines::EngineError;
use crate::execution_engine::ExecutionEngine;
use crate::payload_status::PayloadStatus;
use async_trait::async_trait;
use types::EthSpec;

/// Configuration for the stateless execution engine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatelessEngineConfig {
    /// List of execution proof subnet IDs to validate.
    pub execution_proof_subnets: Vec<u64>,
    /// Maximum number of execution proof subnets.
    pub max_execution_proof_subnets: u64,
}

impl Default for StatelessEngineConfig {
    fn default() -> Self {
        Self {
            execution_proof_subnets: (0..8).collect(), // Default to subnets 0-7
            max_execution_proof_subnets: 8,
        }
    }
}

/// Stateless execution engine that validates using proofs.
///
/// This engine optimistically accepts all payloads and relies on
/// execution proofs received via gossip to validate them later.
pub struct StatelessExecutionEngine {
    /// Configuration for the stateless engine.
    config: StatelessEngineConfig,
}

impl StatelessExecutionEngine {
    /// Create a new stateless execution engine.
    pub fn new(config: StatelessEngineConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl<E: EthSpec> ExecutionEngine<E> for StatelessExecutionEngine {
    async fn notify_new_payload(
        &self,
        _new_payload_request: NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatus, EngineError> {
        // In stateless mode, we optimistically accept all payloads
        // Actual validation will happen when execution proofs arrive
        Ok(PayloadStatus::Syncing)
    }

    async fn is_synced(&self) -> bool {
        // Stateless nodes are always "syncing" as they rely on proofs
        false
    }

    async fn is_offline(&self) -> bool {
        // Stateless nodes are never offline as they don't connect to an EL
        false
    }
}
