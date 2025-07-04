//! Trait abstraction for execution engines.
//!
//! This module provides a trait-based abstraction for different execution engine implementations,
//! allowing for standard execution engines, stateless validation engines, and testing mocks.

use crate::engine_api::NewPayloadRequest;
use crate::engines::EngineError;
use crate::payload_status::PayloadStatus;
use async_trait::async_trait;
use types::EthSpec;

/// A trait that defines the interface for execution engines.
///
/// This trait abstracts the core operations that an execution engine must provide,
/// allowing for different implementations such as:
/// - Standard execution engines (e.g., Geth, Nethermind)
/// - Stateless validation engines that use proofs
/// - Mock engines for testing
#[async_trait]
pub trait ExecutionEngine<E: EthSpec>: Send + Sync {
    /// Process a new execution payload - the core method that needs abstraction.
    async fn notify_new_payload(
        &self,
        new_payload_request: NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatus, EngineError>;

    /// Check if the engine is synced.
    async fn is_synced(&self) -> bool;

    /// Check if the engine is offline.
    async fn is_offline(&self) -> bool;
}
