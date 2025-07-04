//! Trait abstraction for execution engines.
//!
//! This module provides a trait-based abstraction for different execution engine implementations,
//! allowing for standard execution engines, stateless validation engines, and testing mocks.

use crate::engine_api::{
    BlockByNumberQuery, EngineCapabilities, ForkchoiceUpdatedResponse, NewPayloadRequest,
    PayloadAttributes, PayloadId,
};
use crate::engines::EngineError;
use crate::json_structures::{BlobAndProofV1, BlobAndProofV2};
use crate::payload_status::PayloadStatus;
use crate::ForkchoiceState;
use crate::{ClientVersionV1, ExecutionBlock, ExecutionPayloadBodyV1};
use async_trait::async_trait;
use std::time::Duration;
use types::{EthSpec, ExecutionBlockHash, ForkName, Hash256};

/// A trait that defines the interface for execution engines.
///
/// This trait abstracts the core operations that an execution engine must provide,
/// allowing for different implementations such as:
/// - Standard execution engines (e.g., Geth, Nethermind)
/// - Stateless validation engines that use proofs
/// - Mock engines for testing
#[async_trait]
pub trait ExecutionEngine<E: EthSpec>: Send + Sync {
    /// Process a new execution payload.
    async fn notify_new_payload(
        &self,
        new_payload_request: NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatus, EngineError>;

    /// Check if the engine is synced.
    async fn is_synced(&self) -> bool;

    /// Check if the engine is offline.
    async fn is_offline(&self) -> bool;

    /// Perform an upcheck on the engine to test connectivity.
    async fn upcheck(&self) -> Result<(), EngineError>;

    /// Notify the engine of forkchoice updates.
    async fn notify_forkchoice_updated(
        &self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, EngineError>;

    /// Get a payload from the engine.
    async fn get_payload(
        &self,
        fork_name: ForkName,
        payload_id: PayloadId,
    ) -> Result<crate::engine_api::GetPayloadResponse<E>, EngineError>;

    /// Get engine capabilities.
    async fn get_engine_capabilities(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<EngineCapabilities, EngineError>;

    /// Get engine version information.
    async fn get_engine_version(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<Vec<ClientVersionV1>, EngineError>;

    /// Get payload bodies by hash.
    async fn get_payload_bodies_by_hash(
        &self,
        hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, EngineError>;

    /// Get payload bodies by range.
    async fn get_payload_bodies_by_range(
        &self,
        start: u64,
        count: u64,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, EngineError>;

    /// Get blobs (v1).
    async fn get_blobs_v1(
        &self,
        query: Vec<Hash256>,
    ) -> Result<Vec<Option<BlobAndProofV1<E>>>, EngineError>;

    /// Get blobs (v2).
    async fn get_blobs_v2(
        &self,
        query: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV2<E>>>, EngineError>;

    /// Get block by number.
    async fn get_block_by_number(
        &self,
        query: BlockByNumberQuery<'_>,
    ) -> Result<Option<ExecutionBlock>, EngineError>;

    /// Get block by hash.
    async fn get_block_by_hash(
        &self,
        block_hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionBlock>, EngineError>;

    /// Get payload ID for a given head block hash and payload attributes.
    async fn get_payload_id(
        &self,
        head_block_hash: &ExecutionBlockHash,
        payload_attributes: &PayloadAttributes,
    ) -> Option<PayloadId>;
}
