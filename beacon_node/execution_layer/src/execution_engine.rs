//! Trait abstraction for execution engines.
//!
//! This module provides a trait-based abstraction for different execution engine implementations,
//! allowing for standard execution engines, stateless validation engines, and testing mocks.

use crate::engine_api::{ClientCode, EngineCapabilities, Error as ApiError, NewPayloadRequest};
use crate::json_structures::ExecutionPayloadBodyV1;
use crate::payload_status::PayloadStatus;
use crate::{
    BlobAndProofV1, BlobAndProofV2, BlockByNumberQuery, ClientVersionV1, ExecutionBlock, ForkchoiceState,
    ForkchoiceUpdatedResponse, GetPayloadResponse, PayloadAttributes,
};
use async_trait::async_trait;
use types::{Address, EthSpec, ExecutionBlockHash, ForkName, Hash256};

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
    ) -> Result<PayloadStatus, ApiError>;

    /// Get a payload for block production.
    async fn get_payload(
        &self,
        fork_name: ForkName,
        payload_id: u64,
    ) -> Result<GetPayloadResponse<E>, ApiError>;

    /// Update the fork choice state.
    async fn notify_forkchoice_updated(
        &self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, ApiError>;

    /// Exchange capabilities with the execution engine.
    async fn exchange_capabilities(&self) -> Result<EngineCapabilities, ApiError>;

    /// Get the client version.
    async fn get_client_version(&self) -> Result<Vec<ClientVersionV1>, ApiError>;

    /// Get a block by its hash.
    async fn get_block_by_hash(
        &self,
        block_hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionBlock>, ApiError>;

    /// Get a block by number query.
    async fn get_block_by_number(
        &self,
        query: BlockByNumberQuery<'_>,
    ) -> Result<Option<ExecutionBlock>, ApiError>;

    /// Get payload bodies by hash.
    async fn get_payload_bodies_by_hash(
        &self,
        hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, ApiError>;

    /// Get payload bodies by range.
    async fn get_payload_bodies_by_range(
        &self,
        start: u64,
        count: u64,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, ApiError>;

    /// Get blob sidecars v1.
    async fn get_blobs_v1(
        &self,
        query: Vec<Hash256>,
    ) -> Result<Vec<Option<BlobAndProofV1<E>>>, ApiError>;

    /// Get blob sidecars v2.
    async fn get_blobs_v2(
        &self,
        query: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV2<E>>>, ApiError>;

    /// Check if the engine is synced.
    async fn is_synced(&self) -> bool;

    /// Check if the engine is offline.
    async fn is_offline(&self) -> bool;

    /// Get the client code identifier.
    fn client_code(&self) -> ClientCode {
        ClientCode::Unknown
    }

    /// Get a suggested fee recipient if one is configured.
    fn suggested_fee_recipient(&self) -> Option<Address> {
        None
    }
}