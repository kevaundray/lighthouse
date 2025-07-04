//! Stateless execution engine implementation.
//!
//! This module provides a stateless implementation of the ExecutionEngine trait,
//! which validates execution payloads using cryptographic proofs instead of
//! running a full execution client.

use crate::engine_api::{ClientCode, EngineCapabilities, Error as ApiError, NewPayloadRequest};
use crate::execution_engine::ExecutionEngine;
use crate::json_structures::ExecutionPayloadBodyV1;
use crate::payload_status::PayloadStatus;
use crate::{
    BlobAndProofV1, BlobAndProofV2, BlockByNumberQuery, ClientVersionV1, ExecutionBlock, ForkchoiceState,
    ForkchoiceUpdatedResponse, GetPayloadResponse, PayloadAttributes,
};
use async_trait::async_trait;
use types::{Address, EthSpec, ExecutionBlockHash, ForkName, Hash256};

/// Configuration for the stateless execution engine.
pub struct StatelessEngineConfig {
    /// List of execution proof subnet IDs to validate.
    pub execution_proof_subnets: Vec<u64>,
    /// Maximum number of execution proof subnets.
    pub max_execution_proof_subnets: u64,
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
    ) -> Result<PayloadStatus, ApiError> {
        // In stateless mode, we optimistically accept all payloads
        // Actual validation will happen when execution proofs arrive
        Ok(PayloadStatus::Syncing)
    }

    async fn get_payload(
        &self,
        _fork_name: ForkName,
        _payload_id: u64,
    ) -> Result<GetPayloadResponse<E>, ApiError> {
        // Stateless nodes don't produce payloads
        Err(ApiError::PayloadIdUnavailable)
    }

    async fn notify_forkchoice_updated(
        &self,
        _forkchoice_state: ForkchoiceState,
        _payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, ApiError> {
        // Return a basic response indicating we're syncing
        Ok(ForkchoiceUpdatedResponse {
            payload_status: PayloadStatus::Syncing.into(),
            payload_id: None,
        })
    }

    async fn exchange_capabilities(&self) -> Result<EngineCapabilities, ApiError> {
        // Return minimal capabilities for stateless mode
        Ok(EngineCapabilities {
            new_payload_v1: true,
            new_payload_v2: true,
            new_payload_v3: true,
            new_payload_v4: true,
            forkchoice_updated_v1: true,
            forkchoice_updated_v2: true,
            forkchoice_updated_v3: true,
            get_payload_v1: false,
            get_payload_v2: false,
            get_payload_v3: false,
            get_payload_v4: false,
            get_payload_bodies_by_hash_v1: false,
            get_payload_bodies_by_hash_v2: false,
            get_payload_bodies_by_range_v1: false,
            get_payload_bodies_by_range_v2: false,
            get_blobs_v1: false,
            get_blobs_v2: false,
        })
    }

    async fn get_client_version(&self) -> Result<Vec<ClientVersionV1>, ApiError> {
        // Return a stateless client identifier
        Ok(vec![ClientVersionV1 {
            code: "SL".to_string(), // Stateless
            name: "Lighthouse Stateless".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: "00000000".to_string(),
        }])
    }

    async fn get_block_by_hash(
        &self,
        _block_hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionBlock>, ApiError> {
        // Stateless nodes don't have block storage
        Ok(None)
    }

    async fn get_block_by_number(
        &self,
        _query: BlockByNumberQuery<'_>,
    ) -> Result<Option<ExecutionBlock>, ApiError> {
        // Stateless nodes don't have block storage
        Ok(None)
    }

    async fn get_payload_bodies_by_hash(
        &self,
        _hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, ApiError> {
        // Stateless nodes don't have payload bodies
        Err(ApiError::Unsupported("get_payload_bodies_by_hash"))
    }

    async fn get_payload_bodies_by_range(
        &self,
        _start: u64,
        _count: u64,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, ApiError> {
        // Stateless nodes don't have payload bodies
        Err(ApiError::Unsupported("get_payload_bodies_by_range"))
    }

    async fn get_blobs_v1(
        &self,
        _query: Vec<Hash256>,
    ) -> Result<Vec<Option<BlobAndProofV1<E>>>, ApiError> {
        // Stateless nodes don't have blob storage
        Err(ApiError::Unsupported("get_blobs_v1"))
    }

    async fn get_blobs_v2(
        &self,
        _query: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV2<E>>>, ApiError> {
        // Stateless nodes don't have blob storage
        Err(ApiError::Unsupported("get_blobs_v2"))
    }

    async fn is_synced(&self) -> bool {
        // Stateless nodes are always "syncing" as they rely on proofs
        false
    }

    async fn is_offline(&self) -> bool {
        // Stateless nodes are never offline as they don't connect to an EL
        false
    }

    fn client_code(&self) -> ClientCode {
        ClientCode::Lighthouse
    }
}