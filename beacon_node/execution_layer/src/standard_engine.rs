//! Standard execution engine implementation.
//!
//! This module provides the standard implementation of the ExecutionEngine trait,
//! which communicates with real execution clients via JSON-RPC.

use crate::engine_api::{ClientCode, EngineCapabilities, Error as ApiError, NewPayloadRequest};
use crate::engines::Engine;
use crate::execution_engine::ExecutionEngine;
use crate::json_structures::ExecutionPayloadBodyV1;
use crate::payload_status::PayloadStatus;
use crate::{
    BlobAndProofV1, BlobAndProofV2, BlockByNumberQuery, ClientVersionV1, ExecutionBlock, ForkchoiceState,
    ForkchoiceUpdatedResponse, GetPayloadResponse, PayloadAttributes,
};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use types::{Address, EthSpec, ExecutionBlockHash, ForkName, Hash256};

/// Standard execution engine that communicates with execution clients.
pub struct StandardExecutionEngine {
    /// The underlying engine that handles JSON-RPC communication.
    engine: Arc<Engine>,
}

impl StandardExecutionEngine {
    /// Create a new standard execution engine.
    pub fn new(engine: Arc<Engine>) -> Self {
        Self { engine }
    }

    /// Get the underlying engine.
    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }
}

#[async_trait]
impl<E: EthSpec> ExecutionEngine<E> for StandardExecutionEngine {
    async fn notify_new_payload(
        &self,
        new_payload_request: NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatus, ApiError> {
        self.engine
            .request(|engine| engine.api.new_payload(new_payload_request))
            .await
            .map(|response| PayloadStatus::from(response.status))
    }

    async fn get_payload(
        &self,
        fork_name: ForkName,
        payload_id: u64,
    ) -> Result<GetPayloadResponse<E>, ApiError> {
        self.engine
            .request(|engine| engine.api.get_payload::<E>(fork_name, payload_id))
            .await
    }

    async fn notify_forkchoice_updated(
        &self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, ApiError> {
        self.engine
            .request(|engine| {
                engine
                    .notify_forkchoice_updated(forkchoice_state, payload_attributes)
            })
            .await
    }

    async fn exchange_capabilities(&self) -> Result<EngineCapabilities, ApiError> {
        self.engine
            .request(|engine| engine.get_engine_capabilities(Some(Duration::ZERO)))
            .await
    }

    async fn get_client_version(&self) -> Result<Vec<ClientVersionV1>, ApiError> {
        self.engine
            .request(|engine| engine.get_engine_version(Some(Duration::ZERO)))
            .await
    }

    async fn get_block_by_hash(
        &self,
        block_hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionBlock>, ApiError> {
        self.engine
            .request(|engine| engine.api.get_block_by_hash(block_hash))
            .await
    }

    async fn get_block_by_number(
        &self,
        query: BlockByNumberQuery<'_>,
    ) -> Result<Option<ExecutionBlock>, ApiError> {
        self.engine
            .request(|engine| engine.api.get_block_by_number(query))
            .await
    }

    async fn get_payload_bodies_by_hash(
        &self,
        hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, ApiError> {
        self.engine
            .request(|engine| engine.api.get_payload_bodies_by_hash_v1(hashes))
            .await
    }

    async fn get_payload_bodies_by_range(
        &self,
        start: u64,
        count: u64,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, ApiError> {
        self.engine
            .request(|engine| engine.api.get_payload_bodies_by_range_v1(start, count))
            .await
    }

    async fn get_blobs_v1(
        &self,
        query: Vec<Hash256>,
    ) -> Result<Vec<Option<BlobAndProofV1<E>>>, ApiError> {
        self.engine
            .request(|engine| engine.api.get_blobs_v1(query))
            .await
    }

    async fn get_blobs_v2(
        &self,
        query: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV2<E>>>, ApiError> {
        self.engine
            .request(|engine| engine.api.get_blobs_v2(query))
            .await
    }

    async fn is_synced(&self) -> bool {
        self.engine.is_synced().await
    }

    async fn is_offline(&self) -> bool {
        self.engine.is_offline().await
    }

    fn client_code(&self) -> ClientCode {
        self.engine.client_code()
    }
}