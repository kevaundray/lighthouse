//! Standard execution engine implementation.
//!
//! This module provides the standard implementation of the ExecutionEngine trait,
//! which communicates with real execution clients via JSON-RPC.

use crate::engine_api::{
    BlockByNumberQuery, EngineCapabilities, ForkchoiceUpdatedResponse,
    NewPayloadRequest, PayloadAttributes, PayloadId,
};
use crate::engines::{Engine, EngineError};
use crate::execution_engine::ExecutionEngine;
use crate::json_structures::{BlobAndProofV1, BlobAndProofV2};
use crate::payload_status::{process_payload_status, PayloadStatus};
use crate::{ClientVersionV1, ExecutionBlock, ExecutionPayloadBodyV1};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use types::{
    EthSpec, ExecutionBlockHash, ForkName, Hash256,
};
use crate::ForkchoiceState;

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
    ) -> Result<PayloadStatus, EngineError> {
        let block_hash = new_payload_request.block_hash();
        let result = self
            .engine
            .request(|engine| engine.api.new_payload(new_payload_request))
            .await;

        process_payload_status(block_hash, result)
    }

    async fn is_synced(&self) -> bool {
        self.engine.is_synced().await
    }

    async fn is_offline(&self) -> bool {
        self.engine.is_offline().await
    }

    async fn upcheck(&self) -> Result<(), EngineError> {
        self.engine.upcheck().await;
        Ok(())
    }

    async fn notify_forkchoice_updated(
        &self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, EngineError> {
        self.engine
            .request(|engine| async move {
                engine
                    .notify_forkchoice_updated(forkchoice_state, payload_attributes)
                    .await
            })
            .await
    }

    async fn get_payload(
        &self,
        fork_name: ForkName,
        payload_id: PayloadId,
    ) -> Result<crate::engine_api::GetPayloadResponse<E>, EngineError> {
        self.engine
            .request(|engine| async move {
                engine.api.get_payload(fork_name, payload_id).await
            })
            .await
    }

    async fn get_engine_capabilities(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<EngineCapabilities, EngineError> {
        self.engine
            .request(|engine| engine.get_engine_capabilities(age_limit))
            .await
    }

    async fn get_engine_version(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<Vec<ClientVersionV1>, EngineError> {
        self.engine
            .request(|engine| engine.get_engine_version(age_limit))
            .await
    }

    async fn get_payload_bodies_by_hash(
        &self,
        hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, EngineError> {
        self.engine
            .request(|engine| async move { engine.api.get_payload_bodies_by_hash_v1(hashes).await })
            .await
    }

    async fn get_payload_bodies_by_range(
        &self,
        start: u64,
        count: u64,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, EngineError> {
        self.engine
            .request(|engine| async move {
                engine
                    .api
                    .get_payload_bodies_by_range_v1(start, count)
                    .await
            })
            .await
    }

    async fn get_blobs_v1(
        &self,
        query: Vec<Hash256>,
    ) -> Result<Vec<Option<BlobAndProofV1<E>>>, EngineError> {
        self.engine
            .request(|engine| async move { engine.api.get_blobs_v1(query).await })
            .await
    }

    async fn get_blobs_v2(
        &self,
        query: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV2<E>>>, EngineError> {
        self.engine
            .request(|engine| async move { engine.api.get_blobs_v2(query).await })
            .await
    }

    async fn get_block_by_number(
        &self,
        query: BlockByNumberQuery<'_>,
    ) -> Result<Option<ExecutionBlock>, EngineError> {
        self.engine
            .request(|engine| async move { engine.api.get_block_by_number(query).await })
            .await
    }

    async fn get_block_by_hash(
        &self,
        block_hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionBlock>, EngineError> {
        self.engine
            .request(|engine| async move { engine.api.get_block_by_hash(block_hash).await })
            .await
    }

    async fn get_payload_id(
        &self,
        head_block_hash: &ExecutionBlockHash,
        payload_attributes: &PayloadAttributes,
    ) -> Option<PayloadId> {
        self.engine
            .get_payload_id(head_block_hash, payload_attributes)
            .await
    }
}
