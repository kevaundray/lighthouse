//! Standard execution engine implementation.
//!
//! This module provides the standard implementation of the ExecutionEngine trait,
//! which communicates with real execution clients via JSON-RPC.

use crate::engine_api::NewPayloadRequest;
use crate::engines::{Engine, EngineError};
use crate::execution_engine::ExecutionEngine;
use crate::payload_status::{process_payload_status, PayloadStatus};
use async_trait::async_trait;
use std::sync::Arc;
use types::EthSpec;

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
}
