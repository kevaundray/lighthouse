//! Mock execution engine implementation for testing.
//!
//! This module provides a lightweight mock implementation of the ExecutionEngine trait,
//! designed for fast unit testing without HTTP overhead.

use crate::engine_api::{
    BlockByNumberQuery, EngineCapabilities, ForkchoiceUpdatedResponse,
    NewPayloadRequest, PayloadAttributes, PayloadId,
};
use crate::engines::EngineError;
use crate::execution_engine::ExecutionEngine;
use crate::json_structures::{BlobAndProofV1, BlobAndProofV2};
use crate::payload_status::PayloadStatus;
use crate::{ClientVersionV1, ExecutionBlock, ExecutionPayloadBodyV1};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use types::{EthSpec, ExecutionBlockHash, ForkName, Hash256};
use crate::ForkchoiceState;

/// Configuration for mock execution engine behavior.
#[derive(Debug, Clone)]
pub struct MockEngineConfig {
    /// Whether the engine should report as synced.
    pub is_synced: bool,
    /// Whether the engine should report as offline.
    pub is_offline: bool,
    /// Default payload status to return for new payloads.
    pub default_payload_status: PayloadStatus,
    /// Engine capabilities to report.
    pub capabilities: EngineCapabilities,
}

impl Default for MockEngineConfig {
    fn default() -> Self {
        Self {
            is_synced: true,
            is_offline: false,
            default_payload_status: PayloadStatus::Valid,
            capabilities: EngineCapabilities {
                new_payload_v1: true,
                new_payload_v2: true,
                new_payload_v3: true,
                new_payload_v4: true,
                new_payload_v5: true,
                forkchoice_updated_v1: true,
                forkchoice_updated_v2: true,
                forkchoice_updated_v3: true,
                get_payload_bodies_by_hash_v1: true,
                get_payload_bodies_by_range_v1: true,
                get_payload_v1: true,
                get_payload_v2: true,
                get_payload_v3: true,
                get_payload_v4: true,
                get_payload_v5: true,
                get_client_version_v1: true,
                get_blobs_v1: true,
                get_blobs_v2: true,
            },
        }
    }
}

/// Mock execution engine for testing.
///
/// This engine provides configurable responses for all execution engine operations,
/// allowing for fast unit testing without the overhead of HTTP requests or real
/// execution client interaction.
pub struct MockExecutionEngine {
    config: MockEngineConfig,
    /// Stored payload statuses for specific block hashes.
    payload_statuses: Arc<Mutex<HashMap<ExecutionBlockHash, PayloadStatus>>>,
    /// Call count tracking for verification in tests.
    call_counts: Arc<Mutex<HashMap<String, usize>>>,
}

impl MockExecutionEngine {
    /// Create a new mock execution engine with default configuration.
    pub fn new() -> Self {
        Self::with_config(MockEngineConfig::default())
    }

    /// Create a new mock execution engine with custom configuration.
    pub fn with_config(config: MockEngineConfig) -> Self {
        Self {
            config,
            payload_statuses: Arc::new(Mutex::new(HashMap::new())),
            call_counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set the payload status for a specific block hash.
    pub fn set_payload_status(&self, block_hash: ExecutionBlockHash, status: PayloadStatus) {
        self.payload_statuses.lock().unwrap().insert(block_hash, status);
    }

    /// Set all payloads to return valid status.
    pub fn all_payloads_valid(&self) {
        let mut config = self.config.clone();
        config.default_payload_status = PayloadStatus::Valid;
    }

    /// Set all payloads to return syncing status.
    pub fn all_payloads_syncing(&self) {
        let mut config = self.config.clone();
        config.default_payload_status = PayloadStatus::Syncing;
    }

    /// Get the number of times a method was called.
    pub fn call_count(&self, method: &str) -> usize {
        self.call_counts
            .lock()
            .unwrap()
            .get(method)
            .copied()
            .unwrap_or(0)
    }

    /// Reset all call counts.
    pub fn reset_call_counts(&self) {
        self.call_counts.lock().unwrap().clear();
    }

    /// Increment call count for a method.
    fn increment_call_count(&self, method: &str) {
        let mut counts = self.call_counts.lock().unwrap();
        *counts.entry(method.to_string()).or_insert(0) += 1;
    }
}

impl Default for MockExecutionEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<E: EthSpec> ExecutionEngine<E> for MockExecutionEngine {
    async fn notify_new_payload(
        &self,
        new_payload_request: NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatus, EngineError> {
        self.increment_call_count("notify_new_payload");

        let block_hash = new_payload_request.block_hash();
        
        // Check for specific payload status override
        if let Some(status) = self.payload_statuses.lock().unwrap().get(&block_hash) {
            return Ok(status.clone());
        }

        // Return default status
        Ok(self.config.default_payload_status.clone())
    }

    async fn is_synced(&self) -> bool {
        self.increment_call_count("is_synced");
        self.config.is_synced
    }

    async fn is_offline(&self) -> bool {
        self.increment_call_count("is_offline");
        self.config.is_offline
    }

    async fn upcheck(&self) -> Result<(), EngineError> {
        self.increment_call_count("upcheck");
        if self.config.is_offline {
            Err(EngineError::Offline)
        } else {
            Ok(())
        }
    }

    async fn notify_forkchoice_updated(
        &self,
        _forkchoice_state: ForkchoiceState,
        _payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, EngineError> {
        self.increment_call_count("notify_forkchoice_updated");
        
        // Return a basic successful response
        Ok(ForkchoiceUpdatedResponse {
            payload_status: crate::engine_api::PayloadStatusV1 {
                status: crate::engine_api::PayloadStatusV1Status::Valid,
                latest_valid_hash: None,
                validation_error: None,
            },
            payload_id: None,
        })
    }

    async fn get_payload(
        &self,
        _fork_name: ForkName,
        _payload_id: PayloadId,
    ) -> Result<crate::engine_api::GetPayloadResponse<E>, EngineError> {
        self.increment_call_count("get_payload");
        
        // For mocking, we don't actually generate payloads
        Err(EngineError::Api {
            error: crate::engine_api::Error::BadResponse("Mock engine cannot generate payloads".to_string()),
        })
    }

    async fn get_engine_capabilities(
        &self,
        _age_limit: Option<Duration>,
    ) -> Result<EngineCapabilities, EngineError> {
        self.increment_call_count("get_engine_capabilities");
        Ok(self.config.capabilities.clone())
    }

    async fn get_engine_version(
        &self,
        _age_limit: Option<Duration>,
    ) -> Result<Vec<ClientVersionV1>, EngineError> {
        self.increment_call_count("get_engine_version");
        
        // Return a mock client version
        Ok(vec![ClientVersionV1 {
            code: crate::engine_api::ClientCode::Unknown("MOCK".to_string()),
            name: "MockEngine".to_string(),
            version: "1.0.0".to_string(),
            commit: crate::engine_api::CommitPrefix("test".to_string()),
        }])
    }

    async fn get_payload_bodies_by_hash(
        &self,
        _hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, EngineError> {
        self.increment_call_count("get_payload_bodies_by_hash");
        
        // Return empty for mocking
        Ok(vec![])
    }

    async fn get_payload_bodies_by_range(
        &self,
        _start: u64,
        _count: u64,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, EngineError> {
        self.increment_call_count("get_payload_bodies_by_range");
        
        // Return empty for mocking
        Ok(vec![])
    }

    async fn get_blobs_v1(
        &self,
        _query: Vec<Hash256>,
    ) -> Result<Vec<Option<BlobAndProofV1<E>>>, EngineError> {
        self.increment_call_count("get_blobs_v1");
        
        // Return empty for mocking
        Ok(vec![])
    }

    async fn get_blobs_v2(
        &self,
        _query: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV2<E>>>, EngineError> {
        self.increment_call_count("get_blobs_v2");
        
        // Return empty for mocking
        Ok(None)
    }

    async fn get_block_by_number(
        &self,
        _query: BlockByNumberQuery<'_>,
    ) -> Result<Option<ExecutionBlock>, EngineError> {
        self.increment_call_count("get_block_by_number");
        
        // Return None for mocking
        Ok(None)
    }

    async fn get_block_by_hash(
        &self,
        _block_hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionBlock>, EngineError> {
        self.increment_call_count("get_block_by_hash");
        
        // Return None for mocking
        Ok(None)
    }

    async fn get_payload_id(
        &self,
        _head_block_hash: &ExecutionBlockHash,
        _payload_attributes: &PayloadAttributes,
    ) -> Option<PayloadId> {
        self.increment_call_count("get_payload_id");
        
        // Return None for mocking
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::MainnetEthSpec;

    #[tokio::test]
    async fn test_mock_engine_basic() {
        let engine = MockExecutionEngine::new();
        
        // Test sync status
        assert!(<MockExecutionEngine as ExecutionEngine<MainnetEthSpec>>::is_synced(&engine).await);
        assert!(!<MockExecutionEngine as ExecutionEngine<MainnetEthSpec>>::is_offline(&engine).await);
        
        // Test call counting
        assert_eq!(engine.call_count("is_synced"), 1);
        assert_eq!(engine.call_count("is_offline"), 1);
    }

    #[tokio::test]
    async fn test_mock_engine_configuration() {
        let config = MockEngineConfig {
            is_synced: false,
            is_offline: true,
            default_payload_status: PayloadStatus::Syncing,
            ..Default::default()
        };
        
        let engine = MockExecutionEngine::with_config(config);
        
        assert!(!<MockExecutionEngine as ExecutionEngine<MainnetEthSpec>>::is_synced(&engine).await);
        assert!(<MockExecutionEngine as ExecutionEngine<MainnetEthSpec>>::is_offline(&engine).await);
        
        // Test upcheck with offline engine
        assert!(matches!(<MockExecutionEngine as ExecutionEngine<MainnetEthSpec>>::upcheck(&engine).await, Err(EngineError::Offline)));
    }
}