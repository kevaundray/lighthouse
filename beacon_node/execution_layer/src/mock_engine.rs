//! Mock execution engine implementation for testing.
//!
//! This module provides a lightweight mock implementation of the ExecutionEngine trait,
//! designed for fast unit testing without HTTP overhead.

use crate::engine_api::{
    BlockByNumberQuery, EngineCapabilities, ForkchoiceUpdatedResponse, NewPayloadRequest,
    PayloadAttributes, PayloadId,
};
use crate::engines::EngineError;
use crate::execution_engine::ExecutionEngine;
use crate::json_structures::{BlobAndProofV1, BlobAndProofV2};
use crate::payload_status::PayloadStatus;
use crate::ForkchoiceState;
use crate::{ClientVersionV1, ExecutionBlock, ExecutionPayloadBodyV1};
use async_trait::async_trait;
use eth2::types::BlobsBundle;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use types::{
    ChainSpec, EthSpec, ExecutionBlockHash, ExecutionPayload, ExecutionPayloadBellatrix,
    ExecutionPayloadCapella, ExecutionPayloadDeneb, ExecutionPayloadElectra, ExecutionPayloadFulu,
    ForkName, Hash256, Transactions, Uint256,
};

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
    /// Chain specification for fork detection.
    pub chain_spec: Option<Arc<ChainSpec>>,
    /// Terminal total difficulty for PoW transition.
    pub terminal_total_difficulty: Uint256,
    /// Terminal block number.
    pub terminal_block_number: u64,
    /// Shanghai fork time.
    pub shanghai_time: Option<u64>,
    /// Cancun fork time.
    pub cancun_time: Option<u64>,
    /// Prague fork time.
    pub prague_time: Option<u64>,
    /// Osaka fork time.
    pub osaka_time: Option<u64>,
}

impl Default for MockEngineConfig {
    fn default() -> Self {
        use crate::test_utils::{DEFAULT_TERMINAL_BLOCK, DEFAULT_TERMINAL_DIFFICULTY};

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
            chain_spec: None,
            terminal_total_difficulty: Uint256::from(DEFAULT_TERMINAL_DIFFICULTY),
            terminal_block_number: DEFAULT_TERMINAL_BLOCK,
            shanghai_time: None,
            cancun_time: None,
            prague_time: None,
            osaka_time: None,
        }
    }
}

/// Mock execution engine for testing.
///
/// This engine provides configurable responses for all execution engine operations,
/// allowing for fast unit testing without the overhead of HTTP requests or real
/// execution client interaction.
///
/// **Why we can't easily generate blocks like MockServer:**
/// The original MockServer used ExecutionBlockGenerator to create realistic blocks,
/// but adding this to MockExecutionEngine faces several challenges:
/// 1. ExecutionEngine trait doesn't have EthSpec generic parameter
/// 2. Block generation requires complex state management (chain state, block numbers, etc.)
/// 3. Adding generics would break the trait object usage in ExecutionLayer
///
/// **Potential solutions:**
/// - Make MockExecutionEngine generic and handle trait object complexity
/// - Add block generation methods outside the trait
/// - Create a specialized MockExecutionEngineWithBlocks variant
///
/// For now, this provides a simpler mock focused on response configuration.
pub struct MockExecutionEngine {
    config: Arc<Mutex<MockEngineConfig>>,
    /// Stored payload statuses for specific block hashes.
    payload_statuses: Arc<Mutex<HashMap<ExecutionBlockHash, PayloadStatus>>>,
    /// Stored forkchoice updated responses for specific block hashes.
    forkchoice_responses: Arc<Mutex<HashMap<ExecutionBlockHash, ForkchoiceUpdatedResponse>>>,
    /// Stored execution blocks for block hash queries.
    execution_blocks: Arc<Mutex<HashMap<ExecutionBlockHash, ExecutionBlock>>>,
    /// Stored execution payloads for payload ID queries.
    stored_payloads: Arc<Mutex<HashMap<PayloadId, Box<dyn std::any::Any + Send + Sync>>>>,
    /// Stored blobs bundles for Deneb+ forks.
    blobs_bundles: Arc<Mutex<HashMap<PayloadId, Box<dyn std::any::Any + Send + Sync>>>>,
    /// Next payload ID to assign.
    next_payload_id: Arc<Mutex<u64>>,
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
            config: Arc::new(Mutex::new(config)),
            payload_statuses: Arc::new(Mutex::new(HashMap::new())),
            forkchoice_responses: Arc::new(Mutex::new(HashMap::new())),
            execution_blocks: Arc::new(Mutex::new(HashMap::new())),
            stored_payloads: Arc::new(Mutex::new(HashMap::new())),
            blobs_bundles: Arc::new(Mutex::new(HashMap::new())),
            next_payload_id: Arc::new(Mutex::new(1)),
            call_counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set the payload status for a specific block hash.
    pub fn set_payload_status(&self, block_hash: ExecutionBlockHash, status: PayloadStatus) {
        self.payload_statuses
            .lock()
            .unwrap()
            .insert(block_hash, status);
    }

    /// Set all payloads to return valid status.
    pub fn all_payloads_valid(&self) {
        let mut config = self.config.lock().unwrap();
        config.default_payload_status = PayloadStatus::Valid;
    }

    /// Set all payloads to return syncing status.
    pub fn all_payloads_syncing(&self) {
        let mut config = self.config.lock().unwrap();
        config.default_payload_status = PayloadStatus::Syncing;
    }

    /// Set all payloads to return invalid status.
    pub fn all_payloads_invalid(&self, latest_valid_hash: ExecutionBlockHash) {
        let mut config = self.config.lock().unwrap();
        config.default_payload_status = PayloadStatus::Invalid {
            latest_valid_hash: Some(latest_valid_hash),
            validation_error: Some("Mock invalid".to_string()),
        };
    }

    /// Set specific forkchoice response.
    pub fn set_forkchoice_updated_response(
        &self,
        head_hash: ExecutionBlockHash,
        response: ForkchoiceUpdatedResponse,
    ) {
        self.forkchoice_responses
            .lock()
            .unwrap()
            .insert(head_hash, response);
    }

    /// Set a specific execution block for hash queries.
    pub fn set_execution_block(&self, block_hash: ExecutionBlockHash, block: ExecutionBlock) {
        self.execution_blocks
            .lock()
            .unwrap()
            .insert(block_hash, block);
    }

    /// Configure chain specification for fork detection.
    pub fn set_chain_spec(&self, chain_spec: Arc<ChainSpec>) {
        self.config.lock().unwrap().chain_spec = Some(chain_spec);
    }

    /// Configure fork times for payload generation.
    pub fn set_fork_times(
        &self,
        shanghai_time: Option<u64>,
        cancun_time: Option<u64>,
        prague_time: Option<u64>,
        osaka_time: Option<u64>,
    ) {
        let mut config = self.config.lock().unwrap();
        config.shanghai_time = shanghai_time;
        config.cancun_time = cancun_time;
        config.prague_time = prague_time;
        config.osaka_time = osaka_time;
    }

    /// Configure terminal block settings.
    pub fn set_terminal_block_settings(&self, total_difficulty: Uint256, block_number: u64) {
        let mut config = self.config.lock().unwrap();
        config.terminal_total_difficulty = total_difficulty;
        config.terminal_block_number = block_number;
    }

    /// Enable full payload verification (like MockServer).
    pub fn full_payload_verification(&self) {
        let mut config = self.config.lock().unwrap();
        config.default_payload_status = PayloadStatus::Valid;
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

    /// Get the fork at a given timestamp.
    fn get_fork_at_timestamp(&self, timestamp: u64) -> ForkName {
        let config = self.config.lock().unwrap();

        if let Some(osaka_time) = config.osaka_time {
            if timestamp >= osaka_time {
                return ForkName::Fulu;
            }
        }

        if let Some(prague_time) = config.prague_time {
            if timestamp >= prague_time {
                return ForkName::Electra;
            }
        }

        if let Some(cancun_time) = config.cancun_time {
            if timestamp >= cancun_time {
                return ForkName::Deneb;
            }
        }

        if let Some(shanghai_time) = config.shanghai_time {
            if timestamp >= shanghai_time {
                return ForkName::Capella;
            }
        }

        ForkName::Bellatrix
    }

    /// Generate a payload ID from a u64.
    fn payload_id_from_u64(&self, id: u64) -> PayloadId {
        PayloadId::from([id as u8; 8])
    }

    /// Build a new execution payload for the given attributes.
    fn build_execution_payload<E: EthSpec>(
        &self,
        parent_hash: ExecutionBlockHash,
        parent_block_number: u64,
        payload_attributes: &PayloadAttributes,
    ) -> Result<ExecutionPayload<E>, EngineError> {
        use crate::test_utils::{mock_el_extra_data, DEFAULT_GAS_LIMIT};

        let fork = self.get_fork_at_timestamp(payload_attributes.timestamp());
        let block_number = parent_block_number + 1;

        // Use mock extra data function
        let extra_data = mock_el_extra_data::<E>();

        let execution_payload = match fork {
            ForkName::Bellatrix => ExecutionPayload::Bellatrix(ExecutionPayloadBellatrix {
                parent_hash,
                fee_recipient: payload_attributes.suggested_fee_recipient(),
                receipts_root: Hash256::repeat_byte(42),
                state_root: Hash256::repeat_byte(43),
                logs_bloom: vec![0; 256].into(),
                prev_randao: payload_attributes.prev_randao(),
                block_number,
                gas_limit: DEFAULT_GAS_LIMIT,
                gas_used: DEFAULT_GAS_LIMIT - 1,
                timestamp: payload_attributes.timestamp(),
                extra_data,
                base_fee_per_gas: Uint256::from(1u64),
                block_hash: ExecutionBlockHash::zero(),
                transactions: Transactions::<E>::default(),
            }),
            ForkName::Capella => ExecutionPayload::Capella(ExecutionPayloadCapella {
                parent_hash,
                fee_recipient: payload_attributes.suggested_fee_recipient(),
                receipts_root: Hash256::repeat_byte(42),
                state_root: Hash256::repeat_byte(43),
                logs_bloom: vec![0; 256].into(),
                prev_randao: payload_attributes.prev_randao(),
                block_number,
                gas_limit: DEFAULT_GAS_LIMIT,
                gas_used: DEFAULT_GAS_LIMIT - 1,
                timestamp: payload_attributes.timestamp(),
                extra_data,
                base_fee_per_gas: Uint256::from(1u64),
                block_hash: ExecutionBlockHash::zero(),
                transactions: Transactions::<E>::default(),
                withdrawals: Default::default(),
            }),
            ForkName::Deneb => ExecutionPayload::Deneb(ExecutionPayloadDeneb {
                parent_hash,
                fee_recipient: payload_attributes.suggested_fee_recipient(),
                receipts_root: Hash256::repeat_byte(42),
                state_root: Hash256::repeat_byte(43),
                logs_bloom: vec![0; 256].into(),
                prev_randao: payload_attributes.prev_randao(),
                block_number,
                gas_limit: DEFAULT_GAS_LIMIT,
                gas_used: DEFAULT_GAS_LIMIT - 1,
                timestamp: payload_attributes.timestamp(),
                extra_data,
                base_fee_per_gas: Uint256::from(1u64),
                block_hash: ExecutionBlockHash::zero(),
                transactions: Transactions::<E>::default(),
                withdrawals: Default::default(),
                blob_gas_used: 0,
                excess_blob_gas: 0,
            }),
            ForkName::Electra => ExecutionPayload::Electra(ExecutionPayloadElectra {
                parent_hash,
                fee_recipient: payload_attributes.suggested_fee_recipient(),
                receipts_root: Hash256::repeat_byte(42),
                state_root: Hash256::repeat_byte(43),
                logs_bloom: vec![0; 256].into(),
                prev_randao: payload_attributes.prev_randao(),
                block_number,
                gas_limit: DEFAULT_GAS_LIMIT,
                gas_used: DEFAULT_GAS_LIMIT - 1,
                timestamp: payload_attributes.timestamp(),
                extra_data,
                base_fee_per_gas: Uint256::from(1u64),
                block_hash: ExecutionBlockHash::zero(),
                transactions: Transactions::<E>::default(),
                withdrawals: Default::default(),
                blob_gas_used: 0,
                excess_blob_gas: 0,
            }),
            ForkName::Fulu => ExecutionPayload::Fulu(ExecutionPayloadFulu {
                parent_hash,
                fee_recipient: payload_attributes.suggested_fee_recipient(),
                receipts_root: Hash256::repeat_byte(42),
                state_root: Hash256::repeat_byte(43),
                logs_bloom: vec![0; 256].into(),
                prev_randao: payload_attributes.prev_randao(),
                block_number,
                gas_limit: DEFAULT_GAS_LIMIT,
                gas_used: DEFAULT_GAS_LIMIT - 1,
                timestamp: payload_attributes.timestamp(),
                extra_data,
                base_fee_per_gas: Uint256::from(1u64),
                block_hash: ExecutionBlockHash::zero(),
                transactions: Transactions::<E>::default(),
                withdrawals: Default::default(),
                blob_gas_used: 0,
                excess_blob_gas: 0,
            }),
            _ => {
                return Err(EngineError::Api {
                    error: crate::engine_api::Error::BadResponse(format!(
                        "Unsupported fork: {}",
                        fork
                    )),
                });
            }
        };

        Ok(execution_payload)
    }

    /// Generate a mock blobs bundle for Deneb+ forks.
    fn generate_blobs_bundle<E: EthSpec>(&self) -> BlobsBundle<E> {
        // Create an empty blobs bundle for now - in a real implementation this would
        // contain actual blob data based on transactions in the payload
        BlobsBundle::default()
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
        Ok(self.config.lock().unwrap().default_payload_status.clone())
    }

    async fn is_synced(&self) -> bool {
        self.increment_call_count("is_synced");
        self.config.lock().unwrap().is_synced
    }

    async fn is_offline(&self) -> bool {
        self.increment_call_count("is_offline");
        self.config.lock().unwrap().is_offline
    }

    async fn upcheck(&self) -> Result<(), EngineError> {
        self.increment_call_count("upcheck");
        if self.config.lock().unwrap().is_offline {
            Err(EngineError::Offline)
        } else {
            Ok(())
        }
    }

    async fn notify_forkchoice_updated(
        &self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, EngineError> {
        self.increment_call_count("notify_forkchoice_updated");

        // Check for specific forkchoice response override
        if let Some(response) = self
            .forkchoice_responses
            .lock()
            .unwrap()
            .get(&forkchoice_state.head_block_hash)
        {
            return Ok(response.clone());
        }

        // Generate payload if attributes are provided
        let payload_id = if let Some(attributes) = payload_attributes {
            // Get the parent block to determine block number
            let parent_block = self
                .execution_blocks
                .lock()
                .unwrap()
                .get(&forkchoice_state.head_block_hash)
                .cloned();

            if let Some(parent) = parent_block {
                // Generate a new payload ID
                let payload_id = {
                    let mut id_counter = self.next_payload_id.lock().unwrap();
                    let id = self.payload_id_from_u64(*id_counter);
                    *id_counter += 1;
                    id
                };

                // Build the execution payload based on the fork
                // Note: We need to store as Any because we can't make MockExecutionEngine generic
                match self.build_execution_payload::<types::MainnetEthSpec>(
                    forkchoice_state.head_block_hash,
                    parent.block_number,
                    &attributes,
                ) {
                    Ok(payload) => {
                        // Store the payload
                        self.stored_payloads
                            .lock()
                            .unwrap()
                            .insert(payload_id, Box::new(payload.clone()));

                        // Generate and store blobs bundle for Deneb+ forks
                        let fork = self.get_fork_at_timestamp(attributes.timestamp());
                        if matches!(fork, ForkName::Deneb | ForkName::Electra | ForkName::Fulu) {
                            let blobs_bundle =
                                self.generate_blobs_bundle::<types::MainnetEthSpec>();
                            self.blobs_bundles
                                .lock()
                                .unwrap()
                                .insert(payload_id, Box::new(blobs_bundle));
                        }

                        Some(payload_id)
                    }
                    Err(_) => {
                        // If payload generation fails, don't return a payload ID
                        None
                    }
                }
            } else {
                // Parent block not found, can't generate payload
                None
            }
        } else {
            None
        };

        // Return successful response with optional payload ID
        Ok(ForkchoiceUpdatedResponse {
            payload_status: crate::engine_api::PayloadStatusV1 {
                status: crate::engine_api::PayloadStatusV1Status::Valid,
                latest_valid_hash: Some(forkchoice_state.head_block_hash),
                validation_error: None,
            },
            payload_id,
        })
    }

    async fn get_payload(
        &self,
        fork_name: ForkName,
        payload_id: PayloadId,
    ) -> Result<crate::engine_api::GetPayloadResponse<E>, EngineError> {
        self.increment_call_count("get_payload");

        // Retrieve the stored payload
        let stored_payloads = self.stored_payloads.lock().unwrap();
        if let Some(payload_any) = stored_payloads.get(&payload_id) {
            // Try to downcast to the expected payload type
            if let Some(payload) = payload_any.downcast_ref::<ExecutionPayload<E>>() {
                use crate::test_utils::DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI;

                // Build the GetPayloadResponse based on the fork
                match fork_name {
                    ForkName::Bellatrix => {
                        if let ExecutionPayload::Bellatrix(bellatrix_payload) = payload {
                            Ok(crate::engine_api::GetPayloadResponse::Bellatrix(
                                crate::engine_api::GetPayloadResponseBellatrix {
                                    execution_payload: bellatrix_payload.clone(),
                                    block_value: Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI),
                                },
                            ))
                        } else {
                            Err(EngineError::Api {
                                error: crate::engine_api::Error::BadResponse(
                                    "Payload type mismatch for Bellatrix fork".to_string(),
                                ),
                            })
                        }
                    }
                    ForkName::Capella => {
                        if let ExecutionPayload::Capella(capella_payload) = payload {
                            Ok(crate::engine_api::GetPayloadResponse::Capella(
                                crate::engine_api::GetPayloadResponseCapella {
                                    execution_payload: capella_payload.clone(),
                                    block_value: Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI),
                                },
                            ))
                        } else {
                            Err(EngineError::Api {
                                error: crate::engine_api::Error::BadResponse(
                                    "Payload type mismatch for Capella fork".to_string(),
                                ),
                            })
                        }
                    }
                    ForkName::Deneb => {
                        if let ExecutionPayload::Deneb(deneb_payload) = payload {
                            // For Deneb, we need to include blobs bundle
                            let blobs_bundle = self
                                .blobs_bundles
                                .lock()
                                .unwrap()
                                .get(&payload_id)
                                .and_then(|b| b.downcast_ref::<BlobsBundle<E>>())
                                .cloned();

                            Ok(crate::engine_api::GetPayloadResponse::Deneb(
                                crate::engine_api::GetPayloadResponseDeneb {
                                    execution_payload: deneb_payload.clone(),
                                    block_value: Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI),
                                    blobs_bundle: blobs_bundle.unwrap_or_default(),
                                    should_override_builder: false,
                                },
                            ))
                        } else {
                            Err(EngineError::Api {
                                error: crate::engine_api::Error::BadResponse(
                                    "Payload type mismatch for Deneb fork".to_string(),
                                ),
                            })
                        }
                    }
                    ForkName::Electra => {
                        if let ExecutionPayload::Electra(electra_payload) = payload {
                            // For Electra, we need to include blobs bundle
                            let blobs_bundle = self
                                .blobs_bundles
                                .lock()
                                .unwrap()
                                .get(&payload_id)
                                .and_then(|b| b.downcast_ref::<BlobsBundle<E>>())
                                .cloned();

                            Ok(crate::engine_api::GetPayloadResponse::Electra(
                                crate::engine_api::GetPayloadResponseElectra {
                                    execution_payload: electra_payload.clone(),
                                    block_value: Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI),
                                    blobs_bundle: blobs_bundle.unwrap_or_default(),
                                    should_override_builder: false,
                                    requests: Default::default(),
                                },
                            ))
                        } else {
                            Err(EngineError::Api {
                                error: crate::engine_api::Error::BadResponse(
                                    "Payload type mismatch for Electra fork".to_string(),
                                ),
                            })
                        }
                    }
                    ForkName::Fulu => {
                        if let ExecutionPayload::Fulu(fulu_payload) = payload {
                            // For Fulu, similar to Electra
                            let blobs_bundle = self
                                .blobs_bundles
                                .lock()
                                .unwrap()
                                .get(&payload_id)
                                .and_then(|b| b.downcast_ref::<BlobsBundle<E>>())
                                .cloned();

                            Ok(crate::engine_api::GetPayloadResponse::Fulu(
                                crate::engine_api::GetPayloadResponseFulu {
                                    execution_payload: fulu_payload.clone(),
                                    block_value: Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI),
                                    blobs_bundle: blobs_bundle.unwrap_or_default(),
                                    should_override_builder: false,
                                    requests: Default::default(),
                                },
                            ))
                        } else {
                            Err(EngineError::Api {
                                error: crate::engine_api::Error::BadResponse(
                                    "Payload type mismatch for Fulu fork".to_string(),
                                ),
                            })
                        }
                    }
                    _ => Err(EngineError::Api {
                        error: crate::engine_api::Error::BadResponse(format!(
                            "Unsupported fork for get_payload: {}",
                            fork_name
                        )),
                    }),
                }
            } else {
                Err(EngineError::Api {
                    error: crate::engine_api::Error::BadResponse(
                        "Failed to downcast stored payload".to_string(),
                    ),
                })
            }
        } else {
            Err(EngineError::Api {
                error: crate::engine_api::Error::BadResponse(format!(
                    "Payload not found for ID: {:?}",
                    payload_id
                )),
            })
        }
    }

    async fn get_engine_capabilities(
        &self,
        _age_limit: Option<Duration>,
    ) -> Result<EngineCapabilities, EngineError> {
        self.increment_call_count("get_engine_capabilities");
        Ok(self.config.lock().unwrap().capabilities.clone())
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
        query: BlockByNumberQuery<'_>,
    ) -> Result<Option<ExecutionBlock>, EngineError> {
        self.increment_call_count("get_block_by_number");

        // For tag queries (like "latest"), return the latest block from our stored blocks
        match query {
            BlockByNumberQuery::Tag(_tag) => {
                // Return the latest block (highest block number) from stored blocks
                let blocks = self.execution_blocks.lock().unwrap();
                let latest_block = blocks
                    .values()
                    .max_by_key(|block| block.block_number)
                    .cloned();
                Ok(latest_block)
            }
        }
    }

    async fn get_block_by_hash(
        &self,
        block_hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionBlock>, EngineError> {
        self.increment_call_count("get_block_by_hash");

        // Check if we have a stored block for this hash
        let block = self
            .execution_blocks
            .lock()
            .unwrap()
            .get(&block_hash)
            .cloned();
        Ok(block)
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
    use crate::engine_api::PayloadAttributes;
    use crate::engines::ForkchoiceState;
    use types::{FixedBytesExtended, MainnetEthSpec};

    #[tokio::test]
    async fn test_mock_engine_basic() {
        let engine = MockExecutionEngine::new();

        // Test sync status
        assert!(<MockExecutionEngine as ExecutionEngine<MainnetEthSpec>>::is_synced(&engine).await);
        assert!(
            !<MockExecutionEngine as ExecutionEngine<MainnetEthSpec>>::is_offline(&engine).await
        );

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

        assert!(
            !<MockExecutionEngine as ExecutionEngine<MainnetEthSpec>>::is_synced(&engine).await
        );
        assert!(
            <MockExecutionEngine as ExecutionEngine<MainnetEthSpec>>::is_offline(&engine).await
        );

        // Test upcheck with offline engine
        assert!(matches!(
            <MockExecutionEngine as ExecutionEngine<MainnetEthSpec>>::upcheck(&engine).await,
            Err(EngineError::Offline)
        ));
    }

    #[tokio::test]
    async fn test_mock_engine_payload_generation() {
        let engine = MockExecutionEngine::new();

        // Set up a parent block for payload generation
        let parent_hash = ExecutionBlockHash::from_root(Hash256::from_low_u64_be(42));
        let parent_block = crate::ExecutionBlock {
            block_hash: parent_hash,
            block_number: 100,
            parent_hash: ExecutionBlockHash::from_root(Hash256::from_low_u64_be(41)),
            total_difficulty: Some(Uint256::from(1000000u64)),
            timestamp: 1234567890,
        };
        engine.set_execution_block(parent_hash, parent_block);

        // Set up forkchoice state and payload attributes
        let forkchoice_state = ForkchoiceState {
            head_block_hash: parent_hash,
            safe_block_hash: parent_hash,
            finalized_block_hash: parent_hash,
        };

        let payload_attributes = PayloadAttributes::new(
            1234567900,                     // timestamp
            Hash256::from_low_u64_be(999),  // prev_randao
            crate::Address::repeat_byte(1), // fee_recipient
            None,                           // withdrawals
            None,                           // parent_beacon_block_root
        );

        // Test forkchoice_updated with payload generation
        let response =
            <MockExecutionEngine as ExecutionEngine<MainnetEthSpec>>::notify_forkchoice_updated(
                &engine,
                forkchoice_state,
                Some(payload_attributes),
            )
            .await
            .unwrap();

        // Should return a payload ID
        assert!(response.payload_id.is_some());
        let payload_id = response.payload_id.unwrap();

        // Test get_payload
        let payload_response =
            <MockExecutionEngine as ExecutionEngine<MainnetEthSpec>>::get_payload(
                &engine,
                types::ForkName::Bellatrix,
                payload_id,
            )
            .await
            .unwrap();

        // Verify the payload was generated correctly
        if let crate::engine_api::GetPayloadResponse::Bellatrix(bellatrix_response) =
            payload_response
        {
            assert_eq!(
                bellatrix_response.execution_payload.parent_hash,
                parent_hash
            );
            assert_eq!(bellatrix_response.execution_payload.block_number, 101);
            assert_eq!(bellatrix_response.execution_payload.timestamp, 1234567900);
        } else {
            panic!("Expected Bellatrix payload response");
        }

        // Test call counting
        assert_eq!(engine.call_count("notify_forkchoice_updated"), 1);
        assert_eq!(engine.call_count("get_payload"), 1);
    }
}
