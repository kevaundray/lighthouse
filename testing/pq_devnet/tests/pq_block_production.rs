#[cfg(target_feature = "avx2")]
use beacon_chain::{
    PQ_BLOCK_PRODUCTION_ADMISSION_CAPACITY, PqBlockProductionError, PqBlockProductionLocalError,
    PqImportError, PqNewPayloadTransport, PqPayloadBuildRequest, PqProposerDutiesError,
    TestingPqBlockingHook, TestingPqPayloadBuildObservation, TestingPqPayloadExpectation,
    builder::{BeaconChainBuilder, Witness},
    testing_only_running_pq_operational_event_sink, testing_only_validate_pq_full_payload,
    testing_only_validate_pq_production_advance,
};
#[cfg(target_feature = "avx2")]
use consensus_signature::{
    AggregationService, OneTimeUseId, PqPublicKey, PqRawSignature, SigningDuty,
    ValidatorPublicKeyBytes, serialize_individual_signature,
};
#[cfg(target_feature = "avx2")]
use eth2::{BeaconNodeHttpClient, SensitiveUrl, StrictBeaconNodeHttpClient, Timeouts};
#[cfg(target_feature = "avx2")]
use futures::StreamExt;
#[cfg(target_feature = "avx2")]
use initialized_validators::InitializedValidators;
#[cfg(target_feature = "avx2")]
use lighthouse_network::{Context, NetworkConfig, NetworkGlobals, identity::secp256k1};
#[cfg(target_feature = "avx2")]
use lighthouse_validator_store::{Config as ValidatorStoreConfig, LighthouseValidatorStore};
#[cfg(target_feature = "avx2")]
use network::{
    PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY, PqBlockPublicationDisposition,
    PqBlockPublicationService, PqGossipBlockDisposition, PqPublicationBodyLimits,
    PqPublicationCapacity, pq_block_broadcast_channel,
};
#[cfg(target_feature = "avx2")]
use network::{PqNetworkBlockProcessor, PqNetworkService};
#[cfg(target_feature = "avx2")]
use network_utils::enr_ext::EnrExt;
#[cfg(target_feature = "avx2")]
use pq_http_api::{PqHttpApi, TestingPqHttpBlockingHook};
#[cfg(target_feature = "avx2")]
use pq_proposer_service::{PqProposalCompletion, PqProposerService};
#[cfg(target_feature = "avx2")]
use pq_signing::{PqKeyUnlock, PqKeystore, PqSigningAuthority, provision_usage_journal};
#[cfg(target_feature = "avx2")]
use sha2::{Digest, Sha256};
#[cfg(target_feature = "avx2")]
use slashing_protection::SlashingDatabase;
#[cfg(target_feature = "avx2")]
use slot_clock::SlotClock;
#[cfg(target_feature = "avx2")]
use ssz::{Decode, Encode};
#[cfg(target_feature = "avx2")]
use std::collections::VecDeque;
#[cfg(target_feature = "avx2")]
use std::fs;
#[cfg(all(target_feature = "avx2", unix))]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_feature = "avx2")]
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
#[cfg(target_feature = "avx2")]
use std::time::Duration;
#[cfg(target_feature = "avx2")]
use store::{HotColdDB, MemoryStore, StoreConfig};
#[cfg(target_feature = "avx2")]
use types::{
    Address, AttestationData, BeaconBlock, BeaconState, Blob, Checkpoint, ConsolidationRequest,
    DepositRequest, Domain, Epoch, EthSpec, ExecPayload, ExecutionBlockHash, ExecutionPayload,
    ExecutionPayloadRef, ExecutionRequests, ForkContext, ForkName, FullPayload, Graffiti, Hash256,
    KzgCommitment, KzgProof, MinimalEthSpec, ProposerPreparationData, SignedBeaconBlock,
    SignedRoot, SingleAttestation, Slot, Uint256, Withdrawal, WithdrawalRequest,
};

#[cfg(target_feature = "avx2")]
type TestWitness = Witness<slot_clock::TestingSlotClock, MinimalEthSpec, MemoryStore, MemoryStore>;

#[cfg(target_feature = "avx2")]
static REAL_AGGREGATION_SERVICE_TEST_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

#[cfg(target_feature = "avx2")]
fn pure_payload_expectation() -> TestingPqPayloadExpectation<MinimalEthSpec> {
    TestingPqPayloadExpectation::new(
        Hash256::repeat_byte(0x11),
        ExecutionBlockHash::repeat_byte(0x22),
        33,
        Hash256::repeat_byte(0x44),
        Vec::new(),
    )
}

#[cfg(target_feature = "avx2")]
struct PurePayloadFields {
    parent_hash: ExecutionBlockHash,
    timestamp: u64,
    prev_randao: Hash256,
    withdrawals: Vec<Withdrawal>,
    blob_gas_used: u64,
    excess_blob_gas: u64,
}

#[cfg(target_feature = "avx2")]
impl Default for PurePayloadFields {
    fn default() -> Self {
        Self {
            parent_hash: ExecutionBlockHash::repeat_byte(0x22),
            timestamp: 33,
            prev_randao: Hash256::repeat_byte(0x44),
            withdrawals: Vec::new(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }
}

#[cfg(target_feature = "avx2")]
fn pure_payload_contents(
    fields: PurePayloadFields,
    requests: ExecutionRequests<MinimalEthSpec>,
) -> execution_layer::BlockProposalContents<MinimalEthSpec, FullPayload<MinimalEthSpec>> {
    let mut payload = types::ExecutionPayloadElectra::<MinimalEthSpec>::default();
    payload.parent_hash = fields.parent_hash;
    payload.timestamp = fields.timestamp;
    payload.prev_randao = fields.prev_randao;
    payload.withdrawals = fields
        .withdrawals
        .try_into()
        .expect("pure payload withdrawal capacity");
    payload.blob_gas_used = fields.blob_gas_used;
    payload.excess_blob_gas = fields.excess_blob_gas;
    payload.block_hash = execution_layer::calculate_execution_block_hash(
        ExecutionPayloadRef::Electra(&payload),
        Some(Hash256::repeat_byte(0x11)),
        Some(&requests),
    )
    .0;
    execution_layer::BlockProposalContents::PayloadAndBlobs {
        payload: FullPayload::from(ExecutionPayload::Electra(payload)),
        block_value: Uint256::from(55),
        kzg_commitments: Default::default(),
        blobs_and_proofs: Some((Default::default(), Default::default())),
        requests: Some(requests),
    }
}

#[cfg(target_feature = "avx2")]
#[test]
fn full_payload_response_rejects_wrong_fork_before_transition() {
    let contents = execution_layer::BlockProposalContents::PayloadAndBlobs {
        payload: FullPayload::from(ExecutionPayload::<MinimalEthSpec>::Fulu(Default::default())),
        block_value: Uint256::ZERO,
        kzg_commitments: Default::default(),
        blobs_and_proofs: Some((Default::default(), Default::default())),
        requests: Some(Default::default()),
    };

    assert!(
        testing_only_validate_pq_full_payload(contents, &pure_payload_expectation()).is_err(),
        "lean PQ V1 must reject a non-Electra getPayload response",
    );
}

#[cfg(target_feature = "avx2")]
#[test]
fn full_payload_response_rejects_rehashed_parent_mismatch() {
    let contents = pure_payload_contents(
        PurePayloadFields {
            parent_hash: ExecutionBlockHash::repeat_byte(0x23),
            ..Default::default()
        },
        Default::default(),
    );

    assert!(
        testing_only_validate_pq_full_payload(contents, &pure_payload_expectation()).is_err(),
        "a self-consistent execution block hash must not hide the wrong requested parent",
    );
}

#[cfg(target_feature = "avx2")]
fn assert_pure_payload_invalid(
    contents: execution_layer::BlockProposalContents<MinimalEthSpec, FullPayload<MinimalEthSpec>>,
    label: &str,
) {
    assert!(
        testing_only_validate_pq_full_payload(contents, &pure_payload_expectation()).is_err(),
        "{label} must be rejected by the production-shared payload validator",
    );
}

#[cfg(target_feature = "avx2")]
#[test]
fn full_payload_response_binds_all_requested_fields_and_preserves_value() {
    let value = testing_only_validate_pq_full_payload(
        pure_payload_contents(Default::default(), Default::default()),
        &pure_payload_expectation(),
    )
    .expect("exact payload response");
    assert_eq!(value, Uint256::from(55));

    let excess_blob_gas = testing_only_validate_pq_full_payload(
        pure_payload_contents(
            PurePayloadFields {
                excess_blob_gas: 7,
                ..Default::default()
            },
            Default::default(),
        ),
        &pure_payload_expectation(),
    );
    assert!(
        excess_blob_gas.is_ok(),
        "excess blob gas is an allowed parent-derived payload field",
    );

    assert_pure_payload_invalid(
        pure_payload_contents(
            PurePayloadFields {
                timestamp: 34,
                ..Default::default()
            },
            Default::default(),
        ),
        "rehashed timestamp mismatch",
    );
    assert_pure_payload_invalid(
        pure_payload_contents(
            PurePayloadFields {
                prev_randao: Hash256::repeat_byte(0x45),
                ..Default::default()
            },
            Default::default(),
        ),
        "rehashed prev_randao mismatch",
    );
    assert_pure_payload_invalid(
        pure_payload_contents(
            PurePayloadFields {
                withdrawals: vec![Withdrawal {
                    index: 1,
                    validator_index: 2,
                    address: Address::repeat_byte(0x46),
                    amount: 3,
                }],
                ..Default::default()
            },
            Default::default(),
        ),
        "rehashed withdrawals mismatch",
    );
    assert_pure_payload_invalid(
        pure_payload_contents(
            PurePayloadFields {
                blob_gas_used: 1,
                ..Default::default()
            },
            Default::default(),
        ),
        "rehashed nonzero blob gas",
    );

    let mut invalid_hash = pure_payload_contents(Default::default(), Default::default());
    let execution_layer::BlockProposalContents::PayloadAndBlobs { payload, .. } = &mut invalid_hash
    else {
        panic!("pure payload-and-blobs fixture")
    };
    let FullPayload::Electra(payload) = payload else {
        panic!("pure Electra payload fixture")
    };
    payload.execution_payload.block_hash = ExecutionBlockHash::repeat_byte(0x47);
    assert_pure_payload_invalid(invalid_hash, "invalid execution block hash");
}

#[cfg(target_feature = "avx2")]
#[test]
fn full_payload_response_rejects_each_blob_and_request_component() {
    let mut commitment = pure_payload_contents(Default::default(), Default::default());
    let execution_layer::BlockProposalContents::PayloadAndBlobs {
        kzg_commitments, ..
    } = &mut commitment
    else {
        panic!("pure payload-and-blobs fixture")
    };
    kzg_commitments
        .push(KzgCommitment::empty_for_testing())
        .expect("commitment capacity");
    assert_pure_payload_invalid(commitment, "nonempty KZG commitments");

    let mut blob = pure_payload_contents(Default::default(), Default::default());
    let execution_layer::BlockProposalContents::PayloadAndBlobs {
        blobs_and_proofs, ..
    } = &mut blob
    else {
        panic!("pure payload-and-blobs fixture")
    };
    blobs_and_proofs
        .as_mut()
        .expect("explicit blob/proof lists")
        .0
        .push(Blob::<MinimalEthSpec>::default())
        .expect("blob capacity");
    assert_pure_payload_invalid(blob, "nonempty blob list");

    let mut proof = pure_payload_contents(Default::default(), Default::default());
    let execution_layer::BlockProposalContents::PayloadAndBlobs {
        blobs_and_proofs, ..
    } = &mut proof
    else {
        panic!("pure payload-and-blobs fixture")
    };
    blobs_and_proofs
        .as_mut()
        .expect("explicit blob/proof lists")
        .1
        .push(KzgProof::empty())
        .expect("proof capacity");
    assert_pure_payload_invalid(proof, "nonempty proof list");

    let mut deposits = ExecutionRequests::<MinimalEthSpec>::default();
    deposits
        .deposits
        .push(
            DepositRequest::from_ssz_bytes(&vec![0; DepositRequest::max_size()])
                .expect("zero deposit request encoding"),
        )
        .expect("deposit request capacity");
    assert_pure_payload_invalid(
        pure_payload_contents(Default::default(), deposits),
        "nonempty deposit requests",
    );

    let mut withdrawals = ExecutionRequests::<MinimalEthSpec>::default();
    withdrawals
        .withdrawals
        .push(WithdrawalRequest {
            source_address: Address::ZERO,
            validator_pubkey: ValidatorPublicKeyBytes::empty(),
            amount: 1,
        })
        .expect("withdrawal request capacity");
    assert_pure_payload_invalid(
        pure_payload_contents(Default::default(), withdrawals),
        "nonempty withdrawal requests",
    );

    let mut consolidations = ExecutionRequests::<MinimalEthSpec>::default();
    consolidations
        .consolidations
        .push(ConsolidationRequest {
            source_address: Address::ZERO,
            source_pubkey: ValidatorPublicKeyBytes::empty(),
            target_pubkey: ValidatorPublicKeyBytes::empty(),
        })
        .expect("consolidation request capacity");
    assert_pure_payload_invalid(
        pure_payload_contents(Default::default(), consolidations),
        "nonempty consolidation requests",
    );
}

#[cfg(target_feature = "avx2")]
#[test]
fn production_slot_advance_accepts_cap_eight_and_rejects_cap_nine() {
    assert_eq!(
        testing_only_validate_pq_production_advance(Slot::new(0), Slot::new(8))
            .expect("advance at cap"),
        8,
    );
    let error = testing_only_validate_pq_production_advance(Slot::new(0), Slot::new(9))
        .expect_err("advance above cap");
    assert!(matches!(
        error,
        PqBlockProductionError::Local(PqBlockProductionLocalError::StateAdvanceTooLarge {
            supplied: 9,
            maximum: 8,
        })
    ));
}

#[cfg(target_feature = "avx2")]
#[test]
fn invalid_randao_and_stale_head_are_terminal() {
    let invalid = PqBlockProductionError::Invalid(state_processing::PqConsensusError::Invalid(
        state_processing::PqConsensusInvalid::InvalidEvidence(
            state_processing::PqConsensusComponent::RandaoReveal,
        ),
    ));
    let stale = PqBlockProductionError::StaleHead {
        expected_parent: Hash256::repeat_byte(0x51),
        actual_head: Hash256::repeat_byte(0x52),
    };

    assert!(!invalid.is_retryable(), "invalid RANDAO must be terminal");
    assert!(
        !stale.is_retryable(),
        "stale verified work must be terminal"
    );
}

#[cfg(target_feature = "avx2")]
struct RecordingExecution {
    new_payload_calls: AtomicUsize,
    new_payload_responses: Mutex<VecDeque<execution_layer::PayloadStatus>>,
    stall_new_payload: AtomicBool,
    new_payload_release: tokio::sync::Semaphore,
    forkchoice_calls: AtomicUsize,
    forkchoice_responses: Mutex<VecDeque<execution_layer::PayloadStatus>>,
    stall_forkchoice: AtomicBool,
    forkchoice_release: tokio::sync::Semaphore,
    payload_calls: AtomicUsize,
    stall_payload: std::sync::atomic::AtomicBool,
    omit_payload_bundle: std::sync::atomic::AtomicBool,
    invalid_payload_block_hash: std::sync::atomic::AtomicBool,
    nonzero_blob_gas: std::sync::atomic::AtomicBool,
    payload_release: tokio::sync::Semaphore,
}

#[cfg(target_feature = "avx2")]
impl RecordingExecution {
    fn set_new_payload_responses(
        &self,
        responses: impl IntoIterator<Item = execution_layer::PayloadStatus>,
    ) {
        *self
            .new_payload_responses
            .lock()
            .expect("new-payload response lock") = responses.into_iter().collect();
    }

    fn set_forkchoice_responses(
        &self,
        responses: impl IntoIterator<Item = execution_layer::PayloadStatus>,
    ) {
        *self
            .forkchoice_responses
            .lock()
            .expect("forkchoice response lock") = responses.into_iter().collect();
    }
}

#[cfg(target_feature = "avx2")]
impl PqNewPayloadTransport<MinimalEthSpec> for RecordingExecution {
    fn notify_new_payload<'a>(
        &'a self,
        _request: execution_layer::NewPayloadRequest<'a, MinimalEthSpec>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                > + Send
                + 'a,
        >,
    > {
        self.new_payload_calls.fetch_add(1, Ordering::SeqCst);
        let response = self
            .new_payload_responses
            .lock()
            .expect("new-payload response lock")
            .pop_front()
            .unwrap_or(execution_layer::PayloadStatus::Valid);
        Box::pin(async move {
            if self.stall_new_payload.load(Ordering::SeqCst) {
                let permit = self.new_payload_release.acquire().await.map_err(|_| {
                    execution_layer::Error::Unexpected(
                        "publication new-payload release closed".to_owned(),
                    )
                })?;
                permit.forget();
            }
            Ok(response)
        })
    }

    fn notify_forkchoice_updated<'a>(
        &'a self,
        _head_block_hash: types::ExecutionBlockHash,
        _current_slot: Slot,
        _head_block_root: Hash256,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                > + Send
                + 'a,
        >,
    > {
        self.forkchoice_calls.fetch_add(1, Ordering::SeqCst);
        let response = self
            .forkchoice_responses
            .lock()
            .expect("forkchoice response lock")
            .pop_front()
            .unwrap_or(execution_layer::PayloadStatus::Valid);
        Box::pin(async move {
            if self.stall_forkchoice.load(Ordering::SeqCst) {
                let permit = self.forkchoice_release.acquire().await.map_err(|_| {
                    execution_layer::Error::Unexpected(
                        "publication forkchoice release closed".to_owned(),
                    )
                })?;
                permit.forget();
            }
            Ok(response)
        })
    }

    fn get_full_payload<'a>(
        &'a self,
        request: PqPayloadBuildRequest<MinimalEthSpec>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        execution_layer::BlockProposalContents<
                            MinimalEthSpec,
                            FullPayload<MinimalEthSpec>,
                        >,
                        execution_layer::Error,
                    >,
                > + Send
                + 'a,
        >,
    > {
        self.payload_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.stall_payload.load(Ordering::SeqCst) {
                let permit = self.payload_release.acquire().await.map_err(|_| {
                    execution_layer::Error::Unexpected(
                        "production payload release closed".to_owned(),
                    )
                })?;
                permit.forget();
            }
            let response = full_payload_response(
                request,
                self.invalid_payload_block_hash.load(Ordering::SeqCst),
                self.nonzero_blob_gas.load(Ordering::SeqCst),
            )?;
            if self.omit_payload_bundle.load(Ordering::SeqCst) {
                let execution_layer::BlockProposalContents::PayloadAndBlobs {
                    payload,
                    block_value,
                    ..
                } = response
                else {
                    return Err(execution_layer::Error::InvalidPayloadBody(
                        "fixture expected payload-and-blobs".to_owned(),
                    ));
                };
                Ok(execution_layer::BlockProposalContents::Payload {
                    payload,
                    block_value,
                })
            } else {
                Ok(response)
            }
        })
    }
}

#[cfg(target_feature = "avx2")]
fn full_payload_response(
    request: PqPayloadBuildRequest<MinimalEthSpec>,
    invalid_block_hash: bool,
    nonzero_blob_gas: bool,
) -> Result<
    execution_layer::BlockProposalContents<MinimalEthSpec, FullPayload<MinimalEthSpec>>,
    execution_layer::Error,
> {
    let mut empty: BeaconBlock<MinimalEthSpec> = BeaconBlock::empty(request.spec());
    let BeaconBlock::Electra(inner) = &mut empty else {
        return Err(execution_layer::Error::InvalidForkForPayload);
    };
    inner.body.execution_payload.execution_payload.parent_hash = request.parent_hash();
    inner.body.execution_payload.execution_payload.timestamp = request.timestamp();
    inner.body.execution_payload.execution_payload.prev_randao = request.prev_randao();
    inner.body.execution_payload.execution_payload.withdrawals = request
        .withdrawals()
        .clone()
        .try_into()
        .map_err(|_| execution_layer::Error::InvalidPayloadConversion)?;
    if nonzero_blob_gas {
        inner.body.execution_payload.execution_payload.blob_gas_used = 1;
    }
    let block_hash = execution_layer::calculate_execution_block_hash(
        ExecutionPayloadRef::Electra(&inner.body.execution_payload.execution_payload),
        Some(request.parent_beacon_block_root()),
        Some(&inner.body.execution_requests),
    )
    .0;
    inner.body.execution_payload.execution_payload.block_hash = if invalid_block_hash {
        ExecutionBlockHash::repeat_byte(0x5a)
    } else {
        block_hash
    };
    Ok(execution_layer::BlockProposalContents::PayloadAndBlobs {
        payload: FullPayload::from(ExecutionPayload::Electra(
            inner.body.execution_payload.execution_payload.clone(),
        )),
        block_value: Default::default(),
        kzg_commitments: Default::default(),
        blobs_and_proofs: Some((Default::default(), Default::default())),
        requests: Some(Default::default()),
    })
}

#[cfg(target_feature = "avx2")]
fn electra_spec() -> types::ChainSpec {
    ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(17_000)
}

#[cfg(target_feature = "avx2")]
fn exact_snapshot_store(
    spec: Arc<types::ChainSpec>,
) -> Arc<HotColdDB<MinimalEthSpec, MemoryStore, MemoryStore>> {
    let mut config = StoreConfig::default();
    config.hierarchy_config.exponents = vec![0];
    config.block_cache_size = 0;
    Arc::new(HotColdDB::open_ephemeral(config, spec).expect("snapshot-every-slot store"))
}

#[cfg(target_feature = "avx2")]
struct ValidProductionFixture {
    chain: Arc<beacon_chain::BeaconChain<TestWitness>>,
    operational_events: Arc<beacon_chain::PqOperationalEventSink>,
    store: Arc<HotColdDB<MinimalEthSpec, MemoryStore, MemoryStore>>,
    aggregation_service: Arc<AggregationService>,
    execution: Arc<RecordingExecution>,
    randao: PqRawSignature,
    genesis_root: Hash256,
    genesis_checkpoint: types::Checkpoint,
    authority: PqSigningAuthority,
    spec: Arc<types::ChainSpec>,
    proposal_state: types::BeaconState<MinimalEthSpec>,
    proposer_index: usize,
    _runtime: task_executor::test_utils::TestRuntime,
    _temporary_directory: tempfile::TempDir,
}

#[cfg(target_feature = "avx2")]
struct IndependentPqReceiverFixture {
    chain: Arc<beacon_chain::BeaconChain<TestWitness>>,
    store: Arc<HotColdDB<MinimalEthSpec, MemoryStore, MemoryStore>>,
    aggregation_service: Arc<AggregationService>,
    execution: Arc<RecordingExecution>,
    genesis_root: Hash256,
    genesis_checkpoint: types::Checkpoint,
}

#[cfg(target_feature = "avx2")]
fn independent_pq_receiver_fixture(
    publisher: &ValidProductionFixture,
) -> IndependentPqReceiverFixture {
    let genesis = publisher.chain.head_snapshot().beacon_state.clone();
    let store = exact_snapshot_store(Arc::clone(&publisher.spec));
    let execution = Arc::new(RecordingExecution {
        new_payload_calls: AtomicUsize::new(0),
        new_payload_responses: Mutex::new(VecDeque::new()),
        stall_new_payload: AtomicBool::new(false),
        new_payload_release: tokio::sync::Semaphore::new(0),
        forkchoice_calls: AtomicUsize::new(0),
        forkchoice_responses: Mutex::new(VecDeque::new()),
        stall_forkchoice: AtomicBool::new(false),
        forkchoice_release: tokio::sync::Semaphore::new(0),
        payload_calls: AtomicUsize::new(0),
        stall_payload: AtomicBool::new(false),
        omit_payload_bundle: AtomicBool::new(false),
        invalid_payload_block_hash: AtomicBool::new(false),
        nonzero_blob_gas: AtomicBool::new(false),
        payload_release: tokio::sync::Semaphore::new(0),
    });
    let chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&store))
            .custom_spec(Arc::clone(&publisher.spec))
            .genesis_state(genesis)
            .expect("persist independent receiver genesis")
            .pq_aggregation_service(Arc::clone(&publisher.aggregation_service))
            .task_executor(publisher._runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(execution.clone())
            .build()
            .expect("independent receiver chain"),
    );
    chain.slot_clock.set_slot(1);
    let head = chain.head_snapshot();
    let genesis_root = head.beacon_block_root;
    let genesis_checkpoint = head.beacon_state.finalized_checkpoint();
    IndependentPqReceiverFixture {
        chain,
        store,
        aggregation_service: Arc::clone(&publisher.aggregation_service),
        execution,
        genesis_root,
        genesis_checkpoint,
    }
}

#[cfg(target_feature = "avx2")]
fn restart_independent_pq_chain(
    fixture: &ValidProductionFixture,
    store: Arc<HotColdDB<MinimalEthSpec, MemoryStore, MemoryStore>>,
    execution: Arc<RecordingExecution>,
) -> Arc<beacon_chain::BeaconChain<TestWitness>> {
    Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(store)
            .custom_spec(Arc::clone(&fixture.spec))
            .resume_from_db()
            .expect("resume independent PQ head")
            .pq_aggregation_service(Arc::clone(&fixture.aggregation_service))
            .task_executor(fixture._runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(execution)
            .build()
            .expect("rebuild independent PQ head"),
    )
}

#[cfg(target_feature = "avx2")]
fn valid_production_fixture(
    stall_payload: bool,
    omit_payload_bundle: bool,
) -> ValidProductionFixture {
    valid_production_fixture_with_blocking_hook(stall_payload, omit_payload_bundle, None)
}

#[cfg(target_feature = "avx2")]
#[tokio::test]
async fn proposer_duties_are_derived_from_the_exact_current_or_next_snapshot() {
    let fixture = valid_production_fixture(false, false);
    let current = fixture
        .chain
        .pq_proposer_duties(Epoch::new(0))
        .await
        .expect("current-epoch proposer duties");
    let expected = fixture
        .proposal_state
        .get_beacon_proposer_indices(Epoch::new(0), &fixture.spec)
        .expect("current proposer indices");
    assert_eq!(
        current.entries().len(),
        MinimalEthSpec::slots_per_epoch() as usize
    );
    for (offset, (entry, expected_index)) in current.entries().iter().zip(expected).enumerate() {
        assert_eq!(
            entry.slot(),
            Epoch::new(0).start_slot(MinimalEthSpec::slots_per_epoch()) + offset as u64
        );
        assert_eq!(entry.validator_index(), expected_index as u64);
        assert_eq!(
            entry.pubkey(),
            fixture
                .proposal_state
                .get_validator(expected_index)
                .expect("proposer validator")
                .pubkey,
        );
    }
    assert_eq!(current.bound_head_root(), fixture.genesis_root);
    assert_eq!(current.testing_only_advanced_slots(), 0);

    let next = fixture
        .chain
        .pq_proposer_duties(Epoch::new(1))
        .await
        .expect("next-epoch proposer duties");
    let mut advanced = fixture.proposal_state.clone();
    while advanced.slot() < Epoch::new(1).start_slot(MinimalEthSpec::slots_per_epoch()) {
        state_processing::per_slot_processing_pq(&mut advanced, &fixture.spec)
            .expect("bounded independent next-epoch advance");
    }
    let expected_next = advanced
        .get_beacon_proposer_indices(Epoch::new(1), &fixture.spec)
        .expect("next proposer indices");
    assert_eq!(
        next.entries()
            .iter()
            .map(|entry| entry.validator_index())
            .collect::<Vec<_>>(),
        expected_next
            .iter()
            .map(|index| *index as u64)
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        next.dependent_root(),
        advanced
            .legacy_proposer_shuffling_decision_root_at_epoch(Epoch::new(1), fixture.genesis_root)
            .expect("next dependent root"),
    );
    assert_eq!(next.bound_head_root(), fixture.genesis_root);
    assert_eq!(
        next.testing_only_advanced_slots(),
        MinimalEthSpec::slots_per_epoch()
    );

    let capacity = fixture
        .chain
        .pq_proposer_duties(Epoch::new(0))
        .await
        .expect_err("two retained duty responses must exhaust admission");
    assert!(matches!(capacity, PqProposerDutiesError::Capacity));
    drop(current);
    drop(next);

    let error = fixture
        .chain
        .pq_proposer_duties(Epoch::new(2))
        .await
        .expect_err("too-far-future duties must fail before derivation");
    assert!(matches!(
        error,
        PqProposerDutiesError::EpochOutsideWindow { .. }
    ));
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn proposer_duties_reject_clock_rollover_and_head_change_after_derivation_starts() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let hook = TestingPqBlockingHook::blocking();
    let fixture = valid_production_fixture_with_duties_hook(Arc::clone(&hook));

    let rollover_chain = Arc::clone(&fixture.chain);
    let rollover =
        tokio::spawn(async move { rollover_chain.pq_proposer_duties(Epoch::new(0)).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while hook.entered() < 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("duty derivation entered blocking executor");
    fixture.chain.slot_clock.set_slot(
        Epoch::new(1)
            .start_slot(MinimalEthSpec::slots_per_epoch())
            .as_u64(),
    );
    hook.release();
    assert!(matches!(
        rollover.await.expect("rollover task"),
        Err(PqProposerDutiesError::EpochOutsideWindow {
            current,
            requested,
        }) if current == Epoch::new(1) && requested == Epoch::new(0)
    ));

    fixture.chain.slot_clock.set_slot(1);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("canonical candidate before stale duty race");
    let signed = sign_produced_block(&fixture, produced);
    hook.block();
    let stale_chain = Arc::clone(&fixture.chain);
    let stale = tokio::spawn(async move { stale_chain.pq_proposer_duties(Epoch::new(0)).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while hook.entered() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("second duty derivation entered blocking executor");
    PqNetworkBlockProcessor::new(Arc::clone(&fixture.chain))
        .import_rpc_block(Arc::clone(&signed))
        .await
        .expect("canonical import while duty derivation is paused");
    hook.release();
    assert!(matches!(
        stale.await.expect("stale-head task"),
        Err(PqProposerDutiesError::StaleHead { expected, actual })
            if expected == fixture.genesis_root && actual == signed.canonical_root()
    ));
}

#[cfg(target_feature = "avx2")]
fn valid_production_fixture_with_blocking_hook(
    stall_payload: bool,
    omit_payload_bundle: bool,
    blocking_hook: Option<Arc<TestingPqBlockingHook>>,
) -> ValidProductionFixture {
    valid_production_fixture_with_hooks(
        stall_payload,
        omit_payload_bundle,
        blocking_hook,
        None,
        None,
    )
}

#[cfg(target_feature = "avx2")]
fn valid_production_fixture_with_duties_hook(
    duties_hook: Arc<TestingPqBlockingHook>,
) -> ValidProductionFixture {
    valid_production_fixture_with_hooks(false, false, None, None, Some(duties_hook))
}

#[cfg(target_feature = "avx2")]
fn valid_production_fixture_with_hooks(
    stall_payload: bool,
    omit_payload_bundle: bool,
    blocking_hook: Option<Arc<TestingPqBlockingHook>>,
    persistence_hook: Option<Arc<TestingPqBlockingHook>>,
    duties_hook: Option<Arc<TestingPqBlockingHook>>,
) -> ValidProductionFixture {
    valid_production_fixture_with_hooks_and_spec(
        stall_payload,
        omit_payload_bundle,
        blocking_hook,
        persistence_hook,
        duties_hook,
        electra_spec(),
    )
}

#[cfg(target_feature = "avx2")]
fn valid_production_fixture_with_hooks_and_spec(
    stall_payload: bool,
    omit_payload_bundle: bool,
    blocking_hook: Option<Arc<TestingPqBlockingHook>>,
    persistence_hook: Option<Arc<TestingPqBlockingHook>>,
    duties_hook: Option<Arc<TestingPqBlockingHook>>,
    spec: types::ChainSpec,
) -> ValidProductionFixture {
    valid_production_fixture_with_hooks_spec_and_executor(
        stall_payload,
        omit_payload_bundle,
        blocking_hook,
        persistence_hook,
        duties_hook,
        spec,
        None,
    )
}

#[cfg(target_feature = "avx2")]
fn valid_production_fixture_with_hooks_spec_and_executor(
    stall_payload: bool,
    omit_payload_bundle: bool,
    blocking_hook: Option<Arc<TestingPqBlockingHook>>,
    persistence_hook: Option<Arc<TestingPqBlockingHook>>,
    duties_hook: Option<Arc<TestingPqBlockingHook>>,
    spec: types::ChainSpec,
    task_executor: Option<task_executor::TaskExecutor>,
) -> ValidProductionFixture {
    const PASSWORD: &[u8] = b"correct horse battery staple";

    let runtime = task_executor::test_utils::TestRuntime::default();
    let task_executor = task_executor.unwrap_or_else(|| runtime.task_executor.clone());
    let temporary_directory = tempfile::TempDir::new().expect("temporary directory");
    let spec = Arc::new(spec);
    let mut genesis = state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16)
            .map(|byte| state_processing::DirectGenesisValidator {
                public_key: PqPublicKey::deserialize(&[byte; 32])
                    .expect("canonical synthetic public key"),
                withdrawal_credentials: Hash256::ZERO,
            })
            .collect(),
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    genesis
        .build_all_committee_caches(&spec)
        .expect("genesis committee caches");
    let proposer_index = genesis
        .get_beacon_proposer_index(Slot::new(1), &spec)
        .expect("slot-one proposer");
    let maximum_leaf = OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::BeaconBlockProposal)
        .expect("slot-one proposal leaf")
        .as_u32();
    let proposer_keystore =
        PqKeystore::from_seed([0xa5; 32], 0..=maximum_leaf, PASSWORD).expect("fixture keystore");
    let authenticated = proposer_keystore
        .authenticate(PASSWORD)
        .expect("authenticated proposer key");
    genesis
        .validators_mut()
        .get_mut(proposer_index)
        .expect("proposer validator")
        .pubkey = *authenticated.public_key();
    let validators_root = genesis.genesis_validators_root().0;
    let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
    provision_usage_journal(&journal_path, validators_root, &[authenticated])
        .expect("usage journal");
    let authority = PqSigningAuthority::open(
        &journal_path,
        validators_root,
        vec![PqKeyUnlock::new(proposer_keystore, PASSWORD).expect("proposer unlock")],
    )
    .expect("signing authority");
    let execution = Arc::new(RecordingExecution {
        new_payload_calls: AtomicUsize::new(0),
        new_payload_responses: Mutex::new(VecDeque::new()),
        stall_new_payload: AtomicBool::new(false),
        new_payload_release: tokio::sync::Semaphore::new(0),
        forkchoice_calls: AtomicUsize::new(0),
        forkchoice_responses: Mutex::new(VecDeque::new()),
        stall_forkchoice: AtomicBool::new(false),
        forkchoice_release: tokio::sync::Semaphore::new(0),
        payload_calls: AtomicUsize::new(0),
        stall_payload: std::sync::atomic::AtomicBool::new(stall_payload),
        omit_payload_bundle: std::sync::atomic::AtomicBool::new(omit_payload_bundle),
        invalid_payload_block_hash: std::sync::atomic::AtomicBool::new(false),
        nonzero_blob_gas: std::sync::atomic::AtomicBool::new(false),
        payload_release: tokio::sync::Semaphore::new(0),
    });
    let store = exact_snapshot_store(Arc::clone(&spec));
    let aggregation_service = Arc::new(AggregationService::new().expect("PQ aggregation service"));
    let operational_events = testing_only_running_pq_operational_event_sink(&runtime.task_executor);
    let mut builder = BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
        .store(Arc::clone(&store))
        .custom_spec(Arc::clone(&spec))
        .genesis_state(genesis.clone())
        .expect("persist genesis")
        .pq_aggregation_service(Arc::clone(&aggregation_service))
        .pq_operational_events(Arc::downgrade(&operational_events))
        .task_executor(task_executor)
        .testing_only_pq_execution_notifier(execution.clone());
    if let Some(blocking_hook) = blocking_hook {
        builder = builder.testing_only_pq_blocking_hook(blocking_hook);
    }
    if let Some(persistence_hook) = persistence_hook {
        builder = builder.testing_only_pq_persistence_hook(persistence_hook);
    }
    if let Some(duties_hook) = duties_hook {
        builder = builder.testing_only_pq_proposer_duties_hook(duties_hook);
    }
    let chain = Arc::new(builder.build().expect("PQ chain"));
    chain.slot_clock.set_slot(1);
    let head = chain.head_snapshot();
    let genesis_root = head.beacon_block_root;
    let genesis_checkpoint = head.beacon_state.finalized_checkpoint();
    let mut proposal_state = genesis;
    state_processing::per_slot_processing_pq(&mut proposal_state, &spec)
        .expect("advance proposal state");
    let randao_domain = spec.get_domain(
        proposal_state.current_epoch(),
        Domain::Randao,
        &proposal_state.fork(),
        proposal_state.genesis_validators_root(),
    );
    let proposer_public_key = proposal_state
        .validators()
        .get(proposer_index)
        .expect("proposer validator")
        .pubkey;
    let randao = authority
        .signer(&proposer_public_key)
        .expect("bound proposer signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            proposal_state.current_epoch().signing_root(randao_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::RandaoReveal).expect("RANDAO leaf"),
        ))
        .expect("RANDAO signature");

    ValidProductionFixture {
        chain,
        operational_events,
        store,
        aggregation_service,
        execution,
        randao,
        genesis_root,
        genesis_checkpoint,
        authority,
        spec,
        proposal_state,
        proposer_index,
        _runtime: runtime,
        _temporary_directory: temporary_directory,
    }
}

#[cfg(target_feature = "avx2")]
fn sign_produced_block(
    fixture: &ValidProductionFixture,
    produced: beacon_chain::PqProducedBlockV3<MinimalEthSpec>,
) -> Arc<SignedBeaconBlock<MinimalEthSpec>> {
    let (block, blob_data) = produced.into_contents().deconstruct();
    let (proofs, blobs) = blob_data.expect("Electra V3 has explicit blob lists");
    assert!(proofs.is_empty());
    assert!(blobs.is_empty());
    sign_block(fixture, block)
}

#[cfg(target_feature = "avx2")]
async fn start_pq_network_worker(
    fixture: &ValidProductionFixture,
    disable_discovery: bool,
) -> (
    network::PqBlockBroadcastSender<MinimalEthSpec>,
    Arc<NetworkGlobals<MinimalEthSpec>>,
    tokio::sync::mpsc::Sender<lighthouse_network::Multiaddr>,
    Arc<lighthouse_network::PqGossipValidationAdmission>,
) {
    let (broadcast_sender, globals, dial_sender, admission, _shutdown) =
        start_pq_network_worker_for_chain(
            fixture,
            Arc::clone(&fixture.chain),
            disable_discovery,
            None,
        )
        .await;
    (broadcast_sender, globals, dial_sender, admission)
}

#[cfg(target_feature = "avx2")]
async fn start_pq_network_worker_for_chain(
    fixture: &ValidProductionFixture,
    chain: Arc<beacon_chain::BeaconChain<TestWitness>>,
    disable_discovery: bool,
    encoding_hook: Option<Arc<dyn Fn() + Send + Sync>>,
) -> (
    network::PqBlockBroadcastSender<MinimalEthSpec>,
    Arc<NetworkGlobals<MinimalEthSpec>>,
    tokio::sync::mpsc::Sender<lighthouse_network::Multiaddr>,
    Arc<lighthouse_network::PqGossipValidationAdmission>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let head = chain.head_snapshot();
    let genesis_validators_root = head.beacon_state.genesis_validators_root();
    let mut network_config = NetworkConfig::default();
    network_config.set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, 0, 0, 0);
    network_config.enr_address = (Some(std::net::Ipv4Addr::LOCALHOST), None);
    network_config.disable_discovery = disable_discovery;
    network_config.network_dir = tempfile::TempDir::new().expect("network directory").keep();
    let context = Context {
        config: Arc::new(network_config),
        enr_fork_id: fixture
            .spec
            .enr_fork_id::<MinimalEthSpec>(head.beacon_block.slot(), genesis_validators_root),
        fork_context: Arc::new(ForkContext::new::<MinimalEthSpec>(
            head.beacon_block.slot(),
            genesis_validators_root,
            &fixture.spec,
        )),
        chain_spec: Arc::clone(&fixture.spec),
        libp2p_registry: None,
    };
    let (broadcast_sender, broadcast_receiver) = pq_block_broadcast_channel();
    let mut service = PqNetworkService::new(
        fixture._runtime.task_executor.clone(),
        context,
        fixture.spec.custody_requirement,
        secp256k1::Keypair::generate().into(),
        chain,
        broadcast_receiver,
        testing_only_running_pq_operational_event_sink(&fixture._runtime.task_executor),
    )
    .await
    .expect("PQ network service");
    if let Some(hook) = encoding_hook {
        service.testing_only_set_block_encoding_hook(hook);
    }
    let globals = service.network_globals();
    let dial_sender = service.testing_only_dial_sender();
    let admission = service.testing_only_gossip_admission();
    let shutdown = service
        .testing_only_shutdown_receipt()
        .expect("one shutdown receipt per PQ network owner");
    service.start().expect("start PQ network service");
    (broadcast_sender, globals, dial_sender, admission, shutdown)
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn real_delayed_network_proof_survives_old_history_and_commits_engine_db_head() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let test_started = std::time::Instant::now();
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    let import_hook = TestingPqBlockingHook::counting();
    let fixture = valid_production_fixture_with_hooks_and_spec(
        false,
        false,
        Some(Arc::clone(&import_hook)),
        None,
        None,
        spec,
    );
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    eprintln!("PQ delayed proof: produced at {:?}", test_started.elapsed());
    let signed = sign_produced_block(&fixture, produced);
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0
    );

    let (receiver_sender, receiver_globals, _receiver_dial, receiver_admission) =
        start_pq_network_worker(&fixture, false).await;
    let receiver_address = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let enr = receiver_globals.local_enr();
            if let Some(address) = enr.multiaddr_p2p_tcp().into_iter().next() {
                break address;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receiver listening ENR");
    let (sender, sender_globals, sender_dial, sender_admission) =
        start_pq_network_worker(&fixture, true).await;
    sender_dial
        .try_send(receiver_address)
        .expect("bounded testing dial command");
    tokio::time::timeout(Duration::from_secs(30), async {
        while sender_globals.connected_peers() == 0
            || receiver_globals.connected_peers() == 0
            || !sender_admission.has_compatible_peers()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("compatible PQ Status handshake");
    eprintln!(
        "PQ delayed proof: compatible handshake at {:?}",
        test_started.elapsed()
    );

    let hook_entries_before_publish = import_hook.entered();
    import_hook.block();

    let acknowledgement = sender
        .try_send(Arc::clone(&signed))
        .expect("bounded exact publication");
    let publish_result =
        tokio::time::timeout(Duration::from_secs(30), acknowledgement.wait()).await;
    let admission_result = tokio::time::timeout(Duration::from_secs(30), async {
        while receiver_admission.testing_only_active_total() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let hook_entry_result = tokio::time::timeout(Duration::from_secs(5), async {
        while import_hook.entered() == hook_entries_before_publish {
            tokio::task::yield_now().await;
        }
    })
    .await;
    if publish_result.is_err() || admission_result.is_err() || hook_entry_result.is_err() {
        import_hook.release();
    }
    publish_result
        .expect("initial network acknowledgement")
        .expect("initial exact block publish");
    admission_result.expect("receiver admits exact block before progress assertion");
    hook_entry_result.expect("receiver import enters the blocking phase after publication");
    eprintln!(
        "PQ delayed proof: receiver import blocked at {:?}",
        test_started.elapsed()
    );
    let proof_started = std::time::Instant::now();

    let pending = receiver_sender
        .try_send(Arc::clone(&signed))
        .expect("receiver network loop accepts a command during proof");
    let pending_result = tokio::time::timeout(Duration::from_secs(5), pending.wait()).await;
    if pending_result.is_err() {
        import_hook.release();
    }
    assert_eq!(
        pending_result.expect("receiver network loop remains live while proof runs"),
        Err(network::PqBlockBroadcastError::Rejected),
        "local publication of an exact pending validation must remain negative",
    );
    tokio::time::sleep(Duration::from_secs(13)).await;
    let retained_admissions = receiver_admission.testing_only_active_total();
    let new_payload_calls_before_release =
        fixture.execution.new_payload_calls.load(Ordering::SeqCst);
    let head_before_release = fixture.chain.head_snapshot().beacon_block_root;
    import_hook.release();
    eprintln!(
        "PQ delayed proof: released receiver import at {:?}",
        test_started.elapsed()
    );
    assert_eq!(
        retained_admissions, 1,
        "one-slot admission must retain the exact raw block beyond twelve heartbeats",
    );
    assert_eq!(new_payload_calls_before_release, 0);
    assert_eq!(head_before_release, fixture.genesis_root);

    tokio::time::timeout(Duration::from_secs(300), async {
        while fixture.chain.head_snapshot().beacon_block_root != signed.canonical_root() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("full network proof and import before one-slot admission expiry");
    eprintln!("PQ delayed proof: imported at {:?}", test_started.elapsed());
    assert!(
        proof_started.elapsed() > Duration::from_secs(12),
        "real proof must exceed the ordinary twelve-heartbeat history",
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture
            .store
            .get_full_block(&signed.canonical_root())
            .expect("persisted block lookup")
            .expect("persisted exact block"),
        *signed,
    );
    let restarted = BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
        .store(Arc::clone(&fixture.store))
        .custom_spec(Arc::clone(&fixture.spec))
        .resume_from_db()
        .expect("resume network-imported head")
        .pq_aggregation_service(Arc::clone(&fixture.aggregation_service))
        .task_executor(fixture._runtime.task_executor.clone())
        .testing_only_pq_execution_notifier(fixture.execution.clone())
        .build()
        .expect("restart network-imported head");
    assert_eq!(
        restarted.head_snapshot().beacon_block_root,
        signed.canonical_root(),
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn real_publication_service_converges_two_independent_network_chains() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let test_started = std::time::Instant::now();
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    let publisher =
        valid_production_fixture_with_hooks_and_spec(false, false, None, None, None, spec);
    let receiver = independent_pq_receiver_fixture(&publisher);
    assert!(!Arc::ptr_eq(&publisher.store, &receiver.store));
    assert!(!Arc::ptr_eq(&publisher.chain, &receiver.chain));
    assert!(!Arc::ptr_eq(&publisher.execution, &receiver.execution));
    assert!(Arc::ptr_eq(
        &publisher.aggregation_service,
        &receiver.aggregation_service,
    ));
    assert_eq!(publisher.genesis_root, receiver.genesis_root);
    assert_eq!(
        publisher.genesis_checkpoint,
        publisher
            .chain
            .head_snapshot()
            .beacon_state
            .finalized_checkpoint(),
    );
    assert_eq!(
        receiver.genesis_checkpoint,
        receiver
            .chain
            .head_snapshot()
            .beacon_state
            .finalized_checkpoint(),
    );

    let produced = publisher
        .chain
        .produce_pq_block_v3(Slot::new(1), publisher.randao.clone(), Graffiti::default())
        .await
        .expect("valid publisher candidate");
    let signed = sign_produced_block(&publisher, produced);
    let signed_root = signed.canonical_root();
    eprintln!("PQ e4b: produced at {:?}", test_started.elapsed());

    let (receiver_sender, receiver_globals, _receiver_dial, _, receiver_shutdown) =
        start_pq_network_worker_for_chain(&publisher, Arc::clone(&receiver.chain), false, None)
            .await;
    let receiver_address = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let enr = receiver_globals.local_enr();
            if let Some(address) = enr.multiaddr_p2p_tcp().into_iter().next() {
                break address;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receiver listening ENR");

    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let (entered_sender, mut entered_receiver) = tokio::sync::mpsc::unbounded_channel();
    let encoding_hook = {
        let release = Arc::clone(&release);
        Arc::new(move || {
            entered_sender.send(()).expect("encoding observer alive");
            let (lock, condition) = &*release;
            let mut released = lock.lock().expect("encoding release lock");
            while !*released {
                released = condition.wait(released).expect("encoding release wait");
            }
        }) as Arc<dyn Fn() + Send + Sync>
    };
    let (
        publisher_sender,
        publisher_globals,
        publisher_dial,
        publisher_admission,
        publisher_shutdown,
    ) = start_pq_network_worker_for_chain(
        &publisher,
        Arc::clone(&publisher.chain),
        true,
        Some(encoding_hook),
    )
    .await;
    publisher_dial
        .try_send(receiver_address)
        .expect("bounded testing dial command");
    tokio::time::timeout(Duration::from_secs(30), async {
        while publisher_globals.connected_peers() == 0
            || receiver_globals.connected_peers() == 0
            || !publisher_admission.has_compatible_peers()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("compatible PQ Status handshake");
    eprintln!(
        "PQ e4b: compatible handshake at {:?}",
        test_started.elapsed()
    );

    let publication_service = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&publisher.chain),
            publisher._runtime.task_executor.clone(),
            publisher_sender,
        )
        .expect("publisher publication service"),
    );
    let admission = publication_service
        .try_admit()
        .expect("publication admission");
    let signed_for_publish = Arc::clone(&signed);
    let publication = tokio::spawn(async move { admission.publish(signed_for_publish).await });

    let entered = tokio::time::timeout(Duration::from_secs(300), entered_receiver.recv()).await;
    let publication_finished_before_ack = publication.is_finished();
    let publisher_engine_before_ack = publisher.execution.new_payload_calls.load(Ordering::SeqCst);
    let receiver_engine_before_ack = receiver.execution.new_payload_calls.load(Ordering::SeqCst);
    let publisher_head_before_ack = publisher.chain.head_snapshot().beacon_block_root;
    let receiver_head_before_ack = receiver.chain.head_snapshot().beacon_block_root;
    let (lock, condition) = &*release;
    *lock.lock().expect("encoding release lock") = true;
    condition.notify_all();
    entered
        .expect("real publication reaches network encoding")
        .expect("encoding observer");
    eprintln!("PQ e4b: pre-ack barrier at {:?}", test_started.elapsed());
    assert!(!publication_finished_before_ack);
    assert_eq!(publisher_engine_before_ack, 0);
    assert_eq!(receiver_engine_before_ack, 0);
    assert_eq!(publisher_head_before_ack, publisher.genesis_root);
    assert_eq!(receiver_head_before_ack, receiver.genesis_root);

    let disposition = tokio::time::timeout(Duration::from_secs(300), publication)
        .await
        .expect("publisher publication completes")
        .expect("publisher publication task");
    let PqBlockPublicationDisposition::Published(outcome) = disposition else {
        panic!("real publication must commit the publisher")
    };
    assert_eq!(outcome.source, beacon_chain::PqBlockImportSource::Publish);
    assert_eq!(outcome.block_root, signed_root);
    eprintln!(
        "PQ e4b: publisher committed at {:?}",
        test_started.elapsed()
    );

    tokio::time::timeout(Duration::from_secs(300), async {
        while receiver.chain.head_snapshot().beacon_block_root != signed_root {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receiver full proof and import");
    eprintln!("PQ e4b: receiver committed at {:?}", test_started.elapsed());
    assert_eq!(
        publisher.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        receiver.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        publisher
            .store
            .get_full_block(&signed_root)
            .expect("publisher block lookup")
            .expect("publisher persisted exact block"),
        *signed,
    );
    assert_eq!(
        receiver
            .store
            .get_full_block(&signed_root)
            .expect("receiver block lookup")
            .expect("receiver persisted exact block"),
        *signed,
    );
    assert_eq!(
        publisher
            .chain
            .head_snapshot()
            .beacon_state
            .finalized_checkpoint(),
        publisher.genesis_checkpoint,
    );
    assert_eq!(
        receiver
            .chain
            .head_snapshot()
            .beacon_state
            .finalized_checkpoint(),
        receiver.genesis_checkpoint,
    );

    drop(publication_service);
    drop(receiver_sender);
    tokio::time::timeout(Duration::from_secs(10), publisher_shutdown)
        .await
        .expect("publisher network owner shuts down")
        .expect("publisher shutdown receipt");
    tokio::time::timeout(Duration::from_secs(10), receiver_shutdown)
        .await
        .expect("receiver network owner shuts down")
        .expect("receiver shutdown receipt");
    let restarted_publisher = restart_independent_pq_chain(
        &publisher,
        Arc::clone(&publisher.store),
        Arc::clone(&publisher.execution),
    );
    let restarted_receiver = restart_independent_pq_chain(
        &publisher,
        Arc::clone(&receiver.store),
        Arc::clone(&receiver.execution),
    );
    assert_eq!(
        restarted_publisher.head_snapshot().beacon_block_root,
        signed_root
    );
    assert_eq!(
        restarted_receiver.head_snapshot().beacon_block_root,
        signed_root
    );
    assert_eq!(
        restarted_publisher.head_snapshot().beacon_block.as_ref(),
        signed.as_ref(),
    );
    assert_eq!(
        restarted_receiver.head_snapshot().beacon_block.as_ref(),
        signed.as_ref(),
    );
    assert_eq!(
        restarted_publisher
            .head_snapshot()
            .beacon_state
            .finalized_checkpoint(),
        publisher.genesis_checkpoint,
    );
    assert_eq!(
        restarted_receiver
            .head_snapshot()
            .beacon_state
            .finalized_checkpoint(),
        receiver.genesis_checkpoint,
    );
}

#[cfg(target_feature = "avx2")]
fn sign_block(
    fixture: &ValidProductionFixture,
    block: BeaconBlock<MinimalEthSpec>,
) -> Arc<SignedBeaconBlock<MinimalEthSpec>> {
    let proposal_domain = fixture.spec.get_domain(
        fixture.proposal_state.current_epoch(),
        Domain::BeaconProposer,
        &fixture.proposal_state.fork(),
        fixture.proposal_state.genesis_validators_root(),
    );
    let proposer_public_key = fixture
        .proposal_state
        .validators()
        .get(fixture.proposer_index)
        .expect("proposer validator")
        .pubkey;
    let proposal_signature = fixture
        .authority
        .signer(&proposer_public_key)
        .expect("bound proposer signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            block.signing_root(proposal_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::BeaconBlockProposal)
                .expect("proposal leaf"),
        ))
        .expect("proposal signature");
    Arc::new(SignedBeaconBlock::from_block(block, proposal_signature))
}

#[cfg(target_feature = "avx2")]
fn sign_equivocating_block(
    fixture: &ValidProductionFixture,
    block: BeaconBlock<MinimalEthSpec>,
) -> Arc<SignedBeaconBlock<MinimalEthSpec>> {
    const PASSWORD: &[u8] = b"correct horse battery staple";
    let maximum_leaf = OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::BeaconBlockProposal)
        .expect("slot-one proposal leaf")
        .as_u32();
    let keystore = PqKeystore::from_seed([0xa5; 32], 0..=maximum_leaf, PASSWORD)
        .expect("equivocation fixture keystore");
    let authenticated = keystore
        .authenticate(PASSWORD)
        .expect("equivocation fixture authentication");
    let authenticated_public_key = *authenticated.public_key();
    let journal_path = fixture
        ._temporary_directory
        .path()
        .join("equivocation_usage.sqlite");
    provision_usage_journal(
        &journal_path,
        fixture.proposal_state.genesis_validators_root().0,
        &[authenticated],
    )
    .expect("equivocation usage journal");
    let authority = PqSigningAuthority::open(
        &journal_path,
        fixture.proposal_state.genesis_validators_root().0,
        vec![PqKeyUnlock::new(keystore, PASSWORD).expect("equivocation unlock")],
    )
    .expect("equivocation signing authority");
    let proposal_domain = fixture.spec.get_domain(
        fixture.proposal_state.current_epoch(),
        Domain::BeaconProposer,
        &fixture.proposal_state.fork(),
        fixture.proposal_state.genesis_validators_root(),
    );
    let proposer_public_key = fixture
        .proposal_state
        .validators()
        .get(fixture.proposer_index)
        .expect("proposer validator")
        .pubkey;
    assert_eq!(authenticated_public_key, proposer_public_key);
    let proposal_signature = authority
        .signer(&proposer_public_key)
        .expect("equivocation proposer signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            block.signing_root(proposal_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::BeaconBlockProposal)
                .expect("proposal leaf"),
        ))
        .expect("equivocation proposal signature");
    Arc::new(SignedBeaconBlock::from_block(block, proposal_signature))
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn invalid_randao_is_rejected_before_any_execution_work() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let runtime = task_executor::test_utils::TestRuntime::default();
    let spec = Arc::new(electra_spec());
    let mut genesis = state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16)
            .map(|byte| state_processing::DirectGenesisValidator {
                public_key: PqPublicKey::deserialize(&[byte; 32])
                    .expect("canonical synthetic public key"),
                withdrawal_credentials: Hash256::ZERO,
            })
            .collect(),
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    genesis
        .build_all_committee_caches(&spec)
        .expect("genesis committee caches");

    let execution = Arc::new(RecordingExecution {
        new_payload_calls: AtomicUsize::new(0),
        new_payload_responses: Mutex::new(VecDeque::new()),
        stall_new_payload: AtomicBool::new(false),
        new_payload_release: tokio::sync::Semaphore::new(0),
        forkchoice_calls: AtomicUsize::new(0),
        forkchoice_responses: Mutex::new(VecDeque::new()),
        stall_forkchoice: AtomicBool::new(false),
        forkchoice_release: tokio::sync::Semaphore::new(0),
        payload_calls: AtomicUsize::new(0),
        stall_payload: std::sync::atomic::AtomicBool::new(false),
        omit_payload_bundle: std::sync::atomic::AtomicBool::new(false),
        invalid_payload_block_hash: std::sync::atomic::AtomicBool::new(false),
        nonzero_blob_gas: std::sync::atomic::AtomicBool::new(false),
        payload_release: tokio::sync::Semaphore::new(0),
    });
    let chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis)
            .expect("persist genesis")
            .pq_aggregation_service(Arc::new(
                AggregationService::new().expect("PQ aggregation service"),
            ))
            .task_executor(runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(execution.clone())
            .build()
            .expect("PQ chain"),
    );
    chain.slot_clock.set_slot(1);

    let error = chain
        .produce_pq_block_v3(Slot::new(1), PqRawSignature::empty(), Graffiti::default())
        .await
        .expect_err("empty RANDAO evidence must fail");

    assert!(!error.is_retryable());
    assert!(matches!(error, PqBlockProductionError::Invalid(_)));
    assert_eq!(execution.new_payload_calls.load(Ordering::SeqCst), 0);
    assert_eq!(execution.payload_calls.load(Ordering::SeqCst), 0);
    assert_eq!(chain.head_snapshot().beacon_state.slot(), Slot::new(0));
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn initial_slot_outcomes_distinguish_retryable_future_from_terminal_past_and_head() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);

    let future = fixture
        .chain
        .produce_pq_block_v3(Slot::new(2), fixture.randao.clone(), Graffiti::default())
        .await
        .expect_err("future proposal slot");
    assert!(matches!(
        future,
        PqBlockProductionError::InitialFutureSlot {
            current,
            requested,
        } if current == Slot::new(1) && requested == Slot::new(2)
    ));
    assert!(future.is_retryable());

    let past = fixture
        .chain
        .produce_pq_block_v3(Slot::new(0), fixture.randao.clone(), Graffiti::default())
        .await
        .expect_err("past proposal slot");
    assert!(matches!(
        past,
        PqBlockProductionError::InitialPastSlot {
            current,
            requested,
        } if current == Slot::new(1) && requested == Slot::new(0)
    ));
    assert!(!past.is_retryable());

    fixture.chain.slot_clock.set_slot(0);
    let at_head = fixture
        .chain
        .produce_pq_block_v3(Slot::new(0), fixture.randao.clone(), Graffiti::default())
        .await
        .expect_err("proposal slot at canonical head");
    assert!(matches!(
        at_head,
        PqBlockProductionError::AtOrBehindHead {
            head,
            requested,
        } if head == Slot::new(0) && requested == Slot::new(0)
    ));
    assert!(!at_head.is_retryable());
    assert_eq!(fixture.execution.payload_calls.load(Ordering::SeqCst), 0);
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn slot_expiry_after_attestation_selection_skips_get_payload() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let post_selection = TestingPqBlockingHook::blocking();
    fixture
        .chain
        .testing_only_set_pq_attestation_pool_post_selection_hook(Some(Arc::clone(
            &post_selection,
        )));

    struct ReleaseSelectionHook(Option<Arc<TestingPqBlockingHook>>);

    impl ReleaseSelectionHook {
        fn release(&mut self) {
            if let Some(hook) = self.0.take() {
                hook.release();
            }
        }
    }

    impl Drop for ReleaseSelectionHook {
        fn drop(&mut self) {
            self.release();
        }
    }

    let mut release_selection = ReleaseSelectionHook(Some(Arc::clone(&post_selection)));
    let producing_chain = Arc::clone(&fixture.chain);
    let randao = fixture.randao.clone();
    let production = tokio::spawn(async move {
        producing_chain
            .produce_pq_block_v3(Slot::new(1), randao, Graffiti::default())
            .await
    });
    let reached_post_selection = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            if post_selection.entered() == 1 {
                break true;
            }
            if production.is_finished() {
                break false;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    match reached_post_selection {
        Ok(true) => {}
        Ok(false) => panic!("production completed before the post-selection expiry barrier"),
        Err(error) => panic!("production did not reach the post-selection expiry barrier: {error}"),
    }

    fixture.chain.slot_clock.set_slot(2);
    release_selection.release();
    let error = production
        .await
        .expect("slot-expiry production task")
        .expect_err("slot-one production must expire after selection");
    assert!(matches!(
        error,
        PqBlockProductionError::ExpiredAfterWork { current, requested }
            if current == Slot::new(2) && requested == Slot::new(1)
    ));
    assert_eq!(
        fixture.execution.payload_calls.load(Ordering::SeqCst),
        0,
        "expired selection must be rejected before getPayload",
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn valid_randao_produces_one_full_canonical_empty_block_without_head_mutation() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let chain = &fixture.chain;
    let execution = &fixture.execution;
    let randao = &fixture.randao;
    let genesis_root = fixture.genesis_root;

    let produced = chain
        .produce_pq_block_v3(Slot::new(1), randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let block = produced.contents().block();

    assert_eq!(execution.payload_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execution.new_payload_calls.load(Ordering::SeqCst), 0);
    assert_eq!(block.slot(), Slot::new(1));
    assert_eq!(block.parent_root(), genesis_root);
    assert_ne!(block.state_root(), Hash256::ZERO);
    assert_eq!(block.body().randao_reveal(), randao);
    assert_eq!(block.body().attestations_len(), 0);
    let sync_aggregate = block
        .body()
        .sync_aggregate()
        .expect("Electra sync aggregate");
    assert_eq!(sync_aggregate.sync_committee_bits.num_set_bits(), 0);
    assert!(sync_aggregate.sync_committee_signature.is_empty());
    assert_eq!(chain.head_snapshot().beacon_state.slot(), Slot::new(0));
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert_eq!(
        fixture.operational_events.testing_only_events(),
        vec![beacon_chain::PqOperationalEvent::ProposalStarted {
            slot: Slot::new(1),
            parent_root: genesis_root,
        }],
        "production emits only after RANDAO and the late parent/slot check",
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn actual_block_production_selects_one_retained_authentic_pq_attestation_before_payload() {
    const PASSWORD: &[u8] = b"retained PQ block candidate";

    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let runtime = task_executor::test_utils::TestRuntime::default();
    let temporary_directory = tempfile::TempDir::new().expect("selection fixture directory");
    let spec = Arc::new(electra_spec());
    let provisional_validators = (1..=16)
        .map(|byte| state_processing::DirectGenesisValidator {
            public_key: PqPublicKey::deserialize(&[byte; 32])
                .expect("canonical provisional public key"),
            withdrawal_credentials: Hash256::ZERO,
        })
        .collect::<Vec<_>>();
    let mut provisional =
        state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
            Hash256::ZERO,
            0,
            provisional_validators,
            None,
            &spec,
        )
        .expect("provisional direct PQ genesis");
    provisional
        .build_all_committee_caches(&spec)
        .expect("provisional committee caches");
    let proposer_index = provisional
        .get_beacon_proposer_index(Slot::new(2), &spec)
        .expect("slot-two proposer");
    let slot_one_committee = provisional
        .get_beacon_committee(Slot::new(1), 0)
        .expect("slot-one committee");
    let attester_index = *slot_one_committee
        .committee
        .iter()
        .find(|index| **index != proposer_index)
        .expect("slot-one attester distinct from slot-two proposer");
    let late_attester_index = *slot_one_committee
        .committee
        .iter()
        .find(|index| **index != attester_index)
        .expect("second disjoint slot-one attester");

    let maximum_leaf = [
        OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::Attestation)
            .expect("slot-one attestation leaf")
            .as_u32(),
        OneTimeUseId::for_lean_pq_devnet_v1(2, SigningDuty::RandaoReveal)
            .expect("slot-two RANDAO leaf")
            .as_u32(),
        OneTimeUseId::for_lean_pq_devnet_v1(2, SigningDuty::BeaconBlockProposal)
            .expect("slot-two block-proposal leaf")
            .as_u32(),
    ]
    .into_iter()
    .max()
    .expect("nonempty one-time-use range");
    let proposer_keystore = PqKeystore::from_seed([0xc1; 32], 0..=maximum_leaf, PASSWORD)
        .expect("slot-two proposer keystore");
    let attester_keystore = PqKeystore::from_seed([0xc2; 32], 0..=maximum_leaf, PASSWORD)
        .expect("slot-one attester keystore");
    let late_attester_keystore = (late_attester_index != proposer_index)
        .then(|| PqKeystore::from_seed([0xc3; 32], 0..=maximum_leaf, PASSWORD))
        .transpose()
        .expect("late slot-one attester keystore");
    let proposer_authenticated = proposer_keystore
        .authenticate(PASSWORD)
        .expect("authenticated slot-two proposer");
    let attester_authenticated = attester_keystore
        .authenticate(PASSWORD)
        .expect("authenticated slot-one attester");
    let late_attester_authenticated = late_attester_keystore
        .as_ref()
        .map(|keystore| keystore.authenticate(PASSWORD))
        .transpose()
        .expect("authenticated late slot-one attester");
    let mut final_validators = (1..=16)
        .map(|byte| state_processing::DirectGenesisValidator {
            public_key: PqPublicKey::deserialize(&[byte; 32]).expect("canonical final public key"),
            withdrawal_credentials: Hash256::ZERO,
        })
        .collect::<Vec<_>>();
    final_validators[proposer_index].public_key = *proposer_authenticated.public_key();
    final_validators[attester_index].public_key = *attester_authenticated.public_key();
    if let Some(authenticated) = &late_attester_authenticated {
        final_validators[late_attester_index].public_key = *authenticated.public_key();
    }
    let mut genesis = state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        final_validators,
        None,
        &spec,
    )
    .expect("final direct PQ genesis");
    genesis
        .build_all_committee_caches(&spec)
        .expect("final committee caches");
    assert_eq!(
        genesis
            .get_beacon_proposer_index(Slot::new(2), &spec)
            .expect("final slot-two proposer"),
        proposer_index,
        "supplying final keys must not change the specialized proposer",
    );
    assert!(
        genesis
            .get_beacon_committee(Slot::new(1), 0)
            .expect("final slot-one committee")
            .committee
            .contains(&attester_index),
        "supplying final keys must preserve the specialized attester",
    );
    assert!(
        genesis
            .get_beacon_committee(Slot::new(1), 0)
            .expect("final slot-one committee")
            .committee
            .contains(&late_attester_index),
        "supplying final keys must preserve the second specialized attester",
    );
    let validators_root = genesis.genesis_validators_root().0;
    let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
    let mut authenticated_keys = vec![proposer_authenticated, attester_authenticated];
    if let Some(authenticated) = late_attester_authenticated {
        authenticated_keys.push(authenticated);
    }
    provision_usage_journal(&journal_path, validators_root, &authenticated_keys)
        .expect("selection usage journal");
    let mut key_unlocks = vec![
        PqKeyUnlock::new(proposer_keystore, PASSWORD).expect("slot-two proposer unlock"),
        PqKeyUnlock::new(attester_keystore, PASSWORD).expect("slot-one attester unlock"),
    ];
    if let Some(keystore) = late_attester_keystore {
        key_unlocks
            .push(PqKeyUnlock::new(keystore, PASSWORD).expect("late slot-one attester unlock"));
    }
    let authority = PqSigningAuthority::open(&journal_path, validators_root, key_unlocks)
        .expect("selection signing authority");
    let execution = Arc::new(RecordingExecution {
        new_payload_calls: AtomicUsize::new(0),
        new_payload_responses: Mutex::new(VecDeque::new()),
        stall_new_payload: AtomicBool::new(false),
        new_payload_release: tokio::sync::Semaphore::new(0),
        forkchoice_calls: AtomicUsize::new(0),
        forkchoice_responses: Mutex::new(VecDeque::new()),
        stall_forkchoice: AtomicBool::new(false),
        forkchoice_release: tokio::sync::Semaphore::new(0),
        payload_calls: AtomicUsize::new(0),
        stall_payload: AtomicBool::new(false),
        omit_payload_bundle: AtomicBool::new(false),
        invalid_payload_block_hash: AtomicBool::new(false),
        nonzero_blob_gas: AtomicBool::new(false),
        payload_release: tokio::sync::Semaphore::new(0),
    });
    let aggregation_service =
        Arc::new(AggregationService::new().expect("one process aggregation service"));
    let chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis)
            .expect("persist specialized genesis")
            .pq_aggregation_service(Arc::clone(&aggregation_service))
            .task_executor(runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(execution.clone())
            .build()
            .expect("specialized selection chain"),
    );
    chain.slot_clock.set_slot(2);
    let genesis_head = chain.head_snapshot();
    let genesis_root = genesis_head.beacon_block_root;
    let genesis_finalized_checkpoint = genesis_head.beacon_state.finalized_checkpoint().clone();
    let mut advanced_state = chain.head_snapshot().beacon_state.clone();
    while advanced_state.slot() < Slot::new(2) {
        state_processing::per_slot_processing_pq(&mut advanced_state, &spec)
            .expect("advance exact block-production state");
    }
    let attestation_data = AttestationData {
        slot: Slot::new(1),
        index: 0,
        beacon_block_root: genesis_root,
        source: Checkpoint::default(),
        target: Checkpoint {
            epoch: Epoch::new(0),
            root: genesis_root,
        },
    };
    let attestation_domain = spec.get_domain(
        Epoch::new(0),
        Domain::BeaconAttester,
        &advanced_state.fork(),
        advanced_state.genesis_validators_root(),
    );
    let attester_public_key = advanced_state
        .validators()
        .get(attester_index)
        .expect("final attester validator")
        .pubkey;
    let attestation_signature = authority
        .signer(&attester_public_key)
        .expect("bound attester signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            attestation_data.signing_root(attestation_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::Attestation)
                .expect("slot-one attestation leaf"),
        ))
        .expect("journal-backed slot-one attestation");
    let late_attester_public_key = advanced_state
        .validators()
        .get(late_attester_index)
        .expect("final late attester validator")
        .pubkey;
    let late_attestation_signature = authority
        .signer(&late_attester_public_key)
        .expect("bound late attester signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            attestation_data.signing_root(attestation_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::Attestation)
                .expect("late slot-one attestation leaf"),
        ))
        .expect("journal-backed late slot-one attestation");
    let prepared = state_processing::prepare_pq_single_attestation(
        &advanced_state,
        &chain.pq_validator_key_cache,
        SingleAttestation {
            committee_index: 0,
            attester_index: u64::try_from(attester_index).expect("bounded attester index"),
            data: attestation_data.clone(),
            signature: (&attestation_signature).into(),
        },
        &spec,
    )
    .expect("prepare exact retained raw single");
    let late_prepared = state_processing::prepare_pq_single_attestation(
        &advanced_state,
        &chain.pq_validator_key_cache,
        SingleAttestation {
            committee_index: 0,
            attester_index: u64::try_from(late_attester_index)
                .expect("bounded late attester index"),
            data: attestation_data,
            signature: (&late_attestation_signature).into(),
        },
        &spec,
    )
    .expect("prepare exact late retained raw single");
    let (verified_candidate, late_verified_candidate) = tokio::join!(
        prepared.verify(&aggregation_service),
        late_prepared.verify(&aggregation_service),
    );
    let (_, verified_candidate) = verified_candidate
        .expect("authenticate exact retained raw single")
        .into_parts();
    let (_, late_verified_candidate) = late_verified_candidate
        .expect("authenticate exact late retained raw single")
        .into_parts();
    assert_eq!(
        state_processing::validate_pq_attestation_for_block_selection(
            &advanced_state,
            &chain.pq_validator_key_cache,
            &verified_candidate,
            &spec,
        ),
        Ok(true),
        "the sealed candidate remains authoritative for its original state",
    );
    let mut changed_key_state = advanced_state.clone();
    let changed_key_index = (0..changed_key_state.validators().len())
        .find(|index| *index != attester_index)
        .expect("a distinct changed-context validator");
    let attester_state_b_pubkey = changed_key_state
        .validators()
        .get(changed_key_index)
        .expect("state-B source validator")
        .pubkey;
    let changed_state_b_pubkey = changed_key_state
        .validators()
        .get(attester_index)
        .expect("state-B attester validator")
        .pubkey;
    changed_key_state
        .validators_mut()
        .get_mut(attester_index)
        .expect("state-B attester validator")
        .pubkey = attester_state_b_pubkey;
    changed_key_state
        .validators_mut()
        .get_mut(changed_key_index)
        .expect("state-B changed-context validator")
        .pubkey = changed_state_b_pubkey;
    let changed_key_cache = state_processing::PqValidatorKeyCache::from_state(&changed_key_state)
        .expect("synthetic state-B matching PQ key cache");
    assert_eq!(
        state_processing::validate_pq_attestation_for_block_selection(
            &changed_key_state,
            &changed_key_cache,
            &verified_candidate,
            &spec,
        ),
        Ok(false),
        "a synthetic state-B key context skips a state-A sealed token",
    );
    assert_eq!(
        state_processing::validate_pq_attestation_for_block_selection(
            &advanced_state,
            &chain.pq_validator_key_cache,
            &verified_candidate,
            &spec,
        ),
        Ok(true),
        "synthetic state-B validation must not consume or corrupt the state-A candidate",
    );
    assert_eq!(
        state_processing::validate_pq_attestation_for_block_selection(
            &advanced_state,
            &chain.pq_validator_key_cache,
            &late_verified_candidate,
            &spec,
        ),
        Ok(true),
        "the held late candidate is independently authoritative for state A",
    );
    let expected_attestation = verified_candidate.attestation().clone();
    let late_expected_attestation = late_verified_candidate.attestation().clone();
    chain
        .testing_only_insert_pq_attestation_pool_candidate(verified_candidate)
        .expect("move sealed candidate into the chain-owned pool");
    let retained_snapshot = chain.testing_only_pq_attestation_pool_snapshot();
    assert_eq!(retained_snapshot.candidate_count, 1);
    assert_eq!(
        retained_snapshot.candidate_signer_sets,
        vec![vec![
            u64::try_from(attester_index).expect("bounded attester index")
        ]],
    );

    let post_selection = TestingPqBlockingHook::blocking();
    struct ReleasePostSelectionHook(Option<Arc<TestingPqBlockingHook>>);

    impl ReleasePostSelectionHook {
        fn release(&mut self) {
            if let Some(hook) = self.0.take() {
                hook.release();
            }
        }
    }

    impl Drop for ReleasePostSelectionHook {
        fn drop(&mut self) {
            self.release();
        }
    }

    let mut release_post_selection = ReleasePostSelectionHook(Some(Arc::clone(&post_selection)));
    chain.testing_only_set_pq_attestation_pool_post_selection_hook(Some(Arc::clone(
        &post_selection,
    )));
    let randao_domain = spec.get_domain(
        advanced_state.current_epoch(),
        Domain::Randao,
        &advanced_state.fork(),
        advanced_state.genesis_validators_root(),
    );
    let proposer_public_key = advanced_state
        .validators()
        .get(proposer_index)
        .expect("final proposer validator")
        .pubkey;
    let randao = authority
        .signer(&proposer_public_key)
        .expect("bound proposer signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            advanced_state.current_epoch().signing_root(randao_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(2, SigningDuty::RandaoReveal)
                .expect("slot-two RANDAO leaf"),
        ))
        .expect("journal-backed slot-two RANDAO");
    let producing_chain = Arc::clone(&chain);
    let first_randao = randao.clone();
    let production = tokio::spawn(async move {
        producing_chain
            .produce_pq_block_v3(Slot::new(2), first_randao, Graffiti::default())
            .await
    });
    let reached_post_selection = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            if post_selection.entered() == 1 {
                break true;
            }
            if production.is_finished() {
                break false;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    match reached_post_selection {
        Ok(true) => {}
        Ok(false) => {
            panic!("actual production completed before the post-selection barrier");
        }
        Err(error) => {
            panic!("actual production did not reach the post-selection barrier: {error}");
        }
    }
    let payload_calls_before_release = execution.payload_calls.load(Ordering::SeqCst);
    let late_insertion = {
        let chain = Arc::clone(&chain);
        tokio::task::spawn_blocking(move || {
            chain.testing_only_insert_pq_attestation_pool_candidate(late_verified_candidate)
        })
    };
    tokio::time::timeout(Duration::from_secs(5), late_insertion)
        .await
        .expect("late insertion cannot remain blocked behind the immutable selection")
        .expect("late insertion blocking task")
        .expect("insert late sealed candidate after the production snapshot");
    let blocked_snapshot = {
        let chain = Arc::clone(&chain);
        tokio::task::spawn_blocking(move || chain.testing_only_pq_attestation_pool_snapshot())
    };
    let snapshot_before_release =
        tokio::time::timeout(Duration::from_secs(5), blocked_snapshot).await;
    release_post_selection.release();
    assert_eq!(
        payload_calls_before_release, 0,
        "authoritative attestation selection must finish before getPayload",
    );
    let retained_after_late_insert = snapshot_before_release
        .expect("pool snapshot cannot be locked behind the post-selection hook")
        .expect("pool snapshot blocking task");
    assert_eq!(retained_after_late_insert.candidate_count, 2);
    let mut expected_signer_sets = vec![
        vec![u64::try_from(attester_index).expect("bounded attester index")],
        vec![u64::try_from(late_attester_index).expect("bounded late attester index")],
    ];
    expected_signer_sets.sort_unstable();
    assert_eq!(
        retained_after_late_insert.candidate_signer_sets, expected_signer_sets,
        "the off-loop pool snapshot must see both retained disjoint candidates",
    );
    let produced = production
        .await
        .expect("slot-two production task")
        .expect("slot-two production with one retained candidate");
    let block = produced.contents().block();
    assert_eq!(block.body().attestations_len(), 1);
    assert_eq!(
        block
            .body()
            .attestations()
            .next()
            .expect("one selected attestation")
            .clone_as_attestation(),
        expected_attestation,
        "the block must contain the exact authenticated pool bytes",
    );
    assert_ne!(
        expected_attestation, late_expected_attestation,
        "the late candidate must carry a distinct signer and exact signature bytes",
    );
    assert_eq!(execution.payload_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        chain.testing_only_pq_attestation_pool_snapshot(),
        retained_after_late_insert,
        "production consumes its immutable A-only selection while the pool retains A and late B",
    );

    chain.testing_only_set_pq_attestation_pool_post_selection_hook(None);
    execution
        .invalid_payload_block_hash
        .store(true, Ordering::SeqCst);
    let error = tokio::time::timeout(
        Duration::from_secs(180),
        chain.produce_pq_block_v3(Slot::new(2), randao.clone(), Graffiti::default()),
    )
    .await
    .expect("populated-pool payload-failure production must complete")
    .expect_err("invalid payload block hash must reject slot-two production");
    assert!(error.is_retryable());
    assert!(matches!(
        error,
        PqBlockProductionError::Local(PqBlockProductionLocalError::Execution(
            execution_layer::Error::BlockHashMismatch { .. }
        ))
    ));
    assert_eq!(execution.payload_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        chain.testing_only_pq_attestation_pool_snapshot(),
        retained_after_late_insert,
        "payload failure must leave the exact populated pool snapshot retryable",
    );

    execution
        .invalid_payload_block_hash
        .store(false, Ordering::SeqCst);
    let produced = tokio::time::timeout(
        Duration::from_secs(180),
        chain.produce_pq_block_v3(Slot::new(2), randao, Graffiti::default()),
    )
    .await
    .expect("populated-pool payload retry must complete")
    .expect("slot-two retry with both retained candidates");
    let (block, sidecars) = produced.into_contents().deconstruct();
    let (proofs, blobs) = sidecars.expect("Electra V3 has explicit empty sidecars");
    assert!(proofs.is_empty());
    assert!(blobs.is_empty());
    assert_eq!(block.body().attestations_len(), 2);
    let mut expected_canonical_attestations = vec![
        (attester_index, expected_attestation.clone()),
        (late_attester_index, late_expected_attestation.clone()),
    ];
    expected_canonical_attestations.sort_unstable_by_key(|(signer_index, _)| *signer_index);
    let expected_canonical_bytes = expected_canonical_attestations
        .iter()
        .map(|(_, attestation)| attestation.as_ssz_bytes())
        .collect::<Vec<_>>();
    assert_eq!(
        block
            .body()
            .attestations()
            .map(|attestation| attestation.clone_as_attestation().as_ssz_bytes())
            .collect::<Vec<_>>(),
        expected_canonical_bytes,
        "the retry must contain both exact authenticated candidates in canonical order",
    );
    assert_eq!(execution.payload_calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        chain.testing_only_pq_attestation_pool_snapshot(),
        retained_after_late_insert,
        "successful retry must leave the exact populated pool snapshot unchanged",
    );

    let signed = sign_pq_block_for_slot(&authority, &advanced_state, block, &spec);
    let signed_root = signed.canonical_root();
    let outcome = tokio::time::timeout(
        Duration::from_secs(180),
        PqNetworkBlockProcessor::new(Arc::clone(&chain)).import_rpc_block(Arc::clone(&signed)),
    )
    .await
    .expect("sealed RPC import must complete")
    .expect("sealed RPC import of the exact selected block");
    assert_eq!(outcome.source, beacon_chain::PqBlockImportSource::Rpc);
    assert_eq!(outcome.block_root, signed_root);
    assert_eq!(execution.new_payload_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execution.forkchoice_calls.load(Ordering::SeqCst), 1);

    let canonical_head = chain.head_snapshot();
    assert_eq!(canonical_head.beacon_block_root, signed_root);
    assert_eq!(canonical_head.beacon_state.slot(), Slot::new(2));
    let mut expected_current_participation =
        vec![0u8; canonical_head.beacon_state.validators().len()];
    *expected_current_participation
        .get_mut(attester_index)
        .expect("selected attester participation index") = 0b111;
    *expected_current_participation
        .get_mut(late_attester_index)
        .expect("selected late attester participation index") = 0b111;
    assert_eq!(
        canonical_head
            .beacon_state
            .current_epoch_participation()
            .expect("Electra current-epoch participation")
            .iter()
            .map(|flags| flags.into_u8())
            .collect::<Vec<_>>(),
        expected_current_participation,
    );
    assert_eq!(
        canonical_head
            .beacon_state
            .previous_epoch_participation()
            .expect("Electra previous-epoch participation")
            .iter()
            .map(|flags| flags.into_u8())
            .collect::<Vec<_>>(),
        vec![0u8; canonical_head.beacon_state.validators().len()],
    );
    assert_eq!(
        canonical_head.beacon_state.finalized_checkpoint(),
        genesis_finalized_checkpoint,
    );
}

#[cfg(target_feature = "avx2")]
fn advance_pq_state_to_slot(
    mut state: BeaconState<MinimalEthSpec>,
    slot: Slot,
    spec: &types::ChainSpec,
) -> BeaconState<MinimalEthSpec> {
    while state.slot() < slot {
        state_processing::per_slot_processing_pq(&mut state, spec)
            .expect("bounded PQ proposal-state advance");
    }
    state
}

#[cfg(target_feature = "avx2")]
fn sign_pq_randao_for_slot(
    authority: &PqSigningAuthority,
    state: &BeaconState<MinimalEthSpec>,
    slot: Slot,
    spec: &types::ChainSpec,
) -> PqRawSignature {
    let proposer_index = state
        .get_beacon_proposer_index(slot, spec)
        .expect("PQ proposer index");
    let proposer_public_key = state
        .validators()
        .get(proposer_index)
        .expect("PQ proposer validator")
        .pubkey;
    let randao_domain = spec.get_domain(
        state.current_epoch(),
        Domain::Randao,
        &state.fork(),
        state.genesis_validators_root(),
    );
    authority
        .signer(&proposer_public_key)
        .expect("bound PQ proposer signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            state.current_epoch().signing_root(randao_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(slot.as_u64(), SigningDuty::RandaoReveal)
                .expect("slot-bound PQ RANDAO leaf"),
        ))
        .expect("PQ RANDAO signature")
}

#[cfg(target_feature = "avx2")]
fn sign_pq_block_for_slot(
    authority: &PqSigningAuthority,
    state: &BeaconState<MinimalEthSpec>,
    block: BeaconBlock<MinimalEthSpec>,
    spec: &types::ChainSpec,
) -> Arc<SignedBeaconBlock<MinimalEthSpec>> {
    let proposer_public_key = state
        .validators()
        .get(block.proposer_index() as usize)
        .expect("PQ block proposer validator")
        .pubkey;
    let proposal_domain = spec.get_domain(
        state.current_epoch(),
        Domain::BeaconProposer,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let signature = authority
        .signer(&proposer_public_key)
        .expect("bound PQ block signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            block.signing_root(proposal_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(
                block.slot().as_u64(),
                SigningDuty::BeaconBlockProposal,
            )
            .expect("slot-bound PQ proposal leaf"),
        ))
        .expect("PQ proposal signature");
    Arc::new(SignedBeaconBlock::from_block(block, signature))
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn consecutive_imports_reconcile_two_independent_stateful_execution_engines() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    const PASSWORD: &[u8] = b"independent execution reconciliation";
    let runtime = task_executor::test_utils::TestRuntime::default();
    let temporary_directory = tempfile::TempDir::new().expect("reconciliation fixture directory");
    let spec = Arc::new(electra_spec());
    let publisher_execution =
        execution_layer::test_utils::MockExecutionLayer::<MinimalEthSpec>::new(
            runtime.task_executor.clone(),
            Some(0),
            Some(0),
            Some(0),
            None,
            None,
            Some(
                execution_layer::auth::JwtKey::from_slice(
                    &execution_layer::test_utils::DEFAULT_JWT_SECRET,
                )
                .expect("publisher MockEngine JWT"),
            ),
            Arc::clone(&spec),
            None,
        );
    let receiver_execution = execution_layer::test_utils::MockExecutionLayer::<MinimalEthSpec>::new(
        runtime.task_executor.clone(),
        Some(0),
        Some(0),
        Some(0),
        None,
        None,
        Some(
            execution_layer::auth::JwtKey::from_slice(
                &execution_layer::test_utils::DEFAULT_JWT_SECRET,
            )
            .expect("receiver MockEngine JWT"),
        ),
        Arc::clone(&spec),
        None,
    );
    let (genesis_execution_hash, genesis_execution_gas_limit) = {
        let mut publisher = publisher_execution.server.execution_block_generator();
        publisher.set_blob_count_range(0, 0);
        publisher.set_next_execution_requests(Default::default());
        let publisher_genesis = publisher.latest_block().expect("publisher EL genesis");
        let mut receiver = receiver_execution.server.execution_block_generator();
        receiver.set_blob_count_range(0, 0);
        receiver.set_next_execution_requests(Default::default());
        let receiver_genesis = receiver.latest_block().expect("receiver EL genesis");
        assert_eq!(
            publisher_genesis.block_hash(),
            receiver_genesis.block_hash()
        );
        assert_ne!(publisher_genesis.block_hash(), ExecutionBlockHash::zero());
        (
            publisher_genesis.block_hash(),
            publisher_genesis.gas_limit(),
        )
    };
    let receiver_forkchoice = Arc::new(Mutex::new(Vec::new()));
    let receiver_forkchoice_hook = Arc::clone(&receiver_forkchoice);
    receiver_execution
        .server
        .ctx
        .hook
        .lock()
        .set_forkchoice_updated_hook(Box::new(move |state, payload_attributes| {
            receiver_forkchoice_hook
                .lock()
                .expect("receiver FCU observation lock")
                .push((
                    execution_layer::ForkchoiceState::from(state),
                    payload_attributes.is_some(),
                ));
            None
        }));

    let mut genesis = state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16)
            .map(|byte| state_processing::DirectGenesisValidator {
                public_key: PqPublicKey::deserialize(&[byte; 32])
                    .expect("canonical synthetic public key"),
                withdrawal_credentials: Hash256::ZERO,
            })
            .collect(),
        None,
        &spec,
    )
    .expect("direct PQ reconciliation genesis");
    genesis
        .build_all_committee_caches(&spec)
        .expect("reconciliation genesis committee caches");
    let mut proposer_indices = [Slot::new(1), Slot::new(2)]
        .into_iter()
        .map(|slot| {
            let state = advance_pq_state_to_slot(genesis.clone(), slot, &spec);
            state
                .get_beacon_proposer_index(slot, &spec)
                .expect("two-slot proposer index")
        })
        .collect::<Vec<_>>();
    proposer_indices.sort_unstable();
    proposer_indices.dedup();
    let maximum_leaf = OneTimeUseId::for_lean_pq_devnet_v1(2, SigningDuty::BeaconBlockProposal)
        .expect("slot-two proposal leaf")
        .as_u32()
        .max(
            OneTimeUseId::for_lean_pq_devnet_v1(2, SigningDuty::RandaoReveal)
                .expect("slot-two RANDAO leaf")
                .as_u32(),
        );
    let mut keystores = Vec::with_capacity(proposer_indices.len());
    let mut authenticated = Vec::with_capacity(proposer_indices.len());
    for (offset, proposer_index) in proposer_indices.iter().copied().enumerate() {
        let seed_byte = u8::try_from(offset)
            .ok()
            .and_then(|offset| 0x80u8.checked_add(offset))
            .expect("bounded reconciliation seed byte");
        let keystore = PqKeystore::from_seed([seed_byte; 32], 0..=maximum_leaf, PASSWORD)
            .expect("two-slot proposer keystore");
        let metadata = keystore
            .authenticate(PASSWORD)
            .expect("two-slot proposer authentication");
        genesis
            .validators_mut()
            .get_mut(proposer_index)
            .expect("two-slot proposer validator")
            .pubkey = *metadata.public_key();
        keystores.push(keystore);
        authenticated.push(metadata);
    }
    let BeaconState::Electra(genesis_inner) = &mut genesis else {
        panic!("Electra reconciliation genesis")
    };
    genesis_inner.latest_execution_payload_header.block_hash = genesis_execution_hash;
    genesis_inner.latest_execution_payload_header.gas_limit = genesis_execution_gas_limit;
    let validators_root = genesis.genesis_validators_root().0;
    let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
    provision_usage_journal(&journal_path, validators_root, &authenticated)
        .expect("two-slot usage journal");
    let authority = PqSigningAuthority::open(
        &journal_path,
        validators_root,
        keystores
            .into_iter()
            .map(|keystore| PqKeyUnlock::new(keystore, PASSWORD).expect("two-slot proposer unlock"))
            .collect(),
    )
    .expect("two-slot signing authority");
    let aggregation_service = Arc::new(AggregationService::new().expect("aggregation service"));
    let publisher = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("publisher genesis")
            .pq_aggregation_service(Arc::clone(&aggregation_service))
            .pq_execution_layer(Arc::new(publisher_execution.el.clone()))
            .task_executor(runtime.task_executor.clone())
            .build()
            .expect("publisher chain"),
    );
    let receiver_store = exact_snapshot_store(Arc::clone(&spec));
    let mut receiver = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&receiver_store))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis)
            .expect("receiver genesis")
            .pq_aggregation_service(Arc::clone(&aggregation_service))
            .pq_execution_layer(Arc::new(receiver_execution.el.clone()))
            .task_executor(runtime.task_executor.clone())
            .build()
            .expect("receiver chain"),
    );
    receiver
        .reconcile_persisted_pq_head()
        .await
        .expect("startup reconciles the exact persisted genesis execution head");

    for slot_u64 in 1..=2 {
        let slot = Slot::new(slot_u64);
        publisher.slot_clock.set_slot(slot_u64);
        receiver.slot_clock.set_slot(slot_u64);
        let proposal_state =
            advance_pq_state_to_slot(publisher.head_snapshot().beacon_state.clone(), slot, &spec);
        let randao = sign_pq_randao_for_slot(&authority, &proposal_state, slot, &spec);
        let produced = publisher
            .produce_pq_block_v3(slot, randao, Graffiti::default())
            .await
            .expect("two-slot full block production");
        let (block, sidecars) = produced.into_contents().deconstruct();
        let (proofs, blobs) = sidecars.expect("Electra V3 empty sidecars");
        assert!(proofs.is_empty());
        assert!(blobs.is_empty());
        let signed = sign_pq_block_for_slot(&authority, &proposal_state, block, &spec);
        receiver_execution
            .el
            .insert_proposer(
                slot + 1,
                signed.canonical_root(),
                fork_choice::PayloadStatus::Full,
                0,
                execution_layer::PayloadAttributes::new(
                    1_000 + slot_u64,
                    Hash256::repeat_byte(0x5a),
                    Address::repeat_byte(0x6b),
                    Some(Default::default()),
                    Some(signed.canonical_root()),
                    None,
                    None,
                ),
            )
            .await;
        PqNetworkBlockProcessor::new(Arc::clone(&publisher))
            .import_rpc_block(Arc::clone(&signed))
            .await
            .expect("publisher imports consecutive block");
        if slot_u64 == 1 {
            receiver_execution
                .server
                .all_payloads_syncing_on_forkchoice_updated();
            assert!(matches!(
                PqNetworkBlockProcessor::new(Arc::clone(&receiver))
                    .import_rpc_block(Arc::clone(&signed))
                    .await,
                Err(beacon_chain::PqImportError::ExecutionReconciliation(
                    beacon_chain::PqExecutionReconciliationError::Unavailable { attempts: 3 }
                ))
            ));
            assert_eq!(
                receiver.head_snapshot().beacon_block.as_ref(),
                signed.as_ref(),
                "DB/head publication remains authoritative after FCU exhaustion",
            );
            let mut tampered = receiver.head_snapshot().as_ref().clone();
            let BeaconState::Electra(tampered_state) = &mut tampered.beacon_state else {
                panic!("Electra durable head")
            };
            tampered_state.latest_execution_payload_header.block_hash =
                ExecutionBlockHash::repeat_byte(0x77);
            assert!(matches!(
                beacon_chain::testing_only_persisted_pq_execution_head(&tampered, Slot::new(0),),
                Err(beacon_chain::PqImportError::Local(
                    beacon_chain::PqImportLocalError::Persistence(
                        beacon_chain::PqRuntimeError::PersistedHeadBinding(
                            "block payload hash does not match post-state execution header"
                        )
                    )
                ))
            ));
            receiver_execution.server.full_payload_verification();
            receiver = Arc::new(
                BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
                    .store(Arc::clone(&receiver_store))
                    .custom_spec(Arc::clone(&spec))
                    .resume_from_db()
                    .expect("resume receiver after failed post-commit FCU")
                    .pq_aggregation_service(Arc::clone(&aggregation_service))
                    .pq_execution_layer(Arc::new(receiver_execution.el.clone()))
                    .task_executor(runtime.task_executor.clone())
                    .build()
                    .expect("rebuild receiver after failed post-commit FCU"),
            );
            receiver.slot_clock.set_slot(slot_u64);
            receiver
                .reconcile_persisted_pq_head()
                .await
                .expect("startup reconciles the exact durable slot-one head");
        } else {
            PqNetworkBlockProcessor::new(Arc::clone(&receiver))
                .import_rpc_block(Arc::clone(&signed))
                .await
                .expect("independent receiver imports slot two after startup reconciliation");
        }
        assert_eq!(
            publisher.head_snapshot().beacon_block.as_ref(),
            signed.as_ref()
        );
        assert_eq!(
            receiver.head_snapshot().beacon_block.as_ref(),
            signed.as_ref()
        );
    }

    let receiver_forkchoice = receiver_forkchoice
        .lock()
        .expect("receiver FCU observation lock");
    assert_eq!(receiver_forkchoice.len(), 6);
    assert!(
        receiver_forkchoice
            .iter()
            .all(|(_, has_attributes)| !has_attributes)
    );
    for (forkchoice, _) in receiver_forkchoice.iter() {
        assert_eq!(forkchoice.safe_block_hash, ExecutionBlockHash::zero());
        assert_eq!(forkchoice.finalized_block_hash, ExecutionBlockHash::zero());
    }
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_execution_layer_uses_exact_parent_local_payload_and_bypasses_builder() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    const PASSWORD: &[u8] = b"production execution layer fixture";
    const PROPOSER_GAS_LIMIT: u64 = 31_337_000;
    let fee_recipient = Address::repeat_byte(0x71);
    let graffiti = Graffiti([0x42; 32]);
    let runtime = task_executor::test_utils::TestRuntime::default();
    let temporary_directory = tempfile::TempDir::new().expect("temporary directory");
    let spec = Arc::new(electra_spec());
    let mock_execution = execution_layer::test_utils::MockExecutionLayer::<MinimalEthSpec>::new(
        runtime.task_executor.clone(),
        Some(0),
        Some(0),
        Some(0),
        None,
        None,
        Some(
            execution_layer::auth::JwtKey::from_slice(
                &execution_layer::test_utils::DEFAULT_JWT_SECRET,
            )
            .expect("default MockEngine JWT"),
        ),
        Arc::clone(&spec),
        None,
    );
    let (execution_parent_hash, execution_parent_gas_limit) = {
        let mut generator = mock_execution.server.execution_block_generator();
        generator.set_blob_count_range(0, 0);
        generator.set_next_execution_requests(Default::default());
        let parent = generator.latest_block().expect("MockEngine genesis block");
        (parent.block_hash(), parent.gas_limit())
    };

    let (mock_builder, (builder_address, builder_server)) =
        execution_layer::test_utils::MockBuilder::<MinimalEthSpec>::new_for_testing(
            mock_execution.server.url().parse().expect("MockEngine URL"),
            "http://127.0.0.1:1/"
                .parse()
                .expect("unused beacon-node URL"),
            false,
            true,
            false,
            Arc::clone(&spec),
            runtime.task_executor.clone(),
        );
    runtime
        .task_executor
        .spawn(builder_server, "pq-production-mock-builder");
    mock_execution
        .el
        .set_builder_url(
            format!("http://{builder_address}/")
                .parse()
                .expect("MockBuilder URL"),
            None,
            None,
            false,
        )
        .expect("install MockBuilder");

    let observed_fcu = Arc::new(Mutex::new(None));
    let observed_fcu_for_hook = Arc::clone(&observed_fcu);
    let forkchoice_calls = Arc::new(AtomicUsize::new(0));
    let forkchoice_calls_for_hook = Arc::clone(&forkchoice_calls);
    let payload_forkchoice_hook = TestingPqBlockingHook::blocking();
    let payload_forkchoice_hook_for_engine = Arc::clone(&payload_forkchoice_hook);
    mock_execution
        .server
        .ctx
        .hook
        .lock()
        .set_forkchoice_updated_hook(Box::new(move |state, payload_attributes| {
            forkchoice_calls_for_hook.fetch_add(1, Ordering::SeqCst);
            if payload_attributes.is_some() {
                *observed_fcu_for_hook.lock().expect("FCU observation lock") = Some((
                    execution_layer::ForkchoiceState::from(state),
                    payload_attributes.map(execution_layer::PayloadAttributes::from),
                ));
                payload_forkchoice_hook_for_engine.run();
            }
            None
        }));

    let mut genesis = state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16)
            .map(|byte| state_processing::DirectGenesisValidator {
                public_key: PqPublicKey::deserialize(&[byte; 32])
                    .expect("canonical synthetic public key"),
                withdrawal_credentials: Hash256::ZERO,
            })
            .collect(),
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    genesis
        .build_all_committee_caches(&spec)
        .expect("genesis committee caches");
    let proposer_index = genesis
        .get_beacon_proposer_index(Slot::new(1), &spec)
        .expect("slot-one proposer");
    let maximum_leaf = OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::BeaconBlockProposal)
        .expect("slot-one proposal leaf")
        .as_u32();
    let proposer_keystore =
        PqKeystore::from_seed([0x3c; 32], 0..=maximum_leaf, PASSWORD).expect("fixture keystore");
    let authenticated = proposer_keystore
        .authenticate(PASSWORD)
        .expect("authenticated proposer key");
    genesis
        .validators_mut()
        .get_mut(proposer_index)
        .expect("proposer validator")
        .pubkey = *authenticated.public_key();
    let BeaconState::Electra(genesis_inner) = &mut genesis else {
        panic!("Electra genesis")
    };
    genesis_inner.latest_execution_payload_header.block_hash = execution_parent_hash;
    genesis_inner.latest_execution_payload_header.gas_limit = execution_parent_gas_limit;
    let validators_root = genesis.genesis_validators_root().0;
    let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
    provision_usage_journal(&journal_path, validators_root, &[authenticated])
        .expect("usage journal");
    let authority = PqSigningAuthority::open(
        &journal_path,
        validators_root,
        vec![PqKeyUnlock::new(proposer_keystore, PASSWORD).expect("proposer unlock")],
    )
    .expect("signing authority");

    let observed_request: Arc<Mutex<Option<TestingPqPayloadBuildObservation<MinimalEthSpec>>>> =
        Arc::new(Mutex::new(None));
    let observed_request_for_hook = Arc::clone(&observed_request);
    let chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist genesis")
            .pq_aggregation_service(Arc::new(
                AggregationService::new().expect("PQ aggregation service"),
            ))
            .task_executor(runtime.task_executor.clone())
            .pq_execution_layer(Arc::new(mock_execution.el.clone()))
            .testing_only_pq_production_payload_observer(Arc::new(move |observation| {
                assert_eq!(
                    observation.current_fork(),
                    ForkName::Electra,
                    "observer must report the actual PayloadParameters current_fork",
                );
                *observed_request_for_hook
                    .lock()
                    .expect("payload observation lock") = Some(observation);
            }))
            .expect("production payload observer")
            .build()
            .expect("PQ chain with production ExecutionLayer"),
    );
    chain.slot_clock.set_slot(1);
    let genesis_root = chain.head_snapshot().beacon_block_root;
    let proposer_data = ProposerPreparationData {
        validator_index: proposer_index as u64,
        fee_recipient,
    };
    let proposer_gas_limit = Some(PROPOSER_GAS_LIMIT);
    mock_execution
        .el
        .update_proposer_preparation(Epoch::new(0), [(&proposer_data, &proposer_gas_limit)])
        .await;

    let mut proposal_state = genesis;
    state_processing::per_slot_processing_pq(&mut proposal_state, &spec)
        .expect("advance proposal state");
    let randao_domain = spec.get_domain(
        proposal_state.current_epoch(),
        Domain::Randao,
        &proposal_state.fork(),
        proposal_state.genesis_validators_root(),
    );
    let proposer_public_key = proposal_state
        .validators()
        .get(proposer_index)
        .expect("proposer validator")
        .pubkey;
    let randao = authority
        .signer(&proposer_public_key)
        .expect("bound proposer signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            proposal_state.current_epoch().signing_root(randao_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::RandaoReveal).expect("RANDAO leaf"),
        ))
        .expect("RANDAO signature");

    let production_chain = Arc::clone(&chain);
    let production = tokio::spawn(async move {
        production_chain
            .produce_pq_block_v3(Slot::new(1), randao, graffiti)
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while payload_forkchoice_hook.entered() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("PQ getPayload reaches the real Engine while owning forkchoice");
    let reconciliation_chain = Arc::clone(&chain);
    let reconciliation =
        tokio::spawn(async move { reconciliation_chain.reconcile_persisted_pq_head().await });
    let heartbeat = tokio::spawn(async { tokio::task::yield_now().await });
    tokio::time::timeout(Duration::from_secs(5), heartbeat)
        .await
        .expect("async heartbeat remains live")
        .expect("heartbeat task");
    tokio::time::sleep(Duration::from_secs(1)).await;
    let request_while_payload_forkchoice_is_blocked = mock_execution
        .server
        .take_previous_request()
        .expect("blocked Engine request");
    let reconciliation_reached_engine = request_while_payload_forkchoice_is_blocked
        .pointer("/params/1")
        .is_some_and(serde_json::Value::is_null);
    payload_forkchoice_hook.release();
    assert!(
        !reconciliation_reached_engine,
        "startup reconciliation cannot reach the real Engine while PQ getPayload owns the lock"
    );
    reconciliation
        .await
        .expect("reconciliation task")
        .expect("reconciliation after getPayload releases forkchoice");
    let produced = production
        .await
        .expect("production task")
        .expect("production ExecutionLayer candidate");
    assert_eq!(forkchoice_calls.load(Ordering::SeqCst), 2);

    let observation = observed_request
        .lock()
        .expect("payload observation lock")
        .take()
        .expect("production payload request observed");
    assert_eq!(observation.proposer_index(), proposer_index as u64);
    assert_eq!(observation.parent_beacon_block_root(), genesis_root);
    assert_eq!(observation.parent_hash(), execution_parent_hash);
    assert_eq!(observation.parent_gas_limit(), execution_parent_gas_limit);
    assert_eq!(observation.proposer_gas_limit(), Some(PROPOSER_GAS_LIMIT));
    assert_eq!(observation.suggested_fee_recipient(), fee_recipient);
    assert_eq!(observation.current_fork(), ForkName::Electra);
    assert_eq!(observation.forkchoice_head_root(), genesis_root);
    assert_eq!(
        observation.forkchoice_head_hash(),
        Some(execution_parent_hash)
    );
    assert_eq!(observation.forkchoice_justified_hash(), None);
    assert_eq!(observation.forkchoice_finalized_hash(), None);

    let (forkchoice, payload_attributes) = observed_fcu
        .lock()
        .expect("FCU observation lock")
        .take()
        .expect("MockEngine FCU observed");
    assert_eq!(forkchoice.head_block_hash, execution_parent_hash);
    assert_eq!(forkchoice.safe_block_hash, ExecutionBlockHash::zero());
    assert_eq!(forkchoice.finalized_block_hash, ExecutionBlockHash::zero());
    let payload_attributes = payload_attributes.expect("FCU payload attributes");
    assert_eq!(payload_attributes.suggested_fee_recipient(), fee_recipient);
    assert_eq!(
        payload_attributes
            .parent_beacon_block_root()
            .expect("Electra parent beacon root"),
        genesis_root
    );
    assert_eq!(
        mock_execution
            .server
            .take_previous_request()
            .and_then(|request| request.get("method").cloned()),
        Some(serde_json::Value::String(
            "engine_forkchoiceUpdatedV3".to_owned()
        )),
        "the queued no-attributes reconciliation FCU follows the successful V4 payload response",
    );
    assert_eq!(mock_builder.get_header_call_count(), 0);

    let block = produced.contents().block();
    assert_eq!(*block.body().graffiti(), graffiti);
    let payload = block.body().execution_payload().expect("execution payload");
    assert_eq!(payload.fee_recipient(), fee_recipient);
    assert_eq!(
        produced.execution_payload_value(),
        types::Uint256::from(execution_layer::test_utils::DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI),
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn produced_block_can_be_proposal_signed_and_imported_through_the_sealed_rpc_path() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);

    let outcome = PqNetworkBlockProcessor::new(Arc::clone(&fixture.chain))
        .import_rpc_block(Arc::clone(&signed))
        .await
        .expect("sealed RPC import");
    assert_eq!(outcome.source, beacon_chain::PqBlockImportSource::Rpc);
    assert_eq!(outcome.block_root, signed.canonical_root());
    assert_eq!(fixture.execution.payload_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_state.slot(),
        Slot::new(1)
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        signed.canonical_root()
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn produced_block_publication_broadcasts_exact_verified_block_before_import() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );
    let admission = publisher.try_admit().expect("publication admission");
    let signed_for_publish = Arc::clone(&signed);
    let publication = tokio::spawn(async move { admission.publish(signed_for_publish).await });

    let command = broadcast_receiver.recv().await.expect("broadcast command");
    assert!(Arc::ptr_eq(command.block(), &signed));
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0
    );
    command.acknowledge(Ok(()));

    let disposition = publication.await.expect("publication task");
    let PqBlockPublicationDisposition::Published(outcome) = disposition else {
        panic!("acknowledged valid block must publish and import")
    };
    assert_eq!(outcome.source, beacon_chain::PqBlockImportSource::Publish);
    assert_eq!(outcome.block_root, signed.canonical_root());
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    let block_root = signed.canonical_root();
    let signed_ssz_digest: [u8; 32] = Sha256::digest(signed.as_ssz_bytes()).into();
    let execution_hash = signed
        .message()
        .body()
        .execution_payload()
        .expect("published execution payload")
        .block_hash();
    assert_eq!(
        fixture.operational_events.testing_only_events(),
        vec![
            beacon_chain::PqOperationalEvent::ProposalStarted {
                slot: Slot::new(1),
                parent_root: fixture.genesis_root,
            },
            beacon_chain::PqOperationalEvent::BlockPersisted {
                source: beacon_chain::PqBlockEventSource::Publish,
                slot: Slot::new(1),
                block_root,
                execution_hash,
                finalized_epoch: fixture.genesis_checkpoint.epoch,
                finalized_root: fixture.genesis_checkpoint.root,
                signed_ssz_digest,
            },
            beacon_chain::PqOperationalEvent::ExecutionReconciled {
                source: beacon_chain::PqBlockEventSource::Publish,
                slot: Slot::new(1),
                block_root,
                execution_hash,
                finalized_epoch: fixture.genesis_checkpoint.epoch,
                finalized_root: fixture.genesis_checkpoint.root,
                signed_ssz_digest,
            },
            beacon_chain::PqOperationalEvent::ProposalPublished {
                slot: Slot::new(1),
                block_root,
                signed_ssz_digest,
            },
        ],
        "fresh publication events are exact and ordered",
    );

    let duplicate = publisher.try_admit().expect("duplicate admission");
    assert!(matches!(
        duplicate.publish(Arc::clone(&signed)).await,
        PqBlockPublicationDisposition::Committed,
    ));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(1),
            broadcast_receiver.recv(),
        )
        .await
        .is_err(),
        "a committed duplicate must not be broadcast again",
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture.operational_events.testing_only_events().len(),
        4,
        "a committed duplicate must not emit ProposalPublished again",
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn block_persisted_event_failure_still_reconciles_then_returns_fatal() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    let block_root = signed.canonical_root();
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );
    fixture.operational_events.testing_only_fail_closed();
    let admission = publisher.try_admit().expect("publication admission");
    let publication = tokio::spawn(async move { admission.publish(signed).await });
    broadcast_receiver
        .recv()
        .await
        .expect("broadcast command")
        .acknowledge(Ok(()));

    assert!(matches!(
        publication.await.expect("publication task"),
        PqBlockPublicationDisposition::Local(network::PqBlockPublicationLocalError::Import(
            PqImportError::OperationalEvent(beacon_chain::PqOperationalEventError::Closed)
        ))
    ));
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        block_root,
        "the atomic DB/head publication remains authoritative",
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(fixture.execution.forkchoice_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.operational_events.testing_only_events(),
        vec![beacon_chain::PqOperationalEvent::ProposalStarted {
            slot: Slot::new(1),
            parent_root: fixture.genesis_root,
        }],
        "failed BlockPersisted and later events are never misreported",
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn exact_cross_source_duplicates_coalesce_while_post_commit_forkchoice_is_pending() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let persistence = TestingPqBlockingHook::counting();
    let fixture = valid_production_fixture_with_hooks(
        false,
        false,
        None,
        Some(Arc::clone(&persistence)),
        None,
    );
    fixture
        .execution
        .stall_forkchoice
        .store(true, Ordering::SeqCst);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );
    let first = publisher.try_admit().expect("first admission");
    let first_block = Arc::clone(&signed);
    let first = tokio::spawn(async move { first.publish(first_block).await });
    broadcast_receiver
        .recv()
        .await
        .expect("first broadcast")
        .acknowledge(Ok(()));

    tokio::time::timeout(Duration::from_secs(180), async {
        while fixture.execution.forkchoice_calls.load(Ordering::SeqCst) != 1
            || fixture.chain.head_snapshot().beacon_block_root != signed.canonical_root()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("durable head reaches blocked post-commit forkchoice");
    assert!(!first.is_finished());
    assert_eq!(persistence.entered(), 1);

    let pending_publish = publisher
        .try_admit()
        .expect("pending duplicate admission")
        .publish(Arc::clone(&signed))
        .await;
    assert!(matches!(
        pending_publish,
        PqBlockPublicationDisposition::Pending
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(1), broadcast_receiver.recv())
            .await
            .is_err(),
        "pending exact duplicate must not rebroadcast",
    );
    assert!(matches!(
        PqNetworkBlockProcessor::new(Arc::clone(&fixture.chain))
            .verify_gossip_block(Arc::clone(&signed))
            .await,
        PqGossipBlockDisposition::IgnorePending
    ));
    let rpc_chain = Arc::clone(&fixture.chain);
    let rpc_block = Arc::clone(&signed);
    let rpc = tokio::spawn(async move {
        PqNetworkBlockProcessor::new(rpc_chain)
            .import_rpc_block(rpc_block)
            .await
    });
    tokio::task::yield_now().await;
    assert!(
        !rpc.is_finished(),
        "RPC duplicate coalesces on the shared FCU result"
    );
    assert_eq!(
        fixture.chain.testing_only_pq_import_available_permits(),
        0,
        "the pending exact RPC waiter retains the second chain import admission"
    );
    assert!(matches!(
        PqNetworkBlockProcessor::new(Arc::clone(&fixture.chain))
            .import_lookup_block(Arc::clone(&signed))
            .await,
        Err(PqImportError::Local(
            beacon_chain::PqImportLocalError::IngressCapacity
        ))
    ));
    rpc.abort();
    assert!(rpc.await.is_err(), "the pending RPC caller is canceled");
    tokio::time::timeout(Duration::from_secs(1), async {
        while fixture.chain.testing_only_pq_import_available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("canceling a pending waiter releases exactly its admission");

    let lookup_chain = Arc::clone(&fixture.chain);
    let lookup_block = Arc::clone(&signed);
    let lookup = tokio::spawn(async move {
        PqNetworkBlockProcessor::new(lookup_chain)
            .import_lookup_block(lookup_block)
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while fixture.chain.testing_only_pq_import_available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replacement pending lookup owns the released admission");
    let drain = {
        let chain = Arc::clone(&fixture.chain);
        tokio::spawn(async move { chain.close_and_drain_pq_imports().await })
    };
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert!(
        !drain.is_finished(),
        "shutdown drain accounts for the admitted pending lookup waiter"
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(fixture.execution.forkchoice_calls.load(Ordering::SeqCst), 1);
    assert_eq!(persistence.entered(), 1);

    fixture.execution.forkchoice_release.add_permits(1);
    assert!(matches!(
        first.await.expect("first publication"),
        PqBlockPublicationDisposition::Published(_)
    ));
    let lookup = lookup
        .await
        .expect("lookup duplicate task")
        .expect("lookup duplicate outcome");
    assert_eq!(lookup.source, beacon_chain::PqBlockImportSource::Lookup);
    assert_eq!(lookup.block_root, signed.canonical_root());
    drain.await.expect("chain import drain");
    assert!(matches!(
        publisher
            .try_admit()
            .expect("committed duplicate admission")
            .publish(Arc::clone(&signed))
            .await,
        PqBlockPublicationDisposition::Committed
    ));
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(fixture.execution.forkchoice_calls.load(Ordering::SeqCst), 1);
    assert_eq!(persistence.entered(), 1);
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn exact_cross_source_duplicates_share_terminal_post_commit_forkchoice_result() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let persistence = TestingPqBlockingHook::counting();
    let fixture = valid_production_fixture_with_hooks(
        false,
        false,
        None,
        Some(Arc::clone(&persistence)),
        None,
    );
    fixture.execution.set_forkchoice_responses([
        execution_layer::PayloadStatus::InvalidBlockHash {
            validation_error: Some("terminal reconciliation fixture".to_owned()),
        },
    ]);
    fixture
        .execution
        .stall_forkchoice
        .store(true, Ordering::SeqCst);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );
    let first = publisher.try_admit().expect("first admission");
    let first_block = Arc::clone(&signed);
    let first = tokio::spawn(async move { first.publish(first_block).await });
    broadcast_receiver
        .recv()
        .await
        .expect("first broadcast")
        .acknowledge(Ok(()));
    tokio::time::timeout(Duration::from_secs(180), async {
        while fixture.execution.forkchoice_calls.load(Ordering::SeqCst) != 1
            || fixture.chain.head_snapshot().beacon_block_root != signed.canonical_root()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("durable head reaches blocked terminal forkchoice");

    assert!(matches!(
        publisher
            .try_admit()
            .expect("pending duplicate admission")
            .publish(Arc::clone(&signed))
            .await,
        PqBlockPublicationDisposition::Pending
    ));
    let rpc_chain = Arc::clone(&fixture.chain);
    let rpc_block = Arc::clone(&signed);
    let rpc = tokio::spawn(async move {
        PqNetworkBlockProcessor::new(rpc_chain)
            .import_rpc_block(rpc_block)
            .await
    });
    tokio::task::yield_now().await;
    assert!(!rpc.is_finished());
    fixture.execution.forkchoice_release.add_permits(1);

    assert!(matches!(
        first.await.expect("terminal publication"),
        PqBlockPublicationDisposition::Terminal(_)
    ));
    assert!(matches!(
        rpc.await.expect("terminal RPC task"),
        Err(PqImportError::TerminalObservation { block_root })
            if block_root == signed.canonical_root()
    ));
    assert!(matches!(
        PqNetworkBlockProcessor::new(Arc::clone(&fixture.chain))
            .verify_gossip_block(Arc::clone(&signed))
            .await,
        PqGossipBlockDisposition::IgnoreTerminal
    ));
    assert!(matches!(
        publisher
            .try_admit()
            .expect("terminal duplicate admission")
            .publish(Arc::clone(&signed))
            .await,
        PqBlockPublicationDisposition::Terminal(_)
    ));
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(fixture.execution.forkchoice_calls.load(Ordering::SeqCst), 1);
    assert_eq!(persistence.entered(), 1);
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn post_persist_join_loss_is_nonretryable_and_restart_recovers_exact_head() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let (executor_exit, executor_exit_receiver) = async_channel::bounded(1);
    let (shutdown_sender, mut shutdown_receiver) = futures::channel::mpsc::channel(1);
    let observed_executor = task_executor::TaskExecutor::new(
        tokio::runtime::Handle::current(),
        executor_exit_receiver,
        shutdown_sender,
    );
    let fixture = valid_production_fixture_with_hooks_spec_and_executor(
        false,
        false,
        None,
        None,
        None,
        electra_spec(),
        Some(observed_executor),
    );
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    let post_persist = TestingPqBlockingHook::panicking();
    fixture
        .chain
        .testing_only_set_pq_post_persist_hook(Arc::clone(&post_persist));

    let error = PqNetworkBlockProcessor::new(Arc::clone(&fixture.chain))
        .import_rpc_block(Arc::clone(&signed))
        .await
        .expect_err("post-persist panic cannot report an imported head");
    assert_eq!(post_persist.entered(), 1);
    assert!(matches!(
        error,
        PqImportError::DurableStateUnknown {
            phase: "pq-import-persist-and-publish"
        }
    ));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), shutdown_receiver.next())
            .await
            .expect("durable-state-unknown signals process shutdown"),
        Some(task_executor::ShutdownReason::Failure(
            "PQ execution reconciliation failed"
        ))
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        fixture.genesis_root,
        "panic before the memory swap leaves the live head unchanged"
    );
    assert!(matches!(
        PqNetworkBlockProcessor::new(Arc::clone(&fixture.chain))
            .import_rpc_block(Arc::clone(&signed))
            .await,
        Err(PqImportError::Local(
            beacon_chain::PqImportLocalError::Transport(execution_layer::Error::ShuttingDown)
        ))
    ));
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    let restarted = restart_independent_pq_chain(
        &fixture,
        Arc::clone(&fixture.store),
        Arc::clone(&fixture.execution),
    );
    assert_eq!(
        restarted.head_snapshot().beacon_block_root,
        signed.canonical_root()
    );
    assert_eq!(
        restarted.head_snapshot().beacon_block.as_ref(),
        signed.as_ref()
    );
    restarted
        .reconcile_persisted_pq_head()
        .await
        .expect("restart reconciles the exact durable head");
    drop(executor_exit);
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn post_broadcast_engine_retry_does_not_rebroadcast() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    fixture.execution.set_new_payload_responses([
        execution_layer::PayloadStatus::Syncing,
        execution_layer::PayloadStatus::Valid,
    ]);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );

    let first = publisher.try_admit().expect("first admission");
    let first_block = Arc::clone(&signed);
    let first = tokio::spawn(async move { first.publish(first_block).await });
    broadcast_receiver
        .recv()
        .await
        .expect("first broadcast")
        .acknowledge(Ok(()));
    assert!(matches!(
        first.await.expect("first publication"),
        PqBlockPublicationDisposition::Local(_)
    ));

    let second = publisher.try_admit().expect("retry admission");
    let disposition = second.publish(Arc::clone(&signed)).await;
    assert!(matches!(
        disposition,
        PqBlockPublicationDisposition::Published(_)
    ));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(1),
            broadcast_receiver.recv(),
        )
        .await
        .is_err(),
        "post-broadcast retry must not enqueue a second broadcast",
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        2
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn dropped_and_rejected_broadcasts_retry_propagation() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );

    let first = publisher.try_admit().expect("first admission");
    let first_block = Arc::clone(&signed);
    let first = tokio::spawn(async move { first.publish(first_block).await });
    drop(broadcast_receiver.recv().await.expect("first broadcast"));
    assert!(matches!(
        first.await.expect("failed publication"),
        PqBlockPublicationDisposition::Local(_)
    ));
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0
    );

    let rejected = publisher.try_admit().expect("rejected retry admission");
    let rejected_block = Arc::clone(&signed);
    let rejected = tokio::spawn(async move { rejected.publish(rejected_block).await });
    broadcast_receiver
        .recv()
        .await
        .expect("rejected retry broadcast")
        .acknowledge(Err(network::PqBlockBroadcastError::Rejected));
    assert!(matches!(
        rejected.await.expect("rejected publication"),
        PqBlockPublicationDisposition::Local(_)
    ));
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0
    );

    let retry = publisher.try_admit().expect("successful retry admission");
    let retry_block = Arc::clone(&signed);
    let retry = tokio::spawn(async move { retry.publish(retry_block).await });
    broadcast_receiver
        .recv()
        .await
        .expect("successful retry broadcast")
        .acknowledge(Ok(()));
    assert!(matches!(
        retry.await.expect("retried publication"),
        PqBlockPublicationDisposition::Published(_)
    ));
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn engine_invalid_publication_is_terminal_and_never_rebroadcast() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    fixture.execution.set_new_payload_responses([
        execution_layer::PayloadStatus::InvalidBlockHash {
            validation_error: Some("terminal publication fixture".to_owned()),
        },
    ]);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );

    let first = publisher.try_admit().expect("first admission");
    let first_block = Arc::clone(&signed);
    let first = tokio::spawn(async move { first.publish(first_block).await });
    broadcast_receiver
        .recv()
        .await
        .expect("first broadcast")
        .acknowledge(Ok(()));
    assert!(matches!(
        first.await.expect("terminal publication"),
        PqBlockPublicationDisposition::Terminal(network::PqBlockPublicationTerminal::Rejected)
    ));

    let duplicate = publisher.try_admit().expect("terminal duplicate admission");
    assert!(matches!(
        duplicate.publish(Arc::clone(&signed)).await,
        PqBlockPublicationDisposition::Terminal(network::PqBlockPublicationTerminal::Rejected)
    ));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(1),
            broadcast_receiver.recv(),
        )
        .await
        .is_err(),
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn canceled_publication_waiter_does_not_cancel_broadcast_or_commit() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    fixture
        .execution
        .stall_new_payload
        .store(true, Ordering::SeqCst);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );

    let first = publisher.try_admit().expect("first admission");
    let first_block = Arc::clone(&signed);
    let waiter = tokio::spawn(async move { first.publish(first_block).await });
    let command = broadcast_receiver.recv().await.expect("broadcast command");
    assert!(Arc::ptr_eq(command.block(), &signed));

    let duplicate = publisher.try_admit().expect("pending duplicate admission");
    assert!(matches!(
        duplicate.publish(Arc::clone(&signed)).await,
        PqBlockPublicationDisposition::Pending
    ));
    let second = publisher.try_admit().expect("second exact admission");
    assert_eq!(publisher.testing_only_available_admission_permits(), 0);
    assert!(matches!(
        publisher.try_admit(),
        Err(PqPublicationCapacity::Admission)
    ));
    waiter.abort();
    assert!(
        waiter
            .await
            .expect_err("publication waiter canceled")
            .is_cancelled()
    );
    assert_eq!(
        publisher.testing_only_available_admission_permits(),
        0,
        "the detached operation retains its admission after caller cancellation"
    );
    drop(second);
    assert_eq!(publisher.testing_only_available_admission_permits(), 1);

    command.acknowledge(Ok(()));
    tokio::time::timeout(std::time::Duration::from_secs(180), async {
        while fixture.execution.new_payload_calls.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached publication reaches the stalled Engine");
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        fixture.genesis_root
    );
    assert_eq!(
        publisher.testing_only_available_admission_permits(),
        1,
        "the detached operation retains admission while Engine is pending"
    );
    fixture.execution.new_payload_release.add_permits(1);
    for _ in 0..10_000 {
        if fixture.chain.head_snapshot().beacon_block_root == signed.canonical_root()
            && publisher.testing_only_available_admission_permits()
                == PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        signed.canonical_root(),
        "detached acknowledged publication commits after its waiter is dropped"
    );
    assert_eq!(
        publisher.testing_only_available_admission_permits(),
        PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    let restarted = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&fixture.store))
            .custom_spec(Arc::clone(&fixture.spec))
            .resume_from_db()
            .expect("resume detached publication")
            .pq_aggregation_service(Arc::clone(&fixture.aggregation_service))
            .task_executor(fixture._runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(fixture.execution.clone())
            .build()
            .expect("restart after detached publication"),
    );
    assert_eq!(
        restarted.head_snapshot().beacon_block_root,
        signed.canonical_root()
    );
    let (restart_broadcast, mut restart_receiver) = pq_block_broadcast_channel();
    let restart_publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&restarted),
            fixture._runtime.task_executor.clone(),
            restart_broadcast,
        )
        .expect("restart publication service"),
    );
    assert!(matches!(
        restart_publisher
            .try_admit()
            .expect("restart duplicate admission")
            .publish(Arc::clone(&signed))
            .await,
        PqBlockPublicationDisposition::Committed
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1), restart_receiver.recv(),)
            .await
            .is_err(),
        "an exact persisted-head duplicate must not rebroadcast"
    );

    let (message, _) = signed.as_ref().clone().deconstruct();
    let mutated_signature = Arc::new(SignedBeaconBlock::from_block(
        message,
        consensus_signature::IndividualSignature::empty(),
    ));
    assert_eq!(mutated_signature.canonical_root(), signed.canonical_root());
    assert_ne!(mutated_signature.as_ref(), signed.as_ref());
    assert!(
        !matches!(
            restart_publisher
                .try_admit()
                .expect("mutated-signature admission")
                .publish(mutated_signature)
                .await,
            PqBlockPublicationDisposition::Committed
        ),
        "message-root equality must not make a different proposal signature idempotent"
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn canceled_persistence_failure_retries_commit_without_rebroadcast() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let persistence_hook = TestingPqBlockingHook::blocking();
    let fixture = valid_production_fixture_with_hooks(
        false,
        false,
        None,
        Some(Arc::clone(&persistence_hook)),
        None,
    );
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    fixture
        .store
        .hot_db
        .fail_atomic_batch_containing(store::DBColumn::BeaconBlock);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );

    let first = publisher.try_admit().expect("first admission");
    let first_block = Arc::clone(&signed);
    let waiter = tokio::spawn(async move { first.publish(first_block).await });
    broadcast_receiver
        .recv()
        .await
        .expect("first broadcast")
        .acknowledge(Ok(()));
    for _ in 0..10_000 {
        if persistence_hook.entered() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        persistence_hook.entered(),
        1,
        "post-VALID persistence barrier"
    );
    waiter.abort();
    assert!(
        waiter
            .await
            .expect_err("publication waiter canceled")
            .is_cancelled()
    );
    assert_eq!(publisher.testing_only_available_admission_permits(), 1);
    let second = publisher.try_admit().expect("second exact admission");
    assert!(matches!(
        publisher.try_admit(),
        Err(PqPublicationCapacity::Admission)
    ));
    drop(second);
    persistence_hook.release();
    for _ in 0..10_000 {
        if publisher.testing_only_available_admission_permits()
            == PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        publisher.testing_only_available_admission_permits(),
        PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        fixture.genesis_root
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );

    let retry = publisher.try_admit().expect("persistence retry admission");
    assert!(matches!(
        retry.publish(Arc::clone(&signed)).await,
        PqBlockPublicationDisposition::Published(_)
    ));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(1),
            broadcast_receiver.recv(),
        )
        .await
        .is_err(),
        "post-broadcast persistence retry must not enqueue another broadcast"
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        signed.canonical_root()
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        2
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn proposal_signed_wrong_post_state_root_is_invalid_before_broadcast() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let (mut block, blob_data) = produced.into_contents().deconstruct();
    let (proofs, blobs) = blob_data.expect("Electra V3 has explicit blob lists");
    assert!(proofs.is_empty());
    assert!(blobs.is_empty());
    *block.state_root_mut() = Hash256::repeat_byte(0x7d);
    let signed = sign_block(&fixture, block);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );

    let admission = publisher
        .try_admit()
        .expect("invalid publication admission");
    assert!(matches!(
        admission.publish(signed).await,
        PqBlockPublicationDisposition::Invalid(_)
    ));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(1),
            broadcast_receiver.recv(),
        )
        .await
        .is_err(),
        "post-state-root mismatch must not reach the broadcaster"
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        fixture.genesis_root
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn same_root_rpc_commit_during_publish_ack_is_committed() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );

    let admission = publisher.try_admit().expect("publication admission");
    let publish_block = Arc::clone(&signed);
    let publication = tokio::spawn(async move { admission.publish(publish_block).await });
    let command = broadcast_receiver.recv().await.expect("broadcast command");
    let rpc_outcome = PqNetworkBlockProcessor::new(Arc::clone(&fixture.chain))
        .import_rpc_block(Arc::clone(&signed))
        .await
        .expect("same-root RPC commit during broadcast acknowledgement");
    assert_eq!(rpc_outcome.source, beacon_chain::PqBlockImportSource::Rpc);
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );

    command.acknowledge(Ok(()));
    assert!(matches!(
        publication.await.expect("publication task"),
        PqBlockPublicationDisposition::Committed
    ));
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        signed.canonical_root()
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn promoted_publish_queued_behind_same_root_rpc_commit_is_committed() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    fixture
        .execution
        .stall_new_payload
        .store(true, Ordering::SeqCst);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );

    let admission = publisher.try_admit().expect("publication admission");
    let publish_block = Arc::clone(&signed);
    let publication = tokio::spawn(async move { admission.publish(publish_block).await });
    let command = broadcast_receiver.recv().await.expect("broadcast command");

    let rpc_chain = Arc::clone(&fixture.chain);
    let rpc_block = Arc::clone(&signed);
    let rpc = tokio::spawn(async move {
        PqNetworkBlockProcessor::new(rpc_chain)
            .import_rpc_block(rpc_block)
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(180), async {
        while fixture.execution.new_payload_calls.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("RPC reaches the stalled Engine");
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );

    command.acknowledge(Ok(()));
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while !fixture.chain.testing_only_pq_observation_is_pending_commit(
            signed.slot(),
            signed.message().proposer_index(),
            signed.canonical_root(),
        ) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Publish promotes before RPC leaves the commit gate");
    assert!(fixture.chain.testing_only_pq_observation_is_pending_commit(
        signed.slot(),
        signed.message().proposer_index(),
        signed.canonical_root(),
    ));

    fixture.execution.new_payload_release.add_permits(1);
    assert_eq!(
        rpc.await
            .expect("RPC task")
            .expect("same-root RPC commit")
            .source,
        beacon_chain::PqBlockImportSource::Rpc
    );
    assert!(matches!(
        publication.await.expect("publication task"),
        PqBlockPublicationDisposition::Committed
    ));
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        signed.canonical_root()
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn same_root_lookup_rejection_during_publish_ack_is_terminal() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    fixture.execution.set_new_payload_responses([
        execution_layer::PayloadStatus::InvalidBlockHash {
            validation_error: Some("lookup race rejection".to_owned()),
        },
    ]);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let signed = sign_produced_block(&fixture, produced);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );

    let admission = publisher.try_admit().expect("publication admission");
    let publish_block = Arc::clone(&signed);
    let publication = tokio::spawn(async move { admission.publish(publish_block).await });
    let command = broadcast_receiver.recv().await.expect("broadcast command");
    assert!(matches!(
        PqNetworkBlockProcessor::new(Arc::clone(&fixture.chain))
            .import_lookup_block(Arc::clone(&signed))
            .await,
        Err(beacon_chain::PqImportError::ExecutionRejected(
            execution_layer::PayloadStatus::InvalidBlockHash { .. }
        ))
    ));
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );

    command.acknowledge(Ok(()));
    assert!(matches!(
        publication.await.expect("publication task"),
        PqBlockPublicationDisposition::Terminal(network::PqBlockPublicationTerminal::Rejected)
    ));
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        fixture.genesis_root
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn different_root_publication_during_publish_ack_is_equivocation() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let first_produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("first valid full block production");
    let second_produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti([0xe2; 32]))
        .await
        .expect("equivocating full block production");
    let first = sign_produced_block(&fixture, first_produced);
    let (second_block, second_blob_data) = second_produced.into_contents().deconstruct();
    let (second_proofs, second_blobs) =
        second_blob_data.expect("Electra V3 has explicit blob lists");
    assert!(second_proofs.is_empty());
    assert!(second_blobs.is_empty());
    let second = sign_equivocating_block(&fixture, second_block);
    assert_eq!(first.slot(), second.slot());
    assert_eq!(
        first.message().proposer_index(),
        second.message().proposer_index()
    );
    assert_ne!(first.canonical_root(), second.canonical_root());

    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let publisher = Arc::new(
        PqBlockPublicationService::new(
            Arc::clone(&fixture.chain),
            fixture._runtime.task_executor.clone(),
            broadcast_sender,
        )
        .expect("publication service"),
    );
    let first_admission = publisher.try_admit().expect("first admission");
    let first_for_publish = Arc::clone(&first);
    let first_publication =
        tokio::spawn(async move { first_admission.publish(first_for_publish).await });
    let command = broadcast_receiver
        .recv()
        .await
        .expect("first broadcast command");

    assert!(matches!(
        publisher
            .try_admit()
            .expect("equivocation admission")
            .publish(Arc::clone(&second))
            .await,
        PqBlockPublicationDisposition::Equivocation { previous }
            if previous == first.canonical_root()
    ));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(1),
            broadcast_receiver.recv(),
        )
        .await
        .is_err(),
        "a verified equivocation must not enqueue another broadcast"
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0
    );

    command.acknowledge(Ok(()));
    assert!(matches!(
        first_publication.await.expect("first publication"),
        PqBlockPublicationDisposition::Published(_)
    ));
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        first.canonical_root()
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn head_change_while_get_payload_is_stalled_returns_terminal_stale_parent() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let canonical = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("canonical production candidate");
    let signed = sign_produced_block(&fixture, canonical);

    fixture
        .execution
        .stall_payload
        .store(true, Ordering::SeqCst);
    let stale_chain = Arc::clone(&fixture.chain);
    let stale_randao = fixture.randao.clone();
    let stale = tokio::spawn(async move {
        stale_chain
            .produce_pq_block_v3(Slot::new(1), stale_randao, Graffiti::default())
            .await
    });
    while fixture.execution.payload_calls.load(Ordering::SeqCst) < 2 {
        tokio::task::yield_now().await;
    }

    PqNetworkBlockProcessor::new(Arc::clone(&fixture.chain))
        .import_rpc_block(Arc::clone(&signed))
        .await
        .expect("canonical block import while competing production is stalled");
    fixture.execution.payload_release.add_permits(1);
    let error = stale
        .await
        .expect("stale production task")
        .expect_err("production bound to the superseded head must fail");
    assert!(!error.is_retryable());
    assert!(matches!(
        error,
        PqBlockProductionError::StaleHead {
            expected_parent,
            actual_head,
        } if expected_parent == fixture.genesis_root && actual_head == signed.canonical_root()
    ));
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        signed.canonical_root()
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn payload_without_explicit_empty_blob_and_request_bundle_is_rejected() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, true);
    let error = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect_err("PQ V1 requires explicit empty payload-and-blobs contents");
    assert!(matches!(
        error,
        PqBlockProductionError::Local(PqBlockProductionLocalError::Execution(
            execution_layer::Error::InvalidPayloadBody(_)
        ))
    ));
    assert_eq!(fixture.execution.payload_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        fixture.genesis_root
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn payload_with_incorrect_execution_block_hash_is_rejected_before_returning_a_proposal() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    fixture
        .execution
        .invalid_payload_block_hash
        .store(true, Ordering::SeqCst);

    let error = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect_err("a proposal rejected by the sealed import boundary must not be returned");
    assert!(matches!(
        error,
        PqBlockProductionError::Local(PqBlockProductionLocalError::Execution(
            execution_layer::Error::BlockHashMismatch { .. }
        ))
    ));
    assert_eq!(fixture.execution.payload_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        fixture.genesis_root
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn payload_with_nonzero_blob_gas_is_rejected_even_when_its_block_hash_is_valid() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    fixture
        .execution
        .nonzero_blob_gas
        .store(true, Ordering::SeqCst);

    let error = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect_err("lean PQ V1 rejects blob gas without blobs");
    assert!(matches!(
        error,
        PqBlockProductionError::Local(PqBlockProductionLocalError::Execution(
            execution_layer::Error::InvalidPayloadBody(_)
        ))
    ));
    assert_eq!(fixture.execution.payload_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        fixture.genesis_root
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn payload_request_state_work_runs_on_blocking_executor_without_stalling_heartbeat() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let blocking_hook = TestingPqBlockingHook::blocking();
    let fixture =
        valid_production_fixture_with_blocking_hook(false, false, Some(Arc::clone(&blocking_hook)));
    let heartbeat_count = Arc::new(AtomicUsize::new(0));
    let heartbeat_stop = Arc::new(AtomicBool::new(false));
    let heartbeat = {
        let heartbeat_count = Arc::clone(&heartbeat_count);
        let heartbeat_stop = Arc::clone(&heartbeat_stop);
        tokio::spawn(async move {
            while !heartbeat_stop.load(Ordering::SeqCst) {
                heartbeat_count.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
            }
        })
    };
    let production = {
        let chain = Arc::clone(&fixture.chain);
        let randao = fixture.randao.clone();
        tokio::spawn(async move {
            chain
                .produce_pq_block_v3(Slot::new(1), randao, Graffiti::default())
                .await
        })
    };

    while blocking_hook.entered() == 0 && !production.is_finished() {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        blocking_hook.entered(),
        1,
        "payload-request state work must enter the production blocking boundary",
    );
    let heartbeat_before = heartbeat_count.load(Ordering::SeqCst);
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert!(
        heartbeat_count.load(Ordering::SeqCst) > heartbeat_before,
        "blocking payload-request state work must not stall the async worker",
    );

    blocking_hook.release();
    production
        .await
        .expect("production task")
        .expect("production after blocking barrier");
    heartbeat_stop.store(true, Ordering::SeqCst);
    heartbeat.await.expect("heartbeat task");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn canceled_stalled_payload_retains_admission_and_late_slot_is_ignored() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(true, false);
    let first_chain = Arc::clone(&fixture.chain);
    let first_randao = fixture.randao.clone();
    let first = tokio::spawn(async move {
        first_chain
            .produce_pq_block_v3(Slot::new(1), first_randao, Graffiti::default())
            .await
    });
    let second_chain = Arc::clone(&fixture.chain);
    let second_randao = fixture.randao.clone();
    let second = tokio::spawn(async move {
        second_chain
            .produce_pq_block_v3(Slot::new(1), second_randao, Graffiti::default())
            .await
    });
    while fixture.execution.payload_calls.load(Ordering::SeqCst)
        < PQ_BLOCK_PRODUCTION_ADMISSION_CAPACITY
    {
        tokio::task::yield_now().await;
    }

    first.abort();
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_block_production_available_permits(),
        0,
        "caller cancellation must not release a chain-owned in-flight admission",
    );
    let capacity_error = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect_err("cap+1 request must fail without waiting");
    assert!(matches!(
        capacity_error,
        PqBlockProductionError::Local(PqBlockProductionLocalError::IngressCapacity)
    ));
    assert_eq!(
        fixture.execution.payload_calls.load(Ordering::SeqCst),
        PQ_BLOCK_PRODUCTION_ADMISSION_CAPACITY,
    );

    fixture.chain.slot_clock.set_slot(2);
    fixture
        .execution
        .payload_release
        .add_permits(PQ_BLOCK_PRODUCTION_ADMISSION_CAPACITY);
    let second_error = second
        .await
        .expect("second caller task")
        .expect_err("payload completed after its proposal slot");
    assert!(matches!(
        second_error,
        PqBlockProductionError::ExpiredAfterWork {
            current,
            requested,
        } if current == Slot::new(2) && requested == Slot::new(1)
    ));
    assert!(!second_error.is_retryable());
    while fixture
        .chain
        .testing_only_pq_block_production_available_permits()
        != PQ_BLOCK_PRODUCTION_ADMISSION_CAPACITY
    {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block_root,
        fixture.genesis_root
    );
}

#[cfg(not(target_feature = "avx2"))]
#[test]
fn pq_block_production_requires_avx2_backend() {
    assert_eq!(
        <types::MinimalEthSpec as types::EthSpec>::slots_per_epoch(),
        8
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_http_surface_exposes_only_full_v3_production_and_full_v2_publication() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let (broadcast_sender, _broadcast_receiver) = pq_block_broadcast_channel();
    let routes = PqHttpApi::new(
        Arc::clone(&fixture.chain),
        fixture._runtime.task_executor.clone(),
        broadcast_sender,
    )
    .expect("PQ HTTP API")
    .routes();

    for (method, path) in [
        ("GET", "/eth/v2/validator/blocks/1"),
        ("GET", "/eth/v4/validator/blocks/1"),
        ("GET", "/eth/v1/validator/blinded_blocks/1"),
        ("POST", "/eth/v2/beacon/blinded_blocks"),
        ("POST", "/eth/v1/beacon/blocks"),
    ] {
        let response = warp::test::request()
            .method(method)
            .path(path)
            .reply(&routes)
            .await;
        assert_eq!(response.status(), 404, "unsupported route {method} {path}");
    }
    for (method, path) in [
        ("POST", "/eth/v3/validator/blocks/1"),
        ("GET", "/eth/v2/beacon/blocks"),
    ] {
        let response = warp::test::request()
            .method(method)
            .path(path)
            .reply(&routes)
            .await;
        assert_eq!(response.status(), 405, "wrong method {method} {path}");
    }

    let duties = warp::test::request()
        .method("GET")
        .path("/eth/v1/validator/duties/proposer/0")
        .reply(&routes)
        .await;
    assert_eq!(duties.status(), 200, "standard PQ proposer duties route");
    assert_eq!(
        duties
            .headers()
            .get("eth-consensus-version")
            .expect("duty fork header"),
        "electra",
    );
    let duties: eth2::types::DutiesResponse<Vec<eth2::types::ProposerData>> =
        serde_json::from_slice(duties.body()).expect("standard proposer duties JSON");
    assert_eq!(duties.execution_optimistic, Some(false));
    assert_eq!(
        duties.data.len(),
        MinimalEthSpec::slots_per_epoch() as usize
    );
    let duties_query = warp::test::request()
        .method("GET")
        .path("/eth/v1/validator/duties/proposer/0?unexpected=true")
        .reply(&routes)
        .await;
    assert_eq!(duties_query.status(), 400, "duty query options are absent");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn proposer_duty_http_bodies_and_clones_retain_exact_chain_admission() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let (broadcast_sender, _broadcast_receiver) = pq_block_broadcast_channel();
    let routes = PqHttpApi::new(
        Arc::clone(&fixture.chain),
        fixture._runtime.task_executor.clone(),
        broadcast_sender,
    )
    .expect("PQ HTTP API")
    .routes();

    let mut retained = Vec::new();
    for _ in 0..beacon_chain::PQ_PROPOSER_DUTY_ADMISSION_CAPACITY {
        let response = warp::test::request()
            .method("GET")
            .path("/eth/v1/validator/duties/proposer/0")
            .reply(&routes)
            .await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get("eth-consensus-version")
                .expect("duty fork header"),
            "electra",
        );
        retained.push(response);
    }
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_proposer_duty_available_permits(),
        0,
        "slow HTTP bodies must retain the chain duty capabilities",
    );
    let third = warp::test::request()
        .method("GET")
        .path("/eth/v1/validator/duties/proposer/0")
        .reply(&routes)
        .await;
    assert_eq!(third.status(), 429);

    let clone = retained[0].body().clone();
    retained.remove(0);
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_proposer_duty_available_permits(),
        0,
        "a body clone must retain the exact owned duty capability",
    );
    drop(clone);
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_proposer_duty_available_permits(),
        1,
    );
    drop(retained);
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_proposer_duty_available_permits(),
        beacon_chain::PQ_PROPOSER_DUTY_ADMISSION_CAPACITY,
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_http_request_policy_rejects_before_production_or_body_decode() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let (broadcast_sender, _broadcast_receiver) = pq_block_broadcast_channel();
    let routes = PqHttpApi::new(
        Arc::clone(&fixture.chain),
        fixture._runtime.task_executor.clone(),
        broadcast_sender,
    )
    .expect("PQ HTTP API")
    .routes();
    let randao = serialize_individual_signature(&fixture.randao).to_string();
    let body_limits = PqPublicationBodyLimits::try_from_spec::<MinimalEthSpec>(&fixture.spec)
        .expect("publication body limits");
    let max_json_bytes = body_limits.max_json_bytes();

    let cases = [
        (
            warp::test::request()
                .method("GET")
                .path("/eth/v3/validator/blocks/1"),
            400,
            "missing randao",
        ),
        (
            warp::test::request().method("GET").path(&format!(
                "/eth/v3/validator/blocks/not-a-slot?randao_reveal={randao}"
            )),
            400,
            "malformed slot",
        ),
        (
            warp::test::request().method("GET").path(&format!(
                "/eth/v3/validator/blocks/18446744073709551616?randao_reveal={randao}"
            )),
            400,
            "overflowing slot",
        ),
        (
            warp::test::request().method("GET").path(&format!(
                "/eth/v3/validator/blocks/1?randao_reveal={randao}&skip_randao_verification"
            )),
            400,
            "skip randao",
        ),
        (
            warp::test::request().method("GET").path(&format!(
                "/eth/v3/validator/blocks/1?randao_reveal={randao}&builder_boost_factor=100"
            )),
            400,
            "builder option",
        ),
        (
            warp::test::request().method("GET").path(&format!(
                "/eth/v3/validator/blocks/1?randao_reveal={randao}&randao_reveal={randao}"
            )),
            400,
            "duplicate randao query",
        ),
        (
            warp::test::request()
                .method("GET")
                .path(&format!(
                    "/eth/v3/validator/blocks/1?randao_reveal={randao}"
                ))
                .header("accept", "text/plain"),
            406,
            "unsupported accept",
        ),
        (
            warp::test::request()
                .method("POST")
                .path("/eth/v2/beacon/blocks"),
            411,
            "missing content length",
        ),
        (
            warp::test::request()
                .method("POST")
                .path("/eth/v2/beacon/blocks")
                .header(
                    "content-length",
                    max_json_bytes.saturating_add(1).to_string(),
                ),
            413,
            "body cap plus one",
        ),
        (
            warp::test::request()
                .method("POST")
                .path("/eth/v2/beacon/blocks")
                .header("content-length", max_json_bytes.to_string())
                .header("content-type", "application/json")
                .header("eth-consensus-version", "electra")
                .body("{}"),
            400,
            "exact body cap reaches contextual decode",
        ),
        (
            warp::test::request()
                .method("POST")
                .path("/eth/v2/beacon/blocks")
                .header("content-length", "2")
                .header("content-type", "text/plain")
                .header("eth-consensus-version", "electra")
                .body("{}"),
            415,
            "unsupported content type",
        ),
        (
            warp::test::request()
                .method("POST")
                .path("/eth/v2/beacon/blocks")
                .header("content-length", "2")
                .header("content-type", "application/json")
                .body("{}"),
            400,
            "missing consensus version",
        ),
        (
            warp::test::request()
                .method("POST")
                .path("/eth/v2/beacon/blocks")
                .header("content-length", "2")
                .header("content-type", "application/json")
                .header("eth-consensus-version", "fulu")
                .body("{}"),
            400,
            "wrong consensus version",
        ),
        (
            warp::test::request()
                .method("POST")
                .path("/eth/v2/beacon/blocks?broadcast_validation=consensus")
                .header("content-length", "2")
                .header("content-type", "application/json")
                .header("eth-consensus-version", "electra")
                .body("{}"),
            400,
            "unsupported publish query",
        ),
        (
            warp::test::request()
                .method("POST")
                .path("/eth/v2/beacon/blocks")
                .header("content-length", "2")
                .header("content-type", "Application/JSON; charset=UTF-8")
                .header("eth-consensus-version", "electra")
                .body("{}"),
            400,
            "case-insensitive JSON media essence with valid parameters",
        ),
        (
            warp::test::request()
                .method("POST")
                .path("/eth/v2/beacon/blocks")
                .header("content-length", "2")
                .header("content-type", "application/json")
                .header("eth-consensus-version", "electra")
                .header("accept", "text/plain")
                .body("{}"),
            400,
            "publish ignores Accept",
        ),
        (
            warp::test::request()
                .method("POST")
                .path("/eth/v2/beacon/blocks")
                .header("content-length", "2")
                .header("content-type", "application/json")
                .header("eth-consensus-version", "electra")
                .body("{}"),
            400,
            "malformed contextual block contents",
        ),
    ];

    for (request, expected, label) in cases {
        let response = request.reply(&routes).await;
        assert_eq!(response.status(), expected, "{label}");
    }

    let raw_at_cap = format!("x={}", "a".repeat(4094));
    let at_cap = warp::test::request()
        .method("GET")
        .path(&format!("/eth/v3/validator/blocks/1?{raw_at_cap}"))
        .reply(&routes)
        .await;
    assert_eq!(at_cap.status(), 400);
    assert!(
        std::str::from_utf8(at_cap.body())
            .expect("error JSON")
            .contains("request parameters are invalid"),
        "the exact raw-query cap must reach typed parsing",
    );
    let raw_over_cap = format!("x={}", "a".repeat(4095));
    let over_cap = warp::test::request()
        .method("GET")
        .path(&format!("/eth/v3/validator/blocks/1?{raw_over_cap}"))
        .reply(&routes)
        .await;
    assert_eq!(over_cap.status(), 400);
    assert!(
        std::str::from_utf8(over_cap.body())
            .expect("error JSON")
            .contains("query exceeds the PQ HTTP limit"),
        "cap+1 must fail in the raw-query guard before typed parsing",
    );
    assert_eq!(fixture.execution.payload_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_http_publication_admission_precedes_stream_polling_and_recovers_after_timeout() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let (broadcast_sender, _broadcast_receiver) = pq_block_broadcast_channel();
    let body_collections_started = Arc::new(AtomicUsize::new(0));
    let routes = PqHttpApi::new(
        Arc::clone(&fixture.chain),
        fixture._runtime.task_executor.clone(),
        broadcast_sender,
    )
    .expect("PQ HTTP API")
    .testing_only_observe_body_collections(Arc::clone(&body_collections_started))
    .routes();
    let (address, server) = warp::serve(routes).bind_ephemeral(([127, 0, 0, 1], 0));
    let server = tokio::spawn(server);
    let client = warp::hyper::Client::new();
    let uri = format!("http://{address}/eth/v2/beacon/blocks");

    let mut body_senders = Vec::new();
    let mut stalled = Vec::new();
    for _ in 0..PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY {
        let (body_sender, body) = warp::hyper::Body::channel();
        body_senders.push(body_sender);
        let request = warp::hyper::Request::post(&uri)
            .header("content-length", "2")
            .header("content-type", "application/json")
            .header("eth-consensus-version", "electra")
            .body(body)
            .expect("stalled publication request");
        let client = client.clone();
        stalled.push(tokio::spawn(async move { client.request(request).await }));
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while body_collections_started.load(Ordering::SeqCst)
            != PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("exact admitted body collectors started");

    let cap_plus_one = warp::hyper::Request::post(&uri)
        .header("content-length", "2")
        .header("content-type", "application/json")
        .header("eth-consensus-version", "electra")
        .body(warp::hyper::Body::from("{}"))
        .expect("cap+1 request");
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.request(cap_plus_one),
    )
    .await
    .expect("cap+1 must not wait")
    .expect("cap+1 response");
    assert_eq!(response.status(), 429);
    assert_eq!(
        body_collections_started.load(Ordering::SeqCst),
        PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY,
        "the rejected request body stream must remain unpolled",
    );

    for response in stalled {
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), response)
            .await
            .expect("stalled body timeout")
            .expect("client task")
            .expect("timeout response");
        assert_eq!(response.status(), 408);
    }
    drop(body_senders);

    let recovered = warp::hyper::Request::post(&uri)
        .header("content-length", "2")
        .header("content-type", "application/json")
        .header("eth-consensus-version", "electra")
        .body(warp::hyper::Body::from("{}"))
        .expect("recovered request");
    let response = client.request(recovered).await.expect("recovered response");
    assert_eq!(response.status(), 400);
    assert_eq!(
        body_collections_started.load(Ordering::SeqCst),
        PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY + 1,
    );
    server.abort();
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_proposer_service_composes_with_real_http_import_and_restart() {
    run_real_pq_proposer_http_composition().await;
}

#[cfg(target_feature = "avx2")]
async fn run_real_pq_proposer_http_composition() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let started = std::time::Instant::now();
    eprintln!("PQ composition: provisioning 16 authenticated validators");
    let root = tempfile::TempDir::new().expect("composition root");
    let seed_path = root.path().join("seed");
    let password_path = root.path().join("password");
    fs::write(&seed_path, [0x63; 32]).expect("seed");
    fs::write(&password_path, b"composition password").expect("password");
    #[cfg(unix)]
    {
        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).expect("seed mode");
        fs::set_permissions(&password_path, fs::Permissions::from_mode(0o600))
            .expect("password mode");
    }
    let bundle_path = root.path().join("bundle");
    let provisioned = pq_devnet::provision_devnet(
        pq_devnet::ProvisionConfig::for_test(bundle_path.clone(), 16, 0..=125, 0x63),
        &seed_path,
        &password_path,
    )
    .expect("authenticated 16-validator bundle");
    eprintln!(
        "PQ composition: provisioning complete after {:?}",
        started.elapsed()
    );
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let mut genesis =
        BeaconState::<MinimalEthSpec>::from_ssz_bytes(provisioned.genesis_state_bytes(), &spec)
            .expect("provisioned genesis");
    genesis
        .build_all_committee_caches(&spec)
        .expect("genesis committee caches");
    let runtime = task_executor::test_utils::TestRuntime::default();
    let initialized = InitializedValidators::from_pq_bundle(
        provisioned.bundle_dir().to_path_buf(),
        provisioned.genesis_validators_root(),
        provisioned.genesis_time(),
        provisioned.validator_registry().to_vec(),
        runtime.task_executor.clone(),
    )
    .await
    .expect("sealed manifest identities");
    eprintln!(
        "PQ composition: authenticated authority open after {:?}",
        started.elapsed()
    );
    let slashing =
        SlashingDatabase::create(&root.path().join("slashing.sqlite")).expect("slashing database");
    for public_key in provisioned.public_keys() {
        slashing
            .register_validator(public_key)
            .expect("register provisioned validator");
    }
    let proposer_clock =
        slot_clock::TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
    proposer_clock.set_slot(1);
    let validator_store = Arc::new(LighthouseValidatorStore::new(
        initialized,
        slashing,
        Hash256::from(provisioned.genesis_validators_root()),
        Arc::clone(&spec),
        None,
        proposer_clock.clone(),
        &ValidatorStoreConfig::default(),
        runtime.task_executor.clone(),
    ));

    let execution = Arc::new(RecordingExecution {
        new_payload_calls: AtomicUsize::new(0),
        new_payload_responses: Mutex::new(VecDeque::new()),
        stall_new_payload: AtomicBool::new(false),
        new_payload_release: tokio::sync::Semaphore::new(0),
        forkchoice_calls: AtomicUsize::new(0),
        forkchoice_responses: Mutex::new(VecDeque::new()),
        stall_forkchoice: AtomicBool::new(false),
        forkchoice_release: tokio::sync::Semaphore::new(0),
        payload_calls: AtomicUsize::new(0),
        stall_payload: AtomicBool::new(false),
        omit_payload_bundle: AtomicBool::new(false),
        invalid_payload_block_hash: AtomicBool::new(false),
        nonzero_blob_gas: AtomicBool::new(false),
        payload_release: tokio::sync::Semaphore::new(0),
    });
    let store = exact_snapshot_store(Arc::clone(&spec));
    let aggregation_service = Arc::new(AggregationService::new().expect("aggregation service"));
    let chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&store))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis)
            .expect("persist composition genesis")
            .pq_aggregation_service(Arc::clone(&aggregation_service))
            .task_executor(runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(execution.clone())
            .build()
            .expect("composition chain"),
    );
    chain.slot_clock.set_slot(1);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let routes = PqHttpApi::new(
        Arc::clone(&chain),
        runtime.task_executor.clone(),
        broadcast_sender,
    )
    .expect("real PQ HTTP API")
    .routes();
    let (address, server) = warp::serve(routes).bind_ephemeral(([127, 0, 0, 1], 0));
    let server = tokio::spawn(server);
    eprintln!(
        "PQ composition: real HTTP API listening after {:?}",
        started.elapsed()
    );
    let beacon_node = StrictBeaconNodeHttpClient::from_builder(
        SensitiveUrl::parse(&format!("http://{address}/")).expect("composition HTTP URL"),
        Timeouts::set_all(Duration::from_secs(180)),
        reqwest::Client::builder(),
    )
    .expect("strict composition client");
    let service = Arc::new(
        PqProposerService::new(
            proposer_clock,
            runtime.task_executor.clone(),
            Arc::clone(&validator_store),
            beacon_node,
        )
        .expect("concrete proposer service"),
    );
    let execution_for_broadcast = Arc::clone(&execution);
    let (broadcasted_tx, broadcasted_rx) = tokio::sync::oneshot::channel();
    let broadcast_task = tokio::spawn(async move {
        let command = broadcast_receiver
            .recv()
            .await
            .expect("exact broadcast command");
        assert_eq!(
            execution_for_broadcast
                .new_payload_calls
                .load(Ordering::SeqCst),
            0,
            "broadcast acknowledgement must precede Engine notification",
        );
        let block = Arc::clone(command.block());
        command.acknowledge(Ok(()));
        broadcasted_tx.send(block).expect("record broadcast block");
    });
    let receipt = service
        .try_propose_current_slot()
        .expect("start current-slot proposal");
    eprintln!(
        "PQ composition: current-slot proposal admitted after {:?}",
        started.elapsed()
    );
    let completion = tokio::time::timeout(Duration::from_secs(180), receipt.completion())
        .await
        .expect("proposal completion timeout")
        .expect("published proposal");
    broadcast_task.await.expect("broadcast task");
    let broadcasted = broadcasted_rx.await.expect("broadcast block");
    eprintln!(
        "PQ composition: broadcast acknowledged and import committed after {:?}",
        started.elapsed()
    );
    let PqProposalCompletion::Published { slot, block_root } = completion else {
        panic!("local current-slot duty must publish")
    };
    assert_eq!(slot, Slot::new(1));
    assert_eq!(block_root, broadcasted.canonical_root());
    assert_eq!(execution.payload_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execution.new_payload_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        chain.head_snapshot().beacon_block.as_ref(),
        broadcasted.as_ref()
    );

    let restarted = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&store))
            .custom_spec(Arc::clone(&spec))
            .resume_from_db()
            .expect("resume exact proposer publication")
            .pq_aggregation_service(Arc::clone(&aggregation_service))
            .task_executor(runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(execution.clone())
            .build()
            .expect("restart composition chain"),
    );
    assert_eq!(
        restarted.head_snapshot().beacon_block.as_ref(),
        broadcasted.as_ref(),
        "restart must restore the exact signed persisted identity",
    );
    eprintln!(
        "PQ composition: persisted signed head restored after {:?}",
        started.elapsed()
    );
    let (restart_sender, mut restart_receiver) = pq_block_broadcast_channel();
    let restart_routes = PqHttpApi::new(restarted, runtime.task_executor.clone(), restart_sender)
        .expect("restart HTTP API")
        .routes();
    let duplicate = eth2::types::PublishBlockRequest::new(
        Arc::clone(&broadcasted),
        Some((
            types::KzgProofs::<MinimalEthSpec>::default(),
            types::BlobsList::<MinimalEthSpec>::default(),
        )),
    );
    let duplicate_body = duplicate.as_ssz_bytes();
    let response = warp::test::request()
        .method("POST")
        .path("/eth/v2/beacon/blocks")
        .header("content-length", duplicate_body.len().to_string())
        .header("content-type", "application/octet-stream")
        .header("eth-consensus-version", "electra")
        .body(duplicate_body)
        .reply(&restart_routes)
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(execution.new_payload_calls.load(Ordering::SeqCst), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(1), restart_receiver.recv())
            .await
            .is_err(),
        "restart duplicate must not rebroadcast",
    );
    eprintln!(
        "PQ composition: restart duplicate remained idempotent after {:?}",
        started.elapsed()
    );
    server.abort();
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_http_v3_json_production_and_full_publication_round_trip() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let decode_hook = TestingPqHttpBlockingHook::blocking();
    let routes = PqHttpApi::new(
        Arc::clone(&fixture.chain),
        fixture._runtime.task_executor.clone(),
        broadcast_sender.clone(),
    )
    .expect("PQ HTTP API")
    .testing_only_block_decode(Arc::clone(&decode_hook))
    .routes();
    let (address, server) = warp::serve(routes.clone()).bind_ephemeral(([127, 0, 0, 1], 0));
    let server = tokio::spawn(server);
    let client = BeaconNodeHttpClient::new(
        SensitiveUrl::parse(&format!("http://{address}/")).expect("ephemeral PQ HTTP URL"),
        Timeouts::set_all(Duration::from_secs(180)),
    );
    let randao = serialize_individual_signature(&fixture.randao);
    let graffiti = Graffiti([0x6b; 32]);
    let (decoded, metadata) = client
        .get_validator_blocks_v3::<MinimalEthSpec>(
            Slot::new(1),
            &randao,
            Some(&graffiti),
            None,
            None,
        )
        .await
        .expect("BeaconNodeHttpClient V3 JSON response");
    assert_eq!(decoded.version, ForkName::Electra);
    assert!(!metadata.execution_payload_blinded);
    assert_eq!(metadata.execution_payload_value, Uint256::ZERO);
    assert_eq!(metadata.consensus_block_value, Uint256::ZERO);
    let eth2::types::ProduceBlockV3Response::Full(decoded_contents) = decoded.data else {
        panic!("PQ V3 JSON must be full")
    };
    assert_eq!(decoded_contents.block().body().graffiti(), &graffiti);
    assert!(matches!(
        &decoded_contents,
        eth2::types::FullBlockContents::BlockContents(_)
    ));
    assert_eq!(fixture.execution.payload_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0
    );

    let (ssz_response, ssz_metadata) = client
        .get_validator_blocks_v3_ssz::<MinimalEthSpec>(
            Slot::new(1),
            &randao,
            Some(&graffiti),
            None,
            None,
        )
        .await
        .expect("BeaconNodeHttpClient V3 SSZ response");
    assert!(!ssz_metadata.execution_payload_blinded);
    assert_eq!(ssz_metadata.execution_payload_value, Uint256::ZERO);
    assert_eq!(ssz_metadata.consensus_block_value, Uint256::ZERO);
    let eth2::types::ProduceBlockV3Response::Full(ssz_contents) = ssz_response else {
        panic!("PQ V3 SSZ must be full")
    };
    assert_eq!(
        ssz_contents.block().canonical_root(),
        decoded_contents.block().canonical_root(),
    );
    assert_eq!(fixture.execution.payload_calls.load(Ordering::SeqCst), 2);

    let (block, sidecars) = decoded_contents.deconstruct();
    let signed = sign_block(&fixture, block);
    let (invalid_message, _) = signed.as_ref().clone().deconstruct();
    let invalid_signature = Arc::new(SignedBeaconBlock::from_block(
        invalid_message,
        consensus_signature::IndividualSignature::empty(),
    ));
    let invalid_request =
        eth2::types::PublishBlockRequest::new(invalid_signature, sidecars.clone());
    let invalid_body = serde_json::to_vec(&invalid_request).expect("invalid signed Electra JSON");
    let missing_context_request = eth2::types::PublishBlockRequest::new(Arc::clone(&signed), None);
    let missing_context_body =
        serde_json::to_vec(&missing_context_request).expect("block-only Electra JSON");
    let (mut wrong_root_message, _) = signed.as_ref().clone().deconstruct();
    *wrong_root_message.state_root_mut() = Hash256::repeat_byte(0x7d);
    let wrong_root = sign_equivocating_block(&fixture, wrong_root_message);
    let wrong_root_request = eth2::types::PublishBlockRequest::new(wrong_root, sidecars.clone());
    let wrong_root_body =
        serde_json::to_vec(&wrong_root_request).expect("wrong-root signed Electra JSON");
    let invalid_routes = PqHttpApi::new(
        Arc::clone(&fixture.chain),
        fixture._runtime.task_executor.clone(),
        broadcast_sender,
    )
    .expect("invalid-publication PQ HTTP API")
    .routes();
    let invalid = warp::test::request()
        .method("POST")
        .path("/eth/v2/beacon/blocks")
        .header("content-length", invalid_body.len().to_string())
        .header("content-type", "application/json")
        .header("eth-consensus-version", "electra")
        .body(invalid_body)
        .reply(&invalid_routes)
        .await;
    assert_eq!(invalid.status(), 400);
    let missing_context = warp::test::request()
        .method("POST")
        .path("/eth/v2/beacon/blocks")
        .header("content-length", missing_context_body.len().to_string())
        .header("content-type", "application/json")
        .header("eth-consensus-version", "electra")
        .body(missing_context_body)
        .reply(&invalid_routes)
        .await;
    assert_eq!(missing_context.status(), 400);
    let wrong_root = warp::test::request()
        .method("POST")
        .path("/eth/v2/beacon/blocks")
        .header("content-length", wrong_root_body.len().to_string())
        .header("content-type", "application/json")
        .header("eth-consensus-version", "electra")
        .body(wrong_root_body)
        .reply(&invalid_routes)
        .await;
    assert_eq!(wrong_root.status(), 400);
    assert!(
        tokio::time::timeout(Duration::from_millis(1), broadcast_receiver.recv())
            .await
            .is_err(),
        "an invalid proposal signature must be rejected before broadcast",
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0,
        "an invalid proposal signature must be rejected before Engine",
    );
    let publish_request = eth2::types::PublishBlockRequest::new(Arc::clone(&signed), sidecars);
    let mut json_body = serde_json::to_vec(&publish_request).expect("full signed Electra JSON");
    json_body.resize(json_body.len().max(2 * 1024 * 1024), b' ');
    assert!(json_body.len() >= 2 * 1024 * 1024);
    let request = warp::test::request()
        .method("POST")
        .path("/eth/v2/beacon/blocks")
        .header("content-length", json_body.len().to_string())
        .header("content-type", "application/json")
        .header("eth-consensus-version", "electra")
        .body(json_body.clone());
    let publish_routes = routes.clone();
    let response = tokio::spawn(async move { request.reply(&publish_routes).await });
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while decode_hook.entered() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("blocking decode entered");
    let heartbeat = tokio::spawn(async {
        tokio::task::yield_now().await;
        1usize
    });
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), heartbeat)
            .await
            .expect("heartbeat while decode is blocked")
            .expect("heartbeat task"),
        1,
    );
    response.abort();
    assert!(
        response
            .await
            .expect_err("canceled HTTP caller")
            .is_cancelled(),
        "the HTTP caller must be gone while blocking decode owns the body and admission",
    );
    decode_hook.release();
    let broadcast = tokio::time::timeout(Duration::from_secs(180), broadcast_receiver.recv())
        .await
        .expect("publication broadcast timeout")
        .expect("publication broadcast command");
    assert_eq!(broadcast.block().as_ref(), signed.as_ref());
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0,
        "broadcast must be acknowledged before Engine notification",
    );
    let pending = warp::test::request()
        .method("POST")
        .path("/eth/v2/beacon/blocks")
        .header("content-length", json_body.len().to_string())
        .header("content-type", "application/json")
        .header("eth-consensus-version", "electra")
        .body(json_body)
        .reply(&routes)
        .await;
    assert_eq!(pending.status(), 202);
    broadcast.acknowledge(Ok(()));
    tokio::time::timeout(std::time::Duration::from_secs(180), async {
        while fixture.execution.new_payload_calls.load(Ordering::SeqCst) == 0
            || fixture.chain.head_snapshot().beacon_block.slot() != Slot::new(1)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached HTTP publication commits");
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture.chain.head_snapshot().beacon_block.slot(),
        Slot::new(1)
    );

    let duplicate = client
        .post_beacon_blocks_v2_ssz(&publish_request, None)
        .await;
    assert_eq!(
        duplicate
            .expect("BeaconNodeHttpClient SSZ publication duplicate")
            .status(),
        200,
    );
    assert_eq!(
        client
            .post_beacon_blocks_v2(&publish_request, None)
            .await
            .expect("BeaconNodeHttpClient JSON publication duplicate")
            .status(),
        200,
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1,
        "an exact committed duplicate must not re-notify Engine",
    );

    let restarted = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&fixture.store))
            .custom_spec(Arc::clone(&fixture.spec))
            .resume_from_db()
            .expect("resume HTTP-published block")
            .pq_aggregation_service(Arc::clone(&fixture.aggregation_service))
            .task_executor(fixture._runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(fixture.execution.clone())
            .build()
            .expect("restart after HTTP publication"),
    );
    let (restart_broadcast, _restart_receiver) = pq_block_broadcast_channel();
    let restart_routes = PqHttpApi::new(
        restarted,
        fixture._runtime.task_executor.clone(),
        restart_broadcast,
    )
    .expect("restart PQ HTTP API")
    .routes();
    let restart_body = publish_request.as_ssz_bytes();
    let restart_duplicate = warp::test::request()
        .method("POST")
        .path("/eth/v2/beacon/blocks")
        .header("content-length", restart_body.len().to_string())
        .header("content-type", "application/octet-stream")
        .header("eth-consensus-version", "electra")
        .body(restart_body)
        .reply(&restart_routes)
        .await;
    assert_eq!(restart_duplicate.status(), 200);
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1,
        "persisted exact signed duplicate must not notify Engine after restart",
    );
    server.abort();
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_http_publication_maps_retry_and_equivocation_after_awaiting_service() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    fixture.execution.set_new_payload_responses([
        execution_layer::PayloadStatus::Syncing,
        execution_layer::PayloadStatus::Valid,
    ]);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let (block, sidecars) = produced.into_contents().deconstruct();
    let signed = sign_block(&fixture, block);
    let request = eth2::types::PublishBlockRequest::new(Arc::clone(&signed), sidecars);
    let body = serde_json::to_vec(&request).expect("full signed Electra JSON");
    let equivocation = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti([0xe2; 32]))
        .await
        .expect("valid equivocating full block production");
    let (equivocation, equivocation_sidecars) = equivocation.into_contents().deconstruct();
    let equivocation = sign_equivocating_block(&fixture, equivocation);
    let equivocation_request =
        eth2::types::PublishBlockRequest::new(equivocation, equivocation_sidecars);
    let equivocation_body =
        serde_json::to_vec(&equivocation_request).expect("equivocating Electra JSON");
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let routes = PqHttpApi::new(
        Arc::clone(&fixture.chain),
        fixture._runtime.task_executor.clone(),
        broadcast_sender,
    )
    .expect("PQ HTTP API")
    .routes();

    let first_routes = routes.clone();
    let first_body = body.clone();
    let first = tokio::spawn(async move {
        warp::test::request()
            .method("POST")
            .path("/eth/v2/beacon/blocks")
            .header("content-length", first_body.len().to_string())
            .header("content-type", "application/json")
            .header("eth-consensus-version", "electra")
            .body(first_body)
            .reply(&first_routes)
            .await
    });
    let first_broadcast = tokio::time::timeout(Duration::from_secs(180), broadcast_receiver.recv())
        .await
        .expect("first broadcast timeout")
        .expect("first broadcast");
    let equivocation = warp::test::request()
        .method("POST")
        .path("/eth/v2/beacon/blocks")
        .header("content-length", equivocation_body.len().to_string())
        .header("content-type", "application/json")
        .header("eth-consensus-version", "electra")
        .body(equivocation_body)
        .reply(&routes)
        .await;
    assert_eq!(equivocation.status(), 409);
    assert!(
        tokio::time::timeout(Duration::from_millis(1), broadcast_receiver.recv())
            .await
            .is_err(),
        "a conflicting root must not broadcast",
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        0,
        "live equivocation must be resolved before Engine",
    );
    first_broadcast.acknowledge(Ok(()));
    let first = tokio::time::timeout(Duration::from_secs(180), first)
        .await
        .expect("retryable publication completes")
        .expect("retryable publication task");
    assert_eq!(first.status(), 503);

    let retry = warp::test::request()
        .method("POST")
        .path("/eth/v2/beacon/blocks")
        .header("content-length", body.len().to_string())
        .header("content-type", "application/json")
        .header("eth-consensus-version", "electra")
        .body(body)
        .reply(&routes)
        .await;
    assert_eq!(retry.status(), 200);
    assert!(
        tokio::time::timeout(Duration::from_millis(1), broadcast_receiver.recv())
            .await
            .is_err(),
        "post-broadcast Engine retry must not rebroadcast",
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        2,
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_http_publication_maps_engine_rejection_to_terminal_conflict() {
    let _service_guard = REAL_AGGREGATION_SERVICE_TEST_LOCK.lock().await;
    let fixture = valid_production_fixture(false, false);
    fixture.execution.set_new_payload_responses([
        execution_layer::PayloadStatus::InvalidBlockHash {
            validation_error: Some("terminal HTTP publication fixture".to_owned()),
        },
    ]);
    let produced = fixture
        .chain
        .produce_pq_block_v3(Slot::new(1), fixture.randao.clone(), Graffiti::default())
        .await
        .expect("valid full block production");
    let (block, sidecars) = produced.into_contents().deconstruct();
    let signed = sign_block(&fixture, block);
    let request = eth2::types::PublishBlockRequest::new(signed, sidecars);
    let body = serde_json::to_vec(&request).expect("full signed Electra JSON");
    let (broadcast_sender, mut broadcast_receiver) = pq_block_broadcast_channel();
    let routes = PqHttpApi::new(
        Arc::clone(&fixture.chain),
        fixture._runtime.task_executor.clone(),
        broadcast_sender,
    )
    .expect("PQ HTTP API")
    .routes();

    let first_routes = routes.clone();
    let first_body = body.clone();
    let first = tokio::spawn(async move {
        warp::test::request()
            .method("POST")
            .path("/eth/v2/beacon/blocks")
            .header("content-length", first_body.len().to_string())
            .header("content-type", "application/json")
            .header("eth-consensus-version", "electra")
            .body(first_body)
            .reply(&first_routes)
            .await
    });
    tokio::time::timeout(Duration::from_secs(180), broadcast_receiver.recv())
        .await
        .expect("terminal broadcast timeout")
        .expect("terminal broadcast")
        .acknowledge(Ok(()));
    let first = tokio::time::timeout(Duration::from_secs(180), first)
        .await
        .expect("terminal publication completes")
        .expect("terminal publication task");
    assert_eq!(first.status(), 409);

    let duplicate = warp::test::request()
        .method("POST")
        .path("/eth/v2/beacon/blocks")
        .header("content-length", body.len().to_string())
        .header("content-type", "application/json")
        .header("eth-consensus-version", "electra")
        .body(body)
        .reply(&routes)
        .await;
    assert_eq!(duplicate.status(), 409);
    assert!(
        tokio::time::timeout(Duration::from_millis(1), broadcast_receiver.recv())
            .await
            .is_err(),
        "terminal duplicate must not rebroadcast",
    );
    assert_eq!(
        fixture.execution.new_payload_calls.load(Ordering::SeqCst),
        1,
        "terminal duplicate must not re-notify Engine",
    );
}
