#[cfg(target_feature = "avx2")]
use beacon_chain::{
    PQ_BLOCK_PRODUCTION_ADMISSION_CAPACITY, PqBlockProductionError, PqBlockProductionLocalError,
    PqNewPayloadTransport, PqPayloadBuildRequest, TestingPqBlockingHook,
    TestingPqPayloadBuildObservation, TestingPqPayloadExpectation,
    builder::{BeaconChainBuilder, Witness},
    testing_only_validate_pq_full_payload, testing_only_validate_pq_production_advance,
};
#[cfg(target_feature = "avx2")]
use consensus_signature::{
    AggregationService, OneTimeUseId, PqPublicKey, PqRawSignature, SigningDuty,
    ValidatorPublicKeyBytes,
};
#[cfg(target_feature = "avx2")]
use network::PqNetworkBlockProcessor;
#[cfg(target_feature = "avx2")]
use pq_signing::{PqKeyUnlock, PqKeystore, PqSigningAuthority, provision_usage_journal};
#[cfg(target_feature = "avx2")]
use ssz::Decode;
#[cfg(target_feature = "avx2")]
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
#[cfg(target_feature = "avx2")]
use store::{HotColdDB, MemoryStore, StoreConfig};
#[cfg(target_feature = "avx2")]
use types::{
    Address, BeaconBlock, BeaconState, Blob, ConsolidationRequest, DepositRequest, Domain, Epoch,
    EthSpec, ExecPayload, ExecutionBlockHash, ExecutionPayload, ExecutionPayloadRef,
    ExecutionRequests, ForkName, FullPayload, Graffiti, Hash256, KzgCommitment, KzgProof,
    MinimalEthSpec, ProposerPreparationData, SignedBeaconBlock, SignedRoot, Slot, Uint256,
    Withdrawal, WithdrawalRequest,
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
    payload_calls: AtomicUsize,
    stall_payload: std::sync::atomic::AtomicBool,
    omit_payload_bundle: std::sync::atomic::AtomicBool,
    invalid_payload_block_hash: std::sync::atomic::AtomicBool,
    nonzero_blob_gas: std::sync::atomic::AtomicBool,
    payload_release: tokio::sync::Semaphore,
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
        Box::pin(async { Ok(execution_layer::PayloadStatus::Valid) })
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
    execution: Arc<RecordingExecution>,
    randao: PqRawSignature,
    genesis_root: Hash256,
    authority: PqSigningAuthority,
    spec: Arc<types::ChainSpec>,
    proposal_state: types::BeaconState<MinimalEthSpec>,
    proposer_index: usize,
    _runtime: task_executor::test_utils::TestRuntime,
    _temporary_directory: tempfile::TempDir,
}

#[cfg(target_feature = "avx2")]
fn valid_production_fixture(
    stall_payload: bool,
    omit_payload_bundle: bool,
) -> ValidProductionFixture {
    valid_production_fixture_with_blocking_hook(stall_payload, omit_payload_bundle, None)
}

#[cfg(target_feature = "avx2")]
fn valid_production_fixture_with_blocking_hook(
    stall_payload: bool,
    omit_payload_bundle: bool,
    blocking_hook: Option<Arc<TestingPqBlockingHook>>,
) -> ValidProductionFixture {
    const PASSWORD: &[u8] = b"correct horse battery staple";

    let runtime = task_executor::test_utils::TestRuntime::default();
    let temporary_directory = tempfile::TempDir::new().expect("temporary directory");
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
        payload_calls: AtomicUsize::new(0),
        stall_payload: std::sync::atomic::AtomicBool::new(stall_payload),
        omit_payload_bundle: std::sync::atomic::AtomicBool::new(omit_payload_bundle),
        invalid_payload_block_hash: std::sync::atomic::AtomicBool::new(false),
        nonzero_blob_gas: std::sync::atomic::AtomicBool::new(false),
        payload_release: tokio::sync::Semaphore::new(0),
    });
    let mut builder = BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
        .store(exact_snapshot_store(Arc::clone(&spec)))
        .custom_spec(Arc::clone(&spec))
        .genesis_state(genesis.clone())
        .expect("persist genesis")
        .pq_aggregation_service(Arc::new(
            AggregationService::new().expect("PQ aggregation service"),
        ))
        .task_executor(runtime.task_executor.clone())
        .testing_only_pq_execution_notifier(execution.clone());
    if let Some(blocking_hook) = blocking_hook {
        builder = builder.testing_only_pq_blocking_hook(blocking_hook);
    }
    let chain = Arc::new(builder.build().expect("PQ chain"));
    chain.slot_clock.set_slot(1);
    let genesis_root = chain.head_snapshot().beacon_block_root;
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
        execution,
        randao,
        genesis_root,
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
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
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
    mock_execution
        .server
        .ctx
        .hook
        .lock()
        .set_forkchoice_updated_hook(Box::new(move |state, payload_attributes| {
            *observed_fcu_for_hook.lock().expect("FCU observation lock") = Some((
                execution_layer::ForkchoiceState::from(state),
                payload_attributes.map(execution_layer::PayloadAttributes::from),
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

    let produced = chain
        .produce_pq_block_v3(Slot::new(1), randao, graffiti)
        .await
        .expect("production ExecutionLayer candidate");

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
        Some(serde_json::Value::String("engine_getPayloadV4".to_owned())),
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
