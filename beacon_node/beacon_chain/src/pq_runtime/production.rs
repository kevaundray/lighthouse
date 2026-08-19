use crate::{BeaconChain, BeaconChainTypes};
use consensus_signature::IndividualSignature;
use eth2::types::FullBlockContents;
use execution_layer::BlockProposalContents;
use fork_choice::ForkchoiceUpdateParameters;
use slot_clock::SlotClock;
use state_processing::{
    BlockProcessingError, PqConsensusError, PqLocalBlockError, PqTransitionError, PreparedPqRandao,
    VerifiedPqRandao, compute_timestamp_at_slot, get_expected_withdrawals,
    per_block_processing_pq_local, per_slot_processing_pq, prepare_pq_local_block,
    prepare_pq_randao,
};
use std::{error::Error, sync::Arc};
use tokio::sync::OwnedSemaphorePermit;
#[cfg(feature = "pq-startup-testing")]
use types::{Address, ForkName};
use types::{
    BeaconBlock, BeaconState, ChainSpec, EthSpec, ExecPayload, ExecutionBlockHash,
    ExecutionPayload, ExecutionPayloadRef, FullPayload, Graffiti, Hash256, Slot, Uint256,
    Withdrawal, Withdrawals,
};

pub const PQ_BLOCK_PRODUCTION_ADMISSION_CAPACITY: usize = 2;
const PQ_BLOCK_PRODUCTION_ADVANCE_CAPACITY: u64 = 8;

#[derive(Debug)]
pub struct PqProducedBlockV3<E: EthSpec> {
    contents: FullBlockContents<E>,
    execution_payload_value: Uint256,
}

impl<E: EthSpec> PqProducedBlockV3<E> {
    pub const fn contents(&self) -> &FullBlockContents<E> {
        &self.contents
    }

    pub const fn execution_payload_value(&self) -> Uint256 {
        self.execution_payload_value
    }

    pub fn into_contents(self) -> FullBlockContents<E> {
        self.contents
    }
}

/// Owned inputs for the chain's one immutable execution capability.
///
/// This type is public only so the isolated startup-testing transport can implement the same
/// process-owned boundary. Production callers cannot construct it.
pub struct PqPayloadBuildRequest<E: EthSpec> {
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) spec: Arc<ChainSpec>,
    pub(crate) proposer_index: u64,
    pub(crate) parent_beacon_block_root: Hash256,
    pub(crate) timestamp: u64,
    pub(crate) prev_randao: Hash256,
    pub(crate) parent_hash: ExecutionBlockHash,
    pub(crate) parent_gas_limit: u64,
    pub(crate) withdrawals: Vec<Withdrawal>,
    pub(crate) forkchoice_update_parameters: ForkchoiceUpdateParameters,
    _eth_spec: std::marker::PhantomData<E>,
}

#[cfg(feature = "pq-startup-testing")]
impl<E: EthSpec> PqPayloadBuildRequest<E> {
    pub fn spec(&self) -> &ChainSpec {
        &self.spec
    }

    pub const fn proposer_index(&self) -> u64 {
        self.proposer_index
    }

    pub const fn parent_beacon_block_root(&self) -> Hash256 {
        self.parent_beacon_block_root
    }

    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub const fn prev_randao(&self) -> Hash256 {
        self.prev_randao
    }

    pub const fn parent_hash(&self) -> ExecutionBlockHash {
        self.parent_hash
    }

    pub const fn parent_gas_limit(&self) -> u64 {
        self.parent_gas_limit
    }

    pub const fn withdrawals(&self) -> &Vec<Withdrawal> {
        &self.withdrawals
    }
}

/// Test-only observation of inputs derived by the real production execution branch.
///
/// Local Engine API calls do not carry proposer or parent gas-limit hints on the wire. This
/// observer sits immediately beside the real `ExecutionLayer` call so tests can inspect those
/// inputs without replacing the process-owned execution capability.
#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Debug)]
pub struct TestingPqPayloadBuildObservation<E: EthSpec> {
    proposer_index: u64,
    parent_beacon_block_root: Hash256,
    parent_hash: ExecutionBlockHash,
    parent_gas_limit: u64,
    proposer_gas_limit: Option<u64>,
    suggested_fee_recipient: Address,
    current_fork: ForkName,
    forkchoice_update_parameters: ForkchoiceUpdateParameters,
    withdrawals: Vec<Withdrawal>,
    _eth_spec: std::marker::PhantomData<E>,
}

#[cfg(feature = "pq-startup-testing")]
impl<E: EthSpec> TestingPqPayloadBuildObservation<E> {
    pub const fn proposer_index(&self) -> u64 {
        self.proposer_index
    }

    pub const fn parent_beacon_block_root(&self) -> Hash256 {
        self.parent_beacon_block_root
    }

    pub const fn parent_hash(&self) -> ExecutionBlockHash {
        self.parent_hash
    }

    pub const fn parent_gas_limit(&self) -> u64 {
        self.parent_gas_limit
    }

    pub const fn proposer_gas_limit(&self) -> Option<u64> {
        self.proposer_gas_limit
    }

    pub const fn suggested_fee_recipient(&self) -> Address {
        self.suggested_fee_recipient
    }

    pub const fn current_fork(&self) -> ForkName {
        self.current_fork
    }

    pub const fn forkchoice_head_root(&self) -> Hash256 {
        self.forkchoice_update_parameters.head_root
    }

    pub const fn forkchoice_head_hash(&self) -> Option<ExecutionBlockHash> {
        self.forkchoice_update_parameters.head_hash
    }

    pub const fn forkchoice_justified_hash(&self) -> Option<ExecutionBlockHash> {
        self.forkchoice_update_parameters.justified_hash
    }

    pub const fn forkchoice_finalized_hash(&self) -> Option<ExecutionBlockHash> {
        self.forkchoice_update_parameters.finalized_hash
    }

    pub fn withdrawals(&self) -> &[Withdrawal] {
        &self.withdrawals
    }

    pub(crate) fn from_payload_parameters(
        proposer_index: u64,
        parameters: &execution_layer::PayloadParameters<'_>,
    ) -> Self {
        Self {
            proposer_index,
            parent_beacon_block_root: parameters
                .payload_attributes
                .parent_beacon_block_root()
                .expect("PQ production uses V3 payload attributes"),
            parent_hash: parameters.parent_hash,
            parent_gas_limit: parameters
                .parent_gas_limit
                .expect("PQ production supplies the parent gas limit"),
            proposer_gas_limit: parameters.proposer_gas_limit,
            suggested_fee_recipient: parameters.payload_attributes.suggested_fee_recipient(),
            current_fork: parameters.current_fork,
            forkchoice_update_parameters: *parameters.forkchoice_update_params,
            withdrawals: parameters
                .payload_attributes
                .withdrawals()
                .expect("PQ production uses V3 payload attributes")
                .clone(),
            _eth_spec: std::marker::PhantomData,
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
pub(crate) type TestingPqPayloadBuildObserver<E> =
    Arc<dyn Fn(TestingPqPayloadBuildObservation<E>) + Send + Sync>;

pub(crate) struct PqFullPayloadResponse<E: EthSpec> {
    payload: ExecutionPayload<E>,
    block_value: Uint256,
}

pub(crate) struct PqPayloadExpectation<E: EthSpec> {
    parent_beacon_block_root: Hash256,
    parent_hash: ExecutionBlockHash,
    timestamp: u64,
    prev_randao: Hash256,
    withdrawals: Vec<Withdrawal>,
    _eth_spec: std::marker::PhantomData<E>,
}

impl<E: EthSpec> PqPayloadExpectation<E> {
    pub(crate) fn from_request(request: &PqPayloadBuildRequest<E>) -> Self {
        Self {
            parent_beacon_block_root: request.parent_beacon_block_root,
            parent_hash: request.parent_hash,
            timestamp: request.timestamp,
            prev_randao: request.prev_randao,
            withdrawals: request.withdrawals.clone(),
            _eth_spec: std::marker::PhantomData,
        }
    }
}

/// Test-only construction of the exact expectations used by the production payload validator.
#[cfg(feature = "pq-startup-testing")]
pub struct TestingPqPayloadExpectation<E: EthSpec> {
    expectation: PqPayloadExpectation<E>,
}

#[cfg(feature = "pq-startup-testing")]
impl<E: EthSpec> TestingPqPayloadExpectation<E> {
    pub fn new(
        parent_beacon_block_root: Hash256,
        parent_hash: ExecutionBlockHash,
        timestamp: u64,
        prev_randao: Hash256,
        withdrawals: Vec<Withdrawal>,
    ) -> Self {
        Self {
            expectation: PqPayloadExpectation {
                parent_beacon_block_root,
                parent_hash,
                timestamp,
                prev_randao,
                withdrawals,
                _eth_spec: std::marker::PhantomData,
            },
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_validate_pq_full_payload<E: EthSpec>(
    contents: BlockProposalContents<E, FullPayload<E>>,
    expectation: &TestingPqPayloadExpectation<E>,
) -> Result<Uint256, execution_layer::Error> {
    PqFullPayloadResponse::try_from_execution_contents(contents, &expectation.expectation)
        .map(|response| response.block_value)
}

impl<E: EthSpec> PqFullPayloadResponse<E> {
    pub(crate) fn try_from_execution_contents(
        contents: BlockProposalContents<E, FullPayload<E>>,
        expectation: &PqPayloadExpectation<E>,
    ) -> Result<Self, execution_layer::Error> {
        let BlockProposalContents::PayloadAndBlobs {
            payload,
            block_value,
            kzg_commitments,
            blobs_and_proofs,
            requests,
        } = contents
        else {
            return Err(execution_layer::Error::InvalidPayloadBody(
                "lean PQ V1 requires Electra payload contents".to_owned(),
            ));
        };
        let Some((blobs, proofs)) = blobs_and_proofs else {
            return Err(execution_layer::Error::InvalidPayloadBody(
                "lean PQ V1 requires explicit empty blob/proof lists".to_owned(),
            ));
        };
        let Some(requests) = requests else {
            return Err(execution_layer::Error::InvalidPayloadBody(
                "lean PQ V1 requires explicit empty execution requests".to_owned(),
            ));
        };
        let FullPayload::Electra(payload) = payload else {
            return Err(execution_layer::Error::InvalidForkForPayload);
        };
        if !kzg_commitments.is_empty()
            || !blobs.is_empty()
            || !proofs.is_empty()
            || !requests.deposits.is_empty()
            || !requests.withdrawals.is_empty()
            || !requests.consolidations.is_empty()
            || payload
                .blob_gas_used()
                .is_ok_and(|blob_gas_used| blob_gas_used != 0)
        {
            return Err(execution_layer::Error::InvalidPayloadBody(
                "lean PQ V1 rejects blobs and execution requests".to_owned(),
            ));
        }
        let execution_payload = payload.execution_payload;
        if execution_payload.parent_hash != expectation.parent_hash
            || execution_payload.timestamp != expectation.timestamp
            || execution_payload.prev_randao != expectation.prev_randao
            || &execution_payload.withdrawals[..] != expectation.withdrawals.as_slice()
        {
            return Err(execution_layer::Error::InvalidPayloadBody(
                "lean PQ V1 payload does not match its exact production request".to_owned(),
            ));
        }
        let (expected_block_hash, transactions_root) =
            execution_layer::calculate_execution_block_hash(
                ExecutionPayloadRef::Electra(&execution_payload),
                Some(expectation.parent_beacon_block_root),
                Some(&requests),
            );
        if execution_payload.block_hash != expected_block_hash {
            return Err(execution_layer::Error::BlockHashMismatch {
                computed: expected_block_hash,
                payload: execution_payload.block_hash,
                transactions_root,
            });
        }
        Ok(Self {
            payload: ExecutionPayload::Electra(execution_payload),
            block_value,
        })
    }
}

#[derive(Debug)]
pub enum PqBlockProductionLocalError {
    IngressCapacity,
    ClockUnavailable,
    StateAdvanceTooLarge { supplied: u64, maximum: u64 },
    BlockingTask(&'static str),
    AsyncTask(&'static str),
    Arithmetic(safe_arith::ArithError),
    State(types::BeaconStateError),
    BlockProcessing(BlockProcessingError),
    Consensus(PqConsensusError),
    LocalBlock(PqLocalBlockError),
    Transition(PqTransitionError),
    Execution(execution_layer::Error),
    Invariant(&'static str),
}

#[derive(Debug)]
pub enum PqBlockProductionError {
    Invalid(PqConsensusError),
    InitialFutureSlot {
        current: Slot,
        requested: Slot,
    },
    InitialPastSlot {
        current: Slot,
        requested: Slot,
    },
    AtOrBehindHead {
        head: Slot,
        requested: Slot,
    },
    ExpiredAfterWork {
        current: Slot,
        requested: Slot,
    },
    StaleHead {
        expected_parent: Hash256,
        actual_head: Hash256,
    },
    Local(PqBlockProductionLocalError),
}

impl std::fmt::Display for PqBlockProductionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(error) => {
                write!(formatter, "invalid PQ block-production request: {error}")
            }
            Self::InitialFutureSlot { current, requested } => write!(
                formatter,
                "PQ block-production request is early: current {current}, requested {requested}",
            ),
            Self::InitialPastSlot { current, requested } => write!(
                formatter,
                "PQ block-production request is past: current {current}, requested {requested}",
            ),
            Self::AtOrBehindHead { head, requested } => write!(
                formatter,
                "PQ block-production slot is at or behind head: head {head}, requested {requested}",
            ),
            Self::ExpiredAfterWork { current, requested } => write!(
                formatter,
                "PQ block-production request expired during work: current {current}, requested {requested}",
            ),
            Self::StaleHead {
                expected_parent,
                actual_head,
            } => write!(
                formatter,
                "PQ block-production parent became stale: expected {expected_parent:?}, head {actual_head:?}"
            ),
            Self::Local(error) => write!(formatter, "PQ block production unavailable: {error:?}"),
        }
    }
}

impl Error for PqBlockProductionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invalid(error) => Some(error),
            Self::Local(PqBlockProductionLocalError::Consensus(error)) => Some(error),
            Self::Local(PqBlockProductionLocalError::LocalBlock(error)) => Some(error),
            Self::Local(PqBlockProductionLocalError::Transition(error)) => Some(error),
            Self::InitialFutureSlot { .. }
            | Self::InitialPastSlot { .. }
            | Self::AtOrBehindHead { .. }
            | Self::ExpiredAfterWork { .. }
            | Self::StaleHead { .. }
            | Self::Local(
                PqBlockProductionLocalError::IngressCapacity
                | PqBlockProductionLocalError::ClockUnavailable
                | PqBlockProductionLocalError::StateAdvanceTooLarge { .. }
                | PqBlockProductionLocalError::BlockingTask(_)
                | PqBlockProductionLocalError::AsyncTask(_)
                | PqBlockProductionLocalError::Arithmetic(_)
                | PqBlockProductionLocalError::State(_)
                | PqBlockProductionLocalError::BlockProcessing(_)
                | PqBlockProductionLocalError::Execution(_)
                | PqBlockProductionLocalError::Invariant(_),
            ) => None,
        }
    }
}

impl PqBlockProductionError {
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::InitialFutureSlot { .. } | Self::Local(_))
    }
}

fn validate_pq_production_advance(
    head: Slot,
    requested: Slot,
) -> Result<u64, PqBlockProductionError> {
    if requested <= head {
        return Err(PqBlockProductionError::AtOrBehindHead { head, requested });
    }
    let advance =
        requested
            .as_u64()
            .checked_sub(head.as_u64())
            .ok_or(PqBlockProductionError::Local(
                PqBlockProductionLocalError::Invariant(
                    "proposal slot preceded head after ordering check",
                ),
            ))?;
    if advance > PQ_BLOCK_PRODUCTION_ADVANCE_CAPACITY {
        return Err(PqBlockProductionError::Local(
            PqBlockProductionLocalError::StateAdvanceTooLarge {
                supplied: advance,
                maximum: PQ_BLOCK_PRODUCTION_ADVANCE_CAPACITY,
            },
        ));
    }
    Ok(advance)
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_validate_pq_production_advance(
    head: Slot,
    requested: Slot,
) -> Result<u64, PqBlockProductionError> {
    validate_pq_production_advance(head, requested)
}

struct PreparedPqProduction<E: EthSpec> {
    state: BeaconState<E>,
    parent_root: Hash256,
    randao_reveal: IndividualSignature,
    prepared_randao: PreparedPqRandao<E>,
    admission: OwnedSemaphorePermit,
}

struct VerifiedPqProduction<E: EthSpec> {
    state: BeaconState<E>,
    parent_root: Hash256,
    randao_reveal: IndividualSignature,
    verified_randao: VerifiedPqRandao<E>,
    admission: OwnedSemaphorePermit,
}

fn map_consensus_error(error: PqConsensusError) -> PqBlockProductionError {
    match error {
        PqConsensusError::Invalid(_) => PqBlockProductionError::Invalid(error),
        PqConsensusError::Local(_) => {
            PqBlockProductionError::Local(PqBlockProductionLocalError::Consensus(error))
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_block_production_available_permits(&self) -> usize {
        self.pq_block_production_admission.available_permits()
    }

    pub async fn produce_pq_block_v3(
        self: &Arc<Self>,
        slot: Slot,
        randao_reveal: IndividualSignature,
        graffiti: Graffiti,
    ) -> Result<PqProducedBlockV3<T::EthSpec>, PqBlockProductionError> {
        let admission = self
            .pq_block_production_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                PqBlockProductionError::Local(PqBlockProductionLocalError::IngressCapacity)
            })?;
        self.validate_initial_production_slot(slot)?;

        let chain = Arc::clone(self);
        let task = self
            .task_executor
            .spawn_handle(
                async move {
                    chain
                        .produce_pq_block_v3_owned(slot, randao_reveal, graffiti, admission)
                        .await
                },
                "pq-block-production",
            )
            .ok_or(PqBlockProductionError::Local(
                PqBlockProductionLocalError::AsyncTask("pq-block-production"),
            ))?;
        task.await
            .map_err(|_| {
                PqBlockProductionError::Local(PqBlockProductionLocalError::AsyncTask(
                    "pq-block-production",
                ))
            })?
            .ok_or(PqBlockProductionError::Local(
                PqBlockProductionLocalError::AsyncTask("pq-block-production"),
            ))?
    }

    async fn produce_pq_block_v3_owned(
        self: Arc<Self>,
        slot: Slot,
        randao_reveal: IndividualSignature,
        graffiti: Graffiti,
        admission: OwnedSemaphorePermit,
    ) -> Result<PqProducedBlockV3<T::EthSpec>, PqBlockProductionError> {
        let snapshot = self.head_snapshot();
        let head_slot = snapshot.beacon_state.slot();
        validate_pq_production_advance(head_slot, slot)?;

        let spec = Arc::clone(&self.spec);
        let key_cache = Arc::clone(&self.pq_validator_key_cache);
        let prepared_randao_reveal = randao_reveal.clone();
        let preparation = self
            .task_executor
            .spawn_blocking_handle(
                move || {
                    let mut state = snapshot.beacon_state.clone();
                    while state.slot() < slot {
                        per_slot_processing_pq(&mut state, &spec).map_err(|error| {
                            PqBlockProductionError::Local(PqBlockProductionLocalError::Transition(
                                error,
                            ))
                        })?;
                    }
                    let prepared_randao = prepare_pq_randao(
                        &state,
                        key_cache,
                        slot,
                        prepared_randao_reveal.clone(),
                        spec,
                    )
                    .map_err(map_consensus_error)?;
                    Ok(PreparedPqProduction {
                        state,
                        parent_root: snapshot.beacon_block_root,
                        randao_reveal: prepared_randao_reveal,
                        prepared_randao,
                        admission,
                    })
                },
                "pq-block-production-prepare-randao",
            )
            .ok_or(PqBlockProductionError::Local(
                PqBlockProductionLocalError::BlockingTask("pq-block-production-prepare-randao"),
            ))?
            .await
            .map_err(|_| {
                PqBlockProductionError::Local(PqBlockProductionLocalError::BlockingTask(
                    "pq-block-production-prepare-randao",
                ))
            })??;

        let service = Arc::clone(&self.pq_aggregation_service);
        let PreparedPqProduction {
            state,
            parent_root,
            randao_reveal,
            prepared_randao,
            admission,
        } = preparation;
        let verified_randao = prepared_randao
            .verify(&service)
            .await
            .map_err(map_consensus_error)?;
        let verified = VerifiedPqProduction {
            state,
            parent_root,
            randao_reveal,
            verified_randao,
            admission,
        };

        self.validate_late_production_context(slot, verified.parent_root)?;
        let spec = Arc::clone(&self.spec);
        let parent_root = verified.parent_root;
        #[cfg(feature = "pq-startup-testing")]
        let blocking_test_hook = self.pq_blocking_test_hook.clone();
        let payload_request = self
            .task_executor
            .spawn_blocking_handle(
                move || {
                    #[cfg(feature = "pq-startup-testing")]
                    if let Some(hook) = blocking_test_hook {
                        hook.run();
                    }
                    build_payload_request(&verified.state, spec, parent_root)
                        .map(|request| (request, verified))
                },
                "pq-block-production-payload-request",
            )
            .ok_or(PqBlockProductionError::Local(
                PqBlockProductionLocalError::BlockingTask("pq-block-production-payload-request"),
            ))?
            .await
            .map_err(|_| {
                PqBlockProductionError::Local(PqBlockProductionLocalError::BlockingTask(
                    "pq-block-production-payload-request",
                ))
            })??;
        let (payload_request, verified) = payload_request;
        let payload = self
            .pq_execution_notifier
            .get_full_payload(payload_request)
            .await
            .map_err(|error| {
                PqBlockProductionError::Local(PqBlockProductionLocalError::Execution(error))
            })?;

        self.validate_late_production_context(slot, verified.parent_root)?;
        let spec = Arc::clone(&self.spec);
        let (output, admission) = self
            .task_executor
            .spawn_blocking_handle(
                move || assemble_and_transition(verified, payload, graffiti, spec),
                "pq-block-production-transition",
            )
            .ok_or(PqBlockProductionError::Local(
                PqBlockProductionLocalError::BlockingTask("pq-block-production-transition"),
            ))?
            .await
            .map_err(|_| {
                PqBlockProductionError::Local(PqBlockProductionLocalError::BlockingTask(
                    "pq-block-production-transition",
                ))
            })??;
        self.validate_late_production_context(slot, output.contents().block().parent_root())?;
        drop(admission);
        Ok(output)
    }

    fn validate_initial_production_slot(
        &self,
        requested: Slot,
    ) -> Result<(), PqBlockProductionError> {
        let current = self.slot_clock.now().ok_or(PqBlockProductionError::Local(
            PqBlockProductionLocalError::ClockUnavailable,
        ))?;
        match current.cmp(&requested) {
            std::cmp::Ordering::Less => {
                Err(PqBlockProductionError::InitialFutureSlot { current, requested })
            }
            std::cmp::Ordering::Equal => Ok(()),
            std::cmp::Ordering::Greater => {
                Err(PqBlockProductionError::InitialPastSlot { current, requested })
            }
        }
    }

    fn validate_late_production_context(
        &self,
        requested: Slot,
        expected_parent: Hash256,
    ) -> Result<(), PqBlockProductionError> {
        let current = self.slot_clock.now().ok_or(PqBlockProductionError::Local(
            PqBlockProductionLocalError::ClockUnavailable,
        ))?;
        match current.cmp(&requested) {
            std::cmp::Ordering::Less => {
                return Err(PqBlockProductionError::InitialFutureSlot { current, requested });
            }
            std::cmp::Ordering::Equal => {}
            std::cmp::Ordering::Greater => {
                return Err(PqBlockProductionError::ExpiredAfterWork { current, requested });
            }
        }
        let actual_head = self.head_snapshot().beacon_block_root;
        if actual_head == expected_parent {
            Ok(())
        } else {
            Err(PqBlockProductionError::StaleHead {
                expected_parent,
                actual_head,
            })
        }
    }
}

fn build_payload_request<E: EthSpec>(
    state: &BeaconState<E>,
    spec: Arc<ChainSpec>,
    parent_beacon_block_root: Hash256,
) -> Result<PqPayloadBuildRequest<E>, PqBlockProductionError> {
    let proposer_index = state
        .get_beacon_proposer_index(state.slot(), &spec)
        .map_err(|error| PqBlockProductionError::Local(PqBlockProductionLocalError::State(error)))?
        .try_into()
        .map_err(|_| {
            PqBlockProductionError::Local(PqBlockProductionLocalError::Invariant(
                "proposer index does not fit u64",
            ))
        })?;
    let timestamp = compute_timestamp_at_slot(state, state.slot(), &spec).map_err(|error| {
        PqBlockProductionError::Local(PqBlockProductionLocalError::Arithmetic(error))
    })?;
    let prev_randao = *state
        .get_randao_mix(state.current_epoch())
        .map_err(|error| {
            PqBlockProductionError::Local(PqBlockProductionLocalError::State(error))
        })?;
    let header = state.latest_execution_payload_header().map_err(|error| {
        PqBlockProductionError::Local(PqBlockProductionLocalError::State(error))
    })?;
    let parent_hash = header.block_hash();
    let parent_gas_limit = header.gas_limit();
    let withdrawals: Withdrawals<E> = get_expected_withdrawals(state, &spec)
        .map_err(|error| {
            PqBlockProductionError::Local(PqBlockProductionLocalError::BlockProcessing(error))
        })?
        .into();
    Ok(PqPayloadBuildRequest {
        #[cfg(feature = "pq-startup-testing")]
        spec,
        proposer_index,
        parent_beacon_block_root,
        timestamp,
        prev_randao,
        parent_hash,
        parent_gas_limit,
        withdrawals: withdrawals.into(),
        forkchoice_update_parameters: ForkchoiceUpdateParameters {
            head_root: parent_beacon_block_root,
            head_hash: Some(parent_hash),
            justified_hash: None,
            finalized_hash: None,
        },
        _eth_spec: std::marker::PhantomData,
    })
}

fn assemble_and_transition<E: EthSpec>(
    verified: VerifiedPqProduction<E>,
    payload: PqFullPayloadResponse<E>,
    graffiti: Graffiti,
    spec: Arc<ChainSpec>,
) -> Result<(PqProducedBlockV3<E>, OwnedSemaphorePermit), PqBlockProductionError> {
    let VerifiedPqProduction {
        state,
        parent_root,
        randao_reveal,
        verified_randao,
        admission,
    } = verified;
    let PqFullPayloadResponse {
        payload,
        block_value,
    } = payload;
    let ExecutionPayload::Electra(execution_payload) = payload else {
        return Err(PqBlockProductionError::Local(
            PqBlockProductionLocalError::Execution(execution_layer::Error::InvalidForkForPayload),
        ));
    };
    let proposer_index = state
        .get_beacon_proposer_index(state.slot(), &spec)
        .map_err(|error| PqBlockProductionError::Local(PqBlockProductionLocalError::State(error)))?
        .try_into()
        .map_err(|_| {
            PqBlockProductionError::Local(PqBlockProductionLocalError::Invariant(
                "proposer index does not fit u64",
            ))
        })?;
    let mut block: BeaconBlock<E> = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(inner) = &mut block else {
        return Err(PqBlockProductionError::Local(
            PqBlockProductionLocalError::Invariant("Electra block constructor returned wrong fork"),
        ));
    };
    inner.slot = state.slot();
    inner.proposer_index = proposer_index;
    inner.parent_root = parent_root;
    inner.state_root = Hash256::ZERO;
    inner.body.randao_reveal = randao_reveal;
    inner.body.eth1_data = state.eth1_data().clone();
    inner.body.graffiti = graffiti;
    inner.body.execution_payload.execution_payload = execution_payload;

    let payload_request = execution_layer::NewPayloadRequest::try_from(block.to_ref())
        .map_err(execution_layer::Error::from)
        .map_err(|error| {
            PqBlockProductionError::Local(PqBlockProductionLocalError::Execution(error))
        })?;
    payload_request
        .perform_optimistic_sync_verifications()
        .map_err(|error| {
            PqBlockProductionError::Local(PqBlockProductionLocalError::Execution(error))
        })?;

    let sealed =
        prepare_pq_local_block(&state, block, verified_randao, Vec::new()).map_err(|error| {
            PqBlockProductionError::Local(PqBlockProductionLocalError::LocalBlock(error))
        })?;
    let mut post_state = state;
    let local_output = per_block_processing_pq_local(&mut post_state, sealed).map_err(|error| {
        PqBlockProductionError::Local(PqBlockProductionLocalError::Transition(error))
    })?;
    let (mut block, _context) = local_output.into_parts();
    let state_root = post_state.canonical_root().map_err(|error| {
        PqBlockProductionError::Local(PqBlockProductionLocalError::State(error))
    })?;
    *block.state_root_mut() = state_root;
    Ok((
        PqProducedBlockV3 {
            contents: FullBlockContents::new(block, Some((Default::default(), Default::default()))),
            execution_payload_value: block_value,
        },
        admission,
    ))
}
