use consensus_signature::AggregationService;
use fork_choice::ForkChoiceStore as _;
#[cfg(feature = "pq-proposer")]
use lighthouse_network::{
    GossipTopic, IdentTopic, PqLocalSinglePublicationToken, pq_anonymous_message_id,
    types::{GossipEncoding, GossipKind},
};
#[cfg(feature = "pq-startup-testing")]
use operation_pool::PqAttestationPoolInsertDisposition;
use operation_pool::{OperationPool, PqAttestationPoolInsertInvariant};
use parking_lot::{Mutex, RwLock};
#[cfg(feature = "pq-proposer")]
use sha2::{Digest, Sha256};
use slot_clock::SlotClock;
use state_processing::PqValidatorKeyCache;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use store::{HotColdDB, ItemStore};
use task_executor::TaskExecutor;
use types::{
    BeaconState, ChainSpec, EthSpec, ExecutionBlockHash, Hash256, SignedBeaconBlock, Slot,
};

use crate::pq_background_attestation_aggregation::PqBackgroundAttestationAggregator;

type PqForkChoice<T> = fork_choice::ForkChoice<
    crate::beacon_fork_choice_store::BeaconForkChoiceStore<
        <T as BeaconChainTypes>::EthSpec,
        <T as BeaconChainTypes>::HotStore,
        <T as BeaconChainTypes>::ColdStore,
    >,
    <T as BeaconChainTypes>::EthSpec,
>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PqForkChoiceAncestryQueryError {
    Busy,
    Unavailable,
}

pub const PQ_FORK_CHOICE_TICK_MAX_ADVANCE: u64 = 8;

const PQ_BACKGROUND_AGGREGATION_SLOT_DURATION: Duration = Duration::from_secs(300);
const PQ_BACKGROUND_AGGREGATION_MINIMUM_REMAINING: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PqBackgroundAggregationCandidateShape {
    TwoRawSingletons,
    #[cfg(feature = "pq-startup-testing")]
    ContainsAggregate,
    #[cfg(feature = "pq-startup-testing")]
    WrongContributionCount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PqBackgroundAggregationDecision {
    Admitted,
    UnsupportedProfile,
    UnsupportedCandidateShape,
    HeadNotCurrent,
    HeadNotReconciled,
    InsufficientRemaining,
    AlreadyStartedThisSlot,
    DisabledAfterOverrun,
}

pub(crate) struct PqBackgroundAggregationGate {
    slot_duration: Duration,
    last_started_slot: Option<Slot>,
    disabled_after_overrun: bool,
}

impl PqBackgroundAggregationGate {
    pub(crate) fn new(slot_duration: Duration) -> Self {
        Self {
            slot_duration,
            last_started_slot: None,
            disabled_after_overrun: false,
        }
    }

    pub(crate) fn try_admit(
        &mut self,
        clock_slot: Slot,
        head_slot: Slot,
        reconciled_slot: Slot,
        remaining: Duration,
        candidate_shape: PqBackgroundAggregationCandidateShape,
    ) -> PqBackgroundAggregationDecision {
        if self.disabled_after_overrun {
            return PqBackgroundAggregationDecision::DisabledAfterOverrun;
        }
        if self.slot_duration != PQ_BACKGROUND_AGGREGATION_SLOT_DURATION {
            return PqBackgroundAggregationDecision::UnsupportedProfile;
        }
        if candidate_shape != PqBackgroundAggregationCandidateShape::TwoRawSingletons {
            return PqBackgroundAggregationDecision::UnsupportedCandidateShape;
        }
        if head_slot != clock_slot {
            return PqBackgroundAggregationDecision::HeadNotCurrent;
        }
        if reconciled_slot != head_slot {
            return PqBackgroundAggregationDecision::HeadNotReconciled;
        }
        if remaining < PQ_BACKGROUND_AGGREGATION_MINIMUM_REMAINING {
            return PqBackgroundAggregationDecision::InsufficientRemaining;
        }
        if self
            .last_started_slot
            .is_some_and(|last_started_slot| clock_slot <= last_started_slot)
        {
            return PqBackgroundAggregationDecision::AlreadyStartedThisSlot;
        }
        self.last_started_slot = Some(clock_slot);
        PqBackgroundAggregationDecision::Admitted
    }

    pub(crate) fn record_completion(&mut self, elapsed: Duration) {
        if elapsed > PQ_BACKGROUND_AGGREGATION_MINIMUM_REMAINING {
            self.disabled_after_overrun = true;
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPqBackgroundAggregationCandidateShape {
    TwoRawSingletons,
    ContainsAggregate,
    WrongContributionCount,
}

#[cfg(feature = "pq-startup-testing")]
impl From<TestingPqBackgroundAggregationCandidateShape> for PqBackgroundAggregationCandidateShape {
    fn from(shape: TestingPqBackgroundAggregationCandidateShape) -> Self {
        match shape {
            TestingPqBackgroundAggregationCandidateShape::TwoRawSingletons => {
                Self::TwoRawSingletons
            }
            TestingPqBackgroundAggregationCandidateShape::ContainsAggregate => {
                Self::ContainsAggregate
            }
            TestingPqBackgroundAggregationCandidateShape::WrongContributionCount => {
                Self::WrongContributionCount
            }
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPqBackgroundAggregationDecision {
    Admitted,
    UnsupportedProfile,
    UnsupportedCandidateShape,
    HeadNotCurrent,
    HeadNotReconciled,
    InsufficientRemaining,
    AlreadyStartedThisSlot,
    DisabledAfterOverrun,
}

#[cfg(feature = "pq-startup-testing")]
impl From<PqBackgroundAggregationDecision> for TestingPqBackgroundAggregationDecision {
    fn from(decision: PqBackgroundAggregationDecision) -> Self {
        match decision {
            PqBackgroundAggregationDecision::Admitted => Self::Admitted,
            PqBackgroundAggregationDecision::UnsupportedProfile => Self::UnsupportedProfile,
            PqBackgroundAggregationDecision::UnsupportedCandidateShape => {
                Self::UnsupportedCandidateShape
            }
            PqBackgroundAggregationDecision::HeadNotCurrent => Self::HeadNotCurrent,
            PqBackgroundAggregationDecision::HeadNotReconciled => Self::HeadNotReconciled,
            PqBackgroundAggregationDecision::InsufficientRemaining => Self::InsufficientRemaining,
            PqBackgroundAggregationDecision::AlreadyStartedThisSlot => Self::AlreadyStartedThisSlot,
            PqBackgroundAggregationDecision::DisabledAfterOverrun => Self::DisabledAfterOverrun,
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub struct TestingPqBackgroundAggregationGate(PqBackgroundAggregationGate);

#[cfg(feature = "pq-startup-testing")]
impl TestingPqBackgroundAggregationGate {
    pub fn new(slot_duration: Duration) -> Self {
        Self(PqBackgroundAggregationGate::new(slot_duration))
    }

    pub fn try_admit(
        &mut self,
        clock_slot: Slot,
        head_slot: Slot,
        reconciled_slot: Slot,
        remaining: Duration,
        candidate_shape: TestingPqBackgroundAggregationCandidateShape,
    ) -> TestingPqBackgroundAggregationDecision {
        self.0
            .try_admit(
                clock_slot,
                head_slot,
                reconciled_slot,
                remaining,
                candidate_shape.into(),
            )
            .into()
    }

    pub fn last_started_slot(&self) -> Option<Slot> {
        self.0.last_started_slot
    }

    pub fn record_completion(&mut self, elapsed: Duration) {
        self.0.record_completion(elapsed);
    }

    pub fn is_disabled(&self) -> bool {
        self.0.disabled_after_overrun
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Default)]
struct TestingPqAttestationPoolSourceTrace {
    gossip_inserted: usize,
    gossip_dominated: usize,
    gossip_removed_subsets: usize,
    local_inserted: usize,
    local_dominated: usize,
    local_removed_subsets: usize,
}

#[cfg(feature = "pq-proposer")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_pq_local_single_publication_token(
    member: usize,
    token: &PqLocalSinglePublicationToken,
    message_id: &lighthouse_network::MessageId,
    topic_hash: &lighthouse_network::TopicHash,
    fork_digest: [u8; 4],
    subnet: types::SubnetId,
    signed_ssz_digest: [u8; 32],
) -> Result<(), crate::PqPublishedLocalAttestationEvidenceError> {
    for (matches, field) in [
        (token.message_id() == message_id, "message-id"),
        (token.topic_hash() == topic_hash, "topic"),
        (token.fork_digest() == fork_digest, "fork-digest"),
        (token.subnet() == subnet, "subnet"),
        (
            token.signed_ssz_digest() == signed_ssz_digest,
            "signed-ssz-digest",
        ),
    ] {
        if !matches {
            return Err(crate::PqPublishedLocalAttestationEvidenceError::Mismatch {
                member,
                field,
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqForkChoiceAttestationOutcome {
    Applied,
    Queued,
}

#[derive(Debug)]
pub enum PqForkChoiceAttestationError {
    ShuttingDown,
    IngressCapacity,
    Unavailable,
    ClockUnavailable,
    TickMismatch {
        clock: Slot,
        requested: Slot,
    },
    TickRollback {
        current: Slot,
        requested: Slot,
    },
    TickAdvanceTooLarge {
        current: Slot,
        requested: Slot,
        maximum: u64,
    },
    InvalidIndexedAttestation,
    ObservationLost,
    TaskUnavailable,
    ReconciliationFailed {
        block_root: Hash256,
    },
    BoundHeadUnavailable {
        block_root: Hash256,
    },
    Pool(PqAttestationPoolInsertInvariant),
    ForkChoice(fork_choice::Error<crate::beacon_fork_choice_store::Error>),
}

impl std::fmt::Display for PqForkChoiceAttestationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShuttingDown => formatter.write_str("PQ fork-choice ingress is shutting down"),
            Self::IngressCapacity => {
                formatter.write_str("PQ fork-choice attestation admission is exhausted")
            }
            Self::Unavailable => formatter.write_str(
                "PQ in-memory Fresh fork choice is unavailable for this runtime snapshot",
            ),
            Self::ClockUnavailable => formatter.write_str("PQ slot clock is unavailable"),
            Self::TickMismatch { clock, requested } => write!(
                formatter,
                "PQ fork-choice tick {requested} does not match clock slot {clock}"
            ),
            Self::TickRollback { current, requested } => write!(
                formatter,
                "PQ fork-choice tick rolls back from {current} to {requested}"
            ),
            Self::TickAdvanceTooLarge {
                current,
                requested,
                maximum,
            } => write!(
                formatter,
                "PQ fork-choice tick advance from {current} to {requested} exceeds {maximum} slots"
            ),
            Self::InvalidIndexedAttestation => {
                formatter.write_str("sealed PQ single could not form an indexed attestation")
            }
            Self::ObservationLost => {
                formatter.write_str("sealed PQ single observation ownership was lost")
            }
            Self::TaskUnavailable => {
                formatter.write_str("PQ fork-choice task executor is unavailable")
            }
            Self::ReconciliationFailed { block_root } => write!(
                formatter,
                "PQ attestation head {block_root:?} failed execution reconciliation"
            ),
            Self::BoundHeadUnavailable { block_root } => write!(
                formatter,
                "PQ attestation head {block_root:?} is absent from reconciled fork choice"
            ),
            Self::Pool(error) => write!(formatter, "PQ attestation pool failed: {error}"),
            Self::ForkChoice(error) => write!(formatter, "PQ fork-choice failed: {error:?}"),
        }
    }
}

impl std::error::Error for PqForkChoiceAttestationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pool(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PqExecutionReconciliationState {
    Pending { block_root: Hash256 },
    Reconciled { block_root: Hash256 },
    Failed { block_root: Hash256 },
}

pub(crate) struct PqExecutionReconciliation {
    state: tokio::sync::watch::Sender<PqExecutionReconciliationState>,
}

impl PqExecutionReconciliation {
    pub(crate) fn new(state: PqExecutionReconciliationState) -> Self {
        let (state, _) = tokio::sync::watch::channel(state);
        Self { state }
    }

    pub(crate) fn current(&self) -> PqExecutionReconciliationState {
        *self.state.borrow()
    }

    pub(crate) fn set(&self, state: PqExecutionReconciliationState) {
        self.state.send_replace(state);
    }

    pub(crate) async fn wait_for(&self, block_root: Hash256) -> PqExecutionReconciliationState {
        let mut receiver = self.state.subscribe();
        loop {
            let state = *receiver.borrow_and_update();
            if !matches!(
                state,
                PqExecutionReconciliationState::Pending {
                    block_root: pending_root,
                } if pending_root == block_root
            ) {
                return state;
            }
            if receiver.changed().await.is_err() {
                return self.current();
            }
        }
    }
}

#[derive(Default)]
struct PqImportCoordinatorState {
    closed: bool,
    active: usize,
}

/// Process-owned close/drain boundary for every admitted PQ import and its detached commit.
///
/// Activities are counted before raw verification and remain owned across all blocking proof,
/// persistence and execution-reconciliation continuations. Closing rejects new work and waiting
/// never cancels work which has already durably published a head.
pub(crate) struct PqImportCoordinator {
    state: Mutex<PqImportCoordinatorState>,
    active: tokio::sync::watch::Sender<usize>,
}

impl Default for PqImportCoordinator {
    fn default() -> Self {
        let (active, _) = tokio::sync::watch::channel(0);
        Self {
            state: Mutex::new(PqImportCoordinatorState::default()),
            active,
        }
    }
}

impl PqImportCoordinator {
    pub(crate) fn close(&self) {
        self.state.lock().closed = true;
    }

    pub(crate) fn try_start(self: &Arc<Self>) -> Option<Arc<PqImportActivity>> {
        let mut state = self.state.lock();
        if state.closed {
            return None;
        }
        state.active = state.active.checked_add(1)?;
        self.active.send_replace(state.active);
        Some(Arc::new(PqImportActivity {
            coordinator: Arc::clone(self),
        }))
    }

    pub(crate) async fn close_and_drain(&self) {
        self.close_and_drain_after_observed(|| {}).await;
    }

    async fn close_and_drain_after_observed(&self, hook: impl FnOnce()) {
        let mut active = self.active.subscribe();
        {
            let mut state = self.state.lock();
            state.closed = true;
            if state.active == 0 {
                return;
            }
        }
        hook();
        loop {
            if *active.borrow_and_update() == 0 {
                return;
            }
            if active.changed().await.is_err() {
                return;
            }
        }
    }
}

pub(crate) struct PqImportPanicGuard {
    coordinator: Arc<PqImportCoordinator>,
    armed: bool,
}

impl PqImportPanicGuard {
    pub(crate) fn new(coordinator: Arc<PqImportCoordinator>) -> Self {
        Self {
            coordinator,
            armed: true,
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PqImportPanicGuard {
    fn drop(&mut self) {
        if self.armed {
            self.coordinator.close();
        }
    }
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
struct PqPostWireFailClosedGuard {
    fail_closed: Option<Box<dyn FnOnce() + Send>>,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPqPublishedLocalAttestationSupervisorFailure {
    Preflight,
    InvalidIndexed,
    Observation,
    Panic,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub struct TestingPqPublishedLocalAttestationSupervisorReceipt(tokio::sync::oneshot::Receiver<()>);

#[cfg(feature = "pq-startup-testing")]
impl TestingPqPublishedLocalAttestationSupervisorReceipt {
    pub async fn wait(self) {
        let _ = self.0.await;
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub struct TestingPqPublishedLocalAttestationSupervisorHarness {
    failure: TestingPqPublishedLocalAttestationSupervisorFailure,
    hook: Arc<crate::TestingPqBlockingHook>,
    coordinator: Arc<PqImportCoordinator>,
    fail_closed_calls: Arc<std::sync::atomic::AtomicUsize>,
    active_operations: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(feature = "pq-startup-testing")]
impl TestingPqPublishedLocalAttestationSupervisorHarness {
    pub fn new(
        failure: TestingPqPublishedLocalAttestationSupervisorFailure,
        hook: Arc<crate::TestingPqBlockingHook>,
    ) -> Self {
        Self {
            failure,
            hook,
            coordinator: Arc::new(PqImportCoordinator::default()),
            fail_closed_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            active_operations: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub fn start_after_wire(&self) -> TestingPqPublishedLocalAttestationSupervisorReceipt {
        struct ActiveGuard(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for ActiveGuard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
        }

        let activity = self
            .coordinator
            .try_start()
            .expect("fresh Cycle W supervisor harness admits one operation");
        self.active_operations
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let active_guard = ActiveGuard(Arc::clone(&self.active_operations));
        let hook = Arc::clone(&self.hook);
        let failure = self.failure;
        let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _activity = activity;
            let _active_guard = active_guard;
            let mut fail_closed = PqPostWireFailClosedGuard::new(move || {
                fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
            let blocking = tokio::task::spawn_blocking(move || hook.run()).await;
            if blocking.is_err()
                || matches!(
                    failure,
                    TestingPqPublishedLocalAttestationSupervisorFailure::Panic
                )
            {
                panic!("injected Cycle W post-wire supervisor panic");
            }
            let _ = sender.send(());
            let _semantic_error = match failure {
                TestingPqPublishedLocalAttestationSupervisorFailure::Preflight => "preflight",
                TestingPqPublishedLocalAttestationSupervisorFailure::InvalidIndexed => {
                    "invalid-indexed"
                }
                TestingPqPublishedLocalAttestationSupervisorFailure::Observation => "observation",
                TestingPqPublishedLocalAttestationSupervisorFailure::Panic => unreachable!(),
            };
            // Every harness case represents an after-wire terminal failure, so the same
            // production guard remains armed.
            let _ = &mut fail_closed;
        });
        TestingPqPublishedLocalAttestationSupervisorReceipt(receiver)
    }

    pub async fn close_and_drain(&self) {
        self.coordinator.close_and_drain().await;
    }

    pub fn fail_closed_calls(&self) -> usize {
        self.fail_closed_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn active_operations(&self) -> usize {
        self.active_operations
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
impl PqPostWireFailClosedGuard {
    fn new(fail_closed: impl FnOnce() + Send + 'static) -> Self {
        Self {
            fail_closed: Some(Box::new(fail_closed)),
        }
    }

    #[cfg(feature = "pq-proposer")]
    fn disarm(&mut self) {
        self.fail_closed.take();
    }
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
impl Drop for PqPostWireFailClosedGuard {
    fn drop(&mut self) {
        if let Some(fail_closed) = self.fail_closed.take() {
            fail_closed();
        }
    }
}

pub(crate) struct PqImportActivity {
    coordinator: Arc<PqImportCoordinator>,
}

impl Drop for PqImportActivity {
    fn drop(&mut self) {
        let mut state = self.coordinator.state.lock();
        let Some(active) = state.active.checked_sub(1) else {
            state.closed = true;
            return;
        };
        state.active = active;
        self.coordinator.active.send_replace(active);
        drop(state);
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub async fn testing_only_pq_import_drain_race() -> bool {
    let coordinator = Arc::new(PqImportCoordinator::default());
    let Some(activity) = coordinator.try_start() else {
        return false;
    };
    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        coordinator.close_and_drain_after_observed(move || drop(activity)),
    )
    .await
    .is_ok()
}

/// The minimal type family required by the Task 5.3e-b PQ startup core.
pub trait BeaconChainTypes: Send + Sync + 'static {
    type EthSpec: EthSpec;
    type HotStore: ItemStore + 'static;
    type ColdStore: ItemStore + 'static;
    type SlotClock: SlotClock + 'static;
}

pub type BeaconStore<T> = Arc<
    HotColdDB<
        <T as BeaconChainTypes>::EthSpec,
        <T as BeaconChainTypes>::HotStore,
        <T as BeaconChainTypes>::ColdStore,
    >,
>;

/// An exact canonical block/state snapshot loaded without BLS block replay.
#[derive(Clone, Debug, PartialEq)]
pub struct BeaconSnapshot<E: EthSpec> {
    pub beacon_block: Arc<SignedBeaconBlock<E>>,
    pub beacon_block_root: Hash256,
    pub beacon_state: BeaconState<E>,
    pub(crate) validated_state_root: Hash256,
}

impl<E: EthSpec> BeaconSnapshot<E> {
    /// Returns the exact state root committed by the snapshot block.
    pub fn beacon_state_root(&self) -> Hash256 {
        self.beacon_block.message().state_root()
    }

    /// Returns the state root independently computed when this snapshot was admitted.
    ///
    /// This accessor is a cached read and never hashes or mutates the retained state.
    pub const fn validated_state_root(&self) -> Hash256 {
        self.validated_state_root
    }
}

/// Typed failures from the deliberately narrow PQ startup core.
#[derive(Debug)]
pub enum PqRuntimeError {
    InvalidState(state_processing::PqDevnetStateError),
    InvalidKeyCache(state_processing::PqAttestationCacheError),
    MissingPersistedHead,
    MissingHeadBlock,
    MissingHeadState,
    PersistedHeadBinding(&'static str),
    HeadStateRootMismatch { block: Hash256, state: Hash256 },
    Store(store::Error),
    Aggregation(consensus_signature::AggregationError),
    ForkChoiceStore(crate::beacon_fork_choice_store::Error),
    ForkChoice(fork_choice::Error<crate::beacon_fork_choice_store::Error>),
    MissingForkChoiceHistoryBlock(Hash256),
    MissingForkChoiceHistoryState(Hash256),
    ForkChoiceHistoryBinding(&'static str),
    MissingExecutionNotifier,
    MissingTaskExecutor,
    DeferredRuntimeIntegration,
}

impl std::fmt::Display for PqRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidState(error) => write!(formatter, "{error}"),
            Self::InvalidKeyCache(error) => {
                write!(formatter, "lean PQ devnet V1 key cache rejected: {error:?}")
            }
            Self::MissingPersistedHead => formatter.write_str("PQ canonical head metadata missing"),
            Self::MissingHeadBlock => formatter.write_str("PQ canonical head block missing"),
            Self::MissingHeadState => formatter.write_str("PQ canonical head state missing"),
            Self::PersistedHeadBinding(reason) => {
                write!(
                    formatter,
                    "PQ persisted canonical head binding rejected: {reason}"
                )
            }
            Self::HeadStateRootMismatch { block, state } => write!(
                formatter,
                "PQ canonical head state-root mismatch: block {block:?}, state {state:?}"
            ),
            Self::Store(error) => write!(formatter, "PQ store error: {error:?}"),
            Self::Aggregation(error) => write!(formatter, "PQ aggregation startup error: {error}"),
            Self::ForkChoiceStore(error) => {
                write!(formatter, "PQ fork-choice store initialization failed: {error:?}")
            }
            Self::ForkChoice(error) => {
                write!(formatter, "PQ fork-choice initialization failed: {error:?}")
            }
            Self::MissingForkChoiceHistoryBlock(root) => {
                write!(formatter, "PQ fork-choice history block {root:?} is missing")
            }
            Self::MissingForkChoiceHistoryState(root) => {
                write!(formatter, "PQ fork-choice history state {root:?} is missing")
            }
            Self::ForkChoiceHistoryBinding(reason) => {
                write!(formatter, "PQ fork-choice history binding rejected: {reason}")
            }
            Self::MissingExecutionNotifier => {
                formatter.write_str("PQ execution notifier was not installed")
            }
            Self::MissingTaskExecutor => formatter.write_str("PQ task executor was not installed"),
            Self::DeferredRuntimeIntegration => formatter.write_str(
                "lean PQ devnet network-service assembly, HTTP, timers and validator duties are deferred",
            ),
        }
    }
}

impl std::error::Error for PqRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidState(error) => Some(error),
            Self::InvalidKeyCache(error) => Some(error),
            Self::Aggregation(error) => Some(error),
            Self::MissingPersistedHead
            | Self::MissingHeadBlock
            | Self::MissingHeadState
            | Self::PersistedHeadBinding(_)
            | Self::HeadStateRootMismatch { .. }
            | Self::Store(_)
            | Self::ForkChoiceStore(_)
            | Self::ForkChoice(_)
            | Self::MissingForkChoiceHistoryBlock(_)
            | Self::MissingForkChoiceHistoryState(_)
            | Self::ForkChoiceHistoryBinding(_)
            | Self::MissingExecutionNotifier
            | Self::MissingTaskExecutor
            | Self::DeferredRuntimeIntegration => None,
        }
    }
}

impl From<store::Error> for PqRuntimeError {
    fn from(error: store::Error) -> Self {
        Self::Store(error)
    }
}

fn reconstruct_pq_fork_choice<T: BeaconChainTypes>(
    store: &BeaconStore<T>,
    canonical_head: &BeaconSnapshot<T::EthSpec>,
    spec: &ChainSpec,
) -> Result<(PqForkChoice<T>, ExecutionBlockHash), PqRuntimeError> {
    let head_slot = canonical_head.beacon_state.slot();
    let genesis_slot = spec.genesis_slot;
    let (anchor, mut descendants) = if head_slot == genesis_slot {
        (canonical_head.clone(), Vec::new())
    } else {
        let genesis_block_root = *canonical_head
            .beacon_state
            .get_block_root(genesis_slot)
            .map_err(|error| {
                PqRuntimeError::ForkChoiceStore(
                    crate::beacon_fork_choice_store::Error::BeaconStateError(error),
                )
            })?;
        let genesis_state_root = *canonical_head
            .beacon_state
            .get_state_root(genesis_slot)
            .map_err(|error| {
                PqRuntimeError::ForkChoiceStore(
                    crate::beacon_fork_choice_store::Error::BeaconStateError(error),
                )
            })?;
        let genesis_block = store.get_full_block(&genesis_block_root)?.ok_or(
            PqRuntimeError::MissingForkChoiceHistoryBlock(genesis_block_root),
        )?;
        let mut genesis_state = store
            .get_state(&genesis_state_root, Some(genesis_slot), true)?
            .ok_or(PqRuntimeError::MissingForkChoiceHistoryState(
                genesis_state_root,
            ))?;
        if genesis_block.canonical_root() != genesis_block_root
            || genesis_block.message().state_root() != genesis_state_root
            || genesis_state
                .update_tree_hash_cache()
                .map_err(store::Error::from)?
                != genesis_state_root
        {
            return Err(PqRuntimeError::ForkChoiceHistoryBinding(
                "genesis block and state do not match the canonical history roots",
            ));
        }
        let anchor = BeaconSnapshot {
            beacon_block: Arc::new(genesis_block),
            beacon_block_root: genesis_block_root,
            beacon_state: genesis_state,
            validated_state_root: genesis_state_root,
        };

        let mut descendants = Vec::new();
        let mut descendant_root = canonical_head.beacon_block_root;
        while descendant_root != genesis_block_root {
            if descendants.len() >= T::EthSpec::slots_per_historical_root() {
                return Err(PqRuntimeError::ForkChoiceHistoryBinding(
                    "canonical history exceeds the bounded V1 reconstruction window",
                ));
            }
            let block = store.get_full_block(&descendant_root)?.ok_or(
                PqRuntimeError::MissingForkChoiceHistoryBlock(descendant_root),
            )?;
            if block.canonical_root() != descendant_root || block.slot() <= genesis_slot {
                return Err(PqRuntimeError::ForkChoiceHistoryBinding(
                    "canonical descendant block root or slot is invalid",
                ));
            }
            let state_root = block.message().state_root();
            let mut state = store
                .get_state(&state_root, Some(block.slot()), true)?
                .ok_or(PqRuntimeError::MissingForkChoiceHistoryState(state_root))?;
            if state.slot() != block.slot()
                || state.update_tree_hash_cache().map_err(store::Error::from)? != state_root
            {
                return Err(PqRuntimeError::ForkChoiceHistoryBinding(
                    "canonical descendant state does not match its block",
                ));
            }
            descendant_root = block.parent_root();
            descendants.push((block, state));
        }
        descendants.reverse();
        (anchor, descendants)
    };

    let genesis_execution_hash = anchor
        .beacon_state
        .latest_execution_payload_header()
        .map_err(|_| {
            PqRuntimeError::PersistedHeadBinding("genesis state has no execution payload header")
        })?
        .block_hash();
    let fork_choice_store =
        crate::beacon_fork_choice_store::BeaconForkChoiceStore::get_forkchoice_store(
            Arc::clone(store),
            anchor.clone(),
        )
        .map_err(PqRuntimeError::ForkChoiceStore)?;
    let mut fork_choice = fork_choice::ForkChoice::from_anchor(
        fork_choice_store,
        anchor.beacon_block_root,
        anchor.beacon_block.as_ref(),
        &anchor.beacon_state,
        Some(head_slot),
        spec,
    )
    .map_err(PqRuntimeError::ForkChoice)?;
    for (block, state) in descendants.drain(..) {
        let block_root = block.canonical_root();
        fork_choice
            .on_block(
                head_slot,
                block.message(),
                block_root,
                spec.get_attestation_due::<T::EthSpec>(block.slot()),
                &state,
                fork_choice::PayloadVerificationStatus::Verified,
                spec,
            )
            .map_err(PqRuntimeError::ForkChoice)?;
    }
    let (reconstructed_head, _) = fork_choice
        .get_head(head_slot, spec)
        .map_err(PqRuntimeError::ForkChoice)?;
    if reconstructed_head != canonical_head.beacon_block_root {
        return Err(PqRuntimeError::ForkChoiceHistoryBinding(
            "reconstructed fork-choice head does not match the durable canonical head",
        ));
    }
    Ok((fork_choice, genesis_execution_hash))
}

/// Immutable ownership root for the Task 5.3e-b PQ runtime.
pub struct BeaconChain<T: BeaconChainTypes> {
    pub spec: Arc<ChainSpec>,
    pub store: BeaconStore<T>,
    pub(crate) canonical_head: Arc<RwLock<Arc<BeaconSnapshot<T::EthSpec>>>>,
    pq_fork_choice: Option<Arc<Mutex<PqForkChoice<T>>>>,
    pub(crate) observed_pq_blocks: Arc<Mutex<crate::pq_import::PqGossipObservationCache>>,
    pub(crate) pq_import_gate: Arc<tokio::sync::Semaphore>,
    pub(crate) pq_import_admission: Arc<tokio::sync::Semaphore>,
    pub(crate) pq_import_coordinator: Arc<PqImportCoordinator>,
    pub(crate) pq_block_production_admission: Arc<tokio::sync::Semaphore>,
    pub(crate) pq_proposer_duty_admission: Arc<tokio::sync::Semaphore>,
    pub(crate) pq_local_attester_context_admission: Arc<tokio::sync::Semaphore>,
    pub(crate) pq_attestation_gossip_admission: Arc<tokio::sync::Semaphore>,
    pq_local_attestation_proof_admission: Arc<tokio::sync::Semaphore>,
    pub(crate) pq_attestation_gossip_observations:
        Arc<Mutex<crate::pq_attestation_gossip::PqAttestationGossipObservationCache<T::EthSpec>>>,
    pub(crate) pq_execution_notifier: crate::pq_import::PqExecutionNotifier<T::EthSpec>,
    pub(crate) pq_genesis_execution_hash: ExecutionBlockHash,
    pub(crate) pq_operational_events: Option<std::sync::Weak<crate::PqOperationalEventSink>>,
    pub(crate) pq_execution_reconciliation: Arc<PqExecutionReconciliation>,
    pub(crate) task_executor: TaskExecutor,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_blocking_test_hook: Option<Arc<crate::TestingPqBlockingHook>>,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_persistence_test_hook: Option<Arc<crate::TestingPqBlockingHook>>,
    #[cfg(feature = "pq-startup-testing")]
    pq_fork_choice_block_test_hook: Mutex<Option<Arc<crate::TestingPqBlockingHook>>>,
    #[cfg(feature = "pq-startup-testing")]
    pq_fork_choice_clock_unavailable: std::sync::atomic::AtomicBool,
    #[cfg(feature = "pq-startup-testing")]
    pq_fork_choice_tick_test_hook: Mutex<Option<Arc<crate::TestingPqBlockingHook>>>,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_post_persist_test_hook: Mutex<Option<Arc<crate::TestingPqBlockingHook>>>,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_proposer_duties_test_hook: Option<Arc<crate::TestingPqBlockingHook>>,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_local_attester_context_test_hook: Option<Arc<crate::TestingPqBlockingHook>>,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_remote_attestation_snapshot_test_hook:
        Mutex<Option<Arc<crate::TestingPqBlockingHook>>>,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_attestation_lineage_test_hook: Mutex<Option<Arc<crate::TestingPqBlockingHook>>>,
    #[cfg(feature = "pq-startup-testing")]
    pq_attestation_pool_gossip_post_insert_test_hook:
        Mutex<Option<Arc<crate::TestingPqBlockingHook>>>,
    #[cfg(feature = "pq-startup-testing")]
    pq_attestation_pool_gossip_before_source_trace_test_hook:
        Mutex<Option<Arc<crate::TestingPqBlockingHook>>>,
    #[cfg(feature = "pq-startup-testing")]
    pq_attestation_pool_local_post_insert_test_hook:
        Mutex<Option<Arc<crate::TestingPqBlockingHook>>>,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_attestation_pool_post_selection_test_hook:
        Mutex<Option<Arc<crate::TestingPqBlockingHook>>>,
    #[cfg(feature = "pq-startup-testing")]
    pq_attestation_pool_snapshot_guard: Mutex<()>,
    #[cfg(feature = "pq-startup-testing")]
    pq_attestation_pool_source_trace: Mutex<TestingPqAttestationPoolSourceTrace>,
    #[cfg(feature = "pq-startup-testing")]
    pq_fork_choice_attestation_calls: std::sync::atomic::AtomicUsize,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_local_attestation_batch_verification_calls: std::sync::atomic::AtomicUsize,
    pub pq_validator_key_cache: Arc<PqValidatorKeyCache>,
    pub pq_aggregation_service: Arc<AggregationService>,
    _pq_attestation_pool: Arc<OperationPool<T::EthSpec>>,
    pub(crate) pq_background_attestation_aggregator:
        PqBackgroundAttestationAggregator<T::EthSpec, T::SlotClock>,
    pub slot_clock: T::SlotClock,
    marker: PhantomData<T>,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub(crate) fn try_reserve_pq_attestation_gossip_admission(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.pq_attestation_gossip_admission).try_acquire_owned()
    }

    pub(crate) fn try_reserve_pq_local_attestation_proof_admission(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.pq_local_attestation_proof_admission).try_acquire_owned()
    }

    #[cfg(feature = "pq-startup-testing")]
    pub(crate) fn pq_local_attestation_proof_available_permits(&self) -> usize {
        self.pq_local_attestation_proof_admission
            .available_permits()
    }

    pub(crate) fn try_pq_fork_choice_descendants(
        &self,
        ancestors: &[Hash256],
        descendant: Hash256,
    ) -> Result<Vec<bool>, PqForkChoiceAncestryQueryError> {
        let fork_choice = self
            .pq_fork_choice
            .as_ref()
            .ok_or(PqForkChoiceAncestryQueryError::Unavailable)?;
        let fork_choice = fork_choice
            .try_lock()
            .ok_or(PqForkChoiceAncestryQueryError::Busy)?;
        Ok(ancestors
            .iter()
            .map(|ancestor| fork_choice.is_descendant(*ancestor, descendant))
            .collect())
    }

    pub(crate) fn emit_pq_operational_event(
        &self,
        event: crate::PqOperationalEvent,
    ) -> Result<(), crate::PqOperationalEventError> {
        match self
            .pq_operational_events
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            Some(events) => events.try_emit(event),
            #[cfg(feature = "pq-startup-testing")]
            None => Ok(()),
            #[cfg(not(feature = "pq-startup-testing"))]
            None => Err(crate::PqOperationalEventError::Closed),
        }
    }

    pub(crate) fn fail_pq_operational_events(&self, reason: &'static str) {
        self.pq_import_coordinator.close();
        let _ = self
            .task_executor
            .shutdown_sender()
            .try_send(task_executor::ShutdownReason::Failure(reason));
    }

    /// Records only a freshly imported local publication after its result-bearing broadcaster and
    /// commit path have both completed. Exact committed duplicates never call this method.
    pub fn emit_pq_proposal_published(
        &self,
        slot: types::Slot,
        block_root: types::Hash256,
        signed_ssz_digest: [u8; 32],
    ) -> Result<(), crate::PqOperationalEventError> {
        let result = self.emit_pq_operational_event(crate::PqOperationalEvent::ProposalPublished {
            slot,
            block_root,
            signed_ssz_digest,
        });
        if result.is_err() {
            self.fail_pq_operational_events("PQ proposal-published operational event failed");
        }
        result
    }

    /// Records a freshly committed gossip import only after the admitted gossipsub message has
    /// been resolved terminally. Event failure closes import ingress before signalling shutdown.
    pub fn emit_pq_gossip_imported(
        &self,
        slot: types::Slot,
        block_root: types::Hash256,
        signed_ssz_digest: [u8; 32],
    ) -> Result<(), crate::PqOperationalEventError> {
        let result = self.emit_pq_operational_event(crate::PqOperationalEvent::GossipImported {
            slot,
            block_root,
            signed_ssz_digest,
        });
        if result.is_err() {
            self.fail_pq_operational_events("PQ gossip-imported operational event failed");
        }
        result
    }

    pub(crate) fn new(
        spec: Arc<ChainSpec>,
        store: BeaconStore<T>,
        canonical_head: BeaconSnapshot<T::EthSpec>,
        pq_validator_key_cache: Arc<PqValidatorKeyCache>,
        pq_aggregation_service: Arc<AggregationService>,
        pq_execution_notifier: crate::pq_import::PqExecutionNotifier<T::EthSpec>,
        pq_operational_events: Option<std::sync::Weak<crate::PqOperationalEventSink>>,
        task_executor: TaskExecutor,
        #[cfg(feature = "pq-startup-testing")] pq_blocking_test_hook: Option<
            Arc<crate::TestingPqBlockingHook>,
        >,
        #[cfg(feature = "pq-startup-testing")] pq_persistence_test_hook: Option<
            Arc<crate::TestingPqBlockingHook>,
        >,
        #[cfg(feature = "pq-startup-testing")] pq_proposer_duties_test_hook: Option<
            Arc<crate::TestingPqBlockingHook>,
        >,
        #[cfg(feature = "pq-startup-testing")] pq_local_attester_context_test_hook: Option<
            Arc<crate::TestingPqBlockingHook>,
        >,
        slot_clock: T::SlotClock,
    ) -> Result<Self, PqRuntimeError> {
        let initial_block_root = canonical_head.beacon_block_root;
        let pq_attestation_pool = Arc::new(OperationPool::new(Arc::clone(&pq_aggregation_service)));
        let (fork_choice, pq_genesis_execution_hash) =
            reconstruct_pq_fork_choice::<T>(&store, &canonical_head, &spec)?;
        let pq_fork_choice = Some(Arc::new(Mutex::new(fork_choice)));
        let canonical_head = Arc::new(RwLock::new(Arc::new(canonical_head)));
        let pq_execution_reconciliation = Arc::new(PqExecutionReconciliation::new(
            PqExecutionReconciliationState::Pending {
                block_root: initial_block_root,
            },
        ));
        let pq_background_attestation_aggregator = PqBackgroundAttestationAggregator::spawn(
            Arc::clone(&pq_attestation_pool),
            Arc::clone(&canonical_head),
            Arc::clone(&pq_execution_reconciliation),
            Arc::clone(&pq_validator_key_cache),
            Arc::clone(&spec),
            slot_clock.clone(),
            task_executor.clone(),
        )
        .ok_or(PqRuntimeError::MissingTaskExecutor)?;
        Ok(Self {
            spec,
            store,
            canonical_head,
            pq_fork_choice,
            observed_pq_blocks: Arc::new(Mutex::new(
                crate::pq_import::PqGossipObservationCache::default(),
            )),
            pq_import_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            pq_import_admission: Arc::new(tokio::sync::Semaphore::new(
                crate::PQ_BLOCK_IMPORT_ADMISSION_CAPACITY,
            )),
            pq_import_coordinator: Arc::new(PqImportCoordinator::default()),
            pq_block_production_admission: Arc::new(tokio::sync::Semaphore::new(
                crate::PQ_BLOCK_PRODUCTION_ADMISSION_CAPACITY,
            )),
            pq_proposer_duty_admission: Arc::new(tokio::sync::Semaphore::new(
                crate::PQ_PROPOSER_DUTY_ADMISSION_CAPACITY,
            )),
            pq_local_attester_context_admission: Arc::new(tokio::sync::Semaphore::new(
                crate::PQ_LOCAL_ATTESTATION_CONTEXT_ADMISSION_CAPACITY,
            )),
            pq_attestation_gossip_admission: Arc::new(tokio::sync::Semaphore::new(
                crate::PQ_ATTESTATION_GOSSIP_ADMISSION_CAPACITY,
            )),
            pq_local_attestation_proof_admission: Arc::new(tokio::sync::Semaphore::new(
                crate::PQ_LOCAL_ATTESTATION_PROOF_ADMISSION_CAPACITY,
            )),
            pq_attestation_gossip_observations: Arc::new(Mutex::new(
                crate::pq_attestation_gossip::PqAttestationGossipObservationCache::default(),
            )),
            pq_execution_notifier,
            pq_genesis_execution_hash,
            pq_operational_events,
            pq_execution_reconciliation,
            task_executor,
            #[cfg(feature = "pq-startup-testing")]
            pq_blocking_test_hook,
            #[cfg(feature = "pq-startup-testing")]
            pq_persistence_test_hook,
            #[cfg(feature = "pq-startup-testing")]
            pq_fork_choice_block_test_hook: Mutex::new(None),
            #[cfg(feature = "pq-startup-testing")]
            pq_fork_choice_clock_unavailable: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "pq-startup-testing")]
            pq_fork_choice_tick_test_hook: Mutex::new(None),
            #[cfg(feature = "pq-startup-testing")]
            pq_post_persist_test_hook: Mutex::new(None),
            #[cfg(feature = "pq-startup-testing")]
            pq_proposer_duties_test_hook,
            #[cfg(feature = "pq-startup-testing")]
            pq_local_attester_context_test_hook,
            #[cfg(feature = "pq-startup-testing")]
            pq_remote_attestation_snapshot_test_hook: Mutex::new(None),
            #[cfg(feature = "pq-startup-testing")]
            pq_attestation_lineage_test_hook: Mutex::new(None),
            #[cfg(feature = "pq-startup-testing")]
            pq_attestation_pool_gossip_post_insert_test_hook: Mutex::new(None),
            #[cfg(feature = "pq-startup-testing")]
            pq_attestation_pool_gossip_before_source_trace_test_hook: Mutex::new(None),
            #[cfg(feature = "pq-startup-testing")]
            pq_attestation_pool_local_post_insert_test_hook: Mutex::new(None),
            #[cfg(feature = "pq-startup-testing")]
            pq_attestation_pool_post_selection_test_hook: Mutex::new(None),
            #[cfg(feature = "pq-startup-testing")]
            pq_attestation_pool_snapshot_guard: Mutex::new(()),
            #[cfg(feature = "pq-startup-testing")]
            pq_attestation_pool_source_trace: Mutex::new(
                TestingPqAttestationPoolSourceTrace::default(),
            ),
            #[cfg(feature = "pq-startup-testing")]
            pq_fork_choice_attestation_calls: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(feature = "pq-startup-testing")]
            pq_local_attestation_batch_verification_calls: std::sync::atomic::AtomicUsize::new(0),
            pq_validator_key_cache,
            pq_aggregation_service,
            _pq_attestation_pool: pq_attestation_pool,
            pq_background_attestation_aggregator,
            slot_clock,
            marker: PhantomData,
        })
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_attestation_pool_uses_aggregation_service(
        &self,
        service: &Arc<AggregationService>,
    ) -> bool {
        self._pq_attestation_pool
            .testing_only_pq_uses_aggregation_service(service)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_attestation_pool_snapshot(
        &self,
    ) -> operation_pool::TestingPqAttestationPoolSnapshot {
        let _snapshot_guard = self.pq_attestation_pool_snapshot_guard.lock();
        let mut snapshot = self._pq_attestation_pool.testing_only_pq_snapshot();
        let trace = self.pq_attestation_pool_source_trace.lock();
        snapshot.gossip_inserted = trace.gossip_inserted;
        snapshot.gossip_dominated = trace.gossip_dominated;
        snapshot.gossip_removed_subsets = trace.gossip_removed_subsets;
        snapshot.local_inserted = trace.local_inserted;
        snapshot.local_dominated = trace.local_dominated;
        snapshot.local_removed_subsets = trace.local_removed_subsets;
        snapshot
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_attestation_pool_gossip_post_insert_hook(
        &self,
        hook: Option<Arc<crate::TestingPqBlockingHook>>,
    ) {
        *self.pq_attestation_pool_gossip_post_insert_test_hook.lock() = hook;
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_attestation_pool_gossip_before_source_trace_hook(
        &self,
        hook: Option<Arc<crate::TestingPqBlockingHook>>,
    ) {
        *self
            .pq_attestation_pool_gossip_before_source_trace_test_hook
            .lock() = hook;
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_attestation_pool_local_post_insert_hook(
        &self,
        hook: Option<Arc<crate::TestingPqBlockingHook>>,
    ) {
        *self.pq_attestation_pool_local_post_insert_test_hook.lock() = hook;
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_insert_pq_attestation_pool_candidate(
        &self,
        candidate: state_processing::VerifiedPqAttestation<T::EthSpec>,
    ) -> Result<(), PqAttestationPoolInsertInvariant> {
        self.insert_pq_gossip_attestation_pool_candidate(candidate)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_attestation_pool_post_selection_hook(
        &self,
        hook: Option<Arc<crate::TestingPqBlockingHook>>,
    ) {
        *self.pq_attestation_pool_post_selection_test_hook.lock() = hook;
    }

    pub(crate) fn select_pq_attestations_for_block(
        &self,
        state: &types::BeaconState<T::EthSpec>,
        key_cache: &PqValidatorKeyCache,
        spec: &types::ChainSpec,
    ) -> Result<
        operation_pool::PqBlockAttestationSelection<T::EthSpec>,
        state_processing::PqBlockAttestationSelectionError,
    > {
        let selection = self
            ._pq_attestation_pool
            .select_pq_attestations_for_block(state, key_cache, spec)?;
        #[cfg(feature = "pq-startup-testing")]
        if let Some(hook) = self
            .pq_attestation_pool_post_selection_test_hook
            .lock()
            .clone()
        {
            hook.run();
        }
        Ok(selection)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_attestation_pool_next_generation(&self, next_generation: u64) {
        self._pq_attestation_pool
            .testing_only_set_pq_next_generation(next_generation);
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_try_lock_pq_fork_choice(&self) -> bool {
        self.pq_fork_choice
            .as_ref()
            .and_then(|fork_choice| fork_choice.try_lock())
            .is_some()
    }

    fn insert_pq_gossip_attestation_pool_candidate(
        &self,
        candidate: state_processing::VerifiedPqAttestation<T::EthSpec>,
    ) -> Result<(), PqAttestationPoolInsertInvariant> {
        #[cfg(feature = "pq-startup-testing")]
        let snapshot_guard = self.pq_attestation_pool_snapshot_guard.lock();
        let _disposition = self._pq_attestation_pool.insert_verified(candidate)?;
        #[cfg(feature = "pq-startup-testing")]
        {
            if let Some(hook) = self
                .pq_attestation_pool_gossip_before_source_trace_test_hook
                .lock()
                .clone()
            {
                hook.run();
            }
            let mut trace = self.pq_attestation_pool_source_trace.lock();
            match _disposition {
                PqAttestationPoolInsertDisposition::Inserted { removed_subsets } => {
                    trace.gossip_inserted = trace.gossip_inserted.saturating_add(1);
                    trace.gossip_removed_subsets =
                        trace.gossip_removed_subsets.saturating_add(removed_subsets);
                }
                PqAttestationPoolInsertDisposition::Dominated => {
                    trace.gossip_dominated = trace.gossip_dominated.saturating_add(1);
                }
                PqAttestationPoolInsertDisposition::ResourceLimited(_) => {}
            }
            drop(trace);
            drop(snapshot_guard);
            if let Some(hook) = self
                .pq_attestation_pool_gossip_post_insert_test_hook
                .lock()
                .clone()
            {
                hook.run();
            }
        }
        self.pq_background_attestation_aggregator.kick();
        Ok(())
    }

    #[cfg(feature = "pq-proposer")]
    fn insert_pq_local_attestation_pool_candidate(
        &self,
        candidate: state_processing::VerifiedPqAttestation<T::EthSpec>,
    ) -> Result<(), PqAttestationPoolInsertInvariant> {
        #[cfg(feature = "pq-startup-testing")]
        let snapshot_guard = self.pq_attestation_pool_snapshot_guard.lock();
        let _disposition = self._pq_attestation_pool.insert_verified(candidate)?;
        #[cfg(feature = "pq-startup-testing")]
        {
            let mut trace = self.pq_attestation_pool_source_trace.lock();
            match _disposition {
                PqAttestationPoolInsertDisposition::Inserted { removed_subsets } => {
                    trace.local_inserted = trace.local_inserted.saturating_add(1);
                    trace.local_removed_subsets =
                        trace.local_removed_subsets.saturating_add(removed_subsets);
                }
                PqAttestationPoolInsertDisposition::Dominated => {
                    trace.local_dominated = trace.local_dominated.saturating_add(1);
                }
                PqAttestationPoolInsertDisposition::ResourceLimited(_) => {}
            }
            drop(trace);
            drop(snapshot_guard);
            if let Some(hook) = self
                .pq_attestation_pool_local_post_insert_test_hook
                .lock()
                .clone()
            {
                hook.run();
            }
        }
        self.pq_background_attestation_aggregator.kick();
        Ok(())
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_remote_attestation_snapshot_hook(
        &self,
        hook: Option<Arc<crate::TestingPqBlockingHook>>,
    ) {
        *self.pq_remote_attestation_snapshot_test_hook.lock() = hook;
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_attestation_lineage_hook(
        &self,
        hook: Option<Arc<crate::TestingPqBlockingHook>>,
    ) {
        *self.pq_attestation_lineage_test_hook.lock() = hook;
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_local_attestation_batch_verification_count(&self) -> usize {
        self.pq_local_attestation_batch_verification_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Returns the exact snapshot which was strictly validated before worker construction.
    pub fn head_snapshot(&self) -> Arc<BeaconSnapshot<T::EthSpec>> {
        self.canonical_head.read().clone()
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_replace_pq_canonical_head_root(&self, block_root: Hash256) {
        let mut snapshot = (*self.head_snapshot()).clone();
        snapshot.beacon_block_root = block_root;
        *self.canonical_head.write() = Arc::new(snapshot);
    }

    pub(crate) async fn on_reconciled_pq_block(
        &self,
        snapshot: Arc<BeaconSnapshot<T::EthSpec>>,
    ) -> Result<(), crate::PqImportError> {
        let Some(fork_choice) = &self.pq_fork_choice else {
            return Ok(());
        };
        #[cfg(feature = "pq-startup-testing")]
        let current_slot = if self
            .pq_fork_choice_clock_unavailable
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            None
        } else {
            self.slot_clock.now()
        };
        #[cfg(not(feature = "pq-startup-testing"))]
        let current_slot = self.slot_clock.now();
        let current_slot = current_slot.ok_or(crate::PqImportError::DurableStateUnknown {
            phase: "pq-fork-choice-on-reconciled-block",
        })?;
        let fork_choice = Arc::clone(fork_choice);
        let spec = Arc::clone(&self.spec);
        #[cfg(feature = "pq-startup-testing")]
        let test_hook = self.pq_fork_choice_block_test_hook.lock().clone();
        let Some(task) = self.task_executor.spawn_blocking_handle_without_exit(
            move || {
                #[cfg(feature = "pq-startup-testing")]
                if let Some(hook) = test_hook {
                    hook.run();
                }
                fork_choice
                    .lock()
                    .on_block(
                        current_slot,
                        snapshot.beacon_block.message(),
                        snapshot.beacon_block_root,
                        Duration::ZERO,
                        &snapshot.beacon_state,
                        fork_choice::PayloadVerificationStatus::Verified,
                        &spec,
                    )
                    .map_err(crate::PqImportError::ForkChoice)
            },
            "pq-fork-choice-on-reconciled-block",
        ) else {
            return Err(crate::PqImportError::DurableStateUnknown {
                phase: "pq-fork-choice-on-reconciled-block",
            });
        };
        match task.await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => Err(crate::PqImportError::DurableStateUnknown {
                phase: "pq-fork-choice-on-reconciled-block",
            }),
        }
    }

    fn try_start_pq_fork_choice_ingress(
        &self,
    ) -> Result<
        (Arc<PqImportActivity>, tokio::sync::OwnedSemaphorePermit),
        PqForkChoiceAttestationError,
    > {
        let activity = self
            .pq_import_coordinator
            .try_start()
            .ok_or(PqForkChoiceAttestationError::ShuttingDown)?;
        let admission = Arc::clone(&self.pq_attestation_gossip_admission)
            .try_acquire_owned()
            .map_err(|_| PqForkChoiceAttestationError::IngressCapacity)?;
        Ok((activity, admission))
    }

    /// Consumes only the sealed result of PQ single-attestation gossip verification. The shared
    /// activity owner makes shutdown account for this update, while the nonwaiting admission
    /// preserves the frozen two-item proof/fork-choice bound.
    pub async fn consume_pq_verified_gossip_single(
        self: &Arc<Self>,
        verified: crate::PqVerifiedGossipSingle<T::EthSpec>,
    ) -> Result<PqForkChoiceAttestationOutcome, PqForkChoiceAttestationError> {
        let chain = Arc::clone(self);
        let coordinator = Arc::clone(&self.pq_import_coordinator);
        let Some(task) = self.task_executor.spawn_handle_without_exit(
            async move {
                let mut panic_guard = PqImportPanicGuard::new(coordinator);
                let result = chain
                    .consume_pq_verified_gossip_single_continuation(verified)
                    .await;
                panic_guard.disarm();
                if result.is_err() {
                    chain.fail_pq_fork_choice_task();
                }
                result
            },
            "pq-attestation-fork-choice-consume",
        ) else {
            self.fail_pq_fork_choice_task();
            return Err(PqForkChoiceAttestationError::TaskUnavailable);
        };
        match task.await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) if error.is_panic() => {
                // `spawn_handle_without_exit` monitors panics and is the sole process-failure
                // signal owner. `PqImportPanicGuard` has already closed ingress while unwinding.
                Err(PqForkChoiceAttestationError::TaskUnavailable)
            }
            Ok(Err(_)) | Err(_) => {
                self.fail_pq_fork_choice_task();
                Err(PqForkChoiceAttestationError::TaskUnavailable)
            }
        }
    }

    fn fail_pq_fork_choice_task(&self) {
        self.pq_import_coordinator.close();
        let mut shutdown = self.task_executor.shutdown_sender();
        let _ = shutdown.try_send(task_executor::ShutdownReason::Failure(
            "PQ fork-choice task failed",
        ));
    }

    /// Fail closed after an already-propagated PQ attestation cannot be consumed locally.
    pub fn fail_pq_attestation_after_propagation(&self) {
        self.fail_pq_fork_choice_task();
    }

    /// Binds the sole post-publication consumption authority to this chain instance.
    #[cfg(feature = "pq-proposer")]
    pub fn pq_published_local_attestation_batch_consumer(
        self: &Arc<Self>,
    ) -> PqPublishedLocalAttestationBatchConsumer<T> {
        PqPublishedLocalAttestationBatchConsumer {
            chain: Arc::clone(self),
        }
    }

    /// Consumes one complete, already-published local PQ attestation batch.
    ///
    /// The sealed batch is the sole authority: exact observation identities and deterministic
    /// member order are inferred internally. The monitored continuation retains every proof,
    /// admission and activity guard until all local fork-choice results are finalized.
    #[cfg(feature = "pq-proposer")]
    async fn consume_pq_published_local_attestation_batch(
        self: &Arc<Self>,
        evidence: crate::PqPublishedLocalAttestationEvidenceBatch<T::EthSpec>,
    ) -> Result<
        crate::PqPublishedLocalAttestationBatchConsumptionOutcome,
        crate::PqPublishedLocalAttestationBatchConsumptionError,
    > {
        let failure_sent = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let chain = Arc::clone(self);
        let task_failure_sent = Arc::clone(&failure_sent);
        let Some(task) = self.task_executor.spawn_handle_without_exit(
            async move {
                chain
                    .consume_pq_published_local_attestation_batch_continuation(
                        evidence,
                        task_failure_sent,
                    )
                    .await
            },
            "pq-published-local-attestation-batch-consume",
        ) else {
            self.fail_pq_fork_choice_task_once(&failure_sent);
            return Err(crate::PqPublishedLocalAttestationBatchConsumptionError::TaskUnavailable);
        };
        match task.await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => {
                self.fail_pq_fork_choice_task_once(&failure_sent);
                Err(crate::PqPublishedLocalAttestationBatchConsumptionError::TaskUnavailable)
            }
        }
    }

    #[cfg(feature = "pq-proposer")]
    async fn consume_pq_published_local_attestation_batch_continuation(
        self: &Arc<Self>,
        evidence: crate::PqPublishedLocalAttestationEvidenceBatch<T::EthSpec>,
        failure_sent: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<
        crate::PqPublishedLocalAttestationBatchConsumptionOutcome,
        crate::PqPublishedLocalAttestationBatchConsumptionError,
    > {
        let fail_chain = Arc::clone(self);
        let guard_failure_sent = Arc::clone(&failure_sent);
        let mut fail_closed = PqPostWireFailClosedGuard::new(move || {
            fail_chain.fail_pq_fork_choice_task_once(&guard_failure_sent);
        });
        let result = self
            .consume_pq_published_local_attestation_batch_inner(evidence, failure_sent)
            .await;
        if result.is_ok() {
            fail_closed.disarm();
        }
        result
    }

    #[cfg(feature = "pq-proposer")]
    async fn consume_pq_published_local_attestation_batch_inner(
        self: &Arc<Self>,
        evidence: crate::PqPublishedLocalAttestationEvidenceBatch<T::EthSpec>,
        failure_sent: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<
        crate::PqPublishedLocalAttestationBatchConsumptionOutcome,
        crate::PqPublishedLocalAttestationBatchConsumptionError,
    > {
        let crate::PqLocalAttestationBatchPreflightOutcome::Ready { slot, .. } = self
            .preflight_pq_local_attestation_batch(evidence.verified())
            .map_err(crate::PqPublishedLocalAttestationBatchConsumptionError::Preflight)?;
        let publication_members = self
            .validate_pq_local_attestation_publication_evidence(&evidence)
            .map_err(crate::PqPublishedLocalAttestationBatchConsumptionError::Evidence)?;
        let (batch, _evidence) = evidence.into_parts();
        let indexed = batch
            .verified()
            .iter()
            .enumerate()
            .map(|(index, verified)| {
                verified
                    .single()
                    .to_indexed::<T::EthSpec>(types::ForkName::Electra)
                    .map_err(|_| {
                        crate::PqPublishedLocalAttestationBatchConsumptionError::InvalidIndexedAttestation {
                            index,
                        }
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let earliest_slot = (slot - T::EthSpec::slots_per_epoch())
            .epoch(T::EthSpec::slots_per_epoch())
            .start_slot(T::EthSpec::slots_per_epoch());
        let fail_chain = Arc::clone(self);
        let owner_failure_sent = Arc::clone(&failure_sent);
        let owner = crate::pq_attestation_gossip::PqSingleObservationBatchResolutionOwner::resolve_publication_evidence(
            Arc::clone(&self.pq_attestation_gossip_observations),
            &publication_members,
            earliest_slot,
            Some(Box::new(move || {
                fail_chain.fail_pq_fork_choice_task_once(&owner_failure_sent);
            })),
        )
        .map_err(crate::PqPublishedLocalAttestationBatchConsumptionError::Observation)?;
        let owner = owner.settle_remote_members().await?;
        let late_apply = self
            .acquire_pq_local_attestation_late_apply_context(&batch)
            .await
            .map_err(crate::PqPublishedLocalAttestationBatchConsumptionError::Preflight)?;
        let fork_choice = self
            .pq_fork_choice
            .as_ref()
            .map(Arc::clone)
            .ok_or(crate::PqPublishedLocalAttestationBatchConsumptionError::TaskUnavailable)?;
        let spec = Arc::clone(&self.spec);
        let slot_clock = self.slot_clock.clone();
        let mut pool_candidates = batch.into_pool_candidate_batch();
        let pool_chain = Arc::clone(self);
        #[cfg(feature = "pq-startup-testing")]
        let call_chain = Arc::clone(self);
        let Some(blocking) = self.task_executor.spawn_blocking_handle_without_exit(
            move || {
                let mut fork_choice = fork_choice.lock();
                let result = crate::pq_local_attester_context::consume_pq_published_local_attestation_batch_after_settlement(
                    late_apply,
                    &mut *fork_choice,
                    || slot_clock.now(),
                    |fork_choice| fork_choice.fc_store().get_current_slot(),
                    |fork_choice, bound, current| fork_choice.is_descendant(bound, current),
                    |fork_choice, current_slot| {
                        // Every member follows one irreversible order: fork-choice disposition,
                        // then sealed pool insertion, then observation finalization.  The
                        // callback runs for both fresh-local and coalesced dispositions before
                        // `consume_all_local_after_disposition` finalizes any local reservation.
                        owner.consume_all_local_after_disposition(
                            |index| {
                                let indexed = indexed.get(index).ok_or(())?;
                                let queued_before = fork_choice.queued_attestations().len();
                                fork_choice
                                    .on_attestation(
                                        current_slot,
                                        indexed.to_ref(),
                                        fork_choice::AttestationFromBlock::False,
                                        &spec,
                                    )
                                    .map_err(|_| ())?;
                                #[cfg(feature = "pq-startup-testing")]
                                call_chain
                                    .pq_fork_choice_attestation_calls
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                if fork_choice.queued_attestations().len() > queued_before {
                                    Ok::<PqForkChoiceAttestationOutcome, ()>(
                                        PqForkChoiceAttestationOutcome::Queued,
                                    )
                                } else {
                                    Ok::<PqForkChoiceAttestationOutcome, ()>(
                                        PqForkChoiceAttestationOutcome::Applied,
                                    )
                                }
                            },
                            |index, _result| {
                                let (validator_index, candidate) = pool_candidates.take(index).ok_or(
                                    PqAttestationPoolInsertInvariant::UnsupportedCandidate,
                                )?;
                                if candidate.signer_indices() != [validator_index] {
                                    return Err(
                                        PqAttestationPoolInsertInvariant::UnsupportedCandidate,
                                    );
                                }
                                // A fresh local member reaches fork choice first; both fresh and
                                // coalesced members then move their exact sealed candidate into the
                                // pool before their observation reservation is finalized.
                                pool_chain
                                    .insert_pq_local_attestation_pool_candidate(candidate)?;
                                Ok(())
                            },
                        )
                    },
                )
                .map_err(crate::PqPublishedLocalAttestationBatchConsumptionError::Preflight)
                .and_then(std::convert::identity);
                result
            },
            "pq-published-local-attestation-batch-fork-choice",
        ) else {
            self.fail_pq_fork_choice_task_once(&failure_sent);
            return Err(crate::PqPublishedLocalAttestationBatchConsumptionError::TaskUnavailable);
        };
        match blocking.await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => {
                self.fail_pq_fork_choice_task_once(&failure_sent);
                Err(crate::PqPublishedLocalAttestationBatchConsumptionError::TaskUnavailable)
            }
        }
    }

    #[cfg(feature = "pq-proposer")]
    fn validate_pq_local_attestation_publication_evidence(
        &self,
        evidence: &crate::PqPublishedLocalAttestationEvidenceBatch<T::EthSpec>,
    ) -> Result<
        Vec<(
            crate::PqSingleObservationIdentity,
            crate::PqSingleWireMessageId,
            Option<crate::PqSingleConsumptionResult>,
        )>,
        crate::PqPublishedLocalAttestationEvidenceError,
    > {
        let verified = evidence.verified().verified();
        if verified.len() != evidence.members().len() {
            return Err(
                crate::PqPublishedLocalAttestationEvidenceError::CountMismatch {
                    expected: verified.len(),
                    actual: evidence.members().len(),
                },
            );
        }
        verified
            .iter()
            .zip(evidence.members())
            .enumerate()
            .map(|(member, (verified, publication))| {
                let signed_ssz = ssz::Encode::as_ssz_bytes(verified.single());
                let signed_ssz_digest: [u8; 32] = Sha256::digest(&signed_ssz).into();
                if signed_ssz_digest != verified.signed_ssz_digest() {
                    return Err(crate::PqPublishedLocalAttestationEvidenceError::Mismatch {
                        member,
                        field: "verified-signed-ssz-digest",
                    });
                }
                let fork_digest = self
                    .spec
                    .enr_fork_id::<T::EthSpec>(
                        verified.slot(),
                        self.head_snapshot().beacon_state.genesis_validators_root(),
                    )
                    .fork_digest;
                let gossip_topic = GossipTopic::new(
                    GossipKind::Attestation(verified.subnet()),
                    GossipEncoding::default(),
                    fork_digest,
                );
                let topic = IdentTopic::from(gossip_topic);
                let topic_hash = topic.hash();
                let message_id = pq_anonymous_message_id(
                    &topic_hash,
                    &signed_ssz,
                    self.spec.message_domain_valid_snappy,
                    self.spec
                        .fork_name_at_slot::<T::EthSpec>(verified.slot())
                        .altair_enabled(),
                );
                let remote_result = match publication {
                    crate::PqPublishedLocalAttestationMemberEvidence::Local(token) => {
                        validate_pq_local_single_publication_token(
                            member,
                            token,
                            &message_id,
                            &topic_hash,
                            fork_digest,
                            verified.subnet(),
                            signed_ssz_digest,
                        )?;
                        None
                    }
                    crate::PqPublishedLocalAttestationMemberEvidence::Remote {
                        message_id: claimed_message_id,
                        result,
                    } => {
                        if claimed_message_id != &message_id {
                            return Err(
                                crate::PqPublishedLocalAttestationEvidenceError::Mismatch {
                                    member,
                                    field: "remote-message-id",
                                },
                            );
                        }
                        if !matches!(
                            result,
                            crate::PqSingleConsumptionResult::Applied
                                | crate::PqSingleConsumptionResult::Queued
                        ) {
                            return Err(
                                crate::PqPublishedLocalAttestationEvidenceError::RemoteResult {
                                    member,
                                },
                            );
                        }
                        Some(*result)
                    }
                };
                let wire_id = crate::PqSingleWireMessageId::try_from(message_id.0.as_slice())
                    .map_err(
                        |_| crate::PqPublishedLocalAttestationEvidenceError::Mismatch {
                            member,
                            field: "message-id-length",
                        },
                    )?;
                Ok((verified.observation_identity(), wire_id, remote_result))
            })
            .collect()
    }

    #[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
    #[cfg(feature = "pq-proposer")]
    fn fail_pq_fork_choice_task_once(&self, failure_sent: &std::sync::atomic::AtomicBool) {
        if !failure_sent.swap(true, std::sync::atomic::Ordering::AcqRel) {
            self.fail_pq_fork_choice_task();
        }
    }

    async fn consume_pq_verified_gossip_single_continuation(
        self: &Arc<Self>,
        verified: crate::PqVerifiedGossipSingle<T::EthSpec>,
    ) -> Result<PqForkChoiceAttestationOutcome, PqForkChoiceAttestationError> {
        let fork_choice = self
            .pq_fork_choice
            .as_ref()
            .map(Arc::clone)
            .ok_or(PqForkChoiceAttestationError::Unavailable)?;
        let (verified, _, bound_head_root, consumption) = verified
            .into_consumption_parts()
            .map_err(|_| PqForkChoiceAttestationError::ObservationLost)?;
        match self
            .pq_execution_reconciliation
            .wait_for(bound_head_root)
            .await
        {
            PqExecutionReconciliationState::Reconciled { block_root }
                if block_root == bound_head_root => {}
            PqExecutionReconciliationState::Failed { block_root }
                if block_root == bound_head_root =>
            {
                let _ = consumption.finalize_terminal();
                return Err(PqForkChoiceAttestationError::ReconciliationFailed { block_root });
            }
            _ if fork_choice.lock().contains_block(&bound_head_root) => {}
            _ => {
                return Err(PqForkChoiceAttestationError::BoundHeadUnavailable {
                    block_root: bound_head_root,
                });
            }
        }
        let current_slot = self
            .slot_clock
            .now()
            .ok_or(PqForkChoiceAttestationError::ClockUnavailable)?;
        let indexed = verified
            .single_attestation()
            .to_indexed::<T::EthSpec>(types::ForkName::Electra)
            .map_err(|_| PqForkChoiceAttestationError::InvalidIndexedAttestation)?;
        let (_single, pool_candidate) = verified.into_parts();
        let spec = Arc::clone(&self.spec);
        let pool_chain = Arc::clone(self);
        let Some(blocking) = self.task_executor.spawn_blocking_handle_without_exit(
            move || {
                let mut fork_choice = fork_choice.lock();
                let queued_before = fork_choice.queued_attestations().len();
                fork_choice
                    .on_attestation(
                        current_slot,
                        indexed.to_ref(),
                        fork_choice::AttestationFromBlock::False,
                        &spec,
                    )
                    .map_err(PqForkChoiceAttestationError::ForkChoice)?;
                let outcome = if fork_choice.queued_attestations().len() > queued_before {
                    PqForkChoiceAttestationOutcome::Queued
                } else {
                    PqForkChoiceAttestationOutcome::Applied
                };
                #[cfg(feature = "pq-startup-testing")]
                pool_chain
                    .pq_fork_choice_attestation_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(fork_choice);
                // Keep the verified candidate sealed through the successful fork-choice
                // disposition, then release the FC guard before touching the independent pool.
                // Observation finalization happens only after this closure returns, so the pool
                // insertion cannot race ahead of fork choice or trail a visible consumed
                // observation.
                pool_chain
                    .insert_pq_gossip_attestation_pool_candidate(pool_candidate)
                    .map_err(PqForkChoiceAttestationError::Pool)?;
                Ok(outcome)
            },
            "pq-attestation-fork-choice-blocking",
        ) else {
            let _ = consumption.finalize_terminal();
            return Err(PqForkChoiceAttestationError::TaskUnavailable);
        };
        let outcome = match blocking.await {
            Ok(Ok(Ok(outcome))) => outcome,
            Ok(Ok(Err(error))) => {
                let _ = consumption.finalize_terminal();
                return Err(error);
            }
            Ok(Err(_)) | Err(_) => {
                let _ = consumption.finalize_terminal();
                return Err(PqForkChoiceAttestationError::TaskUnavailable);
            }
        };
        consumption
            .finalize_fork_choice(outcome)
            .map_err(|_| PqForkChoiceAttestationError::ObservationLost)?;
        Ok(outcome)
    }

    /// Applies the exact observed slot to fork choice. Callers must update the process clock first;
    /// accepting an arbitrary future tick would bypass the slot-loop timing boundary.
    pub async fn on_pq_fork_choice_tick(
        self: &Arc<Self>,
        requested: Slot,
    ) -> Result<(), PqForkChoiceAttestationError> {
        let clock = self
            .slot_clock
            .now()
            .ok_or(PqForkChoiceAttestationError::ClockUnavailable)?;
        if clock != requested {
            return Err(PqForkChoiceAttestationError::TickMismatch { clock, requested });
        }
        let (_activity, _admission) = self.try_start_pq_fork_choice_ingress()?;
        let fork_choice = self
            .pq_fork_choice
            .as_ref()
            .map(Arc::clone)
            .ok_or(PqForkChoiceAttestationError::Unavailable)?;
        #[cfg(feature = "pq-startup-testing")]
        let test_hook = self.pq_fork_choice_tick_test_hook.lock().clone();
        let chain = Arc::clone(self);
        let coordinator = Arc::clone(&self.pq_import_coordinator);
        let Some(task) = self.task_executor.spawn_handle_without_exit(
            async move {
                let mut panic_guard = PqImportPanicGuard::new(coordinator);
                let Some(blocking) = chain.task_executor.spawn_blocking_handle_without_exit(
                    move || {
                        #[cfg(feature = "pq-startup-testing")]
                        if let Some(hook) = test_hook {
                            hook.run();
                        }
                        let mut fork_choice = fork_choice.lock();
                        let current = fork_choice.fc_store().get_current_slot();
                        let Some(delta) = requested.as_u64().checked_sub(current.as_u64()) else {
                            return Err(PqForkChoiceAttestationError::TickRollback {
                                current,
                                requested,
                            });
                        };
                        if delta > PQ_FORK_CHOICE_TICK_MAX_ADVANCE {
                            return Err(PqForkChoiceAttestationError::TickAdvanceTooLarge {
                                current,
                                requested,
                                maximum: PQ_FORK_CHOICE_TICK_MAX_ADVANCE,
                            });
                        }
                        if delta == 0 {
                            return Ok(());
                        }
                        fork_choice
                            .update_time(requested)
                            .map(|_| ())
                            .map_err(PqForkChoiceAttestationError::ForkChoice)
                    },
                    "pq-fork-choice-tick-blocking",
                ) else {
                    chain.fail_pq_fork_choice_task();
                    return Err(PqForkChoiceAttestationError::TaskUnavailable);
                };
                let result = match blocking.await {
                    Ok(Ok(result)) => result,
                    Ok(Err(_)) | Err(_) => {
                        chain.fail_pq_fork_choice_task();
                        Err(PqForkChoiceAttestationError::TaskUnavailable)
                    }
                };
                panic_guard.disarm();
                drop(_admission);
                drop(_activity);
                result
            },
            "pq-fork-choice-tick",
        ) else {
            self.fail_pq_fork_choice_task();
            return Err(PqForkChoiceAttestationError::TaskUnavailable);
        };
        match task.await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => {
                self.fail_pq_fork_choice_task();
                Err(PqForkChoiceAttestationError::TaskUnavailable)
            }
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_fork_choice_contains_block(&self, block_root: Hash256) -> bool {
        self.pq_fork_choice
            .as_ref()
            .is_some_and(|fork_choice| fork_choice.lock().contains_block(&block_root))
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_fork_choice_current_slot(&self) -> Option<Slot> {
        self.pq_fork_choice
            .as_ref()
            .map(|fork_choice| fork_choice.lock().fc_store().get_current_slot())
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_fork_choice_proposer_boost_root(&self) -> Option<Hash256> {
        self.pq_fork_choice
            .as_ref()
            .map(|fork_choice| fork_choice.lock().proposer_boost_root())
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_fork_choice_cached_head_root(&self) -> Option<Hash256> {
        self.pq_fork_choice
            .as_ref()
            .map(|fork_choice| fork_choice.lock().cached_fork_choice_view().head_block_root)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_fork_choice_queued_attestation_count(&self) -> usize {
        self.pq_fork_choice.as_ref().map_or(0, |fork_choice| {
            fork_choice.lock().queued_attestations().len()
        })
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_fork_choice_latest_message(
        &self,
        validator_index: u64,
    ) -> Option<(Slot, Hash256)> {
        let validator_index = usize::try_from(validator_index).ok()?;
        self.pq_fork_choice
            .as_ref()?
            .lock()
            .latest_message(validator_index)
            .map(|message| (message.slot, message.root))
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_fork_choice_attestation_calls(&self) -> usize {
        self.pq_fork_choice_attestation_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_single_consumption_result(
        &self,
        epoch: types::Epoch,
        validator_index: u64,
    ) -> Option<crate::PqSingleConsumptionResult> {
        self.pq_attestation_gossip_observations
            .lock()
            .single_consumption_result((epoch, validator_index))
    }

    /// Reads the exact chain-authoritative lifecycle state for an already verified single.
    ///
    /// This grants no claim, subscription, publication or fork-choice authority. The network
    /// completion coordinator uses it only to confirm that an inbound consumption completion
    /// agrees with the state finalized by the chain-owned continuation.
    pub fn pq_attestation_consumption_status(
        &self,
        identity: &crate::PqSingleObservationIdentity,
        wire_id: crate::PqSingleWireMessageId,
    ) -> crate::PqSingleObservationStatus {
        self.pq_attestation_gossip_observations
            .lock()
            .exact_single_wire_status(identity, wire_id)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_try_start_pq_fork_choice_ingress(
        &self,
    ) -> Result<Box<dyn Send>, PqForkChoiceAttestationError> {
        self.try_start_pq_fork_choice_ingress()
            .map(|reservation| Box::new(reservation) as Box<dyn Send>)
    }

    /// Stops new PQ block and fork-choice imports and awaits all admitted proof, persistence,
    /// reconciliation and vote ownership. Runtime shutdown must await this after closing ingress.
    pub async fn close_and_drain_pq_imports(&self) {
        self.pq_import_coordinator.close();
        self.pq_background_attestation_aggregator
            .close_and_drain()
            .await;
        self.pq_import_coordinator.close_and_drain().await;
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_background_aggregation_close_hook(
        &self,
        hook: Option<Arc<crate::TestingPqBlockingHook>>,
    ) {
        self.pq_background_attestation_aggregator
            .testing_only_set_close_hook(hook);
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_post_persist_hook(&self, hook: Arc<crate::TestingPqBlockingHook>) {
        *self.pq_post_persist_test_hook.lock() = Some(hook);
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_fork_choice_block_hook(
        &self,
        hook: Arc<crate::TestingPqBlockingHook>,
    ) {
        *self.pq_fork_choice_block_test_hook.lock() = Some(hook);
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_force_pq_fork_choice_clock_unavailable(&self) {
        self.pq_fork_choice_clock_unavailable
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_fork_choice_tick_hook(
        &self,
        hook: Arc<crate::TestingPqBlockingHook>,
    ) {
        *self.pq_fork_choice_tick_test_hook.lock() = Some(hook);
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_execution_reconciliation_failed(&self, block_root: Hash256) {
        self.pq_execution_reconciliation
            .set(PqExecutionReconciliationState::Failed { block_root });
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_execution_reconciled(&self, block_root: Hash256) -> bool {
        matches!(
            self.pq_execution_reconciliation.current(),
            PqExecutionReconciliationState::Reconciled {
                block_root: reconciled,
            } if reconciled == block_root
        )
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_import_gate_available_permits(&self) -> usize {
        self.pq_import_gate.available_permits()
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub async fn testing_only_hold_pq_import_gate(&self) -> tokio::sync::OwnedSemaphorePermit {
        Arc::clone(&self.pq_import_gate)
            .acquire_owned()
            .await
            .expect("PQ import gate remains open for the chain lifetime")
    }
}

/// Opaque authority for consuming a whole locally-published PQ attestation batch on its bound
/// chain. The network service owns this capability and never exposes the batch's proof tokens.
#[cfg(feature = "pq-proposer")]
pub struct PqPublishedLocalAttestationBatchConsumer<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
}

#[cfg(feature = "pq-proposer")]
impl<T: BeaconChainTypes> PqPublishedLocalAttestationBatchConsumer<T> {
    /// Resolves one exact lower publication outcome against the chain-owned observation state.
    /// The caller supplies only the retained sealed batch, its member index and the actual lower
    /// message ID; identity and wire metadata are derived from the sealed member.
    pub fn resolve_member(
        &self,
        batch: &crate::PqVerifiedLocalAttestationBatch<T::EthSpec>,
        member: usize,
        message_id: &lighthouse_network::MessageId,
    ) -> Result<crate::PqPublishedLocalMemberResolution, crate::PqPublishedLocalMemberResolutionError>
    {
        let verified = batch
            .verified()
            .get(member)
            .ok_or(crate::PqPublishedLocalMemberResolutionError::Member)?;
        let signed_ssz = ssz::Encode::as_ssz_bytes(verified.single());
        let recomputed_identity = crate::PqSingleObservationIdentity::from_signed_attestation(
            verified.single(),
            verified.subnet(),
        );
        if recomputed_identity != verified.observation_identity() {
            return Err(crate::PqPublishedLocalMemberResolutionError::Identity);
        }
        let fork_digest = self
            .chain
            .spec
            .enr_fork_id::<T::EthSpec>(
                verified.slot(),
                self.chain
                    .head_snapshot()
                    .beacon_state
                    .genesis_validators_root(),
            )
            .fork_digest;
        let topic = IdentTopic::from(GossipTopic::new(
            GossipKind::Attestation(verified.subnet()),
            GossipEncoding::default(),
            fork_digest,
        ));
        let expected_message_id = pq_anonymous_message_id(
            &topic.hash(),
            &signed_ssz,
            self.chain.spec.message_domain_valid_snappy,
            self.chain
                .spec
                .fork_name_at_slot::<T::EthSpec>(verified.slot())
                .altair_enabled(),
        );
        crate::pq_attestation_gossip::resolve_pq_published_local_member(
            &self.chain.pq_attestation_gossip_observations,
            recomputed_identity,
            &signed_ssz,
            verified.signed_ssz_digest(),
            &expected_message_id,
            message_id,
        )
    }

    pub async fn consume(
        &self,
        evidence: crate::PqPublishedLocalAttestationEvidenceBatch<T::EthSpec>,
    ) -> Result<
        crate::PqPublishedLocalAttestationBatchConsumptionOutcome,
        crate::PqPublishedLocalAttestationBatchConsumptionError,
    > {
        self.chain
            .consume_pq_published_local_attestation_batch(evidence)
            .await
    }

    /// Closes PQ ingress after the outer monitored network task already emitted the sole process
    /// failure signal for a panic.
    pub fn close_ingress_after_monitored_task_failure(&self) {
        self.chain.pq_import_coordinator.close();
    }
}
