use consensus_signature::AggregationService;
use fork_choice::ForkChoiceStore as _;
use parking_lot::{Mutex, RwLock};
use slot_clock::SlotClock;
use state_processing::PqValidatorKeyCache;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use store::{HotColdDB, ItemStore};
use task_executor::TaskExecutor;
use types::{BeaconState, ChainSpec, EthSpec, Hash256, SignedBeaconBlock, Slot};

type PqForkChoice<T> = fork_choice::ForkChoice<
    crate::beacon_fork_choice_store::BeaconForkChoiceStore<
        <T as BeaconChainTypes>::EthSpec,
        <T as BeaconChainTypes>::HotStore,
        <T as BeaconChainTypes>::ColdStore,
    >,
    <T as BeaconChainTypes>::EthSpec,
>;

pub const PQ_FORK_CHOICE_TICK_MAX_ADVANCE: u64 = 8;

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
            Self::ForkChoice(error) => write!(formatter, "PQ fork-choice failed: {error:?}"),
        }
    }
}

impl std::error::Error for PqForkChoiceAttestationError {}

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
}

impl<E: EthSpec> BeaconSnapshot<E> {
    /// Returns the exact state root committed by the snapshot block.
    pub fn beacon_state_root(&self) -> Hash256 {
        self.beacon_block.message().state_root()
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
    pub(crate) pq_attestation_gossip_admission: Arc<tokio::sync::Semaphore>,
    pub(crate) pq_attestation_gossip_observations:
        Arc<Mutex<crate::pq_attestation_gossip::PqAttestationGossipObservationCache<T::EthSpec>>>,
    pub(crate) pq_execution_notifier: crate::pq_import::PqExecutionNotifier<T::EthSpec>,
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
    pq_fork_choice_attestation_calls: std::sync::atomic::AtomicUsize,
    pub pq_validator_key_cache: Arc<PqValidatorKeyCache>,
    pub pq_aggregation_service: Arc<AggregationService>,
    pub slot_clock: T::SlotClock,
    marker: PhantomData<T>,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
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
        slot_clock: T::SlotClock,
    ) -> Result<Self, PqRuntimeError> {
        let initial_block_root = canonical_head.beacon_block_root;
        // Task 7.2 cycle 1 deliberately establishes only an in-memory Fresh fork choice. Resume
        // reconstruction/persistence is a later vertical slice and must not be inferred here.
        let pq_fork_choice = if canonical_head.beacon_state.slot() == spec.genesis_slot {
            let fork_choice_store =
                crate::beacon_fork_choice_store::BeaconForkChoiceStore::get_forkchoice_store(
                    Arc::clone(&store),
                    canonical_head.clone(),
                )
                .map_err(PqRuntimeError::ForkChoiceStore)?;
            let fork_choice = fork_choice::ForkChoice::from_anchor(
                fork_choice_store,
                canonical_head.beacon_block_root,
                canonical_head.beacon_block.as_ref(),
                &canonical_head.beacon_state,
                Some(canonical_head.beacon_state.slot()),
                &spec,
            )
            .map_err(PqRuntimeError::ForkChoice)?;
            Some(Arc::new(Mutex::new(fork_choice)))
        } else {
            None
        };
        Ok(Self {
            spec,
            store,
            canonical_head: Arc::new(RwLock::new(Arc::new(canonical_head))),
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
            pq_attestation_gossip_admission: Arc::new(tokio::sync::Semaphore::new(
                crate::PQ_ATTESTATION_GOSSIP_ADMISSION_CAPACITY,
            )),
            pq_attestation_gossip_observations: Arc::new(Mutex::new(
                crate::pq_attestation_gossip::PqAttestationGossipObservationCache::default(),
            )),
            pq_execution_notifier,
            pq_operational_events,
            pq_execution_reconciliation: Arc::new(PqExecutionReconciliation::new(
                PqExecutionReconciliationState::Pending {
                    block_root: initial_block_root,
                },
            )),
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
            pq_fork_choice_attestation_calls: std::sync::atomic::AtomicUsize::new(0),
            pq_validator_key_cache,
            pq_aggregation_service,
            slot_clock,
            marker: PhantomData,
        })
    }

    /// Returns the exact snapshot which was strictly validated before worker construction.
    pub fn head_snapshot(&self) -> Arc<BeaconSnapshot<T::EthSpec>> {
        self.canonical_head.read().clone()
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
                result
            },
            "pq-attestation-fork-choice-consume",
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

    fn fail_pq_fork_choice_task(&self) {
        self.pq_import_coordinator.close();
        let mut shutdown = self.task_executor.shutdown_sender();
        let _ = shutdown.try_send(task_executor::ShutdownReason::Failure(
            "PQ fork-choice task failed",
        ));
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
        let spec = Arc::clone(&self.spec);
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
                if fork_choice.queued_attestations().len() > queued_before {
                    Ok(PqForkChoiceAttestationOutcome::Queued)
                } else {
                    Ok(PqForkChoiceAttestationOutcome::Applied)
                }
            },
            "pq-attestation-fork-choice-blocking",
        ) else {
            self.fail_pq_fork_choice_task();
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
                self.fail_pq_fork_choice_task();
                let _ = consumption.finalize_terminal();
                return Err(PqForkChoiceAttestationError::TaskUnavailable);
            }
        };
        #[cfg(feature = "pq-startup-testing")]
        self.pq_fork_choice_attestation_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        consumption
            .finalize_applied()
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
        self.pq_import_coordinator.close_and_drain().await;
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
}
