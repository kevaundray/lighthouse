use consensus_signature::AggregationService;
use parking_lot::{Mutex, RwLock};
use slot_clock::SlotClock;
use state_processing::PqValidatorKeyCache;
use std::marker::PhantomData;
use std::sync::Arc;
use store::{HotColdDB, ItemStore};
use task_executor::TaskExecutor;
use types::{BeaconState, ChainSpec, EthSpec, Hash256, SignedBeaconBlock};

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
    pub(crate) pq_execution_reconciliation: Arc<PqExecutionReconciliation>,
    pub(crate) task_executor: TaskExecutor,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_blocking_test_hook: Option<Arc<crate::TestingPqBlockingHook>>,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_persistence_test_hook: Option<Arc<crate::TestingPqBlockingHook>>,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_post_persist_test_hook: Mutex<Option<Arc<crate::TestingPqBlockingHook>>>,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_proposer_duties_test_hook: Option<Arc<crate::TestingPqBlockingHook>>,
    pub pq_validator_key_cache: Arc<PqValidatorKeyCache>,
    pub pq_aggregation_service: Arc<AggregationService>,
    pub slot_clock: T::SlotClock,
    marker: PhantomData<T>,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub(crate) fn new(
        spec: Arc<ChainSpec>,
        store: BeaconStore<T>,
        canonical_head: BeaconSnapshot<T::EthSpec>,
        pq_validator_key_cache: Arc<PqValidatorKeyCache>,
        pq_aggregation_service: Arc<AggregationService>,
        pq_execution_notifier: crate::pq_import::PqExecutionNotifier<T::EthSpec>,
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
    ) -> Self {
        let initial_block_root = canonical_head.beacon_block_root;
        Self {
            spec,
            store,
            canonical_head: Arc::new(RwLock::new(Arc::new(canonical_head))),
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
            pq_post_persist_test_hook: Mutex::new(None),
            #[cfg(feature = "pq-startup-testing")]
            pq_proposer_duties_test_hook,
            pq_validator_key_cache,
            pq_aggregation_service,
            slot_clock,
            marker: PhantomData,
        }
    }

    /// Returns the exact snapshot which was strictly validated before worker construction.
    pub fn head_snapshot(&self) -> Arc<BeaconSnapshot<T::EthSpec>> {
        self.canonical_head.read().clone()
    }

    /// Stops new PQ block imports and awaits all admitted proof, persistence and reconciliation
    /// ownership. Runtime shutdown must await this after closing external ingress.
    pub async fn close_and_drain_pq_imports(&self) {
        self.pq_import_coordinator.close_and_drain().await;
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_post_persist_hook(&self, hook: Arc<crate::TestingPqBlockingHook>) {
        *self.pq_post_persist_test_hook.lock() = Some(hook);
    }
}
