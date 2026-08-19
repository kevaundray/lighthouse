use consensus_signature::AggregationService;
use parking_lot::{Mutex, RwLock};
use slot_clock::SlotClock;
use state_processing::PqValidatorKeyCache;
use std::marker::PhantomData;
use std::sync::Arc;
use store::{HotColdDB, ItemStore};
use task_executor::TaskExecutor;
use types::{BeaconState, ChainSpec, EthSpec, Hash256, SignedBeaconBlock};

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
    pub(crate) pq_block_production_admission: Arc<tokio::sync::Semaphore>,
    pub(crate) pq_proposer_duty_admission: Arc<tokio::sync::Semaphore>,
    pub(crate) pq_attestation_gossip_admission: Arc<tokio::sync::Semaphore>,
    pub(crate) pq_attestation_gossip_observations:
        Arc<Mutex<crate::pq_attestation_gossip::PqAttestationGossipObservationCache<T::EthSpec>>>,
    pub(crate) pq_execution_notifier: crate::pq_import::PqExecutionNotifier<T::EthSpec>,
    pub(crate) task_executor: TaskExecutor,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_blocking_test_hook: Option<Arc<crate::TestingPqBlockingHook>>,
    #[cfg(feature = "pq-startup-testing")]
    pub(crate) pq_persistence_test_hook: Option<Arc<crate::TestingPqBlockingHook>>,
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
            task_executor,
            #[cfg(feature = "pq-startup-testing")]
            pq_blocking_test_hook,
            #[cfg(feature = "pq-startup-testing")]
            pq_persistence_test_hook,
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
}
