use crate::{BeaconChain, BeaconChainTypes, PqRuntimeError};
use execution_layer::{ExecutionLayer, NewPayloadRequest, PayloadStatus};
use slot_clock::SlotClock;
use state_processing::{
    BlockProcessingError, PqConsensusError, PqConsensusLocalError, PqTransitionError,
    per_slot_processing_pq, prepare_pq_block, transition_pq_imported_block,
};
use std::collections::HashMap;
use std::error::Error;
#[cfg(feature = "pq-startup-testing")]
use std::future::Future;
#[cfg(feature = "pq-startup-testing")]
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "pq-startup-testing")]
use std::sync::{
    Condvar, Mutex as StdMutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use types::{EthSpec, ExecPayload, ExecutionBlockHash, Hash256, SignedBeaconBlock, Slot};

pub const PQ_EXECUTION_RECONCILIATION_ATTEMPTS: usize = 3;
const PQ_EXECUTION_RECONCILIATION_BACKOFF: Duration = Duration::from_millis(25);
const PQ_EXECUTION_RECONCILIATION_FAILURE: &str = "PQ execution reconciliation failed";

/// At most two imported blocks may retain advanced state, proof evidence, or a commit waiter.
/// A forward range consumes one permit and processes its blocks sequentially under that permit.
pub const PQ_BLOCK_IMPORT_ADMISSION_CAPACITY: usize = 2;

/// A single admitted forward-range request retains at most this many raw PQ blocks. They are
/// verified and committed strictly one at a time, so the global verified-state bound remains the
/// admission capacity above.
pub const PQ_FORWARD_RANGE_BLOCK_CAPACITY: usize = 8;

/// Test barrier proving that synchronous preparation executes away from the async worker.
#[cfg(feature = "pq-startup-testing")]
pub struct TestingPqBlockingHook {
    entered: AtomicUsize,
    released: StdMutex<bool>,
    release: Condvar,
    panic_after_release: bool,
}

#[cfg(feature = "pq-startup-testing")]
impl TestingPqBlockingHook {
    pub fn blocking() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicUsize::new(0),
            released: StdMutex::new(false),
            release: Condvar::new(),
            panic_after_release: false,
        })
    }

    pub fn counting() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicUsize::new(0),
            released: StdMutex::new(true),
            release: Condvar::new(),
            panic_after_release: false,
        })
    }

    pub fn panicking() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicUsize::new(0),
            released: StdMutex::new(true),
            release: Condvar::new(),
            panic_after_release: true,
        })
    }

    pub fn entered(&self) -> usize {
        self.entered.load(Ordering::SeqCst)
    }

    pub fn release(&self) {
        *self.released.lock().expect("PQ blocking test hook lock") = true;
        self.release.notify_all();
    }

    pub fn block(&self) {
        *self.released.lock().expect("PQ blocking test hook lock") = false;
    }

    pub fn is_released(&self) -> bool {
        *self.released.lock().expect("PQ blocking test hook lock")
    }

    #[doc(hidden)]
    pub fn run(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let mut released = self.released.lock().expect("PQ blocking test hook lock");
        while !*released {
            released = self
                .release
                .wait(released)
                .expect("PQ blocking test hook wait");
        }
        assert!(!self.panic_after_release, "testing post-persist panic");
    }
}

/// The external route which supplied a block to the single sealed PQ import boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqBlockImportSource {
    Gossip,
    Publish,
    Rpc,
    Lookup,
    ForwardRange,
}

impl PqBlockImportSource {
    pub const ALL: [Self; 5] = [
        Self::Gossip,
        Self::Publish,
        Self::Rpc,
        Self::Lookup,
        Self::ForwardRange,
    ];
}

/// Raw wire ownership at an explicit ingress boundary. Only this type can enter verification;
/// transition and persistence never accept a raw `SignedBeaconBlock`.
pub struct PqBlockImportRequest<E: EthSpec> {
    source: PqBlockImportSource,
    block: Arc<SignedBeaconBlock<E>>,
}

impl<E: EthSpec> PqBlockImportRequest<E> {
    pub fn gossip(block: Arc<SignedBeaconBlock<E>>) -> Self {
        Self::new(PqBlockImportSource::Gossip, block)
    }

    pub fn rpc(block: Arc<SignedBeaconBlock<E>>) -> Self {
        Self::new(PqBlockImportSource::Rpc, block)
    }

    pub fn publish(block: Arc<SignedBeaconBlock<E>>) -> Self {
        Self::new(PqBlockImportSource::Publish, block)
    }

    pub fn lookup(block: Arc<SignedBeaconBlock<E>>) -> Self {
        Self::new(PqBlockImportSource::Lookup, block)
    }

    pub fn forward_range(block: Arc<SignedBeaconBlock<E>>) -> Self {
        Self::new(PqBlockImportSource::ForwardRange, block)
    }

    fn new(source: PqBlockImportSource, block: Arc<SignedBeaconBlock<E>>) -> Self {
        Self { source, block }
    }
}

/// Boxed test-only local-payload future returned by the deterministic execution seam.
#[cfg(feature = "pq-startup-testing")]
pub type PqFullPayloadFuture<'a, E> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    execution_layer::BlockProposalContents<E, types::FullPayload<E>>,
                    execution_layer::Error,
                >,
            > + Send
            + 'a,
    >,
>;

/// Small asynchronous seam implemented by the real execution layer and deterministic tests.
#[cfg(feature = "pq-startup-testing")]
pub trait PqNewPayloadTransport<E: EthSpec>: Send + Sync {
    fn notify_new_payload<'a>(
        &'a self,
        request: NewPayloadRequest<'a, E>,
    ) -> Pin<Box<dyn Future<Output = Result<PayloadStatus, execution_layer::Error>> + Send + 'a>>;

    fn get_full_payload<'a>(
        &'a self,
        _request: crate::pq_production::PqPayloadBuildRequest<E>,
    ) -> PqFullPayloadFuture<'a, E> {
        Box::pin(async { Err(execution_layer::Error::NoEngine) })
    }

    fn notify_forkchoice_updated<'a>(
        &'a self,
        head_block_hash: ExecutionBlockHash,
        current_slot: Slot,
        head_block_root: Hash256,
    ) -> Pin<Box<dyn Future<Output = Result<PayloadStatus, execution_layer::Error>> + Send + 'a>>;
}

enum PqExecutionForkchoiceGuard {
    Production(tokio::sync::OwnedMutexGuard<()>),
    #[cfg(feature = "pq-startup-testing")]
    Testing,
}

pub(crate) enum PqExecutionNotifier<E: EthSpec> {
    Deferred,
    Production {
        execution_layer: Arc<ExecutionLayer<E>>,
        #[cfg(feature = "pq-startup-testing")]
        payload_observer: Option<crate::pq_production::TestingPqPayloadBuildObserver<E>>,
    },
    #[cfg(feature = "pq-startup-testing")]
    Testing(Arc<dyn PqNewPayloadTransport<E>>),
}

impl<E: EthSpec> PqExecutionNotifier<E> {
    pub(crate) fn production(execution_layer: Arc<ExecutionLayer<E>>) -> Self {
        Self::Production {
            execution_layer,
            #[cfg(feature = "pq-startup-testing")]
            payload_observer: None,
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    pub(crate) fn set_payload_observer(
        &mut self,
        observer: crate::pq_production::TestingPqPayloadBuildObserver<E>,
    ) -> Result<(), PqRuntimeError> {
        match self {
            Self::Production {
                payload_observer, ..
            } => {
                *payload_observer = Some(observer);
                Ok(())
            }
            Self::Deferred | Self::Testing(_) => Err(PqRuntimeError::MissingExecutionNotifier),
        }
    }

    #[cfg(not(feature = "pq-startup-testing"))]
    pub(crate) const fn is_deferred(&self) -> bool {
        matches!(self, Self::Deferred)
    }

    async fn notify_new_payload(
        &self,
        request: NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatus, execution_layer::Error> {
        match self {
            Self::Deferred => Err(execution_layer::Error::NoEngine),
            Self::Production {
                execution_layer, ..
            } => execution_layer.notify_new_payload(request).await,
            #[cfg(feature = "pq-startup-testing")]
            Self::Testing(notifier) => notifier.notify_new_payload(request).await,
        }
    }

    async fn acquire_forkchoice_guard(
        &self,
    ) -> Result<PqExecutionForkchoiceGuard, execution_layer::Error> {
        match self {
            Self::Deferred => Err(execution_layer::Error::NoEngine),
            Self::Production {
                execution_layer, ..
            } => Ok(PqExecutionForkchoiceGuard::Production(
                execution_layer
                    .execution_engine_forkchoice_lock_owned()
                    .await,
            )),
            #[cfg(feature = "pq-startup-testing")]
            Self::Testing(_) => Ok(PqExecutionForkchoiceGuard::Testing),
        }
    }

    async fn notify_forkchoice_updated(
        &self,
        guard: &PqExecutionForkchoiceGuard,
        head_block_hash: ExecutionBlockHash,
        _current_slot: Slot,
        _head_block_root: Hash256,
    ) -> Result<PayloadStatus, execution_layer::Error> {
        match (self, guard) {
            (
                Self::Production {
                    execution_layer, ..
                },
                PqExecutionForkchoiceGuard::Production(_guard),
            ) => {
                execution_layer
                    .notify_forkchoice_updated_for_pq(execution_layer::ForkchoiceState {
                        head_block_hash,
                        safe_block_hash: ExecutionBlockHash::zero(),
                        finalized_block_hash: ExecutionBlockHash::zero(),
                    })
                    .await
            }
            #[cfg(feature = "pq-startup-testing")]
            (Self::Testing(notifier), PqExecutionForkchoiceGuard::Testing) => {
                notifier
                    .notify_forkchoice_updated(head_block_hash, _current_slot, _head_block_root)
                    .await
            }
            (Self::Deferred, _) => Err(execution_layer::Error::NoEngine),
            #[cfg(feature = "pq-startup-testing")]
            (Self::Production { .. }, PqExecutionForkchoiceGuard::Testing) => {
                Err(execution_layer::Error::NoEngine)
            }
            #[cfg(feature = "pq-startup-testing")]
            (Self::Testing(_), PqExecutionForkchoiceGuard::Production(_)) => {
                Err(execution_layer::Error::NoEngine)
            }
        }
    }

    pub(crate) async fn get_full_payload(
        &self,
        request: crate::pq_production::PqPayloadBuildRequest<E>,
    ) -> Result<crate::pq_production::PqFullPayloadResponse<E>, execution_layer::Error> {
        let expectation = crate::pq_production::PqPayloadExpectation::from_request(&request);
        let _forkchoice_guard = self.acquire_forkchoice_guard().await?;
        let contents = match self {
            Self::Deferred => Err(execution_layer::Error::NoEngine),
            Self::Production {
                execution_layer,
                #[cfg(feature = "pq-startup-testing")]
                payload_observer,
            } => {
                let suggested_fee_recipient = execution_layer
                    .get_suggested_fee_recipient(request.proposer_index)
                    .await;
                let proposer_gas_limit = execution_layer
                    .get_proposer_gas_limit(request.proposer_index)
                    .await;
                let payload_attributes = execution_layer::PayloadAttributes::new(
                    request.timestamp,
                    request.prev_randao,
                    suggested_fee_recipient,
                    Some(request.withdrawals.clone()),
                    Some(request.parent_beacon_block_root),
                    None,
                    None,
                );
                let payload_parameters = execution_layer::PayloadParameters {
                    parent_hash: request.parent_hash,
                    parent_gas_limit: Some(request.parent_gas_limit),
                    proposer_gas_limit,
                    payload_attributes: &payload_attributes,
                    forkchoice_update_params: &request.forkchoice_update_parameters,
                    current_fork: types::ForkName::Electra,
                };
                #[cfg(feature = "pq-startup-testing")]
                if let Some(observer) = payload_observer {
                    observer(
                        crate::pq_production::TestingPqPayloadBuildObservation::from_payload_parameters(
                            request.proposer_index,
                            &payload_parameters,
                        ),
                    );
                }
                execution_layer
                    .get_full_payload_for_pq_v3(payload_parameters)
                    .await
            }
            #[cfg(feature = "pq-startup-testing")]
            Self::Testing(notifier) => notifier.get_full_payload(request).await,
        }?;
        crate::pq_production::PqFullPayloadResponse::try_from_execution_contents(
            contents,
            &expectation,
        )
    }
}

/// Typed Engine response class. V1 persists only `Valid`; `Syncing` is retry-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqEnginePayloadStatus {
    Valid,
    Syncing,
}

impl PqEnginePayloadStatus {
    pub const fn would_require_optimistic_import(self) -> bool {
        matches!(self, Self::Syncing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqEnginePayloadDisposition {
    CommitValid,
    Retry(PqEnginePayloadStatus),
    Reject,
}

pub fn classify_pq_engine_payload_status(status: &PayloadStatus) -> PqEnginePayloadDisposition {
    match status {
        PayloadStatus::Valid => PqEnginePayloadDisposition::CommitValid,
        PayloadStatus::Syncing | PayloadStatus::Accepted => {
            PqEnginePayloadDisposition::Retry(PqEnginePayloadStatus::Syncing)
        }
        PayloadStatus::Invalid { .. } | PayloadStatus::InvalidBlockHash { .. } => {
            PqEnginePayloadDisposition::Reject
        }
    }
}

fn signal_pq_execution_reconciliation_failure(task_executor: &task_executor::TaskExecutor) {
    let mut shutdown = task_executor.shutdown_sender();
    let _ = shutdown.try_send(task_executor::ShutdownReason::Failure(
        PQ_EXECUTION_RECONCILIATION_FAILURE,
    ));
}

async fn reconcile_pq_execution<E: EthSpec>(
    notifier: &PqExecutionNotifier<E>,
    guard: &PqExecutionForkchoiceGuard,
    reconciliation: &Arc<crate::beacon_chain::PqExecutionReconciliation>,
    task_executor: &task_executor::TaskExecutor,
    head_block_hash: ExecutionBlockHash,
    current_slot: Slot,
    head_block_root: Hash256,
) -> Result<(), PqImportError> {
    let mut attempts = 0usize;
    loop {
        let Some(next_attempt) = attempts.checked_add(1) else {
            signal_pq_execution_reconciliation_failure(task_executor);
            reconciliation.set(
                crate::beacon_chain::PqExecutionReconciliationState::Failed {
                    block_root: head_block_root,
                },
            );
            return Err(PqImportError::ExecutionReconciliation(
                PqExecutionReconciliationError::Unavailable { attempts },
            ));
        };
        attempts = next_attempt;
        let response = notifier
            .notify_forkchoice_updated(guard, head_block_hash, current_slot, head_block_root)
            .await;
        match response {
            Ok(status)
                if classify_pq_engine_payload_status(&status)
                    == PqEnginePayloadDisposition::CommitValid =>
            {
                reconciliation.set(
                    crate::beacon_chain::PqExecutionReconciliationState::Reconciled {
                        block_root: head_block_root,
                    },
                );
                return Ok(());
            }
            Ok(status)
                if classify_pq_engine_payload_status(&status)
                    == PqEnginePayloadDisposition::Reject =>
            {
                signal_pq_execution_reconciliation_failure(task_executor);
                reconciliation.set(
                    crate::beacon_chain::PqExecutionReconciliationState::Failed {
                        block_root: head_block_root,
                    },
                );
                return Err(PqImportError::ExecutionReconciliation(
                    PqExecutionReconciliationError::Rejected(status),
                ));
            }
            Ok(_) if attempts == PQ_EXECUTION_RECONCILIATION_ATTEMPTS => {
                signal_pq_execution_reconciliation_failure(task_executor);
                reconciliation.set(
                    crate::beacon_chain::PqExecutionReconciliationState::Failed {
                        block_root: head_block_root,
                    },
                );
                return Err(PqImportError::ExecutionReconciliation(
                    PqExecutionReconciliationError::Unavailable { attempts },
                ));
            }
            Err(error) if attempts == PQ_EXECUTION_RECONCILIATION_ATTEMPTS => {
                signal_pq_execution_reconciliation_failure(task_executor);
                reconciliation.set(
                    crate::beacon_chain::PqExecutionReconciliationState::Failed {
                        block_root: head_block_root,
                    },
                );
                return Err(PqImportError::ExecutionReconciliation(
                    PqExecutionReconciliationError::Transport {
                        attempts,
                        error: Box::new(error),
                    },
                ));
            }
            Ok(_) | Err(_) => {
                tokio::time::sleep(PQ_EXECUTION_RECONCILIATION_BACKOFF).await;
            }
        }
    }
}

fn persisted_pq_execution_head<E: EthSpec>(
    snapshot: &crate::BeaconSnapshot<E>,
    genesis_slot: Slot,
) -> Result<ExecutionBlockHash, PqImportError> {
    let state_hash = snapshot
        .beacon_state
        .latest_execution_payload_header()
        .map_err(|_| {
            PqImportError::Local(PqImportLocalError::Persistence(
                PqRuntimeError::PersistedHeadBinding("post-state has no execution payload header"),
            ))
        })?
        .block_hash();
    if snapshot.beacon_state.slot() == genesis_slot {
        return Ok(state_hash);
    }
    let payload_hash = snapshot
        .beacon_block
        .message()
        .body()
        .execution_payload()
        .map_err(|_| {
            PqImportError::Local(PqImportLocalError::Persistence(
                PqRuntimeError::PersistedHeadBinding(
                    "non-genesis head has no full execution payload",
                ),
            ))
        })?
        .block_hash();
    if payload_hash != state_hash {
        return Err(PqImportError::Local(PqImportLocalError::Persistence(
            PqRuntimeError::PersistedHeadBinding(
                "block payload hash does not match post-state execution header",
            ),
        )));
    }
    Ok(payload_hash)
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_persisted_pq_execution_head<E: EthSpec>(
    snapshot: &crate::BeaconSnapshot<E>,
    genesis_slot: Slot,
) -> Result<ExecutionBlockHash, PqImportError> {
    persisted_pq_execution_head(snapshot, genesis_slot)
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub async fn testing_only_reconcile_pq_execution<E: EthSpec>(
    transport: Arc<dyn PqNewPayloadTransport<E>>,
    task_executor: task_executor::TaskExecutor,
    head_block_hash: ExecutionBlockHash,
    current_slot: Slot,
    head_block_root: Hash256,
) -> Result<(), PqImportError> {
    let notifier = PqExecutionNotifier::Testing(transport);
    let guard = notifier
        .acquire_forkchoice_guard()
        .await
        .map_err(|error| PqImportError::Local(PqImportLocalError::Transport(error)))?;
    let reconciliation = Arc::new(crate::beacon_chain::PqExecutionReconciliation::new(
        crate::beacon_chain::PqExecutionReconciliationState::Pending {
            block_root: head_block_root,
        },
    ));
    reconcile_pq_execution(
        &notifier,
        &guard,
        &reconciliation,
        &task_executor,
        head_block_hash,
        current_slot,
        head_block_root,
    )
    .await
}

/// Errors attributable to hostile or malformed remote block data.
#[derive(Debug)]
pub enum PqImportPeerInvalid {
    NonLinearRange { expected: Hash256, actual: Hash256 },
    Equivocation { previous: Hash256, actual: Hash256 },
    NonAdvancingSlot { parent: Slot, block: Slot },
    FutureSlot { current: Slot, block: Slot },
    Consensus(PqConsensusError),
    Transition(PqTransitionError),
    ExecutionPayload(execution_layer::Error),
}

/// Retryable local failures which must never penalize the supplying peer.
#[derive(Debug)]
pub enum PqImportLocalError {
    Invariant(&'static str),
    ClockUnavailable,
    ParentUnavailable { parent_root: Hash256 },
    ObservationCapacity,
    IngressCapacity,
    ForwardRangeCapacity { supplied: usize, maximum: usize },
    BlockingTask(&'static str),
    Consensus(PqConsensusError),
    Transition(PqTransitionError),
    ExecutionUnavailable(PqEnginePayloadStatus),
    Transport(execution_layer::Error),
    Persistence(PqRuntimeError),
}

/// A durable PQ head could not be reconciled with the process-owned execution engine. These
/// failures are local and never attributable to a peer, but are non-retryable at the import or
/// network boundary because the continuation already committed the exact block to disk.
#[derive(Debug)]
pub enum PqExecutionReconciliationError {
    Unavailable {
        attempts: usize,
    },
    Transport {
        attempts: usize,
        error: Box<execution_layer::Error>,
    },
    Rejected(PayloadStatus),
}

/// Stable peer-scoring boundary for all PQ block ingress routes.
#[derive(Debug)]
pub enum PqImportError {
    PeerInvalid(PqImportPeerInvalid),
    /// The remote execution engine rejected the payload. An honest peer can have relayed it, so
    /// this is terminal but does not incur a peer penalty.
    ExecutionRejected(PayloadStatus),
    ExecutionReconciliation(PqExecutionReconciliationError),
    /// A detached continuation was lost after durable persistence may have begun. The live
    /// process must stop and recover the authoritative head from disk before accepting retries.
    DurableStateUnknown {
        phase: &'static str,
    },
    /// A prior Engine rejection or canonical commit invalidated this observation generation.
    TerminalObservation {
        block_root: Hash256,
    },
    /// Verification completed against a parent that ceased to be canonical before commit.
    StaleHeadAfterVerification {
        expected_parent: Hash256,
        actual_head: Hash256,
    },
    Local(PqImportLocalError),
}

impl PqImportError {
    pub const fn should_penalize_peer(&self) -> bool {
        matches!(self, Self::PeerInvalid(_))
    }

    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Local(_))
    }
}

impl std::fmt::Display for PqImportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PeerInvalid(error) => write!(formatter, "invalid PQ block: {error:?}"),
            Self::ExecutionRejected(status) => {
                write!(formatter, "PQ execution payload rejected: {status:?}")
            }
            Self::ExecutionReconciliation(error) => {
                write!(
                    formatter,
                    "PQ committed-head reconciliation failed: {error:?}"
                )
            }
            Self::DurableStateUnknown { phase } => {
                write!(formatter, "PQ durable state is unknown after {phase}")
            }
            Self::TerminalObservation { block_root } => {
                write!(
                    formatter,
                    "PQ block observation is terminal: {block_root:?}"
                )
            }
            Self::StaleHeadAfterVerification {
                expected_parent,
                actual_head,
            } => write!(
                formatter,
                "PQ verified block parent became stale: expected {expected_parent:?}, head {actual_head:?}"
            ),
            Self::Local(PqImportLocalError::ParentUnavailable { parent_root }) => {
                write!(formatter, "PQ block parent is unavailable: {parent_root:?}")
            }
            Self::Local(PqImportLocalError::Invariant(reason)) => {
                write!(formatter, "PQ import invariant failed: {reason}")
            }
            Self::Local(PqImportLocalError::ClockUnavailable) => {
                formatter.write_str("PQ slot clock is unavailable")
            }
            Self::Local(PqImportLocalError::ObservationCapacity) => {
                formatter.write_str("PQ gossip observation capacity is exhausted")
            }
            Self::Local(PqImportLocalError::IngressCapacity) => {
                formatter.write_str("PQ imported-block admission capacity is exhausted")
            }
            Self::Local(PqImportLocalError::ForwardRangeCapacity { supplied, maximum }) => write!(
                formatter,
                "PQ forward range has {supplied} blocks, exceeding the {maximum}-block bound"
            ),
            Self::Local(PqImportLocalError::BlockingTask(phase)) => {
                write!(formatter, "PQ blocking task failed during {phase}")
            }
            Self::Local(PqImportLocalError::Consensus(error)) => error.fmt(formatter),
            Self::Local(PqImportLocalError::Transition(error)) => error.fmt(formatter),
            Self::Local(PqImportLocalError::ExecutionUnavailable(status)) => {
                write!(formatter, "PQ execution engine is not ready: {status:?}")
            }
            Self::Local(PqImportLocalError::Transport(error)) => {
                write!(formatter, "PQ execution transport failed: {error:?}")
            }
            Self::Local(PqImportLocalError::Persistence(error)) => error.fmt(formatter),
        }
    }
}

impl Error for PqImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PeerInvalid(PqImportPeerInvalid::Consensus(error)) => Some(error),
            Self::PeerInvalid(PqImportPeerInvalid::Transition(error)) => Some(error),
            Self::Local(PqImportLocalError::Consensus(error)) => Some(error),
            Self::Local(PqImportLocalError::Transition(error)) => Some(error),
            Self::Local(PqImportLocalError::Persistence(error)) => Some(error),
            Self::PeerInvalid(
                PqImportPeerInvalid::NonLinearRange { .. }
                | PqImportPeerInvalid::Equivocation { .. }
                | PqImportPeerInvalid::NonAdvancingSlot { .. }
                | PqImportPeerInvalid::FutureSlot { .. }
                | PqImportPeerInvalid::ExecutionPayload(_),
            )
            | Self::ExecutionRejected(_)
            | Self::ExecutionReconciliation(_)
            | Self::DurableStateUnknown { .. }
            | Self::TerminalObservation { .. }
            | Self::StaleHeadAfterVerification { .. }
            | Self::Local(
                PqImportLocalError::Invariant(_)
                | PqImportLocalError::ClockUnavailable
                | PqImportLocalError::ParentUnavailable { .. }
                | PqImportLocalError::ObservationCapacity
                | PqImportLocalError::IngressCapacity
                | PqImportLocalError::ForwardRangeCapacity { .. }
                | PqImportLocalError::BlockingTask(_)
                | PqImportLocalError::Transport(_)
                | PqImportLocalError::ExecutionUnavailable(_),
            ) => None,
        }
    }
}

/// Fully authenticated, transitioned and locally payload-checked block. Network code may mark a
/// gossip block observed and propagate it at this point; Engine notification and canonical commit
/// still require consuming this capability.
pub struct PqVerifiedBlockImport<E: EthSpec> {
    source: PqBlockImportSource,
    expected_parent_root: Hash256,
    observation_key: PqGossipObservationKey,
    block_root: Hash256,
    output: state_processing::PqImportedTransitionOutput<E>,
    _admission: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    _activity: Option<Arc<crate::beacon_chain::PqImportActivity>>,
}

impl<E: EthSpec> PqVerifiedBlockImport<E> {
    pub const fn source(&self) -> PqBlockImportSource {
        self.source
    }

    pub fn block(&self) -> &Arc<SignedBeaconBlock<E>> {
        self.output.block()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqBlockImportOutcome {
    pub source: PqBlockImportSource,
    pub block_root: Hash256,
    pub state_root: Hash256,
    pub payload_status: PqEnginePayloadStatus,
}

enum PqVerifiedCommitOutcome {
    Imported(PqBlockImportOutcome),
    Committed,
}

pub enum PqPublishCommitOutcome {
    Imported(PqBlockImportOutcome),
    Committed,
}

pub(crate) const PQ_GOSSIP_OBSERVATION_CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PqGossipObservationKey {
    slot: Slot,
    proposer: u64,
}

impl PqGossipObservationKey {
    pub(crate) const fn new(slot: Slot, proposer: u64) -> Self {
        Self { slot, proposer }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqGossipLifecycle {
    PendingPropagation,
    PendingCommit,
    PendingExternal,
    RetryablePropagation,
    RetryableCommit,
    PendingReconciliation,
    Terminal,
    Committed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqPublishPromotionResolution {
    Promoted,
    Pending,
    Committed,
    Terminal,
    Equivocation { previous: Hash256 },
    Stale,
}

#[derive(Clone, Copy, Debug)]
struct PqGossipObservationRecord {
    root: Hash256,
    generation: u64,
    lifecycle: PqGossipLifecycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PqGossipClaim {
    Propagate { generation: u64 },
    Retry { generation: u64 },
    Pending,
    Committed,
    Terminal,
    Equivocation { previous: Hash256 },
    Capacity,
}

impl PqGossipClaim {
    #[cfg(test)]
    fn propagation_generation(self) -> Option<u64> {
        match self {
            Self::Propagate { generation } => Some(generation),
            _ => None,
        }
    }

    #[cfg(test)]
    fn retry_generation(self) -> Option<u64> {
        match self {
            Self::Retry { generation } => Some(generation),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PqGossipClaimFinish {
    Retryable,
    Terminal,
}

#[derive(Clone, Copy)]
struct PqGossipClaimBinding {
    key: PqGossipObservationKey,
    generation: u64,
}

enum PqExternalReservationClaim {
    Authorized(Option<PqGossipClaimBinding>),
    Terminal,
    Equivocation { previous: Hash256 },
    Capacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqGossipCommitAuthorization {
    Authorized,
    Terminal,
    Unavailable,
}

struct PqExternalObservationReservation {
    observations: Arc<parking_lot::Mutex<PqGossipObservationCache>>,
    binding: Option<PqGossipClaimBinding>,
    armed: bool,
}

impl PqExternalObservationReservation {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PqExternalObservationReservation {
    fn drop(&mut self) {
        if self.armed
            && let Some(binding) = self.binding
        {
            self.observations
                .lock()
                .cancel_external(binding.key, binding.generation);
        }
    }
}

struct PqPostPayloadCommit<E: EthSpec> {
    source: PqBlockImportSource,
    output: state_processing::PqImportedTransitionOutput<E>,
    observation_key: PqGossipObservationKey,
    committed_slot: Slot,
    execution_block_hash: ExecutionBlockHash,
    gossip_binding: Option<PqGossipClaimBinding>,
    external_reservation: Option<PqExternalObservationReservation>,
    _commit_permit: tokio::sync::OwnedSemaphorePermit,
    forkchoice_guard: PqExecutionForkchoiceGuard,
    _admission: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    _activity: Option<Arc<crate::beacon_chain::PqImportActivity>>,
}

enum PqCommitPreparation<E: EthSpec> {
    Commit(Box<PqPostPayloadCommit<E>>),
    Committed,
}

/// The unique capability allowed to cross the external gossipsub propagation boundary.
/// Dropping it makes the same verified block retryable instead of leaving a permanent pending
/// entry.
pub struct PqGossipPropagationToken<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
    verified: Option<PqVerifiedBlockImport<T::EthSpec>>,
    binding: PqGossipClaimBinding,
    armed: bool,
}

impl<T: BeaconChainTypes> PqGossipPropagationToken<T> {
    /// Call only after gossipsub has propagated the block. The exact first claim then becomes the
    /// only commit-ready capability for its generation.
    pub fn after_propagation(mut self) -> Result<PqGossipCommitToken<T>, PqImportError> {
        let promoted = self
            .chain
            .observed_pq_blocks
            .lock()
            .mark_propagated(self.binding.key, self.binding.generation);
        if !promoted {
            return Err(PqImportError::Local(PqImportLocalError::Invariant(
                "PQ gossip propagation claim is no longer current",
            )));
        }
        let verified =
            self.verified
                .take()
                .ok_or(PqImportError::Local(PqImportLocalError::Invariant(
                    "PQ gossip propagation capability was consumed",
                )))?;
        self.armed = false;
        Ok(PqGossipCommitToken {
            chain: Arc::clone(&self.chain),
            verified: Some(verified),
            binding: self.binding,
            armed: true,
        })
    }
}

impl<T: BeaconChainTypes> Drop for PqGossipPropagationToken<T> {
    fn drop(&mut self) {
        if self.armed {
            self.chain
                .observed_pq_blocks
                .lock()
                .cancel(self.binding.key, self.binding.generation);
        }
    }
}

/// A generation-bound gossip import capability. Only a propagated first block or a claimed
/// retryable-local failure can construct it.
pub struct PqGossipCommitToken<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
    verified: Option<PqVerifiedBlockImport<T::EthSpec>>,
    binding: PqGossipClaimBinding,
    armed: bool,
}

impl<T: BeaconChainTypes> PqGossipCommitToken<T> {
    pub async fn commit(mut self) -> Result<PqBlockImportOutcome, PqImportError> {
        let verified =
            self.verified
                .take()
                .ok_or(PqImportError::Local(PqImportLocalError::Invariant(
                    "PQ gossip commit capability was consumed",
                )))?;
        let result = self
            .chain
            .commit_verified_pq_block(verified, Some(self.binding))
            .await
            .and_then(|outcome| match outcome {
                PqVerifiedCommitOutcome::Imported(outcome) => Ok(outcome),
                PqVerifiedCommitOutcome::Committed => {
                    Err(PqImportError::Local(PqImportLocalError::Invariant(
                        "non-publication PQ import resolved as an existing committed block",
                    )))
                }
            });
        let finish = match &result {
            Ok(_) => None,
            Err(PqImportError::Local(
                PqImportLocalError::ExecutionUnavailable(_)
                | PqImportLocalError::Transport(_)
                | PqImportLocalError::BlockingTask(_)
                | PqImportLocalError::Persistence(_),
            )) => Some(PqGossipClaimFinish::Retryable),
            Err(
                PqImportError::PeerInvalid(_)
                | PqImportError::ExecutionRejected(_)
                | PqImportError::ExecutionReconciliation(_)
                | PqImportError::DurableStateUnknown { .. }
                | PqImportError::TerminalObservation { .. }
                | PqImportError::StaleHeadAfterVerification { .. }
                | PqImportError::Local(_),
            ) => Some(PqGossipClaimFinish::Terminal),
        };
        if let Some(finish) = finish {
            let mut observations = self.chain.observed_pq_blocks.lock();
            observations.finish(self.binding.key, self.binding.generation, finish);
        }
        self.armed = false;
        result
    }
}

impl<T: BeaconChainTypes> Drop for PqGossipCommitToken<T> {
    fn drop(&mut self) {
        if self.armed {
            self.chain
                .observed_pq_blocks
                .lock()
                .cancel(self.binding.key, self.binding.generation);
        }
    }
}

/// The unique capability allowed to cross the local HTTP publication boundary. It retains the
/// exact immutable block accepted by full PQ verification.
pub struct PqPublishPropagationToken<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
    verified: Option<PqVerifiedBlockImport<T::EthSpec>>,
    binding: PqGossipClaimBinding,
    armed: bool,
}

impl<T: BeaconChainTypes> PqPublishPropagationToken<T> {
    pub fn block(&self) -> Result<&Arc<SignedBeaconBlock<T::EthSpec>>, PqImportError> {
        self.verified
            .as_ref()
            .map(PqVerifiedBlockImport::block)
            .ok_or(PqImportError::Local(PqImportLocalError::Invariant(
                "PQ publication propagation capability was consumed",
            )))
    }

    pub fn after_propagation(mut self) -> Result<PqPublishPromotion<T>, PqImportError> {
        let verified =
            self.verified
                .as_ref()
                .ok_or(PqImportError::Local(PqImportLocalError::Invariant(
                    "PQ publication propagation capability was consumed",
                )))?;
        let resolution = self
            .chain
            .observed_pq_blocks
            .lock()
            .promote_or_resolve_publish(
                self.binding.key,
                verified.block_root,
                self.binding.generation,
            );
        match resolution {
            PqPublishPromotionResolution::Promoted => {}
            PqPublishPromotionResolution::Pending => {
                self.armed = false;
                return Ok(PqPublishPromotion::Pending);
            }
            PqPublishPromotionResolution::Committed => {
                self.armed = false;
                // A committed cache record is installed only after the durable write and
                // canonical-head swap while holding the import gate. After releasing the cache
                // lock, this exact signed-head read therefore sees either that publication or a
                // later head; it cannot observe the pre-publication head.
                return Ok(
                    if self.chain.known_pq_publish_observation(verified.block())
                        == Some(PqKnownPublishObservation::Committed)
                    {
                        PqPublishPromotion::Committed
                    } else {
                        PqPublishPromotion::Stale
                    },
                );
            }
            PqPublishPromotionResolution::Terminal => {
                self.armed = false;
                return Ok(PqPublishPromotion::Terminal);
            }
            PqPublishPromotionResolution::Equivocation { previous } => {
                self.armed = false;
                return Ok(PqPublishPromotion::Equivocation { previous });
            }
            PqPublishPromotionResolution::Stale => {
                self.armed = false;
                return Ok(PqPublishPromotion::Stale);
            }
        }
        let verified =
            self.verified
                .take()
                .ok_or(PqImportError::Local(PqImportLocalError::Invariant(
                    "PQ publication propagation capability was consumed",
                )))?;
        self.armed = false;
        Ok(PqPublishPromotion::Commit(Box::new(PqPublishCommitToken {
            chain: Arc::clone(&self.chain),
            verified: Some(verified),
            binding: self.binding,
            armed: true,
        })))
    }
}

impl<T: BeaconChainTypes> Drop for PqPublishPropagationToken<T> {
    fn drop(&mut self) {
        if self.armed {
            self.chain
                .observed_pq_blocks
                .lock()
                .cancel(self.binding.key, self.binding.generation);
        }
    }
}

pub struct PqPublishCommitToken<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
    verified: Option<PqVerifiedBlockImport<T::EthSpec>>,
    binding: PqGossipClaimBinding,
    armed: bool,
}

pub enum PqPublishPromotion<T: BeaconChainTypes> {
    Commit(Box<PqPublishCommitToken<T>>),
    Pending,
    Committed,
    Terminal,
    Equivocation { previous: Hash256 },
    Stale,
}

impl<T: BeaconChainTypes> PqPublishCommitToken<T> {
    pub async fn commit(mut self) -> Result<PqPublishCommitOutcome, PqImportError> {
        let verified =
            self.verified
                .take()
                .ok_or(PqImportError::Local(PqImportLocalError::Invariant(
                    "PQ publication commit capability was consumed",
                )))?;
        let result = self
            .chain
            .commit_verified_pq_block(verified, Some(self.binding))
            .await
            .map(|outcome| match outcome {
                PqVerifiedCommitOutcome::Imported(outcome) => {
                    PqPublishCommitOutcome::Imported(outcome)
                }
                PqVerifiedCommitOutcome::Committed => PqPublishCommitOutcome::Committed,
            });
        let finish = match &result {
            Ok(_) => None,
            Err(PqImportError::Local(
                PqImportLocalError::ExecutionUnavailable(_)
                | PqImportLocalError::Transport(_)
                | PqImportLocalError::BlockingTask(_)
                | PqImportLocalError::Persistence(_),
            )) => Some(PqGossipClaimFinish::Retryable),
            Err(
                PqImportError::PeerInvalid(_)
                | PqImportError::ExecutionRejected(_)
                | PqImportError::ExecutionReconciliation(_)
                | PqImportError::DurableStateUnknown { .. }
                | PqImportError::TerminalObservation { .. }
                | PqImportError::StaleHeadAfterVerification { .. }
                | PqImportError::Local(_),
            ) => Some(PqGossipClaimFinish::Terminal),
        };
        if let Some(finish) = finish {
            self.chain.observed_pq_blocks.lock().finish(
                self.binding.key,
                self.binding.generation,
                finish,
            );
        }
        self.armed = false;
        result
    }
}

impl<T: BeaconChainTypes> Drop for PqPublishCommitToken<T> {
    fn drop(&mut self) {
        if self.armed {
            self.chain
                .observed_pq_blocks
                .lock()
                .cancel(self.binding.key, self.binding.generation);
        }
    }
}

pub enum PqPublishObservation<T: BeaconChainTypes> {
    New(PqPublishPropagationToken<T>),
    Retry(PqPublishCommitToken<T>),
    Pending,
    Committed,
    Terminal,
    Equivocation { previous: Hash256 },
    NotPublish,
    Capacity,
}

/// An exact-root publication lifecycle that can be answered without repeating the expensive
/// sealed verification. Retryable records are intentionally omitted: they must regain a fresh
/// sealed capability before retrying propagation or commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqKnownPublishObservation {
    Pending,
    Committed,
    Terminal,
}

pub enum PqGossipObservation<T: BeaconChainTypes> {
    New(PqGossipPropagationToken<T>),
    Retry(PqGossipCommitToken<T>),
    Pending,
    Terminal,
    Equivocation { previous: Hash256 },
    NotGossip,
    Capacity,
}

#[derive(Default)]
pub(crate) struct PqGossipObservationCache {
    entries: HashMap<PqGossipObservationKey, PqGossipObservationRecord>,
    next_generation: u64,
}

impl PqGossipObservationCache {
    fn promote_or_resolve_publish(
        &mut self,
        key: PqGossipObservationKey,
        root: Hash256,
        generation: u64,
    ) -> PqPublishPromotionResolution {
        let Some(record) = self.entries.get_mut(&key) else {
            return PqPublishPromotionResolution::Stale;
        };
        if record.root != root {
            return PqPublishPromotionResolution::Equivocation {
                previous: record.root,
            };
        }
        match record.lifecycle {
            PqGossipLifecycle::PendingPropagation if record.generation == generation => {
                record.lifecycle = PqGossipLifecycle::PendingCommit;
                PqPublishPromotionResolution::Promoted
            }
            PqGossipLifecycle::Committed => PqPublishPromotionResolution::Committed,
            PqGossipLifecycle::Terminal => PqPublishPromotionResolution::Terminal,
            PqGossipLifecycle::PendingReconciliation => PqPublishPromotionResolution::Pending,
            PqGossipLifecycle::PendingPropagation
            | PqGossipLifecycle::PendingCommit
            | PqGossipLifecycle::PendingExternal
            | PqGossipLifecycle::RetryablePropagation
            | PqGossipLifecycle::RetryableCommit => PqPublishPromotionResolution::Stale,
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    fn is_committed(&self, key: PqGossipObservationKey, root: Hash256) -> bool {
        self.entries.get(&key).is_some_and(|record| {
            record.root == root && record.lifecycle == PqGossipLifecycle::Committed
        })
    }

    #[cfg(feature = "pq-startup-testing")]
    fn is_absent(&self, key: PqGossipObservationKey) -> bool {
        !self.entries.contains_key(&key)
    }

    #[cfg(feature = "pq-startup-testing")]
    fn is_pending_commit(&self, key: PqGossipObservationKey, root: Hash256) -> bool {
        self.entries.get(&key).is_some_and(|record| {
            record.root == root && record.lifecycle == PqGossipLifecycle::PendingCommit
        })
    }

    pub(crate) fn claim(
        &mut self,
        key: PqGossipObservationKey,
        root: Hash256,
        retained_head_slot: Slot,
    ) -> PqGossipClaim {
        self.entries.retain(|key, _| key.slot >= retained_head_slot);
        if let Some(record) = self.entries.get(&key).copied() {
            if record.root != root {
                return PqGossipClaim::Equivocation {
                    previous: record.root,
                };
            }
            return match record.lifecycle {
                PqGossipLifecycle::PendingPropagation
                | PqGossipLifecycle::PendingCommit
                | PqGossipLifecycle::PendingReconciliation => PqGossipClaim::Pending,
                PqGossipLifecycle::PendingExternal => PqGossipClaim::Pending,
                PqGossipLifecycle::Terminal => PqGossipClaim::Terminal,
                PqGossipLifecycle::Committed => PqGossipClaim::Committed,
                PqGossipLifecycle::RetryablePropagation | PqGossipLifecycle::RetryableCommit => {
                    let Some(generation) = self.allocate_generation() else {
                        return PqGossipClaim::Capacity;
                    };
                    if let Some(record) = self.entries.get_mut(&key) {
                        record.generation = generation;
                        if record.lifecycle == PqGossipLifecycle::RetryablePropagation {
                            record.lifecycle = PqGossipLifecycle::PendingPropagation;
                            PqGossipClaim::Propagate { generation }
                        } else {
                            record.lifecycle = PqGossipLifecycle::PendingCommit;
                            PqGossipClaim::Retry { generation }
                        }
                    } else {
                        PqGossipClaim::Capacity
                    }
                }
            };
        }
        if self.entries.len() >= PQ_GOSSIP_OBSERVATION_CAPACITY {
            return PqGossipClaim::Capacity;
        }
        let Some(generation) = self.allocate_generation() else {
            return PqGossipClaim::Capacity;
        };
        self.entries.insert(
            key,
            PqGossipObservationRecord {
                root,
                generation,
                lifecycle: PqGossipLifecycle::PendingPropagation,
            },
        );
        PqGossipClaim::Propagate { generation }
    }

    pub(crate) fn mark_propagated(&mut self, key: PqGossipObservationKey, generation: u64) -> bool {
        self.transition(
            key,
            generation,
            PqGossipLifecycle::PendingPropagation,
            PqGossipLifecycle::PendingCommit,
        )
    }

    pub(crate) fn cancel(&mut self, key: PqGossipObservationKey, generation: u64) -> bool {
        let pending = self
            .entries
            .get(&key)
            .filter(|record| record.generation == generation)
            .map(|record| record.lifecycle);
        match pending {
            Some(PqGossipLifecycle::PendingPropagation) => {
                if let Some(record) = self.entries.get_mut(&key) {
                    record.lifecycle = PqGossipLifecycle::RetryablePropagation;
                    true
                } else {
                    false
                }
            }
            Some(PqGossipLifecycle::PendingCommit) => {
                if let Some(record) = self.entries.get_mut(&key) {
                    record.lifecycle = PqGossipLifecycle::RetryableCommit;
                    true
                } else {
                    false
                }
            }
            Some(
                PqGossipLifecycle::RetryablePropagation
                | PqGossipLifecycle::RetryableCommit
                | PqGossipLifecycle::PendingExternal
                | PqGossipLifecycle::PendingReconciliation
                | PqGossipLifecycle::Terminal
                | PqGossipLifecycle::Committed,
            )
            | None => false,
        }
    }

    pub(crate) fn finish(
        &mut self,
        key: PqGossipObservationKey,
        generation: u64,
        finish: PqGossipClaimFinish,
    ) -> bool {
        let lifecycle = match finish {
            PqGossipClaimFinish::Retryable => PqGossipLifecycle::RetryableCommit,
            PqGossipClaimFinish::Terminal => PqGossipLifecycle::Terminal,
        };
        self.transition(key, generation, PqGossipLifecycle::PendingCommit, lifecycle)
    }

    pub(crate) fn prune_after_commit(&mut self, committed_slot: Slot) {
        self.entries.retain(|key, _| key.slot >= committed_slot);
    }

    fn resolve_gossip_commit(
        &self,
        key: PqGossipObservationKey,
        root: Hash256,
        generation: u64,
    ) -> PqGossipCommitAuthorization {
        let Some(record) = self.entries.get(&key) else {
            return PqGossipCommitAuthorization::Unavailable;
        };
        if record.root != root {
            return PqGossipCommitAuthorization::Unavailable;
        }
        if record.generation == generation && record.lifecycle == PqGossipLifecycle::PendingCommit {
            return PqGossipCommitAuthorization::Authorized;
        }
        if matches!(
            record.lifecycle,
            PqGossipLifecycle::PendingReconciliation
                | PqGossipLifecycle::Terminal
                | PqGossipLifecycle::Committed
        ) {
            return PqGossipCommitAuthorization::Terminal;
        }
        PqGossipCommitAuthorization::Unavailable
    }

    fn reserve_external(
        &mut self,
        key: PqGossipObservationKey,
        root: Hash256,
        retained_head_slot: Slot,
    ) -> PqExternalReservationClaim {
        self.entries.retain(|key, _| key.slot >= retained_head_slot);
        if let Some(record) = self.entries.get(&key) {
            if record.root != root {
                return PqExternalReservationClaim::Equivocation {
                    previous: record.root,
                };
            }
            if record.root == root
                && matches!(
                    record.lifecycle,
                    PqGossipLifecycle::PendingReconciliation
                        | PqGossipLifecycle::Terminal
                        | PqGossipLifecycle::Committed
                )
            {
                return PqExternalReservationClaim::Terminal;
            }
            return PqExternalReservationClaim::Authorized(None);
        }
        if self.entries.len() >= PQ_GOSSIP_OBSERVATION_CAPACITY {
            return PqExternalReservationClaim::Capacity;
        }
        let Some(generation) = self.allocate_generation() else {
            return PqExternalReservationClaim::Capacity;
        };
        self.entries.insert(
            key,
            PqGossipObservationRecord {
                root,
                generation,
                lifecycle: PqGossipLifecycle::PendingExternal,
            },
        );
        PqExternalReservationClaim::Authorized(Some(PqGossipClaimBinding { key, generation }))
    }

    fn cancel_external(&mut self, key: PqGossipObservationKey, generation: u64) -> bool {
        if self.entries.get(&key).is_some_and(|record| {
            record.generation == generation
                && record.lifecycle == PqGossipLifecycle::PendingExternal
        }) {
            self.entries.remove(&key);
            true
        } else {
            false
        }
    }

    pub(crate) fn record_commit(
        &mut self,
        key: PqGossipObservationKey,
        root: Hash256,
        committed_slot: Slot,
    ) {
        self.prune_after_commit(committed_slot);
        self.install_terminal_record(key, root, PqGossipLifecycle::Committed);
    }

    pub(crate) fn record_pending_reconciliation(
        &mut self,
        key: PqGossipObservationKey,
        root: Hash256,
        committed_slot: Slot,
    ) {
        self.prune_after_commit(committed_slot);
        self.install_terminal_record(key, root, PqGossipLifecycle::PendingReconciliation);
    }

    pub(crate) fn record_terminal(&mut self, key: PqGossipObservationKey, root: Hash256) {
        if let Some(record) = self
            .entries
            .get_mut(&key)
            .filter(|record| record.root == root)
        {
            record.lifecycle = PqGossipLifecycle::Terminal;
        }
    }

    pub(crate) fn record_durable_state_unknown(
        &mut self,
        key: PqGossipObservationKey,
        root: Hash256,
    ) {
        self.install_terminal_record(key, root, PqGossipLifecycle::Terminal);
    }

    fn install_terminal_record(
        &mut self,
        key: PqGossipObservationKey,
        root: Hash256,
        lifecycle: PqGossipLifecycle,
    ) {
        self.entries.insert(
            key,
            PqGossipObservationRecord {
                root,
                generation: self.next_generation,
                lifecycle,
            },
        );
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn transition(
        &mut self,
        key: PqGossipObservationKey,
        generation: u64,
        from: PqGossipLifecycle,
        to: PqGossipLifecycle,
    ) -> bool {
        if let Some(record) = self
            .entries
            .get_mut(&key)
            .filter(|record| record.generation == generation && record.lifecycle == from)
        {
            record.lifecycle = to;
            true
        } else {
            false
        }
    }

    fn allocate_generation(&mut self) -> Option<u64> {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.checked_add(1)?;
        Some(generation)
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPqGossipClaim {
    Propagate(u64),
    Retry(u64),
    Pending,
    Committed,
    Terminal,
    Equivocation(Hash256),
    Capacity,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPqGossipFinish {
    Retryable,
    Terminal,
    Committed,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPqExternalReservation {
    Authorized,
    Terminal,
    Equivocation(Hash256),
    Capacity,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPqPublishPromotionResolution {
    Promoted,
    Pending,
    Committed,
    Terminal,
    Equivocation(Hash256),
    Stale,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Default)]
pub struct TestingPqGossipObservationCache(PqGossipObservationCache);

#[cfg(feature = "pq-startup-testing")]
impl TestingPqGossipObservationCache {
    pub const CAPACITY: usize = PQ_GOSSIP_OBSERVATION_CAPACITY;

    pub fn claim(
        &mut self,
        slot: Slot,
        proposer: u64,
        root: Hash256,
        retained_head_slot: Slot,
    ) -> TestingPqGossipClaim {
        match self.0.claim(
            PqGossipObservationKey::new(slot, proposer),
            root,
            retained_head_slot,
        ) {
            PqGossipClaim::Propagate { generation } => TestingPqGossipClaim::Propagate(generation),
            PqGossipClaim::Retry { generation } => TestingPqGossipClaim::Retry(generation),
            PqGossipClaim::Pending => TestingPqGossipClaim::Pending,
            PqGossipClaim::Committed => TestingPqGossipClaim::Committed,
            PqGossipClaim::Terminal => TestingPqGossipClaim::Terminal,
            PqGossipClaim::Equivocation { previous } => {
                TestingPqGossipClaim::Equivocation(previous)
            }
            PqGossipClaim::Capacity => TestingPqGossipClaim::Capacity,
        }
    }

    pub fn mark_propagated(&mut self, slot: Slot, proposer: u64, generation: u64) -> bool {
        self.0
            .mark_propagated(PqGossipObservationKey::new(slot, proposer), generation)
    }

    pub fn cancel(&mut self, slot: Slot, proposer: u64, generation: u64) -> bool {
        self.0
            .cancel(PqGossipObservationKey::new(slot, proposer), generation)
    }

    pub fn finish(
        &mut self,
        slot: Slot,
        proposer: u64,
        generation: u64,
        finish: TestingPqGossipFinish,
    ) -> bool {
        let key = PqGossipObservationKey::new(slot, proposer);
        if finish == TestingPqGossipFinish::Committed {
            let Some(root) = self.0.entries.get(&key).map(|record| record.root) else {
                return false;
            };
            self.0.record_commit(key, root, slot);
            return true;
        }
        self.0.finish(
            key,
            generation,
            match finish {
                TestingPqGossipFinish::Retryable => PqGossipClaimFinish::Retryable,
                TestingPqGossipFinish::Terminal => PqGossipClaimFinish::Terminal,
                TestingPqGossipFinish::Committed => return false,
            },
        )
    }

    pub fn prune_after_commit(&mut self, committed_slot: Slot) {
        self.0.prune_after_commit(committed_slot);
    }

    pub fn authorize_commit(
        &self,
        slot: Slot,
        proposer: u64,
        root: Hash256,
        generation: u64,
    ) -> bool {
        self.0.resolve_gossip_commit(
            PqGossipObservationKey::new(slot, proposer),
            root,
            generation,
        ) == PqGossipCommitAuthorization::Authorized
    }

    pub fn reserve_external(
        &mut self,
        slot: Slot,
        proposer: u64,
        root: Hash256,
        retained_head_slot: Slot,
    ) -> TestingPqExternalReservation {
        match self.0.reserve_external(
            PqGossipObservationKey::new(slot, proposer),
            root,
            retained_head_slot,
        ) {
            PqExternalReservationClaim::Authorized(_) => TestingPqExternalReservation::Authorized,
            PqExternalReservationClaim::Terminal => TestingPqExternalReservation::Terminal,
            PqExternalReservationClaim::Equivocation { previous } => {
                TestingPqExternalReservation::Equivocation(previous)
            }
            PqExternalReservationClaim::Capacity => TestingPqExternalReservation::Capacity,
        }
    }

    pub fn record_commit(&mut self, slot: Slot, proposer: u64, root: Hash256) {
        self.0
            .record_commit(PqGossipObservationKey::new(slot, proposer), root, slot);
    }

    pub fn record_terminal(&mut self, slot: Slot, proposer: u64, root: Hash256) {
        self.0
            .record_terminal(PqGossipObservationKey::new(slot, proposer), root);
    }

    pub fn promote_or_resolve_publish(
        &mut self,
        slot: Slot,
        proposer: u64,
        root: Hash256,
        generation: u64,
    ) -> TestingPqPublishPromotionResolution {
        match self.0.promote_or_resolve_publish(
            PqGossipObservationKey::new(slot, proposer),
            root,
            generation,
        ) {
            PqPublishPromotionResolution::Promoted => TestingPqPublishPromotionResolution::Promoted,
            PqPublishPromotionResolution::Pending => TestingPqPublishPromotionResolution::Pending,
            PqPublishPromotionResolution::Committed => {
                TestingPqPublishPromotionResolution::Committed
            }
            PqPublishPromotionResolution::Terminal => TestingPqPublishPromotionResolution::Terminal,
            PqPublishPromotionResolution::Equivocation { previous } => {
                TestingPqPublishPromotionResolution::Equivocation(previous)
            }
            PqPublishPromotionResolution::Stale => TestingPqPublishPromotionResolution::Stale,
        }
    }

    pub fn len(&self) -> usize {
        self.0.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.entries.is_empty()
    }
}

#[derive(Debug)]
pub struct PqForwardRangeError {
    pub imported: Vec<PqBlockImportOutcome>,
    pub error: PqImportError,
}

impl std::fmt::Display for PqForwardRangeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PQ forward range stopped after {} imports: {}",
            self.imported.len(),
            self.error
        )
    }
}

impl Error for PqForwardRangeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Replays the exact durable PQ head into the process-owned execution engine before any
    /// external ingress is exposed. Frozen V1 has no fork-choice finality, so safe and finalized
    /// remain the exact zero hashes used by [`PqExecutionNotifier`].
    pub async fn reconcile_persisted_pq_head(&self) -> Result<(), PqImportError> {
        let _commit_permit = Arc::clone(&self.pq_import_gate)
            .acquire_owned()
            .await
            .map_err(|_| {
                PqImportError::Local(PqImportLocalError::Transport(
                    execution_layer::Error::ShuttingDown,
                ))
            })?;
        let snapshot = self.head_snapshot();
        let current_slot = snapshot.beacon_state.slot();
        let head_block_root = snapshot.beacon_block_root;
        let genesis_slot = self.slot_clock.genesis_slot();
        let head_block_hash = self
            .run_pq_blocking("pq-persisted-head-execution-binding", move || {
                persisted_pq_execution_head(&snapshot, genesis_slot)
            })
            .await??;
        let guard = self
            .pq_execution_notifier
            .acquire_forkchoice_guard()
            .await
            .map_err(|error| PqImportError::Local(PqImportLocalError::Transport(error)))?;
        self.pq_execution_reconciliation.set(
            crate::beacon_chain::PqExecutionReconciliationState::Pending {
                block_root: head_block_root,
            },
        );
        reconcile_pq_execution(
            &self.pq_execution_notifier,
            &guard,
            &self.pq_execution_reconciliation,
            &self.task_executor,
            head_block_hash,
            current_slot,
            head_block_root,
        )
        .await
    }

    async fn run_pq_blocking<F, R>(&self, phase: &'static str, task: F) -> Result<R, PqImportError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.task_executor
            .spawn_blocking_handle(task, phase)
            .ok_or(PqImportError::Local(PqImportLocalError::BlockingTask(
                phase,
            )))?
            .await
            .map_err(|_| PqImportError::Local(PqImportLocalError::BlockingTask(phase)))
    }

    /// Performs the same complete PQ verification and consuming state transition for every source.
    /// It makes no observed-block, fork-choice or persistence mutation and holds no lock or
    /// state/cache borrow across the proof-worker await.
    pub async fn verify_pq_block(
        &self,
        request: PqBlockImportRequest<T::EthSpec>,
    ) -> Result<PqVerifiedBlockImport<T::EthSpec>, PqImportError> {
        let activity = self
            .pq_import_coordinator
            .try_start()
            .ok_or(PqImportError::Local(PqImportLocalError::Transport(
                execution_layer::Error::ShuttingDown,
            )))?;
        let admission = Arc::clone(&self.pq_import_admission)
            .try_acquire_owned()
            .map_err(|_| PqImportError::Local(PqImportLocalError::IngressCapacity))?;
        self.verify_pq_block_admitted(request, Some(Arc::new(admission)), Some(activity))
            .await
    }

    async fn verify_pq_block_admitted(
        &self,
        request: PqBlockImportRequest<T::EthSpec>,
        admission: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
        activity: Option<Arc<crate::beacon_chain::PqImportActivity>>,
    ) -> Result<PqVerifiedBlockImport<T::EthSpec>, PqImportError> {
        let head = self.head_snapshot();
        let actual_parent = request.block.message().parent_root();
        if actual_parent != head.beacon_block_root {
            return Err(match request.source {
                PqBlockImportSource::ForwardRange => {
                    PqImportError::PeerInvalid(PqImportPeerInvalid::NonLinearRange {
                        expected: head.beacon_block_root,
                        actual: actual_parent,
                    })
                }
                PqBlockImportSource::Gossip
                | PqBlockImportSource::Publish
                | PqBlockImportSource::Rpc
                | PqBlockImportSource::Lookup => {
                    PqImportError::Local(PqImportLocalError::ParentUnavailable {
                        parent_root: actual_parent,
                    })
                }
            });
        }
        if request.block.slot() <= head.beacon_state.slot() {
            return Err(PqImportError::PeerInvalid(
                PqImportPeerInvalid::NonAdvancingSlot {
                    parent: head.beacon_state.slot(),
                    block: request.block.slot(),
                },
            ));
        }
        let current_slot = self
            .slot_clock
            .now_with_future_tolerance(self.spec.maximum_gossip_clock_disparity())
            .ok_or(PqImportError::Local(PqImportLocalError::ClockUnavailable))?;
        if request.block.slot() > current_slot {
            return Err(PqImportError::PeerInvalid(
                PqImportPeerInvalid::FutureSlot {
                    current: current_slot,
                    block: request.block.slot(),
                },
            ));
        }

        let source = request.source;
        let expected_parent_root = head.beacon_block_root;
        let spec = Arc::clone(&self.spec);
        let key_cache = Arc::clone(&self.pq_validator_key_cache);
        let prepare_admission = admission.clone();
        let prepare_activity = activity.clone();
        #[cfg(feature = "pq-startup-testing")]
        let blocking_test_hook = self.pq_blocking_test_hook.clone();
        let (advanced_parent, prepared) = self
            .run_pq_blocking("pq-import-prepare", move || {
                let _admission = prepare_admission;
                let _activity = prepare_activity;
                #[cfg(feature = "pq-startup-testing")]
                if let Some(hook) = blocking_test_hook {
                    hook.run();
                }
                let mut advanced_parent = head.beacon_state.clone();
                while advanced_parent.slot() < request.block.slot() {
                    per_slot_processing_pq(&mut advanced_parent, &spec)
                        .map_err(classify_transition_error)?;
                }
                let payload_request = NewPayloadRequest::try_from(request.block.message())
                    .map_err(|error| {
                        PqImportError::PeerInvalid(PqImportPeerInvalid::ExecutionPayload(
                            error.into(),
                        ))
                    })?;
                payload_request
                    .perform_optimistic_sync_verifications()
                    .map_err(|error| {
                        PqImportError::PeerInvalid(PqImportPeerInvalid::ExecutionPayload(error))
                    })?;
                let prepared = prepare_pq_block(&advanced_parent, &key_cache, request.block, &spec)
                    .map_err(classify_consensus_error)?;
                Ok::<_, PqImportError>((advanced_parent, prepared))
            })
            .await??;
        let service = Arc::clone(&self.pq_aggregation_service);
        let verified = prepared
            .verify(&service)
            .await
            .map_err(classify_consensus_error)?;
        let transition_admission = admission.clone();
        let transition_activity = activity.clone();
        let (output, observation_key, block_root) = self
            .run_pq_blocking("pq-import-transition", move || {
                let _admission = transition_admission;
                let _activity = transition_activity;
                let output = transition_pq_imported_block(advanced_parent, verified)
                    .map_err(classify_transition_error)?;
                let block = output.block();
                let observation_key =
                    PqGossipObservationKey::new(block.slot(), block.message().proposer_index());
                let block_root = block.canonical_root();
                Ok::<_, PqImportError>((output, observation_key, block_root))
            })
            .await??;
        Ok(PqVerifiedBlockImport {
            source,
            expected_parent_root,
            observation_key,
            block_root,
            output,
            _admission: admission,
            _activity: activity,
        })
    }

    /// Records a fully verified gossip block only after the sealed boundary has succeeded.
    /// Reports duplicate/equivocation semantics or a non-gossip capability invariant.
    pub fn observe_verified_pq_gossip_block(
        self: &Arc<Self>,
        verified: PqVerifiedBlockImport<T::EthSpec>,
    ) -> PqGossipObservation<T> {
        if verified.source != PqBlockImportSource::Gossip {
            return PqGossipObservation::NotGossip;
        }
        let key = verified.observation_key;
        let root = verified.block_root;
        let retained_head_slot = self.head_snapshot().beacon_state.slot();
        let claim = self
            .observed_pq_blocks
            .lock()
            .claim(key, root, retained_head_slot);
        match claim {
            PqGossipClaim::Propagate { generation } => {
                PqGossipObservation::New(PqGossipPropagationToken {
                    chain: Arc::clone(self),
                    verified: Some(verified),
                    binding: PqGossipClaimBinding { key, generation },
                    armed: true,
                })
            }
            PqGossipClaim::Retry { generation } => {
                PqGossipObservation::Retry(PqGossipCommitToken {
                    chain: Arc::clone(self),
                    verified: Some(verified),
                    binding: PqGossipClaimBinding { key, generation },
                    armed: true,
                })
            }
            PqGossipClaim::Pending => PqGossipObservation::Pending,
            PqGossipClaim::Committed => PqGossipObservation::Terminal,
            PqGossipClaim::Terminal => PqGossipObservation::Terminal,
            PqGossipClaim::Equivocation { previous } => {
                PqGossipObservation::Equivocation { previous }
            }
            PqGossipClaim::Capacity => PqGossipObservation::Capacity,
        }
    }

    /// Records a fully verified local publication only after the sealed boundary has succeeded.
    pub fn observe_verified_pq_publish_block(
        self: &Arc<Self>,
        verified: PqVerifiedBlockImport<T::EthSpec>,
    ) -> PqPublishObservation<T> {
        if verified.source != PqBlockImportSource::Publish {
            return PqPublishObservation::NotPublish;
        }
        let key = verified.observation_key;
        let root = verified.block_root;
        let retained_head_slot = self.head_snapshot().beacon_state.slot();
        match self
            .observed_pq_blocks
            .lock()
            .claim(key, root, retained_head_slot)
        {
            PqGossipClaim::Propagate { generation } => {
                PqPublishObservation::New(PqPublishPropagationToken {
                    chain: Arc::clone(self),
                    verified: Some(verified),
                    binding: PqGossipClaimBinding { key, generation },
                    armed: true,
                })
            }
            PqGossipClaim::Retry { generation } => {
                PqPublishObservation::Retry(PqPublishCommitToken {
                    chain: Arc::clone(self),
                    verified: Some(verified),
                    binding: PqGossipClaimBinding { key, generation },
                    armed: true,
                })
            }
            PqGossipClaim::Pending => PqPublishObservation::Pending,
            PqGossipClaim::Committed => PqPublishObservation::Committed,
            PqGossipClaim::Terminal => PqPublishObservation::Terminal,
            PqGossipClaim::Equivocation { previous } => {
                PqPublishObservation::Equivocation { previous }
            }
            PqGossipClaim::Capacity => PqPublishObservation::Capacity,
        }
    }

    /// Returns committed only for the exact signed current persisted head. The canonical block
    /// root excludes the proposal signature, so root equality alone is not sufficient. Older
    /// committed blocks are intentionally not indexed in linear V1 and fall through to the normal
    /// stale/parent-unavailable import policy.
    pub fn known_pq_publish_observation(
        &self,
        block: &SignedBeaconBlock<T::EthSpec>,
    ) -> Option<PqKnownPublishObservation> {
        let head = self.head_snapshot();
        if head.beacon_block_root != block.canonical_root() || head.beacon_block.as_ref() != block {
            return None;
        }
        match self.pq_execution_reconciliation.current() {
            crate::beacon_chain::PqExecutionReconciliationState::Pending { block_root }
                if block_root == head.beacon_block_root =>
            {
                Some(PqKnownPublishObservation::Pending)
            }
            crate::beacon_chain::PqExecutionReconciliationState::Reconciled { block_root }
                if block_root == head.beacon_block_root =>
            {
                Some(PqKnownPublishObservation::Committed)
            }
            crate::beacon_chain::PqExecutionReconciliationState::Failed { block_root }
                if block_root == head.beacon_block_root =>
            {
                Some(PqKnownPublishObservation::Terminal)
            }
            _ => None,
        }
    }

    fn exact_current_pq_import_outcome(
        &self,
        block: &SignedBeaconBlock<T::EthSpec>,
        source: PqBlockImportSource,
    ) -> Option<PqBlockImportOutcome> {
        let head = self.head_snapshot();
        (head.beacon_block_root == block.canonical_root() && head.beacon_block.as_ref() == block)
            .then(|| PqBlockImportOutcome {
                source,
                block_root: head.beacon_block_root,
                state_root: head.beacon_block.message().state_root(),
                payload_status: PqEnginePayloadStatus::Valid,
            })
    }

    async fn wait_for_exact_pq_reconciliation(
        &self,
        block_root: Hash256,
    ) -> crate::beacon_chain::PqExecutionReconciliationState {
        self.pq_execution_reconciliation.wait_for(block_root).await
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_fill_pq_observation_capacity(&self) -> bool {
        let head_slot = self.head_snapshot().beacon_state.slot();
        let mut observations = self.observed_pq_blocks.lock();
        for offset in 0..PQ_GOSSIP_OBSERVATION_CAPACITY {
            let Ok(offset_u64) = u64::try_from(offset) else {
                return false;
            };
            let Some(slot_u64) = head_slot
                .as_u64()
                .checked_add(offset_u64)
                .and_then(|slot| slot.checked_add(2))
            else {
                return false;
            };
            let Ok(root_byte) = u8::try_from(offset % 251) else {
                return false;
            };
            observations.install_terminal_record(
                PqGossipObservationKey::new(Slot::new(slot_u64), offset_u64 % 16),
                Hash256::with_last_byte(root_byte),
                PqGossipLifecycle::Terminal,
            );
        }
        observations.entries.len() == PQ_GOSSIP_OBSERVATION_CAPACITY
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_import_available_permits(&self) -> usize {
        self.pq_import_admission.available_permits()
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_observation_is_committed(
        &self,
        slot: Slot,
        proposer: u64,
        root: Hash256,
    ) -> bool {
        self.observed_pq_blocks
            .lock()
            .is_committed(PqGossipObservationKey::new(slot, proposer), root)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_observation_is_absent(&self, slot: Slot, proposer: u64) -> bool {
        self.observed_pq_blocks
            .lock()
            .is_absent(PqGossipObservationKey::new(slot, proposer))
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_observation_is_pending_commit(
        &self,
        slot: Slot,
        proposer: u64,
        root: Hash256,
    ) -> bool {
        self.observed_pq_blocks
            .lock()
            .is_pending_commit(PqGossipObservationKey::new(slot, proposer), root)
    }

    /// Calls Engine after full PQ verification (and, for gossip, after caller propagation), then
    /// atomically persists the sealed transition output before publishing the new head.
    async fn commit_verified_pq_block(
        self: &Arc<Self>,
        verified: PqVerifiedBlockImport<T::EthSpec>,
        gossip_binding: Option<PqGossipClaimBinding>,
    ) -> Result<PqVerifiedCommitOutcome, PqImportError> {
        let prepared = match self
            .prepare_pq_commit_after_new_payload(verified, gossip_binding)
            .await?
        {
            PqCommitPreparation::Commit(prepared) => prepared,
            PqCommitPreparation::Committed => return Ok(PqVerifiedCommitOutcome::Committed),
        };
        let durable_block_root = prepared.output.block().canonical_root();
        let durable_observation_key = prepared.observation_key;
        let chain = Arc::clone(self);
        let coordinator = Arc::clone(&self.pq_import_coordinator);
        let task = self.task_executor.spawn_handle_without_exit(
            async move {
                let mut panic_guard = crate::beacon_chain::PqImportPanicGuard::new(coordinator);
                let result = chain.persist_and_reconcile_pq_commit(*prepared).await;
                panic_guard.disarm();
                result
            },
            "pq-block-import-commit-and-reconcile",
        );
        let Some(task) = task else {
            return Err(PqImportError::Local(PqImportLocalError::BlockingTask(
                "pq-block-import-commit-and-reconcile",
            )));
        };
        match task.await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => {
                self.pq_import_coordinator.close();
                self.pq_execution_reconciliation.set(
                    crate::beacon_chain::PqExecutionReconciliationState::Failed {
                        block_root: durable_block_root,
                    },
                );
                self.observed_pq_blocks
                    .lock()
                    .record_durable_state_unknown(durable_observation_key, durable_block_root);
                signal_pq_execution_reconciliation_failure(&self.task_executor);
                Err(PqImportError::DurableStateUnknown {
                    phase: "pq-block-import-commit-and-reconcile",
                })
            }
        }
    }

    async fn prepare_pq_commit_after_new_payload(
        &self,
        verified: PqVerifiedBlockImport<T::EthSpec>,
        gossip_binding: Option<PqGossipClaimBinding>,
    ) -> Result<PqCommitPreparation<T::EthSpec>, PqImportError> {
        let observation_key = verified.observation_key;
        let block_root = verified.block_root;
        // This owned permit queues commit attempts without holding a borrowed lock, state or cache
        // reference across the Engine await.
        let commit_permit = Arc::clone(&self.pq_import_gate)
            .acquire_owned()
            .await
            .map_err(|_| {
                PqImportError::Local(PqImportLocalError::Transport(
                    execution_layer::Error::ShuttingDown,
                ))
            })?;
        let head = self.head_snapshot();
        if head.beacon_block_root == block_root
            && head.beacon_block.as_ref() == verified.output.block().as_ref()
        {
            return match self.pq_execution_reconciliation.current() {
                crate::beacon_chain::PqExecutionReconciliationState::Reconciled {
                    block_root: reconciled,
                } if reconciled == block_root => Ok(PqCommitPreparation::Committed),
                crate::beacon_chain::PqExecutionReconciliationState::Pending {
                    block_root: pending,
                } if pending == block_root => {
                    Err(PqImportError::Local(PqImportLocalError::Invariant(
                        "PQ exact-head duplicate acquired the import gate before reconciliation",
                    )))
                }
                _ => Err(PqImportError::TerminalObservation { block_root }),
            };
        }
        if gossip_binding.is_none() && head.beacon_block_root != verified.expected_parent_root {
            return Err(PqImportError::StaleHeadAfterVerification {
                expected_parent: verified.expected_parent_root,
                actual_head: head.beacon_block_root,
            });
        }
        let mut external_reservation = match gossip_binding {
            Some(binding) => {
                let authorization = if binding.key == observation_key {
                    self.observed_pq_blocks.lock().resolve_gossip_commit(
                        observation_key,
                        block_root,
                        binding.generation,
                    )
                } else {
                    PqGossipCommitAuthorization::Unavailable
                };
                if authorization == PqGossipCommitAuthorization::Authorized {
                    None
                } else if verified.source != PqBlockImportSource::Publish
                    && authorization == PqGossipCommitAuthorization::Terminal
                {
                    return Err(PqImportError::TerminalObservation { block_root });
                } else {
                    if verified.source == PqBlockImportSource::Publish
                        && head.beacon_block_root == block_root
                        && head.beacon_block.as_ref() == verified.output.block().as_ref()
                    {
                        return Ok(PqCommitPreparation::Committed);
                    }
                    if head.beacon_block_root != verified.expected_parent_root {
                        return Err(PqImportError::StaleHeadAfterVerification {
                            expected_parent: verified.expected_parent_root,
                            actual_head: head.beacon_block_root,
                        });
                    }
                    return Err(PqImportError::TerminalObservation { block_root });
                }
            }
            None => {
                let claim = self.observed_pq_blocks.lock().reserve_external(
                    observation_key,
                    block_root,
                    head.beacon_state.slot(),
                );
                match claim {
                    PqExternalReservationClaim::Authorized(binding) => {
                        Some(PqExternalObservationReservation {
                            observations: Arc::clone(&self.observed_pq_blocks),
                            binding,
                            armed: true,
                        })
                    }
                    PqExternalReservationClaim::Terminal => {
                        return Err(PqImportError::TerminalObservation { block_root });
                    }
                    PqExternalReservationClaim::Equivocation { previous } => {
                        return Err(PqImportError::PeerInvalid(
                            PqImportPeerInvalid::Equivocation {
                                previous,
                                actual: block_root,
                            },
                        ));
                    }
                    PqExternalReservationClaim::Capacity => {
                        return Err(PqImportError::Local(
                            PqImportLocalError::ObservationCapacity,
                        ));
                    }
                }
            }
        };
        if head.beacon_block_root != verified.expected_parent_root {
            return Err(PqImportError::StaleHeadAfterVerification {
                expected_parent: verified.expected_parent_root,
                actual_head: head.beacon_block_root,
            });
        }
        let forkchoice_guard = self
            .pq_execution_notifier
            .acquire_forkchoice_guard()
            .await
            .map_err(|error| PqImportError::Local(PqImportLocalError::Transport(error)))?;
        let payload_status = {
            let request = NewPayloadRequest::try_from(verified.output.block().message()).map_err(
                |error| {
                    PqImportError::PeerInvalid(PqImportPeerInvalid::ExecutionPayload(error.into()))
                },
            )?;
            self.pq_execution_notifier
                .notify_new_payload(request)
                .await
                .map_err(|error| PqImportError::Local(PqImportLocalError::Transport(error)))?
        };
        match classify_pq_engine_payload_status(&payload_status) {
            PqEnginePayloadDisposition::CommitValid => {}
            PqEnginePayloadDisposition::Retry(status) => {
                return Err(PqImportError::Local(
                    PqImportLocalError::ExecutionUnavailable(status),
                ));
            }
            PqEnginePayloadDisposition::Reject => {
                self.observed_pq_blocks
                    .lock()
                    .record_terminal(observation_key, block_root);
                if let Some(reservation) = &mut external_reservation {
                    reservation.disarm();
                }
                return Err(PqImportError::ExecutionRejected(payload_status));
            }
        }
        let execution_block_hash = verified
            .output
            .block()
            .message()
            .body()
            .execution_payload()
            .map_err(|error| {
                PqImportError::PeerInvalid(PqImportPeerInvalid::ExecutionPayload(error.into()))
            })?
            .block_hash();
        let PqVerifiedBlockImport {
            source,
            output,
            _admission,
            _activity,
            ..
        } = verified;
        let committed_slot = output.block().slot();
        Ok(PqCommitPreparation::Commit(Box::new(PqPostPayloadCommit {
            source,
            output,
            observation_key,
            committed_slot,
            execution_block_hash,
            gossip_binding,
            external_reservation,
            _commit_permit: commit_permit,
            forkchoice_guard,
            _admission,
            _activity,
        })))
    }

    async fn persist_and_reconcile_pq_commit(
        &self,
        prepared: PqPostPayloadCommit<T::EthSpec>,
    ) -> Result<PqVerifiedCommitOutcome, PqImportError> {
        let PqPostPayloadCommit {
            source,
            output,
            observation_key,
            committed_slot,
            execution_block_hash,
            gossip_binding,
            mut external_reservation,
            _commit_permit,
            forkchoice_guard,
            _admission,
            _activity,
        } = prepared;
        let store = Arc::clone(&self.store);
        let canonical_head = Arc::clone(&self.canonical_head);
        let observations = Arc::clone(&self.observed_pq_blocks);
        let persistence_observations = Arc::clone(&observations);
        let reconciliation = Arc::clone(&self.pq_execution_reconciliation);
        #[cfg(feature = "pq-startup-testing")]
        let persistence_test_hook = self.pq_persistence_test_hook.clone();
        #[cfg(feature = "pq-startup-testing")]
        let post_persist_test_hook = self.pq_post_persist_test_hook.lock().clone();
        let durable_block_root = output.block().canonical_root();
        let persistence = self.task_executor.spawn_blocking_handle(
            move || {
                #[cfg(feature = "pq-startup-testing")]
                if let Some(hook) = persistence_test_hook {
                    hook.run();
                }
                let snapshot =
                    match crate::builder::persist_pq_imported_transition::<T>(&store, output) {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            if let Some(binding) = gossip_binding {
                                persistence_observations.lock().finish(
                                    binding.key,
                                    binding.generation,
                                    PqGossipClaimFinish::Retryable,
                                );
                            }
                            return Err(PqImportError::Local(PqImportLocalError::Persistence(
                                error,
                            )));
                        }
                    };
                #[cfg(feature = "pq-startup-testing")]
                if let Some(hook) = post_persist_test_hook {
                    hook.run();
                }
                let outcome = PqBlockImportOutcome {
                    source,
                    block_root: snapshot.beacon_block_root,
                    state_root: snapshot.beacon_block.message().state_root(),
                    payload_status: PqEnginePayloadStatus::Valid,
                };
                *canonical_head.write() = Arc::new(snapshot);
                reconciliation.set(
                    crate::beacon_chain::PqExecutionReconciliationState::Pending {
                        block_root: outcome.block_root,
                    },
                );
                persistence_observations
                    .lock()
                    .record_pending_reconciliation(
                        observation_key,
                        outcome.block_root,
                        committed_slot,
                    );
                if let Some(reservation) = &mut external_reservation {
                    reservation.disarm();
                }
                Ok(outcome)
            },
            "pq-import-persist-and-publish",
        );
        let Some(persistence) = persistence else {
            return Err(PqImportError::Local(PqImportLocalError::BlockingTask(
                "pq-import-persist-and-publish",
            )));
        };
        let outcome = match persistence.await {
            Ok(outcome) => outcome?,
            Err(_) => {
                self.pq_import_coordinator.close();
                self.pq_execution_reconciliation.set(
                    crate::beacon_chain::PqExecutionReconciliationState::Failed {
                        block_root: durable_block_root,
                    },
                );
                observations
                    .lock()
                    .record_durable_state_unknown(observation_key, durable_block_root);
                signal_pq_execution_reconciliation_failure(&self.task_executor);
                return Err(PqImportError::DurableStateUnknown {
                    phase: "pq-import-persist-and-publish",
                });
            }
        };
        let result = reconcile_pq_execution(
            &self.pq_execution_notifier,
            &forkchoice_guard,
            &self.pq_execution_reconciliation,
            &self.task_executor,
            execution_block_hash,
            committed_slot,
            outcome.block_root,
        )
        .await
        .map(|()| PqVerifiedCommitOutcome::Imported(outcome.clone()));
        match &result {
            Ok(_) => observations.lock().record_commit(
                observation_key,
                outcome.block_root,
                committed_slot,
            ),
            Err(_) => observations
                .lock()
                .record_terminal(observation_key, outcome.block_root),
        }
        drop(forkchoice_guard);
        drop(_commit_permit);
        drop(_admission);
        drop(_activity);
        result
    }

    /// Imports an RPC or lookup block through the full sealed boundary. Gossip requires the
    /// propagation capability, while forward ranges use their sequential batch entry point.
    pub async fn import_pq_block(
        self: &Arc<Self>,
        request: PqBlockImportRequest<T::EthSpec>,
    ) -> Result<PqBlockImportOutcome, PqImportError> {
        if !matches!(
            request.source,
            PqBlockImportSource::Rpc | PqBlockImportSource::Lookup
        ) {
            return Err(PqImportError::Local(PqImportLocalError::Invariant(
                "PQ direct import accepts only RPC or lookup sources",
            )));
        }
        let activity = self
            .pq_import_coordinator
            .try_start()
            .ok_or(PqImportError::Local(PqImportLocalError::Transport(
                execution_layer::Error::ShuttingDown,
            )))?;
        let admission = Arc::new(
            Arc::clone(&self.pq_import_admission)
                .try_acquire_owned()
                .map_err(|_| PqImportError::Local(PqImportLocalError::IngressCapacity))?,
        );
        let source = request.source;
        let block = Arc::clone(&request.block);
        match self.known_pq_publish_observation(&request.block) {
            Some(PqKnownPublishObservation::Pending) => {
                let block_root = request.block.canonical_root();
                match self.wait_for_exact_pq_reconciliation(block_root).await {
                    crate::beacon_chain::PqExecutionReconciliationState::Reconciled {
                        block_root: reconciled,
                    } if reconciled == block_root => {
                        return self
                            .exact_current_pq_import_outcome(&request.block, source)
                            .ok_or(PqImportError::TerminalObservation { block_root });
                    }
                    crate::beacon_chain::PqExecutionReconciliationState::Failed {
                        block_root: failed,
                    } if failed == block_root => {
                        return Err(PqImportError::TerminalObservation { block_root });
                    }
                    _ => {}
                }
            }
            Some(PqKnownPublishObservation::Committed) => {
                return self
                    .exact_current_pq_import_outcome(&request.block, source)
                    .ok_or_else(|| PqImportError::TerminalObservation {
                        block_root: request.block.canonical_root(),
                    });
            }
            Some(PqKnownPublishObservation::Terminal) => {
                return Err(PqImportError::TerminalObservation {
                    block_root: request.block.canonical_root(),
                });
            }
            None => {}
        }
        let verified = self
            .verify_pq_block_admitted(request, Some(admission), Some(activity))
            .await?;
        match self.commit_verified_pq_block(verified, None).await? {
            PqVerifiedCommitOutcome::Imported(outcome) => Ok(outcome),
            PqVerifiedCommitOutcome::Committed => self
                .exact_current_pq_import_outcome(&block, source)
                .ok_or(PqImportError::Local(PqImportLocalError::Invariant(
                    "direct PQ import resolved without the exact committed head",
                ))),
        }
    }

    /// Validates and imports a forward range strictly sequentially, stopping at the first error.
    pub async fn import_pq_forward_range(
        self: &Arc<Self>,
        requests: Vec<PqBlockImportRequest<T::EthSpec>>,
    ) -> Result<Vec<PqBlockImportOutcome>, PqForwardRangeError> {
        if requests.len() > PQ_FORWARD_RANGE_BLOCK_CAPACITY {
            return Err(PqForwardRangeError {
                imported: vec![],
                error: PqImportError::Local(PqImportLocalError::ForwardRangeCapacity {
                    supplied: requests.len(),
                    maximum: PQ_FORWARD_RANGE_BLOCK_CAPACITY,
                }),
            });
        }
        let activity =
            self.pq_import_coordinator
                .try_start()
                .ok_or_else(|| PqForwardRangeError {
                    imported: vec![],
                    error: PqImportError::Local(PqImportLocalError::Transport(
                        execution_layer::Error::ShuttingDown,
                    )),
                })?;
        let admission = Arc::new(
            Arc::clone(&self.pq_import_admission)
                .try_acquire_owned()
                .map_err(|_| PqForwardRangeError {
                    imported: vec![],
                    error: PqImportError::Local(PqImportLocalError::IngressCapacity),
                })?,
        );
        let mut imported = Vec::with_capacity(requests.len());
        let head = self.head_snapshot();
        let preflight_admission = Arc::clone(&admission);
        let preflight_activity = Arc::clone(&activity);
        let requests = match self
            .run_pq_blocking("pq-range-preflight", move || {
                let _admission = preflight_admission;
                let _activity = preflight_activity;
                let mut expected_parent = head.beacon_block_root;
                let mut previous_slot = head.beacon_state.slot();
                for request in &requests {
                    let actual_parent = request.block.message().parent_root();
                    if request.source != PqBlockImportSource::ForwardRange
                        || actual_parent != expected_parent
                    {
                        return Err(PqImportError::PeerInvalid(
                            PqImportPeerInvalid::NonLinearRange {
                                expected: expected_parent,
                                actual: actual_parent,
                            },
                        ));
                    }
                    if request.block.slot() <= previous_slot {
                        return Err(PqImportError::PeerInvalid(
                            PqImportPeerInvalid::NonAdvancingSlot {
                                parent: previous_slot,
                                block: request.block.slot(),
                            },
                        ));
                    }
                    expected_parent = request.block.canonical_root();
                    previous_slot = request.block.slot();
                }
                Ok::<_, PqImportError>(requests)
            })
            .await
        {
            Ok(Ok(requests)) => requests,
            Ok(Err(error)) | Err(error) => return Err(PqForwardRangeError { imported, error }),
        };
        for request in requests {
            let verified = match self
                .verify_pq_block_admitted(
                    request,
                    Some(Arc::clone(&admission)),
                    Some(Arc::clone(&activity)),
                )
                .await
            {
                Ok(verified) => verified,
                Err(error) => {
                    return Err(PqForwardRangeError { imported, error });
                }
            };
            match self.commit_verified_pq_block(verified, None).await {
                Ok(PqVerifiedCommitOutcome::Imported(outcome)) => imported.push(outcome),
                Ok(PqVerifiedCommitOutcome::Committed) => {
                    return Err(PqForwardRangeError {
                        imported,
                        error: PqImportError::Local(PqImportLocalError::Invariant(
                            "forward PQ import resolved as an existing committed publication",
                        )),
                    });
                }
                Err(error) => return Err(PqForwardRangeError { imported, error }),
            }
        }
        Ok(imported)
    }
}

fn classify_consensus_error(error: PqConsensusError) -> PqImportError {
    match error {
        PqConsensusError::Invalid(_) => {
            PqImportError::PeerInvalid(PqImportPeerInvalid::Consensus(error))
        }
        PqConsensusError::Local(PqConsensusLocalError::UnsupportedProfile) => {
            PqImportError::Local(PqImportLocalError::Consensus(error))
        }
        PqConsensusError::Local(_) => PqImportError::Local(PqImportLocalError::Consensus(error)),
    }
}

fn classify_transition_error(error: PqTransitionError) -> PqImportError {
    match &error {
        PqTransitionError::Invalidated(PqConsensusError::Invalid(_))
        | PqTransitionError::PostStateRootMismatch { .. } => {
            PqImportError::PeerInvalid(PqImportPeerInvalid::Transition(error))
        }
        PqTransitionError::BlockProcessing(block_error)
            if !block_processing_error_is_local(block_error) =>
        {
            PqImportError::PeerInvalid(PqImportPeerInvalid::Transition(error))
        }
        PqTransitionError::PreStateMismatch { .. }
        | PqTransitionError::Invalidated(PqConsensusError::Local(_))
        | PqTransitionError::SlotProcessing(_)
        | PqTransitionError::BlockProcessing(_) => {
            PqImportError::Local(PqImportLocalError::Transition(error))
        }
    }
}

fn block_processing_error_is_local(error: &BlockProcessingError) -> bool {
    matches!(
        error,
        BlockProcessingError::IncorrectStateType
            | BlockProcessingError::BeaconStateError(_)
            | BlockProcessingError::SignatureSetError(_)
            | BlockProcessingError::SszTypesError(_)
            | BlockProcessingError::SszDecodeError(_)
            | BlockProcessingError::BitfieldError(_)
            | BlockProcessingError::MerkleTreeError(_)
            | BlockProcessingError::ArithError(_)
            | BlockProcessingError::InconsistentStateFork(_)
            | BlockProcessingError::ConsensusContext(_)
            | BlockProcessingError::MilhouseError(_)
            | BlockProcessingError::EpochCacheError(_)
            | BlockProcessingError::WithdrawalsLimitExceeded { .. }
            | BlockProcessingError::IncorrectExpectedWithdrawalsVariant
            | BlockProcessingError::MissingLastWithdrawal
            | BlockProcessingError::PendingAttestationInElectra
            | BlockProcessingError::BuilderPaymentIndexOutOfBounds(_)
    )
}
