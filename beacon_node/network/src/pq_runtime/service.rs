use super::{
    PqBlockBroadcastError, PqBlockBroadcastReceiver, PqGossipAttestationDisposition,
    PqGossipBlockDisposition, PqNetworkBlockProcessor,
};
use beacon_chain::{
    BeaconChain, BeaconChainTypes, PqAttestationGossipError, PqBlockImportOutcome,
    PqForkChoiceAttestationError, PqForkChoiceAttestationOutcome, PqGossipCommitToken,
    PqGossipPropagationToken, PqImportError, PqImportLocalError, PqOperationalEvent,
    PqOperationalEventSink, PqPeerConnectionDirection, PqSingleGossipPropagationToken,
    PqStatusMessageDirection, PqStatusRejectionCode, PqVerifiedGossipSingle,
};
#[cfg(feature = "pq-startup-testing")]
use beacon_chain::{PqAttestationGossipLocalError, PqAttestationGossipObservation};
use fixed_bytes::FixedBytesExtended;
use lighthouse_network::libp2p::gossipsub::{
    AdmittedMessageCommit, AdmittedMessageCommitOutcome, AdmittedMessageReport,
    AdmittedMessageValidationOutcome,
};
use lighthouse_network::rpc::{
    GoodbyeReason, RequestType, StatusMessage, methods::StatusMessageV2,
};
use lighthouse_network::service::Network;
use lighthouse_network::service::api_types::{AppRequestId, Response};
use lighthouse_network::types::GossipKind;
use lighthouse_network::{
    Context, MessageAcceptance, MessageId, NetworkEvent, NetworkGlobals, PeerAction, PeerId,
    PqBeaconBlockPublishError, PqBeaconBlockPublishOutcome, PqCompatiblePeerAdmission,
    PqEncodedBeaconBlock, PqGossipValidationAdmission, PubsubMessage, ReportSource,
    identity::Keypair,
};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use task_executor::TaskExecutor;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tracing::{debug, warn};
use types::{EthSpec, Hash256, SubnetId};

/// Maximum number of raw blocks retained by detached full-proof jobs.
pub const PQ_NETWORK_BLOCK_PROOF_CAPACITY: usize = 2;

/// Maximum number of exact blocks retained by detached SSZ encoding jobs.
pub const PQ_NETWORK_BLOCK_ENCODING_CAPACITY: usize = 2;

/// Maximum number of detached Engine/DB commits whose exact gossipsub reservations are retained.
pub const PQ_NETWORK_BLOCK_COMMIT_CAPACITY: usize = 2;

const PQ_NETWORK_ATTESTATION_SUBNET_COUNT: u64 = 8;

#[derive(Default)]
struct PqNetworkInFlight {
    count: AtomicUsize,
    drained: Notify,
}

impl PqNetworkInFlight {
    fn start(self: &Arc<Self>) -> PqNetworkInFlightGuard {
        self.count.fetch_add(1, Ordering::AcqRel);
        PqNetworkInFlightGuard {
            tracker: Arc::clone(self),
        }
    }

    async fn wait_until_drained(&self) {
        loop {
            let drained = self.drained.notified();
            if self.count.load(Ordering::Acquire) == 0 {
                return;
            }
            drained.await;
        }
    }
}

struct PqNetworkInFlightGuard {
    tracker: Arc<PqNetworkInFlight>,
}

impl Drop for PqNetworkInFlightGuard {
    fn drop(&mut self) {
        if self.tracker.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.tracker.drained.notify_waiters();
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
type PqBlockEncodingHook = Arc<dyn Fn() + Send + Sync>;
#[cfg(feature = "pq-startup-testing")]
type PqNetworkRunHook = Arc<dyn Fn() + Send + Sync>;

#[cfg(feature = "pq-startup-testing")]
const PQ_TESTING_ATTESTATION_PUBLISH_CAPACITY: usize = 2;

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqTestingAttestationPublishError {
    Capacity,
    WorkerUnavailable,
    Duplicate,
    NoPeersSubscribed,
    Rejected,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone)]
#[doc(hidden)]
pub struct PqTestingAttestationPublishSender<E: EthSpec> {
    sender: mpsc::Sender<PqTestingAttestationPublishCommand<E>>,
}

#[cfg(feature = "pq-startup-testing")]
impl<E: EthSpec> PqTestingAttestationPublishSender<E> {
    pub fn try_send(
        &self,
        attestation: types::SingleAttestation,
        subnet: SubnetId,
    ) -> Result<PqTestingAttestationPublishAcknowledgement, PqTestingAttestationPublishError> {
        let (acknowledgement, receiver) = tokio::sync::oneshot::channel();
        self.sender
            .try_send(PqTestingAttestationPublishCommand {
                attestation,
                subnet,
                acknowledgement: Some(acknowledgement),
                _phantom: std::marker::PhantomData,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => PqTestingAttestationPublishError::Capacity,
                mpsc::error::TrySendError::Closed(_) => {
                    PqTestingAttestationPublishError::WorkerUnavailable
                }
            })?;
        Ok(PqTestingAttestationPublishAcknowledgement { receiver })
    }
}

#[cfg(feature = "pq-startup-testing")]
struct PqTestingAttestationPublishCommand<E: EthSpec> {
    attestation: types::SingleAttestation,
    subnet: SubnetId,
    acknowledgement:
        Option<tokio::sync::oneshot::Sender<Result<(), PqTestingAttestationPublishError>>>,
    _phantom: std::marker::PhantomData<E>,
}

#[cfg(feature = "pq-startup-testing")]
impl<E: EthSpec> PqTestingAttestationPublishCommand<E> {
    fn acknowledge(mut self, result: Result<(), PqTestingAttestationPublishError>) {
        if let Some(sender) = self.acknowledgement.take() {
            let _ = sender.send(result);
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub struct PqTestingAttestationPublishAcknowledgement {
    receiver: tokio::sync::oneshot::Receiver<Result<(), PqTestingAttestationPublishError>>,
}

#[cfg(feature = "pq-startup-testing")]
impl PqTestingAttestationPublishAcknowledgement {
    pub async fn wait(self) -> Result<(), PqTestingAttestationPublishError> {
        self.receiver
            .await
            .unwrap_or(Err(PqTestingAttestationPublishError::WorkerUnavailable))
    }
}

#[cfg(feature = "pq-startup-testing")]
struct PqNetworkShutdownTestGuard(Option<tokio::sync::oneshot::Sender<()>>);

#[cfg(feature = "pq-startup-testing")]
impl Drop for PqNetworkShutdownTestGuard {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

/// Result-bearing ownership receipt for the sole PQ network worker.
pub struct PqNetworkServiceShutdown {
    shutdown_sender: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::sync::oneshot::Receiver<Result<(), tokio::task::JoinError>>,
}

impl PqNetworkServiceShutdown {
    pub async fn wait(mut self) -> Result<(), PqNetworkServiceError> {
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        }
        self.wait_for_completion().await
    }

    async fn wait_for_completion(self) -> Result<(), PqNetworkServiceError> {
        match self.task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) | Err(_) => Err(PqNetworkServiceError::TaskUnavailable),
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub async fn testing_only_wait_for_exit(mut self) -> Result<(), PqNetworkServiceError> {
        let shutdown_sender = self.shutdown_sender.take();
        let result = self.wait_for_completion().await;
        drop(shutdown_sender);
        result
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqNetworkServiceError {
    Construction(String),
    BeaconBlockSubscription,
    AttestationSubnetSubscription(SubnetId),
    TaskUnavailable,
}

impl std::fmt::Display for PqNetworkServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Construction(detail) => {
                write!(
                    formatter,
                    "could not construct the PQ libp2p service: {detail}"
                )
            }
            Self::BeaconBlockSubscription => {
                formatter.write_str("could not subscribe to the PQ beacon-block topic")
            }
            Self::AttestationSubnetSubscription(subnet) => {
                write!(
                    formatter,
                    "could not subscribe to PQ attestation subnet {subnet:?}"
                )
            }
            Self::TaskUnavailable => formatter.write_str("PQ network task executor is unavailable"),
        }
    }
}

impl std::error::Error for PqNetworkServiceError {}

struct PqBlockVerificationCompletion<T: BeaconChainTypes> {
    message_id: MessageId,
    source: PeerId,
    disposition: PqGossipBlockDisposition<T>,
    _permit: OwnedSemaphorePermit,
}

struct PqAttestationVerificationCompletion<T: BeaconChainTypes> {
    message_id: MessageId,
    source: PeerId,
    disposition: PqGossipAttestationDisposition<T::EthSpec>,
    _permit: OwnedSemaphorePermit,
}

struct PqBlockEncodingCompletion<E: EthSpec> {
    command: super::PqBlockBroadcastCommand<E>,
    encoded: PqEncodedBeaconBlock,
    _permit: OwnedSemaphorePermit,
}

struct PqBlockCommitCompletion {
    admission: AdmittedMessageCommit,
    result: Result<PqBlockImportOutcome, PqImportError>,
    identity: Option<(types::Slot, Hash256, [u8; 32])>,
}

struct PqAttestationConsumptionCompletion {
    admission: AdmittedMessageCommit,
    result: Result<PqForkChoiceAttestationOutcome, PqForkChoiceAttestationError>,
}

enum PqCompletionDisposition<Propagation, Commit, Error> {
    Accept(Propagation),
    Retry(Commit),
    Reject(Error),
    Pending,
    TerminalIgnore,
    Equivocation,
    RetryableIgnore(Error),
    TerminalIgnoreError(Error),
}

enum PqAdmissionReport<Reservation> {
    NotFound,
    Complete,
    Commit(Reservation),
}

trait PqCompletionLifecycle<Propagation, Commit, Error> {
    type Reservation;

    fn report(
        &mut self,
        outcome: AdmittedMessageValidationOutcome,
    ) -> PqAdmissionReport<Self::Reservation>;
    fn after_propagation(&mut self, propagation: Propagation) -> Result<Commit, Error>;
    fn commit(&mut self, reservation: Self::Reservation, commit: Commit);
    fn resolve_promotion_failed(&mut self, reservation: Self::Reservation, error: &Error);
    fn reject(&mut self, error: Error);
    fn promotion_failed(&mut self, error: Error);
    fn ignored_error(&mut self, error: Error);
}

fn handle_completion_lifecycle<Propagation, Commit, Error>(
    disposition: PqCompletionDisposition<Propagation, Commit, Error>,
    lifecycle: &mut impl PqCompletionLifecycle<Propagation, Commit, Error>,
) {
    match disposition {
        PqCompletionDisposition::Accept(propagation) => {
            if let PqAdmissionReport::Commit(reservation) =
                lifecycle.report(AdmittedMessageValidationOutcome::Accept)
            {
                match lifecycle.after_propagation(propagation) {
                    Ok(commit) => lifecycle.commit(reservation, commit),
                    Err(error) => {
                        lifecycle.resolve_promotion_failed(reservation, &error);
                        lifecycle.promotion_failed(error);
                    }
                }
            }
        }
        PqCompletionDisposition::Retry(commit) => {
            if let PqAdmissionReport::Commit(reservation) =
                lifecycle.report(AdmittedMessageValidationOutcome::CommitWithoutPropagation)
            {
                lifecycle.commit(reservation, commit);
            }
        }
        PqCompletionDisposition::Reject(error) => {
            let _ = lifecycle.report(AdmittedMessageValidationOutcome::Reject);
            lifecycle.reject(error);
        }
        PqCompletionDisposition::Pending => {
            let _ = lifecycle.report(AdmittedMessageValidationOutcome::Pending);
        }
        PqCompletionDisposition::TerminalIgnore => {
            let _ = lifecycle.report(AdmittedMessageValidationOutcome::TerminalIgnore);
        }
        PqCompletionDisposition::Equivocation => {
            let _ = lifecycle.report(AdmittedMessageValidationOutcome::Equivocation);
        }
        PqCompletionDisposition::RetryableIgnore(error) => {
            let _ = lifecycle.report(AdmittedMessageValidationOutcome::RetryableIgnore);
            lifecycle.ignored_error(error);
        }
        PqCompletionDisposition::TerminalIgnoreError(error) => {
            let _ = lifecycle.report(AdmittedMessageValidationOutcome::TerminalIgnore);
            lifecycle.ignored_error(error);
        }
    }
}

struct PqNetworkCompletionLifecycle<'a, T: BeaconChainTypes> {
    network: &'a mut Network<T::EthSpec>,
    processor: Arc<PqNetworkBlockProcessor<T>>,
    task_executor: TaskExecutor,
    commit_sender: mpsc::Sender<PqBlockCommitCompletion>,
    message_id: MessageId,
    source: PeerId,
    in_flight: Arc<PqNetworkInFlight>,
}

impl<T: BeaconChainTypes>
    PqCompletionLifecycle<PqGossipPropagationToken<T>, PqGossipCommitToken<T>, PqImportError>
    for PqNetworkCompletionLifecycle<'_, T>
{
    type Reservation = AdmittedMessageCommit;

    fn report(
        &mut self,
        outcome: AdmittedMessageValidationOutcome,
    ) -> PqAdmissionReport<Self::Reservation> {
        match self
            .network
            .report_pq_admitted_message_outcome(self.message_id.clone(), outcome)
        {
            AdmittedMessageReport::NotFound => PqAdmissionReport::NotFound,
            AdmittedMessageReport::Complete => PqAdmissionReport::Complete,
            AdmittedMessageReport::Commit(commit) => PqAdmissionReport::Commit(commit),
        }
    }

    fn after_propagation(
        &mut self,
        propagation: PqGossipPropagationToken<T>,
    ) -> Result<PqGossipCommitToken<T>, PqImportError> {
        propagation.after_propagation()
    }

    fn commit(&mut self, admission: Self::Reservation, commit: PqGossipCommitToken<T>) {
        let identity = commit.operational_identity().ok();
        let processor = Arc::clone(&self.processor);
        let commit_sender = self.commit_sender.clone();
        let _in_flight = self.in_flight.start();
        self.task_executor.spawn(
            async move {
                let _in_flight_guard = _in_flight;
                let result = processor.commit_gossip_block(commit).await;
                try_send_completion(
                    &commit_sender,
                    PqBlockCommitCompletion {
                        admission,
                        result,
                        identity,
                    },
                );
            },
            "pq_network_block_commit",
        );
    }

    fn resolve_promotion_failed(&mut self, admission: Self::Reservation, error: &PqImportError) {
        let outcome = if error.is_retryable() {
            AdmittedMessageCommitOutcome::Retryable
        } else {
            AdmittedMessageCommitOutcome::Terminal
        };
        let _ = self
            .network
            .resolve_pq_admitted_message_commit(admission, outcome);
    }

    fn reject(&mut self, error: PqImportError) {
        self.network.report_peer(
            &self.source,
            PeerAction::LowToleranceError,
            ReportSource::Gossipsub,
            "pq_gossip_block_invalid",
        );
        debug!(?error, "Rejected invalid PQ gossip block");
    }

    fn promotion_failed(&mut self, error: PqImportError) {
        debug!(?error, "PQ gossip propagation claim became stale");
    }

    fn ignored_error(&mut self, error: PqImportError) {
        debug!(?error, "Ignored PQ gossip block without peer penalty");
    }
}

struct PqNetworkAttestationCompletionLifecycle<'a, T: BeaconChainTypes> {
    network: &'a mut Network<T::EthSpec>,
    processor: Arc<PqNetworkBlockProcessor<T>>,
    task_executor: TaskExecutor,
    consumption_sender: mpsc::Sender<PqAttestationConsumptionCompletion>,
    message_id: MessageId,
    source: PeerId,
    in_flight: Arc<PqNetworkInFlight>,
}

impl<T: BeaconChainTypes>
    PqCompletionLifecycle<
        PqSingleGossipPropagationToken<T::EthSpec>,
        PqVerifiedGossipSingle<T::EthSpec>,
        beacon_chain::PqAttestationGossipError,
    > for PqNetworkAttestationCompletionLifecycle<'_, T>
{
    type Reservation = AdmittedMessageCommit;

    fn report(
        &mut self,
        outcome: AdmittedMessageValidationOutcome,
    ) -> PqAdmissionReport<Self::Reservation> {
        match self
            .network
            .report_pq_admitted_message_outcome(self.message_id.clone(), outcome)
        {
            AdmittedMessageReport::NotFound => PqAdmissionReport::NotFound,
            AdmittedMessageReport::Complete => PqAdmissionReport::Complete,
            AdmittedMessageReport::Commit(commit) => PqAdmissionReport::Commit(commit),
        }
    }

    fn after_propagation(
        &mut self,
        propagation: PqSingleGossipPropagationToken<T::EthSpec>,
    ) -> Result<PqVerifiedGossipSingle<T::EthSpec>, beacon_chain::PqAttestationGossipError> {
        propagation.mark_propagated()
    }

    fn commit(
        &mut self,
        admission: Self::Reservation,
        verified: PqVerifiedGossipSingle<T::EthSpec>,
    ) {
        let chain = Arc::clone(&self.processor.chain);
        let completion_sender = self.consumption_sender.clone();
        let admission = Arc::new(Mutex::new(Some(admission)));
        let task_admission = Arc::clone(&admission);
        if !spawn_owned_attestation_task(
            &self.task_executor,
            &self.in_flight,
            async move {
                let Some(admission) = task_admission.lock().take() else {
                    return;
                };
                let result = chain.consume_pq_verified_gossip_single(verified).await;
                try_send_completion(
                    &completion_sender,
                    PqAttestationConsumptionCompletion { admission, result },
                );
            },
            "pq_network_attestation_consumption",
        ) {
            if let Some(admission) = admission.lock().take() {
                let _ = self.network.resolve_pq_admitted_message_commit(
                    admission,
                    AdmittedMessageCommitOutcome::Terminal,
                );
            }
            self.processor.fail_gossip_attestation_consumption();
        }
    }

    fn resolve_promotion_failed(
        &mut self,
        admission: Self::Reservation,
        _error: &beacon_chain::PqAttestationGossipError,
    ) {
        let _ = self
            .network
            .resolve_pq_admitted_message_commit(admission, AdmittedMessageCommitOutcome::Terminal);
    }

    fn reject(&mut self, error: beacon_chain::PqAttestationGossipError) {
        self.network.report_peer(
            &self.source,
            PeerAction::LowToleranceError,
            ReportSource::Gossipsub,
            "pq_gossip_attestation_invalid",
        );
        debug!(?error, "Rejected invalid PQ gossip attestation");
    }

    fn promotion_failed(&mut self, error: beacon_chain::PqAttestationGossipError) {
        debug!(?error, "PQ attestation propagation promotion failed");
        self.processor.fail_gossip_attestation_consumption();
    }

    fn ignored_error(&mut self, error: beacon_chain::PqAttestationGossipError) {
        debug!(?error, "Ignored PQ gossip attestation without peer penalty");
    }
}

fn completion_disposition<T: BeaconChainTypes>(
    disposition: PqGossipBlockDisposition<T>,
) -> PqCompletionDisposition<PqGossipPropagationToken<T>, PqGossipCommitToken<T>, PqImportError> {
    match disposition {
        PqGossipBlockDisposition::Accept(propagation) => {
            PqCompletionDisposition::Accept(propagation)
        }
        PqGossipBlockDisposition::Retry(commit) => PqCompletionDisposition::Retry(commit),
        PqGossipBlockDisposition::Reject(error) => PqCompletionDisposition::Reject(error),
        PqGossipBlockDisposition::Ignore(error) if error.is_retryable() => {
            PqCompletionDisposition::RetryableIgnore(error)
        }
        PqGossipBlockDisposition::Ignore(error) => {
            PqCompletionDisposition::TerminalIgnoreError(error)
        }
        PqGossipBlockDisposition::IgnorePending => PqCompletionDisposition::Pending,
        PqGossipBlockDisposition::IgnoreTerminal => PqCompletionDisposition::TerminalIgnore,
        PqGossipBlockDisposition::IgnoreEquivocation => PqCompletionDisposition::Equivocation,
    }
}

fn commit_resolution(
    result: &Result<PqBlockImportOutcome, PqImportError>,
) -> AdmittedMessageCommitOutcome {
    commit_error_resolution(result.as_ref().err())
}

fn attestation_consumption_commit_outcome() -> AdmittedMessageCommitOutcome {
    AdmittedMessageCommitOutcome::Terminal
}

fn attestation_consumption_requires_shutdown(result_failed: bool, resolved: bool) -> bool {
    result_failed || !resolved
}

fn commit_error_resolution(error: Option<&PqImportError>) -> AdmittedMessageCommitOutcome {
    match error {
        Some(PqImportError::Local(
            PqImportLocalError::ExecutionUnavailable(_)
            | PqImportLocalError::Transport(_)
            | PqImportLocalError::BlockingTask(_)
            | PqImportLocalError::Persistence(_),
        )) => AdmittedMessageCommitOutcome::Retryable,
        None
        | Some(
            PqImportError::PeerInvalid(_)
            | PqImportError::ExecutionRejected(_)
            | PqImportError::ExecutionReconciliation(_)
            | PqImportError::ForkChoice(_)
            | PqImportError::OperationalEvent(_)
            | PqImportError::DurableStateUnknown { .. }
            | PqImportError::TerminalObservation { .. }
            | PqImportError::StaleHeadAfterVerification { .. }
            | PqImportError::Local(_),
        ) => AdmittedMessageCommitOutcome::Terminal,
    }
}

fn gossip_imported_event(
    identity: Option<(types::Slot, Hash256, [u8; 32])>,
    commit_succeeded: bool,
    resolution_succeeded: bool,
) -> Option<PqOperationalEvent> {
    let (slot, block_root, signed_ssz_digest) =
        identity.filter(|_| commit_succeeded && resolution_succeeded)?;
    Some(PqOperationalEvent::GossipImported {
        slot,
        block_root,
        signed_ssz_digest,
    })
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqGossipImportedEventGateTestTrace {
    pub committed_and_resolved: Option<PqOperationalEvent>,
    pub committed_but_unresolved: Option<PqOperationalEvent>,
    pub resolved_but_failed: Option<PqOperationalEvent>,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_gossip_imported_event_gate() -> PqGossipImportedEventGateTestTrace {
    let identity = Some((types::Slot::new(3), Hash256::repeat_byte(4), [5; 32]));
    PqGossipImportedEventGateTestTrace {
        committed_and_resolved: gossip_imported_event(identity, true, true),
        committed_but_unresolved: gossip_imported_event(identity, true, false),
        resolved_but_failed: gossip_imported_event(identity, false, true),
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqCommitResolutionTestCase {
    Success,
    BlockingTask,
    ParentUnavailable,
    ReconciliationFailure,
    TerminalObservation,
    DurableStateUnknown,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_commit_resolution(case: PqCommitResolutionTestCase) -> bool {
    let error = match case {
        PqCommitResolutionTestCase::Success => None,
        PqCommitResolutionTestCase::BlockingTask => Some(PqImportError::Local(
            PqImportLocalError::BlockingTask("test"),
        )),
        PqCommitResolutionTestCase::ParentUnavailable => Some(PqImportError::Local(
            PqImportLocalError::ParentUnavailable {
                parent_root: Hash256::ZERO,
            },
        )),
        PqCommitResolutionTestCase::ReconciliationFailure => {
            Some(PqImportError::ExecutionReconciliation(
                beacon_chain::PqExecutionReconciliationError::Unavailable { attempts: 3 },
            ))
        }
        PqCommitResolutionTestCase::TerminalObservation => {
            Some(PqImportError::TerminalObservation {
                block_root: Hash256::ZERO,
            })
        }
        PqCommitResolutionTestCase::DurableStateUnknown => {
            Some(PqImportError::DurableStateUnknown {
                phase: "testing-post-persist",
            })
        }
    };
    matches!(
        commit_error_resolution(error.as_ref()),
        AdmittedMessageCommitOutcome::Retryable
    )
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqCommitCompletionQueueTestTrace {
    pub admitted: Vec<bool>,
    pub dropped_after_overflow: usize,
    pub dropped_after_shutdown: usize,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_commit_completion_queue() -> PqCommitCompletionQueueTestTrace {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct DropCapability(Arc<AtomicUsize>);
    impl Drop for DropCapability {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = mpsc::channel(PQ_NETWORK_BLOCK_COMMIT_CAPACITY);
    let admitted = (0..=PQ_NETWORK_BLOCK_COMMIT_CAPACITY)
        .map(|_| sender.try_send(DropCapability(Arc::clone(&drops))).is_ok())
        .collect();
    let dropped_after_overflow = drops.load(Ordering::SeqCst);
    drop(receiver);
    PqCommitCompletionQueueTestTrace {
        admitted,
        dropped_after_overflow,
        dropped_after_shutdown: drops.load(Ordering::SeqCst),
    }
}

fn try_admit_proof(admission: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    Arc::clone(admission).try_acquire_owned().ok()
}

fn try_send_completion<Completion>(sender: &mpsc::Sender<Completion>, completion: Completion) {
    let _ = sender.try_send(completion);
}

fn spawn_owned_attestation_task<R: Send + 'static>(
    task_executor: &TaskExecutor,
    in_flight: &Arc<PqNetworkInFlight>,
    task: impl Future<Output = R> + Send + 'static,
    name: &'static str,
) -> bool {
    let in_flight = in_flight.start();
    let Some(receipt) = task_executor.spawn_handle_without_exit(
        async move {
            let _in_flight = in_flight;
            task.await
        },
        name,
    ) else {
        return false;
    };
    drop(receipt);
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqNetworkAttestationRoute {
    VerifySingle(SubnetId),
    RetryableIgnore,
    Ignore,
}

fn pq_attestation_route(
    pq_admitted: bool,
    single_subnet: Option<SubnetId>,
) -> PqNetworkAttestationRoute {
    match (pq_admitted, single_subnet) {
        (true, Some(subnet)) => PqNetworkAttestationRoute::VerifySingle(subnet),
        (true, None) => PqNetworkAttestationRoute::RetryableIgnore,
        (false, _) => PqNetworkAttestationRoute::Ignore,
    }
}

fn pq_attestation_ignore_outcome(
    error: &PqAttestationGossipError,
) -> AdmittedMessageValidationOutcome {
    if error.is_retryable() {
        AdmittedMessageValidationOutcome::RetryableIgnore
    } else {
        AdmittedMessageValidationOutcome::TerminalIgnore
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqNetworkAttestationRouteTestCase {
    AdmittedSingle { subnet: SubnetId },
    OrdinarySingle { subnet: SubnetId },
    AdmittedAggregate,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqNetworkAttestationRouteTestTrace {
    VerifySingle { subnet: SubnetId },
    RetryableIgnore,
    Ignore,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_attestation_route(
    case: PqNetworkAttestationRouteTestCase,
) -> PqNetworkAttestationRouteTestTrace {
    let route = match case {
        PqNetworkAttestationRouteTestCase::AdmittedSingle { subnet } => {
            pq_attestation_route(true, Some(subnet))
        }
        PqNetworkAttestationRouteTestCase::OrdinarySingle { subnet } => {
            pq_attestation_route(false, Some(subnet))
        }
        PqNetworkAttestationRouteTestCase::AdmittedAggregate => pq_attestation_route(true, None),
    };
    match route {
        PqNetworkAttestationRoute::VerifySingle(subnet) => {
            PqNetworkAttestationRouteTestTrace::VerifySingle { subnet }
        }
        PqNetworkAttestationRoute::RetryableIgnore => {
            PqNetworkAttestationRouteTestTrace::RetryableIgnore
        }
        PqNetworkAttestationRoute::Ignore => PqNetworkAttestationRouteTestTrace::Ignore,
    }
}

fn pq_peer_digest(peer_id: &PeerId) -> [u8; 16] {
    let digest = Sha256::digest(peer_id.to_bytes());
    let mut peer_digest = [0; 16];
    peer_digest.copy_from_slice(&digest[..16]);
    peer_digest
}

trait PqStatusLifecycle {
    fn mark_compatible(&mut self) -> PqCompatiblePeerAdmission;
    fn emit_peer_compatible(&mut self) -> bool;
    fn emit_status_rejected(&mut self, code: PqStatusRejectionCode) -> bool;
    fn operational_event_failed(&mut self);
    fn disconnect_irrelevant_network(&mut self);
    fn disconnect_too_many_peers(&mut self);
}

fn handle_status_lifecycle(
    expected: &StatusMessageV2,
    received: &StatusMessageV2,
    lifecycle: &mut impl PqStatusLifecycle,
) {
    let rejection = if received.fork_digest != expected.fork_digest {
        Some(PqStatusRejectionCode::ForkDigest)
    } else if received.finalized_epoch != expected.finalized_epoch {
        Some(PqStatusRejectionCode::FinalizedEpoch)
    } else if received.finalized_root != expected.finalized_root {
        Some(PqStatusRejectionCode::FinalizedRoot)
    } else {
        None
    };
    if let Some(code) = rejection {
        if !lifecycle.emit_status_rejected(code) {
            lifecycle.operational_event_failed();
        }
        lifecycle.disconnect_irrelevant_network();
    } else {
        match lifecycle.mark_compatible() {
            PqCompatiblePeerAdmission::Added => {
                if !lifecycle.emit_peer_compatible() {
                    lifecycle.operational_event_failed();
                }
            }
            PqCompatiblePeerAdmission::Existing => {}
            PqCompatiblePeerAdmission::Capacity => {
                if !lifecycle.emit_status_rejected(PqStatusRejectionCode::Capacity) {
                    lifecycle.operational_event_failed();
                }
                lifecycle.disconnect_too_many_peers();
            }
        }
    }
}

struct PqNetworkStatusLifecycle<'a, E: EthSpec> {
    network: &'a mut Network<E>,
    peer_id: PeerId,
    gossip_admission: &'a PqGossipValidationAdmission,
    operational_events: &'a PqOperationalEventSink,
    task_executor: &'a TaskExecutor,
}

impl<E: EthSpec> PqStatusLifecycle for PqNetworkStatusLifecycle<'_, E> {
    fn mark_compatible(&mut self) -> PqCompatiblePeerAdmission {
        self.gossip_admission.admit_compatible(self.peer_id)
    }

    fn emit_peer_compatible(&mut self) -> bool {
        let peer_digest = pq_peer_digest(&self.peer_id);
        self.operational_events
            .try_emit(PqOperationalEvent::PeerCompatible { peer_digest })
            .is_ok()
    }

    fn emit_status_rejected(&mut self, code: PqStatusRejectionCode) -> bool {
        self.operational_events
            .try_emit(PqOperationalEvent::StatusRejected {
                peer_digest: pq_peer_digest(&self.peer_id),
                code,
            })
            .is_ok()
    }

    fn operational_event_failed(&mut self) {
        self.gossip_admission.remove_compatible(&self.peer_id);
        warn!(peer_id = %self.peer_id, "PQ operational event sink unavailable");
        let _ =
            self.task_executor
                .shutdown_sender()
                .try_send(task_executor::ShutdownReason::Failure(
                    "PQ operational event sink unavailable",
                ));
    }

    fn disconnect_irrelevant_network(&mut self) {
        self.gossip_admission.remove_compatible(&self.peer_id);
        warn!(peer_id = %self.peer_id, "Disconnecting PQ peer with an incompatible status");
        self.network.goodbye_peer(
            &self.peer_id,
            GoodbyeReason::IrrelevantNetwork,
            ReportSource::RPC,
        );
    }

    fn disconnect_too_many_peers(&mut self) {
        warn!(peer_id = %self.peer_id, "Disconnecting PQ peer beyond the compatible-peer cap");
        self.network.goodbye_peer(
            &self.peer_id,
            GoodbyeReason::TooManyPeers,
            ReportSource::RPC,
        );
    }
}

enum PqNetworkServiceEvent<T: BeaconChainTypes> {
    Broadcast(Option<super::PqBlockBroadcastCommand<T::EthSpec>>),
    Encoding(Option<PqBlockEncodingCompletion<T::EthSpec>>),
    Verification(Option<Box<PqBlockVerificationCompletion<T>>>),
    AttestationVerification(Option<Box<PqAttestationVerificationCompletion<T>>>),
    AttestationConsumption(Option<Box<PqAttestationConsumptionCompletion>>),
    Commit(Option<Box<PqBlockCommitCompletion>>),
    Network(Box<NetworkEvent<T::EthSpec>>),
    TestingDial(Option<lighthouse_network::Multiaddr>),
    #[cfg(feature = "pq-startup-testing")]
    TestingAttestationPublish(Option<PqTestingAttestationPublishCommand<T::EthSpec>>),
}

#[cfg(feature = "pq-startup-testing")]
async fn next_testing_attestation_publish_event<T: BeaconChainTypes>(
    receiver: &mut mpsc::Receiver<PqTestingAttestationPublishCommand<T::EthSpec>>,
) -> PqNetworkServiceEvent<T> {
    PqNetworkServiceEvent::TestingAttestationPublish(receiver.recv().await)
}

#[cfg(not(feature = "pq-startup-testing"))]
async fn next_testing_attestation_publish_event<T: BeaconChainTypes>() -> PqNetworkServiceEvent<T> {
    std::future::pending().await
}

/// Minimal PQ network owner. It deliberately has no router, sync manager, or unbounded message
/// channel.
pub struct PqNetworkService<T: BeaconChainTypes> {
    network: Network<T::EthSpec>,
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    chain: Arc<BeaconChain<T>>,
    processor: Arc<PqNetworkBlockProcessor<T>>,
    broadcast_receiver: PqBlockBroadcastReceiver<T::EthSpec>,
    proof_admission: Arc<Semaphore>,
    encoding_admission: Arc<Semaphore>,
    gossip_admission: Arc<PqGossipValidationAdmission>,
    operational_events: std::sync::Weak<PqOperationalEventSink>,
    encoding_sender: mpsc::Sender<PqBlockEncodingCompletion<T::EthSpec>>,
    encoding_receiver: mpsc::Receiver<PqBlockEncodingCompletion<T::EthSpec>>,
    completion_sender: mpsc::Sender<PqBlockVerificationCompletion<T>>,
    completion_receiver: mpsc::Receiver<PqBlockVerificationCompletion<T>>,
    attestation_completion_sender: mpsc::Sender<PqAttestationVerificationCompletion<T>>,
    attestation_completion_receiver: mpsc::Receiver<PqAttestationVerificationCompletion<T>>,
    attestation_consumption_sender: mpsc::Sender<PqAttestationConsumptionCompletion>,
    attestation_consumption_receiver: mpsc::Receiver<PqAttestationConsumptionCompletion>,
    commit_sender: mpsc::Sender<PqBlockCommitCompletion>,
    commit_receiver: mpsc::Receiver<PqBlockCommitCompletion>,
    task_executor: TaskExecutor,
    fork_digest: [u8; 4],
    _testing_dial_sender: mpsc::Sender<lighthouse_network::Multiaddr>,
    testing_dial_receiver: mpsc::Receiver<lighthouse_network::Multiaddr>,
    #[cfg(feature = "pq-startup-testing")]
    testing_attestation_publish_sender:
        mpsc::Sender<PqTestingAttestationPublishCommand<T::EthSpec>>,
    #[cfg(feature = "pq-startup-testing")]
    testing_attestation_publish_receiver:
        mpsc::Receiver<PqTestingAttestationPublishCommand<T::EthSpec>>,
    #[cfg(feature = "pq-startup-testing")]
    testing_block_encoding_hook: Option<PqBlockEncodingHook>,
    #[cfg(feature = "pq-startup-testing")]
    testing_run_hook: Option<PqNetworkRunHook>,
    #[cfg(feature = "pq-startup-testing")]
    testing_shutdown_sender: Option<tokio::sync::oneshot::Sender<()>>,
    live_sender: Option<tokio::sync::oneshot::Sender<()>>,
    shutdown_receiver: Option<tokio::sync::oneshot::Receiver<()>>,
    in_flight: Arc<PqNetworkInFlight>,
}

impl<T: BeaconChainTypes> PqNetworkService<T> {
    pub async fn new(
        task_executor: TaskExecutor,
        context: Context<'_>,
        custody_group_count: u64,
        local_keypair: Keypair,
        chain: Arc<BeaconChain<T>>,
        broadcast_receiver: PqBlockBroadcastReceiver<T::EthSpec>,
        operational_events: Arc<PqOperationalEventSink>,
    ) -> Result<Self, PqNetworkServiceError> {
        let fork_digest = context.enr_fork_id.fork_digest;
        let gossip_admission = Arc::new(PqGossipValidationAdmission::new());
        let (mut network, network_globals) = Network::new_pq(
            task_executor.clone(),
            context,
            custody_group_count,
            local_keypair,
            Arc::clone(&gossip_admission),
        )
        .await
        .map_err(PqNetworkServiceError::Construction)?;
        if !network.subscribe_kind(GossipKind::BeaconBlock) {
            return Err(PqNetworkServiceError::BeaconBlockSubscription);
        }
        for subnet in 0..PQ_NETWORK_ATTESTATION_SUBNET_COUNT {
            let subnet = SubnetId::new(subnet);
            if !network.subscribe_kind(GossipKind::Attestation(subnet)) {
                return Err(PqNetworkServiceError::AttestationSubnetSubscription(subnet));
            }
        }
        let (completion_sender, completion_receiver) =
            mpsc::channel(PQ_NETWORK_BLOCK_PROOF_CAPACITY);
        let (attestation_completion_sender, attestation_completion_receiver) =
            mpsc::channel(PQ_NETWORK_BLOCK_PROOF_CAPACITY);
        let (attestation_consumption_sender, attestation_consumption_receiver) =
            mpsc::channel(PQ_NETWORK_BLOCK_PROOF_CAPACITY);
        let (encoding_sender, encoding_receiver) =
            mpsc::channel(PQ_NETWORK_BLOCK_ENCODING_CAPACITY);
        let (commit_sender, commit_receiver) = mpsc::channel(PQ_NETWORK_BLOCK_COMMIT_CAPACITY);
        let (testing_dial_sender, testing_dial_receiver) = mpsc::channel(1);
        #[cfg(feature = "pq-startup-testing")]
        let (testing_attestation_publish_sender, testing_attestation_publish_receiver) =
            mpsc::channel(PQ_TESTING_ATTESTATION_PUBLISH_CAPACITY);
        Ok(Self {
            network,
            network_globals,
            processor: Arc::new(PqNetworkBlockProcessor::new(Arc::clone(&chain))),
            chain,
            broadcast_receiver,
            proof_admission: Arc::new(Semaphore::new(PQ_NETWORK_BLOCK_PROOF_CAPACITY)),
            encoding_admission: Arc::new(Semaphore::new(PQ_NETWORK_BLOCK_ENCODING_CAPACITY)),
            gossip_admission,
            operational_events: Arc::downgrade(&operational_events),
            encoding_sender,
            encoding_receiver,
            completion_sender,
            completion_receiver,
            attestation_completion_sender,
            attestation_completion_receiver,
            attestation_consumption_sender,
            attestation_consumption_receiver,
            commit_sender,
            commit_receiver,
            task_executor,
            fork_digest,
            _testing_dial_sender: testing_dial_sender,
            testing_dial_receiver,
            #[cfg(feature = "pq-startup-testing")]
            testing_attestation_publish_sender,
            #[cfg(feature = "pq-startup-testing")]
            testing_attestation_publish_receiver,
            #[cfg(feature = "pq-startup-testing")]
            testing_block_encoding_hook: None,
            #[cfg(feature = "pq-startup-testing")]
            testing_run_hook: None,
            #[cfg(feature = "pq-startup-testing")]
            testing_shutdown_sender: None,
            live_sender: None,
            shutdown_receiver: None,
            in_flight: Arc::new(PqNetworkInFlight::default()),
        })
    }

    pub fn network_globals(&self) -> Arc<NetworkGlobals<T::EthSpec>> {
        Arc::clone(&self.network_globals)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_dial_sender(&self) -> mpsc::Sender<lighthouse_network::Multiaddr> {
        self._testing_dial_sender.clone()
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_gossip_admission(&self) -> Arc<PqGossipValidationAdmission> {
        Arc::clone(&self.gossip_admission)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_attestation_publish_sender(
        &self,
    ) -> PqTestingAttestationPublishSender<T::EthSpec> {
        PqTestingAttestationPublishSender {
            sender: self.testing_attestation_publish_sender.clone(),
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_block_encoding_hook(&mut self, hook: Arc<dyn Fn() + Send + Sync>) {
        self.testing_block_encoding_hook = Some(hook);
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_run_hook(&mut self, hook: Arc<dyn Fn() + Send + Sync>) {
        self.testing_run_hook = Some(hook);
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_shutdown_receipt(&mut self) -> Option<tokio::sync::oneshot::Receiver<()>> {
        if self.testing_shutdown_sender.is_some() {
            return None;
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.testing_shutdown_sender = Some(sender);
        Some(receiver)
    }

    pub fn start(self) -> Result<(), PqNetworkServiceError> {
        self.spawn()
    }

    /// Start the sole PQ network worker and return a receipt that resolves only after it exits.
    pub async fn start_with_shutdown_receipt(
        mut self,
    ) -> Result<PqNetworkServiceShutdown, PqNetworkServiceError> {
        let (live_sender, live_receiver) = tokio::sync::oneshot::channel();
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        self.live_sender = Some(live_sender);
        self.shutdown_receiver = Some(shutdown_receiver);
        let executor = self.task_executor.clone();
        let mut task = executor
            .spawn_handle_without_exit(self.run(), "pq_network_service")
            .ok_or(PqNetworkServiceError::TaskUnavailable)?;
        tokio::select! {
            biased;
            _ = &mut task => Err(PqNetworkServiceError::TaskUnavailable),
            live = live_receiver => {
                live.map_err(|_| PqNetworkServiceError::TaskUnavailable)?;
                Ok(PqNetworkServiceShutdown {
                    shutdown_sender: Some(shutdown_sender),
                    task,
                })
            }
        }
    }

    fn spawn(self) -> Result<(), PqNetworkServiceError> {
        let executor = self.task_executor.clone();
        let _task = executor
            .spawn_handle_without_exit(self.run(), "pq_network_service")
            .ok_or(PqNetworkServiceError::TaskUnavailable)?;
        Ok(())
    }

    async fn run(mut self) {
        let mut executor_exit = Box::pin(self.task_executor.exit());
        tokio::select! {
            biased;
            _ = &mut executor_exit => {
                self.shutdown_and_drain().await;
                return;
            }
            _ = tokio::task::yield_now() => {}
        }
        #[cfg(feature = "pq-startup-testing")]
        if let Some(hook) = self.testing_run_hook.take() {
            hook();
        }
        if let Some(sender) = self.live_sender.take() {
            let _ = sender.send(());
        }
        #[cfg(feature = "pq-startup-testing")]
        let _testing_shutdown_guard =
            PqNetworkShutdownTestGuard(self.testing_shutdown_sender.take());
        let mut shutdown_receiver = self.shutdown_receiver.take();
        loop {
            #[cfg(feature = "pq-startup-testing")]
            let testing_attestation_publish_event = next_testing_attestation_publish_event::<T>(
                &mut self.testing_attestation_publish_receiver,
            );
            #[cfg(not(feature = "pq-startup-testing"))]
            let testing_attestation_publish_event = next_testing_attestation_publish_event::<T>();
            let event = tokio::select! {
                biased;
                _ = &mut executor_exit => break,
                _ = async {
                    match shutdown_receiver.as_mut() {
                        Some(receiver) => {
                            let _ = receiver.await;
                        }
                        None => std::future::pending::<()>().await,
                    }
                } => break,
                command = self.broadcast_receiver.recv() => {
                    PqNetworkServiceEvent::Broadcast(command)
                }
                completion = self.encoding_receiver.recv() => {
                    PqNetworkServiceEvent::Encoding(completion)
                }
                completion = self.completion_receiver.recv() => {
                    PqNetworkServiceEvent::Verification(completion.map(Box::new))
                }
                completion = self.attestation_completion_receiver.recv() => {
                    PqNetworkServiceEvent::AttestationVerification(completion.map(Box::new))
                }
                completion = self.attestation_consumption_receiver.recv() => {
                    PqNetworkServiceEvent::AttestationConsumption(completion.map(Box::new))
                }
                completion = self.commit_receiver.recv() => {
                    PqNetworkServiceEvent::Commit(completion.map(Box::new))
                }
                event = self.network.next_event() => PqNetworkServiceEvent::Network(Box::new(event)),
                address = self.testing_dial_receiver.recv() => {
                    PqNetworkServiceEvent::TestingDial(address)
                }
                event = testing_attestation_publish_event => event,
            };
            match event {
                PqNetworkServiceEvent::Broadcast(Some(command)) => {
                    self.start_block_encoding(command);
                }
                PqNetworkServiceEvent::Encoding(Some(completion)) => {
                    let PqBlockEncodingCompletion {
                        command,
                        encoded,
                        _permit,
                    } = completion;
                    let result = if self.gossip_admission.has_compatible_peers() {
                        match self.network.publish_pq_encoded_beacon_block(encoded) {
                            Ok(
                                PqBeaconBlockPublishOutcome::Published
                                | PqBeaconBlockPublishOutcome::Duplicate,
                            ) => Ok(()),
                            Err(
                                PqBeaconBlockPublishError::NoPeersSubscribed
                                | PqBeaconBlockPublishError::Rejected,
                            ) => Err(PqBlockBroadcastError::Rejected),
                        }
                    } else {
                        Err(PqBlockBroadcastError::Rejected)
                    };
                    command.acknowledge(result);
                    drop(_permit);
                }
                PqNetworkServiceEvent::Encoding(None) => break,
                PqNetworkServiceEvent::Broadcast(None) => break,
                PqNetworkServiceEvent::Verification(Some(completion)) => {
                    self.handle_verification_completion(*completion);
                }
                PqNetworkServiceEvent::Verification(None) => break,
                PqNetworkServiceEvent::AttestationVerification(Some(completion)) => {
                    self.handle_attestation_verification_completion(*completion);
                }
                PqNetworkServiceEvent::AttestationVerification(None) => break,
                PqNetworkServiceEvent::AttestationConsumption(Some(completion)) => {
                    self.handle_attestation_consumption_completion(*completion);
                }
                PqNetworkServiceEvent::AttestationConsumption(None) => break,
                PqNetworkServiceEvent::Commit(Some(completion)) => {
                    self.handle_commit_completion(*completion);
                }
                PqNetworkServiceEvent::Commit(None) => break,
                PqNetworkServiceEvent::Network(event) => self.handle_network_event(*event),
                PqNetworkServiceEvent::TestingDial(Some(address)) => {
                    let _ = self.network.testing_dial(address);
                }
                PqNetworkServiceEvent::TestingDial(None) => break,
                #[cfg(feature = "pq-startup-testing")]
                PqNetworkServiceEvent::TestingAttestationPublish(Some(command)) => {
                    self.handle_testing_attestation_publish(command);
                }
                #[cfg(feature = "pq-startup-testing")]
                PqNetworkServiceEvent::TestingAttestationPublish(None) => break,
            }
        }
        self.shutdown_and_drain().await;
    }

    async fn shutdown_and_drain(&mut self) {
        self.broadcast_receiver.close_and_reject_pending();
        #[cfg(feature = "pq-startup-testing")]
        {
            self.testing_attestation_publish_receiver.close();
            while let Ok(command) = self.testing_attestation_publish_receiver.try_recv() {
                command.acknowledge(Err(PqTestingAttestationPublishError::WorkerUnavailable));
            }
        }
        self.in_flight.wait_until_drained().await;
    }

    fn start_block_encoding(&mut self, command: super::PqBlockBroadcastCommand<T::EthSpec>) {
        if !self.gossip_admission.has_compatible_peers() {
            command.acknowledge(Err(PqBlockBroadcastError::Rejected));
            return;
        }
        let Some(permit) = try_admit_proof(&self.encoding_admission) else {
            command.acknowledge(Err(PqBlockBroadcastError::Capacity));
            return;
        };
        if self.task_executor.handle().is_none() {
            command.acknowledge(Err(PqBlockBroadcastError::WorkerUnavailable));
            return;
        }
        let block = Arc::clone(command.block());
        let fork_digest = self.fork_digest;
        let sender = self.encoding_sender.clone();
        let _in_flight = self.in_flight.start();
        #[cfg(feature = "pq-startup-testing")]
        let hook = self.testing_block_encoding_hook.clone();
        self.task_executor.spawn_blocking(
            move || {
                let _in_flight_guard = _in_flight;
                #[cfg(feature = "pq-startup-testing")]
                if let Some(hook) = hook {
                    hook();
                }
                let encoded = PqEncodedBeaconBlock::encode(block, fork_digest);
                try_send_completion(
                    &sender,
                    PqBlockEncodingCompletion {
                        command,
                        encoded,
                        _permit: permit,
                    },
                );
            },
            "pq_network_block_encoding",
        );
    }

    fn handle_network_event(&mut self, event: NetworkEvent<T::EthSpec>) {
        match event {
            NetworkEvent::PubsubMessage {
                id,
                source,
                message: PubsubMessage::BeaconBlock(block),
                pq_admitted: true,
                ..
            } => self.start_block_verification(id, source, block),
            NetworkEvent::PubsubMessage {
                id,
                source,
                message,
                pq_admitted,
                ..
            } => match pq_attestation_route(
                pq_admitted,
                match &message {
                    PubsubMessage::Attestation(single) => Some(single.0),
                    _ => None,
                },
            ) {
                PqNetworkAttestationRoute::VerifySingle(subnet) => {
                    if let PubsubMessage::Attestation(single) = message {
                        self.start_attestation_verification(id, source, single.1, subnet);
                    }
                }
                PqNetworkAttestationRoute::RetryableIgnore => {
                    let _ = self.network.report_pq_admitted_message_outcome(
                        id,
                        AdmittedMessageValidationOutcome::RetryableIgnore,
                    );
                }
                PqNetworkAttestationRoute::Ignore => {
                    let _ = self.network.report_message_validation_result(
                        &source,
                        id,
                        MessageAcceptance::Ignore,
                    );
                }
            },
            NetworkEvent::StatusPeer(peer_id) => {
                self.send_status_request(peer_id);
            }
            NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                if self.emit_operational_event(PqOperationalEvent::PeerConnected {
                    peer_digest: pq_peer_digest(&peer_id),
                    direction: PqPeerConnectionDirection::Outgoing,
                }) {
                    self.send_status_request(peer_id);
                }
            }
            NetworkEvent::PeerConnectedIncoming(peer_id) => {
                if self.emit_operational_event(PqOperationalEvent::PeerConnected {
                    peer_digest: pq_peer_digest(&peer_id),
                    direction: PqPeerConnectionDirection::Incoming,
                }) {
                    self.send_status_request(peer_id);
                }
            }
            NetworkEvent::RequestReceived {
                peer_id,
                inbound_request_id,
                request_type: RequestType::Status(status),
            } => {
                let local_status = self.status_message();
                self.network.send_response(
                    peer_id,
                    inbound_request_id,
                    Response::Status(local_status),
                );
                if !self.emit_operational_event(PqOperationalEvent::StatusSent {
                    peer_digest: pq_peer_digest(&peer_id),
                    direction: PqStatusMessageDirection::Response,
                }) {
                    return;
                }
                self.validate_status(peer_id, &status);
            }
            NetworkEvent::RequestReceived {
                peer_id,
                inbound_request_id,
                ..
            } => self
                .network
                .send_pq_unsupported_response(peer_id, inbound_request_id),
            NetworkEvent::ResponseReceived {
                peer_id,
                app_request_id: AppRequestId::Router,
                response: Response::Status(status),
            } => self.validate_status(peer_id, &status),
            NetworkEvent::ResponseReceived { .. }
            | NetworkEvent::RPCFailed { .. }
            | NetworkEvent::NewListenAddr(_)
            | NetworkEvent::ZeroListeners
            | NetworkEvent::PeerUpdatedCustodyGroupCount(_)
            | NetworkEvent::PartialDataColumnSidecar { .. } => {}
            NetworkEvent::PeerDisconnected(peer_id) => {
                self.gossip_admission.remove_compatible(&peer_id);
            }
        }
    }

    fn start_attestation_verification(
        &mut self,
        message_id: MessageId,
        source: PeerId,
        attestation: types::SingleAttestation,
        subnet: SubnetId,
    ) {
        let Some(permit) = try_admit_proof(&self.proof_admission) else {
            let _ = self.network.report_pq_admitted_message_outcome(
                message_id,
                AdmittedMessageValidationOutcome::RetryableIgnore,
            );
            return;
        };
        let processor = Arc::clone(&self.processor);
        let completion_sender = self.attestation_completion_sender.clone();
        let retry_message_id = message_id.clone();
        if !spawn_owned_attestation_task(
            &self.task_executor,
            &self.in_flight,
            async move {
                let disposition = processor
                    .verify_gossip_attestation(attestation, subnet)
                    .await;
                try_send_completion(
                    &completion_sender,
                    PqAttestationVerificationCompletion {
                        message_id,
                        source,
                        disposition,
                        _permit: permit,
                    },
                );
            },
            "pq_network_attestation_verification",
        ) {
            let _ = self.network.report_pq_admitted_message_outcome(
                retry_message_id,
                AdmittedMessageValidationOutcome::RetryableIgnore,
            );
        }
    }

    fn handle_attestation_verification_completion(
        &mut self,
        completion: PqAttestationVerificationCompletion<T>,
    ) {
        let PqAttestationVerificationCompletion {
            message_id,
            source,
            disposition,
            _permit,
        } = completion;
        let disposition = match disposition {
            PqGossipAttestationDisposition::Accept(token) => {
                PqCompletionDisposition::Accept(*token)
            }
            PqGossipAttestationDisposition::Reject(error) => PqCompletionDisposition::Reject(error),
            PqGossipAttestationDisposition::Ignore(error) => {
                if matches!(
                    pq_attestation_ignore_outcome(&error),
                    AdmittedMessageValidationOutcome::RetryableIgnore
                ) {
                    PqCompletionDisposition::RetryableIgnore(error)
                } else {
                    PqCompletionDisposition::TerminalIgnoreError(error)
                }
            }
        };
        let mut lifecycle = PqNetworkAttestationCompletionLifecycle {
            network: &mut self.network,
            processor: Arc::clone(&self.processor),
            task_executor: self.task_executor.clone(),
            consumption_sender: self.attestation_consumption_sender.clone(),
            message_id,
            source,
            in_flight: Arc::clone(&self.in_flight),
        };
        handle_completion_lifecycle(disposition, &mut lifecycle);
        drop(_permit);
    }

    fn handle_attestation_consumption_completion(
        &mut self,
        completion: PqAttestationConsumptionCompletion,
    ) {
        let PqAttestationConsumptionCompletion { admission, result } = completion;
        let resolved = self.network.resolve_pq_admitted_message_commit(
            admission,
            attestation_consumption_commit_outcome(),
        );
        if attestation_consumption_requires_shutdown(result.is_err(), resolved) {
            self.processor.fail_gossip_attestation_consumption();
        }
        if let Err(error) = result {
            debug!(?error, "PQ gossip attestation consumption failed");
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    fn handle_testing_attestation_publish(
        &mut self,
        command: PqTestingAttestationPublishCommand<T::EthSpec>,
    ) {
        let result = self
            .network
            .testing_only_publish_pq_attestation(command.attestation.clone(), command.subnet)
            .map_err(|error| match error {
                lighthouse_network::PqTestingAttestationLowerPublishError::Duplicate => {
                    PqTestingAttestationPublishError::Duplicate
                }
                lighthouse_network::PqTestingAttestationLowerPublishError::NoPeersSubscribed => {
                    PqTestingAttestationPublishError::NoPeersSubscribed
                }
                lighthouse_network::PqTestingAttestationLowerPublishError::Rejected => {
                    PqTestingAttestationPublishError::Rejected
                }
            });
        command.acknowledge(result);
    }

    fn send_status_request(&mut self, peer_id: PeerId) {
        if self
            .network
            .send_request(
                peer_id,
                AppRequestId::Router,
                RequestType::Status(self.status_message()),
            )
            .is_ok()
        {
            let _ = self.emit_operational_event(PqOperationalEvent::StatusSent {
                peer_digest: pq_peer_digest(&peer_id),
                direction: PqStatusMessageDirection::Request,
            });
        }
    }

    fn emit_operational_event(&mut self, event: PqOperationalEvent) -> bool {
        if self
            .operational_events
            .upgrade()
            .is_some_and(|events| events.try_emit(event).is_ok())
        {
            return true;
        }
        warn!("PQ operational event sink unavailable");
        let _ =
            self.task_executor
                .shutdown_sender()
                .try_send(task_executor::ShutdownReason::Failure(
                    "PQ operational event sink unavailable",
                ));
        false
    }

    fn start_block_verification(
        &mut self,
        message_id: MessageId,
        source: PeerId,
        block: Arc<types::SignedBeaconBlock<T::EthSpec>>,
    ) {
        let Some(permit) = try_admit_proof(&self.proof_admission) else {
            let _ = self.network.report_pq_admitted_message_outcome(
                message_id,
                AdmittedMessageValidationOutcome::RetryableIgnore,
            );
            return;
        };
        if self.task_executor.handle().is_none() {
            let _ = self.network.report_pq_admitted_message_outcome(
                message_id,
                AdmittedMessageValidationOutcome::RetryableIgnore,
            );
            return;
        }
        let processor = Arc::clone(&self.processor);
        let completion_sender = self.completion_sender.clone();
        let _in_flight = self.in_flight.start();
        self.task_executor.spawn(
            async move {
                let _in_flight_guard = _in_flight;
                let disposition = processor.verify_gossip_block(block).await;
                try_send_completion(
                    &completion_sender,
                    PqBlockVerificationCompletion {
                        message_id,
                        source,
                        disposition,
                        _permit: permit,
                    },
                );
            },
            "pq_network_block_verification",
        );
    }

    fn handle_verification_completion(&mut self, completion: PqBlockVerificationCompletion<T>) {
        let PqBlockVerificationCompletion {
            message_id,
            source,
            disposition,
            _permit,
        } = completion;
        let mut lifecycle = PqNetworkCompletionLifecycle {
            network: &mut self.network,
            processor: Arc::clone(&self.processor),
            task_executor: self.task_executor.clone(),
            commit_sender: self.commit_sender.clone(),
            message_id,
            source,
            in_flight: Arc::clone(&self.in_flight),
        };
        handle_completion_lifecycle(completion_disposition(disposition), &mut lifecycle);
        drop(_permit);
    }

    fn handle_commit_completion(&mut self, completion: PqBlockCommitCompletion) {
        let PqBlockCommitCompletion {
            admission,
            result,
            identity,
        } = completion;
        let resolution = commit_resolution(&result);
        let resolved = self
            .network
            .resolve_pq_admitted_message_commit(admission, resolution);
        if let Some(PqOperationalEvent::GossipImported {
            slot,
            block_root,
            signed_ssz_digest,
        }) = gossip_imported_event(identity, result.is_ok(), resolved)
        {
            let _ =
                self.processor
                    .chain
                    .emit_pq_gossip_imported(slot, block_root, signed_ssz_digest);
        }
        if let Err(error) = result {
            debug!(
                ?error,
                ?resolution,
                "PQ gossip block commit did not complete"
            );
        }
    }

    fn status_message(&self) -> StatusMessage {
        let head = self.chain.head_snapshot();
        let genesis_epoch = self
            .chain
            .spec
            .genesis_slot
            .epoch(T::EthSpec::slots_per_epoch());
        StatusMessage::V2(StatusMessageV2 {
            fork_digest: self.fork_digest,
            finalized_root: Hash256::zero(),
            finalized_epoch: genesis_epoch,
            head_root: head.beacon_block_root,
            head_slot: head.beacon_block.slot(),
            earliest_available_slot: self.chain.spec.genesis_slot,
        })
    }

    fn validate_status(&mut self, peer_id: PeerId, status: &StatusMessage) {
        let expected = self.status_message().status_v2();
        let received = status.status_v2();
        let Some(operational_events) = self.operational_events.upgrade() else {
            warn!("PQ operational event sink unavailable");
            let _ = self.task_executor.shutdown_sender().try_send(
                task_executor::ShutdownReason::Failure("PQ operational event sink unavailable"),
            );
            return;
        };
        let mut lifecycle = PqNetworkStatusLifecycle {
            network: &mut self.network,
            peer_id,
            gossip_admission: &self.gossip_admission,
            operational_events: &operational_events,
            task_executor: &self.task_executor,
        };
        handle_status_lifecycle(&expected, &received, &mut lifecycle);
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqCompletionTestDisposition {
    Accept { report_succeeded: bool },
    Retry,
    Reject,
    Ignore,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqCompletionTestEvent {
    ReportedAccept,
    ReportedCommitWithoutPropagation,
    ReportedRetryableIgnore,
    PromotedAfterPropagation,
    CommitSpawned,
    PropagationCapabilityDropped,
    ReportedIgnore,
    ReportedReject,
    PeerPenalized,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqNetworkAttestationCompletionTestDisposition {
    Accept { report_succeeded: bool },
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqNetworkAttestationCompletionTestEvent {
    ReportedAccept,
    MarkedPropagated,
    ConsumptionSpawned,
    PropagationCapabilityDropped,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqNetworkAttestationIgnoreTestCase {
    RemoteDuplicate,
    Aged,
    StaleHead,
    ShuttingDown,
    GenerationExhausted,
    TerminalWindow,
    LocalCapacity,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqNetworkAttestationIgnoreTestTrace {
    pub retryable_ignore: bool,
    pub terminal_ignore: bool,
    pub retained_history: bool,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_attestation_ignore_classification(
    case: PqNetworkAttestationIgnoreTestCase,
) -> PqNetworkAttestationIgnoreTestTrace {
    let error = match case {
        PqNetworkAttestationIgnoreTestCase::RemoteDuplicate => {
            PqAttestationGossipError::Duplicate(PqAttestationGossipObservation::Observed)
        }
        PqNetworkAttestationIgnoreTestCase::Aged => {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::ReceiptAfterWindow {
                attestation: types::Slot::new(1),
                earliest_permissible: types::Slot::new(2),
            })
        }
        PqNetworkAttestationIgnoreTestCase::StaleHead => PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::BoundHeadNoLongerCanonical {
                bound: Hash256::ZERO,
                current: Hash256::repeat_byte(1),
            },
        ),
        PqNetworkAttestationIgnoreTestCase::ShuttingDown => {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::ShuttingDown)
        }
        PqNetworkAttestationIgnoreTestCase::GenerationExhausted => PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationGenerationExhausted,
        ),
        PqNetworkAttestationIgnoreTestCase::TerminalWindow => PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ProofOutlivedPropagationWindow {
                attestation: types::Slot::new(1),
            },
        ),
        PqNetworkAttestationIgnoreTestCase::LocalCapacity => {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::IngressCapacity)
        }
    };
    let outcome = pq_attestation_ignore_outcome(&error);
    let retryable_ignore = matches!(outcome, AdmittedMessageValidationOutcome::RetryableIgnore);
    let terminal_ignore = matches!(outcome, AdmittedMessageValidationOutcome::TerminalIgnore);
    PqNetworkAttestationIgnoreTestTrace {
        retryable_ignore,
        terminal_ignore,
        retained_history: terminal_ignore,
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_completion_lifecycle(
    disposition: PqCompletionTestDisposition,
) -> Vec<PqCompletionTestEvent> {
    use std::{cell::RefCell, rc::Rc};

    struct PropagationCapability {
        armed: bool,
        events: Rc<RefCell<Vec<PqCompletionTestEvent>>>,
    }

    impl Drop for PropagationCapability {
        fn drop(&mut self) {
            if self.armed {
                self.events
                    .borrow_mut()
                    .push(PqCompletionTestEvent::PropagationCapabilityDropped);
            }
        }
    }

    struct RecordingLifecycle {
        report_succeeded: bool,
        expected_outcome: AdmittedMessageValidationOutcome,
        events: Rc<RefCell<Vec<PqCompletionTestEvent>>>,
    }

    impl PqCompletionLifecycle<PropagationCapability, (), ()> for RecordingLifecycle {
        type Reservation = ();

        fn report(
            &mut self,
            outcome: AdmittedMessageValidationOutcome,
        ) -> PqAdmissionReport<Self::Reservation> {
            assert_eq!(outcome, self.expected_outcome);
            self.events.borrow_mut().push(match outcome {
                AdmittedMessageValidationOutcome::Accept => PqCompletionTestEvent::ReportedAccept,
                AdmittedMessageValidationOutcome::CommitWithoutPropagation => {
                    PqCompletionTestEvent::ReportedCommitWithoutPropagation
                }
                AdmittedMessageValidationOutcome::RetryableIgnore => {
                    PqCompletionTestEvent::ReportedRetryableIgnore
                }
                AdmittedMessageValidationOutcome::Reject => PqCompletionTestEvent::ReportedReject,
                AdmittedMessageValidationOutcome::TerminalIgnore
                | AdmittedMessageValidationOutcome::Equivocation
                | AdmittedMessageValidationOutcome::Pending => {
                    PqCompletionTestEvent::ReportedIgnore
                }
            });
            if matches!(
                outcome,
                AdmittedMessageValidationOutcome::Accept
                    | AdmittedMessageValidationOutcome::CommitWithoutPropagation
            ) {
                if self.report_succeeded {
                    PqAdmissionReport::Commit(())
                } else {
                    PqAdmissionReport::NotFound
                }
            } else {
                PqAdmissionReport::Complete
            }
        }

        fn after_propagation(&mut self, mut propagation: PropagationCapability) -> Result<(), ()> {
            propagation.armed = false;
            self.events
                .borrow_mut()
                .push(PqCompletionTestEvent::PromotedAfterPropagation);
            Ok(())
        }

        fn commit(&mut self, (): (), (): ()) {
            self.events
                .borrow_mut()
                .push(PqCompletionTestEvent::CommitSpawned);
        }

        fn resolve_promotion_failed(&mut self, (): (), (): &()) {
            unreachable!("accept test capability promotion cannot fail");
        }

        fn reject(&mut self, (): ()) {
            self.events
                .borrow_mut()
                .push(PqCompletionTestEvent::PeerPenalized);
        }

        fn promotion_failed(&mut self, (): ()) {
            unreachable!("accept test capability promotion cannot fail");
        }

        fn ignored_error(&mut self, (): ()) {
            // The typed report event above is the only lifecycle effect for a local ignore.
        }
    }

    let events = Rc::new(RefCell::new(vec![]));
    match disposition {
        PqCompletionTestDisposition::Accept { report_succeeded } => {
            let mut lifecycle = RecordingLifecycle {
                report_succeeded,
                expected_outcome: AdmittedMessageValidationOutcome::Accept,
                events: Rc::clone(&events),
            };
            handle_completion_lifecycle(
                PqCompletionDisposition::Accept(PropagationCapability {
                    armed: true,
                    events: Rc::clone(&events),
                }),
                &mut lifecycle,
            );
        }
        PqCompletionTestDisposition::Retry => {
            let mut lifecycle = RecordingLifecycle {
                report_succeeded: false,
                expected_outcome: AdmittedMessageValidationOutcome::CommitWithoutPropagation,
                events: Rc::clone(&events),
            };
            lifecycle.report_succeeded = true;
            handle_completion_lifecycle(PqCompletionDisposition::Retry(()), &mut lifecycle);
        }
        PqCompletionTestDisposition::Reject => {
            let mut lifecycle = RecordingLifecycle {
                report_succeeded: false,
                expected_outcome: AdmittedMessageValidationOutcome::Reject,
                events: Rc::clone(&events),
            };
            handle_completion_lifecycle(PqCompletionDisposition::Reject(()), &mut lifecycle);
        }
        PqCompletionTestDisposition::Ignore => {
            let mut lifecycle = RecordingLifecycle {
                report_succeeded: false,
                expected_outcome: AdmittedMessageValidationOutcome::RetryableIgnore,
                events: Rc::clone(&events),
            };
            handle_completion_lifecycle(
                PqCompletionDisposition::RetryableIgnore(()),
                &mut lifecycle,
            );
        }
    }
    events.borrow().clone()
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_attestation_completion_lifecycle(
    disposition: PqNetworkAttestationCompletionTestDisposition,
) -> Vec<PqNetworkAttestationCompletionTestEvent> {
    let PqNetworkAttestationCompletionTestDisposition::Accept { report_succeeded } = disposition;
    testing_only_pq_completion_lifecycle(PqCompletionTestDisposition::Accept { report_succeeded })
        .into_iter()
        .filter_map(|event| match event {
            PqCompletionTestEvent::ReportedAccept => {
                Some(PqNetworkAttestationCompletionTestEvent::ReportedAccept)
            }
            PqCompletionTestEvent::PromotedAfterPropagation => {
                Some(PqNetworkAttestationCompletionTestEvent::MarkedPropagated)
            }
            PqCompletionTestEvent::CommitSpawned => {
                Some(PqNetworkAttestationCompletionTestEvent::ConsumptionSpawned)
            }
            PqCompletionTestEvent::PropagationCapabilityDropped => {
                Some(PqNetworkAttestationCompletionTestEvent::PropagationCapabilityDropped)
            }
            _ => None,
        })
        .collect()
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqProofAdmissionTestTrace {
    pub admitted: Vec<bool>,
    pub proofs_started: usize,
    pub admitted_after_drop: bool,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_proof_admission() -> PqProofAdmissionTestTrace {
    let admission = Arc::new(Semaphore::new(PQ_NETWORK_BLOCK_PROOF_CAPACITY));
    let mut permits = vec![];
    let mut admitted = vec![];
    let mut proofs_started = 0;
    for _ in 0..=PQ_NETWORK_BLOCK_PROOF_CAPACITY {
        let permit = try_admit_proof(&admission);
        admitted.push(permit.is_some());
        if permit.is_some() {
            proofs_started += 1;
        }
        permits.extend(permit);
    }
    drop(permits.pop());
    let admitted_after_drop = try_admit_proof(&admission).is_some();
    PqProofAdmissionTestTrace {
        admitted,
        proofs_started,
        admitted_after_drop,
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqNetworkAttestationInFlightTestTrace {
    pub admitted: Vec<bool>,
    pub retryable_ignored: usize,
    pub heartbeat_completed: bool,
    pub drain_pending_with_two: bool,
    pub drain_pending_with_one: bool,
    pub drained_after_release: bool,
    pub available_permits_after_release: usize,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub async fn testing_only_pq_attestation_in_flight_lifecycle()
-> PqNetworkAttestationInFlightTestTrace {
    let admission = Arc::new(Semaphore::new(PQ_NETWORK_BLOCK_PROOF_CAPACITY));
    let in_flight = Arc::new(PqNetworkInFlight::default());
    let mut owned = vec![];
    let mut admitted = vec![];
    let mut retryable_ignored = 0;
    for _ in 0..=PQ_NETWORK_BLOCK_PROOF_CAPACITY {
        match try_admit_proof(&admission) {
            Some(permit) => {
                admitted.push(true);
                owned.push((permit, in_flight.start()));
            }
            None => {
                admitted.push(false);
                retryable_ignored += 1;
            }
        }
    }
    let heartbeat_completed = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::task::yield_now().await;
        true
    })
    .await
    .unwrap_or(false);
    let drain_tracker = Arc::clone(&in_flight);
    let mut drain = Box::pin(async move { drain_tracker.wait_until_drained().await });
    let drain_pending_with_two =
        tokio::time::timeout(std::time::Duration::from_millis(1), &mut drain)
            .await
            .is_err();
    drop(owned.pop());
    let drain_pending_with_one =
        tokio::time::timeout(std::time::Duration::from_millis(1), &mut drain)
            .await
            .is_err();
    drop(owned.pop());
    let drained_after_release = tokio::time::timeout(std::time::Duration::from_secs(1), &mut drain)
        .await
        .is_ok();
    PqNetworkAttestationInFlightTestTrace {
        admitted,
        retryable_ignored,
        heartbeat_completed,
        drain_pending_with_two,
        drain_pending_with_one,
        drained_after_release,
        available_permits_after_release: admission.available_permits(),
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqNetworkAttestationConsumptionTestCase {
    Success,
    ReconciliationFailed,
    TaskUnavailable,
    ResolutionLost,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqNetworkAttestationConsumptionTestTrace {
    pub terminal_history: bool,
    pub signal_shutdown: bool,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_attestation_consumption_resolution(
    case: PqNetworkAttestationConsumptionTestCase,
) -> PqNetworkAttestationConsumptionTestTrace {
    let (result_failed, resolved) = match case {
        PqNetworkAttestationConsumptionTestCase::Success => (false, true),
        PqNetworkAttestationConsumptionTestCase::ReconciliationFailed
        | PqNetworkAttestationConsumptionTestCase::TaskUnavailable => (true, true),
        PqNetworkAttestationConsumptionTestCase::ResolutionLost => (false, false),
    };
    PqNetworkAttestationConsumptionTestTrace {
        terminal_history: matches!(
            attestation_consumption_commit_outcome(),
            AdmittedMessageCommitOutcome::Terminal
        ),
        signal_shutdown: attestation_consumption_requires_shutdown(result_failed, resolved),
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqNetworkAttestationDetachedTestTrace {
    pub entered: bool,
    pub caller_drop_retained: bool,
    pub executor_exit_retained: bool,
    pub drained_after_release: bool,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub async fn testing_only_pq_attestation_detached_lifecycle()
-> PqNetworkAttestationDetachedTestTrace {
    let (executor_owner, executor_exit) = async_channel::bounded(1);
    let (shutdown_sender, _shutdown_receiver) = futures::channel::mpsc::channel(1);
    let executor = TaskExecutor::new(
        tokio::runtime::Handle::current(),
        executor_exit,
        shutdown_sender,
    );
    let in_flight = Arc::new(PqNetworkInFlight::default());
    let release = Arc::new(Semaphore::new(0));
    let task_release = Arc::clone(&release);
    let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
    let spawned = spawn_owned_attestation_task(
        &executor,
        &in_flight,
        async move {
            let _ = entered_sender.send(());
            if let Ok(permit) = task_release.acquire().await {
                permit.forget();
            }
        },
        "pq_testing_attestation_detached",
    );
    let entered = tokio::time::timeout(std::time::Duration::from_secs(1), entered_receiver)
        .await
        .is_ok();
    debug_assert!(spawned);
    let drain_tracker = Arc::clone(&in_flight);
    let mut drain = Box::pin(async move { drain_tracker.wait_until_drained().await });
    let caller_drop_retained =
        tokio::time::timeout(std::time::Duration::from_millis(1), &mut drain)
            .await
            .is_err();
    drop(executor_owner);
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let executor_exit_retained =
        tokio::time::timeout(std::time::Duration::from_millis(1), &mut drain)
            .await
            .is_err();
    release.add_permits(1);
    let drained_after_release = tokio::time::timeout(std::time::Duration::from_secs(1), &mut drain)
        .await
        .is_ok();
    PqNetworkAttestationDetachedTestTrace {
        entered,
        caller_drop_retained,
        executor_exit_retained,
        drained_after_release,
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqCompletionQueueTestScenario {
    Full,
    Closed,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqCompletionQueueTestTrace {
    pub dropped_after_send: usize,
    pub available_after_send: usize,
    pub dropped_after_receiver_drop: usize,
    pub available_after_receiver_drop: usize,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_completion_queue(
    scenario: PqCompletionQueueTestScenario,
) -> PqCompletionQueueTestTrace {
    use std::{cell::Cell, rc::Rc};

    struct Capability {
        drops: Rc<Cell<usize>>,
    }

    impl Drop for Capability {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    struct Completion {
        _capability: Capability,
        _permit: OwnedSemaphorePermit,
    }

    let admission = Arc::new(Semaphore::new(PQ_NETWORK_BLOCK_PROOF_CAPACITY));
    let drops = Rc::new(Cell::new(0));
    match scenario {
        PqCompletionQueueTestScenario::Full => {
            let (sender, receiver) = mpsc::channel(1);
            for _ in 0..2 {
                try_send_completion(
                    &sender,
                    Completion {
                        _capability: Capability {
                            drops: Rc::clone(&drops),
                        },
                        _permit: try_admit_proof(&admission).expect("capacity for two proof jobs"),
                    },
                );
            }
            let dropped_after_send = drops.get();
            let available_after_send = admission.available_permits();
            drop(receiver);
            PqCompletionQueueTestTrace {
                dropped_after_send,
                available_after_send,
                dropped_after_receiver_drop: drops.get(),
                available_after_receiver_drop: admission.available_permits(),
            }
        }
        PqCompletionQueueTestScenario::Closed => {
            let (sender, receiver) = mpsc::channel(1);
            drop(receiver);
            try_send_completion(
                &sender,
                Completion {
                    _capability: Capability {
                        drops: Rc::clone(&drops),
                    },
                    _permit: try_admit_proof(&admission).expect("proof admission"),
                },
            );
            PqCompletionQueueTestTrace {
                dropped_after_send: drops.get(),
                available_after_send: admission.available_permits(),
                dropped_after_receiver_drop: drops.get(),
                available_after_receiver_drop: admission.available_permits(),
            }
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqEncodingShutdownTestTrace {
    pub acknowledgement: Result<(), PqBlockBroadcastError>,
    pub available_permits: usize,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub async fn testing_only_pq_encoding_shutdown<E: EthSpec>(
    block: Arc<types::SignedBeaconBlock<E>>,
    fork_digest: [u8; 4],
) -> PqEncodingShutdownTestTrace {
    let (broadcast_sender, mut broadcast_receiver) = super::pq_block_broadcast_channel();
    let acknowledgement = broadcast_sender
        .try_send(block)
        .expect("test broadcast ingress");
    let command = broadcast_receiver
        .recv()
        .await
        .expect("test broadcast command");
    let admission = Arc::new(Semaphore::new(PQ_NETWORK_BLOCK_ENCODING_CAPACITY));
    let permit = Arc::clone(&admission)
        .try_acquire_owned()
        .expect("test encoding admission");
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    try_send_completion(
        &sender,
        PqBlockEncodingCompletion {
            encoded: PqEncodedBeaconBlock::encode(Arc::clone(command.block()), fork_digest),
            command,
            _permit: permit,
        },
    );
    PqEncodingShutdownTestTrace {
        acknowledgement: acknowledgement.wait().await,
        available_permits: admission.available_permits(),
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqStatusTestScenario {
    Compatible,
    CompatibleAlreadyKnown,
    CompatibleCapacityFull,
    ForkDigestMismatch,
    FinalizedEpochMismatch,
    FinalizedRootMismatch,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqStatusTestEvent {
    MarkedCompatible,
    EmittedPeerCompatible,
    EmittedStatusRejected(PqStatusRejectionCode),
    DisconnectedIrrelevantNetwork,
    DisconnectedTooManyPeers,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqStatusTestTrace {
    pub events: Vec<PqStatusTestEvent>,
    pub block_verifications_started: usize,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_status_lifecycle(scenario: PqStatusTestScenario) -> PqStatusTestTrace {
    struct RecordingStatusLifecycle {
        events: Vec<PqStatusTestEvent>,
        block_verifications_started: usize,
        compatible_capacity_available: bool,
    }

    impl PqStatusLifecycle for RecordingStatusLifecycle {
        fn mark_compatible(&mut self) -> PqCompatiblePeerAdmission {
            if !self.compatible_capacity_available {
                return PqCompatiblePeerAdmission::Capacity;
            }
            if self.events.contains(&PqStatusTestEvent::MarkedCompatible) {
                PqCompatiblePeerAdmission::Existing
            } else {
                self.events.push(PqStatusTestEvent::MarkedCompatible);
                PqCompatiblePeerAdmission::Added
            }
        }

        fn emit_peer_compatible(&mut self) -> bool {
            self.events.push(PqStatusTestEvent::EmittedPeerCompatible);
            true
        }

        fn emit_status_rejected(&mut self, code: PqStatusRejectionCode) -> bool {
            self.events
                .push(PqStatusTestEvent::EmittedStatusRejected(code));
            true
        }

        fn operational_event_failed(&mut self) {
            unreachable!("recording event sink is available")
        }

        fn disconnect_irrelevant_network(&mut self) {
            self.events
                .push(PqStatusTestEvent::DisconnectedIrrelevantNetwork);
        }

        fn disconnect_too_many_peers(&mut self) {
            self.events
                .push(PqStatusTestEvent::DisconnectedTooManyPeers);
        }
    }

    let expected = StatusMessageV2 {
        fork_digest: [1; 4],
        finalized_root: Hash256::repeat_byte(2),
        finalized_epoch: types::Epoch::new(3),
        head_root: Hash256::repeat_byte(4),
        head_slot: types::Slot::new(5),
        earliest_available_slot: types::Slot::new(0),
    };
    let mut received = expected.clone();
    match scenario {
        PqStatusTestScenario::Compatible
        | PqStatusTestScenario::CompatibleAlreadyKnown
        | PqStatusTestScenario::CompatibleCapacityFull => {}
        PqStatusTestScenario::ForkDigestMismatch => received.fork_digest = [9; 4],
        PqStatusTestScenario::FinalizedEpochMismatch => {
            received.finalized_epoch = types::Epoch::new(9);
        }
        PqStatusTestScenario::FinalizedRootMismatch => {
            received.finalized_root = Hash256::repeat_byte(9);
        }
    }
    let mut lifecycle = RecordingStatusLifecycle {
        events: vec![],
        block_verifications_started: 0,
        compatible_capacity_available: scenario != PqStatusTestScenario::CompatibleCapacityFull,
    };
    handle_status_lifecycle(&expected, &received, &mut lifecycle);
    if scenario == PqStatusTestScenario::CompatibleAlreadyKnown {
        handle_status_lifecycle(&expected, &received, &mut lifecycle);
    }
    PqStatusTestTrace {
        events: lifecycle.events,
        block_verifications_started: lifecycle.block_verifications_started,
    }
}
