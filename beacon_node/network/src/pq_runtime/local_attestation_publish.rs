use beacon_chain::PqVerifiedLocalAttestationBatch;
use lighthouse_network::libp2p::gossipsub::IdentTopic as Topic;
use lighthouse_network::types::{GossipEncoding, GossipKind};
use lighthouse_network::{
    GossipTopic, MessageId, PqSingleAttestationPublishOutcome, classify_pq_single_publish_result,
};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
#[cfg(feature = "pq-startup-testing")]
use types::MinimalEthSpec;
use types::{ChainSpec, EthSpec, Hash256, Slot, SubnetId};

const PQ_LOCAL_ATTESTATION_BATCH_PUBLISH_CAPACITY: usize = 1;

/// Non-clone ownership returned after one whole-batch publication attempt.
pub struct PqLocalAttestationBatchPublishProgress<E: EthSpec> {
    batch: PqVerifiedLocalAttestationBatch<E>,
    encoded: Vec<PqEncodedLocalAttestation>,
    encoding_error: Option<PqLocalAttestationBatchEncodingFailure>,
    members: Vec<PqLocalAttestationMemberPublishProgress>,
    next_member: usize,
    encoding_complete: bool,
    _admission: OwnedSemaphorePermit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqLocalAttestationMemberPublishProgress {
    Verified,
    Published {
        message_id: MessageId,
        duplicate: bool,
    },
    WaitingRemote {
        message_id: MessageId,
        retained: bool,
    },
    Retryable {
        message_id: MessageId,
    },
    Terminal {
        message_id: Option<MessageId>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqLocalAttestationBatchEncodingFailure {
    SignedSszDigestMismatch { member: usize },
    TaskUnavailable,
    TaskPanicked,
}

fn validate_exact_signed_ssz_buffer(
    signed_ssz: Vec<u8>,
    expected_digest: [u8; 32],
    member: usize,
) -> Result<Vec<u8>, PqLocalAttestationBatchEncodingFailure> {
    let actual_digest: [u8; 32] = Sha256::digest(&signed_ssz).into();
    if actual_digest != expected_digest {
        return Err(PqLocalAttestationBatchEncodingFailure::SignedSszDigestMismatch { member });
    }
    Ok(signed_ssz)
}

fn encode_exact_pq_local_attestation_member(
    signed_ssz: Vec<u8>,
    expected_digest: [u8; 32],
    subnet: SubnetId,
    fork_digest: [u8; 4],
    member: usize,
) -> Result<PqEncodedLocalAttestation, PqLocalAttestationBatchEncodingFailure> {
    let data = validate_exact_signed_ssz_buffer(signed_ssz, expected_digest, member)?;
    let topic = GossipTopic::new(
        GossipKind::Attestation(subnet),
        GossipEncoding::default(),
        fork_digest,
    );
    Ok(PqEncodedLocalAttestation {
        topic: Topic::from(topic),
        data,
        _subnet: subnet,
        _instance: member,
    })
}

fn encode_pq_local_attestation_members<E: EthSpec>(
    members: impl IntoIterator<Item = (Vec<u8>, [u8; 32], SubnetId, Slot)>,
    spec: &ChainSpec,
    genesis_validators_root: Hash256,
) -> Result<Vec<PqEncodedLocalAttestation>, PqLocalAttestationBatchEncodingFailure> {
    members
        .into_iter()
        .enumerate()
        .map(|(member, (signed_ssz, expected_digest, subnet, slot))| {
            let fork_digest = spec
                .enr_fork_id::<E>(slot, genesis_validators_root)
                .fork_digest;
            encode_exact_pq_local_attestation_member(
                signed_ssz,
                expected_digest,
                subnet,
                fork_digest,
                member,
            )
        })
        .collect()
}

impl<E: EthSpec> PqLocalAttestationBatchPublishProgress<E> {
    pub fn verified_count(&self) -> usize {
        self.batch.len()
    }

    pub fn member_progress(&self) -> &[PqLocalAttestationMemberPublishProgress] {
        &self.members
    }

    pub const fn encoding_failure(&self) -> Option<PqLocalAttestationBatchEncodingFailure> {
        self.encoding_error
    }

    pub fn is_terminal(&self) -> bool {
        self.encoding_error.is_some()
            || self.members.iter().any(|member| {
                matches!(
                    member,
                    PqLocalAttestationMemberPublishProgress::Terminal { .. }
                )
            })
    }

    pub fn is_retryable(&self) -> bool {
        self.encoding_complete
            && self.encoding_error.is_none()
            && matches!(
                self.members.get(self.next_member),
                Some(PqLocalAttestationMemberPublishProgress::Retryable { .. })
            )
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_encoding_trace(&self) -> PqLocalAttestationBatchEncodingTestTrace {
        let attempted_member0_message_id = match self.members.first() {
            Some(PqLocalAttestationMemberPublishProgress::Published { message_id, .. })
            | Some(PqLocalAttestationMemberPublishProgress::WaitingRemote { message_id, .. })
            | Some(PqLocalAttestationMemberPublishProgress::Retryable { message_id }) => {
                Some(message_id.clone())
            }
            Some(PqLocalAttestationMemberPublishProgress::Terminal { message_id }) => {
                message_id.clone()
            }
            Some(PqLocalAttestationMemberPublishProgress::Verified) | None => None,
        };
        PqLocalAttestationBatchEncodingTestTrace {
            encoded_member_count: self.encoded.len(),
            attempted_member0_topic: attempted_member0_message_id
                .as_ref()
                .and_then(|_| self.encoded.first())
                .map(|encoded| encoded.topic.hash().to_string()),
            attempted_member0_message_id,
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqLocalAttestationBatchEncodingTestTrace {
    pub encoded_member_count: usize,
    pub attempted_member0_topic: Option<String>,
    pub attempted_member0_message_id: Option<MessageId>,
}

struct PqEncodedLocalAttestation {
    topic: Topic,
    data: Vec<u8>,
    _subnet: SubnetId,
    _instance: usize,
}

type PqLocalAttestationBatchPublishShared<E> =
    Arc<Mutex<Option<PqLocalAttestationBatchPublishProgress<E>>>>;

/// Result-bearing receipt for one admitted whole-batch publication attempt.
pub struct PqLocalAttestationBatchPublishReceipt<E: EthSpec> {
    shared: PqLocalAttestationBatchPublishShared<E>,
    completion: oneshot::Receiver<()>,
}

impl<E: EthSpec> std::fmt::Debug for PqLocalAttestationBatchPublishReceipt<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PqLocalAttestationBatchPublishReceipt(..)")
    }
}

impl<E: EthSpec> PqLocalAttestationBatchPublishReceipt<E> {
    pub async fn wait(self) -> Option<PqLocalAttestationBatchPublishProgress<E>> {
        let _ = self.completion.await;
        self.shared.lock().take()
    }
}

/// A non-admitted command always returns the exact whole verified batch to its caller.
pub enum PqLocalAttestationBatchPublishSendError<E: EthSpec> {
    Capacity(PqVerifiedLocalAttestationBatch<E>),
    Closed(PqVerifiedLocalAttestationBatch<E>),
}

/// A non-admitted retry returns the exact opaque progress owner without exposing its tokens.
pub enum PqLocalAttestationBatchPublishRetryError<E: EthSpec> {
    NotRetryable(PqLocalAttestationBatchPublishProgress<E>),
    Capacity(PqLocalAttestationBatchPublishProgress<E>),
    Closed(PqLocalAttestationBatchPublishProgress<E>),
}

impl<E: EthSpec> std::fmt::Debug for PqLocalAttestationBatchPublishRetryError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NotRetryable(_) => "PqLocalAttestationBatchPublishRetryError::NotRetryable(..)",
            Self::Capacity(_) => "PqLocalAttestationBatchPublishRetryError::Capacity(..)",
            Self::Closed(_) => "PqLocalAttestationBatchPublishRetryError::Closed(..)",
        })
    }
}

impl<E: EthSpec> PqLocalAttestationBatchPublishRetryError<E> {
    pub fn is_not_retryable(&self) -> bool {
        matches!(self, Self::NotRetryable(_))
    }

    pub fn into_progress(self) -> PqLocalAttestationBatchPublishProgress<E> {
        match self {
            Self::NotRetryable(progress) | Self::Capacity(progress) | Self::Closed(progress) => {
                progress
            }
        }
    }
}

impl<E: EthSpec> std::fmt::Debug for PqLocalAttestationBatchPublishSendError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct(match self {
                Self::Capacity(_) => "Capacity",
                Self::Closed(_) => "Closed",
            })
            .field("verified_count", &self.returned_verified_count())
            .finish()
    }
}

impl<E: EthSpec> PqLocalAttestationBatchPublishSendError<E> {
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed(_))
    }

    pub fn returned_verified_count(&self) -> usize {
        match self {
            Self::Capacity(batch) | Self::Closed(batch) => batch.len(),
        }
    }
}

pub(crate) struct PqLocalAttestationBatchPublishCommand<E: EthSpec> {
    shared: PqLocalAttestationBatchPublishShared<E>,
    completion: oneshot::Sender<()>,
}

impl<E: EthSpec> PqLocalAttestationBatchPublishCommand<E> {
    fn fail_encoding(&self, failure: PqLocalAttestationBatchEncodingFailure) {
        if let Some(progress) = self.shared.lock().as_mut() {
            progress.encoding_error = Some(failure);
        }
    }

    pub(crate) fn needs_encoding(&self) -> bool {
        self.shared
            .lock()
            .as_ref()
            .is_some_and(|progress| !progress.encoding_complete)
    }

    pub(crate) fn publish(&self, network: &mut lighthouse_network::service::Network<E>) {
        let mut shared = self.shared.lock();
        let Some(progress) = shared.as_mut() else {
            return;
        };
        publish_pq_local_attestation_prefix(progress, |encoded| {
            let Some(message_id) = network
                .gossipsub()
                .anonymous_message_id(encoded.topic.hash(), &encoded.data)
            else {
                return PqSingleAttestationPublishOutcome::NonAnonymousPublisher;
            };
            let result = network
                .gossipsub_mut()
                .publish(encoded.topic.clone(), encoded.data.clone());
            classify_pq_single_publish_result(message_id, result)
        });
    }

    pub(crate) fn complete(self) {
        let _ = self.completion.send(());
    }
}

fn encode_pq_local_attestation_batch<E: EthSpec>(
    shared: &PqLocalAttestationBatchPublishShared<E>,
    spec: &ChainSpec,
    genesis_validators_root: Hash256,
) {
    let mut shared = shared.lock();
    let Some(progress) = shared.as_mut() else {
        return;
    };
    let encoded = encode_pq_local_attestation_members::<E>(
        progress.batch.verified().iter().map(|verified| {
            (
                ssz::Encode::as_ssz_bytes(verified.single()),
                verified.signed_ssz_digest(),
                verified.subnet(),
                verified.slot(),
            )
        }),
        spec,
        genesis_validators_root,
    );
    match encoded {
        Ok(encoded) => {
            progress.encoded = encoded;
            progress.encoding_complete = true;
        }
        Err(error) => progress.encoding_error = Some(error),
    }
}

#[derive(Clone)]
pub struct PqLocalAttestationBatchPublishSender<E: EthSpec> {
    sender: mpsc::Sender<PqLocalAttestationBatchPublishCommand<E>>,
    admission: Arc<Semaphore>,
}

impl<E: EthSpec> PqLocalAttestationBatchPublishSender<E> {
    pub fn try_publish(
        &self,
        batch: PqVerifiedLocalAttestationBatch<E>,
    ) -> Result<PqLocalAttestationBatchPublishReceipt<E>, PqLocalAttestationBatchPublishSendError<E>>
    {
        let admission = match Arc::clone(&self.admission).try_acquire_owned() {
            Ok(admission) => admission,
            Err(_) => return Err(PqLocalAttestationBatchPublishSendError::Capacity(batch)),
        };
        let channel_permit = match self.sender.try_reserve() {
            Ok(channel_permit) => channel_permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                return Err(PqLocalAttestationBatchPublishSendError::Capacity(batch));
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                return Err(PqLocalAttestationBatchPublishSendError::Closed(batch));
            }
        };
        let shared = Arc::new(Mutex::new(Some(PqLocalAttestationBatchPublishProgress {
            members: vec![PqLocalAttestationMemberPublishProgress::Verified; batch.len()],
            batch,
            encoded: vec![],
            encoding_error: None,
            next_member: 0,
            encoding_complete: false,
            _admission: admission,
        })));
        let (completion, receiver) = oneshot::channel();
        channel_permit.send(PqLocalAttestationBatchPublishCommand {
            shared: Arc::clone(&shared),
            completion,
        });
        Ok(PqLocalAttestationBatchPublishReceipt {
            shared,
            completion: receiver,
        })
    }

    pub fn try_retry(
        &self,
        progress: PqLocalAttestationBatchPublishProgress<E>,
    ) -> Result<PqLocalAttestationBatchPublishReceipt<E>, PqLocalAttestationBatchPublishRetryError<E>>
    {
        if !progress.is_retryable() {
            return Err(PqLocalAttestationBatchPublishRetryError::NotRetryable(
                progress,
            ));
        }
        let channel_permit = match self.sender.try_reserve() {
            Ok(channel_permit) => channel_permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                return Err(PqLocalAttestationBatchPublishRetryError::Capacity(progress));
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                return Err(PqLocalAttestationBatchPublishRetryError::Closed(progress));
            }
        };
        let shared = Arc::new(Mutex::new(Some(progress)));
        let (completion, receiver) = oneshot::channel();
        channel_permit.send(PqLocalAttestationBatchPublishCommand {
            shared: Arc::clone(&shared),
            completion,
        });
        Ok(PqLocalAttestationBatchPublishReceipt {
            shared,
            completion: receiver,
        })
    }
}

fn publish_pq_local_attestation_prefix<E: EthSpec>(
    progress: &mut PqLocalAttestationBatchPublishProgress<E>,
    mut publish: impl FnMut(&mut PqEncodedLocalAttestation) -> PqSingleAttestationPublishOutcome,
) {
    publish_pq_local_attestation_cursor(
        &mut progress.encoded,
        &mut progress.members,
        &mut progress.next_member,
        |_, encoded| publish(encoded),
    );
}

fn publish_pq_local_attestation_cursor(
    encoded_members: &mut [PqEncodedLocalAttestation],
    member_progress: &mut [PqLocalAttestationMemberPublishProgress],
    next_member: &mut usize,
    mut publish: impl FnMut(usize, &mut PqEncodedLocalAttestation) -> PqSingleAttestationPublishOutcome,
) {
    while let Some(encoded) = encoded_members.get_mut(*next_member) {
        let member = *next_member;
        let outcome = publish(member, encoded);
        let (progress, continue_to_next) = match outcome {
            PqSingleAttestationPublishOutcome::Published { message_id } => (
                PqLocalAttestationMemberPublishProgress::Published {
                    message_id,
                    duplicate: false,
                },
                true,
            ),
            PqSingleAttestationPublishOutcome::DuplicateLocal { message_id } => (
                PqLocalAttestationMemberPublishProgress::Published {
                    message_id,
                    duplicate: true,
                },
                true,
            ),
            PqSingleAttestationPublishOutcome::PendingRemote { message_id } => (
                PqLocalAttestationMemberPublishProgress::WaitingRemote {
                    message_id,
                    retained: false,
                },
                false,
            ),
            PqSingleAttestationPublishOutcome::DuplicateRemote { message_id } => (
                PqLocalAttestationMemberPublishProgress::WaitingRemote {
                    message_id,
                    retained: true,
                },
                false,
            ),
            PqSingleAttestationPublishOutcome::NoPeers { message_id }
            | PqSingleAttestationPublishOutcome::ValidationAdmissionFull { message_id }
            | PqSingleAttestationPublishOutcome::AllQueuesFull { message_id, .. } => (
                PqLocalAttestationMemberPublishProgress::Retryable { message_id },
                false,
            ),
            PqSingleAttestationPublishOutcome::DuplicateUnknown { message_id }
            | PqSingleAttestationPublishOutcome::MessageTooLarge { message_id }
            | PqSingleAttestationPublishOutcome::Transform { message_id, .. } => (
                PqLocalAttestationMemberPublishProgress::Terminal {
                    message_id: Some(message_id),
                },
                false,
            ),
            PqSingleAttestationPublishOutcome::MessageIdMismatch { expected, .. } => (
                PqLocalAttestationMemberPublishProgress::Terminal {
                    message_id: Some(expected),
                },
                false,
            ),
            PqSingleAttestationPublishOutcome::NonAnonymousPublisher => (
                PqLocalAttestationMemberPublishProgress::Terminal { message_id: None },
                false,
            ),
        };
        let Some(current) = member_progress.get_mut(member) else {
            return;
        };
        *current = progress;
        if !continue_to_next {
            return;
        }
        let Some(next) = next_member.checked_add(1) else {
            return;
        };
        *next_member = next;
    }
}

struct PqLocalAttestationEncodingTask<E: EthSpec> {
    command: PqLocalAttestationBatchPublishCommand<E>,
    result: oneshot::Receiver<Result<(), tokio::task::JoinError>>,
}

async fn finish_pq_local_attestation_encoding<E: EthSpec>(
    task: &mut Option<PqLocalAttestationEncodingTask<E>>,
) -> PqLocalAttestationBatchPublishCommand<E> {
    let result = match task.as_mut() {
        Some(task) => (&mut task.result).await,
        None => std::future::pending().await,
    };
    let Some(task) = task.take() else {
        return std::future::pending().await;
    };
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) if error.is_panic() => {
            task.command
                .fail_encoding(PqLocalAttestationBatchEncodingFailure::TaskPanicked);
        }
        Ok(Err(_)) | Err(_) => {
            task.command
                .fail_encoding(PqLocalAttestationBatchEncodingFailure::TaskUnavailable);
        }
    }
    task.command
}

pub(crate) enum PqLocalAttestationBatchPublishEvent<E: EthSpec> {
    Incoming(PqLocalAttestationBatchPublishCommand<E>),
    Encoded(PqLocalAttestationBatchPublishCommand<E>),
}

pub(crate) struct PqLocalAttestationBatchPublishReceiver<E: EthSpec> {
    receiver: mpsc::Receiver<PqLocalAttestationBatchPublishCommand<E>>,
    encoding_task: Option<PqLocalAttestationEncodingTask<E>>,
    completed: Option<PqLocalAttestationBatchPublishShared<E>>,
    spec: Arc<ChainSpec>,
    genesis_validators_root: Hash256,
}

impl<E: EthSpec> PqLocalAttestationBatchPublishReceiver<E> {
    fn release_taken_completion(&mut self) {
        if self
            .completed
            .as_ref()
            .is_some_and(|completed| completed.lock().is_none())
        {
            self.completed = None;
        }
    }

    pub(crate) fn retain_and_complete(
        &mut self,
        command: PqLocalAttestationBatchPublishCommand<E>,
    ) {
        self.release_taken_completion();
        if self.completed.is_none() {
            self.completed = Some(Arc::clone(&command.shared));
        }
        command.complete();
    }

    pub(crate) async fn next_event(&mut self) -> Option<PqLocalAttestationBatchPublishEvent<E>> {
        self.release_taken_completion();
        let encoding_task = &mut self.encoding_task;
        let receiver = &mut self.receiver;
        tokio::select! {
            biased;
            encoded = finish_pq_local_attestation_encoding(encoding_task) => {
                Some(PqLocalAttestationBatchPublishEvent::Encoded(encoded))
            }
            command = receiver.recv() => {
                command.map(PqLocalAttestationBatchPublishEvent::Incoming)
            }
        }
    }

    pub(crate) fn start_encoding(
        &mut self,
        command: PqLocalAttestationBatchPublishCommand<E>,
        task_executor: TaskExecutor,
        hook: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> bool {
        let spec = Arc::clone(&self.spec);
        let genesis_validators_root = self.genesis_validators_root;
        let shared = Arc::clone(&command.shared);
        let Some(result) = task_executor.spawn_blocking_handle_without_exit(
            move || {
                if let Some(hook) = hook {
                    hook();
                }
                encode_pq_local_attestation_batch(&shared, &spec, genesis_validators_root);
            },
            "pq_local_attestation_batch_encoding",
        ) else {
            command.fail_encoding(PqLocalAttestationBatchEncodingFailure::TaskUnavailable);
            let mut shutdown_sender = task_executor.shutdown_sender();
            let _ = shutdown_sender.try_send(task_executor::ShutdownReason::Failure(
                "PQ local attestation encoding worker unavailable",
            ));
            self.retain_and_complete(command);
            return false;
        };
        self.encoding_task = Some(PqLocalAttestationEncodingTask { command, result });
        true
    }

    pub(crate) async fn close_and_drain(&mut self) {
        self.receiver.close();
        while let Ok(command) = self.receiver.try_recv() {
            command.complete();
        }
        if self.encoding_task.is_some() {
            let command = finish_pq_local_attestation_encoding(&mut self.encoding_task).await;
            command.complete();
        }
        self.completed = None;
    }
}

pub(crate) fn pq_local_attestation_batch_publish_channel<E: EthSpec>(
    spec: Arc<ChainSpec>,
    genesis_validators_root: Hash256,
) -> (
    PqLocalAttestationBatchPublishSender<E>,
    PqLocalAttestationBatchPublishReceiver<E>,
) {
    let (sender, receiver) = mpsc::channel(PQ_LOCAL_ATTESTATION_BATCH_PUBLISH_CAPACITY);
    (
        PqLocalAttestationBatchPublishSender {
            sender,
            admission: Arc::new(Semaphore::new(PQ_LOCAL_ATTESTATION_BATCH_PUBLISH_CAPACITY)),
        },
        PqLocalAttestationBatchPublishReceiver {
            receiver,
            encoding_task: None,
            completed: None,
            spec,
            genesis_validators_root,
        },
    )
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub struct TestingPqLocalAttestationBatchPublishReceiver<E: EthSpec> {
    _receiver: PqLocalAttestationBatchPublishReceiver<E>,
}

#[cfg(feature = "pq-startup-testing")]
impl<E: EthSpec> TestingPqLocalAttestationBatchPublishReceiver<E> {
    pub fn close_and_return_pending(&mut self) {
        self._receiver.receiver.close();
        while let Ok(command) = self._receiver.receiver.try_recv() {
            command.complete();
        }
    }

    pub fn start_next_encoding(
        &mut self,
        task_executor: TaskExecutor,
        hook: Arc<dyn Fn() + Send + Sync>,
    ) -> bool {
        let Ok(command) = self._receiver.receiver.try_recv() else {
            return false;
        };
        self._receiver
            .start_encoding(command, task_executor, Some(hook))
    }

    pub async fn finish_next_encoding(&mut self) -> bool {
        match self._receiver.next_event().await {
            Some(PqLocalAttestationBatchPublishEvent::Encoded(command)) => {
                self._receiver.retain_and_complete(command);
                true
            }
            Some(PqLocalAttestationBatchPublishEvent::Incoming(command)) => {
                command.complete();
                false
            }
            None => false,
        }
    }

    pub fn complete_next_terminal(&mut self) -> bool {
        let Ok(command) = self._receiver.receiver.try_recv() else {
            return false;
        };
        if let Some(progress) = command.shared.lock().as_mut() {
            progress.encoding_error =
                Some(PqLocalAttestationBatchEncodingFailure::SignedSszDigestMismatch { member: 0 });
        }
        self._receiver.retain_and_complete(command);
        true
    }

    /// Creates no verified token and is only a lifecycle seam for queued opaque-owner tests.
    pub fn complete_next_retryable_for_ownership_test(&mut self) -> bool {
        let Ok(command) = self._receiver.receiver.try_recv() else {
            return false;
        };
        if let Some(progress) = command.shared.lock().as_mut() {
            progress.encoded = vec![PqEncodedLocalAttestation {
                topic: Topic::new("pq-local-attestation-ownership-test"),
                data: vec![],
                _subnet: SubnetId::new(0),
                _instance: 0,
            }];
            progress.members = vec![PqLocalAttestationMemberPublishProgress::Retryable {
                message_id: MessageId(vec![0]),
            }];
            progress.encoding_complete = true;
        }
        self._receiver.retain_and_complete(command);
        true
    }

    pub fn complete_next_published_for_ownership_test(&mut self) -> bool {
        let Ok(command) = self._receiver.receiver.try_recv() else {
            return false;
        };
        if let Some(progress) = command.shared.lock().as_mut() {
            progress.encoded = vec![PqEncodedLocalAttestation {
                topic: Topic::new("pq-local-attestation-published-ownership-test"),
                data: vec![],
                _subnet: SubnetId::new(0),
                _instance: 0,
            }];
            progress.members = vec![PqLocalAttestationMemberPublishProgress::Published {
                message_id: MessageId(vec![0]),
                duplicate: false,
            }];
            progress.next_member = 1;
            progress.encoding_complete = true;
        }
        self._receiver.retain_and_complete(command);
        true
    }

    pub fn completed_owner_count(&self) -> usize {
        usize::from(
            self._receiver
                .completed
                .as_ref()
                .is_some_and(|completed| completed.lock().is_some()),
        )
    }

    pub fn take_completed_for_test(&mut self) -> Option<PqLocalAttestationBatchPublishProgress<E>> {
        let completed = self._receiver.completed.take()?;
        let progress = completed.lock().take();
        progress
    }

    pub async fn close_and_drain(mut self) {
        self._receiver.close_and_drain().await;
    }

    pub async fn close_and_drain_in_place(&mut self) {
        self._receiver.close_and_drain().await;
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_local_attestation_batch_publish_channel() -> (
    PqLocalAttestationBatchPublishSender<MinimalEthSpec>,
    TestingPqLocalAttestationBatchPublishReceiver<MinimalEthSpec>,
) {
    let spec = types::ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    let (sender, receiver) =
        pq_local_attestation_batch_publish_channel(Arc::new(spec), Hash256::ZERO);
    (
        sender,
        TestingPqLocalAttestationBatchPublishReceiver {
            _receiver: receiver,
        },
    )
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqLocalAttestationExactSszBufferTestTrace {
    pub data: Vec<u8>,
    pub reused_allocation: bool,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_local_attestation_encode_exact_signed_ssz(
    signed_ssz: Vec<u8>,
    expected_digest: [u8; 32],
    subnet: SubnetId,
    fork_digest: [u8; 4],
) -> Result<PqLocalAttestationExactSszBufferTestTrace, ()> {
    let original_allocation = signed_ssz.as_ptr();
    let encoded = encode_exact_pq_local_attestation_member(
        signed_ssz,
        expected_digest,
        subnet,
        fork_digest,
        0,
    )
    .map_err(|_| ())?;
    Ok(PqLocalAttestationExactSszBufferTestTrace {
        reused_allocation: original_allocation == encoded.data.as_ptr(),
        data: encoded.data,
    })
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqLocalAttestationBatchEncoderTestTrace {
    pub encoded_member_count: usize,
    pub topics: Vec<String>,
    pub data: Vec<Vec<u8>>,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_local_attestation_encode_batch(
    members: Vec<(Vec<u8>, [u8; 32], SubnetId, Slot)>,
) -> Result<PqLocalAttestationBatchEncoderTestTrace, PqLocalAttestationBatchEncodingFailure> {
    let spec = types::ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    let encoded =
        encode_pq_local_attestation_members::<MinimalEthSpec>(members, &spec, Hash256::ZERO)?;
    Ok(PqLocalAttestationBatchEncoderTestTrace {
        encoded_member_count: encoded.len(),
        topics: encoded
            .iter()
            .map(|member| member.topic.hash().to_string())
            .collect(),
        data: encoded.into_iter().map(|member| member.data).collect(),
    })
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqLocalAttestationPublishTestOutcome {
    Published,
    DuplicateLocal,
    NoPeers,
    PendingRemote,
    DuplicateRemote,
    DuplicateUnknown,
    Transform,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqLocalAttestationPublishTestTrace {
    pub attempted_members: Vec<usize>,
    pub encoded_member_instances: Vec<usize>,
    pub published_members: Vec<usize>,
    pub duplicate_local_members: Vec<usize>,
    pub retryable_members: Vec<usize>,
    pub waiting_remote_members: Vec<(usize, bool)>,
    pub terminal_members: Vec<usize>,
    pub encoding_passes: usize,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_local_attestation_publish_progress(
    member_count: usize,
    outcomes: &[PqLocalAttestationPublishTestOutcome],
) -> PqLocalAttestationPublishTestTrace {
    let mut encoded = (0..member_count)
        .map(|instance| PqEncodedLocalAttestation {
            topic: Topic::new(format!("pq-local-attestation-{instance}")),
            data: vec![u8::try_from(instance).unwrap_or(u8::MAX)],
            _subnet: SubnetId::new(0),
            _instance: instance,
        })
        .collect::<Vec<_>>();
    let mut members = vec![PqLocalAttestationMemberPublishProgress::Verified; member_count];
    let mut next_member = 0;
    let mut outcomes = outcomes.iter().copied();
    let mut attempted_members = vec![];
    let mut encoded_member_instances = vec![];
    while outcomes.len() > 0 && next_member < member_count {
        publish_pq_local_attestation_cursor(
            &mut encoded,
            &mut members,
            &mut next_member,
            |member, encoded| {
                attempted_members.push(member);
                encoded_member_instances.push(encoded._instance);
                let message_id = MessageId(vec![u8::try_from(member).unwrap_or(u8::MAX)]);
                match outcomes.next() {
                    Some(PqLocalAttestationPublishTestOutcome::Published) => {
                        PqSingleAttestationPublishOutcome::Published { message_id }
                    }
                    Some(PqLocalAttestationPublishTestOutcome::DuplicateLocal) => {
                        PqSingleAttestationPublishOutcome::DuplicateLocal { message_id }
                    }
                    Some(PqLocalAttestationPublishTestOutcome::NoPeers) | None => {
                        PqSingleAttestationPublishOutcome::NoPeers { message_id }
                    }
                    Some(PqLocalAttestationPublishTestOutcome::PendingRemote) => {
                        PqSingleAttestationPublishOutcome::PendingRemote { message_id }
                    }
                    Some(PqLocalAttestationPublishTestOutcome::DuplicateRemote) => {
                        PqSingleAttestationPublishOutcome::DuplicateRemote { message_id }
                    }
                    Some(PqLocalAttestationPublishTestOutcome::DuplicateUnknown) => {
                        PqSingleAttestationPublishOutcome::DuplicateUnknown { message_id }
                    }
                    Some(PqLocalAttestationPublishTestOutcome::Transform) => {
                        PqSingleAttestationPublishOutcome::Transform {
                            message_id,
                            error_kind: std::io::ErrorKind::InvalidData,
                        }
                    }
                }
            },
        );
    }
    PqLocalAttestationPublishTestTrace {
        attempted_members,
        encoded_member_instances,
        published_members: members
            .iter()
            .enumerate()
            .filter_map(|(member, progress)| {
                matches!(
                    progress,
                    PqLocalAttestationMemberPublishProgress::Published { .. }
                )
                .then_some(member)
            })
            .collect(),
        duplicate_local_members: members
            .iter()
            .enumerate()
            .filter_map(|(member, progress)| match progress {
                PqLocalAttestationMemberPublishProgress::Published {
                    duplicate: true, ..
                } => Some(member),
                _ => None,
            })
            .collect(),
        retryable_members: members
            .iter()
            .enumerate()
            .filter_map(|(member, progress)| {
                matches!(
                    progress,
                    PqLocalAttestationMemberPublishProgress::Retryable { .. }
                )
                .then_some(member)
            })
            .collect(),
        waiting_remote_members: members
            .iter()
            .enumerate()
            .filter_map(|(member, progress)| match progress {
                PqLocalAttestationMemberPublishProgress::WaitingRemote { retained, .. } => {
                    Some((member, *retained))
                }
                _ => None,
            })
            .collect(),
        terminal_members: members
            .iter()
            .enumerate()
            .filter_map(|(member, progress)| {
                matches!(
                    progress,
                    PqLocalAttestationMemberPublishProgress::Terminal { .. }
                )
                .then_some(member)
            })
            .collect(),
        encoding_passes: 1,
    }
}
