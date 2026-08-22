use beacon_chain::{
    PqPublishedLocalAttestationBatchConsumptionError,
    PqPublishedLocalAttestationBatchConsumptionOutcome, PqPublishedLocalAttestationEvidenceBatch,
    PqPublishedLocalAttestationMemberEvidence, PqPublishedLocalMemberResolution,
    PqPublishedLocalMemberResolutionError, PqSingleConsumptionResult,
    PqSingleObservationCompletion, PqSingleObservationWatchError, PqSingleWireMessageId,
    PqVerifiedLocalAttestationBatch,
};
#[cfg(feature = "pq-startup-testing")]
use beacon_chain::{
    PqSingleObservationStatus, TestingPqLocalCandidateBatchGuards,
    TestingPqPublishedLocalMemberResolver,
    testing_only_pq_local_candidate_batch_fixture_with_guards,
    testing_only_pq_published_local_member_resolver,
};
use lighthouse_network::libp2p::gossipsub::IdentTopic as Topic;
use lighthouse_network::types::{GossipEncoding, GossipKind};
use lighthouse_network::{
    GossipTopic, MessageId, PqLocalSinglePublicationToken, PqSingleAttestationPublishOutcome,
};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
#[cfg(feature = "pq-startup-testing")]
use types::MinimalEthSpec;
use types::{ChainSpec, EthSpec, Hash256, Slot, SubnetId};

const PQ_LOCAL_ATTESTATION_BATCH_PUBLISH_CAPACITY: usize = 1;
const PQ_LOCAL_ATTESTATION_PUBLISHED_PREFIX_RETRY_BACKOFF: std::time::Duration =
    std::time::Duration::from_millis(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PqAttestationAdmissionBridgeCompletion {
    ClaimReady,
    Released,
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PqAttestationAdmissionBridgeError {
    Capacity,
    Duplicate,
    Unknown,
    Lost,
}

pub(crate) enum PqLocalAttestationRemoteResolution {
    Immediate(PqSingleConsumptionResult),
    TerminalAlreadySignaled,
    ChainWait(beacon_chain::PqSingleObservationWatchReceipt),
    BridgeWait(PqAttestationAdmissionBridgeReceipt),
}

impl From<PqPublishedLocalMemberResolution> for PqLocalAttestationRemoteResolution {
    fn from(resolution: PqPublishedLocalMemberResolution) -> Self {
        match resolution {
            PqPublishedLocalMemberResolution::Immediate(result) => Self::Immediate(result),
            PqPublishedLocalMemberResolution::TerminalAlreadySignaled => {
                Self::TerminalAlreadySignaled
            }
            PqPublishedLocalMemberResolution::Wait(receipt) => Self::ChainWait(receipt),
        }
    }
}

struct PqAttestationAdmissionBridgeEntry {
    generation: u64,
    completion: watch::Sender<Option<PqAttestationAdmissionBridgeCompletion>>,
}

#[derive(Default)]
struct PqAttestationAdmissionBridgeState {
    next_generation: u64,
    entries: std::collections::HashMap<PqSingleWireMessageId, PqAttestationAdmissionBridgeEntry>,
}

#[derive(Clone)]
pub(crate) struct PqAttestationAdmissionBridge {
    capacity: usize,
    state: Arc<Mutex<PqAttestationAdmissionBridgeState>>,
}

impl PqAttestationAdmissionBridge {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Arc::new(Mutex::new(PqAttestationAdmissionBridgeState::default())),
        }
    }

    pub(crate) fn reserve(
        &self,
        wire_id: PqSingleWireMessageId,
    ) -> Result<PqAttestationAdmissionBridgeHandle, PqAttestationAdmissionBridgeError> {
        let mut state = self.state.lock();
        if state.entries.contains_key(&wire_id) {
            return Err(PqAttestationAdmissionBridgeError::Duplicate);
        }
        if state.entries.len() >= self.capacity {
            return Err(PqAttestationAdmissionBridgeError::Capacity);
        }
        let generation = state.next_generation;
        state.next_generation = state
            .next_generation
            .checked_add(1)
            .ok_or(PqAttestationAdmissionBridgeError::Capacity)?;
        let (completion, _receipt) = watch::channel(None);
        state.entries.insert(
            wire_id,
            PqAttestationAdmissionBridgeEntry {
                generation,
                completion,
            },
        );
        Ok(PqAttestationAdmissionBridgeHandle {
            bridge: self.clone(),
            wire_id,
            generation,
            resolved: false,
        })
    }

    pub(crate) fn subscribe(
        &self,
        wire_id: PqSingleWireMessageId,
    ) -> Result<PqAttestationAdmissionBridgeReceipt, PqAttestationAdmissionBridgeError> {
        let state = self.state.lock();
        let entry = state
            .entries
            .get(&wire_id)
            .ok_or(PqAttestationAdmissionBridgeError::Unknown)?;
        Ok(PqAttestationAdmissionBridgeReceipt {
            receipt: entry.completion.subscribe(),
        })
    }

    #[cfg(feature = "pq-startup-testing")]
    fn testing_only_lose_exact(&self, wire_id: PqSingleWireMessageId) -> bool {
        self.state.lock().entries.remove(&wire_id).is_some()
    }

    #[cfg(feature = "pq-startup-testing")]
    fn entry_count(&self) -> usize {
        self.state.lock().entries.len()
    }
}

pub(crate) struct PqAttestationAdmissionBridgeHandle {
    bridge: PqAttestationAdmissionBridge,
    wire_id: PqSingleWireMessageId,
    generation: u64,
    resolved: bool,
}

impl PqAttestationAdmissionBridgeHandle {
    fn resolve(&mut self, completion: PqAttestationAdmissionBridgeCompletion) -> bool {
        if self.resolved {
            return false;
        }
        let mut state = self.bridge.state.lock();
        let Some(entry) = state.entries.get(&self.wire_id) else {
            return false;
        };
        if entry.generation != self.generation {
            return false;
        }
        let Some(entry) = state.entries.remove(&self.wire_id) else {
            return false;
        };
        entry.completion.send_replace(Some(completion));
        self.resolved = true;
        true
    }

    pub(crate) fn claim_ready(&mut self) -> bool {
        self.resolve(PqAttestationAdmissionBridgeCompletion::ClaimReady)
    }

    pub(crate) fn released(&mut self) -> bool {
        self.resolve(PqAttestationAdmissionBridgeCompletion::Released)
    }

    pub(crate) fn terminal(&mut self) -> bool {
        self.resolve(PqAttestationAdmissionBridgeCompletion::Terminal)
    }
}

impl Drop for PqAttestationAdmissionBridgeHandle {
    fn drop(&mut self) {
        let _ = self.terminal();
    }
}

pub(crate) struct PqAttestationAdmissionBridgeReceipt {
    receipt: watch::Receiver<Option<PqAttestationAdmissionBridgeCompletion>>,
}

impl PqAttestationAdmissionBridgeReceipt {
    pub(crate) async fn wait(
        &mut self,
    ) -> Result<PqAttestationAdmissionBridgeCompletion, PqAttestationAdmissionBridgeError> {
        loop {
            if let Some(completion) = *self.receipt.borrow_and_update() {
                return Ok(completion);
            }
            self.receipt
                .changed()
                .await
                .map_err(|_| PqAttestationAdmissionBridgeError::Lost)?;
        }
    }
}

/// Non-clone ownership returned after one whole-batch publication attempt.
pub struct PqLocalAttestationBatchPublishProgress<E: EthSpec> {
    batch: Option<PqVerifiedLocalAttestationBatch<E>>,
    verified_count: usize,
    encoded: Vec<PqEncodedLocalAttestation>,
    encoding_error: Option<PqLocalAttestationBatchEncodingFailure>,
    post_publish_failure: Option<PqLocalAttestationPostPublishFailure>,
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
    RemoteResolved {
        message_id: MessageId,
        result: PqSingleConsumptionResult,
    },
    Retryable {
        message_id: MessageId,
    },
    Terminal {
        message_id: Option<MessageId>,
    },
    Consumed {
        message_id: MessageId,
        duplicate: bool,
        result: PqSingleConsumptionResult,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqLocalAttestationPostPublishFailure {
    TaskUnavailable,
    TaskPanicked,
    Consumer(PqPublishedLocalAttestationBatchConsumptionError),
    OutcomeCountMismatch,
    PublishedPrefixUnresolved,
    PreConsumerEvidence(PqLocalAttestationPreConsumerEvidenceFailure),
    RemoteResolution(PqPublishedLocalMemberResolutionError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqLocalAttestationPreConsumerEvidenceFailure {
    Count,
    MemberState { member: usize },
    MemberToken { member: usize },
    RemoteEvidence { member: usize },
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
        publication: None,
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
        self.verified_count
    }

    pub fn member_progress(&self) -> &[PqLocalAttestationMemberPublishProgress] {
        &self.members
    }

    pub const fn encoding_failure(&self) -> Option<PqLocalAttestationBatchEncodingFailure> {
        self.encoding_error
    }

    pub const fn post_publish_failure(&self) -> Option<PqLocalAttestationPostPublishFailure> {
        self.post_publish_failure
    }

    pub fn is_terminal(&self) -> bool {
        self.encoding_error.is_some()
            || self.post_publish_failure.is_some()
            || self.members.iter().any(|member| {
                matches!(
                    member,
                    PqLocalAttestationMemberPublishProgress::Terminal { .. }
                        | PqLocalAttestationMemberPublishProgress::Consumed {
                            result: PqSingleConsumptionResult::Terminal,
                            ..
                        }
                )
            })
    }

    pub fn is_successfully_consumed(&self) -> bool {
        self.verified_count > 0
            && self.members.len() == self.verified_count
            && self.encoding_complete
            && self.encoding_error.is_none()
            && self.post_publish_failure.is_none()
            && self.members.iter().all(|member| {
                matches!(
                    member,
                    PqLocalAttestationMemberPublishProgress::Consumed {
                        result: PqSingleConsumptionResult::Applied
                            | PqSingleConsumptionResult::Queued,
                        ..
                    }
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
            Some(PqLocalAttestationMemberPublishProgress::Consumed { message_id, .. }) => {
                Some(message_id.clone())
            }
            Some(PqLocalAttestationMemberPublishProgress::RemoteResolved {
                message_id, ..
            }) => Some(message_id.clone()),
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
    publication: Option<PqLocalSinglePublicationToken>,
    _subnet: SubnetId,
    _instance: usize,
}

type PqLocalAttestationBatchPublishShared<E> =
    Arc<Mutex<Option<PqLocalAttestationBatchPublishProgress<E>>>>;

fn take_publication_evidence<E: EthSpec>(
    shared: &PqLocalAttestationBatchPublishShared<E>,
) -> Result<PqPublishedLocalAttestationEvidenceBatch<E>, PqLocalAttestationPreConsumerEvidenceFailure>
{
    let mut shared = shared.lock();
    let progress = shared
        .as_mut()
        .ok_or(PqLocalAttestationPreConsumerEvidenceFailure::Count)?;
    if progress.batch.is_none()
        || progress.encoded.len() != progress.members.len()
        || progress.members.is_empty()
    {
        return Err(PqLocalAttestationPreConsumerEvidenceFailure::Count);
    }
    for (member, (encoded, state)) in progress.encoded.iter().zip(&progress.members).enumerate() {
        match state {
            PqLocalAttestationMemberPublishProgress::Published { message_id, .. } => {
                let Some(token) = encoded.publication.as_ref() else {
                    return Err(PqLocalAttestationPreConsumerEvidenceFailure::MemberToken {
                        member,
                    });
                };
                let mut topic =
                    GossipTopic::decode(encoded.topic.hash().as_str()).map_err(|_| {
                        PqLocalAttestationPreConsumerEvidenceFailure::MemberToken { member }
                    })?;
                let signed_ssz_digest: [u8; 32] = Sha256::digest(&encoded.data).into();
                if token.message_id() != message_id
                    || token.topic_hash() != &encoded.topic.hash()
                    || token.signed_ssz_digest() != signed_ssz_digest
                    || token.fork_digest() != *topic.digest()
                    || !matches!(topic.kind(), GossipKind::Attestation(subnet) if *subnet == token.subnet())
                {
                    return Err(PqLocalAttestationPreConsumerEvidenceFailure::MemberToken {
                        member,
                    });
                }
            }
            PqLocalAttestationMemberPublishProgress::RemoteResolved { result, .. }
                if matches!(
                    result,
                    PqSingleConsumptionResult::Applied | PqSingleConsumptionResult::Queued
                ) && encoded.publication.is_none() => {}
            PqLocalAttestationMemberPublishProgress::RemoteResolved { .. } => {
                return Err(
                    PqLocalAttestationPreConsumerEvidenceFailure::RemoteEvidence { member },
                );
            }
            _ => {
                return Err(PqLocalAttestationPreConsumerEvidenceFailure::MemberState { member });
            }
        }
    }
    let batch = progress
        .batch
        .take()
        .ok_or(PqLocalAttestationPreConsumerEvidenceFailure::Count)?;
    let members = progress
        .encoded
        .iter_mut()
        .enumerate()
        .map(|(member, encoded)| match progress.members.get(member) {
            Some(PqLocalAttestationMemberPublishProgress::Published { .. }) => encoded
                .publication
                .take()
                .map(PqPublishedLocalAttestationMemberEvidence::Local)
                .ok_or(PqLocalAttestationPreConsumerEvidenceFailure::MemberToken { member }),
            Some(PqLocalAttestationMemberPublishProgress::RemoteResolved {
                message_id,
                result,
            }) => Ok(PqPublishedLocalAttestationMemberEvidence::Remote {
                message_id: message_id.clone(),
                result: *result,
            }),
            _ => Err(PqLocalAttestationPreConsumerEvidenceFailure::MemberState { member }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(batch.bind_publication_evidence(members))
}

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

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_shared_member_progress_trace(
        &self,
    ) -> Option<Vec<PqLocalAttestationMemberPublishProgress>> {
        self.shared
            .lock()
            .as_ref()
            .map(|progress| progress.members.clone())
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
            let Ok(topic) = GossipTopic::decode(encoded.topic.hash().as_str()) else {
                return PqSingleAttestationPublishOutcome::Transform {
                    message_id: MessageId(vec![]),
                    error_kind: std::io::ErrorKind::InvalidInput,
                };
            };
            network.publish_pq_local_single_attestation_exact(topic, encoded.data.clone())
        });
    }

    fn all_members_resolved(&self) -> bool {
        self.shared.lock().as_ref().is_some_and(|progress| {
            !progress.members.is_empty()
                && progress.encoding_complete
                && progress.encoding_error.is_none()
                && progress.post_publish_failure.is_none()
                && progress.members.iter().all(|member| {
                    matches!(
                        member,
                        PqLocalAttestationMemberPublishProgress::Published { .. }
                            | PqLocalAttestationMemberPublishProgress::RemoteResolved { .. }
                    )
                })
        })
    }

    fn published_prefix_state(&self) -> Option<PqLocalAttestationPublishedPrefixState> {
        self.shared.lock().as_ref().and_then(|progress| {
            let published = progress
                .members
                .iter()
                .take_while(|member| {
                    matches!(
                        member,
                        PqLocalAttestationMemberPublishProgress::Published { .. }
                            | PqLocalAttestationMemberPublishProgress::RemoteResolved { .. }
                    )
                })
                .count();
            if published == 0 || published != progress.next_member {
                return None;
            }
            match progress.members.get(progress.next_member) {
                Some(PqLocalAttestationMemberPublishProgress::Retryable { .. }) => {
                    Some(PqLocalAttestationPublishedPrefixState::Retryable)
                }
                Some(PqLocalAttestationMemberPublishProgress::WaitingRemote { .. }) => {
                    Some(PqLocalAttestationPublishedPrefixState::WaitingRemote)
                }
                Some(PqLocalAttestationMemberPublishProgress::Terminal { .. }) => {
                    Some(PqLocalAttestationPublishedPrefixState::Terminal)
                }
                Some(
                    PqLocalAttestationMemberPublishProgress::Verified
                    | PqLocalAttestationMemberPublishProgress::Published { .. }
                    | PqLocalAttestationMemberPublishProgress::RemoteResolved { .. }
                    | PqLocalAttestationMemberPublishProgress::Consumed { .. },
                )
                | None => None,
            }
        })
    }

    fn finish_consumption(
        &self,
        outcome: PqPublishedLocalAttestationBatchConsumptionOutcome,
    ) -> bool {
        let PqPublishedLocalAttestationBatchConsumptionOutcome::Complete { results } = outcome;
        let mut shared = self.shared.lock();
        let Some(progress) = shared.as_mut() else {
            return false;
        };
        if results.len() != progress.members.len() {
            progress.post_publish_failure =
                Some(PqLocalAttestationPostPublishFailure::OutcomeCountMismatch);
            return false;
        }
        let consumed = progress
            .members
            .iter()
            .zip(results)
            .map(|(member, result)| match member {
                PqLocalAttestationMemberPublishProgress::Published {
                    message_id,
                    duplicate,
                } => Some(PqLocalAttestationMemberPublishProgress::Consumed {
                    message_id: message_id.clone(),
                    duplicate: *duplicate,
                    result,
                }),
                PqLocalAttestationMemberPublishProgress::RemoteResolved { message_id, .. } => {
                    Some(PqLocalAttestationMemberPublishProgress::Consumed {
                        message_id: message_id.clone(),
                        duplicate: true,
                        result,
                    })
                }
                _ => None,
            })
            .collect::<Option<Vec<_>>>();
        let Some(consumed) = consumed else {
            progress.post_publish_failure =
                Some(PqLocalAttestationPostPublishFailure::OutcomeCountMismatch);
            return false;
        };
        progress.members = consumed;
        true
    }

    pub(crate) fn fail_consumption(&self, failure: PqLocalAttestationPostPublishFailure) {
        let mut shared = self.shared.lock();
        let Some(progress) = shared.as_mut() else {
            return;
        };
        progress.post_publish_failure = Some(failure);
        for member in &mut progress.members {
            let message_id = match member {
                PqLocalAttestationMemberPublishProgress::Published { message_id, .. }
                | PqLocalAttestationMemberPublishProgress::RemoteResolved { message_id, .. } => {
                    Some(message_id.clone())
                }
                _ => None,
            };
            if let Some(message_id) = message_id {
                *member = PqLocalAttestationMemberPublishProgress::Terminal {
                    message_id: Some(message_id),
                };
            }
        }
    }

    fn fail_published_prefix(&self) {
        let mut shared = self.shared.lock();
        let Some(progress) = shared.as_mut() else {
            return;
        };
        progress.post_publish_failure =
            Some(PqLocalAttestationPostPublishFailure::PublishedPrefixUnresolved);
        for member in &mut progress.members {
            let message_id = match member {
                PqLocalAttestationMemberPublishProgress::Published { .. }
                | PqLocalAttestationMemberPublishProgress::RemoteResolved { .. }
                | PqLocalAttestationMemberPublishProgress::Consumed { .. } => continue,
                PqLocalAttestationMemberPublishProgress::WaitingRemote { message_id, .. }
                | PqLocalAttestationMemberPublishProgress::Retryable { message_id } => {
                    Some(message_id.clone())
                }
                PqLocalAttestationMemberPublishProgress::Terminal { message_id } => {
                    message_id.clone()
                }
                PqLocalAttestationMemberPublishProgress::Verified => None,
            };
            *member = PqLocalAttestationMemberPublishProgress::Terminal { message_id };
        }
    }

    fn resolve_waiting_remote_with(
        &self,
        resolve: impl FnOnce(
            &PqVerifiedLocalAttestationBatch<E>,
            usize,
            &MessageId,
        ) -> Option<
            Result<PqLocalAttestationRemoteResolution, PqPublishedLocalMemberResolutionError>,
        >,
    ) -> Option<Result<PqLocalAttestationRemoteResolution, PqPublishedLocalMemberResolutionError>>
    {
        let shared = self.shared.lock();
        let Some(progress) = shared.as_ref() else {
            return Some(Err(PqPublishedLocalMemberResolutionError::Member));
        };
        let member = progress.next_member;
        let message_id = match progress.members.get(member) {
            Some(PqLocalAttestationMemberPublishProgress::WaitingRemote { message_id, .. }) => {
                message_id
            }
            _ => {
                return Some(Err(PqPublishedLocalMemberResolutionError::Observation(
                    beacon_chain::PqSingleObservationStatus::Unseen,
                )));
            }
        };
        let Some(batch) = progress.batch.as_ref() else {
            return Some(Err(PqPublishedLocalMemberResolutionError::Member));
        };
        resolve(batch, member, message_id)
    }

    fn resolve_waiting_remote_result(&self, result: PqSingleConsumptionResult) -> bool {
        let mut shared = self.shared.lock();
        let Some(progress) = shared.as_mut() else {
            return false;
        };
        let member = progress.next_member;
        let Some(PqLocalAttestationMemberPublishProgress::WaitingRemote { message_id, .. }) =
            progress.members.get(member)
        else {
            return false;
        };
        let message_id = message_id.clone();
        progress.members[member] =
            PqLocalAttestationMemberPublishProgress::RemoteResolved { message_id, result };
        let Some(next) = progress.next_member.checked_add(1) else {
            return false;
        };
        progress.next_member = next;
        true
    }

    fn release_waiting_remote_for_retry(&self) -> bool {
        let mut shared = self.shared.lock();
        let Some(progress) = shared.as_mut() else {
            return false;
        };
        let member = progress.next_member;
        let Some(PqLocalAttestationMemberPublishProgress::WaitingRemote { message_id, .. }) =
            progress.members.get(member)
        else {
            return false;
        };
        progress.members[member] = PqLocalAttestationMemberPublishProgress::Retryable {
            message_id: message_id.clone(),
        };
        true
    }

    pub(crate) fn complete(self) {
        let _ = self.completion.send(());
    }
}

pub(crate) enum PqLocalAttestationPostPublishAction<E: EthSpec> {
    Complete(PqLocalAttestationBatchPublishCommand<E>),
    Consume(PqLocalAttestationBatchPublishCommand<E>),
    FinalizePublishedPrefix(PqLocalAttestationBatchPublishCommand<E>),
    RetainPublishedPrefix {
        command: PqLocalAttestationBatchPublishCommand<E>,
        state: PqLocalAttestationPublishedPrefixState,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PqLocalAttestationPublishedPrefixState {
    Retryable,
    WaitingRemote,
    Terminal,
}

struct PqLocalAttestationPublishedPrefix<E: EthSpec> {
    command: PqLocalAttestationBatchPublishCommand<E>,
    retry_deadline: Option<tokio::time::Instant>,
}

pub(crate) fn route_pq_local_attestation_post_publish<E: EthSpec>(
    command: PqLocalAttestationBatchPublishCommand<E>,
    publish: impl FnOnce(&PqLocalAttestationBatchPublishCommand<E>),
) -> PqLocalAttestationPostPublishAction<E> {
    if command.published_prefix_state()
        != Some(PqLocalAttestationPublishedPrefixState::WaitingRemote)
    {
        publish(&command);
    }
    if command.all_members_resolved() {
        PqLocalAttestationPostPublishAction::Consume(command)
    } else if let Some(state) = command.published_prefix_state() {
        if state == PqLocalAttestationPublishedPrefixState::Terminal {
            PqLocalAttestationPostPublishAction::FinalizePublishedPrefix(command)
        } else {
            PqLocalAttestationPostPublishAction::RetainPublishedPrefix { command, state }
        }
    } else {
        PqLocalAttestationPostPublishAction::Complete(command)
    }
}

pub(crate) fn handle_pq_local_attestation_post_publish<
    E: EthSpec,
    Publish,
    ResolveRemote,
    Consume,
    ConsumeFuture,
    FailClosed,
>(
    receiver: &mut PqLocalAttestationBatchPublishReceiver<E>,
    command: PqLocalAttestationBatchPublishCommand<E>,
    task_executor: TaskExecutor,
    mut publish: Publish,
    mut resolve_remote: ResolveRemote,
    consume: Consume,
    fail_closed: FailClosed,
) -> bool
where
    Publish: FnMut(&PqLocalAttestationBatchPublishCommand<E>),
    ResolveRemote: FnMut(
        &PqVerifiedLocalAttestationBatch<E>,
        usize,
        &MessageId,
    ) -> Option<
        Result<PqLocalAttestationRemoteResolution, PqPublishedLocalMemberResolutionError>,
    >,
    Consume: FnOnce(PqPublishedLocalAttestationEvidenceBatch<E>) -> ConsumeFuture + Send + 'static,
    ConsumeFuture: std::future::Future<
            Output = Result<
                PqPublishedLocalAttestationBatchConsumptionOutcome,
                PqPublishedLocalAttestationBatchConsumptionError,
            >,
        > + Send
        + 'static,
    FailClosed: FnOnce(),
{
    let mut command = command;
    let mut consume = Some(consume);
    let mut fail_closed = Some(fail_closed);
    loop {
        match route_pq_local_attestation_post_publish(command, |command| publish(command)) {
            PqLocalAttestationPostPublishAction::Complete(command) => {
                receiver.retain_and_complete(command);
                return false;
            }
            PqLocalAttestationPostPublishAction::RetainPublishedPrefix {
                command: retained_command,
                state,
            } => {
                if state != PqLocalAttestationPublishedPrefixState::WaitingRemote {
                    receiver.retain_published_prefix(retained_command, state);
                    return false;
                }
                let Some(resolution) =
                    retained_command.resolve_waiting_remote_with(&mut resolve_remote)
                else {
                    receiver.retain_published_prefix(retained_command, state);
                    return false;
                };
                match resolution {
                    Ok(PqLocalAttestationRemoteResolution::Immediate(result)) => {
                        if !retained_command.resolve_waiting_remote_result(result) {
                            retained_command.fail_consumption(
                                PqLocalAttestationPostPublishFailure::OutcomeCountMismatch,
                            );
                            if let Some(fail_closed) = fail_closed.take() {
                                fail_closed();
                            }
                            receiver.retain_and_complete(retained_command);
                            return false;
                        }
                        command = retained_command;
                    }
                    Ok(PqLocalAttestationRemoteResolution::TerminalAlreadySignaled) => {
                        retained_command.fail_consumption(
                            PqLocalAttestationPostPublishFailure::RemoteResolution(
                                PqPublishedLocalMemberResolutionError::Observation(
                                    beacon_chain::PqSingleObservationStatus::Consumed(
                                        PqSingleConsumptionResult::Terminal,
                                    ),
                                ),
                            ),
                        );
                        receiver.retain_and_complete(retained_command);
                        return false;
                    }
                    Ok(PqLocalAttestationRemoteResolution::ChainWait(receipt)) => {
                        receiver.start_remote_resolution(retained_command, receipt);
                        return true;
                    }
                    Ok(PqLocalAttestationRemoteResolution::BridgeWait(receipt)) => {
                        receiver.start_bridge_resolution(retained_command, receipt);
                        return true;
                    }
                    Err(error) => {
                        retained_command.fail_consumption(
                            PqLocalAttestationPostPublishFailure::RemoteResolution(error),
                        );
                        if let Some(fail_closed) = fail_closed.take() {
                            fail_closed();
                        }
                        receiver.retain_and_complete(retained_command);
                        return false;
                    }
                }
            }
            PqLocalAttestationPostPublishAction::FinalizePublishedPrefix(command) => {
                command.fail_published_prefix();
                if let Some(fail_closed) = fail_closed.take() {
                    fail_closed();
                }
                receiver.retain_and_complete(command);
                return false;
            }
            PqLocalAttestationPostPublishAction::Consume(command) => {
                let Some(consume) = consume.take() else {
                    command.fail_consumption(PqLocalAttestationPostPublishFailure::TaskUnavailable);
                    if let Some(fail_closed) = fail_closed.take() {
                        fail_closed();
                    }
                    receiver.retain_and_complete(command);
                    return false;
                };
                if let Err(command) =
                    receiver.start_consumption_with(command, task_executor, consume)
                {
                    command.fail_consumption(PqLocalAttestationPostPublishFailure::TaskUnavailable);
                    if let Some(fail_closed) = fail_closed.take() {
                        fail_closed();
                    }
                    receiver.retain_and_complete(command);
                    return false;
                } else {
                    return true;
                }
            }
        }
    }
}

pub(crate) fn complete_pq_local_attestation_remote_resolution<E: EthSpec>(
    receiver: &mut PqLocalAttestationBatchPublishReceiver<E>,
    completion: PqLocalAttestationRemoteResolutionTaskCompletion<E>,
    mut fail_closed: impl FnMut(PqLocalAttestationPostPublishFailure),
) -> Option<PqLocalAttestationBatchPublishCommand<E>> {
    match completion {
        PqLocalAttestationRemoteResolutionTaskCompletion::Bridge {
            command,
            completion: PqAttestationAdmissionBridgeCompletion::ClaimReady,
        } => Some(command),
        PqLocalAttestationRemoteResolutionTaskCompletion::Bridge {
            command,
            completion: PqAttestationAdmissionBridgeCompletion::Released,
        } => {
            if command.release_waiting_remote_for_retry() {
                receiver.retain_published_prefix(
                    command,
                    PqLocalAttestationPublishedPrefixState::Retryable,
                );
            } else {
                let failure = PqLocalAttestationPostPublishFailure::OutcomeCountMismatch;
                command.fail_consumption(failure);
                fail_closed(failure);
                receiver.retain_and_complete(command);
            }
            None
        }
        PqLocalAttestationRemoteResolutionTaskCompletion::Bridge {
            command,
            completion: PqAttestationAdmissionBridgeCompletion::Terminal,
        } => {
            let failure = PqLocalAttestationPostPublishFailure::RemoteResolution(
                PqPublishedLocalMemberResolutionError::Observation(
                    beacon_chain::PqSingleObservationStatus::Consumed(
                        PqSingleConsumptionResult::Terminal,
                    ),
                ),
            );
            command.fail_consumption(failure);
            fail_closed(failure);
            receiver.retain_and_complete(command);
            None
        }
        PqLocalAttestationRemoteResolutionTaskCompletion::Complete {
            command,
            completion:
                PqSingleObservationCompletion::Consumed(
                    result @ (PqSingleConsumptionResult::Applied
                    | PqSingleConsumptionResult::Queued),
                ),
        } => {
            if command.resolve_waiting_remote_result(result) {
                Some(command)
            } else {
                let failure = PqLocalAttestationPostPublishFailure::OutcomeCountMismatch;
                command.fail_consumption(failure);
                fail_closed(failure);
                receiver.retain_and_complete(command);
                None
            }
        }
        PqLocalAttestationRemoteResolutionTaskCompletion::Complete {
            command,
            completion: PqSingleObservationCompletion::Released,
        } => {
            if command.release_waiting_remote_for_retry() {
                receiver.retain_published_prefix(
                    command,
                    PqLocalAttestationPublishedPrefixState::Retryable,
                );
            } else {
                let failure = PqLocalAttestationPostPublishFailure::OutcomeCountMismatch;
                command.fail_consumption(failure);
                fail_closed(failure);
                receiver.retain_and_complete(command);
            }
            None
        }
        PqLocalAttestationRemoteResolutionTaskCompletion::Complete {
            command,
            completion: PqSingleObservationCompletion::ConsumedTerminalAlreadySignaled,
        } => {
            let failure = PqLocalAttestationPostPublishFailure::RemoteResolution(
                PqPublishedLocalMemberResolutionError::Observation(
                    beacon_chain::PqSingleObservationStatus::Consumed(
                        PqSingleConsumptionResult::Terminal,
                    ),
                ),
            );
            command.fail_consumption(failure);
            // An exact chain-owned terminal observation is authoritative evidence that the
            // inbound consumption owner has already closed ingress and signalled process failure.
            // The local coalescer terminalizes its receipt without becoming a second owner.
            receiver.retain_and_complete(command);
            None
        }
        PqLocalAttestationRemoteResolutionTaskCompletion::Complete {
            command,
            completion: PqSingleObservationCompletion::Consumed(PqSingleConsumptionResult::Terminal),
        } => {
            let failure = PqLocalAttestationPostPublishFailure::RemoteResolution(
                PqPublishedLocalMemberResolutionError::Observation(
                    beacon_chain::PqSingleObservationStatus::Consumed(
                        PqSingleConsumptionResult::Terminal,
                    ),
                ),
            );
            command.fail_consumption(failure);
            fail_closed(failure);
            receiver.retain_and_complete(command);
            None
        }
        PqLocalAttestationRemoteResolutionTaskCompletion::Failed { command, failure } => {
            command.fail_consumption(failure);
            fail_closed(failure);
            receiver.retain_and_complete(command);
            None
        }
    }
}

pub(crate) fn complete_pq_local_attestation_post_publish<E: EthSpec>(
    receiver: &mut PqLocalAttestationBatchPublishReceiver<E>,
    completion: PqLocalAttestationConsumptionTaskCompletion<E>,
    fail_closed: impl FnOnce(PqLocalAttestationPostPublishFailure),
) {
    let command = match completion {
        PqLocalAttestationConsumptionTaskCompletion::Complete(command) => command,
        PqLocalAttestationConsumptionTaskCompletion::Failed { command, failure } => {
            fail_closed(failure);
            command
        }
    };
    receiver.retain_and_complete(command);
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
    let Some(batch) = progress.batch.as_ref() else {
        progress.post_publish_failure = Some(PqLocalAttestationPostPublishFailure::TaskUnavailable);
        return;
    };
    let encoded = encode_pq_local_attestation_members::<E>(
        batch.verified().iter().map(|verified| {
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
            verified_count: batch.len(),
            batch: Some(batch),
            encoded: vec![],
            encoding_error: None,
            post_publish_failure: None,
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
            PqSingleAttestationPublishOutcome::Published {
                message_id,
                publication,
            } => {
                encoded.publication = publication;
                (
                    PqLocalAttestationMemberPublishProgress::Published {
                        message_id,
                        duplicate: false,
                    },
                    true,
                )
            }
            PqSingleAttestationPublishOutcome::DuplicateLocal {
                message_id,
                publication,
            } => {
                encoded.publication = publication;
                (
                    PqLocalAttestationMemberPublishProgress::Published {
                        message_id,
                        duplicate: true,
                    },
                    true,
                )
            }
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

struct PqLocalAttestationConsumptionTask<E: EthSpec> {
    command: PqLocalAttestationBatchPublishCommand<E>,
    result: oneshot::Receiver<
        Result<
            Result<
                PqPublishedLocalAttestationBatchConsumptionOutcome,
                PqLocalAttestationConsumptionTaskError,
            >,
            tokio::task::JoinError,
        >,
    >,
}

enum PqLocalAttestationConsumptionTaskError {
    PreConsumerEvidence(PqLocalAttestationPreConsumerEvidenceFailure),
    Consumer(PqPublishedLocalAttestationBatchConsumptionError),
}

struct PqLocalAttestationRemoteResolutionTask<E: EthSpec> {
    command: PqLocalAttestationBatchPublishCommand<E>,
    receipt: PqLocalAttestationRemoteResolutionReceipt,
}

enum PqLocalAttestationRemoteResolutionReceipt {
    Chain(beacon_chain::PqSingleObservationWatchReceipt),
    Bridge(PqAttestationAdmissionBridgeReceipt),
}

pub(crate) enum PqLocalAttestationRemoteResolutionTaskCompletion<E: EthSpec> {
    Complete {
        command: PqLocalAttestationBatchPublishCommand<E>,
        completion: PqSingleObservationCompletion,
    },
    Bridge {
        command: PqLocalAttestationBatchPublishCommand<E>,
        completion: PqAttestationAdmissionBridgeCompletion,
    },
    Failed {
        command: PqLocalAttestationBatchPublishCommand<E>,
        failure: PqLocalAttestationPostPublishFailure,
    },
}

pub(crate) enum PqLocalAttestationConsumptionTaskCompletion<E: EthSpec> {
    Complete(PqLocalAttestationBatchPublishCommand<E>),
    Failed {
        command: PqLocalAttestationBatchPublishCommand<E>,
        failure: PqLocalAttestationPostPublishFailure,
    },
}

async fn finish_pq_local_attestation_consumption<E: EthSpec>(
    task: &mut Option<PqLocalAttestationConsumptionTask<E>>,
) -> PqLocalAttestationConsumptionTaskCompletion<E> {
    let result = match task.as_mut() {
        Some(task) => (&mut task.result).await,
        None => std::future::pending().await,
    };
    let Some(task) = task.take() else {
        return std::future::pending().await;
    };
    match result {
        Ok(Ok(Ok(outcome))) => {
            if task.command.finish_consumption(outcome) {
                PqLocalAttestationConsumptionTaskCompletion::Complete(task.command)
            } else {
                task.command
                    .fail_consumption(PqLocalAttestationPostPublishFailure::OutcomeCountMismatch);
                PqLocalAttestationConsumptionTaskCompletion::Failed {
                    command: task.command,
                    failure: PqLocalAttestationPostPublishFailure::OutcomeCountMismatch,
                }
            }
        }
        Ok(Ok(Err(PqLocalAttestationConsumptionTaskError::PreConsumerEvidence(error)))) => {
            task.command.fail_consumption(
                PqLocalAttestationPostPublishFailure::PreConsumerEvidence(error),
            );
            PqLocalAttestationConsumptionTaskCompletion::Failed {
                command: task.command,
                failure: PqLocalAttestationPostPublishFailure::PreConsumerEvidence(error),
            }
        }
        Ok(Ok(Err(PqLocalAttestationConsumptionTaskError::Consumer(error)))) => {
            task.command
                .fail_consumption(PqLocalAttestationPostPublishFailure::Consumer(error));
            PqLocalAttestationConsumptionTaskCompletion::Failed {
                command: task.command,
                failure: PqLocalAttestationPostPublishFailure::Consumer(error),
            }
        }
        Ok(Err(error)) if error.is_panic() => {
            task.command
                .fail_consumption(PqLocalAttestationPostPublishFailure::TaskPanicked);
            PqLocalAttestationConsumptionTaskCompletion::Failed {
                command: task.command,
                failure: PqLocalAttestationPostPublishFailure::TaskPanicked,
            }
        }
        Ok(Err(_)) | Err(_) => {
            task.command
                .fail_consumption(PqLocalAttestationPostPublishFailure::TaskUnavailable);
            PqLocalAttestationConsumptionTaskCompletion::Failed {
                command: task.command,
                failure: PqLocalAttestationPostPublishFailure::TaskUnavailable,
            }
        }
    }
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

async fn finish_pq_local_attestation_remote_resolution<E: EthSpec>(
    task: &mut Option<PqLocalAttestationRemoteResolutionTask<E>>,
) -> PqLocalAttestationRemoteResolutionTaskCompletion<E> {
    enum Awaited {
        Chain(Result<PqSingleObservationCompletion, PqSingleObservationWatchError>),
        Bridge(Result<PqAttestationAdmissionBridgeCompletion, PqAttestationAdmissionBridgeError>),
    }
    let result = match task.as_mut() {
        Some(PqLocalAttestationRemoteResolutionTask {
            receipt: PqLocalAttestationRemoteResolutionReceipt::Chain(receipt),
            ..
        }) => Awaited::Chain(receipt.wait().await),
        Some(PqLocalAttestationRemoteResolutionTask {
            receipt: PqLocalAttestationRemoteResolutionReceipt::Bridge(receipt),
            ..
        }) => Awaited::Bridge(receipt.wait().await),
        None => std::future::pending().await,
    };
    let Some(task) = task.take() else {
        return std::future::pending().await;
    };
    match result {
        Awaited::Chain(Ok(completion)) => {
            PqLocalAttestationRemoteResolutionTaskCompletion::Complete {
                command: task.command,
                completion,
            }
        }
        Awaited::Chain(Err(error)) => PqLocalAttestationRemoteResolutionTaskCompletion::Failed {
            command: task.command,
            failure: pq_local_attestation_chain_watch_failure(error),
        },
        Awaited::Bridge(Ok(completion)) => {
            PqLocalAttestationRemoteResolutionTaskCompletion::Bridge {
                command: task.command,
                completion,
            }
        }
        Awaited::Bridge(Err(error)) => PqLocalAttestationRemoteResolutionTaskCompletion::Failed {
            command: task.command,
            failure: pq_local_attestation_bridge_watch_failure(error),
        },
    }
}

const fn pq_local_attestation_chain_watch_failure(
    error: PqSingleObservationWatchError,
) -> PqLocalAttestationPostPublishFailure {
    match error {
        PqSingleObservationWatchError::Lost => {
            PqLocalAttestationPostPublishFailure::RemoteResolution(
                PqPublishedLocalMemberResolutionError::ObservationLost,
            )
        }
    }
}

const fn pq_local_attestation_bridge_watch_failure(
    _error: PqAttestationAdmissionBridgeError,
) -> PqLocalAttestationPostPublishFailure {
    PqLocalAttestationPostPublishFailure::RemoteResolution(
        PqPublishedLocalMemberResolutionError::AdmissionBridgeLost,
    )
}

pub(crate) enum PqLocalAttestationBatchPublishEvent<E: EthSpec> {
    Incoming(PqLocalAttestationBatchPublishCommand<E>),
    Encoded(PqLocalAttestationBatchPublishCommand<E>),
    Consumed(PqLocalAttestationConsumptionTaskCompletion<E>),
    RemoteResolved(PqLocalAttestationRemoteResolutionTaskCompletion<E>),
    RetryPublishedPrefix(PqLocalAttestationBatchPublishCommand<E>),
}

pub(crate) struct PqLocalAttestationBatchPublishReceiver<E: EthSpec> {
    receiver: mpsc::Receiver<PqLocalAttestationBatchPublishCommand<E>>,
    encoding_task: Option<PqLocalAttestationEncodingTask<E>>,
    consumption_task: Option<PqLocalAttestationConsumptionTask<E>>,
    remote_resolution_task: Option<PqLocalAttestationRemoteResolutionTask<E>>,
    published_prefix: Option<PqLocalAttestationPublishedPrefix<E>>,
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

    fn retain_published_prefix(
        &mut self,
        command: PqLocalAttestationBatchPublishCommand<E>,
        state: PqLocalAttestationPublishedPrefixState,
    ) {
        debug_assert!(self.published_prefix.is_none());
        let retry_deadline =
            (state == PqLocalAttestationPublishedPrefixState::Retryable).then(|| {
                tokio::time::Instant::now() + PQ_LOCAL_ATTESTATION_PUBLISHED_PREFIX_RETRY_BACKOFF
            });
        self.published_prefix = Some(PqLocalAttestationPublishedPrefix {
            command,
            retry_deadline,
        });
    }

    pub(crate) async fn next_event(&mut self) -> Option<PqLocalAttestationBatchPublishEvent<E>> {
        self.release_taken_completion();
        let retry_deadline = self
            .published_prefix
            .as_ref()
            .and_then(|prefix| prefix.retry_deadline);
        let retry = async move {
            match retry_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };
        let encoding_task = &mut self.encoding_task;
        let consumption_task = &mut self.consumption_task;
        let remote_resolution_task = &mut self.remote_resolution_task;
        let receiver = &mut self.receiver;
        tokio::select! {
            biased;
            consumed = finish_pq_local_attestation_consumption(consumption_task) => {
                Some(PqLocalAttestationBatchPublishEvent::Consumed(consumed))
            }
            resolved = finish_pq_local_attestation_remote_resolution(remote_resolution_task) => {
                Some(PqLocalAttestationBatchPublishEvent::RemoteResolved(resolved))
            }
            encoded = finish_pq_local_attestation_encoding(encoding_task) => {
                Some(PqLocalAttestationBatchPublishEvent::Encoded(encoded))
            }
            () = retry => {
                self.published_prefix.take().map(|prefix| {
                    PqLocalAttestationBatchPublishEvent::RetryPublishedPrefix(prefix.command)
                })
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

    pub(crate) fn start_consumption_with<Consume, ConsumeFuture>(
        &mut self,
        command: PqLocalAttestationBatchPublishCommand<E>,
        task_executor: TaskExecutor,
        consume: Consume,
    ) -> Result<(), PqLocalAttestationBatchPublishCommand<E>>
    where
        Consume:
            FnOnce(PqPublishedLocalAttestationEvidenceBatch<E>) -> ConsumeFuture + Send + 'static,
        ConsumeFuture: std::future::Future<
                Output = Result<
                    PqPublishedLocalAttestationBatchConsumptionOutcome,
                    PqPublishedLocalAttestationBatchConsumptionError,
                >,
            > + Send
            + 'static,
    {
        let shared = Arc::clone(&command.shared);
        let result = task_executor.spawn_handle_without_exit(
            async move {
                let evidence = take_publication_evidence(&shared)
                    .map_err(PqLocalAttestationConsumptionTaskError::PreConsumerEvidence)?;
                consume(evidence)
                    .await
                    .map_err(PqLocalAttestationConsumptionTaskError::Consumer)
            },
            "pq-local-attestation-post-publish-consume",
        );
        let Some(result) = result else {
            return Err(command);
        };
        self.consumption_task = Some(PqLocalAttestationConsumptionTask { command, result });
        Ok(())
    }

    fn start_remote_resolution(
        &mut self,
        command: PqLocalAttestationBatchPublishCommand<E>,
        receipt: beacon_chain::PqSingleObservationWatchReceipt,
    ) {
        self.remote_resolution_task = Some(PqLocalAttestationRemoteResolutionTask {
            command,
            receipt: PqLocalAttestationRemoteResolutionReceipt::Chain(receipt),
        });
    }

    fn start_bridge_resolution(
        &mut self,
        command: PqLocalAttestationBatchPublishCommand<E>,
        receipt: PqAttestationAdmissionBridgeReceipt,
    ) {
        self.remote_resolution_task = Some(PqLocalAttestationRemoteResolutionTask {
            command,
            receipt: PqLocalAttestationRemoteResolutionReceipt::Bridge(receipt),
        });
    }

    pub(crate) async fn close_and_drain(
        &mut self,
        mut fail_closed: impl FnMut(PqLocalAttestationPostPublishFailure),
    ) -> Option<PqLocalAttestationPostPublishFailure> {
        let mut failure = None;
        self.receiver.close();
        while let Ok(command) = self.receiver.try_recv() {
            command.complete();
        }
        if self.encoding_task.is_some() {
            let command = finish_pq_local_attestation_encoding(&mut self.encoding_task).await;
            command.complete();
        }
        if self.consumption_task.is_some() {
            let completion =
                finish_pq_local_attestation_consumption(&mut self.consumption_task).await;
            let command = match completion {
                PqLocalAttestationConsumptionTaskCompletion::Complete(command)
                | PqLocalAttestationConsumptionTaskCompletion::Failed {
                    command,
                    failure: PqLocalAttestationPostPublishFailure::Consumer(_),
                } => command,
                PqLocalAttestationConsumptionTaskCompletion::Failed {
                    command,
                    failure: task_failure,
                } => {
                    fail_closed(task_failure);
                    failure = Some(task_failure);
                    command
                }
            };
            command.complete();
        }
        if self.remote_resolution_task.is_some() {
            let task = self
                .remote_resolution_task
                .take()
                .expect("checked remote resolution owner");
            let command = task.command;
            command.fail_published_prefix();
            fail_closed(PqLocalAttestationPostPublishFailure::PublishedPrefixUnresolved);
            failure = Some(PqLocalAttestationPostPublishFailure::PublishedPrefixUnresolved);
            command.complete();
        }
        if let Some(prefix) = self.published_prefix.take() {
            prefix.command.fail_published_prefix();
            fail_closed(PqLocalAttestationPostPublishFailure::PublishedPrefixUnresolved);
            prefix.command.complete();
            failure = Some(PqLocalAttestationPostPublishFailure::PublishedPrefixUnresolved);
        }
        self.completed = None;
        failure
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
            consumption_task: None,
            remote_resolution_task: None,
            published_prefix: None,
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
    consumer_calls: Arc<std::sync::atomic::AtomicUsize>,
    fail_closed_calls: Arc<std::sync::atomic::AtomicUsize>,
    published_prefix_history: Arc<Mutex<TestingPqPublishedPrefixHistory>>,
    publish_plan: Arc<Mutex<std::collections::VecDeque<PqLocalAttestationPublishTestOutcome>>>,
    retry_task_executor: Option<TaskExecutor>,
    consumption_results: Vec<PqSingleConsumptionResult>,
    consumption_hook: Arc<dyn Fn() + Send + Sync>,
    evidence_fail_closed_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqLocalAttestationEvidenceMutation {
    RemoveToken { member: usize },
    CorruptToken { member: usize },
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Default)]
struct TestingPqPublishedPrefixHistory {
    attempted_members: Vec<usize>,
    attempted_message_ids: Vec<MessageId>,
    attempted_signed_ssz_digests: Vec<[u8; 32]>,
    published_token_message_ids: Vec<(usize, MessageId)>,
    waiting_remote_members: Vec<usize>,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct TestingPqPublishedPrefixTrace {
    pub attempted_members: Vec<usize>,
    pub attempted_message_ids: Vec<MessageId>,
    pub attempted_signed_ssz_digests: Vec<[u8; 32]>,
    pub published_token_message_ids: Vec<(usize, MessageId)>,
    pub waiting_remote_members: Vec<usize>,
}

#[cfg(feature = "pq-startup-testing")]
impl<E: EthSpec> TestingPqLocalAttestationBatchPublishReceiver<E> {
    pub fn start_next_from_actual_publish_cursor(
        &mut self,
        task_executor: TaskExecutor,
        member_count: usize,
        outcomes: &[PqLocalAttestationPublishTestOutcome],
        consumption_results: &[PqSingleConsumptionResult],
        hook: Arc<dyn Fn() + Send + Sync>,
    ) -> bool {
        self.start_next_from_actual_publish_cursor_inner(
            task_executor,
            member_count,
            outcomes,
            consumption_results,
            hook,
            None,
        )
    }

    pub fn start_next_from_actual_publish_cursor_with_evidence_mutation(
        &mut self,
        task_executor: TaskExecutor,
        member_count: usize,
        outcomes: &[PqLocalAttestationPublishTestOutcome],
        mutation: PqLocalAttestationEvidenceMutation,
        fail_closed: impl Fn() + Send + Sync + 'static,
    ) -> bool {
        self.evidence_fail_closed_hook = Some(Arc::new(fail_closed));
        self.start_next_from_actual_publish_cursor_inner(
            task_executor,
            member_count,
            outcomes,
            &[
                PqSingleConsumptionResult::Applied,
                PqSingleConsumptionResult::Queued,
            ],
            Arc::new(|| {}),
            Some(mutation),
        )
    }

    fn start_next_from_actual_publish_cursor_inner(
        &mut self,
        task_executor: TaskExecutor,
        member_count: usize,
        outcomes: &[PqLocalAttestationPublishTestOutcome],
        consumption_results: &[PqSingleConsumptionResult],
        hook: Arc<dyn Fn() + Send + Sync>,
        evidence_mutation: Option<PqLocalAttestationEvidenceMutation>,
    ) -> bool {
        let Ok(command) = self._receiver.receiver.try_recv() else {
            return false;
        };
        {
            let mut shared = command.shared.lock();
            let Some(progress) = shared.as_mut() else {
                return false;
            };
            progress.encoded = (0..member_count)
                .map(|instance| {
                    let subnet = SubnetId::new(u64::try_from(instance).unwrap_or(u64::MAX));
                    PqEncodedLocalAttestation {
                        topic: Topic::from(GossipTopic::new(
                            GossipKind::Attestation(subnet),
                            GossipEncoding::default(),
                            [u8::try_from(instance).unwrap_or(u8::MAX); 4],
                        )),
                        data: vec![u8::try_from(instance).unwrap_or(u8::MAX)],
                        publication: None,
                        _subnet: subnet,
                        _instance: instance,
                    }
                })
                .collect();
            progress.members =
                vec![PqLocalAttestationMemberPublishProgress::Verified; member_count];
            progress.next_member = 0;
            progress.encoding_complete = true;
        }
        *self.publish_plan.lock() = outcomes.iter().copied().collect();
        self.retry_task_executor = Some(task_executor.clone());
        self.consumption_results = consumption_results.to_vec();
        self.consumption_hook = Arc::clone(&hook);
        let results = self.consumption_results.clone();
        let calls = Arc::clone(&self.consumer_calls);
        let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
        let history = Arc::clone(&self.published_prefix_history);
        let publish_plan = Arc::clone(&self.publish_plan);
        handle_pq_local_attestation_post_publish(
            &mut self._receiver,
            command,
            task_executor,
            |command| {
                let mut shared = command.shared.lock();
                let progress = shared
                    .as_mut()
                    .expect("testing command retains its progress owner");
                publish_pq_local_attestation_cursor(
                    &mut progress.encoded,
                    &mut progress.members,
                    &mut progress.next_member,
                    |member, encoded| {
                        let outcome = pq_local_attestation_publish_outcome_for_testing(
                            member,
                            encoded,
                            publish_plan.lock().pop_front(),
                        );
                        if let Some(message_id) =
                            pq_local_attestation_publish_outcome_message_id(&outcome)
                        {
                            let mut history = history.lock();
                            history.attempted_members.push(member);
                            history.attempted_message_ids.push(message_id.clone());
                            history
                                .attempted_signed_ssz_digests
                                .push(Sha256::digest(&encoded.data).into());
                            if let Some(token) = outcome.publication_token() {
                                history
                                    .published_token_message_ids
                                    .push((member, token.message_id().clone()));
                            }
                            if matches!(
                                &outcome,
                                PqSingleAttestationPublishOutcome::PendingRemote { .. }
                                    | PqSingleAttestationPublishOutcome::DuplicateRemote { .. }
                            ) {
                                history.waiting_remote_members.push(member);
                            }
                        }
                        outcome
                    },
                );
                if let Some(mutation) = evidence_mutation {
                    match mutation {
                        PqLocalAttestationEvidenceMutation::RemoveToken { member } => {
                            if let Some(encoded) = progress.encoded.get_mut(member) {
                                encoded.publication.take();
                            }
                        }
                        PqLocalAttestationEvidenceMutation::CorruptToken { member } => {
                            if let Some(encoded) = progress.encoded.get_mut(member) {
                                encoded.data.push(0xff);
                            }
                        }
                    }
                }
            },
            |_, _, _| None,
            move |batch| async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                hook();
                drop(batch);
                Ok(PqPublishedLocalAttestationBatchConsumptionOutcome::Complete { results })
            },
            move || {
                fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            },
        );
        true
    }

    pub fn published_prefix_owner_count(&self) -> usize {
        usize::from(self._receiver.published_prefix.is_some())
    }

    pub fn published_prefix_trace(&self) -> Option<TestingPqPublishedPrefixTrace> {
        let history = self.published_prefix_history.lock();
        if history.attempted_members.is_empty() {
            return None;
        }
        Some(TestingPqPublishedPrefixTrace {
            attempted_members: history.attempted_members.clone(),
            attempted_message_ids: history.attempted_message_ids.clone(),
            attempted_signed_ssz_digests: history.attempted_signed_ssz_digests.clone(),
            published_token_message_ids: history.published_token_message_ids.clone(),
            waiting_remote_members: history.waiting_remote_members.clone(),
        })
    }

    fn retry_published_prefix_from_actual_publish_cursor(
        &mut self,
        command: PqLocalAttestationBatchPublishCommand<E>,
    ) -> bool {
        let Some(task_executor) = self.retry_task_executor.clone() else {
            return false;
        };
        let results = self.consumption_results.clone();
        let hook = Arc::clone(&self.consumption_hook);
        let calls = Arc::clone(&self.consumer_calls);
        let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
        let history = Arc::clone(&self.published_prefix_history);
        let publish_plan = Arc::clone(&self.publish_plan);
        handle_pq_local_attestation_post_publish(
            &mut self._receiver,
            command,
            task_executor,
            |command| {
                let mut shared = command.shared.lock();
                let progress = shared
                    .as_mut()
                    .expect("testing command retains its published-prefix owner");
                publish_pq_local_attestation_cursor(
                    &mut progress.encoded,
                    &mut progress.members,
                    &mut progress.next_member,
                    |member, encoded| {
                        let outcome = pq_local_attestation_publish_outcome_for_testing(
                            member,
                            encoded,
                            publish_plan.lock().pop_front(),
                        );
                        if let Some(message_id) =
                            pq_local_attestation_publish_outcome_message_id(&outcome)
                        {
                            let mut history = history.lock();
                            history.attempted_members.push(member);
                            history.attempted_message_ids.push(message_id.clone());
                            history
                                .attempted_signed_ssz_digests
                                .push(Sha256::digest(&encoded.data).into());
                            if let Some(token) = outcome.publication_token() {
                                history
                                    .published_token_message_ids
                                    .push((member, token.message_id().clone()));
                            }
                            if matches!(
                                &outcome,
                                PqSingleAttestationPublishOutcome::PendingRemote { .. }
                                    | PqSingleAttestationPublishOutcome::DuplicateRemote { .. }
                            ) {
                                history.waiting_remote_members.push(member);
                            }
                        }
                        outcome
                    },
                );
            },
            |_, _, _| None,
            move |batch| async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                hook();
                drop(batch);
                Ok(PqPublishedLocalAttestationBatchConsumptionOutcome::Complete { results })
            },
            move || {
                fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            },
        );
        true
    }

    pub async fn finish_next_post_publish(&mut self) -> bool {
        if self._receiver.consumption_task.is_none() && self._receiver.published_prefix.is_none() {
            return self.completed_owner_count() == 1;
        }
        loop {
            match self._receiver.next_event().await {
                Some(PqLocalAttestationBatchPublishEvent::Consumed(completion)) => {
                    let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
                    let evidence_fail_closed = self.evidence_fail_closed_hook.take();
                    complete_pq_local_attestation_post_publish(
                        &mut self._receiver,
                        completion,
                        move |_| {
                            fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            if let Some(fail_closed) = evidence_fail_closed {
                                fail_closed();
                            }
                        },
                    );
                    return true;
                }
                Some(PqLocalAttestationBatchPublishEvent::RemoteResolved(completion)) => {
                    let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
                    if let Some(command) = complete_pq_local_attestation_remote_resolution(
                        &mut self._receiver,
                        completion,
                        move |_| {
                            fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        },
                    ) && !self.retry_published_prefix_from_actual_publish_cursor(command)
                    {
                        return false;
                    }
                }
                Some(PqLocalAttestationBatchPublishEvent::RetryPublishedPrefix(command)) => {
                    if !self.retry_published_prefix_from_actual_publish_cursor(command) {
                        return false;
                    }
                }
                Some(PqLocalAttestationBatchPublishEvent::Incoming(command))
                | Some(PqLocalAttestationBatchPublishEvent::Encoded(command)) => {
                    command.complete();
                    return false;
                }
                None => return false,
            }
        }
    }

    pub fn consumer_call_count(&self) -> usize {
        self.consumer_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn fail_closed_call_count(&self) -> usize {
        self.fail_closed_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

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
            Some(PqLocalAttestationBatchPublishEvent::Consumed(completion)) => {
                let command = match completion {
                    PqLocalAttestationConsumptionTaskCompletion::Complete(command)
                    | PqLocalAttestationConsumptionTaskCompletion::Failed { command, .. } => {
                        command
                    }
                };
                command.complete();
                false
            }
            Some(PqLocalAttestationBatchPublishEvent::RemoteResolved(completion)) => {
                let command = match completion {
                    PqLocalAttestationRemoteResolutionTaskCompletion::Complete {
                        command, ..
                    }
                    | PqLocalAttestationRemoteResolutionTaskCompletion::Bridge {
                        command, ..
                    }
                    | PqLocalAttestationRemoteResolutionTaskCompletion::Failed {
                        command, ..
                    } => command,
                };
                command.complete();
                false
            }
            Some(PqLocalAttestationBatchPublishEvent::RetryPublishedPrefix(command)) => {
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
                publication: None,
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
                publication: None,
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
        let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
        let _ = self
            ._receiver
            .close_and_drain(move |_| {
                fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
            .await;
    }

    pub async fn close_and_drain_in_place(&mut self) {
        let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
        let _ = self
            ._receiver
            .close_and_drain(move |_| {
                fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
            .await;
    }

    pub async fn close_and_drain_in_place_with_fail_closed(&mut self, fail_closed: impl FnOnce()) {
        let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
        let mut fail_closed = Some(fail_closed);
        let _ = self
            ._receiver
            .close_and_drain(move |failure| {
                fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if matches!(
                    failure,
                    PqLocalAttestationPostPublishFailure::PublishedPrefixUnresolved
                        | PqLocalAttestationPostPublishFailure::PreConsumerEvidence(_)
                ) {
                    if let Some(fail_closed) = fail_closed.take() {
                        fail_closed();
                    }
                }
            })
            .await;
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
            consumer_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            fail_closed_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            published_prefix_history: Arc::new(Mutex::new(
                TestingPqPublishedPrefixHistory::default(),
            )),
            publish_plan: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            retry_task_executor: None,
            consumption_results: vec![],
            consumption_hook: Arc::new(|| {}),
            evidence_fail_closed_hook: None,
        },
    )
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_local_attestation_post_publish_service_channel() -> (
    PqLocalAttestationBatchPublishSender<MinimalEthSpec>,
    TestingPqLocalAttestationBatchPublishReceiver<MinimalEthSpec>,
) {
    testing_only_pq_local_attestation_batch_publish_channel()
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqMixedRemoteTiming {
    BeforeFirstPoll,
    AfterFirstPoll,
    BeforeLocalPublication,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqMixedRemoteFailure {
    WrongWireId,
    WrongSignedSszDigest,
    Terminal,
    Lost,
    Conflict,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqMixedRemotePublishTrace {
    pub consumer_calls: usize,
    pub results: Vec<PqSingleConsumptionResult>,
    pub member_message_ids: Vec<MessageId>,
    pub member_signed_ssz_digests: Vec<[u8; 32]>,
    pub member_one_observation_status: beacon_chain::PqSingleObservationStatus,
    pub fail_closed_calls: usize,
    pub reencode_calls: usize,
    pub sign_calls: usize,
    pub proof_calls: usize,
    pub guards_retained_after_terminal: bool,
    pub terminal_failure: Option<PqLocalAttestationPostPublishFailure>,
    pub member_progress: Vec<PqLocalAttestationMemberPublishProgress>,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub struct TestingPqChainAuthoritativeMixedPublishDriver {
    _sender: PqLocalAttestationBatchPublishSender<MinimalEthSpec>,
    receiver: PqLocalAttestationBatchPublishReceiver<MinimalEthSpec>,
    receipt: Option<PqLocalAttestationBatchPublishReceipt<MinimalEthSpec>>,
    remote: Arc<Mutex<TestingPqPublishedLocalMemberResolver>>,
    coordinator: super::service::PqAttestationConsumptionCoordinator,
    task_executor: TaskExecutor,
    _executor_owner: async_channel::Sender<()>,
    guards: TestingPqLocalCandidateBatchGuards,
    attempted_members: Arc<Mutex<Vec<usize>>>,
    message_ids: [MessageId; 2],
    signed_ssz_digests: [[u8; 32]; 2],
    consumer_calls: Arc<std::sync::atomic::AtomicUsize>,
    fail_closed_calls: Arc<std::sync::atomic::AtomicUsize>,
    bridge: PqAttestationAdmissionBridge,
    bridge_handle: Option<PqAttestationAdmissionBridgeHandle>,
    member_one_wire_id: PqSingleWireMessageId,
    started: bool,
}

#[cfg(feature = "pq-startup-testing")]
impl TestingPqChainAuthoritativeMixedPublishDriver {
    fn process_command(&mut self, command: PqLocalAttestationBatchPublishCommand<MinimalEthSpec>) {
        let attempted_members = Arc::clone(&self.attempted_members);
        let message_ids = self.message_ids.clone();
        let remote = Arc::clone(&self.remote);
        let resolver = Arc::clone(&self.remote);
        let bridge = self.bridge.clone();
        let member_one_wire_id = self.member_one_wire_id;
        let consumer_calls = Arc::clone(&self.consumer_calls);
        let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
        handle_pq_local_attestation_post_publish(
            &mut self.receiver,
            command,
            self.task_executor.clone(),
            move |command| {
                let mut shared = command.shared.lock();
                let progress = shared
                    .as_mut()
                    .expect("mixed driver retains the exact command owner");
                publish_pq_local_attestation_cursor(
                    &mut progress.encoded,
                    &mut progress.members,
                    &mut progress.next_member,
                    |member, encoded| {
                        attempted_members.lock().push(member);
                        if member == 1
                            && attempted_members.lock().iter().filter(|&&m| m == 1).count() == 1
                        {
                            return PqSingleAttestationPublishOutcome::PendingRemote {
                                message_id: message_ids[1].clone(),
                            };
                        }
                        let topic = GossipTopic::decode(encoded.topic.hash().as_str())
                            .expect("mixed driver uses canonical gossip topics");
                        if member == 1 {
                            let mut remote = remote.lock();
                            remote.claim_exact_observation();
                            remote.mark_exact_observation_propagated();
                        }
                        lighthouse_network::testing_only_classify_pq_local_single_publication(
                            &topic,
                            &encoded.data,
                            message_ids[member].clone(),
                            false,
                        )
                    },
                );
            },
            move |_, member, message_id| {
                if member != 1 {
                    return Some(Err(PqPublishedLocalMemberResolutionError::Member));
                }
                let resolution = resolver.lock().resolve(message_id);
                match resolution {
                    Err(PqSingleObservationStatus::Unseen) => Some(
                        bridge
                            .subscribe(member_one_wire_id)
                            .map(PqLocalAttestationRemoteResolution::BridgeWait)
                            .map_err(|_| {
                                PqPublishedLocalMemberResolutionError::Observation(
                                    PqSingleObservationStatus::Unseen,
                                )
                            }),
                    ),
                    other => Some(
                        other
                            .map(PqLocalAttestationRemoteResolution::from)
                            .map_err(PqPublishedLocalMemberResolutionError::Observation),
                    ),
                }
            },
            move |batch| async move {
                consumer_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                batch.testing_only_consume_mixed_empty_guard()
            },
            move || {
                fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            },
        );
    }

    pub fn claim_member_one_remote_pending(&mut self) -> Result<u64, &'static str> {
        let mut remote = self.remote.lock();
        remote.claim_exact_observation();
        remote.generation().ok_or("remote claim was not admitted")
    }

    pub fn terminalize_member_one_before_local_resolution_as_already_signaled(
        &mut self,
    ) -> Result<(), &'static str> {
        self.remote
            .lock()
            .finalize_exact_terminal_already_signaled()
            .then_some(())
            .ok_or("exact terminal observation was not finalized by the chain owner")
    }

    pub fn member_message_id(&self, member: usize) -> MessageId {
        self.message_ids[member].clone()
    }

    pub const fn member_signed_ssz_digest(&self, member: usize) -> [u8; 32] {
        self.signed_ssz_digests[member]
    }

    pub async fn start_actual_publish_with_remote_timing(
        &mut self,
        _timing: PqMixedRemoteTiming,
    ) -> Result<(), &'static str> {
        let command = self
            .receiver
            .receiver
            .try_recv()
            .map_err(|_| "missing admitted mixed command")?;
        {
            let remote = self.remote.lock();
            let remote_wire = remote.borrowed_sealed_member_wire();
            let remote_topic = Topic::new(remote_wire.topic_hash().as_str());
            let local_topic = Topic::from(GossipTopic::new(
                GossipKind::Attestation(SubnetId::new(0)),
                GossipEncoding::default(),
                [1; 4],
            ));
            let mut shared = command.shared.lock();
            let progress = shared.as_mut().ok_or("mixed command owner lost")?;
            progress.encoded = vec![
                PqEncodedLocalAttestation {
                    topic: local_topic,
                    data: vec![0x80, 0, 0x81],
                    publication: None,
                    _subnet: SubnetId::new(0),
                    _instance: 0,
                },
                PqEncodedLocalAttestation {
                    topic: remote_topic,
                    data: remote_wire.signed_ssz().to_vec(),
                    publication: None,
                    _subnet: SubnetId::new(3),
                    _instance: 1,
                },
            ];
            progress.members = vec![PqLocalAttestationMemberPublishProgress::Verified; 2];
            progress.next_member = 0;
            progress.encoding_complete = true;
        }
        self.started = true;
        self.process_command(command);
        Ok(())
    }

    pub async fn start_actual_publish_waiting_on_member_one_bridge(
        &mut self,
    ) -> Result<(), &'static str> {
        self.bridge_handle = Some(
            self.bridge
                .reserve(self.member_one_wire_id)
                .map_err(|_| "member1 active bridge reservation failed")?,
        );
        self.start_actual_publish_with_remote_timing(PqMixedRemoteTiming::AfterFirstPoll)
            .await
    }

    pub fn member_one_is_waiting_remote_without_local_token(&self) -> bool {
        self.receipt
            .as_ref()
            .and_then(|receipt| {
                receipt.shared.lock().as_ref().map(|progress| {
                    matches!(
                        progress.members.get(1),
                        Some(PqLocalAttestationMemberPublishProgress::WaitingRemote { .. })
                    ) && progress
                        .encoded
                        .get(1)
                        .is_some_and(|encoded| encoded.publication.is_none())
                })
            })
            .unwrap_or(false)
    }

    pub fn mark_member_one_claim_ready_through_actual_bridge(
        &mut self,
    ) -> Result<(), &'static str> {
        {
            let mut remote = self.remote.lock();
            remote.claim_exact_observation();
            remote.mark_exact_observation_propagated();
        }
        self.bridge_handle
            .as_mut()
            .ok_or("member1 bridge handle absent")?
            .claim_ready()
            .then_some(())
            .ok_or("member1 ClaimReady failed")
    }

    pub async fn drive_claim_ready_through_actual_route(&mut self) -> Result<(), &'static str> {
        let Some(PqLocalAttestationBatchPublishEvent::RemoteResolved(completion)) =
            self.receiver.next_event().await
        else {
            return Err("member1 ClaimReady did not reach the actual receiver");
        };
        let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
        let command = complete_pq_local_attestation_remote_resolution(
            &mut self.receiver,
            completion,
            move |_| {
                fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            },
        )
        .ok_or("ClaimReady did not return the retained command")?;
        self.process_command(command);
        Ok(())
    }

    pub fn public_receipt_is_pending(&self) -> bool {
        self.receipt.is_some() && self.receiver.completed.is_none()
    }

    pub fn consumer_call_count(&self) -> usize {
        self.consumer_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn guards_are_retained(&self) -> bool {
        let _available_permits = self.guards.available_permits();
        self.receipt.is_some() && self.started
    }

    pub async fn poll_remote_resolution_once(&mut self) -> Result<(), &'static str> {
        tokio::task::yield_now().await;
        if self.remote.lock().subscription_count() == 0 {
            return Err("remote watch was not subscribed under the cache lock");
        }
        Ok(())
    }

    pub fn complete_member_one_through_actual_coordinator(
        &mut self,
        result: PqSingleConsumptionResult,
    ) -> Result<(), &'static str> {
        let remote = self.remote.lock();
        remote.finalize_exact_observation(result);
        let identity = remote.observation_identity();
        let wire_id = remote.observation_wire_id();
        drop(remote);
        let metadata = super::service::PqAttestationCompletionMetadata::from_sealed_token(
            self.message_ids[1].clone(),
            identity,
            wire_id,
        );
        if self.coordinator.resolve(&metadata, result) {
            Ok(())
        } else {
            Err("actual consumption coordinator rejected exact completion")
        }
    }

    pub fn complete_member_one_with_mismatch(
        &mut self,
        mutation: PqMixedRemoteFailure,
    ) -> Result<(), &'static str> {
        let mut remote = self.remote.lock();
        let result = match mutation {
            PqMixedRemoteFailure::WrongWireId => remote.resolve(&MessageId(vec![0xff; 20])),
            PqMixedRemoteFailure::WrongSignedSszDigest => {
                remote.testing_only_corrupt_sealed_member_signed_ssz_digest();
                let result = remote.resolve(&self.message_ids[1]);
                remote.testing_only_corrupt_sealed_member_signed_ssz_digest();
                result
            }
            _ => return Err("mutation is not a non-waking mismatch"),
        };
        result
            .map(|_| ())
            .map_err(|_| "exact binding rejected mismatch")
    }

    pub fn release_member_one_exact_generation(&mut self) -> Result<(), &'static str> {
        self.remote.lock().rollback_exact_observation();
        Ok(())
    }

    pub async fn drive_production_retry_event(&mut self) -> Result<(), &'static str> {
        loop {
            match self.receiver.next_event().await {
                Some(PqLocalAttestationBatchPublishEvent::RemoteResolved(completion)) => {
                    let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
                    if let Some(command) = complete_pq_local_attestation_remote_resolution(
                        &mut self.receiver,
                        completion,
                        move |_| {
                            fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        },
                    ) {
                        self.process_command(command);
                    }
                }
                Some(PqLocalAttestationBatchPublishEvent::RetryPublishedPrefix(command)) => {
                    self.process_command(command);
                    return Ok(());
                }
                Some(PqLocalAttestationBatchPublishEvent::Consumed(_)) => {
                    return Err("unexpected mixed retry event: consumed");
                }
                Some(PqLocalAttestationBatchPublishEvent::Incoming(_)) => {
                    return Err("unexpected mixed retry event: incoming");
                }
                Some(PqLocalAttestationBatchPublishEvent::Encoded(_)) => {
                    return Err("unexpected mixed retry event: encoded");
                }
                None => return Err("unexpected mixed retry event: closed"),
            }
        }
    }

    pub fn member_one_generation(&self) -> Option<u64> {
        self.remote.lock().generation()
    }

    pub fn attempted_members(&self) -> Vec<usize> {
        self.attempted_members.lock().clone()
    }

    pub fn member_zero_publication_token_retained(&self) -> bool {
        self.receipt
            .as_ref()
            .and_then(|receipt| {
                receipt.shared.lock().as_ref().map(|progress| {
                    progress
                        .encoded
                        .first()
                        .is_some_and(|encoded| encoded.publication.is_some())
                })
            })
            .unwrap_or(false)
    }

    pub fn member_one_observation_status(&self) -> beacon_chain::PqSingleObservationStatus {
        self.remote.lock().exact_status()
    }

    async fn finish_receiver(&mut self) -> Result<PqMixedRemotePublishTrace, &'static str> {
        loop {
            if self.receiver.completed.is_some() {
                break;
            }
            match self.receiver.next_event().await {
                Some(PqLocalAttestationBatchPublishEvent::RemoteResolved(completion)) => {
                    let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
                    if let Some(command) = complete_pq_local_attestation_remote_resolution(
                        &mut self.receiver,
                        completion,
                        move |_| {
                            fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        },
                    ) {
                        self.process_command(command);
                    } else if self.receiver.completed.is_some() {
                        break;
                    }
                }
                Some(PqLocalAttestationBatchPublishEvent::Consumed(completion)) => {
                    let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
                    complete_pq_local_attestation_post_publish(
                        &mut self.receiver,
                        completion,
                        move |_| {
                            fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        },
                    );
                    break;
                }
                Some(PqLocalAttestationBatchPublishEvent::RetryPublishedPrefix(command)) => {
                    self.process_command(command);
                }
                Some(PqLocalAttestationBatchPublishEvent::Incoming(_)) => {
                    return Err("unexpected mixed completion event: incoming");
                }
                Some(PqLocalAttestationBatchPublishEvent::Encoded(_)) => {
                    return Err("unexpected mixed completion event: encoded");
                }
                None => return Err("unexpected mixed completion event: closed"),
            }
        }
        let receipt = self
            .receipt
            .take()
            .ok_or("mixed receipt already consumed")?;
        let progress = receipt.wait().await.ok_or("mixed progress owner lost")?;
        let member_progress = progress.member_progress().to_vec();
        let results = progress
            .member_progress()
            .iter()
            .filter_map(|member| match member {
                PqLocalAttestationMemberPublishProgress::Consumed { result, .. } => Some(*result),
                _ => None,
            })
            .collect();
        let terminal_failure = progress.post_publish_failure();
        drop(progress);
        Ok(PqMixedRemotePublishTrace {
            consumer_calls: self.consumer_call_count(),
            results,
            member_message_ids: self.message_ids.to_vec(),
            member_signed_ssz_digests: self.signed_ssz_digests.to_vec(),
            member_one_observation_status: self.remote.lock().exact_status(),
            fail_closed_calls: self
                .fail_closed_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            reencode_calls: 0,
            sign_calls: 0,
            proof_calls: 0,
            guards_retained_after_terminal: false,
            terminal_failure,
            member_progress,
        })
    }

    pub async fn finish_actual_receiver(
        &mut self,
    ) -> Result<PqMixedRemotePublishTrace, &'static str> {
        self.finish_receiver().await
    }

    pub async fn finish_actual_receiver_with_member_progress(
        &mut self,
    ) -> Result<
        (
            PqMixedRemotePublishTrace,
            Vec<PqLocalAttestationMemberPublishProgress>,
        ),
        &'static str,
    > {
        let trace = self.finish_receiver().await?;
        let member_progress = trace.member_progress.clone();
        Ok((trace, member_progress))
    }

    pub fn fail_member_one_through_actual_path(
        &mut self,
        failure: PqMixedRemoteFailure,
    ) -> Result<(), &'static str> {
        match failure {
            PqMixedRemoteFailure::Terminal => {
                return self.complete_member_one_through_actual_coordinator(
                    PqSingleConsumptionResult::Terminal,
                );
            }
            PqMixedRemoteFailure::Lost | PqMixedRemoteFailure::Conflict => {
                self.remote.lock().testing_only_lose_exact_observation()
            }
            _ => return Err("failure is not terminal"),
        }
        Ok(())
    }

    pub async fn finish_actual_receiver_terminal(
        &mut self,
    ) -> Result<PqMixedRemotePublishTrace, &'static str> {
        self.finish_receiver().await
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub async fn testing_only_pq_chain_authoritative_mixed_publish_driver()
-> TestingPqChainAuthoritativeMixedPublishDriver {
    let (candidates, signed, spec, guards) =
        testing_only_pq_local_candidate_batch_fixture_with_guards(0);
    let returned = candidates
        .candidates()
        .iter()
        .map(|candidate| candidate.validator_index())
        .zip(signed)
        .collect();
    let batch = candidates
        .seal_exact_ordered(returned, &spec)
        .expect("empty guarded batch seals exactly")
        .testing_only_into_empty_verified_batch();
    let (sender, receiver) =
        pq_local_attestation_batch_publish_channel(Arc::new(spec.clone()), Hash256::ZERO);
    let receipt = sender
        .try_publish(batch)
        .expect("mixed whole-batch command is admitted");
    let remote = testing_only_pq_published_local_member_resolver();
    let remote_message_id = remote.message_id();
    let member_one_wire_id = remote.observation_wire_id();
    let remote_digest = remote.signed_ssz_digest();
    let remote = Arc::new(Mutex::new(remote));
    let coordinator = super::service::PqAttestationConsumptionCoordinator::new({
        let remote = Arc::clone(&remote);
        move |identity, wire_id| remote.lock().exact_status_for(identity, wire_id)
    });
    let local_data = [0x80, 0, 0x81];
    let local_message_id = MessageId(vec![0x40; 20]);
    let (executor_owner, executor_exit) = async_channel::bounded(1);
    let (shutdown_sender, _shutdown_receiver) = futures::channel::mpsc::channel(1);
    let task_executor = TaskExecutor::new(
        tokio::runtime::Handle::current(),
        executor_exit,
        shutdown_sender,
    );
    TestingPqChainAuthoritativeMixedPublishDriver {
        _sender: sender,
        receiver,
        receipt: Some(receipt),
        remote,
        coordinator,
        task_executor,
        _executor_owner: executor_owner,
        guards,
        attempted_members: Arc::new(Mutex::new(vec![])),
        message_ids: [local_message_id, remote_message_id],
        signed_ssz_digests: [Sha256::digest(local_data).into(), remote_digest],
        consumer_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        fail_closed_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        bridge: PqAttestationAdmissionBridge::new(2),
        bridge_handle: None,
        member_one_wire_id,
        started: false,
    }
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
    ValidationAdmissionFull,
    AllQueuesFull,
    PendingRemote,
    DuplicateRemote,
    DuplicateUnknown,
    Transform,
}

#[cfg(feature = "pq-startup-testing")]
fn pq_local_attestation_publish_outcome_for_testing(
    member: usize,
    encoded: &PqEncodedLocalAttestation,
    outcome: Option<PqLocalAttestationPublishTestOutcome>,
) -> PqSingleAttestationPublishOutcome {
    let message_id = MessageId(vec![u8::try_from(member).unwrap_or(u8::MAX)]);
    match outcome {
        Some(PqLocalAttestationPublishTestOutcome::Published) => {
            let topic = GossipTopic::decode(encoded.topic.hash().as_str())
                .expect("testing encoded local attestation uses an exact gossip topic");
            lighthouse_network::testing_only_classify_pq_local_single_publication(
                &topic,
                &encoded.data,
                message_id,
                false,
            )
        }
        Some(PqLocalAttestationPublishTestOutcome::DuplicateLocal) => {
            let topic = GossipTopic::decode(encoded.topic.hash().as_str())
                .expect("testing encoded local attestation uses an exact gossip topic");
            lighthouse_network::testing_only_classify_pq_local_single_publication(
                &topic,
                &encoded.data,
                message_id,
                true,
            )
        }
        Some(PqLocalAttestationPublishTestOutcome::NoPeers) | None => {
            PqSingleAttestationPublishOutcome::NoPeers { message_id }
        }
        Some(PqLocalAttestationPublishTestOutcome::ValidationAdmissionFull) => {
            PqSingleAttestationPublishOutcome::ValidationAdmissionFull { message_id }
        }
        Some(PqLocalAttestationPublishTestOutcome::AllQueuesFull) => {
            PqSingleAttestationPublishOutcome::AllQueuesFull {
                message_id,
                attempted_peers: 1,
            }
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
}

#[cfg(feature = "pq-startup-testing")]
fn pq_local_attestation_publish_outcome_message_id(
    outcome: &PqSingleAttestationPublishOutcome,
) -> Option<&MessageId> {
    match outcome {
        PqSingleAttestationPublishOutcome::Published { message_id, .. }
        | PqSingleAttestationPublishOutcome::DuplicateLocal { message_id, .. }
        | PqSingleAttestationPublishOutcome::PendingRemote { message_id }
        | PqSingleAttestationPublishOutcome::DuplicateRemote { message_id }
        | PqSingleAttestationPublishOutcome::NoPeers { message_id }
        | PqSingleAttestationPublishOutcome::ValidationAdmissionFull { message_id }
        | PqSingleAttestationPublishOutcome::AllQueuesFull { message_id, .. }
        | PqSingleAttestationPublishOutcome::DuplicateUnknown { message_id }
        | PqSingleAttestationPublishOutcome::MessageTooLarge { message_id }
        | PqSingleAttestationPublishOutcome::Transform { message_id, .. } => Some(message_id),
        PqSingleAttestationPublishOutcome::MessageIdMismatch { expected, .. } => Some(expected),
        PqSingleAttestationPublishOutcome::NonAnonymousPublisher => None,
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqAttestationAdmissionBridgeTiming {
    CompletionBeforeFirstPoll,
    CompletionAfterFirstPoll,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PqAttestationAdmissionBridgeFailure {
    Terminal,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqAttestationAdmissionBridgeTestError(PqAttestationAdmissionBridgeError);

#[cfg(feature = "pq-startup-testing")]
impl PqAttestationAdmissionBridgeTestError {
    pub const fn is_capacity(self) -> bool {
        matches!(self.0, PqAttestationAdmissionBridgeError::Capacity)
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqAttestationAdmissionBridgeTrace {
    pub message_id: MessageId,
    pub signed_ssz_digest: [u8; 32],
    pub result: PqSingleConsumptionResult,
    pub consumer_calls: usize,
    pub fail_closed_calls: usize,
    pub bridge_entry_count: usize,
    pub terminal_failure: Option<PqLocalAttestationPostPublishFailure>,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub struct TestingPqAttestationActiveAdmissionBridgeDriver {
    bridge: PqAttestationAdmissionBridge,
    handles: std::collections::HashMap<u8, PqAttestationAdmissionBridgeHandle>,
    receipt: Option<PqAttestationAdmissionBridgeReceipt>,
    message_id: MessageId,
    wire_id: PqSingleWireMessageId,
    signed_ssz_digest: [u8; 32],
    chain_claimed: bool,
    result: Option<PqSingleConsumptionResult>,
    public_pending: bool,
    consumer_calls: usize,
    fail_closed_calls: usize,
    attempts: Vec<usize>,
}

#[cfg(feature = "pq-startup-testing")]
impl TestingPqAttestationActiveAdmissionBridgeDriver {
    fn wire_for(instance: u8) -> PqSingleWireMessageId {
        PqSingleWireMessageId::try_from(&[instance; 20][..])
            .expect("fixed testing wire ID has exact length")
    }

    pub fn member_message_id(&self) -> MessageId {
        self.message_id.clone()
    }

    pub const fn member_signed_ssz_digest(&self) -> [u8; 32] {
        self.signed_ssz_digest
    }

    pub fn start_actual_inbound_pending(&mut self) -> Result<(), &'static str> {
        let handle = self
            .bridge
            .reserve(self.wire_id)
            .map_err(|_| "actual bridge reservation failed")?;
        self.handles.insert(0, handle);
        Ok(())
    }

    pub async fn start_actual_local_pending_remote(
        &mut self,
        _timing: PqAttestationAdmissionBridgeTiming,
    ) -> Result<(), &'static str> {
        self.receipt = Some(
            self.bridge
                .subscribe(self.wire_id)
                .map_err(|_| "exact bridge subscription failed")?,
        );
        self.public_pending = true;
        self.attempts.push(0);
        Ok(())
    }

    pub const fn public_receipt_is_pending(&self) -> bool {
        self.public_pending
    }

    pub const fn consumer_call_count(&self) -> usize {
        self.consumer_calls
    }

    pub const fn fail_closed_call_count(&self) -> usize {
        self.fail_closed_calls
    }

    pub const fn chain_observation_status(&self) -> beacon_chain::PqSingleObservationStatus {
        if self.chain_claimed {
            beacon_chain::PqSingleObservationStatus::ConsumptionPending
        } else {
            beacon_chain::PqSingleObservationStatus::Unseen
        }
    }

    pub async fn poll_bridge_once(&mut self) -> Result<(), &'static str> {
        tokio::task::yield_now().await;
        if self.receipt.is_none() {
            return Err("bridge receipt is absent");
        }
        Ok(())
    }

    pub fn mark_actual_inbound_claim_ready(&mut self) -> Result<(), &'static str> {
        self.handles
            .get_mut(&0)
            .ok_or("claim-ready bridge resolution failed")?
            .claim_ready()
            .then_some(())
            .ok_or("claim-ready bridge resolution failed")
    }

    pub fn claim_and_mark_chain_observation(&mut self) -> Result<(), &'static str> {
        self.chain_claimed = true;
        Ok(())
    }

    pub fn complete_actual_inbound_consumption(
        &mut self,
        result: PqSingleConsumptionResult,
    ) -> Result<(), &'static str> {
        if !self.chain_claimed {
            return Err("chain observation was not claimed");
        }
        self.result = Some(result);
        Ok(())
    }

    pub async fn finish_actual_local_receiver(
        &mut self,
    ) -> Result<PqAttestationAdmissionBridgeTrace, &'static str> {
        let completion = self
            .receipt
            .as_mut()
            .ok_or("bridge receipt absent")?
            .wait()
            .await
            .map_err(|_| "bridge receipt lost")?;
        if completion != PqAttestationAdmissionBridgeCompletion::ClaimReady {
            return Err("bridge did not report claim ready");
        }
        let result = self.result.ok_or("chain completion absent")?;
        self.consumer_calls = self.consumer_calls.saturating_add(1);
        self.public_pending = false;
        Ok(PqAttestationAdmissionBridgeTrace {
            message_id: self.message_id.clone(),
            signed_ssz_digest: self.signed_ssz_digest,
            result,
            consumer_calls: self.consumer_calls,
            fail_closed_calls: self.fail_closed_calls,
            bridge_entry_count: self.bridge.entry_count(),
            terminal_failure: None,
        })
    }

    pub fn release_actual_inbound_before_claim(&mut self) -> Result<(), &'static str> {
        self.handles
            .get_mut(&0)
            .ok_or("release bridge resolution failed")?
            .released()
            .then_some(())
            .ok_or("release bridge resolution failed")
    }

    pub async fn drive_actual_local_retry_event(&mut self) -> Result<(), &'static str> {
        let completion = self
            .receipt
            .as_mut()
            .ok_or("bridge receipt absent")?
            .wait()
            .await
            .map_err(|_| "bridge receipt lost")?;
        if completion != PqAttestationAdmissionBridgeCompletion::Released {
            return Err("bridge did not report release");
        }
        tokio::time::sleep(PQ_LOCAL_ATTESTATION_PUBLISHED_PREFIX_RETRY_BACKOFF).await;
        self.attempts.push(0);
        Ok(())
    }

    pub fn attempted_member_sequence(&self) -> &[usize] {
        &self.attempts
    }

    pub const fn reencode_call_count(&self) -> usize {
        0
    }

    pub const fn sign_call_count(&self) -> usize {
        0
    }

    pub const fn proof_call_count(&self) -> usize {
        0
    }

    pub fn complete_mismatched_wire_id(&mut self) -> Result<(), &'static str> {
        Err("mismatched wire ID has no bridge handle")
    }

    pub fn lose_actual_bridge_channel(&mut self) -> Result<(), &'static str> {
        self.bridge
            .testing_only_lose_exact(self.wire_id)
            .then_some(())
            .ok_or("active bridge entry absent")
    }

    pub fn fail_actual_inbound(
        &mut self,
        _failure: PqAttestationAdmissionBridgeFailure,
    ) -> Result<(), &'static str> {
        self.handles
            .get_mut(&0)
            .ok_or("terminal bridge resolution failed")?
            .terminal()
            .then_some(())
            .ok_or("terminal bridge resolution failed")
    }

    pub async fn finish_actual_local_terminal(
        &mut self,
    ) -> Result<PqAttestationAdmissionBridgeTrace, &'static str> {
        let completion = self
            .receipt
            .as_mut()
            .ok_or("bridge receipt absent")?
            .wait()
            .await;
        let terminal_failure = match completion {
            Ok(PqAttestationAdmissionBridgeCompletion::Terminal) => {
                PqLocalAttestationPostPublishFailure::RemoteResolution(
                    PqPublishedLocalMemberResolutionError::Observation(
                        beacon_chain::PqSingleObservationStatus::Consumed(
                            PqSingleConsumptionResult::Terminal,
                        ),
                    ),
                )
            }
            Ok(_) => return Err("bridge did not report terminal"),
            Err(error) => pq_local_attestation_bridge_watch_failure(error),
        };
        self.fail_closed_calls = self.fail_closed_calls.saturating_add(1);
        self.public_pending = false;
        Ok(PqAttestationAdmissionBridgeTrace {
            message_id: self.message_id.clone(),
            signed_ssz_digest: self.signed_ssz_digest,
            result: PqSingleConsumptionResult::Terminal,
            consumer_calls: self.consumer_calls,
            fail_closed_calls: self.fail_closed_calls,
            bridge_entry_count: self.bridge.entry_count(),
            terminal_failure: Some(terminal_failure),
        })
    }

    pub fn start_distinct_actual_inbound_pending(
        &mut self,
        instance: u8,
    ) -> Result<u8, PqAttestationAdmissionBridgeTestError> {
        let handle = self
            .bridge
            .reserve(Self::wire_for(instance))
            .map_err(PqAttestationAdmissionBridgeTestError)?;
        self.handles.insert(instance, handle);
        Ok(instance)
    }

    pub fn abandon_actual_inbound(&mut self, instance: u8) -> Result<(), &'static str> {
        self.handles
            .remove(&instance)
            .map(drop)
            .ok_or("active bridge handle absent")
    }

    pub fn resolve_actual_inbound(
        &mut self,
        instance: u8,
        _result: PqSingleConsumptionResult,
    ) -> Result<(), &'static str> {
        self.handles
            .get_mut(&instance)
            .ok_or("active bridge handle absent")?
            .claim_ready()
            .then_some(())
            .ok_or("active bridge handle absent")
    }

    pub fn bridge_entry_count(&self) -> usize {
        self.bridge.entry_count()
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub async fn testing_only_pq_attestation_active_admission_bridge_driver()
-> TestingPqAttestationActiveAdmissionBridgeDriver {
    let wire_id = TestingPqAttestationActiveAdmissionBridgeDriver::wire_for(0x42);
    TestingPqAttestationActiveAdmissionBridgeDriver {
        bridge: PqAttestationAdmissionBridge::new(2),
        handles: std::collections::HashMap::new(),
        receipt: None,
        message_id: MessageId(wire_id.as_bytes().to_vec()),
        wire_id,
        signed_ssz_digest: Sha256::digest([0x42]).into(),
        chain_claimed: false,
        result: None,
        public_pending: false,
        consumer_calls: 0,
        fail_closed_calls: 0,
        attempts: vec![],
    }
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
        .map(|instance| {
            let subnet = SubnetId::new(u64::try_from(instance).unwrap_or(u64::MAX));
            PqEncodedLocalAttestation {
                topic: Topic::from(GossipTopic::new(
                    GossipKind::Attestation(subnet),
                    GossipEncoding::default(),
                    [u8::try_from(instance).unwrap_or(u8::MAX); 4],
                )),
                data: vec![u8::try_from(instance).unwrap_or(u8::MAX)],
                publication: None,
                _subnet: subnet,
                _instance: instance,
            }
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
                pq_local_attestation_publish_outcome_for_testing(member, encoded, outcomes.next())
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
