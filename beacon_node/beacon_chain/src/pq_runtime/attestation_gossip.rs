use crate::{
    BeaconChain, BeaconChainTypes, BeaconSnapshot, PqForkChoiceAttestationOutcome,
    PqLocallyConstructedSingle, PqSealedLocalAttestationBatch, PqVerifiedLocalAttestationBatch,
};
use futures::StreamExt;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use slot_clock::SlotClock;
#[cfg(feature = "pq-proposer")]
use state_processing::VerifiedPqAttestation;
use state_processing::{
    PqAttestationError, PqAttestationInvalid, PqAttestationLocalError, PqConsensusError,
    PqConsensusInvalid, PqConsensusLocalError, PreparedPqAggregateAndProof,
    PreparedPqSingleAttestation, VerifiedPqAggregateAndProof, VerifiedPqSingleAttestation,
    prepare_pq_aggregate_and_proof, prepare_pq_single_attestation,
};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, watch};
use tree_hash::TreeHash;
use types::{
    AttestationRef, BeaconState, ChainSpec, Epoch, EthSpec, Hash256, SignedAggregateAndProof,
    SignedBeaconBlock, SingleAttestation, Slot, SubnetId,
};

/// At most two large PQ gossip candidates may retain preparation/proof state concurrently.
pub const PQ_ATTESTATION_GOSSIP_ADMISSION_CAPACITY: usize = 2;
/// Local proof retention is independently capped, leaving remote gossip admission available.
pub const PQ_LOCAL_ATTESTATION_PROOF_ADMISSION_CAPACITY: usize = 2;
// The V1 profile has exactly 16 validators and gossip retains at most the current and previous
// epoch, so each per-validator observation index is bounded by 16 * 2 entries.
const PQ_ATTESTATION_OBSERVATION_CAPACITY: usize = 16 * 2;

#[derive(Debug)]
pub enum PqAttestationGossipPeerInvalid {
    InvalidTargetEpoch,
    TargetRootMismatch {
        expected: Hash256,
        actual: Hash256,
    },
    InvalidSubnet {
        expected: SubnetId,
        actual: SubnetId,
    },
    ReferencedBlockAfterAttestation {
        block: Slot,
        attestation: Slot,
    },
    InvalidAttestation(PqAttestationInvalid),
    InvalidAggregate(PqConsensusInvalid),
}

#[derive(Debug)]
pub enum PqAttestationGossipLocalError {
    ShuttingDown,
    IngressCapacity,
    ClockUnavailable,
    ReceiptBeforeWindow {
        attestation: Slot,
        latest_permissible: Slot,
    },
    ReceiptAfterWindow {
        attestation: Slot,
        earliest_permissible: Slot,
    },
    BlockingTask(&'static str),
    AsyncTask(&'static str),
    BoundHeadNoLongerCanonical {
        bound: Hash256,
        current: Hash256,
    },
    ProofOutlivedPropagationWindow {
        attestation: Slot,
    },
    ReferencedBlockUnavailable(Hash256),
    ReferencedStateUnavailable(Hash256),
    StateAdvanceTooLarge {
        referenced_block: Slot,
        attestation: Slot,
        maximum: u64,
    },
    StateUnavailable,
    ObservationCapacity,
    ObservationGenerationExhausted,
    ObservationLost,
    WireMessageIdLength {
        actual: usize,
    },
    WireMessageIdMismatch {
        expected: PqSingleWireMessageId,
        actual: PqSingleWireMessageId,
    },
    WireTopicMismatch {
        expected: String,
        actual: String,
    },
    Attestation(PqAttestationLocalError),
    Aggregate(PqConsensusLocalError),
    Store(store::Error),
}

#[derive(Debug)]
pub enum PqAttestationGossipError {
    PeerInvalid(PqAttestationGossipPeerInvalid),
    Local(PqAttestationGossipLocalError),
    Duplicate(PqAttestationGossipObservation),
}

#[derive(Debug)]
pub enum PqLocalAttestationInvariant {
    Contextual(PqAttestationGossipPeerInvalid),
    UnexpectedObservation,
    ProvenanceMismatch(&'static str),
}

#[derive(Debug)]
pub enum PqLocalAttestationVerificationError {
    Invariant(PqLocalAttestationInvariant),
    Local(PqAttestationGossipLocalError),
}

#[derive(Debug)]
pub enum PqLocalAttestationBatchVerificationError {
    Capacity { count: usize, maximum: usize },
    Proof(PqLocalAttestationVerificationError),
}

enum PqAtomicLocalBatchError<E> {
    Capacity { count: usize, maximum: usize },
    Proof(E),
}

async fn collect_pq_local_batch_atomically<I, O, E, F, Fut>(
    inputs: Vec<I>,
    verifier: F,
) -> Result<Vec<O>, PqAtomicLocalBatchError<E>>
where
    F: Fn(I) -> Fut,
    Fut: Future<Output = Result<O, E>>,
{
    if inputs.len() > PQ_LOCAL_ATTESTATION_PROOF_ADMISSION_CAPACITY {
        return Err(PqAtomicLocalBatchError::Capacity {
            count: inputs.len(),
            maximum: PQ_LOCAL_ATTESTATION_PROOF_ADMISSION_CAPACITY,
        });
    }
    let results = futures::stream::iter(inputs)
        .map(verifier)
        .buffered(PQ_LOCAL_ATTESTATION_PROOF_ADMISSION_CAPACITY)
        .collect::<Vec<_>>()
        .await;
    let mut outputs = Vec::with_capacity(results.len());
    for result in results {
        outputs.push(result.map_err(PqAtomicLocalBatchError::Proof)?);
    }
    Ok(outputs)
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub enum TestingPqAtomicLocalBatchError<E> {
    Capacity { count: usize, maximum: usize },
    Proof(E),
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub async fn testing_only_collect_pq_local_batch_atomically<I, O, E, F, Fut>(
    inputs: Vec<I>,
    verifier: F,
) -> Result<Vec<O>, TestingPqAtomicLocalBatchError<E>>
where
    F: Fn(I) -> Fut,
    Fut: Future<Output = Result<O, E>>,
{
    collect_pq_local_batch_atomically(inputs, verifier)
        .await
        .map_err(|error| match error {
            PqAtomicLocalBatchError::Capacity { count, maximum } => {
                TestingPqAtomicLocalBatchError::Capacity { count, maximum }
            }
            PqAtomicLocalBatchError::Proof(error) => TestingPqAtomicLocalBatchError::Proof(error),
        })
}

impl std::fmt::Display for PqLocalAttestationBatchVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PQ local attestation batch verification failed: {self:?}"
        )
    }
}

impl std::error::Error for PqLocalAttestationBatchVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Proof(error) => Some(error),
            Self::Capacity { .. } => None,
        }
    }
}

impl std::fmt::Display for PqLocalAttestationVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PQ local attestation verification failed: {self:?}"
        )
    }
}

impl std::error::Error for PqLocalAttestationVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Local(error) => pq_attestation_local_error_source(error),
            Self::Invariant(_) => None,
        }
    }
}

impl PqAttestationGossipError {
    pub const fn should_penalize_peer(&self) -> bool {
        matches!(self, Self::PeerInvalid(_))
    }

    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Local(error) if !matches!(
            error,
            PqAttestationGossipLocalError::ProofOutlivedPropagationWindow { .. }
                | PqAttestationGossipLocalError::BoundHeadNoLongerCanonical { .. }
                | PqAttestationGossipLocalError::StateAdvanceTooLarge { .. }
                | PqAttestationGossipLocalError::ObservationGenerationExhausted
                | PqAttestationGossipLocalError::WireMessageIdMismatch { .. }
                | PqAttestationGossipLocalError::WireMessageIdLength { .. }
                | PqAttestationGossipLocalError::WireTopicMismatch { .. }
                | PqAttestationGossipLocalError::ShuttingDown
                | PqAttestationGossipLocalError::ReceiptAfterWindow { .. }
        ))
    }
}

impl std::fmt::Display for PqAttestationGossipError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ attestation gossip failed: {self:?}")
    }
}

impl std::error::Error for PqAttestationGossipError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Local(error) => pq_attestation_local_error_source(error),
            Self::PeerInvalid(_) | Self::Duplicate(_) => None,
        }
    }
}

fn pq_attestation_local_error_source(
    error: &PqAttestationGossipLocalError,
) -> Option<&(dyn std::error::Error + 'static)> {
    match error {
        PqAttestationGossipLocalError::Attestation(PqAttestationLocalError::SigningId(error)) => {
            Some(error)
        }
        PqAttestationGossipLocalError::Attestation(PqAttestationLocalError::Aggregation(error)) => {
            Some(error)
        }
        PqAttestationGossipLocalError::Aggregate(PqConsensusLocalError::SigningId(error)) => {
            Some(error)
        }
        PqAttestationGossipLocalError::Aggregate(PqConsensusLocalError::Aggregation(error)) => {
            Some(error)
        }
        PqAttestationGossipLocalError::Aggregate(PqConsensusLocalError::Attestation(
            PqAttestationLocalError::SigningId(error),
        )) => Some(error),
        PqAttestationGossipLocalError::Aggregate(PqConsensusLocalError::Attestation(
            PqAttestationLocalError::Aggregation(error),
        )) => Some(error),
        PqAttestationGossipLocalError::ShuttingDown
        | PqAttestationGossipLocalError::IngressCapacity
        | PqAttestationGossipLocalError::ClockUnavailable
        | PqAttestationGossipLocalError::ReceiptBeforeWindow { .. }
        | PqAttestationGossipLocalError::ReceiptAfterWindow { .. }
        | PqAttestationGossipLocalError::BlockingTask(_)
        | PqAttestationGossipLocalError::AsyncTask(_)
        | PqAttestationGossipLocalError::BoundHeadNoLongerCanonical { .. }
        | PqAttestationGossipLocalError::ProofOutlivedPropagationWindow { .. }
        | PqAttestationGossipLocalError::ReferencedBlockUnavailable(_)
        | PqAttestationGossipLocalError::ReferencedStateUnavailable(_)
        | PqAttestationGossipLocalError::StateAdvanceTooLarge { .. }
        | PqAttestationGossipLocalError::StateUnavailable
        | PqAttestationGossipLocalError::ObservationCapacity
        | PqAttestationGossipLocalError::ObservationGenerationExhausted
        | PqAttestationGossipLocalError::ObservationLost
        | PqAttestationGossipLocalError::WireMessageIdLength { .. }
        | PqAttestationGossipLocalError::WireMessageIdMismatch { .. }
        | PqAttestationGossipLocalError::WireTopicMismatch { .. }
        | PqAttestationGossipLocalError::Store(_)
        | PqAttestationGossipLocalError::Attestation(
            PqAttestationLocalError::UnsupportedProfile
            | PqAttestationLocalError::CommitteeCacheUnavailable
            | PqAttestationLocalError::CacheInvariant,
        )
        | PqAttestationGossipLocalError::Aggregate(
            PqConsensusLocalError::UnsupportedProfile
            | PqConsensusLocalError::StateUnavailable
            | PqConsensusLocalError::CacheInvariant
            | PqConsensusLocalError::Attestation(
                PqAttestationLocalError::UnsupportedProfile
                | PqAttestationLocalError::CommitteeCacheUnavailable
                | PqAttestationLocalError::CacheInvariant,
            ),
        ) => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PqSingleObservationIdentity {
    target_epoch: Epoch,
    validator_index: u64,
    slot: Slot,
    subnet: SubnetId,
    signed_tree_hash_root: Hash256,
    signed_ssz_digest: [u8; 32],
}

impl PqSingleObservationIdentity {
    pub const fn new(
        target_epoch: Epoch,
        validator_index: u64,
        slot: Slot,
        subnet: SubnetId,
        signed_tree_hash_root: Hash256,
        signed_ssz_digest: [u8; 32],
    ) -> Self {
        Self {
            target_epoch,
            validator_index,
            slot,
            subnet,
            signed_tree_hash_root,
            signed_ssz_digest,
        }
    }

    /// Derives immutable wire identity data. This value carries no verification or consumption
    /// authority.
    pub fn from_signed_attestation(attestation: &SingleAttestation, subnet: SubnetId) -> Self {
        Self::new(
            attestation.data.target.epoch,
            attestation.attester_index,
            attestation.data.slot,
            subnet,
            attestation.tree_hash_root(),
            Sha256::digest(ssz::Encode::as_ssz_bytes(attestation)).into(),
        )
    }

    const fn key(self) -> (Epoch, u64) {
        (self.target_epoch, self.validator_index)
    }
}

/// Network-neutral binding for the exact anonymous gossipsub message that created a remote claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PqSingleWireMessageId([u8; 20]);

impl PqSingleWireMessageId {
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PqSingleWireMessageId {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

fn canonical_pq_single_wire_provenance<E: EthSpec>(
    attestation: &SingleAttestation,
    subnet: SubnetId,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> (PqSingleWireMessageId, String) {
    let fork_digest = spec
        .enr_fork_id::<E>(attestation.data.slot, genesis_validators_root)
        .fork_digest;
    let topic = format!(
        "/eth2/{}/beacon_attestation_{}/ssz_snappy",
        hex::encode(fork_digest),
        *subnet,
    );
    let signed_ssz = ssz::Encode::as_ssz_bytes(attestation);
    let topic_bytes = topic.as_bytes();
    let altair_enabled = spec
        .fork_name_at_slot::<E>(attestation.data.slot)
        .altair_enabled();
    let mut prefixed = if altair_enabled {
        Vec::with_capacity(
            spec.message_domain_valid_snappy.len()
                + std::mem::size_of::<usize>()
                + topic_bytes.len()
                + signed_ssz.len(),
        )
    } else {
        Vec::with_capacity(spec.message_domain_valid_snappy.len() + signed_ssz.len())
    };
    prefixed.extend_from_slice(&spec.message_domain_valid_snappy);
    if altair_enabled {
        prefixed.extend_from_slice(&topic_bytes.len().to_le_bytes());
        prefixed.extend_from_slice(topic_bytes);
    }
    prefixed.extend_from_slice(&signed_ssz);
    let digest = Sha256::digest(prefixed);
    let mut wire_id = [0_u8; 20];
    wire_id.copy_from_slice(&digest[..20]);
    (PqSingleWireMessageId(wire_id), topic)
}

/// Recomputes and validates the exact anonymous gossipsub identity without depending on the
/// networking crate. This grants no observation authority and performs no cache mutation.
pub fn validate_pq_single_wire_provenance<E: EthSpec>(
    attestation: &SingleAttestation,
    subnet: SubnetId,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
    wire_id: PqSingleWireMessageId,
    actual_topic: Option<&str>,
) -> Result<PqSingleWireMessageId, PqAttestationGossipError> {
    let (expected_wire_id, expected_topic) = canonical_pq_single_wire_provenance::<E>(
        attestation,
        subnet,
        genesis_validators_root,
        spec,
    );
    if let Some(actual_topic) = actual_topic
        && actual_topic != expected_topic
    {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::WireTopicMismatch {
                expected: expected_topic,
                actual: actual_topic.to_owned(),
            },
        ));
    }
    if wire_id != expected_wire_id {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::WireMessageIdMismatch {
                expected: expected_wire_id,
                actual: wire_id,
            },
        ));
    }
    Ok(expected_wire_id)
}

#[derive(Clone)]
enum SingleObservationState {
    Pending {
        identity: PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        generation: u64,
        completion: watch::Sender<Option<PqSingleObservationCompletion>>,
    },
    ConsumptionPending {
        identity: PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        generation: u64,
        completion: watch::Sender<Option<PqSingleObservationCompletion>>,
    },
    Consumed {
        identity: PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        result: PqSingleConsumptionResult,
        completion: watch::Sender<Option<PqSingleObservationCompletion>>,
    },
}

impl SingleObservationState {
    fn completion(&self) -> &watch::Sender<Option<PqSingleObservationCompletion>> {
        match self {
            Self::Pending { completion, .. }
            | Self::ConsumptionPending { completion, .. }
            | Self::Consumed { completion, .. } => completion,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObservationState {
    Pending { identity: Hash256, generation: u64 },
    Observed { identity: Hash256 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqSingleConsumptionResult {
    Applied,
    Queued,
    Terminal,
}

pub const fn pq_single_consumption_result_from_fork_choice(
    outcome: PqForkChoiceAttestationOutcome,
) -> PqSingleConsumptionResult {
    match outcome {
        PqForkChoiceAttestationOutcome::Applied => PqSingleConsumptionResult::Applied,
        PqForkChoiceAttestationOutcome::Queued => PqSingleConsumptionResult::Queued,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqSingleObservationStatus {
    Unseen,
    Pending,
    ConsumptionPending,
    Consumed(PqSingleConsumptionResult),
    Conflict,
    Capacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqSingleObservationCompletion {
    Released,
    Consumed(PqSingleConsumptionResult),
    /// The inbound chain consumption owner has already closed ingress and signalled the process.
    ConsumedTerminalAlreadySignaled,
}

/// Exact chain-authoritative resolution for one sealed, locally verified member after a lower
/// publication outcome references the same anonymous gossipsub message ID.
#[cfg(feature = "pq-proposer")]
pub enum PqPublishedLocalMemberResolution {
    Immediate(PqSingleConsumptionResult),
    TerminalAlreadySignaled,
    Wait(PqSingleObservationWatchReceipt),
}

#[cfg(feature = "pq-proposer")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqPublishedLocalMemberResolutionError {
    Member,
    Identity,
    SignedSszDigest,
    MessageId,
    ObservationLost,
    AdmissionBridgeLost,
    Observation(PqSingleObservationStatus),
}

#[cfg(feature = "pq-proposer")]
pub(crate) fn resolve_pq_published_local_member<E: EthSpec>(
    cache: &Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
    identity: PqSingleObservationIdentity,
    signed_ssz: &[u8],
    sealed_signed_ssz_digest: [u8; 32],
    expected_message_id: &lighthouse_network::MessageId,
    actual_message_id: &lighthouse_network::MessageId,
) -> Result<PqPublishedLocalMemberResolution, PqPublishedLocalMemberResolutionError> {
    let actual_digest: [u8; 32] = Sha256::digest(signed_ssz).into();
    if actual_digest != sealed_signed_ssz_digest {
        return Err(PqPublishedLocalMemberResolutionError::SignedSszDigest);
    }
    if actual_message_id != expected_message_id {
        return Err(PqPublishedLocalMemberResolutionError::MessageId);
    }
    let wire_id = PqSingleWireMessageId::try_from(actual_message_id.0.as_slice())
        .map_err(|_| PqPublishedLocalMemberResolutionError::MessageId)?;
    let cache = cache.lock();
    let status = cache.exact_single_wire_status(&identity, wire_id);
    if status == PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Terminal)
        && cache.exact_single_wire_completion(&identity, wire_id)
            == Some(PqSingleObservationCompletion::ConsumedTerminalAlreadySignaled)
    {
        return Ok(PqPublishedLocalMemberResolution::TerminalAlreadySignaled);
    }
    match status {
        PqSingleObservationStatus::Consumed(
            result @ (PqSingleConsumptionResult::Applied | PqSingleConsumptionResult::Queued),
        ) => Ok(PqPublishedLocalMemberResolution::Immediate(result)),
        status @ (PqSingleObservationStatus::Pending
        | PqSingleObservationStatus::ConsumptionPending) => cache
            .subscribe_exact_single(&identity, wire_id)
            .map(PqPublishedLocalMemberResolution::Wait)
            .map_err(|_| PqPublishedLocalMemberResolutionError::Observation(status)),
        status => Err(PqPublishedLocalMemberResolutionError::Observation(status)),
    }
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqSingleObservationWatchError {
    Lost,
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
pub struct PqSingleObservationWatchReceipt {
    receiver: watch::Receiver<Option<PqSingleObservationCompletion>>,
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
impl PqSingleObservationWatchReceipt {
    pub async fn wait(
        &mut self,
    ) -> Result<PqSingleObservationCompletion, PqSingleObservationWatchError> {
        loop {
            if let Some(completion) = *self.receiver.borrow_and_update() {
                return Ok(completion);
            }
            self.receiver
                .changed()
                .await
                .map_err(|_| PqSingleObservationWatchError::Lost)?;
        }
    }
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
const PQ_SINGLE_OBSERVATION_BATCH_CAPACITY: usize = 2;

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PqSingleObservationBatchSource {
    LocalWireSuccess,
    #[cfg(feature = "pq-proposer")]
    RemoteConsumed(PqSingleConsumptionResult),
    #[cfg(feature = "pq-startup-testing")]
    Remote,
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PqSingleObservationBatchRequest {
    identity: PqSingleObservationIdentity,
    wire_id: PqSingleWireMessageId,
    source: PqSingleObservationBatchSource,
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
impl PqSingleObservationBatchRequest {
    pub(crate) const fn new(
        identity: PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        source: PqSingleObservationBatchSource,
    ) -> Self {
        Self {
            identity,
            wire_id,
            source,
        }
    }

    const fn permits_unseen_local_reservation(self) -> bool {
        match self.source {
            PqSingleObservationBatchSource::LocalWireSuccess => true,
            #[cfg(feature = "pq-proposer")]
            PqSingleObservationBatchSource::RemoteConsumed(_) => false,
            #[cfg(feature = "pq-startup-testing")]
            PqSingleObservationBatchSource::Remote => false,
        }
    }

    #[cfg(feature = "pq-proposer")]
    const fn claimed_remote_result(self) -> Option<PqSingleConsumptionResult> {
        match self.source {
            PqSingleObservationBatchSource::RemoteConsumed(result) => Some(result),
            PqSingleObservationBatchSource::LocalWireSuccess => None,
            #[cfg(feature = "pq-startup-testing")]
            PqSingleObservationBatchSource::Remote => None,
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqSingleObservationBatchResolution {
    LocalReserved,
    WaitRemote(PqSingleObservationStatus),
    Coalesced(PqSingleConsumptionResult),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqSingleObservationBatchError {
    BatchCapacity { count: usize, maximum: usize },
    RemoteUnseen,
    RemoteNotConsumed { status: PqSingleObservationStatus },
    Terminal,
    Conflict,
    ObservationCapacity,
    GenerationExhausted,
}

impl std::fmt::Display for PqSingleObservationBatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PQ single-observation batch resolution failed: {self:?}"
        )
    }
}

impl std::error::Error for PqSingleObservationBatchError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqPublishedLocalAttestationBatchConsumptionOutcome {
    Complete {
        results: Vec<PqSingleConsumptionResult>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqPublishedLocalAttestationBatchConsumptionError {
    #[cfg(feature = "pq-proposer")]
    Evidence(crate::PqPublishedLocalAttestationEvidenceError),
    Preflight(crate::PqLocalAttestationBatchPreflightError),
    InvalidIndexedAttestation {
        index: usize,
    },
    Observation(PqSingleObservationBatchError),
    RemotePending {
        index: usize,
        status: PqSingleObservationStatus,
    },
    ApplyFailed {
        applied_count: usize,
        failed_index: usize,
    },
    ObservationLost {
        index: usize,
    },
    PoolInvariant {
        index: usize,
        invariant: operation_pool::PqAttestationPoolInsertInvariant,
    },
    TaskUnavailable,
}

impl std::fmt::Display for PqPublishedLocalAttestationBatchConsumptionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PQ published local attestation batch consumption failed: {self:?}"
        )
    }
}

impl std::error::Error for PqPublishedLocalAttestationBatchConsumptionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "pq-proposer")]
            Self::Evidence(error) => Some(error),
            Self::Preflight(error) => Some(error),
            Self::Observation(error) => Some(error),
            Self::PoolInvariant { invariant, .. } => Some(invariant),
            _ => None,
        }
    }
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
enum PqSingleObservationBatchMemberResolution {
    LocalReserved(SingleObservationBinding),
    WaitRemote {
        identity: PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        status: PqSingleObservationStatus,
        local_reclaim: bool,
    },
    Coalesced(PqSingleConsumptionResult),
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
struct PqSingleObservationBatchReservation {
    members: Vec<PqSingleObservationBatchMemberResolution>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAttestationGossipObservation {
    Unseen,
    Pending,
    Observed,
    Conflict,
    Capacity,
    GenerationExhausted,
}

pub(crate) struct PqAttestationGossipObservationCache<E: EthSpec> {
    singles: HashMap<(Epoch, u64), SingleObservationState>,
    aggregators: HashMap<(Epoch, u64), ObservationState>,
    aggregate_candidates: HashMap<(Slot, Hash256, u64), Vec<AggregateObservation<E>>>,
    next_generation: u64,
}

struct AggregateObservation<E: EthSpec> {
    identity: Hash256,
    generation: u64,
    pending: bool,
    bits: ssz_types::BitList<E::MaxValidatorsPerSlot>,
}

impl<E: EthSpec> Default for PqAttestationGossipObservationCache<E> {
    fn default() -> Self {
        Self {
            singles: HashMap::new(),
            aggregators: HashMap::new(),
            aggregate_candidates: HashMap::new(),
            next_generation: 0,
        }
    }
}

impl<E: EthSpec> PqAttestationGossipObservationCache<E> {
    fn allocate_generation(&mut self) -> Result<u64, PqAttestationGossipObservation> {
        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or(PqAttestationGossipObservation::GenerationExhausted)?;
        self.next_generation = generation;
        Ok(generation)
    }

    fn prune(&mut self, earliest_slot: Slot) {
        let earliest_epoch = earliest_slot.epoch(E::slots_per_epoch());
        self.singles.retain(|(epoch, _), state| {
            let retain = *epoch >= earliest_epoch
                || matches!(state, SingleObservationState::ConsumptionPending { .. });
            if !retain && matches!(state, SingleObservationState::Pending { .. }) {
                state
                    .completion()
                    .send_replace(Some(PqSingleObservationCompletion::Released));
            }
            retain
        });
        self.aggregators
            .retain(|(epoch, _), _| *epoch >= earliest_epoch);
        self.aggregate_candidates
            .retain(|(slot, _, _), _| *slot >= earliest_slot);
    }

    fn single_status(&self, key: (Epoch, u64)) -> PqAttestationGossipObservation {
        match self.singles.get(&key) {
            Some(SingleObservationState::Pending { .. }) => PqAttestationGossipObservation::Pending,
            Some(SingleObservationState::ConsumptionPending { .. }) => {
                PqAttestationGossipObservation::Observed
            }
            Some(SingleObservationState::Consumed { .. }) => {
                PqAttestationGossipObservation::Observed
            }
            None if self.singles.len() >= PQ_ATTESTATION_OBSERVATION_CAPACITY => {
                PqAttestationGossipObservation::Capacity
            }
            None => PqAttestationGossipObservation::Unseen,
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    pub(crate) fn exact_single_status(
        &self,
        identity: &PqSingleObservationIdentity,
    ) -> PqSingleObservationStatus {
        Self::exact_single_status_in(&self.singles, identity)
    }

    pub(crate) fn exact_single_wire_status(
        &self,
        identity: &PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
    ) -> PqSingleObservationStatus {
        Self::exact_single_wire_status_in(&self.singles, identity, wire_id)
    }

    #[cfg(feature = "pq-proposer")]
    fn exact_single_wire_completion(
        &self,
        identity: &PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
    ) -> Option<PqSingleObservationCompletion> {
        let completion = match self.singles.get(&identity.key()) {
            Some(SingleObservationState::Consumed {
                identity: known,
                wire_id: known_wire_id,
                completion,
                ..
            }) if known == identity && *known_wire_id == wire_id => completion,
            _ => return None,
        };
        let observed = *completion.borrow();
        observed
    }

    #[cfg(feature = "pq-startup-testing")]
    fn exact_single_status_in(
        singles: &HashMap<(Epoch, u64), SingleObservationState>,
        identity: &PqSingleObservationIdentity,
    ) -> PqSingleObservationStatus {
        match singles.get(&identity.key()) {
            Some(SingleObservationState::Pending {
                identity: known, ..
            }) if known == identity => PqSingleObservationStatus::Pending,
            Some(SingleObservationState::ConsumptionPending {
                identity: known, ..
            }) if known == identity => PqSingleObservationStatus::ConsumptionPending,
            Some(SingleObservationState::Consumed {
                identity: known,
                result,
                ..
            }) if known == identity => PqSingleObservationStatus::Consumed(*result),
            Some(_) => PqSingleObservationStatus::Conflict,
            None if singles.len() >= PQ_ATTESTATION_OBSERVATION_CAPACITY => {
                PqSingleObservationStatus::Capacity
            }
            None => PqSingleObservationStatus::Unseen,
        }
    }

    fn exact_single_wire_status_in(
        singles: &HashMap<(Epoch, u64), SingleObservationState>,
        identity: &PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
    ) -> PqSingleObservationStatus {
        match singles.get(&identity.key()) {
            Some(SingleObservationState::Pending {
                identity: known,
                wire_id: known_wire_id,
                ..
            }) if known == identity && *known_wire_id == wire_id => {
                PqSingleObservationStatus::Pending
            }
            Some(SingleObservationState::ConsumptionPending {
                identity: known,
                wire_id: known_wire_id,
                ..
            }) if known == identity && *known_wire_id == wire_id => {
                PqSingleObservationStatus::ConsumptionPending
            }
            Some(SingleObservationState::Consumed {
                identity: known,
                wire_id: known_wire_id,
                result,
                ..
            }) if known == identity && *known_wire_id == wire_id => {
                PqSingleObservationStatus::Consumed(*result)
            }
            Some(_) => PqSingleObservationStatus::Conflict,
            None if singles.len() >= PQ_ATTESTATION_OBSERVATION_CAPACITY => {
                PqSingleObservationStatus::Capacity
            }
            None => PqSingleObservationStatus::Unseen,
        }
    }

    #[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
    fn resolve_exact_single_batch(
        &mut self,
        requests: &[PqSingleObservationBatchRequest],
        earliest_slot: Slot,
    ) -> Result<PqSingleObservationBatchReservation, PqSingleObservationBatchError> {
        if requests.len() > PQ_SINGLE_OBSERVATION_BATCH_CAPACITY {
            return Err(PqSingleObservationBatchError::BatchCapacity {
                count: requests.len(),
                maximum: PQ_SINGLE_OBSERVATION_BATCH_CAPACITY,
            });
        }

        let earliest_epoch = earliest_slot.epoch(E::slots_per_epoch());
        let mut staged_singles = self.singles.clone();
        let mut staged_releases = Vec::new();
        staged_singles.retain(|(epoch, _), state| {
            let retain = *epoch >= earliest_epoch
                || matches!(state, SingleObservationState::ConsumptionPending { .. });
            if !retain && matches!(state, SingleObservationState::Pending { .. }) {
                staged_releases.push(state.completion().clone());
            }
            retain
        });
        let mut staged_generation = self.next_generation;
        let mut members = Vec::with_capacity(requests.len());

        for request in requests {
            match Self::exact_single_wire_status_in(
                &staged_singles,
                &request.identity,
                request.wire_id,
            ) {
                PqSingleObservationStatus::Unseen => {
                    if !request.permits_unseen_local_reservation() {
                        return Err(PqSingleObservationBatchError::RemoteUnseen);
                    }
                    let generation = staged_generation
                        .checked_add(1)
                        .ok_or(PqSingleObservationBatchError::GenerationExhausted)?;
                    staged_generation = generation;
                    let (completion, _receiver) = watch::channel(None);
                    staged_singles.insert(
                        request.identity.key(),
                        SingleObservationState::ConsumptionPending {
                            identity: request.identity,
                            wire_id: request.wire_id,
                            generation,
                            completion,
                        },
                    );
                    members.push(PqSingleObservationBatchMemberResolution::LocalReserved(
                        SingleObservationBinding {
                            identity: request.identity,
                            wire_id: request.wire_id,
                            generation,
                        },
                    ));
                }
                status @ (PqSingleObservationStatus::Pending
                | PqSingleObservationStatus::ConsumptionPending) => {
                    #[cfg(feature = "pq-proposer")]
                    if request.claimed_remote_result().is_some() {
                        return Err(PqSingleObservationBatchError::RemoteNotConsumed { status });
                    }
                    members.push(PqSingleObservationBatchMemberResolution::WaitRemote {
                        identity: request.identity,
                        wire_id: request.wire_id,
                        status,
                        local_reclaim: request.permits_unseen_local_reservation(),
                    });
                }
                PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Applied) => {
                    #[cfg(feature = "pq-proposer")]
                    if request
                        .claimed_remote_result()
                        .is_some_and(|claimed| claimed != PqSingleConsumptionResult::Applied)
                    {
                        return Err(PqSingleObservationBatchError::Conflict);
                    }
                    members.push(PqSingleObservationBatchMemberResolution::Coalesced(
                        PqSingleConsumptionResult::Applied,
                    ));
                }
                PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Queued) => {
                    #[cfg(feature = "pq-proposer")]
                    if request
                        .claimed_remote_result()
                        .is_some_and(|claimed| claimed != PqSingleConsumptionResult::Queued)
                    {
                        return Err(PqSingleObservationBatchError::Conflict);
                    }
                    members.push(PqSingleObservationBatchMemberResolution::Coalesced(
                        PqSingleConsumptionResult::Queued,
                    ));
                }
                PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Terminal) => {
                    return Err(PqSingleObservationBatchError::Terminal);
                }
                PqSingleObservationStatus::Conflict => {
                    return Err(PqSingleObservationBatchError::Conflict);
                }
                PqSingleObservationStatus::Capacity => {
                    return Err(PqSingleObservationBatchError::ObservationCapacity);
                }
            }
        }

        for completion in staged_releases {
            completion.send_replace(Some(PqSingleObservationCompletion::Released));
        }
        self.singles = staged_singles;
        self.next_generation = staged_generation;
        Ok(PqSingleObservationBatchReservation { members })
    }

    fn precheck_single(
        &mut self,
        key: (Epoch, u64),
        earliest_slot: Slot,
    ) -> PqAttestationGossipObservation {
        self.prune(earliest_slot);
        self.single_status(key)
    }

    fn claim_single(
        &mut self,
        identity: PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        earliest_slot: Slot,
    ) -> Result<u64, PqAttestationGossipObservation> {
        self.prune(earliest_slot);
        let key = identity.key();
        match self.exact_single_wire_status(&identity, wire_id) {
            PqSingleObservationStatus::Unseen => {
                let generation = self.allocate_generation()?;
                let (completion, _receiver) = watch::channel(None);
                self.singles.insert(
                    key,
                    SingleObservationState::Pending {
                        identity,
                        wire_id,
                        generation,
                        completion,
                    },
                );
                Ok(generation)
            }
            PqSingleObservationStatus::Pending => Err(PqAttestationGossipObservation::Pending),
            PqSingleObservationStatus::ConsumptionPending
            | PqSingleObservationStatus::Consumed(_) => {
                Err(PqAttestationGossipObservation::Observed)
            }
            PqSingleObservationStatus::Conflict => Err(PqAttestationGossipObservation::Conflict),
            PqSingleObservationStatus::Capacity => Err(PqAttestationGossipObservation::Capacity),
        }
    }

    fn finalize_single(
        &mut self,
        identity: PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        generation: u64,
        result: PqSingleConsumptionResult,
    ) -> bool {
        self.finalize_single_with_authority(identity, wire_id, generation, result, false)
    }

    fn finalize_single_with_authority(
        &mut self,
        identity: PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        generation: u64,
        result: PqSingleConsumptionResult,
        failure_already_signaled: bool,
    ) -> bool {
        let key = identity.key();
        let completion = match self.singles.get(&key) {
            Some(
                SingleObservationState::Pending {
                    identity: known,
                    wire_id: known_wire_id,
                    generation: known_generation,
                    completion,
                }
                | SingleObservationState::ConsumptionPending {
                    identity: known,
                    wire_id: known_wire_id,
                    generation: known_generation,
                    completion,
                },
            ) if *known == identity
                && *known_wire_id == wire_id
                && *known_generation == generation =>
            {
                Some(completion.clone())
            }
            _ => None,
        };
        if let Some(completion) = completion {
            let observed_completion =
                if result == PqSingleConsumptionResult::Terminal && failure_already_signaled {
                    PqSingleObservationCompletion::ConsumedTerminalAlreadySignaled
                } else {
                    PqSingleObservationCompletion::Consumed(result)
                };
            completion.send_replace(Some(observed_completion));
            self.singles.insert(
                key,
                SingleObservationState::Consumed {
                    identity,
                    wire_id,
                    result,
                    completion,
                },
            );
            true
        } else {
            false
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    pub(crate) fn single_consumption_result(
        &self,
        key: (Epoch, u64),
    ) -> Option<PqSingleConsumptionResult> {
        match self.singles.get(&key) {
            Some(SingleObservationState::Consumed { result, .. }) => Some(*result),
            _ => None,
        }
    }

    fn mark_single_propagated(
        &mut self,
        identity: PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        generation: u64,
    ) -> bool {
        let completion = match self.singles.get(&identity.key()) {
            Some(SingleObservationState::Pending {
                identity: known,
                wire_id: known_wire_id,
                generation: known_generation,
                completion,
            }) if *known == identity
                && *known_wire_id == wire_id
                && *known_generation == generation =>
            {
                Some(completion.clone())
            }
            _ => None,
        };
        if let Some(completion) = completion {
            self.singles.insert(
                identity.key(),
                SingleObservationState::ConsumptionPending {
                    identity,
                    wire_id,
                    generation,
                    completion,
                },
            );
            true
        } else {
            false
        }
    }

    fn rollback_single(
        &mut self,
        identity: PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        generation: u64,
    ) -> bool {
        let key = identity.key();
        let completion = match self.singles.get(&key) {
            Some(SingleObservationState::Pending {
                identity: known,
                wire_id: known_wire_id,
                generation: known_generation,
                completion,
            }) if *known == identity
                && *known_wire_id == wire_id
                && *known_generation == generation =>
            {
                Some(completion.clone())
            }
            _ => None,
        };
        if let Some(completion) = completion {
            completion.send_replace(Some(PqSingleObservationCompletion::Released));
            self.singles.remove(&key);
            true
        } else {
            false
        }
    }

    #[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
    fn subscribe_exact_single(
        &self,
        identity: &PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
    ) -> Result<PqSingleObservationWatchReceipt, PqSingleObservationStatus> {
        match self.singles.get(&identity.key()) {
            Some(
                state @ SingleObservationState::Pending {
                    identity: known,
                    wire_id: known_wire_id,
                    ..
                },
            )
            | Some(
                state @ SingleObservationState::ConsumptionPending {
                    identity: known,
                    wire_id: known_wire_id,
                    ..
                },
            )
            | Some(
                state @ SingleObservationState::Consumed {
                    identity: known,
                    wire_id: known_wire_id,
                    ..
                },
            ) if known == identity && *known_wire_id == wire_id => {
                Ok(PqSingleObservationWatchReceipt {
                    receiver: state.completion().subscribe(),
                })
            }
            Some(_) => Err(PqSingleObservationStatus::Conflict),
            None if self.singles.len() >= PQ_ATTESTATION_OBSERVATION_CAPACITY => {
                Err(PqSingleObservationStatus::Capacity)
            }
            None => Err(PqSingleObservationStatus::Unseen),
        }
    }

    fn aggregate_status(
        &self,
        aggregator_key: (Epoch, u64),
        data_key: (Slot, Hash256, u64),
        identity: Hash256,
        bits: &ssz_types::BitList<E::MaxValidatorsPerSlot>,
    ) -> PqAttestationGossipObservation {
        if let Some(state) = self.aggregators.get(&aggregator_key) {
            return match state {
                ObservationState::Pending {
                    identity: known, ..
                } if *known == identity => PqAttestationGossipObservation::Pending,
                ObservationState::Observed { identity: known } if *known == identity => {
                    PqAttestationGossipObservation::Observed
                }
                _ => PqAttestationGossipObservation::Observed,
            };
        }
        if let Some(known) = self.aggregate_candidates.get(&data_key) {
            for candidate in known {
                if bits.is_subset(&candidate.bits) {
                    return if candidate.pending {
                        PqAttestationGossipObservation::Pending
                    } else {
                        PqAttestationGossipObservation::Observed
                    };
                }
                if candidate.pending && candidate.bits.is_subset(bits) {
                    return PqAttestationGossipObservation::Pending;
                }
            }
        }
        let candidate_count = self
            .aggregate_candidates
            .values()
            .fold(0usize, |count, candidates| {
                count.saturating_add(candidates.len())
            });
        if self.aggregators.len() >= PQ_ATTESTATION_OBSERVATION_CAPACITY
            || candidate_count >= PQ_ATTESTATION_OBSERVATION_CAPACITY
        {
            PqAttestationGossipObservation::Capacity
        } else {
            PqAttestationGossipObservation::Unseen
        }
    }

    fn precheck_aggregate(
        &mut self,
        aggregator_key: (Epoch, u64),
        data_key: (Slot, Hash256, u64),
        bits: &ssz_types::BitList<E::MaxValidatorsPerSlot>,
        earliest_slot: Slot,
    ) -> PqAttestationGossipObservation {
        self.prune(earliest_slot);
        self.aggregate_status(aggregator_key, data_key, Hash256::default(), bits)
    }

    fn claim_aggregate(
        &mut self,
        aggregator_key: (Epoch, u64),
        data_key: (Slot, Hash256, u64),
        identity: Hash256,
        bits: ssz_types::BitList<E::MaxValidatorsPerSlot>,
        earliest_slot: Slot,
    ) -> Result<u64, PqAttestationGossipObservation> {
        self.prune(earliest_slot);
        match self.aggregate_status(aggregator_key, data_key, identity, &bits) {
            PqAttestationGossipObservation::Unseen => {
                let generation = self.allocate_generation()?;
                self.aggregators.insert(
                    aggregator_key,
                    ObservationState::Pending {
                        identity,
                        generation,
                    },
                );
                self.aggregate_candidates
                    .entry(data_key)
                    .or_default()
                    .push(AggregateObservation {
                        identity,
                        generation,
                        pending: true,
                        bits,
                    });
                Ok(generation)
            }
            other => Err(other),
        }
    }

    fn finalize_aggregate(&mut self, binding: &AggregateObservationBinding<E>) -> bool {
        let aggregator_authorized = matches!(
            self.aggregators.get(&binding.aggregator_key),
            Some(ObservationState::Pending { identity, generation })
                if *identity == binding.identity && *generation == binding.generation
        );
        let candidate_authorized = self
            .aggregate_candidates
            .get(&binding.data_key)
            .is_some_and(|candidates| {
                candidates.iter().any(|candidate| {
                    candidate.pending
                        && candidate.identity == binding.identity
                        && candidate.generation == binding.generation
                })
            });
        if !aggregator_authorized || !candidate_authorized {
            return false;
        }
        self.aggregators.insert(
            binding.aggregator_key,
            ObservationState::Observed {
                identity: binding.identity,
            },
        );
        if let Some(candidates) = self.aggregate_candidates.get_mut(&binding.data_key) {
            candidates.retain(|candidate| {
                candidate.generation == binding.generation
                    || candidate.pending
                    || !candidate.bits.is_subset(&binding.bits)
            });
            if let Some(candidate) = candidates
                .iter_mut()
                .find(|candidate| candidate.generation == binding.generation)
            {
                candidate.pending = false;
            }
        }
        true
    }

    fn rollback_aggregate(&mut self, binding: &AggregateObservationBinding<E>) {
        if matches!(
            self.aggregators.get(&binding.aggregator_key),
            Some(ObservationState::Pending { identity, generation })
                if *identity == binding.identity && *generation == binding.generation
        ) {
            self.aggregators.remove(&binding.aggregator_key);
        }
        if let Some(candidates) = self.aggregate_candidates.get_mut(&binding.data_key) {
            candidates.retain(|candidate| {
                !(candidate.pending
                    && candidate.identity == binding.identity
                    && candidate.generation == binding.generation)
            });
            if candidates.is_empty() {
                self.aggregate_candidates.remove(&binding.data_key);
            }
        }
    }
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
enum PqSingleObservationOwnedMember<E: EthSpec> {
    LocalReserved {
        reservation: PqSingleObservationLocalReservation<E>,
        #[cfg(feature = "pq-startup-testing")]
        completion: PqSingleObservationWatchReceipt,
    },
    WaitRemote {
        identity: PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        status: PqSingleObservationStatus,
        local_reclaim: bool,
        completion: PqSingleObservationWatchReceipt,
    },
    Coalesced(PqSingleConsumptionResult),
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
struct PqSingleObservationLocalReservation<E: EthSpec> {
    cache: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
    binding: Option<SingleObservationBinding>,
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
impl<E: EthSpec> PqSingleObservationLocalReservation<E> {
    fn finalize(
        mut self,
        result: PqSingleConsumptionResult,
    ) -> Result<(), PqSingleObservationWatchError> {
        let binding = self
            .binding
            .take()
            .ok_or(PqSingleObservationWatchError::Lost)?;
        if self.cache.lock().finalize_single(
            binding.identity,
            binding.wire_id,
            binding.generation,
            result,
        ) {
            Ok(())
        } else {
            Err(PqSingleObservationWatchError::Lost)
        }
    }
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
impl<E: EthSpec> Drop for PqSingleObservationLocalReservation<E> {
    fn drop(&mut self) {
        if let Some(binding) = self.binding.take() {
            self.cache.lock().finalize_single(
                binding.identity,
                binding.wire_id,
                binding.generation,
                PqSingleConsumptionResult::Terminal,
            );
        }
    }
}

/// Atomic owner for exact local reservations, remote completion receipts, and coalesced results.
///
/// The owner is intentionally non-Clone. Dropping an unconsumed local wire-success reservation
/// terminalizes it, so `ConsumptionPending` cannot be stranded.
#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
pub(crate) struct PqSingleObservationBatchResolutionOwner<E: EthSpec = types::MinimalEthSpec> {
    cache: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
    earliest_slot: Slot,
    members: Option<Vec<PqSingleObservationOwnedMember<E>>>,
    fail_closed: Option<Box<dyn FnOnce() + Send>>,
    #[cfg(feature = "pq-startup-testing")]
    owner_count: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
impl<E: EthSpec> PqSingleObservationBatchResolutionOwner<E> {
    #[cfg(feature = "pq-proposer")]
    pub(crate) fn resolve_publication_evidence(
        cache: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
        members: &[(
            PqSingleObservationIdentity,
            PqSingleWireMessageId,
            Option<PqSingleConsumptionResult>,
        )],
        earliest_slot: Slot,
        fail_closed: Option<Box<dyn FnOnce() + Send>>,
    ) -> Result<Self, PqSingleObservationBatchError> {
        let requests = members
            .iter()
            .map(|(identity, wire_id, remote_result)| {
                PqSingleObservationBatchRequest::new(
                    *identity,
                    *wire_id,
                    remote_result.map_or(
                        PqSingleObservationBatchSource::LocalWireSuccess,
                        PqSingleObservationBatchSource::RemoteConsumed,
                    ),
                )
            })
            .collect::<Vec<_>>();
        Self::resolve(
            cache,
            &requests,
            earliest_slot,
            #[cfg(feature = "pq-startup-testing")]
            None,
            fail_closed,
        )
    }

    #[cfg(feature = "pq-startup-testing")]
    pub(crate) fn resolve_local_wire_success(
        cache: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
        identities: &[PqSingleObservationIdentity],
        earliest_slot: Slot,
        fail_closed: Option<Box<dyn FnOnce() + Send>>,
    ) -> Result<Self, PqSingleObservationBatchError> {
        let requests = identities
            .iter()
            .copied()
            .map(|identity| {
                PqSingleObservationBatchRequest::new(
                    identity,
                    testing_wire_id(identity),
                    PqSingleObservationBatchSource::LocalWireSuccess,
                )
            })
            .collect::<Vec<_>>();
        Self::resolve(
            cache,
            &requests,
            earliest_slot,
            #[cfg(feature = "pq-startup-testing")]
            None,
            fail_closed,
        )
    }

    fn resolve(
        cache: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
        requests: &[PqSingleObservationBatchRequest],
        earliest_slot: Slot,
        #[cfg(feature = "pq-startup-testing")] owner_count: Option<
            Arc<std::sync::atomic::AtomicUsize>,
        >,
        fail_closed: Option<Box<dyn FnOnce() + Send>>,
    ) -> Result<Self, PqSingleObservationBatchError> {
        let mut cache_guard = cache.lock();
        let reservation = cache_guard.resolve_exact_single_batch(requests, earliest_slot)?;
        let mut members = Vec::with_capacity(reservation.members.len());
        for member in reservation.members {
            let owned = match member {
                PqSingleObservationBatchMemberResolution::LocalReserved(binding) => {
                    #[cfg(feature = "pq-startup-testing")]
                    let completion = cache_guard
                        .subscribe_exact_single(&binding.identity, binding.wire_id)
                        .map_err(|_| PqSingleObservationBatchError::Conflict)?;
                    PqSingleObservationOwnedMember::LocalReserved {
                        reservation: PqSingleObservationLocalReservation {
                            cache: Arc::clone(&cache),
                            binding: Some(binding),
                        },
                        #[cfg(feature = "pq-startup-testing")]
                        completion,
                    }
                }
                PqSingleObservationBatchMemberResolution::WaitRemote {
                    identity,
                    wire_id,
                    status,
                    local_reclaim,
                } => {
                    let completion = cache_guard
                        .subscribe_exact_single(&identity, wire_id)
                        .map_err(|_| PqSingleObservationBatchError::Conflict)?;
                    PqSingleObservationOwnedMember::WaitRemote {
                        identity,
                        wire_id,
                        status,
                        local_reclaim,
                        completion,
                    }
                }
                PqSingleObservationBatchMemberResolution::Coalesced(result) => {
                    PqSingleObservationOwnedMember::Coalesced(result)
                }
            };
            members.push(owned);
        }
        drop(cache_guard);
        #[cfg(feature = "pq-startup-testing")]
        if let Some(count) = owner_count.as_ref() {
            count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        Ok(Self {
            cache,
            earliest_slot,
            members: Some(members),
            fail_closed,
            #[cfg(feature = "pq-startup-testing")]
            owner_count,
        })
    }

    #[cfg(feature = "pq-startup-testing")]
    async fn wait_all(
        mut self,
    ) -> Result<Vec<PqSingleObservationCompletion>, PqSingleObservationWatchError> {
        let members = self
            .members
            .take()
            .ok_or(PqSingleObservationWatchError::Lost)?;
        let mut completions = Vec::with_capacity(members.len());
        for member in members {
            let completion = match member {
                PqSingleObservationOwnedMember::LocalReserved {
                    reservation,
                    mut completion,
                } => {
                    let _reservation = reservation;
                    completion.wait().await?
                }
                PqSingleObservationOwnedMember::WaitRemote { mut completion, .. } => {
                    completion.wait().await?
                }
                PqSingleObservationOwnedMember::Coalesced(result) => {
                    PqSingleObservationCompletion::Consumed(result)
                }
            };
            completions.push(completion);
        }
        Ok(completions)
    }

    pub(crate) async fn settle_remote_members(
        mut self,
    ) -> Result<Self, PqPublishedLocalAttestationBatchConsumptionError> {
        let members = self
            .members
            .take()
            .ok_or(PqPublishedLocalAttestationBatchConsumptionError::TaskUnavailable)?;
        let mut members = members.into_iter().enumerate();
        let mut settled = Vec::new();

        while let Some((index, member)) = members.next() {
            let settled_member = match member {
                local @ PqSingleObservationOwnedMember::LocalReserved { .. }
                | local @ PqSingleObservationOwnedMember::Coalesced(_) => local,
                PqSingleObservationOwnedMember::WaitRemote {
                    identity,
                    wire_id,
                    local_reclaim,
                    mut completion,
                    ..
                } => match completion.wait().await {
                    Ok(PqSingleObservationCompletion::Consumed(
                        result @ (PqSingleConsumptionResult::Applied
                        | PqSingleConsumptionResult::Queued),
                    )) => PqSingleObservationOwnedMember::Coalesced(result),
                    Ok(PqSingleObservationCompletion::Released) if local_reclaim => {
                        match self.reclaim_released_local(identity, wire_id) {
                            Ok(local) => local,
                            Err(error) => {
                                drop(settled);
                                drop(members);
                                self.signal_fail_closed();
                                return Err(error);
                            }
                        }
                    }
                    Ok(PqSingleObservationCompletion::Consumed(
                        PqSingleConsumptionResult::Terminal,
                    )) => {
                        drop(settled);
                        drop(members);
                        self.signal_fail_closed();
                        return Err(
                            PqPublishedLocalAttestationBatchConsumptionError::Observation(
                                PqSingleObservationBatchError::Terminal,
                            ),
                        );
                    }
                    Ok(PqSingleObservationCompletion::ConsumedTerminalAlreadySignaled) => {
                        drop(settled);
                        drop(members);
                        return Err(
                            PqPublishedLocalAttestationBatchConsumptionError::Observation(
                                PqSingleObservationBatchError::Terminal,
                            ),
                        );
                    }
                    Ok(PqSingleObservationCompletion::Released) => {
                        drop(settled);
                        drop(members);
                        self.signal_fail_closed();
                        return Err(
                            PqPublishedLocalAttestationBatchConsumptionError::Observation(
                                PqSingleObservationBatchError::RemoteUnseen,
                            ),
                        );
                    }
                    Err(PqSingleObservationWatchError::Lost) => {
                        drop(settled);
                        drop(members);
                        self.signal_fail_closed();
                        return Err(
                            PqPublishedLocalAttestationBatchConsumptionError::ObservationLost {
                                index,
                            },
                        );
                    }
                },
            };
            settled.push(settled_member);
        }

        self.members = Some(settled);
        Ok(self)
    }

    fn reclaim_released_local(
        &self,
        identity: PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
    ) -> Result<PqSingleObservationOwnedMember<E>, PqPublishedLocalAttestationBatchConsumptionError>
    {
        let request = PqSingleObservationBatchRequest::new(
            identity,
            wire_id,
            PqSingleObservationBatchSource::LocalWireSuccess,
        );
        let mut cache = self.cache.lock();
        let reservation = cache
            .resolve_exact_single_batch(&[request], self.earliest_slot)
            .map_err(PqPublishedLocalAttestationBatchConsumptionError::Observation)?;
        let Some(PqSingleObservationBatchMemberResolution::LocalReserved(binding)) =
            reservation.members.into_iter().next()
        else {
            return Err(
                PqPublishedLocalAttestationBatchConsumptionError::Observation(
                    PqSingleObservationBatchError::Conflict,
                ),
            );
        };
        #[cfg(feature = "pq-startup-testing")]
        let completion = cache
            .subscribe_exact_single(&binding.identity, binding.wire_id)
            .map_err(|_| {
                PqPublishedLocalAttestationBatchConsumptionError::Observation(
                    PqSingleObservationBatchError::Conflict,
                )
            })?;
        Ok(PqSingleObservationOwnedMember::LocalReserved {
            reservation: PqSingleObservationLocalReservation {
                cache: Arc::clone(&self.cache),
                binding: Some(binding),
            },
            #[cfg(feature = "pq-startup-testing")]
            completion,
        })
    }

    fn signal_fail_closed(&mut self) {
        if let Some(fail_closed) = self.fail_closed.take() {
            fail_closed();
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    pub(crate) fn consume_all_local<F, ApplyError>(
        self,
        apply: F,
    ) -> Result<
        PqPublishedLocalAttestationBatchConsumptionOutcome,
        PqPublishedLocalAttestationBatchConsumptionError,
    >
    where
        F: FnMut(usize) -> Result<PqForkChoiceAttestationOutcome, ApplyError>,
    {
        self.consume_all_local_after_disposition(apply, |_, _| Ok(()))
    }

    pub(crate) fn consume_all_local_after_disposition<F, D, ApplyError>(
        mut self,
        mut apply: F,
        mut after_disposition: D,
    ) -> Result<
        PqPublishedLocalAttestationBatchConsumptionOutcome,
        PqPublishedLocalAttestationBatchConsumptionError,
    >
    where
        F: FnMut(usize) -> Result<PqForkChoiceAttestationOutcome, ApplyError>,
        D: FnMut(
            usize,
            PqSingleConsumptionResult,
        ) -> Result<(), operation_pool::PqAttestationPoolInsertInvariant>,
    {
        let members = self
            .members
            .take()
            .ok_or(PqPublishedLocalAttestationBatchConsumptionError::TaskUnavailable)?;
        let mut results = Vec::with_capacity(members.len());
        let mut applied_count = 0_usize;

        let mut members = members.into_iter().enumerate();
        while let Some((index, member)) = members.next() {
            match member {
                PqSingleObservationOwnedMember::LocalReserved { reservation, .. } => {
                    let outcome = match apply(index) {
                        Ok(outcome) => outcome,
                        Err(_) => {
                            drop(reservation);
                            drop(members);
                            if let Some(fail_closed) = self.fail_closed.take() {
                                fail_closed();
                            }
                            return Err(
                                PqPublishedLocalAttestationBatchConsumptionError::ApplyFailed {
                                    applied_count,
                                    failed_index: index,
                                },
                            );
                        }
                    };
                    let result = pq_single_consumption_result_from_fork_choice(outcome);
                    if let Err(invariant) = after_disposition(index, result) {
                        drop(reservation);
                        drop(members);
                        if let Some(fail_closed) = self.fail_closed.take() {
                            fail_closed();
                        }
                        return Err(
                            PqPublishedLocalAttestationBatchConsumptionError::PoolInvariant {
                                index,
                                invariant,
                            },
                        );
                    }
                    if reservation.finalize(result).is_err() {
                        drop(members);
                        if let Some(fail_closed) = self.fail_closed.take() {
                            fail_closed();
                        }
                        return Err(
                            PqPublishedLocalAttestationBatchConsumptionError::ObservationLost {
                                index,
                            },
                        );
                    }
                    applied_count = applied_count.saturating_add(1);
                    results.push(result);
                }
                PqSingleObservationOwnedMember::WaitRemote {
                    status, completion, ..
                } => {
                    drop(completion);
                    drop(members);
                    if let Some(fail_closed) = self.fail_closed.take() {
                        fail_closed();
                    }
                    return Err(
                        PqPublishedLocalAttestationBatchConsumptionError::RemotePending {
                            index,
                            status,
                        },
                    );
                }
                PqSingleObservationOwnedMember::Coalesced(result) => {
                    if let Err(invariant) = after_disposition(index, result) {
                        drop(members);
                        if let Some(fail_closed) = self.fail_closed.take() {
                            fail_closed();
                        }
                        return Err(
                            PqPublishedLocalAttestationBatchConsumptionError::PoolInvariant {
                                index,
                                invariant,
                            },
                        );
                    }
                    results.push(result);
                }
            }
        }

        self.fail_closed.take();
        Ok(PqPublishedLocalAttestationBatchConsumptionOutcome::Complete { results })
    }
}

#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
impl<E: EthSpec> Drop for PqSingleObservationBatchResolutionOwner<E> {
    fn drop(&mut self) {
        let has_local_reservation = self.members.as_ref().is_some_and(|members| {
            members.iter().any(|member| {
                matches!(member, PqSingleObservationOwnedMember::LocalReserved { .. })
            })
        });
        if has_local_reservation && let Some(fail_closed) = self.fail_closed.take() {
            fail_closed();
        }
        #[cfg(feature = "pq-startup-testing")]
        if let Some(count) = self.owner_count.take() {
            count.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }
}

#[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
struct TestingPqPublishedLocalLateApplyState {
    state_slot: Slot,
    block_slot: Slot,
    current_head_root: Hash256,
    reconciliation_root: Hash256,
    bound_is_ancestor: bool,
    fork_choice_slot: Slot,
    last_fork_choice_current_slot: Option<Slot>,
}

#[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
#[doc(hidden)]
pub struct TestingPqPublishedLocalLateApplyHarness {
    state: Arc<Mutex<TestingPqPublishedLocalLateApplyState>>,
    clock_slot: Arc<std::sync::atomic::AtomicU64>,
    fork_choice_entry_hook: Arc<Mutex<Option<Arc<crate::TestingPqBlockingHook>>>>,
    import_gate: Arc<tokio::sync::Semaphore>,
    local_proof_admission: Arc<tokio::sync::Semaphore>,
    observations: Arc<Mutex<PqAttestationGossipObservationCache<types::MinimalEthSpec>>>,
    local_identity: PqSingleObservationIdentity,
    remote_identity: PqSingleObservationIdentity,
    remote_wire_id: PqSingleWireMessageId,
    remote_generation: u64,
    remote_waiting: Arc<std::sync::atomic::AtomicBool>,
    fork_choice_calls: Arc<std::sync::atomic::AtomicUsize>,
    fail_closed_calls: Arc<std::sync::atomic::AtomicUsize>,
    apply_hook: Arc<crate::TestingPqBlockingHook>,
    bound_head_root: Hash256,
    signed_slot: Slot,
}

#[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
#[doc(hidden)]
pub struct TestingPqPublishedLocalLateApplyReceipt {
    task: tokio::task::JoinHandle<
        Result<
            PqPublishedLocalAttestationBatchConsumptionOutcome,
            PqPublishedLocalAttestationBatchConsumptionError,
        >,
    >,
}

#[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
impl TestingPqPublishedLocalLateApplyReceipt {
    pub async fn wait(
        self,
    ) -> Result<
        PqPublishedLocalAttestationBatchConsumptionOutcome,
        PqPublishedLocalAttestationBatchConsumptionError,
    > {
        self.task.await.unwrap_or(Err(
            PqPublishedLocalAttestationBatchConsumptionError::TaskUnavailable,
        ))
    }
}

#[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
impl TestingPqPublishedLocalLateApplyHarness {
    pub fn new(
        signed_slot: Slot,
        bound_head_root: Hash256,
        apply_hook: Arc<crate::TestingPqBlockingHook>,
    ) -> Self {
        let local_identity = PqSingleObservationIdentity::new(
            signed_slot.epoch(types::MinimalEthSpec::slots_per_epoch()),
            1,
            signed_slot,
            SubnetId::new(0),
            Hash256::repeat_byte(0xb1),
            [0xc1; 32],
        );
        let remote_identity = PqSingleObservationIdentity::new(
            signed_slot.epoch(types::MinimalEthSpec::slots_per_epoch()),
            2,
            signed_slot,
            SubnetId::new(0),
            Hash256::repeat_byte(0xb2),
            [0xc2; 32],
        );
        let remote_wire_id = testing_wire_id(remote_identity);
        let observations = Arc::new(Mutex::new(PqAttestationGossipObservationCache::default()));
        let earliest_slot = signed_slot
            .epoch(types::MinimalEthSpec::slots_per_epoch())
            .start_slot(types::MinimalEthSpec::slots_per_epoch());
        let remote_generation = observations
            .lock()
            .claim_single(remote_identity, remote_wire_id, earliest_slot)
            .expect("testing remote observation claim");
        assert!(observations.lock().mark_single_propagated(
            remote_identity,
            remote_wire_id,
            remote_generation,
        ));
        Self {
            state: Arc::new(Mutex::new(TestingPqPublishedLocalLateApplyState {
                state_slot: signed_slot,
                block_slot: signed_slot,
                current_head_root: bound_head_root,
                reconciliation_root: bound_head_root,
                bound_is_ancestor: true,
                fork_choice_slot: signed_slot,
                last_fork_choice_current_slot: None,
            })),
            clock_slot: Arc::new(std::sync::atomic::AtomicU64::new(signed_slot.as_u64())),
            fork_choice_entry_hook: Arc::new(Mutex::new(None)),
            import_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            local_proof_admission: Arc::new(tokio::sync::Semaphore::new(
                PQ_LOCAL_ATTESTATION_PROOF_ADMISSION_CAPACITY,
            )),
            observations,
            local_identity,
            remote_identity,
            remote_wire_id,
            remote_generation,
            remote_waiting: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            fork_choice_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            fail_closed_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            apply_hook,
            bound_head_root,
            signed_slot,
        }
    }

    pub fn start_mixed_local_and_remote(&self) -> TestingPqPublishedLocalLateApplyReceipt {
        let proof_permit = Arc::clone(&self.local_proof_admission)
            .try_acquire_many_owned(
                u32::try_from(PQ_LOCAL_ATTESTATION_PROOF_ADMISSION_CAPACITY)
                    .expect("local proof capacity fits u32"),
            )
            .expect("testing verified batch retains both local proof permits");
        let fail_closed_calls = Arc::clone(&self.fail_closed_calls);
        let owner = PqSingleObservationBatchResolutionOwner::resolve_publication_evidence(
            Arc::clone(&self.observations),
            &[
                (
                    self.local_identity,
                    testing_wire_id(self.local_identity),
                    None,
                ),
                (self.remote_identity, self.remote_wire_id, None),
            ],
            self.signed_slot
                .epoch(types::MinimalEthSpec::slots_per_epoch())
                .start_slot(types::MinimalEthSpec::slots_per_epoch()),
            Some(Box::new(move || {
                fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        )
        .expect("testing mixed local/remote observation owner");
        let state = Arc::clone(&self.state);
        let clock_slot = Arc::clone(&self.clock_slot);
        let fork_choice_entry_hook = self.fork_choice_entry_hook.lock().clone();
        let import_gate = Arc::clone(&self.import_gate);
        let remote_waiting = Arc::clone(&self.remote_waiting);
        let fork_choice_calls = Arc::clone(&self.fork_choice_calls);
        let apply_hook = Arc::clone(&self.apply_hook);
        let signed_slot = self.signed_slot;
        let bound_head_root = self.bound_head_root;
        let task = tokio::spawn(async move {
            let _proof_permit = proof_permit;
            remote_waiting.store(true, std::sync::atomic::Ordering::SeqCst);
            let owner = owner.settle_remote_members().await?;
            let import_gate = import_gate.acquire_owned().await.map_err(|_| {
                PqPublishedLocalAttestationBatchConsumptionError::Preflight(
                    crate::PqLocalAttestationBatchPreflightError::HeadTransitionBusy,
                )
            })?;
            let sampled = {
                let state = state.lock();
                (
                    Slot::new(clock_slot.load(std::sync::atomic::Ordering::SeqCst)),
                    state.state_slot,
                    state.block_slot,
                    state.current_head_root,
                    state.reconciliation_root,
                )
            };
            let state_root = Hash256::repeat_byte(0xd1);
            let members = [
                crate::TestingPqLocalAttestationPreflightMember::new(signed_slot, bound_head_root),
                crate::TestingPqLocalAttestationPreflightMember::new(signed_slot, bound_head_root),
            ];
            let final_current_slot =
                Slot::new(clock_slot.load(std::sync::atomic::Ordering::SeqCst));
            let late_apply = crate::pq_local_attester_context::testing_prepare_pq_local_attestation_late_apply_context(
                import_gate,
                &members,
                sampled.0,
                sampled
                    .0
                    .epoch(types::MinimalEthSpec::slots_per_epoch())
                    .start_slot(types::MinimalEthSpec::slots_per_epoch()),
                sampled.0 + 1,
                sampled.1,
                sampled.2,
                sampled.3,
                state_root,
                state_root,
                crate::TestingPqLocalAttestationPreflightReconciliation::Reconciled(sampled.4),
                final_current_slot,
            )
            .map_err(PqPublishedLocalAttestationBatchConsumptionError::Preflight)?;
            tokio::task::spawn_blocking(move || {
                if let Some(hook) = fork_choice_entry_hook {
                    hook.run();
                }
                let mut state = state.lock();
                crate::pq_local_attester_context::consume_pq_published_local_attestation_batch_after_settlement(
                    late_apply,
                    &mut *state,
                    || {
                        Some(Slot::new(
                            clock_slot.load(std::sync::atomic::Ordering::SeqCst),
                        ))
                    },
                    |state| state.fork_choice_slot,
                    |state, bound, current| bound == current || state.bound_is_ancestor,
                    |state, current_slot| {
                        owner.consume_all_local(|_| {
                            apply_hook.run();
                            state.last_fork_choice_current_slot = Some(current_slot);
                            fork_choice_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            Ok::<PqForkChoiceAttestationOutcome, ()>(
                                PqForkChoiceAttestationOutcome::Applied,
                            )
                        })
                    },
                )
                .map_err(PqPublishedLocalAttestationBatchConsumptionError::Preflight)
                .and_then(std::convert::identity)
            })
            .await
            .unwrap_or(Err(
                PqPublishedLocalAttestationBatchConsumptionError::TaskUnavailable,
            ))
        });
        TestingPqPublishedLocalLateApplyReceipt { task }
    }

    pub async fn wait_until_remote_settlement(&self) {
        for _ in 0..1_000 {
            if self
                .remote_waiting
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("testing mixed batch did not enter remote settlement");
    }

    pub fn try_hold_import_gate(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.import_gate).try_acquire_owned().ok()
    }

    pub fn set_clock(&self, slot: Slot) {
        self.clock_slot
            .store(slot.as_u64(), std::sync::atomic::Ordering::SeqCst);
    }

    pub fn set_fork_choice_entry_hook(&self, hook: Arc<crate::TestingPqBlockingHook>) {
        *self.fork_choice_entry_hook.lock() = Some(hook);
    }

    pub fn set_fork_choice_slot(&self, slot: Slot) {
        self.state.lock().fork_choice_slot = slot;
    }

    pub fn set_reconciled_head(
        &self,
        slot: Slot,
        current_head_root: Hash256,
        bound_is_ancestor: bool,
    ) {
        let mut state = self.state.lock();
        state.state_slot = slot;
        state.block_slot = slot;
        state.current_head_root = current_head_root;
        state.reconciliation_root = current_head_root;
        state.bound_is_ancestor = bound_is_ancestor;
    }

    pub fn finalize_remote(&self, result: PqSingleConsumptionResult) {
        assert!(self.observations.lock().finalize_single(
            self.remote_identity,
            self.remote_wire_id,
            self.remote_generation,
            result,
        ));
    }

    pub fn fork_choice_attestation_calls(&self) -> usize {
        self.fork_choice_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn fail_closed_calls(&self) -> usize {
        self.fail_closed_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn local_observation_status(&self) -> PqSingleObservationStatus {
        self.observations
            .lock()
            .exact_single_status(&self.local_identity)
    }

    pub fn available_local_proof_permits(&self) -> usize {
        self.local_proof_admission.available_permits()
    }

    pub fn last_fork_choice_current_slot(&self) -> Option<Slot> {
        self.state.lock().last_fork_choice_current_slot
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Default)]
pub struct TestingPqAttestationObservationCache {
    inner: PqAttestationGossipObservationCache<types::MinimalEthSpec>,
}

#[cfg(feature = "pq-startup-testing")]
fn testing_wire_id(identity: PqSingleObservationIdentity) -> PqSingleWireMessageId {
    let mut bytes = [0_u8; 20];
    bytes.copy_from_slice(&identity.signed_ssz_digest[..20]);
    PqSingleWireMessageId(bytes)
}

#[cfg(feature = "pq-startup-testing")]
impl TestingPqAttestationObservationCache {
    fn legacy_single_identity(
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
    ) -> PqSingleObservationIdentity {
        PqSingleObservationIdentity::new(
            epoch,
            validator_index,
            Slot::new(0),
            SubnetId::new(0),
            identity,
            [0; 32],
        )
    }

    fn participant_bits(
        participant_indices: &[usize],
    ) -> ssz_types::BitList<<types::MinimalEthSpec as EthSpec>::MaxValidatorsPerSlot> {
        let mut bits = ssz_types::BitList::with_capacity(16)
            .expect("16 participants fit the minimal test profile");
        for index in participant_indices {
            bits.set(*index, true)
                .expect("test participant index is within the 16-validator profile");
        }
        bits
    }

    pub const fn capacity(&self) -> usize {
        PQ_ATTESTATION_OBSERVATION_CAPACITY
    }

    pub fn len_singles(&self) -> usize {
        self.inner.singles.len()
    }

    pub fn set_next_generation(&mut self, generation: u64) {
        self.inner.next_generation = generation;
    }

    pub const fn next_generation(&self) -> u64 {
        self.inner.next_generation
    }

    pub fn observe_single(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
        earliest_slot: Slot,
    ) -> Result<(), PqAttestationGossipObservation> {
        let identity = Self::legacy_single_identity(epoch, validator_index, identity);
        let wire_id = testing_wire_id(identity);
        let generation = self.inner.claim_single(identity, wire_id, earliest_slot)?;
        if self.inner.finalize_single(
            identity,
            wire_id,
            generation,
            PqSingleConsumptionResult::Applied,
        ) {
            Ok(())
        } else {
            Err(PqAttestationGossipObservation::Conflict)
        }
    }

    pub fn claim_single(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
        earliest_slot: Slot,
    ) -> Result<u64, PqAttestationGossipObservation> {
        let identity = Self::legacy_single_identity(epoch, validator_index, identity);
        self.inner
            .claim_single(identity, testing_wire_id(identity), earliest_slot)
    }

    pub fn status_single(
        &self,
        epoch: Epoch,
        validator_index: u64,
        _identity: Hash256,
    ) -> PqAttestationGossipObservation {
        self.inner.single_status((epoch, validator_index))
    }

    pub fn finalize_single(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
        generation: u64,
    ) -> bool {
        let identity = Self::legacy_single_identity(epoch, validator_index, identity);
        self.inner.finalize_single(
            identity,
            testing_wire_id(identity),
            generation,
            PqSingleConsumptionResult::Applied,
        )
    }

    pub fn mark_single_propagated(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
        generation: u64,
    ) -> bool {
        let identity = Self::legacy_single_identity(epoch, validator_index, identity);
        self.inner
            .mark_single_propagated(identity, testing_wire_id(identity), generation)
    }

    pub fn finalize_single_terminal(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
        generation: u64,
    ) -> bool {
        let identity = Self::legacy_single_identity(epoch, validator_index, identity);
        self.inner.finalize_single(
            identity,
            testing_wire_id(identity),
            generation,
            PqSingleConsumptionResult::Terminal,
        )
    }

    pub fn single_consumption_result(
        &self,
        epoch: Epoch,
        validator_index: u64,
    ) -> Option<PqSingleConsumptionResult> {
        self.inner
            .single_consumption_result((epoch, validator_index))
    }

    pub fn rollback_single(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
        generation: u64,
    ) -> bool {
        let identity = Self::legacy_single_identity(epoch, validator_index, identity);
        self.inner
            .rollback_single(identity, testing_wire_id(identity), generation)
    }

    pub fn claim_exact_single(
        &mut self,
        identity: &PqSingleObservationIdentity,
        earliest_slot: Slot,
    ) -> Result<u64, PqAttestationGossipObservation> {
        self.inner
            .claim_single(*identity, testing_wire_id(*identity), earliest_slot)
    }

    pub fn exact_single_status(
        &self,
        identity: &PqSingleObservationIdentity,
    ) -> PqSingleObservationStatus {
        self.inner.exact_single_status(identity)
    }

    pub fn subscribe_exact_single(
        &self,
        identity: &PqSingleObservationIdentity,
    ) -> Result<PqSingleObservationWatchReceipt, PqSingleObservationStatus> {
        self.inner
            .subscribe_exact_single(identity, testing_wire_id(*identity))
    }

    pub fn rollback_exact_single(
        &mut self,
        identity: &PqSingleObservationIdentity,
        generation: u64,
    ) -> bool {
        self.inner
            .rollback_single(*identity, testing_wire_id(*identity), generation)
    }

    pub fn mark_exact_single_propagated(
        &mut self,
        identity: &PqSingleObservationIdentity,
        generation: u64,
    ) -> bool {
        self.inner
            .mark_single_propagated(*identity, testing_wire_id(*identity), generation)
    }

    pub fn finalize_exact_single(
        &mut self,
        identity: &PqSingleObservationIdentity,
        generation: u64,
        result: PqSingleConsumptionResult,
    ) -> bool {
        self.inner
            .finalize_single(*identity, testing_wire_id(*identity), generation, result)
    }

    pub fn resolve_exact_single_batch(
        &mut self,
        inputs: &[TestingPqSingleObservationBatchInput],
        earliest_slot: Slot,
    ) -> Result<Vec<PqSingleObservationBatchResolution>, PqSingleObservationBatchError> {
        let requests = inputs
            .iter()
            .map(|input| match input {
                TestingPqSingleObservationBatchInput::LocalWireSuccess(identity) => {
                    PqSingleObservationBatchRequest::new(
                        *identity,
                        testing_wire_id(*identity),
                        PqSingleObservationBatchSource::LocalWireSuccess,
                    )
                }
                TestingPqSingleObservationBatchInput::Remote(identity) => {
                    PqSingleObservationBatchRequest::new(
                        *identity,
                        testing_wire_id(*identity),
                        PqSingleObservationBatchSource::Remote,
                    )
                }
            })
            .collect::<Vec<_>>();
        self.inner
            .resolve_exact_single_batch(&requests, earliest_slot)
            .map(|reservation| {
                reservation
                    .members
                    .into_iter()
                    .map(|member| match member {
                        PqSingleObservationBatchMemberResolution::LocalReserved(_binding) => {
                            PqSingleObservationBatchResolution::LocalReserved
                        }
                        PqSingleObservationBatchMemberResolution::WaitRemote { status, .. } => {
                            PqSingleObservationBatchResolution::WaitRemote(status)
                        }
                        PqSingleObservationBatchMemberResolution::Coalesced(result) => {
                            PqSingleObservationBatchResolution::Coalesced(result)
                        }
                    })
                    .collect()
            })
    }

    pub fn precheck_single(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        earliest_slot: Slot,
    ) -> PqAttestationGossipObservation {
        self.inner
            .precheck_single((epoch, validator_index), earliest_slot)
    }

    pub fn len_aggregators(&self) -> usize {
        self.inner.aggregators.len()
    }

    pub fn len_aggregate_candidates(&self) -> usize {
        self.inner.aggregate_candidates.values().map(Vec::len).sum()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn claim_aggregate(
        &mut self,
        epoch: Epoch,
        aggregator_index: u64,
        slot: Slot,
        data_root: Hash256,
        committee_index: u64,
        identity: Hash256,
        participant_indices: &[usize],
        earliest_slot: Slot,
    ) -> Result<u64, PqAttestationGossipObservation> {
        self.inner.claim_aggregate(
            (epoch, aggregator_index),
            (slot, data_root, committee_index),
            identity,
            Self::participant_bits(participant_indices),
            earliest_slot,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finalize_aggregate(
        &mut self,
        epoch: Epoch,
        aggregator_index: u64,
        slot: Slot,
        data_root: Hash256,
        committee_index: u64,
        identity: Hash256,
        generation: u64,
        participant_indices: &[usize],
    ) -> bool {
        self.inner.finalize_aggregate(&AggregateObservationBinding {
            aggregator_key: (epoch, aggregator_index),
            data_key: (slot, data_root, committee_index),
            identity,
            generation,
            bits: Self::participant_bits(participant_indices),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rollback_aggregate(
        &mut self,
        epoch: Epoch,
        aggregator_index: u64,
        slot: Slot,
        data_root: Hash256,
        committee_index: u64,
        identity: Hash256,
        generation: u64,
        participant_indices: &[usize],
    ) -> bool {
        let binding = AggregateObservationBinding {
            aggregator_key: (epoch, aggregator_index),
            data_key: (slot, data_root, committee_index),
            identity,
            generation,
            bits: Self::participant_bits(participant_indices),
        };
        let authorized = matches!(
            self.inner.aggregators.get(&binding.aggregator_key),
            Some(ObservationState::Pending {
                identity: known,
                generation: known_generation,
            }) if *known == identity && *known_generation == generation
        );
        self.inner.rollback_aggregate(&binding);
        authorized
    }

    #[allow(clippy::too_many_arguments)]
    pub fn precheck_aggregate(
        &mut self,
        epoch: Epoch,
        aggregator_index: u64,
        slot: Slot,
        data_root: Hash256,
        committee_index: u64,
        participant_indices: &[usize],
        earliest_slot: Slot,
    ) -> PqAttestationGossipObservation {
        self.inner.precheck_aggregate(
            (epoch, aggregator_index),
            (slot, data_root, committee_index),
            &Self::participant_bits(participant_indices),
            earliest_slot,
        )
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Default)]
pub struct TestingPqAttestationObservationOwnerCache {
    inner: Arc<Mutex<PqAttestationGossipObservationCache<types::MinimalEthSpec>>>,
    owner_count: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Default)]
pub struct TestingPqWireBoundObservationCache {
    inner: Arc<Mutex<PqAttestationGossipObservationCache<types::MinimalEthSpec>>>,
}

#[cfg(feature = "pq-startup-testing")]
impl TestingPqWireBoundObservationCache {
    pub fn claim_exact_single(
        &self,
        identity: &PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        earliest_slot: Slot,
    ) -> Result<u64, PqAttestationGossipObservation> {
        self.inner
            .lock()
            .claim_single(*identity, wire_id, earliest_slot)
    }

    pub fn exact_single_status(
        &self,
        identity: &PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
    ) -> PqSingleObservationStatus {
        self.inner
            .lock()
            .exact_single_wire_status(identity, wire_id)
    }

    pub fn subscribe_exact_single(
        &self,
        identity: &PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
    ) -> Result<PqSingleObservationWatchReceipt, PqSingleObservationStatus> {
        self.inner.lock().subscribe_exact_single(identity, wire_id)
    }

    pub fn mark_exact_single_propagated(
        &self,
        identity: &PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        generation: u64,
    ) -> bool {
        self.inner
            .lock()
            .mark_single_propagated(*identity, wire_id, generation)
    }

    pub fn finalize_exact_single(
        &self,
        identity: &PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        generation: u64,
        result: PqSingleConsumptionResult,
    ) -> bool {
        self.inner
            .lock()
            .finalize_single(*identity, wire_id, generation, result)
    }

    pub fn rollback_exact_single(
        &self,
        identity: &PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
        generation: u64,
    ) -> bool {
        self.inner
            .lock()
            .rollback_single(*identity, wire_id, generation)
    }
}

#[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
#[doc(hidden)]
pub struct TestingPqPublishedLocalMemberWire {
    topic_hash: lighthouse_network::TopicHash,
    signed_ssz: Vec<u8>,
    message_domain_valid_snappy: [u8; 4],
    altair_enabled: bool,
}

#[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
impl TestingPqPublishedLocalMemberWire {
    pub const fn topic_hash(&self) -> &lighthouse_network::TopicHash {
        &self.topic_hash
    }

    pub fn signed_ssz(&self) -> &[u8] {
        &self.signed_ssz
    }

    pub const fn message_domain_valid_snappy(&self) -> [u8; 4] {
        self.message_domain_valid_snappy
    }

    pub const fn altair_enabled(&self) -> bool {
        self.altair_enabled
    }
}

/// Opaque fixture around the same sealed-member validation and exact cache subscription core used
/// by `PqPublishedLocalAttestationBatchConsumer`. No observation identity leaves this driver.
#[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
#[doc(hidden)]
pub struct TestingPqPublishedLocalMemberResolver {
    cache: Arc<Mutex<PqAttestationGossipObservationCache<types::MinimalEthSpec>>>,
    identity: PqSingleObservationIdentity,
    wire: TestingPqPublishedLocalMemberWire,
    sealed_signed_ssz_digest: [u8; 32],
    generation: Option<u64>,
}

#[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
impl TestingPqPublishedLocalMemberResolver {
    pub const fn borrowed_sealed_member_wire(&self) -> &TestingPqPublishedLocalMemberWire {
        &self.wire
    }

    pub fn claim_exact_observation(&mut self) {
        let wire_id = self.wire_id();
        self.generation = self
            .cache
            .lock()
            .claim_single(self.identity, wire_id, Slot::new(0))
            .ok();
    }

    pub const fn generation(&self) -> Option<u64> {
        self.generation
    }

    pub fn message_id(&self) -> lighthouse_network::MessageId {
        lighthouse_network::pq_anonymous_message_id(
            &self.wire.topic_hash,
            &self.wire.signed_ssz,
            self.wire.message_domain_valid_snappy,
            self.wire.altair_enabled,
        )
    }

    pub const fn signed_ssz_digest(&self) -> [u8; 32] {
        self.sealed_signed_ssz_digest
    }

    pub fn exact_status(&self) -> PqSingleObservationStatus {
        self.cache
            .lock()
            .exact_single_wire_status(&self.identity, self.wire_id())
    }

    pub const fn observation_identity(&self) -> PqSingleObservationIdentity {
        self.identity
    }

    pub fn observation_wire_id(&self) -> PqSingleWireMessageId {
        self.wire_id()
    }

    pub fn exact_status_for(
        &self,
        identity: &PqSingleObservationIdentity,
        wire_id: PqSingleWireMessageId,
    ) -> PqSingleObservationStatus {
        self.cache
            .lock()
            .exact_single_wire_status(identity, wire_id)
    }

    fn wire_id(&self) -> PqSingleWireMessageId {
        let message_id = lighthouse_network::pq_anonymous_message_id(
            &self.wire.topic_hash,
            &self.wire.signed_ssz,
            self.wire.message_domain_valid_snappy,
            self.wire.altair_enabled,
        );
        PqSingleWireMessageId::try_from(message_id.0.as_slice())
            .expect("anonymous gossipsub IDs are exactly 20 bytes")
    }

    pub fn mark_exact_observation_propagated(&self) {
        if let Some(generation) = self.generation {
            let _ =
                self.cache
                    .lock()
                    .mark_single_propagated(self.identity, self.wire_id(), generation);
        }
    }

    pub fn finalize_exact_observation(&self, result: PqSingleConsumptionResult) {
        if let Some(generation) = self.generation {
            let _ = self.cache.lock().finalize_single(
                self.identity,
                self.wire_id(),
                generation,
                result,
            );
        }
    }

    pub fn finalize_exact_terminal_already_signaled(&self) -> bool {
        self.generation.is_some_and(|generation| {
            self.cache.lock().finalize_single_with_authority(
                self.identity,
                self.wire_id(),
                generation,
                PqSingleConsumptionResult::Terminal,
                true,
            )
        })
    }

    pub fn finalize_exact_observation_before_resolution(
        &mut self,
        result: PqSingleConsumptionResult,
    ) {
        self.claim_exact_observation();
        self.finalize_exact_observation(result);
    }

    pub fn rollback_exact_observation(&self) {
        if let Some(generation) = self.generation {
            let _ = self
                .cache
                .lock()
                .rollback_single(self.identity, self.wire_id(), generation);
        }
    }

    pub fn arrange_exact_status(&mut self, status: PqSingleObservationStatus) {
        match status {
            PqSingleObservationStatus::Unseen => {}
            PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Terminal) => {
                self.finalize_exact_observation_before_resolution(
                    PqSingleConsumptionResult::Terminal,
                );
            }
            PqSingleObservationStatus::Conflict => {
                let conflicting = PqSingleObservationIdentity::new(
                    self.identity.target_epoch,
                    self.identity.validator_index,
                    self.identity.slot,
                    self.identity.subnet,
                    Hash256::repeat_byte(0x7f),
                    [0x7f; 32],
                );
                let _ = self
                    .cache
                    .lock()
                    .claim_single(conflicting, self.wire_id(), Slot::new(0));
            }
            _ => {}
        }
    }

    pub fn resolve(
        &self,
        message_id: &lighthouse_network::MessageId,
    ) -> Result<PqPublishedLocalMemberResolution, PqSingleObservationStatus> {
        let expected_message_id = lighthouse_network::pq_anonymous_message_id(
            &self.wire.topic_hash,
            &self.wire.signed_ssz,
            self.wire.message_domain_valid_snappy,
            self.wire.altair_enabled,
        );
        resolve_pq_published_local_member(
            &self.cache,
            self.identity,
            &self.wire.signed_ssz,
            self.sealed_signed_ssz_digest,
            &expected_message_id,
            message_id,
        )
        .map_err(|error| match error {
            PqPublishedLocalMemberResolutionError::Observation(status) => status,
            PqPublishedLocalMemberResolutionError::Member
            | PqPublishedLocalMemberResolutionError::Identity
            | PqPublishedLocalMemberResolutionError::SignedSszDigest
            | PqPublishedLocalMemberResolutionError::MessageId
            | PqPublishedLocalMemberResolutionError::ObservationLost
            | PqPublishedLocalMemberResolutionError::AdmissionBridgeLost => {
                PqSingleObservationStatus::Conflict
            }
        })
    }

    pub fn testing_only_corrupt_sealed_member_signed_ssz_digest(&mut self) {
        self.sealed_signed_ssz_digest[0] ^= 1;
    }

    pub fn testing_only_lose_exact_observation(&mut self) {
        self.cache = Arc::new(Mutex::new(PqAttestationGossipObservationCache::default()));
        self.generation = None;
    }

    pub fn subscription_count(&self) -> usize {
        self.cache
            .lock()
            .singles
            .get(&self.identity.key())
            .map_or(0, |state| state.completion().receiver_count())
    }
}

#[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
#[doc(hidden)]
pub fn testing_only_pq_published_local_member_resolver() -> TestingPqPublishedLocalMemberResolver {
    let signed_ssz = vec![0x31, 0x41, 0x59, 0x26];
    let signed_ssz_digest: [u8; 32] = Sha256::digest(&signed_ssz).into();
    let subnet = SubnetId::new(3);
    let fork_digest = [0x11; 4];
    let topic = lighthouse_network::IdentTopic::from(lighthouse_network::GossipTopic::new(
        lighthouse_network::types::GossipKind::Attestation(subnet),
        lighthouse_network::types::GossipEncoding::default(),
        fork_digest,
    ));
    let identity = PqSingleObservationIdentity::new(
        Epoch::new(1),
        3,
        Slot::new(8),
        subnet,
        Hash256::repeat_byte(0x22),
        signed_ssz_digest,
    );
    TestingPqPublishedLocalMemberResolver {
        cache: Arc::new(Mutex::new(PqAttestationGossipObservationCache::default())),
        identity,
        sealed_signed_ssz_digest: identity.signed_ssz_digest,
        wire: TestingPqPublishedLocalMemberWire {
            topic_hash: topic.hash(),
            signed_ssz,
            message_domain_valid_snappy: [0x33; 4],
            altair_enabled: true,
        },
        generation: None,
    }
}

#[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPqPublishedLocalAttestationEvidenceMutation {
    SignedSszByte,
    Topic,
    MessageId,
    MemberIdentity,
    MemberOrder,
    MemberCount,
}

#[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPqRemotePublicationEvidenceStatus {
    Unseen,
    Conflict,
    Terminal,
}

#[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
#[doc(hidden)]
pub struct TestingPqPublishedLocalAttestationEvidenceTrace {
    pub result: Result<
        PqPublishedLocalAttestationBatchConsumptionOutcome,
        crate::PqPublishedLocalAttestationEvidenceError,
    >,
    pub fork_choice_calls: usize,
    pub fail_closed_calls: usize,
}

#[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
struct TestingPqLocalPublicationEvidence {
    token: lighthouse_network::PqLocalSinglePublicationToken,
    message_id: lighthouse_network::MessageId,
    topic_hash: lighthouse_network::TopicHash,
    fork_digest: [u8; 4],
    subnet: SubnetId,
    signed_ssz_digest: [u8; 32],
}

#[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
#[doc(hidden)]
pub struct TestingPqPublishedLocalAttestationEvidenceHarness {
    cache: TestingPqAttestationObservationOwnerCache,
    identities: Vec<PqSingleObservationIdentity>,
    message_ids: Vec<lighthouse_network::MessageId>,
    local: Option<Vec<TestingPqLocalPublicationEvidence>>,
}

#[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
impl TestingPqPublishedLocalAttestationEvidenceHarness {
    pub async fn from_exact_lower_publications<const N: usize>(
        identities: [PqSingleObservationIdentity; N],
    ) -> Result<Self, crate::PqPublishedLocalAttestationEvidenceError> {
        let mut local = Vec::with_capacity(N);
        let mut message_ids = Vec::with_capacity(N);
        for (member, identity) in identities.iter().enumerate() {
            let member_byte = u8::try_from(member).unwrap_or(u8::MAX);
            let fork_digest = [member_byte.saturating_add(1); 4];
            let topic = lighthouse_network::GossipTopic::new(
                lighthouse_network::types::GossipKind::Attestation(identity.subnet),
                lighthouse_network::types::GossipEncoding::default(),
                fork_digest,
            );
            let topic_hash = lighthouse_network::IdentTopic::from(topic.clone()).hash();
            let data = vec![0x80, member_byte, 0x81];
            let message_id =
                lighthouse_network::MessageId(vec![member_byte.saturating_add(0x40); 20]);
            let outcome = lighthouse_network::testing_only_classify_pq_local_single_publication(
                &topic,
                &data,
                message_id.clone(),
                false,
            );
            let token = match outcome {
                lighthouse_network::PqSingleAttestationPublishOutcome::Published {
                    publication: Some(token),
                    ..
                } => token,
                _ => {
                    return Err(crate::PqPublishedLocalAttestationEvidenceError::Mismatch {
                        member,
                        field: "testing-lower-publication",
                    });
                }
            };
            let signed_ssz_digest = token.signed_ssz_digest();
            local.push(TestingPqLocalPublicationEvidence {
                token,
                message_id: message_id.clone(),
                topic_hash,
                fork_digest,
                subnet: identity.subnet,
                signed_ssz_digest,
            });
            message_ids.push(message_id);
        }
        Ok(Self {
            cache: TestingPqAttestationObservationOwnerCache::default(),
            identities: identities.to_vec(),
            message_ids,
            local: Some(local),
        })
    }

    pub fn with_remote_observations<const N: usize>(
        members: [(lighthouse_network::MessageId, PqSingleObservationIdentity); N],
        status: TestingPqRemotePublicationEvidenceStatus,
    ) -> Self {
        let cache = TestingPqAttestationObservationOwnerCache::default();
        let earliest_slot = Slot::new(0);
        for (message_id, identity) in &members {
            let Ok(wire_id) = PqSingleWireMessageId::try_from(message_id.0.as_slice()) else {
                continue;
            };
            match status {
                TestingPqRemotePublicationEvidenceStatus::Unseen => {}
                TestingPqRemotePublicationEvidenceStatus::Conflict => {
                    let conflicting = PqSingleObservationIdentity::new(
                        identity.target_epoch,
                        identity.validator_index,
                        identity.slot,
                        identity.subnet,
                        identity.signed_tree_hash_root,
                        [identity.signed_ssz_digest[0].wrapping_add(1); 32],
                    );
                    let _ = cache
                        .inner
                        .lock()
                        .claim_single(conflicting, wire_id, earliest_slot);
                }
                TestingPqRemotePublicationEvidenceStatus::Terminal => {
                    let mut inner = cache.inner.lock();
                    if let Ok(generation) = inner.claim_single(*identity, wire_id, earliest_slot) {
                        let _ = inner.mark_single_propagated(*identity, wire_id, generation);
                        let _ = inner.finalize_single(
                            *identity,
                            wire_id,
                            generation,
                            PqSingleConsumptionResult::Terminal,
                        );
                    }
                }
            }
        }
        Self {
            cache,
            identities: members.iter().map(|(_, identity)| *identity).collect(),
            message_ids: members
                .iter()
                .map(|(message_id, _)| message_id.clone())
                .collect(),
            local: None,
        }
    }

    pub fn with_remote_consumed<const N: usize>(
        members: [(
            lighthouse_network::MessageId,
            PqSingleObservationIdentity,
            PqSingleConsumptionResult,
        ); N],
    ) -> Self {
        let cache = TestingPqAttestationObservationOwnerCache::default();
        let earliest_slot = Slot::new(0);
        for (message_id, identity, result) in &members {
            let Ok(wire_id) = PqSingleWireMessageId::try_from(message_id.0.as_slice()) else {
                continue;
            };
            let mut inner = cache.inner.lock();
            if let Ok(generation) = inner.claim_single(*identity, wire_id, earliest_slot) {
                let _ = inner.mark_single_propagated(*identity, wire_id, generation);
                let _ = inner.finalize_single(*identity, wire_id, generation, *result);
            }
        }
        Self {
            cache,
            identities: members.iter().map(|(_, identity, _)| *identity).collect(),
            message_ids: members
                .iter()
                .map(|(message_id, _, _)| message_id.clone())
                .collect(),
            local: None,
        }
    }

    pub async fn consume_with_local_evidence_mutation(
        mut self,
        mutation: TestingPqPublishedLocalAttestationEvidenceMutation,
    ) -> TestingPqPublishedLocalAttestationEvidenceTrace {
        let mut local = self.local.take().unwrap_or_default();
        match mutation {
            TestingPqPublishedLocalAttestationEvidenceMutation::SignedSszByte => {
                if let Some(expected) = local.first_mut() {
                    expected.signed_ssz_digest[0] ^= 1;
                }
            }
            TestingPqPublishedLocalAttestationEvidenceMutation::Topic => {
                if let Some(expected) = local.first_mut() {
                    expected.topic_hash = lighthouse_network::IdentTopic::new("wrong-topic").hash();
                }
            }
            TestingPqPublishedLocalAttestationEvidenceMutation::MessageId => {
                if let Some(expected) = local.first_mut() {
                    expected.message_id = lighthouse_network::MessageId(vec![0xff; 20]);
                }
            }
            TestingPqPublishedLocalAttestationEvidenceMutation::MemberIdentity => {
                if let Some(expected) = local.first_mut() {
                    expected.subnet = SubnetId::new(u64::from(expected.subnet).saturating_add(1));
                }
            }
            TestingPqPublishedLocalAttestationEvidenceMutation::MemberOrder => {
                if local.len() >= 2 {
                    let (first, rest) = local.split_at_mut(1);
                    std::mem::swap(&mut first[0].token, &mut rest[0].token);
                }
            }
            TestingPqPublishedLocalAttestationEvidenceMutation::MemberCount => {
                let _ = local.pop();
            }
        }
        let result = if local.len() != self.identities.len() {
            Err(crate::PqPublishedLocalAttestationEvidenceError::Mismatch {
                member: local.len(),
                field: "member-count",
            })
        } else {
            local
                .iter()
                .enumerate()
                .try_for_each(|(index, expected)| {
                    crate::beacon_chain::validate_pq_local_single_publication_token(
                        index,
                        &expected.token,
                        &expected.message_id,
                        &expected.topic_hash,
                        expected.fork_digest,
                        expected.subnet,
                        expected.signed_ssz_digest,
                    )
                })
                .map(
                    |()| PqPublishedLocalAttestationBatchConsumptionOutcome::Complete {
                        results: vec![],
                    },
                )
        };
        let fail_closed_calls = usize::from(result.is_err());
        TestingPqPublishedLocalAttestationEvidenceTrace {
            result,
            fork_choice_calls: 0,
            fail_closed_calls,
        }
    }

    pub async fn consume_claimed_remote<const N: usize>(
        self,
        claims: [(lighthouse_network::MessageId, PqSingleConsumptionResult); N],
    ) -> TestingPqPublishedLocalAttestationEvidenceTrace {
        if claims.len() != self.identities.len()
            || claims
                .iter()
                .zip(&self.message_ids)
                .any(|((claimed, _), expected)| claimed != expected)
        {
            return TestingPqPublishedLocalAttestationEvidenceTrace {
                result: Err(crate::PqPublishedLocalAttestationEvidenceError::Mismatch {
                    member: 0,
                    field: "remote-message-id",
                }),
                fork_choice_calls: 0,
                fail_closed_calls: 1,
            };
        }
        let members = self
            .identities
            .iter()
            .copied()
            .zip(&claims)
            .map(|(identity, (message_id, result))| {
                Ok((
                    identity,
                    PqSingleWireMessageId::try_from(message_id.0.as_slice()).map_err(|_| ())?,
                    Some(*result),
                ))
            })
            .collect::<Result<Vec<_>, ()>>();
        let Ok(members) = members else {
            return TestingPqPublishedLocalAttestationEvidenceTrace {
                result: Err(crate::PqPublishedLocalAttestationEvidenceError::Mismatch {
                    member: 0,
                    field: "remote-message-id",
                }),
                fork_choice_calls: 0,
                fail_closed_calls: 1,
            };
        };
        let owner = PqSingleObservationBatchResolutionOwner::resolve_publication_evidence(
            Arc::clone(&self.cache.inner),
            &members,
            Slot::new(0),
            None,
        );
        let mut fork_choice_calls = 0_usize;
        let result = match owner {
            Ok(owner) => match owner.settle_remote_members().await {
                Ok(owner) => owner
                    .consume_all_local(|_| {
                        fork_choice_calls = fork_choice_calls.saturating_add(1);
                        Ok::<PqForkChoiceAttestationOutcome, ()>(
                            PqForkChoiceAttestationOutcome::Applied,
                        )
                    })
                    .map_err(
                        |_| crate::PqPublishedLocalAttestationEvidenceError::RemoteResult {
                            member: 0,
                        },
                    ),
                Err(_) => {
                    Err(crate::PqPublishedLocalAttestationEvidenceError::RemoteResult { member: 0 })
                }
            },
            Err(_) => {
                Err(crate::PqPublishedLocalAttestationEvidenceError::RemoteResult { member: 0 })
            }
        };
        TestingPqPublishedLocalAttestationEvidenceTrace {
            fail_closed_calls: usize::from(result.is_err()),
            result,
            fork_choice_calls,
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestingPqSingleObservationBatchInput {
    LocalWireSuccess(PqSingleObservationIdentity),
    Remote(PqSingleObservationIdentity),
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub struct TestingPqSingleObservationResolutionReceipt(
    PqSingleObservationBatchResolutionOwner<types::MinimalEthSpec>,
);

#[cfg(feature = "pq-startup-testing")]
impl TestingPqSingleObservationResolutionReceipt {
    pub async fn wait_all(
        self,
    ) -> Result<Vec<PqSingleObservationCompletion>, PqSingleObservationWatchError> {
        self.0.wait_all().await
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub struct TestingPqPublishedLocalAttestationConsumptionTrace {
    pub result: Result<
        PqPublishedLocalAttestationBatchConsumptionOutcome,
        PqPublishedLocalAttestationBatchConsumptionError,
    >,
    pub apply_attempt_order: Vec<usize>,
    pub fail_closed_calls: usize,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub struct TestingPqPublishedLocalAttestationWaitReceipt {
    owner: Result<
        PqSingleObservationBatchResolutionOwner<types::MinimalEthSpec>,
        PqPublishedLocalAttestationBatchConsumptionError,
    >,
    apply_plan: Vec<Result<PqForkChoiceAttestationOutcome, crate::PqForkChoiceAttestationError>>,
    fail_closed_calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(feature = "pq-startup-testing")]
impl TestingPqPublishedLocalAttestationWaitReceipt {
    pub async fn wait(self) -> TestingPqPublishedLocalAttestationConsumptionTrace {
        let Self {
            owner,
            apply_plan,
            fail_closed_calls,
        } = self;
        let mut apply_plan = apply_plan.into_iter();
        let mut apply_attempt_order = Vec::new();
        let result = match owner {
            Ok(owner) => match owner.settle_remote_members().await {
                Ok(owner) => owner.consume_all_local(|index| {
                    apply_attempt_order.push(index);
                    apply_plan
                        .next()
                        .unwrap_or(Err(crate::PqForkChoiceAttestationError::TaskUnavailable))
                }),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        TestingPqPublishedLocalAttestationConsumptionTrace {
            result,
            apply_attempt_order,
            fail_closed_calls: fail_closed_calls.load(std::sync::atomic::Ordering::SeqCst),
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
impl TestingPqAttestationObservationOwnerCache {
    pub fn claim_exact_single(
        &self,
        identity: &PqSingleObservationIdentity,
        earliest_slot: Slot,
    ) -> Result<u64, PqAttestationGossipObservation> {
        self.inner
            .lock()
            .claim_single(*identity, testing_wire_id(*identity), earliest_slot)
    }

    pub fn exact_single_status(
        &self,
        identity: &PqSingleObservationIdentity,
    ) -> PqSingleObservationStatus {
        self.inner.lock().exact_single_status(identity)
    }

    pub fn subscribe_exact_single(
        &self,
        identity: &PqSingleObservationIdentity,
    ) -> Result<PqSingleObservationWatchReceipt, PqSingleObservationStatus> {
        self.inner
            .lock()
            .subscribe_exact_single(identity, testing_wire_id(*identity))
    }

    pub fn mark_exact_single_propagated(
        &self,
        identity: &PqSingleObservationIdentity,
        generation: u64,
    ) -> bool {
        self.inner
            .lock()
            .mark_single_propagated(*identity, testing_wire_id(*identity), generation)
    }

    pub fn finalize_exact_single(
        &self,
        identity: &PqSingleObservationIdentity,
        generation: u64,
        result: PqSingleConsumptionResult,
    ) -> bool {
        self.inner
            .lock()
            .finalize_single(*identity, testing_wire_id(*identity), generation, result)
    }

    pub fn rollback_exact_single(
        &self,
        identity: &PqSingleObservationIdentity,
        generation: u64,
    ) -> bool {
        self.inner
            .lock()
            .rollback_single(*identity, testing_wire_id(*identity), generation)
    }

    pub fn lose_exact_single_completion_for_testing(&self, identity: &PqSingleObservationIdentity) {
        self.inner.lock().singles.remove(&identity.key());
    }

    pub fn resolve_exact_single_batch_owned(
        &self,
        inputs: &[TestingPqSingleObservationBatchInput],
        earliest_slot: Slot,
    ) -> Result<TestingPqSingleObservationResolutionReceipt, PqSingleObservationBatchError> {
        let requests = inputs
            .iter()
            .map(|input| match input {
                TestingPqSingleObservationBatchInput::LocalWireSuccess(identity) => {
                    PqSingleObservationBatchRequest::new(
                        *identity,
                        testing_wire_id(*identity),
                        PqSingleObservationBatchSource::LocalWireSuccess,
                    )
                }
                TestingPqSingleObservationBatchInput::Remote(identity) => {
                    PqSingleObservationBatchRequest::new(
                        *identity,
                        testing_wire_id(*identity),
                        PqSingleObservationBatchSource::Remote,
                    )
                }
            })
            .collect::<Vec<_>>();
        PqSingleObservationBatchResolutionOwner::resolve(
            Arc::clone(&self.inner),
            &requests,
            earliest_slot,
            Some(Arc::clone(&self.owner_count)),
            None,
        )
        .map(TestingPqSingleObservationResolutionReceipt)
    }

    pub async fn consume_published_local_batch_for_testing(
        &self,
        identities: &[PqSingleObservationIdentity],
        apply_plan: Vec<
            Result<PqForkChoiceAttestationOutcome, crate::PqForkChoiceAttestationError>,
        >,
    ) -> TestingPqPublishedLocalAttestationConsumptionTrace {
        let fail_closed_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let owner_fail_closed_calls = Arc::clone(&fail_closed_calls);
        let owner = PqSingleObservationBatchResolutionOwner::resolve_local_wire_success(
            Arc::clone(&self.inner),
            identities,
            Slot::new(0),
            Some(Box::new(move || {
                owner_fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        );
        let mut apply_plan = apply_plan.into_iter();
        let mut apply_attempt_order = Vec::new();
        let result = match owner {
            Ok(owner) => owner.consume_all_local(|index| {
                apply_attempt_order.push(index);
                apply_plan
                    .next()
                    .unwrap_or(Err(crate::PqForkChoiceAttestationError::TaskUnavailable))
            }),
            Err(error) => Err(PqPublishedLocalAttestationBatchConsumptionError::Observation(error)),
        };
        TestingPqPublishedLocalAttestationConsumptionTrace {
            result,
            apply_attempt_order,
            fail_closed_calls: fail_closed_calls.load(std::sync::atomic::Ordering::SeqCst),
        }
    }

    pub async fn consume_published_local_batch_with_pool_invariant_for_testing(
        &self,
        identities: &[PqSingleObservationIdentity],
        failing_index: usize,
    ) -> TestingPqPublishedLocalAttestationConsumptionTrace {
        let fail_closed_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let owner_fail_closed_calls = Arc::clone(&fail_closed_calls);
        let owner = PqSingleObservationBatchResolutionOwner::resolve_local_wire_success(
            Arc::clone(&self.inner),
            identities,
            Slot::new(0),
            Some(Box::new(move || {
                owner_fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        );
        let mut apply_attempt_order = Vec::new();
        let result = match owner {
            Ok(owner) => owner.consume_all_local_after_disposition(
                |index| {
                    apply_attempt_order.push(index);
                    Ok::<PqForkChoiceAttestationOutcome, ()>(
                        PqForkChoiceAttestationOutcome::Applied,
                    )
                },
                |index, _| {
                    if index == failing_index {
                        Err(operation_pool::PqAttestationPoolInsertInvariant::GenerationExhausted)
                    } else {
                        Ok(())
                    }
                },
            ),
            Err(error) => Err(PqPublishedLocalAttestationBatchConsumptionError::Observation(error)),
        };
        TestingPqPublishedLocalAttestationConsumptionTrace {
            result,
            apply_attempt_order,
            fail_closed_calls: fail_closed_calls.load(std::sync::atomic::Ordering::SeqCst),
        }
    }

    pub fn start_published_local_batch_wait_for_testing(
        &self,
        inputs: &[TestingPqSingleObservationBatchInput],
        apply_plan: Vec<
            Result<PqForkChoiceAttestationOutcome, crate::PqForkChoiceAttestationError>,
        >,
    ) -> TestingPqPublishedLocalAttestationWaitReceipt {
        let requests = inputs
            .iter()
            .map(|input| match input {
                TestingPqSingleObservationBatchInput::LocalWireSuccess(identity) => {
                    PqSingleObservationBatchRequest::new(
                        *identity,
                        testing_wire_id(*identity),
                        PqSingleObservationBatchSource::LocalWireSuccess,
                    )
                }
                TestingPqSingleObservationBatchInput::Remote(identity) => {
                    PqSingleObservationBatchRequest::new(
                        *identity,
                        testing_wire_id(*identity),
                        PqSingleObservationBatchSource::Remote,
                    )
                }
            })
            .collect::<Vec<_>>();
        let fail_closed_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let owner_fail_closed_calls = Arc::clone(&fail_closed_calls);
        let owner = PqSingleObservationBatchResolutionOwner::resolve(
            Arc::clone(&self.inner),
            &requests,
            Slot::new(0),
            Some(Arc::clone(&self.owner_count)),
            Some(Box::new(move || {
                owner_fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        )
        .map_err(|error| {
            fail_closed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            PqPublishedLocalAttestationBatchConsumptionError::Observation(error)
        });
        TestingPqPublishedLocalAttestationWaitReceipt {
            owner,
            apply_plan,
            fail_closed_calls,
        }
    }

    pub fn drop_published_local_batch_owner_before_apply_for_testing(
        &self,
        identities: &[PqSingleObservationIdentity],
        fail_closed: impl FnOnce() + Send + 'static,
    ) {
        let owner = PqSingleObservationBatchResolutionOwner::resolve_local_wire_success(
            Arc::clone(&self.inner),
            identities,
            Slot::new(0),
            Some(Box::new(fail_closed)),
        )
        .expect("bounded exact local test batch resolves atomically");
        drop(owner);
    }

    pub fn precheck_single(
        &self,
        epoch: Epoch,
        validator_index: u64,
        earliest_slot: Slot,
    ) -> PqAttestationGossipObservation {
        self.inner
            .lock()
            .precheck_single((epoch, validator_index), earliest_slot)
    }

    pub fn next_generation(&self) -> u64 {
        self.inner.lock().next_generation
    }

    pub fn resolution_owner_count(&self) -> usize {
        self.owner_count.load(std::sync::atomic::Ordering::Acquire)
    }
}

struct SingleObservationBinding {
    identity: PqSingleObservationIdentity,
    wire_id: PqSingleWireMessageId,
    generation: u64,
}

/// BeaconChain-contextual sealed provenance for a propagated single attestation.
pub struct PqVerifiedGossipSingle<E: EthSpec> {
    verified: Option<VerifiedPqSingleAttestation<E>>,
    observations: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
    binding: Option<SingleObservationBinding>,
    admission: Option<OwnedSemaphorePermit>,
    activity: Option<Arc<crate::beacon_chain::PqImportActivity>>,
    subnet: SubnetId,
    bound_head_root: Hash256,
}

impl<E: EthSpec> PqVerifiedGossipSingle<E> {
    pub const fn verified(&self) -> Option<&VerifiedPqSingleAttestation<E>> {
        self.verified.as_ref()
    }

    pub const fn subnet(&self) -> SubnetId {
        self.subnet
    }

    pub const fn bound_head_root(&self) -> Hash256 {
        self.bound_head_root
    }

    pub(crate) fn into_consumption_parts(
        mut self,
    ) -> Result<
        (
            VerifiedPqSingleAttestation<E>,
            SubnetId,
            Hash256,
            PqSingleGossipConsumption<E>,
        ),
        PqAttestationGossipError,
    > {
        if self.verified.is_none()
            || self.binding.is_none()
            || self.admission.is_none()
            || self.activity.is_none()
        {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ));
        }
        let verified = self.verified.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        let binding = self.binding.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        let admission = self
            .admission
            .take()
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ))?;
        let activity = self.activity.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        Ok((
            verified,
            self.subnet,
            self.bound_head_root,
            PqSingleGossipConsumption {
                observations: Arc::clone(&self.observations),
                binding: Some(binding),
                _admission: admission,
                _activity: activity,
            },
        ))
    }
}

impl<E: EthSpec> Drop for PqVerifiedGossipSingle<E> {
    fn drop(&mut self) {
        if let Some(binding) = self.binding.take() {
            self.observations.lock().finalize_single(
                binding.identity,
                binding.wire_id,
                binding.generation,
                PqSingleConsumptionResult::Terminal,
            );
        }
    }
}

/// Contextually verified local single, sealed without touching remote gossip observations.
///
/// The exact signed wire object, signing root, complete signed-SSZ digest and immutable local duty
/// metadata remain bound together. This type is deliberately non-`Clone` and has no fork-choice
/// application or gossip-propagation method in Slice B1.
pub struct PqVerifiedLocalSingle<E: EthSpec> {
    verified: VerifiedPqSingleAttestation<E>,
    pubkey: consensus_signature::ValidatorPublicKeyBytes,
    validator_index: u64,
    committee_index: u64,
    committee_position: usize,
    committee_length: usize,
    committee_count_at_slot: u64,
    subnet: SubnetId,
    slot: Slot,
    bound_head_root: Hash256,
    dependent_root: Hash256,
    signing_root: Hash256,
    signed_tree_hash_root: Hash256,
    signed_ssz_digest: [u8; 32],
    _admission: OwnedSemaphorePermit,
    _activity: Arc<crate::beacon_chain::PqImportActivity>,
}

#[cfg(feature = "pq-proposer")]
pub(crate) struct PqVerifiedLocalSinglePoolGuard {
    _admission: OwnedSemaphorePermit,
    _activity: Arc<crate::beacon_chain::PqImportActivity>,
}

impl<E: EthSpec> PqVerifiedLocalSingle<E> {
    pub const fn verified(&self) -> &VerifiedPqSingleAttestation<E> {
        &self.verified
    }

    pub const fn single(&self) -> &SingleAttestation {
        self.verified.single_attestation()
    }

    pub const fn pubkey(&self) -> consensus_signature::ValidatorPublicKeyBytes {
        self.pubkey
    }

    pub const fn validator_index(&self) -> u64 {
        self.validator_index
    }

    pub const fn committee_index(&self) -> u64 {
        self.committee_index
    }

    pub const fn committee_position(&self) -> usize {
        self.committee_position
    }

    pub const fn committee_length(&self) -> usize {
        self.committee_length
    }

    pub const fn committee_count_at_slot(&self) -> u64 {
        self.committee_count_at_slot
    }

    pub const fn subnet(&self) -> SubnetId {
        self.subnet
    }

    pub const fn slot(&self) -> Slot {
        self.slot
    }

    pub const fn bound_head_root(&self) -> Hash256 {
        self.bound_head_root
    }

    pub const fn dependent_root(&self) -> Hash256 {
        self.dependent_root
    }

    pub const fn signing_root(&self) -> Hash256 {
        self.signing_root
    }

    pub const fn observation_identity(&self) -> PqSingleObservationIdentity {
        PqSingleObservationIdentity::new(
            self.single().data.target.epoch,
            self.validator_index,
            self.slot,
            self.subnet,
            self.signed_tree_hash_root,
            self.signed_ssz_digest,
        )
    }

    pub const fn signed_ssz_digest(&self) -> [u8; 32] {
        self.signed_ssz_digest
    }

    #[cfg(feature = "pq-proposer")]
    pub(crate) fn into_pool_parts(
        self,
    ) -> (
        u64,
        VerifiedPqAttestation<E>,
        PqVerifiedLocalSinglePoolGuard,
    ) {
        let Self {
            verified,
            validator_index,
            _admission,
            _activity,
            ..
        } = self;
        let (_single, candidate) = verified.into_parts();
        (
            validator_index,
            candidate,
            PqVerifiedLocalSinglePoolGuard {
                _admission,
                _activity,
            },
        )
    }
}

pub(crate) struct PqSingleGossipConsumption<E: EthSpec> {
    observations: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
    binding: Option<SingleObservationBinding>,
    _admission: OwnedSemaphorePermit,
    _activity: Arc<crate::beacon_chain::PqImportActivity>,
}

impl<E: EthSpec> PqSingleGossipConsumption<E> {
    pub(crate) fn finalize_fork_choice(
        mut self,
        outcome: PqForkChoiceAttestationOutcome,
    ) -> Result<(), PqAttestationGossipError> {
        self.finalize(pq_single_consumption_result_from_fork_choice(outcome))
    }

    pub(crate) fn finalize_terminal(mut self) -> Result<(), PqAttestationGossipError> {
        self.finalize_with_authority(PqSingleConsumptionResult::Terminal, true)
    }

    fn finalize(
        &mut self,
        result: PqSingleConsumptionResult,
    ) -> Result<(), PqAttestationGossipError> {
        self.finalize_with_authority(result, false)
    }

    fn finalize_with_authority(
        &mut self,
        result: PqSingleConsumptionResult,
        failure_already_signaled: bool,
    ) -> Result<(), PqAttestationGossipError> {
        let binding = self.binding.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        if self.observations.lock().finalize_single_with_authority(
            binding.identity,
            binding.wire_id,
            binding.generation,
            result,
            failure_already_signaled,
        ) {
            Ok(())
        } else {
            Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ))
        }
    }
}

impl<E: EthSpec> Drop for PqSingleGossipConsumption<E> {
    fn drop(&mut self) {
        if let Some(binding) = self.binding.take() {
            self.observations.lock().finalize_single_with_authority(
                binding.identity,
                binding.wire_id,
                binding.generation,
                PqSingleConsumptionResult::Terminal,
                true,
            );
        }
    }
}

/// Unique post-proof capability which must be consumed only after gossipsub accepts propagation.
pub struct PqSingleGossipPropagationToken<E: EthSpec> {
    verified: Option<VerifiedPqSingleAttestation<E>>,
    observations: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
    binding: Option<SingleObservationBinding>,
    _admission: Option<OwnedSemaphorePermit>,
    _activity: Option<Arc<crate::beacon_chain::PqImportActivity>>,
    subnet: SubnetId,
    bound_head_root: Hash256,
}

impl<E: EthSpec> PqSingleGossipPropagationToken<E> {
    pub const fn verified(&self) -> Option<&VerifiedPqSingleAttestation<E>> {
        self.verified.as_ref()
    }

    /// Returns the exact observation identity sealed by the chain's blocking preparation.
    ///
    /// Network callers may carry this immutable identity into the post-propagation lifecycle, but
    /// cannot construct or alter the binding consumed by [`Self::mark_propagated`].
    pub const fn observation_identity(&self) -> Option<PqSingleObservationIdentity> {
        match self.binding.as_ref() {
            Some(binding) => Some(binding.identity),
            None => None,
        }
    }

    pub const fn observation_wire_id(&self) -> Option<PqSingleWireMessageId> {
        match self.binding.as_ref() {
            Some(binding) => Some(binding.wire_id),
            None => None,
        }
    }

    /// Marks actual gossipsub propagation and returns the sealed provenance for Task 5.2b.
    pub fn mark_propagated(
        mut self,
    ) -> Result<PqVerifiedGossipSingle<E>, PqAttestationGossipError> {
        if self.verified.is_none()
            || self.binding.is_none()
            || self._admission.is_none()
            || self._activity.is_none()
        {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ));
        }
        let binding = self.binding.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        let verified = self.verified.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        let admission = self
            ._admission
            .take()
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ))?;
        let activity = self
            ._activity
            .take()
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ))?;
        if !self.observations.lock().mark_single_propagated(
            binding.identity,
            binding.wire_id,
            binding.generation,
        ) {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ));
        }
        Ok(PqVerifiedGossipSingle {
            verified: Some(verified),
            observations: Arc::clone(&self.observations),
            binding: Some(binding),
            admission: Some(admission),
            activity: Some(activity),
            subnet: self.subnet,
            bound_head_root: self.bound_head_root,
        })
    }
}

impl<E: EthSpec> Drop for PqSingleGossipPropagationToken<E> {
    fn drop(&mut self) {
        if let Some(binding) = self.binding.take() {
            self.observations.lock().rollback_single(
                binding.identity,
                binding.wire_id,
                binding.generation,
            );
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_single_prepropagation_retry() -> bool {
    let observations = Arc::new(Mutex::new(PqAttestationGossipObservationCache::<
        types::MinimalEthSpec,
    >::default()));
    let key = (Epoch::new(0), 1);
    let identity = PqSingleObservationIdentity::new(
        key.0,
        key.1,
        Slot::new(0),
        SubnetId::new(0),
        Hash256::repeat_byte(2),
        [0; 32],
    );
    let wire_id = testing_wire_id(identity);
    let Ok(generation) = observations
        .lock()
        .claim_single(identity, wire_id, Slot::new(0))
    else {
        return false;
    };
    drop(PqSingleGossipPropagationToken {
        verified: None,
        observations: Arc::clone(&observations),
        binding: Some(SingleObservationBinding {
            identity,
            wire_id,
            generation,
        }),
        _admission: None,
        _activity: None,
        subnet: SubnetId::new(0),
        bound_head_root: Hash256::ZERO,
    });
    if observations.lock().single_status(key) != PqAttestationGossipObservation::Unseen {
        return false;
    }
    matches!(
        observations
            .lock()
            .claim_single(identity, wire_id, Slot::new(0)),
        Ok(retry_generation) if retry_generation != generation
    )
}

struct AggregateObservationBinding<E: EthSpec> {
    aggregator_key: (Epoch, u64),
    data_key: (Slot, Hash256, u64),
    identity: Hash256,
    generation: u64,
    bits: ssz_types::BitList<E::MaxValidatorsPerSlot>,
}

/// BeaconChain-contextual sealed provenance for a propagated aggregate-and-proof.
pub struct PqVerifiedGossipAggregate<E: EthSpec> {
    verified: VerifiedPqAggregateAndProof<E>,
    bound_head_root: Hash256,
}

impl<E: EthSpec> PqVerifiedGossipAggregate<E> {
    pub const fn verified(&self) -> &VerifiedPqAggregateAndProof<E> {
        &self.verified
    }

    pub const fn bound_head_root(&self) -> Hash256 {
        self.bound_head_root
    }

    pub fn into_parts(self) -> (VerifiedPqAggregateAndProof<E>, Hash256) {
        (self.verified, self.bound_head_root)
    }
}

/// Unique aggregate propagation capability holding both exact outer and verified inner provenance.
pub struct PqAggregateGossipPropagationToken<E: EthSpec> {
    verified: Option<VerifiedPqAggregateAndProof<E>>,
    observations: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
    binding: Option<AggregateObservationBinding<E>>,
    _admission: Option<OwnedSemaphorePermit>,
    bound_head_root: Hash256,
}

impl<E: EthSpec> PqAggregateGossipPropagationToken<E> {
    pub const fn verified(&self) -> Option<&VerifiedPqAggregateAndProof<E>> {
        self.verified.as_ref()
    }

    pub fn mark_propagated(
        mut self,
    ) -> Result<PqVerifiedGossipAggregate<E>, PqAttestationGossipError> {
        let binding = self.binding.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        if !self.observations.lock().finalize_aggregate(&binding) {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ));
        }
        let verified = self.verified.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        Ok(PqVerifiedGossipAggregate {
            verified,
            bound_head_root: self.bound_head_root,
        })
    }
}

impl<E: EthSpec> Drop for PqAggregateGossipPropagationToken<E> {
    fn drop(&mut self) {
        if let Some(binding) = self.binding.take() {
            self.observations.lock().rollback_aggregate(&binding);
        }
    }
}

struct PreparedSingle<E: EthSpec> {
    prepared: PreparedPqSingleAttestation<E>,
    identity: PqSingleObservationIdentity,
    bound_head_root: Hash256,
    admission: OwnedSemaphorePermit,
    activity: Arc<crate::beacon_chain::PqImportActivity>,
}

struct VerifiedSingle<E: EthSpec> {
    verified: VerifiedPqSingleAttestation<E>,
    identity: PqSingleObservationIdentity,
    bound_head_root: Hash256,
    admission: OwnedSemaphorePermit,
    activity: Arc<crate::beacon_chain::PqImportActivity>,
}

struct PreparedAggregate<E: EthSpec> {
    prepared: PreparedPqAggregateAndProof<E>,
    identity: Hash256,
    aggregator_key: (Epoch, u64),
    data_key: (Slot, Hash256, u64),
    bits: ssz_types::BitList<E::MaxValidatorsPerSlot>,
    bound_head_root: Hash256,
    admission: OwnedSemaphorePermit,
}

struct CanonicalReference<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    state: BeaconState<E>,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_try_reserve_pq_attestation_gossip_admission(
        &self,
    ) -> Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.try_reserve_pq_attestation_gossip_admission()
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_attestation_gossip_available_permits(&self) -> usize {
        self.pq_attestation_gossip_admission.available_permits()
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_try_reserve_pq_local_attestation_proof_admission(
        &self,
    ) -> Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.try_reserve_pq_local_attestation_proof_admission()
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_local_attestation_proof_available_permits(&self) -> usize {
        self.pq_local_attestation_proof_available_permits()
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub async fn testing_only_pq_attestation_bound_is_canonical(
        &self,
        bound_root: Hash256,
    ) -> Result<bool, PqAttestationGossipError> {
        let activity =
            self.pq_import_coordinator
                .try_start()
                .ok_or(PqAttestationGossipError::Local(
                    PqAttestationGossipLocalError::ShuttingDown,
                ))?;
        let admission = self
            .try_reserve_pq_attestation_gossip_admission()
            .map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::IngressCapacity)
            })?;
        self.pq_attestation_bound_is_canonical_owned(bound_root, admission, activity)
            .await
            .map(|(is_canonical, _admission, _activity)| is_canonical)
    }

    async fn pq_attestation_bound_is_canonical(
        &self,
        bound_root: Hash256,
        admission: OwnedSemaphorePermit,
    ) -> Result<(bool, OwnedSemaphorePermit), PqAttestationGossipError> {
        self.pq_attestation_bound_is_canonical_owned(bound_root, admission, ())
            .await
            .map(|(is_canonical, admission, ())| (is_canonical, admission))
    }

    async fn pq_attestation_bound_is_canonical_owned<O: Send + 'static>(
        &self,
        bound_root: Hash256,
        admission: OwnedSemaphorePermit,
        ownership: O,
    ) -> Result<(bool, OwnedSemaphorePermit, O), PqAttestationGossipError> {
        let snapshot = self.head_snapshot();
        let store = Arc::clone(&self.store);
        #[cfg(feature = "pq-startup-testing")]
        let blocking_test_hook = self
            .pq_attestation_lineage_test_hook
            .lock()
            .clone()
            .or_else(|| self.pq_blocking_test_hook.clone());
        self.task_executor
            .spawn_blocking_handle(
                move || {
                    #[cfg(feature = "pq-startup-testing")]
                    if let Some(hook) = blocking_test_hook {
                        hook.run();
                    }
                    canonical_lineage_contains::<T>(&store, &snapshot, bound_root)
                        .map(|is_canonical| (is_canonical, admission, ownership))
                },
                "pq-attestation-gossip-late-lineage",
            )
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::BlockingTask("pq-attestation-gossip-late-lineage"),
            ))?
            .await
            .map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::BlockingTask(
                    "pq-attestation-gossip-late-lineage",
                ))
            })?
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_pq_single_verification(
        &self,
        snapshot: Arc<BeaconSnapshot<T::EthSpec>>,
        attestation: SingleAttestation,
        subnet: SubnetId,
        latest_slot: Slot,
        earliest_slot: Slot,
        bound_head_root: Hash256,
        admission: OwnedSemaphorePermit,
        activity: Arc<crate::beacon_chain::PqImportActivity>,
    ) -> Result<PreparedSingle<T::EthSpec>, PqAttestationGossipError> {
        let store = Arc::clone(&self.store);
        let spec = Arc::clone(&self.spec);
        let key_cache = Arc::clone(&self.pq_validator_key_cache);
        Ok(self
            .task_executor
            .spawn_blocking_handle(
                move || {
                    prepare_single_context::<T>(
                        store,
                        snapshot,
                        spec,
                        key_cache,
                        attestation,
                        subnet,
                        latest_slot,
                        earliest_slot,
                        bound_head_root,
                        admission,
                        activity,
                    )
                },
                "pq-attestation-gossip-prepare",
            )
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::BlockingTask("pq-attestation-gossip-prepare"),
            ))?
            .await
            .map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::BlockingTask(
                    "pq-attestation-gossip-prepare",
                ))
            })??)
    }

    async fn prove_pq_single_verification(
        &self,
        preparation: PreparedSingle<T::EthSpec>,
    ) -> Result<VerifiedSingle<T::EthSpec>, PqAttestationGossipError> {
        let service = Arc::clone(&self.pq_aggregation_service);
        let proof_task = self
            .task_executor
            .spawn_handle(
                async move {
                    let PreparedSingle {
                        prepared,
                        identity,
                        bound_head_root,
                        admission,
                        activity,
                    } = preparation;
                    let verified = prepared.verify(&service).await;
                    (verified, identity, bound_head_root, admission, activity)
                },
                "pq-attestation-gossip-proof",
            )
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::AsyncTask("pq-attestation-gossip-proof"),
            ))?;
        let Some((verified, identity, bound_head_root, admission, activity)) =
            proof_task.await.map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::AsyncTask(
                    "pq-attestation-gossip-proof",
                ))
            })?
        else {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::AsyncTask("pq-attestation-gossip-proof"),
            ));
        };
        Ok(VerifiedSingle {
            verified: verified.map_err(map_attestation_error)?,
            identity,
            bound_head_root,
            admission,
            activity,
        })
    }

    async fn finish_pq_single_verification(
        &self,
        verified: VerifiedSingle<T::EthSpec>,
    ) -> Result<(VerifiedSingle<T::EthSpec>, Slot), PqAttestationGossipError> {
        let verified_slot = verified.verified.single_attestation().data.slot;
        let (late_latest_slot, late_earliest_slot) =
            propagation_bounds::<T::EthSpec, _>(&self.slot_clock, &self.spec).map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::ClockUnavailable)
            })?;
        validate_late_propagation_window(verified_slot, late_earliest_slot, late_latest_slot)?;
        let actual_head = self.head_snapshot().beacon_block_root;
        let (bound_is_canonical, admission, activity) = self
            .pq_attestation_bound_is_canonical_owned(
                verified.bound_head_root,
                verified.admission,
                verified.activity,
            )
            .await?;
        if !bound_is_canonical {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::BoundHeadNoLongerCanonical {
                    bound: verified.bound_head_root,
                    current: actual_head,
                },
            ));
        }
        Ok((
            VerifiedSingle {
                verified: verified.verified,
                identity: verified.identity,
                bound_head_root: verified.bound_head_root,
                admission,
                activity,
            },
            late_earliest_slot,
        ))
    }

    pub async fn verify_pq_single_attestation_for_gossip_with_wire_id(
        &self,
        attestation: SingleAttestation,
        subnet: SubnetId,
        wire_id: PqSingleWireMessageId,
    ) -> Result<PqSingleGossipPropagationToken<T::EthSpec>, PqAttestationGossipError> {
        self.validate_pq_single_wire_provenance(&attestation, subnet, wire_id, None)?;
        let activity =
            self.pq_import_coordinator
                .try_start()
                .ok_or(PqAttestationGossipError::Local(
                    PqAttestationGossipLocalError::ShuttingDown,
                ))?;
        let admission = self
            .try_reserve_pq_attestation_gossip_admission()
            .map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::IngressCapacity)
            })?;
        let (latest_slot, earliest_slot) =
            propagation_bounds::<T::EthSpec, _>(&self.slot_clock, &self.spec)?;
        let key = (attestation.data.target.epoch, attestation.attester_index);
        let early_status = self
            .pq_attestation_gossip_observations
            .lock()
            .precheck_single(key, earliest_slot);
        classify_observation(early_status)?;
        let snapshot = self.head_snapshot();
        let bound_head_root = snapshot.beacon_block_root;
        #[cfg(feature = "pq-startup-testing")]
        let remote_snapshot_hook = { self.pq_remote_attestation_snapshot_test_hook.lock().clone() };
        #[cfg(feature = "pq-startup-testing")]
        if let Some(hook) = remote_snapshot_hook {
            self.task_executor
                .spawn_blocking_handle(move || hook.run(), "pq-remote-attestation-snapshot-hook")
                .ok_or(PqAttestationGossipError::Local(
                    PqAttestationGossipLocalError::BlockingTask(
                        "pq-remote-attestation-snapshot-hook",
                    ),
                ))?
                .await
                .map_err(|_| {
                    PqAttestationGossipError::Local(PqAttestationGossipLocalError::BlockingTask(
                        "pq-remote-attestation-snapshot-hook",
                    ))
                })?;
        }
        let prepared = self
            .prepare_pq_single_verification(
                snapshot,
                attestation,
                subnet,
                latest_slot,
                earliest_slot,
                bound_head_root,
                admission,
                activity,
            )
            .await?;
        let verified = self.prove_pq_single_verification(prepared).await?;
        let (verified, late_earliest_slot) = self.finish_pq_single_verification(verified).await?;
        let generation = self
            .pq_attestation_gossip_observations
            .lock()
            .claim_single(verified.identity, wire_id, late_earliest_slot)
            .map_err(observation_error)?;
        Ok(PqSingleGossipPropagationToken {
            verified: Some(verified.verified),
            observations: Arc::clone(&self.pq_attestation_gossip_observations),
            binding: Some(SingleObservationBinding {
                identity: verified.identity,
                wire_id,
                generation,
            }),
            _admission: Some(verified.admission),
            _activity: Some(verified.activity),
            subnet,
            bound_head_root: verified.bound_head_root,
        })
    }

    /// Validates the anonymous gossipsub identity independently of network-owned provenance.
    /// Supplying the actual topic additionally pins the decoded event to the attestation subnet
    /// and slot fork digest. This performs no observation mutation.
    pub fn validate_pq_single_wire_provenance(
        &self,
        attestation: &SingleAttestation,
        subnet: SubnetId,
        wire_id: PqSingleWireMessageId,
        actual_topic: Option<&str>,
    ) -> Result<PqSingleWireMessageId, PqAttestationGossipError> {
        let genesis_validators_root = self.head_snapshot().beacon_state.genesis_validators_root();
        validate_pq_single_wire_provenance::<T::EthSpec>(
            attestation,
            subnet,
            genesis_validators_root,
            &self.spec,
            wire_id,
            actual_topic,
        )
    }

    #[cfg(feature = "pq-startup-testing")]
    pub async fn verify_pq_single_attestation_for_gossip(
        &self,
        attestation: SingleAttestation,
        subnet: SubnetId,
    ) -> Result<PqSingleGossipPropagationToken<T::EthSpec>, PqAttestationGossipError> {
        let genesis_validators_root = self.head_snapshot().beacon_state.genesis_validators_root();
        let (wire_id, _) = canonical_pq_single_wire_provenance::<T::EthSpec>(
            &attestation,
            subnet,
            genesis_validators_root,
            &self.spec,
        );
        self.verify_pq_single_attestation_for_gossip_with_wire_id(attestation, subnet, wire_id)
            .await
    }

    /// Verifies a complete sealed local signing batch without separating its candidate guards.
    /// Every proof is awaited, successful siblings are dropped on any error, and no partial
    /// verified capability escapes.
    pub async fn verify_pq_local_attestation_batch(
        &self,
        sealed: PqSealedLocalAttestationBatch<T::EthSpec>,
    ) -> Result<PqVerifiedLocalAttestationBatch<T::EthSpec>, PqLocalAttestationBatchVerificationError>
    {
        #[cfg(feature = "pq-startup-testing")]
        self.pq_local_attestation_batch_verification_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (provenances, candidate_guard) = sealed.into_proof_parts();
        let verified = collect_pq_local_batch_atomically(provenances, |provenance| {
            self.verify_pq_single_attestation_for_local(provenance)
        })
        .await
        .map_err(|error| match error {
            PqAtomicLocalBatchError::Capacity { count, maximum } => {
                PqLocalAttestationBatchVerificationError::Capacity { count, maximum }
            }
            PqAtomicLocalBatchError::Proof(error) => {
                PqLocalAttestationBatchVerificationError::Proof(error)
            }
        })?;
        Ok(PqVerifiedLocalAttestationBatch {
            verified,
            _candidate_guard: candidate_guard,
        })
    }

    pub async fn verify_pq_single_attestation_for_local(
        &self,
        provenance: PqLocallyConstructedSingle<T::EthSpec>,
    ) -> Result<PqVerifiedLocalSingle<T::EthSpec>, PqLocalAttestationVerificationError> {
        let activity = self.pq_import_coordinator.try_start().ok_or(
            PqLocalAttestationVerificationError::Local(PqAttestationGossipLocalError::ShuttingDown),
        )?;
        let admission = self
            .try_reserve_pq_local_attestation_proof_admission()
            .map_err(|_| {
                PqLocalAttestationVerificationError::Local(
                    PqAttestationGossipLocalError::IngressCapacity,
                )
            })?;
        let (latest_slot, earliest_slot) =
            propagation_bounds::<T::EthSpec, _>(&self.slot_clock, &self.spec)
                .map_err(map_local_attestation_error)?;
        let PqLocallyConstructedSingle {
            single,
            signed_attestation,
            pubkey,
            validator_index,
            committee_index,
            committee_position,
            committee_length,
            committee_count_at_slot,
            subnet,
            slot,
            bound_head_root,
            dependent_root,
            signing_root,
            signed_ssz_digest,
            _phantom: _,
        } = provenance;
        let preparation_snapshot = self.head_snapshot();
        let prepared = self
            .prepare_pq_single_verification(
                preparation_snapshot,
                single,
                subnet,
                latest_slot,
                earliest_slot,
                bound_head_root,
                admission,
                activity,
            )
            .await
            .map_err(map_local_attestation_error)?;
        let verified = self
            .prove_pq_single_verification(prepared)
            .await
            .map_err(map_local_attestation_error)?;
        let (verified, _) = self
            .finish_pq_single_verification(verified)
            .await
            .map_err(map_local_attestation_error)?;
        if verified.verified.attestation() != &signed_attestation {
            return Err(PqLocalAttestationVerificationError::Invariant(
                PqLocalAttestationInvariant::ProvenanceMismatch("signed-attestation"),
            ));
        }
        if verified.verified.signer_index() != validator_index
            || verified.verified.signer_public_key() != Some(pubkey)
        {
            return Err(PqLocalAttestationVerificationError::Invariant(
                PqLocalAttestationInvariant::ProvenanceMismatch("signer"),
            ));
        }
        if Hash256::from(verified.verified.claim().signing_root) != signing_root {
            return Err(PqLocalAttestationVerificationError::Invariant(
                PqLocalAttestationInvariant::ProvenanceMismatch("signing-root"),
            ));
        }
        let verified_single = verified.verified.single_attestation();
        if verified_single.committee_index != committee_index
            || verified_single.data.slot != slot
            || verified_single.data.beacon_block_root != bound_head_root
        {
            return Err(PqLocalAttestationVerificationError::Invariant(
                PqLocalAttestationInvariant::ProvenanceMismatch("duty"),
            ));
        }
        let actual_digest: [u8; 32] =
            Sha256::digest(ssz::Encode::as_ssz_bytes(verified_single)).into();
        if actual_digest != signed_ssz_digest {
            return Err(PqLocalAttestationVerificationError::Invariant(
                PqLocalAttestationInvariant::ProvenanceMismatch("signed-ssz-digest"),
            ));
        }
        let signed_tree_hash_root = verified_single.tree_hash_root();
        Ok(PqVerifiedLocalSingle {
            verified: verified.verified,
            pubkey,
            validator_index,
            committee_index,
            committee_position,
            committee_length,
            committee_count_at_slot,
            subnet,
            slot,
            bound_head_root,
            dependent_root,
            signing_root,
            signed_tree_hash_root,
            signed_ssz_digest,
            _admission: verified.admission,
            _activity: verified.activity,
        })
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_attestation_gossip_observation_count(&self) -> usize {
        let observations = self.pq_attestation_gossip_observations.lock();
        observations.singles.len()
            + observations.aggregators.len()
            + observations.aggregate_candidates.len()
    }

    pub async fn verify_pq_aggregate_for_gossip(
        &self,
        aggregate: SignedAggregateAndProof<T::EthSpec>,
    ) -> Result<PqAggregateGossipPropagationToken<T::EthSpec>, PqAttestationGossipError> {
        let admission = self
            .try_reserve_pq_attestation_gossip_admission()
            .map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::IngressCapacity)
            })?;
        let (latest_slot, earliest_slot) =
            propagation_bounds::<T::EthSpec, _>(&self.slot_clock, &self.spec)?;
        let AggregateObservationInput {
            aggregator_key: early_aggregator_key,
            data_key: early_data_key,
            bits: early_bits,
        } = aggregate_observation_input::<T::EthSpec>(&aggregate)?;
        let early_status = self
            .pq_attestation_gossip_observations
            .lock()
            .precheck_aggregate(
                early_aggregator_key,
                early_data_key,
                &early_bits,
                earliest_slot,
            );
        classify_observation(early_status)?;
        let snapshot = self.head_snapshot();
        let store = Arc::clone(&self.store);
        let spec = Arc::clone(&self.spec);
        let key_cache = Arc::clone(&self.pq_validator_key_cache);
        let preparation = self
            .task_executor
            .spawn_blocking_handle(
                move || {
                    prepare_aggregate_context::<T>(
                        store,
                        snapshot,
                        spec,
                        key_cache,
                        aggregate,
                        latest_slot,
                        earliest_slot,
                        admission,
                    )
                },
                "pq-aggregate-gossip-prepare",
            )
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::BlockingTask("pq-aggregate-gossip-prepare"),
            ))?
            .await
            .map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::BlockingTask(
                    "pq-aggregate-gossip-prepare",
                ))
            })??;

        let service = Arc::clone(&self.pq_aggregation_service);
        let proof_task = self
            .task_executor
            .spawn_handle(
                async move {
                    let PreparedAggregate {
                        prepared,
                        identity,
                        aggregator_key,
                        data_key,
                        bits,
                        bound_head_root,
                        admission,
                    } = preparation;
                    (
                        prepared.verify(&service).await,
                        identity,
                        aggregator_key,
                        data_key,
                        bits,
                        bound_head_root,
                        admission,
                    )
                },
                "pq-aggregate-gossip-proof",
            )
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::AsyncTask("pq-aggregate-gossip-proof"),
            ))?;
        let Some((verified, identity, aggregator_key, data_key, bits, bound_head_root, admission)) =
            proof_task.await.map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::AsyncTask(
                    "pq-aggregate-gossip-proof",
                ))
            })?
        else {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::AsyncTask("pq-aggregate-gossip-proof"),
            ));
        };
        let verified = verified.map_err(map_consensus_error)?;
        let (late_latest_slot, late_earliest_slot) =
            propagation_bounds::<T::EthSpec, _>(&self.slot_clock, &self.spec)?;
        let verified_slot = verified.aggregate().message().aggregate().data().slot;
        validate_late_propagation_window(verified_slot, late_earliest_slot, late_latest_slot)?;
        let actual_head = self.head_snapshot().beacon_block_root;
        let (bound_is_canonical, admission) = self
            .pq_attestation_bound_is_canonical(bound_head_root, admission)
            .await?;
        if !bound_is_canonical {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::BoundHeadNoLongerCanonical {
                    bound: bound_head_root,
                    current: actual_head,
                },
            ));
        }
        let generation = self
            .pq_attestation_gossip_observations
            .lock()
            .claim_aggregate(
                aggregator_key,
                data_key,
                identity,
                bits.clone(),
                late_earliest_slot,
            )
            .map_err(observation_error)?;
        Ok(PqAggregateGossipPropagationToken {
            verified: Some(verified),
            observations: Arc::clone(&self.pq_attestation_gossip_observations),
            binding: Some(AggregateObservationBinding {
                aggregator_key,
                data_key,
                identity,
                generation,
                bits,
            }),
            _admission: Some(admission),
            bound_head_root,
        })
    }
}

struct AggregateObservationInput<E: EthSpec> {
    aggregator_key: (Epoch, u64),
    data_key: (Slot, Hash256, u64),
    bits: ssz_types::BitList<E::MaxValidatorsPerSlot>,
}

fn aggregate_observation_input<E: EthSpec>(
    aggregate: &SignedAggregateAndProof<E>,
) -> Result<AggregateObservationInput<E>, PqAttestationGossipError> {
    let aggregate_ref = aggregate.message();
    let aggregator_index = aggregate_ref.aggregator_index();
    let AttestationRef::Electra(inner) = aggregate_ref.aggregate() else {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(
                PqConsensusInvalid::BaseAggregateAndProof,
            ),
        ));
    };
    let mut selected_committees = inner
        .committee_bits
        .iter()
        .enumerate()
        .filter_map(|(index, selected)| selected.then_some(index));
    let committee_index = selected_committees
        .next()
        .and_then(|index| u64::try_from(index).ok())
        .ok_or(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(
                PqConsensusInvalid::BaseAggregateAndProof,
            ),
        ))?;
    if selected_committees.next().is_some() {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(
                PqConsensusInvalid::BaseAggregateAndProof,
            ),
        ));
    }
    Ok(AggregateObservationInput {
        aggregator_key: (inner.data.target.epoch, aggregator_index),
        data_key: (
            inner.data.slot,
            inner.data.tree_hash_root(),
            committee_index,
        ),
        bits: inner.aggregation_bits.clone(),
    })
}

fn propagation_bounds<E: EthSpec, S: SlotClock>(
    clock: &S,
    spec: &ChainSpec,
) -> Result<(Slot, Slot), PqAttestationGossipError> {
    let latest = clock
        .now_with_future_tolerance(spec.maximum_gossip_clock_disparity())
        .ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ClockUnavailable,
        ))?;
    let now_past = clock
        .now_with_past_tolerance(spec.maximum_gossip_clock_disparity())
        .ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ClockUnavailable,
        ))?;
    let one_epoch_prior = now_past - E::slots_per_epoch();
    let now = clock.now().ok_or(PqAttestationGossipError::Local(
        PqAttestationGossipLocalError::ClockUnavailable,
    ))?;
    let earliest = if spec.fork_name_at_slot::<E>(now).deneb_enabled() {
        one_epoch_prior
            .epoch(E::slots_per_epoch())
            .start_slot(E::slots_per_epoch())
    } else {
        one_epoch_prior
    };
    Ok((latest, earliest))
}

fn validate_late_propagation_window(
    attestation_slot: Slot,
    earliest_slot: Slot,
    latest_slot: Slot,
) -> Result<(), PqAttestationGossipError> {
    if attestation_slot > latest_slot {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ReceiptBeforeWindow {
                attestation: attestation_slot,
                latest_permissible: latest_slot,
            },
        ));
    }
    if attestation_slot < earliest_slot {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ProofOutlivedPropagationWindow {
                attestation: attestation_slot,
            },
        ));
    }
    Ok(())
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_attestation_late_window(
    attestation_slot: Slot,
    earliest_slot: Slot,
    latest_slot: Slot,
) -> Result<(), PqAttestationGossipError> {
    validate_late_propagation_window(attestation_slot, earliest_slot, latest_slot)
}

#[allow(clippy::too_many_arguments)]
fn prepare_single_context<T: BeaconChainTypes>(
    store: crate::BeaconStore<T>,
    snapshot: Arc<BeaconSnapshot<T::EthSpec>>,
    spec: Arc<ChainSpec>,
    key_cache: Arc<state_processing::PqValidatorKeyCache>,
    attestation: SingleAttestation,
    subnet: SubnetId,
    latest_slot: Slot,
    earliest_slot: Slot,
    bound_head_root: Hash256,
    admission: OwnedSemaphorePermit,
    activity: Arc<crate::beacon_chain::PqImportActivity>,
) -> Result<PreparedSingle<T::EthSpec>, PqAttestationGossipError> {
    if attestation.data.slot > latest_slot {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ReceiptBeforeWindow {
                attestation: attestation.data.slot,
                latest_permissible: latest_slot,
            },
        ));
    }
    if attestation.data.slot < earliest_slot {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ReceiptAfterWindow {
                attestation: attestation.data.slot,
                earliest_permissible: earliest_slot,
            },
        ));
    }
    if attestation.data.target.epoch != attestation.data.slot.epoch(T::EthSpec::slots_per_epoch()) {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidTargetEpoch,
        ));
    }
    let CanonicalReference {
        block: reference_block,
        mut state,
    } = canonical_reference::<T>(&store, &snapshot, attestation.data.beacon_block_root)?;
    if reference_block.slot() > attestation.data.slot {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::ReferencedBlockAfterAttestation {
                block: reference_block.slot(),
                attestation: attestation.data.slot,
            },
        ));
    }
    let advance_distance = pq_attestation_advance_distance::<T::EthSpec>(
        reference_block.slot(),
        attestation.data.slot,
    )?;
    for _ in 0..advance_distance {
        state_processing::per_slot_processing_pq(&mut state, &spec).map_err(|_| {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
        })?;
    }
    let target_slot = attestation
        .data
        .target
        .epoch
        .start_slot(T::EthSpec::slots_per_epoch());
    let reference_is_target = reference_block.slot().epoch(T::EthSpec::slots_per_epoch())
        < attestation.data.slot.epoch(T::EthSpec::slots_per_epoch())
        || reference_block.slot() == target_slot;
    let expected_target = if reference_is_target {
        attestation.data.beacon_block_root
    } else {
        let historical_target = *state.get_block_root(target_slot).map_err(|_| {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
        })?;
        pq_attestation_target_root::<T::EthSpec>(
            reference_block.slot(),
            attestation.data.beacon_block_root,
            attestation.data.slot,
            historical_target,
        )
    };
    if attestation.data.target.root != expected_target {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::TargetRootMismatch {
                expected: expected_target,
                actual: attestation.data.target.root,
            },
        ));
    }
    state.build_all_committee_caches(&spec).map_err(|_| {
        PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
    })?;
    let committee_count = state
        .get_committee_count_at_slot(attestation.data.slot)
        .map_err(|_| {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
        })?;
    let expected_subnet = SubnetId::compute_subnet_for_single_attestation::<T::EthSpec>(
        &attestation,
        committee_count,
        &spec,
    )
    .map_err(|_| {
        PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
    })?;
    if subnet != expected_subnet {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidSubnet {
                expected: expected_subnet,
                actual: subnet,
            },
        ));
    }
    let identity = PqSingleObservationIdentity::from_signed_attestation(&attestation, subnet);
    let prepared = prepare_pq_single_attestation(&state, &key_cache, attestation, &spec)
        .map_err(map_attestation_error)?;
    Ok(PreparedSingle {
        prepared,
        identity,
        bound_head_root,
        admission,
        activity,
    })
}

#[allow(clippy::too_many_arguments)]
fn prepare_aggregate_context<T: BeaconChainTypes>(
    store: crate::BeaconStore<T>,
    snapshot: Arc<BeaconSnapshot<T::EthSpec>>,
    spec: Arc<ChainSpec>,
    key_cache: Arc<state_processing::PqValidatorKeyCache>,
    aggregate: SignedAggregateAndProof<T::EthSpec>,
    latest_slot: Slot,
    earliest_slot: Slot,
    admission: OwnedSemaphorePermit,
) -> Result<PreparedAggregate<T::EthSpec>, PqAttestationGossipError> {
    let aggregate_ref = aggregate.message();
    let aggregator_index = aggregate_ref.aggregator_index();
    let inner = aggregate_ref.aggregate();
    let AttestationRef::Electra(inner) = inner else {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(
                PqConsensusInvalid::BaseAggregateAndProof,
            ),
        ));
    };
    let data = inner.data.clone();
    let bits = inner.aggregation_bits.clone();
    let mut selected_committees = inner
        .committee_bits
        .iter()
        .enumerate()
        .filter_map(|(index, selected)| selected.then_some(index));
    let committee_index = selected_committees
        .next()
        .and_then(|index| u64::try_from(index).ok())
        .ok_or(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(
                PqConsensusInvalid::BaseAggregateAndProof,
            ),
        ))?;
    if selected_committees.next().is_some() {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(
                PqConsensusInvalid::BaseAggregateAndProof,
            ),
        ));
    }
    if data.slot > latest_slot {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ReceiptBeforeWindow {
                attestation: data.slot,
                latest_permissible: latest_slot,
            },
        ));
    }
    if data.slot < earliest_slot {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ReceiptAfterWindow {
                attestation: data.slot,
                earliest_permissible: earliest_slot,
            },
        ));
    }
    if data.target.epoch != data.slot.epoch(T::EthSpec::slots_per_epoch()) {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidTargetEpoch,
        ));
    }
    let bound_head_root = snapshot.beacon_block_root;
    let CanonicalReference {
        block: reference_block,
        mut state,
    } = canonical_reference::<T>(&store, &snapshot, data.beacon_block_root)?;
    if reference_block.slot() > data.slot {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::ReferencedBlockAfterAttestation {
                block: reference_block.slot(),
                attestation: data.slot,
            },
        ));
    }
    let advance_distance =
        pq_attestation_advance_distance::<T::EthSpec>(reference_block.slot(), data.slot)?;
    for _ in 0..advance_distance {
        state_processing::per_slot_processing_pq(&mut state, &spec).map_err(|_| {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
        })?;
    }
    let target_slot = data.target.epoch.start_slot(T::EthSpec::slots_per_epoch());
    let reference_is_target = reference_block.slot().epoch(T::EthSpec::slots_per_epoch())
        < data.slot.epoch(T::EthSpec::slots_per_epoch())
        || reference_block.slot() == target_slot;
    let expected_target = if reference_is_target {
        data.beacon_block_root
    } else {
        let historical_target = *state.get_block_root(target_slot).map_err(|_| {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
        })?;
        pq_attestation_target_root::<T::EthSpec>(
            reference_block.slot(),
            data.beacon_block_root,
            data.slot,
            historical_target,
        )
    };
    if data.target.root != expected_target {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::TargetRootMismatch {
                expected: expected_target,
                actual: data.target.root,
            },
        ));
    }
    state.build_all_committee_caches(&spec).map_err(|_| {
        PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
    })?;
    let identity = aggregate.tree_hash_root();
    let data_key = (data.slot, data.tree_hash_root(), committee_index);
    let aggregator_key = (data.target.epoch, aggregator_index);
    let prepared = prepare_pq_aggregate_and_proof(&state, &key_cache, aggregate, &spec)
        .map_err(map_consensus_error)?;
    Ok(PreparedAggregate {
        prepared,
        identity,
        aggregator_key,
        data_key,
        bits,
        bound_head_root,
        admission,
    })
}

fn pq_attestation_target_root<E: EthSpec>(
    referenced_block_slot: Slot,
    referenced_block_root: Hash256,
    attestation_slot: Slot,
    same_epoch_target_root: Hash256,
) -> Hash256 {
    if referenced_block_slot.epoch(E::slots_per_epoch())
        < attestation_slot.epoch(E::slots_per_epoch())
        || referenced_block_slot
            == attestation_slot
                .epoch(E::slots_per_epoch())
                .start_slot(E::slots_per_epoch())
    {
        referenced_block_root
    } else {
        same_epoch_target_root
    }
}

fn pq_attestation_advance_distance<E: EthSpec>(
    referenced_block_slot: Slot,
    attestation_slot: Slot,
) -> Result<u64, PqAttestationGossipError> {
    let distance = attestation_slot
        .as_u64()
        .checked_sub(referenced_block_slot.as_u64())
        .ok_or(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::ReferencedBlockAfterAttestation {
                block: referenced_block_slot,
                attestation: attestation_slot,
            },
        ))?;
    let maximum = E::slots_per_epoch()
        .checked_mul(2)
        .and_then(|slots| slots.checked_add(2))
        .ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::StateUnavailable,
        ))?;
    if distance > maximum {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::StateAdvanceTooLarge {
                referenced_block: referenced_block_slot,
                attestation: attestation_slot,
                maximum,
            },
        ));
    }
    Ok(distance)
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_attestation_advance_distance<E: EthSpec>(
    referenced_block_slot: Slot,
    attestation_slot: Slot,
) -> Result<u64, PqAttestationGossipError> {
    pq_attestation_advance_distance::<E>(referenced_block_slot, attestation_slot)
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_attestation_target_root<E: EthSpec>(
    referenced_block_slot: Slot,
    referenced_block_root: Hash256,
    attestation_slot: Slot,
    same_epoch_target_root: Hash256,
) -> Hash256 {
    pq_attestation_target_root::<E>(
        referenced_block_slot,
        referenced_block_root,
        attestation_slot,
        same_epoch_target_root,
    )
}

fn canonical_reference<T: BeaconChainTypes>(
    store: &crate::BeaconStore<T>,
    snapshot: &BeaconSnapshot<T::EthSpec>,
    requested_root: Hash256,
) -> Result<CanonicalReference<T::EthSpec>, PqAttestationGossipError> {
    let mut block = Arc::clone(&snapshot.beacon_block);
    let mut root = snapshot.beacon_block_root;
    let max_steps = T::EthSpec::slots_per_epoch()
        .saturating_mul(2)
        .saturating_add(2);
    for _ in 0..max_steps {
        if root == requested_root {
            if root == snapshot.beacon_block_root {
                return Ok(CanonicalReference {
                    block,
                    state: snapshot.beacon_state.clone(),
                });
            }
            let state_root = block.message().state_root();
            let state = store
                .get_state(&state_root, Some(block.slot()), true)
                .map_err(|error| {
                    PqAttestationGossipError::Local(PqAttestationGossipLocalError::Store(error))
                })?
                .ok_or(PqAttestationGossipError::Local(
                    PqAttestationGossipLocalError::ReferencedStateUnavailable(state_root),
                ))?;
            return Ok(CanonicalReference { block, state });
        }
        if block.slot() == Slot::new(0) {
            break;
        }
        root = block.parent_root();
        block = Arc::new(
            store
                .get_full_block(&root)
                .map_err(|error| {
                    PqAttestationGossipError::Local(PqAttestationGossipLocalError::Store(error))
                })?
                .ok_or(PqAttestationGossipError::Local(
                    PqAttestationGossipLocalError::ReferencedBlockUnavailable(root),
                ))?,
        );
    }
    Err(PqAttestationGossipError::Local(
        PqAttestationGossipLocalError::ReferencedBlockUnavailable(requested_root),
    ))
}

fn canonical_lineage_contains<T: BeaconChainTypes>(
    store: &crate::BeaconStore<T>,
    snapshot: &BeaconSnapshot<T::EthSpec>,
    requested_root: Hash256,
) -> Result<bool, PqAttestationGossipError> {
    let mut block = Arc::clone(&snapshot.beacon_block);
    let mut root = snapshot.beacon_block_root;
    let max_steps = T::EthSpec::slots_per_epoch()
        .saturating_mul(2)
        .saturating_add(2);
    for _ in 0..max_steps {
        if root == requested_root {
            return Ok(true);
        }
        if block.slot() == Slot::new(0) {
            return Ok(false);
        }
        root = block.parent_root();
        block = Arc::new(
            store
                .get_full_block(&root)
                .map_err(|error| {
                    PqAttestationGossipError::Local(PqAttestationGossipLocalError::Store(error))
                })?
                .ok_or(PqAttestationGossipError::Local(
                    PqAttestationGossipLocalError::ReferencedBlockUnavailable(root),
                ))?,
        );
    }
    Ok(false)
}

fn map_attestation_error(error: PqAttestationError) -> PqAttestationGossipError {
    match error {
        PqAttestationError::Invalid(error) => PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAttestation(error),
        ),
        PqAttestationError::Local(error) => {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::Attestation(error))
        }
    }
}

fn map_local_attestation_error(
    error: PqAttestationGossipError,
) -> PqLocalAttestationVerificationError {
    match error {
        PqAttestationGossipError::PeerInvalid(error) => {
            PqLocalAttestationVerificationError::Invariant(PqLocalAttestationInvariant::Contextual(
                error,
            ))
        }
        PqAttestationGossipError::Local(error) => PqLocalAttestationVerificationError::Local(error),
        PqAttestationGossipError::Duplicate(_) => PqLocalAttestationVerificationError::Invariant(
            PqLocalAttestationInvariant::UnexpectedObservation,
        ),
    }
}

fn map_consensus_error(error: PqConsensusError) -> PqAttestationGossipError {
    match error {
        PqConsensusError::Invalid(error) => PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(error),
        ),
        PqConsensusError::Local(error) => {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::Aggregate(error))
        }
    }
}

fn classify_observation(
    observation: PqAttestationGossipObservation,
) -> Result<(), PqAttestationGossipError> {
    match observation {
        PqAttestationGossipObservation::Unseen => Ok(()),
        PqAttestationGossipObservation::Pending
        | PqAttestationGossipObservation::Observed
        | PqAttestationGossipObservation::Conflict => {
            Err(PqAttestationGossipError::Duplicate(observation))
        }
        PqAttestationGossipObservation::Capacity => Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationCapacity,
        )),
        PqAttestationGossipObservation::GenerationExhausted => {
            Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationGenerationExhausted,
            ))
        }
    }
}

fn observation_error(observation: PqAttestationGossipObservation) -> PqAttestationGossipError {
    match classify_observation(observation) {
        Err(error) => error,
        Ok(()) => PqAttestationGossipError::Local(PqAttestationGossipLocalError::ObservationLost),
    }
}
