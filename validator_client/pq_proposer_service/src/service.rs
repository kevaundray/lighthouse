use consensus_signature::{
    PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN, PQ_RAW_SIGNATURE_LEN, ValidatorPublicKeyBytes,
    serialize_individual_signature,
};
use eth2::{
    ForkVersionedResponse, StrictBeaconNodeHttpClient,
    types::{
        Accept, DutiesResponse, FullBlockContents, ProduceBlockV3Metadata, ProduceBlockV3Response,
        PublishBlockRequest,
    },
};
use futures::{Stream, StreamExt};
use lighthouse_validator_store::LighthouseValidatorStore;
use slot_clock::SlotClock;
use ssz::Encode;
use std::error::Error;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, watch};
use types::{EthSpec, Hash256, MinimalEthSpec, Slot};
use validator_store::{SignedBlock, UnsignedBlock, ValidatorStore};

const PQ_PROPOSER_SLOT_DURATION: Duration = Duration::from_secs(300);
const PQ_LOCAL_VALIDATOR_CAPACITY: usize = 16;
const PQ_GLOBAL_DEADLINE_OFFSET: Duration = Duration::from_secs(285);
const PQ_PREPARE_DEADLINE_OFFSET: Duration = Duration::from_secs(120);
const PQ_BLOCK_SIGN_BUDGET: Duration = Duration::from_secs(120);
const PQ_PUBLISH_BUDGET: Duration = Duration::from_secs(45);
const PQ_DUTIES_RESPONSE_MAX_BYTES: usize = 64 * 1024;
const PQ_ERROR_RESPONSE_MAX_BYTES: usize = 64 * 1024;
const PQ_RESPONSE_CHUNK_CAPACITY: usize = 4096;
const PQ_RESPONSE_FIXED_BODY_ALLOWANCE_BYTES: usize = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum PqResponseCollectionError {
    PayloadTooLarge,
    FragmentLimit,
    Stream,
    Resource,
}

impl std::fmt::Display for PqResponseCollectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Debug)]
enum PqStrictResponseError {
    Transport(eth2::Error),
    Collection(PqResponseCollectionError),
    Status(reqwest::StatusCode),
    InvalidHeaders(String),
    InvalidJson(serde_json::Error),
    InvalidSsz(ssz::DecodeError),
}

impl From<PqResponseCollectionError> for PqStrictResponseError {
    fn from(error: PqResponseCollectionError) -> Self {
        Self::Collection(error)
    }
}

impl std::fmt::Display for PqStrictResponseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "transport: {error}"),
            Self::Collection(error) => write!(formatter, "bounded collection: {error}"),
            Self::Status(status) => write!(formatter, "HTTP status: {status}"),
            Self::InvalidHeaders(error) => write!(formatter, "invalid headers: {error}"),
            Self::InvalidJson(error) => write!(formatter, "invalid JSON: {error}"),
            Self::InvalidSsz(error) => write!(formatter, "invalid SSZ: {error:?}"),
        }
    }
}

struct PqCollectedResponse {
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
    chunks: Vec<bytes::Bytes>,
    length: usize,
    #[cfg(all(test, feature = "pq-startup-testing"))]
    coalesce_hook: Option<Box<dyn FnOnce() + Send>>,
}

#[derive(Debug, PartialEq, Eq)]
struct PqCollectedResponseBody {
    chunks: Vec<bytes::Bytes>,
    length: usize,
}

fn pq_v3_response_body_limits() -> Option<(usize, usize)> {
    let payload_bytes = usize::try_from(MinimalEthSpec::default_spec().max_payload_size).ok()?;
    let attestation_evidence_bytes =
        MinimalEthSpec::max_attestations_electra().checked_mul(PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN)?;
    let individual_signature_bytes = 2usize.checked_mul(PQ_RAW_SIGNATURE_LEN)?;
    let max_ssz_bytes = payload_bytes
        .checked_add(attestation_evidence_bytes)?
        .checked_add(individual_signature_bytes)?
        .checked_add(PQ_RESPONSE_FIXED_BODY_ALLOWANCE_BYTES)?;
    let max_json_bytes = max_ssz_bytes
        .checked_mul(2)?
        .checked_add(PQ_RESPONSE_FIXED_BODY_ALLOWANCE_BYTES)?;
    Some((max_ssz_bytes, max_json_bytes))
}

async fn collect_pq_response(
    response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<PqCollectedResponse, PqResponseCollectionError> {
    let status = response.status();
    let headers = response.headers().clone();
    let declared = response.content_length();
    let maximum_bytes = pq_response_body_limit(status, maximum_bytes);
    let body = collect_pq_response_body(response.bytes_stream(), declared, maximum_bytes).await?;
    Ok(PqCollectedResponse {
        status,
        headers,
        chunks: body.chunks,
        length: body.length,
        #[cfg(all(test, feature = "pq-startup-testing"))]
        coalesce_hook: None,
    })
}

async fn collect_pq_success_response(
    response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<PqCollectedResponse, PqStrictResponseError> {
    let response = collect_pq_response(response, maximum_bytes)
        .await
        .map_err(PqStrictResponseError::Collection)?;
    if response.status != reqwest::StatusCode::OK {
        return Err(PqStrictResponseError::Status(response.status));
    }
    Ok(response)
}

fn pq_response_body_limit(status: reqwest::StatusCode, success_maximum: usize) -> usize {
    if status == reqwest::StatusCode::OK {
        success_maximum
    } else {
        success_maximum.min(PQ_ERROR_RESPONSE_MAX_BYTES)
    }
}

async fn collect_pq_response_body<S, E>(
    body: S,
    declared: Option<u64>,
    maximum_bytes: usize,
) -> Result<PqCollectedResponseBody, PqResponseCollectionError>
where
    S: Stream<Item = Result<bytes::Bytes, E>>,
{
    let maximum_bytes =
        u64::try_from(maximum_bytes).map_err(|_| PqResponseCollectionError::PayloadTooLarge)?;
    if declared.is_some_and(|declared| declared > maximum_bytes) {
        return Err(PqResponseCollectionError::PayloadTooLarge);
    }
    futures::pin_mut!(body);
    let mut chunks = Vec::new();
    let mut length = 0usize;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|_| PqResponseCollectionError::Stream)?;
        let next = length
            .checked_add(chunk.len())
            .ok_or(PqResponseCollectionError::PayloadTooLarge)?;
        if u64::try_from(next).map_or(true, |next| next > maximum_bytes) {
            return Err(PqResponseCollectionError::PayloadTooLarge);
        }
        if chunks.len() == PQ_RESPONSE_CHUNK_CAPACITY {
            return Err(PqResponseCollectionError::FragmentLimit);
        }
        chunks
            .try_reserve(1)
            .map_err(|_| PqResponseCollectionError::Resource)?;
        chunks.push(chunk);
        length = next;
    }
    Ok(PqCollectedResponseBody { chunks, length })
}

async fn run_pq_response_decode<R, F>(
    task_executor: &TaskExecutor,
    decode: F,
) -> Result<R, PqResponseCollectionError>
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    task_executor
        .spawn_blocking_handle(decode, "pq-proposer-response-decode")
        .ok_or(PqResponseCollectionError::Resource)?
        .await
        .map_err(|_| PqResponseCollectionError::Resource)
}

fn coalesce_pq_response(
    response: PqCollectedResponse,
) -> Result<(reqwest::header::HeaderMap, Vec<u8>), PqResponseCollectionError> {
    #[cfg(all(test, feature = "pq-startup-testing"))]
    let response = {
        let mut response = response;
        if let Some(hook) = response.coalesce_hook.take() {
            hook();
        }
        response
    };
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(response.length)
        .map_err(|_| PqResponseCollectionError::Resource)?;
    for chunk in response.chunks {
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != response.length {
        return Err(PqResponseCollectionError::Stream);
    }
    Ok((response.headers, bytes))
}

async fn decode_collected_pq_duties_response(
    task_executor: &TaskExecutor,
    response: PqCollectedResponse,
) -> Result<DutiesResponse<Vec<eth2::types::ProposerData>>, PqStrictResponseError> {
    run_pq_response_decode(task_executor, move || {
        let (_, bytes) = coalesce_pq_response(response)?;
        serde_json::from_slice(&bytes).map_err(PqStrictResponseError::InvalidJson)
    })
    .await
    .map_err(PqStrictResponseError::Collection)?
}

async fn decode_collected_pq_v3_ssz_response(
    task_executor: &TaskExecutor,
    response: PqCollectedResponse,
) -> Result<
    (
        ProduceBlockV3Response<MinimalEthSpec>,
        ProduceBlockV3Metadata,
    ),
    PqStrictResponseError,
> {
    run_pq_response_decode(task_executor, move || {
        let (headers, bytes) = coalesce_pq_response(response)?;
        let metadata = ProduceBlockV3Metadata::try_from(&headers)
            .map_err(PqStrictResponseError::InvalidHeaders)?;
        let response = if metadata.execution_payload_blinded {
            ProduceBlockV3Response::Blinded(
                types::BlindedBeaconBlock::from_ssz_bytes_for_fork(
                    &bytes,
                    metadata.consensus_version,
                )
                .map_err(PqStrictResponseError::InvalidSsz)?,
            )
        } else {
            ProduceBlockV3Response::Full(
                FullBlockContents::from_ssz_bytes_for_fork(&bytes, metadata.consensus_version)
                    .map_err(PqStrictResponseError::InvalidSsz)?,
            )
        };
        Ok((response, metadata))
    })
    .await
    .map_err(PqStrictResponseError::Collection)?
}

async fn decode_collected_pq_v3_json_response(
    task_executor: &TaskExecutor,
    response: PqCollectedResponse,
) -> Result<
    (
        ForkVersionedResponse<ProduceBlockV3Response<MinimalEthSpec>, ProduceBlockV3Metadata>,
        ProduceBlockV3Metadata,
    ),
    PqStrictResponseError,
> {
    run_pq_response_decode(task_executor, move || {
        let (headers, bytes) = coalesce_pq_response(response)?;
        let header_metadata = ProduceBlockV3Metadata::try_from(&headers)
            .map_err(PqStrictResponseError::InvalidHeaders)?;
        let response = if header_metadata.execution_payload_blinded {
            serde_json::from_slice::<
                ForkVersionedResponse<
                    types::BlindedBeaconBlock<MinimalEthSpec>,
                    ProduceBlockV3Metadata,
                >,
            >(&bytes)
            .map(|response| response.map_data(ProduceBlockV3Response::Blinded))
        } else {
            serde_json::from_slice::<
                ForkVersionedResponse<FullBlockContents<MinimalEthSpec>, ProduceBlockV3Metadata>,
            >(&bytes)
            .map(|response| response.map_data(ProduceBlockV3Response::Full))
        }
        .map_err(PqStrictResponseError::InvalidJson)?;
        Ok((response, header_metadata))
    })
    .await
    .map_err(PqStrictResponseError::Collection)?
}

#[cfg(feature = "pq-startup-testing")]
type PqTestingHookFuture = std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
#[cfg(feature = "pq-startup-testing")]
type PqTestingAsyncHook = dyn Fn() -> PqTestingHookFuture + Send + Sync;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqProposalPhase {
    PrepareAndProduce,
    BlockSign,
    Publish,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqNonCancellablePhase {
    Randao,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqNonCancellableCompletion {
    OnTime,
    PhaseOverrun,
    GlobalExpired,
}

impl PqNonCancellableCompletion {
    #[cfg(all(test, feature = "pq-startup-testing"))]
    pub const fn allows_next_phase(self) -> bool {
        matches!(self, Self::OnTime)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqProposalTimingError {
    ClockUnavailable,
    Overflow,
    PhaseExpired {
        phase: PqProposalPhase,
        deadline: Duration,
    },
    GlobalExpired {
        deadline: Duration,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqProposalTiming {
    slot_start: Duration,
    prepare_deadline: Duration,
    global_deadline: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqCapturedPhaseDeadline {
    phase: PqProposalPhase,
    deadline: Duration,
    global_deadline: Duration,
}

impl PqCapturedPhaseDeadline {
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    pub fn remaining(&self, now: Duration) -> Result<Duration, PqProposalTimingError> {
        if now >= self.global_deadline {
            return Err(PqProposalTimingError::GlobalExpired {
                deadline: self.global_deadline,
            });
        }
        self.deadline
            .checked_sub(now)
            .filter(|remaining| !remaining.is_zero())
            .ok_or(PqProposalTimingError::PhaseExpired {
                phase: self.phase,
                deadline: self.deadline,
            })
    }

    pub fn classify_non_cancellable_completion(
        &self,
        completed_at: Duration,
    ) -> PqNonCancellableCompletion {
        if completed_at >= self.global_deadline {
            PqNonCancellableCompletion::GlobalExpired
        } else if completed_at >= self.deadline {
            PqNonCancellableCompletion::PhaseOverrun
        } else {
            PqNonCancellableCompletion::OnTime
        }
    }
}

impl PqProposalTiming {
    pub fn new<T: SlotClock>(clock: &T, slot: Slot) -> Result<Self, PqProposalTimingError> {
        let slot_start = clock
            .start_of(slot)
            .ok_or(PqProposalTimingError::ClockUnavailable)?;
        Ok(Self {
            slot_start,
            prepare_deadline: slot_start
                .checked_add(PQ_PREPARE_DEADLINE_OFFSET)
                .ok_or(PqProposalTimingError::Overflow)?,
            global_deadline: slot_start
                .checked_add(PQ_GLOBAL_DEADLINE_OFFSET)
                .ok_or(PqProposalTimingError::Overflow)?,
        })
    }

    #[cfg(all(test, feature = "pq-startup-testing"))]
    pub const fn slot_start(&self) -> Duration {
        self.slot_start
    }

    #[cfg(all(test, feature = "pq-startup-testing"))]
    pub const fn global_deadline(&self) -> Duration {
        self.global_deadline
    }

    pub fn remaining_prepare(&self, now: Duration) -> Result<Duration, PqProposalTimingError> {
        if now >= self.global_deadline {
            return Err(PqProposalTimingError::GlobalExpired {
                deadline: self.global_deadline,
            });
        }
        self.prepare_deadline
            .checked_sub(now)
            .filter(|remaining| !remaining.is_zero())
            .ok_or(PqProposalTimingError::PhaseExpired {
                phase: PqProposalPhase::PrepareAndProduce,
                deadline: self.prepare_deadline,
            })
    }

    fn capture_phase(
        &self,
        phase: PqProposalPhase,
        started_at: Duration,
        budget: Duration,
    ) -> Result<PqCapturedPhaseDeadline, PqProposalTimingError> {
        if started_at >= self.global_deadline {
            return Err(PqProposalTimingError::GlobalExpired {
                deadline: self.global_deadline,
            });
        }
        let phase_deadline = started_at
            .checked_add(budget)
            .ok_or(PqProposalTimingError::Overflow)?
            .min(self.global_deadline);
        Ok(PqCapturedPhaseDeadline {
            phase,
            deadline: phase_deadline,
            global_deadline: self.global_deadline,
        })
    }

    pub fn start_block_sign(
        &self,
        started_at: Duration,
    ) -> Result<PqCapturedPhaseDeadline, PqProposalTimingError> {
        self.capture_phase(PqProposalPhase::BlockSign, started_at, PQ_BLOCK_SIGN_BUDGET)
    }

    pub fn start_publish(
        &self,
        started_at: Duration,
    ) -> Result<PqCapturedPhaseDeadline, PqProposalTimingError> {
        self.capture_phase(PqProposalPhase::Publish, started_at, PQ_PUBLISH_BUDGET)
    }

    pub fn classify_non_cancellable_completion(
        &self,
        phase: PqNonCancellablePhase,
        completed_at: Duration,
    ) -> PqNonCancellableCompletion {
        if completed_at >= self.global_deadline {
            return PqNonCancellableCompletion::GlobalExpired;
        }
        let phase_deadline = match phase {
            PqNonCancellablePhase::Randao => self.prepare_deadline,
        };
        if completed_at >= phase_deadline {
            PqNonCancellableCompletion::PhaseOverrun
        } else {
            PqNonCancellableCompletion::OnTime
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqLocalIdentity {
    pubkey: ValidatorPublicKeyBytes,
    validator_index: u64,
}

impl PqLocalIdentity {
    pub const fn new(pubkey: ValidatorPublicKeyBytes, validator_index: u64) -> Self {
        Self {
            pubkey,
            validator_index,
        }
    }
}

fn validate_identity_set(identities: &[PqLocalIdentity]) -> bool {
    !identities.is_empty()
        && identities.len() <= PQ_LOCAL_VALIDATOR_CAPACITY
        && !identities.iter().enumerate().any(|(position, identity)| {
            identities[position + 1..].iter().any(|other| {
                identity.pubkey == other.pubkey || identity.validator_index == other.validator_index
            })
        })
}

fn validate_slot_duration(slot_duration: Duration) -> Result<(), PqProposerServiceError> {
    if slot_duration != PQ_PROPOSER_SLOT_DURATION {
        return Err(PqProposerServiceError::WrongSlotDuration {
            supplied: slot_duration,
            required: PQ_PROPOSER_SLOT_DURATION,
        });
    }
    Ok(())
}

async fn run_pq_prepare_response<T, R, C, CF, D, DF>(
    timing: &PqProposalTiming,
    clock: &T,
    collect: C,
    decode: D,
) -> Result<Result<R, PqStrictResponseError>, PqProposerServiceError>
where
    T: SlotClock,
    C: FnOnce(Duration) -> CF,
    CF: Future<Output = Result<PqCollectedResponse, PqStrictResponseError>>,
    D: FnOnce(PqCollectedResponse) -> DF,
    DF: Future<Output = Result<R, PqStrictResponseError>>,
{
    let before_collection = clock
        .now_duration()
        .ok_or(PqProposerServiceError::ClockUnavailable)?;
    let remaining = timing
        .remaining_prepare(before_collection)
        .map_err(map_timing_error)?;
    let collected = tokio::time::timeout(remaining, collect(remaining))
        .await
        .map_err(|_| PqProposerServiceError::PreparationExpired {
            deadline: timing.prepare_deadline,
        })?;
    let decoded = match collected {
        Ok(response) => decode(response).await,
        Err(error) => Err(error),
    };
    let after_decode = clock
        .now_duration()
        .ok_or(PqProposerServiceError::ClockUnavailable)?;
    timing
        .remaining_prepare(after_decode)
        .map_err(map_timing_error)?;
    Ok(decoded)
}

fn is_exact_connect_error(error: &eth2::Error, expected_url: &reqwest::Url) -> bool {
    matches!(
        error,
        eth2::Error::HttpClient(error)
            if error.inner().is_connect() && error.inner().url() == Some(expected_url)
    )
}

fn allows_production_json_fallback(error: &eth2::Error, expected_url: &reqwest::Url) -> bool {
    match error {
        eth2::Error::InvalidSsz(_) => true,
        _ => is_exact_connect_error(error, expected_url),
    }
}

fn allows_bounded_production_json_fallback(
    error: &PqStrictResponseError,
    expected_url: &reqwest::Url,
) -> bool {
    match error {
        PqStrictResponseError::InvalidSsz(_) => true,
        PqStrictResponseError::Transport(error) => {
            allows_production_json_fallback(error, expected_url)
        }
        _ => false,
    }
}

fn allows_publication_json_fallback(error: &eth2::Error, expected_url: &reqwest::Url) -> bool {
    is_exact_connect_error(error, expected_url)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqPublicationStatus {
    Published,
    Retry,
    Terminal(u16),
    Protocol(u16),
}

#[derive(Clone, Copy)]
enum PqPublicationBody {
    Ssz,
    Json,
}

struct PqEncodedPublication {
    ssz: bytes::Bytes,
    json: bytes::Bytes,
    fork: types::ForkName,
    block_root: Hash256,
}

fn encode_pq_publication(
    signed: PublishBlockRequest<MinimalEthSpec>,
) -> Result<PqEncodedPublication, serde_json::Error> {
    let fork = signed.signed_block().message().body().fork_name();
    let block_root = signed.signed_block().canonical_root();
    let ssz = bytes::Bytes::from(signed.as_ssz_bytes());
    let json = bytes::Bytes::from(serde_json::to_vec(&signed)?);
    Ok(PqEncodedPublication {
        ssz,
        json,
        fork,
        block_root,
    })
}

fn classify_publication_status(status: u16) -> PqPublicationStatus {
    match status {
        200 => PqPublicationStatus::Published,
        202 | 408 | 429 | 503 => PqPublicationStatus::Retry,
        status if (200..300).contains(&status) => PqPublicationStatus::Protocol(status),
        status => PqPublicationStatus::Terminal(status),
    }
}

async fn post_pq_publication_attempt(
    beacon_node: &StrictBeaconNodeHttpClient,
    body: PqPublicationBody,
    encoded: &PqEncodedPublication,
) -> Result<PqPublicationStatus, eth2::Error> {
    let response = match body {
        PqPublicationBody::Ssz => {
            beacon_node
                .post_pq_beacon_blocks_v2_ssz_bytes_raw(encoded.ssz.clone(), encoded.fork)
                .await?
        }
        PqPublicationBody::Json => {
            beacon_node
                .post_pq_beacon_blocks_v2_json_bytes_raw(encoded.json.clone(), encoded.fork)
                .await?
        }
    };
    let status = response.status().as_u16();
    drop(response);
    Ok(classify_publication_status(status))
}

fn ensure_exact_duty_slot<T: SlotClock>(
    clock: &T,
    requested: Slot,
) -> Result<(), PqProposerServiceError> {
    let current = clock.now();
    if current != Some(requested) {
        return Err(PqProposerServiceError::StaleAfterDuty { requested, current });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqProposalCompletion {
    NoLocalDuty { slot: Slot },
    Published { slot: Slot, block_root: Hash256 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PqResolvedDuty {
    slot: Slot,
    pubkey: ValidatorPublicKeyBytes,
    validator_index: u64,
    dependent_root: Hash256,
}

impl PqResolvedDuty {
    #[cfg(all(test, feature = "pq-startup-testing"))]
    pub const fn slot(&self) -> Slot {
        self.slot
    }

    #[cfg(all(test, feature = "pq-startup-testing"))]
    pub const fn pubkey(&self) -> ValidatorPublicKeyBytes {
        self.pubkey
    }

    #[cfg(all(test, feature = "pq-startup-testing"))]
    pub const fn validator_index(&self) -> u64 {
        self.validator_index
    }

    #[cfg(all(test, feature = "pq-startup-testing"))]
    pub const fn dependent_root(&self) -> Hash256 {
        self.dependent_root
    }
}

fn resolve_current_duty(
    slot: Slot,
    identities: &[PqLocalIdentity],
    response: DutiesResponse<Vec<eth2::types::ProposerData>>,
) -> Result<Option<PqResolvedDuty>, PqProposerServiceError> {
    if response.execution_optimistic != Some(false) {
        return Err(PqProposerServiceError::OptimisticDuties);
    }
    let current_duties = response
        .data
        .into_iter()
        .filter(|duty| duty.slot == slot)
        .collect::<Vec<_>>();
    let [duty] = current_duties.as_slice() else {
        return Err(PqProposerServiceError::InvalidCurrentSlotDutyCount {
            slot,
            count: current_duties.len(),
        });
    };
    let pubkey_match = identities
        .iter()
        .find(|identity| identity.pubkey == duty.pubkey);
    let index_match = identities
        .iter()
        .find(|identity| identity.validator_index == duty.validator_index);
    match (pubkey_match, index_match) {
        (Some(by_pubkey), Some(by_index)) if by_pubkey == by_index => Ok(Some(PqResolvedDuty {
            slot,
            pubkey: duty.pubkey,
            validator_index: duty.validator_index,
            dependent_root: response.dependent_root,
        })),
        (Some(_), _) | (_, Some(_)) => Err(PqProposerServiceError::DutyIdentityMismatch { slot }),
        (None, None) => Ok(None),
    }
}

fn validate_pq_v3_response(
    duty: PqResolvedDuty,
    expected_randao: consensus_signature::IndividualSignature,
    requested_graffiti: types::Graffiti,
    response: eth2::types::ProduceBlockV3Response<MinimalEthSpec>,
    metadata: eth2::types::ProduceBlockV3Metadata,
) -> Result<
    (
        eth2::types::FullBlockContents<MinimalEthSpec>,
        types::Uint256,
    ),
    PqProposerServiceError,
> {
    if metadata.consensus_version != types::ForkName::Electra {
        return Err(PqProposerServiceError::InvalidProducedBlock(
            "consensus version is not Electra",
        ));
    }
    if metadata.execution_payload_blinded {
        return Err(PqProposerServiceError::InvalidProducedBlock(
            "metadata marks the payload blinded",
        ));
    }
    if metadata.consensus_block_value != types::Uint256::ZERO {
        return Err(PqProposerServiceError::InvalidProducedBlock(
            "consensus block value is nonzero",
        ));
    }
    match response {
        eth2::types::ProduceBlockV3Response::Full(contents) => match &contents {
            eth2::types::FullBlockContents::BlockContents(block_contents) => {
                if !block_contents.kzg_proofs.is_empty() || !block_contents.blobs.is_empty() {
                    return Err(PqProposerServiceError::InvalidProducedBlock(
                        "Electra blob proofs or blobs are nonempty",
                    ));
                }
                let block = &block_contents.block;
                let types::BeaconBlock::Electra(electra) = block else {
                    return Err(PqProposerServiceError::InvalidProducedBlock(
                        "block body is not Electra",
                    ));
                };
                if electra.state_root == Hash256::ZERO {
                    return Err(PqProposerServiceError::InvalidProducedBlock(
                        "post-state root is zero",
                    ));
                }
                if block.slot() != duty.slot {
                    return Err(PqProposerServiceError::InvalidProducedBlock(
                        "block slot does not match duty",
                    ));
                }
                if block.proposer_index() != duty.validator_index {
                    return Err(PqProposerServiceError::InvalidProducedBlock(
                        "block proposer does not match duty",
                    ));
                }
                if block.body().randao_reveal() != &expected_randao {
                    return Err(PqProposerServiceError::InvalidProducedBlock(
                        "block RANDAO does not match request",
                    ));
                }
                if block.body().graffiti() != &requested_graffiti {
                    return Err(PqProposerServiceError::InvalidProducedBlock(
                        "block graffiti does not match request",
                    ));
                }
                let body = &electra.body;
                let unsupported = if !body.attestations.is_empty() {
                    Some("attestations are nonempty")
                } else if body.sync_aggregate.sync_committee_bits.num_set_bits() != 0 {
                    Some("sync committee participants are nonempty")
                } else if !body.sync_aggregate.sync_committee_signature.is_empty() {
                    Some("sync committee evidence is nonempty")
                } else if body.eth1_data.deposit_count != 0 {
                    Some("eth1 deposit count is nonzero")
                } else if !body.proposer_slashings.is_empty() {
                    Some("proposer slashings are nonempty")
                } else if !body.attester_slashings.is_empty() {
                    Some("attester slashings are nonempty")
                } else if !body.deposits.is_empty() {
                    Some("deposits are nonempty")
                } else if !body.voluntary_exits.is_empty() {
                    Some("voluntary exits are nonempty")
                } else if !body.bls_to_execution_changes.is_empty() {
                    Some("BLS-to-execution changes are nonempty")
                } else if !body.execution_requests.deposits.is_empty() {
                    Some("deposit requests are nonempty")
                } else if !body.execution_requests.withdrawals.is_empty() {
                    Some("withdrawal requests are nonempty")
                } else if !body.execution_requests.consolidations.is_empty() {
                    Some("consolidation requests are nonempty")
                } else if !body.blob_kzg_commitments.is_empty() {
                    Some("blob KZG commitments are nonempty")
                } else {
                    None
                };
                if let Some(reason) = unsupported {
                    return Err(PqProposerServiceError::InvalidProducedBlock(reason));
                }
                Ok((contents, metadata.execution_payload_value))
            }
            eth2::types::FullBlockContents::Block(_) => {
                Err(PqProposerServiceError::InvalidProducedBlock(
                    "Electra response is not BlockContents",
                ))
            }
        },
        eth2::types::ProduceBlockV3Response::Blinded(_) => Err(
            PqProposerServiceError::InvalidProducedBlock("blinded V3 response"),
        ),
    }
}

fn reconcile_pq_v3_json_metadata(
    response: ForkVersionedResponse<ProduceBlockV3Response<MinimalEthSpec>, ProduceBlockV3Metadata>,
    headers: ProduceBlockV3Metadata,
) -> Result<
    (
        ProduceBlockV3Response<MinimalEthSpec>,
        ProduceBlockV3Metadata,
    ),
    PqProposerServiceError,
> {
    if response.version != headers.consensus_version
        || response.metadata.execution_payload_blinded != headers.execution_payload_blinded
        || response.metadata.execution_payload_value != headers.execution_payload_value
        || response.metadata.consensus_block_value != headers.consensus_block_value
    {
        return Err(PqProposerServiceError::InvalidProducedBlock(
            "JSON body metadata disagrees with response headers",
        ));
    }
    Ok((response.data, headers))
}

#[derive(Clone)]
pub struct PqProposalReceipt {
    slot: Slot,
    completion: watch::Receiver<Option<Result<PqProposalCompletion, PqProposerServiceError>>>,
}

impl PqProposalReceipt {
    pub const fn slot(&self) -> Slot {
        self.slot
    }

    pub async fn completion(&self) -> Result<PqProposalCompletion, PqProposerServiceError> {
        let mut completion = self.completion.clone();
        loop {
            if let Some(result) = completion.borrow().clone() {
                return result;
            }
            completion
                .changed()
                .await
                .map_err(|_| PqProposerServiceError::TaskUnavailable)?;
        }
    }
}

struct PqSchedulerState {
    highest_started: Option<Slot>,
    current_receipt: Option<PqProposalReceipt>,
}

struct PqProposalScheduler<T: SlotClock + 'static> {
    clock: T,
    admission: Arc<Semaphore>,
    state: Mutex<PqSchedulerState>,
    idle: Arc<Notify>,
}

enum PqProposalAdmission<T: SlotClock + 'static> {
    Started {
        admitted: PqAdmittedProposal<T>,
        receipt: PqProposalReceipt,
    },
    Coalesced(PqProposalReceipt),
}

struct PqAdmittedProposal<T: SlotClock + 'static> {
    scheduler: Arc<PqProposalScheduler<T>>,
    slot: Slot,
    previous_highest: Option<Slot>,
    admission: Option<OwnedSemaphorePermit>,
    completion: Option<watch::Sender<Option<Result<PqProposalCompletion, PqProposerServiceError>>>>,
    started: bool,
    finished: bool,
}

impl<T: SlotClock + 'static> PqProposalScheduler<T> {
    fn new(clock: T) -> Self {
        Self {
            clock,
            admission: Arc::new(Semaphore::new(1)),
            state: Mutex::new(PqSchedulerState {
                highest_started: None,
                current_receipt: None,
            }),
            idle: Arc::new(Notify::new()),
        }
    }

    fn try_admit(self: &Arc<Self>) -> Result<PqProposalAdmission<T>, PqProposerServiceError> {
        let slot = self
            .clock
            .now()
            .ok_or(PqProposerServiceError::ClockUnavailable)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| PqProposerServiceError::TaskUnavailable)?;
        if state.highest_started == Some(slot) {
            let receipt = state
                .current_receipt
                .clone()
                .ok_or(PqProposerServiceError::TaskUnavailable)?;
            return Ok(PqProposalAdmission::Coalesced(receipt));
        }
        if slot == self.clock.genesis_slot()
            || state
                .highest_started
                .is_some_and(|highest_started| slot < highest_started)
        {
            return Err(PqProposerServiceError::StaleSlot {
                slot,
                highest_started: state.highest_started,
            });
        }
        let admission = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| PqProposerServiceError::Capacity)?;
        let previous_highest = state.highest_started;
        let (completion, receiver) = watch::channel(None);
        let receipt = PqProposalReceipt {
            slot,
            completion: receiver,
        };
        state.highest_started = Some(slot);
        state.current_receipt = Some(receipt.clone());
        Ok(PqProposalAdmission::Started {
            admitted: PqAdmittedProposal {
                scheduler: Arc::clone(self),
                slot,
                previous_highest,
                admission: Some(admission),
                completion: Some(completion),
                started: false,
                finished: false,
            },
            receipt,
        })
    }

    #[cfg(all(test, feature = "pq-startup-testing"))]
    async fn wait_until_idle(&self) {
        while self.admission.available_permits() == 0 {
            let notified = self.idle.notified();
            if self.admission.available_permits() == 0 {
                notified.await;
            }
        }
    }
}

impl<T: SlotClock + 'static> PqAdmittedProposal<T> {
    fn mark_started(&mut self) {
        self.started = true;
    }

    fn finish(mut self, result: Result<PqProposalCompletion, PqProposerServiceError>) {
        let completion = self.completion.take();
        drop(self.admission.take());
        self.scheduler.idle.notify_waiters();
        if let Some(completion) = completion {
            completion.send_replace(Some(result));
        }
        self.finished = true;
    }
}

impl<T: SlotClock + 'static> Drop for PqAdmittedProposal<T> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if !self.started
            && let Ok(mut state) = self.scheduler.state.lock()
            && state.highest_started == Some(self.slot)
        {
            state.highest_started = self.previous_highest;
            state.current_receipt = None;
        }
        let completion = self.completion.take();
        drop(self.admission.take());
        self.scheduler.idle.notify_waiters();
        if let Some(completion) = completion {
            completion.send_replace(Some(Err(PqProposerServiceError::TaskUnavailable)));
        }
    }
}

/// Concrete process-owned boundary for the single configured PQ beacon node and local validator
/// store. Proposal scheduling remains private until the duty-to-signature pipeline is complete.
pub struct PqProposerService<T: SlotClock + 'static> {
    scheduler: Arc<PqProposalScheduler<T>>,
    task_executor: TaskExecutor,
    validator_store: Arc<LighthouseValidatorStore<T, MinimalEthSpec>>,
    beacon_node: StrictBeaconNodeHttpClient,
    identities: Arc<[PqLocalIdentity]>,
    #[cfg(feature = "pq-startup-testing")]
    publication_encode_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "pq-startup-testing")]
    publication_json_fallback_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "pq-startup-testing")]
    post_production_hook: Option<Arc<PqTestingAsyncHook>>,
}

impl<T: SlotClock + 'static> PqProposerService<T> {
    pub fn new(
        clock: T,
        task_executor: TaskExecutor,
        validator_store: Arc<LighthouseValidatorStore<T, MinimalEthSpec>>,
        beacon_node: StrictBeaconNodeHttpClient,
    ) -> Result<Self, PqProposerServiceError> {
        validate_slot_duration(clock.slot_duration())?;
        let identities = validator_store
            .pq_validator_identity_snapshot()
            .ok_or(PqProposerServiceError::InvalidIdentitySet)?
            .into_iter()
            .map(|(pubkey, validator_index)| PqLocalIdentity::new(pubkey, validator_index))
            .collect::<Vec<_>>();
        if !validate_identity_set(&identities) {
            return Err(PqProposerServiceError::InvalidIdentitySet);
        }
        Ok(Self {
            scheduler: Arc::new(PqProposalScheduler::new(clock)),
            task_executor,
            validator_store,
            beacon_node,
            identities: identities.into(),
            #[cfg(feature = "pq-startup-testing")]
            publication_encode_hook: None,
            #[cfg(feature = "pq-startup-testing")]
            publication_json_fallback_hook: None,
            #[cfg(feature = "pq-startup-testing")]
            post_production_hook: None,
        })
    }

    #[cfg(feature = "pq-startup-testing")]
    pub fn testing_only_publication_encode_hook(
        mut self,
        hook: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        self.publication_encode_hook = Some(hook);
        self
    }

    #[cfg(feature = "pq-startup-testing")]
    pub fn testing_only_publication_json_fallback_hook(
        mut self,
        hook: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        self.publication_json_fallback_hook = Some(hook);
        self
    }

    #[cfg(feature = "pq-startup-testing")]
    pub fn testing_only_post_production_hook<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.post_production_hook = Some(Arc::new(move || Box::pin(hook())));
        self
    }

    pub fn try_propose_current_slot(
        self: &Arc<Self>,
    ) -> Result<PqProposalReceipt, PqProposerServiceError> {
        match self.scheduler.try_admit()? {
            PqProposalAdmission::Coalesced(receipt) => Ok(receipt),
            PqProposalAdmission::Started {
                mut admitted,
                receipt,
            } => {
                let service = Arc::clone(self);
                let task = self.task_executor.spawn_handle(
                    async move {
                        admitted.mark_started();
                        let slot = admitted.slot;
                        let completion = service.propose(slot).await;
                        admitted.finish(completion);
                    },
                    "pq-proposer-current-slot",
                );
                if task.is_none() {
                    return Err(PqProposerServiceError::TaskUnavailable);
                }
                drop(task);
                Ok(receipt)
            }
        }
    }

    async fn propose(&self, slot: Slot) -> Result<PqProposalCompletion, PqProposerServiceError> {
        let timing =
            PqProposalTiming::new(&self.scheduler.clock, slot).map_err(map_timing_error)?;
        let epoch = slot.epoch(MinimalEthSpec::slots_per_epoch());
        let response = run_pq_prepare_response(
            &timing,
            &self.scheduler.clock,
            |remaining| async move {
                let response = self
                    .beacon_node
                    .pq_get_validator_duties_proposer_response(epoch, remaining)
                    .await
                    .map_err(PqStrictResponseError::Transport)?;
                collect_pq_success_response(response, PQ_DUTIES_RESPONSE_MAX_BYTES).await
            },
            |response| decode_collected_pq_duties_response(&self.task_executor, response),
        )
        .await?
        .map_err(|error| PqProposerServiceError::DutyRequest(error.into()))?;
        let current_slot = self.scheduler.clock.now();
        if current_slot != Some(slot) {
            return Err(PqProposerServiceError::StaleAfterDuty {
                requested: slot,
                current: current_slot,
            });
        }
        let Some(duty) = resolve_current_duty(slot, &self.identities, response)? else {
            return Ok(PqProposalCompletion::NoLocalDuty { slot });
        };
        self.produce_sign_and_publish(duty, timing).await
    }

    async fn produce_sign_and_publish(
        &self,
        duty: PqResolvedDuty,
        timing: PqProposalTiming,
    ) -> Result<PqProposalCompletion, PqProposerServiceError> {
        ensure_exact_duty_slot(&self.scheduler.clock, duty.slot)?;
        let before_randao = self
            .scheduler
            .clock
            .now_duration()
            .ok_or(PqProposerServiceError::ClockUnavailable)?;
        timing
            .remaining_prepare(before_randao)
            .map_err(map_timing_error)?;
        if !self
            .validator_store
            .doppelganger_protection_allows_signing(duty.pubkey)
        {
            return Err(PqProposerServiceError::DoppelgangerNotReady {
                pubkey: duty.pubkey,
            });
        }

        let randao = self
            .validator_store
            .randao_reveal(duty.pubkey, duty.slot)
            .await
            .map_err(|error| {
                PqProposerServiceError::Randao(classify_store_operation_error(error))
            })?;
        let serialized_randao = serialize_individual_signature(&randao);
        let after_randao = self
            .scheduler
            .clock
            .now_duration()
            .ok_or(PqProposerServiceError::ClockUnavailable)?;
        match timing
            .classify_non_cancellable_completion(PqNonCancellablePhase::Randao, after_randao)
        {
            PqNonCancellableCompletion::OnTime => {}
            PqNonCancellableCompletion::PhaseOverrun => {
                return Err(PqProposerServiceError::PreparationExpired {
                    deadline: timing.prepare_deadline,
                });
            }
            PqNonCancellableCompletion::GlobalExpired => {
                return Err(PqProposerServiceError::PreparationExpired {
                    deadline: timing.global_deadline,
                });
            }
        }
        if self.scheduler.clock.now() != Some(duty.slot) {
            return Err(PqProposerServiceError::StaleAfterDuty {
                requested: duty.slot,
                current: self.scheduler.clock.now(),
            });
        }

        let graffiti = self
            .validator_store
            .graffiti(&duty.pubkey)
            .unwrap_or_default();
        let production_url = self
            .beacon_node
            .get_validator_blocks_v3_path(
                duty.slot,
                &serialized_randao,
                Some(&graffiti),
                eth2::types::SkipRandaoVerification::No,
                None,
                None,
            )
            .await
            .map_err(|error| PqProposerServiceError::BlockProduction(error.into()))?;
        let (max_v3_ssz_bytes, max_v3_json_bytes) =
            pq_v3_response_body_limits().ok_or(PqProposerServiceError::Configuration(
                PqProposerConfigurationError::ResponseBodyLimitsOverflow,
            ))?;
        let ssz_response = run_pq_prepare_response(
            &timing,
            &self.scheduler.clock,
            |remaining| {
                let production_url = production_url.clone();
                async move {
                    let response = self
                        .beacon_node
                        .pq_get_validator_blocks_v3_response(production_url, Accept::Ssz, remaining)
                        .await
                        .map_err(PqStrictResponseError::Transport)?;
                    collect_pq_success_response(response, max_v3_ssz_bytes).await
                }
            },
            |response| decode_collected_pq_v3_ssz_response(&self.task_executor, response),
        )
        .await?;
        let (response, metadata) = match ssz_response {
            Ok(response) => response,
            Err(error) if allows_bounded_production_json_fallback(&error, &production_url) => {
                ensure_exact_duty_slot(&self.scheduler.clock, duty.slot)?;
                let (response, metadata) = run_pq_prepare_response(
                    &timing,
                    &self.scheduler.clock,
                    |remaining| {
                        let production_url = production_url.clone();
                        async move {
                            let response = self
                                .beacon_node
                                .pq_get_validator_blocks_v3_response(
                                    production_url,
                                    Accept::Json,
                                    remaining,
                                )
                                .await
                                .map_err(PqStrictResponseError::Transport)?;
                            collect_pq_success_response(response, max_v3_json_bytes).await
                        }
                    },
                    |response| decode_collected_pq_v3_json_response(&self.task_executor, response),
                )
                .await?
                .map_err(|error| PqProposerServiceError::BlockProduction(error.into()))?;
                reconcile_pq_v3_json_metadata(response, metadata)?
            }
            Err(error) => {
                return Err(PqProposerServiceError::BlockProduction(error.into()));
            }
        };
        let (contents, _execution_payload_value) =
            validate_pq_v3_response(duty.clone(), randao, graffiti, response, metadata)?;
        #[cfg(feature = "pq-startup-testing")]
        if let Some(hook) = &self.post_production_hook {
            hook().await;
        }
        let sign_started = self
            .scheduler
            .clock
            .now_duration()
            .ok_or(PqProposerServiceError::ClockUnavailable)?;
        timing
            .remaining_prepare(sign_started)
            .map_err(map_timing_error)?;
        let sign_deadline = timing
            .start_block_sign(sign_started)
            .map_err(map_timing_error)?;
        if !self
            .validator_store
            .doppelganger_protection_allows_signing(duty.pubkey)
        {
            return Err(PqProposerServiceError::DoppelgangerNotReady {
                pubkey: duty.pubkey,
            });
        }
        ensure_exact_duty_slot(&self.scheduler.clock, duty.slot)?;
        let signed = self
            .validator_store
            .sign_block(duty.pubkey, UnsignedBlock::Full(contents), duty.slot)
            .await
            .map_err(|error| {
                PqProposerServiceError::BlockSigning(classify_store_operation_error(error))
            })?;
        let signed_at = self
            .scheduler
            .clock
            .now_duration()
            .ok_or(PqProposerServiceError::ClockUnavailable)?;
        match sign_deadline.classify_non_cancellable_completion(signed_at) {
            PqNonCancellableCompletion::OnTime => {}
            PqNonCancellableCompletion::PhaseOverrun
            | PqNonCancellableCompletion::GlobalExpired => {
                return Err(PqProposerServiceError::BlockSigningExpired {
                    deadline: sign_deadline.deadline(),
                });
            }
        }
        let SignedBlock::Full(signed) = signed else {
            return Err(PqProposerServiceError::InvalidProducedBlock(
                "validator store returned a blinded block",
            ));
        };
        let publish_started = self
            .scheduler
            .clock
            .now_duration()
            .ok_or(PqProposerServiceError::ClockUnavailable)?;
        let publish_deadline = timing
            .start_publish(publish_started)
            .map_err(map_publish_timing_error)?;
        let encode = self
            .task_executor
            .spawn_blocking_handle(
                {
                    #[cfg(feature = "pq-startup-testing")]
                    let hook = self.publication_encode_hook.clone();
                    move || {
                        #[cfg(feature = "pq-startup-testing")]
                        if let Some(hook) = hook {
                            hook();
                        }
                        encode_pq_publication(signed)
                    }
                },
                "pq-proposer-publication-encode",
            )
            .ok_or(PqProposerServiceError::TaskUnavailable)?;
        let encoded = encode
            .await
            .map_err(|_| PqProposerServiceError::TaskUnavailable)?
            .map_err(|error| {
                PqProposerServiceError::PublicationEncoding(PqJsonEncodingError(Arc::new(error)))
            })?;
        let publish_http_started = self
            .scheduler
            .clock
            .now_duration()
            .ok_or(PqProposerServiceError::ClockUnavailable)?;
        let remaining = publish_deadline
            .remaining(publish_http_started)
            .map_err(map_publish_timing_error)?;
        let wall_deadline = tokio::time::Instant::now()
            .checked_add(remaining)
            .ok_or(PqProposerServiceError::TimingOverflow)?;
        let publication_url = self
            .beacon_node
            .post_beacon_blocks_v2_path(None)
            .map_err(|error| PqProposerServiceError::Publication(error.into()))?;
        let mut publication_body = PqPublicationBody::Ssz;
        let mut retry_delay = Duration::from_millis(50);
        loop {
            let request =
                post_pq_publication_attempt(&self.beacon_node, publication_body, &encoded);
            let attempt = tokio::time::timeout_at(wall_deadline, request)
                .await
                .map_err(|_| PqProposerServiceError::PublicationExpired {
                    deadline: publish_deadline.deadline(),
                })?;
            if let Err(error) = &attempt
                && matches!(publication_body, PqPublicationBody::Ssz)
                && allows_publication_json_fallback(error, &publication_url)
            {
                publication_body = PqPublicationBody::Json;
                #[cfg(feature = "pq-startup-testing")]
                if let Some(hook) = &self.publication_json_fallback_hook {
                    hook();
                }
                continue;
            }
            let status = match attempt {
                Ok(status) => status,
                Err(error) => match error.status() {
                    Some(status) => classify_publication_status(status.as_u16()),
                    None if matches!(error, eth2::Error::HttpClient(_)) => {
                        PqPublicationStatus::Retry
                    }
                    None => {
                        return Err(PqProposerServiceError::Publication(error.into()));
                    }
                },
            };
            match status {
                PqPublicationStatus::Published => break,
                PqPublicationStatus::Terminal(status) => {
                    return Err(PqProposerServiceError::PublicationRejected { status });
                }
                PqPublicationStatus::Protocol(status) => {
                    return Err(PqProposerServiceError::PublicationProtocol { status });
                }
                PqPublicationStatus::Retry => {
                    tokio::time::timeout_at(wall_deadline, tokio::time::sleep(retry_delay))
                        .await
                        .map_err(|_| PqProposerServiceError::PublicationExpired {
                            deadline: publish_deadline.deadline(),
                        })?;
                    retry_delay = retry_delay
                        .checked_mul(2)
                        .unwrap_or(Duration::from_secs(1))
                        .min(Duration::from_secs(1));
                }
            }
        }
        let published_at = self
            .scheduler
            .clock
            .now_duration()
            .ok_or(PqProposerServiceError::ClockUnavailable)?;
        if publish_deadline.classify_non_cancellable_completion(published_at)
            != PqNonCancellableCompletion::OnTime
        {
            return Err(PqProposerServiceError::PublicationExpired {
                deadline: publish_deadline.deadline(),
            });
        }
        Ok(PqProposalCompletion::Published {
            slot: duty.slot,
            block_root: encoded.block_root,
        })
    }
}

fn map_timing_error(error: PqProposalTimingError) -> PqProposerServiceError {
    match error {
        PqProposalTimingError::ClockUnavailable => PqProposerServiceError::ClockUnavailable,
        PqProposalTimingError::Overflow => PqProposerServiceError::TimingOverflow,
        PqProposalTimingError::PhaseExpired { deadline, .. }
        | PqProposalTimingError::GlobalExpired { deadline } => {
            PqProposerServiceError::PreparationExpired { deadline }
        }
    }
}

fn map_publish_timing_error(error: PqProposalTimingError) -> PqProposerServiceError {
    match error {
        PqProposalTimingError::ClockUnavailable => PqProposerServiceError::ClockUnavailable,
        PqProposalTimingError::Overflow => PqProposerServiceError::TimingOverflow,
        PqProposalTimingError::PhaseExpired { deadline, .. }
        | PqProposalTimingError::GlobalExpired { deadline } => {
            PqProposerServiceError::PublicationExpired { deadline }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqBeaconFailure {
    Connect,
    Timeout,
    Status(u16),
    ResponseTooLarge,
    FragmentLimit,
    Stream,
    Resource,
    InvalidHeaders,
    InvalidJson,
    InvalidSsz,
    Protocol,
}

impl From<eth2::Error> for PqBeaconFailure {
    fn from(error: eth2::Error) -> Self {
        if let Some(status) = error.status() {
            return Self::Status(status.as_u16());
        }
        match error {
            eth2::Error::HttpClient(error) if error.inner().is_connect() => Self::Connect,
            eth2::Error::HttpClient(error) if error.inner().is_timeout() => Self::Timeout,
            eth2::Error::InvalidHeaders(_) => Self::InvalidHeaders,
            eth2::Error::InvalidJson(_) => Self::InvalidJson,
            eth2::Error::InvalidSsz(_) => Self::InvalidSsz,
            _ => Self::Protocol,
        }
    }
}

impl From<PqStrictResponseError> for PqBeaconFailure {
    fn from(error: PqStrictResponseError) -> Self {
        match error {
            PqStrictResponseError::Transport(error) => error.into(),
            PqStrictResponseError::Collection(error) => match error {
                PqResponseCollectionError::PayloadTooLarge => Self::ResponseTooLarge,
                PqResponseCollectionError::FragmentLimit => Self::FragmentLimit,
                PqResponseCollectionError::Stream => Self::Stream,
                PqResponseCollectionError::Resource => Self::Resource,
            },
            PqStrictResponseError::Status(status) => Self::Status(status.as_u16()),
            PqStrictResponseError::InvalidHeaders(_) => Self::InvalidHeaders,
            PqStrictResponseError::InvalidJson(_) => Self::InvalidJson,
            PqStrictResponseError::InvalidSsz(_) => Self::InvalidSsz,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqStoreFailureKind {
    InvalidSigningRequest,
    ExecutorUnavailable,
    DoppelgangerProtected,
    UnknownValidator,
    Slashable,
    SigningBackend,
    InvalidRequest,
}

#[derive(Clone, Debug)]
pub struct PqStoreOperationError {
    kind: PqStoreFailureKind,
    source: Option<Arc<signing_method::Error>>,
}

impl PqStoreOperationError {
    pub const fn kind(&self) -> PqStoreFailureKind {
        self.kind
    }

    pub const fn is_transient(&self) -> bool {
        matches!(
            self.kind,
            PqStoreFailureKind::ExecutorUnavailable | PqStoreFailureKind::DoppelgangerProtected
        )
    }
}

impl PartialEq for PqStoreOperationError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}

impl Eq for PqStoreOperationError {}

impl std::fmt::Display for PqStoreOperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PQ validator-store operation failed: {:?}",
            self.kind
        )
    }
}

impl Error for PqStoreOperationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|error| error as &(dyn Error + 'static))
    }
}

fn classify_store_operation_error(
    error: lighthouse_validator_store::Error,
) -> PqStoreOperationError {
    let (kind, source) = match error {
        validator_store::Error::SpecificError(error) => {
            let kind = match &error {
                signing_method::Error::ShuttingDown | signing_method::Error::TokioJoin(_) => {
                    PqStoreFailureKind::ExecutorUnavailable
                }
                signing_method::Error::PqSigning(
                    pq_signing::PqSigningError::InvalidSigningRequest,
                ) => PqStoreFailureKind::InvalidSigningRequest,
                signing_method::Error::InconsistentDomains { .. }
                | signing_method::Error::InconsistentEpochs { .. }
                | signing_method::Error::PqSigningDutyUnsupported(_)
                | signing_method::Error::PqSigningId(_) => PqStoreFailureKind::InvalidRequest,
                _ => PqStoreFailureKind::SigningBackend,
            };
            (kind, Some(Arc::new(error)))
        }
        validator_store::Error::ExecutorError => (PqStoreFailureKind::ExecutorUnavailable, None),
        validator_store::Error::DoppelgangerProtected(_)
        | validator_store::Error::UnknownToDoppelgangerService(_) => {
            (PqStoreFailureKind::DoppelgangerProtected, None)
        }
        validator_store::Error::UnknownPubkey(_) => (PqStoreFailureKind::UnknownValidator, None),
        validator_store::Error::Slashable(_) => (PqStoreFailureKind::Slashable, None),
        validator_store::Error::SameData
        | validator_store::Error::GreaterThanCurrentSlot { .. }
        | validator_store::Error::UnableToSignAttestation(_)
        | validator_store::Error::Middleware(_) => (PqStoreFailureKind::InvalidRequest, None),
    };
    PqStoreOperationError { kind, source }
}

#[derive(Clone, Debug)]
pub struct PqJsonEncodingError(Arc<serde_json::Error>);

impl PartialEq for PqJsonEncodingError {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for PqJsonEncodingError {}

impl std::fmt::Display for PqJsonEncodingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PQ signed-block JSON encoding failed")
    }
}

impl Error for PqJsonEncodingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqProposerConfigurationError {
    ResponseBodyLimitsOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqProposerServiceError {
    InvalidIdentitySet,
    WrongSlotDuration {
        supplied: Duration,
        required: Duration,
    },
    ClockUnavailable,
    Configuration(PqProposerConfigurationError),
    MissingValidatorIndex {
        pubkey: ValidatorPublicKeyBytes,
    },
    OptimisticDuties,
    DutyIdentityMismatch {
        slot: Slot,
    },
    InvalidCurrentSlotDutyCount {
        slot: Slot,
        count: usize,
    },
    DutyRequest(PqBeaconFailure),
    DoppelgangerNotReady {
        pubkey: ValidatorPublicKeyBytes,
    },
    Randao(PqStoreOperationError),
    BlockProduction(PqBeaconFailure),
    InvalidProducedBlock(&'static str),
    BlockSigning(PqStoreOperationError),
    BlockSigningExpired {
        deadline: Duration,
    },
    Publication(PqBeaconFailure),
    PublicationEncoding(PqJsonEncodingError),
    PublicationRejected {
        status: u16,
    },
    PublicationProtocol {
        status: u16,
    },
    PublicationExpired {
        deadline: Duration,
    },
    TimingOverflow,
    PreparationExpired {
        deadline: Duration,
    },
    StaleAfterDuty {
        requested: Slot,
        current: Option<Slot>,
    },
    StaleSlot {
        slot: Slot,
        highest_started: Option<Slot>,
    },
    Capacity,
    TaskUnavailable,
}

impl PqProposerServiceError {
    /// Whether a synchronous failure returned by `try_propose_current_slot` may be retried.
    pub const fn is_start_retryable(&self) -> bool {
        matches!(
            self,
            Self::ClockUnavailable | Self::Capacity | Self::TaskUnavailable
        )
    }

    /// A completed receipt is permanently coalesced at the scheduler high-water mark.
    ///
    /// Allowlisted fallbacks and exact signed-publication retries occur inside that detached
    /// operation under its original deadlines. A caller must never start a second same-slot
    /// journal operation after completion.
    pub const fn is_same_slot_retryable_after_completion(&self) -> bool {
        false
    }
}

impl std::fmt::Display for PqProposerServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ proposer service unavailable: {self:?}")
    }
}

impl Error for PqProposerServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Randao(error) | Self::BlockSigning(error) => Some(error),
            Self::PublicationEncoding(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "pq-startup-testing"))]
mod tests {
    use super::*;
    use consensus_signature::PqPublicKey;
    use futures::stream;
    use slot_clock::TestingSlotClock;
    use ssz::Decode;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn bounded_response_rejects_declared_actual_and_fragment_excess() {
        let (max_v3_ssz, max_v3_json) =
            pq_v3_response_body_limits().expect("checked V3 response limits");
        assert!(max_v3_ssz > PQ_DUTIES_RESPONSE_MAX_BYTES);
        assert!(max_v3_json > max_v3_ssz);
        assert_eq!(PQ_ERROR_RESPONSE_MAX_BYTES, PQ_DUTIES_RESPONSE_MAX_BYTES);
        let polled = Arc::new(AtomicUsize::new(0));
        let polled_for_stream = Arc::clone(&polled);
        let declared_oversize = stream::iter([Ok::<_, ()>(bytes::Bytes::from_static(b"ignored"))])
            .map(move |item| {
                polled_for_stream.fetch_add(1, Ordering::SeqCst);
                item
            });
        assert_eq!(
            collect_pq_response_body(
                declared_oversize,
                Some((PQ_DUTIES_RESPONSE_MAX_BYTES + 1) as u64),
                PQ_DUTIES_RESPONSE_MAX_BYTES,
            )
            .await,
            Err(PqResponseCollectionError::PayloadTooLarge),
        );
        assert_eq!(polled.load(Ordering::SeqCst), 0);

        let actual_oversize = stream::iter([
            Ok::<_, ()>(bytes::Bytes::from(vec![0; PQ_DUTIES_RESPONSE_MAX_BYTES])),
            Ok(bytes::Bytes::from_static(&[1])),
        ]);
        assert_eq!(
            collect_pq_response_body(actual_oversize, None, PQ_DUTIES_RESPONSE_MAX_BYTES).await,
            Err(PqResponseCollectionError::PayloadTooLarge),
        );

        let fragmented = stream::iter(vec![
            Ok::<_, ()>(bytes::Bytes::from_static(b"x"));
            PQ_RESPONSE_CHUNK_CAPACITY + 1
        ]);
        assert_eq!(
            collect_pq_response_body(fragmented, None, PQ_DUTIES_RESPONSE_MAX_BYTES).await,
            Err(PqResponseCollectionError::FragmentLimit),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn response_coalescing_and_decode_run_on_the_owned_blocking_executor() {
        let runtime = task_executor::test_utils::TestRuntime::default();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let entered_tx = std::sync::Mutex::new(Some(entered_tx));
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let body = serde_json::to_vec(&DutiesResponse::<Vec<eth2::types::ProposerData>> {
            dependent_root: Hash256::repeat_byte(0x42),
            execution_optimistic: Some(false),
            data: vec![],
        })
        .expect("duties JSON");
        let length = body.len();
        let decode = decode_collected_pq_duties_response(
            &runtime.task_executor,
            PqCollectedResponse {
                status: reqwest::StatusCode::OK,
                headers: reqwest::header::HeaderMap::new(),
                chunks: vec![bytes::Bytes::from(body)],
                length,
                coalesce_hook: Some(Box::new(move || {
                    entered_tx
                        .lock()
                        .expect("decode entered lock")
                        .take()
                        .expect("first decoder entry")
                        .send(())
                        .expect("decode entered");
                    release_rx.recv().expect("release decode");
                })),
            },
        );
        tokio::pin!(decode);
        tokio::select! {
            _ = &mut decode => panic!("decode must remain behind the barrier"),
            entered = entered_rx => entered.expect("blocking decoder entered"),
        }
        assert_eq!(
            tokio::spawn(async { 23usize }).await.expect("heartbeat"),
            23
        );
        release_tx.send(()).expect("release blocking decoder");
        assert!(decode.await.expect("blocking decode").data.is_empty());
    }

    fn v3_headers() -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in [
            (eth2::CONSENSUS_VERSION_HEADER, "electra"),
            (eth2::EXECUTION_PAYLOAD_BLINDED_HEADER, "false"),
            (eth2::EXECUTION_PAYLOAD_VALUE_HEADER, "17"),
            (eth2::CONSENSUS_BLOCK_VALUE_HEADER, "0"),
        ] {
            headers.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                reqwest::header::HeaderValue::from_static(value),
            );
        }
        headers
    }

    fn collected_response(
        body: Vec<u8>,
        headers: reqwest::header::HeaderMap,
    ) -> PqCollectedResponse {
        let length = body.len();
        PqCollectedResponse {
            status: reqwest::StatusCode::OK,
            headers,
            chunks: vec![bytes::Bytes::from(body)],
            length,
            coalesce_hook: None,
        }
    }

    #[tokio::test]
    async fn specialized_v3_ssz_and_json_decoders_share_the_bounded_blocking_seam() {
        let runtime = task_executor::test_utils::TestRuntime::default();
        let (_, _, _, response, _) = valid_v3_response();
        let ProduceBlockV3Response::Full(contents) = response else {
            panic!("valid fixture is full")
        };
        let ssz = collected_response(contents.as_ssz_bytes(), v3_headers());
        let (decoded_ssz, decoded_ssz_metadata) =
            decode_collected_pq_v3_ssz_response(&runtime.task_executor, ssz)
                .await
                .expect("bounded SSZ decode");
        assert_eq!(
            decoded_ssz_metadata.consensus_version,
            types::ForkName::Electra
        );
        assert!(!decoded_ssz_metadata.execution_payload_blinded);
        assert_eq!(
            decoded_ssz_metadata.execution_payload_value,
            types::Uint256::from(17_u64)
        );
        assert_eq!(
            decoded_ssz_metadata.consensus_block_value,
            types::Uint256::ZERO
        );
        assert!(matches!(decoded_ssz, ProduceBlockV3Response::Full(_)));

        let json = serde_json::to_vec(&ForkVersionedResponse {
            version: types::ForkName::Electra,
            metadata: ProduceBlockV3Metadata {
                consensus_version: types::ForkName::Electra,
                execution_payload_blinded: false,
                execution_payload_value: types::Uint256::from(17_u64),
                consensus_block_value: types::Uint256::ZERO,
            },
            data: contents,
        })
        .expect("V3 JSON");
        let (decoded_json, decoded_json_headers) = decode_collected_pq_v3_json_response(
            &runtime.task_executor,
            collected_response(json, v3_headers()),
        )
        .await
        .expect("bounded JSON decode");
        assert_eq!(
            decoded_json_headers.consensus_version,
            types::ForkName::Electra
        );
        assert!(!decoded_json_headers.execution_payload_blinded);
        assert_eq!(
            decoded_json_headers.execution_payload_value,
            types::Uint256::from(17_u64)
        );
        assert_eq!(
            decoded_json_headers.consensus_block_value,
            types::Uint256::ZERO
        );
        assert_eq!(decoded_json.version, types::ForkName::Electra);
        assert!(matches!(decoded_json.data, ProduceBlockV3Response::Full(_)));
    }

    #[test]
    fn non_success_responses_use_the_small_error_body_cap() {
        let (_, max_v3_json) = pq_v3_response_body_limits().expect("checked V3 limits");
        assert_eq!(
            pq_response_body_limit(reqwest::StatusCode::OK, max_v3_json),
            max_v3_json,
        );
        for status in [
            reqwest::StatusCode::BAD_REQUEST,
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert_eq!(
                pq_response_body_limit(status, max_v3_json),
                PQ_ERROR_RESPONSE_MAX_BYTES,
            );
        }
    }

    #[test]
    fn json_body_metadata_must_exactly_match_response_headers() {
        let body_response =
            |version, execution_payload_blinded, execution_payload_value, consensus_block_value| {
                ForkVersionedResponse {
                    version,
                    metadata: ProduceBlockV3Metadata {
                        consensus_version: types::ForkName::Base,
                        execution_payload_blinded,
                        execution_payload_value,
                        consensus_block_value,
                    },
                    data: valid_v3_response().3,
                }
            };
        let header_metadata = || ProduceBlockV3Metadata {
            consensus_version: types::ForkName::Electra,
            execution_payload_blinded: false,
            execution_payload_value: types::Uint256::from(17_u64),
            consensus_block_value: types::Uint256::ZERO,
        };
        assert!(
            reconcile_pq_v3_json_metadata(
                body_response(
                    types::ForkName::Electra,
                    false,
                    types::Uint256::from(17_u64),
                    types::Uint256::ZERO
                ),
                header_metadata(),
            )
            .is_ok()
        );
        for response in [
            body_response(
                types::ForkName::Electra,
                true,
                types::Uint256::from(17_u64),
                types::Uint256::ZERO,
            ),
            body_response(
                types::ForkName::Electra,
                false,
                types::Uint256::from(18_u64),
                types::Uint256::ZERO,
            ),
            body_response(
                types::ForkName::Electra,
                false,
                types::Uint256::from(17_u64),
                types::Uint256::from(1_u64),
            ),
            body_response(
                types::ForkName::Fulu,
                false,
                types::Uint256::from(17_u64),
                types::Uint256::ZERO,
            ),
        ] {
            assert!(matches!(
                reconcile_pq_v3_json_metadata(response, header_metadata()),
                Err(PqProposerServiceError::InvalidProducedBlock(
                    "JSON body metadata disagrees with response headers"
                ))
            ));
        }
    }

    fn identity(byte: u8, index: u64) -> PqLocalIdentity {
        PqLocalIdentity::new(
            PqPublicKey::deserialize(&[byte; 32]).expect("canonical PQ public key"),
            index,
        )
    }

    fn decode_zero_fixed<T: Decode>() -> T {
        T::from_ssz_bytes(&vec![0; T::ssz_fixed_len()]).expect("zero fixed-length test value")
    }

    fn valid_v3_response() -> (
        PqResolvedDuty,
        consensus_signature::IndividualSignature,
        types::Graffiti,
        eth2::types::ProduceBlockV3Response<MinimalEthSpec>,
        eth2::types::ProduceBlockV3Metadata,
    ) {
        let local = identity(7, 3);
        let duty = PqResolvedDuty {
            slot: Slot::new(4),
            pubkey: local.pubkey,
            validator_index: local.validator_index,
            dependent_root: Hash256::repeat_byte(0x42),
        };
        let spec = types::ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
        let mut block = types::BeaconBlock::<MinimalEthSpec>::empty(&spec);
        *block.slot_mut() = duty.slot;
        *block.proposer_index_mut() = duty.validator_index;
        *block.state_root_mut() = Hash256::repeat_byte(0x55);
        let randao = consensus_signature::IndividualSignature::empty();
        *block.body_mut().randao_reveal_mut() = randao.clone();
        let graffiti = types::Graffiti([0x6b; 32]);
        *block.body_mut().graffiti_mut() = graffiti;
        let contents = eth2::types::FullBlockContents::new(
            block,
            Some((
                types::KzgProofs::<MinimalEthSpec>::default(),
                types::BlobsList::<MinimalEthSpec>::default(),
            )),
        );
        let metadata = eth2::types::ProduceBlockV3Metadata {
            consensus_version: types::ForkName::Electra,
            execution_payload_blinded: false,
            execution_payload_value: types::Uint256::from(17_u64),
            consensus_block_value: types::Uint256::ZERO,
        };
        (
            duty,
            randao,
            graffiti,
            eth2::types::ProduceBlockV3Response::Full(contents),
            metadata,
        )
    }

    fn mutate_valid_v3_block(
        mutate: impl FnOnce(&mut types::BeaconBlock<MinimalEthSpec>),
    ) -> (
        PqResolvedDuty,
        consensus_signature::IndividualSignature,
        types::Graffiti,
        eth2::types::ProduceBlockV3Response<MinimalEthSpec>,
        eth2::types::ProduceBlockV3Metadata,
    ) {
        let (duty, randao, graffiti, response, metadata) = valid_v3_response();
        let eth2::types::ProduceBlockV3Response::Full(
            eth2::types::FullBlockContents::BlockContents(mut contents),
        ) = response
        else {
            panic!("fixture is Electra BlockContents")
        };
        mutate(&mut contents.block);
        (
            duty,
            randao,
            graffiti,
            eth2::types::ProduceBlockV3Response::Full(
                eth2::types::FullBlockContents::BlockContents(contents),
            ),
            metadata,
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn same_slot_receipts_are_cloneable_and_observe_the_same_completion() {
        let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
        clock.set_slot(4);
        let scheduler = Arc::new(PqProposalScheduler::new(clock));
        let (mut admitted, first) = match scheduler.try_admit().expect("first admission") {
            PqProposalAdmission::Started { admitted, receipt } => (admitted, receipt),
            PqProposalAdmission::Coalesced(_) => panic!("first admission cannot coalesce"),
        };
        let second = match scheduler.try_admit().expect("same slot coalesces") {
            PqProposalAdmission::Coalesced(receipt) => receipt,
            PqProposalAdmission::Started { .. } => panic!("same slot must not start twice"),
        };
        admitted.mark_started();
        admitted.finish(Ok(PqProposalCompletion::NoLocalDuty { slot: Slot::new(4) }));
        assert_eq!(
            first.completion().await,
            Ok(PqProposalCompletion::NoLocalDuty { slot: Slot::new(4) })
        );
        assert_eq!(second.completion().await, first.completion().await);
    }

    #[test]
    fn duty_resolution_requires_the_exact_local_pubkey_and_index_pair() {
        let local = identity(7, 3);
        let dependent_root = types::Hash256::repeat_byte(0x42);
        let response = eth2::types::DutiesResponse {
            dependent_root,
            execution_optimistic: Some(false),
            data: vec![eth2::types::ProposerData {
                pubkey: local.pubkey,
                validator_index: local.validator_index,
                slot: Slot::new(4),
            }],
        };
        let duty = resolve_current_duty(Slot::new(4), &[local], response)
            .expect("exact BN duty and immutable local identity match");
        let duty = duty.expect("local proposer duty retained only inside the service");
        assert_eq!(duty.slot(), Slot::new(4));
        assert_eq!(duty.pubkey(), local.pubkey);
        assert_eq!(duty.validator_index(), 3);
        assert_eq!(duty.dependent_root(), dependent_root);
    }

    #[test]
    fn duty_resolution_requires_exactly_one_total_current_slot_duty() {
        let local = identity(7, 3);
        let foreign = identity(8, 4);
        let response = |data| eth2::types::DutiesResponse {
            dependent_root: Hash256::repeat_byte(0x42),
            execution_optimistic: Some(false),
            data,
        };

        assert_eq!(
            resolve_current_duty(Slot::new(4), &[local], response(vec![])),
            Err(PqProposerServiceError::InvalidCurrentSlotDutyCount {
                slot: Slot::new(4),
                count: 0,
            }),
        );
        for duties in [
            vec![
                eth2::types::ProposerData {
                    pubkey: foreign.pubkey,
                    validator_index: foreign.validator_index,
                    slot: Slot::new(4),
                },
                eth2::types::ProposerData {
                    pubkey: identity(9, 5).pubkey,
                    validator_index: 5,
                    slot: Slot::new(4),
                },
            ],
            vec![
                eth2::types::ProposerData {
                    pubkey: local.pubkey,
                    validator_index: local.validator_index,
                    slot: Slot::new(4),
                },
                eth2::types::ProposerData {
                    pubkey: foreign.pubkey,
                    validator_index: foreign.validator_index,
                    slot: Slot::new(4),
                },
            ],
        ] {
            assert_eq!(
                resolve_current_duty(Slot::new(4), &[local], response(duties)),
                Err(PqProposerServiceError::InvalidCurrentSlotDutyCount {
                    slot: Slot::new(4),
                    count: 2,
                }),
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn scheduling_is_clock_derived_nonwaiting_and_same_slot_coalesced() {
        let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
        let scheduler = Arc::new(PqProposalScheduler::new(clock.clone()));

        assert_eq!(
            scheduler.try_admit().map(|_| ()),
            Err(PqProposerServiceError::StaleSlot {
                slot: Slot::new(0),
                highest_started: None,
            }),
        );
        assert_eq!(scheduler.admission.available_permits(), 1);
        clock.set_slot(4);

        let mut slot_four = match scheduler.try_admit().expect("first schedule") {
            PqProposalAdmission::Started { admitted, .. } => admitted,
            PqProposalAdmission::Coalesced(_) => panic!("first slot cannot coalesce"),
        };
        slot_four.mark_started();
        assert!(matches!(
            scheduler.try_admit().expect("same slot coalesces"),
            PqProposalAdmission::Coalesced(_)
        ));
        clock.set_slot(5);
        assert!(matches!(
            scheduler.try_admit(),
            Err(PqProposerServiceError::Capacity)
        ));
        slot_four.finish(Ok(PqProposalCompletion::NoLocalDuty { slot: Slot::new(4) }));
        let mut slot_five = match scheduler.try_admit().expect("next slot starts") {
            PqProposalAdmission::Started { admitted, .. } => admitted,
            PqProposalAdmission::Coalesced(_) => panic!("new slot cannot coalesce"),
        };
        slot_five.mark_started();
        clock.set_slot(3);
        assert_eq!(
            scheduler.try_admit().map(|_| ()),
            Err(PqProposerServiceError::StaleSlot {
                slot: Slot::new(3),
                highest_started: Some(Slot::new(5)),
            }),
        );
        slot_five.finish(Ok(PqProposalCompletion::NoLocalDuty { slot: Slot::new(5) }));
    }

    #[test]
    fn configured_nonzero_genesis_slot_is_never_admitted() {
        let clock = TestingSlotClock::new(
            Slot::new(8),
            Duration::from_secs(2_400),
            Duration::from_secs(300),
        );
        clock.set_slot(8);
        let scheduler = Arc::new(PqProposalScheduler::new(clock));

        assert_eq!(
            scheduler.try_admit().map(|_| ()),
            Err(PqProposerServiceError::StaleSlot {
                slot: Slot::new(8),
                highest_started: None,
            }),
        );
        assert_eq!(scheduler.admission.available_permits(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_notification_observes_released_admission_without_a_lost_wakeup() {
        let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
        clock.set_slot(4);
        let scheduler = Arc::new(PqProposalScheduler::new(clock.clone()));
        let mut admitted = match scheduler.try_admit().expect("slot starts") {
            PqProposalAdmission::Started { admitted, .. } => admitted,
            PqProposalAdmission::Coalesced(_) => panic!("first slot cannot coalesce"),
        };
        admitted.mark_started();

        let idle_scheduler = Arc::clone(&scheduler);
        let idle = tokio::spawn(async move { idle_scheduler.wait_until_idle().await });
        tokio::task::yield_now().await;
        admitted.finish(Ok(PqProposalCompletion::NoLocalDuty { slot: Slot::new(4) }));
        tokio::time::timeout(Duration::from_secs(2), idle)
            .await
            .expect("idle notification cannot be lost")
            .expect("idle waiter task");

        clock.set_slot(5);
        assert!(matches!(
            scheduler.try_admit(),
            Ok(PqProposalAdmission::Started { .. })
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completion_observer_can_immediately_admit_the_next_slot() {
        for _ in 0..32 {
            let clock =
                TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
            clock.set_slot(4);
            let scheduler = Arc::new(PqProposalScheduler::new(clock.clone()));
            let (mut admitted, receipt) = match scheduler.try_admit().expect("slot four starts") {
                PqProposalAdmission::Started { admitted, receipt } => (admitted, receipt),
                PqProposalAdmission::Coalesced(_) => panic!("first slot cannot coalesce"),
            };
            admitted.mark_started();
            let observer_scheduler = Arc::clone(&scheduler);
            let observer_clock = clock.clone();
            let observer = tokio::spawn(async move {
                receipt.completion().await.expect("slot four completion");
                observer_clock.set_slot(5);
                matches!(
                    observer_scheduler.try_admit(),
                    Ok(PqProposalAdmission::Started { .. })
                )
            });
            tokio::task::spawn_blocking(move || {
                admitted.finish(Ok(PqProposalCompletion::NoLocalDuty { slot: Slot::new(4) }));
            })
            .await
            .expect("finish task");
            assert!(
                observer.await.expect("completion observer"),
                "completion was visible before the admission permit was released",
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn duty_timeout_is_typed_and_releases_proposal_admission() {
        let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
        clock.set_current_time(Duration::from_millis(1_319_999));
        let scheduler = Arc::new(PqProposalScheduler::new(clock.clone()));
        let mut admitted = match scheduler.try_admit().expect("slot four admission") {
            PqProposalAdmission::Started { admitted, .. } => admitted,
            PqProposalAdmission::Coalesced(_) => panic!("first slot cannot coalesce"),
        };
        admitted.mark_started();
        let timing = PqProposalTiming::new(&clock, Slot::new(4)).expect("slot-four timing");
        let error = run_pq_prepare_response(
            &timing,
            &clock,
            |_| std::future::pending::<Result<PqCollectedResponse, PqStrictResponseError>>(),
            |_| async { Ok::<(), PqStrictResponseError>(()) },
        )
        .await
        .expect_err("stalled duty request expires at the preparation deadline");
        assert_eq!(
            error,
            PqProposerServiceError::PreparationExpired {
                deadline: Duration::from_secs(1_320),
            }
        );
        admitted.finish(Err(error));

        clock.set_slot(5);
        assert!(matches!(
            scheduler.try_admit(),
            Ok(PqProposalAdmission::Started { .. })
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn decode_overrun_retains_admission_until_blocking_work_completes() {
        let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
        clock.set_current_time(Duration::from_millis(1_319_990));
        let timing = PqProposalTiming::new(&clock, Slot::new(4)).expect("slot-four timing");
        let scheduler = Arc::new(PqProposalScheduler::new(clock.clone()));
        let (mut admitted, caller) = match scheduler.try_admit().expect("slot-four admission") {
            PqProposalAdmission::Started { admitted, receipt } => (admitted, receipt),
            PqProposalAdmission::Coalesced(_) => panic!("first slot cannot coalesce"),
        };
        let observer = match scheduler.try_admit().expect("same slot coalesces") {
            PqProposalAdmission::Coalesced(receipt) => receipt,
            PqProposalAdmission::Started { .. } => panic!("same slot must coalesce"),
        };
        drop(caller);
        admitted.mark_started();

        let runtime = task_executor::test_utils::TestRuntime::default();
        let executor = runtime.task_executor.clone();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let body = serde_json::to_vec(&DutiesResponse::<Vec<eth2::types::ProposerData>> {
            dependent_root: Hash256::repeat_byte(0x42),
            execution_optimistic: Some(false),
            data: vec![],
        })
        .expect("duties JSON");
        let response = PqCollectedResponse {
            status: reqwest::StatusCode::OK,
            headers: reqwest::header::HeaderMap::new(),
            length: body.len(),
            chunks: vec![bytes::Bytes::from(body)],
            coalesce_hook: Some(Box::new(move || {
                entered_tx.send(()).expect("decoder entered");
                release_rx.recv().expect("release decoder");
            })),
        };
        let operation_clock = clock.clone();
        let operation = tokio::spawn(async move {
            let result = run_pq_prepare_response(
                &timing,
                &operation_clock,
                |_| async { Ok::<_, PqStrictResponseError>(response) },
                |response| decode_collected_pq_duties_response(&executor, response),
            )
            .await
            .and_then(|decoded| {
                decoded
                    .map(|_| PqProposalCompletion::NoLocalDuty { slot: Slot::new(4) })
                    .map_err(|error| PqProposerServiceError::DutyRequest(error.into()))
            });
            admitted.finish(result);
        });

        entered_rx.await.expect("blocking decoder entered");
        assert_eq!(
            tokio::spawn(async { 23usize }).await.expect("heartbeat"),
            23
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        clock.advance_time(Duration::from_millis(20));
        assert_eq!(
            scheduler.admission.available_permits(),
            0,
            "caller drop and deadline expiry cannot free admission while decode still runs",
        );

        release_tx.send(()).expect("release blocking decoder");
        operation.await.expect("proposal operation");
        assert_eq!(
            observer.completion().await,
            Err(PqProposerServiceError::PreparationExpired {
                deadline: Duration::from_secs(1_320),
            }),
        );
        assert_eq!(scheduler.admission.available_permits(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_before_start_rolls_back_high_water_and_restores_capacity() {
        let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
        clock.set_slot(4);
        let scheduler = Arc::new(PqProposalScheduler::new(clock));
        let (admitted, receipt) = match scheduler.try_admit().expect("slot four admission") {
            PqProposalAdmission::Started { admitted, receipt } => (admitted, receipt),
            PqProposalAdmission::Coalesced(_) => panic!("first slot cannot coalesce"),
        };

        drop(admitted);

        assert_eq!(
            receipt.completion().await,
            Err(PqProposerServiceError::TaskUnavailable),
        );
        assert_eq!(scheduler.admission.available_permits(), 1);
        assert_eq!(
            scheduler
                .state
                .lock()
                .expect("scheduler state")
                .highest_started,
            None,
        );
        assert!(matches!(
            scheduler.try_admit(),
            Ok(PqProposalAdmission::Started { .. })
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panic_after_start_preserves_high_water_and_restores_capacity() {
        let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
        clock.set_slot(4);
        let scheduler = Arc::new(PqProposalScheduler::new(clock.clone()));
        let (mut admitted, receipt) = match scheduler.try_admit().expect("slot four admission") {
            PqProposalAdmission::Started { admitted, receipt } => (admitted, receipt),
            PqProposalAdmission::Coalesced(_) => panic!("first slot cannot coalesce"),
        };
        admitted.mark_started();
        let panicked = tokio::spawn(async move {
            let _admitted = admitted;
            panic!("deterministic proposal-task panic");
        })
        .await;
        assert!(panicked.expect_err("proposal task must panic").is_panic());

        assert_eq!(
            receipt.completion().await,
            Err(PqProposerServiceError::TaskUnavailable),
        );
        assert_eq!(scheduler.admission.available_permits(), 1);
        clock.set_slot(3);
        assert_eq!(
            scheduler.try_admit().map(|_| ()),
            Err(PqProposerServiceError::StaleSlot {
                slot: Slot::new(3),
                highest_started: Some(Slot::new(4)),
            }),
        );
        clock.set_slot(5);
        assert!(matches!(
            scheduler.try_admit(),
            Ok(PqProposalAdmission::Started { .. })
        ));
    }

    #[test]
    fn identity_and_slot_profile_are_validated_once_at_construction() {
        assert!(!validate_identity_set(&[]));
        assert!(!validate_identity_set(&[identity(1, 7), identity(1, 8)]));
        assert!(!validate_identity_set(&[identity(1, 7), identity(2, 7)]));
        let exact_capacity = (1..=16)
            .map(|byte| identity(byte, u64::from(byte)))
            .collect::<Vec<_>>();
        assert!(validate_identity_set(&exact_capacity));
        let above_capacity = (1..=17)
            .map(|byte| identity(byte, u64::from(byte)))
            .collect::<Vec<_>>();
        assert!(!validate_identity_set(&above_capacity));
        assert!(validate_slot_duration(Duration::from_secs(300)).is_ok());
        assert!(matches!(
            validate_slot_duration(Duration::from_secs(299)),
            Err(PqProposerServiceError::WrongSlotDuration { .. })
        ));
    }

    #[test]
    fn timing_policy_has_exact_phase_and_global_deadlines() {
        let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
        let timing = PqProposalTiming::new(&clock, Slot::new(3)).expect("slot timing");
        assert_eq!(timing.slot_start(), Duration::from_secs(900));
        assert_eq!(timing.global_deadline(), Duration::from_secs(1_185));
        assert_eq!(
            timing
                .remaining_prepare(Duration::from_secs(1_019))
                .expect("prepare at 119 seconds"),
            Duration::from_secs(1),
        );
        assert!(matches!(
            timing.remaining_prepare(Duration::from_secs(1_020)),
            Err(PqProposalTimingError::PhaseExpired {
                phase: PqProposalPhase::PrepareAndProduce,
                ..
            })
        ));
        let sign = timing
            .start_block_sign(Duration::from_secs(1_030))
            .expect("late block-sign start still gets its captured budget");
        assert_eq!(sign.deadline(), Duration::from_secs(1_150));
        assert_eq!(
            sign.remaining(Duration::from_secs(1_149))
                .expect("one second remains"),
            Duration::from_secs(1),
        );
        let publish = timing
            .start_publish(Duration::from_secs(1_140))
            .expect("publication phase start");
        assert_eq!(publish.deadline(), Duration::from_secs(1_185));
        assert!(matches!(
            publish.remaining(Duration::from_secs(1_185)),
            Err(PqProposalTimingError::GlobalExpired { .. })
        ));
    }

    #[test]
    fn late_phase_start_is_capped_by_the_global_deadline() {
        let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
        let timing = PqProposalTiming::new(&clock, Slot::new(3)).expect("slot timing");
        let sign = timing
            .start_block_sign(Duration::from_secs(1_180))
            .expect("late signing may use the remaining global budget");
        assert_eq!(sign.deadline(), Duration::from_secs(1_185));
        assert_eq!(
            sign.classify_non_cancellable_completion(Duration::from_secs(1_184)),
            PqNonCancellableCompletion::OnTime,
        );
        assert_eq!(
            sign.classify_non_cancellable_completion(Duration::from_secs(1_185)),
            PqNonCancellableCompletion::GlobalExpired,
        );
    }

    #[test]
    fn phase_budgets_begin_at_the_actual_early_start() {
        let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
        let timing = PqProposalTiming::new(&clock, Slot::new(3)).expect("slot timing");
        assert_eq!(
            timing
                .start_block_sign(Duration::from_secs(901))
                .expect("early signing start")
                .deadline(),
            Duration::from_secs(1_021),
        );
        assert_eq!(
            timing
                .start_publish(Duration::from_secs(902))
                .expect("early publication start")
                .deadline(),
            Duration::from_secs(947),
        );
    }

    #[test]
    fn dynamic_phase_deadline_overflow_fails_closed() {
        let timing = PqProposalTiming {
            slot_start: Duration::ZERO,
            prepare_deadline: Duration::from_secs(120),
            global_deadline: Duration::MAX,
        };
        assert_eq!(
            timing.start_block_sign(Duration::MAX - Duration::from_secs(1)),
            Err(PqProposalTimingError::Overflow),
        );
        assert_eq!(
            timing.start_publish(Duration::MAX - Duration::from_secs(1)),
            Err(PqProposalTimingError::Overflow),
        );
    }

    #[test]
    fn journal_signing_completion_is_classified_after_non_cancellable_await() {
        let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
        let timing = PqProposalTiming::new(&clock, Slot::new(0)).expect("slot timing");
        assert_eq!(
            timing.classify_non_cancellable_completion(
                PqNonCancellablePhase::Randao,
                Duration::from_secs(119),
            ),
            PqNonCancellableCompletion::OnTime,
        );
        let sign = timing
            .start_block_sign(Duration::from_secs(121))
            .expect("capture block-sign deadline at actual start");
        assert_eq!(sign.deadline(), Duration::from_secs(241));
        assert_eq!(
            sign.classify_non_cancellable_completion(Duration::from_secs(241)),
            PqNonCancellableCompletion::PhaseOverrun,
        );
        assert_eq!(
            sign.classify_non_cancellable_completion(Duration::from_secs(286)),
            PqNonCancellableCompletion::GlobalExpired,
        );
        assert!(
            !PqNonCancellableCompletion::PhaseOverrun.allows_next_phase(),
            "a completed but over-budget signature must not start later HTTP work",
        );
    }

    #[test]
    fn valid_electra_full_v3_response_is_retained_for_exact_block_signing() {
        let (duty, randao, graffiti, response, metadata) = valid_v3_response();

        let (validated, execution_payload_value) =
            validate_pq_v3_response(duty, randao, graffiti, response, metadata)
                .expect("exact Electra full response");

        assert_eq!(validated.block().slot(), Slot::new(4));
        assert_eq!(validated.block().proposer_index(), 3);
        assert_eq!(execution_payload_value, types::Uint256::from(17_u64));
    }

    #[test]
    fn public_completion_reports_only_final_published_identity() {
        let completion = PqProposalCompletion::Published {
            slot: Slot::new(4),
            block_root: Hash256::repeat_byte(0x44),
        };
        assert_eq!(
            completion,
            PqProposalCompletion::Published {
                slot: Slot::new(4),
                block_root: Hash256::repeat_byte(0x44),
            }
        );
    }

    #[test]
    fn v3_response_rejects_non_electra_metadata() {
        let (duty, randao, graffiti, response, mut metadata) = valid_v3_response();
        metadata.consensus_version = types::ForkName::Fulu;

        assert!(matches!(
            validate_pq_v3_response(duty, randao, graffiti, response, metadata),
            Err(PqProposerServiceError::InvalidProducedBlock(
                "consensus version is not Electra"
            ))
        ));
    }

    #[test]
    fn v3_metadata_requires_unblinded_zero_consensus_value() {
        let (duty, randao, graffiti, response, mut metadata) = valid_v3_response();
        metadata.execution_payload_blinded = true;
        assert!(matches!(
            validate_pq_v3_response(duty.clone(), randao.clone(), graffiti, response, metadata),
            Err(PqProposerServiceError::InvalidProducedBlock(
                "metadata marks the payload blinded"
            ))
        ));

        let (_, _, _, response, mut metadata) = valid_v3_response();
        metadata.consensus_block_value = types::Uint256::from(1_u64);
        assert!(matches!(
            validate_pq_v3_response(duty, randao, graffiti, response, metadata),
            Err(PqProposerServiceError::InvalidProducedBlock(
                "consensus block value is nonzero"
            ))
        ));
    }

    #[test]
    fn electra_v3_requires_block_contents_with_empty_blob_sidecars() {
        let (duty, randao, graffiti, response, metadata) = valid_v3_response();
        let eth2::types::ProduceBlockV3Response::Full(contents) = response else {
            panic!("fixture is full")
        };
        let (block, _) = contents.deconstruct();
        assert!(matches!(
            validate_pq_v3_response(
                duty.clone(),
                randao.clone(),
                graffiti,
                eth2::types::ProduceBlockV3Response::Full(eth2::types::FullBlockContents::Block(
                    block
                )),
                metadata,
            ),
            Err(PqProposerServiceError::InvalidProducedBlock(
                "Electra response is not BlockContents"
            ))
        ));

        let (_, _, _, response, metadata) = valid_v3_response();
        let eth2::types::ProduceBlockV3Response::Full(contents) = response else {
            panic!("fixture is full")
        };
        let (block, _) = contents.deconstruct();
        let nonempty_proofs =
            types::KzgProofs::<MinimalEthSpec>::try_from(vec![types::KzgProof::empty()])
                .expect("one proof is within the Electra bound");
        assert!(matches!(
            validate_pq_v3_response(
                duty,
                randao,
                graffiti,
                eth2::types::ProduceBlockV3Response::Full(eth2::types::FullBlockContents::new(
                    block,
                    Some((
                        nonempty_proofs,
                        types::BlobsList::<MinimalEthSpec>::default(),
                    )),
                )),
                metadata,
            ),
            Err(PqProposerServiceError::InvalidProducedBlock(
                "Electra blob proofs or blobs are nonempty"
            ))
        ));
    }

    #[test]
    fn produced_block_is_bound_to_exact_duty_randao_and_graffiti() {
        let mutations: Vec<Box<dyn FnOnce(&mut types::BeaconBlock<MinimalEthSpec>)>> = vec![
            Box::new(|block| *block.slot_mut() = Slot::new(5)),
            Box::new(|block| *block.proposer_index_mut() = 4),
            Box::new(|block| {
                let mut bytes = block.body().randao_reveal().serialize();
                let last = bytes.len().saturating_sub(1);
                bytes[last] ^= 1;
                *block.body_mut().randao_reveal_mut() =
                    consensus_signature::PqRawSignature::from_bytes(&bytes)
                        .expect("mutated canonical PQ signature envelope");
            }),
            Box::new(|block| *block.body_mut().graffiti_mut() = types::Graffiti([0x8c; 32])),
        ];
        let expected = [
            "block slot does not match duty",
            "block proposer does not match duty",
            "block RANDAO does not match request",
            "block graffiti does not match request",
        ];

        for (mutate, expected) in mutations.into_iter().zip(expected) {
            let (duty, randao, graffiti, response, metadata) = mutate_valid_v3_block(mutate);
            assert!(matches!(
                validate_pq_v3_response(duty, randao, graffiti, response, metadata),
                Err(PqProposerServiceError::InvalidProducedBlock(reason)) if reason == expected
            ));
        }
    }

    #[test]
    fn produced_block_rejects_every_unsupported_v1_body_family() {
        fn assert_invalid_profile(
            mutate: impl FnOnce(&mut types::BeaconBlock<MinimalEthSpec>),
            expected: &'static str,
        ) {
            let (duty, randao, graffiti, response, metadata) = mutate_valid_v3_block(mutate);
            assert!(matches!(
                validate_pq_v3_response(duty, randao, graffiti, response, metadata),
                Err(PqProposerServiceError::InvalidProducedBlock(reason)) if reason == expected
            ));
        }
        fn electra(
            block: &mut types::BeaconBlock<MinimalEthSpec>,
        ) -> &mut types::BeaconBlockElectra<MinimalEthSpec> {
            let types::BeaconBlock::Electra(electra) = block else {
                panic!("fixture block is Electra")
            };
            electra
        }

        assert_invalid_profile(
            |block| *block.state_root_mut() = Hash256::ZERO,
            "post-state root is zero",
        );
        assert_invalid_profile(
            |block| {
                let spec = types::ForkName::Fulu.make_genesis_spec(MinimalEthSpec::default_spec());
                *block = types::BeaconBlock::empty(&spec);
            },
            "block body is not Electra",
        );
        assert_invalid_profile(
            |block| {
                let body = &mut electra(block).body;
                let mut aggregation_bits = ssz_types::BitList::<
                    <MinimalEthSpec as EthSpec>::MaxValidatorsPerSlot,
                >::with_capacity(1)
                .expect("attestation bitlist");
                aggregation_bits.set(0, true).expect("attestation bit");
                let mut committee_bits = ssz_types::BitVector::<
                    <MinimalEthSpec as EthSpec>::MaxCommitteesPerSlot,
                >::default();
                committee_bits.set(0, true).expect("committee bit");
                body.attestations
                    .push(types::AttestationElectra {
                        aggregation_bits,
                        data: types::AttestationData::default(),
                        signature: consensus_signature::PqSameMessageEvidence::empty(),
                        committee_bits,
                    })
                    .expect("attestation capacity");
            },
            "attestations are nonempty",
        );
        assert_invalid_profile(
            |block| {
                electra(block)
                    .body
                    .sync_aggregate
                    .sync_committee_bits
                    .set(0, true)
                    .expect("sync bit");
            },
            "sync committee participants are nonempty",
        );
        assert_invalid_profile(
            |block| {
                electra(block).body.sync_aggregate.sync_committee_signature =
                    consensus_signature::PqSameMessageEvidence::from_bytes(
                        consensus_signature::PqRawSignature::empty().as_bytes(),
                    )
                    .expect("raw evidence envelope");
            },
            "sync committee evidence is nonempty",
        );
        assert_invalid_profile(
            |block| electra(block).body.eth1_data.deposit_count = 1,
            "eth1 deposit count is nonzero",
        );
        assert_invalid_profile(
            |block| {
                let signed_header = types::SignedBeaconBlockHeader {
                    message: types::BeaconBlockHeader::empty(),
                    signature: consensus_signature::PqRawSignature::empty(),
                };
                electra(block)
                    .body
                    .proposer_slashings
                    .push(types::ProposerSlashing {
                        signed_header_1: signed_header.clone(),
                        signed_header_2: signed_header,
                    })
                    .expect("proposer slashing capacity");
            },
            "proposer slashings are nonempty",
        );
        assert_invalid_profile(
            |block| {
                let indexed = types::IndexedAttestationElectra {
                    attesting_indices: ssz_types::VariableList::empty(),
                    data: types::AttestationData::default(),
                    signature: consensus_signature::PqSameMessageEvidence::empty(),
                };
                electra(block)
                    .body
                    .attester_slashings
                    .push(types::AttesterSlashingElectra {
                        attestation_1: indexed.clone(),
                        attestation_2: indexed,
                    })
                    .expect("attester slashing capacity");
            },
            "attester slashings are nonempty",
        );
        assert_invalid_profile(
            |block| {
                electra(block)
                    .body
                    .deposits
                    .push(decode_zero_fixed::<types::Deposit>())
                    .expect("deposit capacity");
            },
            "deposits are nonempty",
        );
        assert_invalid_profile(
            |block| {
                electra(block)
                    .body
                    .voluntary_exits
                    .push(types::SignedVoluntaryExit {
                        message: types::VoluntaryExit {
                            epoch: types::Epoch::new(0),
                            validator_index: 0,
                        },
                        signature: consensus_signature::PqRawSignature::empty(),
                    })
                    .expect("voluntary exit capacity");
            },
            "voluntary exits are nonempty",
        );
        assert_invalid_profile(
            |block| {
                electra(block)
                    .body
                    .bls_to_execution_changes
                    .push(types::SignedBlsToExecutionChange {
                        message: types::BlsToExecutionChange {
                            validator_index: 0,
                            from_bls_pubkey: decode_zero_fixed(),
                            to_execution_address: types::Address::ZERO,
                        },
                        signature: decode_zero_fixed(),
                    })
                    .expect("BLS change capacity");
            },
            "BLS-to-execution changes are nonempty",
        );
        assert_invalid_profile(
            |block| {
                electra(block)
                    .body
                    .execution_requests
                    .deposits
                    .push(decode_zero_fixed::<types::DepositRequest>())
                    .expect("deposit request capacity");
            },
            "deposit requests are nonempty",
        );
        assert_invalid_profile(
            |block| {
                electra(block)
                    .body
                    .execution_requests
                    .withdrawals
                    .push(types::WithdrawalRequest {
                        source_address: types::Address::ZERO,
                        validator_pubkey: ValidatorPublicKeyBytes::empty(),
                        amount: 0,
                    })
                    .expect("withdrawal request capacity");
            },
            "withdrawal requests are nonempty",
        );
        assert_invalid_profile(
            |block| {
                electra(block)
                    .body
                    .execution_requests
                    .consolidations
                    .push(types::ConsolidationRequest {
                        source_address: types::Address::ZERO,
                        source_pubkey: ValidatorPublicKeyBytes::empty(),
                        target_pubkey: ValidatorPublicKeyBytes::empty(),
                    })
                    .expect("consolidation request capacity");
            },
            "consolidation requests are nonempty",
        );
        assert_invalid_profile(
            |block| {
                electra(block)
                    .body
                    .blob_kzg_commitments
                    .push(decode_zero_fixed::<types::KzgCommitment>())
                    .expect("blob commitment capacity");
            },
            "blob KZG commitments are nonempty",
        );
    }

    #[test]
    fn json_fallback_is_allowlisted_only_for_completed_ssz_decode_failure() {
        let decode_error = types::BeaconBlock::<MinimalEthSpec>::from_ssz_bytes_for_fork(
            &[],
            types::ForkName::Electra,
        )
        .expect_err("empty bytes are not an Electra block");
        let invalid_ssz = eth2::Error::InvalidSsz(decode_error);
        let expected_url = reqwest::Url::parse("http://127.0.0.1:5052/eth/v3/validator/blocks/4")
            .expect("test URL");
        assert!(allows_production_json_fallback(&invalid_ssz, &expected_url));
        assert!(!allows_publication_json_fallback(
            &invalid_ssz,
            &expected_url
        ));
        assert!(!allows_production_json_fallback(
            &eth2::Error::StatusCode(reqwest::StatusCode::SERVICE_UNAVAILABLE),
            &expected_url,
        ));
        assert!(!allows_production_json_fallback(
            &eth2::Error::InvalidHeaders("missing consensus version".to_string()),
            &expected_url,
        ));
    }

    #[tokio::test]
    async fn publication_connect_fallback_requires_the_exact_intended_url() {
        let closed = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("closed test port");
        let closed_address = closed.local_addr().expect("closed test address");
        drop(closed);
        let direct_client = StrictBeaconNodeHttpClient::from_builder(
            eth2::SensitiveUrl::parse(&format!("http://{closed_address}/"))
                .expect("direct test URL"),
            eth2::Timeouts::set_all(Duration::from_secs(2)),
            reqwest::Client::builder(),
        )
        .expect("strict direct client");
        let intended = direct_client
            .post_beacon_blocks_v2_path(None)
            .expect("intended V2 URL");
        let direct_error = direct_client
            .post_beacon_blocks_v2_ssz_bytes(
                bytes::Bytes::from_static(b"signed"),
                types::ForkName::Electra,
                None,
            )
            .await
            .expect_err("closed intended port");
        assert!(allows_publication_json_fallback(&direct_error, &intended));

        let redirect_listener =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("redirect listener");
        let redirect_address = redirect_listener.local_addr().expect("redirect address");
        let redirect_target =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("redirect target port");
        let redirect_target_address = redirect_target.local_addr().expect("redirect target");
        drop(redirect_target);
        let redirect_server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = redirect_listener.accept().expect("redirect request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("redirect read timeout");
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).expect("read redirect request");
            let request = String::from_utf8_lossy(&request[..read]).to_ascii_lowercase();
            assert!(request.contains("x-pq-transport-config: retained"));
            write!(
                stream,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{redirect_target_address}/eth/v2/beacon/blocks\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .expect("write redirect");
        });
        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert(
            reqwest::header::HeaderName::from_static("x-pq-transport-config"),
            reqwest::header::HeaderValue::from_static("retained"),
        );
        let redirect_client = StrictBeaconNodeHttpClient::from_builder(
            eth2::SensitiveUrl::parse(&format!("http://{redirect_address}/"))
                .expect("redirect test URL"),
            eth2::Timeouts::set_all(Duration::from_secs(2)),
            reqwest::Client::builder().default_headers(default_headers),
        )
        .expect("strict redirect client");
        let redirect_intended = redirect_client
            .post_beacon_blocks_v2_path(None)
            .expect("redirect V2 URL");
        let redirect_error = redirect_client
            .post_beacon_blocks_v2_ssz_bytes(
                bytes::Bytes::from_static(b"signed"),
                types::ForkName::Electra,
                None,
            )
            .await
            .expect_err("redirect response is not followed");
        redirect_server.join().expect("redirect server");
        assert!(matches!(
            &redirect_error,
            eth2::Error::StatusCode(reqwest::StatusCode::TEMPORARY_REDIRECT)
        ));
        assert!(!allows_publication_json_fallback(
            &redirect_error,
            &redirect_intended
        ));
    }

    fn publication_response_server(
        status: u16,
        body_code: u16,
        trailing_fragments: usize,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<usize>) {
        let listener =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("publication response listener");
        let address = listener.local_addr().expect("publication response address");
        let task = std::thread::spawn(move || {
            use std::io::{Read, Write};

            let (mut stream, _) = listener.accept().expect("publication request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("request timeout");
            stream
                .set_write_timeout(Some(Duration::from_millis(100)))
                .expect("response write timeout");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).expect("read publication request");
            let prefix = format!(r#"{{"code":{body_code},"message":"mismatch"}}"#);
            let fragment = [b' '; 4096];
            let length = prefix
                .len()
                .checked_add(
                    trailing_fragments
                        .checked_mul(fragment.len())
                        .expect("fragment length"),
                )
                .expect("response length");
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n\r\n{prefix}"
            )
            .expect("write response headers");
            let mut written = 0;
            for _ in 0..trailing_fragments {
                if stream.write_all(&fragment).is_err() {
                    break;
                }
                written += 1;
                std::thread::sleep(Duration::from_millis(1));
            }
            written
        });
        (address, task)
    }

    #[tokio::test]
    async fn publication_uses_http_status_and_drops_untrusted_response_bodies() {
        let encoded = PqEncodedPublication {
            ssz: bytes::Bytes::from_static(b"signed-ssz"),
            json: bytes::Bytes::from_static(br#"{"signed":"json"}"#),
            fork: types::ForkName::Electra,
            block_root: Hash256::ZERO,
        };

        const OVERSIZED_FRAGMENT_COUNT: usize = 4096;
        let (bad_request, oversized) =
            publication_response_server(400, 503, OVERSIZED_FRAGMENT_COUNT);
        let client = StrictBeaconNodeHttpClient::from_builder(
            eth2::SensitiveUrl::parse(&format!("http://{bad_request}/")).expect("bad-request URL"),
            eth2::Timeouts::set_all(Duration::from_secs(2)),
            reqwest::Client::builder(),
        )
        .expect("strict bad-request client");
        assert_eq!(
            post_pq_publication_attempt(&client, PqPublicationBody::Ssz, &encoded)
                .await
                .expect("raw HTTP 400 response"),
            PqPublicationStatus::Terminal(400),
            "the HTTP status, never an untrusted JSON code, decides publication policy",
        );
        assert!(
            oversized.join().expect("oversized response server") < OVERSIZED_FRAGMENT_COUNT,
            "the proposer must drop, not retain or parse, an oversized fragmented error body",
        );

        let (unavailable, body) = publication_response_server(503, 400, 0);
        let client = StrictBeaconNodeHttpClient::from_builder(
            eth2::SensitiveUrl::parse(&format!("http://{unavailable}/")).expect("unavailable URL"),
            eth2::Timeouts::set_all(Duration::from_secs(2)),
            reqwest::Client::builder(),
        )
        .expect("strict unavailable client");
        assert_eq!(
            post_pq_publication_attempt(&client, PqPublicationBody::Json, &encoded)
                .await
                .expect("raw HTTP 503 response"),
            PqPublicationStatus::Retry,
            "HTTP 503 remains retryable even when the untrusted body claims 400",
        );
        assert_eq!(body.join().expect("unavailable response server"), 0);
    }

    #[test]
    fn publication_status_policy_requires_200_and_retries_only_allowlisted_statuses() {
        assert_eq!(
            classify_publication_status(200),
            PqPublicationStatus::Published
        );
        for status in [202, 408, 429, 503] {
            assert_eq!(
                classify_publication_status(status),
                PqPublicationStatus::Retry,
                "status {status} retains and retries the exact signed SSZ",
            );
        }
        for status in [400, 409, 413, 415] {
            assert_eq!(
                classify_publication_status(status),
                PqPublicationStatus::Terminal(status),
            );
        }
        for status in [201, 204] {
            assert_eq!(
                classify_publication_status(status),
                PqPublicationStatus::Protocol(status),
                "non-200 success is not final publication success",
            );
        }
    }

    #[test]
    fn retry_classification_distinguishes_start_failure_from_completed_receipt() {
        for error in [
            PqProposerServiceError::DutyRequest(PqBeaconFailure::Timeout),
            PqProposerServiceError::Randao(classify_store_operation_error(
                validator_store::Error::ExecutorError,
            )),
            PqProposerServiceError::BlockProduction(PqBeaconFailure::Connect),
            PqProposerServiceError::Publication(PqBeaconFailure::Timeout),
            PqProposerServiceError::PublicationRejected { status: 400 },
            PqProposerServiceError::PublicationProtocol { status: 204 },
            PqProposerServiceError::TaskUnavailable,
        ] {
            assert!(!error.is_same_slot_retryable_after_completion());
        }
        assert!(PqProposerServiceError::Capacity.is_start_retryable());
        assert!(PqProposerServiceError::ClockUnavailable.is_start_retryable());
        assert!(PqProposerServiceError::TaskUnavailable.is_start_retryable());
        assert!(!PqProposerServiceError::InvalidIdentitySet.is_start_retryable());
    }

    #[test]
    fn store_failures_preserve_typed_terminal_and_transient_classification() {
        let invalid = classify_store_operation_error(validator_store::Error::SpecificError(
            signing_method::Error::PqSigning(pq_signing::PqSigningError::InvalidSigningRequest),
        ));
        assert_eq!(invalid.kind(), PqStoreFailureKind::InvalidSigningRequest);
        assert!(!invalid.is_transient());
        assert!(std::error::Error::source(&invalid).is_some());

        let executor = classify_store_operation_error(validator_store::Error::ExecutorError);
        assert_eq!(executor.kind(), PqStoreFailureKind::ExecutorUnavailable);
        assert!(executor.is_transient());
        assert!(std::error::Error::source(&executor).is_none());

        for error in [
            signing_method::Error::ShuttingDown,
            signing_method::Error::TokioJoin("blocking signer join failed".to_owned()),
        ] {
            let executor =
                classify_store_operation_error(validator_store::Error::SpecificError(error));
            assert_eq!(executor.kind(), PqStoreFailureKind::ExecutorUnavailable);
            assert!(executor.is_transient());
            assert!(std::error::Error::source(&executor).is_some());
        }

        for error in [
            signing_method::Error::InconsistentDomains {
                message_type_domain: types::Domain::Randao,
                domain: types::Domain::BeaconProposer,
            },
            signing_method::Error::InconsistentEpochs {
                message_epoch: types::Epoch::new(1),
                context_epoch: types::Epoch::new(2),
            },
            signing_method::Error::PqSigningId(
                consensus_signature::SigningIdError::SlotOutOfRange(16),
            ),
        ] {
            let terminal =
                classify_store_operation_error(validator_store::Error::SpecificError(error));
            assert_eq!(terminal.kind(), PqStoreFailureKind::InvalidRequest);
            assert!(!terminal.is_transient());
            assert!(std::error::Error::source(&terminal).is_some());
        }
    }

    #[test]
    fn publication_encoding_consumes_the_already_captured_phase_budget() {
        let timing = PqProposalTiming {
            slot_start: Duration::ZERO,
            prepare_deadline: Duration::from_secs(120),
            global_deadline: Duration::from_secs(285),
        };
        let deadline = timing
            .start_publish(Duration::from_secs(100))
            .expect("publish phase starts before the global deadline");
        assert_eq!(deadline.deadline(), Duration::from_secs(145));
        assert_eq!(
            deadline
                .remaining(Duration::from_secs(146))
                .map_err(map_publish_timing_error),
            Err(PqProposerServiceError::PublicationExpired {
                deadline: Duration::from_secs(145),
            }),
            "blocking serialization may not restart the 45-second publication budget",
        );
    }

    #[test]
    fn block_signing_requires_the_exact_duty_slot_at_sign_start() {
        let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
        clock.set_slot(4);
        assert!(ensure_exact_duty_slot(&clock, Slot::new(4)).is_ok());
        clock.set_slot(5);
        assert_eq!(
            ensure_exact_duty_slot(&clock, Slot::new(4)),
            Err(PqProposerServiceError::StaleAfterDuty {
                requested: Slot::new(4),
                current: Some(Slot::new(5)),
            })
        );
    }
}
