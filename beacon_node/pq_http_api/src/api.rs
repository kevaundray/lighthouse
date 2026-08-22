use beacon_chain::{
    BeaconChain, BeaconChainTypes, PqBlockProductionError, PqBlockProductionLocalError,
    PqProposerDuties, PqProposerDutiesError,
};
use bytes::{Buf, Bytes};
use consensus_signature::{SerializedIndividualSignature, decode_individual_signature};
use context_deserialize::ContextDeserialize;
use eth2::{
    CONSENSUS_BLOCK_VALUE_HEADER, CONSENSUS_VERSION_HEADER, CONTENT_TYPE_HEADER,
    EXECUTION_PAYLOAD_BLINDED_HEADER, EXECUTION_PAYLOAD_VALUE_HEADER, ForkVersionedResponse,
    JSON_CONTENT_TYPE_HEADER, SSZ_CONTENT_TYPE_HEADER,
    types::{Accept, DutiesResponse, ProduceBlockV3Metadata, ProposerData, PublishBlockRequest},
};
use futures::{Stream, StreamExt};
use network::{
    PQ_BLOCK_PUBLICATION_BODY_CHUNK_CAPACITY, PQ_BLOCK_PUBLICATION_BODY_CHUNK_METADATA_BYTES,
    PqBlockBroadcastSender, PqBlockPublicationAdmission, PqBlockPublicationConfigurationError,
    PqBlockPublicationDisposition, PqBlockPublicationService, PqPublicationCapacity,
};
use serde::Deserialize;
use ssz::Encode;
#[cfg(feature = "pq-startup-testing")]
use std::sync::{
    Condvar, Mutex as StdMutex,
    atomic::{AtomicUsize, Ordering},
};
use std::{convert::Infallible, str::FromStr, sync::Arc, time::Duration};
use task_executor::TaskExecutor;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use types::{Epoch, ForkName, Graffiti, SignedBeaconBlock, Slot, Uint256};
use warp::{Filter, Rejection, Reply, filters::BoxedFilter, hyper::Body, reply::Response};

const PQ_HTTP_QUERY_CAPACITY_BYTES: usize = 4096;
const PQ_HTTP_RESPONSE_CAPACITY: usize = 2;
const PQ_HTTP_BODY_CHUNK_CAPACITY: usize = PQ_BLOCK_PUBLICATION_BODY_CHUNK_CAPACITY;
#[cfg(not(feature = "pq-startup-testing"))]
const PQ_HTTP_BODY_COLLECTION_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "pq-startup-testing")]
const PQ_HTTP_BODY_COLLECTION_TIMEOUT: Duration = Duration::from_secs(2);

/// Test barrier proving contextual decoding executes away from the async worker and that the
/// detached publication operation retains its body and admission after the HTTP caller leaves.
#[cfg(feature = "pq-startup-testing")]
#[derive(Debug)]
pub struct TestingPqHttpBlockingHook {
    entered: AtomicUsize,
    released: StdMutex<bool>,
    release: Condvar,
}

#[cfg(feature = "pq-startup-testing")]
impl TestingPqHttpBlockingHook {
    pub fn blocking() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicUsize::new(0),
            released: StdMutex::new(false),
            release: Condvar::new(),
        })
    }

    pub fn entered(&self) -> usize {
        self.entered.load(Ordering::SeqCst)
    }

    pub fn release(&self) {
        *self
            .released
            .lock()
            .expect("PQ HTTP blocking test hook lock") = true;
        self.release.notify_all();
    }

    fn run(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let mut released = self
            .released
            .lock()
            .expect("PQ HTTP blocking test hook lock");
        while !*released {
            released = self
                .release
                .wait(released)
                .expect("PQ HTTP blocking test hook wait");
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PqProduceBlockQuery {
    randao_reveal: SerializedIndividualSignature,
    graffiti: Option<Graffiti>,
}

#[derive(Clone, Copy)]
enum PqRequestMediaType {
    Json,
    Ssz,
}

#[derive(Debug)]
enum PqHttpRejection {
    BadRequest(&'static str),
    NotAcceptable,
    UnsupportedMediaType,
    PayloadTooLarge,
    RequestTimeout,
    Capacity,
    ServiceUnavailable,
}

impl warp::reject::Reject for PqHttpRejection {}

struct PqAdmittedPublishBody<T: BeaconChainTypes> {
    admission: PqBlockPublicationAdmission<T>,
    media_type: PqRequestMediaType,
    declared_body_bytes: usize,
    maximum_body_bytes: usize,
    task_executor: TaskExecutor,
    #[cfg(feature = "pq-startup-testing")]
    body_collections_started: Option<Arc<AtomicUsize>>,
    #[cfg(feature = "pq-startup-testing")]
    decode_hook: Option<Arc<TestingPqHttpBlockingHook>>,
}

#[derive(Debug, PartialEq, Eq)]
enum PqPublishDecodeError {
    PayloadTooLarge,
    Invalid,
    Resource,
}

#[derive(Debug, PartialEq, Eq)]
enum PqBodyCollectionError {
    PayloadTooLarge,
    DeclaredLengthExceeded,
    Stream,
    Timeout,
    Resource,
}

#[derive(Debug)]
struct PqCollectedBody<B> {
    chunks: Vec<B>,
    length: usize,
    #[cfg(feature = "pq-startup-testing")]
    coalesce_hook: Option<Arc<TestingPqHttpBlockingHook>>,
}

impl<B> PqCollectedBody<B> {
    #[cfg(test)]
    fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    #[cfg(feature = "pq-startup-testing")]
    fn testing_only_with_coalesce_hook(mut self, hook: Arc<TestingPqHttpBlockingHook>) -> Self {
        self.coalesce_hook = Some(hook);
        self
    }
}

enum PqPublishOperationResult {
    Disposition(PqBlockPublicationDisposition),
    Collection(PqBodyCollectionError),
    Decode(PqPublishDecodeError),
    ServiceUnavailable,
}

struct PqResponseBodyOwner {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
    _duties: Option<PqProposerDuties>,
}

impl PqResponseBodyOwner {
    const fn new(bytes: Vec<u8>, permit: OwnedSemaphorePermit) -> Self {
        Self {
            bytes,
            _permit: permit,
            _duties: None,
        }
    }

    const fn with_duties(
        bytes: Vec<u8>,
        permit: OwnedSemaphorePermit,
        duties: PqProposerDuties,
    ) -> Self {
        Self {
            bytes,
            _permit: permit,
            _duties: Some(duties),
        }
    }
}

impl AsRef<[u8]> for PqResponseBodyOwner {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// The isolated PQ-only HTTP facade. Runtime binding and the real network broadcast worker remain
/// owned by the later assembly task.
pub struct PqHttpApi<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
    publisher: Arc<PqBlockPublicationService<T>>,
    task_executor: TaskExecutor,
    response_admission: Arc<Semaphore>,
    #[cfg(feature = "pq-startup-testing")]
    body_collections_started: Option<Arc<AtomicUsize>>,
    #[cfg(feature = "pq-startup-testing")]
    decode_hook: Option<Arc<TestingPqHttpBlockingHook>>,
}

impl<T: BeaconChainTypes> PqHttpApi<T> {
    pub fn new(
        chain: Arc<BeaconChain<T>>,
        task_executor: TaskExecutor,
        broadcaster: PqBlockBroadcastSender<T::EthSpec>,
    ) -> Result<Self, PqBlockPublicationConfigurationError> {
        let publisher = Arc::new(PqBlockPublicationService::new(
            Arc::clone(&chain),
            task_executor.clone(),
            broadcaster,
        )?);
        Ok(Self {
            chain,
            publisher,
            task_executor,
            response_admission: Arc::new(Semaphore::new(PQ_HTTP_RESPONSE_CAPACITY)),
            #[cfg(feature = "pq-startup-testing")]
            body_collections_started: None,
            #[cfg(feature = "pq-startup-testing")]
            decode_hook: None,
        })
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_observe_body_collections(mut self, observer: Arc<AtomicUsize>) -> Self {
        self.body_collections_started = Some(observer);
        self
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_block_decode(mut self, hook: Arc<TestingPqHttpBlockingHook>) -> Self {
        self.decode_hook = Some(hook);
        self
    }

    /// Returns only the three routes supported by the first PQ proposer profile.
    pub fn routes(&self) -> BoxedFilter<(Response,)> {
        let chain = Arc::clone(&self.chain);
        let produce_task_executor = self.task_executor.clone();
        let response_admission = Arc::clone(&self.response_admission);
        let produce = warp::path!("eth" / "v3" / "validator" / "blocks" / String)
            .and(warp::path::end())
            .and(warp::get())
            .and_then(parse_slot)
            .and(bounded_raw_query())
            .and(warp::query::<PqProduceBlockQuery>())
            .and(warp::header::optional::<String>("accept"))
            .and(warp::any().map(move || Arc::clone(&chain)))
            .and(warp::any().map(move || produce_task_executor.clone()))
            .and_then(
                move |slot: Slot,
                      _query_guard: (),
                      query: PqProduceBlockQuery,
                      accept: Option<String>,
                      chain: Arc<BeaconChain<T>>,
                      task_executor: TaskExecutor| {
                    produce_block(
                        slot,
                        query,
                        accept,
                        chain,
                        task_executor,
                        Arc::clone(&response_admission),
                    )
                },
            );

        let publisher = Arc::clone(&self.publisher);
        let task_executor = self.task_executor.clone();
        #[cfg(feature = "pq-startup-testing")]
        let body_collections_started = self.body_collections_started.clone();
        #[cfg(feature = "pq-startup-testing")]
        let decode_hook = self.decode_hook.clone();
        let max_json_body_bytes = self.publisher.body_limits().max_json_bytes();
        let max_ssz_body_bytes = self.publisher.body_limits().max_ssz_bytes();
        let max_json_bytes = u64::try_from(max_json_body_bytes).unwrap_or(u64::MAX);
        let max_ssz_bytes = u64::try_from(max_ssz_body_bytes).unwrap_or(u64::MAX);
        let publish = warp::path!("eth" / "v2" / "beacon" / "blocks")
            .and(warp::path::end())
            .and(warp::post())
            .and(empty_raw_query())
            .and(warp::any().map(move || Arc::clone(&publisher)))
            .and_then(admit_publication::<T>)
            .and(warp::body::content_length_limit(max_json_bytes))
            .and(warp::header::<u64>("content-length"))
            .and(warp::header::optional::<String>("content-type"))
            .and(warp::header::optional::<String>("eth-consensus-version"))
            .and(warp::any().map(move || task_executor.clone()))
            .and_then(
                move |admission: PqBlockPublicationAdmission<T>,
                      content_length: u64,
                      content_type: Option<String>,
                      consensus_version: Option<String>,
                      task_executor: TaskExecutor| {
                    #[cfg(feature = "pq-startup-testing")]
                    let body_collections_started = body_collections_started.clone();
                    #[cfg(feature = "pq-startup-testing")]
                    let decode_hook = decode_hook.clone();
                    async move {
                        let media_type = validate_publish_headers(
                            content_length,
                            content_type.as_deref(),
                            consensus_version.as_deref(),
                            max_json_bytes,
                            max_ssz_bytes,
                        )?;
                        let maximum_body_bytes = match media_type {
                            PqRequestMediaType::Json => max_json_body_bytes,
                            PqRequestMediaType::Ssz => max_ssz_body_bytes,
                        };
                        let declared_body_bytes = usize::try_from(content_length)
                            .map_err(|_| warp::reject::custom(PqHttpRejection::PayloadTooLarge))?;
                        Ok::<_, Rejection>(PqAdmittedPublishBody {
                            admission,
                            media_type,
                            declared_body_bytes,
                            maximum_body_bytes,
                            task_executor,
                            #[cfg(feature = "pq-startup-testing")]
                            body_collections_started,
                            #[cfg(feature = "pq-startup-testing")]
                            decode_hook,
                        })
                    }
                },
            )
            .and(warp::body::stream())
            .and_then(|admitted, body| publish_block::<T, _, _>(admitted, body));

        let duty_chain = Arc::clone(&self.chain);
        let duty_task_executor = self.task_executor.clone();
        let duty_response_admission = Arc::clone(&self.response_admission);
        let duties = warp::path!("eth" / "v1" / "validator" / "duties" / "proposer" / String)
            .and(warp::path::end())
            .and(warp::get())
            .and_then(parse_epoch)
            .and(empty_raw_query())
            .and(warp::any().map(move || Arc::clone(&duty_chain)))
            .and(warp::any().map(move || duty_task_executor.clone()))
            .and_then(
                move |epoch: Epoch,
                      _query_guard: (),
                      chain: Arc<BeaconChain<T>>,
                      task_executor: TaskExecutor| {
                    proposer_duties(
                        epoch,
                        chain,
                        task_executor,
                        Arc::clone(&duty_response_admission),
                    )
                },
            );

        produce
            .or(publish)
            .unify()
            .or(duties)
            .unify()
            .recover(handle_rejection)
            .unify()
            .boxed()
    }
}

async fn parse_slot(raw: String) -> Result<Slot, Rejection> {
    raw.parse::<u64>().map(Slot::new).map_err(|_| {
        warp::reject::custom(PqHttpRejection::BadRequest(
            "slot must be an unsigned 64-bit integer",
        ))
    })
}

async fn parse_epoch(raw: String) -> Result<Epoch, Rejection> {
    raw.parse::<u64>().map(Epoch::new).map_err(|_| {
        warp::reject::custom(PqHttpRejection::BadRequest(
            "epoch must be an unsigned 64-bit integer",
        ))
    })
}

async fn proposer_duties<T: BeaconChainTypes>(
    epoch: Epoch,
    chain: Arc<BeaconChain<T>>,
    task_executor: TaskExecutor,
    response_admission: Arc<Semaphore>,
) -> Result<Response, Rejection> {
    let response_permit = response_admission
        .try_acquire_owned()
        .map_err(|_| warp::reject::custom(PqHttpRejection::Capacity))?;
    let duties = chain
        .pq_proposer_duties(epoch)
        .await
        .map_err(map_proposer_duties_error)?;
    let encode = task_executor
        .spawn_blocking_handle(
            move || encode_proposer_duties(duties, response_permit),
            "pq-http-encode-proposer-duties",
        )
        .ok_or_else(|| warp::reject::custom(PqHttpRejection::ServiceUnavailable))?;
    encode
        .await
        .map_err(|_| warp::reject::custom(PqHttpRejection::ServiceUnavailable))?
}

fn map_proposer_duties_error(error: PqProposerDutiesError) -> Rejection {
    match error {
        PqProposerDutiesError::Capacity => warp::reject::custom(PqHttpRejection::Capacity),
        PqProposerDutiesError::EpochOutsideWindow { .. } => warp::reject::custom(
            PqHttpRejection::BadRequest("proposer duty epoch is outside the current/next window"),
        ),
        PqProposerDutiesError::ClockUnavailable
        | PqProposerDutiesError::HeadOutsideWindow { .. }
        | PqProposerDutiesError::WrongFork(_)
        | PqProposerDutiesError::State(_)
        | PqProposerDutiesError::Transition(_)
        | PqProposerDutiesError::ValidatorIndexOverflow(_)
        | PqProposerDutiesError::SlotOverflow
        | PqProposerDutiesError::BlockingTask
        | PqProposerDutiesError::StaleHead { .. } => {
            warp::reject::custom(PqHttpRejection::ServiceUnavailable)
        }
    }
}

fn encode_proposer_duties(
    duties: PqProposerDuties,
    response_permit: OwnedSemaphorePermit,
) -> Result<Response, Rejection> {
    let response: DutiesResponse<Vec<ProposerData>> = DutiesResponse {
        dependent_root: duties.dependent_root(),
        execution_optimistic: Some(false),
        data: duties
            .entries()
            .iter()
            .map(|entry| ProposerData {
                pubkey: entry.pubkey(),
                validator_index: entry.validator_index(),
                slot: entry.slot(),
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&response)
        .map_err(|_| warp::reject::custom(PqHttpRejection::ServiceUnavailable))?;
    let body = Bytes::from_owner(PqResponseBodyOwner::with_duties(
        bytes,
        response_permit,
        duties,
    ));
    warp::http::Response::builder()
        .status(warp::http::StatusCode::OK)
        .header(CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE_HEADER)
        .header(CONSENSUS_VERSION_HEADER, "electra")
        .body(Body::from(body))
        .map_err(|_| warp::reject::custom(PqHttpRejection::ServiceUnavailable))
}

fn bounded_raw_query() -> impl Filter<Extract = ((),), Error = Rejection> + Clone {
    optional_raw_query().and_then(|raw_query: String| async move {
        if raw_query.len() > PQ_HTTP_QUERY_CAPACITY_BYTES {
            Err(warp::reject::custom(PqHttpRejection::BadRequest(
                "query exceeds the PQ HTTP limit",
            )))
        } else {
            Ok(())
        }
    })
}

fn empty_raw_query() -> impl Filter<Extract = ((),), Error = Rejection> + Clone {
    optional_raw_query().and_then(|raw_query: String| async move {
        if raw_query.is_empty() {
            Ok(())
        } else {
            Err(warp::reject::custom(PqHttpRejection::BadRequest(
                "publication query options are unsupported",
            )))
        }
    })
}

fn optional_raw_query() -> impl Filter<Extract = (String,), Error = Infallible> + Clone {
    warp::query::raw().or(warp::any().map(String::new)).unify()
}

async fn admit_publication<T: BeaconChainTypes>(
    _query_guard: (),
    publisher: Arc<PqBlockPublicationService<T>>,
) -> Result<PqBlockPublicationAdmission<T>, Rejection> {
    publisher.try_admit().map_err(|capacity| match capacity {
        PqPublicationCapacity::Admission
        | PqPublicationCapacity::Observation
        | PqPublicationCapacity::Broadcast => warp::reject::custom(PqHttpRejection::Capacity),
    })
}

fn validate_accept(accept: Option<&str>) -> Result<Accept, Rejection> {
    accept
        .map(Accept::from_str)
        .transpose()
        .map_err(|_| warp::reject::custom(PqHttpRejection::NotAcceptable))
        .map(|accept| accept.unwrap_or(Accept::Json))
}

fn validate_publish_headers(
    content_length: u64,
    content_type: Option<&str>,
    consensus_version: Option<&str>,
    max_json_bytes: u64,
    max_ssz_bytes: u64,
) -> Result<PqRequestMediaType, Rejection> {
    if consensus_version != Some("electra") {
        return Err(warp::reject::custom(PqHttpRejection::BadRequest(
            "Eth-Consensus-Version must be electra",
        )));
    }
    let parsed = content_type
        .ok_or_else(|| warp::reject::custom(PqHttpRejection::UnsupportedMediaType))
        .and_then(|content_type| {
            mediatype::MediaType::parse(content_type)
                .map_err(|_| warp::reject::custom(PqHttpRejection::UnsupportedMediaType))
        })?;
    let essence = parsed.essence();
    let media_type = if essence
        == mediatype::MediaType::new(mediatype::names::APPLICATION, mediatype::names::JSON)
    {
        PqRequestMediaType::Json
    } else if essence
        == mediatype::MediaType::new(
            mediatype::names::APPLICATION,
            mediatype::names::OCTET_STREAM,
        )
    {
        PqRequestMediaType::Ssz
    } else {
        return Err(warp::reject::custom(PqHttpRejection::UnsupportedMediaType));
    };
    let maximum = match media_type {
        PqRequestMediaType::Json => max_json_bytes,
        PqRequestMediaType::Ssz => max_ssz_bytes,
    };
    if content_length > maximum {
        return Err(warp::reject::custom(PqHttpRejection::PayloadTooLarge));
    }
    Ok(media_type)
}

async fn produce_block<T: BeaconChainTypes>(
    slot: Slot,
    query: PqProduceBlockQuery,
    accept: Option<String>,
    chain: Arc<BeaconChain<T>>,
    task_executor: TaskExecutor,
    response_admission: Arc<Semaphore>,
) -> Result<Response, Rejection> {
    let accept = validate_accept(accept.as_deref())?;
    let randao_reveal = decode_individual_signature(&query.randao_reveal).map_err(|_| {
        warp::reject::custom(PqHttpRejection::BadRequest(
            "randao_reveal is not a canonical PQ signature",
        ))
    })?;
    let response_permit = response_admission
        .try_acquire_owned()
        .map_err(|_| warp::reject::custom(PqHttpRejection::Capacity))?;
    let produced = match chain
        .produce_pq_block_v3(slot, randao_reveal, query.graffiti.unwrap_or_default())
        .await
    {
        Ok(produced) => produced,
        Err(error) => return Ok(production_error_response(error)),
    };
    let encode = task_executor
        .spawn_blocking_handle(
            move || encode_produced_block(produced, accept, response_permit),
            "pq-http-encode-produced-block",
        )
        .ok_or_else(|| warp::reject::custom(PqHttpRejection::ServiceUnavailable))?;
    encode
        .await
        .map_err(|_| warp::reject::custom(PqHttpRejection::ServiceUnavailable))?
}

fn encode_produced_block<E: types::EthSpec>(
    produced: beacon_chain::PqProducedBlockV3<E>,
    accept: Accept,
    response_permit: OwnedSemaphorePermit,
) -> Result<Response, Rejection> {
    let execution_payload_value = produced.execution_payload_value();
    encode_full_block_contents(
        produced.into_contents(),
        execution_payload_value,
        accept,
        response_permit,
    )
}

fn encode_full_block_contents<E: types::EthSpec>(
    contents: eth2::types::FullBlockContents<E>,
    execution_payload_value: Uint256,
    accept: Accept,
    response_permit: OwnedSemaphorePermit,
) -> Result<Response, Rejection> {
    let (body, content_type) = match accept {
        Accept::Ssz => (contents.as_ssz_bytes(), SSZ_CONTENT_TYPE_HEADER),
        Accept::Json | Accept::Any => (
            serde_json::to_vec(&ForkVersionedResponse {
                version: ForkName::Electra,
                metadata: ProduceBlockV3Metadata {
                    consensus_version: ForkName::Electra,
                    execution_payload_blinded: false,
                    execution_payload_value,
                    consensus_block_value: Uint256::ZERO,
                },
                data: contents,
            })
            .map_err(|_| warp::reject::custom(PqHttpRejection::ServiceUnavailable))?,
            JSON_CONTENT_TYPE_HEADER,
        ),
    };
    let body = Bytes::from_owner(PqResponseBodyOwner::new(body, response_permit));
    warp::http::Response::builder()
        .status(warp::http::StatusCode::OK)
        .header(CONTENT_TYPE_HEADER, content_type)
        .header(CONSENSUS_VERSION_HEADER, "electra")
        .header(EXECUTION_PAYLOAD_BLINDED_HEADER, "false")
        .header(
            EXECUTION_PAYLOAD_VALUE_HEADER,
            execution_payload_value.to_string(),
        )
        .header(CONSENSUS_BLOCK_VALUE_HEADER, "0")
        .body(Body::from(body))
        .map_err(|_| warp::reject::custom(PqHttpRejection::ServiceUnavailable))
}

async fn publish_block<T, S, B>(
    admitted: PqAdmittedPublishBody<T>,
    body: S,
) -> Result<Response, Rejection>
where
    T: BeaconChainTypes,
    S: Stream<Item = Result<B, warp::Error>> + Send + 'static,
    B: Buf + Send + 'static,
{
    let PqAdmittedPublishBody {
        admission,
        media_type,
        declared_body_bytes,
        maximum_body_bytes,
        task_executor,
        #[cfg(feature = "pq-startup-testing")]
        body_collections_started,
        #[cfg(feature = "pq-startup-testing")]
        decode_hook,
    } = admitted;
    let blocking_executor = task_executor.clone();
    let operation = task_executor
        .spawn_handle(
            async move {
                #[cfg(feature = "pq-startup-testing")]
                if let Some(observer) = body_collections_started {
                    observer.fetch_add(1, Ordering::SeqCst);
                }
                let body = match collect_bounded_body(
                    body,
                    declared_body_bytes,
                    maximum_body_bytes,
                    PQ_HTTP_BODY_COLLECTION_TIMEOUT,
                )
                .await
                {
                    Ok(body) => body,
                    Err(error) => return PqPublishOperationResult::Collection(error),
                };
                #[cfg(feature = "pq-startup-testing")]
                let body = if let Some(hook) = decode_hook {
                    body.testing_only_with_coalesce_hook(hook)
                } else {
                    body
                };
                let Some(decode) = blocking_executor.spawn_blocking_handle(
                    move || {
                        let body =
                            coalesce_collected_body(body, declared_body_bytes, maximum_body_bytes)?;
                        decode_full_electra_block::<T::EthSpec>(media_type, &body)
                    },
                    "pq-http-decode-published-block",
                ) else {
                    return PqPublishOperationResult::ServiceUnavailable;
                };
                let block = match decode.await {
                    Ok(Ok(block)) => block,
                    Ok(Err(error)) => return PqPublishOperationResult::Decode(error),
                    Err(_) => return PqPublishOperationResult::ServiceUnavailable,
                };
                PqPublishOperationResult::Disposition(admission.publish(block).await)
            },
            "pq-http-publish-block",
        )
        .ok_or_else(|| warp::reject::custom(PqHttpRejection::ServiceUnavailable))?;
    let result = operation
        .await
        .map_err(|_| warp::reject::custom(PqHttpRejection::ServiceUnavailable))?
        .ok_or_else(|| warp::reject::custom(PqHttpRejection::ServiceUnavailable))?;
    map_publish_operation_result(result)
}

fn map_publish_operation_result(result: PqPublishOperationResult) -> Result<Response, Rejection> {
    match result {
        PqPublishOperationResult::Disposition(disposition) => Ok(publication_response(disposition)),
        PqPublishOperationResult::Collection(error) => Err(match error {
            PqBodyCollectionError::PayloadTooLarge => {
                warp::reject::custom(PqHttpRejection::PayloadTooLarge)
            }
            PqBodyCollectionError::DeclaredLengthExceeded => warp::reject::custom(
                PqHttpRejection::BadRequest("request body exceeds declared Content-Length"),
            ),
            PqBodyCollectionError::Stream => {
                warp::reject::custom(PqHttpRejection::BadRequest("request body stream failed"))
            }
            PqBodyCollectionError::Timeout => warp::reject::custom(PqHttpRejection::RequestTimeout),
            PqBodyCollectionError::Resource => {
                warp::reject::custom(PqHttpRejection::ServiceUnavailable)
            }
        }),
        PqPublishOperationResult::Decode(error) => Err(match error {
            PqPublishDecodeError::PayloadTooLarge => {
                warp::reject::custom(PqHttpRejection::PayloadTooLarge)
            }
            PqPublishDecodeError::Invalid => warp::reject::custom(PqHttpRejection::BadRequest(
                "invalid full Electra block contents",
            )),
            PqPublishDecodeError::Resource => {
                warp::reject::custom(PqHttpRejection::ServiceUnavailable)
            }
        }),
        PqPublishOperationResult::ServiceUnavailable => {
            Err(warp::reject::custom(PqHttpRejection::ServiceUnavailable))
        }
    }
}

async fn collect_bounded_body<S, B>(
    body: S,
    declared_body_bytes: usize,
    maximum_body_bytes: usize,
    timeout: Duration,
) -> Result<PqCollectedBody<B>, PqBodyCollectionError>
where
    S: Stream<Item = Result<B, warp::Error>> + Send,
    B: Buf + Send,
{
    let collect = async move {
        if std::mem::size_of::<B>() > PQ_BLOCK_PUBLICATION_BODY_CHUNK_METADATA_BYTES {
            return Err(PqBodyCollectionError::Resource);
        }
        futures::pin_mut!(body);
        let mut chunks = Vec::new();
        let mut length = 0usize;
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|_| PqBodyCollectionError::Stream)?;
            let next_length = length
                .checked_add(chunk.remaining())
                .ok_or(PqBodyCollectionError::PayloadTooLarge)?;
            if next_length > maximum_body_bytes {
                return Err(PqBodyCollectionError::PayloadTooLarge);
            }
            if next_length > declared_body_bytes {
                return Err(PqBodyCollectionError::DeclaredLengthExceeded);
            }
            if chunks.len() == PQ_HTTP_BODY_CHUNK_CAPACITY {
                return Err(PqBodyCollectionError::Resource);
            }
            chunks
                .try_reserve(1)
                .map_err(|_| PqBodyCollectionError::Resource)?;
            chunks.push(chunk);
            length = next_length;
        }
        Ok(PqCollectedBody {
            chunks,
            length,
            #[cfg(feature = "pq-startup-testing")]
            coalesce_hook: None,
        })
    };
    tokio::time::timeout(timeout, collect)
        .await
        .map_err(|_| PqBodyCollectionError::Timeout)?
}

fn coalesce_collected_body<B: Buf>(
    collected: PqCollectedBody<B>,
    declared_body_bytes: usize,
    maximum_body_bytes: usize,
) -> Result<Vec<u8>, PqPublishDecodeError> {
    #[cfg(feature = "pq-startup-testing")]
    if let Some(hook) = &collected.coalesce_hook {
        hook.run();
    }
    validate_actual_body_length(collected.length, declared_body_bytes, maximum_body_bytes)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(collected.length)
        .map_err(|_| PqPublishDecodeError::Resource)?;
    for mut chunk in collected.chunks {
        while chunk.has_remaining() {
            let part = chunk.chunk();
            if part.is_empty()
                || bytes
                    .len()
                    .checked_add(part.len())
                    .is_none_or(|next| next > collected.length)
            {
                return Err(PqPublishDecodeError::Invalid);
            }
            bytes.extend_from_slice(part);
            chunk.advance(part.len());
        }
    }
    validate_actual_body_length(bytes.len(), declared_body_bytes, maximum_body_bytes)?;
    Ok(bytes)
}

fn decode_full_electra_block<E: types::EthSpec>(
    media_type: PqRequestMediaType,
    body: &[u8],
) -> Result<Arc<SignedBeaconBlock<E>>, PqPublishDecodeError> {
    let request = match media_type {
        PqRequestMediaType::Json => {
            let mut deserializer = serde_json::Deserializer::from_slice(body);
            let request =
                PublishBlockRequest::<E>::context_deserialize(&mut deserializer, ForkName::Electra)
                    .map_err(|_| PqPublishDecodeError::Invalid)?;
            deserializer
                .end()
                .map_err(|_| PqPublishDecodeError::Invalid)?;
            request
        }
        PqRequestMediaType::Ssz => {
            PublishBlockRequest::<E>::from_ssz_bytes(body, ForkName::Electra)
                .map_err(|_| PqPublishDecodeError::Invalid)?
        }
    };
    let (block, sidecars) = request.deconstruct();
    let Some((proofs, blobs)) = sidecars else {
        return Err(PqPublishDecodeError::Invalid);
    };
    if !proofs.is_empty() || !blobs.is_empty() || block.fork_name_unchecked() != ForkName::Electra {
        return Err(PqPublishDecodeError::Invalid);
    }
    Ok(block)
}

fn validate_actual_body_length(
    actual: usize,
    declared: usize,
    maximum: usize,
) -> Result<(), PqPublishDecodeError> {
    if actual > maximum {
        Err(PqPublishDecodeError::PayloadTooLarge)
    } else if actual != declared {
        Err(PqPublishDecodeError::Invalid)
    } else {
        Ok(())
    }
}

fn publication_response(disposition: PqBlockPublicationDisposition) -> Response {
    match disposition {
        PqBlockPublicationDisposition::Published(_) | PqBlockPublicationDisposition::Committed => {
            warp::reply::with_status("published", warp::http::StatusCode::OK).into_response()
        }
        PqBlockPublicationDisposition::Pending => {
            warp::reply::with_status("pending", warp::http::StatusCode::ACCEPTED).into_response()
        }
        PqBlockPublicationDisposition::Terminal(_)
        | PqBlockPublicationDisposition::Equivocation { .. } => {
            error_response(warp::http::StatusCode::CONFLICT, "publication conflict")
        }
        PqBlockPublicationDisposition::Capacity(_) => error_response(
            warp::http::StatusCode::TOO_MANY_REQUESTS,
            "publication capacity is exhausted",
        ),
        PqBlockPublicationDisposition::Invalid(_) => {
            error_response(warp::http::StatusCode::BAD_REQUEST, "invalid block")
        }
        PqBlockPublicationDisposition::Local(_) => error_response(
            warp::http::StatusCode::SERVICE_UNAVAILABLE,
            "publication unavailable",
        ),
    }
}

fn production_error_response(error: PqBlockProductionError) -> Response {
    let (status, message) = match error {
        PqBlockProductionError::Invalid(_) => {
            (warp::http::StatusCode::BAD_REQUEST, "invalid RANDAO reveal")
        }
        PqBlockProductionError::InitialFutureSlot { .. } => (
            warp::http::StatusCode::SERVICE_UNAVAILABLE,
            "proposal slot is not yet current",
        ),
        PqBlockProductionError::InitialPastSlot { .. }
        | PqBlockProductionError::AtOrBehindHead { .. }
        | PqBlockProductionError::ExpiredAfterWork { .. }
        | PqBlockProductionError::StaleHead { .. } => (
            warp::http::StatusCode::CONFLICT,
            "proposal slot or parent is stale",
        ),
        PqBlockProductionError::AttestationSelectionInvariant => (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            "block-attestation selection invariant failed",
        ),
        PqBlockProductionError::Local(PqBlockProductionLocalError::IngressCapacity) => (
            warp::http::StatusCode::TOO_MANY_REQUESTS,
            "block-production capacity is exhausted",
        ),
        PqBlockProductionError::Local(
            PqBlockProductionLocalError::ClockUnavailable
            | PqBlockProductionLocalError::StateAdvanceTooLarge { .. }
            | PqBlockProductionLocalError::BlockingTask(_)
            | PqBlockProductionLocalError::AsyncTask(_)
            | PqBlockProductionLocalError::Arithmetic(_)
            | PqBlockProductionLocalError::State(_)
            | PqBlockProductionLocalError::BlockProcessing(_)
            | PqBlockProductionLocalError::Consensus(_)
            | PqBlockProductionLocalError::LocalBlock(_)
            | PqBlockProductionLocalError::Transition(_)
            | PqBlockProductionLocalError::Execution(_)
            | PqBlockProductionLocalError::OperationalEvent(_)
            | PqBlockProductionLocalError::AttestationSelection(_)
            | PqBlockProductionLocalError::Invariant(_),
        ) => (
            warp::http::StatusCode::SERVICE_UNAVAILABLE,
            "block production is unavailable",
        ),
    };
    error_response(status, message)
}

fn error_response(status: warp::http::StatusCode, message: &'static str) -> Response {
    warp::reply::with_status(
        warp::reply::json(&eth2::types::ErrorMessage {
            code: status.as_u16(),
            message: message.to_owned(),
            stacktraces: Vec::new(),
        }),
        status,
    )
    .into_response()
}

async fn handle_rejection(rejection: Rejection) -> Result<Response, Infallible> {
    let (status, message) = if let Some(error) = rejection.find::<PqHttpRejection>() {
        match error {
            PqHttpRejection::BadRequest(message) => (warp::http::StatusCode::BAD_REQUEST, *message),
            PqHttpRejection::NotAcceptable => (
                warp::http::StatusCode::NOT_ACCEPTABLE,
                "requested response media type is unsupported",
            ),
            PqHttpRejection::UnsupportedMediaType => (
                warp::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "request media type is unsupported",
            ),
            PqHttpRejection::PayloadTooLarge => (
                warp::http::StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds the PQ HTTP limit",
            ),
            PqHttpRejection::RequestTimeout => (
                warp::http::StatusCode::REQUEST_TIMEOUT,
                "request body timed out",
            ),
            PqHttpRejection::Capacity => (
                warp::http::StatusCode::TOO_MANY_REQUESTS,
                "PQ HTTP admission capacity is exhausted",
            ),
            PqHttpRejection::ServiceUnavailable => (
                warp::http::StatusCode::SERVICE_UNAVAILABLE,
                "PQ HTTP task service is unavailable",
            ),
        }
    } else if rejection.find::<warp::reject::PayloadTooLarge>().is_some() {
        (
            warp::http::StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the PQ HTTP limit",
        )
    } else if rejection.find::<warp::reject::LengthRequired>().is_some() {
        (
            warp::http::StatusCode::LENGTH_REQUIRED,
            "Content-Length is required",
        )
    } else if rejection.find::<warp::reject::InvalidQuery>().is_some()
        || rejection.find::<warp::reject::MissingHeader>().is_some()
        || rejection.find::<warp::reject::InvalidHeader>().is_some()
    {
        (
            warp::http::StatusCode::BAD_REQUEST,
            "request parameters are invalid",
        )
    } else if rejection.find::<warp::reject::MethodNotAllowed>().is_some() {
        (
            warp::http::StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
        )
    } else if rejection.is_not_found() {
        (warp::http::StatusCode::NOT_FOUND, "not found")
    } else {
        (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            "unhandled PQ HTTP rejection",
        )
    };
    Ok(error_response(status, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use network::{
        PqBlockPublicationLocalError, PqBlockPublicationTerminal, PqPublicationCapacity,
    };
    use tokio::sync::Semaphore;
    use types::EthSpec;

    #[tokio::test]
    async fn raw_query_cap_is_awaited_at_exact_capacity_and_cap_plus_one() {
        let filter = bounded_raw_query()
            .map(|_guard| warp::reply::reply().into_response())
            .recover(handle_rejection)
            .unify();
        let at_cap = format!("/?{}", "a".repeat(PQ_HTTP_QUERY_CAPACITY_BYTES));
        let over_cap = format!("/?{}", "a".repeat(PQ_HTTP_QUERY_CAPACITY_BYTES + 1));
        assert_eq!(
            warp::test::request()
                .path(&at_cap)
                .reply(&filter)
                .await
                .status(),
            200
        );
        assert_eq!(
            warp::test::request()
                .path(&over_cap)
                .reply(&filter)
                .await
                .status(),
            400
        );
    }

    #[tokio::test]
    async fn warp_length_rejections_keep_411_and_413() {
        let filter = warp::post()
            .and(warp::body::content_length_limit(4))
            .map(|| warp::reply::reply().into_response())
            .recover(handle_rejection)
            .unify();
        assert_eq!(
            warp::test::request()
                .method("POST")
                .reply(&filter)
                .await
                .status(),
            411
        );
        assert_eq!(
            warp::test::request()
                .method("POST")
                .header("content-length", "5")
                .reply(&filter)
                .await
                .status(),
            413
        );
    }

    #[tokio::test]
    async fn response_bytes_hold_exact_capacity_and_clones_until_final_drop() {
        let capacity = Arc::new(Semaphore::new(PQ_HTTP_RESPONSE_CAPACITY));
        let mut retained = Vec::new();
        for _ in 0..PQ_HTTP_RESPONSE_CAPACITY {
            let permit = Arc::clone(&capacity)
                .try_acquire_owned()
                .expect("response admission up to the exact cap");
            retained.push(Bytes::from_owner(PqResponseBodyOwner::new(
                vec![1, 2, 3],
                permit,
            )));
        }
        assert_eq!(capacity.available_permits(), 0);
        assert!(Arc::clone(&capacity).try_acquire_owned().is_err());
        let clone = retained[0].clone();
        retained.remove(0);
        assert_eq!(capacity.available_permits(), 0);
        drop(clone);
        assert_eq!(capacity.available_permits(), 1);
        drop(retained);
        assert_eq!(capacity.available_permits(), PQ_HTTP_RESPONSE_CAPACITY);
    }

    #[test]
    fn publication_dispositions_have_exhaustive_http_statuses() {
        let cases = [
            (PqBlockPublicationDisposition::Committed, 200),
            (PqBlockPublicationDisposition::Pending, 202),
            (
                PqBlockPublicationDisposition::Terminal(PqBlockPublicationTerminal::Rejected),
                409,
            ),
            (
                PqBlockPublicationDisposition::Equivocation {
                    previous: types::Hash256::repeat_byte(0x11),
                },
                409,
            ),
            (
                PqBlockPublicationDisposition::Capacity(PqPublicationCapacity::Admission),
                429,
            ),
            (
                PqBlockPublicationDisposition::Capacity(PqPublicationCapacity::Observation),
                429,
            ),
            (
                PqBlockPublicationDisposition::Capacity(PqPublicationCapacity::Broadcast),
                429,
            ),
            (
                PqBlockPublicationDisposition::Local(PqBlockPublicationLocalError::TaskUnavailable),
                503,
            ),
        ];
        for (disposition, expected) in cases {
            assert_eq!(publication_response(disposition).status(), expected);
        }
    }

    #[test]
    fn blocking_decode_rechecks_actual_body_length() {
        assert!(validate_actual_body_length(4, 4, 4).is_ok());
        assert!(matches!(
            validate_actual_body_length(5, 5, 4),
            Err(PqPublishDecodeError::PayloadTooLarge)
        ));
        assert!(matches!(
            validate_actual_body_length(3, 4, 4),
            Err(PqPublishDecodeError::Invalid)
        ));
        assert!(matches!(
            validate_actual_body_length(4, 3, 4),
            Err(PqPublishDecodeError::Invalid)
        ));
    }

    #[test]
    fn retained_body_bound_accounts_for_raw_chunks_and_blocking_decode_copy() {
        type E = types::MinimalEthSpec;
        let spec = E::default_spec();
        let limits = network::PqPublicationBodyLimits::try_from_spec::<E>(&spec)
            .expect("minimal body limits");
        let retained_per_admission = limits
            .max_json_bytes()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(
                    network::PQ_BLOCK_PUBLICATION_BODY_CHUNK_CAPACITY
                        * network::PQ_BLOCK_PUBLICATION_BODY_CHUNK_METADATA_BYTES,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(network::PQ_BLOCK_PUBLICATION_RETAINED_BODY_FIXED_BYTES)
            })
            .expect("test body-limit arithmetic");
        assert_eq!(
            limits.max_retained_body_bytes(),
            retained_per_admission * network::PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY,
        );
        assert!(
            limits.max_retained_body_bytes()
                > limits.max_json_bytes() * network::PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY,
            "the bound must include simultaneous raw chunks and contiguous decode copies",
        );
    }

    #[test]
    fn publish_media_type_uses_case_insensitive_essence_and_valid_parameters() {
        assert!(matches!(
            validate_publish_headers(
                2,
                Some("Application/JSON; charset=UTF-8"),
                Some("electra"),
                4,
                4,
            ),
            Ok(PqRequestMediaType::Json)
        ));
        assert!(matches!(
            validate_publish_headers(
                2,
                Some("APPLICATION/OCTET-STREAM; x-profile=pq"),
                Some("electra"),
                4,
                4,
            ),
            Ok(PqRequestMediaType::Ssz)
        ));
        for content_type in [
            "application/json; charset",
            "application/json garbage",
            "text/plain; charset=UTF-8",
        ] {
            assert!(
                validate_publish_headers(2, Some(content_type), Some("electra"), 4, 4,).is_err(),
                "{content_type} must be rejected",
            );
        }
    }

    #[test]
    fn contextual_json_decode_rejects_trailing_bytes() {
        let spec = ForkName::Electra.make_genesis_spec(types::MinimalEthSpec::default_spec());
        let block: Arc<SignedBeaconBlock<types::MinimalEthSpec>> =
            Arc::new(SignedBeaconBlock::from_block(
                types::BeaconBlock::empty(&spec),
                consensus_signature::IndividualSignature::empty(),
            ));
        let request =
            PublishBlockRequest::new(block, Some((Default::default(), Default::default())));
        let mut body = serde_json::to_vec(&request).expect("full Electra block contents JSON");
        body.extend_from_slice(b" {}");

        assert!(matches!(
            decode_full_electra_block::<types::MinimalEthSpec>(PqRequestMediaType::Json, &body),
            Err(PqPublishDecodeError::Invalid)
        ));
    }

    #[test]
    fn production_errors_have_exhaustive_retry_aware_http_statuses() {
        let cases = [
            (
                PqBlockProductionError::InitialFutureSlot {
                    current: Slot::new(1),
                    requested: Slot::new(2),
                },
                503,
            ),
            (
                PqBlockProductionError::InitialPastSlot {
                    current: Slot::new(2),
                    requested: Slot::new(1),
                },
                409,
            ),
            (
                PqBlockProductionError::AtOrBehindHead {
                    head: Slot::new(1),
                    requested: Slot::new(1),
                },
                409,
            ),
            (
                PqBlockProductionError::ExpiredAfterWork {
                    current: Slot::new(2),
                    requested: Slot::new(1),
                },
                409,
            ),
            (
                PqBlockProductionError::StaleHead {
                    expected_parent: types::Hash256::repeat_byte(0x11),
                    actual_head: types::Hash256::repeat_byte(0x22),
                },
                409,
            ),
            (
                PqBlockProductionError::Local(PqBlockProductionLocalError::IngressCapacity),
                429,
            ),
            (
                PqBlockProductionError::Local(PqBlockProductionLocalError::ClockUnavailable),
                503,
            ),
            (
                PqBlockProductionError::Local(PqBlockProductionLocalError::StateAdvanceTooLarge {
                    supplied: 9,
                    maximum: 8,
                }),
                503,
            ),
            (
                PqBlockProductionError::Local(PqBlockProductionLocalError::BlockingTask("test")),
                503,
            ),
            (
                PqBlockProductionError::Local(PqBlockProductionLocalError::AsyncTask("test")),
                503,
            ),
            (
                PqBlockProductionError::Local(PqBlockProductionLocalError::Invariant("test")),
                503,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(production_error_response(error).status(), expected);
        }
    }

    #[tokio::test]
    async fn full_v3_ssz_response_has_exact_headers_and_round_trips() {
        let spec = ForkName::Electra.make_genesis_spec(types::MinimalEthSpec::default_spec());
        let contents: eth2::types::FullBlockContents<types::MinimalEthSpec> =
            eth2::types::FullBlockContents::new(
                types::BeaconBlock::empty(&spec),
                Some((Default::default(), Default::default())),
            );
        let capacity = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&capacity)
            .try_acquire_owned()
            .expect("response admission");
        let response = encode_full_block_contents(contents, Uint256::from(17), Accept::Ssz, permit)
            .expect("SSZ response");

        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()[CONTENT_TYPE_HEADER],
            SSZ_CONTENT_TYPE_HEADER
        );
        assert_eq!(response.headers()[CONSENSUS_VERSION_HEADER], "electra");
        assert_eq!(
            response.headers()[EXECUTION_PAYLOAD_BLINDED_HEADER],
            "false"
        );
        assert_eq!(response.headers()[EXECUTION_PAYLOAD_VALUE_HEADER], "17");
        assert_eq!(response.headers()[CONSENSUS_BLOCK_VALUE_HEADER], "0");
        let body = warp::hyper::body::to_bytes(response.into_body())
            .await
            .expect("SSZ body");
        assert!(
            eth2::types::FullBlockContents::<types::MinimalEthSpec>::from_ssz_bytes_for_fork(
                &body,
                ForkName::Electra,
            )
            .is_ok()
        );
        assert_eq!(capacity.available_permits(), 0);
        drop(body);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn every_non_success_application_response_is_standard_eth2_error_json() {
        async fn assert_error(response: Response, expected_status: u16) {
            assert_eq!(response.status(), expected_status);
            let body = warp::hyper::body::to_bytes(response.into_body())
                .await
                .expect("error body");
            let error: eth2::types::ErrorMessage =
                serde_json::from_slice(&body).expect("standard eth2 error JSON");
            assert_eq!(error.code, expected_status);
            assert!(!error.message.is_empty());
            assert!(error.stacktraces.is_empty());
        }

        assert_error(
            handle_rejection(warp::reject::custom(PqHttpRejection::BadRequest(
                "invalid request",
            )))
            .await
            .expect("recovered rejection"),
            400,
        )
        .await;
        assert_error(
            production_error_response(PqBlockProductionError::InitialFutureSlot {
                current: Slot::new(1),
                requested: Slot::new(2),
            }),
            503,
        )
        .await;
        assert_error(
            publication_response(PqBlockPublicationDisposition::Terminal(
                PqBlockPublicationTerminal::Rejected,
            )),
            409,
        )
        .await;
        assert_error(
            publication_response(PqBlockPublicationDisposition::Local(
                PqBlockPublicationLocalError::TaskUnavailable,
            )),
            503,
        )
        .await;
    }

    #[test]
    fn publication_decode_requires_full_electra_and_empty_sidecars() {
        type E = types::MinimalEthSpec;
        let spec = ForkName::Electra.make_genesis_spec(E::default_spec());
        let block: Arc<SignedBeaconBlock<E>> = Arc::new(SignedBeaconBlock::from_block(
            types::BeaconBlock::empty(&spec),
            consensus_signature::IndividualSignature::empty(),
        ));
        let full = PublishBlockRequest::new(
            Arc::clone(&block),
            Some((Default::default(), Default::default())),
        );
        let full_json = serde_json::to_vec(&full).expect("full JSON");
        assert!(decode_full_electra_block::<E>(PqRequestMediaType::Json, &full_json).is_ok());
        assert!(
            decode_full_electra_block::<E>(PqRequestMediaType::Ssz, &full.as_ssz_bytes()).is_ok()
        );

        let block_only = PublishBlockRequest::new(Arc::clone(&block), None);
        assert!(matches!(
            decode_full_electra_block::<E>(
                PqRequestMediaType::Json,
                &serde_json::to_vec(&block_only).expect("block-only JSON"),
            ),
            Err(PqPublishDecodeError::Invalid)
        ));
        assert!(matches!(
            decode_full_electra_block::<E>(PqRequestMediaType::Ssz, &block_only.as_ssz_bytes()),
            Err(PqPublishDecodeError::Invalid)
        ));

        let mut proofs: types::KzgProofs<E> = Default::default();
        proofs
            .push(types::KzgProof::empty())
            .expect("proof capacity");
        let with_proof =
            PublishBlockRequest::new(Arc::clone(&block), Some((proofs, Default::default())));
        assert!(matches!(
            decode_full_electra_block::<E>(
                PqRequestMediaType::Json,
                &serde_json::to_vec(&with_proof).expect("proof JSON"),
            ),
            Err(PqPublishDecodeError::Invalid)
        ));

        let mut blobs: types::BlobsList<E> = Default::default();
        blobs
            .push(types::Blob::<E>::default())
            .expect("blob capacity");
        let with_blob = PublishBlockRequest::new(block, Some((Default::default(), blobs)));
        assert!(matches!(
            decode_full_electra_block::<E>(
                PqRequestMediaType::Json,
                &serde_json::to_vec(&with_blob).expect("blob JSON"),
            ),
            Err(PqPublishDecodeError::Invalid)
        ));
    }

    #[tokio::test]
    async fn streamed_body_collection_enforces_actual_cap_and_timeout() {
        let exact = futures::stream::iter([
            Ok::<_, warp::Error>(Bytes::from_static(b"ab")),
            Ok(Bytes::from_static(b"cd")),
        ]);
        assert_eq!(
            coalesce_collected_body(
                collect_bounded_body(exact, 4, 4, std::time::Duration::from_secs(1))
                    .await
                    .expect("exact raw chunks"),
                4,
                4,
            )
            .expect("exact blocking coalesce"),
            b"abcd",
        );

        let over_declared = futures::stream::iter([
            Ok::<_, warp::Error>(Bytes::from_static(b"ab")),
            Ok(Bytes::from_static(b"cde")),
        ]);
        assert!(matches!(
            collect_bounded_body(over_declared, 4, 8, std::time::Duration::from_secs(1),)
                .await
                .expect_err("declared length must be enforced while streaming"),
            PqBodyCollectionError::DeclaredLengthExceeded
        ));

        let over_maximum = futures::stream::iter([
            Ok::<_, warp::Error>(Bytes::from_static(b"ab")),
            Ok(Bytes::from_static(b"cde")),
        ]);
        assert!(matches!(
            collect_bounded_body(over_maximum, 5, 4, std::time::Duration::from_secs(1),).await,
            Err(PqBodyCollectionError::PayloadTooLarge)
        ));

        let too_many_chunks = futures::stream::iter(
            (0..=PQ_HTTP_BODY_CHUNK_CAPACITY).map(|_| Ok::<_, warp::Error>(Bytes::new())),
        );
        assert!(matches!(
            collect_bounded_body(too_many_chunks, 0, 0, std::time::Duration::from_secs(1),).await,
            Err(PqBodyCollectionError::Resource)
        ));

        let pending = futures::stream::pending::<Result<Bytes, warp::Error>>();
        assert!(matches!(
            collect_bounded_body(pending, 4, 4, std::time::Duration::from_millis(1),).await,
            Err(PqBodyCollectionError::Timeout)
        ));
    }

    #[cfg(feature = "pq-startup-testing")]
    #[tokio::test(flavor = "current_thread")]
    async fn a_single_large_chunk_is_coalesced_only_on_the_blocking_executor() {
        let body = Bytes::from(vec![0x5a; 2 * 1024 * 1024]);
        let collected = collect_bounded_body(
            futures::stream::once(async move { Ok::<_, warp::Error>(body) }),
            2 * 1024 * 1024,
            2 * 1024 * 1024,
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("one retained raw chunk");
        assert_eq!(collected.chunk_count(), 1);

        let hook = TestingPqHttpBlockingHook::blocking();
        let collected = collected.testing_only_with_coalesce_hook(Arc::clone(&hook));
        let coalesce = tokio::task::spawn_blocking(move || {
            coalesce_collected_body(collected, 2 * 1024 * 1024, 2 * 1024 * 1024)
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while hook.entered() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking coalesce entered");
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                tokio::task::yield_now().await;
                1usize
            })
            .await
            .expect("async heartbeat during coalesce barrier"),
            1,
        );
        hook.release();
        assert_eq!(
            coalesce
                .await
                .expect("blocking coalesce task")
                .expect("large body coalesce")
                .len(),
            2 * 1024 * 1024,
        );
    }

    #[tokio::test]
    async fn coalescing_capacity_overflow_maps_to_standard_503() {
        let error = coalesce_collected_body(
            PqCollectedBody::<Bytes> {
                chunks: Vec::new(),
                length: usize::MAX,
                #[cfg(feature = "pq-startup-testing")]
                coalesce_hook: None,
            },
            usize::MAX,
            usize::MAX,
        )
        .expect_err("capacity overflow must be a local resource error");
        assert!(matches!(error, PqPublishDecodeError::Resource));
        let rejection = map_publish_operation_result(PqPublishOperationResult::Decode(error))
            .expect_err("resource failure must reject the request");
        let response = handle_rejection(rejection)
            .await
            .expect("resource rejection response");
        assert_eq!(response.status(), 503);
        let body = warp::hyper::body::to_bytes(response.into_body())
            .await
            .expect("resource error body");
        let error: eth2::types::ErrorMessage =
            serde_json::from_slice(&body).expect("standard eth2 resource error");
        assert_eq!(error.code, 503);
    }
}
