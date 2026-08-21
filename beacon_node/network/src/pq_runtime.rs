use beacon_chain::{
    BeaconChain, BeaconChainTypes, PqAggregateGossipPropagationToken, PqAttestationGossipError,
    PqBlockImportOutcome, PqBlockImportRequest, PqForwardRangeError, PqGossipCommitToken,
    PqGossipObservation, PqGossipPropagationToken, PqImportError, PqKnownPublishObservation,
    PqSingleGossipPropagationToken,
};
use std::sync::Arc;
use types::{SignedAggregateAndProof, SignedBeaconBlock, SingleAttestation, SubnetId};

mod broadcast;
#[cfg(feature = "pq-proposer")]
mod local_attestation_publish;
mod publication;
mod service;

pub use broadcast::{
    PQ_BLOCK_BROADCAST_QUEUE_CAPACITY, PqBlockBroadcastAcknowledgement, PqBlockBroadcastCommand,
    PqBlockBroadcastError, PqBlockBroadcastReceiver, PqBlockBroadcastSender,
    pq_block_broadcast_channel,
};
#[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
pub use local_attestation_publish::{
    PqLocalAttestationBatchEncoderTestTrace, PqLocalAttestationBatchEncodingTestTrace,
    PqLocalAttestationExactSszBufferTestTrace, PqLocalAttestationPublishTestOutcome,
    PqLocalAttestationPublishTestTrace, testing_only_pq_local_attestation_batch_publish_channel,
    testing_only_pq_local_attestation_encode_batch,
    testing_only_pq_local_attestation_encode_exact_signed_ssz,
    testing_only_pq_local_attestation_publish_progress,
};
#[cfg(feature = "pq-proposer")]
pub use local_attestation_publish::{
    PqLocalAttestationBatchEncodingFailure, PqLocalAttestationBatchPublishProgress,
    PqLocalAttestationBatchPublishReceipt, PqLocalAttestationBatchPublishRetryError,
    PqLocalAttestationBatchPublishSendError, PqLocalAttestationBatchPublishSender,
    PqLocalAttestationMemberPublishProgress,
};
#[cfg(feature = "pq-proposer")]
pub(crate) use local_attestation_publish::{
    PqLocalAttestationBatchPublishEvent, PqLocalAttestationBatchPublishReceiver,
    pq_local_attestation_batch_publish_channel,
};
pub use publication::{
    PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY, PQ_BLOCK_PUBLICATION_BODY_CHUNK_CAPACITY,
    PQ_BLOCK_PUBLICATION_BODY_CHUNK_METADATA_BYTES, PQ_BLOCK_PUBLICATION_RETAINED_BODY_FIXED_BYTES,
    PQ_PUBLICATION_FIXED_BODY_ALLOWANCE_BYTES, PqBlockPublicationAdmission,
    PqBlockPublicationConfigurationError, PqBlockPublicationDisposition,
    PqBlockPublicationLocalError, PqBlockPublicationService, PqBlockPublicationTerminal,
    PqPublicationBodyLimits, PqPublicationCapacity,
};
pub use service::{
    PQ_NETWORK_BLOCK_COMMIT_CAPACITY, PQ_NETWORK_BLOCK_ENCODING_CAPACITY,
    PQ_NETWORK_BLOCK_PROOF_CAPACITY, PqNetworkService, PqNetworkServiceError,
    PqNetworkServiceShutdown,
};
#[cfg(feature = "pq-startup-testing")]
pub use service::{
    PqCommitCompletionQueueTestTrace, PqCommitResolutionTestCase, PqCompletionQueueTestScenario,
    PqCompletionQueueTestTrace, PqCompletionTestDisposition, PqCompletionTestEvent,
    PqEncodingShutdownTestTrace, PqGossipImportedEventGateTestTrace,
    PqNetworkAttestationCompletionTestDisposition, PqNetworkAttestationCompletionTestEvent,
    PqNetworkAttestationConsumptionTestCase, PqNetworkAttestationConsumptionTestTrace,
    PqNetworkAttestationDetachedTestTrace, PqNetworkAttestationIgnoreTestCase,
    PqNetworkAttestationIgnoreTestTrace, PqNetworkAttestationInFlightTestTrace,
    PqNetworkAttestationRouteTestCase, PqNetworkAttestationRouteTestTrace,
    PqProofAdmissionTestTrace, PqStatusTestEvent, PqStatusTestScenario, PqStatusTestTrace,
    PqTestingAttestationPublishAcknowledgement, PqTestingAttestationPublishError,
    PqTestingAttestationPublishSender, testing_only_pq_attestation_completion_lifecycle,
    testing_only_pq_attestation_consumption_resolution,
    testing_only_pq_attestation_detached_lifecycle,
    testing_only_pq_attestation_ignore_classification,
    testing_only_pq_attestation_in_flight_lifecycle, testing_only_pq_attestation_route,
    testing_only_pq_commit_completion_queue, testing_only_pq_commit_resolution,
    testing_only_pq_completion_lifecycle, testing_only_pq_completion_queue,
    testing_only_pq_encoding_shutdown, testing_only_pq_gossip_imported_event_gate,
    testing_only_pq_proof_admission, testing_only_pq_status_lifecycle,
};

/// Result of full contextual and PQ evidence verification for unaggregated gossip.
pub enum PqGossipAttestationDisposition<E: types::EthSpec> {
    /// Propagate, then consume with `PqSingleGossipPropagationToken::mark_propagated`.
    Accept(Box<PqSingleGossipPropagationToken<E>>),
    /// Deterministically invalid context or evidence. Reject and penalize the peer.
    Reject(PqAttestationGossipError),
    /// Local resource/head/service failure or duplicate. Ignore without peer penalty.
    Ignore(PqAttestationGossipError),
}

/// Result of full contextual and PQ evidence verification for aggregate-and-proof gossip.
pub enum PqGossipAggregateDisposition<E: types::EthSpec> {
    Accept(Box<PqAggregateGossipPropagationToken<E>>),
    Reject(PqAttestationGossipError),
    Ignore(PqAttestationGossipError),
}

/// Result of the complete sealed verification which precedes a gossipsub decision.
pub enum PqGossipBlockDisposition<T: BeaconChainTypes> {
    /// Propagate this fully authenticated block, then consume it in `commit_gossip_block`.
    Accept(PqGossipPropagationToken<T>),
    /// Do not propagate again. This is the unique retry claim made available only after an earlier
    /// local Engine/transport/store failure or a dropped propagation/commit capability.
    Retry(PqGossipCommitToken<T>),
    /// Another exact capability is still pending propagation or commit.
    IgnorePending,
    /// The same root was rejected by Engine, committed, or otherwise completed terminally.
    IgnoreTerminal,
    /// A fully verified equivocation is not propagated in V1, which has no slashing pipeline.
    IgnoreEquivocation,
    /// Hostile deterministic input. Reject and apply the caller's peer-invalid policy.
    Reject(PqImportError),
    /// Missing parent or local proof/resource failure. Ignore without penalizing the peer.
    Ignore(PqImportError),
}

/// PQ-only network boundary. The ordinary BLS router/sync processor remains cfg-omitted.
pub struct PqNetworkBlockProcessor<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
}

impl<T: BeaconChainTypes> PqNetworkBlockProcessor<T> {
    pub fn new(chain: Arc<BeaconChain<T>>) -> Self {
        Self { chain }
    }

    pub async fn verify_gossip_attestation(
        &self,
        attestation: SingleAttestation,
        subnet: SubnetId,
    ) -> PqGossipAttestationDisposition<T::EthSpec> {
        match self
            .chain
            .verify_pq_single_attestation_for_gossip(attestation, subnet)
            .await
        {
            Ok(token) => PqGossipAttestationDisposition::Accept(Box::new(token)),
            Err(error) if error.should_penalize_peer() => {
                PqGossipAttestationDisposition::Reject(error)
            }
            Err(error) => PqGossipAttestationDisposition::Ignore(error),
        }
    }

    pub fn fail_gossip_attestation_consumption(&self) {
        self.chain.fail_pq_attestation_after_propagation();
    }

    pub async fn verify_gossip_aggregate(
        &self,
        aggregate: SignedAggregateAndProof<T::EthSpec>,
    ) -> PqGossipAggregateDisposition<T::EthSpec> {
        match self.chain.verify_pq_aggregate_for_gossip(aggregate).await {
            Ok(token) => PqGossipAggregateDisposition::Accept(Box::new(token)),
            Err(error) if error.should_penalize_peer() => {
                PqGossipAggregateDisposition::Reject(error)
            }
            Err(error) => PqGossipAggregateDisposition::Ignore(error),
        }
    }

    pub async fn verify_gossip_block(
        &self,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> PqGossipBlockDisposition<T> {
        match self.chain.known_pq_publish_observation(&block) {
            Some(PqKnownPublishObservation::Pending) => {
                return PqGossipBlockDisposition::IgnorePending;
            }
            Some(PqKnownPublishObservation::Committed)
            | Some(PqKnownPublishObservation::Terminal) => {
                return PqGossipBlockDisposition::IgnoreTerminal;
            }
            None => {}
        }
        match self
            .chain
            .verify_pq_block(PqBlockImportRequest::gossip(block))
            .await
        {
            Ok(verified) => match self.chain.observe_verified_pq_gossip_block(verified) {
                PqGossipObservation::New(token) => PqGossipBlockDisposition::Accept(token),
                PqGossipObservation::Retry(token) => PqGossipBlockDisposition::Retry(token),
                PqGossipObservation::Pending => PqGossipBlockDisposition::IgnorePending,
                PqGossipObservation::Terminal => PqGossipBlockDisposition::IgnoreTerminal,
                PqGossipObservation::Equivocation { .. } => {
                    PqGossipBlockDisposition::IgnoreEquivocation
                }
                PqGossipObservation::NotGossip => {
                    PqGossipBlockDisposition::Ignore(verified_source_invariant())
                }
                PqGossipObservation::Capacity => PqGossipBlockDisposition::Ignore(
                    PqImportError::Local(beacon_chain::PqImportLocalError::ObservationCapacity),
                ),
            },
            Err(error) if error.should_penalize_peer() => PqGossipBlockDisposition::Reject(error),
            Err(error) => PqGossipBlockDisposition::Ignore(error),
        }
    }

    /// Call only after gossipsub propagation for `Accept`, or immediately for a duplicate retry.
    pub async fn commit_gossip_block(
        &self,
        verified: PqGossipCommitToken<T>,
    ) -> Result<PqBlockImportOutcome, PqImportError> {
        verified.commit().await
    }

    pub async fn import_rpc_block(
        &self,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<PqBlockImportOutcome, PqImportError> {
        self.chain
            .import_pq_block(PqBlockImportRequest::rpc(block))
            .await
    }

    pub async fn import_lookup_block(
        &self,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<PqBlockImportOutcome, PqImportError> {
        self.chain
            .import_pq_block(PqBlockImportRequest::lookup(block))
            .await
    }

    pub async fn import_forward_range(
        &self,
        blocks: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Result<Vec<PqBlockImportOutcome>, PqForwardRangeError> {
        self.chain
            .import_pq_forward_range(
                blocks
                    .into_iter()
                    .map(PqBlockImportRequest::forward_range)
                    .collect(),
            )
            .await
    }
}

fn verified_source_invariant() -> PqImportError {
    PqImportError::Local(beacon_chain::PqImportLocalError::Invariant(
        "gossip verifier returned a non-gossip capability",
    ))
}
