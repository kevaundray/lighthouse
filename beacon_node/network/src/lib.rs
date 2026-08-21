/// This crate provides the network server for Lighthouse.
#[cfg(not(feature = "pq-devnet"))]
pub mod service;

#[cfg(not(feature = "pq-devnet"))]
mod metrics;
#[cfg(not(feature = "pq-devnet"))]
mod nat;
#[cfg(not(feature = "pq-devnet"))]
mod network_beacon_processor;
#[cfg(not(feature = "pq-devnet"))]
mod persisted_dht;
#[cfg(feature = "pq-devnet")]
mod pq_runtime;
#[cfg(not(feature = "pq-devnet"))]
mod router;
#[cfg(not(feature = "pq-devnet"))]
mod status;
#[cfg(not(feature = "pq-devnet"))]
mod subnet_service;
#[cfg(not(feature = "pq-devnet"))]
mod sync;

pub use lighthouse_network::NetworkConfig;
#[cfg(not(feature = "pq-devnet"))]
pub use network_beacon_processor::NetworkBeaconProcessor;
#[cfg(feature = "pq-devnet")]
pub use pq_runtime::{
    PQ_BLOCK_BROADCAST_QUEUE_CAPACITY, PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY,
    PQ_BLOCK_PUBLICATION_BODY_CHUNK_CAPACITY, PQ_BLOCK_PUBLICATION_BODY_CHUNK_METADATA_BYTES,
    PQ_BLOCK_PUBLICATION_RETAINED_BODY_FIXED_BYTES, PQ_NETWORK_BLOCK_COMMIT_CAPACITY,
    PQ_NETWORK_BLOCK_ENCODING_CAPACITY, PQ_NETWORK_BLOCK_PROOF_CAPACITY,
    PQ_PUBLICATION_FIXED_BODY_ALLOWANCE_BYTES, PqBlockBroadcastAcknowledgement,
    PqBlockBroadcastCommand, PqBlockBroadcastError, PqBlockBroadcastReceiver,
    PqBlockBroadcastSender, PqBlockPublicationAdmission, PqBlockPublicationConfigurationError,
    PqBlockPublicationDisposition, PqBlockPublicationLocalError, PqBlockPublicationService,
    PqBlockPublicationTerminal, PqGossipAggregateDisposition, PqGossipAttestationDisposition,
    PqGossipBlockDisposition, PqNetworkBlockProcessor, PqNetworkService, PqNetworkServiceError,
    PqNetworkServiceShutdown, PqPublicationBodyLimits, PqPublicationCapacity,
    pq_block_broadcast_channel,
};
#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub use pq_runtime::{
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
#[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
#[doc(hidden)]
pub use pq_runtime::{
    PqLocalAttestationBatchEncoderTestTrace, PqLocalAttestationBatchEncodingTestTrace,
    PqLocalAttestationExactSszBufferTestTrace, PqLocalAttestationPublishTestOutcome,
    PqLocalAttestationPublishTestTrace, testing_only_pq_local_attestation_batch_publish_channel,
    testing_only_pq_local_attestation_encode_batch,
    testing_only_pq_local_attestation_encode_exact_signed_ssz,
    testing_only_pq_local_attestation_publish_progress,
};
#[cfg(feature = "pq-proposer")]
pub use pq_runtime::{
    PqLocalAttestationBatchEncodingFailure, PqLocalAttestationBatchPublishProgress,
    PqLocalAttestationBatchPublishReceipt, PqLocalAttestationBatchPublishRetryError,
    PqLocalAttestationBatchPublishSendError, PqLocalAttestationBatchPublishSender,
    PqLocalAttestationMemberPublishProgress,
};
#[cfg(not(feature = "pq-devnet"))]
pub use service::{
    NetworkMessage, NetworkReceivers, NetworkSenders, NetworkService, ValidatorSubscriptionMessage,
};
