#[cfg(target_feature = "avx2")]
use beacon_chain::testing_only_running_pq_operational_event_sink;
use beacon_chain::{
    PqForkChoiceAttestationOutcome, PqOperationalEventError, PqOperationalEventRole,
    PqSingleConsumptionResult, PqSingleObservationIdentity, PqSingleObservationStatus,
    PqSingleWireMessageId, PqStatusRejectionCode,
    testing_only_pq_extended_operational_event_contract,
    testing_only_pq_operational_event_acknowledgement,
    testing_only_pq_operational_event_nonblocking_writer, testing_only_pq_operational_event_sink,
    testing_only_pq_operational_event_stdout_kinds,
};
use consensus_signature::IndividualSignature;
use lighthouse_network::MessageId;
use network::{
    PQ_NETWORK_BLOCK_COMMIT_CAPACITY, PQ_NETWORK_BLOCK_ENCODING_CAPACITY,
    PQ_NETWORK_BLOCK_PROOF_CAPACITY, PqBlockBroadcastError, PqCommitCompletionQueueTestTrace,
    PqCommitResolutionTestCase, PqCompletionQueueTestScenario, PqCompletionQueueTestTrace,
    PqCompletionTestDisposition, PqCompletionTestEvent, PqEncodingShutdownTestTrace,
    PqNetworkAttestationCompletionTestDisposition, PqNetworkAttestationCompletionTestEvent,
    PqNetworkAttestationConsumptionMetadataRetentionTrace, PqNetworkAttestationConsumptionTestCase,
    PqNetworkAttestationConsumptionTestTrace, PqNetworkAttestationDetachedTestTrace,
    PqNetworkAttestationIdentityCompletionTestTrace, PqNetworkAttestationIdentityIngressTestCase,
    PqNetworkAttestationIdentityIngressTestEvent, PqNetworkAttestationIdentityIngressTestTrace,
    PqNetworkAttestationIgnoreTestCase, PqNetworkAttestationIgnoreTestTrace,
    PqNetworkAttestationInFlightTestTrace, PqNetworkAttestationRouteTestCase,
    PqNetworkAttestationRouteTestTrace, PqNetworkAttestationWireIdIngressTestEvent,
    PqNetworkAttestationWireIdIngressTestMutation, PqNetworkAttestationWireIdIngressTestTrace,
    PqNetworkAttestationWireProvenanceError, PqNetworkServiceError, PqProofAdmissionTestTrace,
    PqStatusTestEvent, PqStatusTestScenario, PqStatusTestTrace, pq_block_broadcast_channel,
    testing_only_pq_attestation_completion_lifecycle,
    testing_only_pq_attestation_consumption_metadata_retention,
    testing_only_pq_attestation_consumption_resolution,
    testing_only_pq_attestation_detached_lifecycle,
    testing_only_pq_attestation_identity_completion_trace,
    testing_only_pq_attestation_identity_ingress_actual_path,
    testing_only_pq_attestation_ignore_classification,
    testing_only_pq_attestation_in_flight_lifecycle, testing_only_pq_attestation_route,
    testing_only_pq_attestation_wire_id_ingress_actual_path,
    testing_only_pq_attestation_wire_provenance_actual_path,
    testing_only_pq_commit_completion_queue, testing_only_pq_commit_resolution,
    testing_only_pq_completion_lifecycle, testing_only_pq_completion_queue,
    testing_only_pq_encoding_shutdown, testing_only_pq_gossip_imported_event_gate,
    testing_only_pq_proof_admission, testing_only_pq_status_lifecycle,
};
use std::sync::Arc;
use types::{
    BeaconBlock, EthSpec, ForkContext, ForkName, Hash256, MinimalEthSpec, SignedBeaconBlock,
};

#[cfg(target_feature = "avx2")]
use beacon_chain::{
    PqNewPayloadTransport,
    builder::{BeaconChainBuilder, Witness},
};
#[cfg(target_feature = "avx2")]
use consensus_signature::{AggregationService, OneTimeUseId, PqPublicKey, SigningDuty};
#[cfg(target_feature = "avx2")]
use lighthouse_network::types::{GossipEncoding, GossipKind, GossipTopic};
#[cfg(target_feature = "avx2")]
use lighthouse_network::{Context, NetworkConfig, identity::secp256k1};
#[cfg(target_feature = "avx2")]
use network::PqNetworkService;
#[cfg(target_feature = "avx2")]
use network_utils::enr_ext::EnrExt;
#[cfg(target_feature = "avx2")]
use pq_signing::{PqKeyUnlock, PqKeystore, PqSigningAuthority, provision_usage_journal};
#[cfg(target_feature = "avx2")]
use ssz::Encode;
#[cfg(target_feature = "avx2")]
use store::{HotColdDB, MemoryStore, StoreConfig};
#[cfg(target_feature = "avx2")]
use types::{
    AttestationData, ChainSpec, Checkpoint, Domain, ExecutionPayloadRef, SignedRoot,
    SingleAttestation, Slot, SubnetId,
};

#[test]
fn pq_network_service_has_the_frozen_bounded_proof_contract() {
    assert_eq!(PQ_NETWORK_BLOCK_PROOF_CAPACITY, 2);
    assert_eq!(PQ_NETWORK_BLOCK_ENCODING_CAPACITY, 2);
    assert_eq!(PQ_NETWORK_BLOCK_COMMIT_CAPACITY, 2);
}

#[test]
fn detached_commit_resolution_releases_only_exact_retryable_commit_failures() {
    assert!(!testing_only_pq_commit_resolution(
        PqCommitResolutionTestCase::Success,
    ));
    assert!(testing_only_pq_commit_resolution(
        PqCommitResolutionTestCase::BlockingTask,
    ));
    assert!(!testing_only_pq_commit_resolution(
        PqCommitResolutionTestCase::ParentUnavailable,
    ));
    assert!(!testing_only_pq_commit_resolution(
        PqCommitResolutionTestCase::ReconciliationFailure,
    ));
    assert!(!testing_only_pq_commit_resolution(
        PqCommitResolutionTestCase::TerminalObservation,
    ));
    assert!(!testing_only_pq_commit_resolution(
        PqCommitResolutionTestCase::DurableStateUnknown,
    ));
}

#[test]
fn detached_commit_completion_queue_is_exactly_bounded_and_raii_on_shutdown() {
    assert_eq!(
        testing_only_pq_commit_completion_queue(),
        PqCommitCompletionQueueTestTrace {
            admitted: vec![true, true, false],
            dropped_after_overflow: 1,
            dropped_after_shutdown: 3,
        },
    );
}

#[test]
fn pq_network_construction_error_preserves_lower_detail() {
    assert_eq!(
        PqNetworkServiceError::Construction("lower network detail".into()).to_string(),
        "could not construct the PQ libp2p service: lower network detail",
    );
}

#[test]
fn admitted_single_routes_to_exact_subnet_verifier_only() {
    assert_eq!(
        testing_only_pq_attestation_route(PqNetworkAttestationRouteTestCase::AdmittedSingle {
            subnet: types::SubnetId::new(3),
        }),
        PqNetworkAttestationRouteTestTrace::VerifySingle {
            subnet: types::SubnetId::new(3),
        },
    );
    assert_eq!(
        testing_only_pq_attestation_route(PqNetworkAttestationRouteTestCase::OrdinarySingle {
            subnet: types::SubnetId::new(3),
        }),
        PqNetworkAttestationRouteTestTrace::Ignore,
    );
    assert_eq!(
        testing_only_pq_attestation_route(PqNetworkAttestationRouteTestCase::AdmittedAggregate),
        PqNetworkAttestationRouteTestTrace::RetryableIgnore,
    );
}

#[test]
fn admitted_single_accept_reports_before_propagation_and_consumption() {
    assert_eq!(
        testing_only_pq_attestation_completion_lifecycle(
            PqNetworkAttestationCompletionTestDisposition::Accept {
                report_succeeded: true,
            },
        ),
        vec![
            PqNetworkAttestationCompletionTestEvent::ReportedAccept,
            PqNetworkAttestationCompletionTestEvent::MarkedPropagated,
            PqNetworkAttestationCompletionTestEvent::ConsumptionSpawned,
        ],
    );
}

#[test]
fn admitted_single_failed_report_rolls_back_without_consumption() {
    assert_eq!(
        testing_only_pq_attestation_completion_lifecycle(
            PqNetworkAttestationCompletionTestDisposition::Accept {
                report_succeeded: false,
            },
        ),
        vec![
            PqNetworkAttestationCompletionTestEvent::ReportedAccept,
            PqNetworkAttestationCompletionTestEvent::PropagationCapabilityDropped,
        ],
    );
}

#[test]
fn remote_attestation_redelivery_is_terminal_while_local_capacity_is_retryable() {
    for case in [
        PqNetworkAttestationIgnoreTestCase::RemoteDuplicate,
        PqNetworkAttestationIgnoreTestCase::Aged,
        PqNetworkAttestationIgnoreTestCase::StaleHead,
        PqNetworkAttestationIgnoreTestCase::ShuttingDown,
        PqNetworkAttestationIgnoreTestCase::GenerationExhausted,
        PqNetworkAttestationIgnoreTestCase::TerminalWindow,
    ] {
        assert_eq!(
            testing_only_pq_attestation_ignore_classification(case),
            PqNetworkAttestationIgnoreTestTrace {
                retryable_ignore: false,
                terminal_ignore: true,
                retained_history: true,
            },
        );
    }
    assert_eq!(
        testing_only_pq_attestation_ignore_classification(
            PqNetworkAttestationIgnoreTestCase::LocalCapacity,
        ),
        PqNetworkAttestationIgnoreTestTrace {
            retryable_ignore: true,
            terminal_ignore: false,
            retained_history: false,
        },
    );
}

#[test]
fn dropped_prepropagation_single_rolls_back_and_exact_retry_reclaims() {
    assert!(beacon_chain::testing_only_pq_single_prepropagation_retry());
}

#[tokio::test(flavor = "current_thread")]
async fn attestation_proofs_are_cap_two_and_shutdown_drains_owned_work() {
    assert_eq!(
        testing_only_pq_attestation_in_flight_lifecycle().await,
        PqNetworkAttestationInFlightTestTrace {
            admitted: vec![true, true, false],
            retryable_ignored: 1,
            heartbeat_completed: true,
            drain_pending_with_two: true,
            drain_pending_with_one: true,
            drained_after_release: true,
            available_permits_after_release: 2,
        },
    );
}

#[test]
fn post_accept_attestation_failures_retain_history_and_signal_shutdown() {
    assert_eq!(
        testing_only_pq_attestation_consumption_resolution(
            PqNetworkAttestationConsumptionTestCase::Success,
        ),
        PqNetworkAttestationConsumptionTestTrace {
            terminal_history: true,
            signal_shutdown: false,
        },
    );
    for case in [
        PqNetworkAttestationConsumptionTestCase::ReconciliationFailed,
        PqNetworkAttestationConsumptionTestCase::TaskUnavailable,
        PqNetworkAttestationConsumptionTestCase::ResolutionLost,
    ] {
        assert_eq!(
            testing_only_pq_attestation_consumption_resolution(case),
            PqNetworkAttestationConsumptionTestTrace {
                terminal_history: true,
                signal_shutdown: true,
            },
        );
    }
}

#[test]
fn inbound_attestation_completion_retains_exact_wire_identity_and_fork_choice_outcome() {
    let identity = |signed_root_byte, signed_ssz_byte| {
        PqSingleObservationIdentity::new(
            types::Epoch::new(2),
            9,
            types::Slot::new(17),
            types::SubnetId::new(4),
            Hash256::repeat_byte(signed_root_byte),
            [signed_ssz_byte; 32],
        )
    };
    for (message_id, wire_identity, outcome, observation_status) in [
        (
            MessageId(vec![0x11; 20]),
            identity(0x21, 0x31),
            PqForkChoiceAttestationOutcome::Applied,
            PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Applied),
        ),
        (
            MessageId(vec![0x41; 20]),
            identity(0x22, 0x31),
            PqForkChoiceAttestationOutcome::Queued,
            PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Queued),
        ),
        (
            MessageId(vec![0x51; 20]),
            identity(0x21, 0x32),
            PqForkChoiceAttestationOutcome::Applied,
            PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Applied),
        ),
    ] {
        assert_eq!(
            testing_only_pq_attestation_identity_completion_trace(
                message_id.clone(),
                wire_identity,
                outcome,
            ),
            PqNetworkAttestationIdentityCompletionTestTrace {
                verification_message_id: message_id.clone(),
                verification_identity: wire_identity,
                consumption_message_id: message_id,
                consumption_identity: wire_identity,
                observation_status,
            },
        );
    }
}

#[test]
fn inbound_consumption_handler_retains_metadata_for_future_cross_source_coalescing() {
    let message_id = MessageId(vec![0x61; 20]);
    let identity = PqSingleObservationIdentity::new(
        types::Epoch::new(2),
        9,
        types::Slot::new(17),
        types::SubnetId::new(4),
        Hash256::repeat_byte(0x71),
        [0x81; 32],
    );
    assert_eq!(
        testing_only_pq_attestation_consumption_metadata_retention(
            message_id.clone(),
            identity,
            PqForkChoiceAttestationOutcome::Queued,
        ),
        PqNetworkAttestationConsumptionMetadataRetentionTrace {
            message_id,
            identity,
            result: PqSingleConsumptionResult::Queued,
            retained_for_coalescer: false,
            coordinator_wired: true,
        },
        "the completion handler must defer to chain authority without retaining network history",
    );
}

#[test]
fn attestation_ingress_admits_before_deriving_identity_from_the_sealed_token() {
    let identity = |root_byte, digest_byte| {
        PqSingleObservationIdentity::new(
            types::Epoch::new(2),
            9,
            types::Slot::new(17),
            types::SubnetId::new(4),
            Hash256::repeat_byte(root_byte),
            [digest_byte; 32],
        )
    };
    let decoded_network_identity = identity(0x31, 0x41);
    let sealed_token_identity = identity(0x32, 0x42);
    let message_id = MessageId(vec![0x51; 20]);

    assert_eq!(
        testing_only_pq_attestation_identity_ingress_actual_path(
            PqNetworkAttestationIdentityIngressTestCase::CapacityExhausted,
            message_id.clone(),
            decoded_network_identity,
            sealed_token_identity,
        ),
        PqNetworkAttestationIdentityIngressTestTrace {
            events: vec![PqNetworkAttestationIdentityIngressTestEvent::AdmissionAttempted],
            identity_derivations_before_admission: 0,
            verification_message_id: None,
            verification_identity: None,
        },
        "a cap2 miss must not hash or derive any observation identity",
    );

    assert_eq!(
        testing_only_pq_attestation_identity_ingress_actual_path(
            PqNetworkAttestationIdentityIngressTestCase::Accepted,
            message_id.clone(),
            decoded_network_identity,
            sealed_token_identity,
        ),
        PqNetworkAttestationIdentityIngressTestTrace {
            events: vec![
                PqNetworkAttestationIdentityIngressTestEvent::AdmissionAttempted,
                PqNetworkAttestationIdentityIngressTestEvent::AdmissionAcquired,
                PqNetworkAttestationIdentityIngressTestEvent::SealedTokenIdentityTransferred,
                PqNetworkAttestationIdentityIngressTestEvent::CompletionQueued,
            ],
            identity_derivations_before_admission: 0,
            verification_message_id: Some(message_id),
            verification_identity: Some(sealed_token_identity),
        },
        "accepted completion identity must come from the sealed verifier result, never decoded input",
    );
}

#[test]
fn attestation_ingress_converts_and_transfers_the_exact_wire_id_once() {
    let message_id = MessageId(vec![0x51; 20]);
    let expected_wire_id = PqSingleWireMessageId::try_from(message_id.0.as_slice())
        .expect("the real gossipsub MessageId has the exact chain wire-ID length");

    assert_eq!(
        testing_only_pq_attestation_wire_id_ingress_actual_path(
            message_id.clone(),
            PqNetworkAttestationWireIdIngressTestMutation::None,
        )
        .expect("the actual admitted verification path retains exact wire authority"),
        PqNetworkAttestationWireIdIngressTestTrace {
            events: vec![
                PqNetworkAttestationWireIdIngressTestEvent::Converted,
                PqNetworkAttestationWireIdIngressTestEvent::Claimed,
                PqNetworkAttestationWireIdIngressTestEvent::SealedTokenTransferred,
                PqNetworkAttestationWireIdIngressTestEvent::MarkedPropagated,
                PqNetworkAttestationWireIdIngressTestEvent::CompletionQueued,
            ],
            conversion_count: 1,
            claim_wire_id: expected_wire_id,
            sealed_token_wire_id: expected_wire_id,
            completion_wire_id: expected_wire_id,
        },
        "the MessageId must be converted once and moved through claim, sealed token, and completion",
    );

    assert!(
        testing_only_pq_attestation_wire_id_ingress_actual_path(
            message_id.clone(),
            PqNetworkAttestationWireIdIngressTestMutation::DropBeforeClaim,
        )
        .is_err(),
        "claiming without the converted wire authority must fail",
    );
    assert!(
        testing_only_pq_attestation_wire_id_ingress_actual_path(
            message_id,
            PqNetworkAttestationWireIdIngressTestMutation::ReplaceAfterClaim,
        )
        .is_err(),
        "the authority bound by initial preparation cannot be replaced after propagation",
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn fabricated_wire_id_cannot_claim_an_otherwise_valid_single_observation() {
    let runtime = task_executor::test_utils::TestRuntime::default();
    let fixture = live_single_attestation_fixture(&runtime).await;
    let (single, subnet) = slot_one_single_attestation(&fixture);
    let fork_digest = fixture
        .spec
        .enr_fork_id::<MinimalEthSpec>(
            single.data.slot,
            fixture.post_state.genesis_validators_root(),
        )
        .fork_digest;
    let topic = lighthouse_network::Topic::from(GossipTopic::new(
        GossipKind::Attestation(subnet),
        GossipEncoding::default(),
        fork_digest,
    ));
    let expected_message_id = lighthouse_network::pq_anonymous_message_id(
        &topic.hash(),
        &single.as_ssz_bytes(),
        fixture.spec.message_domain_valid_snappy,
        true,
    );

    let accepted = testing_only_pq_attestation_wire_provenance_actual_path(
        expected_message_id.clone(),
        topic.hash(),
        single.clone(),
        subnet,
        fixture.post_state.genesis_validators_root(),
        Arc::clone(&fixture.spec),
    )
    .expect("the exact deterministic anonymous wire ID authorizes the observation claim");
    assert_eq!(accepted.expected_message_id, expected_message_id);
    assert_eq!(accepted.observation_claim_count, 1);
    assert_eq!(
        accepted.observation_status,
        PqSingleObservationStatus::Pending
    );

    let fabricated = MessageId(vec![0xa5; 20]);
    let rejected = testing_only_pq_attestation_wire_provenance_actual_path(
        fabricated.clone(),
        topic.hash(),
        single.clone(),
        subnet,
        fixture.post_state.genesis_validators_root(),
        Arc::clone(&fixture.spec),
    )
    .expect_err("a length-valid fabricated ID carries no observation authority");
    assert!(matches!(
        rejected,
        PqNetworkAttestationWireProvenanceError::MessageIdMismatch {
            expected,
            actual,
            observation_claim_count: 0,
            observation_status: PqSingleObservationStatus::Unseen,
        } if expected == expected_message_id && actual == fabricated
    ));

    let fabricated_wire_id = PqSingleWireMessageId::try_from(fabricated.0.as_slice())
        .expect("the fabricated ID is deliberately length-valid");
    assert!(matches!(
        fixture
            .chain
            .verify_pq_single_attestation_for_gossip_with_wire_id(
                single.clone(),
                subnet,
                fabricated_wire_id,
            )
            .await,
        Err(beacon_chain::PqAttestationGossipError::Local(
            beacon_chain::PqAttestationGossipLocalError::WireMessageIdMismatch { .. }
        ))
    ));
    let identity = PqSingleObservationIdentity::from_signed_attestation(&single, subnet);
    assert_eq!(
        fixture
            .chain
            .pq_attestation_consumption_status(&identity, fabricated_wire_id),
        PqSingleObservationStatus::Unseen,
        "the independent public chain boundary rejects before observation mutation",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn attestation_task_survives_caller_drop_and_executor_exit_until_release() {
    assert_eq!(
        testing_only_pq_attestation_detached_lifecycle().await,
        PqNetworkAttestationDetachedTestTrace {
            entered: true,
            caller_drop_retained: true,
            executor_exit_retained: true,
            drained_after_release: true,
        },
    );
}

#[test]
fn accept_is_reported_before_propagation_promotion_and_commit() {
    assert_eq!(
        testing_only_pq_completion_lifecycle(PqCompletionTestDisposition::Accept {
            report_succeeded: true,
        }),
        vec![
            PqCompletionTestEvent::ReportedAccept,
            PqCompletionTestEvent::PromotedAfterPropagation,
            PqCompletionTestEvent::CommitSpawned,
        ]
    );
}

#[test]
fn failed_accept_report_drops_propagation_capability_without_commit() {
    assert_eq!(
        testing_only_pq_completion_lifecycle(PqCompletionTestDisposition::Accept {
            report_succeeded: false,
        }),
        vec![
            PqCompletionTestEvent::ReportedAccept,
            PqCompletionTestEvent::PropagationCapabilityDropped,
        ]
    );
}

#[test]
fn retry_is_ignored_for_gossip_then_committed_without_repropagation() {
    assert_eq!(
        testing_only_pq_completion_lifecycle(PqCompletionTestDisposition::Retry),
        vec![
            PqCompletionTestEvent::ReportedCommitWithoutPropagation,
            PqCompletionTestEvent::CommitSpawned,
        ]
    );
}

#[test]
fn reject_reports_reject_and_penalizes_without_commit() {
    assert_eq!(
        testing_only_pq_completion_lifecycle(PqCompletionTestDisposition::Reject),
        vec![
            PqCompletionTestEvent::ReportedReject,
            PqCompletionTestEvent::PeerPenalized,
        ]
    );
}

#[test]
fn ignore_reports_ignore_without_penalty_or_commit() {
    assert_eq!(
        testing_only_pq_completion_lifecycle(PqCompletionTestDisposition::Ignore),
        vec![PqCompletionTestEvent::ReportedRetryableIgnore]
    );
}

#[test]
fn proof_admission_is_nonwaiting_and_recovers_after_raii_drop() {
    assert_eq!(
        testing_only_pq_proof_admission(),
        PqProofAdmissionTestTrace {
            admitted: vec![true, true, false],
            proofs_started: 2,
            admitted_after_drop: true,
        }
    );
}

#[test]
fn full_completion_queue_drops_token_and_releases_permit() {
    assert_eq!(
        testing_only_pq_completion_queue(PqCompletionQueueTestScenario::Full),
        PqCompletionQueueTestTrace {
            dropped_after_send: 1,
            available_after_send: 1,
            dropped_after_receiver_drop: 2,
            available_after_receiver_drop: 2,
        }
    );
}

#[test]
fn closed_completion_queue_drops_token_and_releases_permit() {
    assert_eq!(
        testing_only_pq_completion_queue(PqCompletionQueueTestScenario::Closed),
        PqCompletionQueueTestTrace {
            dropped_after_send: 1,
            available_after_send: 2,
            dropped_after_receiver_drop: 1,
            available_after_receiver_drop: 2,
        }
    );
}

#[tokio::test(flavor = "current_thread")]
async fn pending_broadcast_ack_reports_worker_unavailable_when_owner_drops() {
    let spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
    let block = Arc::new(SignedBeaconBlock::from_block(
        BeaconBlock::<MinimalEthSpec>::empty(&spec),
        IndividualSignature::empty(),
    ));
    let (sender, receiver) = pq_block_broadcast_channel();
    let acknowledgement = sender.try_send(block).expect("bounded broadcast ingress");
    drop(receiver);
    assert_eq!(
        acknowledgement.wait().await,
        Err(PqBlockBroadcastError::WorkerUnavailable)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn encoded_completion_after_owner_shutdown_releases_ack_and_permit() {
    let spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
    let block = Arc::new(SignedBeaconBlock::from_block(
        BeaconBlock::<MinimalEthSpec>::empty(&spec),
        IndividualSignature::empty(),
    ));
    assert_eq!(
        testing_only_pq_encoding_shutdown(block, [8; 4]).await,
        PqEncodingShutdownTestTrace {
            acknowledgement: Err(PqBlockBroadcastError::WorkerUnavailable),
            available_permits: PQ_NETWORK_BLOCK_ENCODING_CAPACITY,
        }
    );
}

#[test]
fn pq_rpc_profile_advertises_only_status_and_control_protocols() {
    let spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
    let fork_context = Arc::new(ForkContext::new::<MinimalEthSpec>(
        spec.genesis_slot,
        Hash256::ZERO,
        &spec,
    ));
    let pq = lighthouse_network::rpc::testing_only_pq_rpc_protocols(Arc::clone(&fork_context));
    assert_eq!(
        pq,
        vec![
            "/eth2/beacon_chain/req/status/2/ssz_snappy",
            "/eth2/beacon_chain/req/status/1/ssz_snappy",
            "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
            "/eth2/beacon_chain/req/ping/1/ssz_snappy",
            "/eth2/beacon_chain/req/metadata/2/ssz_snappy",
            "/eth2/beacon_chain/req/metadata/1/ssz_snappy",
        ]
    );

    let full = lighthouse_network::rpc::testing_only_full_rpc_protocols(fork_context);
    assert!(
        full.iter()
            .any(|protocol| protocol.contains("beacon_blocks_by_range")),
        "ordinary construction must retain the full RPC profile",
    );
    assert!(full.len() > pq.len());
}

#[test]
fn mismatched_status_fork_disconnects_without_starting_block_verification() {
    assert_eq!(
        testing_only_pq_status_lifecycle(PqStatusTestScenario::ForkDigestMismatch),
        PqStatusTestTrace {
            events: vec![
                PqStatusTestEvent::EmittedStatusRejected(PqStatusRejectionCode::ForkDigest),
                PqStatusTestEvent::DisconnectedIrrelevantNetwork,
            ],
            block_verifications_started: 0,
        }
    );
}

#[test]
fn mismatched_status_finalized_fields_disconnect_without_starting_block_verification() {
    for (scenario, code) in [
        (
            PqStatusTestScenario::FinalizedEpochMismatch,
            PqStatusRejectionCode::FinalizedEpoch,
        ),
        (
            PqStatusTestScenario::FinalizedRootMismatch,
            PqStatusRejectionCode::FinalizedRoot,
        ),
    ] {
        assert_eq!(
            testing_only_pq_status_lifecycle(scenario),
            PqStatusTestTrace {
                events: vec![
                    PqStatusTestEvent::EmittedStatusRejected(code),
                    PqStatusTestEvent::DisconnectedIrrelevantNetwork,
                ],
                block_verifications_started: 0,
            }
        );
    }
}

#[test]
fn compatible_status_marks_peer_and_seventeenth_disconnects_without_verification() {
    assert_eq!(
        testing_only_pq_status_lifecycle(PqStatusTestScenario::Compatible),
        PqStatusTestTrace {
            events: vec![
                PqStatusTestEvent::MarkedCompatible,
                PqStatusTestEvent::EmittedPeerCompatible,
            ],
            block_verifications_started: 0,
        }
    );
    assert_eq!(
        testing_only_pq_status_lifecycle(PqStatusTestScenario::CompatibleAlreadyKnown),
        PqStatusTestTrace {
            events: vec![
                PqStatusTestEvent::MarkedCompatible,
                PqStatusTestEvent::EmittedPeerCompatible,
            ],
            block_verifications_started: 0,
        }
    );
    assert_eq!(
        testing_only_pq_status_lifecycle(PqStatusTestScenario::CompatibleCapacityFull),
        PqStatusTestTrace {
            events: vec![
                PqStatusTestEvent::EmittedStatusRejected(PqStatusRejectionCode::Capacity),
                PqStatusTestEvent::DisconnectedTooManyPeers,
            ],
            block_verifications_started: 0,
        }
    );
}

#[tokio::test]
async fn operational_event_sink_is_bounded_sequenced_and_fail_closed() {
    let trace = testing_only_pq_operational_event_sink().await;
    assert_eq!(trace.sequences, vec![1, 2]);
    assert_eq!(
        trace.roles,
        vec![
            PqOperationalEventRole::Proposer,
            PqOperationalEventRole::Proposer,
        ]
    );
    assert_eq!(trace.capacity_error, PqOperationalEventError::Capacity);
    assert_eq!(trace.closed_error, PqOperationalEventError::Closed);
    assert_eq!(
        trace.output,
        b"PQ_EVENT_V1 event=PeerCompatible sequence=1 role=proposer \
peer_digest=01010101010101010101010101010101\n\
PQ_EVENT_V1 event=PeerCompatible sequence=2 role=proposer \
peer_digest=02020202020202020202020202020202\n"
    );
    assert_eq!(trace.output_error, PqOperationalEventError::OutputClosed);
    assert_eq!(
        trace.overflow_error,
        PqOperationalEventError::SequenceOverflow
    );
    assert_eq!(trace.forced_closed_error, PqOperationalEventError::Closed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operational_event_acknowledges_only_after_the_complete_line_is_written() {
    let trace = testing_only_pq_operational_event_acknowledgement().await;
    assert!(trace.pending_before_output);
    assert!(trace.heartbeat_completed);
    assert_eq!(trace.result, Ok(()));
    assert_eq!(
        trace.output,
        b"PQ_EVENT_V1 event=EventWriterReady sequence=1 role=proposer\n"
    );
}

#[test]
fn gossip_imported_event_requires_commit_and_gossipsub_resolution() {
    let trace = testing_only_pq_gossip_imported_event_gate();
    assert!(matches!(
        trace.committed_and_resolved,
        Some(beacon_chain::PqOperationalEvent::GossipImported {
            slot,
            block_root,
            signed_ssz_digest,
        }) if slot == types::Slot::new(3)
            && block_root == types::Hash256::repeat_byte(4)
            && signed_ssz_digest == [5; 32]
    ));
    assert_eq!(trace.committed_but_unresolved, None);
    assert_eq!(trace.resolved_but_failed, None);
}

#[tokio::test(flavor = "current_thread")]
async fn operational_event_writer_full_pipe_is_nonblocking_and_does_not_starve_tokio() {
    let runtime = task_executor::test_utils::TestRuntime::default();
    let trace = testing_only_pq_operational_event_nonblocking_writer(&runtime.task_executor).await;
    assert_eq!(trace.error, PqOperationalEventError::OutputWouldBlock);
    assert!(trace.stdout_flags_unchanged);
    assert!(trace.dedicated_thread);
    assert!(trace.heartbeat_completed);
    assert!(trace.completion_bounded);
}

#[test]
fn operational_event_writer_preserves_kind_specific_stdout_semantics() {
    let trace = testing_only_pq_operational_event_stdout_kinds();
    assert!(trace.nonappend_shared_offset_advanced);
    assert!(trace.nonappend_prefix_preserved);
    assert!(trace.append_retained);
    assert!(trace.socket_flags_unchanged);
    assert!(matches!(
        trace.socket_result,
        Ok(()) | Err(PqOperationalEventError::OutputWouldBlock)
    ));
    assert!(trace.pipe_flags_unchanged);
    assert_eq!(
        trace.pipe_result,
        Err(PqOperationalEventError::OutputWouldBlock)
    );
}

#[test]
fn extended_operational_event_contract_is_fixed_and_bounded() {
    let output = testing_only_pq_extended_operational_event_contract();
    assert_eq!(
        output,
        b"PQ_EVENT_V1 event=RuntimeReady sequence=1 role=proposer startup=fresh slot=1 \
block_root=0x0101010101010101010101010101010101010101010101010101010101010101 \
execution_hash=0x0202020202020202020202020202020202020202020202020202020202020202 \
justified_epoch=0 justified_root=0x0000000000000000000000000000000000000000000000000000000000000000 \
finalized_epoch=0 finalized_root=0x0303030303030303030303030303030303030303030303030303030303030303 \
signed_ssz_digest=0404040404040404040404040404040404040404040404040404040404040404\n\
PQ_EVENT_V1 event=ProposalStarted sequence=2 role=proposer slot=2 \
parent_root=0x0505050505050505050505050505050505050505050505050505050505050505\n\
PQ_EVENT_V1 event=BlockPersisted sequence=3 role=proposer source=publish slot=2 \
block_root=0x0606060606060606060606060606060606060606060606060606060606060606 \
execution_hash=0x0707070707070707070707070707070707070707070707070707070707070707 \
justified_epoch=0 justified_root=0x0000000000000000000000000000000000000000000000000000000000000000 \
finalized_epoch=0 finalized_root=0x0303030303030303030303030303030303030303030303030303030303030303 \
signed_ssz_digest=0808080808080808080808080808080808080808080808080808080808080808\n\
PQ_EVENT_V1 event=ExecutionReconciled sequence=4 role=proposer source=publish slot=2 \
block_root=0x0606060606060606060606060606060606060606060606060606060606060606 \
execution_hash=0x0707070707070707070707070707070707070707070707070707070707070707 \
justified_epoch=0 justified_root=0x0000000000000000000000000000000000000000000000000000000000000000 \
finalized_epoch=0 finalized_root=0x0303030303030303030303030303030303030303030303030303030303030303 \
signed_ssz_digest=0808080808080808080808080808080808080808080808080808080808080808\n\
PQ_EVENT_V1 event=ProposalPublished sequence=5 role=proposer slot=2 \
block_root=0x0606060606060606060606060606060606060606060606060606060606060606 \
signed_ssz_digest=0808080808080808080808080808080808080808080808080808080808080808\n\
PQ_EVENT_V1 event=GossipImported sequence=6 role=proposer slot=2 \
block_root=0x0606060606060606060606060606060606060606060606060606060606060606 \
signed_ssz_digest=0808080808080808080808080808080808080808080808080808080808080808\n"
    );
    assert!(
        output
            .split(|byte| *byte == b'\n')
            .all(|line| line.len() <= 4096)
    );
}

#[cfg(target_feature = "avx2")]
type TestWitness = Witness<slot_clock::TestingSlotClock, MinimalEthSpec, MemoryStore, MemoryStore>;

#[cfg(target_feature = "avx2")]
struct UnusedValidTransport;

#[cfg(target_feature = "avx2")]
impl PqNewPayloadTransport<MinimalEthSpec> for UnusedValidTransport {
    fn notify_new_payload<'a>(
        &'a self,
        _request: execution_layer::NewPayloadRequest<'a, MinimalEthSpec>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Ok(execution_layer::PayloadStatus::Valid) })
    }

    fn notify_forkchoice_updated<'a>(
        &'a self,
        _head_block_hash: types::ExecutionBlockHash,
        _safe_block_hash: types::ExecutionBlockHash,
        _finalized_block_hash: types::ExecutionBlockHash,
        _current_slot: types::Slot,
        _head_block_root: Hash256,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Ok(execution_layer::PayloadStatus::Valid) })
    }
}

#[cfg(target_feature = "avx2")]
fn exact_snapshot_store(
    spec: Arc<ChainSpec>,
) -> Arc<HotColdDB<MinimalEthSpec, MemoryStore, MemoryStore>> {
    let mut config = StoreConfig::default();
    config.hierarchy_config.exponents = vec![0];
    config.block_cache_size = 0;
    Arc::new(HotColdDB::open_ephemeral(config, spec).expect("snapshot-every-slot store"))
}

#[cfg(target_feature = "avx2")]
fn build_chain(
    runtime: &task_executor::test_utils::TestRuntime,
) -> (Arc<beacon_chain::BeaconChain<TestWitness>>, Arc<ChainSpec>) {
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let mut genesis = state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16)
            .map(|byte| state_processing::DirectGenesisValidator {
                public_key: PqPublicKey::deserialize(&[byte; 32])
                    .expect("canonical synthetic public key"),
                withdrawal_credentials: Hash256::ZERO,
            })
            .collect(),
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    genesis
        .build_all_committee_caches(&spec)
        .expect("genesis committee caches");
    let chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis)
            .expect("persist genesis")
            .pq_aggregation_service(Arc::new(
                AggregationService::new().expect("PQ aggregation service"),
            ))
            .task_executor(runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(Arc::new(UnusedValidTransport))
            .build()
            .expect("PQ chain"),
    );
    (chain, spec)
}

#[cfg(target_feature = "avx2")]
struct LiveSingleAttestationFixture {
    _temporary_directory: tempfile::TempDir,
    chain: Arc<beacon_chain::BeaconChain<TestWitness>>,
    processor: Arc<network::PqNetworkBlockProcessor<TestWitness>>,
    signed_block: Arc<SignedBeaconBlock<MinimalEthSpec>>,
    block_root: Hash256,
    genesis_root: Hash256,
    post_state: types::BeaconState<MinimalEthSpec>,
    attester_index: u64,
    authority: PqSigningAuthority,
    spec: Arc<ChainSpec>,
}

#[cfg(target_feature = "avx2")]
async fn live_single_attestation_fixture(
    runtime: &task_executor::test_utils::TestRuntime,
) -> LiveSingleAttestationFixture {
    const PASSWORD: &[u8] = b"correct horse battery staple";

    let temporary_directory = tempfile::TempDir::new().expect("temporary directory");
    let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let mut genesis = state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16)
            .map(|byte| state_processing::DirectGenesisValidator {
                public_key: PqPublicKey::deserialize(&[byte; 32])
                    .expect("canonical synthetic public key"),
                withdrawal_credentials: Hash256::ZERO,
            })
            .collect(),
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    genesis
        .build_all_committee_caches(&spec)
        .expect("genesis committee caches");
    let proposer_index = genesis
        .get_beacon_proposer_index(Slot::new(1), &spec)
        .expect("slot-one proposer");
    let attester_index = *genesis
        .get_beacon_committee(Slot::new(1), 0)
        .expect("slot-one committee")
        .committee
        .iter()
        .find(|validator_index| **validator_index != proposer_index)
        .expect("slot-one attester distinct from proposer");
    let maximum_leaf = [SigningDuty::BeaconBlockProposal, SigningDuty::Attestation]
        .into_iter()
        .map(|duty| {
            OneTimeUseId::for_lean_pq_devnet_v1(1, duty)
                .expect("slot-one V1 leaf")
                .as_u32()
        })
        .max()
        .expect("nonempty duty set");
    let proposer_keystore = PqKeystore::from_seed([0xa5; 32], 0..=maximum_leaf, PASSWORD)
        .expect("fixture proposer keystore");
    let proposer_authenticated = proposer_keystore
        .authenticate(PASSWORD)
        .expect("authenticated proposer key");
    let attester_keystore = PqKeystore::from_seed([0xb5; 32], 0..=maximum_leaf, PASSWORD)
        .expect("fixture attester keystore");
    let attester_authenticated = attester_keystore
        .authenticate(PASSWORD)
        .expect("authenticated attester key");
    genesis
        .validators_mut()
        .get_mut(proposer_index)
        .expect("proposer validator")
        .pubkey = *proposer_authenticated.public_key();
    genesis
        .validators_mut()
        .get_mut(attester_index)
        .expect("attester validator")
        .pubkey = *attester_authenticated.public_key();
    let genesis_validators_root = genesis.genesis_validators_root().0;
    provision_usage_journal(
        &journal_path,
        genesis_validators_root,
        &[proposer_authenticated, attester_authenticated],
    )
    .expect("usage journal");
    let authority = PqSigningAuthority::open(
        &journal_path,
        genesis_validators_root,
        vec![
            PqKeyUnlock::new(proposer_keystore, PASSWORD).expect("proposer unlock"),
            PqKeyUnlock::new(attester_keystore, PASSWORD).expect("attester unlock"),
        ],
    )
    .expect("signing authority");
    let aggregation_service = Arc::new(AggregationService::new().expect("PQ aggregation service"));
    let chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist genesis")
            .pq_aggregation_service(Arc::clone(&aggregation_service))
            .task_executor(runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(Arc::new(UnusedValidTransport))
            .build()
            .expect("PQ chain"),
    );
    let genesis_root = chain.head_snapshot().beacon_block_root;
    let mut pre_state = genesis;
    state_processing::per_slot_processing_pq(&mut pre_state, &spec)
        .expect("advance exact parent state");
    let sign = |duty: SigningDuty, signing_root: [u8; 32]| {
        let public_key = pre_state
            .validators()
            .get(proposer_index)
            .expect("proposer validator")
            .pubkey;
        authority
            .signer(&public_key)
            .expect("bound signer")
            .sign(consensus_signature::pq::PqSigningClaim::new(
                signing_root,
                OneTimeUseId::for_lean_pq_devnet_v1(1, duty).expect("V1 leaf"),
            ))
            .expect("journal-backed signature")
    };
    let randao_domain = spec.get_domain(
        pre_state.current_epoch(),
        Domain::Randao,
        &pre_state.fork(),
        pre_state.genesis_validators_root(),
    );
    let randao_signature = sign(
        SigningDuty::RandaoReveal,
        pre_state.current_epoch().signing_root(randao_domain).0,
    );
    let verified_randao = state_processing::prepare_pq_randao(
        &pre_state,
        Arc::clone(&chain.pq_validator_key_cache),
        Slot::new(1),
        randao_signature.clone(),
        Arc::clone(&spec),
    )
    .expect("prepared RANDAO")
    .verify(&aggregation_service)
    .await
    .expect("verified RANDAO");

    let mut block: BeaconBlock<MinimalEthSpec> = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(inner) = &mut block else {
        panic!("Electra fixture")
    };
    inner.slot = Slot::new(1);
    inner.proposer_index = proposer_index as u64;
    inner.parent_root = genesis_root;
    inner.body.randao_reveal = randao_signature;
    inner.body.execution_payload.execution_payload.timestamp = pre_state
        .genesis_time()
        .checked_add(spec.get_slot_duration().as_secs())
        .expect("slot-one timestamp");
    inner.body.execution_payload.execution_payload.prev_randao = *pre_state
        .get_randao_mix(pre_state.current_epoch())
        .expect("current RANDAO mix");
    inner.body.execution_payload.execution_payload.block_hash =
        execution_layer::calculate_execution_block_hash(
            ExecutionPayloadRef::Electra(&inner.body.execution_payload.execution_payload),
            Some(inner.parent_root),
            Some(&inner.body.execution_requests),
        )
        .0;
    let local =
        state_processing::prepare_pq_local_block(&pre_state, block, verified_randao, vec![])
            .expect("sealed local block");
    let mut post_state = pre_state.clone();
    let local_output = state_processing::per_block_processing_pq_local(&mut post_state, local)
        .expect("local transition");
    let (mut block, _) = local_output.into_parts();
    *block.state_root_mut() = post_state.canonical_root().expect("post-state root");
    let proposal_domain = spec.get_domain(
        pre_state.current_epoch(),
        Domain::BeaconProposer,
        &pre_state.fork(),
        pre_state.genesis_validators_root(),
    );
    let proposal_signature = sign(
        SigningDuty::BeaconBlockProposal,
        block.signing_root(proposal_domain).0,
    );
    let signed_block = Arc::new(SignedBeaconBlock::from_block(block, proposal_signature));
    let block_root = signed_block.canonical_root();
    let processor = Arc::new(network::PqNetworkBlockProcessor::new(Arc::clone(&chain)));
    LiveSingleAttestationFixture {
        _temporary_directory: temporary_directory,
        chain,
        processor,
        signed_block,
        block_root,
        genesis_root,
        post_state,
        attester_index: attester_index as u64,
        authority,
        spec,
    }
}

#[cfg(target_feature = "avx2")]
fn slot_one_single_attestation(
    fixture: &LiveSingleAttestationFixture,
) -> (SingleAttestation, SubnetId) {
    let data = AttestationData {
        slot: Slot::new(1),
        index: 0,
        beacon_block_root: fixture.block_root,
        source: Checkpoint::default(),
        target: Checkpoint {
            epoch: types::Epoch::new(0),
            root: fixture.genesis_root,
        },
    };
    let domain = fixture.spec.get_domain(
        types::Epoch::new(0),
        Domain::BeaconAttester,
        &fixture.post_state.fork(),
        fixture.post_state.genesis_validators_root(),
    );
    let public_key = fixture
        .post_state
        .validators()
        .get(fixture.attester_index as usize)
        .expect("attester validator")
        .pubkey;
    let signature = fixture
        .authority
        .signer(&public_key)
        .expect("bound attester signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            data.signing_root(domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::Attestation)
                .expect("slot-one attestation leaf"),
        ))
        .expect("attestation signature");
    let single = SingleAttestation {
        committee_index: 0,
        attester_index: fixture.attester_index,
        data,
        signature: (&signature).into(),
    };
    let subnet = SubnetId::compute_subnet_for_single_attestation::<MinimalEthSpec>(
        &single,
        fixture
            .post_state
            .get_committee_count_at_slot(Slot::new(1))
            .expect("slot-one committee count"),
        &fixture.spec,
    )
    .expect("slot-one subnet");
    (single, subnet)
}

#[cfg(target_feature = "avx2")]
async fn start_network_service(
    runtime: &task_executor::test_utils::TestRuntime,
    chain: Arc<beacon_chain::BeaconChain<TestWitness>>,
    spec: Arc<ChainSpec>,
    boot_nodes: Vec<lighthouse_network::Enr>,
    disable_discovery: bool,
    encoding_hook: Option<Arc<dyn Fn() + Send + Sync>>,
) -> (
    network::PqBlockBroadcastSender<MinimalEthSpec>,
    network::PqTestingAttestationPublishSender<MinimalEthSpec>,
    Arc<lighthouse_network::NetworkGlobals<MinimalEthSpec>>,
    tokio::sync::mpsc::Sender<lighthouse_network::Multiaddr>,
    Arc<lighthouse_network::PqGossipValidationAdmission>,
    Arc<beacon_chain::PqOperationalEventSink>,
) {
    start_network_service_with_topics(
        runtime,
        chain,
        spec,
        boot_nodes,
        disable_discovery,
        encoding_hook,
        vec![],
    )
    .await
}

#[cfg(target_feature = "avx2")]
async fn start_network_service_with_topics(
    runtime: &task_executor::test_utils::TestRuntime,
    chain: Arc<beacon_chain::BeaconChain<TestWitness>>,
    spec: Arc<ChainSpec>,
    boot_nodes: Vec<lighthouse_network::Enr>,
    disable_discovery: bool,
    encoding_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    configured_topics: Vec<GossipKind>,
) -> (
    network::PqBlockBroadcastSender<MinimalEthSpec>,
    network::PqTestingAttestationPublishSender<MinimalEthSpec>,
    Arc<lighthouse_network::NetworkGlobals<MinimalEthSpec>>,
    tokio::sync::mpsc::Sender<lighthouse_network::Multiaddr>,
    Arc<lighthouse_network::PqGossipValidationAdmission>,
    Arc<beacon_chain::PqOperationalEventSink>,
) {
    let head = chain.head_snapshot();
    let genesis_validators_root = head.beacon_state.genesis_validators_root();
    let mut network_config = NetworkConfig::default();
    network_config.set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, 0, 0, 0);
    network_config.enr_address = (Some(std::net::Ipv4Addr::LOCALHOST), None);
    network_config.boot_nodes_enr = boot_nodes;
    network_config.disable_discovery = disable_discovery;
    network_config.topics = configured_topics;
    network_config.network_dir = tempfile::TempDir::new().expect("network directory").keep();
    let network_config = Arc::new(network_config);
    let context = Context {
        config: network_config,
        enr_fork_id: spec
            .enr_fork_id::<MinimalEthSpec>(head.beacon_block.slot(), genesis_validators_root),
        fork_context: Arc::new(ForkContext::new::<MinimalEthSpec>(
            head.beacon_block.slot(),
            genesis_validators_root,
            &spec,
        )),
        chain_spec: Arc::clone(&spec),
        libp2p_registry: None,
    };
    let (broadcast_sender, broadcast_receiver) = pq_block_broadcast_channel();
    let operational_events = testing_only_running_pq_operational_event_sink(&runtime.task_executor);
    let mut service = PqNetworkService::new(
        runtime.task_executor.clone(),
        context,
        spec.custody_requirement,
        secp256k1::Keypair::generate().into(),
        chain,
        broadcast_receiver,
        Arc::clone(&operational_events),
    )
    .await
    .expect("PQ network service");
    if let Some(hook) = encoding_hook {
        service.testing_only_set_block_encoding_hook(hook);
    }
    let globals = service.network_globals();
    let attestation_sender = service.testing_only_attestation_publish_sender();
    let dial_sender = service.testing_only_dial_sender();
    let gossip_admission = service.testing_only_gossip_admission();
    service.start().expect("start PQ network service");
    (
        broadcast_sender,
        attestation_sender,
        globals,
        dial_sender,
        gossip_admission,
        operational_events,
    )
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_network_subscribes_only_block_and_all_minimal_attestation_subnets() {
    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let fork_digest = spec
        .enr_fork_id::<MinimalEthSpec>(
            chain.head_snapshot().beacon_block.slot(),
            chain.head_snapshot().beacon_state.genesis_validators_root(),
        )
        .fork_digest;
    let (_sender, _attestation_sender, globals, _dial_sender, _admission, _events) =
        start_network_service_with_topics(
            &runtime,
            chain,
            spec,
            vec![],
            true,
            None,
            vec![
                GossipKind::BeaconAggregateAndProof,
                GossipKind::VoluntaryExit,
            ],
        )
        .await;

    let subscriptions = globals.gossipsub_subscriptions.read();
    assert_eq!(subscriptions.len(), 9);
    assert!(subscriptions.contains(&GossipTopic::new(
        GossipKind::BeaconBlock,
        GossipEncoding::default(),
        fork_digest,
    )));
    for subnet in 0..8 {
        assert!(subscriptions.contains(&GossipTopic::new(
            GossipKind::Attestation(types::SubnetId::new(subnet)),
            GossipEncoding::default(),
            fork_digest,
        )));
    }
    assert!(!subscriptions.contains(&GossipTopic::new(
        GossipKind::BeaconAggregateAndProof,
        GossipEncoding::default(),
        fork_digest,
    )));
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn result_bearing_network_start_confirms_owner_shutdown() {
    use std::sync::{Condvar, Mutex};

    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let (lock, condition) = &*self.0;
            *lock.lock().expect("release lock") = true;
            condition.notify_all();
        }
    }

    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let head = chain.head_snapshot();
    let block = Arc::clone(&head.beacon_block);
    let genesis_validators_root = head.beacon_state.genesis_validators_root();
    let mut network_config = NetworkConfig::default();
    network_config.set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, 0, 0, 0);
    network_config.enr_address = (Some(std::net::Ipv4Addr::LOCALHOST), None);
    network_config.disable_discovery = true;
    network_config.network_dir = tempfile::TempDir::new().expect("network directory").keep();
    let context = Context {
        config: Arc::new(network_config),
        enr_fork_id: spec
            .enr_fork_id::<MinimalEthSpec>(head.beacon_block.slot(), genesis_validators_root),
        fork_context: Arc::new(ForkContext::new::<MinimalEthSpec>(
            head.beacon_block.slot(),
            genesis_validators_root,
            &spec,
        )),
        chain_spec: spec,
        libp2p_registry: None,
    };
    let (broadcast_sender, broadcast_receiver) = pq_block_broadcast_channel();
    let (network_runtime_owner, network_exit) = async_channel::bounded(1);
    let (network_shutdown_sender, _) = futures::channel::mpsc::channel(1);
    let network_executor = task_executor::TaskExecutor::new(
        tokio::runtime::Handle::current(),
        network_exit,
        network_shutdown_sender,
    );
    let mut service = PqNetworkService::new(
        network_executor,
        context,
        MinimalEthSpec::default_spec().custody_requirement,
        secp256k1::Keypair::generate().into(),
        chain,
        broadcast_receiver,
        testing_only_running_pq_operational_event_sink(&runtime.task_executor),
    )
    .await
    .expect("PQ network service");
    assert!(
        service
            .testing_only_gossip_admission()
            .try_add_compatible(lighthouse_network::PeerId::random())
    );
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let _release_on_drop = ReleaseOnDrop(Arc::clone(&release));
    let (entered_sender, mut entered_receiver) = tokio::sync::mpsc::unbounded_channel();
    let hook = {
        let release = Arc::clone(&release);
        Arc::new(move || {
            entered_sender.send(()).expect("shutdown test alive");
            let (lock, condition) = &*release;
            let mut released = lock.lock().expect("release lock");
            while !*released {
                released = condition.wait(released).expect("release wait");
            }
        }) as Arc<dyn Fn() + Send + Sync>
    };
    service.testing_only_set_block_encoding_hook(hook);

    let shutdown = service
        .start_with_shutdown_receipt()
        .await
        .expect("result-bearing network start");
    let retained_sender = broadcast_sender.clone();
    let pending = broadcast_sender
        .try_send(Arc::clone(&block))
        .expect("bounded pending broadcast");
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_receiver.recv())
        .await
        .expect("encoding hook entered")
        .expect("encoding hook signal");
    let mut shutdown_task = tokio::spawn(shutdown.testing_only_wait_for_exit());
    drop(network_runtime_owner);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut shutdown_task)
            .await
            .is_err(),
        "shutdown must retain the in-flight encoder owner",
    );
    assert!(matches!(
        AggregationService::new(),
        Err(consensus_signature::AggregationError::AlreadyActive),
    ));
    {
        let (lock, condition) = &*release;
        *lock.lock().expect("release lock") = true;
        condition.notify_all();
    }
    assert_eq!(
        pending.wait().await,
        Err(PqBlockBroadcastError::WorkerUnavailable),
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), shutdown_task)
        .await
        .expect("network owner shutdown")
        .expect("shutdown task")
        .expect("network worker result");
    assert!(matches!(
        retained_sender.try_send(block),
        Err(PqBlockBroadcastError::WorkerUnavailable),
    ));
    drop(AggregationService::new().expect("aggregation owner released after drain"));
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn result_bearing_network_start_rejects_executor_shutdown_before_first_poll() {
    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let head = chain.head_snapshot();
    let genesis_validators_root = head.beacon_state.genesis_validators_root();
    let mut network_config = NetworkConfig::default();
    network_config.set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, 0, 0, 0);
    network_config.enr_address = (Some(std::net::Ipv4Addr::LOCALHOST), None);
    network_config.disable_discovery = true;
    network_config.network_dir = tempfile::TempDir::new().expect("network directory").keep();
    let context = Context {
        config: Arc::new(network_config),
        enr_fork_id: spec
            .enr_fork_id::<MinimalEthSpec>(head.beacon_block.slot(), genesis_validators_root),
        fork_context: Arc::new(ForkContext::new::<MinimalEthSpec>(
            head.beacon_block.slot(),
            genesis_validators_root,
            &spec,
        )),
        chain_spec: Arc::clone(&spec),
        libp2p_registry: None,
    };
    let (runtime_owner, exit) = async_channel::bounded(1);
    let (shutdown_sender, _) = futures::channel::mpsc::channel(1);
    let shutting_down_executor =
        task_executor::TaskExecutor::new(tokio::runtime::Handle::current(), exit, shutdown_sender);
    let (_broadcast_sender, broadcast_receiver) = pq_block_broadcast_channel();
    let service = PqNetworkService::new(
        shutting_down_executor,
        context,
        spec.custody_requirement,
        secp256k1::Keypair::generate().into(),
        chain,
        broadcast_receiver,
        testing_only_running_pq_operational_event_sink(&runtime.task_executor),
    )
    .await
    .expect("PQ network service");
    drop(runtime_owner);

    assert!(matches!(
        service.start_with_shutdown_receipt().await,
        Err(PqNetworkServiceError::TaskUnavailable),
    ));
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn result_bearing_network_start_reports_worker_panic_through_task_executor() {
    use futures::StreamExt;

    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let head = chain.head_snapshot();
    let genesis_validators_root = head.beacon_state.genesis_validators_root();
    let mut network_config = NetworkConfig::default();
    network_config.set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, 0, 0, 0);
    network_config.enr_address = (Some(std::net::Ipv4Addr::LOCALHOST), None);
    network_config.disable_discovery = true;
    network_config.network_dir = tempfile::TempDir::new().expect("network directory").keep();
    let context = Context {
        config: Arc::new(network_config),
        enr_fork_id: spec
            .enr_fork_id::<MinimalEthSpec>(head.beacon_block.slot(), genesis_validators_root),
        fork_context: Arc::new(ForkContext::new::<MinimalEthSpec>(
            head.beacon_block.slot(),
            genesis_validators_root,
            &spec,
        )),
        chain_spec: Arc::clone(&spec),
        libp2p_registry: None,
    };
    let (_runtime_owner, exit) = async_channel::bounded(1);
    let (shutdown_sender, mut shutdown_receiver) = futures::channel::mpsc::channel(1);
    let monitored_executor =
        task_executor::TaskExecutor::new(tokio::runtime::Handle::current(), exit, shutdown_sender);
    let (_broadcast_sender, broadcast_receiver) = pq_block_broadcast_channel();
    let mut service = PqNetworkService::new(
        monitored_executor,
        context,
        spec.custody_requirement,
        secp256k1::Keypair::generate().into(),
        chain,
        broadcast_receiver,
        testing_only_running_pq_operational_event_sink(&runtime.task_executor),
    )
    .await
    .expect("PQ network service");
    service.testing_only_set_run_hook(Arc::new(|| panic!("PQ network worker panic")));

    assert!(matches!(
        service.start_with_shutdown_receipt().await,
        Err(PqNetworkServiceError::TaskUnavailable),
    ));
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), shutdown_receiver.next())
            .await
            .expect("panic monitor notification"),
        Some(task_executor::ShutdownReason::Failure(
            "Panic (fatal error)"
        )),
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn live_worker_negatively_acknowledges_exact_block_without_peers() {
    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let genesis_root = chain.head_snapshot().beacon_block_root;
    let (
        sender,
        _attestation_sender,
        _globals,
        _dial_sender,
        gossip_admission,
        _operational_events,
    ) = start_network_service(
        &runtime,
        Arc::clone(&chain),
        Arc::clone(&spec),
        vec![],
        true,
        None,
    )
    .await;
    let block = Arc::new(SignedBeaconBlock::from_block(
        BeaconBlock::empty(&spec),
        IndividualSignature::empty(),
    ));
    let acknowledgement = sender.try_send(block).expect("bounded broadcast ingress");
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), acknowledgement.wait())
            .await
            .expect("worker acknowledgement"),
        Err(PqBlockBroadcastError::Rejected),
    );
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert_eq!(gossip_admission.testing_only_active_total(), 0);
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn live_workers_status_and_acknowledge_publish_and_exact_duplicate() {
    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let (
        _receiver_sender,
        _receiver_attestation_sender,
        receiver_globals,
        _receiver_dial,
        receiver_admission,
        receiver_events,
    ) = start_network_service(
        &runtime,
        Arc::clone(&chain),
        Arc::clone(&spec),
        vec![],
        false,
        None,
    )
    .await;
    let receiver_address = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let enr = receiver_globals.local_enr();
            if let Some(address) = enr.multiaddr_p2p_tcp().into_iter().next() {
                break address;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receiver listening ENR");
    let (sender, _attestation_sender, sender_globals, sender_dial, sender_admission, sender_events) =
        start_network_service(&runtime, chain, Arc::clone(&spec), vec![], true, None).await;
    sender_dial
        .try_send(receiver_address)
        .expect("bounded testing dial command");
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while sender_globals.connected_peers() == 0 || receiver_globals.connected_peers() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("PQ status-compatible peers connect");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !sender_admission.has_compatible_peers()
            || !receiver_admission.has_compatible_peers()
            || sender_events.testing_only_peer_compatible_count() != 1
            || receiver_events.testing_only_peer_compatible_count() != 1
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("outbound Status response marks the receiver compatible");

    let block = Arc::new(SignedBeaconBlock::from_block(
        BeaconBlock::empty(&spec),
        IndividualSignature::empty(),
    ));
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let acknowledgement = sender
                .try_send(Arc::clone(&block))
                .expect("bounded broadcast ingress");
            if acknowledgement.wait().await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("initial publication must become publishable after topic subscription");

    let acknowledgement = sender
        .try_send(Arc::clone(&block))
        .expect("bounded broadcast ingress");
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), acknowledgement.wait())
            .await
            .expect("exact duplicate acknowledgement"),
        Ok(()),
        "exact duplicate must be positively acknowledged",
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn live_workers_route_one_authentic_single_to_fork_choice_exactly_once() {
    let runtime = task_executor::test_utils::TestRuntime::default();
    let fixture = live_single_attestation_fixture(&runtime).await;
    fixture.chain.slot_clock.set_slot(1);
    tokio::time::timeout(
        std::time::Duration::from_secs(240),
        fixture
            .processor
            .import_rpc_block(Arc::clone(&fixture.signed_block)),
    )
    .await
    .expect("slot-one block proof deadline")
    .expect("real imported slot-one block");
    assert!(
        fixture
            .chain
            .testing_only_pq_fork_choice_contains_block(fixture.block_root)
    );
    let (single, subnet) = slot_one_single_attestation(&fixture);

    let (
        receiver_block_sender,
        _receiver_attestation_sender,
        receiver_globals,
        _receiver_dial,
        receiver_admission,
        receiver_events,
    ) = start_network_service(
        &runtime,
        Arc::clone(&fixture.chain),
        Arc::clone(&fixture.spec),
        vec![],
        false,
        None,
    )
    .await;
    let receiver_address = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(address) = receiver_globals
                .local_enr()
                .multiaddr_p2p_tcp()
                .into_iter()
                .next()
            {
                break address;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receiver listening ENR");
    let (
        _sender_block_sender,
        attestation_sender,
        sender_globals,
        sender_dial,
        sender_admission,
        sender_events,
    ) = start_network_service(
        &runtime,
        Arc::clone(&fixture.chain),
        Arc::clone(&fixture.spec),
        vec![],
        true,
        None,
    )
    .await;
    sender_dial
        .try_send(receiver_address)
        .expect("bounded testing dial command");
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while sender_globals.connected_peers() == 0 || receiver_globals.connected_peers() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("PQ workers connect");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !sender_admission.has_compatible_peers()
            || !receiver_admission.has_compatible_peers()
            || sender_events.testing_only_peer_compatible_count() != 1
            || receiver_events.testing_only_peer_compatible_count() != 1
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both PQ workers admit compatible Status");

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let acknowledgement = attestation_sender
                .try_send(single.clone(), subnet)
                .expect("bounded attestation publication ingress");
            match acknowledgement.wait().await {
                Ok(()) => break,
                Err(network::PqTestingAttestationPublishError::NoPeersSubscribed) => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("attestation publication failed: {error:?}"),
            }
        }
    })
    .await
    .expect("attestation subnet publication becomes live");
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while receiver_admission.testing_only_active_total() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receiver retains one admitted attestation during proof");
    let progress = receiver_block_sender
        .try_send(Arc::clone(&fixture.signed_block))
        .expect("receiver broadcaster remains responsive");
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), progress.wait())
            .await
            .expect("receiver network loop progress during attestation proof"),
        Ok(()),
    );
    tokio::time::timeout(std::time::Duration::from_secs(240), async {
        while fixture
            .chain
            .testing_only_pq_fork_choice_attestation_calls()
            != 1
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receiver verifies and consumes authentic single");
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_fork_choice_queued_attestation_count(),
        1,
    );
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_fork_choice_latest_message(fixture.attester_index),
        None,
    );

    fixture.chain.slot_clock.set_slot(2);
    fixture
        .chain
        .on_pq_fork_choice_tick(Slot::new(2))
        .await
        .expect("checked slot-two tick");
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_fork_choice_latest_message(fixture.attester_index),
        Some((Slot::new(1), fixture.block_root)),
    );
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_fork_choice_attestation_calls(),
        1,
    );

    let duplicate = attestation_sender
        .try_send(single, subnet)
        .expect("bounded exact duplicate publication");
    assert_eq!(
        duplicate.wait().await,
        Err(network::PqTestingAttestationPublishError::Duplicate),
    );
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_fork_choice_attestation_calls(),
        1,
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn block_encoding_is_cap_two_offloop_and_poll_loop_remains_responsive() {
    use std::sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let (
        _receiver_sender,
        _receiver_attestation_sender,
        receiver_globals,
        _receiver_dial,
        _receiver_admission,
        _receiver_events,
    ) = start_network_service(
        &runtime,
        Arc::clone(&chain),
        Arc::clone(&spec),
        vec![],
        false,
        None,
    )
    .await;
    let receiver_address = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let enr = receiver_globals.local_enr();
            if let Some(address) = enr.multiaddr_p2p_tcp().into_iter().next() {
                break address;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receiver listening ENR");

    let armed = Arc::new(AtomicBool::new(false));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let (entered_sender, mut entered_receiver) = tokio::sync::mpsc::unbounded_channel();
    let hook = {
        let armed = Arc::clone(&armed);
        let release = Arc::clone(&release);
        Arc::new(move || {
            if !armed.load(Ordering::SeqCst) {
                return;
            }
            entered_sender.send(()).expect("test observer alive");
            let (lock, condition) = &*release;
            let mut released = lock.lock().expect("release lock");
            while !*released {
                released = condition.wait(released).expect("release wait");
            }
        }) as Arc<dyn Fn() + Send + Sync>
    };
    let (
        sender,
        _attestation_sender,
        sender_globals,
        sender_dial,
        sender_admission,
        _sender_events,
    ) = start_network_service(&runtime, chain, Arc::clone(&spec), vec![], true, Some(hook)).await;
    sender_dial
        .try_send(receiver_address)
        .expect("bounded testing dial command");
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while sender_globals.connected_peers() == 0 || receiver_globals.connected_peers() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("PQ workers connect");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !sender_admission.has_compatible_peers() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("outbound Status response marks the receiver compatible");

    let mut unsigned = BeaconBlock::<MinimalEthSpec>::empty(&spec);
    match unsigned.body_mut() {
        types::BeaconBlockBodyRefMut::Electra(body) => body
            .execution_payload
            .execution_payload
            .transactions
            .push(
                vec![0x5a; 2_000_000]
                    .try_into()
                    .expect("bounded transaction"),
            )
            .expect("transaction capacity"),
        _ => panic!("expected Electra body"),
    }
    let block = Arc::new(SignedBeaconBlock::from_block(
        unsigned,
        IndividualSignature::empty(),
    ));
    assert!(
        block.as_ssz_bytes().len() > 1_000_000,
        "fixture must exercise a large PQ evidence body",
    );
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let acknowledgement = sender
                .try_send(Arc::clone(&block))
                .expect("bounded broadcast ingress");
            if acknowledgement.wait().await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("status and subscription become publishable");

    armed.store(true, Ordering::SeqCst);
    let first = sender
        .try_send(Arc::clone(&block))
        .expect("first encoding admission");
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_receiver.recv())
        .await
        .expect("first encoder enters")
        .expect("first encoder observer");
    let second = sender
        .try_send(Arc::clone(&block))
        .expect("second encoding admission");
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_receiver.recv())
        .await
        .expect("second encoder enters while the first is blocked")
        .expect("second encoder observer");
    let third = sender
        .try_send(Arc::clone(&block))
        .expect("broadcast queue remains responsive");
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), third.wait())
            .await
            .expect("cap+1 acknowledgement while encoders are blocked"),
        Err(PqBlockBroadcastError::Capacity),
    );

    sender_admission.remove_compatible(&receiver_globals.local_enr().peer_id());
    let (lock, condition) = &*release;
    *lock.lock().expect("release lock") = true;
    condition.notify_all();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), first.wait())
            .await
            .expect("first acknowledgement"),
        Err(PqBlockBroadcastError::Rejected),
        "a peer lost after encoding started must prevent lower publication",
    );
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), second.wait())
            .await
            .expect("second acknowledgement"),
        Err(PqBlockBroadcastError::Rejected),
    );
}
