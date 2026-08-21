use lighthouse_network::service::Network;
use lighthouse_network::{PqEncodedSingleAttestation, PqSingleAttestationPublishOutcome};
use types::MinimalEthSpec;

#[test]
fn exact_pq_single_publish_api_is_result_bearing() {
    let _: fn(
        &mut Network<MinimalEthSpec>,
        &mut PqEncodedSingleAttestation,
    ) -> PqSingleAttestationPublishOutcome =
        Network::<MinimalEthSpec>::publish_pq_encoded_single_attestation;
}

#[cfg(feature = "pq-startup-testing")]
mod behavior {
    use super::*;
    use crate::common;
    use consensus_signature::{PqRawSignature, PqSameMessageEvidence};
    use lighthouse_network::libp2p::gossipsub::{
        AdmittedMessageReport, AdmittedMessageValidationOutcome,
    };
    use lighthouse_network::types::GossipKind;
    use lighthouse_network::{
        GossipTopic, NetworkEvent, PqTestingAttestationLowerPublishError, PubsubMessage,
    };
    use std::{sync::Arc, time::Duration};
    use tokio::runtime::Runtime;
    use types::{
        AttestationData, Checkpoint, EthSpec, ForkName, Hash256, SingleAttestation, Slot, SubnetId,
    };

    fn single(attester_index: u64) -> SingleAttestation {
        SingleAttestation {
            committee_index: 0,
            attester_index,
            data: AttestationData {
                slot: Slot::new(1),
                index: 0,
                beacon_block_root: Hash256::repeat_byte(0x42),
                source: Checkpoint::default(),
                target: Checkpoint::default(),
            },
            signature: PqSameMessageEvidence::from(&PqRawSignature::empty()),
        }
    }

    #[test]
    fn encoded_single_binds_exact_ssz_topic_and_fork_digest_before_publication() {
        let subnet = SubnetId::new(3);
        let fork_digest = [0x4a; 4];
        let single = single(7);
        let encoded = PqEncodedSingleAttestation::testing_only_encode::<MinimalEthSpec>(
            single.clone(),
            subnet,
            fork_digest,
        );
        let expected: PubsubMessage<MinimalEthSpec> =
            PubsubMessage::Attestation(Box::new((subnet, single)));
        let mut topic = GossipTopic::decode(encoded.topic_hash().as_str()).expect("exact topic");

        assert_eq!(
            encoded.as_ssz_bytes(),
            expected.encode(topic.encoding().clone())
        );
        assert_eq!(topic.kind(), &GossipKind::Attestation(subnet));
        assert_eq!(*topic.digest(), fork_digest);
        assert_eq!(encoded.fork_digest(), fork_digest);
    }

    #[test]
    fn oversized_exact_single_reports_transform_failure_with_its_message_id() {
        let runtime = Arc::new(Runtime::new().expect("test runtime"));
        let mut spec = ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000);
        spec.max_payload_size = 1;
        let spec = Arc::new(spec);

        runtime.block_on(async {
            let (mut publisher, _, _) = common::build_pq_libp2p_instance(
                Arc::downgrade(&runtime),
                ForkName::Electra,
                Arc::clone(&spec),
            )
            .await;
            let fork_digest = spec
                .enr_fork_id::<MinimalEthSpec>(spec.genesis_slot, Hash256::ZERO)
                .fork_digest;
            let mut encoded = PqEncodedSingleAttestation::testing_only_encode::<MinimalEthSpec>(
                single(0),
                SubnetId::new(0),
                fork_digest,
            );

            let outcome = publisher.publish_pq_encoded_single_attestation(&mut encoded);
            assert!(
                matches!(
                &outcome,
                PqSingleAttestationPublishOutcome::Transform {
                    message_id,
                    error_kind: std::io::ErrorKind::InvalidData,
                } if !message_id.0.is_empty()
                ),
                "unexpected exact oversized outcome: {outcome:?}",
            );
        });
    }

    #[test]
    fn no_peers_rolls_back_then_publish_and_exact_local_duplicate_are_source_aware() {
        let runtime = Arc::new(Runtime::new().expect("test runtime"));
        let spec = Arc::new(
            ForkName::Electra
                .make_genesis_spec(MinimalEthSpec::default_spec())
                .set_slot_duration_ms::<MinimalEthSpec>(300_000),
        );

        runtime.block_on(async {
            let (mut publisher, compatible, _) = common::build_pq_libp2p_instance(
                Arc::downgrade(&runtime),
                ForkName::Electra,
                Arc::clone(&spec),
            )
            .await;
            let subnet = SubnetId::new(0);
            let fork_digest = spec
                .enr_fork_id::<MinimalEthSpec>(spec.genesis_slot, Hash256::ZERO)
                .fork_digest;
            let mut encoded = PqEncodedSingleAttestation::testing_only_encode::<MinimalEthSpec>(
                single(0),
                subnet,
                fork_digest,
            );
            let first_id = match publisher.publish_pq_encoded_single_attestation(&mut encoded) {
                PqSingleAttestationPublishOutcome::NoPeers { message_id } => message_id,
                other => panic!("unexpected initial outcome: {other:?}"),
            };

            let (mut receiver, _, receiver_peer) = common::build_pq_libp2p_instance(
                Arc::downgrade(&runtime),
                ForkName::Electra,
                Arc::clone(&spec),
            )
            .await;
            assert!(receiver.subscribe_kind(GossipKind::Attestation(subnet)));
            let receiver_address = loop {
                if let NetworkEvent::NewListenAddr(address) = receiver.next_event().await
                    && address
                        .iter()
                        .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::Tcp(_)))
                {
                    break address;
                }
            };
            publisher
                .testing_dial(receiver_address)
                .expect("publisher dials receiver");
            assert!(compatible.try_add_compatible(receiver_peer));

            let deadline = tokio::time::sleep(Duration::from_secs(10));
            tokio::pin!(deadline);
            let published_id = loop {
                match publisher.publish_pq_encoded_single_attestation(&mut encoded) {
                    PqSingleAttestationPublishOutcome::Published { message_id } => {
                        break message_id;
                    }
                    PqSingleAttestationPublishOutcome::NoPeers { message_id } => {
                        assert_eq!(message_id, first_id);
                    }
                    other => panic!("unexpected retry outcome: {other:?}"),
                }
                tokio::select! {
                    _ = publisher.next_event() => {}
                    _ = receiver.next_event() => {}
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                    _ = &mut deadline => panic!("receiver did not become publishable"),
                }
            };
            assert_eq!(published_id, first_id);
            assert_eq!(
                publisher.publish_pq_encoded_single_attestation(&mut encoded),
                PqSingleAttestationPublishOutcome::DuplicateLocal {
                    message_id: first_id.clone(),
                },
            );

            let mut different = PqEncodedSingleAttestation::testing_only_encode::<MinimalEthSpec>(
                single(1),
                subnet,
                fork_digest,
            );
            assert!(matches!(
                publisher.publish_pq_encoded_single_attestation(&mut different),
                PqSingleAttestationPublishOutcome::Published { message_id }
                    if message_id != first_id
            ));
        });
    }

    #[test]
    fn seventh_unique_local_single_reports_validation_admission_full() {
        let runtime = Arc::new(Runtime::new().expect("test runtime"));
        let spec = Arc::new(
            ForkName::Electra
                .make_genesis_spec(MinimalEthSpec::default_spec())
                .set_slot_duration_ms::<MinimalEthSpec>(300_000),
        );

        runtime.block_on(async {
            let (mut publisher, compatible, _) = common::build_pq_libp2p_instance(
                Arc::downgrade(&runtime),
                ForkName::Electra,
                Arc::clone(&spec),
            )
            .await;
            let (mut receiver, _, receiver_peer) = common::build_pq_libp2p_instance(
                Arc::downgrade(&runtime),
                ForkName::Electra,
                Arc::clone(&spec),
            )
            .await;
            let subnet = SubnetId::new(0);
            assert!(receiver.subscribe_kind(GossipKind::Attestation(subnet)));
            let receiver_address = loop {
                if let NetworkEvent::NewListenAddr(address) = receiver.next_event().await
                    && address
                        .iter()
                        .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::Tcp(_)))
                {
                    break address;
                }
            };
            publisher
                .testing_dial(receiver_address)
                .expect("publisher dials receiver");
            assert!(compatible.try_add_compatible(receiver_peer));
            let fork_digest = spec
                .enr_fork_id::<MinimalEthSpec>(spec.genesis_slot, Hash256::ZERO)
                .fork_digest;
            let deadline = tokio::time::sleep(Duration::from_secs(10));
            tokio::pin!(deadline);

            for attester_index in 0_u64..6 {
                loop {
                    let mut encoded = PqEncodedSingleAttestation::testing_only_encode::<
                        MinimalEthSpec,
                    >(
                        single(attester_index), subnet, fork_digest
                    );
                    match publisher.publish_pq_encoded_single_attestation(&mut encoded) {
                        PqSingleAttestationPublishOutcome::Published { .. } => break,
                        PqSingleAttestationPublishOutcome::NoPeers { .. } => {}
                        other => panic!("unexpected publication below local cap: {other:?}"),
                    }
                    tokio::select! {
                        _ = publisher.next_event() => {}
                        _ = receiver.next_event() => {}
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                        _ = &mut deadline => panic!("receiver did not become publishable"),
                    }
                }
            }

            let mut seventh = PqEncodedSingleAttestation::testing_only_encode::<MinimalEthSpec>(
                single(6),
                subnet,
                fork_digest,
            );
            assert!(matches!(
                publisher.publish_pq_encoded_single_attestation(&mut seventh),
                PqSingleAttestationPublishOutcome::ValidationAdmissionFull { message_id }
                    if !message_id.0.is_empty()
            ));
        });
    }

    #[test]
    fn pending_retained_and_retryable_remote_ids_have_exact_lower_outcomes() {
        let runtime = Arc::new(Runtime::new().expect("test runtime"));
        let spec = Arc::new(
            ForkName::Electra
                .make_genesis_spec(MinimalEthSpec::default_spec())
                .set_slot_duration_ms::<MinimalEthSpec>(300_000),
        );

        runtime.block_on(async {
            let (mut remote, remote_compatible, remote_peer) =
                common::build_pq_libp2p_instance(
                    Arc::downgrade(&runtime),
                    ForkName::Electra,
                    Arc::clone(&spec),
                )
                .await;
            let (mut local, local_compatible, local_peer) = common::build_pq_libp2p_instance(
                Arc::downgrade(&runtime),
                ForkName::Electra,
                Arc::clone(&spec),
            )
            .await;
            let subnet = SubnetId::new(0);
            assert!(remote.subscribe_kind(GossipKind::Attestation(subnet)));
            assert!(local.subscribe_kind(GossipKind::Attestation(subnet)));
            let local_address = loop {
                if let NetworkEvent::NewListenAddr(address) = local.next_event().await
                    && address
                        .iter()
                        .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::Tcp(_)))
                {
                    break address;
                }
            };
            remote
                .testing_dial(local_address)
                .expect("remote dials local");
            assert!(remote_compatible.try_add_compatible(local_peer));
            assert!(local_compatible.try_add_compatible(remote_peer));
            let fork_digest = spec
                .enr_fork_id::<MinimalEthSpec>(spec.genesis_slot, Hash256::ZERO)
                .fork_digest;
            let encoded = |attester_index| {
                PqEncodedSingleAttestation::testing_only_encode::<MinimalEthSpec>(
                    single(attester_index),
                    subnet,
                    fork_digest,
                )
            };
            let deadline = tokio::time::sleep(Duration::from_secs(10));
            tokio::pin!(deadline);

            for (attester_index, terminal) in [(2_u64, true), (3_u64, false)] {
                loop {
                    match remote
                        .testing_only_publish_pq_attestation(single(attester_index), subnet)
                    {
                        Ok(()) | Err(PqTestingAttestationLowerPublishError::Duplicate) => break,
                        Err(PqTestingAttestationLowerPublishError::NoPeersSubscribed) => {}
                        Err(error) => panic!("unexpected remote publish failure: {error:?}"),
                    }
                    tokio::select! {
                        _ = remote.next_event() => {}
                        _ = local.next_event() => {}
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                        _ = &mut deadline => panic!("remote did not become publishable"),
                    }
                }

                let remote_id = loop {
                    tokio::select! {
                        _ = remote.next_event() => {}
                        event = local.next_event() => {
                            if let NetworkEvent::PubsubMessage { id, message, pq_admitted, .. } = event
                                && matches!(message, lighthouse_network::PubsubMessage::Attestation(single_message) if single_message.1.attester_index == attester_index)
                            {
                                assert!(pq_admitted);
                                break id;
                            }
                        }
                        _ = &mut deadline => panic!("local did not admit remote single"),
                    }
                };
                let mut encoded = encoded(attester_index);
                assert_eq!(
                    local.publish_pq_encoded_single_attestation(&mut encoded),
                    PqSingleAttestationPublishOutcome::PendingRemote {
                        message_id: remote_id.clone(),
                    },
                );

                let report = local.report_pq_admitted_message_outcome(
                    remote_id.clone(),
                    if terminal {
                        AdmittedMessageValidationOutcome::TerminalIgnore
                    } else {
                        AdmittedMessageValidationOutcome::RetryableIgnore
                    },
                );
                assert!(matches!(report, AdmittedMessageReport::Complete));
                if terminal {
                    assert_eq!(
                        local.publish_pq_encoded_single_attestation(&mut encoded),
                        PqSingleAttestationPublishOutcome::DuplicateRemote {
                            message_id: remote_id,
                        },
                    );
                } else {
                    assert_eq!(
                        local.publish_pq_encoded_single_attestation(&mut encoded),
                        PqSingleAttestationPublishOutcome::Published {
                            message_id: remote_id,
                        },
                    );
                }
            }
        });
    }
}
