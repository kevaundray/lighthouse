use crate::common;
use consensus_signature::IndividualSignature;
use lighthouse_network::types::GossipKind;
use lighthouse_network::{
    GossipTopic, MessageAcceptance, MessageId, NetworkEvent, PqBeaconBlockPublishError,
    PqBeaconBlockPublishOutcome, PqEncodedBeaconBlock, PubsubMessage,
};
use ssz::Encode;
use std::time::Duration;
use std::{collections::HashSet, sync::Arc};
use tokio::runtime::Runtime;
use types::{BeaconBlock, EthSpec, ForkName, Hash256, MinimalEthSpec, SignedBeaconBlock, Slot};

#[test]
fn exact_pq_block_can_be_encoded_before_entering_the_network_poll_loop() {
    let runtime = Arc::new(Runtime::new().expect("test runtime"));
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));

    runtime.block_on(async {
        let mut network = common::build_libp2p_instance(
            Arc::downgrade(&runtime),
            vec![],
            ForkName::Electra,
            Arc::clone(&spec),
            false,
            None,
        )
        .await;
        let block = Arc::new(SignedBeaconBlock::from_block(
            BeaconBlock::<MinimalEthSpec>::empty(&spec),
            IndividualSignature::empty(),
        ));
        let encoded = PqEncodedBeaconBlock::encode(Arc::clone(&block), [7; 4]);

        assert_eq!(encoded.as_ssz_bytes(), block.as_ssz_bytes());
        assert_eq!(encoded.fork_digest(), [7; 4]);
        assert_eq!(
            network.publish_pq_encoded_beacon_block(encoded),
            Err(PqBeaconBlockPublishError::NoPeersSubscribed),
        );
    });
}

#[test]
fn pq_publish_requires_an_exact_status_compatible_subscribed_recipient() {
    let runtime = Arc::new(Runtime::new().expect("test runtime"));
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );

    runtime.block_on(async {
        let (mut publisher, admission, _) = common::build_pq_libp2p_instance(
            Arc::downgrade(&runtime),
            ForkName::Electra,
            Arc::clone(&spec),
        )
        .await;
        let (mut compatible_unsubscribed, _, compatible_peer) = common::build_pq_libp2p_instance(
            Arc::downgrade(&runtime),
            ForkName::Electra,
            Arc::clone(&spec),
        )
        .await;
        let (mut incompatible_subscribed, _, incompatible_peer) = common::build_pq_libp2p_instance(
            Arc::downgrade(&runtime),
            ForkName::Electra,
            Arc::clone(&spec),
        )
        .await;
        assert!(incompatible_subscribed.subscribe_kind(GossipKind::BeaconBlock));

        let compatible_address = loop {
            if let NetworkEvent::NewListenAddr(address) = compatible_unsubscribed.next_event().await
                && address
                    .iter()
                    .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::Tcp(_)))
            {
                break address;
            }
        };
        let incompatible_address = loop {
            if let NetworkEvent::NewListenAddr(address) = incompatible_subscribed.next_event().await
                && address
                    .iter()
                    .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::Tcp(_)))
            {
                break address;
            }
        };
        publisher
            .testing_dial(compatible_address)
            .expect("dial compatible peer");
        publisher
            .testing_dial(incompatible_address)
            .expect("dial incompatible peer");

        let mut connected = HashSet::new();
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);
        while connected.len() < 2 {
            tokio::select! {
                event = publisher.next_event() => {
                    if let NetworkEvent::PeerConnectedOutgoing(peer)
                    | NetworkEvent::PeerConnectedIncoming(peer) = event
                    {
                        connected.insert(peer);
                    }
                }
                _ = compatible_unsubscribed.next_event() => {}
                _ = incompatible_subscribed.next_event() => {}
                _ = &mut deadline => panic!("publisher did not connect to both peers"),
            }
        }
        assert!(connected.contains(&compatible_peer));
        assert!(connected.contains(&incompatible_peer));

        let subscription_settle = tokio::time::sleep(Duration::from_millis(100));
        tokio::pin!(subscription_settle);
        loop {
            tokio::select! {
                _ = publisher.next_event() => {}
                _ = compatible_unsubscribed.next_event() => {}
                _ = incompatible_subscribed.next_event() => {}
                _ = &mut subscription_settle => break,
            }
        }

        assert!(admission.try_add_compatible(compatible_peer));
        let mut target = BeaconBlock::<MinimalEthSpec>::empty(&spec);
        *target.slot_mut() = Slot::new(2);
        let target = Arc::new(SignedBeaconBlock::from_block(
            target,
            IndividualSignature::empty(),
        ));
        assert_eq!(
            publisher.publish_pq_beacon_block(target),
            Err(PqBeaconBlockPublishError::NoPeersSubscribed),
            "an incompatible subscribed peer must not satisfy outbound recipient selection",
        );
    });
}

#[test]
fn exact_pq_block_publish_reports_no_subscribed_peers() {
    let runtime = Arc::new(Runtime::new().expect("test runtime"));
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));

    runtime.block_on(async {
        let mut network = common::build_libp2p_instance(
            Arc::downgrade(&runtime),
            vec![],
            ForkName::Electra,
            Arc::clone(&spec),
            false,
            None,
        )
        .await;
        let block = Arc::new(SignedBeaconBlock::from_block(
            BeaconBlock::empty(&spec),
            IndividualSignature::empty(),
        ));

        assert!(matches!(
            network.publish_pq_beacon_block(block),
            Err(PqBeaconBlockPublishError::NoPeersSubscribed)
        ));
    });
}

#[test]
fn exact_pq_block_publish_rejects_non_peer_publish_errors() {
    let runtime = Arc::new(Runtime::new().expect("test runtime"));
    let mut spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
    spec.max_payload_size = 1;
    let spec = Arc::new(spec);

    runtime.block_on(async {
        let mut network = common::build_libp2p_instance(
            Arc::downgrade(&runtime),
            vec![],
            ForkName::Electra,
            Arc::clone(&spec),
            false,
            None,
        )
        .await;
        let block = Arc::new(SignedBeaconBlock::from_block(
            BeaconBlock::empty(&spec),
            IndividualSignature::empty(),
        ));

        assert_eq!(
            network.publish_pq_beacon_block(block),
            Err(PqBeaconBlockPublishError::Rejected),
        );
    });
}

#[test]
fn failed_exact_pq_block_publish_is_not_cached_for_later_peer() {
    let runtime = Arc::new(Runtime::new().expect("test runtime"));
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));

    runtime.block_on(async {
        let mut sender = common::build_libp2p_instance(
            Arc::downgrade(&runtime),
            vec![],
            ForkName::Electra,
            Arc::clone(&spec),
            false,
            None,
        )
        .await;
        let block = Arc::new(SignedBeaconBlock::from_block(
            BeaconBlock::empty(&spec),
            IndividualSignature::empty(),
        ));
        assert_eq!(
            sender.publish_pq_beacon_block(Arc::clone(&block)),
            Err(PqBeaconBlockPublishError::NoPeersSubscribed),
        );

        let mut receiver = common::build_libp2p_instance(
            Arc::downgrade(&runtime),
            vec![],
            ForkName::Electra,
            Arc::clone(&spec),
            false,
            None,
        )
        .await;
        assert!(receiver.subscribe_kind(GossipKind::BeaconBlock));
        let receiver_address = loop {
            if let NetworkEvent::NewListenAddr(address) = receiver.next_event().await
                && address
                    .iter()
                    .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::Tcp(_)))
            {
                break address;
            }
        };
        sender
            .testing_dial(receiver_address)
            .expect("sender should dial receiver");

        let quiet_period = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(quiet_period);
        loop {
            tokio::select! {
                _ = sender.next_event() => {}
                event = receiver.next_event() => {
                    assert!(
                        !matches!(event, NetworkEvent::PubsubMessage { .. }),
                        "failed exact publication must not be replayed from a cache",
                    );
                }
                _ = &mut quiet_period => break,
            }
        }

        let retry_deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(retry_deadline);
        loop {
            match sender.publish_pq_beacon_block(Arc::clone(&block)) {
                Ok(PqBeaconBlockPublishOutcome::Published) => break,
                Err(PqBeaconBlockPublishError::NoPeersSubscribed) => {}
                other => panic!("unexpected explicit retry result: {other:?}"),
            }
            tokio::select! {
                _ = sender.next_event() => {}
                _ = receiver.next_event() => {}
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                _ = &mut retry_deadline => panic!("explicit retry never found subscribed peer"),
            }
        }
    });
}

#[test]
fn validation_reporting_returns_exact_gossipsub_ownership() {
    let runtime = Arc::new(Runtime::new().expect("test runtime"));
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));

    runtime.block_on(async {
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&runtime),
            ForkName::Electra,
            Arc::clone(&spec),
            common::Protocol::Tcp,
            false,
            None,
        )
        .await;
        assert!(receiver.subscribe_kind(GossipKind::BeaconBlock));
        let block = Arc::new(SignedBeaconBlock::from_block(
            BeaconBlock::empty(&spec),
            IndividualSignature::empty(),
        ));
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);

        loop {
            match sender.publish_pq_beacon_block(Arc::clone(&block)) {
                Ok(PqBeaconBlockPublishOutcome::Published) => break,
                Ok(PqBeaconBlockPublishOutcome::Duplicate) => {}
                Err(PqBeaconBlockPublishError::NoPeersSubscribed) => {}
                Err(error) => panic!("unexpected exact-block publication failure: {error:?}"),
            }
            tokio::select! {
                _ = sender.next_event() => {}
                _ = receiver.next_event() => {}
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                _ = &mut deadline => panic!("receiver did not obtain exact beacon block"),
            }
        }

        let (message_id, source) = loop {
            tokio::select! {
                _ = sender.next_event() => {}
                event = receiver.next_event() => {
                    if let NetworkEvent::PubsubMessage { id, source, .. } = event {
                        break (id, source);
                    }
                }
                _ = &mut deadline => panic!("receiver did not obtain exact beacon block"),
            }
        };

        assert!(receiver.report_message_validation_result(
            &source,
            message_id.clone(),
            MessageAcceptance::Accept,
        ));
        assert!(!receiver.report_message_validation_result(
            &source,
            MessageId(vec![0xff; message_id.0.len()]),
            MessageAcceptance::Accept,
        ));
    });
}

#[test]
fn exact_pq_block_publish_reports_real_gossipsub_acceptance() {
    let runtime = Arc::new(Runtime::new().expect("test runtime"));
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));

    runtime.block_on(async {
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&runtime),
            ForkName::Electra,
            Arc::clone(&spec),
            common::Protocol::Tcp,
            false,
            None,
        )
        .await;
        assert!(receiver.subscribe_kind(GossipKind::BeaconBlock));
        let block = Arc::new(SignedBeaconBlock::from_block(
            BeaconBlock::empty(&spec),
            IndividualSignature::empty(),
        ));
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);

        loop {
            match sender.publish_pq_beacon_block(Arc::clone(&block)) {
                Ok(outcome) => {
                    assert_eq!(outcome, PqBeaconBlockPublishOutcome::Published);
                    break;
                }
                Err(PqBeaconBlockPublishError::NoPeersSubscribed) => {}
                Err(error) => panic!("unexpected exact-block publication failure: {error:?}"),
            }
            tokio::select! {
                _ = sender.next_event() => {}
                _ = receiver.next_event() => {}
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                _ = &mut deadline => panic!("gossipsub peer did not become publishable"),
            }
        }

        let expected_fork_digest = spec
            .enr_fork_id::<MinimalEthSpec>(spec.genesis_slot, Hash256::ZERO)
            .fork_digest;
        loop {
            tokio::select! {
                _ = sender.next_event() => {}
                event = receiver.next_event() => {
                    if let NetworkEvent::PubsubMessage { topic, message, .. } = event {
                        let mut decoded_topic = GossipTopic::decode(topic.as_str())
                            .expect("exact beacon-block topic");
                        assert_eq!(decoded_topic.kind(), &GossipKind::BeaconBlock);
                        assert_eq!(*decoded_topic.digest(), expected_fork_digest);
                        let PubsubMessage::BeaconBlock(received) = message else {
                            panic!("exact beacon-block topic must decode as a block");
                        };
                        assert_eq!(received, block);
                        break;
                    }
                }
                _ = &mut deadline => panic!("receiver did not decode exact beacon block"),
            }
        }
    });
}

#[test]
fn exact_pq_block_publish_treats_duplicate_as_positive_idempotence() {
    let runtime = Arc::new(Runtime::new().expect("test runtime"));
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));

    runtime.block_on(async {
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&runtime),
            ForkName::Electra,
            Arc::clone(&spec),
            common::Protocol::Tcp,
            false,
            None,
        )
        .await;
        assert!(receiver.subscribe_kind(GossipKind::BeaconBlock));
        let block = Arc::new(SignedBeaconBlock::from_block(
            BeaconBlock::empty(&spec),
            IndividualSignature::empty(),
        ));
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);

        loop {
            match sender.publish_pq_beacon_block(Arc::clone(&block)) {
                Ok(PqBeaconBlockPublishOutcome::Published) => break,
                Err(PqBeaconBlockPublishError::NoPeersSubscribed) => {}
                other => panic!("unexpected initial publication result: {other:?}"),
            }
            tokio::select! {
                _ = sender.next_event() => {}
                _ = receiver.next_event() => {}
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                _ = &mut deadline => panic!("gossipsub peer did not become publishable"),
            }
        }

        assert_eq!(
            sender.publish_pq_beacon_block(Arc::clone(&block)),
            Ok(PqBeaconBlockPublishOutcome::Duplicate),
        );

        let (mut different_message, signature) = (*block).clone().deconstruct();
        match &mut different_message {
            BeaconBlock::Electra(inner) => inner.proposer_index = 1,
            _ => panic!("test block must be Electra"),
        }
        let different_block = Arc::new(SignedBeaconBlock::from_block(different_message, signature));
        assert_eq!(
            sender.publish_pq_beacon_block(different_block),
            Ok(PqBeaconBlockPublishOutcome::Published),
            "different encoded block bytes must have a different gossipsub message id",
        );
    });
}
