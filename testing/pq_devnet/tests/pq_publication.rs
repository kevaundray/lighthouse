use beacon_chain::{
    PqBlockImportSource, TestingPqGossipClaim, TestingPqGossipFinish,
    TestingPqGossipObservationCache, TestingPqPublishPromotionResolution,
};
use consensus_signature::IndividualSignature;
use consensus_signature::{PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN, PQ_RAW_SIGNATURE_LEN};
use network::{
    PQ_BLOCK_BROADCAST_QUEUE_CAPACITY, PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY,
    PQ_BLOCK_PUBLICATION_BODY_CHUNK_CAPACITY, PQ_BLOCK_PUBLICATION_BODY_CHUNK_METADATA_BYTES,
    PQ_BLOCK_PUBLICATION_RETAINED_BODY_FIXED_BYTES, PQ_PUBLICATION_FIXED_BODY_ALLOWANCE_BYTES,
    PqBlockBroadcastError, PqBlockPublicationConfigurationError, PqBlockPublicationDisposition,
    PqBlockPublicationTerminal, PqPublicationBodyLimits, PqPublicationCapacity,
    pq_block_broadcast_channel,
};
use std::sync::Arc;
use types::{BeaconBlock, EthSpec, ForkName, MinimalEthSpec, SignedBeaconBlock};

#[test]
fn publication_has_distinct_import_provenance() {
    assert!(PqBlockImportSource::ALL.contains(&PqBlockImportSource::Publish));
    assert_ne!(PqBlockImportSource::Publish, PqBlockImportSource::Rpc);
    assert_ne!(PqBlockImportSource::Publish, PqBlockImportSource::Gossip);
}

fn empty_signed_block() -> Arc<SignedBeaconBlock<MinimalEthSpec>> {
    let spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
    Arc::new(SignedBeaconBlock::from_block(
        BeaconBlock::empty(&spec),
        IndividualSignature::empty(),
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn acknowledged_broadcast_channel_is_bounded_and_owns_the_exact_block() {
    let (sender, mut receiver) = pq_block_broadcast_channel();
    let block = empty_signed_block();
    let mut acknowledgements = Vec::new();

    for _ in 0..PQ_BLOCK_BROADCAST_QUEUE_CAPACITY {
        acknowledgements.push(sender.try_send(Arc::clone(&block)).expect("queue capacity"));
    }
    assert!(matches!(
        sender.try_send(Arc::clone(&block)),
        Err(PqBlockBroadcastError::Capacity)
    ));

    for acknowledgement in acknowledgements {
        let command = receiver.recv().await.expect("broadcast command");
        assert!(Arc::ptr_eq(command.block(), &block));
        command.acknowledge(Ok(()));
        acknowledgement
            .wait()
            .await
            .expect("positive broadcast acknowledgment");
    }
}

#[test]
fn committed_observation_is_distinct_from_terminal_rejection() {
    let slot = types::Slot::new(1);
    let root = types::Hash256::repeat_byte(0x31);
    let mut committed = TestingPqGossipObservationCache::default();
    let TestingPqGossipClaim::Propagate(generation) = committed.claim(slot, 2, root, slot) else {
        panic!("first committed claim must propagate")
    };
    assert!(committed.mark_propagated(slot, 2, generation));
    assert!(committed.finish(slot, 2, generation, TestingPqGossipFinish::Committed,));
    assert_eq!(
        committed.claim(slot, 2, root, slot),
        TestingPqGossipClaim::Committed,
    );

    let mut terminal = TestingPqGossipObservationCache::default();
    let TestingPqGossipClaim::Propagate(generation) = terminal.claim(slot, 2, root, slot) else {
        panic!("first terminal claim must propagate")
    };
    assert!(terminal.mark_propagated(slot, 2, generation));
    assert!(terminal.finish(slot, 2, generation, TestingPqGossipFinish::Terminal));
    assert_eq!(
        terminal.claim(slot, 2, root, slot),
        TestingPqGossipClaim::Terminal,
    );
}

#[test]
fn publication_disposition_keeps_all_http_policy_classes_distinct() {
    fn classify(disposition: PqBlockPublicationDisposition) -> (&'static str, bool) {
        match disposition {
            PqBlockPublicationDisposition::Published(_) => ("published", false),
            PqBlockPublicationDisposition::Committed => ("committed", false),
            PqBlockPublicationDisposition::Pending => ("pending", true),
            PqBlockPublicationDisposition::Terminal(PqBlockPublicationTerminal::Rejected) => {
                ("terminal", false)
            }
            PqBlockPublicationDisposition::Terminal(PqBlockPublicationTerminal::Stale) => {
                ("stale", false)
            }
            PqBlockPublicationDisposition::Equivocation { .. } => ("equivocation", false),
            PqBlockPublicationDisposition::Capacity(PqPublicationCapacity::Admission) => {
                ("admission-capacity", true)
            }
            PqBlockPublicationDisposition::Capacity(PqPublicationCapacity::Observation) => {
                ("observation-capacity", true)
            }
            PqBlockPublicationDisposition::Capacity(PqPublicationCapacity::Broadcast) => {
                ("broadcast-capacity", true)
            }
            PqBlockPublicationDisposition::Invalid(_) => ("invalid", false),
            PqBlockPublicationDisposition::Local(_) => ("local", true),
        }
    }

    assert_eq!(
        classify(PqBlockPublicationDisposition::Committed),
        ("committed", false),
    );
    assert_eq!(
        classify(PqBlockPublicationDisposition::Terminal(
            PqBlockPublicationTerminal::Rejected,
        )),
        ("terminal", false),
    );
}

#[test]
fn publication_body_limits_are_checked_and_bound_all_admitted_json() {
    let mut spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
    spec.max_payload_size = 10 * 1024 * 1024;
    let limits = PqPublicationBodyLimits::checked::<MinimalEthSpec>(&spec)
        .expect("frozen profile body limits");
    let expected_ssz = usize::try_from(spec.max_payload_size).expect("test payload size")
        + MinimalEthSpec::max_attestations_electra() * PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN
        + 2 * PQ_RAW_SIGNATURE_LEN
        + PQ_PUBLICATION_FIXED_BODY_ALLOWANCE_BYTES;
    let expected_json = expected_ssz * 2 + PQ_PUBLICATION_FIXED_BODY_ALLOWANCE_BYTES;
    assert_eq!(limits.max_ssz_bytes(), expected_ssz);
    assert_eq!(limits.max_json_bytes(), expected_json);
    let expected_per_admission = expected_json * 2
        + PQ_BLOCK_PUBLICATION_BODY_CHUNK_CAPACITY * PQ_BLOCK_PUBLICATION_BODY_CHUNK_METADATA_BYTES
        + PQ_BLOCK_PUBLICATION_RETAINED_BODY_FIXED_BYTES;
    assert_eq!(
        limits.max_retained_body_bytes(),
        expected_per_admission * PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY,
    );

    spec.max_payload_size = u64::MAX;
    assert!(PqPublicationBodyLimits::checked::<MinimalEthSpec>(&spec).is_none());
}

#[test]
fn overflowing_body_limits_are_a_nonretryable_configuration_error() {
    let mut spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
    spec.max_payload_size = u64::MAX;
    let error = PqPublicationBodyLimits::try_from_spec::<MinimalEthSpec>(&spec)
        .expect_err("overflowing retained-body arithmetic must fail startup");
    assert!(matches!(
        error,
        PqBlockPublicationConfigurationError::BodyLimitsOverflow
    ));
    assert!(!error.is_retryable());
}

#[test]
fn publish_promotion_reconciliation_reports_the_current_cross_root() {
    let slot = types::Slot::new(3);
    let pending_root = types::Hash256::repeat_byte(0x31);
    let committed_root = types::Hash256::repeat_byte(0x32);
    let mut cache = TestingPqGossipObservationCache::default();
    let TestingPqGossipClaim::Propagate(generation) = cache.claim(slot, 4, pending_root, slot)
    else {
        panic!("initial propagation claim")
    };
    cache.record_commit(slot, 4, committed_root);
    assert_eq!(
        cache.promote_or_resolve_publish(slot, 4, pending_root, generation),
        TestingPqPublishPromotionResolution::Equivocation(committed_root)
    );
}

#[test]
fn publish_promotion_is_one_coherent_cache_transition() {
    let slot = types::Slot::new(4);
    let root = types::Hash256::repeat_byte(0x41);
    let mut promoted = TestingPqGossipObservationCache::default();
    let TestingPqGossipClaim::Propagate(generation) = promoted.claim(slot, 5, root, slot) else {
        panic!("initial propagation claim")
    };
    assert_eq!(
        promoted.promote_or_resolve_publish(slot, 5, root, generation),
        TestingPqPublishPromotionResolution::Promoted
    );

    let mut committed = TestingPqGossipObservationCache::default();
    let TestingPqGossipClaim::Propagate(generation) = committed.claim(slot, 5, root, slot) else {
        panic!("committed propagation claim")
    };
    committed.record_commit(slot, 5, root);
    assert_eq!(
        committed.promote_or_resolve_publish(slot, 5, root, generation),
        TestingPqPublishPromotionResolution::Committed
    );

    committed.prune_after_commit(types::Slot::new(5));
    assert_eq!(
        committed.promote_or_resolve_publish(slot, 5, root, generation),
        TestingPqPublishPromotionResolution::Stale
    );
}
