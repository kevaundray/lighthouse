#[cfg(target_feature = "avx2")]
use beacon_chain::{
    PQ_ATTESTATION_GOSSIP_ADMISSION_CAPACITY, PQ_LOCAL_ATTESTATION_PROOF_ADMISSION_CAPACITY,
    PqNewPayloadTransport, TestingPqBlockingHook, TestingPqPublishedLocalLateApplyHarness,
    builder::{BeaconChainBuilder, Witness},
};
use beacon_chain::{
    PQ_BLOCK_IMPORT_ADMISSION_CAPACITY, PQ_FORWARD_RANGE_BLOCK_CAPACITY, PqAttestationGossipError,
    PqAttestationGossipLocalError, PqBlockImportSource, PqEnginePayloadDisposition,
    PqEnginePayloadStatus, PqForkChoiceAttestationError, PqForkChoiceAttestationOutcome,
    PqImportError, PqImportLocalError, PqImportPeerInvalid,
    PqPublishedLocalAttestationBatchConsumptionError,
    PqPublishedLocalAttestationBatchConsumptionOutcome, PqPublishedLocalAttestationEvidenceBatch,
    PqPublishedLocalAttestationEvidenceError, PqSingleConsumptionResult,
    PqSingleObservationBatchError, PqSingleObservationBatchResolution,
    PqSingleObservationCompletion, PqSingleObservationIdentity, PqSingleObservationStatus,
    PqSingleObservationWatchError, PqSingleObservationWatchReceipt, PqSingleWireMessageId,
    TestingPqAttestationObservationCache, TestingPqAttestationObservationOwnerCache,
    TestingPqExternalReservation, TestingPqGossipClaim, TestingPqGossipFinish,
    TestingPqGossipObservationCache, TestingPqPublishedLocalAttestationEvidenceHarness,
    TestingPqPublishedLocalAttestationEvidenceMutation,
    TestingPqPublishedLocalAttestationSupervisorFailure,
    TestingPqPublishedLocalAttestationSupervisorHarness, TestingPqRemotePublicationEvidenceStatus,
    TestingPqSingleObservationBatchInput, TestingPqSingleObservationResolutionReceipt,
    TestingPqWireBoundObservationCache, classify_pq_engine_payload_status,
    testing_only_pq_attestation_advance_distance, testing_only_pq_attestation_late_window,
    testing_only_pq_attestation_target_root, testing_only_pq_import_drain_race,
};
#[cfg(target_feature = "avx2")]
use consensus_signature::{
    AggregationService, OneTimeUseId, PqPublicKey, PqRawSignature, PqSameMessageEvidence,
    SigningDuty,
};
#[cfg(target_feature = "avx2")]
use lighthouse_network::MessageId;
#[cfg(target_feature = "avx2")]
use network::{
    PqGossipAggregateDisposition, PqGossipAttestationDisposition, PqGossipBlockDisposition,
    PqNetworkBlockProcessor,
};
#[cfg(target_feature = "avx2")]
use pq_signing::{PqKeyUnlock, PqKeystore, PqSigningAuthority, provision_usage_journal};
#[cfg(target_feature = "avx2")]
use ssz_types::{BitList, BitVector};
#[cfg(target_feature = "avx2")]
use std::sync::Arc;
#[cfg(target_feature = "avx2")]
use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
#[cfg(target_feature = "avx2")]
use store::{HotColdDB, MemoryStore, StoreConfig};
use types::EthSpec;
#[cfg(target_feature = "avx2")]
use types::SignedBeaconBlock;
#[cfg(target_feature = "avx2")]
use types::{
    AggregateAndProof, Attestation, AttestationData, AttestationElectra, BeaconBlock, ChainSpec,
    Checkpoint, Domain, ExecutionPayloadRef, ForkName, MinimalEthSpec, SelectionProof,
    SignedAggregateAndProof, SignedRoot, SingleAttestation, SubnetId,
};
use types::{Hash256, Slot};

#[tokio::test]
async fn pq_import_drain_cannot_lose_final_activity() {
    assert!(
        testing_only_pq_import_drain_race().await,
        "dropping the final activity before the drain await must still complete"
    );
}

#[test]
fn pq_attestation_errors_expose_nested_local_causes() {
    use std::error::Error;

    let aggregation = consensus_signature::AggregationError::Unavailable;
    let state_error = state_processing::PqAttestationError::Local(
        state_processing::PqAttestationLocalError::Aggregation(aggregation),
    );
    assert_eq!(
        state_error.source().map(ToString::to_string),
        Some(aggregation.to_string())
    );

    let gossip_error = PqAttestationGossipError::Local(PqAttestationGossipLocalError::Aggregate(
        state_processing::PqConsensusLocalError::Attestation(
            state_processing::PqAttestationLocalError::Aggregation(aggregation),
        ),
    ));
    assert_eq!(
        gossip_error.source().map(ToString::to_string),
        Some(aggregation.to_string())
    );

    let pool_invariant = operation_pool::PqAttestationPoolInsertInvariant::GenerationExhausted;
    let pool_error = PqForkChoiceAttestationError::Pool(pool_invariant);
    assert_eq!(
        pool_error.source().map(ToString::to_string),
        Some(pool_invariant.to_string()),
        "the inbound typed pool failure preserves its invariant source",
    );
}

#[test]
fn pq_attestation_precheck_prunes_stale_capacity_before_status() {
    let mut cache = TestingPqAttestationObservationCache::default();
    assert_eq!(cache.capacity(), 16 * 2);
    for validator in 0..cache.capacity() {
        cache
            .observe_single(
                types::Epoch::new(0),
                validator as u64,
                Hash256::with_last_byte(validator as u8),
                Slot::new(0),
            )
            .expect("fill bounded stale observation cache");
    }
    assert_eq!(cache.len_singles(), cache.capacity());

    let epoch_one_start = types::Epoch::new(1).start_slot(types::MinimalEthSpec::slots_per_epoch());
    assert_eq!(
        cache.precheck_single(types::Epoch::new(1), 0, epoch_one_start),
        beacon_chain::PqAttestationGossipObservation::Unseen
    );
    assert_eq!(cache.len_singles(), 0);
}

#[test]
fn pq_aggregate_precheck_prunes_stale_capacity_before_status() {
    let mut cache = TestingPqAttestationObservationCache::default();
    for validator in 0..cache.capacity() {
        let identity = Hash256::with_last_byte(validator as u8);
        let generation = cache
            .claim_aggregate(
                types::Epoch::new(0),
                validator as u64,
                Slot::new(0),
                identity,
                0,
                identity,
                &[0],
                Slot::new(0),
            )
            .expect("fill bounded stale aggregate cache");
        assert!(cache.finalize_aggregate(
            types::Epoch::new(0),
            validator as u64,
            Slot::new(0),
            identity,
            0,
            identity,
            generation,
            &[0],
        ));
    }
    let epoch_one_start = types::Epoch::new(1).start_slot(types::MinimalEthSpec::slots_per_epoch());
    assert_eq!(
        cache.precheck_aggregate(
            types::Epoch::new(1),
            0,
            epoch_one_start,
            Hash256::repeat_byte(0xf0),
            0,
            &[0],
            epoch_one_start,
        ),
        beacon_chain::PqAttestationGossipObservation::Unseen
    );
    assert_eq!(cache.len_aggregators(), 0);
    assert_eq!(cache.len_aggregate_candidates(), 0);
}

#[test]
fn pq_attestation_prior_epoch_head_becomes_next_epoch_target_root() {
    let referenced_root = Hash256::repeat_byte(0x11);
    let historical_target = Hash256::repeat_byte(0x22);
    assert_eq!(
        testing_only_pq_attestation_target_root::<types::MinimalEthSpec>(
            Slot::new(7),
            referenced_root,
            Slot::new(8),
            historical_target,
        ),
        referenced_root
    );
    assert_eq!(
        testing_only_pq_attestation_target_root::<types::MinimalEthSpec>(
            Slot::new(8),
            referenced_root,
            Slot::new(9),
            historical_target,
        ),
        referenced_root
    );
    assert_eq!(
        testing_only_pq_attestation_target_root::<types::MinimalEthSpec>(
            Slot::new(9),
            referenced_root,
            Slot::new(10),
            historical_target,
        ),
        historical_target
    );
}

#[test]
fn pq_attestation_context_advancement_is_explicitly_bounded() {
    let max = types::MinimalEthSpec::slots_per_epoch()
        .checked_mul(2)
        .and_then(|slots| slots.checked_add(2))
        .expect("minimal bound");
    assert_eq!(
        testing_only_pq_attestation_advance_distance::<types::MinimalEthSpec>(
            Slot::new(0),
            Slot::new(max),
        )
        .expect("exact bound"),
        max
    );
    assert!(matches!(
        testing_only_pq_attestation_advance_distance::<types::MinimalEthSpec>(
            Slot::new(0),
            Slot::new(max + 1),
        ),
        Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::StateAdvanceTooLarge { .. }
        ))
    ));
}

#[test]
fn pq_attestation_generation_exhaustion_fails_closed_without_observation() {
    let mut cache = TestingPqAttestationObservationCache::default();
    cache.set_next_generation(u64::MAX);
    assert_eq!(
        cache.observe_single(
            types::Epoch::new(0),
            1,
            Hash256::repeat_byte(1),
            Slot::new(0),
        ),
        Err(beacon_chain::PqAttestationGossipObservation::GenerationExhausted)
    );
    assert_eq!(cache.len_singles(), 0);
}

#[test]
fn pq_attestation_receipt_timing_is_local_and_never_peer_penalized() {
    let future =
        PqAttestationGossipError::Local(PqAttestationGossipLocalError::ReceiptBeforeWindow {
            attestation: Slot::new(9),
            latest_permissible: Slot::new(8),
        });
    assert!(!future.should_penalize_peer());
    assert!(future.is_retryable());

    let past = PqAttestationGossipError::Local(PqAttestationGossipLocalError::ReceiptAfterWindow {
        attestation: Slot::new(7),
        earliest_permissible: Slot::new(8),
    });
    assert!(!past.should_penalize_peer());
    assert!(!past.is_retryable());

    let lineage_changed = PqAttestationGossipError::Local(
        PqAttestationGossipLocalError::BoundHeadNoLongerCanonical {
            bound: Hash256::repeat_byte(1),
            current: Hash256::repeat_byte(2),
        },
    );
    assert!(!lineage_changed.should_penalize_peer());
    assert!(!lineage_changed.is_retryable());
}

#[test]
fn pq_attestation_late_window_accepts_boundaries_and_ignores_expiry() {
    assert!(
        testing_only_pq_attestation_late_window(Slot::new(8), Slot::new(8), Slot::new(9)).is_ok()
    );
    assert!(
        testing_only_pq_attestation_late_window(Slot::new(9), Slot::new(8), Slot::new(9)).is_ok()
    );
    let expired = testing_only_pq_attestation_late_window(Slot::new(7), Slot::new(8), Slot::new(9))
        .expect_err("proof completed after gossip expiry");
    assert!(matches!(
        expired,
        PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ProofOutlivedPropagationWindow { .. }
        )
    ));
    assert!(!expired.should_penalize_peer());
    assert!(!expired.is_retryable());

    let future = testing_only_pq_attestation_late_window(Slot::new(10), Slot::new(8), Slot::new(9))
        .expect_err("local clock still sees the attestation as future");
    assert!(matches!(
        future,
        PqAttestationGossipError::Local(PqAttestationGossipLocalError::ReceiptBeforeWindow { .. })
    ));
    assert!(!future.should_penalize_peer());
    assert!(future.is_retryable());
}

#[test]
fn pq_single_observation_cancellation_reopens_and_conflicts_ignore() {
    let mut cache = TestingPqAttestationObservationCache::default();
    let epoch = types::Epoch::new(0);
    let first = Hash256::repeat_byte(1);
    let conflicting = Hash256::repeat_byte(2);
    let generation = cache
        .claim_single(epoch, 3, first, Slot::new(0))
        .expect("first pending claim");
    assert_eq!(
        cache.status_single(epoch, 3, conflicting),
        beacon_chain::PqAttestationGossipObservation::Pending
    );
    assert!(cache.rollback_single(epoch, 3, first, generation));
    assert_eq!(
        cache.status_single(epoch, 3, conflicting),
        beacon_chain::PqAttestationGossipObservation::Unseen
    );
    let retry_generation = cache
        .claim_single(epoch, 3, conflicting, Slot::new(0))
        .expect("conflicting single may retry after cancellation");
    assert!(cache.finalize_single(epoch, 3, conflicting, retry_generation));
    assert_eq!(
        cache.status_single(epoch, 3, first),
        beacon_chain::PqAttestationGossipObservation::Observed
    );
}

#[test]
fn pq_single_observation_is_sealed_after_propagation_until_consumed() {
    let mut cache = TestingPqAttestationObservationCache::default();
    let epoch = types::Epoch::new(0);
    let identity = Hash256::repeat_byte(0x31);
    let conflicting = Hash256::repeat_byte(0x32);
    let generation = cache
        .claim_single(epoch, 4, identity, Slot::new(0))
        .expect("claim pending single");

    assert!(cache.mark_single_propagated(epoch, 4, identity, generation));
    assert_eq!(
        cache.status_single(epoch, 4, identity),
        beacon_chain::PqAttestationGossipObservation::Observed
    );
    assert!(
        !cache.rollback_single(epoch, 4, identity, generation),
        "dropping a propagated capability must not reopen the observation"
    );
    assert_eq!(
        cache.status_single(epoch, 4, conflicting),
        beacon_chain::PqAttestationGossipObservation::Observed,
        "a conflicting identity must remain suppressed after propagation"
    );

    let next_epoch = types::Epoch::new(1);
    let next_epoch_start = next_epoch.start_slot(types::MinimalEthSpec::slots_per_epoch());
    assert_eq!(
        cache.precheck_single(next_epoch, 9, next_epoch_start),
        beacon_chain::PqAttestationGossipObservation::Unseen
    );
    assert_eq!(
        cache.status_single(epoch, 4, identity),
        beacon_chain::PqAttestationGossipObservation::Observed,
        "pruning must retain a propagated observation while consumption is pending"
    );
    assert!(cache.finalize_single_terminal(epoch, 4, identity, generation));
    assert_eq!(
        cache.single_consumption_result(epoch, 4),
        Some(beacon_chain::PqSingleConsumptionResult::Terminal)
    );
}

#[test]
fn pq_single_observation_exact_status_is_identity_aware() {
    let identity = |validator_index, slot, subnet, signed_root_byte, signed_ssz_byte| {
        PqSingleObservationIdentity::new(
            types::Epoch::new(0),
            validator_index,
            Slot::new(slot),
            types::SubnetId::new(subnet),
            Hash256::repeat_byte(signed_root_byte),
            [signed_ssz_byte; 32],
        )
    };
    let mut cache = TestingPqAttestationObservationCache::default();
    let earliest_slot = Slot::new(0);

    let pending = identity(5, 1, 3, 0x11, 0x21);
    let pending_generation = cache
        .claim_exact_single(&pending, earliest_slot)
        .expect("claim exact pending identity");
    assert_eq!(
        cache.exact_single_status(&pending),
        PqSingleObservationStatus::Pending
    );
    for (conflicting_pending, changed_field) in [
        (identity(5, 1, 3, 0x12, 0x21), "signed tree-hash root"),
        (identity(5, 1, 3, 0x11, 0x22), "signed SSZ digest"),
        (identity(5, 2, 3, 0x11, 0x21), "slot"),
        (identity(5, 1, 4, 0x11, 0x21), "subnet"),
    ] {
        assert_eq!(
            cache.exact_single_status(&conflicting_pending),
            PqSingleObservationStatus::Conflict,
            "the same validator/target with a different {changed_field} must conflict"
        );
    }

    assert!(cache.mark_exact_single_propagated(&pending, pending_generation));
    assert_eq!(
        cache.exact_single_status(&pending),
        PqSingleObservationStatus::ConsumptionPending
    );

    for (validator_index, result) in [
        (6, PqSingleConsumptionResult::Applied),
        (7, PqSingleConsumptionResult::Queued),
        (8, PqSingleConsumptionResult::Terminal),
    ] {
        let consumed = identity(
            validator_index,
            1,
            3,
            0x30_u8.saturating_add(validator_index as u8),
            0x40_u8.saturating_add(validator_index as u8),
        );
        let conflicting_consumed = identity(
            validator_index,
            1,
            3,
            0x50_u8.saturating_add(validator_index as u8),
            0x60_u8.saturating_add(validator_index as u8),
        );
        let generation = cache
            .claim_exact_single(&consumed, earliest_slot)
            .expect("claim exact consumed identity");
        assert!(cache.mark_exact_single_propagated(&consumed, generation));
        assert!(cache.finalize_exact_single(&consumed, generation, result));
        assert_eq!(
            cache.exact_single_status(&consumed),
            PqSingleObservationStatus::Consumed(result)
        );
        assert_eq!(
            cache.exact_single_status(&conflicting_consumed),
            PqSingleObservationStatus::Conflict,
            "a consumed signed identity must not suppress a conflicting signature"
        );
    }
}

#[test]
fn pq_single_observation_batch_resolution_is_atomic_and_source_aware() {
    let identity = |validator_index, signed_root_byte, signed_ssz_byte| {
        PqSingleObservationIdentity::new(
            types::Epoch::new(0),
            validator_index,
            Slot::new(1),
            types::SubnetId::new(3),
            Hash256::repeat_byte(signed_root_byte),
            [signed_ssz_byte; 32],
        )
    };
    let local = TestingPqSingleObservationBatchInput::LocalWireSuccess;
    let remote = TestingPqSingleObservationBatchInput::Remote;
    let earliest_slot = Slot::new(0);

    let mut local_cache = TestingPqAttestationObservationCache::default();
    let local_identity = identity(1, 0x11, 0x21);
    assert_eq!(
        local_cache.resolve_exact_single_batch(&[local(local_identity)], earliest_slot),
        Ok(vec![PqSingleObservationBatchResolution::LocalReserved]),
    );
    assert_eq!(
        local_cache.exact_single_status(&local_identity),
        PqSingleObservationStatus::ConsumptionPending,
        "wire-success reservation must be non-rollbackable consumption ownership"
    );

    let mut remote_cache = TestingPqAttestationObservationCache::default();
    let remote_pending = identity(2, 0x12, 0x22);
    let pending_generation = remote_cache
        .claim_exact_single(&remote_pending, earliest_slot)
        .expect("existing remote proof claim");
    assert_eq!(
        remote_cache.resolve_exact_single_batch(&[remote(remote_pending)], earliest_slot),
        Ok(vec![PqSingleObservationBatchResolution::WaitRemote(
            PqSingleObservationStatus::Pending,
        )]),
    );
    assert_eq!(
        remote_cache.exact_single_status(&remote_pending),
        PqSingleObservationStatus::Pending,
        "batch resolution must preserve an existing remote Pending claim"
    );
    assert!(remote_cache.mark_exact_single_propagated(&remote_pending, pending_generation));
    assert_eq!(
        remote_cache.resolve_exact_single_batch(&[remote(remote_pending)], earliest_slot),
        Ok(vec![PqSingleObservationBatchResolution::WaitRemote(
            PqSingleObservationStatus::ConsumptionPending,
        )]),
    );

    let remote_applied = identity(3, 0x13, 0x23);
    let applied_generation = remote_cache
        .claim_exact_single(&remote_applied, earliest_slot)
        .expect("remote applied claim");
    assert!(remote_cache.mark_exact_single_propagated(&remote_applied, applied_generation));
    assert!(remote_cache.finalize_exact_single(
        &remote_applied,
        applied_generation,
        PqSingleConsumptionResult::Applied,
    ));
    let remote_queued = identity(4, 0x14, 0x24);
    let queued_generation = remote_cache
        .claim_exact_single(&remote_queued, earliest_slot)
        .expect("remote queued claim");
    assert!(remote_cache.mark_exact_single_propagated(&remote_queued, queued_generation));
    assert!(remote_cache.finalize_exact_single(
        &remote_queued,
        queued_generation,
        PqSingleConsumptionResult::Queued,
    ));
    assert_eq!(
        remote_cache.resolve_exact_single_batch(
            &[remote(remote_applied), remote(remote_queued)],
            earliest_slot,
        ),
        Ok(vec![
            PqSingleObservationBatchResolution::Coalesced(PqSingleConsumptionResult::Applied,),
            PqSingleObservationBatchResolution::Coalesced(PqSingleConsumptionResult::Queued,),
        ]),
    );

    let remote_terminal = identity(5, 0x15, 0x25);
    let terminal_generation = remote_cache
        .claim_exact_single(&remote_terminal, earliest_slot)
        .expect("remote terminal claim");
    assert!(remote_cache.mark_exact_single_propagated(&remote_terminal, terminal_generation));
    assert!(remote_cache.finalize_exact_single(
        &remote_terminal,
        terminal_generation,
        PqSingleConsumptionResult::Terminal,
    ));
    let terminal_first = identity(6, 0x16, 0x26);
    let terminal_len_before = remote_cache.len_singles();
    assert_eq!(
        remote_cache.resolve_exact_single_batch(
            &[local(terminal_first), remote(remote_terminal)],
            earliest_slot,
        ),
        Err(PqSingleObservationBatchError::Terminal),
    );
    assert_eq!(remote_cache.len_singles(), terminal_len_before);
    assert_eq!(
        remote_cache.exact_single_status(&terminal_first),
        PqSingleObservationStatus::Unseen,
        "a terminal second member must not reserve the first"
    );

    let mut conflict_cache = TestingPqAttestationObservationCache::default();
    let known = identity(7, 0x17, 0x27);
    conflict_cache
        .claim_exact_single(&known, earliest_slot)
        .expect("known remote identity");
    let conflicting = identity(7, 0x17, 0x28);
    let conflict_first = identity(8, 0x18, 0x28);
    assert_eq!(
        conflict_cache.resolve_exact_single_batch(
            &[local(conflict_first), remote(conflicting)],
            earliest_slot,
        ),
        Err(PqSingleObservationBatchError::Conflict),
    );
    assert_eq!(
        conflict_cache.exact_single_status(&conflict_first),
        PqSingleObservationStatus::Unseen,
    );

    let mut capacity_cache = TestingPqAttestationObservationCache::default();
    for validator_index in 0..capacity_cache.capacity().saturating_sub(1) {
        let validator_index = u64::try_from(validator_index).expect("bounded test index");
        capacity_cache
            .claim_exact_single(&identity(validator_index, 0x71, 0x81), earliest_slot)
            .expect("fill to one below capacity");
    }
    let capacity_first = identity(100, 0x72, 0x82);
    let capacity_second = identity(101, 0x73, 0x83);
    let capacity_len_before = capacity_cache.len_singles();
    assert_eq!(
        capacity_cache.resolve_exact_single_batch(
            &[local(capacity_first), local(capacity_second)],
            earliest_slot,
        ),
        Err(PqSingleObservationBatchError::ObservationCapacity),
    );
    assert_eq!(capacity_cache.len_singles(), capacity_len_before);
    assert_eq!(
        capacity_cache.exact_single_status(&capacity_first),
        PqSingleObservationStatus::Unseen,
    );

    let mut generation_cache = TestingPqAttestationObservationCache::default();
    let generation_before = u64::MAX.saturating_sub(1);
    generation_cache.set_next_generation(generation_before);
    let generation_first = identity(110, 0x74, 0x84);
    let generation_second = identity(111, 0x75, 0x85);
    assert_eq!(
        generation_cache.resolve_exact_single_batch(
            &[local(generation_first), local(generation_second)],
            earliest_slot,
        ),
        Err(PqSingleObservationBatchError::GenerationExhausted),
    );
    assert_eq!(generation_cache.len_singles(), 0);
    assert_eq!(
        generation_cache.next_generation(),
        generation_before,
        "failed batch generation allocation must not advance the global generation"
    );
    assert_eq!(
        generation_cache.exact_single_status(&generation_first),
        PqSingleObservationStatus::Unseen,
    );

    let mut oversized_cache = TestingPqAttestationObservationCache::default();
    let oversized = [
        identity(120, 0x76, 0x86),
        identity(121, 0x77, 0x87),
        identity(122, 0x78, 0x88),
    ];
    assert_eq!(
        oversized_cache.resolve_exact_single_batch(&oversized.map(local), earliest_slot,),
        Err(PqSingleObservationBatchError::BatchCapacity {
            count: 3,
            maximum: 2,
        }),
    );
    assert_eq!(oversized_cache.len_singles(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn pq_single_observation_watch_is_exact_and_never_loses_completion() {
    async fn wait_for_completion(
        receipt: &mut PqSingleObservationWatchReceipt,
    ) -> PqSingleObservationCompletion {
        tokio::time::timeout(std::time::Duration::from_secs(1), receipt.wait())
            .await
            .expect("observation completion is bounded")
            .expect("observation watch remains result-bearing")
    }

    let identity = |validator_index, signed_root_byte, signed_ssz_byte| {
        PqSingleObservationIdentity::new(
            types::Epoch::new(0),
            validator_index,
            Slot::new(1),
            types::SubnetId::new(3),
            Hash256::repeat_byte(signed_root_byte),
            [signed_ssz_byte; 32],
        )
    };
    let earliest_slot = Slot::new(0);

    let mut rollback_cache = TestingPqAttestationObservationCache::default();
    let rollback_identity = identity(1, 0x11, 0x21);
    let rollback_generation = rollback_cache
        .claim_exact_single(&rollback_identity, earliest_slot)
        .expect("remote Pending claim");
    let mut rollback_receipt = rollback_cache
        .subscribe_exact_single(&rollback_identity)
        .expect("subscribe to exact Pending identity under the cache lock");
    assert!(rollback_cache.rollback_exact_single(&rollback_identity, rollback_generation,));
    assert_eq!(
        wait_for_completion(&mut rollback_receipt).await,
        PqSingleObservationCompletion::Released,
    );
    assert_eq!(
        rollback_cache.exact_single_status(&rollback_identity),
        PqSingleObservationStatus::Unseen,
    );

    for (validator_index, result) in [
        (2, PqSingleConsumptionResult::Applied),
        (3, PqSingleConsumptionResult::Queued),
        (4, PqSingleConsumptionResult::Terminal),
    ] {
        let mut cache = TestingPqAttestationObservationCache::default();
        let observed = identity(
            validator_index,
            0x30_u8.saturating_add(validator_index as u8),
            0x40_u8.saturating_add(validator_index as u8),
        );
        let generation = cache
            .claim_exact_single(&observed, earliest_slot)
            .expect("remote Pending claim");
        assert!(cache.mark_exact_single_propagated(&observed, generation));
        let mut receipt = cache
            .subscribe_exact_single(&observed)
            .expect("subscribe to exact ConsumptionPending identity");
        assert!(cache.finalize_exact_single(&observed, generation, result));
        assert_eq!(
            wait_for_completion(&mut receipt).await,
            PqSingleObservationCompletion::Consumed(result),
        );

        let mut completed_receipt = cache
            .subscribe_exact_single(&observed)
            .expect("already-consumed exact identity remains subscribable");
        assert_eq!(
            wait_for_completion(&mut completed_receipt).await,
            PqSingleObservationCompletion::Consumed(result),
            "a late subscriber must receive the retained result immediately"
        );
    }

    let mut prune_cache = TestingPqAttestationObservationCache::default();
    let pruned_pending = identity(5, 0x15, 0x25);
    prune_cache
        .claim_exact_single(&pruned_pending, earliest_slot)
        .expect("old Pending claim");
    let mut prune_receipt = prune_cache
        .subscribe_exact_single(&pruned_pending)
        .expect("subscribe before pruning old Pending");
    let next_epoch = types::Epoch::new(1);
    let next_epoch_start = next_epoch.start_slot(types::MinimalEthSpec::slots_per_epoch());
    assert_eq!(
        prune_cache.precheck_single(next_epoch, 15, next_epoch_start),
        beacon_chain::PqAttestationGossipObservation::Unseen,
    );
    assert_eq!(
        wait_for_completion(&mut prune_receipt).await,
        PqSingleObservationCompletion::Released,
    );

    let retained_pending = identity(6, 0x16, 0x26);
    let retained_generation = prune_cache
        .claim_exact_single(&retained_pending, earliest_slot)
        .expect("old propagated claim");
    assert!(prune_cache.mark_exact_single_propagated(&retained_pending, retained_generation,));
    let mut retained_receipt = prune_cache
        .subscribe_exact_single(&retained_pending)
        .expect("subscribe before attempted propagated prune");
    assert_eq!(
        prune_cache.precheck_single(next_epoch, 16, next_epoch_start),
        beacon_chain::PqAttestationGossipObservation::Unseen,
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1), retained_receipt.wait(),)
            .await
            .is_err(),
        "pruning must not release or strand ConsumptionPending"
    );
    assert!(prune_cache.finalize_exact_single(
        &retained_pending,
        retained_generation,
        PqSingleConsumptionResult::Queued,
    ));
    assert_eq!(
        wait_for_completion(&mut retained_receipt).await,
        PqSingleObservationCompletion::Consumed(PqSingleConsumptionResult::Queued),
    );

    let mut conflict_cache = TestingPqAttestationObservationCache::default();
    let known = identity(7, 0x17, 0x27);
    conflict_cache
        .claim_exact_single(&known, earliest_slot)
        .expect("known exact identity");
    let conflicting = identity(7, 0x17, 0x28);
    assert!(matches!(
        conflict_cache.subscribe_exact_single(&conflicting),
        Err(PqSingleObservationStatus::Conflict),
    ));

    let mut dropped_receipt = {
        let mut dropped_cache = TestingPqAttestationObservationCache::default();
        let dropped_identity = identity(8, 0x18, 0x28);
        dropped_cache
            .claim_exact_single(&dropped_identity, earliest_slot)
            .expect("pending identity whose cache owner will drop");
        dropped_cache
            .subscribe_exact_single(&dropped_identity)
            .expect("subscribe before cache owner drop")
    };
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_receipt.wait(),)
            .await
            .expect("cache drop closes the watch promptly"),
        Err(PqSingleObservationWatchError::Lost),
        "channel closure must be typed loss, never silent Pending"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn pq_single_observation_is_bound_to_the_exact_network_neutral_wire_message_id() {
    assert!(PqSingleWireMessageId::try_from(&[0x11; 19][..]).is_err());
    assert!(PqSingleWireMessageId::try_from(&[0x11; 21][..]).is_err());
    let wire_a = PqSingleWireMessageId::try_from(&[0xa1; 20][..])
        .expect("an exact 20-byte gossipsub MessageId converts once at ingress");
    let wire_b = PqSingleWireMessageId::try_from(&[0xb2; 20][..])
        .expect("a distinct exact 20-byte gossipsub MessageId is valid data");
    assert_eq!(wire_a.as_bytes(), &[0xa1; 20]);

    let identity = PqSingleObservationIdentity::new(
        types::Epoch::new(2),
        9,
        Slot::new(17),
        types::SubnetId::new(4),
        Hash256::repeat_byte(0x31),
        [0x41; 32],
    );

    for result in [
        PqSingleConsumptionResult::Applied,
        PqSingleConsumptionResult::Queued,
        PqSingleConsumptionResult::Terminal,
    ] {
        let cache = TestingPqWireBoundObservationCache::default();
        let generation = cache
            .claim_exact_single(&identity, wire_a, Slot::new(0))
            .expect("the original remote claim binds identity and wire ID atomically");
        assert_eq!(
            cache.exact_single_status(&identity, wire_a),
            PqSingleObservationStatus::Pending,
        );
        assert_eq!(
            cache.exact_single_status(&identity, wire_b),
            PqSingleObservationStatus::Conflict,
            "the same signed identity under a different wire ID is a conflict",
        );

        let mut receipt = cache
            .subscribe_exact_single(&identity, wire_a)
            .expect("subscription is acquired under the lock for the exact authority pair");
        assert!(cache.mark_exact_single_propagated(&identity, wire_a, generation));
        assert_eq!(
            cache.exact_single_status(&identity, wire_a),
            PqSingleObservationStatus::ConsumptionPending,
        );
        assert_eq!(
            cache.exact_single_status(&identity, wire_b),
            PqSingleObservationStatus::Conflict,
        );

        assert!(!cache.finalize_exact_single(&identity, wire_b, generation, result));
        assert!(!cache.rollback_exact_single(&identity, wire_b, generation));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), receipt.wait())
                .await
                .is_err(),
            "a different wire ID must neither finalize nor wake the exact subscriber",
        );

        assert!(cache.finalize_exact_single(&identity, wire_a, generation, result));
        assert_eq!(
            receipt.wait().await,
            Ok(PqSingleObservationCompletion::Consumed(result)),
        );
        assert_eq!(
            cache.exact_single_status(&identity, wire_a),
            PqSingleObservationStatus::Consumed(result),
        );
        assert_eq!(
            cache.exact_single_status(&identity, wire_b),
            PqSingleObservationStatus::Conflict,
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn pq_single_batch_resolution_owner_is_atomic_and_never_strands_reservations() {
    async fn exact_completion(
        owner: TestingPqSingleObservationResolutionReceipt,
    ) -> PqSingleObservationCompletion {
        let completions = tokio::time::timeout(std::time::Duration::from_secs(1), owner.wait_all())
            .await
            .expect("owned batch resolution remains bounded")
            .expect("owned batch resolution remains result-bearing");
        assert_eq!(completions.len(), 1);
        completions[0]
    }

    let identity = |validator_index, root_byte, digest_byte| {
        PqSingleObservationIdentity::new(
            types::Epoch::new(0),
            validator_index,
            Slot::new(1),
            types::SubnetId::new(3),
            Hash256::repeat_byte(root_byte),
            [digest_byte; 32],
        )
    };
    let local = TestingPqSingleObservationBatchInput::LocalWireSuccess;
    let remote = TestingPqSingleObservationBatchInput::Remote;
    let earliest_slot = Slot::new(0);

    for (validator_index, result) in [
        (1, PqSingleConsumptionResult::Applied),
        (2, PqSingleConsumptionResult::Queued),
    ] {
        let cache = TestingPqAttestationObservationOwnerCache::default();
        let observed = identity(
            validator_index,
            0x20_u8.saturating_add(validator_index as u8),
            0x30_u8.saturating_add(validator_index as u8),
        );
        let generation = cache
            .claim_exact_single(&observed, earliest_slot)
            .expect("remote Pending claim");
        let owner = cache
            .resolve_exact_single_batch_owned(&[remote(observed)], earliest_slot)
            .expect("atomic remote resolution owner");
        assert!(cache.mark_exact_single_propagated(&observed, generation));
        assert!(cache.finalize_exact_single(&observed, generation, result));
        assert_eq!(
            exact_completion(owner).await,
            PqSingleObservationCompletion::Consumed(result),
            "finalization before the first wait must remain retained",
        );
    }

    let released_cache = TestingPqAttestationObservationOwnerCache::default();
    let released = identity(3, 0x23, 0x33);
    released_cache
        .claim_exact_single(&released, earliest_slot)
        .expect("old remote Pending claim");
    let released_owner = released_cache
        .resolve_exact_single_batch_owned(&[remote(released)], earliest_slot)
        .expect("remote Pending watch owner");
    let next_epoch = types::Epoch::new(1);
    let next_epoch_start = next_epoch.start_slot(types::MinimalEthSpec::slots_per_epoch());
    assert_eq!(
        released_cache.precheck_single(next_epoch, 13, next_epoch_start),
        beacon_chain::PqAttestationGossipObservation::Unseen,
    );
    assert_eq!(
        exact_completion(released_owner).await,
        PqSingleObservationCompletion::Released,
        "prune before the first wait must retain Released",
    );

    let local_cache = TestingPqAttestationObservationOwnerCache::default();
    let local_reserved = identity(4, 0x24, 0x34);
    let local_owner = local_cache
        .resolve_exact_single_batch_owned(&[local(local_reserved)], earliest_slot)
        .expect("local wire-success reservation owner");
    assert_eq!(
        local_cache.exact_single_status(&local_reserved),
        PqSingleObservationStatus::ConsumptionPending,
    );
    drop(local_owner);
    assert_eq!(
        local_cache.exact_single_status(&local_reserved),
        PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Terminal),
        "dropping the sole local reservation owner must terminalize, never strand",
    );

    let atomic_cache = TestingPqAttestationObservationOwnerCache::default();
    let generation_before = atomic_cache.next_generation();
    let first_local = identity(5, 0x25, 0x35);
    let second_remote_unseen = identity(6, 0x26, 0x36);
    assert!(matches!(
        atomic_cache.resolve_exact_single_batch_owned(
            &[local(first_local), remote(second_remote_unseen)],
            earliest_slot,
        ),
        Err(PqSingleObservationBatchError::RemoteUnseen),
    ));
    assert_eq!(atomic_cache.resolution_owner_count(), 0);
    assert_eq!(atomic_cache.next_generation(), generation_before);
    assert_eq!(
        atomic_cache.exact_single_status(&first_local),
        PqSingleObservationStatus::Unseen,
        "a second-member error must create neither owner nor first reservation",
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_published_local_batch_consumption_is_atomic_ordered_and_fail_closed() {
    async fn compile_pin_whole_batch_api(
        chain: Arc<beacon_chain::BeaconChain<TestWitness>>,
        evidence: PqPublishedLocalAttestationEvidenceBatch<MinimalEthSpec>,
    ) -> Result<
        PqPublishedLocalAttestationBatchConsumptionOutcome,
        PqPublishedLocalAttestationBatchConsumptionError,
    > {
        chain
            .pq_published_local_attestation_batch_consumer()
            .consume(evidence)
            .await
    }
    let _ = compile_pin_whole_batch_api;

    let identity = |validator_index, root_byte, digest_byte| {
        PqSingleObservationIdentity::new(
            types::Epoch::new(0),
            validator_index,
            Slot::new(1),
            types::SubnetId::new(3),
            Hash256::repeat_byte(root_byte),
            [digest_byte; 32],
        )
    };
    let first = identity(1, 0x11, 0x21);
    let second = identity(2, 0x12, 0x22);
    let identities = [first, second];

    let success_cache = TestingPqAttestationObservationOwnerCache::default();
    let success = success_cache
        .consume_published_local_batch_for_testing(
            &identities,
            vec![
                Ok(PqForkChoiceAttestationOutcome::Applied),
                Ok(PqForkChoiceAttestationOutcome::Queued),
            ],
        )
        .await;
    assert_eq!(
        success.result,
        Ok(
            PqPublishedLocalAttestationBatchConsumptionOutcome::Complete {
                results: vec![
                    PqSingleConsumptionResult::Applied,
                    PqSingleConsumptionResult::Queued,
                ],
            }
        ),
    );
    assert_eq!(
        success.apply_attempt_order,
        vec![0, 1],
        "local wire-success members must reserve atomically and apply in sealed batch order",
    );
    assert_eq!(success.fail_closed_calls, 0);
    assert_eq!(
        success_cache.exact_single_status(&first),
        PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Applied),
    );
    assert_eq!(
        success_cache.exact_single_status(&second),
        PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Queued),
    );

    let replay = success_cache
        .consume_published_local_batch_for_testing(&identities, vec![])
        .await;
    assert_eq!(replay.result, success.result);
    assert!(
        replay.apply_attempt_order.is_empty(),
        "an exact already-consumed replay must coalesce without a second fork-choice call",
    );
    assert_eq!(replay.fail_closed_calls, 0);

    let failure_cache = TestingPqAttestationObservationOwnerCache::default();
    let failure = failure_cache
        .consume_published_local_batch_for_testing(
            &identities,
            vec![
                Ok(PqForkChoiceAttestationOutcome::Applied),
                Err(PqForkChoiceAttestationError::TaskUnavailable),
            ],
        )
        .await;
    assert_eq!(
        failure.result,
        Err(
            PqPublishedLocalAttestationBatchConsumptionError::ApplyFailed {
                applied_count: 1,
                failed_index: 1,
            },
        ),
    );
    assert_eq!(failure.apply_attempt_order, vec![0, 1]);
    assert_eq!(failure.fail_closed_calls, 1);
    assert_eq!(
        failure_cache.exact_single_status(&first),
        PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Applied),
    );
    assert_eq!(
        failure_cache.exact_single_status(&second),
        PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Terminal),
    );

    let failure_replay = failure_cache
        .consume_published_local_batch_for_testing(&identities, vec![])
        .await;
    assert_eq!(
        failure_replay.result,
        Err(
            PqPublishedLocalAttestationBatchConsumptionError::Observation(
                PqSingleObservationBatchError::Terminal,
            )
        ),
    );
    assert!(
        failure_replay.apply_attempt_order.is_empty(),
        "an irreversible partial result must never retry or reapply its successful prefix",
    );
    assert_eq!(failure_replay.fail_closed_calls, 0);

    let dropped_cache = TestingPqAttestationObservationOwnerCache::default();
    let fail_closed_calls = Arc::new(AtomicUsize::new(0));
    let fail_closed_calls_for_owner = Arc::clone(&fail_closed_calls);
    dropped_cache.drop_published_local_batch_owner_before_apply_for_testing(
        &identities,
        move || {
            fail_closed_calls_for_owner.fetch_add(1, Ordering::SeqCst);
        },
    );
    assert_eq!(fail_closed_calls.load(Ordering::SeqCst), 1);
    for identity in identities {
        assert_eq!(
            dropped_cache.exact_single_status(&identity),
            PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Terminal),
            "dropping the post-wire owner must terminalize every local reservation",
        );
    }
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_published_local_pool_invariant_terminalizes_exact_reservation_once() {
    let identity = |validator_index, root_byte, digest_byte| {
        PqSingleObservationIdentity::new(
            types::Epoch::new(0),
            validator_index,
            Slot::new(1),
            types::SubnetId::new(3),
            Hash256::repeat_byte(root_byte),
            [digest_byte; 32],
        )
    };
    let first = identity(1, 0x11, 0x21);
    let second = identity(2, 0x12, 0x22);
    let cache = TestingPqAttestationObservationOwnerCache::default();
    let trace = cache
        .consume_published_local_batch_with_pool_invariant_for_testing(&[first, second], 1)
        .await;

    assert!(matches!(
        trace.result,
        Err(
            PqPublishedLocalAttestationBatchConsumptionError::PoolInvariant {
                index: 1,
                invariant: operation_pool::PqAttestationPoolInsertInvariant::GenerationExhausted,
            }
        )
    ));
    assert_eq!(trace.apply_attempt_order, vec![0, 1]);
    assert_eq!(trace.fail_closed_calls, 1);
    assert_eq!(
        cache.exact_single_status(&first),
        PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Applied),
    );
    assert_eq!(
        cache.exact_single_status(&second),
        PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Terminal),
        "the failed member reservation must not remain ConsumptionPending",
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_published_local_batch_rechecks_head_after_remote_settlement_before_apply() {
    const WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(1);
    let signed_slot = Slot::new(1);
    let advanced_slot = Slot::new(2);
    let bound_head_root = Hash256::repeat_byte(0xa1);
    let advanced_head_root = Hash256::repeat_byte(0xa2);

    let lagging_hook = TestingPqBlockingHook::counting();
    let lagging = TestingPqPublishedLocalLateApplyHarness::new(
        signed_slot,
        bound_head_root,
        Arc::clone(&lagging_hook),
    );
    let lagging_receipt = lagging.start_mixed_local_and_remote();
    tokio::time::timeout(WAIT_BOUND, lagging.wait_until_remote_settlement())
        .await
        .expect("mixed batch genuinely reaches its remote wait");
    drop(
        lagging
            .try_hold_import_gate()
            .expect("the import gate is not held across remote settlement"),
    );
    lagging.set_clock(advanced_slot);
    lagging.finalize_remote(PqSingleConsumptionResult::Queued);
    assert_eq!(
        tokio::time::timeout(WAIT_BOUND, lagging_receipt.wait())
            .await
            .expect("late lagging-head failure is bounded"),
        Err(PqPublishedLocalAttestationBatchConsumptionError::Preflight(
            beacon_chain::PqLocalAttestationBatchPreflightError::HeadNotReady {
                head: signed_slot,
                current: advanced_slot,
            },
        )),
    );
    assert_eq!(lagging.fork_choice_attestation_calls(), 0);
    assert_eq!(lagging.fail_closed_calls(), 1);
    assert_eq!(
        lagging.local_observation_status(),
        PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Terminal),
    );
    assert_eq!(
        lagging.available_local_proof_permits(),
        PQ_LOCAL_ATTESTATION_PROOF_ADMISSION_CAPACITY,
        "terminal post-settlement preflight releases the retained verified-batch guards",
    );

    let incompatible_hook = TestingPqBlockingHook::counting();
    let incompatible = TestingPqPublishedLocalLateApplyHarness::new(
        signed_slot,
        bound_head_root,
        Arc::clone(&incompatible_hook),
    );
    let incompatible_receipt = incompatible.start_mixed_local_and_remote();
    tokio::time::timeout(WAIT_BOUND, incompatible.wait_until_remote_settlement())
        .await
        .expect("incompatible-head case reaches its remote wait");
    incompatible.set_clock(advanced_slot);
    incompatible.set_reconciled_head(advanced_slot, advanced_head_root, false);
    incompatible.finalize_remote(PqSingleConsumptionResult::Queued);
    assert_eq!(
        tokio::time::timeout(WAIT_BOUND, incompatible_receipt.wait())
            .await
            .expect("late incompatible-head failure is bounded"),
        Err(PqPublishedLocalAttestationBatchConsumptionError::Preflight(
            beacon_chain::PqLocalAttestationBatchPreflightError::BoundHeadNotCanonical {
                bound: bound_head_root,
                current: advanced_head_root,
            },
        )),
    );
    assert_eq!(incompatible.fork_choice_attestation_calls(), 0);
    assert_eq!(incompatible.fail_closed_calls(), 1);
    assert_eq!(
        incompatible.local_observation_status(),
        PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Terminal),
    );

    let fork_choice_ahead_hook = TestingPqBlockingHook::counting();
    let fork_choice_ahead = TestingPqPublishedLocalLateApplyHarness::new(
        signed_slot,
        bound_head_root,
        Arc::clone(&fork_choice_ahead_hook),
    );
    let fork_choice_ahead_receipt = fork_choice_ahead.start_mixed_local_and_remote();
    tokio::time::timeout(WAIT_BOUND, fork_choice_ahead.wait_until_remote_settlement())
        .await
        .expect("fork-choice-ahead case reaches its remote wait");
    fork_choice_ahead.set_clock(advanced_slot);
    fork_choice_ahead.set_reconciled_head(advanced_slot, advanced_head_root, true);
    fork_choice_ahead.set_fork_choice_slot(Slot::new(3));
    fork_choice_ahead.finalize_remote(PqSingleConsumptionResult::Queued);
    assert_eq!(
        tokio::time::timeout(WAIT_BOUND, fork_choice_ahead_receipt.wait())
            .await
            .expect("fork-choice-ahead failure is bounded"),
        Err(PqPublishedLocalAttestationBatchConsumptionError::Preflight(
            beacon_chain::PqLocalAttestationBatchPreflightError::ForkChoiceTimeAhead {
                fork_choice: Slot::new(3),
                current: advanced_slot,
            },
        )),
    );
    assert_eq!(fork_choice_ahead.fork_choice_attestation_calls(), 0);
    assert_eq!(fork_choice_ahead.fail_closed_calls(), 1);

    let far_current_slot = Slot::new(10);
    let far_signed_slot = Slot::new(9);
    let far_head_root = Hash256::repeat_byte(0xa3);
    let fork_choice_behind_hook = TestingPqBlockingHook::counting();
    let fork_choice_behind = TestingPqPublishedLocalLateApplyHarness::new(
        far_signed_slot,
        bound_head_root,
        Arc::clone(&fork_choice_behind_hook),
    );
    let fork_choice_behind_receipt = fork_choice_behind.start_mixed_local_and_remote();
    tokio::time::timeout(
        WAIT_BOUND,
        fork_choice_behind.wait_until_remote_settlement(),
    )
    .await
    .expect("fork-choice-behind case reaches its remote wait");
    fork_choice_behind.set_clock(far_current_slot);
    fork_choice_behind.set_reconciled_head(far_current_slot, far_head_root, true);
    fork_choice_behind.set_fork_choice_slot(signed_slot);
    fork_choice_behind.finalize_remote(PqSingleConsumptionResult::Queued);
    assert_eq!(
        tokio::time::timeout(WAIT_BOUND, fork_choice_behind_receipt.wait())
            .await
            .expect("fork-choice-behind failure is bounded"),
        Err(PqPublishedLocalAttestationBatchConsumptionError::Preflight(
            beacon_chain::PqLocalAttestationBatchPreflightError::ForkChoiceTimeTooFarBehind {
                fork_choice: signed_slot,
                current: far_current_slot,
                maximum: beacon_chain::PQ_FORK_CHOICE_TICK_MAX_ADVANCE,
            },
        )),
    );
    assert_eq!(fork_choice_behind.fork_choice_attestation_calls(), 0);
    assert_eq!(fork_choice_behind.fail_closed_calls(), 1);

    let compatible_hook = TestingPqBlockingHook::blocking();
    let compatible = TestingPqPublishedLocalLateApplyHarness::new(
        signed_slot,
        bound_head_root,
        Arc::clone(&compatible_hook),
    );
    let compatible_receipt = compatible.start_mixed_local_and_remote();
    tokio::time::timeout(WAIT_BOUND, compatible.wait_until_remote_settlement())
        .await
        .expect("compatible-head case reaches its remote wait");
    compatible.set_clock(advanced_slot);
    compatible.set_reconciled_head(advanced_slot, advanced_head_root, true);
    compatible.finalize_remote(PqSingleConsumptionResult::Queued);
    let entered = tokio::time::timeout(WAIT_BOUND, async {
        while compatible_hook.entered() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    let import_gate_held_during_apply = compatible.try_hold_import_gate().is_none();
    compatible_hook.release();
    assert_eq!(
        entered, true,
        "local apply reaches the real blocking boundary"
    );
    assert!(
        import_gate_held_during_apply,
        "the post-settlement import gate remains held through blocking fork-choice application",
    );
    assert_eq!(
        tokio::time::timeout(WAIT_BOUND, compatible_receipt.wait())
            .await
            .expect("compatible local application is bounded"),
        Ok(
            PqPublishedLocalAttestationBatchConsumptionOutcome::Complete {
                results: vec![
                    PqSingleConsumptionResult::Applied,
                    PqSingleConsumptionResult::Queued,
                ],
            }
        ),
    );
    assert_eq!(
        compatible.last_fork_choice_current_slot(),
        Some(advanced_slot),
        "fork choice receives the actual post-settlement current slot, not the attestation slot",
    );
    assert_eq!(compatible.fork_choice_attestation_calls(), 1);
    assert_eq!(compatible.fail_closed_calls(), 0);
    drop(
        compatible
            .try_hold_import_gate()
            .expect("successful apply releases the short import-gate guard"),
    );

    let fc_entry_hook = TestingPqBlockingHook::blocking();
    let stale_clock_apply_hook = TestingPqBlockingHook::counting();
    let stale_clock = TestingPqPublishedLocalLateApplyHarness::new(
        signed_slot,
        bound_head_root,
        Arc::clone(&stale_clock_apply_hook),
    );
    stale_clock.set_fork_choice_entry_hook(Arc::clone(&fc_entry_hook));
    let stale_clock_receipt = stale_clock.start_mixed_local_and_remote();
    tokio::time::timeout(WAIT_BOUND, stale_clock.wait_until_remote_settlement())
        .await
        .expect("stale-clock case reaches its remote wait");
    stale_clock.set_clock(advanced_slot);
    stale_clock.set_reconciled_head(advanced_slot, advanced_head_root, true);
    stale_clock.finalize_remote(PqSingleConsumptionResult::Queued);
    let entered = tokio::time::timeout(WAIT_BOUND, async {
        while fc_entry_hook.entered() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    let gate_held_before_fc_lock = stale_clock.try_hold_import_gate().is_none();
    let final_slot = Slot::new(3);
    stale_clock.set_clock(final_slot);
    fc_entry_hook.release();
    assert!(
        entered,
        "the task blocks immediately before the FC critical section"
    );
    assert!(
        gate_held_before_fc_lock,
        "the import gate remains retained while FC entry is blocked",
    );
    assert_eq!(
        tokio::time::timeout(WAIT_BOUND, stale_clock_receipt.wait())
            .await
            .expect("post-FC-wait clock rejection is bounded"),
        Err(PqPublishedLocalAttestationBatchConsumptionError::Preflight(
            beacon_chain::PqLocalAttestationBatchPreflightError::ClockChanged {
                sampled: advanced_slot,
                current: final_slot,
            },
        )),
    );
    assert_eq!(stale_clock.fork_choice_attestation_calls(), 0);
    assert_eq!(stale_clock.fail_closed_calls(), 1);
    assert_eq!(
        stale_clock.local_observation_status(),
        PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Terminal),
    );
    assert_eq!(
        stale_clock.available_local_proof_permits(),
        PQ_LOCAL_ATTESTATION_PROOF_ADMISSION_CAPACITY,
    );
    drop(
        stale_clock
            .try_hold_import_gate()
            .expect("stale-clock terminal resolution releases the import gate"),
    );

    let production_route =
        include_str!("../../../beacon_node/beacon_chain/src/pq_runtime/beacon_chain.rs");
    let harness_route =
        include_str!("../../../beacon_node/beacon_chain/src/pq_runtime/attestation_gossip.rs");
    for source in [production_route, harness_route] {
        assert!(
            source.contains("consume_pq_published_local_attestation_batch_after_settlement"),
            "the real continuation and cfg harness must call one full post-settlement route",
        );
    }
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_post_wire_evidence_is_unforgeable_exact_and_checked_before_fork_choice() {
    let identity = |validator_index, root_byte, digest_byte| {
        PqSingleObservationIdentity::new(
            types::Epoch::new(0),
            validator_index,
            Slot::new(1),
            types::SubnetId::new(validator_index),
            Hash256::repeat_byte(root_byte),
            [digest_byte; 32],
        )
    };
    let members = [identity(1, 0x41, 0x51), identity(2, 0x42, 0x52)];
    let message_ids = [MessageId(vec![0x61; 20]), MessageId(vec![0x62; 20])];

    for mutation in [
        TestingPqPublishedLocalAttestationEvidenceMutation::SignedSszByte,
        TestingPqPublishedLocalAttestationEvidenceMutation::Topic,
        TestingPqPublishedLocalAttestationEvidenceMutation::MessageId,
        TestingPqPublishedLocalAttestationEvidenceMutation::MemberIdentity,
        TestingPqPublishedLocalAttestationEvidenceMutation::MemberOrder,
        TestingPqPublishedLocalAttestationEvidenceMutation::MemberCount,
    ] {
        let harness =
            TestingPqPublishedLocalAttestationEvidenceHarness::from_exact_lower_publications(
                members,
            )
            .await
            .expect("the harness obtains opaque tokens only through the exact lower publisher");
        let trace = harness.consume_with_local_evidence_mutation(mutation).await;
        assert!(matches!(
            trace.result,
            Err(PqPublishedLocalAttestationEvidenceError::Mismatch { .. })
        ));
        assert_eq!(trace.fork_choice_calls, 0);
        assert_eq!(trace.fail_closed_calls, 1);
    }

    for remote_status in [
        TestingPqRemotePublicationEvidenceStatus::Unseen,
        TestingPqRemotePublicationEvidenceStatus::Conflict,
        TestingPqRemotePublicationEvidenceStatus::Terminal,
    ] {
        let harness = TestingPqPublishedLocalAttestationEvidenceHarness::with_remote_observations(
            [
                (message_ids[0].clone(), members[0]),
                (message_ids[1].clone(), members[1]),
            ],
            remote_status,
        );
        let trace = harness
            .consume_claimed_remote([
                (message_ids[0].clone(), PqSingleConsumptionResult::Applied),
                (message_ids[1].clone(), PqSingleConsumptionResult::Queued),
            ])
            .await;
        assert!(trace.result.is_err());
        assert_eq!(trace.fork_choice_calls, 0);
        assert_eq!(trace.fail_closed_calls, 1);
    }

    let swapped_message_id_harness =
        TestingPqPublishedLocalAttestationEvidenceHarness::with_remote_consumed([
            (
                message_ids[0].clone(),
                members[0],
                PqSingleConsumptionResult::Applied,
            ),
            (
                message_ids[1].clone(),
                members[1],
                PqSingleConsumptionResult::Queued,
            ),
        ]);
    let swapped_message_id_trace = swapped_message_id_harness
        .consume_claimed_remote([
            (message_ids[1].clone(), PqSingleConsumptionResult::Applied),
            (message_ids[0].clone(), PqSingleConsumptionResult::Queued),
        ])
        .await;
    assert!(swapped_message_id_trace.result.is_err());
    assert_eq!(swapped_message_id_trace.fork_choice_calls, 0);
    assert_eq!(swapped_message_id_trace.fail_closed_calls, 1);

    let harness = TestingPqPublishedLocalAttestationEvidenceHarness::with_remote_consumed([
        (
            message_ids[0].clone(),
            members[0],
            PqSingleConsumptionResult::Applied,
        ),
        (
            message_ids[1].clone(),
            members[1],
            PqSingleConsumptionResult::Queued,
        ),
    ]);
    let trace = harness
        .consume_claimed_remote([
            (message_ids[0].clone(), PqSingleConsumptionResult::Applied),
            (message_ids[1].clone(), PqSingleConsumptionResult::Queued),
        ])
        .await;
    assert_eq!(
        trace.result,
        Ok(
            PqPublishedLocalAttestationBatchConsumptionOutcome::Complete {
                results: vec![
                    PqSingleConsumptionResult::Applied,
                    PqSingleConsumptionResult::Queued,
                ],
            },
        ),
    );
    assert_eq!(trace.fork_choice_calls, 0);
    assert_eq!(trace.fail_closed_calls, 0);
}

#[test]
fn pq_post_wire_evidence_dependency_is_proposer_only_and_one_way() {
    let manifest = include_str!("../../../beacon_node/beacon_chain/Cargo.toml");
    assert!(manifest.contains("pq-proposer = ["));
    assert!(manifest.contains("dep:lighthouse_network"));
    assert!(manifest.contains("lighthouse_network = {"));
    assert!(manifest.contains("optional = true"));

    let public_surface = include_str!("../../../beacon_node/beacon_chain/src/lib.rs");
    assert!(public_surface.contains("PqPublishedLocalAttestationEvidenceBatch"));
    assert!(!public_surface.contains("PqLocalSinglePublicationToken"));
}

#[test]
fn pq_published_local_batch_consumption_keeps_raw_resolution_types_private() {
    let public_surface = include_str!("../../../beacon_node/beacon_chain/src/lib.rs");
    for forbidden in [
        "PqSingleObservationBatchRequest",
        "PqSingleObservationBatchSource",
        "PqSingleObservationBatchResolutionOwner",
    ] {
        assert!(
            !public_surface.contains(forbidden),
            "raw observation batch type {forbidden} must not be exported by beacon_chain",
        );
    }
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_published_local_batch_supervisor_is_uncancellable_and_fail_closed() {
    async fn wait_until_entered(hook: &TestingPqBlockingHook) {
        for _ in 0..1_000 {
            if hook.entered() > 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("bounded Cycle W supervisor hook was never entered");
    }

    for failure in [
        TestingPqPublishedLocalAttestationSupervisorFailure::Preflight,
        TestingPqPublishedLocalAttestationSupervisorFailure::InvalidIndexed,
        TestingPqPublishedLocalAttestationSupervisorFailure::Observation,
        TestingPqPublishedLocalAttestationSupervisorFailure::Panic,
    ] {
        let hook = TestingPqBlockingHook::blocking();
        let harness =
            TestingPqPublishedLocalAttestationSupervisorHarness::new(failure, Arc::clone(&hook));
        let receipt = harness.start_after_wire();
        wait_until_entered(&hook).await;
        drop(receipt);

        let mut drain = Box::pin(harness.close_and_drain());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), &mut drain)
                .await
                .is_err(),
            "caller drop must not release the after-wire supervisor/coordinator"
        );
        hook.release();
        tokio::time::timeout(std::time::Duration::from_secs(1), drain)
            .await
            .expect("after-wire failure supervisor drains after bounded resolution");
        assert_eq!(
            harness.fail_closed_calls(),
            1,
            "{failure:?} must signal fail-closed exactly once inside the no-exit owner",
        );
        assert_eq!(harness.active_operations(), 0);
    }
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn pq_published_local_batch_waits_and_reclaims_remote_observations_exactly() {
    let identity = |validator_index, root_byte, digest_byte| {
        PqSingleObservationIdentity::new(
            types::Epoch::new(0),
            validator_index,
            Slot::new(1),
            types::SubnetId::new(3),
            Hash256::repeat_byte(root_byte),
            [digest_byte; 32],
        )
    };
    let earliest_slot = Slot::new(0);

    for (validator_index, result) in [
        (1, PqSingleConsumptionResult::Applied),
        (2, PqSingleConsumptionResult::Queued),
    ] {
        let cache = TestingPqAttestationObservationOwnerCache::default();
        let remote = identity(
            validator_index,
            0x10_u8.saturating_add(validator_index as u8),
            0x20_u8.saturating_add(validator_index as u8),
        );
        let generation = cache
            .claim_exact_single(&remote, earliest_slot)
            .expect("remote Pending claim");
        let receipt = cache.start_published_local_batch_wait_for_testing(
            &[TestingPqSingleObservationBatchInput::LocalWireSuccess(
                remote,
            )],
            vec![],
        );
        assert!(cache.mark_exact_single_propagated(&remote, generation));
        assert!(cache.finalize_exact_single(&remote, generation, result));
        let trace = receipt.wait().await;
        assert_eq!(
            trace.result,
            Ok(
                PqPublishedLocalAttestationBatchConsumptionOutcome::Complete {
                    results: vec![result],
                }
            ),
            "completion before the first poll must remain observable",
        );
        assert!(trace.apply_attempt_order.is_empty());
        assert_eq!(trace.fail_closed_calls, 0);
    }

    let after_poll_cache = TestingPqAttestationObservationOwnerCache::default();
    let after_poll = identity(3, 0x13, 0x23);
    let after_poll_generation = after_poll_cache
        .claim_exact_single(&after_poll, earliest_slot)
        .expect("remote Pending claim");
    assert!(after_poll_cache.mark_exact_single_propagated(&after_poll, after_poll_generation));
    let after_poll_receipt = after_poll_cache.start_published_local_batch_wait_for_testing(
        &[TestingPqSingleObservationBatchInput::LocalWireSuccess(
            after_poll,
        )],
        vec![],
    );
    let after_poll_wait = tokio::spawn(async move { after_poll_receipt.wait().await });
    tokio::task::yield_now().await;
    assert!(after_poll_cache.finalize_exact_single(
        &after_poll,
        after_poll_generation,
        PqSingleConsumptionResult::Queued,
    ));
    let after_poll_trace = tokio::time::timeout(std::time::Duration::from_secs(1), after_poll_wait)
        .await
        .expect("after-poll coalescing is bounded")
        .expect("after-poll waiter remains monitored");
    assert_eq!(
        after_poll_trace.result,
        Ok(
            PqPublishedLocalAttestationBatchConsumptionOutcome::Complete {
                results: vec![PqSingleConsumptionResult::Queued],
            }
        ),
    );
    assert!(after_poll_trace.apply_attempt_order.is_empty());
    assert_eq!(after_poll_trace.fail_closed_calls, 0);

    let released_cache = TestingPqAttestationObservationOwnerCache::default();
    let released = identity(4, 0x14, 0x24);
    let released_generation = released_cache
        .claim_exact_single(&released, earliest_slot)
        .expect("remote Pending claim");
    let released_receipt = released_cache.start_published_local_batch_wait_for_testing(
        &[TestingPqSingleObservationBatchInput::LocalWireSuccess(
            released,
        )],
        vec![Ok(PqForkChoiceAttestationOutcome::Applied)],
    );
    assert!(released_cache.rollback_exact_single(&released, released_generation));
    let released_trace = released_receipt.wait().await;
    assert_eq!(
        released_trace.result,
        Ok(
            PqPublishedLocalAttestationBatchConsumptionOutcome::Complete {
                results: vec![PqSingleConsumptionResult::Applied],
            }
        ),
    );
    assert_eq!(released_trace.apply_attempt_order, vec![0]);
    assert_eq!(released_trace.fail_closed_calls, 0);

    let mixed_cache = TestingPqAttestationObservationOwnerCache::default();
    let local = identity(5, 0x15, 0x25);
    let remote = identity(6, 0x16, 0x26);
    let remote_generation = mixed_cache
        .claim_exact_single(&remote, earliest_slot)
        .expect("remote Pending claim");
    assert!(mixed_cache.mark_exact_single_propagated(&remote, remote_generation));
    let mixed_receipt = mixed_cache.start_published_local_batch_wait_for_testing(
        &[
            TestingPqSingleObservationBatchInput::LocalWireSuccess(local),
            TestingPqSingleObservationBatchInput::LocalWireSuccess(remote),
        ],
        vec![Ok(PqForkChoiceAttestationOutcome::Applied)],
    );
    let mixed_wait = tokio::spawn(async move { mixed_receipt.wait().await });
    tokio::task::yield_now().await;
    assert_eq!(
        mixed_cache.exact_single_status(&local),
        PqSingleObservationStatus::ConsumptionPending,
        "local reservation must stay armed while the exact remote member is unresolved",
    );
    assert!(mixed_cache.finalize_exact_single(
        &remote,
        remote_generation,
        PqSingleConsumptionResult::Applied,
    ));
    let mixed_trace = tokio::time::timeout(std::time::Duration::from_secs(1), mixed_wait)
        .await
        .expect("mixed resolution is bounded")
        .expect("mixed resolution owner remains monitored");
    assert_eq!(
        mixed_trace.result,
        Ok(
            PqPublishedLocalAttestationBatchConsumptionOutcome::Complete {
                results: vec![
                    PqSingleConsumptionResult::Applied,
                    PqSingleConsumptionResult::Applied,
                ],
            }
        ),
    );
    assert_eq!(mixed_trace.apply_attempt_order, vec![0]);

    for terminal_case in ["terminal", "lost", "conflict"] {
        let cache = TestingPqAttestationObservationOwnerCache::default();
        let known = identity(7, 0x17, 0x27);
        let generation = cache
            .claim_exact_single(&known, earliest_slot)
            .expect("known remote claim");
        let requested = if terminal_case == "conflict" {
            identity(7, 0x17, 0x28)
        } else {
            known
        };
        let receipt = cache.start_published_local_batch_wait_for_testing(
            &[TestingPqSingleObservationBatchInput::LocalWireSuccess(
                requested,
            )],
            vec![],
        );
        match terminal_case {
            "terminal" => {
                assert!(cache.mark_exact_single_propagated(&known, generation));
                assert!(cache.finalize_exact_single(
                    &known,
                    generation,
                    PqSingleConsumptionResult::Terminal,
                ));
            }
            "lost" => cache.lose_exact_single_completion_for_testing(&known),
            "conflict" => {}
            _ => unreachable!("fixed terminal case"),
        }
        let trace = receipt.wait().await;
        assert!(trace.result.is_err(), "{terminal_case} must be terminal");
        assert_eq!(
            trace.fail_closed_calls, 1,
            "{terminal_case} must signal fail-closed exactly once",
        );
        assert!(trace.apply_attempt_order.is_empty());
    }
}

#[test]
fn pq_aggregate_observation_updates_both_indexes_atomically() {
    let mut cache = TestingPqAttestationObservationCache::default();
    let epoch = types::Epoch::new(0);
    let slot = Slot::new(0);
    let data_root = Hash256::repeat_byte(3);
    let identity = Hash256::repeat_byte(4);
    let first_generation = cache
        .claim_aggregate(epoch, 7, slot, data_root, 0, identity, &[0], slot)
        .expect("first aggregate claim");
    assert_eq!(cache.len_aggregators(), 1);
    assert_eq!(cache.len_aggregate_candidates(), 1);
    assert!(cache.rollback_aggregate(
        epoch,
        7,
        slot,
        data_root,
        0,
        identity,
        first_generation,
        &[0],
    ));
    assert_eq!(cache.len_aggregators(), 0);
    assert_eq!(cache.len_aggregate_candidates(), 0);

    let superset = [0, 1];
    let retry_generation = cache
        .claim_aggregate(epoch, 8, slot, data_root, 0, identity, &superset, slot)
        .expect("aggregate retry");
    assert!(cache.finalize_aggregate(
        epoch,
        8,
        slot,
        data_root,
        0,
        identity,
        retry_generation,
        &superset,
    ));
    assert_eq!(cache.len_aggregators(), 1);
    assert_eq!(cache.len_aggregate_candidates(), 1);
    assert_eq!(
        cache.precheck_aggregate(epoch, 9, slot, data_root, 0, &[0], slot),
        beacon_chain::PqAttestationGossipObservation::Observed
    );
}

#[test]
fn every_external_block_source_uses_the_same_import_boundary() {
    assert_eq!(
        PqBlockImportSource::ALL,
        [
            PqBlockImportSource::Gossip,
            PqBlockImportSource::Publish,
            PqBlockImportSource::Rpc,
            PqBlockImportSource::Lookup,
            PqBlockImportSource::ForwardRange,
        ]
    );
}

#[test]
fn peer_invalid_and_local_failures_have_stable_scoring_and_retry_policy() {
    let peer_error = PqImportError::PeerInvalid(PqImportPeerInvalid::NonLinearRange {
        expected: Hash256::repeat_byte(1),
        actual: Hash256::repeat_byte(2),
    });
    assert!(peer_error.should_penalize_peer());
    assert!(!peer_error.is_retryable());

    let unavailable_parent = PqImportError::Local(PqImportLocalError::ParentUnavailable {
        parent_root: Hash256::repeat_byte(3),
    });
    assert!(!unavailable_parent.should_penalize_peer());
    assert!(unavailable_parent.is_retryable());

    let saturated = PqImportError::Local(PqImportLocalError::IngressCapacity);
    assert!(!saturated.should_penalize_peer());
    assert!(saturated.is_retryable());

    let stale = PqImportError::StaleHeadAfterVerification {
        expected_parent: Hash256::repeat_byte(4),
        actual_head: Hash256::repeat_byte(5),
    };
    assert!(!stale.should_penalize_peer());
    assert!(!stale.is_retryable());
    assert_eq!(PQ_BLOCK_IMPORT_ADMISSION_CAPACITY, 2);
    assert_eq!(PQ_FORWARD_RANGE_BLOCK_CAPACITY, 8);

    let gossip_capacity =
        PqAttestationGossipError::Local(PqAttestationGossipLocalError::IngressCapacity);
    assert!(!gossip_capacity.should_penalize_peer());
    assert!(gossip_capacity.is_retryable());
    let aged_proof = PqAttestationGossipError::Local(
        PqAttestationGossipLocalError::ProofOutlivedPropagationWindow {
            attestation: Slot::new(1),
        },
    );
    assert!(!aged_proof.should_penalize_peer());
    assert!(!aged_proof.is_retryable());
}

#[test]
fn engine_payload_status_retains_valid_and_syncing_outcomes() {
    assert!(!PqEnginePayloadStatus::Valid.would_require_optimistic_import());
    assert!(PqEnginePayloadStatus::Syncing.would_require_optimistic_import());
}

#[test]
fn real_engine_responses_have_typed_commit_retry_and_reject_mapping() {
    use execution_layer::PayloadStatus;

    assert_eq!(
        classify_pq_engine_payload_status(&PayloadStatus::Valid),
        PqEnginePayloadDisposition::CommitValid
    );
    assert_eq!(
        classify_pq_engine_payload_status(&PayloadStatus::Syncing),
        PqEnginePayloadDisposition::Retry(PqEnginePayloadStatus::Syncing)
    );
    assert_eq!(
        classify_pq_engine_payload_status(&PayloadStatus::Accepted),
        PqEnginePayloadDisposition::Retry(PqEnginePayloadStatus::Syncing)
    );
    assert_eq!(
        classify_pq_engine_payload_status(&PayloadStatus::Invalid {
            latest_valid_hash: None,
            validation_error: Some("invalid payload".to_owned()),
        }),
        PqEnginePayloadDisposition::Reject
    );
    assert_eq!(
        classify_pq_engine_payload_status(&PayloadStatus::InvalidBlockHash {
            validation_error: Some("bad hash".to_owned()),
        }),
        PqEnginePayloadDisposition::Reject
    );

    let rejected = PqImportError::ExecutionRejected(PayloadStatus::InvalidBlockHash {
        validation_error: None,
    });
    assert!(!rejected.should_penalize_peer());
    assert!(!rejected.is_retryable());
    let transport = PqImportError::Local(PqImportLocalError::Transport(
        execution_layer::Error::NoEngine,
    ));
    assert!(!transport.should_penalize_peer());
    assert!(transport.is_retryable());
}

#[cfg(target_feature = "avx2")]
async fn run_reconciliation_outcome_case(
    responses: impl IntoIterator<Item = Result<execution_layer::PayloadStatus, execution_layer::Error>>,
) -> (
    Result<(), PqImportError>,
    Arc<ReconciliationOutcomeTransport>,
    futures::channel::mpsc::Receiver<task_executor::ShutdownReason>,
    async_channel::Sender<()>,
) {
    let transport = Arc::new(ReconciliationOutcomeTransport::new(responses));
    let (exit_sender, exit_receiver) = async_channel::bounded(1);
    let (shutdown_sender, shutdown_receiver) = futures::channel::mpsc::channel(1);
    let executor = task_executor::TaskExecutor::new(
        tokio::runtime::Handle::current(),
        exit_receiver,
        shutdown_sender,
    );
    let result = beacon_chain::testing_only_reconcile_pq_execution(
        transport.clone(),
        executor,
        types::ExecutionBlockHash::repeat_byte(0x81),
        Slot::new(1),
        Hash256::repeat_byte(0x82),
    )
    .await;
    (result, transport, shutdown_receiver, exit_sender)
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn committed_execution_reconciliation_has_bounded_terminal_outcomes() {
    use execution_layer::PayloadStatus;
    use futures::StreamExt;

    let (valid, valid_transport, _, _valid_exit) =
        run_reconciliation_outcome_case([Ok(PayloadStatus::Valid)]).await;
    assert!(valid.is_ok());
    assert_eq!(valid_transport.forkchoice_calls.load(Ordering::SeqCst), 1);
    assert_eq!(valid_transport.new_payload_calls.load(Ordering::SeqCst), 0);

    let (transient, transient_transport, _, _transient_exit) = run_reconciliation_outcome_case([
        Ok(PayloadStatus::Syncing),
        Ok(PayloadStatus::Accepted),
        Ok(PayloadStatus::Valid),
    ])
    .await;
    assert!(transient.is_ok());
    assert_eq!(
        transient_transport.forkchoice_calls.load(Ordering::SeqCst),
        3
    );
    assert_eq!(
        transient_transport.new_payload_calls.load(Ordering::SeqCst),
        0
    );

    let (transport_retry, transport_retry_transport, _, _transport_exit) =
        run_reconciliation_outcome_case([
            Err(execution_layer::Error::NoEngine),
            Ok(PayloadStatus::Valid),
        ])
        .await;
    assert!(transport_retry.is_ok());
    assert_eq!(
        transport_retry_transport
            .forkchoice_calls
            .load(Ordering::SeqCst),
        2
    );
    assert_eq!(
        transport_retry_transport
            .new_payload_calls
            .load(Ordering::SeqCst),
        0
    );

    let (exhausted, exhausted_transport, mut exhausted_shutdown, _exhausted_exit) =
        run_reconciliation_outcome_case([
            Ok(PayloadStatus::Syncing),
            Ok(PayloadStatus::Accepted),
            Ok(PayloadStatus::Syncing),
        ])
        .await;
    assert!(matches!(
        exhausted,
        Err(PqImportError::ExecutionReconciliation(
            beacon_chain::PqExecutionReconciliationError::Unavailable { attempts: 3 }
        ))
    ));
    assert!(
        !exhausted
            .as_ref()
            .expect_err("bounded exhaustion")
            .is_retryable()
    );
    assert!(
        !exhausted
            .as_ref()
            .expect_err("bounded exhaustion")
            .should_penalize_peer()
    );
    assert_eq!(
        exhausted_transport.forkchoice_calls.load(Ordering::SeqCst),
        beacon_chain::PQ_EXECUTION_RECONCILIATION_ATTEMPTS
    );
    assert_eq!(
        exhausted_transport.new_payload_calls.load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        exhausted_shutdown.next().await,
        Some(task_executor::ShutdownReason::Failure(
            "PQ execution reconciliation failed"
        ))
    );

    let (transport_exhausted, transport_exhausted_trace, mut transport_shutdown, _exit) =
        run_reconciliation_outcome_case([
            Err(execution_layer::Error::NoEngine),
            Err(execution_layer::Error::NoEngine),
            Err(execution_layer::Error::NoEngine),
        ])
        .await;
    assert!(matches!(
        &transport_exhausted,
        Err(PqImportError::ExecutionReconciliation(
            beacon_chain::PqExecutionReconciliationError::Transport { attempts: 3, .. }
        ))
    ));
    assert!(
        !transport_exhausted
            .as_ref()
            .expect_err("bounded transport exhaustion")
            .is_retryable()
    );
    assert_eq!(
        transport_exhausted_trace
            .forkchoice_calls
            .load(Ordering::SeqCst),
        beacon_chain::PQ_EXECUTION_RECONCILIATION_ATTEMPTS
    );
    assert_eq!(
        transport_exhausted_trace
            .new_payload_calls
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        transport_shutdown.next().await,
        Some(task_executor::ShutdownReason::Failure(
            "PQ execution reconciliation failed"
        ))
    );

    for rejected in [
        PayloadStatus::Invalid {
            latest_valid_hash: None,
            validation_error: Some("invalid reconciliation head".to_owned()),
        },
        PayloadStatus::InvalidBlockHash {
            validation_error: Some("invalid reconciliation hash".to_owned()),
        },
    ] {
        let (result, transport, mut shutdown, _exit) =
            run_reconciliation_outcome_case([Ok(rejected)]).await;
        assert!(matches!(
            result,
            Err(PqImportError::ExecutionReconciliation(
                beacon_chain::PqExecutionReconciliationError::Rejected(_)
            ))
        ));
        assert!(
            !result
                .as_ref()
                .expect_err("Engine rejection")
                .is_retryable()
        );
        assert!(
            !result
                .as_ref()
                .expect_err("Engine rejection")
                .should_penalize_peer()
        );
        assert_eq!(transport.forkchoice_calls.load(Ordering::SeqCst), 1);
        assert_eq!(transport.new_payload_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            shutdown.next().await,
            Some(task_executor::ShutdownReason::Failure(
                "PQ execution reconciliation failed"
            ))
        );
    }
}

#[test]
fn slot_ordering_is_a_peer_invalid_error() {
    let error = PqImportError::PeerInvalid(PqImportPeerInvalid::NonAdvancingSlot {
        parent: Slot::new(7),
        block: Slot::new(7),
    });
    assert!(error.should_penalize_peer());
}

#[test]
fn gossip_claim_lifecycle_blocks_pending_duplicates_and_terminal_retries() {
    let mut cache = TestingPqGossipObservationCache::default();
    let slot = Slot::new(1);
    let root = Hash256::repeat_byte(1);
    let first = cache.claim(slot, 3, root, Slot::new(0));
    let TestingPqGossipClaim::Propagate(first_generation) = first else {
        panic!("first fully verified gossip block must own propagation")
    };
    assert_eq!(
        cache.claim(slot, 3, root, Slot::new(0)),
        TestingPqGossipClaim::Pending
    );
    assert!(cache.mark_propagated(slot, 3, first_generation));
    assert_eq!(
        cache.claim(slot, 3, root, Slot::new(0)),
        TestingPqGossipClaim::Pending
    );
    assert!(cache.cancel(slot, 3, first_generation));
    let TestingPqGossipClaim::Retry(retry_generation) = cache.claim(slot, 3, root, Slot::new(0))
    else {
        panic!("a dropped claim must become retryable")
    };
    assert_ne!(first_generation, retry_generation);
    assert!(cache.finish(slot, 3, retry_generation, TestingPqGossipFinish::Terminal));
    assert_eq!(
        cache.claim(slot, 3, root, Slot::new(0)),
        TestingPqGossipClaim::Terminal
    );
    assert_eq!(
        cache.claim(slot, 3, Hash256::repeat_byte(2), Slot::new(0)),
        TestingPqGossipClaim::Equivocation(root)
    );
}

#[test]
fn gossip_claim_lifecycle_retries_only_after_retryable_completion() {
    let mut cache = TestingPqGossipObservationCache::default();
    let dropped_slot = Slot::new(3);
    let dropped_root = Hash256::repeat_byte(3);
    let TestingPqGossipClaim::Propagate(dropped_generation) =
        cache.claim(dropped_slot, 1, dropped_root, Slot::new(2))
    else {
        panic!("initial propagation claim")
    };
    assert!(cache.cancel(dropped_slot, 1, dropped_generation));
    assert!(matches!(
        cache.claim(dropped_slot, 1, dropped_root, Slot::new(2)),
        TestingPqGossipClaim::Propagate(_)
    ));

    let slot = Slot::new(4);
    let root = Hash256::repeat_byte(4);
    let TestingPqGossipClaim::Propagate(generation) = cache.claim(slot, 2, root, Slot::new(3))
    else {
        panic!("propagation claim")
    };
    assert!(cache.mark_propagated(slot, 2, generation));
    assert!(cache.finish(slot, 2, generation, TestingPqGossipFinish::Retryable));
    let TestingPqGossipClaim::Retry(retry_generation) = cache.claim(slot, 2, root, Slot::new(3))
    else {
        panic!("retry claim")
    };
    assert!(cache.finish(slot, 2, retry_generation, TestingPqGossipFinish::Committed));
    cache.prune_after_commit(slot);
    assert_eq!(
        cache.claim(slot, 2, root, slot),
        TestingPqGossipClaim::Committed
    );
    assert_eq!(cache.len(), 1, "the current committed record is retained");
}

#[test]
fn gossip_claim_cache_prunes_long_chains_and_bounds_failed_entries() {
    let mut cache = TestingPqGossipObservationCache::default();
    let capacity_u64 =
        u64::try_from(TestingPqGossipObservationCache::CAPACITY).expect("capacity fits u64");
    let long_chain_end = capacity_u64.checked_mul(3).expect("small test bound");
    for slot_u64 in 1..=long_chain_end {
        let slot = Slot::new(slot_u64);
        let proposer = slot_u64 % 16;
        let root = Hash256::with_last_byte(
            u8::try_from(slot_u64 % 251).expect("remainder fits in one byte"),
        );
        let TestingPqGossipClaim::Propagate(generation) =
            cache.claim(slot, proposer, root, Slot::new(slot_u64 - 1))
        else {
            panic!("linear propagation claim")
        };
        assert!(cache.mark_propagated(slot, proposer, generation));
        assert!(cache.finish(slot, proposer, generation, TestingPqGossipFinish::Committed));
        cache.prune_after_commit(slot);
        assert_eq!(cache.len(), 1);
    }

    let head = Slot::new(long_chain_end);
    for offset in 1..TestingPqGossipObservationCache::CAPACITY {
        let offset_u64 = u64::try_from(offset).expect("offset fits u64");
        let slot = Slot::new(
            long_chain_end
                .checked_add(offset_u64)
                .expect("small test slot"),
        );
        let proposer = offset_u64 % 16;
        let root = Hash256::with_last_byte(
            u8::try_from(offset_u64 % 251).expect("remainder fits in one byte"),
        );
        let TestingPqGossipClaim::Propagate(generation) = cache.claim(slot, proposer, root, head)
        else {
            panic!("failed-entry propagation claim")
        };
        assert!(cache.mark_propagated(slot, proposer, generation));
        assert!(cache.finish(
            slot,
            proposer,
            generation,
            if offset % 2 == 0 {
                TestingPqGossipFinish::Retryable
            } else {
                TestingPqGossipFinish::Terminal
            }
        ));
    }
    assert_eq!(cache.len(), TestingPqGossipObservationCache::CAPACITY);
    assert_eq!(
        cache.claim(
            Slot::new(long_chain_end.checked_add(10_000).expect("small test slot")),
            0,
            Hash256::repeat_byte(252),
            head,
        ),
        TestingPqGossipClaim::Capacity
    );
    assert_eq!(cache.len(), TestingPqGossipObservationCache::CAPACITY);
    let retained_root = Hash256::with_last_byte(
        u8::try_from(long_chain_end % 251).expect("remainder fits in one byte"),
    );
    assert_eq!(
        cache.reserve_external(
            Slot::new(long_chain_end.checked_add(20_000).expect("small test slot")),
            0,
            Hash256::repeat_byte(253),
            head,
        ),
        TestingPqExternalReservation::Capacity,
    );
    assert_eq!(cache.len(), TestingPqGossipObservationCache::CAPACITY);
    assert_eq!(
        cache.claim(head, long_chain_end % 16, retained_root, head),
        TestingPqGossipClaim::Committed,
        "capacity eviction must preserve the retained current-head record"
    );
}

#[test]
fn cross_source_equivocation_leaves_the_first_pending_root_authorized() {
    let mut cache = TestingPqGossipObservationCache::default();
    let slot = Slot::new(8);
    let first_gossip_root = Hash256::repeat_byte(8);
    let external_equivocation = Hash256::repeat_byte(9);

    let TestingPqGossipClaim::Propagate(first_generation) =
        cache.claim(slot, 4, first_gossip_root, Slot::new(7))
    else {
        panic!("first gossip propagation claim")
    };
    assert!(cache.mark_propagated(slot, 4, first_generation));
    assert_eq!(
        cache.reserve_external(slot, 4, external_equivocation, Slot::new(7)),
        TestingPqExternalReservation::Equivocation(first_gossip_root)
    );
    assert!(cache.authorize_commit(slot, 4, first_gossip_root, first_generation));

    let mut same_root = TestingPqGossipObservationCache::default();
    let TestingPqGossipClaim::Propagate(generation) =
        same_root.claim(slot, 4, first_gossip_root, Slot::new(7))
    else {
        panic!("same-root propagation claim")
    };
    same_root.record_commit(slot, 4, first_gossip_root);
    assert!(!same_root.mark_propagated(slot, 4, generation));
    assert_eq!(
        same_root.claim(slot, 4, first_gossip_root, slot),
        TestingPqGossipClaim::Committed
    );
}

#[test]
fn cross_source_engine_rejection_invalidates_a_queued_exact_generation() {
    let mut cache = TestingPqGossipObservationCache::default();
    let slot = Slot::new(9);
    let root = Hash256::repeat_byte(9);
    let TestingPqGossipClaim::Propagate(generation) = cache.claim(slot, 5, root, Slot::new(8))
    else {
        panic!("propagation claim")
    };
    assert!(cache.mark_propagated(slot, 5, generation));
    assert!(cache.authorize_commit(slot, 5, root, generation));

    cache.record_terminal(slot, 5, root);
    assert!(!cache.authorize_commit(slot, 5, root, generation));
    assert_eq!(
        cache.claim(slot, 5, root, Slot::new(8)),
        TestingPqGossipClaim::Terminal
    );
}

#[cfg(target_feature = "avx2")]
const PASSWORD: &[u8] = b"correct horse battery staple";

#[cfg(target_feature = "avx2")]
type TestWitness = Witness<slot_clock::TestingSlotClock, MinimalEthSpec, MemoryStore, MemoryStore>;

#[cfg(target_feature = "avx2")]
struct RecordingTransport {
    calls: Mutex<Vec<Hash256>>,
    responses: Mutex<VecDeque<Result<execution_layer::PayloadStatus, execution_layer::Error>>>,
    forkchoice_calls: Mutex<Vec<types::ExecutionBlockHash>>,
    forkchoice_responses:
        Mutex<VecDeque<Result<execution_layer::PayloadStatus, execution_layer::Error>>>,
}

#[cfg(target_feature = "avx2")]
impl RecordingTransport {
    fn always_valid() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::from([Ok(execution_layer::PayloadStatus::Valid)])),
            forkchoice_calls: Mutex::new(Vec::new()),
            forkchoice_responses: Mutex::new(VecDeque::from([Ok(
                execution_layer::PayloadStatus::Valid,
            )])),
        }
    }

    fn syncing_then_valid() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::from([
                Ok(execution_layer::PayloadStatus::Syncing),
                Ok(execution_layer::PayloadStatus::Valid),
                Ok(execution_layer::PayloadStatus::Valid),
            ])),
            forkchoice_calls: Mutex::new(Vec::new()),
            forkchoice_responses: Mutex::new(VecDeque::from([Ok(
                execution_layer::PayloadStatus::Valid,
            )])),
        }
    }

    fn invalid_block_hash() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::from([Ok(
                execution_layer::PayloadStatus::InvalidBlockHash {
                    validation_error: Some("fixture rejection".to_owned()),
                },
            )])),
            forkchoice_calls: Mutex::new(Vec::new()),
            forkchoice_responses: Mutex::new(VecDeque::new()),
        }
    }
}

#[cfg(target_feature = "avx2")]
impl PqNewPayloadTransport<MinimalEthSpec> for RecordingTransport {
    fn notify_new_payload<'a>(
        &'a self,
        request: execution_layer::NewPayloadRequest<'a, MinimalEthSpec>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                > + Send
                + 'a,
        >,
    > {
        self.calls
            .lock()
            .expect("recording transport calls lock")
            .push(request.block_hash().into_root());
        let response = self
            .responses
            .lock()
            .expect("recording transport responses lock")
            .pop_front()
            .unwrap_or(Err(execution_layer::Error::Unexpected(
                "missing fixture response".to_owned(),
            )));
        Box::pin(async move { response })
    }

    fn notify_forkchoice_updated<'a>(
        &'a self,
        head_block_hash: types::ExecutionBlockHash,
        _current_slot: Slot,
        _head_block_root: Hash256,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                > + Send
                + 'a,
        >,
    > {
        self.forkchoice_calls
            .lock()
            .expect("recording forkchoice calls lock")
            .push(head_block_hash);
        let response = self
            .forkchoice_responses
            .lock()
            .expect("recording forkchoice responses lock")
            .pop_front()
            .unwrap_or(Err(execution_layer::Error::Unexpected(
                "missing explicit fixture forkchoice response".to_owned(),
            )));
        Box::pin(async move { response })
    }
}

#[cfg(target_feature = "avx2")]
struct StallingTransport {
    calls: AtomicUsize,
    release: tokio::sync::Semaphore,
}

#[cfg(target_feature = "avx2")]
struct BlockingForkchoiceTransport {
    new_payload_calls: AtomicUsize,
    forkchoice_calls: AtomicUsize,
    forkchoice_dropped: AtomicBool,
    forkchoice_release: tokio::sync::Semaphore,
}

#[cfg(target_feature = "avx2")]
struct ReconciliationOutcomeTransport {
    new_payload_calls: AtomicUsize,
    forkchoice_calls: AtomicUsize,
    forkchoice_responses:
        Mutex<VecDeque<Result<execution_layer::PayloadStatus, execution_layer::Error>>>,
}

#[cfg(target_feature = "avx2")]
impl ReconciliationOutcomeTransport {
    fn new(
        responses: impl IntoIterator<
            Item = Result<execution_layer::PayloadStatus, execution_layer::Error>,
        >,
    ) -> Self {
        Self {
            new_payload_calls: AtomicUsize::new(0),
            forkchoice_calls: AtomicUsize::new(0),
            forkchoice_responses: Mutex::new(responses.into_iter().collect()),
        }
    }
}

#[cfg(target_feature = "avx2")]
impl PqNewPayloadTransport<MinimalEthSpec> for ReconciliationOutcomeTransport {
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
        self.new_payload_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(execution_layer::Error::Unexpected(
                "reconciliation helper called newPayload".to_owned(),
            ))
        })
    }

    fn notify_forkchoice_updated<'a>(
        &'a self,
        _head_block_hash: types::ExecutionBlockHash,
        _current_slot: Slot,
        _head_block_root: Hash256,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                > + Send
                + 'a,
        >,
    > {
        self.forkchoice_calls.fetch_add(1, Ordering::SeqCst);
        let response = self
            .forkchoice_responses
            .lock()
            .expect("reconciliation response lock")
            .pop_front()
            .unwrap_or(Err(execution_layer::Error::Unexpected(
                "reconciliation exceeded explicit response table".to_owned(),
            )));
        Box::pin(async move { response })
    }
}

#[cfg(target_feature = "avx2")]
impl BlockingForkchoiceTransport {
    fn new() -> Self {
        Self {
            new_payload_calls: AtomicUsize::new(0),
            forkchoice_calls: AtomicUsize::new(0),
            forkchoice_dropped: AtomicBool::new(false),
            forkchoice_release: tokio::sync::Semaphore::new(0),
        }
    }
}

#[cfg(target_feature = "avx2")]
impl PqNewPayloadTransport<MinimalEthSpec> for BlockingForkchoiceTransport {
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
        self.new_payload_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(execution_layer::PayloadStatus::Valid) })
    }

    fn notify_forkchoice_updated<'a>(
        &'a self,
        _head_block_hash: types::ExecutionBlockHash,
        _current_slot: Slot,
        _head_block_root: Hash256,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                > + Send
                + 'a,
        >,
    > {
        struct DropTrace<'a> {
            dropped: &'a AtomicBool,
            armed: bool,
        }

        impl Drop for DropTrace<'_> {
            fn drop(&mut self) {
                if self.armed {
                    self.dropped.store(true, Ordering::SeqCst);
                }
            }
        }

        self.forkchoice_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let mut trace = DropTrace {
                dropped: &self.forkchoice_dropped,
                armed: true,
            };
            let permit = self.forkchoice_release.acquire().await.map_err(|_| {
                execution_layer::Error::Unexpected(
                    "blocking forkchoice transport closed".to_owned(),
                )
            })?;
            permit.forget();
            trace.armed = false;
            Ok(execution_layer::PayloadStatus::Valid)
        })
    }
}

#[cfg(target_feature = "avx2")]
impl StallingTransport {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            release: tokio::sync::Semaphore::new(0),
        }
    }
}

#[cfg(target_feature = "avx2")]
impl PqNewPayloadTransport<MinimalEthSpec> for StallingTransport {
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let permit = self.release.acquire().await.map_err(|_| {
                execution_layer::Error::Unexpected("stalling test transport closed".to_owned())
            })?;
            permit.forget();
            Ok(execution_layer::PayloadStatus::Valid)
        })
    }

    fn notify_forkchoice_updated<'a>(
        &'a self,
        _head_block_hash: types::ExecutionBlockHash,
        _current_slot: Slot,
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
fn electra_spec() -> ChainSpec {
    ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(17_000)
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
async fn wait_for_test_condition(mut condition: impl FnMut() -> bool, description: &str) {
    for _ in 0..100_000 {
        if condition() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for {description}");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn full_gossip_verification_precedes_observation_engine_commit_and_restart() {
    assert_eq!(PQ_ATTESTATION_GOSSIP_ADMISSION_CAPACITY, 2);
    let test_runtime = task_executor::test_utils::TestRuntime::default();
    let temporary_directory = tempfile::TempDir::new().expect("temporary directory");
    let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
    let spec = Arc::new(electra_spec());
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
        .get_beacon_committee(Slot::new(0), 0)
        .expect("genesis committee")
        .committee
        .iter()
        .find(|validator_index| **validator_index != proposer_index)
        .expect("committee participant distinct from proposer");
    let maximum_leaf = OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::BeaconBlockProposal)
        .expect("slot-one proposal leaf")
        .as_u32();
    let proposer_keystore =
        PqKeystore::from_seed([0xa5; 32], 0..=maximum_leaf, PASSWORD).expect("fixture keystore");
    let proposer_authenticated = proposer_keystore
        .authenticate(PASSWORD)
        .expect("authenticated proposer key");
    let attester_keystore = PqKeystore::from_seed([0xb5; 32], 0..=maximum_leaf, PASSWORD)
        .expect("attester fixture keystore");
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
    let store = exact_snapshot_store(Arc::clone(&spec));
    let service = Arc::new(AggregationService::new().expect("PQ aggregation service"));
    let transport = Arc::new(RecordingTransport::syncing_then_valid());
    let chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&store))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist genesis")
            .pq_aggregation_service(Arc::clone(&service))
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(transport.clone())
            .build()
            .expect("PQ chain"),
    );
    let processor = PqNetworkBlockProcessor::new(Arc::clone(&chain));
    let genesis_root = chain.head_snapshot().beacon_block_root;

    let late_lineage_hook = TestingPqBlockingHook::blocking();
    let late_lineage_chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist late-lineage genesis")
            .pq_aggregation_service(Arc::clone(&service))
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_blocking_hook(Arc::clone(&late_lineage_hook))
            .testing_only_pq_execution_notifier(Arc::new(RecordingTransport::always_valid()))
            .build()
            .expect("late-lineage PQ chain"),
    );
    let late_check_chain = Arc::clone(&late_lineage_chain);
    let late_check = tokio::spawn(async move {
        late_check_chain
            .testing_only_pq_attestation_bound_is_canonical(genesis_root)
            .await
    });
    while late_lineage_hook.entered() == 0 {
        tokio::task::yield_now().await;
    }
    late_check.abort();
    assert_eq!(
        late_lineage_chain.testing_only_pq_attestation_gossip_available_permits(),
        PQ_ATTESTATION_GOSSIP_ADMISSION_CAPACITY - 1,
        "canceling the waiter must not release admission during detached lineage work",
    );
    late_lineage_hook.release();
    while late_lineage_chain.testing_only_pq_attestation_gossip_available_permits()
        != PQ_ATTESTATION_GOSSIP_ADMISSION_CAPACITY
    {
        tokio::task::yield_now().await;
    }

    let mut gossip_state = genesis.clone();
    gossip_state
        .build_all_committee_caches(&spec)
        .expect("genesis gossip committee caches");
    let committee = gossip_state
        .get_beacon_committee(Slot::new(0), 0)
        .expect("genesis gossip committee");
    let attester_index = attester_index as u64;
    let invalid_attestation = SingleAttestation {
        committee_index: 0,
        attester_index,
        data: AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: genesis_root,
            source: Checkpoint::default(),
            target: Checkpoint {
                epoch: types::Epoch::new(0),
                root: genesis_root,
            },
        },
        signature: PqSameMessageEvidence::from(&PqRawSignature::empty()),
    };
    let gossip_subnet = SubnetId::compute_subnet_for_single_attestation::<MinimalEthSpec>(
        &invalid_attestation,
        gossip_state
            .get_committee_count_at_slot(Slot::new(0))
            .expect("committee count"),
        &spec,
    )
    .expect("gossip subnet");
    let first_admission = chain
        .testing_try_reserve_pq_attestation_gossip_admission()
        .expect("first bounded gossip admission");
    let second_admission = chain
        .testing_try_reserve_pq_attestation_gossip_admission()
        .expect("second bounded gossip admission");
    assert!(matches!(
        processor
            .verify_gossip_attestation(invalid_attestation.clone(), gossip_subnet)
            .await,
        PqGossipAttestationDisposition::Ignore(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::IngressCapacity
        ))
    ));
    drop(first_admission);
    let canceled_capacity = chain
        .testing_try_reserve_pq_attestation_gossip_admission()
        .expect("dropped admission immediately frees capacity");
    drop(canceled_capacity);
    drop(second_admission);
    match processor
        .verify_gossip_attestation(invalid_attestation, gossip_subnet)
        .await
    {
        PqGossipAttestationDisposition::Reject(_) => {}
        PqGossipAttestationDisposition::Ignore(error) => {
            panic!("invalid single was ignored instead of rejected: {error:?}")
        }
        PqGossipAttestationDisposition::Accept(_) => {
            panic!("invalid single was accepted")
        }
    }

    let attestation_data = AttestationData {
        slot: Slot::new(0),
        index: 0,
        beacon_block_root: genesis_root,
        source: Checkpoint::default(),
        target: Checkpoint {
            epoch: types::Epoch::new(0),
            root: genesis_root,
        },
    };
    let attestation_domain = spec.get_domain(
        types::Epoch::new(0),
        Domain::BeaconAttester,
        &genesis.fork(),
        genesis.genesis_validators_root(),
    );
    let attestation_signature = authority
        .signer(
            &genesis
                .validators()
                .get(attester_index as usize)
                .expect("attester validator")
                .pubkey,
        )
        .expect("bound attester signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            attestation_data.signing_root(attestation_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(0, SigningDuty::Attestation)
                .expect("attestation leaf"),
        ))
        .expect("valid attestation signature");
    let valid_attestation = SingleAttestation {
        committee_index: 0,
        attester_index,
        data: attestation_data.clone(),
        signature: PqSameMessageEvidence::from(&attestation_signature),
    };
    let PqGossipAttestationDisposition::Accept(first_single_token) = processor
        .verify_gossip_attestation(valid_attestation.clone(), gossip_subnet)
        .await
    else {
        panic!("valid single attestation must receive propagation capability")
    };
    let mut conflicting_single = valid_attestation.clone();
    conflicting_single.data.beacon_block_root = Hash256::repeat_byte(0xa5);
    conflicting_single.data.target.root = Hash256::repeat_byte(0xa6);
    let PqGossipAttestationDisposition::Ignore(conflict) = processor
        .verify_gossip_attestation(conflicting_single, gossip_subnet)
        .await
    else {
        panic!("a prior single observation must ignore conflict before context or evidence work")
    };
    assert!(!conflict.should_penalize_peer());
    assert!(matches!(
        processor
            .verify_gossip_attestation(valid_attestation.clone(), gossip_subnet)
            .await,
        PqGossipAttestationDisposition::Ignore(_)
    ));
    drop(first_single_token);
    let PqGossipAttestationDisposition::Accept(retry_single_token) = processor
        .verify_gossip_attestation(valid_attestation.clone(), gossip_subnet)
        .await
    else {
        panic!("dropped propagation capability must make the exact single retryable")
    };
    let verified_single = (*retry_single_token)
        .mark_propagated()
        .expect("finalize single propagation");
    assert_eq!(
        verified_single
            .verified()
            .expect("sealed verified single")
            .single_attestation(),
        &valid_attestation
    );
    assert_eq!(verified_single.subnet(), gossip_subnet);
    assert_eq!(verified_single.bound_head_root(), genesis_root);
    drop(verified_single);
    assert!(matches!(
        processor
            .verify_gossip_attestation(valid_attestation.clone(), gossip_subnet)
            .await,
        PqGossipAttestationDisposition::Ignore(_)
    ));

    let mut aggregate_bits =
        BitList::<<MinimalEthSpec as EthSpec>::MaxValidatorsPerSlot>::with_capacity(
            committee.committee.len(),
        )
        .expect("aggregate bits");
    aggregate_bits.set(0, true).expect("aggregate participant");
    let mut committee_bits =
        BitVector::<<MinimalEthSpec as EthSpec>::MaxCommitteesPerSlot>::default();
    committee_bits.set(0, true).expect("aggregate committee");
    let aggregate_attestation = Attestation::Electra(AttestationElectra {
        aggregation_bits: aggregate_bits,
        data: AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: genesis_root,
            source: Checkpoint::default(),
            target: Checkpoint {
                epoch: types::Epoch::new(0),
                root: genesis_root,
            },
        },
        signature: PqSameMessageEvidence::from(&PqRawSignature::empty()),
        committee_bits,
    });
    let aggregate_message = AggregateAndProof::from_attestation(
        attester_index,
        aggregate_attestation,
        SelectionProof::from(PqRawSignature::empty()),
    );
    let invalid_aggregate = SignedAggregateAndProof::from_aggregate_and_proof(
        aggregate_message,
        PqRawSignature::empty(),
    );
    assert!(matches!(
        processor.verify_gossip_aggregate(invalid_aggregate).await,
        PqGossipAggregateDisposition::Reject(_)
    ));

    let selection_domain = spec.get_domain(
        types::Epoch::new(0),
        Domain::SelectionProof,
        &genesis.fork(),
        genesis.genesis_validators_root(),
    );
    let selection_signature = authority
        .signer(
            &genesis
                .validators()
                .get(attester_index as usize)
                .expect("aggregate validator")
                .pubkey,
        )
        .expect("bound aggregate signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            Slot::new(0).signing_root(selection_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(0, SigningDuty::AttestationSelectionProof)
                .expect("selection leaf"),
        ))
        .expect("selection signature");
    let mut valid_aggregate_bits =
        BitList::<<MinimalEthSpec as EthSpec>::MaxValidatorsPerSlot>::with_capacity(
            committee.committee.len(),
        )
        .expect("valid aggregate bits");
    let attester_position = committee
        .committee
        .iter()
        .position(|validator_index| *validator_index == attester_index as usize)
        .expect("attester committee position");
    valid_aggregate_bits
        .set(attester_position, true)
        .expect("valid aggregate participant");
    let mut valid_committee_bits =
        BitVector::<<MinimalEthSpec as EthSpec>::MaxCommitteesPerSlot>::default();
    valid_committee_bits
        .set(0, true)
        .expect("valid aggregate committee");
    let valid_inner = Attestation::Electra(AttestationElectra {
        aggregation_bits: valid_aggregate_bits,
        data: attestation_data,
        signature: PqSameMessageEvidence::from(&attestation_signature),
        committee_bits: valid_committee_bits,
    });
    let valid_message = AggregateAndProof::from_attestation(
        attester_index,
        valid_inner,
        SelectionProof::from(selection_signature),
    );
    let outer_domain = spec.get_domain(
        types::Epoch::new(0),
        Domain::AggregateAndProof,
        &genesis.fork(),
        genesis.genesis_validators_root(),
    );
    let outer_signature = authority
        .signer(
            &genesis
                .validators()
                .get(attester_index as usize)
                .expect("outer validator")
                .pubkey,
        )
        .expect("bound outer signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            valid_message.signing_root(outer_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(0, SigningDuty::AggregateAndProof)
                .expect("outer leaf"),
        ))
        .expect("outer signature");
    let valid_aggregate =
        SignedAggregateAndProof::from_aggregate_and_proof(valid_message, outer_signature);
    let PqGossipAggregateDisposition::Accept(aggregate_token) = processor
        .verify_gossip_aggregate(valid_aggregate.clone())
        .await
    else {
        panic!("valid aggregate must receive propagation capability")
    };
    let verified_aggregate = (*aggregate_token)
        .mark_propagated()
        .expect("finalize aggregate propagation");
    let (verified_aggregate, verified_aggregate_head) = verified_aggregate.into_parts();
    assert_eq!(verified_aggregate.aggregate().as_ref(), &valid_aggregate);
    assert_eq!(verified_aggregate_head, genesis_root);

    let mut pre_state = genesis.clone();
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
    .verify(&service)
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
    let execution_block_hash = execution_layer::calculate_execution_block_hash(
        ExecutionPayloadRef::Electra(&inner.body.execution_payload.execution_payload),
        Some(inner.parent_root),
        Some(&inner.body.execution_requests),
    )
    .0;
    inner.body.execution_payload.execution_payload.block_hash = execution_block_hash;

    let local =
        state_processing::prepare_pq_local_block(&pre_state, block, verified_randao, vec![])
            .expect("sealed local block");
    let mut local_state = pre_state.clone();
    let local_output = state_processing::per_block_processing_pq_local(&mut local_state, local)
        .expect("local transition");
    let (mut block, _) = local_output.into_parts();
    let state_root = local_state.canonical_root().expect("post-state root");
    *block.state_root_mut() = state_root;
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
    let signed = Arc::new(SignedBeaconBlock::from_block(block, proposal_signature));

    let cancellation_transport = Arc::new(BlockingForkchoiceTransport::new());
    let (executor_exit_sender, executor_exit_receiver) = async_channel::bounded(1);
    let (executor_shutdown_sender, _executor_shutdown_receiver) =
        futures::channel::mpsc::channel(1);
    let cancellation_executor = task_executor::TaskExecutor::new(
        tokio::runtime::Handle::current(),
        executor_exit_receiver,
        executor_shutdown_sender,
    );
    let cancellation_chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist reconciliation-cancellation genesis")
            .pq_aggregation_service(Arc::clone(&service))
            .task_executor(cancellation_executor)
            .testing_only_pq_execution_notifier(cancellation_transport.clone())
            .build()
            .expect("reconciliation-cancellation PQ chain"),
    );
    cancellation_chain.slot_clock.set_slot(2);
    let cancellation_processor = Arc::new(PqNetworkBlockProcessor::new(Arc::clone(
        &cancellation_chain,
    )));
    let canceled_reconciliation = {
        let processor = Arc::clone(&cancellation_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_rpc_block(block).await })
    };
    wait_for_test_condition(
        || {
            cancellation_transport
                .forkchoice_calls
                .load(Ordering::SeqCst)
                == 1
        },
        "post-commit forkchoice reconciliation barrier",
    )
    .await;
    assert_eq!(
        cancellation_transport
            .new_payload_calls
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        cancellation_chain.head_snapshot().beacon_block_root,
        signed.canonical_root(),
        "the durable head is published before reconciliation"
    );
    assert_eq!(
        cancellation_chain.testing_only_pq_import_available_permits(),
        PQ_BLOCK_IMPORT_ADMISSION_CAPACITY - 1,
        "the detached reconciliation retains admission after DB publication"
    );
    canceled_reconciliation.abort();
    assert!(canceled_reconciliation.await.is_err());
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(
        !cancellation_transport
            .forkchoice_dropped
            .load(Ordering::SeqCst),
        "caller cancellation must not cancel the chain-owned reconciliation"
    );
    assert_eq!(
        cancellation_chain.testing_only_pq_import_available_permits(),
        PQ_BLOCK_IMPORT_ADMISSION_CAPACITY - 1
    );

    drop(executor_exit_sender);
    for _ in 0..256 {
        tokio::task::yield_now().await;
    }
    assert!(
        !cancellation_transport
            .forkchoice_dropped
            .load(Ordering::SeqCst),
        "executor exit must not cancel a durable-but-unreconciled head"
    );
    assert_eq!(
        cancellation_chain.testing_only_pq_import_available_permits(),
        PQ_BLOCK_IMPORT_ADMISSION_CAPACITY - 1,
        "executor exit must not release commit authority before reconciliation"
    );
    let reconciliation_drain = {
        let chain = Arc::clone(&cancellation_chain);
        tokio::spawn(async move { chain.close_and_drain_pq_imports().await })
    };
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(
        !reconciliation_drain.is_finished(),
        "chain shutdown must await the retained reconciliation"
    );
    cancellation_transport.forkchoice_release.add_permits(1);
    reconciliation_drain
        .await
        .expect("reconciliation drain task");
    assert_eq!(
        cancellation_chain.testing_only_pq_import_available_permits(),
        PQ_BLOCK_IMPORT_ADMISSION_CAPACITY
    );
    assert!(
        !cancellation_transport
            .forkchoice_dropped
            .load(Ordering::SeqCst),
        "successful reconciliation disarms cancellation tracing"
    );
    assert_eq!(
        cancellation_chain.known_pq_publish_observation(signed.as_ref()),
        Some(beacon_chain::PqKnownPublishObservation::Committed),
        "only the reconciled exact head becomes a committed fast path"
    );
    assert!(matches!(
        cancellation_processor
            .import_lookup_block(Arc::clone(&signed))
            .await,
        Err(PqImportError::Local(PqImportLocalError::Transport(
            execution_layer::Error::ShuttingDown
        )))
    ));

    let wrong_root_journal_path = temporary_directory.path().join("xmss_wrong_root.sqlite");
    let wrong_root_keystore = PqKeystore::from_seed([0xa5; 32], 0..=maximum_leaf, PASSWORD)
        .expect("wrong-root fixture keystore");
    let wrong_root_authenticated = wrong_root_keystore
        .authenticate(PASSWORD)
        .expect("wrong-root authenticated key");
    provision_usage_journal(
        &wrong_root_journal_path,
        genesis_validators_root,
        &[wrong_root_authenticated],
    )
    .expect("wrong-root usage journal");
    let wrong_root_authority = PqSigningAuthority::open(
        &wrong_root_journal_path,
        genesis_validators_root,
        vec![PqKeyUnlock::new(wrong_root_keystore, PASSWORD).expect("wrong-root unlock")],
    )
    .expect("wrong-root signing authority");
    let (mut wrong_root_block, _) = signed.as_ref().clone().deconstruct();
    *wrong_root_block.state_root_mut() = Hash256::repeat_byte(0x9a);
    let wrong_root_public_key = pre_state
        .validators()
        .get(proposer_index)
        .expect("wrong-root proposer")
        .pubkey;
    let wrong_root_signature = wrong_root_authority
        .signer(&wrong_root_public_key)
        .expect("wrong-root bound signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            wrong_root_block.signing_root(proposal_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::BeaconBlockProposal)
                .expect("wrong-root proposal leaf"),
        ))
        .expect("separately proposal-signed wrong-root block");
    let wrong_root_signed = Arc::new(SignedBeaconBlock::from_block(
        wrong_root_block,
        wrong_root_signature,
    ));

    assert!(matches!(
        processor.verify_gossip_block(Arc::clone(&signed)).await,
        PqGossipBlockDisposition::Reject(PqImportError::PeerInvalid(
            PqImportPeerInvalid::FutureSlot { current, block }
        )) if current == Slot::new(0) && block == Slot::new(1)
    ));
    assert!(transport.calls.lock().expect("calls lock").is_empty());
    chain.slot_clock.set_slot(2);

    assert!(matches!(
        processor.verify_gossip_block(wrong_root_signed).await,
        PqGossipBlockDisposition::Reject(PqImportError::PeerInvalid(
            PqImportPeerInvalid::Transition(
                state_processing::PqTransitionError::PostStateRootMismatch { .. }
            )
        ))
    ));
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert!(transport.calls.lock().expect("calls lock").is_empty());

    let (mut malformed_block, malformed_signature) = signed.as_ref().clone().deconstruct();
    let BeaconBlock::Electra(malformed_inner) = &mut malformed_block else {
        panic!("Electra fixture")
    };
    malformed_inner
        .body
        .execution_payload
        .execution_payload
        .block_hash = types::ExecutionBlockHash::repeat_byte(0x44);
    let malformed = Arc::new(SignedBeaconBlock::from_block(
        malformed_block,
        malformed_signature,
    ));
    assert!(matches!(
        processor.verify_gossip_block(malformed).await,
        PqGossipBlockDisposition::Reject(PqImportError::PeerInvalid(
            PqImportPeerInvalid::ExecutionPayload(_)
        ))
    ));
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert!(transport.calls.lock().expect("calls lock").is_empty());

    let (mut unknown_parent_block, unknown_parent_signature) =
        signed.as_ref().clone().deconstruct();
    *unknown_parent_block.parent_root_mut() = Hash256::repeat_byte(0x55);
    let unknown_parent = Arc::new(SignedBeaconBlock::from_block(
        unknown_parent_block,
        unknown_parent_signature,
    ));
    let unknown_parent_error = match processor.import_lookup_block(unknown_parent).await {
        Ok(_) => panic!("unknown lookup parent must not verify"),
        Err(error) => error,
    };
    assert!(!unknown_parent_error.should_penalize_peer());
    assert!(unknown_parent_error.is_retryable());
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert!(transport.calls.lock().expect("calls lock").is_empty());

    let non_linear = processor
        .import_forward_range(vec![Arc::clone(&signed), Arc::clone(&signed)])
        .await
        .expect_err("non-linear range fails whole-batch preflight");
    assert!(non_linear.imported.is_empty());
    assert!(non_linear.error.should_penalize_peer());
    assert!(transport.calls.lock().expect("calls lock").is_empty());

    let verified = match processor.verify_gossip_block(Arc::clone(&signed)).await {
        PqGossipBlockDisposition::Accept(token) => token,
        _ => panic!("full sealed gossip verification must accept"),
    };
    assert!(matches!(
        processor.verify_gossip_block(Arc::clone(&signed)).await,
        PqGossipBlockDisposition::IgnorePending
    ));
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert!(transport.calls.lock().expect("calls lock").is_empty());
    drop(verified);

    let propagation_retry = match processor.verify_gossip_block(Arc::clone(&signed)).await {
        PqGossipBlockDisposition::Accept(token) => token,
        _ => panic!("drop before propagation requires a new propagation claim"),
    };
    let commit = propagation_retry
        .after_propagation()
        .expect("exact propagation claim promotes to commit-ready");
    assert!(matches!(
        processor.commit_gossip_block(commit).await,
        Err(PqImportError::Local(
            PqImportLocalError::ExecutionUnavailable(PqEnginePayloadStatus::Syncing)
        ))
    ));
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert_eq!(transport.calls.lock().expect("calls lock").len(), 1);

    let retry = match processor.verify_gossip_block(Arc::clone(&signed)).await {
        PqGossipBlockDisposition::Retry(token) => token,
        _ => panic!("local Engine failure creates one commit retry claim"),
    };
    store
        .hot_db
        .fail_atomic_batch_containing(store::DBColumn::BeaconBlock);
    assert!(matches!(
        processor.commit_gossip_block(retry).await,
        Err(PqImportError::Local(PqImportLocalError::Persistence(
            beacon_chain::PqRuntimeError::Store(_)
        )))
    ));
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert_eq!(transport.calls.lock().expect("calls lock").len(), 2);

    let queued_before_range = match processor.verify_gossip_block(Arc::clone(&signed)).await {
        PqGossipBlockDisposition::Retry(token) => token,
        _ => panic!("persistence failure exposes one commit retry"),
    };

    let (mut invalid_child_block, invalid_child_signature) = signed.as_ref().clone().deconstruct();
    *invalid_child_block.slot_mut() = Slot::new(2);
    *invalid_child_block.parent_root_mut() = signed.canonical_root();
    let invalid_child = Arc::new(SignedBeaconBlock::from_block(
        invalid_child_block,
        invalid_child_signature,
    ));
    let range_error = processor
        .import_forward_range(vec![Arc::clone(&signed), invalid_child])
        .await
        .expect_err("second range block is deterministically invalid");
    assert_eq!(range_error.imported.len(), 1);
    assert!(range_error.error.should_penalize_peer());
    let outcome = range_error.imported.first().expect("exact imported prefix");
    assert_eq!(outcome.block_root, signed.canonical_root());
    assert_eq!(chain.head_snapshot().beacon_block_root, outcome.block_root);
    assert!(
        chain
            .testing_only_pq_attestation_bound_is_canonical(genesis_root)
            .await
            .expect("late canonical-lineage check")
    );
    assert!(
        !chain
            .testing_only_pq_attestation_bound_is_canonical(Hash256::repeat_byte(0xfe))
            .await
            .expect("late non-canonical-lineage check")
    );
    assert_eq!(transport.calls.lock().expect("calls lock").len(), 3);
    let queued_after_range = processor.commit_gossip_block(queued_before_range).await;
    assert!(
        matches!(
            queued_after_range,
            Err(PqImportError::TerminalObservation { block_root })
                if block_root == outcome.block_root
        ),
        "queued gossip after range resolved as {queued_after_range:?}"
    );
    assert_eq!(transport.calls.lock().expect("calls lock").len(), 3);

    let restarted = BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
        .store(store)
        .custom_spec(Arc::clone(&spec))
        .resume_from_db()
        .expect("resume imported snapshot")
        .pq_aggregation_service(Arc::clone(&service))
        .task_executor(test_runtime.task_executor.clone())
        .testing_only_pq_execution_notifier(transport)
        .build()
        .expect("restarted chain");
    assert_eq!(
        restarted.head_snapshot().beacon_block_root,
        outcome.block_root
    );

    let rejection_store = exact_snapshot_store(Arc::clone(&spec));
    let rejection_transport = Arc::new(RecordingTransport::invalid_block_hash());
    let rejection_chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(rejection_store)
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist rejection-test genesis")
            .pq_aggregation_service(Arc::clone(&service))
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(rejection_transport.clone())
            .build()
            .expect("rejection-test PQ chain"),
    );
    let rejection_processor = PqNetworkBlockProcessor::new(Arc::clone(&rejection_chain));
    rejection_chain.slot_clock.set_slot(2);
    let queued_gossip = match rejection_processor
        .verify_gossip_block(Arc::clone(&signed))
        .await
    {
        PqGossipBlockDisposition::Accept(token) => token
            .after_propagation()
            .expect("propagated queued gossip claim"),
        _ => panic!("queued gossip owns the initial claim"),
    };
    assert!(matches!(
        rejection_processor
            .import_rpc_block(Arc::clone(&signed))
            .await,
        Err(PqImportError::ExecutionRejected(
            execution_layer::PayloadStatus::InvalidBlockHash { .. }
        ))
    ));
    assert_eq!(
        rejection_transport.calls.lock().expect("calls lock").len(),
        1
    );
    assert!(matches!(
        rejection_processor.commit_gossip_block(queued_gossip).await,
        Err(PqImportError::TerminalObservation { .. })
    ));
    assert_eq!(
        rejection_transport.calls.lock().expect("calls lock").len(),
        1
    );

    let admission_transport = Arc::new(StallingTransport::new());
    let blocking_hook = TestingPqBlockingHook::blocking();
    let admission_chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist admission-test genesis")
            .pq_aggregation_service(Arc::clone(&service))
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_blocking_hook(Arc::clone(&blocking_hook))
            .testing_only_pq_execution_notifier(admission_transport.clone())
            .build()
            .expect("admission-test PQ chain"),
    );
    admission_chain.slot_clock.set_slot(2);
    let admission_processor = Arc::new(PqNetworkBlockProcessor::new(Arc::clone(&admission_chain)));
    let heartbeat_count = Arc::new(AtomicUsize::new(0));
    let heartbeat_stop = Arc::new(AtomicBool::new(false));
    let heartbeat = {
        let heartbeat_count = Arc::clone(&heartbeat_count);
        let heartbeat_stop = Arc::clone(&heartbeat_stop);
        tokio::spawn(async move {
            while !heartbeat_stop.load(Ordering::SeqCst) {
                heartbeat_count.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
            }
        })
    };
    let blocked_import = {
        let processor = Arc::clone(&admission_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_rpc_block(block).await })
    };
    wait_for_test_condition(
        || blocking_hook.entered() == 1,
        "blocking preparation hook entry",
    )
    .await;
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert!(
        heartbeat_count.load(Ordering::SeqCst) > 0,
        "blocking PQ preparation must not stall the async worker"
    );
    blocked_import.abort();
    assert_eq!(
        admission_chain.testing_only_pq_import_available_permits(),
        1,
        "an orphaned blocking phase must retain its admission until owned work exits"
    );
    blocking_hook.release();
    wait_for_test_condition(
        || {
            admission_chain.testing_only_pq_import_available_permits()
                == PQ_BLOCK_IMPORT_ADMISSION_CAPACITY
        },
        "admission release after canceled blocking phase",
    )
    .await;
    heartbeat_stop.store(true, Ordering::SeqCst);
    heartbeat.await.expect("heartbeat task");

    let first_engine = {
        let processor = Arc::clone(&admission_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_rpc_block(block).await })
    };
    let queued_commit = {
        let processor = Arc::clone(&admission_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_lookup_block(block).await })
    };
    wait_for_test_condition(
        || {
            blocking_hook.entered() == 3
                && admission_chain.testing_only_pq_import_available_permits() == 0
                && admission_transport.calls.load(Ordering::SeqCst) == 1
        },
        "two admitted imports and one stalled Engine call",
    )
    .await;
    let preparation_calls_at_capacity = blocking_hook.entered();
    assert!(matches!(
        admission_processor
            .import_rpc_block(Arc::clone(&signed))
            .await,
        Err(PqImportError::Local(PqImportLocalError::IngressCapacity))
    ));
    assert_eq!(blocking_hook.entered(), preparation_calls_at_capacity);
    assert_eq!(admission_transport.calls.load(Ordering::SeqCst), 1);

    let oversized = admission_processor
        .import_forward_range(vec![
            Arc::clone(&signed);
            PQ_FORWARD_RANGE_BLOCK_CAPACITY + 1
        ])
        .await
        .expect_err("oversized raw range fails before hashing or proof preparation");
    assert!(matches!(
        oversized.error,
        PqImportError::Local(PqImportLocalError::ForwardRangeCapacity {
            supplied,
            maximum,
        }) if supplied == PQ_FORWARD_RANGE_BLOCK_CAPACITY + 1
            && maximum == PQ_FORWARD_RANGE_BLOCK_CAPACITY
    ));
    assert_eq!(blocking_hook.entered(), preparation_calls_at_capacity);
    assert_eq!(admission_transport.calls.load(Ordering::SeqCst), 1);

    queued_commit.abort();
    wait_for_test_condition(
        || admission_chain.testing_only_pq_import_available_permits() == 1,
        "queued import cancellation",
    )
    .await;
    first_engine.abort();
    wait_for_test_condition(
        || admission_chain.testing_only_pq_import_available_permits() == 2,
        "pending Engine cancellation",
    )
    .await;
    let retry_after_engine_cancellation = {
        let processor = Arc::clone(&admission_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_rpc_block(block).await })
    };
    let stale_after_verification = {
        let processor = Arc::clone(&admission_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_lookup_block(block).await })
    };
    wait_for_test_condition(
        || {
            admission_transport.calls.load(Ordering::SeqCst) == 2
                && admission_chain.testing_only_pq_import_available_permits() == 0
        },
        "Engine retry and queued verified import after canceled notification",
    )
    .await;
    admission_transport.release.add_permits(1);
    let rpc_result = retry_after_engine_cancellation.await.expect("retry task");
    let lookup_result = stale_after_verification.await.expect("coalesced task");
    let rpc_outcome = rpc_result.expect("RPC exact duplicate coalesces through reconciliation");
    let lookup_outcome =
        lookup_result.expect("lookup exact duplicate coalesces through reconciliation");
    assert_eq!(rpc_outcome.source, PqBlockImportSource::Rpc);
    assert_eq!(lookup_outcome.source, PqBlockImportSource::Lookup);
    assert_eq!(rpc_outcome.block_root, signed.canonical_root());
    assert_eq!(lookup_outcome.block_root, signed.canonical_root());
    assert_eq!(
        admission_transport.calls.load(Ordering::SeqCst),
        2,
        "coalesced exact imports must not call Engine twice"
    );

    for expected_source in [PqBlockImportSource::Rpc, PqBlockImportSource::Lookup] {
        let source_transport = Arc::new(RecordingTransport::always_valid());
        let source_chain = Arc::new(
            BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
                .store(exact_snapshot_store(Arc::clone(&spec)))
                .custom_spec(Arc::clone(&spec))
                .genesis_state(genesis.clone())
                .expect("persist exact-source genesis")
                .pq_aggregation_service(Arc::clone(&service))
                .task_executor(test_runtime.task_executor.clone())
                .testing_only_pq_execution_notifier(source_transport.clone())
                .build()
                .expect("exact-source PQ chain"),
        );
        source_chain.slot_clock.set_slot(2);
        let source_processor = PqNetworkBlockProcessor::new(source_chain);
        let outcome = match expected_source {
            PqBlockImportSource::Rpc => {
                source_processor.import_rpc_block(Arc::clone(&signed)).await
            }
            PqBlockImportSource::Lookup => {
                source_processor
                    .import_lookup_block(Arc::clone(&signed))
                    .await
            }
            _ => unreachable!("exact-source test covers RPC and lookup"),
        }
        .expect("exact source imports through its awaited network route");
        assert_eq!(outcome.source, expected_source);
        assert_eq!(outcome.block_root, signed.canonical_root());
        assert_eq!(source_transport.calls.lock().expect("calls lock").len(), 1);
    }

    let persistence_store = exact_snapshot_store(Arc::clone(&spec));
    let persistence_transport = Arc::new(RecordingTransport::always_valid());
    let persistence_hook = TestingPqBlockingHook::blocking();
    let persistence_chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&persistence_store))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist cancellation-test genesis")
            .pq_aggregation_service(Arc::clone(&service))
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_persistence_hook(Arc::clone(&persistence_hook))
            .testing_only_pq_execution_notifier(persistence_transport.clone())
            .build()
            .expect("persistence-cancellation PQ chain"),
    );
    persistence_chain.slot_clock.set_slot(2);
    let persistence_processor =
        Arc::new(PqNetworkBlockProcessor::new(Arc::clone(&persistence_chain)));
    let canceled_after_valid = {
        let processor = Arc::clone(&persistence_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_rpc_block(block).await })
    };
    wait_for_test_condition(
        || persistence_hook.entered() == 1,
        "post-VALID persistence barrier",
    )
    .await;
    assert_eq!(
        persistence_transport
            .calls
            .lock()
            .expect("calls lock")
            .len(),
        1
    );
    assert_eq!(
        persistence_chain.head_snapshot().beacon_block_root,
        genesis_root
    );
    canceled_after_valid.abort();
    assert_eq!(
        persistence_chain.testing_only_pq_import_available_permits(),
        1,
        "canceled post-VALID publication retains its admission"
    );
    let blocked_behind_publication = {
        let processor = Arc::clone(&persistence_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_lookup_block(block).await })
    };
    wait_for_test_condition(
        || persistence_chain.testing_only_pq_import_available_permits() == 0,
        "second verified import blocked behind owned publication",
    )
    .await;
    assert!(matches!(
        persistence_processor
            .import_rpc_block(Arc::clone(&signed))
            .await,
        Err(PqImportError::Local(PqImportLocalError::IngressCapacity))
    ));
    assert_eq!(
        persistence_transport
            .calls
            .lock()
            .expect("calls lock")
            .len(),
        1,
        "the queued commit cannot reach Engine while publication owns the gate"
    );
    persistence_hook.release();
    wait_for_test_condition(
        || persistence_chain.head_snapshot().beacon_block_root == signed.canonical_root(),
        "cancellation-independent canonical publication",
    )
    .await;
    let coalesced = blocked_behind_publication
        .await
        .expect("blocked publication task")
        .expect("exact lookup coalesces after detached publication");
    assert_eq!(coalesced.source, PqBlockImportSource::Lookup);
    assert_eq!(coalesced.block_root, signed.canonical_root());
    assert!(persistence_chain.testing_only_pq_observation_is_committed(
        signed.slot(),
        signed.message().proposer_index(),
        signed.canonical_root(),
    ));
    let persistence_restarted = BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
        .store(persistence_store)
        .custom_spec(Arc::clone(&spec))
        .resume_from_db()
        .expect("resume cancellation-independent publication")
        .pq_aggregation_service(Arc::clone(&service))
        .task_executor(test_runtime.task_executor.clone())
        .testing_only_pq_execution_notifier(persistence_transport)
        .build()
        .expect("restarted cancellation-independent chain");
    assert_eq!(
        persistence_restarted.head_snapshot().beacon_block_root,
        signed.canonical_root()
    );

    let failed_persistence_store = exact_snapshot_store(Arc::clone(&spec));
    let failed_persistence_transport = Arc::new(RecordingTransport::always_valid());
    let failed_persistence_hook = TestingPqBlockingHook::blocking();
    let failed_persistence_chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&failed_persistence_store))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist failed-publication genesis")
            .pq_aggregation_service(Arc::clone(&service))
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_persistence_hook(Arc::clone(&failed_persistence_hook))
            .testing_only_pq_execution_notifier(failed_persistence_transport.clone())
            .build()
            .expect("failed-publication PQ chain"),
    );
    failed_persistence_chain.slot_clock.set_slot(2);
    failed_persistence_store
        .hot_db
        .fail_atomic_batch_containing(store::DBColumn::BeaconBlock);
    let failed_persistence_processor = Arc::new(PqNetworkBlockProcessor::new(Arc::clone(
        &failed_persistence_chain,
    )));
    let canceled_failed_publication = {
        let processor = Arc::clone(&failed_persistence_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_rpc_block(block).await })
    };
    wait_for_test_condition(
        || failed_persistence_hook.entered() == 1,
        "failed post-VALID persistence barrier",
    )
    .await;
    canceled_failed_publication.abort();
    failed_persistence_hook.release();
    wait_for_test_condition(
        || {
            failed_persistence_chain.testing_only_pq_import_available_permits()
                == PQ_BLOCK_IMPORT_ADMISSION_CAPACITY
                && failed_persistence_chain.testing_only_pq_observation_is_absent(
                    signed.slot(),
                    signed.message().proposer_index(),
                )
        },
        "failed publication owned cleanup",
    )
    .await;
    assert_eq!(
        failed_persistence_chain.head_snapshot().beacon_block_root,
        genesis_root,
        "database failure cannot publish memory after caller cancellation"
    );
    let failed_persistence_restarted = BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
        .store(failed_persistence_store)
        .custom_spec(Arc::clone(&spec))
        .resume_from_db()
        .expect("failed publication retains restartable genesis")
        .pq_aggregation_service(Arc::clone(&service))
        .task_executor(test_runtime.task_executor.clone())
        .testing_only_pq_execution_notifier(failed_persistence_transport)
        .build()
        .expect("restart after canceled database failure");
    assert_eq!(
        failed_persistence_restarted
            .head_snapshot()
            .beacon_block_root,
        genesis_root
    );

    let capacity_transport = Arc::new(RecordingTransport::invalid_block_hash());
    let capacity_chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist capacity-test genesis")
            .pq_aggregation_service(service)
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(capacity_transport.clone())
            .build()
            .expect("capacity-test PQ chain"),
    );
    let capacity_processor = PqNetworkBlockProcessor::new(Arc::clone(&capacity_chain));
    capacity_chain.slot_clock.set_slot(2);
    assert!(capacity_chain.testing_only_fill_pq_observation_capacity());
    assert!(matches!(
        capacity_processor
            .import_rpc_block(Arc::clone(&signed))
            .await,
        Err(PqImportError::Local(
            PqImportLocalError::ObservationCapacity
        ))
    ));
    assert!(
        capacity_transport
            .calls
            .lock()
            .expect("calls lock")
            .is_empty(),
        "a full observation cache must fail before Engine notification"
    );
}
