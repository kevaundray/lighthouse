#![cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]

use beacon_chain::{
    PqPublishedLocalMemberResolutionError, PqSingleConsumptionResult, PqSingleObservationStatus,
};
use network::{
    PqLocalAttestationPostPublishFailure, PqMixedRemoteFailure, PqMixedRemoteTiming,
    testing_only_pq_chain_authoritative_mixed_publish_driver,
};

#[tokio::test]
async fn mixed_local_and_exact_remote_completion_consumes_once_for_every_race() {
    for (timing, remote_result) in [
        (
            PqMixedRemoteTiming::BeforeFirstPoll,
            PqSingleConsumptionResult::Applied,
        ),
        (
            PqMixedRemoteTiming::AfterFirstPoll,
            PqSingleConsumptionResult::Queued,
        ),
        (
            PqMixedRemoteTiming::BeforeLocalPublication,
            PqSingleConsumptionResult::Applied,
        ),
    ] {
        let mut driver = testing_only_pq_chain_authoritative_mixed_publish_driver().await;
        driver
            .claim_member_one_remote_pending()
            .expect("member1 has one exact chain-owned remote Pending claim");
        let member_one_message_id = driver.member_message_id(1);
        let member_one_digest = driver.member_signed_ssz_digest(1);

        driver
            .start_actual_publish_with_remote_timing(timing)
            .await
            .expect("the production receiver publishes member0 and retains member1 PendingRemote");
        assert!(driver.public_receipt_is_pending());
        assert_eq!(driver.consumer_call_count(), 0);
        assert!(driver.guards_are_retained());

        if timing == PqMixedRemoteTiming::AfterFirstPoll {
            driver
                .poll_remote_resolution_once()
                .await
                .expect("the real watch is polled and remains pending");
            assert_eq!(driver.consumer_call_count(), 0);
        }
        driver
            .complete_member_one_through_actual_coordinator(remote_result)
            .expect("the exact completion reaches the chain observation and network coordinator");
        let trace = driver
            .finish_actual_receiver()
            .await
            .expect("the mixed batch completes through the opaque consumer");

        assert_eq!(trace.consumer_calls, 1);
        assert_eq!(trace.results.len(), 2);
        assert_eq!(trace.results[1], remote_result);
        assert_eq!(trace.member_message_ids[1], member_one_message_id);
        assert_eq!(trace.member_signed_ssz_digests[1], member_one_digest);
        assert_eq!(
            trace.member_one_observation_status,
            PqSingleObservationStatus::Consumed(remote_result),
        );
        assert_eq!(trace.fail_closed_calls, 0);
    }
}

#[tokio::test]
async fn bridge_claim_ready_resolves_without_republishing_the_remote_member() {
    let mut driver = testing_only_pq_chain_authoritative_mixed_publish_driver().await;
    driver
        .start_actual_publish_waiting_on_member_one_bridge()
        .await
        .expect("the real route publishes member0 and waits on member1's active bridge");
    assert_eq!(driver.attempted_members(), &[0, 1]);
    assert!(driver.member_zero_publication_token_retained());
    assert!(driver.member_one_is_waiting_remote_without_local_token());
    assert!(driver.public_receipt_is_pending());
    assert_eq!(driver.consumer_call_count(), 0);

    driver
        .mark_member_one_claim_ready_through_actual_bridge()
        .expect("the inbound lifecycle publishes ClaimReady after the exact chain claim");
    driver
        .drive_claim_ready_through_actual_route()
        .await
        .expect("ClaimReady re-enters the production resolver without publishing again");
    assert_eq!(
        driver.attempted_members(),
        &[0, 1],
        "ClaimReady must not turn remote resolution into a second local publish attempt",
    );
    assert!(driver.member_zero_publication_token_retained());
    assert!(driver.member_one_is_waiting_remote_without_local_token());
    assert!(driver.public_receipt_is_pending());
    assert_eq!(driver.consumer_call_count(), 0);

    driver
        .complete_member_one_through_actual_coordinator(PqSingleConsumptionResult::Queued)
        .expect("the real chain watch resolves member1 as Queued");
    let (trace, member_progress) = driver
        .finish_actual_receiver_with_member_progress()
        .await
        .expect("one mixed batch reaches the whole-batch consumer");
    assert_eq!(trace.consumer_calls, 1);
    assert_eq!(
        member_progress,
        vec![
            network::PqLocalAttestationMemberPublishProgress::Consumed {
                message_id: trace.member_message_ids[0].clone(),
                duplicate: false,
                result: PqSingleConsumptionResult::Applied,
            },
            network::PqLocalAttestationMemberPublishProgress::Consumed {
                message_id: trace.member_message_ids[1].clone(),
                duplicate: true,
                result: PqSingleConsumptionResult::Queued,
            },
        ],
    );
}

#[tokio::test]
async fn wrong_wire_or_signed_digest_never_wakes_or_calls_the_consumer() {
    for mutation in [
        PqMixedRemoteFailure::WrongWireId,
        PqMixedRemoteFailure::WrongSignedSszDigest,
    ] {
        let mut driver = testing_only_pq_chain_authoritative_mixed_publish_driver().await;
        driver
            .claim_member_one_remote_pending()
            .expect("member1 starts with one exact pair-bound claim");
        driver
            .start_actual_publish_with_remote_timing(PqMixedRemoteTiming::AfterFirstPoll)
            .await
            .expect("the actual receiver retains the mixed owner");
        driver
            .poll_remote_resolution_once()
            .await
            .expect("the exact watch is armed before the mutation");

        assert!(driver.complete_member_one_with_mismatch(mutation).is_err());
        assert!(driver.public_receipt_is_pending());
        assert_eq!(driver.consumer_call_count(), 0);
        assert!(driver.guards_are_retained());

        driver
            .complete_member_one_through_actual_coordinator(PqSingleConsumptionResult::Queued)
            .expect("the original exact pair remains authoritative after the rejected mismatch");
        let trace = driver
            .finish_actual_receiver()
            .await
            .expect("the exact completion still consumes once");
        assert_eq!(trace.consumer_calls, 1);
        assert_eq!(trace.results[1], PqSingleConsumptionResult::Queued);
        assert_eq!(trace.fail_closed_calls, 0);
    }
}

#[tokio::test]
async fn released_remote_member_retries_identical_suffix_and_rebinds_one_generation() {
    let mut driver = testing_only_pq_chain_authoritative_mixed_publish_driver().await;
    let original_generation = driver
        .claim_member_one_remote_pending()
        .expect("member1 starts with one exact remote generation");
    driver
        .start_actual_publish_with_remote_timing(PqMixedRemoteTiming::AfterFirstPoll)
        .await
        .expect("member0 publishes while member1 waits remotely");
    driver
        .poll_remote_resolution_once()
        .await
        .expect("the real remote receipt is pending");
    assert_eq!(driver.attempted_members(), &[0, 1]);
    assert!(driver.member_zero_publication_token_retained());
    assert!(driver.public_receipt_is_pending());
    assert_eq!(driver.consumer_call_count(), 0);
    let message_id = driver.member_message_id(1);
    let digest = driver.member_signed_ssz_digest(1);

    driver
        .release_member_one_exact_generation()
        .expect("rollback publishes Released for the exact real generation");
    driver
        .drive_production_retry_event()
        .await
        .expect("the production receiver retries only the released suffix");
    let replacement_generation = driver
        .member_one_generation()
        .expect("retry creates one new exact local ConsumptionPending generation");
    assert_ne!(replacement_generation, original_generation);
    assert_eq!(driver.member_message_id(1), message_id);
    assert_eq!(driver.member_signed_ssz_digest(1), digest);
    assert_eq!(driver.attempted_members(), &[0, 1, 1]);
    assert!(driver.member_zero_publication_token_retained());
    assert_eq!(
        driver.member_one_observation_status(),
        PqSingleObservationStatus::ConsumptionPending,
    );

    let trace = driver
        .finish_actual_receiver()
        .await
        .expect("the exact retried mixed batch enters the consumer once");
    assert_eq!(trace.consumer_calls, 1);
    assert_eq!(trace.fail_closed_calls, 0);
    assert_eq!(trace.reencode_calls, 0);
    assert_eq!(trace.sign_calls, 0);
    assert_eq!(trace.proof_calls, 0);
}

#[tokio::test]
async fn remote_terminal_or_conflict_fails_closed_once() {
    for failure in [
        PqMixedRemoteFailure::Terminal,
        PqMixedRemoteFailure::Conflict,
    ] {
        let mut driver = testing_only_pq_chain_authoritative_mixed_publish_driver().await;
        driver
            .claim_member_one_remote_pending()
            .expect("member1 starts with one exact remote observation");
        driver
            .start_actual_publish_with_remote_timing(PqMixedRemoteTiming::AfterFirstPoll)
            .await
            .expect("the production receiver retains the published prefix");
        driver
            .poll_remote_resolution_once()
            .await
            .expect("the real chain watch is pending");
        driver
            .fail_member_one_through_actual_path(failure)
            .expect("the actual observation/coordinator path records the failure");

        let trace = driver
            .finish_actual_receiver_terminal()
            .await
            .expect("terminal receipt completes only after fail-close finalization");
        assert_eq!(trace.consumer_calls, 0);
        assert_eq!(trace.fail_closed_calls, 1);
        assert!(!trace.guards_retained_after_terminal);
    }
}

#[tokio::test]
async fn chain_observation_watch_loss_is_typed_end_to_end() {
    let mut driver = testing_only_pq_chain_authoritative_mixed_publish_driver().await;
    driver
        .claim_member_one_remote_pending()
        .expect("member1 starts with one exact remote observation");
    driver
        .start_actual_publish_with_remote_timing(PqMixedRemoteTiming::AfterFirstPoll)
        .await
        .expect("the production receiver retains the published prefix");
    driver
        .poll_remote_resolution_once()
        .await
        .expect("the real chain watch is pending");
    driver
        .fail_member_one_through_actual_path(PqMixedRemoteFailure::Lost)
        .expect("the exact chain observation watch is lost");

    let trace = driver
        .finish_actual_receiver_terminal()
        .await
        .expect("watch loss completes only after fail-close finalization");
    assert_eq!(trace.consumer_calls, 0);
    assert_eq!(trace.fail_closed_calls, 1);
    assert_eq!(
        trace.terminal_failure,
        Some(PqLocalAttestationPostPublishFailure::RemoteResolution(
            PqPublishedLocalMemberResolutionError::ObservationLost,
        )),
    );
    assert!(!trace.guards_retained_after_terminal);
}
