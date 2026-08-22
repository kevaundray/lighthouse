#![cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]

use beacon_chain::{
    PqPublishedLocalMemberResolutionError, PqSingleConsumptionResult, PqSingleObservationStatus,
};
use network::{
    PqAttestationAdmissionBridgeFailure, PqAttestationAdmissionBridgeTiming,
    PqLocalAttestationPostPublishFailure,
    testing_only_pq_attestation_active_admission_bridge_driver,
};

#[tokio::test]
async fn pending_remote_waits_for_the_inbound_claim_without_polling_or_lost_wake() {
    for (timing, result) in [
        (
            PqAttestationAdmissionBridgeTiming::CompletionBeforeFirstPoll,
            PqSingleConsumptionResult::Applied,
        ),
        (
            PqAttestationAdmissionBridgeTiming::CompletionAfterFirstPoll,
            PqSingleConsumptionResult::Queued,
        ),
    ] {
        let mut driver = testing_only_pq_attestation_active_admission_bridge_driver().await;
        let message_id = driver.member_message_id();
        let digest = driver.member_signed_ssz_digest();

        driver
            .start_actual_inbound_pending()
            .expect("the actual inbound event synchronously creates one active exact bridge entry");
        driver
            .start_actual_local_pending_remote(timing)
            .await
            .expect("H3 obtains a non-clone bridge receipt while chain state is still Unseen");
        assert!(driver.public_receipt_is_pending());
        assert_eq!(driver.consumer_call_count(), 0);
        assert_eq!(driver.fail_closed_call_count(), 0);
        assert_eq!(
            driver.chain_observation_status(),
            PqSingleObservationStatus::Unseen,
        );

        if timing == PqAttestationAdmissionBridgeTiming::CompletionAfterFirstPoll {
            driver
                .poll_bridge_once()
                .await
                .expect("the exact bridge receipt is armed without polling chain state");
        }
        driver
            .mark_actual_inbound_claim_ready()
            .expect("the inbound preparation publishes ClaimReady for the exact wire ID");
        driver
            .claim_and_mark_chain_observation()
            .expect("the same inbound lifecycle claims and propagates the real chain observation");
        driver
            .complete_actual_inbound_consumption(result)
            .expect("the actual inbound coordinator preserves the exact completion");
        let trace = driver
            .finish_actual_local_receiver()
            .await
            .expect("the local owner subscribes after ClaimReady and consumes exactly once");

        assert_eq!(trace.message_id, message_id);
        assert_eq!(trace.signed_ssz_digest, digest);
        assert_eq!(trace.result, result);
        assert_eq!(trace.consumer_calls, 1);
        assert_eq!(trace.fail_closed_calls, 0);
        assert_eq!(trace.bridge_entry_count, 0);
    }
}

#[tokio::test]
async fn released_before_claim_retries_the_identical_local_member_once() {
    let mut driver = testing_only_pq_attestation_active_admission_bridge_driver().await;
    driver
        .start_actual_inbound_pending()
        .expect("one exact active bridge entry");
    driver
        .start_actual_local_pending_remote(
            PqAttestationAdmissionBridgeTiming::CompletionAfterFirstPoll,
        )
        .await
        .expect("local publication waits on the bridge");
    driver
        .poll_bridge_once()
        .await
        .expect("bridge receipt remains pending");
    let message_id = driver.member_message_id();
    let digest = driver.member_signed_ssz_digest();

    driver
        .release_actual_inbound_before_claim()
        .expect("retryable inbound completion publishes Released and removes its active entry");
    driver
        .drive_actual_local_retry_event()
        .await
        .expect("the production receiver retries the same encoded member after 10ms");

    assert_eq!(driver.member_message_id(), message_id);
    assert_eq!(driver.member_signed_ssz_digest(), digest);
    assert_eq!(driver.attempted_member_sequence(), &[0, 0]);
    assert_eq!(driver.reencode_call_count(), 0);
    assert_eq!(driver.sign_call_count(), 0);
    assert_eq!(driver.proof_call_count(), 0);
    assert_eq!(driver.bridge_entry_count(), 0);
}

#[tokio::test]
async fn terminal_or_mismatched_bridge_completion_cannot_wake_the_exact_local_owner() {
    let mut mismatch = testing_only_pq_attestation_active_admission_bridge_driver().await;
    mismatch
        .start_actual_inbound_pending()
        .expect("one exact active bridge entry");
    mismatch
        .start_actual_local_pending_remote(
            PqAttestationAdmissionBridgeTiming::CompletionAfterFirstPoll,
        )
        .await
        .expect("local owner waits on exact ID");
    mismatch
        .poll_bridge_once()
        .await
        .expect("exact receipt is armed");
    assert!(mismatch.complete_mismatched_wire_id().is_err());
    assert!(mismatch.public_receipt_is_pending());
    assert_eq!(mismatch.fail_closed_call_count(), 0);

    let mut terminal = testing_only_pq_attestation_active_admission_bridge_driver().await;
    terminal
        .start_actual_inbound_pending()
        .expect("one exact active bridge entry");
    terminal
        .start_actual_local_pending_remote(
            PqAttestationAdmissionBridgeTiming::CompletionAfterFirstPoll,
        )
        .await
        .expect("local owner waits on exact ID");
    terminal
        .fail_actual_inbound(PqAttestationAdmissionBridgeFailure::Terminal)
        .expect("actual inbound lifecycle resolves terminal");
    let trace = terminal
        .finish_actual_local_terminal()
        .await
        .expect("terminal finalization completes the local receipt");
    assert_eq!(trace.consumer_calls, 0);
    assert_eq!(trace.fail_closed_calls, 1);
    assert_eq!(trace.bridge_entry_count, 0);
}

#[tokio::test]
async fn admission_bridge_loss_is_typed_end_to_end() {
    let mut driver = testing_only_pq_attestation_active_admission_bridge_driver().await;
    driver
        .start_actual_inbound_pending()
        .expect("one exact active bridge entry");
    driver
        .start_actual_local_pending_remote(
            PqAttestationAdmissionBridgeTiming::CompletionAfterFirstPoll,
        )
        .await
        .expect("local owner waits on the exact bridge receipt");
    driver
        .poll_bridge_once()
        .await
        .expect("the real bridge receipt is pending");
    driver
        .lose_actual_bridge_channel()
        .expect("the actual bridge sender disappears without a completion");

    let trace = driver
        .finish_actual_local_terminal()
        .await
        .expect("bridge loss completes only after fail-close finalization");
    assert_eq!(trace.consumer_calls, 0);
    assert_eq!(trace.fail_closed_calls, 1);
    assert_eq!(
        trace.terminal_failure,
        Some(PqLocalAttestationPostPublishFailure::RemoteResolution(
            PqPublishedLocalMemberResolutionError::AdmissionBridgeLost,
        )),
    );
    assert_eq!(trace.bridge_entry_count, 0);
}

#[tokio::test]
async fn active_bridge_is_bounded_to_the_existing_two_pending_admissions_and_removes_entries() {
    let mut driver = testing_only_pq_attestation_active_admission_bridge_driver().await;
    let first = driver
        .start_distinct_actual_inbound_pending(0)
        .expect("first active admission");
    let second = driver
        .start_distinct_actual_inbound_pending(1)
        .expect("second active admission");
    let third = driver
        .start_distinct_actual_inbound_pending(2)
        .expect_err("third concurrent admission is rejected by exact cap two");
    assert!(third.is_capacity());
    assert_eq!(driver.bridge_entry_count(), 2);

    driver
        .abandon_actual_inbound(first)
        .expect("abandoned admission releases its bridge entry");
    assert_eq!(driver.bridge_entry_count(), 1);
    let replacement = driver
        .start_distinct_actual_inbound_pending(2)
        .expect("a third sequential admission succeeds after bounded removal");
    driver
        .resolve_actual_inbound(second, PqSingleConsumptionResult::Applied)
        .expect("resolved admission removes its bridge entry");
    driver
        .abandon_actual_inbound(replacement)
        .expect("replacement cleanup removes its bridge entry");
    assert_eq!(driver.bridge_entry_count(), 0);
}
