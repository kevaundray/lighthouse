#![cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]

use network::{
    PqAttestationBridgeLifecycleEvent, PqAttestationBridgeReportOutcome,
    testing_only_pq_attestation_bridge_lifecycle_driver,
};

#[tokio::test]
async fn claim_ready_is_published_only_after_the_real_chain_mark_succeeds() {
    let mut normal = testing_only_pq_attestation_bridge_lifecycle_driver().await;
    normal
        .start_actual_inbound_and_local_pending()
        .await
        .expect("actual service ingress and lower PendingRemote are active");
    normal
        .complete_actual_verifier_with_valid_token()
        .expect("real chain preparation returns its sealed propagation token");
    normal
        .finish_actual_accept(PqAttestationBridgeReportOutcome::Commit)
        .await
        .expect("normal report/mark/consume lifecycle completes");
    assert_eq!(
        normal.events(),
        &[
            PqAttestationBridgeLifecycleEvent::AdmissionReserved,
            PqAttestationBridgeLifecycleEvent::VerificationSpawned,
            PqAttestationBridgeLifecycleEvent::ReportedAccept,
            PqAttestationBridgeLifecycleEvent::ChainMarkedPropagated,
            PqAttestationBridgeLifecycleEvent::BridgeClaimReady,
            PqAttestationBridgeLifecycleEvent::LocalSubscribedToChain,
        ],
        "ClaimReady must be causally after the actual propagation mark",
    );
    assert_eq!(normal.fail_closed_call_count(), 0);

    let mut pruned = testing_only_pq_attestation_bridge_lifecycle_driver().await;
    pruned
        .start_actual_inbound_and_local_pending()
        .await
        .expect("actual service ingress and lower PendingRemote are active");
    pruned
        .complete_actual_verifier_with_valid_token()
        .expect("real chain preparation returns its sealed propagation token");
    pruned
        .prune_chain_pending_immediately_before_mark()
        .expect("deterministic barrier removes the real Pending observation at the mark boundary");
    let failure = pruned
        .finish_actual_accept(PqAttestationBridgeReportOutcome::Commit)
        .await
        .expect_err("marking a pruned claim must fail before ClaimReady");
    assert!(failure.is_retryable());
    assert!(
        !pruned
            .events()
            .contains(&PqAttestationBridgeLifecycleEvent::BridgeClaimReady)
    );
    assert!(
        pruned
            .events()
            .contains(&PqAttestationBridgeLifecycleEvent::BridgeReleased)
    );
    assert!(pruned.exact_local_retry_is_ready());
    assert_eq!(pruned.fail_closed_call_count(), 0);
}

#[tokio::test]
async fn unavailable_verification_executor_releases_lower_and_bridge_for_exact_retry() {
    let mut driver = testing_only_pq_attestation_bridge_lifecycle_driver().await;
    driver.use_dead_task_executor();
    driver
        .start_actual_inbound_and_local_pending()
        .await
        .expect("actual synchronous ingress reserves lower admission and bridge first");
    let failure = driver
        .finish_spawn_unavailable()
        .await
        .expect_err("the actual verifier spawn is unavailable");

    assert!(failure.is_retryable());
    assert_eq!(driver.lower_retryable_ignore_count(), 1);
    assert_eq!(driver.bridge_released_count(), 1);
    assert_eq!(driver.bridge_terminal_count(), 0);
    assert_eq!(driver.fail_closed_call_count(), 0);
    assert!(driver.exact_local_retry_is_ready());
}

#[tokio::test]
async fn expired_lower_accept_rolls_back_chain_and_releases_bridge_without_terminalizing() {
    for report in [
        PqAttestationBridgeReportOutcome::NotFound,
        PqAttestationBridgeReportOutcome::Complete,
    ] {
        let mut driver = testing_only_pq_attestation_bridge_lifecycle_driver().await;
        driver
            .start_actual_inbound_and_local_pending()
            .await
            .expect("actual service ingress and lower PendingRemote are active");
        driver
            .complete_actual_verifier_with_valid_token()
            .expect("the real chain claim exists before lower reporting");
        driver
            .finish_actual_accept(report)
            .await
            .expect("expired lower admission resolves without propagation");

        assert_eq!(driver.chain_observation_rollback_count(), 1);
        assert_eq!(driver.bridge_released_count(), 1);
        assert_eq!(driver.bridge_terminal_count(), 0);
        assert_eq!(driver.fail_closed_call_count(), 0);
        assert!(driver.exact_local_retry_is_ready());
        assert!(
            !driver
                .events()
                .contains(&PqAttestationBridgeLifecycleEvent::BridgeClaimReady)
        );
    }
}
