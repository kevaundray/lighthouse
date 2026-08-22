#![cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]

use beacon_chain::{
    PqSingleConsumptionResult, PqSingleObservationCompletion, PqSingleObservationIdentity,
};
use lighthouse_network::MessageId;
use network::testing_only_pq_attestation_consumption_coordinator_driver;
use types::{Epoch, Hash256, Slot, SubnetId};

fn identity(instance: u8, slot: u64) -> PqSingleObservationIdentity {
    PqSingleObservationIdentity::new(
        Epoch::new(slot / 8),
        u64::from(instance),
        Slot::new(slot),
        SubnetId::new(u64::from(instance % 8)),
        Hash256::repeat_byte(instance),
        [instance; 32],
    )
}

#[tokio::test]
async fn inbound_completions_are_resolved_by_the_chain_without_permanent_network_history() {
    let mut driver = testing_only_pq_attestation_consumption_coordinator_driver();

    for (instance, slot, outcome) in [
        (1, 7, PqSingleConsumptionResult::Applied),
        (2, 8, PqSingleConsumptionResult::Queued),
        (3, 9, PqSingleConsumptionResult::Applied),
    ] {
        let message_id = MessageId(vec![instance; 20]);
        let exact_identity = identity(instance, slot);
        let mut watch = driver
            .claim_and_subscribe(message_id.clone(), exact_identity, Slot::new(0))
            .expect("the real observation cache accepts the exact inbound claim");
        driver
            .handle_actual_completion(message_id, exact_identity, outcome)
            .expect("the service completion coordinator resolves the chain observation");
        assert_eq!(
            watch.wait().await,
            Ok(PqSingleObservationCompletion::Consumed(outcome)),
            "the third unique completion must resolve just like the first two",
        );
    }
    assert!(driver.ingress_is_open());
    assert_eq!(driver.shutdown_signal_count(), 0);

    let message_id = MessageId(vec![9; 20]);
    let exact_identity = identity(9, 9);
    let mut watch = driver
        .claim_and_subscribe(message_id.clone(), exact_identity, Slot::new(0))
        .expect("the exact conflicting fixture starts as one real claim");
    driver
        .handle_actual_completion(
            message_id.clone(),
            exact_identity,
            PqSingleConsumptionResult::Applied,
        )
        .expect("the first exact completion is authoritative");
    assert_eq!(
        watch.wait().await,
        Ok(PqSingleObservationCompletion::Consumed(
            PqSingleConsumptionResult::Applied,
        )),
    );
    assert!(
        driver
            .handle_actual_completion(
                message_id,
                exact_identity,
                PqSingleConsumptionResult::Terminal,
            )
            .is_err(),
        "a different result for an exact consumed identity is an invariant, not a second record",
    );
    assert_eq!(driver.shutdown_signal_count(), 1);

    let mut exact_wire_driver = testing_only_pq_attestation_consumption_coordinator_driver();
    let wire_a = MessageId(vec![0xa1; 20]);
    let wire_b = MessageId(vec![0xb2; 20]);
    let wire_identity = identity(10, 10);
    let mut exact_wire_watch = exact_wire_driver
        .claim_and_subscribe(wire_a.clone(), wire_identity, Slot::new(0))
        .expect("the original wire ID owns the exact chain observation");
    assert!(
        exact_wire_driver
            .handle_actual_completion(wire_b, wire_identity, PqSingleConsumptionResult::Applied,)
            .is_err(),
        "the H1 coordinator must reject an identical signed identity under another wire ID",
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            exact_wire_watch.wait(),
        )
        .await
        .is_err(),
        "a conflicting completion must not wake the original wire subscriber",
    );
    exact_wire_driver
        .handle_actual_completion(wire_a, wire_identity, PqSingleConsumptionResult::Applied)
        .expect("the exact original wire completion remains authoritative");
    assert_eq!(
        exact_wire_watch.wait().await,
        Ok(PqSingleObservationCompletion::Consumed(
            PqSingleConsumptionResult::Applied,
        )),
    );

    let service_source = include_str!("../src/pq_runtime/service.rs");
    assert!(!service_source.contains("retained_attestation_consumptions"));
    assert!(!service_source.contains("PqRetainedAttestationConsumption"));
    assert!(!service_source.contains("VecDeque<PqRetainedAttestationConsumption>"));
}
