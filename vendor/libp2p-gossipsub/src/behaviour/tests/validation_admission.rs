use super::*;
use crate::{
    AdmittedMessageCommitOutcome, AdmittedMessageReport, AdmittedMessageValidationOutcome,
    ConfigBuilder, ValidationAdmission, ValidationAdmissionConfig, ValidationAdmissionGuard,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

fn bounded_admission_limits() -> ValidationAdmissionConfig {
    ValidationAdmissionConfig {
        pending_capacity: 2,
        per_peer_pending_capacity: 1,
        remote_unique_capacity_per_window: 16,
        local_unique_capacity_per_window: 1,
        pending_timeout: Duration::from_secs(300),
        window: Duration::from_secs(300),
        retained_windows: 17,
    }
}

fn bounded_config(admitted_sources: Arc<Mutex<Vec<PeerId>>>) -> Config {
    ConfigBuilder::default()
        .validate_messages()
        .message_id_fn(|message| MessageId(message.data.clone()))
        .validation_admission(
            bounded_admission_limits(),
            move |source, _topic, _message_id, _message| {
                admitted_sources
                    .lock()
                    .expect("admission source lock")
                    .push(*source);
                ValidationAdmission::Admit(ValidationAdmissionGuard::new(()))
            },
        )
        .build()
        .expect("bounded validation config")
}

#[test]
fn configured_admission_is_source_aware_and_precedes_the_duplicate_cache() {
    let admitted_sources = Arc::new(Mutex::new(vec![]));
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(2)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(bounded_config(Arc::clone(&admitted_sources)))
        .create_network();
    let _queues = flush_events(&mut gs, queues);
    let message = random_message(&mut 1, &topics);

    gs.handle_received_message(message, &peers[0]);

    let event = gs.events.pop_front().expect("admitted message event");
    let admission_id = match event {
        ToSwarm::GenerateEvent(Event::AdmittedMessage {
            propagation_source,
            admission_id,
            message,
        }) => {
            assert_eq!(propagation_source, peers[0]);
            assert_eq!(message.topic, topics[0]);
            admission_id
        }
        other => panic!("unexpected event: {other:?}"),
    };
    assert_eq!(
        *admitted_sources.lock().expect("admission source lock"),
        vec![peers[0]]
    );
    assert!(!gs.duplicate_cache.contains(&admission_id));
    assert!(gs.mcache.get(&admission_id).is_none());
}

#[test]
fn default_none_admission_uses_the_unchanged_ordinary_validation_path() {
    let config = ConfigBuilder::default()
        .validate_messages()
        .message_id_fn(|message| MessageId(message.data.clone()))
        .build()
        .expect("ordinary config");
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(config)
        .create_network();
    let _queues = flush_events(&mut gs, queues);

    gs.handle_received_message(random_message(&mut 1, &topics), &peers[0]);
    let message_id = match gs.events.pop_front().expect("ordinary message event") {
        ToSwarm::GenerateEvent(Event::Message { message_id, .. }) => message_id,
        other => panic!("unexpected event from default admission path: {other:?}"),
    };
    assert!(gs.duplicate_cache.contains(&message_id));
    assert!(gs.mcache.get(&message_id).is_some());
    assert!(
        gs.report_message_validation_result(&message_id, &peers[0], MessageAcceptance::Accept,)
    );
}

#[test]
fn typed_retryable_ignore_releases_but_terminal_ignore_retains_the_exact_id() {
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(bounded_config(Arc::new(Mutex::new(vec![]))))
        .create_network();
    let _queues = flush_events(&mut gs, queues);
    let message = random_message(&mut 1, &topics);

    gs.handle_received_message(message.clone(), &peers[0]);
    let first_id = match gs.events.pop_front().expect("first admission") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };
    assert!(matches!(
        gs.report_admitted_message_outcome(
            &first_id,
            AdmittedMessageValidationOutcome::RetryableIgnore,
        ),
        AdmittedMessageReport::Complete,
    ));

    gs.handle_received_message(message.clone(), &peers[0]);
    let retry_id = match gs.events.pop_front().expect("retry admission") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };
    assert_eq!(retry_id, first_id);
    assert!(matches!(
        gs.report_admitted_message_outcome(
            &retry_id,
            AdmittedMessageValidationOutcome::TerminalIgnore,
        ),
        AdmittedMessageReport::Complete,
    ));

    gs.handle_received_message(message, &peers[0]);
    assert!(
        gs.events.is_empty(),
        "terminal exact ID must remain bounded and suppress re-admission",
    );
}

#[test]
fn accepted_admission_retains_guard_until_retryable_commit_resolution_then_reenters() {
    struct DropGuard(Arc<Mutex<usize>>);
    impl Drop for DropGuard {
        fn drop(&mut self) {
            *self.0.lock().expect("drop count lock") += 1;
        }
    }

    let drops = Arc::new(Mutex::new(0));
    let callback_drops = Arc::clone(&drops);
    let config = ConfigBuilder::default()
        .validate_messages()
        .message_id_fn(|message| MessageId(message.data.clone()))
        .validation_admission(bounded_admission_limits(), move |_, _, _, _| {
            ValidationAdmission::Admit(ValidationAdmissionGuard::new(DropGuard(Arc::clone(
                &callback_drops,
            ))))
        })
        .build()
        .expect("bounded validation config");
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(config)
        .create_network();
    let _queues = flush_events(&mut gs, queues);
    let message = random_message(&mut 1, &topics);

    gs.handle_received_message(message.clone(), &peers[0]);
    let admission_id = match gs.events.pop_front().expect("admitted message") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };
    let commit = match gs
        .report_admitted_message_outcome(&admission_id, AdmittedMessageValidationOutcome::Accept)
    {
        AdmittedMessageReport::Commit(commit) => commit,
        other => panic!("unexpected admitted report: {other:?}"),
    };
    assert_eq!(*drops.lock().expect("drop count lock"), 0);
    assert!(gs.duplicate_cache.contains(&admission_id));
    assert!(
        gs.mcache
            .get(&admission_id)
            .is_some_and(|raw| raw.validated)
    );

    assert!(gs.resolve_admitted_message_commit(commit, AdmittedMessageCommitOutcome::Retryable));
    assert_eq!(*drops.lock().expect("drop count lock"), 1);
    assert!(!gs.duplicate_cache.contains(&admission_id));
    assert!(gs.mcache.get(&admission_id).is_none());
    assert_eq!(
        gs.mcache.testing_history_entry_count(),
        0,
        "retryable commit resolution must remove the exact entry from every history bucket",
    );

    gs.heartbeat();
    gs.handle_received_message(message, &peers[0]);
    let retry_id = match gs.events.pop_front().expect("retry admission") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected retry event: {other:?}"),
    };
    assert_eq!(retry_id, admission_id);
    let retry_commit = match gs
        .report_admitted_message_outcome(&retry_id, AdmittedMessageValidationOutcome::Accept)
    {
        AdmittedMessageReport::Commit(commit) => commit,
        other => panic!("unexpected retry report: {other:?}"),
    };

    for _ in 0..gs.config.history_length() - 1 {
        gs.heartbeat();
    }
    assert!(
        gs.mcache.get(&retry_id).is_some(),
        "expiry of the first acceptance bucket must not evict the exact reacceptance",
    );
    assert_eq!(gs.mcache.testing_history_entry_count(), 1);
    assert!(
        gs.resolve_admitted_message_commit(retry_commit, AdmittedMessageCommitOutcome::Terminal,)
    );
}

#[test]
fn behaviour_shutdown_releases_an_unresolved_accepted_admission() {
    struct DropGuard(Arc<Mutex<usize>>);
    impl Drop for DropGuard {
        fn drop(&mut self) {
            *self.0.lock().expect("drop count lock") += 1;
        }
    }

    let drops = Arc::new(Mutex::new(0));
    let callback_drops = Arc::clone(&drops);
    let config = ConfigBuilder::default()
        .validate_messages()
        .validation_admission(bounded_admission_limits(), move |_, _, _, _| {
            ValidationAdmission::Admit(ValidationAdmissionGuard::new(DropGuard(Arc::clone(
                &callback_drops,
            ))))
        })
        .build()
        .expect("bounded validation config");
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(config)
        .create_network();
    let _queues = flush_events(&mut gs, queues);
    gs.handle_received_message(random_message(&mut 1, &topics), &peers[0]);
    let admission_id = match gs.events.pop_front().expect("admitted message") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };
    let commit = match gs
        .report_admitted_message_outcome(&admission_id, AdmittedMessageValidationOutcome::Accept)
    {
        AdmittedMessageReport::Commit(commit) => commit,
        other => panic!("unexpected admitted report: {other:?}"),
    };
    drop(commit);
    assert_eq!(*drops.lock().expect("drop count lock"), 0);
    drop(gs);
    assert_eq!(*drops.lock().expect("drop count lock"), 1);
}

#[test]
fn commit_without_propagation_retains_only_the_exact_admission_until_resolution() {
    struct DropGuard(Arc<Mutex<usize>>);
    impl Drop for DropGuard {
        fn drop(&mut self) {
            *self.0.lock().expect("drop count lock") += 1;
        }
    }

    let drops = Arc::new(Mutex::new(0));
    let callback_drops = Arc::clone(&drops);
    let config = ConfigBuilder::default()
        .validate_messages()
        .message_id_fn(|message| MessageId(message.data.clone()))
        .validation_admission(bounded_admission_limits(), move |_, _, _, _| {
            ValidationAdmission::Admit(ValidationAdmissionGuard::new(DropGuard(Arc::clone(
                &callback_drops,
            ))))
        })
        .build()
        .expect("bounded validation config");
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(config)
        .create_network();
    let _queues = flush_events(&mut gs, queues);
    let message = random_message(&mut 1, &topics);

    gs.handle_received_message(message.clone(), &peers[0]);
    let admission_id = match gs.events.pop_front().expect("admitted message") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };
    let commit = match gs.report_admitted_message_outcome(
        &admission_id,
        AdmittedMessageValidationOutcome::CommitWithoutPropagation,
    ) {
        AdmittedMessageReport::Commit(commit) => commit,
        other => panic!("unexpected admitted report: {other:?}"),
    };
    assert_eq!(*drops.lock().expect("drop count lock"), 0);
    assert!(!gs.duplicate_cache.contains(&admission_id));
    assert!(gs.mcache.get(&admission_id).is_none());

    assert!(gs.resolve_admitted_message_commit(commit, AdmittedMessageCommitOutcome::Terminal));
    assert_eq!(*drops.lock().expect("drop count lock"), 1);
    gs.handle_received_message(message, &peers[0]);
    assert!(
        gs.events.is_empty(),
        "terminal commit without propagation must retain the exact bounded ID",
    );
}

#[test]
fn every_terminal_admitted_outcome_retains_the_exact_bounded_id() {
    for outcome in [
        AdmittedMessageValidationOutcome::TerminalIgnore,
        AdmittedMessageValidationOutcome::Reject,
        AdmittedMessageValidationOutcome::Equivocation,
        AdmittedMessageValidationOutcome::Pending,
    ] {
        let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
            .peer_no(1)
            .topics(vec!["blocks".into()])
            .to_subscribe(true)
            .gs_config(bounded_config(Arc::new(Mutex::new(vec![]))))
            .create_network();
        let _queues = flush_events(&mut gs, queues);
        let message = random_message(&mut 1, &topics);
        gs.handle_received_message(message.clone(), &peers[0]);
        let admission_id = match gs.events.pop_front().expect("admitted message") {
            ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(matches!(
            gs.report_admitted_message_outcome(&admission_id, outcome),
            AdmittedMessageReport::Complete,
        ));

        gs.handle_received_message(message, &peers[0]);
        assert!(
            gs.events.is_empty(),
            "terminal outcome {outcome:?} must suppress exact re-admission",
        );
    }
}

#[test]
fn pending_admission_is_global_two_per_peer_one_and_exact_duplicates_are_suppressed() {
    let admitted_sources = Arc::new(Mutex::new(vec![]));
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(3)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(bounded_config(Arc::clone(&admitted_sources)))
        .create_network();
    let _queues = flush_events(&mut gs, queues);
    let first = random_message(&mut 1, &topics);
    let same_peer_second = random_message(&mut 2, &topics);
    let other_peer_second = random_message(&mut 3, &topics);
    let over_capacity = random_message(&mut 4, &topics);

    gs.handle_received_message(first.clone(), &peers[0]);
    gs.handle_received_message(first, &peers[1]);
    gs.handle_received_message(same_peer_second, &peers[0]);
    gs.handle_received_message(other_peer_second, &peers[1]);
    gs.handle_received_message(over_capacity, &peers[2]);

    let admitted_events = gs
        .events
        .iter()
        .filter(|event| matches!(event, ToSwarm::GenerateEvent(Event::AdmittedMessage { .. })))
        .count();
    assert_eq!(admitted_events, 2);
    assert_eq!(
        *admitted_sources.lock().expect("admission source lock"),
        vec![peers[0], peers[1]],
        "duplicates and capacity overflow must not invoke the application callback",
    );
}

#[test]
fn accept_moves_exact_pending_raw_message_into_canonical_history() {
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(2)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(bounded_config(Arc::new(Mutex::new(vec![]))))
        .create_network();
    let _queues = flush_events(&mut gs, queues);
    gs.handle_received_message(random_message(&mut 1, &topics), &peers[0]);
    let admission_id = match gs.events.pop_front().expect("admitted message") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };

    let commit = match gs
        .report_admitted_message_outcome(&admission_id, AdmittedMessageValidationOutcome::Accept)
    {
        AdmittedMessageReport::Commit(commit) => commit,
        other => panic!("unexpected admitted report: {other:?}"),
    };
    assert!(gs.resolve_admitted_message_commit(commit, AdmittedMessageCommitOutcome::Terminal));
    assert!(gs.duplicate_cache.contains(&admission_id));
    assert!(
        gs.mcache
            .get(&admission_id)
            .is_some_and(|message| message.validated)
    );
}

#[test]
fn unique_history_is_remote_sixteen_local_one_and_seventeen_windows() {
    let config = ValidationAdmissionConfig {
        pending_capacity: 2,
        per_peer_pending_capacity: 1,
        remote_unique_capacity_per_window: 16,
        local_unique_capacity_per_window: 1,
        pending_timeout: Duration::from_secs(300),
        window: Duration::from_secs(300),
        retained_windows: 17,
    };
    let start = Instant::now();
    let mut history = ValidationAdmissionHistory::new(config, start)
        .expect("valid bounded history configuration");
    let peers = (0..17).map(|_| PeerId::random()).collect::<Vec<_>>();
    let remote_ids = (0_u8..16)
        .map(|byte| MessageId(vec![byte]))
        .collect::<Vec<_>>();
    for (id, peer) in remote_ids.iter().zip(&peers) {
        assert_eq!(
            history.reserve_remote(id, peer, start),
            ValidationReservation::New,
        );
    }
    assert_eq!(
        history.reserve_remote(&remote_ids[0], &peers[16], start),
        ValidationReservation::Duplicate,
    );
    assert_eq!(
        history.reserve_remote(&MessageId(vec![16]), &peers[16], start),
        ValidationReservation::Full,
    );
    history.release(&remote_ids[1]);
    assert_eq!(
        history.reserve_remote(&MessageId(vec![19]), &peers[1], start),
        ValidationReservation::New,
    );
    assert_eq!(
        history.reserve_remote(&MessageId(vec![20]), &peers[1], start),
        ValidationReservation::PeerFull,
    );
    assert_eq!(
        history.reserve_local(&MessageId(vec![17]), start),
        ValidationReservation::New,
    );
    assert_eq!(
        history.reserve_local(&MessageId(vec![18]), start),
        ValidationReservation::Full,
    );

    for window in 1_u32..17 {
        let now = start + config.window * window;
        for offset in 0_u8..17 {
            let id = MessageId(vec![window as u8, offset]);
            let reservation = if offset < 16 {
                history.reserve_remote(&id, &peers[offset as usize], now)
            } else {
                history.reserve_local(&id, now)
            };
            assert_eq!(reservation, ValidationReservation::New);
        }
    }
    assert_eq!(history.retained_len(), 17 * 17);
    let next_window = start + config.window * 17;
    assert_eq!(
        history.reserve_remote(&remote_ids[0], &peers[0], next_window),
        ValidationReservation::New,
        "the oldest of exactly seventeen retained windows expires on rollover",
    );
    assert!(history.retained_len() <= 17 * 17);
}

#[test]
fn retryable_ignore_releases_peer_and_guard_but_terminal_reject_retains_peer_window() {
    struct DropGuard(Arc<Mutex<usize>>);
    impl Drop for DropGuard {
        fn drop(&mut self) {
            *self.0.lock().expect("drop count lock") += 1;
        }
    }

    let drops = Arc::new(Mutex::new(0));
    let drops_for_callback = Arc::clone(&drops);
    let config = ConfigBuilder::default()
        .validate_messages()
        .validation_admission(
            ValidationAdmissionConfig {
                pending_capacity: 2,
                per_peer_pending_capacity: 1,
                remote_unique_capacity_per_window: 16,
                local_unique_capacity_per_window: 1,
                pending_timeout: Duration::from_secs(300),
                window: Duration::from_secs(300),
                retained_windows: 17,
            },
            move |_, _, _, _| {
                ValidationAdmission::Admit(ValidationAdmissionGuard::new(DropGuard(Arc::clone(
                    &drops_for_callback,
                ))))
            },
        )
        .build()
        .expect("bounded validation config");
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(config)
        .create_network();
    let _queues = flush_events(&mut gs, queues);

    gs.handle_received_message(random_message(&mut 1, &topics), &peers[0]);
    let first = match gs.events.pop_front().expect("first admission") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };
    assert!(matches!(
        gs.report_admitted_message_outcome(
            &first,
            AdmittedMessageValidationOutcome::RetryableIgnore,
        ),
        AdmittedMessageReport::Complete,
    ));
    assert_eq!(*drops.lock().expect("drop count lock"), 1);

    gs.handle_received_message(random_message(&mut 2, &topics), &peers[0]);
    let second = match gs.events.pop_front().expect("retry admission") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };
    assert!(matches!(
        gs.report_admitted_message_outcome(&second, AdmittedMessageValidationOutcome::Reject),
        AdmittedMessageReport::Complete,
    ));
    assert_eq!(*drops.lock().expect("drop count lock"), 2);

    gs.handle_received_message(random_message(&mut 3, &topics), &peers[0]);
    assert!(
        gs.events.is_empty(),
        "terminal peer reservation must remain"
    );
}

#[test]
fn expired_pending_admission_releases_raw_guard_peer_and_unique_reservation() {
    let drops = Arc::new(Mutex::new(0));
    struct DropGuard(Arc<Mutex<usize>>);
    impl Drop for DropGuard {
        fn drop(&mut self) {
            *self.0.lock().expect("drop count lock") += 1;
        }
    }
    let callback_drops = Arc::clone(&drops);
    let config = ConfigBuilder::default()
        .validate_messages()
        .validation_admission(
            ValidationAdmissionConfig {
                pending_timeout: Duration::from_secs(300),
                ..bounded_admission_limits()
            },
            move |_, _, _, _| {
                ValidationAdmission::Admit(ValidationAdmissionGuard::new(DropGuard(Arc::clone(
                    &callback_drops,
                ))))
            },
        )
        .build()
        .expect("bounded validation config");
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(config)
        .create_network();
    let _queues = flush_events(&mut gs, queues);

    gs.handle_received_message(random_message(&mut 1, &topics), &peers[0]);
    let admission_id = match gs.events.pop_front().expect("admitted message") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };
    let expiry = gs
        .pending_admissions
        .get(&admission_id)
        .expect("pending admission")
        .expires;
    gs.expire_validation_admissions(expiry);
    assert_eq!(*drops.lock().expect("drop count lock"), 1);
    assert!(!gs.pending_admissions.contains_key(&admission_id));

    gs.handle_received_message(random_message(&mut 2, &topics), &peers[0]);
    assert!(matches!(
        gs.events.pop_front(),
        Some(ToSwarm::GenerateEvent(Event::AdmittedMessage { .. }))
    ));
}

#[test]
fn one_slot_pending_deadline_survives_the_old_twelve_second_policy() {
    macro_rules! admitted_at {
        ($pending_timeout:expr) => {{
            let pending_timeout = $pending_timeout;
            let config = ConfigBuilder::default()
                .validate_messages()
                .message_id_fn(|message| MessageId(message.data.clone()))
                .validation_admission(
                    ValidationAdmissionConfig {
                        pending_timeout,
                        ..bounded_admission_limits()
                    },
                    |_, _, _, _| ValidationAdmission::Admit(ValidationAdmissionGuard::new(())),
                )
                .build()
                .expect("bounded validation config");
            let (mut behaviour, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
                .peer_no(1)
                .topics(vec!["blocks".into()])
                .to_subscribe(true)
                .gs_config(config)
                .create_network();
            let _queues = flush_events(&mut behaviour, queues);
            behaviour.handle_received_message(random_message(&mut 1, &topics), &peers[0]);
            let admission_id = match behaviour.events.pop_front().expect("admitted message") {
                ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
                other => panic!("unexpected event: {other:?}"),
            };
            let admitted_at = behaviour
                .pending_admissions
                .get(&admission_id)
                .expect("pending admission")
                .expires
                .checked_sub(pending_timeout)
                .expect("expiry follows admission");
            (behaviour, admission_id, admitted_at)
        }};
    }

    let after_old_history = Duration::from_secs(13);
    let (mut old_policy, old_id, old_admitted_at) = admitted_at!(Duration::from_secs(12));
    old_policy.expire_validation_admissions(old_admitted_at + after_old_history);
    assert!(!old_policy.pending_admissions.contains_key(&old_id));

    let (mut one_slot_policy, one_slot_id, one_slot_admitted_at) =
        admitted_at!(Duration::from_secs(300));
    one_slot_policy.expire_validation_admissions(one_slot_admitted_at + after_old_history);
    assert!(
        one_slot_policy
            .pending_admissions
            .contains_key(&one_slot_id)
    );
}

#[test]
fn local_publish_of_exact_pending_message_is_negative_not_duplicate() {
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(2)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(bounded_config(Arc::new(Mutex::new(vec![]))))
        .create_network();
    let _queues = flush_events(&mut gs, queues);
    let message = random_message(&mut 1, &topics);
    let data = message.data.clone();
    gs.handle_received_message(message, &peers[0]);
    assert!(matches!(
        gs.publish(topics[0].clone(), data),
        Err(PublishError::PendingValidation)
    ));
}

#[test]
fn remote_window_exhaustion_cannot_consume_one_local_publication_allowance() {
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(16)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(bounded_config(Arc::new(Mutex::new(vec![]))))
        .create_network();
    let _queues = flush_events(&mut gs, queues);
    for (sequence, peer) in (1_u64..=16).zip(&peers) {
        gs.handle_received_message(random_message(&mut sequence.clone(), &topics), peer);
        let admission_id = match gs.events.pop_front().expect("remote admission") {
            ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(matches!(
            gs.report_admitted_message_outcome(
                &admission_id,
                AdmittedMessageValidationOutcome::Reject,
            ),
            AdmittedMessageReport::Complete,
        ));
    }

    assert!(gs.publish(topics[0].clone(), vec![0xaa]).is_ok());
    assert!(matches!(
        gs.publish(topics[0].clone(), vec![0xbb]),
        Err(PublishError::ValidationAdmissionFull)
    ));
}

#[test]
fn validation_history_rejects_checked_capacity_overflow() {
    let config = ValidationAdmissionConfig {
        remote_unique_capacity_per_window: usize::MAX,
        local_unique_capacity_per_window: 1,
        ..bounded_admission_limits()
    };
    assert!(ValidationAdmissionHistory::new(config, Instant::now()).is_err());
}
