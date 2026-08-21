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
        remote_unique_capacity_per_window: 96,
        remote_unique_capacity_per_peer_per_window: 6,
        local_unique_capacity_per_window: 6,
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
fn local_unique_history_accepts_six_and_rejects_seventh() {
    let config = bounded_admission_limits();
    let start = Instant::now();
    let mut history = ValidationAdmissionHistory::new(config, start)
        .expect("valid bounded history configuration");

    for byte in 0_u8..6 {
        assert_eq!(
            history.reserve_local(&MessageId(vec![byte]), start),
            ValidationReservation::New,
            "local retained ID {byte} must fit the frozen two-slot bucket",
        );
    }
    assert_eq!(
        history.reserve_local(&MessageId(vec![6]), start),
        ValidationReservation::Full,
    );
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
fn one_peer_retains_six_sequential_ids_after_each_pending_admission_resolves() {
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(bounded_config(Arc::new(Mutex::new(vec![]))))
        .create_network();
    let _queues = flush_events(&mut gs, queues);

    for sequence in 0_u64..6 {
        gs.handle_received_message(random_message(&mut sequence.clone(), &topics), &peers[0]);
        let admission_id = match gs.events.pop_front().expect("admission below peer cap") {
            ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(matches!(
            gs.report_admitted_message_outcome(
                &admission_id,
                AdmittedMessageValidationOutcome::TerminalIgnore,
            ),
            AdmittedMessageReport::Complete,
        ));
    }

    let mut seventh = 6_u64;
    gs.handle_received_message(random_message(&mut seventh, &topics), &peers[0]);
    assert!(
        gs.events.is_empty(),
        "the seventh retained ID from one peer must be suppressed",
    );
}

#[test]
fn retryable_release_decrements_the_retained_per_peer_count() {
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(bounded_config(Arc::new(Mutex::new(vec![]))))
        .create_network();
    let _queues = flush_events(&mut gs, queues);
    let mut seed = 0_u64;

    for _ in 0..5 {
        gs.handle_received_message(random_message(&mut seed, &topics), &peers[0]);
        let admission_id = match gs.events.pop_front().expect("terminal retained admission") {
            ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(matches!(
            gs.report_admitted_message_outcome(
                &admission_id,
                AdmittedMessageValidationOutcome::TerminalIgnore,
            ),
            AdmittedMessageReport::Complete,
        ));
    }

    gs.handle_received_message(random_message(&mut seed, &topics), &peers[0]);
    let retryable_id = match gs.events.pop_front().expect("retryable admission") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };
    assert!(matches!(
        gs.report_admitted_message_outcome(
            &retryable_id,
            AdmittedMessageValidationOutcome::RetryableIgnore,
        ),
        AdmittedMessageReport::Complete,
    ));

    gs.handle_received_message(random_message(&mut seed, &topics), &peers[0]);
    let replacement = match gs
        .events
        .pop_front()
        .expect("replacement after retryable release")
    {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };
    assert!(matches!(
        gs.report_admitted_message_outcome(
            &replacement,
            AdmittedMessageValidationOutcome::TerminalIgnore,
        ),
        AdmittedMessageReport::Complete,
    ));

    gs.handle_received_message(random_message(&mut seed, &topics), &peers[0]);
    assert!(
        gs.events.is_empty(),
        "replacement must restore the peer cap"
    );
}

#[test]
fn remote_unique_history_accepts_ninety_six_globally_and_rejects_ninety_seventh() {
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(17)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(bounded_config(Arc::new(Mutex::new(vec![]))))
        .create_network();
    let _queues = flush_events(&mut gs, queues);
    let mut seed = 0_u64;

    for peer in &peers[..16] {
        for _ in 0..6 {
            gs.handle_received_message(random_message(&mut seed, &topics), peer);
            let admission_id = match gs.events.pop_front().expect("admission below global cap") {
                ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
                other => panic!("unexpected event: {other:?}"),
            };
            assert!(matches!(
                gs.report_admitted_message_outcome(
                    &admission_id,
                    AdmittedMessageValidationOutcome::TerminalIgnore,
                ),
                AdmittedMessageReport::Complete,
            ));
        }
    }

    disconnect_peer(&mut gs, &peers[0]);
    gs.handle_received_message(random_message(&mut seed, &topics), &peers[16]);
    assert!(
        gs.events.is_empty(),
        "the ninety-seventh global retained ID must be suppressed",
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
fn exact_retained_inventory_is_one_thousand_seven_hundred_thirty_four() {
    let config = bounded_admission_limits();
    let start = Instant::now();
    let mut history = ValidationAdmissionHistory::new(config, start)
        .expect("valid bounded history configuration");
    let peers = (0..16).map(|_| PeerId::random()).collect::<Vec<_>>();

    for window in 0_u8..17 {
        let now = start + config.window * u32::from(window);
        for (peer_index, peer) in peers.iter().enumerate() {
            for message_index in 0_u8..6 {
                let id = MessageId(vec![
                    0,
                    window,
                    u8::try_from(peer_index).expect("sixteen peers fit u8"),
                    message_index,
                ]);
                assert_eq!(
                    history.reserve_remote(&id, peer, now),
                    ValidationReservation::New,
                );
            }
        }
        for message_index in 0_u8..6 {
            assert_eq!(
                history.reserve_local(&MessageId(vec![1, window, message_index]), now),
                ValidationReservation::New,
            );
        }
    }
    assert_eq!(history.retained_len(), 1_734);

    let rollover_window = 17_u8;
    let rollover = start + config.window * u32::from(rollover_window);
    for (peer_index, peer) in peers.iter().enumerate() {
        for message_index in 0_u8..6 {
            let id = MessageId(vec![
                0,
                rollover_window,
                u8::try_from(peer_index).expect("sixteen peers fit u8"),
                message_index,
            ]);
            assert_eq!(
                history.reserve_remote(&id, peer, rollover),
                ValidationReservation::New,
            );
        }
    }
    for message_index in 0_u8..6 {
        assert_eq!(
            history.reserve_local(
                &MessageId(vec![1, rollover_window, message_index]),
                rollover,
            ),
            ValidationReservation::New,
        );
    }
    assert_eq!(history.retained_len(), 1_734);
}

#[test]
fn exact_id_expires_at_retained_window_n_not_n_plus_one() {
    let config = bounded_admission_limits();
    let start = Instant::now();
    let mut history = ValidationAdmissionHistory::new(config, start)
        .expect("valid bounded history configuration");
    let id = MessageId(vec![0x51]);

    assert_eq!(
        history.reserve_local(&id, start),
        ValidationReservation::New,
    );
    assert_eq!(
        history.reserve_local(&id, start + config.window * 16),
        ValidationReservation::Duplicate,
        "the ID remains retained in the final of seventeen windows",
    );
    assert_eq!(
        history.reserve_local(&id, start + config.window * 17),
        ValidationReservation::New,
        "the ID expires exactly at N, not N+1",
    );
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
                remote_unique_capacity_per_peer_per_window: 1,
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
        .message_id_fn(|message| MessageId(message.data.clone()))
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

    let mut seed = 1_u64;
    for _ in 0..5 {
        gs.handle_received_message(random_message(&mut seed, &topics), &peers[0]);
        let retained_id = match gs.events.pop_front().expect("retained admission") {
            ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(matches!(
            gs.report_admitted_message_outcome(
                &retained_id,
                AdmittedMessageValidationOutcome::TerminalIgnore,
            ),
            AdmittedMessageReport::Complete,
        ));
    }
    assert_eq!(*drops.lock().expect("drop count lock"), 5);

    let original = random_message(&mut seed, &topics);
    let admitted_before = Instant::now();
    gs.handle_received_message(original.clone(), &peers[0]);
    let admitted_after = Instant::now();
    let admission_id = match gs.events.pop_front().expect("admitted message") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };
    let expiry = gs
        .pending_admissions
        .get(&admission_id)
        .expect("pending admission")
        .expires;
    assert!(
        expiry >= admitted_before + Duration::from_secs(300)
            && expiry <= admitted_after + Duration::from_secs(300),
        "pending expiry retains the exact frozen 300-second bound",
    );
    gs.expire_validation_admissions(expiry);
    assert_eq!(*drops.lock().expect("drop count lock"), 6);
    assert!(!gs.pending_admissions.contains_key(&admission_id));

    gs.handle_received_message(original, &peers[0]);
    let readmitted_id = match gs.events.pop_front().expect("exact expired ID readmission") {
        ToSwarm::GenerateEvent(Event::AdmittedMessage { admission_id, .. }) => admission_id,
        other => panic!("unexpected event: {other:?}"),
    };
    assert_eq!(readmitted_id, admission_id);
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
fn remote_window_exhaustion_cannot_consume_six_local_publication_allowances() {
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(16)
        .topics(vec!["blocks".into()])
        .to_subscribe(true)
        .gs_config(bounded_config(Arc::new(Mutex::new(vec![]))))
        .create_network();
    let _queues = flush_events(&mut gs, queues);
    let mut sequence = 1_u64;
    for peer in &peers {
        for _ in 0..6 {
            gs.handle_received_message(random_message(&mut sequence, &topics), peer);
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
    }

    for byte in 0_u8..6 {
        assert!(gs.publish(topics[0].clone(), vec![0xaa, byte]).is_ok());
    }
    assert!(matches!(
        gs.publish(topics[0].clone(), vec![0xbb, 6]),
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

#[test]
fn validation_history_rejects_invalid_per_peer_retained_capacity() {
    let zero = ValidationAdmissionConfig {
        remote_unique_capacity_per_peer_per_window: 0,
        ..bounded_admission_limits()
    };
    assert_eq!(
        ValidationAdmissionHistory::new(zero, Instant::now()).err(),
        Some("validation admission bounds must be non-zero"),
    );

    let above_global = ValidationAdmissionConfig {
        remote_unique_capacity_per_window: 5,
        remote_unique_capacity_per_peer_per_window: 6,
        ..bounded_admission_limits()
    };
    assert_eq!(
        ValidationAdmissionHistory::new(above_global, Instant::now()).err(),
        Some("per-peer remote validation history exceeds global remote capacity"),
    );
}
