use futures::StreamExt;
use initialized_validators::InitializedValidators;
use lighthouse_validator_store::{Config, LighthouseValidatorStore};
use pq_devnet::{ProvisionConfig, provision_devnet};
use slashing_protection::{Safe, SlashingDatabase};
use slot_clock::{SlotClock, TestingSlotClock};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;
use task_executor::test_utils::TestRuntime;
use tempfile::tempdir;
use types::{
    Attestation, AttestationData, BeaconBlock, BlindedPayload, ChainSpec, Checkpoint, Domain,
    EthSpec, ForkName, Hash256, MinimalEthSpec, Slot,
};
use validator_store::{AttestationToSign, UnsignedBlock, ValidatorStore};

fn signed_attestation_count(status: &str) -> u64 {
    validator_metrics::get_int_counter(
        &validator_metrics::SIGNED_ATTESTATIONS_TOTAL,
        &[status],
    )
    .expect("signed attestation metric")
    .get()
}

fn signed_block_count(status: &str) -> u64 {
    validator_metrics::get_int_counter(&validator_metrics::SIGNED_BLOCKS_TOTAL, &[status])
        .expect("signed block metric")
        .get()
}

fn attestation(spec: &ChainSpec, slot: Slot, block_root: Hash256) -> Attestation<MinimalEthSpec> {
    let target_epoch = slot.epoch(MinimalEthSpec::slots_per_epoch());
    Attestation::empty_for_signing(
        0,
        1,
        slot,
        block_root,
        Checkpoint {
            epoch: target_epoch.saturating_sub(1_u64),
            root: Hash256::ZERO,
        },
        Checkpoint {
            epoch: target_epoch,
            root: Hash256::ZERO,
        },
        false,
        spec,
    )
    .expect("attestation")
}

#[tokio::test(flavor = "multi_thread")]
async fn slashing_commit_precedes_pq_reservation_and_same_data_is_recoverable() {
    let root = tempdir().expect("root");
    let seed_path = root.path().join("seed");
    let password_path = root.path().join("password");
    fs::write(&seed_path, [42; 32]).expect("seed");
    fs::write(&password_path, b"deterministic test password").expect("password");
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).expect("seed mode");
    fs::set_permissions(&password_path, fs::Permissions::from_mode(0o600)).expect("password mode");
    let destination = root.path().join("devnet");
    let provisioned = provision_devnet(
        ProvisionConfig::for_test(destination.clone(), 1, 0..=125, 42),
        &seed_path,
        &password_path,
    )
    .expect("devnet");
    let public_key = provisioned.public_keys()[0];
    let runtime = TestRuntime::default();
    let initialized = InitializedValidators::from_pq_bundle(
        destination.clone(),
        provisioned.genesis_validators_root(),
        runtime.task_executor.clone(),
    )
    .await
    .expect("initialized validators");
    let slashing_path = destination.join("slashing_protection.sqlite");
    let slashing = SlashingDatabase::create(&slashing_path).expect("fresh slashing DB");
    slashing
        .register_validator(public_key)
        .expect("register validator");
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));
    let slot_zero_data = AttestationData {
        slot: Slot::new(0),
        beacon_block_root: Hash256::repeat_byte(0x11),
        target: Checkpoint::default(),
        ..AttestationData::default()
    };
    let domain = spec.get_domain(
        slot_zero_data.target.epoch,
        Domain::BeaconAttester,
        &spec.fork_at_epoch(slot_zero_data.target.epoch),
        Hash256::from(provisioned.genesis_validators_root()),
    );
    assert_eq!(
        slashing.with_transaction(|txn| {
            slashing.check_and_insert_attestation(&public_key, &slot_zero_data, domain, txn)
        }),
        Ok(Safe::Valid)
    );
    let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(12));
    let store = Arc::new(LighthouseValidatorStore::new(
        initialized,
        slashing,
        Hash256::from(provisioned.genesis_validators_root()),
        spec.clone(),
        None,
        clock,
        &Config::default(),
        runtime.task_executor.clone(),
    ));

    // Simulates cancellation after the ordinary slashing DB commit: Safe::SameData must still
    // reach the deterministic PQ authority.
    let successes_before_recovery = signed_attestation_count(validator_metrics::SUCCESS);
    let same_data_before_recovery = signed_attestation_count(validator_metrics::SAME_DATA);
    let recovered = {
        let recovered_stream = store.sign_attestations(vec![AttestationToSign {
            validator_index: 0,
            pubkey: public_key,
            validator_committee_index: 0,
            attestation: attestation(&spec, Slot::new(0), Hash256::repeat_byte(0x11)),
        }]);
        futures::pin_mut!(recovered_stream);
        recovered_stream
            .next()
            .await
            .expect("batch")
            .expect("recovered signature")
    };
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        signed_attestation_count(validator_metrics::SUCCESS),
        successes_before_recovery,
        "a successful same-data retry must not be classified as a fresh success"
    );
    assert_eq!(
        signed_attestation_count(validator_metrics::SAME_DATA),
        same_data_before_recovery + 1,
        "same-data is recorded only after signature attachment"
    );

    let successes_before_mixed = signed_attestation_count(validator_metrics::SUCCESS);
    let same_data_before_mixed = signed_attestation_count(validator_metrics::SAME_DATA);
    let mixed = {
        let mixed_stream = store.sign_attestations(vec![
            AttestationToSign {
                validator_index: 0,
                pubkey: public_key,
                validator_committee_index: 0,
                attestation: attestation(&spec, Slot::new(8), Hash256::repeat_byte(0x22)),
            },
            AttestationToSign {
                validator_index: 0,
                pubkey: public_key,
                validator_committee_index: 0,
                attestation: attestation(&spec, Slot::new(16), Hash256::repeat_byte(0x44)),
            },
        ]);
        futures::pin_mut!(mixed_stream);
        mixed_stream
            .next()
            .await
            .expect("batch")
            .expect("successful sibling must survive signer failure")
    };
    assert_eq!(mixed.len(), 1);
    assert_eq!(
        signed_attestation_count(validator_metrics::SUCCESS),
        successes_before_mixed + 1
    );
    assert_eq!(
        signed_attestation_count(validator_metrics::SAME_DATA),
        same_data_before_mixed
    );

    let successes_before_concurrent = signed_attestation_count(validator_metrics::SUCCESS);
    let same_data_before_concurrent = signed_attestation_count(validator_metrics::SAME_DATA);
    let concurrent = {
        let concurrent_stream = store.sign_attestations(vec![
            AttestationToSign {
                validator_index: 0,
                pubkey: public_key,
                validator_committee_index: 0,
                attestation: attestation(&spec, Slot::new(8), Hash256::repeat_byte(0x22)),
            },
            AttestationToSign {
                validator_index: 0,
                pubkey: public_key,
                validator_committee_index: 0,
                attestation: attestation(&spec, Slot::new(8), Hash256::repeat_byte(0x22)),
            },
            AttestationToSign {
                validator_index: 0,
                pubkey: public_key,
                validator_committee_index: 0,
                attestation: attestation(&spec, Slot::new(8), Hash256::repeat_byte(0x33)),
            },
        ]);
        futures::pin_mut!(concurrent_stream);
        concurrent_stream
            .next()
            .await
            .expect("batch")
            .expect("safe signatures")
    };
    assert_eq!(concurrent.len(), 2);
    assert_eq!(
        concurrent[0].1.signature().as_bytes(),
        concurrent[1].1.signature().as_bytes()
    );
    assert_eq!(
        signed_attestation_count(validator_metrics::SUCCESS),
        successes_before_concurrent,
        "same-data siblings are not fresh successful signatures"
    );
    assert_eq!(
        signed_attestation_count(validator_metrics::SAME_DATA),
        same_data_before_concurrent + 2,
        "both attached retries are classified as same-data"
    );

    // Slot 16 maps to leaf 226, beyond the provisioned 0..=125 range. Slashing protection
    // accepts and commits this new data, but the stateful signer cannot produce a signature.
    // Therefore it must not be reported as a successful attestation signature.
    let successes_before_failure = signed_attestation_count(validator_metrics::SUCCESS);
    let out_of_range = {
        let out_of_range_stream = store.sign_attestations(vec![AttestationToSign {
            validator_index: 0,
            pubkey: public_key,
            validator_committee_index: 0,
            attestation: attestation(&spec, Slot::new(16), Hash256::repeat_byte(0x44)),
        }]);
        futures::pin_mut!(out_of_range_stream);
        out_of_range_stream
            .next()
            .await
            .expect("batch")
            .expect("failed member is dropped")
    };
    assert!(out_of_range.is_empty(), "out-of-range member must be dropped");
    assert_eq!(
        signed_attestation_count(validator_metrics::SUCCESS),
        successes_before_failure,
        "slashing precheck alone must not increment signing success"
    );

    let mut block =
        BeaconBlock::<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>::empty(&spec);
    *block.slot_mut() = Slot::new(16);
    let retry_block = block.clone();
    let block_success_before = signed_block_count(validator_metrics::SUCCESS);
    let block_same_data_before = signed_block_count(validator_metrics::SAME_DATA);
    assert!(
        store
            .sign_block(
                public_key,
                UnsignedBlock::Blinded(block),
                Slot::new(16)
            )
            .await
            .is_err(),
        "out-of-range Safe::Valid block signing must fail"
    );
    assert_eq!(
        signed_block_count(validator_metrics::SUCCESS),
        block_success_before,
        "Safe::Valid is successful only after block construction"
    );
    assert_eq!(
        signed_block_count(validator_metrics::SAME_DATA),
        block_same_data_before
    );
    assert!(
        store
            .sign_block(
                public_key,
                UnsignedBlock::Blinded(retry_block),
                Slot::new(16)
            )
            .await
            .is_err(),
        "out-of-range Safe::SameData block signing must fail"
    );
    assert_eq!(
        signed_block_count(validator_metrics::SUCCESS),
        block_success_before
    );
    assert_eq!(
        signed_block_count(validator_metrics::SAME_DATA),
        block_same_data_before,
        "Safe::SameData is recorded only after block construction"
    );

    drop(store);
    let connection =
        rusqlite::Connection::open(destination.join("xmss_usage.sqlite")).expect("journal query");
    let reservations: i64 = connection
        .query_row("SELECT COUNT(*) FROM reservations", [], |row| row.get(0))
        .expect("reservation count");
    assert_eq!(
        reservations, 2,
        "unsafe conflicting data must not burn a leaf"
    );
}
