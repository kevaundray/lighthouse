use attestation_aggregation::{
    AggregateFailure, AggregateOutcome, InsertOutcome, PqAttestationAggregationCoordinator,
    PqAttestationBucket, PrepareAggregateError,
};
use consensus_signature::{
    AggregationService, OneTimeUseId, PqPublicKey, PqSameMessageEvidence, SigningDuty,
    VerificationClass,
};
use futures::executor::block_on;
use pq_signing::{PqKeyUnlock, PqKeystore, PqSigningAuthority, provision_usage_journal};
use ssz_types::{BitList, BitVector};
use state_processing::{
    DirectGenesisValidator, PqAttestationContribution, PqAttestationError, PqAttestationInvalid,
    PqAttestationLocalError, PqValidatorKeyCache, build_pq_attestation_job,
    initialize_beacon_state_from_validators, prepare_pq_attestation, verify_pq_attestation_job,
};
use std::sync::Arc;
use types::{
    Attestation, AttestationData, AttestationElectra, ChainSpec, Checkpoint, Domain, EthSpec,
    ForkName, Hash256, MinimalEthSpec, RelativeEpoch, SignedRoot, Slot,
};

const PASSWORD: &[u8] = b"correct horse battery staple";

fn electra_spec() -> ChainSpec {
    ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec())
}

fn synthetic_validator(byte: u8) -> DirectGenesisValidator {
    DirectGenesisValidator {
        public_key: PqPublicKey::deserialize(&[byte; 32]).expect("canonical test public key"),
        withdrawal_credentials: Hash256::ZERO,
    }
}

fn electra_contribution(
    data: AttestationData,
    committee_length: usize,
    committee_position: usize,
    evidence: PqSameMessageEvidence,
) -> Attestation<MinimalEthSpec> {
    let mut aggregation_bits =
        BitList::<<MinimalEthSpec as EthSpec>::MaxValidatorsPerSlot>::with_capacity(
            committee_length,
        )
        .expect("committee bitlist");
    aggregation_bits
        .set(committee_position, true)
        .expect("participant bit");
    let mut committee_bits =
        BitVector::<<MinimalEthSpec as EthSpec>::MaxCommitteesPerSlot>::default();
    committee_bits.set(0, true).expect("committee bit");
    Attestation::Electra(AttestationElectra {
        aggregation_bits,
        data,
        signature: evidence,
        committee_bits,
    })
}

#[test]
fn real_two_raw_candidates_commit_one_contextual_aggregate_and_retry_after_failure() {
    let temporary_directory = tempfile::TempDir::new().expect("temporary directory");
    let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
    let one_time_use_id =
        OneTimeUseId::for_lean_pq_devnet_v1(0, SigningDuty::Attestation).expect("V1 leaf");
    let first_keystore = PqKeystore::from_seed(
        [0xa1; 32],
        one_time_use_id.as_u32()..=one_time_use_id.as_u32(),
        PASSWORD,
    )
    .expect("first keystore");
    let second_keystore = PqKeystore::from_seed(
        [0xa2; 32],
        one_time_use_id.as_u32()..=one_time_use_id.as_u32(),
        PASSWORD,
    )
    .expect("second keystore");
    let metadata = vec![
        first_keystore.authenticate(PASSWORD).expect("first key"),
        second_keystore.authenticate(PASSWORD).expect("second key"),
    ];

    let spec = electra_spec();
    let mut state = initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16).map(synthetic_validator).collect(),
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    state
        .build_committee_cache(RelativeEpoch::Current, &spec)
        .expect("committee cache");
    let committee = state
        .get_beacon_committee(Slot::new(0), 0)
        .expect("genesis committee")
        .committee
        .to_vec();
    let participants = committee
        .get(..2)
        .expect("minimal preset committee has two participants");
    for (validator_index, authenticated) in participants.iter().zip(&metadata) {
        state
            .validators_mut()
            .get_mut(*validator_index)
            .expect("committee validator")
            .pubkey = *authenticated.public_key();
    }
    let genesis_validators_root = state.genesis_validators_root().0;
    provision_usage_journal(&journal_path, genesis_validators_root, &metadata).expect("journal");
    let authority = PqSigningAuthority::open(
        &journal_path,
        genesis_validators_root,
        vec![
            PqKeyUnlock::new(first_keystore, PASSWORD).expect("first unlock"),
            PqKeyUnlock::new(second_keystore, PASSWORD).expect("second unlock"),
        ],
    )
    .expect("authority");
    let data = AttestationData {
        slot: Slot::new(0),
        index: 0,
        beacon_block_root: Hash256::repeat_byte(0xb1),
        source: Checkpoint::default(),
        target: Checkpoint::default(),
    };
    let domain = spec.get_domain(
        data.target.epoch,
        Domain::BeaconAttester,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let signing_claim =
        consensus_signature::pq::PqSigningClaim::new(data.signing_root(domain).0, one_time_use_id);
    let signatures = authority
        .public_keys()
        .iter()
        .map(|public_key| {
            authority
                .signer(public_key)
                .expect("bound signer")
                .sign(signing_claim)
                .expect("raw signature")
        })
        .collect::<Vec<_>>();
    let mut positioned = participants
        .iter()
        .enumerate()
        .map(|(position, validator_index)| (position, *validator_index))
        .collect::<Vec<_>>();
    positioned.sort_by_key(|(_, validator_index)| *validator_index);
    let contributions = positioned
        .iter()
        .map(|(position, validator_index)| {
            let signature_position = participants
                .iter()
                .position(|candidate| candidate == validator_index)
                .expect("signature position");
            electra_contribution(
                data.clone(),
                committee.len(),
                *position,
                PqSameMessageEvidence::from(
                    signatures.get(signature_position).expect("raw signature"),
                ),
            )
        })
        .collect::<Vec<_>>();
    let signer_indices = positioned
        .iter()
        .map(|(_, validator_index)| *validator_index as u64)
        .collect::<Vec<_>>();
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let service = Arc::new(AggregationService::new().expect("PQ aggregation service"));
    let coordinator = PqAttestationAggregationCoordinator::new(Arc::clone(&service));

    for (attestation, validator_index) in contributions.iter().zip(&signer_indices) {
        let prepared = prepare_pq_attestation(
            &state,
            &key_cache,
            attestation.clone(),
            vec![*validator_index],
            &spec,
        )
        .expect("owned verification request");
        let verified = block_on(prepared.verify(&service, VerificationClass::Gossip))
            .expect("valid raw evidence");
        assert!(matches!(
            coordinator.insert_verified(verified),
            InsertOutcome::Inserted { .. }
        ));
    }
    let bucket = PqAttestationBucket {
        data: data.clone(),
        committee_index: 0,
    };

    let dropped = coordinator
        .prepare_aggregate(&bucket, &state, &key_cache, &spec)
        .expect("first in-flight snapshot");
    assert_eq!(
        coordinator
            .prepare_aggregate(&bucket, &state, &key_cache, &spec)
            .map(|_| ()),
        Err(PrepareAggregateError::AlreadyInFlight)
    );
    drop(dropped);
    let retry_after_drop = coordinator
        .prepare_aggregate(&bucket, &state, &key_cache, &spec)
        .expect("dropping PreparedAggregate clears in-flight");
    drop(retry_after_drop);

    let mut wrong_state = state.clone();
    let wrong_key = synthetic_validator(0x61).public_key;
    wrong_state
        .validators_mut()
        .get_mut(positioned[0].1)
        .expect("first participant")
        .pubkey = wrong_key;
    assert_eq!(
        coordinator
            .prepare_aggregate(&bucket, &wrong_state, &key_cache, &spec)
            .map(|_| ()),
        Err(PrepareAggregateError::InvalidLocalRequest(
            PqAttestationError::Local(PqAttestationLocalError::CacheInvariant)
        ))
    );
    let retry_after_construction_failure = coordinator
        .prepare_aggregate(&bucket, &state, &key_cache, &spec)
        .expect("job-construction failure clears in-flight");
    drop(retry_after_construction_failure);

    let wrong_cache = PqValidatorKeyCache::from_state(&wrong_state).expect("coherent wrong cache");
    let failing = coordinator
        .prepare_aggregate(&bucket, &wrong_state, &wrong_cache, &spec)
        .expect("structurally valid wrong-key snapshot");
    assert!(matches!(
        block_on(failing.execute()),
        AggregateOutcome::Failed(AggregateFailure::InvariantInvalid(
            PqAttestationInvalid::InvalidEvidence
        ))
    ));

    let prepared = coordinator
        .prepare_next_aggregate(&state, &key_cache, &spec)
        .expect("canonical background selection succeeds")
        .expect("failure preserved one exact two-raw bucket for retry");
    assert_eq!(
        coordinator
            .prepare_aggregate(&bucket, &state, &key_cache, &spec)
            .map(|_| ()),
        Err(attestation_aggregation::PrepareAggregateError::AlreadyInFlight)
    );
    let AggregateOutcome::Aggregated(aggregate) = block_on(prepared.execute()) else {
        panic!("two raw candidates should aggregate");
    };
    assert_eq!(aggregate.signer_indices(), signer_indices);
    assert_eq!(aggregate.attestation().num_set_aggregation_bits(), 2);
    assert!(
        coordinator
            .prepare_next_aggregate(&state, &key_cache, &spec)
            .expect("committed child is a valid retained candidate")
            .is_none(),
        "a retained aggregate child must never schedule recursive background work",
    );

    let singleton = coordinator
        .prepare_aggregate(&bucket, &state, &key_cache, &spec)
        .expect("installed aggregate is the only candidate");
    let AggregateOutcome::Singleton(singleton) = block_on(singleton.execute()) else {
        panic!("a singleton must bypass aggregate proving");
    };
    assert!(Arc::ptr_eq(&aggregate, &singleton));

    let child = prepare_pq_attestation(
        &state,
        &key_cache,
        aggregate.attestation().clone(),
        aggregate.signer_indices().to_vec(),
        &spec,
    )
    .expect("owned child verification request");
    let verified_child = block_on(child.verify(&service, VerificationClass::Gossip))
        .expect("contextual child verification");
    assert_eq!(
        verified_child.attestation().signature().as_bytes(),
        aggregate.attestation().signature().as_bytes()
    );

    let aggregate_request = [PqAttestationContribution::new(
        aggregate.attestation(),
        aggregate.signer_indices(),
    )];
    let mut wrong_leaf =
        build_pq_attestation_job(&state, &key_cache, &aggregate_request, &spec).expect("valid job");
    wrong_leaf.claim.one_time_use_id =
        OneTimeUseId::for_lean_pq_devnet_v1(0, SigningDuty::BeaconBlockProposal)
            .expect("proposal leaf");
    assert_eq!(
        block_on(verify_pq_attestation_job(
            &service,
            VerificationClass::Gossip,
            wrong_leaf,
        )),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidEvidence
        ))
    );

    let mut wrong_root_attestation = aggregate.attestation().clone();
    let Attestation::Electra(wrong_root_electra) = &mut wrong_root_attestation else {
        panic!("coordinator only returns Electra candidates");
    };
    wrong_root_electra.data.beacon_block_root.0[0] ^= 1;
    let wrong_root = prepare_pq_attestation(
        &state,
        &key_cache,
        wrong_root_attestation,
        aggregate.signer_indices().to_vec(),
        &spec,
    )
    .expect("structurally valid wrong root");
    assert!(matches!(
        block_on(wrong_root.verify(&service, VerificationClass::Gossip)),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidEvidence
        ))
    ));

    let mut wrong_bits = aggregate.attestation().clone();
    let Attestation::Electra(wrong_bits_electra) = &mut wrong_bits else {
        panic!("coordinator only returns Electra candidates");
    };
    wrong_bits_electra
        .aggregation_bits
        .set(positioned[1].0, false)
        .expect("clear participant bit");
    let wrong_bits = prepare_pq_attestation(
        &state,
        &key_cache,
        wrong_bits,
        vec![signer_indices[0]],
        &spec,
    )
    .expect("structurally valid wrong bits");
    assert!(matches!(
        block_on(wrong_bits.verify(&service, VerificationClass::Gossip)),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidEvidence
        ))
    ));
}
