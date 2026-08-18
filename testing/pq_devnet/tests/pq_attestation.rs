use consensus_signature::{
    AggregationService, OneTimeUseId, PqPublicKey, PqRawSignature, PqSameMessageEvidence,
    SigningDuty, V1_MAX_AGGREGATION_CONTRIBUTIONS, VerificationClass,
};
use futures::executor::block_on;
use pq_signing::{PqKeyUnlock, PqKeystore, PqSigningAuthority, provision_usage_journal};
use ssz::Encode;
use ssz_types::{BitList, BitVector};
use state_processing::{
    DirectGenesisValidator, PqAttestationCacheError, PqAttestationContribution, PqAttestationError,
    PqAttestationInvalid, PqAttestationLocalError, PqValidatorKeyCache,
    aggregate_pq_attestation_job, build_pq_attestation_job, build_pq_single_attestation_job,
    initialize_beacon_state_from_validators, verify_pq_attestation_job,
};
use types::{
    Attestation, AttestationData, AttestationElectra, BeaconState, ChainSpec, Checkpoint, Domain,
    Eth1Data, EthSpec, ForkName, Hash256, MinimalEthSpec, RelativeEpoch, SignedRoot,
    SingleAttestation, Slot,
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
fn pq_key_cache_rebuilds_deterministically_in_registry_order() {
    let spec = electra_spec();
    let state = initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        vec![synthetic_validator(7), synthetic_validator(3)],
        None,
        &spec,
    )
    .expect("direct PQ genesis");

    let first = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let second = PqValidatorKeyCache::from_state(&state).expect("deterministic rebuild");

    assert_eq!(first, second);
    assert_eq!(first.len(), 2);
    assert_eq!(first.get(0), Some(&synthetic_validator(7).public_key));
    assert_eq!(first.get(1), Some(&synthetic_validator(3).public_key));
    assert_eq!(
        first.validator_index(&synthetic_validator(7).public_key),
        Some(0)
    );
    assert_eq!(
        first.validator_index(&synthetic_validator(3).public_key),
        Some(1)
    );
    assert_eq!(first.get(2), None);
}

#[test]
fn pq_key_cache_is_not_persisted_into_state_bytes() {
    let spec = electra_spec();
    let state = initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        vec![synthetic_validator(7), synthetic_validator(3)],
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    let before = state.as_ssz_bytes();

    let _cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    assert_eq!(state.as_ssz_bytes(), before);
}

#[test]
fn pq_key_cache_rejects_an_empty_registry() {
    let spec = electra_spec();
    let state = BeaconState::<MinimalEthSpec>::new(0, Eth1Data::default(), &spec);

    assert_eq!(
        PqValidatorKeyCache::from_state(&state),
        Err(PqAttestationCacheError::EmptyRegistry)
    );
}

#[test]
fn pq_key_cache_rejects_duplicate_registry_keys() {
    let spec = electra_spec();
    let mut state = initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        vec![synthetic_validator(7), synthetic_validator(3)],
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    let duplicate = state.validators().get(0).expect("first validator").pubkey;
    state
        .validators_mut()
        .get_mut(1)
        .expect("second validator")
        .pubkey = duplicate;

    assert_eq!(
        PqValidatorKeyCache::from_state(&state),
        Err(PqAttestationCacheError::DuplicatePublicKey {
            first: 0,
            duplicate: 1,
        })
    );
}

#[test]
fn pq_key_cache_rejects_a_registry_beyond_the_v1_cap() {
    let spec = electra_spec();
    let validators = (1..=17).map(synthetic_validator).collect();
    let state = initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        validators,
        None,
        &spec,
    )
    .expect("direct PQ genesis");

    assert_eq!(
        PqValidatorKeyCache::from_state(&state),
        Err(PqAttestationCacheError::TooManyValidators {
            actual: 17,
            max: 16,
        })
    );
}

#[test]
fn single_request_derives_the_attester_claim_and_slot_leaf() {
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
        .expect("genesis committee");
    let attester_index = u64::try_from(*committee.committee.first().expect("non-empty committee"))
        .expect("validator index fits u64");
    let data = AttestationData {
        slot: Slot::new(0),
        index: 0,
        beacon_block_root: Hash256::repeat_byte(0x42),
        source: Checkpoint::default(),
        target: Checkpoint::default(),
    };
    let single = SingleAttestation {
        committee_index: 0,
        attester_index,
        data: data.clone(),
        signature: PqSameMessageEvidence::from(&PqRawSignature::empty()),
    };
    let cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    let job = build_pq_single_attestation_job(&state, &cache, &single, &spec)
        .expect("valid single request");
    let domain = spec.get_domain(
        data.target.epoch,
        Domain::BeaconAttester,
        &state.fork(),
        state.genesis_validators_root(),
    );

    assert_eq!(job.claim.signing_root, data.signing_root(domain).0);
    assert_eq!(
        job.claim.one_time_use_id,
        OneTimeUseId::for_lean_pq_devnet_v1(data.slot.as_u64(), SigningDuty::Attestation)
            .expect("genesis slot has a V1 leaf")
    );
    assert_eq!(job.expected_signers.len(), 1);
    assert_eq!(job.expected_signers[0].validator_index, attester_index);
    assert_eq!(job.contributions.len(), 1);
    assert_eq!(job.contributions[0].evidence, single.signature);
}

#[test]
fn aggregate_request_derives_strict_signers_from_electra_bits() {
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
        .expect("genesis committee");
    let mut participants = committee
        .committee
        .iter()
        .enumerate()
        .map(|(position, validator_index)| (position, *validator_index))
        .collect::<Vec<_>>();
    participants.sort_by_key(|(_, validator_index)| *validator_index);
    let participants = participants
        .get(..2)
        .expect("minimal preset committee has two participants");
    let data = AttestationData {
        slot: Slot::new(0),
        index: 0,
        beacon_block_root: Hash256::repeat_byte(0x51),
        source: Checkpoint::default(),
        target: Checkpoint::default(),
    };
    let mut contributions = Vec::new();
    for (position, _) in participants {
        contributions.push(electra_contribution(
            data.clone(),
            committee.committee.len(),
            *position,
            PqSameMessageEvidence::from(&PqRawSignature::empty()),
        ));
    }
    let cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let claimed_indices = participants
        .iter()
        .map(|(_, validator_index)| vec![*validator_index as u64])
        .collect::<Vec<_>>();
    let requests = contributions
        .iter()
        .zip(&claimed_indices)
        .map(|(attestation, indices)| PqAttestationContribution::new(attestation, indices))
        .collect::<Vec<_>>();

    let job = build_pq_attestation_job(&state, &cache, &requests, &spec)
        .expect("valid aggregate request");

    assert_eq!(
        job.expected_signers
            .iter()
            .map(|signer| signer.validator_index)
            .collect::<Vec<_>>(),
        participants
            .iter()
            .map(|(_, validator_index)| *validator_index as u64)
            .collect::<Vec<_>>()
    );
    assert_eq!(job.contributions.len(), 2);
}

#[test]
fn aggregate_request_rejects_nonzero_electra_data_index() {
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
        .expect("genesis committee");
    let (committee_position, validator_index) = committee
        .committee
        .iter()
        .enumerate()
        .next()
        .expect("non-empty committee");
    let attestation = electra_contribution(
        AttestationData {
            slot: Slot::new(0),
            index: 1,
            beacon_block_root: Hash256::repeat_byte(0x52),
            source: Checkpoint::default(),
            target: Checkpoint::default(),
        },
        committee.committee.len(),
        committee_position,
        PqSameMessageEvidence::from(&PqRawSignature::empty()),
    );
    let claimed_indices = [*validator_index as u64];
    let request = [PqAttestationContribution::new(
        &attestation,
        &claimed_indices,
    )];
    let cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    assert_eq!(
        build_pq_attestation_job(&state, &cache, &request, &spec).map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidCommittee,
        ))
    );
}

#[test]
fn aggregate_request_rejects_claimed_signers_that_differ_from_participant_bits() {
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
        .expect("genesis committee");
    let participants = committee
        .committee
        .iter()
        .enumerate()
        .take(2)
        .collect::<Vec<_>>();
    let [(bit_position, bit_validator), (_, different_validator)] = participants.as_slice() else {
        panic!("minimal preset committee has two participants");
    };
    assert_ne!(bit_validator, different_validator);
    let attestation = electra_contribution(
        AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: Hash256::repeat_byte(0x53),
            source: Checkpoint::default(),
            target: Checkpoint::default(),
        },
        committee.committee.len(),
        *bit_position,
        PqSameMessageEvidence::from(&PqRawSignature::empty()),
    );
    let claimed_indices = [**different_validator as u64];
    let request = [PqAttestationContribution::new(
        &attestation,
        &claimed_indices,
    )];
    let cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    assert_eq!(
        build_pq_attestation_job(&state, &cache, &request, &spec).map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidBitfield,
        ))
    );
}

#[test]
fn aggregate_request_rejects_cross_contribution_signer_overlap() {
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
        .expect("genesis committee");
    let (committee_position, validator_index) = committee
        .committee
        .iter()
        .enumerate()
        .next()
        .expect("non-empty committee");
    let attestation = electra_contribution(
        AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: Hash256::repeat_byte(0x54),
            source: Checkpoint::default(),
            target: Checkpoint::default(),
        },
        committee.committee.len(),
        committee_position,
        PqSameMessageEvidence::from(&PqRawSignature::empty()),
    );
    let claimed_indices = [*validator_index as u64];
    let requests = [
        PqAttestationContribution::new(&attestation, &claimed_indices),
        PqAttestationContribution::new(&attestation, &claimed_indices),
    ];
    let cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    assert_eq!(
        build_pq_attestation_job(&state, &cache, &requests, &spec).map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::DuplicateSignerIndex(*validator_index as u64),
        ))
    );
}

#[test]
fn aggregate_request_rejects_too_many_contributions_before_signer_iteration() {
    let spec = electra_spec();
    let state = initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16).map(synthetic_validator).collect(),
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    let attestation = electra_contribution(
        AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: Hash256::repeat_byte(0x55),
            source: Checkpoint::default(),
            target: Checkpoint::default(),
        },
        1,
        0,
        PqSameMessageEvidence::from(&PqRawSignature::empty()),
    );
    let request = PqAttestationContribution::new(&attestation, &[]);
    let requests = vec![request; V1_MAX_AGGREGATION_CONTRIBUTIONS + 1];
    let cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    assert_eq!(
        build_pq_attestation_job(&state, &cache, &requests, &spec).map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::TooManyContributions {
                actual: V1_MAX_AGGREGATION_CONTRIBUTIONS + 1,
                max: V1_MAX_AGGREGATION_CONTRIBUTIONS,
            },
        ))
    );
}

#[test]
fn structural_attestation_failures_are_rejected_before_service_submission() {
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
        .expect("genesis committee");
    let committee_indices = committee.committee.to_vec();
    let mut participants = committee_indices
        .iter()
        .enumerate()
        .map(|(position, validator_index)| (position, *validator_index))
        .collect::<Vec<_>>();
    participants.sort_by_key(|(_, validator_index)| *validator_index);
    let participants = participants
        .get(..2)
        .expect("minimal preset committee has two participants");
    let data = AttestationData {
        slot: Slot::new(0),
        index: 0,
        beacon_block_root: Hash256::repeat_byte(0xa1),
        source: Checkpoint::default(),
        target: Checkpoint::default(),
    };
    let raw = PqSameMessageEvidence::from(&PqRawSignature::empty());
    let first = electra_contribution(
        data.clone(),
        committee_indices.len(),
        participants[0].0,
        raw.clone(),
    );
    let cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    let unordered_indices = [participants[1].1 as u64, participants[0].1 as u64];
    let unordered = [PqAttestationContribution::new(&first, &unordered_indices)];
    assert_eq!(
        build_pq_attestation_job(&state, &cache, &unordered, &spec).map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::NonCanonicalSignerOrder,
        ))
    );
    let duplicate_indices = [participants[0].1 as u64, participants[0].1 as u64];
    let duplicate = [PqAttestationContribution::new(&first, &duplicate_indices)];
    assert_eq!(
        build_pq_attestation_job(&state, &cache, &duplicate, &spec).map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::DuplicateSignerIndex(participants[0].1 as u64),
        ))
    );
    let out_of_range_indices = [u64::MAX];
    let out_of_range = [PqAttestationContribution::new(
        &first,
        &out_of_range_indices,
    )];
    assert_eq!(
        build_pq_attestation_job(&state, &cache, &out_of_range, &spec).map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidAttesterIndex(u64::MAX),
        ))
    );
    let too_many_indices = (0..=16).collect::<Vec<_>>();
    let too_many = [PqAttestationContribution::new(&first, &too_many_indices)];
    assert_eq!(
        build_pq_attestation_job(&state, &cache, &too_many, &spec).map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::TooManySigners {
                actual: 17,
                max: 16,
            },
        ))
    );
    let no_indices = [PqAttestationContribution::new(&first, &[])];
    assert_eq!(
        build_pq_attestation_job(&state, &cache, &no_indices, &spec).map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::EmptySignerSet,
        ))
    );

    assert_eq!(
        build_pq_attestation_job(&state, &cache, &[], &spec).map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::EmptySignerSet,
        ))
    );
    let invalid_bits = electra_contribution(
        data.clone(),
        committee_indices.len().saturating_add(1),
        participants[0].0,
        raw.clone(),
    );
    assert_eq!(
        build_pq_attestation_job(
            &state,
            &cache,
            &[PqAttestationContribution::new(
                &invalid_bits,
                &[participants[0].1 as u64],
            )],
            &spec,
        )
        .map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidBitfield,
        ))
    );

    let invalid_index = SingleAttestation {
        committee_index: 0,
        attester_index: u64::MAX,
        data: data.clone(),
        signature: raw.clone(),
    };
    assert_eq!(
        build_pq_single_attestation_job(&state, &cache, &invalid_index, &spec).map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidAttesterIndex(u64::MAX),
        ))
    );

    let outsider = (0..state.validators().len())
        .find(|validator_index| !committee_indices.contains(validator_index))
        .expect("validator outside slot-zero committee");
    let wrong_member = SingleAttestation {
        committee_index: 0,
        attester_index: outsider as u64,
        data: data.clone(),
        signature: raw.clone(),
    };
    assert_eq!(
        build_pq_single_attestation_job(&state, &cache, &wrong_member, &spec).map(|_| ()),
        Err(PqAttestationError::Invalid(
            PqAttestationInvalid::AttesterNotInCommittee(outsider as u64),
        ))
    );

    let mut future_fork_spec = spec.clone();
    future_fork_spec.fulu_fork_epoch = Some(types::Epoch::new(10));
    let valid_single = SingleAttestation {
        committee_index: 0,
        attester_index: participants[0].1 as u64,
        data,
        signature: raw,
    };
    assert_eq!(
        build_pq_single_attestation_job(&state, &cache, &valid_single, &future_fork_spec)
            .map(|_| ()),
        Err(PqAttestationError::Local(
            PqAttestationLocalError::UnsupportedProfile,
        ))
    );
}

#[test]
fn invalid_single_evidence_is_classified_as_peer_invalid() {
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
        .expect("genesis committee");
    let attester_index = *committee.committee.first().expect("non-empty committee") as u64;
    let single = SingleAttestation {
        committee_index: 0,
        attester_index,
        data: AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: Hash256::repeat_byte(0x73),
            source: Checkpoint::default(),
            target: Checkpoint::default(),
        },
        signature: PqSameMessageEvidence::from(&PqRawSignature::empty()),
    };
    let cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let job = build_pq_single_attestation_job(&state, &cache, &single, &spec)
        .expect("structurally valid request");
    let service = AggregationService::new().expect("PQ aggregation service");

    assert_eq!(
        block_on(verify_pq_attestation_job(
            &service,
            VerificationClass::Gossip,
            job,
        )),
        Err(state_processing::PqAttestationError::Invalid(
            state_processing::PqAttestationInvalid::InvalidEvidence,
        ))
    );
}

#[test]
fn valid_raw_and_two_signer_evidence_are_verified_against_bits_and_cache_keys() {
    let temporary_directory = tempfile::TempDir::new().expect("temporary directory");
    let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
    let one_time_use_id =
        OneTimeUseId::for_lean_pq_devnet_v1(0, SigningDuty::Attestation).expect("V1 leaf");
    let first_keystore = PqKeystore::from_seed(
        [0x81; 32],
        one_time_use_id.as_u32()..=one_time_use_id.as_u32(),
        PASSWORD,
    )
    .expect("first keystore");
    let second_keystore = PqKeystore::from_seed(
        [0x82; 32],
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
    let committee_indices = state
        .get_beacon_committee(Slot::new(0), 0)
        .expect("genesis committee")
        .committee
        .to_vec();
    let committee_indices = committee_indices
        .get(..2)
        .expect("minimal preset committee has two participants");
    for (validator_index, authenticated) in committee_indices.iter().zip(&metadata) {
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
        beacon_block_root: Hash256::repeat_byte(0x91),
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
    let mut participants = committee_indices
        .iter()
        .enumerate()
        .map(|(position, validator_index)| (position, *validator_index))
        .collect::<Vec<_>>();
    participants.sort_by_key(|(_, validator_index)| *validator_index);
    let contributions = participants
        .iter()
        .map(|(position, validator_index)| {
            let signature_position = committee_indices
                .iter()
                .position(|candidate| candidate == validator_index)
                .expect("signature position");
            electra_contribution(
                data.clone(),
                committee_indices.len(),
                *position,
                PqSameMessageEvidence::from(
                    signatures.get(signature_position).expect("raw signature"),
                ),
            )
        })
        .collect::<Vec<_>>();
    let claimed_indices = participants
        .iter()
        .map(|(_, validator_index)| vec![*validator_index as u64])
        .collect::<Vec<_>>();
    let requests = contributions
        .iter()
        .zip(&claimed_indices)
        .map(|(attestation, indices)| PqAttestationContribution::new(attestation, indices))
        .collect::<Vec<_>>();
    let cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let service = AggregationService::new().expect("PQ aggregation service");

    let single_job = build_pq_attestation_job(&state, &cache, &requests[..1], &spec)
        .expect("single raw contribution");
    let single_bytes = single_job.contributions[0].evidence.as_bytes().to_vec();
    let promoted = block_on(verify_pq_attestation_job(
        &service,
        VerificationClass::Gossip,
        single_job,
    ))
    .expect("valid raw evidence");
    assert_eq!(promoted.as_bytes(), single_bytes);

    let aggregate_job =
        build_pq_attestation_job(&state, &cache, &requests, &spec).expect("two contribution job");
    let aggregate = block_on(aggregate_pq_attestation_job(&service, aggregate_job))
        .expect("valid two-signer evidence");
    assert_ne!(
        aggregate.as_bytes(),
        contributions[0].signature().as_bytes()
    );

    let mut combined = contributions[0].clone();
    let Attestation::Electra(combined_electra) = &mut combined else {
        unreachable!("test helper always constructs Electra attestations");
    };
    combined_electra
        .aggregation_bits
        .set(participants[1].0, true)
        .expect("second participant bit");
    combined_electra.signature = aggregate.clone();
    let combined_indices = [participants[0].1 as u64, participants[1].1 as u64];
    let child_request = [PqAttestationContribution::new(&combined, &combined_indices)];
    let child_job = build_pq_attestation_job(&state, &cache, &child_request, &spec)
        .expect("two-signer child evidence job");
    let child_bytes = child_job.contributions[0].evidence.as_bytes().to_vec();
    let verified_child = block_on(verify_pq_attestation_job(
        &service,
        VerificationClass::Gossip,
        child_job,
    ))
    .expect("two-signer recursive evidence verifies");
    assert_eq!(verified_child.as_bytes(), child_bytes);

    let single_with_recursive_proof = SingleAttestation {
        committee_index: 0,
        attester_index: participants[0].1 as u64,
        data: data.clone(),
        signature: aggregate.clone(),
    };
    assert_eq!(
        build_pq_single_attestation_job(&state, &cache, &single_with_recursive_proof, &spec,)
            .map(|_| ()),
        Err(state_processing::PqAttestationError::Invalid(
            state_processing::PqAttestationInvalid::NonIndividualSingleEvidence,
        ))
    );

    let mut wrong_root =
        build_pq_attestation_job(&state, &cache, &requests[..1], &spec).expect("job");
    wrong_root.claim.signing_root[0] ^= 1;
    assert_eq!(
        block_on(verify_pq_attestation_job(
            &service,
            VerificationClass::Gossip,
            wrong_root,
        )),
        Err(state_processing::PqAttestationError::Invalid(
            state_processing::PqAttestationInvalid::InvalidEvidence,
        ))
    );

    let mut wrong_leaf =
        build_pq_attestation_job(&state, &cache, &requests[..1], &spec).expect("job");
    wrong_leaf.claim.one_time_use_id =
        OneTimeUseId::for_lean_pq_devnet_v1(0, SigningDuty::BeaconBlockProposal)
            .expect("proposal leaf");
    assert_eq!(
        block_on(verify_pq_attestation_job(
            &service,
            VerificationClass::Gossip,
            wrong_leaf,
        )),
        Err(state_processing::PqAttestationError::Invalid(
            state_processing::PqAttestationInvalid::InvalidEvidence,
        ))
    );

    let mut wrong_key =
        build_pq_attestation_job(&state, &cache, &requests[..1], &spec).expect("job");
    let wrong_public_key = synthetic_validator(0x61).public_key;
    wrong_key.expected_signers[0].public_key = wrong_public_key;
    wrong_key.contributions[0].signers[0].public_key = wrong_public_key;
    assert_eq!(
        block_on(verify_pq_attestation_job(
            &service,
            VerificationClass::Gossip,
            wrong_key,
        )),
        Err(state_processing::PqAttestationError::Invalid(
            state_processing::PqAttestationInvalid::InvalidEvidence,
        ))
    );

    let mut wrong_bits = combined;
    if let Attestation::Electra(electra) = &mut wrong_bits {
        electra
            .aggregation_bits
            .set(participants[1].0, false)
            .expect("clear second participant bit");
    }
    let wrong_bits_indices = [participants[0].1 as u64];
    let wrong_bits_request = [PqAttestationContribution::new(
        &wrong_bits,
        &wrong_bits_indices,
    )];
    let wrong_bits_job = build_pq_attestation_job(&state, &cache, &wrong_bits_request, &spec)
        .expect("structurally valid wrong-bits job");
    assert_eq!(
        block_on(verify_pq_attestation_job(
            &service,
            VerificationClass::Gossip,
            wrong_bits_job,
        )),
        Err(state_processing::PqAttestationError::Invalid(
            state_processing::PqAttestationInvalid::InvalidEvidence,
        ))
    );
}
