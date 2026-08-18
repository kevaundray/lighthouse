use consensus_signature::{
    AggregationError, AggregationResource, InvalidAggregationJob, PqPublicKey, PqRawSignature,
    PqSameMessageEvidence, PqWireError, SigningIdError,
};
#[cfg(target_feature = "avx2")]
use consensus_signature::{AggregationService, OneTimeUseId, SigningDuty};
#[cfg(target_feature = "avx2")]
use futures::executor::block_on;
#[cfg(target_feature = "avx2")]
use pq_signing::{PqKeyUnlock, PqKeystore, PqSigningAuthority, provision_usage_journal};
use state_processing::{
    DirectGenesisValidator, PqAttestationLocalError, PqConsensusError, PqConsensusInvalid,
    PqConsensusLocalError, PqValidatorKeyCache, PreparedPqAggregateAndProof, PreparedPqBlock,
    PreparedPqBlockProposal, classify_pq_consensus_aggregation_error,
    initialize_beacon_state_from_validators, prepare_pq_aggregate_and_proof,
    prepare_pq_aggregate_and_proof_with_evidence_work_count, prepare_pq_block,
    prepare_pq_block_proposal, prepare_pq_block_with_evidence_work_count,
};
#[cfg(target_feature = "avx2")]
use state_processing::{
    PqAttestationContribution, PqTransitionError, aggregate_pq_attestation_job,
    build_pq_attestation_job, per_block_processing_pq, per_slot_processing_pq,
};
#[cfg(target_feature = "avx2")]
use std::collections::BTreeMap;
use std::sync::Arc;
use std::{error::Error as _, fmt::Debug};
#[cfg(target_feature = "avx2")]
use types::consts::altair::{PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR};
use types::{
    AggregateAndProof, Attestation, AttestationBase, AttestationData, BeaconBlock, ChainSpec,
    Checkpoint, EthSpec, ForkName, Hash256, MinimalEthSpec, RelativeEpoch, SelectionProof,
    SignedAggregateAndProof, SignedBeaconBlock, Slot,
};
#[cfg(target_feature = "avx2")]
use types::{Domain, SignedRoot};

#[cfg(target_feature = "avx2")]
const PASSWORD: &[u8] = b"correct horse battery staple";

fn assert_send<T: Send>(_: &T) {}

fn electra_spec() -> ChainSpec {
    ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec())
}

fn synthetic_validator(byte: u8) -> DirectGenesisValidator {
    DirectGenesisValidator {
        public_key: PqPublicKey::deserialize(&[byte; 32]).expect("canonical test public key"),
        withdrawal_credentials: Hash256::ZERO,
    }
}

fn electra_attestation(
    data: AttestationData,
    committee_length: usize,
    participant_positions: &[usize],
    evidence: PqSameMessageEvidence,
) -> Attestation<MinimalEthSpec> {
    let mut aggregation_bits = ssz_types::BitList::<
        <MinimalEthSpec as EthSpec>::MaxValidatorsPerSlot,
    >::with_capacity(committee_length)
    .expect("committee bitlist");
    for position in participant_positions {
        aggregation_bits
            .set(*position, true)
            .expect("participant bit");
    }
    let mut committee_bits =
        ssz_types::BitVector::<<MinimalEthSpec as EthSpec>::MaxCommitteesPerSlot>::default();
    committee_bits.set(0, true).expect("committee bit");
    Attestation::Electra(types::AttestationElectra {
        aggregation_bits,
        data,
        signature: evidence,
        committee_bits,
    })
}

#[test]
fn prepared_block_proposal_is_owned_and_send() {
    let spec = electra_spec();
    let state = initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16).map(synthetic_validator).collect(),
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let proposer_index = state
        .get_beacon_proposer_index(types::Slot::new(0), &spec)
        .expect("genesis proposer") as u64;
    let mut block = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(electra) = &mut block else {
        unreachable!("Electra genesis spec constructs an Electra block");
    };
    electra.proposer_index = proposer_index;
    let signed_block = Arc::new(SignedBeaconBlock::from_block(
        block,
        PqRawSignature::empty(),
    ));

    let prepared: PreparedPqBlockProposal<MinimalEthSpec> =
        prepare_pq_block_proposal(&state, &key_cache, Arc::clone(&signed_block), &spec)
            .expect("structurally valid proposal");

    assert_send(&prepared);
    drop(state);
    drop(key_cache);
    assert_eq!(prepared.block(), &signed_block);
}

#[test]
fn proposal_outside_the_state_current_epoch_is_peer_invalid() {
    let spec = electra_spec();
    let state = initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16).map(synthetic_validator).collect(),
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let mut block = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(electra) = &mut block else {
        unreachable!("Electra genesis spec constructs an Electra block");
    };
    electra.slot = Slot::new(MinimalEthSpec::slots_per_epoch());
    let signed_block = Arc::new(SignedBeaconBlock::from_block(
        block,
        PqRawSignature::empty(),
    ));

    assert_eq!(
        prepare_pq_block_proposal(&state, &key_cache, signed_block, &spec).map(|_| ()),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::ProposalSlotOutOfCurrentEpoch {
                proposal: 1,
                current: 0,
            }
        ))
    );
}

#[test]
fn full_block_and_aggregate_requests_are_owned_and_send() {
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
    let aggregator_index = *committee.committee.first().expect("non-empty committee") as u64;
    let mut attestation = Attestation::empty_for_signing(
        0,
        committee.committee.len(),
        Slot::new(0),
        Hash256::repeat_byte(0x31),
        types::Checkpoint::default(),
        types::Checkpoint::default(),
        true,
        &spec,
    )
    .expect("Electra attestation");
    attestation
        .attach_individual_signature(&PqRawSignature::empty(), 0)
        .expect("one participant");
    let message = AggregateAndProof::from_attestation(
        aggregator_index,
        attestation,
        SelectionProof::from(PqRawSignature::empty()),
    );
    let signed_aggregate =
        SignedAggregateAndProof::from_aggregate_and_proof(message, PqRawSignature::empty());
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    let prepared_aggregate: PreparedPqAggregateAndProof<MinimalEthSpec> =
        prepare_pq_aggregate_and_proof(&state, &key_cache, signed_aggregate, &spec)
            .expect("structurally valid aggregate");
    assert_send(&prepared_aggregate);

    let proposer_index = state
        .get_beacon_proposer_index(Slot::new(0), &spec)
        .expect("genesis proposer") as u64;
    let mut block = types::BeaconBlock::empty(&spec);
    let types::BeaconBlock::Electra(electra) = &mut block else {
        unreachable!("Electra genesis spec constructs an Electra block");
    };
    electra.proposer_index = proposer_index;
    let signed_block = Arc::new(SignedBeaconBlock::from_block(
        block,
        PqRawSignature::empty(),
    ));
    let prepared_block: PreparedPqBlock<MinimalEthSpec> =
        prepare_pq_block(&state, &key_cache, Arc::clone(&signed_block), &spec)
            .expect("structurally valid block");
    assert_send(&prepared_block);

    drop(state);
    drop(key_cache);
    assert_eq!(
        prepared_aggregate.aggregate().message().aggregator_index(),
        aggregator_index
    );
    assert_eq!(prepared_block.block(), &signed_block);
}

#[test]
fn aggregate_preparation_rejects_an_unselected_aggregator_before_backend_work() {
    let mut spec = electra_spec();
    spec.target_aggregators_per_committee = 1;
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
    let aggregator_index = *committee.committee.first().expect("non-empty committee") as u64;
    let mut attestation = Attestation::empty_for_signing(
        0,
        committee.committee.len(),
        Slot::new(0),
        Hash256::repeat_byte(0x41),
        types::Checkpoint::default(),
        types::Checkpoint::default(),
        true,
        &spec,
    )
    .expect("Electra attestation");
    attestation
        .attach_individual_signature(&PqRawSignature::empty(), 0)
        .expect("one participant");
    let selection_signature = (0u16..=u16::MAX)
        .find_map(|counter| {
            let mut bytes = PqRawSignature::empty().serialize();
            let counter_bytes = counter.to_le_bytes();
            let last = bytes.len().checked_sub(2)?;
            bytes.get_mut(last..)?.copy_from_slice(&counter_bytes);
            let signature = PqRawSignature::from_bytes(&bytes).ok()?;
            let selected = SelectionProof::from(signature.clone())
                .is_aggregator(committee.committee.len(), &spec)
                .ok()?;
            (!selected).then_some(signature)
        })
        .expect("a non-selected structural proof exists");
    let message = AggregateAndProof::from_attestation(
        aggregator_index,
        attestation,
        SelectionProof::from(selection_signature),
    );
    let signed =
        SignedAggregateAndProof::from_aggregate_and_proof(message, PqRawSignature::empty());
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let mut evidence_work = 0;

    assert_eq!(
        prepare_pq_aggregate_and_proof_with_evidence_work_count(
            &state,
            &key_cache,
            signed,
            &spec,
            &mut evidence_work,
        )
        .map(|_| ()),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::AggregatorNotSelected(aggregator_index),
        ))
    );
    assert_eq!(evidence_work, 1);
}

#[test]
fn aggregate_preparation_rejects_the_base_shape_before_backend_work() {
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
    let aggregator_index = *state
        .get_beacon_committee(Slot::new(0), 0)
        .expect("genesis committee")
        .committee
        .first()
        .expect("non-empty committee") as u64;
    let base = Attestation::Base(AttestationBase {
        aggregation_bits: ssz_types::BitList::with_capacity(1).expect("one bit"),
        data: AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: Hash256::repeat_byte(0x51),
            source: Checkpoint::default(),
            target: Checkpoint::default(),
        },
        signature: PqSameMessageEvidence::from(&PqRawSignature::empty()),
    });
    let message = AggregateAndProof::from_attestation(
        aggregator_index,
        base,
        SelectionProof::from(PqRawSignature::empty()),
    );
    let signed =
        SignedAggregateAndProof::from_aggregate_and_proof(message, PqRawSignature::empty());
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    assert_eq!(
        prepare_pq_aggregate_and_proof(&state, &key_cache, signed, &spec).map(|_| ()),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::BaseAggregateAndProof,
        ))
    );
}

#[test]
fn aggregate_preparation_rejects_a_target_epoch_mismatched_with_the_data_slot() {
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
    let aggregator_index = *committee.committee.first().expect("non-empty committee") as u64;
    let mut attestation = Attestation::empty_for_signing(
        0,
        committee.committee.len(),
        Slot::new(0),
        Hash256::repeat_byte(0x61),
        Checkpoint::default(),
        Checkpoint {
            epoch: types::Epoch::new(1),
            root: Hash256::ZERO,
        },
        true,
        &spec,
    )
    .expect("Electra attestation");
    attestation
        .attach_individual_signature(&PqRawSignature::empty(), 0)
        .expect("one participant");
    let message = AggregateAndProof::from_attestation(
        aggregator_index,
        attestation,
        SelectionProof::from(PqRawSignature::empty()),
    );
    let signed =
        SignedAggregateAndProof::from_aggregate_and_proof(message, PqRawSignature::empty());
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    assert_eq!(
        prepare_pq_aggregate_and_proof(&state, &key_cache, signed, &spec).map(|_| ()),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::InvalidAttestation {
                component: state_processing::PqConsensusComponent::AggregateAttestation,
                error: state_processing::PqAttestationInvalid::InvalidTargetEpoch,
            },
        ))
    );
}

#[test]
fn whole_object_preflight_does_no_evidence_work_when_the_final_input_is_malformed() {
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
    let proposer_index = state
        .get_beacon_proposer_index(Slot::new(0), &spec)
        .expect("genesis proposer") as u64;
    let aggregator_index = *committee.committee.first().expect("non-empty committee") as u64;
    let valid_data = AttestationData {
        slot: Slot::new(0),
        index: 0,
        beacon_block_root: Hash256::repeat_byte(0x69),
        source: Checkpoint::default(),
        target: Checkpoint::default(),
    };
    let valid = electra_attestation(
        valid_data.clone(),
        committee.committee.len(),
        &[0],
        PqSameMessageEvidence::from(&PqRawSignature::empty()),
    );
    let mut invalid_data = valid_data;
    invalid_data.target.epoch = types::Epoch::new(1);
    let invalid = electra_attestation(
        invalid_data,
        committee.committee.len(),
        &[0],
        PqSameMessageEvidence::from(&PqRawSignature::empty()),
    );
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    let mut block = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(electra) = &mut block else {
        unreachable!("Electra genesis spec constructs an Electra block");
    };
    electra.proposer_index = proposer_index;
    for attestation in [valid, invalid.clone()] {
        let Attestation::Electra(attestation) = attestation else {
            unreachable!("helper constructs Electra attestations");
        };
        electra
            .body
            .attestations
            .push(attestation)
            .expect("bounded block attestations");
    }
    let signed_block = Arc::new(SignedBeaconBlock::from_block(
        block,
        PqRawSignature::empty(),
    ));
    let mut block_evidence_work = 0;
    assert_eq!(
        prepare_pq_block_with_evidence_work_count(
            &state,
            &key_cache,
            signed_block,
            &spec,
            &mut block_evidence_work,
        )
        .map(|_| ()),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::InvalidAttestation {
                component: state_processing::PqConsensusComponent::BlockAttestation(1),
                error: state_processing::PqAttestationInvalid::InvalidTargetEpoch,
            }
        ))
    );
    assert_eq!(block_evidence_work, 0);

    let message = AggregateAndProof::from_attestation(
        aggregator_index,
        invalid,
        SelectionProof::from(PqRawSignature::empty()),
    );
    let signed_aggregate =
        SignedAggregateAndProof::from_aggregate_and_proof(message, PqRawSignature::empty());
    let mut aggregate_evidence_work = 0;
    assert_eq!(
        prepare_pq_aggregate_and_proof_with_evidence_work_count(
            &state,
            &key_cache,
            signed_aggregate,
            &spec,
            &mut aggregate_evidence_work,
        )
        .map(|_| ()),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::InvalidAttestation {
                component: state_processing::PqConsensusComponent::AggregateAttestation,
                error: state_processing::PqAttestationInvalid::InvalidTargetEpoch,
            }
        ))
    );
    assert_eq!(aggregate_evidence_work, 0);
}

#[test]
fn aggregate_preparation_classifies_an_invalid_committee_as_peer_invalid() {
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
    let aggregator_index = *committee.committee.first().expect("non-empty committee") as u64;
    let mut attestation = electra_attestation(
        AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: Hash256::repeat_byte(0x71),
            source: Checkpoint::default(),
            target: Checkpoint::default(),
        },
        committee.committee.len(),
        &[0],
        PqSameMessageEvidence::from(&PqRawSignature::empty()),
    );
    let Attestation::Electra(electra) = &mut attestation else {
        unreachable!("helper constructs Electra attestations");
    };
    electra
        .committee_bits
        .set(0, false)
        .expect("clear committee");
    electra
        .committee_bits
        .set(1, true)
        .expect("invalid committee");
    let message = AggregateAndProof::from_attestation(
        aggregator_index,
        attestation,
        SelectionProof::from(PqRawSignature::empty()),
    );
    let signed =
        SignedAggregateAndProof::from_aggregate_and_proof(message, PqRawSignature::empty());
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    assert_eq!(
        prepare_pq_aggregate_and_proof(&state, &key_cache, signed, &spec).map(|_| ()),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::InvalidAttestation {
                component: state_processing::PqConsensusComponent::AggregateAttestation,
                error: state_processing::PqAttestationInvalid::InvalidCommittee,
            },
        ))
    );
}

#[test]
fn malformed_and_oversized_evidence_is_rejected_at_the_wire_boundary() {
    let raw = PqRawSignature::empty().serialize();
    assert!(matches!(
        PqRawSignature::from_bytes(&raw[..raw.len().saturating_sub(1)]),
        Err(PqWireError::InvalidLength { .. })
    ));
    assert!(matches!(
        PqSameMessageEvidence::from_bytes(b"LHPQ"),
        Err(PqWireError::InvalidLength { .. })
    ));
    let oversized = vec![0; consensus_signature::PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN + 1];
    assert_eq!(
        PqSameMessageEvidence::from_bytes(&oversized),
        Err(PqWireError::EvidenceTooLarge {
            actual: oversized.len(),
            max: consensus_signature::PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN,
        })
    );
}

#[test]
fn aggregation_failures_map_to_peer_invalid_or_their_exact_local_class() {
    let component = state_processing::PqConsensusComponent::BlockProposal;
    assert_eq!(
        classify_pq_consensus_aggregation_error(AggregationError::InvalidEvidence, component),
        PqConsensusError::Invalid(PqConsensusInvalid::InvalidEvidence(component))
    );

    for local in [
        AggregationError::InvalidJob(InvalidAggregationJob::EmptySignerSet),
        AggregationError::ResourceExhausted(AggregationResource::QueueSaturated { max_queued: 2 }),
        AggregationError::Unavailable,
        AggregationError::WorkerStopped,
        AggregationError::WorkerPanicked,
        AggregationError::OutputTooLarge { actual: 3, max: 2 },
        AggregationError::Internal,
    ] {
        assert_eq!(
            classify_pq_consensus_aggregation_error(local, component),
            PqConsensusError::Local(state_processing::PqConsensusLocalError::Aggregation(local))
        );
    }
}

#[test]
fn consensus_error_sources_expose_only_nested_local_causes() {
    fn assert_source<T>(error: &PqConsensusError, expected: T)
    where
        T: std::error::Error + PartialEq + Debug + 'static,
    {
        assert_eq!(
            error.source().and_then(|source| source.downcast_ref()),
            Some(&expected)
        );
    }

    let direct_signing = SigningIdError::SlotOutOfRange(u64::MAX);
    assert_source(
        &PqConsensusError::Local(PqConsensusLocalError::SigningId(direct_signing)),
        direct_signing,
    );
    let direct_aggregation = AggregationError::Unavailable;
    assert_source(
        &PqConsensusError::Local(PqConsensusLocalError::Aggregation(direct_aggregation)),
        direct_aggregation,
    );
    let attestation_signing = SigningIdError::UnsupportedSyncSubcommittee(4);
    assert_source(
        &PqConsensusError::Local(PqConsensusLocalError::Attestation(
            PqAttestationLocalError::SigningId(attestation_signing),
        )),
        attestation_signing,
    );
    let attestation_aggregation = AggregationError::WorkerStopped;
    assert_source(
        &PqConsensusError::Local(PqConsensusLocalError::Attestation(
            PqAttestationLocalError::Aggregation(attestation_aggregation),
        )),
        attestation_aggregation,
    );

    for terminal in [
        PqConsensusError::Invalid(PqConsensusInvalid::InvalidEvidence(
            state_processing::PqConsensusComponent::BlockProposal,
        )),
        PqConsensusError::Local(PqConsensusLocalError::UnsupportedProfile),
        PqConsensusError::Local(PqConsensusLocalError::StateUnavailable),
        PqConsensusError::Local(PqConsensusLocalError::CacheInvariant),
        PqConsensusError::Local(PqConsensusLocalError::Attestation(
            PqAttestationLocalError::UnsupportedProfile,
        )),
        PqConsensusError::Local(PqConsensusLocalError::Attestation(
            PqAttestationLocalError::CommitteeCacheUnavailable,
        )),
        PqConsensusError::Local(PqConsensusLocalError::Attestation(
            PqAttestationLocalError::CacheInvariant,
        )),
    ] {
        assert!(
            terminal.source().is_none(),
            "unexpected source for {terminal:?}"
        );
    }
}

#[cfg(not(target_feature = "avx2"))]
#[test]
fn structural_failure_precedes_an_unavailable_backend() {
    let spec = electra_spec();
    let state = initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16).map(synthetic_validator).collect(),
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let mut block = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(electra) = &mut block else {
        unreachable!("Electra genesis spec constructs an Electra block");
    };
    electra.proposer_index = u64::MAX;
    let signed = Arc::new(SignedBeaconBlock::from_block(
        block,
        PqRawSignature::empty(),
    ));

    assert!(matches!(
        consensus_signature::AggregationService::new(),
        Err(AggregationError::Unavailable)
    ));
    assert!(matches!(
        prepare_pq_block_proposal(&state, &key_cache, signed, &spec),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::IncorrectBlockProposer { .. }
        ))
    ));
}

#[cfg(target_feature = "avx2")]
#[test]
fn journal_backed_consensus_requests_verify_and_fail_in_component_order() {
    let temporary_directory = tempfile::TempDir::new().expect("temporary directory");
    let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
    let spec = electra_spec().set_slot_duration_ms::<MinimalEthSpec>(17_000);
    assert_eq!(spec.get_slot_duration().as_secs(), 17);
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
        .expect("minimal preset committee has two participants")
        .to_vec();
    let proposer_zero = state
        .get_beacon_proposer_index(Slot::new(0), &spec)
        .expect("slot-zero proposer");
    let proposer_one = state
        .get_beacon_proposer_index(Slot::new(1), &spec)
        .expect("slot-one proposer");
    let proposer_two = state
        .get_beacon_proposer_index(Slot::new(2), &spec)
        .expect("slot-two proposer");
    let proposer_three = state
        .get_beacon_proposer_index(Slot::new(3), &spec)
        .expect("slot-three proposer");
    let proposer_four = state
        .get_beacon_proposer_index(Slot::new(4), &spec)
        .expect("slot-four proposer");
    let proposer_five = state
        .get_beacon_proposer_index(Slot::new(5), &spec)
        .expect("slot-five proposer");
    let committee_three = state
        .get_beacon_committee(Slot::new(3), 0)
        .expect("slot-three committee")
        .committee
        .to_vec();
    let attester_three = *committee_three
        .first()
        .expect("nonempty slot-three committee");
    let mut required_indices = participants.clone();
    required_indices.extend([
        proposer_zero,
        proposer_one,
        proposer_two,
        proposer_three,
        proposer_four,
        proposer_five,
        attester_three,
    ]);
    required_indices.sort_unstable();
    required_indices.dedup();

    let maximum_leaf = OneTimeUseId::for_lean_pq_devnet_v1(
        Slot::new(5).as_u64(),
        SigningDuty::BeaconBlockProposal,
    )
    .expect("slot-five proposal leaf")
    .as_u32();
    let mut metadata = Vec::new();
    let mut unlocks = Vec::new();
    for (ordinal, validator_index) in required_indices.iter().copied().enumerate() {
        let seed_byte = u8::try_from(ordinal)
            .ok()
            .and_then(|value| value.checked_add(0xc0))
            .expect("bounded fixture seed");
        let keystore = PqKeystore::from_seed([seed_byte; 32], 0..=maximum_leaf, PASSWORD)
            .expect("fixture keystore");
        let authenticated = keystore.authenticate(PASSWORD).expect("authenticated key");
        state
            .validators_mut()
            .get_mut(validator_index)
            .expect("required validator")
            .pubkey = *authenticated.public_key();
        metadata.push(authenticated);
        unlocks.push(PqKeyUnlock::new(keystore, PASSWORD).expect("unlocked key"));
    }
    let genesis_validators_root = state.genesis_validators_root().0;
    provision_usage_journal(&journal_path, genesis_validators_root, &metadata).expect("journal");
    let authority = PqSigningAuthority::open(&journal_path, genesis_validators_root, unlocks)
        .expect("signing authority");
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let service = AggregationService::new().expect("PQ aggregation service");
    let sign = |validator_index: usize, slot: Slot, duty: SigningDuty, signing_root: [u8; 32]| {
        let one_time_use_id =
            OneTimeUseId::for_lean_pq_devnet_v1(slot.as_u64(), duty).expect("V1 leaf");
        let public_key = state
            .validators()
            .get(validator_index)
            .expect("signing validator")
            .pubkey;
        authority
            .signer(&public_key)
            .expect("bound signer")
            .sign(consensus_signature::pq::PqSigningClaim::new(
                signing_root,
                one_time_use_id,
            ))
            .expect("journal-backed signature")
    };

    let attestation_data = AttestationData {
        slot: Slot::new(0),
        index: 0,
        beacon_block_root: Hash256::repeat_byte(0x91),
        source: Checkpoint::default(),
        target: Checkpoint::default(),
    };
    let attester_domain = spec.get_domain(
        attestation_data.target.epoch,
        Domain::BeaconAttester,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let attestation_root = attestation_data.signing_root(attester_domain).0;
    let raw_signatures = participants
        .iter()
        .map(|validator_index| {
            sign(
                *validator_index,
                Slot::new(0),
                SigningDuty::Attestation,
                attestation_root,
            )
        })
        .collect::<Vec<_>>();
    let raw_attestations = raw_signatures
        .iter()
        .enumerate()
        .map(|(position, signature)| {
            electra_attestation(
                attestation_data.clone(),
                committee.len(),
                &[position],
                PqSameMessageEvidence::from(signature),
            )
        })
        .collect::<Vec<_>>();
    let signer_indices = participants
        .iter()
        .map(|validator_index| vec![*validator_index as u64])
        .collect::<Vec<_>>();
    let contributions = raw_attestations
        .iter()
        .zip(&signer_indices)
        .map(|(attestation, indices)| PqAttestationContribution::new(attestation, indices))
        .collect::<Vec<_>>();
    let aggregate_job = build_pq_attestation_job(&state, &key_cache, &contributions, &spec)
        .expect("two raw contributions");
    let recursive_evidence = block_on(aggregate_pq_attestation_job(&service, aggregate_job))
        .expect("recursive evidence");
    let recursive_attestation = electra_attestation(
        attestation_data.clone(),
        committee.len(),
        &[0, 1],
        recursive_evidence,
    );

    let mut block = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(electra) = &mut block else {
        unreachable!("Electra genesis spec constructs an Electra block");
    };
    electra.proposer_index = proposer_zero as u64;
    let randao_domain = spec.get_domain(
        types::Epoch::new(0),
        Domain::Randao,
        &state.fork(),
        state.genesis_validators_root(),
    );
    electra.body.randao_reveal = sign(
        proposer_zero,
        Slot::new(0),
        SigningDuty::RandaoReveal,
        types::Epoch::new(0).signing_root(randao_domain).0,
    );
    let Attestation::Electra(raw_block_attestation) =
        raw_attestations.first().expect("raw attestation").clone()
    else {
        unreachable!("fixture creates Electra attestations");
    };
    electra
        .body
        .attestations
        .push(raw_block_attestation)
        .expect("one block attestation");
    let proposal_domain = spec.get_domain(
        types::Epoch::new(0),
        Domain::BeaconProposer,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let proposal_root = block.signing_root(proposal_domain).0;
    let proposal_signature = sign(
        proposer_zero,
        Slot::new(0),
        SigningDuty::BeaconBlockProposal,
        proposal_root,
    );
    let signed_block = Arc::new(SignedBeaconBlock::from_block(block, proposal_signature));

    let verified_proposal = block_on(
        prepare_pq_block_proposal(&state, &key_cache, Arc::clone(&signed_block), &spec)
            .expect("prepared proposal")
            .verify(&service),
    )
    .expect("valid proposal");
    assert!(Arc::ptr_eq(verified_proposal.block(), &signed_block));
    let verified_block = block_on(
        prepare_pq_block(&state, &key_cache, Arc::clone(&signed_block), &spec)
            .expect("prepared block")
            .verify(&service),
    )
    .expect("valid proposal, RANDAO, and raw attestation");
    assert!(Arc::ptr_eq(verified_block.block(), &signed_block));

    let aggregator_index = participants[0];
    let selection_domain = spec.get_domain(
        types::Epoch::new(0),
        Domain::SelectionProof,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let selection_root = Slot::new(0).signing_root(selection_domain).0;
    let selection_signature = sign(
        aggregator_index,
        Slot::new(0),
        SigningDuty::AttestationSelectionProof,
        selection_root,
    );
    let aggregate_message = AggregateAndProof::from_attestation(
        aggregator_index as u64,
        recursive_attestation.clone(),
        SelectionProof::from(selection_signature),
    );
    let outer_domain = spec.get_domain(
        types::Epoch::new(0),
        Domain::AggregateAndProof,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let outer_root = aggregate_message.signing_root(outer_domain).0;
    let outer_signature = sign(
        aggregator_index,
        Slot::new(0),
        SigningDuty::AggregateAndProof,
        outer_root,
    );
    let signed_aggregate =
        SignedAggregateAndProof::from_aggregate_and_proof(aggregate_message, outer_signature);
    let verified_aggregate = block_on(
        prepare_pq_aggregate_and_proof(&state, &key_cache, signed_aggregate.clone(), &spec)
            .expect("prepared aggregate-and-proof")
            .verify(&service),
    )
    .expect("valid selection, recursive aggregate, and outer signature");
    assert_eq!(verified_aggregate.aggregate().as_ref(), &signed_aggregate);
    assert_eq!(
        verified_aggregate.inner_attestation().signer_indices(),
        &[participants[0] as u64, participants[1] as u64]
    );
    assert_eq!(
        verified_aggregate.inner_attestation().attestation(),
        &recursive_attestation
    );

    let mut wrong_root = signed_block.as_ref().clone();
    let SignedBeaconBlock::Electra(wrong_root_electra) = &mut wrong_root else {
        unreachable!("fixture block is Electra");
    };
    wrong_root_electra.message.parent_root.0[0] ^= 1;
    assert_eq!(
        block_on(
            prepare_pq_block_proposal(&state, &key_cache, Arc::new(wrong_root), &spec)
                .expect("structurally valid wrong-root proposal")
                .verify(&service),
        )
        .map(|_| ()),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::InvalidEvidence(
                state_processing::PqConsensusComponent::BlockProposal,
            ),
        ))
    );

    let alternate_index = required_indices
        .iter()
        .copied()
        .find(|index| *index != proposer_zero && *index != aggregator_index)
        .expect("alternate validator");
    let wrong_key_signature = sign(
        alternate_index,
        Slot::new(0),
        SigningDuty::BeaconBlockProposal,
        proposal_root,
    );
    let (wrong_key_block, _) = signed_block.as_ref().clone().deconstruct();
    let wrong_key_block = Arc::new(SignedBeaconBlock::from_block(
        wrong_key_block,
        wrong_key_signature,
    ));
    assert_eq!(
        block_on(
            prepare_pq_block_proposal(&state, &key_cache, wrong_key_block, &spec)
                .expect("structurally valid wrong-key proposal")
                .verify(&service),
        )
        .map(|_| ()),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::InvalidEvidence(
                state_processing::PqConsensusComponent::BlockProposal,
            ),
        ))
    );

    let mut wrong_leaf_block = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(wrong_leaf_electra) = &mut wrong_leaf_block else {
        unreachable!("fixture block is Electra");
    };
    wrong_leaf_electra.slot = Slot::new(2);
    wrong_leaf_electra.proposer_index = proposer_two as u64;
    let wrong_leaf_root = wrong_leaf_block.signing_root(proposal_domain).0;
    let wrong_leaf_signature = sign(
        proposer_two,
        Slot::new(2),
        SigningDuty::RandaoReveal,
        wrong_leaf_root,
    );
    assert_eq!(
        block_on(
            prepare_pq_block_proposal(
                &state,
                &key_cache,
                Arc::new(SignedBeaconBlock::from_block(
                    wrong_leaf_block,
                    wrong_leaf_signature,
                )),
                &spec,
            )
            .expect("structurally valid wrong-leaf proposal")
            .verify(&service),
        )
        .map(|_| ()),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::InvalidEvidence(
                state_processing::PqConsensusComponent::BlockProposal,
            ),
        ))
    );

    let mut mixed_block = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(mixed_electra) = &mut mixed_block else {
        unreachable!("fixture block is Electra");
    };
    mixed_electra.slot = Slot::new(1);
    mixed_electra.proposer_index = proposer_one as u64;
    mixed_electra.body.randao_reveal = PqRawSignature::empty();
    let mixed_root = mixed_block.signing_root(proposal_domain).0;
    let mixed_proposal = sign(
        proposer_one,
        Slot::new(1),
        SigningDuty::BeaconBlockProposal,
        mixed_root,
    );
    let mut slot_one_state = state.clone();
    per_slot_processing_pq(&mut slot_one_state, &spec).expect("advance to slot one");
    let mixed_result = block_on(
        prepare_pq_block(
            &slot_one_state,
            &key_cache,
            Arc::new(SignedBeaconBlock::from_block(
                mixed_block.clone(),
                mixed_proposal,
            )),
            &spec,
        )
        .expect("all mixed block jobs are prepared before verification")
        .verify(&service),
    );
    assert_eq!(
        mixed_result.map(|_| ()),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::InvalidEvidence(
                state_processing::PqConsensusComponent::RandaoReveal,
            ),
        ))
    );
    let both_invalid_block = block_on(
        prepare_pq_block(
            &slot_one_state,
            &key_cache,
            Arc::new(SignedBeaconBlock::from_block(
                mixed_block,
                PqRawSignature::empty(),
            )),
            &spec,
        )
        .expect("both invalid block jobs are prepared before verification")
        .verify(&service),
    );
    assert_eq!(
        both_invalid_block.map(|_| ()),
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::InvalidEvidence(
                state_processing::PqConsensusComponent::BlockProposal,
            ),
        ))
    );

    let mut slot_three_state = state.clone();
    for _ in 0..3 {
        per_slot_processing_pq(&mut slot_three_state, &spec).expect("advance to slot three");
    }
    let mut wrong_parent_block: BeaconBlock<MinimalEthSpec> = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(wrong_parent_electra) = &mut wrong_parent_block else {
        unreachable!("Electra genesis spec constructs an Electra block");
    };
    wrong_parent_electra.slot = Slot::new(3);
    wrong_parent_electra.proposer_index = proposer_three as u64;
    wrong_parent_electra.parent_root = Hash256::repeat_byte(0x73);
    wrong_parent_electra
        .body
        .execution_payload
        .execution_payload
        .timestamp = spec
        .get_slot_duration()
        .as_secs()
        .checked_mul(3)
        .and_then(|slot_offset| slot_three_state.genesis_time().checked_add(slot_offset))
        .expect("fixture timestamp");
    wrong_parent_electra
        .body
        .execution_payload
        .execution_payload
        .prev_randao = *slot_three_state
        .get_randao_mix(types::Epoch::new(0))
        .expect("current randao mix");
    let transition_randao_root = types::Epoch::new(0).signing_root(randao_domain).0;
    wrong_parent_electra.body.randao_reveal = sign(
        proposer_three,
        Slot::new(3),
        SigningDuty::RandaoReveal,
        transition_randao_root,
    );
    let wrong_parent_root = wrong_parent_block.signing_root(proposal_domain).0;
    let wrong_parent_proposal = sign(
        proposer_three,
        Slot::new(3),
        SigningDuty::BeaconBlockProposal,
        wrong_parent_root,
    );
    let wrong_parent_block = Arc::new(SignedBeaconBlock::from_block(
        wrong_parent_block,
        wrong_parent_proposal,
    ));
    let mismatch_token = block_on(
        prepare_pq_block(
            &slot_three_state,
            &key_cache,
            Arc::clone(&wrong_parent_block),
            &spec,
        )
        .expect("prepared state-bound block")
        .verify(&service),
    )
    .expect("valid PQ signatures");
    let mut changed_same_slot_state = slot_three_state.clone();
    changed_same_slot_state
        .update_randao_mix(types::Epoch::new(0), &PqRawSignature::empty())
        .expect("change claim-critical RANDAO context");
    let changed_state_before = changed_same_slot_state.clone();
    assert!(matches!(
        per_block_processing_pq(&mut changed_same_slot_state, mismatch_token),
        Err(PqTransitionError::PreStateMismatch { .. })
    ));
    assert_eq!(changed_same_slot_state, changed_state_before);

    let wrong_parent_token = block_on(
        prepare_pq_block(
            &slot_three_state,
            &key_cache,
            Arc::clone(&wrong_parent_block),
            &spec,
        )
        .expect("prepared wrong-parent block")
        .verify(&service),
    )
    .expect("wrong parent is signed but not linked to state");
    assert!(matches!(
        per_block_processing_pq(&mut slot_three_state, wrong_parent_token),
        Err(PqTransitionError::BlockProcessing(
            state_processing::BlockProcessingError::HeaderInvalid {
                reason: state_processing::HeaderInvalid::ParentBlockRootMismatch { .. }
            }
        ))
    ));

    let mut slot_four_state = state.clone();
    for _ in 0..4 {
        per_slot_processing_pq(&mut slot_four_state, &spec).expect("advance to slot four");
    }
    let sync_committee = slot_four_state
        .current_sync_committee()
        .expect("current sync committee")
        .clone();
    let sync_indices = slot_four_state
        .get_sync_committee_indices(&sync_committee)
        .expect("sync committee indices");
    let mut sync_occurrences = BTreeMap::<usize, usize>::new();
    for validator_index in sync_indices {
        let count = sync_occurrences.entry(validator_index).or_default();
        *count = count.checked_add(1).expect("bounded committee count");
    }
    assert!(
        sync_occurrences.values().any(|count| *count > 1),
        "16-validator V1 committee contains duplicate positions"
    );
    let balances_before = slot_four_state.balances().to_vec();

    let mut valid_transition_block: BeaconBlock<MinimalEthSpec> = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(valid_transition_electra) = &mut valid_transition_block else {
        unreachable!("Electra genesis spec constructs an Electra block");
    };
    valid_transition_electra.slot = Slot::new(4);
    valid_transition_electra.proposer_index = proposer_four as u64;
    valid_transition_electra.parent_root = slot_four_state.latest_block_header().canonical_root();
    valid_transition_electra.state_root = Hash256::repeat_byte(0x44);
    valid_transition_electra
        .body
        .execution_payload
        .execution_payload
        .timestamp = spec
        .get_slot_duration()
        .as_secs()
        .checked_mul(4)
        .and_then(|slot_offset| slot_four_state.genesis_time().checked_add(slot_offset))
        .expect("fixture timestamp");
    valid_transition_electra
        .body
        .execution_payload
        .execution_payload
        .prev_randao = *slot_four_state
        .get_randao_mix(types::Epoch::new(0))
        .expect("current randao mix");
    valid_transition_electra.body.randao_reveal = sign(
        proposer_four,
        Slot::new(4),
        SigningDuty::RandaoReveal,
        transition_randao_root,
    );
    let transition_attestation_data = AttestationData {
        slot: Slot::new(3),
        index: 0,
        beacon_block_root: *slot_four_state
            .get_block_root(Slot::new(3))
            .expect("slot-three block root"),
        source: slot_four_state.current_justified_checkpoint(),
        target: Checkpoint {
            epoch: types::Epoch::new(0),
            root: *slot_four_state
                .get_block_root_at_epoch(types::Epoch::new(0))
                .expect("epoch-zero target root"),
        },
    };
    let transition_attestation_domain = spec.get_domain(
        types::Epoch::new(0),
        Domain::BeaconAttester,
        &slot_four_state.fork(),
        slot_four_state.genesis_validators_root(),
    );
    let transition_attestation_signature = sign(
        attester_three,
        Slot::new(3),
        SigningDuty::Attestation,
        transition_attestation_data
            .signing_root(transition_attestation_domain)
            .0,
    );
    let attester_three_position = committee_three
        .iter()
        .position(|validator_index| *validator_index == attester_three)
        .expect("attester is in its committee");
    let Attestation::Electra(valid_transition_attestation) = electra_attestation(
        transition_attestation_data,
        committee_three.len(),
        &[attester_three_position],
        PqSameMessageEvidence::from(&transition_attestation_signature),
    ) else {
        unreachable!("fixture creates Electra attestations");
    };
    valid_transition_electra
        .body
        .attestations
        .push(valid_transition_attestation)
        .expect("one transition attestation");
    let valid_transition_root = valid_transition_block.signing_root(proposal_domain).0;
    let valid_transition_proposal = sign(
        proposer_four,
        Slot::new(4),
        SigningDuty::BeaconBlockProposal,
        valid_transition_root,
    );
    let valid_transition_block = Arc::new(SignedBeaconBlock::from_block(
        valid_transition_block,
        valid_transition_proposal,
    ));
    let valid_transition_token = block_on(
        prepare_pq_block(
            &slot_four_state,
            &key_cache,
            Arc::clone(&valid_transition_block),
            &spec,
        )
        .expect("prepared valid transition block")
        .verify(&service),
    )
    .expect("valid transition signatures");
    let transition_context = per_block_processing_pq(&mut slot_four_state, valid_transition_token)
        .expect("valid sealed PQ transition");
    assert_eq!(transition_context.slot, Slot::new(4));
    assert_eq!(
        transition_context.proposer_index,
        Some(proposer_four as u64)
    );
    assert_eq!(transition_context.current_block_root, None);
    assert_eq!(slot_four_state.latest_block_header().slot, Slot::new(4));
    assert_eq!(
        slot_four_state.latest_block_header().state_root,
        Hash256::ZERO,
        "ordinary processing installs a temporary header until the post-state root is known"
    );
    assert_eq!(
        slot_four_state.latest_block_header().body_root,
        valid_transition_block.message().body_root()
    );
    let attester_flags = *slot_four_state
        .current_epoch_participation()
        .expect("Electra participation")
        .get(attester_three)
        .expect("attesting validator");
    assert!(
        attester_flags.into_u8() > 0,
        "ordinary attestation processing updates participation"
    );
    let mut attestation_weight = 0u64;
    for (flag_index, weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
        if attester_flags
            .has_flag(flag_index)
            .expect("known flag index")
        {
            attestation_weight = attestation_weight
                .checked_add(*weight)
                .expect("bounded attestation weight");
        }
    }
    let attestation_proposer_reward = slot_four_state
        .get_base_reward(attester_three)
        .expect("attester base reward")
        .checked_mul(attestation_weight)
        .and_then(|numerator| {
            WEIGHT_DENOMINATOR
                .checked_sub(PROPOSER_WEIGHT)
                .and_then(|difference| difference.checked_mul(WEIGHT_DENOMINATOR))
                .and_then(|product| product.checked_div(PROPOSER_WEIGHT))
                .and_then(|denominator| numerator.checked_div(denominator))
        })
        .expect("ordinary proposer reward arithmetic");

    let mut penalty_per_position = None;
    for (validator_index, occurrence_count) in sync_occurrences {
        let before = *balances_before
            .get(validator_index)
            .expect("pre-transition balance");
        let after = *slot_four_state
            .balances()
            .get(validator_index)
            .expect("post-transition balance");
        let balance_before_sync = if validator_index == proposer_four {
            before
                .checked_add(attestation_proposer_reward)
                .expect("bounded proposer reward")
        } else {
            before
        };
        let total_penalty = balance_before_sync
            .checked_sub(after)
            .expect("all-false sync penalty");
        let per_position = total_penalty
            .checked_div(occurrence_count as u64)
            .expect("nonzero occurrence count");
        assert_eq!(
            total_penalty,
            per_position
                .checked_mul(occurrence_count as u64)
                .expect("bounded penalty"),
            "duplicate committee positions each receive the ordinary false-position penalty"
        );
        if let Some(expected) = penalty_per_position {
            assert_eq!(per_position, expected);
        } else {
            assert!(per_position > 0);
            penalty_per_position = Some(per_position);
        }
    }

    let mut slot_five_state = state.clone();
    for _ in 0..5 {
        per_slot_processing_pq(&mut slot_five_state, &spec).expect("advance to slot five");
    }
    let expected_timestamp = spec
        .get_slot_duration()
        .as_secs()
        .checked_mul(5)
        .and_then(|slot_offset| slot_five_state.genesis_time().checked_add(slot_offset))
        .expect("fixture timestamp");
    let invalid_timestamp = expected_timestamp
        .checked_sub(1)
        .expect("nonzero expected timestamp");
    let mut invalid_execution_block: BeaconBlock<MinimalEthSpec> = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(invalid_execution_electra) = &mut invalid_execution_block else {
        unreachable!("Electra genesis spec constructs an Electra block");
    };
    invalid_execution_electra.slot = Slot::new(5);
    invalid_execution_electra.proposer_index = proposer_five as u64;
    invalid_execution_electra.parent_root = slot_five_state.latest_block_header().canonical_root();
    invalid_execution_electra
        .body
        .execution_payload
        .execution_payload
        .timestamp = invalid_timestamp;
    invalid_execution_electra
        .body
        .execution_payload
        .execution_payload
        .prev_randao = *slot_five_state
        .get_randao_mix(types::Epoch::new(0))
        .expect("current randao mix");
    invalid_execution_electra.body.randao_reveal = sign(
        proposer_five,
        Slot::new(5),
        SigningDuty::RandaoReveal,
        transition_randao_root,
    );
    let invalid_execution_root = invalid_execution_block.signing_root(proposal_domain).0;
    let invalid_execution_proposal = sign(
        proposer_five,
        Slot::new(5),
        SigningDuty::BeaconBlockProposal,
        invalid_execution_root,
    );
    let invalid_execution_block = Arc::new(SignedBeaconBlock::from_block(
        invalid_execution_block,
        invalid_execution_proposal,
    ));
    let invalid_execution_token = block_on(
        prepare_pq_block(&slot_five_state, &key_cache, invalid_execution_block, &spec)
            .expect("prepared invalid-execution block")
            .verify(&service),
    )
    .expect("valid PQ signatures do not imply a valid execution payload");
    assert_eq!(
        per_block_processing_pq(&mut slot_five_state, invalid_execution_token),
        Err(PqTransitionError::BlockProcessing(
            state_processing::BlockProcessingError::ExecutionInvalidTimestamp {
                expected: expected_timestamp,
                found: invalid_timestamp,
            }
        ))
    );

    let mut wrong_aggregator_key = signed_aggregate.clone();
    let SignedAggregateAndProof::Electra(wrong_aggregator_electra) = &mut wrong_aggregator_key
    else {
        unreachable!("fixture aggregate is Electra");
    };
    let wrong_selection = sign(
        alternate_index,
        Slot::new(0),
        SigningDuty::AttestationSelectionProof,
        selection_root,
    );
    wrong_aggregator_electra.message.selection_proof = wrong_selection;
    wrong_aggregator_electra
        .message
        .aggregate
        .aggregation_bits
        .set(1, false)
        .expect("clear second participant");
    wrong_aggregator_electra.signature = PqRawSignature::empty();
    let wrong_selection_result = block_on(
        prepare_pq_aggregate_and_proof(&state, &key_cache, wrong_aggregator_key, &spec)
            .expect("structurally valid wrong-aggregator-key request")
            .verify(&service),
    )
    .map(|_| ());

    let mut wrong_signer_bits = signed_aggregate.clone();
    let SignedAggregateAndProof::Electra(wrong_bits_electra) = &mut wrong_signer_bits else {
        unreachable!("fixture aggregate is Electra");
    };
    wrong_bits_electra
        .message
        .aggregate
        .aggregation_bits
        .set(1, false)
        .expect("clear second participant");
    wrong_bits_electra.signature = PqRawSignature::empty();
    let wrong_inner_result = block_on(
        prepare_pq_aggregate_and_proof(&state, &key_cache, wrong_signer_bits, &spec)
            .expect("structurally valid wrong-signer-set request")
            .verify(&service),
    )
    .map(|_| ());

    let mut wrong_outer = signed_aggregate;
    let SignedAggregateAndProof::Electra(wrong_outer_electra) = &mut wrong_outer else {
        unreachable!("fixture aggregate is Electra");
    };
    wrong_outer_electra.signature = PqRawSignature::empty();
    let wrong_outer_result = block_on(
        prepare_pq_aggregate_and_proof(&state, &key_cache, wrong_outer, &spec)
            .expect("structurally valid wrong-outer request")
            .verify(&service),
    )
    .map(|_| ());
    assert_eq!(
        (
            wrong_selection_result,
            wrong_inner_result,
            wrong_outer_result,
        ),
        (
            Err(PqConsensusError::Invalid(
                PqConsensusInvalid::InvalidEvidence(
                    state_processing::PqConsensusComponent::SelectionProof,
                ),
            )),
            Err(PqConsensusError::Invalid(
                PqConsensusInvalid::InvalidAttestation {
                    component: state_processing::PqConsensusComponent::AggregateAttestation,
                    error: state_processing::PqAttestationInvalid::InvalidEvidence,
                },
            )),
            Err(PqConsensusError::Invalid(
                PqConsensusInvalid::InvalidEvidence(
                    state_processing::PqConsensusComponent::AggregateAndProof,
                ),
            )),
        )
    );
}
