use consensus_signature::PqPublicKey;
#[cfg(target_feature = "avx2")]
use consensus_signature::{
    AggregationService, OneTimeUseId, PqSameMessageEvidence, SigningDuty, VerificationClass,
};
#[cfg(target_feature = "avx2")]
use futures::executor::block_on;
#[cfg(target_feature = "avx2")]
use pq_signing::{PqKeyUnlock, PqKeystore, PqSigningAuthority, provision_usage_journal};
#[cfg(target_feature = "avx2")]
use state_processing::{
    BlockProcessingError, PqConsensusInvalid, PqTransitionError, PqUnsupportedBlock,
    per_block_processing_pq, per_slot_processing_pq,
    preflight_pq_local_block_with_sealing_work_count, prepare_pq_attestation, prepare_pq_block,
};
use state_processing::{
    DirectGenesisValidator, PqConsensusError, PqLocalBlockError, PqLocalBlockInvalid,
    PqLocalTransitionOutput, PqValidatorKeyCache, PreparedPqRandao, VerifiedPqLocalBlock,
    VerifiedPqRandao, initialize_beacon_state_from_validators, per_block_processing_pq_local,
    prepare_pq_local_block, prepare_pq_randao, prepare_pq_randao_with_evidence_work_count,
};
use std::error::Error as _;
use std::sync::Arc;
#[cfg(target_feature = "avx2")]
use types::{
    Attestation, AttestationData, BeaconBlock, Checkpoint, Domain, RelativeEpoch,
    SignedBeaconBlock, SignedRoot,
};
use types::{ChainSpec, EthSpec, ForkName, Hash256, MinimalEthSpec, Slot};

#[cfg(target_feature = "avx2")]
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

#[cfg(target_feature = "avx2")]
fn electra_attestation(
    data: AttestationData,
    committee_length: usize,
    participant_position: usize,
    evidence: PqSameMessageEvidence,
) -> Attestation<MinimalEthSpec> {
    let mut aggregation_bits = ssz_types::BitList::<
        <MinimalEthSpec as EthSpec>::MaxValidatorsPerSlot,
    >::with_capacity(committee_length)
    .expect("committee bitlist");
    aggregation_bits
        .set(participant_position, true)
        .expect("participant bit");
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
fn sealed_local_transition_entry_points_exist() {
    let _ = std::mem::size_of::<PreparedPqRandao<MinimalEthSpec>>();
    let _ = std::mem::size_of::<VerifiedPqRandao<MinimalEthSpec>>();
    let _ = std::mem::size_of::<VerifiedPqLocalBlock<MinimalEthSpec>>();
    let _ = std::mem::size_of::<PqLocalTransitionOutput<MinimalEthSpec>>();
    let _ = prepare_pq_randao::<MinimalEthSpec>;
    let _ = prepare_pq_local_block::<MinimalEthSpec>;
    let _ = per_block_processing_pq_local::<MinimalEthSpec>;
}

#[test]
fn local_assembly_error_exposes_only_nested_consensus_causes() {
    let nested =
        PqConsensusError::Local(state_processing::PqConsensusLocalError::UnsupportedProfile);
    let error = PqLocalBlockError::Consensus(nested);
    assert_eq!(
        error.source().map(ToString::to_string),
        Some(nested.to_string())
    );
    assert!(
        PqLocalBlockError::Invalid(PqLocalBlockInvalid::NonZeroStateRoot)
            .source()
            .is_none()
    );
    assert!(
        PqLocalBlockError::PreStateMismatch {
            expected: Hash256::ZERO,
            actual: Hash256::repeat_byte(1),
        }
        .source()
        .is_none()
    );
}

#[test]
fn randao_context_is_rejected_before_evidence_materialization() {
    let spec = electra_spec();
    let state = initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16).map(synthetic_validator).collect(),
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    let key_cache = Arc::new(PqValidatorKeyCache::from_state(&state).expect("valid PQ registry"));

    let mut evidence_work = 0;
    assert!(
        prepare_pq_randao_with_evidence_work_count(
            &state,
            Arc::clone(&key_cache),
            Slot::new(1),
            consensus_signature::IndividualSignature::empty(),
            Arc::new(spec.clone()),
            &mut evidence_work,
        )
        .is_err()
    );
    assert_eq!(evidence_work, 0);

    let mut future_fork_spec = spec.clone();
    future_fork_spec.fulu_fork_epoch = Some(types::Epoch::new(1));
    assert!(
        prepare_pq_randao_with_evidence_work_count(
            &state,
            Arc::clone(&key_cache),
            Slot::new(0),
            consensus_signature::IndividualSignature::empty(),
            Arc::new(future_fork_spec),
            &mut evidence_work,
        )
        .is_err()
    );
    assert_eq!(evidence_work, 0);

    let proposer_index = state
        .get_beacon_proposer_index(Slot::new(0), &spec)
        .expect("slot-zero proposer");
    let mut changed_state = state;
    changed_state
        .validators_mut()
        .get_mut(proposer_index)
        .expect("proposer validator")
        .pubkey = synthetic_validator(0x71).public_key;
    assert!(
        prepare_pq_randao_with_evidence_work_count(
            &changed_state,
            key_cache,
            Slot::new(0),
            consensus_signature::IndividualSignature::empty(),
            Arc::new(spec),
            &mut evidence_work,
        )
        .is_err()
    );
    assert_eq!(evidence_work, 0);
}

#[cfg(target_feature = "avx2")]
#[test]
fn journal_backed_local_and_imported_transitions_have_the_same_state_root() {
    let temporary_directory = tempfile::TempDir::new().expect("temporary directory");
    let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
    let spec = electra_spec().set_slot_duration_ms::<MinimalEthSpec>(17_000);
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
        .expect("slot-zero committee")
        .committee
        .to_vec();
    let participants = committee
        .get(..2)
        .expect("minimal committee has two participants")
        .to_vec();
    let proposer_index = state
        .get_beacon_proposer_index(Slot::new(1), &spec)
        .expect("slot-one proposer");
    let mut required_indices = participants.clone();
    required_indices.push(proposer_index);
    required_indices.sort_unstable();
    required_indices.dedup();
    let maximum_leaf = OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::BeaconBlockProposal)
        .expect("slot-one proposal leaf")
        .as_u32();
    let mut metadata = Vec::new();
    let mut unlocks = Vec::new();
    for (ordinal, validator_index) in required_indices.iter().copied().enumerate() {
        let seed_byte = u8::try_from(ordinal)
            .ok()
            .and_then(|value| value.checked_add(0xa1))
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
        unlocks.push(PqKeyUnlock::new(keystore, PASSWORD).expect("unlock"));
    }
    let genesis_validators_root = state.genesis_validators_root().0;
    provision_usage_journal(&journal_path, genesis_validators_root, &metadata).expect("journal");
    let authority = PqSigningAuthority::open(&journal_path, genesis_validators_root, unlocks)
        .expect("signing authority");
    per_slot_processing_pq(&mut state, &spec).expect("advance to slot one");
    let key_cache = Arc::new(PqValidatorKeyCache::from_state(&state).expect("valid PQ registry"));
    let spec = Arc::new(spec);
    let service = AggregationService::new().expect("PQ aggregation service");
    let sign = |validator_index: usize, slot: Slot, duty: SigningDuty, signing_root: [u8; 32]| {
        let one_time_use_id =
            OneTimeUseId::for_lean_pq_devnet_v1(slot.as_u64(), duty).expect("V1 signing leaf");
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

    let randao_domain = spec.get_domain(
        state.current_epoch(),
        Domain::Randao,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let randao_signature = sign(
        proposer_index,
        Slot::new(1),
        SigningDuty::RandaoReveal,
        state.current_epoch().signing_root(randao_domain).0,
    );
    let verified_randao = block_on(
        prepare_pq_randao(
            &state,
            Arc::clone(&key_cache),
            Slot::new(1),
            randao_signature.clone(),
            Arc::clone(&spec),
        )
        .expect("prepared RANDAO")
        .verify(&service),
    )
    .expect("valid RANDAO evidence");

    let attestation_data = AttestationData {
        slot: Slot::new(0),
        index: 0,
        beacon_block_root: *state.get_block_root(Slot::new(0)).expect("slot-zero root"),
        source: state.current_justified_checkpoint(),
        target: Checkpoint {
            epoch: types::Epoch::new(0),
            root: *state
                .get_block_root_at_epoch(types::Epoch::new(0))
                .expect("epoch-zero target root"),
        },
    };
    let attestation_domain = spec.get_domain(
        types::Epoch::new(0),
        Domain::BeaconAttester,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let attestation_root = attestation_data.signing_root(attestation_domain).0;
    let mut attestations = Vec::new();
    let mut verified_attestations = Vec::new();
    for validator_index in &participants {
        let position = committee
            .iter()
            .position(|candidate| candidate == validator_index)
            .expect("participant position");
        let signature = sign(
            *validator_index,
            Slot::new(0),
            SigningDuty::Attestation,
            attestation_root,
        );
        let attestation = electra_attestation(
            attestation_data.clone(),
            committee.len(),
            position,
            PqSameMessageEvidence::from(&signature),
        );
        let verified = block_on(
            prepare_pq_attestation(
                &state,
                &key_cache,
                attestation.clone(),
                vec![*validator_index as u64],
                &spec,
            )
            .expect("prepared attestation")
            .verify(&service, VerificationClass::Block),
        )
        .expect("valid attestation evidence");
        attestations.push(attestation);
        verified_attestations.push(Arc::new(verified));
    }

    let mut block: BeaconBlock<MinimalEthSpec> = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(electra) = &mut block else {
        unreachable!("Electra genesis spec constructs an Electra block");
    };
    electra.slot = Slot::new(1);
    electra.proposer_index = proposer_index as u64;
    electra.parent_root = state.latest_block_header().canonical_root();
    electra.body.randao_reveal = randao_signature.clone();
    electra.body.execution_payload.execution_payload.timestamp = state
        .genesis_time()
        .checked_add(spec.get_slot_duration().as_secs())
        .expect("slot-one timestamp");
    electra.body.execution_payload.execution_payload.prev_randao = *state
        .get_randao_mix(types::Epoch::new(0))
        .expect("current RANDAO mix");
    for attestation in &attestations {
        let Attestation::Electra(attestation) = attestation else {
            unreachable!("fixture attestation is Electra");
        };
        electra
            .body
            .attestations
            .push(attestation.clone())
            .expect("bounded block attestation");
    }

    let mut sealing_work = 0;
    preflight_pq_local_block_with_sealing_work_count(
        &state,
        &block,
        &verified_randao,
        &verified_attestations,
        &mut sealing_work,
    )
    .expect("valid local block preflight");
    assert_eq!(sealing_work, 1);

    let mut nonzero_root = block.clone();
    let BeaconBlock::Electra(nonzero_root_inner) = &mut nonzero_root else {
        unreachable!("fixture block is Electra");
    };
    nonzero_root_inner.state_root = Hash256::repeat_byte(0x31);
    sealing_work = 0;
    assert_eq!(
        preflight_pq_local_block_with_sealing_work_count(
            &state,
            &nonzero_root,
            &verified_randao,
            &verified_attestations,
            &mut sealing_work,
        ),
        Err(PqLocalBlockError::Invalid(
            PqLocalBlockInvalid::NonZeroStateRoot,
        ))
    );
    assert_eq!(sealing_work, 0);

    let mut wrong_randao = block.clone();
    let BeaconBlock::Electra(wrong_randao_inner) = &mut wrong_randao else {
        unreachable!("fixture block is Electra");
    };
    wrong_randao_inner.body.randao_reveal = consensus_signature::IndividualSignature::empty();
    sealing_work = 0;
    assert_eq!(
        preflight_pq_local_block_with_sealing_work_count(
            &state,
            &wrong_randao,
            &verified_randao,
            &verified_attestations,
            &mut sealing_work,
        ),
        Err(PqLocalBlockError::Invalid(
            PqLocalBlockInvalid::RandaoMismatch,
        ))
    );
    assert_eq!(sealing_work, 0);

    let mut unsupported = block.clone();
    let BeaconBlock::Electra(unsupported_inner) = &mut unsupported else {
        unreachable!("fixture block is Electra");
    };
    unsupported_inner.body.eth1_data.block_hash = Hash256::repeat_byte(0x41);
    sealing_work = 0;
    assert_eq!(
        preflight_pq_local_block_with_sealing_work_count(
            &state,
            &unsupported,
            &verified_randao,
            &verified_attestations,
            &mut sealing_work,
        ),
        Err(PqLocalBlockError::Consensus(PqConsensusError::Invalid(
            PqConsensusInvalid::UnsupportedBlock(PqUnsupportedBlock::Eth1DataChanged),
        )))
    );
    assert_eq!(sealing_work, 0);

    let mut wrong_state = state.clone();
    let changed_balance = wrong_state
        .balances()
        .get(0)
        .copied()
        .expect("first balance")
        .checked_add(1)
        .expect("bounded balance mutation");
    *wrong_state
        .balances_mut()
        .get_mut(0)
        .expect("first balance") = changed_balance;
    sealing_work = 0;
    assert!(matches!(
        preflight_pq_local_block_with_sealing_work_count(
            &wrong_state,
            &block,
            &verified_randao,
            &verified_attestations,
            &mut sealing_work,
        ),
        Err(PqLocalBlockError::PreStateMismatch { .. })
    ));
    assert_eq!(sealing_work, 0);

    sealing_work = 0;
    assert_eq!(
        preflight_pq_local_block_with_sealing_work_count(
            &state,
            &block,
            &verified_randao,
            &verified_attestations[..1],
            &mut sealing_work,
        ),
        Err(PqLocalBlockError::Invalid(
            PqLocalBlockInvalid::AttestationCountMismatch {
                block: 2,
                tokens: 1,
            },
        ))
    );
    assert_eq!(sealing_work, 0);

    let reversed_tokens = verified_attestations
        .iter()
        .rev()
        .cloned()
        .collect::<Vec<_>>();
    sealing_work = 0;
    assert_eq!(
        preflight_pq_local_block_with_sealing_work_count(
            &state,
            &block,
            &verified_randao,
            &reversed_tokens,
            &mut sealing_work,
        ),
        Err(PqLocalBlockError::Invalid(
            PqLocalBlockInvalid::AttestationBytesMismatch(0),
        ))
    );
    assert_eq!(sealing_work, 0);

    let substituted_tokens = vec![
        Arc::clone(verified_attestations.first().expect("first token")),
        Arc::clone(verified_attestations.first().expect("first token")),
    ];
    sealing_work = 0;
    assert_eq!(
        preflight_pq_local_block_with_sealing_work_count(
            &state,
            &block,
            &verified_randao,
            &substituted_tokens,
            &mut sealing_work,
        ),
        Err(PqLocalBlockError::Invalid(
            PqLocalBlockInvalid::AttestationBytesMismatch(1),
        ))
    );
    assert_eq!(sealing_work, 0);

    let wrong_prestate_randao = block_on(
        prepare_pq_randao(
            &state,
            Arc::clone(&key_cache),
            Slot::new(1),
            randao_signature.clone(),
            Arc::clone(&spec),
        )
        .expect("prepared second RANDAO")
        .verify(&service),
    )
    .expect("second contextual RANDAO verification");
    let wrong_prestate_local = prepare_pq_local_block(
        &state,
        block.clone(),
        wrong_prestate_randao,
        verified_attestations.clone(),
    )
    .expect("sealed wrong-prestate probe");
    let wrong_state_before = wrong_state.clone();
    assert!(matches!(
        per_block_processing_pq_local(&mut wrong_state, wrong_prestate_local),
        Err(PqTransitionError::PreStateMismatch { .. })
    ));
    assert_eq!(wrong_state, wrong_state_before);

    let wrong_spec = Arc::new(
        spec.as_ref()
            .clone()
            .set_slot_duration_ms::<MinimalEthSpec>(19_000),
    );
    let wrong_spec_expected_timestamp = state
        .genesis_time()
        .checked_add(wrong_spec.get_slot_duration().as_secs())
        .expect("wrong-spec slot-one timestamp");
    let produced_timestamp = state
        .genesis_time()
        .checked_add(spec.get_slot_duration().as_secs())
        .expect("fixture slot-one timestamp");
    let wrong_spec_randao = block_on(
        prepare_pq_randao(
            &state,
            Arc::clone(&key_cache),
            Slot::new(1),
            randao_signature.clone(),
            wrong_spec,
        )
        .expect("prepared wrong-spec RANDAO")
        .verify(&service),
    )
    .expect("RANDAO claim is unchanged by slot duration");
    let wrong_spec_local = prepare_pq_local_block(
        &state,
        block.clone(),
        wrong_spec_randao,
        verified_attestations.clone(),
    )
    .expect("local token owns its wrong spec");
    let mut wrong_spec_state = state.clone();
    assert_eq!(
        per_block_processing_pq_local(&mut wrong_spec_state, wrong_spec_local).map(|_| ()),
        Err(PqTransitionError::BlockProcessing(
            BlockProcessingError::ExecutionInvalidTimestamp {
                expected: wrong_spec_expected_timestamp,
                found: produced_timestamp,
            },
        ))
    );

    let pre_state = state.clone();
    let local = prepare_pq_local_block(&state, block, verified_randao, verified_attestations)
        .expect("sealed local block");
    assert_eq!(local.block().state_root(), Hash256::ZERO);
    let mut local_state = pre_state.clone();
    let output =
        per_block_processing_pq_local(&mut local_state, local).expect("sealed local transition");
    assert_eq!(output.context().slot, Slot::new(1));
    let (mut produced_block, _) = output.into_parts();
    let local_state_root = local_state.canonical_root().expect("local post-state root");
    let BeaconBlock::Electra(produced) = &mut produced_block else {
        unreachable!("produced block remains Electra");
    };
    assert_eq!(
        produced
            .body
            .sync_aggregate
            .sync_committee_bits
            .num_set_bits(),
        0
    );
    assert!(
        produced
            .body
            .sync_aggregate
            .sync_committee_signature
            .is_empty()
    );
    produced.state_root = local_state_root;

    let proposal_domain = spec.get_domain(
        types::Epoch::new(0),
        Domain::BeaconProposer,
        &pre_state.fork(),
        pre_state.genesis_validators_root(),
    );
    let proposal_root = produced_block.signing_root(proposal_domain).0;
    let proposal_signature = sign(
        proposer_index,
        Slot::new(1),
        SigningDuty::BeaconBlockProposal,
        proposal_root,
    );
    let signed_block = Arc::new(SignedBeaconBlock::from_block(
        produced_block,
        proposal_signature,
    ));
    let imported_token = block_on(
        prepare_pq_block(&pre_state, &key_cache, Arc::clone(&signed_block), &spec)
            .expect("prepared imported block")
            .verify(&service),
    )
    .expect("independently verified imported block");
    let mut imported_state = pre_state;
    per_block_processing_pq(&mut imported_state, imported_token)
        .expect("sealed imported transition");
    let imported_state_root = imported_state
        .canonical_root()
        .expect("imported post-state root");
    assert_eq!(imported_state_root, local_state_root);
}
