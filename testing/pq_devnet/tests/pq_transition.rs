use consensus_signature::{
    PqPublicKey, PqRawSignature, PqSameMessageEvidence, ValidatorPublicKeyBytes,
};
use ssz::Decode;
use state_processing::{
    DirectGenesisValidator, PqConsensusError, PqConsensusInvalid, PqConsensusLocalError,
    PqTransitionError, PqUnsupportedBlock, PqValidatorKeyCache, VerifiedPqBlock,
    initialize_beacon_state_from_validators, per_block_processing_pq, per_slot_processing_pq,
    prepare_pq_block_with_evidence_work_count,
};
use std::sync::Arc;
use types::{
    Address, AttesterSlashingElectra, BeaconBlock, BeaconState, BlsToExecutionChange, ChainSpec,
    ConsolidationRequest, Deposit, DepositRequest, EthSpec, ForkName, Hash256,
    IndexedAttestationElectra, KzgCommitment, MinimalEthSpec, PendingConsolidation, PendingDeposit,
    PendingPartialWithdrawal, ProposerSlashing, SignedBeaconBlock, SignedBeaconBlockHeader,
    SignedBlsToExecutionChange, SignedVoluntaryExit, Slot, VoluntaryExit, WithdrawalRequest,
};

#[test]
fn sealed_pq_transition_entry_point_exists() {
    let _ = per_block_processing_pq::<MinimalEthSpec>;
    let _ = std::mem::size_of::<VerifiedPqBlock<MinimalEthSpec>>();
}

fn electra_spec() -> ChainSpec {
    ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec())
}

fn synthetic_validator(byte: u8) -> DirectGenesisValidator {
    DirectGenesisValidator {
        public_key: PqPublicKey::deserialize(&[byte; 32]).expect("canonical test public key"),
        withdrawal_credentials: Hash256::ZERO,
    }
}

fn genesis_state(validator_count: usize, spec: &ChainSpec) -> BeaconState<MinimalEthSpec> {
    initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=validator_count)
            .map(|index| synthetic_validator(index as u8))
            .collect(),
        None,
        spec,
    )
    .expect("direct PQ genesis")
}

fn empty_signed_block(
    state: &BeaconState<MinimalEthSpec>,
    spec: &ChainSpec,
) -> Arc<SignedBeaconBlock<MinimalEthSpec>> {
    let mut block = BeaconBlock::empty(spec);
    let BeaconBlock::Electra(electra) = &mut block else {
        unreachable!("Electra genesis spec constructs an Electra block");
    };
    electra.slot = state.slot();
    electra.proposer_index = state
        .get_beacon_proposer_index(state.slot(), spec)
        .expect("genesis proposer") as u64;
    Arc::new(SignedBeaconBlock::from_block(
        block,
        PqRawSignature::empty(),
    ))
}

fn assert_preflight_rejection(
    state: &BeaconState<MinimalEthSpec>,
    key_cache: &PqValidatorKeyCache,
    block: Arc<SignedBeaconBlock<MinimalEthSpec>>,
    spec: &ChainSpec,
    expected: PqConsensusError,
) {
    let mut evidence_work = 0usize;
    assert_eq!(
        prepare_pq_block_with_evidence_work_count(
            state,
            key_cache,
            block,
            spec,
            &mut evidence_work,
        )
        .map(|_| ()),
        Err(expected)
    );
    assert_eq!(evidence_work, 0, "preflight must precede evidence work");
}

fn decode_zero_fixed<T: Decode>() -> T {
    T::from_ssz_bytes(&vec![0; T::ssz_fixed_len()]).expect("zero fixed-size test object")
}

fn reject_mutated_block(
    state: &BeaconState<MinimalEthSpec>,
    key_cache: &PqValidatorKeyCache,
    spec: &ChainSpec,
    mutate: impl FnOnce(&mut types::BeaconBlockElectra<MinimalEthSpec>),
    expected: PqUnsupportedBlock,
) {
    let mut block = empty_signed_block(state, spec).as_ref().clone();
    let SignedBeaconBlock::Electra(electra) = &mut block else {
        unreachable!("fixture block is Electra");
    };
    mutate(&mut electra.message);
    assert_preflight_rejection(
        state,
        key_cache,
        Arc::new(block),
        spec,
        PqConsensusError::Invalid(PqConsensusInvalid::UnsupportedBlock(expected)),
    );
}

#[test]
fn full_block_requires_exact_state_slot_before_evidence_work() {
    let spec = electra_spec();
    let state = genesis_state(16, &spec);
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let mut block = empty_signed_block(&state, &spec).as_ref().clone();
    let SignedBeaconBlock::Electra(electra) = &mut block else {
        unreachable!("fixture block is Electra");
    };
    electra.message.slot = Slot::new(1);

    assert_preflight_rejection(
        &state,
        &key_cache,
        Arc::new(block),
        &spec,
        PqConsensusError::Invalid(PqConsensusInvalid::UnsupportedBlock(
            PqUnsupportedBlock::StateSlotMismatch {
                state: Slot::new(0),
                block: Slot::new(1),
            },
        )),
    );
}

#[test]
fn v1_requires_exactly_sixteen_validators_before_evidence_work() {
    let spec = electra_spec();
    let valid_state = genesis_state(16, &spec);
    let key_cache = PqValidatorKeyCache::from_state(&valid_state).expect("valid PQ registry");

    for validator_count in [15, 17] {
        let state = genesis_state(validator_count, &spec);
        let block = empty_signed_block(&state, &spec);
        assert_preflight_rejection(
            &state,
            &key_cache,
            block,
            &spec,
            PqConsensusError::Local(PqConsensusLocalError::UnsupportedProfile),
        );
    }
}

#[test]
fn v1_rejects_fulu_and_gloas_schedules_before_evidence_work() {
    let base_spec = electra_spec();
    let state = genesis_state(16, &base_spec);
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let mut fulu_spec = base_spec.clone();
    fulu_spec.fulu_fork_epoch = Some(types::Epoch::new(1));
    let mut gloas_spec = base_spec;
    gloas_spec.gloas_fork_epoch = Some(types::Epoch::new(1));

    for spec in [fulu_spec, gloas_spec] {
        assert_preflight_rejection(
            &state,
            &key_cache,
            empty_signed_block(&state, &spec),
            &spec,
            PqConsensusError::Local(PqConsensusLocalError::UnsupportedProfile),
        );
    }
}

#[test]
fn eth1_data_must_remain_the_zero_deposit_value() {
    let spec = electra_spec();
    let state = genesis_state(16, &spec);
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let mut block = empty_signed_block(&state, &spec).as_ref().clone();
    let SignedBeaconBlock::Electra(electra) = &mut block else {
        unreachable!("fixture block is Electra");
    };
    electra.message.body.eth1_data.block_hash = Hash256::repeat_byte(0x51);

    assert_preflight_rejection(
        &state,
        &key_cache,
        Arc::new(block),
        &spec,
        PqConsensusError::Invalid(PqConsensusInvalid::UnsupportedBlock(
            PqUnsupportedBlock::Eth1DataChanged,
        )),
    );
}

#[test]
fn sync_shape_accepts_only_zero_bits_with_absent_evidence() {
    let spec = electra_spec();
    let state = genesis_state(16, &spec);
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");
    let raw = PqSameMessageEvidence::from(&PqRawSignature::empty());
    let aggregate = PqSameMessageEvidence::from_bytes(b"LHPQ\x01\x01\x01x")
        .expect("structural aggregate evidence");

    for (set_bit, evidence, expected) in [
        (
            false,
            raw.clone(),
            PqUnsupportedBlock::SyncCommitteeEvidence,
        ),
        (
            false,
            aggregate.clone(),
            PqUnsupportedBlock::SyncCommitteeEvidence,
        ),
        (
            true,
            PqSameMessageEvidence::empty(),
            PqUnsupportedBlock::SyncCommitteeParticipants,
        ),
        (true, raw, PqUnsupportedBlock::SyncCommitteeParticipants),
        (
            true,
            aggregate,
            PqUnsupportedBlock::SyncCommitteeParticipants,
        ),
    ] {
        let mut block = empty_signed_block(&state, &spec).as_ref().clone();
        let SignedBeaconBlock::Electra(electra) = &mut block else {
            unreachable!("fixture block is Electra");
        };
        electra.message.body.sync_aggregate.sync_committee_signature = evidence;
        if set_bit {
            electra
                .message
                .body
                .sync_aggregate
                .sync_committee_bits
                .set(0, true)
                .expect("sync bit");
        }
        assert_preflight_rejection(
            &state,
            &key_cache,
            Arc::new(block),
            &spec,
            PqConsensusError::Invalid(PqConsensusInvalid::UnsupportedBlock(expected)),
        );
    }

    let mut evidence_work = 0usize;
    let prepared = prepare_pq_block_with_evidence_work_count(
        &state,
        &key_cache,
        empty_signed_block(&state, &spec),
        &spec,
        &mut evidence_work,
    )
    .expect("canonical empty sync shape reaches signature materialization");
    assert!(evidence_work > 0);
    drop(prepared);
}

#[test]
fn every_unsupported_block_operation_is_rejected_before_evidence_work() {
    let spec = electra_spec();
    let state = genesis_state(16, &spec);
    let key_cache = PqValidatorKeyCache::from_state(&state).expect("valid PQ registry");

    reject_mutated_block(
        &state,
        &key_cache,
        &spec,
        |block| {
            block
                .body
                .deposits
                .push(decode_zero_fixed::<Deposit>())
                .expect("deposit capacity");
        },
        PqUnsupportedBlock::Deposits,
    );
    reject_mutated_block(
        &state,
        &key_cache,
        &spec,
        |block| {
            block
                .body
                .execution_requests
                .deposits
                .push(decode_zero_fixed::<DepositRequest>())
                .expect("deposit request capacity");
        },
        PqUnsupportedBlock::DepositRequests,
    );
    reject_mutated_block(
        &state,
        &key_cache,
        &spec,
        |block| {
            let signed_header = SignedBeaconBlockHeader {
                message: types::BeaconBlockHeader::empty(),
                signature: PqRawSignature::empty(),
            };
            block
                .body
                .proposer_slashings
                .push(ProposerSlashing {
                    signed_header_1: signed_header.clone(),
                    signed_header_2: signed_header,
                })
                .expect("proposer slashing capacity");
        },
        PqUnsupportedBlock::ProposerSlashings,
    );
    reject_mutated_block(
        &state,
        &key_cache,
        &spec,
        |block| {
            let indexed = IndexedAttestationElectra {
                attesting_indices: ssz_types::VariableList::empty(),
                data: types::AttestationData::default(),
                signature: PqSameMessageEvidence::empty(),
            };
            block
                .body
                .attester_slashings
                .push(AttesterSlashingElectra {
                    attestation_1: indexed.clone(),
                    attestation_2: indexed,
                })
                .expect("attester slashing capacity");
        },
        PqUnsupportedBlock::AttesterSlashings,
    );
    reject_mutated_block(
        &state,
        &key_cache,
        &spec,
        |block| {
            block
                .body
                .voluntary_exits
                .push(SignedVoluntaryExit {
                    message: VoluntaryExit {
                        epoch: types::Epoch::new(0),
                        validator_index: 0,
                    },
                    signature: PqRawSignature::empty(),
                })
                .expect("voluntary exit capacity");
        },
        PqUnsupportedBlock::VoluntaryExits,
    );
    reject_mutated_block(
        &state,
        &key_cache,
        &spec,
        |block| {
            block
                .body
                .bls_to_execution_changes
                .push(SignedBlsToExecutionChange {
                    message: BlsToExecutionChange {
                        validator_index: 0,
                        from_bls_pubkey: decode_zero_fixed(),
                        to_execution_address: Address::ZERO,
                    },
                    signature: decode_zero_fixed(),
                })
                .expect("BLS change capacity");
        },
        PqUnsupportedBlock::BlsToExecutionChanges,
    );
    reject_mutated_block(
        &state,
        &key_cache,
        &spec,
        |block| {
            block
                .body
                .execution_requests
                .withdrawals
                .push(WithdrawalRequest {
                    source_address: Address::ZERO,
                    validator_pubkey: ValidatorPublicKeyBytes::empty(),
                    amount: 0,
                })
                .expect("withdrawal request capacity");
        },
        PqUnsupportedBlock::WithdrawalRequests,
    );
    reject_mutated_block(
        &state,
        &key_cache,
        &spec,
        |block| {
            block
                .body
                .execution_requests
                .consolidations
                .push(ConsolidationRequest {
                    source_address: Address::ZERO,
                    source_pubkey: ValidatorPublicKeyBytes::empty(),
                    target_pubkey: ValidatorPublicKeyBytes::empty(),
                })
                .expect("consolidation request capacity");
        },
        PqUnsupportedBlock::ConsolidationRequests,
    );
    reject_mutated_block(
        &state,
        &key_cache,
        &spec,
        |block| {
            block
                .body
                .blob_kzg_commitments
                .push(decode_zero_fixed::<KzgCommitment>())
                .expect("blob commitment capacity");
        },
        PqUnsupportedBlock::BlobKzgCommitments,
    );
}

#[test]
fn unsupported_pending_state_is_local_and_precedes_mutation() {
    let spec = electra_spec();
    let valid_state = genesis_state(16, &spec);
    let key_cache = PqValidatorKeyCache::from_state(&valid_state).expect("valid PQ registry");

    let mut states = Vec::new();
    let mut pending_deposit = valid_state.clone();
    pending_deposit
        .pending_deposits_mut()
        .expect("Electra pending deposits")
        .push(decode_zero_fixed::<PendingDeposit>())
        .expect("pending deposit capacity");
    states.push(pending_deposit);

    let mut pending_withdrawal = valid_state.clone();
    pending_withdrawal
        .pending_partial_withdrawals_mut()
        .expect("Electra pending withdrawals")
        .push(PendingPartialWithdrawal {
            validator_index: 0,
            amount: 1,
            withdrawable_epoch: types::Epoch::new(0),
        })
        .expect("pending withdrawal capacity");
    states.push(pending_withdrawal);

    let mut pending_consolidation = valid_state.clone();
    pending_consolidation
        .pending_consolidations_mut()
        .expect("Electra pending consolidations")
        .push(PendingConsolidation {
            source_index: 0,
            target_index: 1,
        })
        .expect("pending consolidation capacity");
    states.push(pending_consolidation);

    let mut nonzero_deposit_root = valid_state;
    nonzero_deposit_root.eth1_data_mut().deposit_root = Hash256::repeat_byte(0x61);
    states.push(nonzero_deposit_root);

    let mut nonzero_deposit_count = states.last().expect("one prior unsupported state").clone();
    nonzero_deposit_count.eth1_data_mut().deposit_root = Hash256::ZERO;
    nonzero_deposit_count.eth1_data_mut().deposit_count = 1;
    states.push(nonzero_deposit_count);

    let mut nonzero_deposit_index = states.last().expect("one prior unsupported state").clone();
    nonzero_deposit_index.eth1_data_mut().deposit_count = 0;
    *nonzero_deposit_index.eth1_deposit_index_mut() = 1;
    states.push(nonzero_deposit_index);

    for mut state in states {
        let before = state.clone();
        assert_preflight_rejection(
            &state,
            &key_cache,
            empty_signed_block(&state, &spec),
            &spec,
            PqConsensusError::Local(PqConsensusLocalError::UnsupportedProfile),
        );
        assert_eq!(
            per_slot_processing_pq(&mut state, &spec),
            Err(PqTransitionError::Invalidated(PqConsensusError::Local(
                PqConsensusLocalError::UnsupportedProfile,
            )))
        );
        assert_eq!(
            state, before,
            "profile rejection must precede slot mutation"
        );
    }
}

#[test]
fn pq_slot_wrapper_runs_normal_epoch_processing() {
    let spec = electra_spec();
    let mut state = genesis_state(16, &spec);
    let mut epoch_summary_seen = false;

    for _ in 0..MinimalEthSpec::slots_per_epoch() {
        epoch_summary_seen |= per_slot_processing_pq(&mut state, &spec)
            .expect("supported V1 slot processing")
            .is_some();
    }

    assert_eq!(state.slot(), Slot::new(MinimalEthSpec::slots_per_epoch()));
    assert!(epoch_summary_seen, "epoch processing runs at the boundary");
    assert_eq!(state.validators().len(), 16);
}
