use consensus_signature::{LEAN_PQ_DEVNET_V1_MAX_SLOT, OneTimeUseId, SigningDuty, SigningIdError};

fn all_duties() -> [SigningDuty; 14] {
    [
        SigningDuty::RandaoReveal,
        SigningDuty::BeaconBlockProposal,
        SigningDuty::Attestation,
        SigningDuty::AttestationSelectionProof,
        SigningDuty::AggregateAndProof,
        SigningDuty::SyncCommitteeMessage,
        SigningDuty::sync_selection_proof(0).expect("subcommittee zero is supported"),
        SigningDuty::sync_selection_proof(1).expect("subcommittee one is supported"),
        SigningDuty::sync_selection_proof(2).expect("subcommittee two is supported"),
        SigningDuty::sync_selection_proof(3).expect("subcommittee three is supported"),
        SigningDuty::sync_contribution_and_proof(0).expect("subcommittee zero is supported"),
        SigningDuty::sync_contribution_and_proof(1).expect("subcommittee one is supported"),
        SigningDuty::sync_contribution_and_proof(2).expect("subcommittee two is supported"),
        SigningDuty::sync_contribution_and_proof(3).expect("subcommittee three is supported"),
    ]
}

#[test]
fn lean_pq_devnet_v1_assigns_all_fourteen_offsets_explicitly() {
    let actual = all_duties()
        .into_iter()
        .map(|duty| {
            OneTimeUseId::for_lean_pq_devnet_v1(0, duty)
                .expect("slot zero is supported")
                .as_u32()
        })
        .collect::<Vec<_>>();

    assert_eq!(actual, (0..=13).collect::<Vec<_>>());
}

#[test]
fn duty_and_slot_identify_one_reproducible_leaf() {
    let slot = 42;
    let attestation = OneTimeUseId::for_lean_pq_devnet_v1(slot, SigningDuty::Attestation)
        .expect("slot is supported");
    let retry = OneTimeUseId::for_lean_pq_devnet_v1(slot, SigningDuty::Attestation)
        .expect("slot is supported");
    let proposal = OneTimeUseId::for_lean_pq_devnet_v1(slot, SigningDuty::BeaconBlockProposal)
        .expect("slot is supported");

    assert_eq!(attestation, retry);
    assert_ne!(attestation, proposal);
}

#[test]
fn adjacent_slot_rows_are_injective() {
    let first_slot = all_duties()
        .into_iter()
        .map(|duty| {
            OneTimeUseId::for_lean_pq_devnet_v1(1_024, duty)
                .expect("slot is supported")
                .as_u32()
        })
        .collect::<Vec<_>>();
    let next_slot = all_duties()
        .into_iter()
        .map(|duty| {
            OneTimeUseId::for_lean_pq_devnet_v1(1_025, duty)
                .expect("slot is supported")
                .as_u32()
        })
        .collect::<Vec<_>>();

    assert!(first_slot.iter().all(|leaf| !next_slot.contains(leaf)));
}

#[test]
fn v1_rejects_out_of_range_sync_subcommittees() {
    for index in [4, u64::MAX] {
        assert_eq!(
            SigningDuty::sync_selection_proof(index),
            Err(SigningIdError::UnsupportedSyncSubcommittee(index))
        );
        assert_eq!(
            SigningDuty::sync_contribution_and_proof(index),
            Err(SigningIdError::UnsupportedSyncSubcommittee(index))
        );
    }
}

#[test]
fn v1_rejects_slots_without_a_complete_duty_row() {
    let maximum_complete_slot = 306_783_377;
    let first_unsupported_slot = 306_783_378;

    assert_eq!(LEAN_PQ_DEVNET_V1_MAX_SLOT, maximum_complete_slot);
    for duty in all_duties() {
        OneTimeUseId::for_lean_pq_devnet_v1(maximum_complete_slot, duty)
            .expect("the maximum complete slot row is supported");
        assert_eq!(
            OneTimeUseId::for_lean_pq_devnet_v1(first_unsupported_slot, duty),
            Err(SigningIdError::SlotOutOfRange(first_unsupported_slot))
        );
    }

    let final_leaf = OneTimeUseId::for_lean_pq_devnet_v1(
        maximum_complete_slot,
        SigningDuty::sync_contribution_and_proof(3).expect("subcommittee three is supported"),
    )
    .expect("the final V1 duty is supported at the maximum slot");
    assert_eq!(final_leaf.as_u32(), 4_294_967_291);
}
