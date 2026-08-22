use beacon_chain::{
    PqBlockProductionError, PqBlockProductionLocalError, PqForkChoiceAttestationError,
    testing_only_map_pq_attestation_assembly_error,
};
use operation_pool::{PqAttestationPoolInsertInvariant, PqRetainedAttestationAssemblyError};
use state_processing::{
    PqBlockAttestationSelectionError, PqBlockAttestationSelectionLocalError, PqConsensusError,
    PqConsensusInvalid, PqConsensusLocalError, PqLocalBlockError, PqLocalBlockInvalid,
};
use std::error::Error;
use types::{BeaconStateError, Hash256};

#[test]
fn pq_attestation_pool_testing_dependency_disables_defaults_explicitly() {
    let testing_manifest = include_str!("../Cargo.toml");
    assert!(testing_manifest.contains(
        "operation_pool = { workspace = true, optional = true, default-features = false }",
    ));
}

#[test]
fn pq_attestation_pool_source_and_classifier_are_not_public_capabilities() {
    let source = include_str!("../../../beacon_node/operation_pool/src/pq_runtime.rs");
    assert!(
        !source.contains("pub enum PqAttestationPoolSource"),
        "source selection belongs to private chain forwarders",
    );
    assert!(
        !source.contains("pub fn classify_pq_attestation_pool_insert"),
        "the exhaustive classifier is production-shared inside operation_pool, not public API",
    );
}

#[test]
fn pq_fork_choice_pool_error_preserves_typed_source() {
    let invariant = PqAttestationPoolInsertInvariant::GenerationExhausted;
    let error = PqForkChoiceAttestationError::Pool(invariant);
    assert_eq!(
        error.source().map(ToString::to_string),
        Some(invariant.to_string()),
    );
}

#[test]
fn pq_block_selection_state_error_preserves_typed_source_chain() {
    let selection_error = PqBlockAttestationSelectionError::Local(
        PqBlockAttestationSelectionLocalError::State(BeaconStateError::IncorrectStateVariant),
    );
    assert!(matches!(
        &selection_error,
        PqBlockAttestationSelectionError::Local(PqBlockAttestationSelectionLocalError::State(
            BeaconStateError::IncorrectStateVariant
        ))
    ));
    assert!(matches!(
        selection_error
            .source()
            .and_then(|source| { source.downcast_ref::<PqBlockAttestationSelectionLocalError>() }),
        Some(PqBlockAttestationSelectionLocalError::State(
            BeaconStateError::IncorrectStateVariant
        ))
    ));

    let production_error =
        PqBlockProductionError::Local(PqBlockProductionLocalError::AttestationSelection(
            PqBlockAttestationSelectionLocalError::State(BeaconStateError::IncorrectStateVariant),
        ));
    assert!(matches!(
        production_error
            .source()
            .and_then(|source| { source.downcast_ref::<PqBlockAttestationSelectionLocalError>() }),
        Some(PqBlockAttestationSelectionLocalError::State(
            BeaconStateError::IncorrectStateVariant
        ))
    ));
}

#[test]
fn pq_attestation_assembly_error_retryability_preserves_consensus_classification() {
    let terminal = [
        PqRetainedAttestationAssemblyError::LocalBlock(PqLocalBlockError::PreStateMismatch {
            expected: Hash256::ZERO,
            actual: Hash256::ZERO,
        }),
        PqRetainedAttestationAssemblyError::LocalBlock(PqLocalBlockError::Invalid(
            PqLocalBlockInvalid::AttestationBytesMismatch(0),
        )),
        PqRetainedAttestationAssemblyError::LocalBlock(PqLocalBlockError::Consensus(
            PqConsensusError::Invalid(PqConsensusInvalid::InconsistentBlockFork),
        )),
        PqRetainedAttestationAssemblyError::WrongFork,
        PqRetainedAttestationAssemblyError::Capacity,
    ];
    for error in terminal {
        let mapped = testing_only_map_pq_attestation_assembly_error(error);
        assert!(matches!(
            &mapped,
            PqBlockProductionError::AttestationSelectionInvariant
        ));
        assert!(!mapped.is_retryable());
    }

    let mapped = testing_only_map_pq_attestation_assembly_error(
        PqRetainedAttestationAssemblyError::LocalBlock(PqLocalBlockError::Consensus(
            PqConsensusError::Local(PqConsensusLocalError::StateUnavailable),
        )),
    );
    assert!(matches!(
        &mapped,
        PqBlockProductionError::Local(PqBlockProductionLocalError::LocalBlock(
            PqLocalBlockError::Consensus(PqConsensusError::Local(
                PqConsensusLocalError::StateUnavailable
            ))
        ))
    ));
    assert!(mapped.is_retryable());
}
