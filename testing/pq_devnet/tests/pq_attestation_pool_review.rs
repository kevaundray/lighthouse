use beacon_chain::PqForkChoiceAttestationError;
use operation_pool::PqAttestationPoolInsertInvariant;
use std::error::Error;

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
