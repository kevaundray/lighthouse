#![cfg(feature = "pq-devnet")]

use pq_proposer_service::{
    PqBeaconFailure, PqJsonEncodingError, PqProposerConfigurationError, PqStoreFailureKind,
    PqStoreOperationError,
};

fn assert_error_type<T: std::error::Error>() {}
fn assert_public_type<T>() {}

#[test]
fn downstream_can_name_read_only_typed_proposer_errors() {
    assert_public_type::<PqBeaconFailure>();
    assert_public_type::<PqProposerConfigurationError>();
    assert_public_type::<PqStoreFailureKind>();
    assert_error_type::<PqStoreOperationError>();
    assert_error_type::<PqJsonEncodingError>();
}
