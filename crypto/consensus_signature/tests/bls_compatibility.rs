#![cfg(not(feature = "pq-wire"))]

use bls::SecretKey;
use consensus_signature::{
    AggregateSignature, AggregateVerificationRequest, Hash256, IndividualSignatureTransportError,
    RawVerificationRequest, SerializedIndividualSignature, SigningClaim, VerificationRequest,
    VerifyError, decode_individual_signature, is_verification_skip_placeholder,
    serialize_individual_signature, verify, verify_all,
};

fn deterministic_secret_key(value: u64) -> SecretKey {
    let mut secret_key_bytes = [0; 32];
    secret_key_bytes[24..].copy_from_slice(&value.to_be_bytes());
    SecretKey::deserialize(&secret_key_bytes).expect("non-zero deterministic secret key")
}

#[test]
fn bls_backend_verifies_raw_and_aggregate_evidence() {
    let first_secret_key = deterministic_secret_key(1);
    let second_secret_key = deterministic_secret_key(2);
    let third_secret_key = deterministic_secret_key(3);
    let first_public_key = first_secret_key.public_key();
    let second_public_key = second_secret_key.public_key();
    let third_public_key = third_secret_key.public_key();
    let claim = SigningClaim::new(Hash256::repeat_byte(42));

    let first_signature = first_secret_key.sign(claim.signing_root());
    let second_signature = second_secret_key.sign(claim.signing_root());
    let raw_request = RawVerificationRequest::new(claim, &first_public_key, &first_signature);
    assert_eq!(verify(raw_request.into()), Ok(()));

    let mut aggregate_signature = AggregateSignature::from(&first_signature);
    aggregate_signature.add_assign(&second_signature);
    let public_keys = [&first_public_key, &second_public_key];
    let aggregate_request =
        AggregateVerificationRequest::new(claim, &public_keys, &aggregate_signature);
    assert_eq!(verify(aggregate_request.into()), Ok(()));
    assert_eq!(
        verify_all([
            VerificationRequest::from(raw_request),
            VerificationRequest::from(aggregate_request),
        ]),
        Ok(())
    );

    let wrong_claim = SigningClaim::new(Hash256::repeat_byte(43));
    let wrong_raw_root_request =
        RawVerificationRequest::new(wrong_claim, &first_public_key, &first_signature);
    assert_eq!(
        verify(wrong_raw_root_request.into()),
        Err(VerifyError::InvalidEvidence)
    );

    let wrong_aggregate_root_request =
        AggregateVerificationRequest::new(wrong_claim, &public_keys, &aggregate_signature);
    assert_eq!(
        verify(wrong_aggregate_root_request.into()),
        Err(VerifyError::InvalidEvidence)
    );
    assert_eq!(
        verify_all([
            VerificationRequest::from(raw_request),
            VerificationRequest::from(wrong_aggregate_root_request),
        ]),
        Err(VerifyError::InvalidEvidence)
    );

    let wrong_public_keys = [&first_public_key, &third_public_key];
    let wrong_aggregate_key_request =
        AggregateVerificationRequest::new(claim, &wrong_public_keys, &aggregate_signature);
    assert_eq!(
        verify(wrong_aggregate_key_request.into()),
        Err(VerifyError::InvalidEvidence)
    );
    assert_eq!(
        verify_all([
            VerificationRequest::from(raw_request),
            VerificationRequest::from(wrong_aggregate_key_request),
        ]),
        Err(VerifyError::InvalidEvidence)
    );
}

#[test]
fn verification_errors_distinguish_invalid_evidence_from_local_failures() {
    for local_failure in [
        VerifyError::LocalUnavailable,
        VerifyError::ResourceExhausted,
        VerifyError::Internal,
    ] {
        assert_ne!(VerifyError::InvalidEvidence, local_failure);
    }
}

#[test]
fn bls_individual_signature_transport_is_byte_compatible() {
    let secret_key = deterministic_secret_key(9);
    let signature = secret_key.sign(Hash256::repeat_byte(7));
    let serialized = serialize_individual_signature(&signature);
    let expected = SerializedIndividualSignature::from(signature.clone());

    assert_eq!(serialized, expected);
    assert_eq!(
        decode_individual_signature(&serialized),
        Ok(signature.clone())
    );
    assert!(!is_verification_skip_placeholder(&signature));

    let infinity = bls::Signature::infinity().expect("BLS infinity signature");
    assert!(is_verification_skip_placeholder(&infinity));
}

#[test]
fn bls_individual_signature_transport_has_a_stable_decode_error() {
    let malformed = SerializedIndividualSignature::empty();
    assert_eq!(
        decode_individual_signature(&malformed),
        Err(IndividualSignatureTransportError::InvalidEncoding)
    );
}
