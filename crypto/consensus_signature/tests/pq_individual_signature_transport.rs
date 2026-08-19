#![cfg(feature = "pq-wire")]

use consensus_signature::{
    IndividualSignatureTransportError, PQ_RAW_SIGNATURE_LEN, PqRawSignature,
    SerializedIndividualSignature, decode_individual_signature, is_verification_skip_placeholder,
    serialize_individual_signature,
};

fn distinctive_signature() -> ([u8; PQ_RAW_SIGNATURE_LEN], PqRawSignature) {
    let mut bytes = [0; PQ_RAW_SIGNATURE_LEN];
    bytes[..7].copy_from_slice(b"LHPQ\x01\x01\x00");
    for (index, byte) in bytes[7..].iter_mut().enumerate() {
        *byte = (index % 251 + 1) as u8;
    }
    let signature = PqRawSignature::from_bytes(&bytes).expect("structurally valid PQ signature");
    (bytes, signature)
}

#[test]
fn pq_individual_signature_transport_preserves_the_strict_wire_value() {
    let (expected_bytes, signature) = distinctive_signature();
    let serialized = serialize_individual_signature(&signature);

    let _: SerializedIndividualSignature = serialized.clone();
    assert_eq!(serialized.as_bytes(), expected_bytes.as_slice());
    assert_eq!(serialized, signature);
    let decoded = decode_individual_signature(&serialized).expect("strict PQ transport decode");
    assert_eq!(decoded.as_bytes(), expected_bytes.as_slice());
    assert_eq!(decoded, signature);
    assert!(!is_verification_skip_placeholder(&signature));
}

#[test]
fn pq_transport_error_remains_typed_even_though_wire_decode_is_infallible() {
    let error = IndividualSignatureTransportError::InvalidEncoding;
    assert_eq!(error.to_string(), "invalid individual signature encoding");
}
