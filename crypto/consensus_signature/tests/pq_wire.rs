#![cfg(feature = "pq-devnet")]

use consensus_signature::pq::{PQ_RAW_SIGNATURE_LEN, PqRawSignature, PqWireError};

const HEADER_LEN: usize = 7;

fn raw_bytes() -> Vec<u8> {
    let mut bytes = vec![0; PQ_RAW_SIGNATURE_LEN];
    bytes[..4].copy_from_slice(b"LHPQ");
    bytes[4] = 1;
    bytes[5] = 1;
    bytes[6] = 0;
    bytes
}

#[test]
fn raw_signature_accepts_only_the_frozen_lighthouse_envelope() {
    let bytes = raw_bytes();
    let signature = PqRawSignature::from_bytes(&bytes).expect("valid raw envelope");

    assert_eq!(bytes.len(), 1_215);
    assert_eq!(signature.as_bytes(), bytes);
}

#[test]
fn raw_signature_rejects_bad_magic() {
    let mut bytes = raw_bytes();
    bytes[..4].copy_from_slice(b"BAD!");

    assert_eq!(
        PqRawSignature::from_bytes(&bytes),
        Err(PqWireError::BadMagic)
    );
}

#[test]
fn raw_signature_rejects_unknown_wire_version() {
    let mut bytes = raw_bytes();
    bytes[4] = 2;

    assert_eq!(
        PqRawSignature::from_bytes(&bytes),
        Err(PqWireError::UnsupportedWireVersion(2))
    );
}

#[test]
fn raw_signature_rejects_unknown_parameter_set() {
    let mut bytes = raw_bytes();
    bytes[5] = 2;

    assert_eq!(
        PqRawSignature::from_bytes(&bytes),
        Err(PqWireError::UnsupportedParameterSet(2))
    );
}

#[test]
fn raw_signature_rejects_unknown_evidence_kind() {
    let mut bytes = raw_bytes();
    bytes[6] = 0xff;

    assert_eq!(
        PqRawSignature::from_bytes(&bytes),
        Err(PqWireError::UnsupportedEvidenceKind(0xff))
    );
}

#[test]
fn individual_field_rejects_aggregate_kind_and_absent_length() {
    let mut aggregate = raw_bytes();
    aggregate[6] = 1;
    let absent = b"LHPQ\x01\x01\x02";

    assert_eq!(
        PqRawSignature::from_bytes(&aggregate),
        Err(PqWireError::WrongEvidenceKind(1))
    );
    assert_eq!(
        PqRawSignature::from_bytes(absent),
        Err(PqWireError::InvalidLength {
            actual: 7,
            expected: PQ_RAW_SIGNATURE_LEN,
        })
    );
}

#[test]
fn raw_signature_rejects_short_and_long_payloads() {
    let mut short = raw_bytes();
    short.pop();
    let mut long = raw_bytes();
    long.push(0);

    assert_eq!(
        PqRawSignature::from_bytes(&short),
        Err(PqWireError::InvalidLength {
            actual: PQ_RAW_SIGNATURE_LEN - 1,
            expected: PQ_RAW_SIGNATURE_LEN,
        })
    );
    assert_eq!(
        PqRawSignature::from_bytes(&long),
        Err(PqWireError::InvalidLength {
            actual: PQ_RAW_SIGNATURE_LEN + 1,
            expected: PQ_RAW_SIGNATURE_LEN,
        })
    );
    assert_eq!(short.len(), HEADER_LEN + 1_207);
}
