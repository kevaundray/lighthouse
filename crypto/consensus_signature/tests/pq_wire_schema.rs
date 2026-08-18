#![cfg(feature = "pq-wire")]

use consensus_signature::{
    AggregateSignature, IndividualSignature, PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN, PQ_PUBLIC_KEY_LEN,
    PQ_RAW_SIGNATURE_LEN, PqPublicKey, PqRawSignature, PqSameMessageEvidence, PqWireError,
    RawSignature, SameMessageEvidence, ValidatorPublicKeyBytes, VerificationKey,
};
use serde::{Deserialize, Deserializer};
use ssz::{Decode, Encode};
use std::str::FromStr;
use tree_hash::TreeHash;

const HEADER_LEN: usize = 7;

fn public_key_bytes() -> [u8; PQ_PUBLIC_KEY_LEN] {
    std::array::from_fn(|index| index as u8)
}

fn raw_bytes() -> Vec<u8> {
    let mut bytes = vec![0; PQ_RAW_SIGNATURE_LEN];
    bytes[..HEADER_LEN].copy_from_slice(b"LHPQ\x01\x01\x00");
    bytes[PQ_RAW_SIGNATURE_LEN - 1] = 0xa5;
    bytes
}

struct BorrowedStrDeserializer<'a>(&'a str);

impl<'de> Deserializer<'de> for BorrowedStrDeserializer<'de> {
    type Error = serde::de::value::Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_borrowed_str(self.0)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_borrowed_str(self.0)
    }

    fn deserialize_string<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::Error::custom("owned string requested"))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char bytes byte_buf option unit
        unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier ignored_any
    }
}

#[test]
fn active_aliases_select_the_pq_wire_types() {
    fn public_key_aliases(_: ValidatorPublicKeyBytes, _: VerificationKey) {}
    fn raw_aliases(_: IndividualSignature, _: RawSignature) {}
    fn same_message_aliases(_: SameMessageEvidence, _: AggregateSignature) {}

    let key = PqPublicKey::empty();
    let raw = PqRawSignature::empty();
    let same_message = PqSameMessageEvidence::from(&raw);

    public_key_aliases(key, key);
    raw_aliases(raw.clone(), raw);
    same_message_aliases(same_message.clone(), same_message);
}

#[test]
fn serde_borrows_and_rejects_overlength_hex_before_decoding() {
    let valid_key = format!("0x{}", "00".repeat(PQ_PUBLIC_KEY_LEN));
    assert_eq!(
        <PqPublicKey as Deserialize>::deserialize(BorrowedStrDeserializer(&valid_key)),
        Ok(PqPublicKey::empty())
    );

    let oversized_key = format!("0x{}", "00".repeat(PQ_PUBLIC_KEY_LEN + 1));
    let key_error =
        <PqPublicKey as Deserialize>::deserialize(BorrowedStrDeserializer(&oversized_key))
            .expect_err("oversized public key must be rejected");
    assert_eq!(
        key_error.to_string(),
        "invalid PQ wire length 33, expected 32"
    );

    let oversized_raw = format!("0x{}", "00".repeat(PQ_RAW_SIGNATURE_LEN + 1));
    let raw_error =
        <PqRawSignature as Deserialize>::deserialize(BorrowedStrDeserializer(&oversized_raw))
            .expect_err("oversized raw signature must be rejected");
    assert_eq!(
        raw_error.to_string(),
        "invalid PQ wire length 1216, expected 1215"
    );

    let oversized_evidence = format!("0x{}", "00".repeat(PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN + 1));
    let evidence_error = <PqSameMessageEvidence as Deserialize>::deserialize(
        BorrowedStrDeserializer(&oversized_evidence),
    )
    .expect_err("oversized same-message evidence must be rejected");
    assert_eq!(
        evidence_error.to_string(),
        format!(
            "PQ evidence length {} exceeds maximum {}",
            PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN + 1,
            PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN
        )
    );
}

#[test]
fn public_key_has_frozen_fixed_wire_schema() {
    const EXPECTED_JSON: &str =
        "\"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\"";
    const EXPECTED_TREE_ROOT: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    let bytes = public_key_bytes();
    let key = PqPublicKey::deserialize(&bytes).expect("32-byte public key");

    assert!(<PqPublicKey as Encode>::is_ssz_fixed_len());
    assert_eq!(<PqPublicKey as Encode>::ssz_fixed_len(), 32);
    assert_eq!(key.as_ssz_bytes(), bytes);
    assert_eq!(PqPublicKey::from_ssz_bytes(&bytes), Ok(key));
    assert_eq!(key.serialize(), bytes);
    assert_eq!(*key.as_serialized(), bytes);
    assert_eq!(key.to_string(), &EXPECTED_JSON[1..EXPECTED_JSON.len() - 1]);
    assert_eq!(format!("{key:?}"), key.to_string());
    assert_eq!(PqPublicKey::from_str(&key.to_string()), Ok(key));
    assert_eq!(
        serde_json::to_string(&key).expect("serialize key"),
        EXPECTED_JSON
    );
    assert_eq!(
        serde_json::from_str::<PqPublicKey>(EXPECTED_JSON).expect("deserialize key"),
        key
    );
    assert_eq!(hex::encode(key.tree_hash_root()), EXPECTED_TREE_ROOT);

    assert!(PqPublicKey::deserialize(&bytes[..31]).is_err());
    assert!(PqPublicKey::deserialize(&[0; 33]).is_err());
    assert!(PqPublicKey::from_str(&key.to_string().to_uppercase()).is_err());
}

#[test]
fn raw_signature_has_frozen_fixed_wire_schema() {
    const EXPECTED_JSON: &str = include_str!("goldens/pq_raw_signature.json");
    const EXPECTED_TREE_ROOT: &str =
        "4577b748a6105cd6f57b0510dd5b50fa51e1857abf338a69dc8f1275e01a0d03";

    let bytes = raw_bytes();
    let signature = PqRawSignature::from_bytes(&bytes).expect("canonical raw signature");

    assert!(<PqRawSignature as Encode>::is_ssz_fixed_len());
    assert_eq!(<PqRawSignature as Encode>::ssz_fixed_len(), 1_215);
    assert_eq!(signature.as_ssz_bytes(), bytes);
    assert_eq!(
        PqRawSignature::from_ssz_bytes(&bytes),
        Ok(signature.clone())
    );
    assert_eq!(
        PqRawSignature::from_str(&signature.to_string()),
        Ok(signature.clone())
    );
    assert_eq!(
        serde_json::to_string(&signature).expect("serialize signature"),
        EXPECTED_JSON.trim()
    );
    assert_eq!(
        serde_json::from_str::<PqRawSignature>(EXPECTED_JSON.trim())
            .expect("deserialize signature"),
        signature
    );
    assert_eq!(hex::encode(signature.tree_hash_root()), EXPECTED_TREE_ROOT);
}

#[test]
fn raw_signature_checks_exact_length_before_header_fields() {
    let mut short_bad_magic = raw_bytes();
    short_bad_magic.pop();
    short_bad_magic[..4].copy_from_slice(b"BAD!");
    let mut long_bad_magic = raw_bytes();
    long_bad_magic.push(0);
    long_bad_magic[..4].copy_from_slice(b"BAD!");

    assert_eq!(
        PqRawSignature::from_bytes(&short_bad_magic),
        Err(PqWireError::InvalidLength {
            actual: 1_214,
            expected: 1_215,
        })
    );
    assert_eq!(
        PqRawSignature::from_bytes(&long_bad_magic),
        Err(PqWireError::InvalidLength {
            actual: 1_216,
            expected: 1_215,
        })
    );

    for (index, expected) in [
        (0, PqWireError::BadMagic),
        (4, PqWireError::UnsupportedWireVersion(2)),
        (5, PqWireError::UnsupportedParameterSet(2)),
        (6, PqWireError::WrongEvidenceKind(1)),
    ] {
        let mut malformed = raw_bytes();
        malformed[index] = if index == 0 {
            b'B'
        } else if index == 6 {
            1
        } else {
            2
        };
        assert_eq!(PqRawSignature::from_bytes(&malformed), Err(expected));
    }
}

#[test]
fn same_message_evidence_is_bounded_variable_ssz_from_v1() {
    const EXPECTED_RAW_JSON: &str = include_str!("goldens/pq_raw_signature.json");
    const EXPECTED_RAW_ROOT: &str =
        "e4c699ee3e7ac6d4c861ecdccd905f1d151dd4c107a06d0ef3f98704fa233e76";
    const EXPECTED_ABSENT_ROOT: &str =
        "9e81a821e6fdaaa4a3fa4193da54a77a8265c80f88f9de209a9430c23ecbd671";
    const EXPECTED_AGGREGATE_ROOT: &str =
        "1fb03994282f6afb35f9656c639afc64e3ff90cba3b978e58e30138925225366";

    let raw = PqRawSignature::from_bytes(&raw_bytes()).expect("canonical raw signature");
    let promoted = PqSameMessageEvidence::from(&raw);
    let absent = PqSameMessageEvidence::empty();
    let aggregate_bytes = b"LHPQ\x01\x01\x01\xa1\xb2\xc3";
    let aggregate =
        PqSameMessageEvidence::from_bytes(aggregate_bytes).expect("framed aggregate evidence");

    assert!(!<PqSameMessageEvidence as Encode>::is_ssz_fixed_len());
    assert_eq!(promoted.as_ssz_bytes(), raw.as_bytes());
    assert_eq!(absent.as_ssz_bytes(), b"LHPQ\x01\x01\x02");
    assert_eq!(aggregate.as_ssz_bytes(), aggregate_bytes);
    assert_eq!(
        serde_json::to_string(&promoted).expect("serialize promoted evidence"),
        EXPECTED_RAW_JSON.trim()
    );
    assert_eq!(
        serde_json::to_string(&absent).expect("serialize absent evidence"),
        "\"0x4c485051010102\""
    );
    assert_eq!(
        serde_json::to_string(&aggregate).expect("serialize aggregate evidence"),
        "\"0x4c485051010101a1b2c3\""
    );
    assert_eq!(hex::encode(promoted.tree_hash_root()), EXPECTED_RAW_ROOT);
    assert_eq!(hex::encode(absent.tree_hash_root()), EXPECTED_ABSENT_ROOT);
    assert_eq!(
        hex::encode(aggregate.tree_hash_root()),
        EXPECTED_AGGREGATE_ROOT
    );
    assert_eq!(
        PqSameMessageEvidence::from_ssz_bytes(promoted.as_bytes()),
        Ok(promoted)
    );
    assert_eq!(
        PqSameMessageEvidence::from_ssz_bytes(absent.as_bytes()),
        Ok(absent)
    );
    assert_eq!(
        PqSameMessageEvidence::from_ssz_bytes(aggregate.as_bytes()),
        Ok(aggregate)
    );
}

#[test]
fn same_message_evidence_rejects_malformed_or_oversized_envelopes() {
    let mut oversized = vec![0; PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN + 1];
    oversized[..HEADER_LEN].copy_from_slice(b"LHPQ\x01\x01\x01");

    assert_eq!(
        PqSameMessageEvidence::from_bytes(&oversized),
        Err(PqWireError::EvidenceTooLarge {
            actual: PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN + 1,
            max: PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN,
        })
    );
    assert_eq!(
        PqSameMessageEvidence::from_bytes(b"LHPQ\x01\x01\x01"),
        Err(PqWireError::InvalidAggregateLength(7))
    );
    assert_eq!(
        PqSameMessageEvidence::from_bytes(b"LHPQ\x01\x01\x02\x00"),
        Err(PqWireError::InvalidAbsentLength(8))
    );
    assert_eq!(
        PqSameMessageEvidence::from_bytes(b"LHPQ\x01\x01\xff"),
        Err(PqWireError::UnsupportedEvidenceKind(0xff))
    );
}
