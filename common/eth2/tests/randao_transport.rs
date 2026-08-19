use consensus_signature::SerializedIndividualSignature;
#[cfg(feature = "pq-wire")]
use consensus_signature::{PQ_RAW_SIGNATURE_LEN, PqRawSignature, serialize_individual_signature};
#[cfg(feature = "pq-wire")]
use eth2::Error;
#[cfg(feature = "pq-wire")]
use eth2::types::RandaoRevealQueryError;
use eth2::types::{SkipRandaoVerification, ValidatorBlocksQuery};
use eth2::{BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use std::time::Duration;
#[cfg(not(feature = "pq-wire"))]
use types::MinimalEthSpec;
use types::Slot;

fn client() -> BeaconNodeHttpClient {
    BeaconNodeHttpClient::new(
        SensitiveUrl::parse("http://127.0.0.1:5052/").expect("valid test URL"),
        Timeouts::set_all(Duration::from_secs(1)),
    )
}

#[cfg(feature = "pq-wire")]
fn distinctive_signature() -> ([u8; PQ_RAW_SIGNATURE_LEN], PqRawSignature) {
    let mut bytes = [0; PQ_RAW_SIGNATURE_LEN];
    bytes[..7].copy_from_slice(b"LHPQ\x01\x01\x00");
    for (index, byte) in bytes[7..].iter_mut().enumerate() {
        *byte = (index % 251 + 1) as u8;
    }
    let signature = PqRawSignature::from_bytes(&bytes).expect("structurally valid PQ signature");
    (bytes, signature)
}

#[cfg(not(feature = "pq-wire"))]
#[tokio::test]
async fn bls_randao_paths_remain_byte_compatible() {
    let signature = SerializedIndividualSignature::empty();
    let signature_query = signature.to_string();
    let slot = Slot::new(12);

    let v2 = client()
        .get_validator_blocks_path::<MinimalEthSpec>(
            slot,
            &signature,
            None,
            SkipRandaoVerification::Yes,
        )
        .await
        .expect("v2 path");
    assert_eq!(
        v2.as_str(),
        format!(
            "http://127.0.0.1:5052/eth/v2/validator/blocks/12?randao_reveal={signature_query}&skip_randao_verification="
        )
    );

    let v3 = client()
        .get_validator_blocks_v3_path(
            slot,
            &signature,
            None,
            SkipRandaoVerification::Yes,
            None,
            None,
        )
        .await
        .expect("v3 path");
    assert_eq!(
        v3.as_str(),
        format!(
            "http://127.0.0.1:5052/eth/v3/validator/blocks/12?randao_reveal={signature_query}&skip_randao_verification="
        )
    );

    let v4 = client()
        .get_validator_blocks_v4_path(
            slot,
            &signature,
            None,
            SkipRandaoVerification::Yes,
            None,
            None,
            None,
        )
        .await
        .expect("v4 path");
    assert_eq!(
        v4.as_str(),
        format!(
            "http://127.0.0.1:5052/eth/v4/validator/blocks/12?randao_reveal={signature_query}&skip_randao_verification="
        )
    );

    let blinded = client()
        .get_validator_blinded_blocks_path::<MinimalEthSpec>(
            slot,
            &signature,
            None,
            SkipRandaoVerification::Yes,
        )
        .await
        .expect("blinded path");
    assert_eq!(
        blinded.as_str(),
        format!(
            "http://127.0.0.1:5052/eth/v1/validator/blinded_blocks/12?randao_reveal={signature_query}&skip_randao_verification"
        )
    );
}

#[cfg(not(feature = "pq-wire"))]
#[test]
fn bls_query_decode_preserves_the_infinity_skip_rule() {
    let infinity = bls::Signature::infinity().expect("BLS infinity signature");
    let query = ValidatorBlocksQuery {
        randao_reveal: infinity.clone().into(),
        graffiti: None,
        skip_randao_verification: SkipRandaoVerification::Yes,
        include_payload: None,
        builder_boost_factor: None,
        graffiti_policy: None,
    };

    assert_eq!(query.decode_randao_reveal(), Ok(infinity));
}

#[cfg(not(feature = "pq-wire"))]
#[test]
fn query_decode_error_preserves_the_backend_transport_source() {
    use std::error::Error as _;

    let query = ValidatorBlocksQuery {
        randao_reveal: SerializedIndividualSignature::empty(),
        graffiti: None,
        skip_randao_verification: SkipRandaoVerification::No,
        include_payload: None,
        builder_boost_factor: None,
        graffiti_policy: None,
    };
    let error = query
        .decode_randao_reveal()
        .expect_err("all-zero BLS bytes must not decode");

    assert_eq!(
        error.source().map(ToString::to_string),
        Some("invalid individual signature encoding".into())
    );
}

#[cfg(feature = "pq-wire")]
#[tokio::test]
async fn pq_randao_paths_round_trip_the_strict_signature() {
    let (expected_bytes, raw_signature) = distinctive_signature();
    let signature = serialize_individual_signature(&raw_signature);
    assert_eq!(signature.as_bytes(), expected_bytes.as_slice());
    let url = client()
        .get_validator_blocks_v3_path(
            Slot::new(12),
            &signature,
            None,
            SkipRandaoVerification::No,
            None,
            None,
        )
        .await
        .expect("PQ v3 path");
    let encoded_signature = url
        .query_pairs()
        .find_map(|(key, value)| (key == "randao_reveal").then(|| value.into_owned()))
        .expect("randao query pair");

    let transported: SerializedIndividualSignature =
        serde_json::from_value(serde_json::json!(encoded_signature))
            .expect("strict URL signature round trip");
    assert_eq!(transported.as_bytes(), expected_bytes.as_slice());
    let query: ValidatorBlocksQuery = serde_json::from_value(serde_json::json!({
        "randao_reveal": signature.to_string(),
        "graffiti": null,
        "skip_randao_verification": null,
        "include_payload": null,
        "builder_boost_factor": null,
        "graffiti_policy": null
    }))
    .expect("strict query round trip");
    assert_eq!(query.randao_reveal.as_bytes(), expected_bytes.as_slice());
    let decoded = query.decode_randao_reveal().expect("strict query decode");
    assert_eq!(decoded.as_bytes(), expected_bytes.as_slice());
}

#[cfg(feature = "pq-wire")]
#[test]
fn pq_query_rejects_malformed_individual_signatures() {
    let canonical = SerializedIndividualSignature::empty().to_string();
    let mut wrong_kind = canonical.clone();
    wrong_kind.replace_range(14..16, "02");
    let mut uppercase = canonical.clone();
    uppercase.replace_range(2..4, "4C");
    let missing_prefix = canonical
        .strip_prefix("0x")
        .expect("canonical PQ hex prefix")
        .to_owned();

    for (malformed, expected_error) in [
        ("0x".to_owned(), "invalid PQ wire length"),
        (wrong_kind, "unexpected PQ evidence kind 2"),
        (uppercase, "lowercase"),
        (missing_prefix, "must start with 0x"),
    ] {
        let result = serde_json::from_value::<ValidatorBlocksQuery>(serde_json::json!({
            "randao_reveal": malformed,
            "graffiti": null,
            "skip_randao_verification": null,
            "include_payload": null,
            "builder_boost_factor": null,
            "graffiti_policy": null
        }));
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("malformed PQ signature must be rejected"),
        };
        assert!(
            error.to_string().contains(expected_error),
            "wrong error for malformed signature: {error}"
        );
    }
}

#[cfg(feature = "pq-wire")]
#[tokio::test]
async fn pq_rejects_skip_before_constructing_any_block_path() {
    let error = client()
        .get_validator_blocks_v3_path(
            Slot::new(12),
            &SerializedIndividualSignature::empty(),
            None,
            SkipRandaoVerification::Yes,
            None,
            None,
        )
        .await
        .expect_err("PQ skip must be rejected");

    assert!(matches!(error, Error::UnsupportedRandaoVerificationSkip));
}

#[cfg(feature = "pq-wire")]
#[test]
fn pq_query_decode_rejects_skip_even_for_the_canonical_empty_raw_signature() {
    let query = ValidatorBlocksQuery {
        randao_reveal: SerializedIndividualSignature::empty(),
        graffiti: None,
        skip_randao_verification: SkipRandaoVerification::Yes,
        include_payload: None,
        builder_boost_factor: None,
        graffiti_policy: None,
    };

    assert_eq!(
        query.decode_randao_reveal(),
        Err(RandaoRevealQueryError::UnsupportedVerificationSkip)
    );
}
