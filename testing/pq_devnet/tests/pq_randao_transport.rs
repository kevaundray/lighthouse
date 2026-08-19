use consensus_signature::{
    PQ_RAW_SIGNATURE_LEN, PqRawSignature, SerializedIndividualSignature,
    serialize_individual_signature,
};
use eth2::types::{RandaoRevealQueryError, SkipRandaoVerification, ValidatorBlocksQuery};
use eth2::{BeaconNodeHttpClient, Error, SensitiveUrl, Timeouts};
use std::time::Duration;
use types::{MinimalEthSpec, Slot};

fn client() -> BeaconNodeHttpClient {
    BeaconNodeHttpClient::new(
        SensitiveUrl::parse("http://127.0.0.1:5052/").expect("valid test URL"),
        Timeouts::set_all(Duration::from_secs(1)),
    )
}

fn distinctive_signature() -> ([u8; PQ_RAW_SIGNATURE_LEN], PqRawSignature) {
    let mut bytes = [0; PQ_RAW_SIGNATURE_LEN];
    bytes[..7].copy_from_slice(b"LHPQ\x01\x01\x00");
    for (index, byte) in bytes[7..].iter_mut().enumerate() {
        *byte = (index % 251 + 1) as u8;
    }
    let signature = PqRawSignature::from_bytes(&bytes).expect("structurally valid PQ signature");
    (bytes, signature)
}

#[tokio::test]
async fn every_pq_randao_path_round_trips_the_exact_signature_and_rejects_skip() {
    let (expected_bytes, raw_signature) = distinctive_signature();
    let signature = serialize_individual_signature(&raw_signature);
    assert_eq!(signature.as_bytes(), expected_bytes.as_slice());
    let slot = Slot::new(12);
    let paths = [
        client()
            .get_validator_blocks_path::<MinimalEthSpec>(
                slot,
                &signature,
                None,
                SkipRandaoVerification::No,
            )
            .await
            .expect("v2 path"),
        client()
            .get_validator_blocks_v3_path(
                slot,
                &signature,
                None,
                SkipRandaoVerification::No,
                None,
                None,
            )
            .await
            .expect("v3 path"),
        client()
            .get_validator_blocks_v4_path(
                slot,
                &signature,
                None,
                SkipRandaoVerification::No,
                None,
                None,
                None,
            )
            .await
            .expect("v4 path"),
        client()
            .get_validator_blinded_blocks_path::<MinimalEthSpec>(
                slot,
                &signature,
                None,
                SkipRandaoVerification::No,
            )
            .await
            .expect("blinded path"),
    ];

    for path in paths {
        let encoded_signature = path
            .query_pairs()
            .find_map(|(key, value)| (key == "randao_reveal").then(|| value.into_owned()))
            .expect("randao query pair");
        let round_trip: SerializedIndividualSignature =
            serde_json::from_value(serde_json::json!(encoded_signature))
                .expect("strict URL signature round trip");
        assert_eq!(round_trip.as_bytes(), expected_bytes.as_slice());
    }

    let query: ValidatorBlocksQuery = serde_json::from_value(serde_json::json!({
        "randao_reveal": signature.to_string(),
        "graffiti": null,
        "skip_randao_verification": null,
        "include_payload": null,
        "builder_boost_factor": null,
        "graffiti_policy": null
    }))
    .expect("strict query deserialization");
    assert_eq!(query.randao_reveal.as_bytes(), expected_bytes.as_slice());
    let decoded = query.decode_randao_reveal().expect("strict query decode");
    assert_eq!(decoded.as_bytes(), expected_bytes.as_slice());

    for endpoint in 0..4 {
        let result = match endpoint {
            0 => {
                client()
                    .get_validator_blocks_path::<MinimalEthSpec>(
                        slot,
                        &signature,
                        None,
                        SkipRandaoVerification::Yes,
                    )
                    .await
            }
            1 => {
                client()
                    .get_validator_blocks_v3_path(
                        slot,
                        &signature,
                        None,
                        SkipRandaoVerification::Yes,
                        None,
                        None,
                    )
                    .await
            }
            2 => {
                client()
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
            }
            _ => {
                client()
                    .get_validator_blinded_blocks_path::<MinimalEthSpec>(
                        slot,
                        &signature,
                        None,
                        SkipRandaoVerification::Yes,
                    )
                    .await
            }
        };
        assert!(matches!(
            result,
            Err(Error::UnsupportedRandaoVerificationSkip)
        ));
    }
}

#[test]
fn pq_query_decode_is_strict_and_never_accepts_a_skip_placeholder() {
    let signature = SerializedIndividualSignature::empty();
    let query = ValidatorBlocksQuery {
        randao_reveal: signature.clone(),
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

    let canonical = signature.to_string();
    let mut wrong_kind = canonical.clone();
    wrong_kind.replace_range(14..16, "02");
    let mut uppercase = canonical.clone();
    uppercase.replace_range(2..4, "4C");

    for (malformed, expected_error) in [
        ("0x".to_owned(), "invalid PQ wire length"),
        (wrong_kind, "unexpected PQ evidence kind 2"),
        (uppercase, "lowercase"),
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
