//! Known-answer tests pinning leanXMSS verification (`lean_pq::xmss`) and the EIP-8450 proof of
//! possession to EIP-CRYPTO v1.
//!
//! The vectors in `xmss_known_answer.txt` come from an independent Python signer over the
//! EIP-CRYPTO pseudocode, which also decided every expected outcome; see the header of that file.

use bls::PublicKeyBytes;
use lean_pq::{Error, xmss};
use state_processing::per_block_processing::{
    get_pq_possession_signing_root, is_valid_pq_possession_proof,
};
use std::collections::HashMap;
use types::test_utils::generate_deterministic_keypair;
use types::{
    BeaconState, ChainSpec, Eth1Data, Hash256, MinimalEthSpec, XmssPublicKey, XmssSignature,
};

const VECTORS: &str = include_str!("xmss_known_answer.txt");

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct Vectors<'a> {
    keys: HashMap<&'a str, Vec<u8>>,
    sigs: HashMap<&'a str, (u32, Vec<u8>)>,
    cases: Vec<Vec<&'a str>>,
    possessions: Vec<Vec<&'a str>>,
}

fn vectors() -> Vectors<'static> {
    let mut vectors = Vectors {
        keys: HashMap::new(),
        sigs: HashMap::new(),
        cases: vec![],
        possessions: vec![],
    };
    for line in VECTORS
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let fields: Vec<&str> = line.split(' ').collect();
        match fields[0] {
            "key" => {
                vectors.keys.insert(fields[1], hex(fields[2]));
            }
            "sig" => {
                vectors
                    .sigs
                    .insert(fields[1], (fields[2].parse().unwrap(), hex(fields[3])));
            }
            "case" => vectors.cases.push(fields),
            "possession" => vectors.possessions.push(fields),
            other => panic!("unknown record {other}"),
        }
    }
    vectors
}

/// Applies `<offset>:<hex>` (overwrite, extending if needed) or `<offset>:cut` (truncate).
fn patch(bytes: &mut Vec<u8>, patch: &str) {
    let (offset, data) = patch.split_once(':').unwrap();
    let offset: usize = offset.parse().unwrap();
    if data == "cut" {
        bytes.truncate(offset);
    } else {
        let data = hex(data);
        bytes.resize(bytes.len().max(offset + data.len()), 0);
        bytes[offset..offset + data.len()].copy_from_slice(&data);
    }
}

/// The outcome of `lean_pq::xmss` on the inputs, in the fixture's terms.
fn lean_pq_outcome(public_key: &[u8], message: &[u8; 32], signature: &[u8]) -> &'static str {
    let (public_key, signature) = match (
        xmss::PublicKey::from_bytes(public_key),
        xmss::Signature::from_bytes(signature),
    ) {
        (Ok(public_key), Ok(signature)) => (public_key, signature),
        (Err(Error::InvalidLength { .. }), _) | (_, Err(Error::InvalidLength { .. })) => {
            return "length";
        }
        (Err(e), _) | (_, Err(e)) => panic!("unexpected decoding error {e:?}"),
    };
    // The leaf index is the little-endian u32 in bytes 0..4 of the signature.
    let bytes = signature.to_bytes();
    assert_eq!(
        signature.leaf_index(),
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    );
    match public_key.verify(message, &signature) {
        Ok(()) => "accept",
        Err(Error::XmssVerify { leaf_index, reason }) => {
            assert_eq!(leaf_index, signature.leaf_index());
            match format!("{reason:?}").as_str() {
                // lean-pq reports a non-codeword digest of either layer as `InvalidEncoding`, and a
                // top root that differs from the public key as `InvalidMerklePath`.
                "InvalidEncoding" => "digest",
                "InvalidMerklePath" => "root",
                other => panic!("unexpected verification error {other}"),
            }
        }
        Err(e) => panic!("unexpected error {e:?}"),
    }
}

#[test]
fn signatures_and_keys_decode_to_their_bytes_and_leaf_index() {
    let vectors = vectors();
    assert_eq!(vectors.keys.len(), 3);
    for (name, public_key) in &vectors.keys {
        let decoded = xmss::PublicKey::from_bytes(public_key).unwrap();
        assert_eq!(decoded.to_bytes().as_slice(), public_key, "key {name}");
    }
    let mut indices: Vec<u32> = vectors.sigs.values().map(|(index, _)| *index).collect();
    indices.sort_unstable();
    indices.dedup();
    assert_eq!(indices, [0, 1, 0xFFFF, 0x1_0000, 0x89AB_CDEF, u32::MAX]);
    for (name, (index, signature)) in &vectors.sigs {
        let decoded = xmss::Signature::from_bytes(signature).unwrap();
        assert_eq!(decoded.to_bytes().as_slice(), signature, "signature {name}");
        assert_eq!(decoded.leaf_index(), *index, "signature {name}");
        assert_eq!(
            u32::from_le_bytes(signature[..4].try_into().unwrap()),
            *index,
            "signature {name}"
        );
    }
}

#[test]
fn lean_pq_matches_every_eip_crypto_outcome() {
    let vectors = vectors();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let mut mismatches = vec![];
    for fields in &vectors.cases {
        let [_, name, expected, key, message, sig, patches @ ..] = fields.as_slice() else {
            panic!("malformed case {fields:?}");
        };
        let mut public_key = vectors.keys[key].clone();
        let mut signature = vectors.sigs[sig].1.clone();
        for p in patches {
            match p.split_once(':').unwrap() {
                ("pk", p) => patch(&mut public_key, p),
                ("sig", p) => patch(&mut signature, p),
                other => panic!("unknown patch {other:?}"),
            }
        }
        let message: [u8; 32] = hex(message).try_into().unwrap();
        let outcome = lean_pq_outcome(&public_key, &message, &signature);
        let expected_outcome = match *expected {
            "bottom_digest" | "top_digest" => "digest",
            other => other,
        };
        if outcome != expected_outcome {
            mismatches.push(format!("{name}: EIP-CRYPTO {expected}, lean-pq {outcome}"));
        }
        *counts.entry(*expected).or_default() += 1;
    }
    eprintln!("{} cases: {counts:?}", vectors.cases.len());
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    assert_eq!(counts["accept"], vectors.sigs.len());
    for outcome in ["bottom_digest", "top_digest", "root", "length"] {
        assert!(
            counts.get(outcome).copied().unwrap_or(0) > 0,
            "no {outcome} case"
        );
    }
}

#[test]
fn possession_proofs_match_eip_8450() {
    let vectors = vectors();
    let spec = ChainSpec::minimal();
    assert_eq!(vectors.possessions.len(), 5);
    for fields in &vectors.possessions {
        let [
            _,
            name,
            expected,
            key,
            sig,
            fork_version,
            gvr,
            validator_index,
            validator_pubkey,
            signing_root,
        ] = fields.as_slice()
        else {
            panic!("malformed possession {fields:?}");
        };
        assert_eq!(hex(fork_version), spec.genesis_fork_version, "{name}");
        let mut state = BeaconState::<MinimalEthSpec>::new(0, Eth1Data::default(), &spec);
        *state.genesis_validators_root_mut() = Hash256::from_slice(&hex(gvr));
        // The proof binds the key to the BLS public key of interop validator `validator_index`.
        let validator_pubkey = PublicKeyBytes::deserialize(&hex(validator_pubkey)).unwrap();
        assert_eq!(
            validator_pubkey,
            generate_deterministic_keypair(validator_index.parse().unwrap())
                .pk
                .compress(),
            "{name}"
        );
        let public_key = XmssPublicKey::new(vectors.keys[key].clone()).unwrap();
        let proof = XmssSignature::new(vectors.sigs[sig].1.clone()).unwrap();

        assert_eq!(
            get_pq_possession_signing_root(&state, &validator_pubkey, &public_key, &spec),
            Hash256::from_slice(&hex(signing_root)),
            "{name}"
        );
        let valid =
            is_valid_pq_possession_proof(&state, &validator_pubkey, &public_key, &proof, &spec);
        assert_eq!(valid, *expected == "accept", "{name}");
    }
}
