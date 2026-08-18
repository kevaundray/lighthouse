use bls::{
    AggregateSignature as BlsAggregateSignature, PublicKey as BlsPublicKey,
    PublicKeyBytes as BlsPublicKeyBytes, SecretKey, Signature as BlsSignature,
};
use consensus_signature::{
    AggregateSignature, IndividualSignature, RawSignature, SameMessageEvidence,
    ValidatorPublicKeyBytes, VerificationKey,
};
use ssz::Encode;
use tree_hash::TreeHash;
use types::{
    AttestationData, BeaconBlockHeader, Checkpoint, Epoch, ForkName, Hash256, MainnetEthSpec,
    SignedBeaconBlockHeader, SingleAttestation, Slot,
};

fn deterministic_secret_key(value: u64) -> SecretKey {
    let mut secret_key_bytes = [0; 32];
    secret_key_bytes[24..].copy_from_slice(&value.to_be_bytes());
    SecretKey::deserialize(&secret_key_bytes).expect("non-zero deterministic secret key")
}

#[test]
fn individual_signature_container_preserves_bls_schema() {
    const EXPECTED_SSZ_HEX: &str = concat!(
        "0b000000000000001100000000000000212121212121212121212121212121212121212121212121",
        "21212121212121213232323232323232323232323232323232323232323232323232323232323232",
        "43434343434343434343434343434343434343434343434343434343434343438d33667f53c2c70f",
        "1358fff43f35418f853d0fd7bfad5cf9c40377af61c39b87f94c0d16c927182692518ef2610105e0",
        "135402b34a6bc01799cf4c37f5031b041dc20b785881ec38058237239d91cad5021d4f889a45eda2",
        "7f6182711c4a483a",
    );
    const EXPECTED_TREE_ROOT_HEX: &str =
        "4a6fca3f9c92ffca6a6dc0a32c73a6f2c870cfbe0c089001a11ba046e5e244a1";

    let header = SignedBeaconBlockHeader {
        message: BeaconBlockHeader {
            slot: Slot::new(11),
            proposer_index: 17,
            parent_root: Hash256::repeat_byte(0x21),
            state_root: Hash256::repeat_byte(0x32),
            body_root: Hash256::repeat_byte(0x43),
        },
        signature: deterministic_secret_key(1).sign(Hash256::repeat_byte(0x54)),
    };

    assert_eq!(hex::encode(header.as_ssz_bytes()), EXPECTED_SSZ_HEX);
    assert_eq!(hex::encode(header.tree_hash_root()), EXPECTED_TREE_ROOT_HEX);
}

#[test]
fn same_message_container_preserves_bls_schema() {
    const EXPECTED_SSZ_HEX: &str = concat!(
        "030000000000000007000000000000000d0000000000000013000000000000007676767676767676",
        "76767676767676767676767676767676767676767676767617000000000000008787878787878787",
        "8787878787878787878787878787878787878787878787871d000000000000009898989898989898",
        "989898989898989898989898989898989898989898989898994aca0b61c464d3bafe28ac4389cb98",
        "d96b9403299d26b877edd89ff175dd176fed7fb13905f4ce59d202f9053826fb086c852472b6bf1f0",
        "a0144c9793330feda146433b668038c90d38540ae9d35f820b8d308b434c00a236f3b1a3c5c0c76",
    );
    const EXPECTED_TREE_ROOT_HEX: &str =
        "be829f4eaaaa6a4b57c07df0f47d78a2ad3734364409a3cc85248a2e28404c30";

    let individual = deterministic_secret_key(2).sign(Hash256::repeat_byte(0x65));
    let attestation = SingleAttestation {
        committee_index: 3,
        attester_index: 7,
        data: AttestationData {
            slot: Slot::new(13),
            index: 19,
            beacon_block_root: Hash256::repeat_byte(0x76),
            source: Checkpoint {
                epoch: Epoch::new(23),
                root: Hash256::repeat_byte(0x87),
            },
            target: Checkpoint {
                epoch: Epoch::new(29),
                root: Hash256::repeat_byte(0x98),
            },
        },
        signature: SameMessageEvidence::from(&individual),
    };

    assert_eq!(hex::encode(attestation.as_ssz_bytes()), EXPECTED_SSZ_HEX);
    assert_eq!(
        hex::encode(attestation.tree_hash_root()),
        EXPECTED_TREE_ROOT_HEX
    );
}

#[test]
fn single_attestation_promotes_same_message_evidence_without_reencoding() {
    let individual: IndividualSignature = deterministic_secret_key(2).sign([24; 32].into());
    let same_message = SameMessageEvidence::from(&individual);
    let attestation = SingleAttestation {
        committee_index: 3,
        attester_index: 7,
        data: AttestationData::default(),
        signature: same_message.clone(),
    };

    let indexed = attestation
        .to_indexed::<MainnetEthSpec>(ForkName::Electra)
        .expect("one attesting index is within the mainnet bound");

    assert_eq!(
        attestation.signature.as_ssz_bytes(),
        same_message.as_ssz_bytes()
    );
    assert_eq!(
        indexed.signature().as_ssz_bytes(),
        same_message.as_ssz_bytes()
    );
    assert_eq!(
        indexed.signature().tree_hash_root(),
        same_message.tree_hash_root()
    );
}

#[test]
fn semantic_aliases_retain_the_exact_bls_types() {
    const EXPECTED_PUBLIC_KEY_JSON: &str = concat!(
        "\"0x89ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff9",
        "81747a0b2ca2179b96d2c0c9024e5224\"",
    );
    const EXPECTED_SIGNATURE_JSON: &str = concat!(
        "\"0xb3b4cd91fca6390da9e32c6fefccd3f3f874da4c117d2ac9199e8d325540f1b7",
        "ddcdaf54db2dca22d2b8d59f4ea4a93f0b178c9c2144eebddd6325b4bb5bc693",
        "6f695ab8564506f98d3b8a7c43b80f539ee0a31a2152b693bdd4f3a5737947fc\"",
    );

    fn accepts_exact_bls_types(
        _: BlsPublicKeyBytes,
        _: BlsPublicKey,
        _: BlsSignature,
        _: BlsSignature,
        _: BlsAggregateSignature,
        _: BlsAggregateSignature,
    ) {
    }

    let secret_key = deterministic_secret_key(3);
    let verification_key: VerificationKey = secret_key.public_key();
    let validator_key: ValidatorPublicKeyBytes = verification_key.compress();
    let individual: IndividualSignature = secret_key.sign(Hash256::repeat_byte(0xa5));
    let raw: RawSignature = individual.clone();
    let same_message = SameMessageEvidence::from(&individual);
    let aggregate: AggregateSignature = same_message.clone();

    accepts_exact_bls_types(
        validator_key.clone(),
        verification_key.clone(),
        individual.clone(),
        raw.clone(),
        same_message.clone(),
        aggregate.clone(),
    );

    assert_eq!(
        serde_json::to_string(&validator_key).expect("serialize validator public key bytes"),
        EXPECTED_PUBLIC_KEY_JSON
    );
    assert_eq!(
        serde_json::to_string(&verification_key).expect("serialize verification key"),
        EXPECTED_PUBLIC_KEY_JSON
    );
    assert_eq!(
        serde_json::to_string(&individual).expect("serialize individual signature"),
        EXPECTED_SIGNATURE_JSON
    );
    assert_eq!(
        serde_json::to_string(&raw).expect("serialize raw signature"),
        EXPECTED_SIGNATURE_JSON
    );
    assert_eq!(
        serde_json::to_string(&same_message).expect("serialize same-message evidence"),
        EXPECTED_SIGNATURE_JSON
    );
    assert_eq!(
        serde_json::to_string(&aggregate).expect("serialize aggregate signature"),
        EXPECTED_SIGNATURE_JSON
    );
}
