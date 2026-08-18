#![cfg(feature = "pq-devnet")]

use bls::SignatureBytes;
use consensus_signature::{
    IndividualSignature, PqPublicKey, PqRawSignature, SameMessageEvidence, ValidatorPublicKeyBytes,
};
use ssz::Encode;
use tree_hash::TreeHash;
use types::{
    Address, AttestationData, BeaconBlockHeader, Checkpoint, ConsolidationRequest, Epoch, Hash256,
    MainnetEthSpec, PendingDeposit, SignedBeaconBlockHeader, SingleAttestation, Slot,
    SyncCommittee, SyncDuty, Validator, WithdrawalRequest,
};

fn public_key() -> PqPublicKey {
    let bytes: [u8; 32] = std::array::from_fn(|index| index as u8);
    PqPublicKey::deserialize(&bytes).expect("32-byte PQ public key")
}

fn raw_signature() -> PqRawSignature {
    let mut bytes = vec![0; 1_215];
    bytes[..7].copy_from_slice(b"LHPQ\x01\x01\x00");
    bytes[1_214] = 0xa5;
    PqRawSignature::from_bytes(&bytes).expect("canonical raw signature")
}

#[test]
fn active_validator_identity_fields_use_the_pq_key_schema() {
    fn accepts_active_key(_: ValidatorPublicKeyBytes) {}

    let key = public_key();
    let validator = Validator {
        pubkey: key,
        withdrawal_credentials: Hash256::repeat_byte(0x11),
        effective_balance: 5,
        slashed: true,
        activation_eligibility_epoch: Epoch::new(6),
        activation_epoch: Epoch::new(7),
        exit_epoch: Epoch::new(8),
        withdrawable_epoch: Epoch::new(9),
    };
    let pending_deposit = PendingDeposit {
        pubkey: key,
        withdrawal_credentials: Hash256::repeat_byte(0x22),
        amount: 5,
        signature: SignatureBytes::empty(),
        slot: Slot::new(6),
    };
    let withdrawal = WithdrawalRequest {
        source_address: Address::repeat_byte(0x33),
        validator_pubkey: key,
        amount: 44,
    };
    let consolidation = ConsolidationRequest {
        source_address: Address::repeat_byte(0x33),
        source_pubkey: key,
        target_pubkey: key,
    };
    let committee = SyncCommittee::<MainnetEthSpec>::temporary();
    let duty = SyncDuty::from_sync_committee_indices(0, key, &[0])
        .expect("matching validator has a sync duty");

    accepts_active_key(validator.pubkey);
    accepts_active_key(pending_deposit.pubkey);
    accepts_active_key(withdrawal.validator_pubkey);
    accepts_active_key(consolidation.source_pubkey);
    accepts_active_key(consolidation.target_pubkey);
    accepts_active_key(committee.aggregate_pubkey);
    accepts_active_key(duty.pubkey);

    assert_eq!(validator.as_ssz_bytes().len(), 105);
    assert_eq!(pending_deposit.as_ssz_bytes().len(), 176);
    assert_eq!(withdrawal.as_ssz_bytes().len(), 60);
    assert_eq!(consolidation.as_ssz_bytes().len(), 84);
    assert_eq!(
        hex::encode(validator.tree_hash_root()),
        "50d61e1899054ae5a15db042fa8d6abca44788ba794c87dd787228fac1e3dbdd"
    );
    assert_eq!(
        hex::encode(pending_deposit.tree_hash_root()),
        "aabe28244ada9d2017885277b767235c0d797f0e7f74b34d0fcb7a569dc391bd"
    );
    assert_eq!(
        hex::encode(withdrawal.tree_hash_root()),
        "3f9530c6a05bd480504f6bd5d6ab42829f758a07ab98625ab0da39f8d915c391"
    );
    assert_eq!(
        hex::encode(consolidation.tree_hash_root()),
        "045436acf1476e93c891cf30251728f870b7328424e5e2f90d431eb593d7074b"
    );
    assert_eq!(committee.aggregate_pubkey, PqPublicKey::empty());
}

#[test]
fn individual_and_same_message_fields_have_the_pq_ssz_shapes() {
    fn accepts_individual(_: IndividualSignature) {}
    fn accepts_same_message(_: SameMessageEvidence) {}

    let raw = raw_signature();
    let same_message = SameMessageEvidence::from(&raw);
    let signed_header = SignedBeaconBlockHeader {
        message: BeaconBlockHeader {
            slot: Slot::new(11),
            proposer_index: 17,
            parent_root: Hash256::repeat_byte(0x21),
            state_root: Hash256::repeat_byte(0x32),
            body_root: Hash256::repeat_byte(0x43),
        },
        signature: raw.clone(),
    };
    let single_attestation = SingleAttestation {
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
        signature: same_message.clone(),
    };

    accepts_individual(raw);
    accepts_same_message(same_message);

    assert_eq!(signed_header.as_ssz_bytes().len(), 1_327);
    assert_eq!(single_attestation.as_ssz_bytes().len(), 1_363);
    assert_eq!(
        &single_attestation.as_ssz_bytes()[144..148],
        &[148, 0, 0, 0]
    );
    assert_eq!(
        hex::encode(signed_header.tree_hash_root()),
        "29f32fb335fb17792fadd9d72ad967b5bb56e7c6fd324b63f440fadfb6554bbc"
    );
    assert_eq!(
        hex::encode(single_attestation.tree_hash_root()),
        "3da0bfe6b277160eb6d0d625c7eafed08cefcc4577e7b8dfb5b64bb0653f262e"
    );
}
