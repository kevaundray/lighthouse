use consensus_signature::PqPublicKey;
use slashing_protection::{Safe, SlashingDatabase};
use tempfile::tempdir;
use types::{BeaconBlockHeader, Hash256, Slot};

#[test]
fn core_database_uses_active_pq_identity_without_bls_shadow() {
    let directory = tempdir().expect("temporary directory");
    let database = SlashingDatabase::create(&directory.path().join("slashing.sqlite"))
        .expect("fresh database");
    let public_key = PqPublicKey::deserialize(&[7; 32]).expect("public key");
    database
        .register_validator(public_key)
        .expect("register PQ key");
    let block = BeaconBlockHeader {
        slot: Slot::new(1),
        ..BeaconBlockHeader::empty()
    };
    assert_eq!(
        database.check_and_insert_block_proposal(&public_key, &block, Hash256::repeat_byte(0x42),),
        Ok(Safe::Valid)
    );
    assert_eq!(
        database.check_and_insert_block_proposal(&public_key, &block, Hash256::repeat_byte(0x42),),
        Ok(Safe::SameData)
    );
}
