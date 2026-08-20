#![cfg(all(feature = "pq-devnet", target_os = "linux"))]

use consensus_signature::{PqPublicKey, PqValidatorRegistryEntry};
use initialized_validators::{Error, InitializedValidators};
use pq_signing::{PqKeystore, PqSigningError, PqUsageJournalError, provision_usage_journal};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use task_executor::test_utils::TestRuntime;
use tempfile::tempdir;
use validator_dir::{
    PQ_DEVNET_JOURNAL_FILE, PQ_DEVNET_MANIFEST_FILE, PqDevnetBundle, PqDevnetManifest,
    PqManifestValidator, PqValidatorDirBuilder,
};

#[tokio::test(flavor = "multi_thread")]
async fn opens_one_authority_after_network_root_and_binds_all_signers() {
    const PASSWORD: &[u8] = b"correct horse battery staple";
    let root = tempdir().expect("bundle root");
    let bundle_root = root.path().join("bundle");
    fs::create_dir(&bundle_root).expect("bundle root");
    let validators = bundle_root.join("validators");
    let secrets = bundle_root.join("secrets");
    fs::create_dir(&validators).expect("validators");
    fs::create_dir(&secrets).expect("secrets");
    fs::set_permissions(&bundle_root, fs::Permissions::from_mode(0o700)).expect("private root");
    fs::set_permissions(&validators, fs::Permissions::from_mode(0o700)).expect("validators mode");
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).expect("secrets mode");
    let keystore = PqKeystore::from_seed([7; 32], 0..=13, PASSWORD).expect("keystore");
    let metadata = keystore.authenticate(PASSWORD).expect("metadata");
    let public_key = PqPublicKey::deserialize(keystore.public_key()).expect("public key");
    PqValidatorDirBuilder::new(validators)
        .password_dir(&secrets)
        .voting_keystore(keystore, PASSWORD)
        .build()
        .expect("validator directory");
    let network_root = [3; 32];
    provision_usage_journal(
        &bundle_root.join(PQ_DEVNET_JOURNAL_FILE),
        network_root,
        std::slice::from_ref(&metadata),
    )
    .expect("journal");
    let manifest = PqDevnetManifest::new(
        1,
        0,
        13,
        42,
        network_root,
        vec![PqManifestValidator::new(0, public_key, [0x22; 32])],
    );
    let manifest_path = bundle_root.join(PQ_DEVNET_MANIFEST_FILE);
    fs::write(&manifest_path, serde_json::to_vec(&manifest).expect("JSON")).expect("manifest");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).expect("manifest mode");
    let runtime = TestRuntime::default();
    let registry = vec![PqValidatorRegistryEntry::new(0, public_key, [0x22; 32])];

    let initialized = InitializedValidators::from_pq_bundle(
        bundle_root.clone(),
        network_root,
        342,
        registry.clone(),
        runtime.task_executor.clone(),
    )
    .await
    .expect("initialized validators");
    assert_eq!(
        initialized
            .iter_voting_pubkeys()
            .copied()
            .collect::<Vec<_>>(),
        vec![public_key]
    );
    assert!(initialized.signing_method(&public_key).is_some());

    let password_path = fs::read_dir(&secrets)
        .expect("secrets directory")
        .next()
        .expect("password entry")
        .expect("password directory entry")
        .path();
    fs::write(&password_path, b"wrong password").expect("poison password before locked retry");
    let second = InitializedValidators::from_pq_bundle(
        bundle_root.clone(),
        network_root,
        342,
        registry.clone(),
        runtime.task_executor.clone(),
    )
    .await;
    assert!(matches!(
        second,
        Err(Error::PqSigning(PqSigningError::Journal(
            PqUsageJournalError::JournalLocked(_)
        )))
    ));
    fs::write(&password_path, PASSWORD).expect("restore password");

    drop(initialized);
    let bundle =
        PqDevnetBundle::load_for_network_registry(&bundle_root, network_root, 342, &registry)
            .expect("anchored bundle");
    let moved_root = root.path().join("moved-bundle");
    fs::rename(&bundle_root, &moved_root).expect("move original bundle");
    fs::create_dir(&bundle_root).expect("replacement root");
    fs::set_permissions(&bundle_root, fs::Permissions::from_mode(0o700)).expect("replacement mode");
    provision_usage_journal(
        &bundle_root.join(PQ_DEVNET_JOURNAL_FILE),
        [9; 32],
        &[metadata],
    )
    .expect("replacement journal");

    let authority = bundle
        .open_authority(network_root)
        .expect("authority must use the held original root");
    assert_eq!(authority.public_keys(), &[public_key]);
}
