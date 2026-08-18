use consensus_signature::PqPublicKey;
use pq_signing::PqKeystore;
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;
use validator_dir::{
    PQ_DEVNET_MANIFEST_FILE, PqDevnetBundle, PqDevnetBundleError, PqDevnetManifest,
    PqDevnetManifestError, PqManifestValidator, PqValidatorDirBuilder,
};

fn manifest_json(root: [u8; 32], duplicate: bool) -> Vec<u8> {
    let validator = serde_json::json!({
        "derivation_index": 0,
        "public_key": "11".repeat(32),
        "withdrawal_credentials": "22".repeat(32),
    });
    let validators = if duplicate {
        let mut second = validator.clone();
        second["derivation_index"] = serde_json::json!(1);
        vec![validator, second]
    } else {
        vec![validator]
    };
    serde_json::to_vec(&serde_json::json!({
        "format": "lighthouse-pq-devnet",
        "version": 1,
        "preset": "minimal",
        "fork": "electra",
        "validator_count": validators.len(),
        "one_time_use_start": 0,
        "one_time_use_end": 1119,
        "eth1_timestamp": 42,
        "genesis_validators_root": hex::encode(root),
        "validators": validators,
    }))
    .expect("manifest JSON")
}

#[test]
fn validates_profile_and_network_root() {
    let root = [3; 32];
    let manifest =
        PqDevnetManifest::from_json_slice(&manifest_json(root, false)).expect("bounded manifest");
    let validated = manifest.validate_for_network(root).expect("valid profile");
    assert_eq!(
        validated.public_keys(),
        &[PqPublicKey::deserialize(&[0x11; 32]).unwrap()]
    );

    assert!(matches!(
        manifest.validate_for_network([4; 32]),
        Err(PqDevnetManifestError::WrongNetworkRoot { .. })
    ));
}

#[test]
fn rejects_duplicate_validator_identity() {
    let root = [3; 32];
    let manifest =
        PqDevnetManifest::from_json_slice(&manifest_json(root, true)).expect("bounded manifest");
    assert!(matches!(
        manifest.validate_for_network(root),
        Err(PqDevnetManifestError::DuplicatePublicKey(_))
    ));
}

#[test]
fn rejects_manifest_over_bound_before_json_parsing() {
    let oversized = vec![b' '; validator_dir::MAX_PQ_DEVNET_MANIFEST_BYTES + 1];
    assert!(matches!(
        PqDevnetManifest::from_json_slice(&oversized),
        Err(PqDevnetManifestError::ManifestTooLarge { .. })
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn bundle_loads_exact_directory_identity_set_and_unlocks() {
    const PASSWORD: &[u8] = b"correct horse battery staple";
    let root = tempdir().expect("bundle root");
    let validators = root.path().join("validators");
    let secrets = root.path().join("secrets");
    fs::create_dir(&validators).expect("validators");
    fs::create_dir(&secrets).expect("secrets");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    fs::set_permissions(&validators, fs::Permissions::from_mode(0o700))
        .expect("private validators");
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).expect("private secrets");
    let keystore = PqKeystore::from_seed([7; 32], 0..=7, PASSWORD).expect("keystore");
    let public_key = PqPublicKey::deserialize(keystore.public_key()).expect("public key");
    PqValidatorDirBuilder::new(validators.clone())
        .password_dir(&secrets)
        .voting_keystore(keystore, PASSWORD)
        .build()
        .expect("validator directory");
    let network_root = [3; 32];
    let manifest = PqDevnetManifest::new(
        1,
        0,
        7,
        42,
        network_root,
        vec![PqManifestValidator::new(0, public_key, [0x22; 32])],
    );
    let manifest_path = root.path().join(PQ_DEVNET_MANIFEST_FILE);
    fs::write(&manifest_path, serde_json::to_vec(&manifest).expect("JSON")).expect("manifest");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))
        .expect("private manifest");

    let bundle = PqDevnetBundle::load(root.path(), network_root).expect("bundle");
    assert_eq!(bundle.public_keys(), &[public_key]);
    assert_eq!(bundle.unlock_count(), 1);

    let mismatched_manifest = PqDevnetManifest::new(
        1,
        0,
        8,
        42,
        network_root,
        vec![PqManifestValidator::new(0, public_key, [0x22; 32])],
    );
    fs::write(
        &manifest_path,
        serde_json::to_vec(&mismatched_manifest).expect("mismatched JSON"),
    )
    .expect("mismatched manifest");
    assert!(matches!(
        PqDevnetBundle::load(root.path(), network_root),
        Err(PqDevnetBundleError::KeyRangeMismatch(key)) if key == public_key
    ));
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("restored JSON"),
    )
    .expect("restore manifest");

    let extra = validators.join("unrelated");
    fs::create_dir(&extra).expect("extra directory");
    assert!(matches!(
        PqDevnetBundle::load(root.path(), network_root),
        Err(PqDevnetBundleError::UnexpectedValidatorDirectory(_))
    ));

    fs::remove_dir(&extra).expect("remove extra directory");
    let validator_directory = validators.join(format!("0x{}", hex::encode(public_key.serialize())));
    fs::remove_dir_all(&validator_directory).expect("remove validator directory");
    assert!(matches!(
        PqDevnetBundle::load(root.path(), network_root),
        Err(PqDevnetBundleError::MissingValidator(missing)) if missing == public_key
    ));
}
