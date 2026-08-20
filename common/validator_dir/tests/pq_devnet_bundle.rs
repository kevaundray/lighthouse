use consensus_signature::PqPublicKey;
use pq_signing::{PqKeystore, provision_usage_journal};
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;
use validator_dir::{
    PQ_DEVNET_MANIFEST_FILE, PqDevnetBundle, PqDevnetBundleError, PqDevnetManifest,
    PqDevnetManifestError, PqManifestValidator, PqValidatorDirBuilder, PqValidatorRegistryEntry,
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
    let validated = manifest
        .validate_for_network_identity(root, 342)
        .expect("valid profile");
    assert_eq!(
        validated.public_keys(),
        &[PqPublicKey::deserialize(&[0x11; 32]).unwrap()]
    );

    assert!(matches!(
        manifest.validate_for_network_identity([4; 32], 342),
        Err(PqDevnetManifestError::WrongNetworkRoot { .. })
    ));
}

#[test]
fn validates_manifest_against_root_and_genesis_time() {
    let root = [3; 32];
    let manifest =
        PqDevnetManifest::from_json_slice(&manifest_json(root, false)).expect("bounded manifest");

    manifest
        .validate_for_network_identity(root, 342)
        .expect("exact network identity");
    assert!(matches!(
        manifest.validate_for_network_identity(root, 343),
        Err(PqDevnetManifestError::WrongGenesisTime {
            manifest: 342,
            network: 343,
        })
    ));
}

#[test]
fn binds_manifest_to_exact_canonical_genesis_registry() {
    let root = [3; 32];
    let first = PqPublicKey::deserialize(&[0x11; 32]).expect("first key");
    let second = PqPublicKey::deserialize(&[0x12; 32]).expect("second key");
    let manifest = PqDevnetManifest::new(
        2,
        0,
        7,
        42,
        root,
        vec![
            PqManifestValidator::new(0, first, [0x21; 32]),
            PqManifestValidator::new(1, second, [0x22; 32]),
        ],
    );
    let canonical = [
        PqValidatorRegistryEntry::new(0, first, [0x21; 32]),
        PqValidatorRegistryEntry::new(1, second, [0x22; 32]),
    ];
    manifest
        .validate_for_network_registry(root, 342, &canonical)
        .expect("exact canonical registry binding");
    let canonical_with_unowned_tail = [
        canonical[0],
        canonical[1],
        PqValidatorRegistryEntry::new(
            2,
            PqPublicKey::deserialize(&[0x13; 32]).expect("third key"),
            [0x23; 32],
        ),
    ];
    manifest
        .validate_for_network_registry(root, 342, &canonical_with_unowned_tail)
        .expect("a bundle may own an exact canonical prefix of the public registry");

    let substituted = [
        PqValidatorRegistryEntry::new(0, second, [0x21; 32]),
        canonical[1],
    ];
    assert!(matches!(
        manifest.validate_for_network_registry(root, 342, &substituted),
        Err(PqDevnetManifestError::RegistryPublicKeyMismatch { index: 0 })
    ));
    let reordered = [canonical[1], canonical[0]];
    assert!(matches!(
        manifest.validate_for_network_registry(root, 342, &reordered),
        Err(PqDevnetManifestError::RegistryIndexMismatch { position: 0, .. })
    ));
    assert!(matches!(
        manifest.validate_for_network_registry(root, 342, &canonical[..1]),
        Err(PqDevnetManifestError::RegistryLengthMismatch {
            manifest: 2,
            registry: 1,
        })
    ));
    let wrong_index = [
        PqValidatorRegistryEntry::new(1, first, [0x21; 32]),
        canonical[1],
    ];
    assert!(matches!(
        manifest.validate_for_network_registry(root, 342, &wrong_index),
        Err(PqDevnetManifestError::RegistryIndexMismatch {
            position: 0,
            actual: 1,
        })
    ));
    let wrong_withdrawal = [
        PqValidatorRegistryEntry::new(0, first, [0x99; 32]),
        canonical[1],
    ];
    assert!(matches!(
        manifest.validate_for_network_registry(root, 342, &wrong_withdrawal),
        Err(PqDevnetManifestError::RegistryWithdrawalCredentialsMismatch { index: 0 })
    ));
}

#[test]
fn rejects_manifest_genesis_time_overflow() {
    let root = [3; 32];
    let mut json: serde_json::Value =
        serde_json::from_slice(&manifest_json(root, false)).expect("manifest value");
    json["eth1_timestamp"] = serde_json::json!(u64::MAX);
    let manifest = PqDevnetManifest::from_json_slice(
        &serde_json::to_vec(&json).expect("overflow manifest JSON"),
    )
    .expect("bounded manifest");

    assert!(matches!(
        manifest.validate_for_network_identity(root, u64::MAX),
        Err(PqDevnetManifestError::GenesisTimeOverflow {
            eth1_timestamp: u64::MAX,
            genesis_delay: 300,
        })
    ));
}

#[test]
fn rejects_duplicate_validator_identity() {
    let root = [3; 32];
    let manifest =
        PqDevnetManifest::from_json_slice(&manifest_json(root, true)).expect("bounded manifest");
    assert!(matches!(
        manifest.validate_for_network_identity(root, 342),
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
    let metadata = keystore
        .authenticate(PASSWORD)
        .expect("authenticated metadata");
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
    provision_usage_journal(
        &root.path().join(pq_signing::XMSS_USAGE_FILENAME),
        network_root,
        &[metadata],
    )
    .expect("usage journal");

    let registry = [PqValidatorRegistryEntry::new(0, public_key, [0x22; 32])];
    let bundle =
        PqDevnetBundle::load_for_network_registry(root.path(), network_root, 342, &registry)
            .expect("bundle");
    assert_eq!(bundle.public_keys(), &[public_key]);
    assert_eq!(bundle.registry(), &registry);
    assert_eq!(bundle.unlock_count(), 1);
    drop(bundle);

    assert!(matches!(
        PqDevnetBundle::load_for_network_registry(
            root.path(),
            network_root,
            342,
            &[PqValidatorRegistryEntry::new(0, public_key, [0x99; 32],)],
        ),
        Err(PqDevnetBundleError::Manifest(
            PqDevnetManifestError::RegistryWithdrawalCredentialsMismatch { index: 0 }
        )),
    ));

    let secret_path = fs::read_dir(&secrets)
        .expect("secret entries")
        .next()
        .expect("one secret")
        .expect("secret entry")
        .path();
    let renamed_secret = secrets.join("missing-canonical-secret");
    fs::rename(&secret_path, &renamed_secret).expect("rename canonical secret");
    assert!(matches!(
        PqDevnetBundle::load_for_network_registry(root.path(), network_root, 342, &registry),
        Err(PqDevnetBundleError::UnexpectedSecretEntry(_)),
    ));
    fs::rename(&renamed_secret, &secret_path).expect("restore canonical secret");

    let extra_secret = secrets.join("extra-secret");
    fs::write(&extra_secret, PASSWORD).expect("extra secret");
    fs::set_permissions(&extra_secret, fs::Permissions::from_mode(0o600))
        .expect("extra secret mode");
    assert!(matches!(
        PqDevnetBundle::load_for_network_registry(root.path(), network_root, 342, &registry),
        Err(PqDevnetBundleError::UnexpectedSecretEntry(_)),
    ));
    fs::remove_file(extra_secret).expect("remove extra secret");

    let secret_overflow = (0..validator_dir::MAX_PQ_DEVNET_VALIDATORS)
        .map(|index| secrets.join(format!("overflow-secret-{index}")))
        .collect::<Vec<_>>();
    for path in &secret_overflow {
        fs::write(path, PASSWORD).expect("secret enumeration overflow entry");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("overflow secret mode");
    }
    assert!(matches!(
        PqDevnetBundle::load_for_network_registry(root.path(), network_root, 342, &registry),
        Err(PqDevnetBundleError::TooManySecretEntries {
            actual_at_least: 17,
            max: 16,
        })
    ));
    for path in secret_overflow {
        fs::remove_file(path).expect("remove secret overflow entry");
    }

    let external_secret = root
        .path()
        .parent()
        .expect("temporary parent")
        .join(format!("external-secret-{}", std::process::id()));
    fs::rename(&secret_path, &external_secret).expect("move secret outside bundle");
    std::os::unix::fs::symlink(&external_secret, &secret_path).expect("secret symlink");
    assert!(matches!(
        PqDevnetBundle::load_for_network_registry(root.path(), network_root, 342, &registry),
        Err(PqDevnetBundleError::UnexpectedSecretEntry(_)),
    ));
    fs::remove_file(&secret_path).expect("remove secret symlink");
    fs::create_dir(&secret_path).expect("secret directory target");
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o700))
        .expect("secret directory mode");
    assert!(matches!(
        PqDevnetBundle::load_for_network_registry(root.path(), network_root, 342, &registry),
        Err(PqDevnetBundleError::UnexpectedSecretEntry(_)),
    ));
    fs::remove_dir(&secret_path).expect("remove secret directory");
    fs::rename(external_secret, &secret_path).expect("restore regular secret");

    assert!(matches!(
        PqDevnetBundle::load_for_network_registry(root.path(), network_root, 343, &registry),
        Err(PqDevnetBundleError::Manifest(
            PqDevnetManifestError::WrongGenesisTime { .. }
        ))
    ));
    let unexpected_bundle_entry = root.path().join("unexpected-private-entry");
    fs::write(&unexpected_bundle_entry, b"unexpected").expect("unexpected bundle entry");
    assert!(matches!(
        PqDevnetBundle::load_for_network_registry(root.path(), network_root, 342, &registry),
        Err(PqDevnetBundleError::TooManyBundleEntries {
            actual_at_least: 6,
            max: 5,
        }),
    ));
    fs::remove_file(unexpected_bundle_entry).expect("remove unexpected bundle entry");

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
        PqDevnetBundle::load_for_network_registry(root.path(), network_root, 342, &registry),
        Err(PqDevnetBundleError::KeyRangeMismatch(key)) if key == public_key
    ));
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("restored JSON"),
    )
    .expect("restore manifest");

    let overflow_entries = (0..=validator_dir::MAX_PQ_DEVNET_VALIDATORS)
        .map(|index| validators.join(format!("overflow-{index}")))
        .collect::<Vec<_>>();
    for path in &overflow_entries {
        fs::create_dir(path).expect("validator enumeration overflow entry");
    }
    assert!(matches!(
        PqDevnetBundle::load_for_network_registry(root.path(), network_root, 342, &registry),
        Err(PqDevnetBundleError::TooManyValidatorEntries {
            actual_at_least: 17,
            max: 16,
        })
    ));
    for path in overflow_entries {
        fs::remove_dir(path).expect("remove validator overflow entry");
    }

    let extra = validators.join("unrelated");
    fs::create_dir(&extra).expect("extra directory");
    assert!(matches!(
        PqDevnetBundle::load_for_network_registry(root.path(), network_root, 342, &registry),
        Err(PqDevnetBundleError::UnexpectedValidatorDirectory(_))
    ));

    fs::remove_dir(&extra).expect("remove extra directory");
    let validator_directory = validators.join(format!("0x{}", hex::encode(public_key.serialize())));
    fs::remove_dir_all(&validator_directory).expect("remove validator directory");
    assert!(matches!(
        PqDevnetBundle::load_for_network_registry(root.path(), network_root, 342, &registry),
        Err(PqDevnetBundleError::MissingValidator(key)) if key == public_key,
    ));
}
