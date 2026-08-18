use pq_devnet::{
    PQ_DEVNET_GENESIS_FILE, PQ_DEVNET_JOURNAL_FILE, PQ_DEVNET_MANIFEST_FILE, ProvisionConfig,
    ProvisionError, production_config, provision_devnet, staging_path,
};
use pq_signing::{AuthenticatedPqKeyMetadata, validate_usage_journal};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;
use types::{BeaconState, EthSpec, ForkName, MinimalEthSpec};
use validator_dir::{PQ_VOTING_KEYSTORE_FILE, PqValidatorDir};

const PASSWORD: &[u8] = b"deterministic test password";

fn write_inputs(root: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let seed_path = root.join("seed");
    let password_path = root.join("password");
    fs::write(&seed_path, [42; 32]).expect("seed");
    fs::write(&password_path, PASSWORD).expect("password");
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).expect("seed mode");
    fs::set_permissions(&password_path, fs::Permissions::from_mode(0o600)).expect("password mode");
    (seed_path, password_path)
}

#[test]
fn one_validator_provisioning_is_reopenable_and_publicly_deterministic() {
    let root = tempdir().expect("root");
    let (seed_path, password_path) = write_inputs(root.path());
    let first_path = root.path().join("first");
    let second_path = root.path().join("second");
    let config = |destination| ProvisionConfig::for_test(destination, 1, 0..=3, 42);

    let first = provision_devnet(config(first_path.clone()), &seed_path, &password_path)
        .expect("first provisioning");
    let second = provision_devnet(config(second_path.clone()), &seed_path, &password_path)
        .expect("second provisioning");

    assert_eq!(first.output_dir(), first_path);
    assert_eq!(second.output_dir(), second_path);
    assert_eq!(first.public_keys(), second.public_keys());
    assert_eq!(first.genesis_state_bytes(), second.genesis_state_bytes());
    assert_eq!(
        first.genesis_validators_root(),
        second.genesis_validators_root()
    );
    assert_eq!(
        fs::read(first_path.join(PQ_DEVNET_MANIFEST_FILE)).expect("manifest"),
        fs::read(second_path.join(PQ_DEVNET_MANIFEST_FILE)).expect("manifest")
    );

    let spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
    let state = BeaconState::<MinimalEthSpec>::from_ssz_bytes(
        &fs::read(first_path.join(PQ_DEVNET_GENESIS_FILE)).expect("genesis"),
        &spec,
    )
    .expect("decode genesis");
    assert_eq!(
        state
            .validators()
            .iter()
            .map(|validator| validator.pubkey)
            .collect::<Vec<_>>(),
        first.public_keys()
    );

    let first_dirs = PqValidatorDir::discover(first_path.join("validators")).expect("discover");
    assert_eq!(first_dirs.len(), 1);
    assert!(first_dirs[0].dir().join(PQ_VOTING_KEYSTORE_FILE).is_file());
    first_dirs[0]
        .validate_keystore_password(first_path.join("secrets"))
        .expect("password and keystore");
    let first_keystore_json = fs::read(first_dirs[0].pq_voting_keystore_path()).expect("keystore");
    let second_dir = PqValidatorDir::discover(second_path.join("validators"))
        .expect("discover")
        .remove(0);
    let second_keystore_json = fs::read(second_dir.pq_voting_keystore_path()).expect("keystore");
    assert_ne!(first_keystore_json, second_keystore_json);

    let metadata = first_dirs
        .iter()
        .map(|validator_dir| {
            validator_dir
                .keystore()
                .expect("keystore")
                .authenticate(PASSWORD)
                .expect("authenticated metadata")
        })
        .collect::<Vec<AuthenticatedPqKeyMetadata>>();
    validate_usage_journal(
        &first_path.join(PQ_DEVNET_JOURNAL_FILE),
        first.genesis_validators_root(),
        &metadata,
    )
    .expect("journal binding");
}

#[test]
fn collisions_are_rejected_without_removing_existing_data() {
    let root = tempdir().expect("root");
    let seed_path = root.path().join("missing-seed");
    let password_path = root.path().join("missing-password");
    let destination = root.path().join("devnet");
    fs::create_dir(&destination).expect("existing destination");
    fs::write(destination.join("marker"), b"keep").expect("marker");

    assert!(matches!(
        provision_devnet(
            ProvisionConfig::for_test(destination.clone(), 1, 0..=1, 0),
            &seed_path,
            &password_path,
        ),
        Err(ProvisionError::DestinationExists(path)) if path == destination
    ));
    assert_eq!(
        fs::read(destination.join("marker")).expect("marker"),
        b"keep"
    );

    fs::remove_dir_all(&destination).expect("fixture cleanup");
    let staging = staging_path(&destination).expect("staging path");
    fs::create_dir(&staging).expect("existing staging");
    fs::write(staging.join("marker"), b"keep").expect("marker");
    assert!(matches!(
        provision_devnet(
            ProvisionConfig::for_test(destination, 1, 0..=1, 0),
            &seed_path,
            &password_path,
        ),
        Err(ProvisionError::StagingExists(path)) if path == staging
    ));
    assert_eq!(fs::read(staging.join("marker")).expect("marker"), b"keep");
}

#[test]
fn input_files_are_bounded_and_seed_is_exactly_32_bytes() {
    let root = tempdir().expect("root");
    let password_path = root.path().join("password");
    fs::write(&password_path, PASSWORD).expect("password");
    fs::set_permissions(&password_path, fs::Permissions::from_mode(0o600)).expect("mode");
    let short_seed = root.path().join("short-seed");
    fs::write(&short_seed, [1; 31]).expect("seed");
    fs::set_permissions(&short_seed, fs::Permissions::from_mode(0o600)).expect("mode");
    assert!(matches!(
        provision_devnet(
            ProvisionConfig::for_test(root.path().join("short"), 1, 0..=1, 0),
            &short_seed,
            &password_path,
        ),
        Err(ProvisionError::InvalidMasterSeedLength(31))
    ));

    let oversized_password = root.path().join("oversized-password");
    fs::write(&oversized_password, vec![b'x'; 4097]).expect("password");
    fs::set_permissions(&oversized_password, fs::Permissions::from_mode(0o600)).expect("mode");
    let valid_seed = root.path().join("valid-seed");
    fs::write(&valid_seed, [1; 32]).expect("seed");
    fs::set_permissions(&valid_seed, fs::Permissions::from_mode(0o600)).expect("mode");
    assert!(matches!(
        provision_devnet(
            ProvisionConfig::for_test(root.path().join("oversized"), 1, 0..=1, 0),
            &valid_seed,
            &oversized_password,
        ),
        Err(ProvisionError::PasswordTooLarge(4097))
    ));
}

#[test]
fn invalid_config_is_rejected_before_secret_files_are_opened() {
    let root = tempdir().expect("root");
    let missing_seed = root.path().join("missing-seed");
    let missing_password = root.path().join("missing-password");
    assert!(matches!(
        provision_devnet(
            ProvisionConfig::for_test(root.path().join("too-many"), 17, 0..=1, 0),
            &missing_seed,
            &missing_password,
        ),
        Err(ProvisionError::ValidatorCountTooLarge(17))
    ));
    assert!(matches!(
        provision_devnet(
            ProvisionConfig::for_test(root.path().join("bad-range"), 1, 0..=1120, 0),
            &missing_seed,
            &missing_password,
        ),
        Err(ProvisionError::InvalidConfig)
    ));
    assert!(matches!(
        provision_devnet(
            ProvisionConfig::for_test(root.path().join("timestamp-overflow"), 1, 0..=1, u64::MAX),
            &missing_seed,
            &missing_password,
        ),
        Err(ProvisionError::InvalidConfig)
    ));
}

#[test]
fn input_files_must_be_private_regular_files() {
    let root = tempdir().expect("root");
    let seed = root.path().join("seed");
    let password = root.path().join("password");
    fs::write(&seed, [1; 32]).expect("seed");
    fs::write(&password, PASSWORD).expect("password");
    fs::set_permissions(&seed, fs::Permissions::from_mode(0o644)).expect("public seed");
    fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).expect("private password");
    assert!(matches!(
        provision_devnet(
            ProvisionConfig::for_test(root.path().join("bad-seed-mode"), 1, 0..=1, 0),
            &seed,
            &password,
        ),
        Err(ProvisionError::UnsafeInput(path)) if path == seed
    ));

    fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).expect("private seed");
    fs::set_permissions(&password, fs::Permissions::from_mode(0o644)).expect("public password");
    assert!(matches!(
        provision_devnet(
            ProvisionConfig::for_test(root.path().join("bad-password-mode"), 1, 0..=1, 0),
            &seed,
            &password,
        ),
        Err(ProvisionError::UnsafeInput(path)) if path == password
    ));
}

#[test]
fn production_profile_is_frozen() {
    let config = production_config("devnet".into(), 1_800_000_000);
    assert_eq!(config.validator_count(), 16);
    assert_eq!(config.one_time_use_range(), 0..=1119);
}

#[test]
#[ignore = "generates the full 16-validator 0..=1119 production profile"]
fn production_profile_end_to_end() {
    let root = tempdir().expect("root");
    let (seed_path, password_path) = write_inputs(root.path());
    provision_devnet(
        production_config(root.path().join("devnet"), 1_800_000_000),
        seed_path,
        password_path,
    )
    .expect("production provisioning");
}
