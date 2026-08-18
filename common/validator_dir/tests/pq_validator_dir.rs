#[cfg(unix)]
use fs2::FileExt;
#[cfg(unix)]
use pq_signing::{PqKeystore, PqSigningAuthority, provision_usage_journal};
#[cfg(unix)]
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::sync::OnceLock;
#[cfg(unix)]
use tempfile::tempdir;
#[cfg(unix)]
use validator_dir::{PQ_VOTING_KEYSTORE_FILE, PqValidatorDirBuilder};
use validator_dir::{PqValidatorDir, PqValidatorDirError};

#[cfg(unix)]
const PASSWORD: &[u8] = b"correct horse battery staple";

#[cfg(unix)]
fn pq_work_lock() -> File {
    let path = std::env::temp_dir().join("lighthouse-pq-crypto-tests.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .expect("open PQ test lock");
    file.lock_exclusive().expect("lock PQ test work");
    file
}

#[cfg(unix)]
fn keystore() -> PqKeystore {
    static KEYSTORE: OnceLock<PqKeystore> = OnceLock::new();
    KEYSTORE
        .get_or_init(|| PqKeystore::from_seed([7; 32], 0..=7, PASSWORD).expect("small key"))
        .clone()
}

#[cfg(unix)]
fn second_keystore() -> PqKeystore {
    static KEYSTORE: OnceLock<PqKeystore> = OnceLock::new();
    KEYSTORE
        .get_or_init(|| PqKeystore::from_seed([9; 32], 0..=7, PASSWORD).expect("small key"))
        .clone()
}

#[cfg(unix)]
#[test]
fn pq_builder_uses_distinct_definition_and_filename() {
    let _work_lock = pq_work_lock();
    let validators = tempdir().expect("validators");
    let passwords = tempdir().expect("passwords");
    let keystore = keystore();
    let public_key = *keystore.public_key();

    let validator = PqValidatorDirBuilder::new(validators.path().into())
        .password_dir(passwords.path())
        .voting_keystore(keystore, PASSWORD)
        .build()
        .expect("build");

    assert_eq!(
        validator.pq_voting_keystore_path(),
        validator.dir().join(PQ_VOTING_KEYSTORE_FILE)
    );
    assert!(!validator.dir().join("voting-keystore.json").exists());
    assert_eq!(validator.public_key(), &public_key);
    validator
        .validate_keystore_password(passwords.path())
        .expect("decrypt and validate");
}

#[cfg(unix)]
#[test]
fn key_unlock_is_bounded_and_bound_to_the_validator_identity() {
    let _work_lock = pq_work_lock();
    let validators = tempdir().expect("validators");
    let passwords = tempdir().expect("passwords");
    let journal = tempdir().expect("journal");
    let keystore = keystore();
    let metadata = keystore.authenticate(PASSWORD).expect("metadata");
    let validator = PqValidatorDirBuilder::new(validators.path().into())
        .password_dir(passwords.path())
        .voting_keystore(keystore, PASSWORD)
        .build()
        .expect("build");
    let journal_path = journal.path().join("xmss_usage.sqlite");
    provision_usage_journal(&journal_path, [3; 32], &[metadata]).expect("journal");

    let unlock = validator.key_unlock(passwords.path()).expect("key unlock");
    let authority =
        PqSigningAuthority::open(&journal_path, [3; 32], vec![unlock]).expect("authority");
    assert_eq!(
        authority.public_keys()[0].serialize(),
        *validator.public_key()
    );
}

#[cfg(unix)]
#[test]
fn builder_refuses_directory_and_file_collisions() {
    let _work_lock = pq_work_lock();
    let validators = tempdir().expect("validators");
    let pq_keystore = keystore();
    let dir = PqValidatorDirBuilder::get_dir_path(validators.path(), &pq_keystore);
    fs::create_dir(&dir).expect("collision directory");
    assert!(matches!(
        PqValidatorDirBuilder::new(validators.path().into())
            .voting_keystore(pq_keystore.clone(), PASSWORD)
            .build(),
        Err(PqValidatorDirError::DirectoryAlreadyExists(_))
    ));

    fs::remove_dir(&dir).expect("remove empty collision");
    PqValidatorDirBuilder::new(validators.path().into())
        .voting_keystore(pq_keystore, PASSWORD)
        .build()
        .expect("first build");
    assert!(matches!(
        PqValidatorDirBuilder::new(validators.path().into())
            .voting_keystore(keystore(), PASSWORD)
            .build(),
        Err(PqValidatorDirError::DirectoryAlreadyExists(_))
    ));
}

#[cfg(not(unix))]
#[test]
fn pq_validator_directories_refuse_unsupported_platforms() {
    assert!(matches!(
        PqValidatorDir::open("unused"),
        Err(PqValidatorDirError::UnsupportedPlatform)
    ));
}

#[cfg(unix)]
#[test]
fn sensitive_files_are_0600_and_symlinks_are_refused() {
    let _work_lock = pq_work_lock();
    use std::os::unix::fs::{PermissionsExt, symlink};

    let validators = tempdir().expect("validators");
    let passwords = tempdir().expect("passwords");
    let pq_keystore = keystore();
    let password_path = passwords
        .path()
        .join(format!("0x{}", hex::encode(pq_keystore.public_key())));
    let target = passwords.path().join("target");
    fs::write(&target, b"untouched").expect("target");
    symlink(&target, &password_path).expect("symlink");

    assert!(
        PqValidatorDirBuilder::new(validators.path().into())
            .password_dir(passwords.path())
            .voting_keystore(pq_keystore.clone(), PASSWORD)
            .build()
            .is_err()
    );
    assert_eq!(fs::read(&target).expect("target"), b"untouched");

    fs::remove_file(&password_path).expect("remove link");
    let validator = PqValidatorDirBuilder::new(validators.path().into())
        .password_dir(passwords.path())
        .voting_keystore(pq_keystore, PASSWORD)
        .build()
        .expect("build");
    let keystore_mode = fs::metadata(validator.pq_voting_keystore_path())
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(keystore_mode, 0o600);
    let directory_mode = fs::metadata(validator.dir())
        .expect("directory metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(directory_mode, 0o700);
    let password_path = passwords
        .path()
        .join(format!("0x{}", hex::encode(validator.public_key())));
    let password_mode = fs::metadata(password_path)
        .expect("password metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(password_mode, 0o600);
}

#[cfg(unix)]
#[test]
fn discovery_skips_unrelated_entries_and_refuses_symlinked_keystores() {
    let _work_lock = pq_work_lock();
    use std::os::unix::fs::{PermissionsExt, symlink};

    let validators = tempdir().expect("validators");
    let first = PqValidatorDirBuilder::new(validators.path().into())
        .voting_keystore(keystore(), PASSWORD)
        .build()
        .expect("first");
    let second_keystore = second_keystore();
    let second = PqValidatorDirBuilder::new(validators.path().into())
        .voting_keystore(second_keystore, PASSWORD)
        .build()
        .expect("second");
    fs::create_dir(validators.path().join("unrelated")).expect("unrelated");

    let discovered = PqValidatorDir::discover(validators.path()).expect("discover");
    assert_eq!(discovered.len(), 2);
    assert!(
        discovered
            .iter()
            .any(|definition| definition.dir() == first.dir())
    );
    assert!(
        discovered
            .iter()
            .any(|definition| definition.dir() == second.dir())
    );

    let malicious = validators.path().join("malicious");
    fs::create_dir(&malicious).expect("malicious dir");
    fs::set_permissions(&malicious, fs::Permissions::from_mode(0o700)).expect("private dir");
    symlink(
        first.pq_voting_keystore_path(),
        malicious.join(PQ_VOTING_KEYSTORE_FILE),
    )
    .expect("symlink");
    assert!(matches!(
        PqValidatorDir::discover(validators.path()),
        Err(PqValidatorDirError::UnsafeFileTarget(_))
    ));
}

#[cfg(unix)]
#[test]
fn discovery_refuses_mixed_partial_and_symlinked_directories() {
    let _work_lock = pq_work_lock();
    use std::os::unix::fs::{PermissionsExt, symlink};

    let mixed_root = tempdir().expect("mixed root");
    let mixed = PqValidatorDirBuilder::new(mixed_root.path().into())
        .voting_keystore(keystore(), PASSWORD)
        .build()
        .expect("PQ dir");
    fs::write(mixed.dir().join("voting-keystore.json"), b"not BLS").expect("mixed marker");
    assert!(matches!(
        PqValidatorDir::discover(mixed_root.path()),
        Err(PqValidatorDirError::MixedSignatureSchemes(_))
    ));

    let partial_root = tempdir().expect("partial root");
    let partial = partial_root.path().join(format!("0x{}", "00".repeat(32)));
    fs::create_dir(&partial).expect("partial");
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o700)).expect("private");
    assert!(matches!(
        PqValidatorDir::discover(partial_root.path()),
        Err(PqValidatorDirError::PartialDirectory(_))
    ));

    let symlink_root = tempdir().expect("symlink root");
    let target = symlink_root.path().join("target");
    fs::create_dir(&target).expect("target");
    let link = symlink_root.path().join("link");
    symlink(&target, &link).expect("link");
    assert!(matches!(
        PqValidatorDir::discover(symlink_root.path()),
        Err(PqValidatorDirError::UnsafeDirectoryTarget(path)) if path == link
    ));
}

#[cfg(unix)]
#[test]
fn reread_rejects_keystore_replacement_with_another_identity() {
    use std::os::unix::fs::OpenOptionsExt;

    let _work_lock = pq_work_lock();
    let validators = tempdir().expect("validators");
    let validator = PqValidatorDirBuilder::new(validators.path().into())
        .voting_keystore(keystore(), PASSWORD)
        .build()
        .expect("build");
    let path = validator.pq_voting_keystore_path();
    let mut value = serde_json::to_value(validator.keystore().expect("keystore")).expect("JSON");
    value["public_key"] = serde_json::json!("00".repeat(32));
    fs::remove_file(&path).expect("remove original");
    let mut replacement = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .expect("replacement");
    replacement
        .write_all(serde_json::to_string(&value).expect("JSON").as_bytes())
        .expect("write replacement");
    replacement.sync_all().expect("sync replacement");

    assert!(validator.keystore().is_err());
}

#[cfg(unix)]
#[test]
fn anchored_builder_never_redirects_writes_after_parent_path_swap() {
    use std::os::unix::fs::PermissionsExt;

    let _work_lock = pq_work_lock();
    let root = tempdir().expect("root");
    let validators = root.path().join("validators");
    let passwords = root.path().join("passwords");
    fs::create_dir(&validators).expect("validators");
    fs::create_dir(&passwords).expect("passwords");
    fs::set_permissions(&validators, fs::Permissions::from_mode(0o700)).expect("private");
    fs::set_permissions(&passwords, fs::Permissions::from_mode(0o700)).expect("private");
    let validators_anchor = fs::File::open(&validators).expect("validators anchor");
    let passwords_anchor = fs::File::open(&passwords).expect("passwords anchor");

    let held_validators = root.path().join("held-validators");
    let held_passwords = root.path().join("held-passwords");
    fs::rename(&validators, &held_validators).expect("move validators");
    fs::rename(&passwords, &held_passwords).expect("move passwords");
    fs::create_dir(&validators).expect("replacement validators");
    fs::create_dir(&passwords).expect("replacement passwords");
    fs::set_permissions(&validators, fs::Permissions::from_mode(0o700)).expect("private");
    fs::set_permissions(&passwords, fs::Permissions::from_mode(0o700)).expect("private");

    let result = PqValidatorDirBuilder::new_anchored(validators.clone(), &validators_anchor)
        .expect("anchored builder")
        .password_dir_anchored(passwords.clone(), &passwords_anchor)
        .expect("anchored passwords")
        .voting_keystore(keystore(), PASSWORD)
        .build();

    assert!(matches!(
        result,
        Err(PqValidatorDirError::UnsafeDirectoryTarget(_))
    ));
    assert_eq!(fs::read_dir(&validators).expect("replacement").count(), 0);
    assert_eq!(fs::read_dir(&passwords).expect("replacement").count(), 0);
    assert_eq!(fs::read_dir(&held_validators).expect("held").count(), 1);
    assert_eq!(fs::read_dir(&held_passwords).expect("held").count(), 1);
}

#[cfg(unix)]
#[test]
fn open_rejects_noncanonical_directory_identity() {
    let _work_lock = pq_work_lock();
    let validators = tempdir().expect("validators");
    let validator = PqValidatorDirBuilder::new(validators.path().into())
        .voting_keystore(keystore(), PASSWORD)
        .build()
        .expect("build");
    let wrong = validators.path().join(format!("0x{}", "00".repeat(32)));
    fs::rename(validator.dir(), &wrong).expect("rename");
    assert!(matches!(
        PqValidatorDir::open(&wrong),
        Err(PqValidatorDirError::NonCanonicalDirectoryName(path)) if path == wrong
    ));
}
