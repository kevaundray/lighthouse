//! Bounded, versioned bundle metadata shared by PQ provisioning and validator startup.

use consensus_signature::{PqPublicKey, PqValidatorRegistryEntry};
use pq_signing::{PqKeyUnlock, PqSigningAuthority, PqSigningError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::{PqValidatorDir, PqValidatorDirError};

pub const PQ_DEVNET_GENESIS_FILE: &str = "genesis.ssz";
pub const PQ_DEVNET_MANIFEST_FILE: &str = "pq-devnet.json";
pub const PQ_DEVNET_JOURNAL_FILE: &str = pq_signing::XMSS_USAGE_FILENAME;
pub const MAX_PQ_DEVNET_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_PQ_DEVNET_VALIDATORS: usize = 16;
pub const PQ_DEVNET_GENESIS_DELAY_SECONDS: u64 = 300;
const MAX_PQ_DEVNET_ONE_TIME_USE_ID: u32 = 1119;
const VALIDATORS_DIR: &str = "validators";
const SECRETS_DIR: &str = "secrets";

#[derive(Debug)]
pub enum PqDevnetBundleError {
    UnsupportedPlatform,
    Io(PathBuf, io::Error),
    UnsafeManifest(PathBuf),
    Manifest(PqDevnetManifestError),
    ValidatorDir(PqValidatorDirError),
    UnexpectedBundleEntry(PathBuf),
    TooManyBundleEntries { actual_at_least: usize, max: usize },
    UnexpectedValidatorDirectory(PathBuf),
    TooManyValidatorEntries { actual_at_least: usize, max: usize },
    UnexpectedSecretEntry(PathBuf),
    TooManySecretEntries { actual_at_least: usize, max: usize },
    MissingValidator(PqPublicKey),
    DuplicateValidator(PqPublicKey),
    KeyRangeMismatch(PqPublicKey),
}

impl std::fmt::Display for PqDevnetBundleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PqDevnetBundleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::ValidatorDir(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PqDevnetManifestError> for PqDevnetBundleError {
    fn from(error: PqDevnetManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl From<PqValidatorDirError> for PqDevnetBundleError {
    fn from(error: PqValidatorDirError) -> Self {
        Self::ValidatorDir(error)
    }
}

/// Fully preflighted PQ validator inputs. Opening the signing authority remains a separate,
/// blocking operation owned by `InitializedValidators`.
pub struct PqDevnetBundle {
    manifest: ValidatedPqDevnetManifest,
    registry: Vec<PqValidatorRegistryEntry>,
    #[cfg(target_os = "linux")]
    root: File,
    unlocks: Vec<PqKeyUnlock>,
}

impl PqDevnetBundle {
    #[cfg(target_os = "linux")]
    pub fn load_for_network_registry(
        root: impl AsRef<Path>,
        network_genesis_validators_root: [u8; 32],
        network_genesis_time: u64,
        registry: &[PqValidatorRegistryEntry],
    ) -> Result<Self, PqDevnetBundleError> {
        Self::load_inner(
            root.as_ref(),
            network_genesis_validators_root,
            network_genesis_time,
            registry,
        )
    }

    #[cfg(target_os = "linux")]
    fn load_inner(
        root: &Path,
        network_genesis_validators_root: [u8; 32],
        network_genesis_time: u64,
        registry: &[PqValidatorRegistryEntry],
    ) -> Result<Self, PqDevnetBundleError> {
        use std::os::unix::fs::PermissionsExt;

        let root_fd = rustix::fs::openat(
            rustix::fs::CWD,
            root,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| PqDevnetBundleError::Io(root.into(), error.into()))?;
        let root_file = File::from(root_fd);
        let root_metadata = root_file
            .metadata()
            .map_err(|error| PqDevnetBundleError::Io(root.into(), error))?;
        if !root_metadata.is_dir() || root_metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(PqDevnetBundleError::UnsafeManifest(root.into()));
        }
        validate_bundle_entries(&root_file, root)?;
        let manifest = read_manifest(&root_file, root)?;
        let manifest = manifest.validate_for_network_registry(
            network_genesis_validators_root,
            network_genesis_time,
            registry,
        )?;
        let owned_registry = registry[..manifest.public_keys().len()].to_vec();
        let validators_root = open_private_directory(&root_file, root, VALIDATORS_DIR)?;
        let secrets_root = open_private_directory(&root_file, root, SECRETS_DIR)?;
        let validators_path = anchored_file_path(&validators_root);
        let secrets_path = anchored_file_path(&secrets_root);
        let discovered = open_bounded_validator_directories(&validators_root, &validators_path)?;
        let mut by_public_key = BTreeMap::new();
        for validator in discovered {
            let public_key = PqPublicKey::deserialize(validator.public_key()).map_err(|_| {
                PqDevnetBundleError::UnexpectedValidatorDirectory(validator.dir().into())
            })?;
            if by_public_key.insert(public_key, validator).is_some() {
                return Err(PqDevnetBundleError::DuplicateValidator(public_key));
            }
        }
        for public_key in manifest.public_keys() {
            if !by_public_key.contains_key(public_key) {
                return Err(PqDevnetBundleError::MissingValidator(*public_key));
            }
        }
        if let Some((_, validator)) = by_public_key
            .iter()
            .find(|(public_key, _)| !manifest.public_keys().contains(public_key))
        {
            return Err(PqDevnetBundleError::UnexpectedValidatorDirectory(
                validator.dir().into(),
            ));
        }

        let secret_entries = read_secret_entries(&secrets_root, &root.join(SECRETS_DIR))?;
        let mut expected_secret_entries = manifest
            .public_keys()
            .iter()
            .map(|public_key| {
                std::ffi::OsString::from(format!("0x{}", hex::encode(public_key.serialize())))
            })
            .collect::<Vec<_>>();
        expected_secret_entries.sort();
        if secret_entries != expected_secret_entries {
            let unexpected = secret_entries
                .into_iter()
                .find(|entry| !expected_secret_entries.contains(entry))
                .unwrap_or_else(|| std::ffi::OsString::from("<missing-secret>"));
            return Err(PqDevnetBundleError::UnexpectedSecretEntry(
                root.join(SECRETS_DIR).join(unexpected),
            ));
        }

        let mut unlocks = Vec::with_capacity(manifest.public_keys().len());
        let expected_range = manifest.one_time_use_start()..=manifest.one_time_use_end();
        for public_key in manifest.public_keys() {
            let validator = by_public_key
                .remove(public_key)
                .ok_or(PqDevnetBundleError::MissingValidator(*public_key))?;
            let unlock = validator.key_unlock(&secrets_path)?;
            if unlock.one_time_use_range() != expected_range {
                return Err(PqDevnetBundleError::KeyRangeMismatch(*public_key));
            }
            unlocks.push(unlock);
        }
        if let Some((_, validator)) = by_public_key.into_iter().next() {
            return Err(PqDevnetBundleError::UnexpectedValidatorDirectory(
                validator.dir().into(),
            ));
        }

        Ok(Self {
            manifest,
            registry: owned_registry,
            root: root_file,
            unlocks,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load_for_network_registry(
        _root: impl AsRef<Path>,
        _network_genesis_validators_root: [u8; 32],
        _network_genesis_time: u64,
        _registry: &[PqValidatorRegistryEntry],
    ) -> Result<Self, PqDevnetBundleError> {
        Err(PqDevnetBundleError::UnsupportedPlatform)
    }

    pub fn public_keys(&self) -> &[PqPublicKey] {
        self.manifest.public_keys()
    }

    pub fn registry(&self) -> &[PqValidatorRegistryEntry] {
        &self.registry
    }

    pub fn unlock_count(&self) -> usize {
        self.unlocks.len()
    }

    #[cfg(target_os = "linux")]
    pub fn open_authority(
        self,
        network_genesis_validators_root: [u8; 32],
    ) -> Result<PqSigningAuthority, PqSigningError> {
        PqSigningAuthority::open_anchored(&self.root, network_genesis_validators_root, self.unlocks)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open_authority(
        self,
        _network_genesis_validators_root: [u8; 32],
    ) -> Result<PqSigningAuthority, PqSigningError> {
        Err(PqSigningError::Journal(
            pq_signing::PqUsageJournalError::UnsupportedPlatform,
        ))
    }
}

#[cfg(target_os = "linux")]
fn anchored_file_path(file: &File) -> PathBuf {
    use std::os::fd::AsRawFd;

    PathBuf::from(format!("/proc/self/fd/{}/.", file.as_raw_fd()))
}

#[cfg(target_os = "linux")]
fn bounded_validator_entry_paths(
    validators_root: &File,
    validators_path: &Path,
) -> Result<Vec<PathBuf>, PqDevnetBundleError> {
    let entry_limit = MAX_PQ_DEVNET_VALIDATORS.checked_add(1).ok_or(
        PqDevnetBundleError::TooManyValidatorEntries {
            actual_at_least: usize::MAX,
            max: MAX_PQ_DEVNET_VALIDATORS,
        },
    )?;
    let mut bounded_entries = Vec::with_capacity(entry_limit);
    let entries = fs::read_dir(anchored_file_path(validators_root))
        .map_err(|error| PqDevnetBundleError::Io(validators_path.into(), error))?;
    for entry in entries.take(entry_limit) {
        let entry =
            entry.map_err(|error| PqDevnetBundleError::Io(validators_path.into(), error))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| PqDevnetBundleError::Io(path.clone(), error))?;
        bounded_entries.push((path, file_type));
    }
    if bounded_entries.len() > MAX_PQ_DEVNET_VALIDATORS {
        return Err(PqDevnetBundleError::TooManyValidatorEntries {
            actual_at_least: bounded_entries.len(),
            max: MAX_PQ_DEVNET_VALIDATORS,
        });
    }
    let mut child_directories = Vec::with_capacity(bounded_entries.len());
    for (path, file_type) in bounded_entries {
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(PqDevnetBundleError::UnexpectedValidatorDirectory(path));
        }
        let valid_public_key_name = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .and_then(|name| name.strip_prefix("0x"))
            .and_then(|encoded| hex::decode(encoded).ok())
            .and_then(|bytes| PqPublicKey::deserialize(&bytes).ok())
            .is_some();
        if !valid_public_key_name {
            return Err(PqDevnetBundleError::UnexpectedValidatorDirectory(path));
        }
        child_directories.push(path);
    }
    child_directories.sort();
    Ok(child_directories)
}

#[cfg(target_os = "linux")]
fn open_bounded_validator_directories(
    validators_root: &File,
    validators_path: &Path,
) -> Result<Vec<PqValidatorDir>, PqDevnetBundleError> {
    open_bounded_validator_directories_with_hook(validators_root, validators_path, || {})
}

#[cfg(target_os = "linux")]
fn open_bounded_validator_directories_with_hook(
    validators_root: &File,
    validators_path: &Path,
    after_initial_scan: impl FnOnce(),
) -> Result<Vec<PqValidatorDir>, PqDevnetBundleError> {
    let initial_paths = bounded_validator_entry_paths(validators_root, validators_path)?;
    after_initial_scan();
    let discovered = initial_paths
        .iter()
        .map(PqValidatorDir::open)
        .collect::<Result<Vec<_>, _>>()?;
    let final_paths = bounded_validator_entry_paths(validators_root, validators_path)?;
    if final_paths != initial_paths {
        let unexpected = final_paths
            .into_iter()
            .find(|path| !initial_paths.contains(path))
            .unwrap_or_else(|| validators_path.to_path_buf());
        return Err(PqDevnetBundleError::UnexpectedValidatorDirectory(
            unexpected,
        ));
    }
    Ok(discovered)
}

#[cfg(target_os = "linux")]
fn validate_bundle_entries(root_file: &File, root: &Path) -> Result<(), PqDevnetBundleError> {
    const EXPECTED_ENTRY_COUNT: usize = 5;

    let entry_limit =
        EXPECTED_ENTRY_COUNT
            .checked_add(1)
            .ok_or(PqDevnetBundleError::TooManyBundleEntries {
                actual_at_least: usize::MAX,
                max: EXPECTED_ENTRY_COUNT,
            })?;
    let anchored_root = anchored_file_path(root_file);
    let mut entries = fs::read_dir(&anchored_root)
        .map_err(|error| PqDevnetBundleError::Io(root.into(), error))?
        .take(entry_limit)
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|error| PqDevnetBundleError::Io(root.into(), error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if entries.len() > EXPECTED_ENTRY_COUNT {
        return Err(PqDevnetBundleError::TooManyBundleEntries {
            actual_at_least: entries.len(),
            max: EXPECTED_ENTRY_COUNT,
        });
    }
    entries.sort();
    let mut expected = vec![
        std::ffi::OsString::from(PQ_DEVNET_MANIFEST_FILE),
        std::ffi::OsString::from(PQ_DEVNET_JOURNAL_FILE),
        std::ffi::OsString::from(format!("{PQ_DEVNET_JOURNAL_FILE}.lock")),
        std::ffi::OsString::from(SECRETS_DIR),
        std::ffi::OsString::from(VALIDATORS_DIR),
    ];
    expected.sort();
    if entries != expected {
        let unexpected = entries
            .into_iter()
            .find(|entry| !expected.contains(entry))
            .unwrap_or_else(|| std::ffi::OsString::from("<missing-entry>"));
        return Err(PqDevnetBundleError::UnexpectedBundleEntry(
            root.join(unexpected),
        ));
    }
    validate_private_regular_file(root_file, root, PQ_DEVNET_JOURNAL_FILE)?;
    let journal_lock = format!("{PQ_DEVNET_JOURNAL_FILE}.lock");
    validate_private_regular_file(root_file, root, &journal_lock)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_private_directory(
    root_file: &File,
    root: &Path,
    name: &'static str,
) -> Result<File, PqDevnetBundleError> {
    use std::os::unix::fs::PermissionsExt;

    let path = root.join(name);
    let fd = rustix::fs::openat(
        root_file,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| PqDevnetBundleError::Io(path.clone(), error.into()))?;
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|error| PqDevnetBundleError::Io(path.clone(), error))?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(PqDevnetBundleError::UnexpectedBundleEntry(path));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn validate_private_regular_file(
    root_file: &File,
    root: &Path,
    name: &str,
) -> Result<(), PqDevnetBundleError> {
    use std::os::unix::fs::PermissionsExt;

    let path = root.join(name);
    let fd = rustix::fs::openat(
        root_file,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| PqDevnetBundleError::Io(path.clone(), error.into()))?;
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|error| PqDevnetBundleError::Io(path.clone(), error))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(PqDevnetBundleError::UnexpectedBundleEntry(path));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_secret_entries(
    secrets: &File,
    secrets_path: &Path,
) -> Result<Vec<std::ffi::OsString>, PqDevnetBundleError> {
    use std::os::unix::fs::PermissionsExt;

    let entry_limit = MAX_PQ_DEVNET_VALIDATORS.checked_add(1).ok_or(
        PqDevnetBundleError::TooManySecretEntries {
            actual_at_least: usize::MAX,
            max: MAX_PQ_DEVNET_VALIDATORS,
        },
    )?;
    let mut names = Vec::with_capacity(entry_limit);
    let entries = fs::read_dir(anchored_file_path(secrets))
        .map_err(|error| PqDevnetBundleError::Io(secrets_path.into(), error))?;
    for entry in entries.take(entry_limit) {
        let entry = entry.map_err(|error| PqDevnetBundleError::Io(secrets_path.into(), error))?;
        let name = entry.file_name();
        let path = secrets_path.join(&name);
        let file_type = entry
            .file_type()
            .map_err(|error| PqDevnetBundleError::Io(path.clone(), error))?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(PqDevnetBundleError::UnexpectedSecretEntry(path));
        }
        let fd = rustix::fs::openat(
            secrets,
            &name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| PqDevnetBundleError::Io(path.clone(), error.into()))?;
        let file = File::from(fd);
        let metadata = file
            .metadata()
            .map_err(|error| PqDevnetBundleError::Io(path.clone(), error))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(PqDevnetBundleError::UnexpectedSecretEntry(path));
        }
        let entry_stat = rustix::fs::statat(secrets, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| PqDevnetBundleError::Io(path.clone(), error.into()))?;
        let file_stat = rustix::fs::fstat(&file)
            .map_err(|error| PqDevnetBundleError::Io(path.clone(), error.into()))?;
        if entry_stat.st_dev != file_stat.st_dev || entry_stat.st_ino != file_stat.st_ino {
            return Err(PqDevnetBundleError::UnexpectedSecretEntry(path));
        }
        names.push(name);
    }
    if names.len() > MAX_PQ_DEVNET_VALIDATORS {
        return Err(PqDevnetBundleError::TooManySecretEntries {
            actual_at_least: names.len(),
            max: MAX_PQ_DEVNET_VALIDATORS,
        });
    }
    names.sort();
    Ok(names)
}

#[cfg(target_os = "linux")]
fn read_manifest(root_file: &File, root: &Path) -> Result<PqDevnetManifest, PqDevnetBundleError> {
    use std::os::unix::fs::PermissionsExt;

    let manifest_path = root.join(PQ_DEVNET_MANIFEST_FILE);
    let manifest_fd = rustix::fs::openat(
        root_file,
        PQ_DEVNET_MANIFEST_FILE,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| PqDevnetBundleError::Io(manifest_path.clone(), error.into()))?;
    let manifest_file = File::from(manifest_fd);
    let metadata = manifest_file
        .metadata()
        .map_err(|error| PqDevnetBundleError::Io(manifest_path.clone(), error))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(PqDevnetBundleError::UnsafeManifest(manifest_path));
    }
    let read_limit = MAX_PQ_DEVNET_MANIFEST_BYTES.checked_add(1).ok_or(
        PqDevnetManifestError::ManifestTooLarge {
            actual: usize::MAX,
            max: MAX_PQ_DEVNET_MANIFEST_BYTES,
        },
    )?;
    let mut bytes = Vec::with_capacity(read_limit);
    manifest_file
        .take(
            u64::try_from(read_limit).map_err(|_| PqDevnetManifestError::ManifestTooLarge {
                actual: read_limit,
                max: MAX_PQ_DEVNET_MANIFEST_BYTES,
            })?,
        )
        .read_to_end(&mut bytes)
        .map_err(|error| PqDevnetBundleError::Io(manifest_path, error))?;
    PqDevnetManifest::from_json_slice(&bytes).map_err(Into::into)
}

#[derive(Debug)]
pub enum PqDevnetManifestError {
    ManifestTooLarge {
        actual: usize,
        max: usize,
    },
    Json(serde_json::Error),
    UnsupportedProfile,
    InvalidValidatorCount(usize),
    InvalidOneTimeUseRange {
        start: u32,
        end: u32,
    },
    InvalidHex(&'static str),
    WrongNetworkRoot {
        manifest: [u8; 32],
        network: [u8; 32],
    },
    WrongGenesisTime {
        manifest: u64,
        network: u64,
    },
    GenesisTimeOverflow {
        eth1_timestamp: u64,
        genesis_delay: u64,
    },
    RegistryLengthMismatch {
        manifest: usize,
        registry: usize,
    },
    RegistryIndexMismatch {
        position: usize,
        actual: u64,
    },
    RegistryPublicKeyMismatch {
        index: u64,
    },
    RegistryWithdrawalCredentialsMismatch {
        index: u64,
    },
    DuplicatePublicKey(PqPublicKey),
    DuplicateDerivationIndex(u64),
    NonCanonicalDerivationOrder,
}

impl std::fmt::Display for PqDevnetManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PqDevnetManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqDevnetManifest {
    format: String,
    version: u32,
    preset: String,
    fork: String,
    validator_count: usize,
    one_time_use_start: u32,
    one_time_use_end: u32,
    eth1_timestamp: u64,
    genesis_validators_root: String,
    validators: Vec<PqManifestValidator>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqManifestValidator {
    derivation_index: u64,
    public_key: String,
    withdrawal_credentials: String,
}

impl PqManifestValidator {
    pub fn new(
        derivation_index: u64,
        public_key: PqPublicKey,
        withdrawal_credentials: [u8; 32],
    ) -> Self {
        Self {
            derivation_index,
            public_key: hex::encode(public_key.serialize()),
            withdrawal_credentials: hex::encode(withdrawal_credentials),
        }
    }
}

impl PqDevnetManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator_count: usize,
        one_time_use_start: u32,
        one_time_use_end: u32,
        eth1_timestamp: u64,
        genesis_validators_root: [u8; 32],
        validators: Vec<PqManifestValidator>,
    ) -> Self {
        Self {
            format: "lighthouse-pq-devnet".to_owned(),
            version: 1,
            preset: "minimal".to_owned(),
            fork: "electra".to_owned(),
            validator_count,
            one_time_use_start,
            one_time_use_end,
            eth1_timestamp,
            genesis_validators_root: hex::encode(genesis_validators_root),
            validators,
        }
    }

    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, PqDevnetManifestError> {
        if bytes.len() > MAX_PQ_DEVNET_MANIFEST_BYTES {
            return Err(PqDevnetManifestError::ManifestTooLarge {
                actual: bytes.len(),
                max: MAX_PQ_DEVNET_MANIFEST_BYTES,
            });
        }
        serde_json::from_slice(bytes).map_err(PqDevnetManifestError::Json)
    }

    fn validate_profile_and_root(
        &self,
        network_genesis_validators_root: [u8; 32],
    ) -> Result<ValidatedPqDevnetManifest, PqDevnetManifestError> {
        if self.format != "lighthouse-pq-devnet"
            || self.version != 1
            || self.preset != "minimal"
            || self.fork != "electra"
        {
            return Err(PqDevnetManifestError::UnsupportedProfile);
        }
        if self.validator_count == 0
            || self.validator_count > MAX_PQ_DEVNET_VALIDATORS
            || self.validators.len() != self.validator_count
        {
            return Err(PqDevnetManifestError::InvalidValidatorCount(
                self.validator_count,
            ));
        }
        if self.one_time_use_start > self.one_time_use_end
            || self.one_time_use_end > MAX_PQ_DEVNET_ONE_TIME_USE_ID
        {
            return Err(PqDevnetManifestError::InvalidOneTimeUseRange {
                start: self.one_time_use_start,
                end: self.one_time_use_end,
            });
        }
        let manifest_root =
            decode_fixed_hex(&self.genesis_validators_root, "genesis_validators_root")?;
        if manifest_root != network_genesis_validators_root {
            return Err(PqDevnetManifestError::WrongNetworkRoot {
                manifest: manifest_root,
                network: network_genesis_validators_root,
            });
        }

        let mut public_key_set = HashSet::with_capacity(self.validator_count);
        let mut derivation_indices = HashSet::with_capacity(self.validator_count);
        let mut public_keys = Vec::with_capacity(self.validator_count);
        let mut withdrawal_credentials = Vec::with_capacity(self.validator_count);
        for (position, validator) in self.validators.iter().enumerate() {
            let expected_index = u64::try_from(position)
                .map_err(|_| PqDevnetManifestError::NonCanonicalDerivationOrder)?;
            if validator.derivation_index != expected_index {
                return Err(PqDevnetManifestError::NonCanonicalDerivationOrder);
            }
            if !derivation_indices.insert(validator.derivation_index) {
                return Err(PqDevnetManifestError::DuplicateDerivationIndex(
                    validator.derivation_index,
                ));
            }
            let public_key = PqPublicKey::deserialize(&decode_fixed_hex(
                &validator.public_key,
                "validator public key",
            )?)
            .map_err(|_| PqDevnetManifestError::InvalidHex("validator public key"))?;
            if !public_key_set.insert(public_key) {
                return Err(PqDevnetManifestError::DuplicatePublicKey(public_key));
            }
            public_keys.push(public_key);
            withdrawal_credentials.push(decode_fixed_hex(
                &validator.withdrawal_credentials,
                "withdrawal credentials",
            )?);
        }

        Ok(ValidatedPqDevnetManifest {
            public_keys,
            withdrawal_credentials,
            genesis_validators_root: manifest_root,
            one_time_use_start: self.one_time_use_start,
            one_time_use_end: self.one_time_use_end,
            eth1_timestamp: self.eth1_timestamp,
        })
    }

    pub fn validate_for_network_identity(
        &self,
        network_genesis_validators_root: [u8; 32],
        network_genesis_time: u64,
    ) -> Result<ValidatedPqDevnetManifest, PqDevnetManifestError> {
        let validated = self.validate_profile_and_root(network_genesis_validators_root)?;
        let manifest_genesis_time = validated
            .eth1_timestamp
            .checked_add(PQ_DEVNET_GENESIS_DELAY_SECONDS)
            .ok_or(PqDevnetManifestError::GenesisTimeOverflow {
                eth1_timestamp: validated.eth1_timestamp,
                genesis_delay: PQ_DEVNET_GENESIS_DELAY_SECONDS,
            })?;
        if manifest_genesis_time != network_genesis_time {
            return Err(PqDevnetManifestError::WrongGenesisTime {
                manifest: manifest_genesis_time,
                network: network_genesis_time,
            });
        }
        Ok(validated)
    }

    pub fn validate_for_network_registry(
        &self,
        network_genesis_validators_root: [u8; 32],
        network_genesis_time: u64,
        registry: &[PqValidatorRegistryEntry],
    ) -> Result<ValidatedPqDevnetManifest, PqDevnetManifestError> {
        let validated = self
            .validate_for_network_identity(network_genesis_validators_root, network_genesis_time)?;
        if validated.public_keys.len() > registry.len() {
            return Err(PqDevnetManifestError::RegistryLengthMismatch {
                manifest: validated.public_keys.len(),
                registry: registry.len(),
            });
        }
        for (position, ((manifest_public_key, manifest_withdrawal), registry_entry)) in validated
            .public_keys
            .iter()
            .zip(&validated.withdrawal_credentials)
            .zip(registry)
            .enumerate()
        {
            let expected_index = u64::try_from(position)
                .map_err(|_| PqDevnetManifestError::NonCanonicalDerivationOrder)?;
            if registry_entry.validator_index() != expected_index {
                return Err(PqDevnetManifestError::RegistryIndexMismatch {
                    position,
                    actual: registry_entry.validator_index(),
                });
            }
            if registry_entry.public_key() != *manifest_public_key {
                return Err(PqDevnetManifestError::RegistryPublicKeyMismatch {
                    index: expected_index,
                });
            }
            if registry_entry.withdrawal_credentials() != *manifest_withdrawal {
                return Err(
                    PqDevnetManifestError::RegistryWithdrawalCredentialsMismatch {
                        index: expected_index,
                    },
                );
            }
        }
        Ok(validated)
    }
}

fn decode_fixed_hex(value: &str, field: &'static str) -> Result<[u8; 32], PqDevnetManifestError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PqDevnetManifestError::InvalidHex(field));
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| PqDevnetManifestError::InvalidHex(field))?;
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPqDevnetManifest {
    public_keys: Vec<PqPublicKey>,
    withdrawal_credentials: Vec<[u8; 32]>,
    genesis_validators_root: [u8; 32],
    one_time_use_start: u32,
    one_time_use_end: u32,
    eth1_timestamp: u64,
}

impl ValidatedPqDevnetManifest {
    pub fn public_keys(&self) -> &[PqPublicKey] {
        &self.public_keys
    }

    pub fn withdrawal_credentials(&self) -> &[[u8; 32]] {
        &self.withdrawal_credentials
    }

    pub const fn genesis_validators_root(&self) -> [u8; 32] {
        self.genesis_validators_root
    }

    pub const fn one_time_use_start(&self) -> u32 {
        self.one_time_use_start
    }

    pub const fn one_time_use_end(&self) -> u32 {
        self.one_time_use_end
    }

    pub const fn eth1_timestamp(&self) -> u64 {
        self.eth1_timestamp
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn entries_added_between_validator_scan_phases_are_bounded_and_rejected() {
        let root = tempfile::tempdir().expect("temporary root");
        let validators = root.path().join(VALIDATORS_DIR);
        fs::create_dir(&validators).expect("validator directory");
        fs::set_permissions(&validators, fs::Permissions::from_mode(0o700))
            .expect("private validator directory");
        let validators_file = File::open(&validators).expect("held validator directory");

        let error =
            open_bounded_validator_directories_with_hook(&validators_file, &validators, || {
                for index in 0..=MAX_PQ_DEVNET_VALIDATORS {
                    fs::create_dir(validators.join(format!("late-{index}")))
                        .expect("late validator entry");
                }
            })
            .expect_err("late entries must be bounded and rejected");
        assert!(matches!(
            error,
            PqDevnetBundleError::TooManyValidatorEntries {
                actual_at_least: 17,
                max: 16,
            }
        ));
    }

    #[test]
    fn bounded_validator_scan_rejects_an_unexpected_directory_name_before_open() {
        let root = tempfile::tempdir().expect("temporary root");
        let validators = root.path().join(VALIDATORS_DIR);
        fs::create_dir(&validators).expect("validator directory");
        fs::set_permissions(&validators, fs::Permissions::from_mode(0o700))
            .expect("private validator directory");
        fs::create_dir(validators.join("unrelated")).expect("unexpected validator directory");
        let validators_file = File::open(&validators).expect("held validator directory");

        assert!(matches!(
            bounded_validator_entry_paths(&validators_file, &validators),
            Err(PqDevnetBundleError::UnexpectedValidatorDirectory(path))
                if path.file_name() == Some(std::ffi::OsStr::new("unrelated"))
        ));
    }
}
