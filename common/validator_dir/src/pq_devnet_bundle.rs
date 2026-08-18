//! Bounded, versioned bundle metadata shared by PQ provisioning and validator startup.

use consensus_signature::PqPublicKey;
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
    UnexpectedValidatorDirectory(PathBuf),
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
    #[cfg(target_os = "linux")]
    root: File,
    unlocks: Vec<PqKeyUnlock>,
}

impl PqDevnetBundle {
    #[cfg(target_os = "linux")]
    pub fn load(
        root: impl AsRef<Path>,
        network_genesis_validators_root: [u8; 32],
    ) -> Result<Self, PqDevnetBundleError> {
        use std::os::unix::fs::PermissionsExt;

        let root = root.as_ref();
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
        let manifest = read_manifest(&root_file, root)?
            .validate_for_network(network_genesis_validators_root)?;
        let validators_path = anchored_child_path(&root_file, VALIDATORS_DIR);
        let secrets_path = anchored_child_path(&root_file, SECRETS_DIR);

        let mut child_directories = Vec::new();
        let entries = fs::read_dir(&validators_path)
            .map_err(|error| PqDevnetBundleError::Io(validators_path.clone(), error))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| PqDevnetBundleError::Io(validators_path.clone(), error))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| PqDevnetBundleError::Io(path.clone(), error))?;
            if file_type.is_symlink() {
                return Err(PqDevnetBundleError::UnexpectedValidatorDirectory(path));
            }
            if file_type.is_dir() {
                child_directories.push(path);
            }
        }

        let discovered = PqValidatorDir::discover(&validators_path)?;
        if discovered.len() != child_directories.len() {
            let unexpected = child_directories
                .into_iter()
                .find(|path| !discovered.iter().any(|validator| validator.dir() == path))
                .unwrap_or(validators_path);
            return Err(PqDevnetBundleError::UnexpectedValidatorDirectory(
                unexpected,
            ));
        }
        let mut by_public_key = BTreeMap::new();
        for validator in discovered {
            let public_key = PqPublicKey::deserialize(validator.public_key()).map_err(|_| {
                PqDevnetBundleError::UnexpectedValidatorDirectory(validator.dir().into())
            })?;
            if by_public_key.insert(public_key, validator).is_some() {
                return Err(PqDevnetBundleError::DuplicateValidator(public_key));
            }
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
            root: root_file,
            unlocks,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load(
        _root: impl AsRef<Path>,
        _network_genesis_validators_root: [u8; 32],
    ) -> Result<Self, PqDevnetBundleError> {
        Err(PqDevnetBundleError::UnsupportedPlatform)
    }

    pub fn public_keys(&self) -> &[PqPublicKey] {
        self.manifest.public_keys()
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
fn anchored_child_path(root: &File, child: &str) -> PathBuf {
    use std::os::fd::AsRawFd;

    PathBuf::from(format!("/proc/self/fd/{}/{}", root.as_raw_fd(), child))
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

    pub fn validate_for_network(
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
