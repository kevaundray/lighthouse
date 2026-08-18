use consensus_signature::PqPublicKey;
use pq_signing::{
    MAX_PQ_PASSWORD_BYTES, PqKeystore, PqKeystoreError, PqSigningError, XMSS_USAGE_FILENAME,
    validate_pq_password,
};
#[cfg(target_os = "linux")]
use pq_signing::{provision_usage_journal_anchored, validate_usage_journal_anchored};
use rustix::fs::{Mode, OFlags, RenameFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssz::Encode;
use state_processing::{DirectGenesisValidator, initialize_beacon_state_from_validators};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::ops::RangeInclusive;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use types::{BeaconState, ChainSpec, EthSpec, ForkName, Hash256, MinimalEthSpec};
use validator_dir::{PqValidatorDir, PqValidatorDirBuilder, PqValidatorDirError};
use zeroize::Zeroizing;

pub const PQ_DEVNET_GENESIS_FILE: &str = "genesis.ssz";
pub const PQ_DEVNET_MANIFEST_FILE: &str = "pq-devnet.json";
pub const PQ_DEVNET_JOURNAL_FILE: &str = XMSS_USAGE_FILENAME;
const VALIDATORS_DIR: &str = "validators";
const PASSWORDS_DIR: &str = "secrets";
const PRODUCTION_VALIDATOR_COUNT: usize = 16;
const MAX_VALIDATOR_COUNT: usize = PRODUCTION_VALIDATOR_COUNT;
const PRODUCTION_RANGE_START: u32 = 0;
const PRODUCTION_RANGE_END: u32 = 1119;
const MAX_INPUT_FILE_BYTES: usize = MAX_PQ_PASSWORD_BYTES;
const MAX_GENESIS_BYTES: usize = 128 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const VALIDATOR_SEED_DOMAIN: &[u8] = b"lighthouse/pq-devnet/validator-seed/v1";
const WITHDRAWAL_DOMAIN: &[u8] = b"lighthouse/pq-devnet/withdrawal-credentials/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionConfig {
    destination: PathBuf,
    validator_count: usize,
    one_time_use_range: RangeInclusive<u32>,
    eth1_timestamp: u64,
}

impl ProvisionConfig {
    /// Small deterministic profile intended for tests and measured development runs.
    pub fn for_test(
        destination: PathBuf,
        validator_count: usize,
        one_time_use_range: RangeInclusive<u32>,
        eth1_timestamp: u64,
    ) -> Self {
        Self {
            destination,
            validator_count,
            one_time_use_range,
            eth1_timestamp,
        }
    }

    pub const fn validator_count(&self) -> usize {
        self.validator_count
    }

    pub fn one_time_use_range(&self) -> RangeInclusive<u32> {
        self.one_time_use_range.clone()
    }
}

pub fn production_config(destination: PathBuf, eth1_timestamp: u64) -> ProvisionConfig {
    ProvisionConfig {
        destination,
        validator_count: PRODUCTION_VALIDATOR_COUNT,
        one_time_use_range: PRODUCTION_RANGE_START..=PRODUCTION_RANGE_END,
        eth1_timestamp,
    }
}

#[derive(Debug)]
pub enum ProvisionError {
    UnsupportedPlatform,
    InvalidConfig,
    ValidatorCountTooLarge(usize),
    DestinationExists(PathBuf),
    StagingExists(PathBuf),
    InvalidDestination(PathBuf),
    UnsafeInput(PathBuf),
    InvalidMasterSeedLength(usize),
    PasswordTooLarge(usize),
    Io(PathBuf, io::Error),
    Keystore(PqKeystoreError),
    ValidatorDir(PqValidatorDirError),
    Journal(PqSigningError),
    State(String),
    Json(String),
    Integrity(String),
    Publish(PathBuf, io::Error),
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProvisionError {}

impl From<PqKeystoreError> for ProvisionError {
    fn from(error: PqKeystoreError) -> Self {
        Self::Keystore(error)
    }
}

impl From<PqValidatorDirError> for ProvisionError {
    fn from(error: PqValidatorDirError) -> Self {
        Self::ValidatorDir(error)
    }
}

impl From<PqSigningError> for ProvisionError {
    fn from(error: PqSigningError) -> Self {
        Self::Journal(error)
    }
}

#[derive(Clone, Debug)]
pub struct ProvisionedDevnet {
    output_dir: PathBuf,
    public_keys: Vec<PqPublicKey>,
    genesis_state_bytes: Vec<u8>,
    genesis_validators_root: [u8; 32],
}

impl ProvisionedDevnet {
    pub fn output_dir(&self) -> &Path {
        &self.output_dir
    }

    pub fn public_keys(&self) -> Vec<PqPublicKey> {
        self.public_keys.clone()
    }

    pub fn genesis_state_bytes(&self) -> &[u8] {
        &self.genesis_state_bytes
    }

    pub const fn genesis_validators_root(&self) -> [u8; 32] {
        self.genesis_validators_root
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    version: u32,
    preset: String,
    fork: String,
    validator_count: usize,
    one_time_use_start: u32,
    one_time_use_end: u32,
    eth1_timestamp: u64,
    genesis_validators_root: String,
    validators: Vec<ManifestValidator>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestValidator {
    derivation_index: u64,
    public_key: String,
    withdrawal_credentials: String,
}

pub fn staging_path(destination: &Path) -> Result<PathBuf, ProvisionError> {
    let file_name = destination
        .file_name()
        .ok_or_else(|| ProvisionError::InvalidDestination(destination.to_path_buf()))?;
    let mut staging_name = OsString::from(file_name);
    staging_name.push(".pq-staging");
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(staging_name))
}

#[cfg(target_os = "linux")]
struct AnchoredDestination {
    destination: PathBuf,
    staging: PathBuf,
    parent_path: PathBuf,
    parent: File,
    destination_component: OsString,
    staging_component: OsString,
}

#[cfg(target_os = "linux")]
struct AnchoredDirectory {
    path: PathBuf,
    file: File,
}

#[cfg(target_os = "linux")]
impl AnchoredDestination {
    fn preflight(destination: &Path) -> Result<Self, ProvisionError> {
        let staging = staging_path(destination)?;
        let destination_component = destination
            .file_name()
            .ok_or_else(|| ProvisionError::InvalidDestination(destination.to_path_buf()))?
            .to_os_string();
        let staging_component = staging
            .file_name()
            .ok_or_else(|| ProvisionError::InvalidDestination(staging.clone()))?
            .to_os_string();
        let parent_path = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            &parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| ProvisionError::Io(parent_path.clone(), error.into()))?;
        let parent = File::from(fd);
        if !parent
            .metadata()
            .map_err(|error| ProvisionError::Io(parent_path.clone(), error))?
            .is_dir()
        {
            return Err(ProvisionError::InvalidDestination(parent_path));
        }
        if entry_exists_at(&parent, &destination_component, destination)? {
            return Err(ProvisionError::DestinationExists(destination.to_path_buf()));
        }
        if entry_exists_at(&parent, &staging_component, &staging)? {
            return Err(ProvisionError::StagingExists(staging));
        }
        Ok(Self {
            destination: destination.to_path_buf(),
            staging,
            parent_path,
            parent,
            destination_component,
            staging_component,
        })
    }

    fn create_staging(&self) -> Result<AnchoredDirectory, ProvisionError> {
        rustix::fs::mkdirat(&self.parent, &self.staging_component, Mode::RWXU)
            .map_err(|error| ProvisionError::Io(self.staging.clone(), error.into()))?;
        rustix::fs::fsync(&self.parent)
            .map_err(|error| ProvisionError::Io(self.parent_path.clone(), error.into()))?;
        let staging =
            open_private_directory_at(&self.parent, &self.staging_component, &self.staging)?;
        verify_entry_identity(
            &self.parent,
            &self.staging_component,
            &staging.file,
            &self.staging,
        )?;
        Ok(staging)
    }

    fn publish(&self, staging: AnchoredDirectory) -> Result<AnchoredDirectory, ProvisionError> {
        self.publish_with_parent_sync(staging, |parent| {
            rustix::fs::fsync(parent).map_err(io::Error::from)
        })
    }

    fn publish_with_parent_sync(
        &self,
        staging: AnchoredDirectory,
        sync_parent: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<AnchoredDirectory, ProvisionError> {
        self.verify_parent_path()?;
        verify_entry_identity(
            &self.parent,
            &self.staging_component,
            &staging.file,
            &self.staging,
        )?;
        if entry_exists_at(&self.parent, &self.destination_component, &self.destination)? {
            return Err(ProvisionError::DestinationExists(self.destination.clone()));
        }
        rustix::fs::renameat_with(
            &self.parent,
            &self.staging_component,
            &self.parent,
            &self.destination_component,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| ProvisionError::Publish(self.destination.clone(), error.into()))?;
        sync_parent(&self.parent)
            .map_err(|error| ProvisionError::Io(self.parent_path.clone(), error))?;
        let published = open_private_directory_at(
            &self.parent,
            &self.destination_component,
            &self.destination,
        )?;
        let staging_stat = rustix::fs::fstat(&staging.file)
            .map_err(|error| ProvisionError::Io(self.destination.clone(), error.into()))?;
        let published_stat = rustix::fs::fstat(&published.file)
            .map_err(|error| ProvisionError::Io(self.destination.clone(), error.into()))?;
        if !same_identity(&staging_stat, &published_stat) {
            return Err(ProvisionError::Integrity(
                "published directory identity mismatch".to_owned(),
            ));
        }
        Ok(published)
    }

    fn verify_parent_path(&self) -> Result<(), ProvisionError> {
        let path_stat = rustix::fs::statat(
            rustix::fs::CWD,
            &self.parent_path,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| ProvisionError::Io(self.parent_path.clone(), error.into()))?;
        let fd_stat = rustix::fs::fstat(&self.parent)
            .map_err(|error| ProvisionError::Io(self.parent_path.clone(), error.into()))?;
        if same_identity(&path_stat, &fd_stat) {
            Ok(())
        } else {
            Err(ProvisionError::InvalidDestination(self.parent_path.clone()))
        }
    }

    fn verify_public_path(&self, published: &AnchoredDirectory) -> Result<(), ProvisionError> {
        self.verify_parent_path()?;
        verify_entry_identity(
            &self.parent,
            &self.destination_component,
            &published.file,
            &self.destination,
        )
    }
}

#[cfg(target_os = "linux")]
fn proc_fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(target_os = "linux")]
fn open_private_directory_at(
    parent: &File,
    component: &OsStr,
    display_path: &Path,
) -> Result<AnchoredDirectory, ProvisionError> {
    let fd = rustix::fs::openat(
        parent,
        component,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ProvisionError::Io(display_path.to_path_buf(), error.into()))?;
    rustix::fs::fchmod(&fd, Mode::RWXU)
        .map_err(|error| ProvisionError::Io(display_path.to_path_buf(), error.into()))?;
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|error| ProvisionError::Io(display_path.to_path_buf(), error))?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(ProvisionError::InvalidDestination(
            display_path.to_path_buf(),
        ));
    }
    Ok(AnchoredDirectory {
        path: proc_fd_path(&file),
        file,
    })
}

#[cfg(target_os = "linux")]
fn entry_exists_at(
    parent: &File,
    component: &OsStr,
    display_path: &Path,
) -> Result<bool, ProvisionError> {
    match rustix::fs::statat(parent, component, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
        Err(error) => Err(ProvisionError::Io(display_path.to_path_buf(), error.into())),
    }
}

#[cfg(target_os = "linux")]
fn verify_entry_identity(
    parent: &File,
    component: &OsStr,
    child: &File,
    display_path: &Path,
) -> Result<(), ProvisionError> {
    let entry = rustix::fs::statat(parent, component, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| ProvisionError::Io(display_path.to_path_buf(), error.into()))?;
    let opened = rustix::fs::fstat(child)
        .map_err(|error| ProvisionError::Io(display_path.to_path_buf(), error.into()))?;
    if same_identity(&entry, &opened) {
        Ok(())
    } else {
        Err(ProvisionError::Integrity(format!(
            "filesystem identity mismatch for {}",
            display_path.display()
        )))
    }
}

#[cfg(target_os = "linux")]
fn same_identity(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

/// Provision a complete PQ devnet directory synchronously.
///
/// Key generation, password KDFs, filesystem I/O, and journal initialization all block. Callers
/// must not invoke this function directly on an async runtime worker.
pub fn provision_devnet(
    config: ProvisionConfig,
    master_seed_file: impl AsRef<Path>,
    password_file: impl AsRef<Path>,
) -> Result<ProvisionedDevnet, ProvisionError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, master_seed_file, password_file);
        return Err(ProvisionError::UnsupportedPlatform);
    }
    #[cfg(target_os = "linux")]
    {
        validate_config(&config)?;
        let destination = AnchoredDestination::preflight(&config.destination)?;
        let master_seed = read_master_seed(master_seed_file.as_ref())?;
        let password = read_password(password_file.as_ref())?;
        let staging = destination.create_staging()?;

        let result = build_staging(&config, &staging, &master_seed, &password)?;
        validate_output(&staging, &config, &result, &password)?;
        let published = destination.publish(staging)?;
        validate_output(&published, &config, &result, &password)?;
        destination.verify_public_path(&published)?;
        Ok(result)
    }
}

fn validate_config(config: &ProvisionConfig) -> Result<(), ProvisionError> {
    if config.validator_count == 0 || config.destination.file_name().is_none() {
        return Err(ProvisionError::InvalidConfig);
    }
    if config.validator_count > MAX_VALIDATOR_COUNT {
        return Err(ProvisionError::ValidatorCountTooLarge(
            config.validator_count,
        ));
    }
    let range_len = config
        .one_time_use_range
        .end()
        .checked_sub(*config.one_time_use_range.start())
        .and_then(|difference| difference.checked_add(1))
        .ok_or(ProvisionError::InvalidConfig)?;
    if range_len > 1120 {
        return Err(ProvisionError::InvalidConfig);
    }
    config
        .eth1_timestamp
        .checked_add(electra_genesis_spec().genesis_delay)
        .ok_or(ProvisionError::InvalidConfig)?;
    Ok(())
}

fn electra_genesis_spec() -> ChainSpec {
    ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec())
}

#[cfg(unix)]
fn read_master_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, ProvisionError> {
    let bytes = read_bounded_file(path, 32)?;
    if bytes.len() != 32 {
        return Err(ProvisionError::InvalidMasterSeedLength(bytes.len()));
    }
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

#[cfg(unix)]
fn read_password(path: &Path) -> Result<Zeroizing<Vec<u8>>, ProvisionError> {
    let password = read_bounded_file(path, MAX_INPUT_FILE_BYTES)?;
    validate_pq_password(&password).map_err(|error| match error {
        PqKeystoreError::PasswordTooLong => ProvisionError::PasswordTooLarge(password.len()),
        other => ProvisionError::Keystore(other),
    })?;
    Ok(password)
}

#[cfg(unix)]
fn read_bounded_file(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>, ProvisionError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| ProvisionError::Io(path.to_path_buf(), error.into()))?;
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|error| ProvisionError::Io(path.to_path_buf(), error))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(ProvisionError::UnsafeInput(path.to_path_buf()));
    }
    let limit = u64::try_from(maximum)
        .map_err(|_| ProvisionError::UnsafeInput(path.to_path_buf()))?
        .saturating_add(1);
    let capacity = maximum.saturating_add(1);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| ProvisionError::Io(path.to_path_buf(), error))?;
    if bytes.len() > maximum {
        if maximum == MAX_INPUT_FILE_BYTES {
            return Err(ProvisionError::PasswordTooLarge(bytes.len()));
        }
        return Err(ProvisionError::InvalidMasterSeedLength(bytes.len()));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn build_staging(
    config: &ProvisionConfig,
    staging: &AnchoredDirectory,
    master_seed: &[u8; 32],
    password: &[u8],
) -> Result<ProvisionedDevnet, ProvisionError> {
    let validators_dir = create_child_directory(staging, VALIDATORS_DIR)?;
    let passwords_dir = create_child_directory(staging, PASSWORDS_DIR)?;
    let mut metadata = Vec::with_capacity(config.validator_count);
    let mut direct_validators = Vec::with_capacity(config.validator_count);
    let mut manifest_validators = Vec::with_capacity(config.validator_count);

    for index in 0..config.validator_count {
        let derivation_index = u64::try_from(index).map_err(|_| ProvisionError::InvalidConfig)?;
        let validator_seed = derive32(VALIDATOR_SEED_DOMAIN, master_seed, derivation_index);
        let keystore =
            PqKeystore::from_seed(*validator_seed, config.one_time_use_range.clone(), password)?;
        let authenticated = keystore.authenticate(password)?;
        let public_key = *authenticated.public_key();
        let withdrawal_credentials = withdrawal_credentials(master_seed, derivation_index)?;

        PqValidatorDirBuilder::new_anchored(validators_dir.path.clone(), &validators_dir.file)?
            .password_dir_anchored(passwords_dir.path.clone(), &passwords_dir.file)?
            .voting_keystore(keystore, password)
            .build()?;

        metadata.push(authenticated);
        direct_validators.push(DirectGenesisValidator {
            public_key,
            withdrawal_credentials,
        });
        manifest_validators.push(ManifestValidator {
            derivation_index,
            public_key: hex::encode(public_key.serialize()),
            withdrawal_credentials: hex::encode(withdrawal_credentials.as_slice()),
        });
    }

    let spec = electra_genesis_spec();
    let state = initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        config.eth1_timestamp,
        direct_validators,
        None,
        &spec,
    )
    .map_err(|error| ProvisionError::State(format!("{error:?}")))?;
    let genesis_state_bytes = state.as_ssz_bytes();
    let genesis_validators_root = hash256_bytes(&state.genesis_validators_root())?;
    let public_keys = metadata
        .iter()
        .map(|entry| *entry.public_key())
        .collect::<Vec<_>>();

    provision_usage_journal_anchored(&staging.file, genesis_validators_root, &metadata)?;

    let manifest = Manifest {
        format: "lighthouse-pq-devnet".to_owned(),
        version: 1,
        preset: "minimal".to_owned(),
        fork: "electra".to_owned(),
        validator_count: config.validator_count,
        one_time_use_start: *config.one_time_use_range.start(),
        one_time_use_end: *config.one_time_use_range.end(),
        eth1_timestamp: config.eth1_timestamp,
        genesis_validators_root: hex::encode(genesis_validators_root),
        validators: manifest_validators,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| ProvisionError::Json(error.to_string()))?;
    write_private_file_at(staging, PQ_DEVNET_GENESIS_FILE, &genesis_state_bytes)?;
    write_private_file_at(staging, PQ_DEVNET_MANIFEST_FILE, &manifest_bytes)?;
    rustix::fs::fsync(&staging.file)
        .map_err(|error| ProvisionError::Io(staging.path.clone(), error.into()))?;

    Ok(ProvisionedDevnet {
        output_dir: config.destination.clone(),
        public_keys,
        genesis_state_bytes,
        genesis_validators_root,
    })
}

fn derive32(domain: &[u8], master_seed: &[u8; 32], index: u64) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(master_seed);
    hasher.update(index.to_be_bytes());
    Zeroizing::new(hasher.finalize().into())
}

fn withdrawal_credentials(master_seed: &[u8; 32], index: u64) -> Result<Hash256, ProvisionError> {
    let digest = derive32(WITHDRAWAL_DOMAIN, master_seed, index);
    let mut credentials = [0; 32];
    let prefix = credentials
        .first_mut()
        .ok_or_else(|| ProvisionError::Integrity("credential prefix is missing".to_owned()))?;
    *prefix = 1;
    let address = credentials
        .get_mut(12..)
        .ok_or_else(|| ProvisionError::Integrity("credential address is missing".to_owned()))?;
    let digest_address = digest
        .get(12..)
        .ok_or_else(|| ProvisionError::Integrity("withdrawal digest is too short".to_owned()))?;
    address.copy_from_slice(digest_address);
    Ok(Hash256::from(credentials))
}

fn hash256_bytes(hash: &Hash256) -> Result<[u8; 32], ProvisionError> {
    hash.as_slice()
        .try_into()
        .map_err(|_| ProvisionError::Integrity("invalid hash length".to_owned()))
}

#[cfg(target_os = "linux")]
fn create_child_directory(
    parent: &AnchoredDirectory,
    component: &str,
) -> Result<AnchoredDirectory, ProvisionError> {
    let display_path = parent.path.join(component);
    rustix::fs::mkdirat(&parent.file, component, Mode::RWXU)
        .map_err(|error| ProvisionError::Io(display_path.clone(), error.into()))?;
    rustix::fs::fsync(&parent.file)
        .map_err(|error| ProvisionError::Io(parent.path.clone(), error.into()))?;
    let child = open_private_directory_at(&parent.file, OsStr::new(component), &display_path)?;
    verify_entry_identity(
        &parent.file,
        OsStr::new(component),
        &child.file,
        &display_path,
    )?;
    Ok(child)
}

#[cfg(target_os = "linux")]
fn write_private_file_at(
    parent: &AnchoredDirectory,
    component: &str,
    bytes: &[u8],
) -> Result<(), ProvisionError> {
    let path = parent.path.join(component);
    let fd = rustix::fs::openat(
        &parent.file,
        component,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error| ProvisionError::Io(path.to_path_buf(), error.into()))?;
    let mut file = File::from(fd);
    file.write_all(bytes)
        .map_err(|error| ProvisionError::Io(path.to_path_buf(), error))?;
    file.sync_all()
        .map_err(|error| ProvisionError::Io(path, error))?;
    rustix::fs::fsync(&parent.file)
        .map_err(|error| ProvisionError::Io(parent.path.clone(), error.into()))
}

#[cfg(target_os = "linux")]
fn validate_output(
    root: &AnchoredDirectory,
    config: &ProvisionConfig,
    expected: &ProvisionedDevnet,
    password: &[u8],
) -> Result<(), ProvisionError> {
    let spec = electra_genesis_spec();
    let state_bytes = read_public_file(&root.path.join(PQ_DEVNET_GENESIS_FILE), MAX_GENESIS_BYTES)?;
    if state_bytes != expected.genesis_state_bytes {
        return Err(ProvisionError::Integrity(
            "genesis state changed after durable write".to_owned(),
        ));
    }
    let state = BeaconState::<MinimalEthSpec>::from_ssz_bytes(&state_bytes, &spec)
        .map_err(|error| ProvisionError::State(format!("{error:?}")))?;
    if hash256_bytes(&state.genesis_validators_root())? != expected.genesis_validators_root {
        return Err(ProvisionError::Integrity(
            "genesis validators root mismatch".to_owned(),
        ));
    }
    let registry_keys = state
        .validators()
        .iter()
        .map(|validator| validator.pubkey)
        .collect::<Vec<_>>();
    let registry_withdrawal_credentials = state
        .validators()
        .iter()
        .map(|validator| validator.withdrawal_credentials)
        .collect::<Vec<_>>();
    if registry_keys != expected.public_keys {
        return Err(ProvisionError::Integrity(
            "registry derivation order mismatch".to_owned(),
        ));
    }
    if state.eth1_data().deposit_count != 0
        || state.eth1_deposit_index() != 0
        || !state
            .pending_deposits()
            .map_err(|error| ProvisionError::State(format!("{error:?}")))?
            .is_empty()
    {
        return Err(ProvisionError::Integrity(
            "direct genesis contains deposit state".to_owned(),
        ));
    }

    let discovered = PqValidatorDir::discover(root.path.join(VALIDATORS_DIR))?;
    if discovered.len() != config.validator_count {
        return Err(ProvisionError::Integrity(
            "validator directory count mismatch".to_owned(),
        ));
    }
    let mut by_public_key = BTreeMap::new();
    let mut authenticated = Vec::with_capacity(discovered.len());
    for validator_dir in discovered {
        validator_dir.validate_keystore_password(root.path.join(PASSWORDS_DIR))?;
        let keystore = validator_dir.keystore()?;
        let entry = keystore.authenticate(password)?;
        if entry.one_time_use_range() != config.one_time_use_range {
            return Err(ProvisionError::Integrity(
                "one-time-use range mismatch".to_owned(),
            ));
        }
        let key = entry.public_key().serialize();
        if by_public_key.insert(key, ()).is_some() {
            return Err(ProvisionError::Integrity(
                "duplicate validator directory".to_owned(),
            ));
        }
        authenticated.push(entry);
    }
    for public_key in &expected.public_keys {
        if !by_public_key.contains_key(&public_key.serialize()) {
            return Err(ProvisionError::Integrity(
                "registry key missing from validator directories".to_owned(),
            ));
        }
    }
    validate_usage_journal_anchored(&root.file, expected.genesis_validators_root, &authenticated)?;

    let manifest_bytes =
        read_public_file(&root.path.join(PQ_DEVNET_MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| ProvisionError::Json(error.to_string()))?;
    let manifest_public_keys = manifest
        .validators
        .iter()
        .map(|validator| validator.public_key.clone())
        .collect::<Vec<_>>();
    let expected_public_keys = expected
        .public_keys
        .iter()
        .map(|key| hex::encode(key.serialize()))
        .collect::<Vec<_>>();
    let expected_withdrawal_credentials = registry_withdrawal_credentials
        .iter()
        .map(|credentials| hex::encode(credentials.as_slice()))
        .collect::<Vec<_>>();
    let manifest_withdrawal_credentials = manifest
        .validators
        .iter()
        .map(|validator| validator.withdrawal_credentials.clone())
        .collect::<Vec<_>>();
    let manifest_indices = manifest
        .validators
        .iter()
        .map(|validator| validator.derivation_index)
        .collect::<Vec<_>>();
    let expected_indices = (0..config.validator_count)
        .map(u64::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProvisionError::InvalidConfig)?;
    if manifest.format != "lighthouse-pq-devnet"
        || manifest.version != 1
        || manifest.preset != "minimal"
        || manifest.fork != "electra"
        || manifest.validator_count != expected.public_keys.len()
        || manifest.validators.len() != expected.public_keys.len()
        || manifest.one_time_use_start != *config.one_time_use_range.start()
        || manifest.one_time_use_end != *config.one_time_use_range.end()
        || manifest.eth1_timestamp != config.eth1_timestamp
        || manifest.genesis_validators_root != hex::encode(expected.genesis_validators_root)
        || manifest_public_keys != expected_public_keys
        || manifest_withdrawal_credentials != expected_withdrawal_credentials
        || manifest_indices != expected_indices
    {
        return Err(ProvisionError::Integrity("manifest mismatch".to_owned()));
    }
    Ok(())
}

#[cfg(unix)]
fn read_public_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ProvisionError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ProvisionError::Io(path.to_path_buf(), error.into()))?;
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|error| ProvisionError::Io(path.to_path_buf(), error))?;
    let file_len = usize::try_from(metadata.len())
        .map_err(|_| ProvisionError::Integrity("public file is too large".to_owned()))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 || file_len > maximum {
        return Err(ProvisionError::Integrity(format!(
            "unsafe or oversized public file {}",
            path.display()
        )));
    }
    let limit = u64::try_from(maximum)
        .map_err(|_| ProvisionError::Integrity("public file limit is invalid".to_owned()))?
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(file_len);
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| ProvisionError::Io(path.to_path_buf(), error))?;
    if bytes.len() > maximum {
        return Err(ProvisionError::Integrity(
            "public file is too large".to_owned(),
        ));
    }
    Ok(bytes)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn post_rename_sync_failure_leaves_final_tombstone() {
        let root = tempdir().expect("root");
        let destination_path = root.path().join("devnet");
        let destination = AnchoredDestination::preflight(&destination_path).expect("preflight");
        let staging = destination.create_staging().expect("staging");
        write_private_file_at(&staging, "marker", b"durable before rename").expect("marker");

        let result = destination.publish_with_parent_sync(staging, |_| {
            Err(io::Error::other("injected parent fsync failure"))
        });

        assert!(matches!(result, Err(ProvisionError::Io(path, _)) if path == root.path()));
        assert!(destination_path.is_dir());
        assert!(
            !staging_path(&destination_path)
                .expect("staging path")
                .exists()
        );
        assert_eq!(
            std::fs::read(destination_path.join("marker")).expect("tombstone marker"),
            b"durable before rename"
        );
    }
}
