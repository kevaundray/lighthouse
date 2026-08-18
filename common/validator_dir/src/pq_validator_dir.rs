//! Filesystem boundary for experimental PQ validator keystores.

use crate::VOTING_KEYSTORE_FILE;
use eth2_keystore::PlainText;
use pq_signing::{MAX_PQ_PASSWORD_BYTES, PqKeystore, PqKeystoreError, validate_pq_password};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const PQ_VOTING_KEYSTORE_FILE: &str = "pq-voting-keystore.json";
const MAX_PASSWORD_BYTES: u64 = MAX_PQ_PASSWORD_BYTES as u64;

#[derive(Debug)]
pub enum PqValidatorDirError {
    UnsupportedPlatform,
    DirectoryAlreadyExists(PathBuf),
    DirectoryDoesNotExist(PathBuf),
    UnsafeDirectoryTarget(PathBuf),
    UnsafeFileTarget(PathBuf),
    MixedSignatureSchemes(PathBuf),
    PartialDirectory(PathBuf),
    NonCanonicalDirectoryName(PathBuf),
    KeystoreIdentityMismatch(PathBuf),
    KeystoreAlreadyExists(PathBuf),
    PasswordAlreadyExists(PathBuf),
    UnableToCreateDirectory(PathBuf, io::Error),
    UnableToReadDirectory(PathBuf, io::Error),
    UnableToReadFile(PathBuf, io::Error),
    UnableToOpenFile(PathBuf, io::Error),
    UnableToWriteFile(PathBuf, io::Error),
    UnableToSync(PathBuf, io::Error),
    Keystore(PqKeystoreError),
    PasswordTooLarge(PathBuf),
}

impl std::fmt::Display for PqValidatorDirError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PqValidatorDirError {}

impl From<PqKeystoreError> for PqValidatorDirError {
    fn from(error: PqKeystoreError) -> Self {
        Self::Keystore(error)
    }
}

/// Directory-local PQ validator identity. This is intentionally not a BLS `ValidatorDefinition`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqValidatorDir {
    dir: PathBuf,
    public_key: [u8; 32],
}

impl PqValidatorDir {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PqValidatorDirError> {
        Self::open_with_hooks(path.as_ref(), &mut NoopDirectoryReadHooks)
    }

    #[cfg(unix)]
    fn open_with_hooks<H: DirectoryReadHooks>(
        path: &Path,
        hooks: &mut H,
    ) -> Result<Self, PqValidatorDirError> {
        let dir = path.to_path_buf();
        let directory = open_directory_path(&dir, true)?;
        hooks.after_directory_opened(&dir)?;
        let pq_path = dir.join(PQ_VOTING_KEYSTORE_FILE);
        let pq_exists = entry_exists(&directory, OsStr::new(PQ_VOTING_KEYSTORE_FILE), &pq_path)?;
        let bls_exists = entry_exists(
            &directory,
            OsStr::new(VOTING_KEYSTORE_FILE),
            &dir.join(VOTING_KEYSTORE_FILE),
        )?;
        if pq_exists && bls_exists {
            return Err(PqValidatorDirError::MixedSignatureSchemes(dir));
        }
        if !pq_exists {
            return Err(PqValidatorDirError::PartialDirectory(dir));
        }
        let keystore = read_keystore_at(&directory, PQ_VOTING_KEYSTORE_FILE, &pq_path)?;
        let expected_name = canonical_directory_name(keystore.public_key());
        if dir.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
            return Err(PqValidatorDirError::NonCanonicalDirectoryName(dir));
        }
        directory.verify_path_binding()?;
        Ok(Self {
            dir,
            public_key: *keystore.public_key(),
        })
    }

    #[cfg(not(unix))]
    fn open_with_hooks<H: DirectoryReadHooks>(
        _path: &Path,
        _hooks: &mut H,
    ) -> Result<Self, PqValidatorDirError> {
        Err(PqValidatorDirError::UnsupportedPlatform)
    }

    pub fn discover(base: impl AsRef<Path>) -> Result<Vec<Self>, PqValidatorDirError> {
        require_unix()?;
        let base = base.as_ref();
        validate_directory(base, false)?;
        let mut entries = fs::read_dir(base)
            .map_err(|error| PqValidatorDirError::UnableToReadDirectory(base.into(), error))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| PqValidatorDirError::UnableToReadDirectory(base.into(), error))?;
        entries.sort_by_key(|entry| entry.file_name());

        let mut discovered = Vec::new();
        for entry in entries {
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| PqValidatorDirError::UnableToReadDirectory(path.clone(), error))?;
            if file_type.is_symlink() {
                return Err(PqValidatorDirError::UnsafeDirectoryTarget(path));
            }
            if !file_type.is_dir() {
                continue;
            }
            let pq_path = path.join(PQ_VOTING_KEYSTORE_FILE);
            let bls_path = path.join(VOTING_KEYSTORE_FILE);
            let pq_exists = path_exists_without_following(&pq_path)?;
            let bls_exists = path_exists_without_following(&bls_path)?;
            if pq_exists || (is_canonical_directory_component(&path) && !bls_exists) {
                discovered.push(Self::open(path)?);
            }
        }
        Ok(discovered)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn pq_voting_keystore_path(&self) -> PathBuf {
        self.dir.join(PQ_VOTING_KEYSTORE_FILE)
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn keystore(&self) -> Result<PqKeystore, PqValidatorDirError> {
        self.keystore_with_hooks(&mut NoopDirectoryReadHooks)
    }

    #[cfg(unix)]
    fn keystore_with_hooks<H: DirectoryReadHooks>(
        &self,
        hooks: &mut H,
    ) -> Result<PqKeystore, PqValidatorDirError> {
        let directory = open_directory_path(&self.dir, true)?;
        hooks.after_directory_opened(&self.dir)?;
        let path = self.pq_voting_keystore_path();
        let pq_exists = entry_exists(&directory, OsStr::new(PQ_VOTING_KEYSTORE_FILE), &path)?;
        let bls_exists = entry_exists(
            &directory,
            OsStr::new(VOTING_KEYSTORE_FILE),
            &self.dir.join(VOTING_KEYSTORE_FILE),
        )?;
        if pq_exists && bls_exists {
            return Err(PqValidatorDirError::MixedSignatureSchemes(self.dir.clone()));
        }
        if !pq_exists {
            return Err(PqValidatorDirError::PartialDirectory(self.dir.clone()));
        }
        let keystore = read_keystore_at(&directory, PQ_VOTING_KEYSTORE_FILE, &path)?;
        let expected_name = canonical_directory_name(keystore.public_key());
        if keystore.public_key() != &self.public_key
            || self.dir.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str())
        {
            return Err(PqValidatorDirError::KeystoreIdentityMismatch(path));
        }
        directory.verify_path_binding()?;
        Ok(keystore)
    }

    #[cfg(not(unix))]
    fn keystore_with_hooks<H: DirectoryReadHooks>(
        &self,
        _hooks: &mut H,
    ) -> Result<PqKeystore, PqValidatorDirError> {
        Err(PqValidatorDirError::UnsupportedPlatform)
    }

    pub fn validate_keystore_password(
        &self,
        password_dir: impl AsRef<Path>,
    ) -> Result<(), PqValidatorDirError> {
        let password_path = password_path(password_dir.as_ref(), &self.public_key);
        let password = read_sensitive_file(&password_path, MAX_PASSWORD_BYTES)?;
        self.keystore()?
            .validate_password(password.as_slice())
            .map_err(Into::into)
    }
}

/// Builder for the separate PQ directory layout.
pub struct PqValidatorDirBuilder {
    base_validators_dir: PathBuf,
    #[cfg(unix)]
    base_validators_anchor: Option<File>,
    password_dir: Option<PathBuf>,
    #[cfg(unix)]
    password_anchor: Option<File>,
    voting_keystore: Option<(PqKeystore, PlainText)>,
}

trait ProvisioningHooks {
    fn after_parent_handles_opened(
        &mut self,
        _validators_path: &Path,
        _password_path: Option<&Path>,
    ) -> Result<(), PqValidatorDirError> {
        Ok(())
    }

    fn after_validator_directory_created(
        &mut self,
        _validator_path: &Path,
    ) -> Result<(), PqValidatorDirError> {
        Ok(())
    }
}

trait DirectoryReadHooks {
    fn after_directory_opened(
        &mut self,
        _validator_path: &Path,
    ) -> Result<(), PqValidatorDirError> {
        Ok(())
    }
}

struct NoopDirectoryReadHooks;

impl DirectoryReadHooks for NoopDirectoryReadHooks {}

struct NoopProvisioningHooks;

impl ProvisioningHooks for NoopProvisioningHooks {}

impl PqValidatorDirBuilder {
    pub fn new(base_validators_dir: PathBuf) -> Self {
        Self {
            base_validators_dir,
            #[cfg(unix)]
            base_validators_anchor: None,
            password_dir: None,
            #[cfg(unix)]
            password_anchor: None,
            voting_keystore: None,
        }
    }

    /// Bind provisioning to an already-open private validator directory.
    #[cfg(unix)]
    pub fn new_anchored(
        base_validators_dir: PathBuf,
        directory: &File,
    ) -> Result<Self, PqValidatorDirError> {
        let file = directory.try_clone().map_err(|error| {
            PqValidatorDirError::UnableToOpenFile(base_validators_dir.clone(), error)
        })?;
        validate_open_directory(&file, &base_validators_dir, true)?;
        Ok(Self {
            base_validators_dir,
            base_validators_anchor: Some(file),
            password_dir: None,
            password_anchor: None,
            voting_keystore: None,
        })
    }

    pub fn password_dir(mut self, password_dir: impl Into<PathBuf>) -> Self {
        self.password_dir = Some(password_dir.into());
        #[cfg(unix)]
        {
            self.password_anchor = None;
        }
        self
    }

    /// Bind password-file provisioning to an already-open private directory.
    #[cfg(unix)]
    pub fn password_dir_anchored(
        mut self,
        password_dir: impl Into<PathBuf>,
        directory: &File,
    ) -> Result<Self, PqValidatorDirError> {
        let password_dir = password_dir.into();
        let file = directory
            .try_clone()
            .map_err(|error| PqValidatorDirError::UnableToOpenFile(password_dir.clone(), error))?;
        validate_open_directory(&file, &password_dir, true)?;
        self.password_dir = Some(password_dir);
        self.password_anchor = Some(file);
        Ok(self)
    }

    pub fn voting_keystore(mut self, keystore: PqKeystore, password: &[u8]) -> Self {
        self.voting_keystore = Some((keystore, password.to_vec().into()));
        self
    }

    pub fn get_dir_path(base_validators_dir: &Path, keystore: &PqKeystore) -> PathBuf {
        base_validators_dir.join(canonical_directory_name(keystore.public_key()))
    }

    pub fn build(self) -> Result<PqValidatorDir, PqValidatorDirError> {
        self.build_with_hooks(&mut NoopProvisioningHooks, |keystore, password| {
            keystore.validate_password(password)
        })
    }

    #[cfg(unix)]
    fn build_with_hooks<H, V>(
        self,
        hooks: &mut H,
        validate_password: V,
    ) -> Result<PqValidatorDir, PqValidatorDirError>
    where
        H: ProvisioningHooks,
        V: FnOnce(&PqKeystore, &[u8]) -> Result<(), PqKeystoreError>,
    {
        require_unix()?;
        let Self {
            base_validators_dir,
            base_validators_anchor,
            password_dir,
            password_anchor,
            voting_keystore,
        } = self;
        let (keystore, password) = voting_keystore.ok_or(PqValidatorDirError::PartialDirectory(
            base_validators_dir.clone(),
        ))?;
        validate_pq_password(password.as_bytes())?;
        keystore.validate_metadata()?;

        let component = canonical_directory_name(keystore.public_key());
        let dir = base_validators_dir.join(&component);
        let password_target = password_dir
            .as_ref()
            .map(|directory| directory.join(&component));
        let prepared_validators = match base_validators_anchor {
            Some(file) => PreparedDirectory::Existing(AnchoredDirectory {
                path: base_validators_dir.clone(),
                file,
                follow_path_binding: true,
            }),
            None => PreparedDirectory::prepare(&base_validators_dir, false)?,
        };
        prepared_validators.refuse_child_collision(
            &component,
            PqValidatorDirError::DirectoryAlreadyExists(dir.clone()),
        )?;
        let prepared_passwords = match (password_dir.as_ref(), password_anchor) {
            (Some(path), Some(file)) => Some(PreparedDirectory::Existing(AnchoredDirectory {
                path: path.clone(),
                file,
                follow_path_binding: true,
            })),
            (Some(path), None) => Some(PreparedDirectory::prepare(path, false)?),
            (None, None) => None,
            (None, Some(_)) => {
                return Err(PqValidatorDirError::PartialDirectory(base_validators_dir));
            }
        };
        if let (Some(passwords), Some(target)) = (&prepared_passwords, &password_target) {
            passwords.refuse_child_collision(
                &component,
                PqValidatorDirError::PasswordAlreadyExists(target.clone()),
            )?;
        }

        hooks.after_parent_handles_opened(&base_validators_dir, password_dir.as_deref())?;
        validate_password(&keystore, password.as_bytes())?;

        let validators = prepared_validators.materialize()?;
        let passwords = prepared_passwords
            .map(PreparedDirectory::materialize)
            .transpose()?;
        let validator_dir = create_directory_at(&validators, &component, &dir)?;
        hooks.after_validator_directory_created(&dir)?;

        let keystore_path = dir.join(PQ_VOTING_KEYSTORE_FILE);
        let keystore_bytes = keystore.to_json_string()?.into_bytes();
        let keystore_file = create_sensitive_file_at(
            &validator_dir,
            PQ_VOTING_KEYSTORE_FILE,
            &keystore_path,
            &keystore_bytes,
            false,
        )?;
        let password_file = match (&passwords, &password_target) {
            (Some(passwords), Some(target)) => Some(create_sensitive_file_at(
                passwords,
                &component,
                target,
                password.as_bytes(),
                true,
            )?),
            (None, None) => None,
            _ => return Err(PqValidatorDirError::PartialDirectory(dir)),
        };

        sync_open_directory(&validator_dir, &dir)?;
        sync_open_directory(&validators, &base_validators_dir)?;
        let restored = read_keystore_at(&validator_dir, PQ_VOTING_KEYSTORE_FILE, &keystore_path)?;
        if restored != keystore {
            return Err(PqValidatorDirError::KeystoreIdentityMismatch(keystore_path));
        }
        if entry_exists(&validator_dir, OsStr::new(VOTING_KEYSTORE_FILE), &dir)? {
            return Err(PqValidatorDirError::MixedSignatureSchemes(dir));
        }
        verify_entry_binding(&validators, OsStr::new(&component), &validator_dir, &dir)?;
        verify_entry_binding(
            &validator_dir,
            OsStr::new(PQ_VOTING_KEYSTORE_FILE),
            &keystore_file,
            &keystore_path,
        )?;
        if let (Some(passwords), Some(password_file), Some(target)) =
            (&passwords, &password_file, &password_target)
        {
            verify_entry_binding(passwords, OsStr::new(&component), password_file, target)?;
        }
        validators.verify_path_binding()?;
        if let Some(passwords) = &passwords {
            passwords.verify_path_binding()?;
        }

        Ok(PqValidatorDir {
            dir,
            public_key: *keystore.public_key(),
        })
    }

    #[cfg(not(unix))]
    fn build_with_hooks<H, V>(
        self,
        _hooks: &mut H,
        _validate_password: V,
    ) -> Result<PqValidatorDir, PqValidatorDirError>
    where
        H: ProvisioningHooks,
        V: FnOnce(&PqKeystore, &[u8]) -> Result<(), PqKeystoreError>,
    {
        Err(PqValidatorDirError::UnsupportedPlatform)
    }
}

fn canonical_directory_name(public_key: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(public_key))
}

fn is_canonical_directory_component(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.len() == 66
        && name.starts_with("0x")
        && name[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn password_path(password_dir: &Path, public_key: &[u8; 32]) -> PathBuf {
    password_dir.join(canonical_directory_name(public_key))
}

fn path_exists_without_following(path: &Path) -> Result<bool, PqValidatorDirError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(PqValidatorDirError::UnableToOpenFile(path.into(), error)),
    }
}

#[cfg(unix)]
fn require_unix() -> Result<(), PqValidatorDirError> {
    Ok(())
}

#[cfg(not(unix))]
fn require_unix() -> Result<(), PqValidatorDirError> {
    Err(PqValidatorDirError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_directory(path: &Path, require_private: bool) -> Result<(), PqValidatorDirError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            PqValidatorDirError::DirectoryDoesNotExist(path.into())
        } else {
            PqValidatorDirError::UnableToReadDirectory(path.into(), error)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PqValidatorDirError::UnsafeDirectoryTarget(path.into()));
    }
    if require_private && metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(PqValidatorDirError::UnsafeDirectoryTarget(path.into()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_directory(_path: &Path, _require_private: bool) -> Result<(), PqValidatorDirError> {
    Err(PqValidatorDirError::UnsupportedPlatform)
}

#[cfg(all(unix, test))]
fn create_private_directory(path: &Path) -> Result<(), PqValidatorDirError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|error| PqValidatorDirError::UnableToCreateDirectory(path.into(), error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| PqValidatorDirError::UnableToCreateDirectory(path.into(), error))?;
    validate_directory(path, true)
}

#[cfg(all(not(unix), test))]
fn create_private_directory(_path: &Path) -> Result<(), PqValidatorDirError> {
    Err(PqValidatorDirError::UnsupportedPlatform)
}

#[cfg(unix)]
struct AnchoredDirectory {
    path: PathBuf,
    file: File,
    follow_path_binding: bool,
}

#[cfg(unix)]
enum PreparedDirectory {
    Existing(AnchoredDirectory),
    Missing {
        path: PathBuf,
        parent: AnchoredDirectory,
        component: OsString,
    },
}

#[cfg(unix)]
impl PreparedDirectory {
    fn prepare(path: &Path, require_private: bool) -> Result<Self, PqValidatorDirError> {
        match fs::symlink_metadata(path) {
            Ok(_) => open_directory_path(path, require_private).map(Self::Existing),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let (parent_path, component) = split_parent_component(path)?;
                let parent = open_directory_path(&parent_path, false)?;
                if entry_exists(&parent, &component, path)? {
                    return Err(PqValidatorDirError::UnsafeDirectoryTarget(path.into()));
                }
                Ok(Self::Missing {
                    path: path.into(),
                    parent,
                    component,
                })
            }
            Err(error) => Err(PqValidatorDirError::UnableToReadDirectory(
                path.into(),
                error,
            )),
        }
    }

    fn refuse_child_collision(
        &self,
        component: &str,
        collision: PqValidatorDirError,
    ) -> Result<(), PqValidatorDirError> {
        let Self::Existing(directory) = self else {
            return Ok(());
        };
        if entry_exists(
            directory,
            OsStr::new(component),
            &directory.path.join(component),
        )? {
            Err(collision)
        } else {
            Ok(())
        }
    }

    fn materialize(self) -> Result<AnchoredDirectory, PqValidatorDirError> {
        match self {
            Self::Existing(directory) => Ok(directory),
            Self::Missing {
                path,
                parent,
                component,
            } => {
                rustix::fs::mkdirat(&parent.file, &component, rustix::fs::Mode::RWXU)
                    .map_err(|error| map_mkdir_error(&path, error))?;
                sync_open_directory(&parent, &parent.path)?;
                let directory = open_directory_at(&parent, &component, &path, true)?;
                verify_entry_binding(&parent, &component, &directory, &path)?;
                Ok(directory)
            }
        }
    }
}

#[cfg(unix)]
impl AnchoredDirectory {
    fn verify_path_binding(&self) -> Result<(), PqValidatorDirError> {
        let flags = if self.follow_path_binding {
            rustix::fs::AtFlags::empty()
        } else {
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW
        };
        let path_stat =
            rustix::fs::statat(rustix::fs::CWD, &self.path, flags).map_err(|error| {
                PqValidatorDirError::UnsafeDirectoryTarget(self.path.clone()).with_io(error)
            })?;
        let fd_stat = rustix::fs::fstat(&self.file).map_err(|error| {
            PqValidatorDirError::UnableToReadDirectory(self.path.clone(), io::Error::from(error))
        })?;
        if same_identity(&path_stat, &fd_stat) {
            Ok(())
        } else {
            Err(PqValidatorDirError::UnsafeDirectoryTarget(
                self.path.clone(),
            ))
        }
    }
}

#[cfg(unix)]
fn split_parent_component(path: &Path) -> Result<(PathBuf, OsString), PqValidatorDirError> {
    let component = path
        .file_name()
        .ok_or_else(|| PqValidatorDirError::UnsafeDirectoryTarget(path.into()))?
        .to_os_string();
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    Ok((parent, component))
}

#[cfg(unix)]
fn open_directory_path(
    path: &Path,
    require_private: bool,
) -> Result<AnchoredDirectory, PqValidatorDirError> {
    let fd = rustix::fs::openat(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        let io_error = io::Error::from(error);
        if io_error.kind() == io::ErrorKind::NotFound {
            PqValidatorDirError::DirectoryDoesNotExist(path.into())
        } else {
            PqValidatorDirError::UnsafeDirectoryTarget(path.into())
        }
    })?;
    let file = File::from(fd);
    validate_open_directory(&file, path, require_private)?;
    Ok(AnchoredDirectory {
        path: path.into(),
        file,
        follow_path_binding: false,
    })
}

#[cfg(unix)]
fn open_directory_at(
    parent: &AnchoredDirectory,
    component: &OsStr,
    path: &Path,
    require_private: bool,
) -> Result<AnchoredDirectory, PqValidatorDirError> {
    let fd = rustix::fs::openat(
        &parent.file,
        component,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| PqValidatorDirError::UnsafeDirectoryTarget(path.into()).with_io(error))?;
    rustix::fs::fchmod(&fd, rustix::fs::Mode::RWXU).map_err(|error| {
        PqValidatorDirError::UnableToCreateDirectory(path.into(), io::Error::from(error))
    })?;
    let file = File::from(fd);
    validate_open_directory(&file, path, require_private)?;
    Ok(AnchoredDirectory {
        path: path.into(),
        file,
        follow_path_binding: false,
    })
}

#[cfg(unix)]
fn validate_open_directory(
    file: &File,
    path: &Path,
    require_private: bool,
) -> Result<(), PqValidatorDirError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = file
        .metadata()
        .map_err(|error| PqValidatorDirError::UnableToReadDirectory(path.into(), error))?;
    if !metadata.is_dir() || (require_private && metadata.permissions().mode() & 0o777 != 0o700) {
        return Err(PqValidatorDirError::UnsafeDirectoryTarget(path.into()));
    }
    Ok(())
}

#[cfg(unix)]
fn create_directory_at(
    parent: &AnchoredDirectory,
    component: &str,
    path: &Path,
) -> Result<AnchoredDirectory, PqValidatorDirError> {
    rustix::fs::mkdirat(&parent.file, component, rustix::fs::Mode::RWXU)
        .map_err(|error| map_mkdir_error(path, error))?;
    sync_open_directory(parent, &parent.path)?;
    let directory = open_directory_at(parent, OsStr::new(component), path, true)?;
    verify_entry_binding(parent, OsStr::new(component), &directory, path)?;
    Ok(directory)
}

#[cfg(unix)]
fn map_mkdir_error(path: &Path, error: rustix::io::Errno) -> PqValidatorDirError {
    let error = io::Error::from(error);
    if error.kind() == io::ErrorKind::AlreadyExists {
        PqValidatorDirError::DirectoryAlreadyExists(path.into())
    } else {
        PqValidatorDirError::UnableToCreateDirectory(path.into(), error)
    }
}

trait AttachIo {
    fn with_io(self, error: rustix::io::Errno) -> Self;
}

impl AttachIo for PqValidatorDirError {
    fn with_io(self, error: rustix::io::Errno) -> Self {
        match self {
            Self::UnsafeDirectoryTarget(path) => {
                Self::UnableToReadDirectory(path, io::Error::from(error))
            }
            Self::UnsafeFileTarget(path) => Self::UnableToOpenFile(path, io::Error::from(error)),
            other => other,
        }
    }
}

#[cfg(unix)]
fn same_identity(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

#[cfg(unix)]
fn entry_exists(
    parent: &AnchoredDirectory,
    component: &OsStr,
    display_path: &Path,
) -> Result<bool, PqValidatorDirError> {
    match rustix::fs::statat(
        &parent.file,
        component,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(_) => Ok(true),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
        Err(error) => Err(PqValidatorDirError::UnableToOpenFile(
            display_path.into(),
            io::Error::from(error),
        )),
    }
}

#[cfg(unix)]
fn verify_entry_binding<F: std::os::fd::AsFd>(
    parent: &AnchoredDirectory,
    component: &OsStr,
    child: &F,
    display_path: &Path,
) -> Result<(), PqValidatorDirError> {
    let entry = rustix::fs::statat(
        &parent.file,
        component,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| {
        PqValidatorDirError::UnableToOpenFile(display_path.into(), io::Error::from(error))
    })?;
    let child = rustix::fs::fstat(child).map_err(|error| {
        PqValidatorDirError::UnableToOpenFile(display_path.into(), io::Error::from(error))
    })?;
    if same_identity(&entry, &child) {
        Ok(())
    } else {
        Err(PqValidatorDirError::UnsafeFileTarget(display_path.into()))
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for AnchoredDirectory {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.file)
    }
}

#[cfg(unix)]
fn create_sensitive_file_at(
    parent: &AnchoredDirectory,
    component: &str,
    display_path: &Path,
    bytes: &[u8],
    password: bool,
) -> Result<File, PqValidatorDirError> {
    use std::io::Write;

    create_sensitive_file_at_with(
        parent,
        OsStr::new(component),
        display_path,
        bytes,
        password,
        |file, bytes| {
            file.write_all(bytes).map_err(|error| {
                PqValidatorDirError::UnableToWriteFile(display_path.into(), error)
            })?;
            file.sync_all()
                .map_err(|error| PqValidatorDirError::UnableToSync(display_path.into(), error))
        },
    )
}

#[cfg(unix)]
fn create_sensitive_file_at_with<F>(
    parent: &AnchoredDirectory,
    component: &OsStr,
    display_path: &Path,
    bytes: &[u8],
    password: bool,
    write_and_sync: F,
) -> Result<File, PqValidatorDirError>
where
    F: FnOnce(&mut File, &[u8]) -> Result<(), PqValidatorDirError>,
{
    use std::os::unix::fs::PermissionsExt;

    let fd = rustix::fs::openat(
        &parent.file,
        component,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|error| {
        let error = io::Error::from(error);
        if error.kind() == io::ErrorKind::AlreadyExists {
            if password {
                PqValidatorDirError::PasswordAlreadyExists(display_path.into())
            } else {
                PqValidatorDirError::KeystoreAlreadyExists(display_path.into())
            }
        } else {
            PqValidatorDirError::UnableToOpenFile(display_path.into(), error)
        }
    })?;
    rustix::fs::fchmod(&fd, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).map_err(|error| {
        PqValidatorDirError::UnableToOpenFile(display_path.into(), io::Error::from(error))
    })?;
    let mut file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|error| PqValidatorDirError::UnableToOpenFile(display_path.into(), error))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(PqValidatorDirError::UnsafeFileTarget(display_path.into()));
    }
    write_and_sync(&mut file, bytes)?;
    sync_open_directory(parent, &parent.path)?;
    Ok(file)
}

#[cfg(all(unix, test))]
fn create_sensitive_file_with<F>(
    path: &Path,
    bytes: &[u8],
    password: bool,
    write_and_sync: F,
) -> Result<File, PqValidatorDirError>
where
    F: FnOnce(&mut File, &[u8]) -> Result<(), PqValidatorDirError>,
{
    let (parent_path, component) = split_parent_component(path)?;
    let parent = open_directory_path(&parent_path, false)?;
    create_sensitive_file_at_with(&parent, &component, path, bytes, password, write_and_sync)
}

#[cfg(unix)]
fn read_keystore_at(
    parent: &AnchoredDirectory,
    component: &str,
    display_path: &Path,
) -> Result<PqKeystore, PqValidatorDirError> {
    let file = open_sensitive_file_at(parent, OsStr::new(component), display_path)?;
    let keystore = PqKeystore::from_json_reader(file)?;
    keystore.validate_metadata()?;
    Ok(keystore)
}

#[cfg(unix)]
fn open_sensitive_file_at(
    parent: &AnchoredDirectory,
    component: &OsStr,
    display_path: &Path,
) -> Result<File, PqValidatorDirError> {
    use std::os::unix::fs::PermissionsExt;

    let fd = rustix::fs::openat(
        &parent.file,
        component,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            PqValidatorDirError::UnsafeFileTarget(display_path.into())
        } else {
            PqValidatorDirError::UnableToOpenFile(display_path.into(), io::Error::from(error))
        }
    })?;
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|error| PqValidatorDirError::UnableToOpenFile(display_path.into(), error))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(PqValidatorDirError::UnsafeFileTarget(display_path.into()));
    }
    Ok(file)
}

#[cfg(unix)]
fn sync_open_directory(
    directory: &AnchoredDirectory,
    display_path: &Path,
) -> Result<(), PqValidatorDirError> {
    rustix::fs::fsync(&directory.file).map_err(|error| {
        PqValidatorDirError::UnableToSync(display_path.into(), io::Error::from(error))
    })
}

fn read_bounded_secret<R: Read>(
    reader: R,
    max_bytes: u64,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, PqValidatorDirError> {
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| PqValidatorDirError::PasswordTooLarge(path.into()))?;
    let capacity = usize::try_from(read_limit)
        .map_err(|_| PqValidatorDirError::PasswordTooLarge(path.into()))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| PqValidatorDirError::UnableToReadFile(path.into(), error))?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > max_bytes) {
        return Err(PqValidatorDirError::PasswordTooLarge(path.into()));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn read_sensitive_file(
    path: &Path,
    max_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>, PqValidatorDirError> {
    let (parent_path, component) = split_parent_component(path)?;
    let parent = open_directory_path(&parent_path, false)?;
    let file = open_sensitive_file_at(&parent, &component, path)?;
    let bytes = read_bounded_secret(file, max_bytes, path)?;
    parent.verify_path_binding()?;
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_sensitive_file(
    _path: &Path,
    _max_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>, PqValidatorDirError> {
    Err(PqValidatorDirError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs2::FileExt;
    use std::cell::Cell;
    use std::fs::OpenOptions;
    use std::io::{Cursor, Write};
    use std::sync::OnceLock;
    use tempfile::tempdir;

    const TEST_PASSWORD: &[u8] = b"password";

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

    fn test_keystore() -> PqKeystore {
        static KEYSTORE: OnceLock<PqKeystore> = OnceLock::new();
        KEYSTORE
            .get_or_init(|| {
                PqKeystore::from_seed([0x41; 32], 0..=7, TEST_PASSWORD).expect("small keystore")
            })
            .clone()
    }

    struct FailAfterValidatorDirectory;

    impl ProvisioningHooks for FailAfterValidatorDirectory {
        fn after_validator_directory_created(
            &mut self,
            validator_path: &Path,
        ) -> Result<(), PqValidatorDirError> {
            Err(PqValidatorDirError::UnableToSync(
                validator_path.into(),
                io::Error::other("injected post-mkdir failure"),
            ))
        }
    }

    struct SwapParentPaths {
        moved_validators: PathBuf,
        moved_passwords: PathBuf,
    }

    #[cfg(unix)]
    struct SwapValidatorPath {
        moved_validator: PathBuf,
    }

    impl ProvisioningHooks for SwapParentPaths {
        fn after_parent_handles_opened(
            &mut self,
            validators_path: &Path,
            password_path: Option<&Path>,
        ) -> Result<(), PqValidatorDirError> {
            let password_path = password_path.expect("password path");
            fs::rename(validators_path, &self.moved_validators).map_err(|error| {
                PqValidatorDirError::UnableToCreateDirectory(validators_path.into(), error)
            })?;
            fs::rename(password_path, &self.moved_passwords).map_err(|error| {
                PqValidatorDirError::UnableToCreateDirectory(password_path.into(), error)
            })?;
            create_private_directory(validators_path)?;
            create_private_directory(password_path)
        }
    }

    #[cfg(unix)]
    impl DirectoryReadHooks for SwapValidatorPath {
        fn after_directory_opened(
            &mut self,
            validator_path: &Path,
        ) -> Result<(), PqValidatorDirError> {
            use std::os::unix::fs::PermissionsExt;

            fs::rename(validator_path, &self.moved_validator).map_err(|error| {
                PqValidatorDirError::UnableToCreateDirectory(validator_path.into(), error)
            })?;
            create_private_directory(validator_path)?;
            let source = self.moved_validator.join(PQ_VOTING_KEYSTORE_FILE);
            let replacement = validator_path.join(PQ_VOTING_KEYSTORE_FILE);
            fs::copy(source, &replacement).map_err(|error| {
                PqValidatorDirError::UnableToWriteFile(replacement.clone(), error)
            })?;
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
                .map_err(|error| PqValidatorDirError::UnableToWriteFile(replacement.clone(), error))
        }
    }

    #[cfg(unix)]
    fn create_stored_validator_fixture(base: &Path, keystore: &PqKeystore) -> PathBuf {
        use std::os::unix::fs::OpenOptionsExt;

        let path = PqValidatorDirBuilder::get_dir_path(base, keystore);
        create_private_directory(&path).expect("validator directory");
        let keystore_path = path.join(PQ_VOTING_KEYSTORE_FILE);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&keystore_path)
            .expect("keystore file");
        file.write_all(keystore.to_json_string().expect("JSON").as_bytes())
            .expect("write keystore");
        file.sync_all().expect("sync keystore");
        path
    }

    struct ErrorAfterData {
        emitted: bool,
    }

    struct RecordingReader<'a> {
        first_buffer_len: &'a Cell<usize>,
        emitted: bool,
    }

    impl Read for RecordingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.emitted {
                Ok(0)
            } else {
                self.emitted = true;
                self.first_buffer_len.set(buffer.len());
                buffer[..8].copy_from_slice(b"password");
                Ok(8)
            }
        }
    }

    impl Read for ErrorAfterData {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.emitted {
                Err(io::Error::other("injected read failure"))
            } else {
                self.emitted = true;
                let data = b"partial-password";
                let len = data.len().min(buffer.len());
                buffer[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
        }
    }

    #[test]
    fn bounded_secret_reader_owns_a_zeroizing_buffer_from_the_first_read() {
        let path = Path::new("password-fixture");
        let first_buffer_len = Cell::new(0);
        let secret: Zeroizing<Vec<u8>> = read_bounded_secret(
            RecordingReader {
                first_buffer_len: &first_buffer_len,
                emitted: false,
            },
            32,
            path,
        )
        .expect("bounded secret");
        assert_eq!(secret.as_slice(), b"password");
        assert_eq!(first_buffer_len.get(), 33);

        assert!(matches!(
            read_bounded_secret(ErrorAfterData { emitted: false }, 32, path),
            Err(PqValidatorDirError::UnableToReadFile(error_path, _))
                if error_path == path
        ));
        assert!(matches!(
            read_bounded_secret(Cursor::new(b"too-long"), 3, path),
            Err(PqValidatorDirError::PasswordTooLarge(error_path)) if error_path == path
        ));
    }

    #[cfg(unix)]
    #[test]
    fn private_writer_refuses_an_existing_file() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("key");
        fs::write(&path, b"existing").expect("fixture");
        let called = Cell::new(false);
        assert!(matches!(
            create_sensitive_file_with(&path, b"replacement", false, |_, _| {
                called.set(true);
                Ok(())
            }),
            Err(PqValidatorDirError::KeystoreAlreadyExists(_))
        ));
        assert!(!called.get());
        assert_eq!(fs::read(path).expect("read"), b"existing");
    }

    #[cfg(unix)]
    #[test]
    fn private_writer_leaves_a_tombstone_after_write_failure() {
        let directory = tempdir().expect("tempdir");
        let existing = directory.path().join("existing");
        fs::write(&existing, b"untouched").expect("fixture");
        let path = directory.path().join("new-password");

        let result = create_sensitive_file_with(&path, b"password", true, |file, bytes| {
            file.write_all(&bytes[..3])
                .map_err(|error| PqValidatorDirError::UnableToWriteFile(path.clone(), error))?;
            Err(PqValidatorDirError::UnableToWriteFile(
                path.clone(),
                io::Error::other("injected write failure"),
            ))
        });

        assert!(matches!(
            result,
            Err(PqValidatorDirError::UnableToWriteFile(error_path, _)) if error_path == path
        ));
        assert_eq!(fs::read(&path).expect("partial tombstone"), b"pas");
        assert_eq!(fs::read(existing).expect("read existing"), b"untouched");
    }

    #[cfg(unix)]
    #[test]
    fn private_writer_leaves_a_tombstone_after_sync_failure() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("new-password");

        let result = create_sensitive_file_with(&path, b"password", true, |file, bytes| {
            file.write_all(bytes)
                .map_err(|error| PqValidatorDirError::UnableToWriteFile(path.clone(), error))?;
            Err(PqValidatorDirError::UnableToSync(
                path.clone(),
                io::Error::other("injected sync failure"),
            ))
        });

        assert!(matches!(
            result,
            Err(PqValidatorDirError::UnableToSync(error_path, _)) if error_path == path
        ));
        assert_eq!(fs::read(&path).expect("complete tombstone"), b"password");
    }

    #[cfg(unix)]
    #[test]
    fn builder_leaves_created_directory_tombstone_after_later_error() {
        let _work_lock = pq_work_lock();
        let validators = tempdir().expect("validators");
        let keystore = test_keystore();
        let validator_path = PqValidatorDirBuilder::get_dir_path(validators.path(), &keystore);
        let mut hooks = FailAfterValidatorDirectory;

        let result = PqValidatorDirBuilder::new(validators.path().into())
            .voting_keystore(keystore, TEST_PASSWORD)
            .build_with_hooks(&mut hooks, |keystore, password| {
                keystore.validate_password(password)
            });

        assert!(matches!(
            result,
            Err(PqValidatorDirError::UnableToSync(_, _))
        ));
        assert!(validator_path.is_dir());
        assert!(matches!(
            PqValidatorDirBuilder::new(validators.path().into())
                .voting_keystore(test_keystore(), TEST_PASSWORD)
                .build_with_hooks(&mut NoopProvisioningHooks, |_, _| Ok(())),
            Err(PqValidatorDirError::DirectoryAlreadyExists(path)) if path == validator_path
        ));
    }

    #[cfg(unix)]
    #[test]
    fn collision_preflight_does_not_run_password_validation() {
        let _work_lock = pq_work_lock();
        let validators = tempdir().expect("validators");
        let passwords = tempdir().expect("passwords");
        let keystore = test_keystore();
        let component = canonical_directory_name(keystore.public_key());
        let validator_path = PqValidatorDirBuilder::get_dir_path(validators.path(), &keystore);
        create_private_directory(&validator_path).expect("collision");
        let validation_called = Cell::new(false);

        let result = PqValidatorDirBuilder::new(validators.path().into())
            .voting_keystore(keystore, TEST_PASSWORD)
            .build_with_hooks(&mut NoopProvisioningHooks, |_, _| {
                validation_called.set(true);
                Ok(())
            });

        assert!(!validation_called.get());
        assert!(matches!(
            result,
            Err(PqValidatorDirError::DirectoryAlreadyExists(path)) if path == validator_path
        ));

        fs::remove_dir(&validator_path).expect("remove test collision");
        let password_target = passwords.path().join(&component);
        fs::write(&password_target, b"existing password").expect("password collision");
        let result = PqValidatorDirBuilder::new(validators.path().into())
            .password_dir(passwords.path())
            .voting_keystore(test_keystore(), TEST_PASSWORD)
            .build_with_hooks(&mut NoopProvisioningHooks, |_, _| {
                validation_called.set(true);
                Ok(())
            });
        assert!(!validation_called.get());
        assert!(matches!(
            result,
            Err(PqValidatorDirError::PasswordAlreadyExists(path)) if path == password_target
        ));
        assert_eq!(
            fs::read(password_target).expect("preexisting password"),
            b"existing password"
        );
    }

    #[cfg(unix)]
    #[test]
    fn provisioning_parent_swap_never_redirects_writes() {
        let _work_lock = pq_work_lock();
        let parent = tempdir().expect("parent");
        let validators = parent.path().join("validators");
        let passwords = parent.path().join("passwords");
        create_private_directory(&validators).expect("validators");
        create_private_directory(&passwords).expect("passwords");
        let moved_validators = parent.path().join("moved-validators");
        let moved_passwords = parent.path().join("moved-passwords");
        let keystore = test_keystore();
        let component = canonical_directory_name(keystore.public_key());
        let mut hooks = SwapParentPaths {
            moved_validators: moved_validators.clone(),
            moved_passwords: moved_passwords.clone(),
        };

        let result = PqValidatorDirBuilder::new(validators.clone())
            .password_dir(passwords.clone())
            .voting_keystore(keystore, TEST_PASSWORD)
            .build_with_hooks(&mut hooks, |keystore, password| {
                keystore.validate_password(password)
            });

        assert!(matches!(
            result,
            Err(PqValidatorDirError::UnsafeDirectoryTarget(_))
        ));
        assert!(
            moved_validators
                .join(&component)
                .join(PQ_VOTING_KEYSTORE_FILE)
                .is_file()
        );
        assert!(moved_passwords.join(&component).is_file());
        assert_eq!(fs::read_dir(&validators).expect("replacement").count(), 0);
        assert_eq!(fs::read_dir(&passwords).expect("replacement").count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn open_rejects_validator_path_swap_after_directory_open() {
        let _work_lock = pq_work_lock();
        let root = tempdir().expect("root");
        let validator_path = create_stored_validator_fixture(root.path(), &test_keystore());
        let moved_validator = root.path().join("moved-validator");
        let mut hooks = SwapValidatorPath {
            moved_validator: moved_validator.clone(),
        };

        let result = PqValidatorDir::open_with_hooks(&validator_path, &mut hooks);

        assert!(matches!(
            result,
            Err(PqValidatorDirError::UnsafeDirectoryTarget(path)) if path == validator_path
        ));
        assert!(moved_validator.join(PQ_VOTING_KEYSTORE_FILE).is_file());
        assert!(validator_path.join(PQ_VOTING_KEYSTORE_FILE).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn keystore_reread_rejects_validator_path_swap_after_directory_open() {
        let _work_lock = pq_work_lock();
        let root = tempdir().expect("root");
        let validator_path = create_stored_validator_fixture(root.path(), &test_keystore());
        let validator = PqValidatorDir::open(&validator_path).expect("open validator");
        let moved_validator = root.path().join("moved-validator");
        let mut hooks = SwapValidatorPath {
            moved_validator: moved_validator.clone(),
        };

        let result = validator.keystore_with_hooks(&mut hooks);

        assert!(matches!(
            result,
            Err(PqValidatorDirError::UnsafeDirectoryTarget(path)) if path == validator_path
        ));
        assert!(moved_validator.join(PQ_VOTING_KEYSTORE_FILE).is_file());
        assert!(validator_path.join(PQ_VOTING_KEYSTORE_FILE).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn directory_builder_rejects_oversized_password_before_validation_or_mutation() {
        let _work_lock = pq_work_lock();
        let validators = tempdir().expect("validators");
        let keystore = test_keystore();
        let validator_path = PqValidatorDirBuilder::get_dir_path(validators.path(), &keystore);
        let validation_called = Cell::new(false);
        let oversized_password = vec![0; MAX_PQ_PASSWORD_BYTES + 1];

        let result = PqValidatorDirBuilder::new(validators.path().into())
            .voting_keystore(keystore, &oversized_password)
            .build_with_hooks(&mut NoopProvisioningHooks, |_, _| {
                validation_called.set(true);
                Ok(())
            });

        assert!(!validation_called.get());
        assert!(matches!(
            result,
            Err(PqValidatorDirError::Keystore(
                PqKeystoreError::PasswordTooLong
            ))
        ));
        assert!(!validator_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn fd_relative_builder_creates_missing_root_directories() {
        let _work_lock = pq_work_lock();
        let parent = tempdir().expect("parent");
        let validators = parent.path().join("validators");
        let passwords = parent.path().join("passwords");
        let keystore = test_keystore();

        let validator = PqValidatorDirBuilder::new(validators.clone())
            .password_dir(passwords.clone())
            .voting_keystore(keystore, TEST_PASSWORD)
            .build_with_hooks(&mut NoopProvisioningHooks, |_, _| Ok(()))
            .expect("build with missing roots");

        assert!(validator.pq_voting_keystore_path().is_file());
        assert!(
            passwords
                .join(canonical_directory_name(validator.public_key()))
                .is_file()
        );
    }
}
