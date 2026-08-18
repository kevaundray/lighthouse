//! Crash-safe, fail-closed XMSS one-time-use journal for the experimental PQ profile.
//!
//! Reservation is deliberately not a public API:
//!
//! ```compile_fail
//! use pq_signing::journal::XmssUsageJournal;
//! ```

use consensus_signature::OneTimeUseId;
use fs2::FileExt;
use parking_lot::Mutex;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub const XMSS_USAGE_FILENAME: &str = "xmss_usage.sqlite";
const APPLICATION_ID: i32 = 0x4c48_5051;
const SCHEMA_VERSION: i32 = 1;
const LEAN_PQ_DEVNET_V1_PROFILE_ID: [u8; 32] = *b"lighthouse/lean-pq-devnet/v1\0\0\0\0";
const LEAN_PQ_DEVNET_V1_ALLOCATION: u32 = 1;
const XMSS_KEYS_SCHEMA: &str = "CREATE TABLE xmss_keys (
                stable_key_id BLOB PRIMARY KEY NOT NULL CHECK(length(stable_key_id) = 32),
                profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
                allocation_version INTEGER NOT NULL,
                genesis_validators_root BLOB NOT NULL CHECK(length(genesis_validators_root) = 32),
                public_key BLOB NOT NULL UNIQUE CHECK(length(public_key) = 32),
                first_leaf INTEGER NOT NULL CHECK(first_leaf >= 0 AND first_leaf <= 4294967295),
                last_leaf INTEGER NOT NULL CHECK(last_leaf >= 0 AND last_leaf <= 4294967295),
                CHECK(first_leaf <= last_leaf)
            ) WITHOUT ROWID, STRICT";
const RESERVATIONS_SCHEMA: &str = "CREATE TABLE reservations (
                stable_key_id BLOB NOT NULL,
                one_time_use_id INTEGER NOT NULL CHECK(one_time_use_id >= 0 AND one_time_use_id <= 4294967295),
                signing_root BLOB NOT NULL CHECK(length(signing_root) = 32),
                PRIMARY KEY(stable_key_id, one_time_use_id),
                FOREIGN KEY(stable_key_id) REFERENCES xmss_keys(stable_key_id)
            ) WITHOUT ROWID, STRICT";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::authority) struct XmssKeyBinding {
    stable_key_id: [u8; 32],
    profile_id: [u8; 32],
    allocation_version: u32,
    genesis_validators_root: [u8; 32],
    public_key: [u8; 32],
    first_leaf: u32,
    last_leaf: u32,
}

impl XmssKeyBinding {
    #[cfg(test)]
    pub(in crate::authority) fn lean_pq_devnet_v1(
        public_key: [u8; 32],
        genesis_validators_root: [u8; 32],
        one_time_use_range: std::ops::RangeInclusive<OneTimeUseId>,
    ) -> Result<Self, XmssJournalError> {
        let first_leaf = one_time_use_range.start().as_u32();
        let last_leaf = one_time_use_range.end().as_u32();
        if first_leaf > last_leaf {
            return Err(XmssJournalError::InvalidLeafRange);
        }
        Ok(Self {
            // V1 uses the canonical public-key bytes as its stable, non-caller-selectable key ID.
            stable_key_id: public_key,
            profile_id: LEAN_PQ_DEVNET_V1_PROFILE_ID,
            allocation_version: LEAN_PQ_DEVNET_V1_ALLOCATION,
            genesis_validators_root,
            public_key,
            first_leaf,
            last_leaf,
        })
    }

    pub(in crate::authority) fn from_raw_range(
        public_key: [u8; 32],
        genesis_validators_root: [u8; 32],
        one_time_use_range: std::ops::RangeInclusive<u32>,
    ) -> Result<Self, XmssJournalError> {
        let first_leaf = *one_time_use_range.start();
        let last_leaf = *one_time_use_range.end();
        if first_leaf > last_leaf {
            return Err(XmssJournalError::InvalidLeafRange);
        }
        Ok(Self {
            stable_key_id: public_key,
            profile_id: LEAN_PQ_DEVNET_V1_PROFILE_ID,
            allocation_version: LEAN_PQ_DEVNET_V1_ALLOCATION,
            genesis_validators_root,
            public_key,
            first_leaf,
            last_leaf,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum XmssJournalError {
    AlreadyExists(PathBuf),
    MissingJournal(PathBuf),
    MissingLockfile(PathBuf),
    JournalLocked(PathBuf),
    Lockfile(PathBuf, String),
    Filesystem(PathBuf, String),
    InsecurePermissions(PathBuf),
    UnsupportedPlatform,
    Database(String),
    WrongApplicationId(i32),
    WrongSchemaVersion(i32),
    WrongJournalMode,
    SchemaMismatch,
    IntegrityCheckFailed,
    InvalidLeafRange,
    LeafOutsideBoundRange,
    UnknownKey,
    BindingMismatch,
    ConflictingRoot,
}

impl std::fmt::Display for XmssJournalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists(path) => {
                write!(formatter, "XMSS journal already exists: {}", path.display())
            }
            Self::MissingJournal(path) => {
                write!(formatter, "XMSS journal is missing: {}", path.display())
            }
            Self::MissingLockfile(path) => write!(
                formatter,
                "XMSS journal lockfile is missing: {}",
                path.display()
            ),
            Self::JournalLocked(path) => {
                write!(formatter, "XMSS journal is locked: {}", path.display())
            }
            Self::Lockfile(path, diagnostic) => write!(
                formatter,
                "unable to use XMSS journal lockfile {}: {diagnostic}",
                path.display(),
            ),
            Self::Filesystem(path, diagnostic) => write!(
                formatter,
                "XMSS journal filesystem operation failed for {}: {diagnostic}",
                path.display(),
            ),
            Self::InsecurePermissions(path) => write!(
                formatter,
                "XMSS journal path must be a regular 0600 file: {}",
                path.display()
            ),
            Self::UnsupportedPlatform => {
                formatter.write_str("the PQ XMSS journal currently requires a Unix platform")
            }
            Self::Database(diagnostic) => {
                write!(
                    formatter,
                    "XMSS journal database operation failed: {diagnostic}"
                )
            }
            Self::WrongApplicationId(actual) => {
                write!(formatter, "wrong XMSS journal application id: {actual}")
            }
            Self::WrongSchemaVersion(actual) => write!(
                formatter,
                "unsupported XMSS journal schema version: {actual}"
            ),
            Self::WrongJournalMode => {
                formatter.write_str("XMSS journal is not in DELETE rollback-journal mode")
            }
            Self::SchemaMismatch => {
                formatter.write_str("XMSS journal schema does not match the fixed version")
            }
            Self::IntegrityCheckFailed => {
                formatter.write_str("XMSS journal integrity check failed")
            }
            Self::InvalidLeafRange => formatter.write_str("invalid XMSS leaf range"),
            Self::LeafOutsideBoundRange => {
                formatter.write_str("XMSS leaf is outside the key's bound range")
            }
            Self::UnknownKey => {
                formatter.write_str("XMSS journal does not contain the requested key")
            }
            Self::BindingMismatch => formatter.write_str("XMSS journal key binding mismatch"),
            Self::ConflictingRoot => {
                formatter.write_str("XMSS leaf is already reserved for a different signing root")
            }
        }
    }
}

impl std::error::Error for XmssJournalError {}

fn database_error(error: rusqlite::Error) -> XmssJournalError {
    XmssJournalError::Database(error.to_string())
}

fn database_invariant(diagnostic: &'static str) -> XmssJournalError {
    XmssJournalError::Database(diagnostic.to_owned())
}

fn lockfile_error(path: &Path, error: std::io::Error) -> XmssJournalError {
    XmssJournalError::Lockfile(path.to_path_buf(), error.to_string())
}

fn filesystem_error(path: &Path, error: std::io::Error) -> XmssJournalError {
    XmssJournalError::Filesystem(path.to_path_buf(), error.to_string())
}

/// Lock and operation order for the combined authority:
///
/// 1. The caller commits ordinary slashing protection before entering this journal.
/// 2. Reservation takes `connection`, opens one exclusive transaction, commits, then releases the
///    transaction and mutex.
/// 3. Only after release may the callback take key-cache/backend locks or perform expensive work.
///
/// Field order is intentional: Rust drops the SQLite connection before `_lockfile`, so the
/// persistent process lock remains held until all database locks have been released.
pub(in crate::authority) struct XmssUsageJournal {
    connection: Mutex<Connection>,
    _lockfile: JournalLock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::authority) enum Reservation {
    Fresh,
    SameRoot,
}

#[derive(Debug, PartialEq, Eq)]
#[cfg(test)]
pub(in crate::authority) enum ReserveAndThenError<CallbackError> {
    Journal(XmssJournalError),
    Callback(CallbackError),
}

impl XmssUsageJournal {
    pub(in crate::authority) fn provision<'a>(
        path: &Path,
        bindings: impl IntoIterator<Item = &'a XmssKeyBinding>,
    ) -> Result<Self, XmssJournalError> {
        ensure_supported_platform()?;
        if path.exists() {
            return Err(XmssJournalError::AlreadyExists(path.to_path_buf()));
        }
        let lockfile = create_lockfile(path)?;
        create_restricted_file(path)?;
        let mut connection = open_connection(path, true)?;
        initialize_schema(&mut connection, bindings)?;
        sync_provisioned_files(path)?;
        Ok(Self {
            connection: Mutex::new(connection),
            _lockfile: lockfile,
        })
    }

    pub(in crate::authority) fn open<'a>(
        path: &Path,
        active_bindings: impl IntoIterator<Item = &'a XmssKeyBinding>,
    ) -> Result<Self, XmssJournalError> {
        ensure_supported_platform()?;
        if !path.is_file() {
            return Err(XmssJournalError::MissingJournal(path.to_path_buf()));
        }
        validate_restrictive_permissions(path)?;
        let lockfile = open_lockfile(path)?;
        let connection = open_connection(path, false)?;
        validate_database(&connection)?;
        for binding in active_bindings {
            validate_binding_on_connection(&connection, binding)?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
            _lockfile: lockfile,
        })
    }

    pub(in crate::authority) fn validate_binding(
        &self,
        expected: &XmssKeyBinding,
    ) -> Result<(), XmssJournalError> {
        let connection = self.connection.lock();
        validate_binding_on_connection(&connection, expected)
    }

    /// Permanently reserve one one-time-use leaf before any signature bytes are produced.
    ///
    /// This remains private so sibling modules can only use the combined journal-owning signing
    /// authority operation.
    pub(in crate::authority) fn reserve(
        &self,
        expected: &XmssKeyBinding,
        one_time_use_id: OneTimeUseId,
        signing_root: [u8; 32],
    ) -> Result<Reservation, XmssJournalError> {
        self.reserve_with_commit_hook(expected, one_time_use_id, signing_root, || Ok(()))
    }

    #[cfg(test)]
    pub(in crate::authority) fn reserve_and_then<T, CallbackError>(
        &self,
        expected: &XmssKeyBinding,
        one_time_use_id: OneTimeUseId,
        signing_root: [u8; 32],
        callback: impl FnOnce(Reservation) -> Result<T, CallbackError>,
    ) -> Result<T, ReserveAndThenError<CallbackError>> {
        let reservation = self
            .reserve(expected, one_time_use_id, signing_root)
            .map_err(ReserveAndThenError::Journal)?;
        callback(reservation).map_err(ReserveAndThenError::Callback)
    }

    #[cfg(test)]
    pub(in crate::authority) fn reserve_and_then_with_commit_hook<T, CallbackError>(
        &self,
        expected: &XmssKeyBinding,
        one_time_use_id: OneTimeUseId,
        signing_root: [u8; 32],
        before_commit: impl FnOnce() -> Result<(), XmssJournalError>,
        callback: impl FnOnce(Reservation) -> Result<T, CallbackError>,
    ) -> Result<T, ReserveAndThenError<CallbackError>> {
        let reservation = self
            .reserve_with_commit_hook(expected, one_time_use_id, signing_root, before_commit)
            .map_err(ReserveAndThenError::Journal)?;
        callback(reservation).map_err(ReserveAndThenError::Callback)
    }

    fn reserve_with_commit_hook(
        &self,
        expected: &XmssKeyBinding,
        one_time_use_id: OneTimeUseId,
        signing_root: [u8; 32],
        before_commit: impl FnOnce() -> Result<(), XmssJournalError>,
    ) -> Result<Reservation, XmssJournalError> {
        let mut connection = self.connection.lock();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .map_err(database_error)?;
        validate_binding_on_connection(&transaction, expected)?;
        let leaf = one_time_use_id.as_u32();
        if leaf < expected.first_leaf || leaf > expected.last_leaf {
            return Err(XmssJournalError::LeafOutsideBoundRange);
        }

        let inserted = transaction
            .execute(
                "INSERT INTO reservations (stable_key_id, one_time_use_id, signing_root)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(stable_key_id, one_time_use_id) DO NOTHING",
                params![expected.stable_key_id, i64::from(leaf), signing_root],
            )
            .map_err(database_error)?;
        let reservation = if inserted == 1 {
            Reservation::Fresh
        } else {
            let existing_root = transaction
                .query_row(
                    "SELECT signing_root FROM reservations
                     WHERE stable_key_id = ?1 AND one_time_use_id = ?2",
                    params![expected.stable_key_id, i64::from(leaf)],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(database_error)?;
            if existing_root.as_slice() == signing_root {
                Reservation::SameRoot
            } else {
                return Err(XmssJournalError::ConflictingRoot);
            }
        };
        before_commit()?;
        transaction.commit().map_err(database_error)?;
        Ok(reservation)
    }
}

fn validate_binding_on_connection(
    connection: &Connection,
    expected: &XmssKeyBinding,
) -> Result<(), XmssJournalError> {
    if expected.stable_key_id != expected.public_key
        || expected.profile_id != LEAN_PQ_DEVNET_V1_PROFILE_ID
        || expected.allocation_version != LEAN_PQ_DEVNET_V1_ALLOCATION
        || expected.first_leaf > expected.last_leaf
    {
        return Err(XmssJournalError::BindingMismatch);
    }
    let stored = connection
        .query_row(
            "SELECT profile_id, allocation_version, genesis_validators_root, \
                public_key, first_leaf, last_leaf FROM xmss_keys WHERE stable_key_id = ?1",
            params![expected.stable_key_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .ok_or(XmssJournalError::UnknownKey)?;

    let matches = stored.0.as_slice() == expected.profile_id
        && stored.1 == i64::from(expected.allocation_version)
        && stored.2.as_slice() == expected.genesis_validators_root
        && stored.3.as_slice() == expected.public_key
        && stored.4 == i64::from(expected.first_leaf)
        && stored.5 == i64::from(expected.last_leaf);
    if matches {
        Ok(())
    } else {
        Err(XmssJournalError::BindingMismatch)
    }
}

fn lockfile_path(database_path: &Path) -> PathBuf {
    let mut path = database_path.as_os_str().to_owned();
    path.push(".lock");
    PathBuf::from(path)
}

struct JournalLock {
    _file: File,
}

fn create_lockfile(database_path: &Path) -> Result<JournalLock, XmssJournalError> {
    let path = lockfile_path(database_path);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(&path)
        .map_err(|error| lockfile_error(&path, error))?;
    file.sync_all()
        .map_err(|error| lockfile_error(&path, error))?;
    lock_file(file, path)
}

fn open_lockfile(database_path: &Path) -> Result<JournalLock, XmssJournalError> {
    let path = lockfile_path(database_path);
    if !path.is_file() {
        return Err(XmssJournalError::MissingLockfile(path));
    }
    validate_restrictive_permissions(&path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(&path)
        .map_err(|error| lockfile_error(&path, error))?;
    #[cfg(unix)]
    validate_open_file_permissions(&file, &path)?;
    lock_file(file, path)
}

fn lock_file(file: File, path: PathBuf) -> Result<JournalLock, XmssJournalError> {
    file.try_lock_exclusive().map_err(|error| {
        if error.kind() == ErrorKind::WouldBlock {
            XmssJournalError::JournalLocked(path.clone())
        } else {
            lockfile_error(&path, error)
        }
    })?;
    Ok(JournalLock { _file: file })
}

#[cfg(unix)]
fn validate_restrictive_permissions(path: &Path) -> Result<(), XmssJournalError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| filesystem_error(path, error))?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(XmssJournalError::InsecurePermissions(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_open_file_permissions(file: &File, path: &Path) -> Result<(), XmssJournalError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = file
        .metadata()
        .map_err(|error| filesystem_error(path, error))?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(XmssJournalError::InsecurePermissions(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_restrictive_permissions(_path: &Path) -> Result<(), XmssJournalError> {
    Err(XmssJournalError::UnsupportedPlatform)
}

#[cfg(unix)]
fn ensure_supported_platform() -> Result<(), XmssJournalError> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_supported_platform() -> Result<(), XmssJournalError> {
    Err(XmssJournalError::UnsupportedPlatform)
}

fn create_restricted_file(path: &Path) -> Result<(), XmssJournalError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    options
        .open(path)
        .map(drop)
        .map_err(|error| filesystem_error(path, error))
}

fn open_connection(path: &Path, provisioning: bool) -> Result<Connection, XmssJournalError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(database_error)?;
    apply_pragmas(&connection, provisioning)?;
    Ok(connection)
}

fn apply_pragmas(connection: &Connection, provisioning: bool) -> Result<(), XmssJournalError> {
    let journal_mode: String = if provisioning {
        connection
            .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
            .map_err(database_error)?
    } else {
        connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(database_error)?
    };
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(XmssJournalError::WrongJournalMode);
    }
    connection
        .pragma_update(None, "synchronous", "EXTRA")
        .and_then(|()| connection.pragma_update(None, "foreign_keys", true))
        .and_then(|()| connection.pragma_update(None, "locking_mode", "EXCLUSIVE"))
        .map_err(database_error)?;
    let synchronous: i32 = connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(database_error)?;
    let foreign_keys: i32 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(database_error)?;
    let locking_mode: String = connection
        .pragma_query_value(None, "locking_mode", |row| row.get(0))
        .map_err(database_error)?;
    if synchronous != 3 || foreign_keys != 1 || !locking_mode.eq_ignore_ascii_case("exclusive") {
        return Err(database_invariant("required SQLite PRAGMA was not applied"));
    }
    Ok(())
}

fn initialize_schema<'a>(
    connection: &mut Connection,
    bindings: impl IntoIterator<Item = &'a XmssKeyBinding>,
) -> Result<(), XmssJournalError> {
    connection
        .pragma_update(None, "application_id", APPLICATION_ID)
        .and_then(|()| connection.pragma_update(None, "user_version", SCHEMA_VERSION))
        .map_err(database_error)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(database_error)?;
    transaction
        .execute_batch(XMSS_KEYS_SCHEMA)
        .and_then(|()| transaction.execute_batch(RESERVATIONS_SCHEMA))
        .map_err(database_error)?;
    for binding in bindings {
        transaction
            .execute(
                "INSERT INTO xmss_keys (
                    stable_key_id, profile_id, allocation_version, genesis_validators_root,
                    public_key, first_leaf, last_leaf
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    binding.stable_key_id,
                    binding.profile_id,
                    i64::from(binding.allocation_version),
                    binding.genesis_validators_root,
                    binding.public_key,
                    i64::from(binding.first_leaf),
                    i64::from(binding.last_leaf),
                ],
            )
            .map_err(database_error)?;
    }
    transaction.commit().map_err(database_error)?;
    validate_database(connection)
}

fn validate_database(connection: &Connection) -> Result<(), XmssJournalError> {
    let application_id: i32 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(database_error)?;
    if application_id != APPLICATION_ID {
        return Err(XmssJournalError::WrongApplicationId(application_id));
    }
    let schema_version: i32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(database_error)?;
    if schema_version != SCHEMA_VERSION {
        return Err(XmssJournalError::WrongSchemaVersion(schema_version));
    }
    validate_schema(connection)?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(database_error)?;
    if integrity != "ok" {
        return Err(XmssJournalError::IntegrityCheckFailed);
    }
    let foreign_key_violation = connection
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
        .optional()
        .map_err(database_error)?
        .is_some();
    if foreign_key_violation {
        return Err(XmssJournalError::IntegrityCheckFailed);
    }
    let invalid_keys: i64 = connection
        .query_row(
            "SELECT count(*) FROM xmss_keys WHERE
                typeof(stable_key_id) != 'blob' OR length(stable_key_id) != 32 OR
                stable_key_id != public_key OR
                typeof(profile_id) != 'blob' OR profile_id != ?1 OR
                allocation_version != ?2 OR
                typeof(genesis_validators_root) != 'blob' OR length(genesis_validators_root) != 32 OR
                typeof(public_key) != 'blob' OR length(public_key) != 32 OR
                typeof(first_leaf) != 'integer' OR first_leaf < 0 OR first_leaf > 4294967295 OR
                typeof(last_leaf) != 'integer' OR last_leaf < first_leaf OR last_leaf > 4294967295",
            params![
                LEAN_PQ_DEVNET_V1_PROFILE_ID,
                i64::from(LEAN_PQ_DEVNET_V1_ALLOCATION)
            ],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    let invalid_reservations: i64 = connection
        .query_row(
            "SELECT count(*) FROM reservations WHERE
                typeof(stable_key_id) != 'blob' OR length(stable_key_id) != 32 OR
                typeof(one_time_use_id) != 'integer' OR
                one_time_use_id < 0 OR one_time_use_id > 4294967295 OR
                typeof(signing_root) != 'blob' OR length(signing_root) != 32",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if invalid_keys != 0 || invalid_reservations != 0 {
        return Err(XmssJournalError::IntegrityCheckFailed);
    }
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<(), XmssJournalError> {
    let mut schema_statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(database_error)?;
    let schema_objects = schema_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    let expected_schema_objects = vec![
        (
            "table".to_owned(),
            "reservations".to_owned(),
            "reservations".to_owned(),
            RESERVATIONS_SCHEMA.to_owned(),
        ),
        (
            "table".to_owned(),
            "xmss_keys".to_owned(),
            "xmss_keys".to_owned(),
            XMSS_KEYS_SCHEMA.to_owned(),
        ),
    ];
    if schema_objects != expected_schema_objects {
        return Err(XmssJournalError::SchemaMismatch);
    }

    let mut statement = connection
        .prepare(
            "SELECT name, type, wr, strict FROM pragma_table_list
             WHERE schema = 'main' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(database_error)?;
    let tables = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    let expected_tables = vec![
        ("reservations".to_owned(), "table".to_owned(), 1, 1),
        ("xmss_keys".to_owned(), "table".to_owned(), 1, 1),
    ];
    if tables != expected_tables {
        return Err(XmssJournalError::SchemaMismatch);
    }

    validate_columns(
        connection,
        "xmss_keys",
        &[
            ("stable_key_id", "BLOB", 1, 1),
            ("profile_id", "BLOB", 1, 0),
            ("allocation_version", "INTEGER", 1, 0),
            ("genesis_validators_root", "BLOB", 1, 0),
            ("public_key", "BLOB", 1, 0),
            ("first_leaf", "INTEGER", 1, 0),
            ("last_leaf", "INTEGER", 1, 0),
        ],
    )?;
    validate_columns(
        connection,
        "reservations",
        &[
            ("stable_key_id", "BLOB", 1, 1),
            ("one_time_use_id", "INTEGER", 1, 2),
            ("signing_root", "BLOB", 1, 0),
        ],
    )?;
    let unique_key_indexes: i64 = connection
        .query_row(
            "SELECT count(*) FROM pragma_index_list('xmss_keys') WHERE \"unique\" = 1",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if unique_key_indexes != 2 {
        return Err(XmssJournalError::SchemaMismatch);
    }
    let foreign_keys = connection
        .query_row(
            "SELECT count(*) FROM pragma_foreign_key_list('reservations')
             WHERE \"table\" = 'xmss_keys' AND \"from\" = 'stable_key_id'
             AND \"to\" = 'stable_key_id' AND on_update = 'NO ACTION' AND on_delete = 'NO ACTION'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(database_error)?;
    if foreign_keys != 1 {
        return Err(XmssJournalError::SchemaMismatch);
    }
    Ok(())
}

fn validate_columns(
    connection: &Connection,
    table: &str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<(), XmssJournalError> {
    let mut statement = connection
        .prepare("SELECT name, type, \"notnull\", pk FROM pragma_table_xinfo(?1) ORDER BY cid")
        .map_err(database_error)?;
    let columns = statement
        .query_map([table], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    let expected = expected
        .iter()
        .map(|(name, data_type, not_null, primary_key)| {
            (
                (*name).to_owned(),
                (*data_type).to_owned(),
                *not_null,
                *primary_key,
            )
        })
        .collect::<Vec<_>>();
    if columns == expected {
        Ok(())
    } else {
        Err(XmssJournalError::SchemaMismatch)
    }
}

fn sync_provisioned_files(path: &Path) -> Result<(), XmssJournalError> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| filesystem_error(path, error))?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| filesystem_error(parent, error))?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use consensus_signature::{OneTimeUseId, SigningDuty};
    use tempfile::tempdir;

    const SUBPROCESS_DATABASE_ENV: &str = "LIGHTHOUSE_XMSS_JOURNAL_TEST_DATABASE";
    const SUBPROCESS_MARKER_ENV: &str = "LIGHTHOUSE_XMSS_JOURNAL_TEST_MARKER";
    const SUBPROCESS_MODE_ENV: &str = "LIGHTHOUSE_XMSS_JOURNAL_TEST_MODE";

    fn leaf(slot: u64, duty: SigningDuty) -> OneTimeUseId {
        OneTimeUseId::for_lean_pq_devnet_v1(slot, duty).expect("test leaf must be valid")
    }

    fn binding() -> XmssKeyBinding {
        XmssKeyBinding::lean_pq_devnet_v1(
            [2; 32],
            [3; 32],
            leaf(0, SigningDuty::RandaoReveal)..=leaf(1, SigningDuty::BeaconBlockProposal),
        )
        .expect("test binding must be valid")
    }

    #[test]
    fn provisioning_creates_a_bound_journal_that_reopens() {
        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();

        let journal = XmssUsageJournal::provision(&path, [&expected_binding])
            .expect("journal provisioning must succeed");
        journal
            .validate_binding(&expected_binding)
            .expect("provisioned binding must validate");
        drop(journal);

        let reopened =
            XmssUsageJournal::open(&path, [&expected_binding]).expect("journal must reopen");
        reopened
            .validate_binding(&expected_binding)
            .expect("reopened binding must validate");
    }

    #[test]
    fn normal_open_refuses_to_create_a_missing_journal() {
        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);

        assert!(matches!(
            XmssUsageJournal::open(&path, []),
            Err(XmssJournalError::MissingJournal(_))
        ));
        assert!(!path.exists(), "normal open must not create the database");
    }

    #[test]
    fn journal_uses_power_loss_safe_rollback_settings() {
        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let journal = XmssUsageJournal::provision(&path, [&expected_binding])
            .expect("journal provisioning must succeed");
        let connection = journal.connection.lock();

        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal mode must be readable");
        let synchronous: i32 = connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .expect("synchronous mode must be readable");
        let locking_mode: String = connection
            .pragma_query_value(None, "locking_mode", |row| row.get(0))
            .expect("locking mode must be readable");

        assert_eq!(journal_mode.to_ascii_lowercase(), "delete");
        assert_eq!(synchronous, 3, "EXTRA is required for directory durability");
        assert_eq!(locking_mode.to_ascii_lowercase(), "exclusive");
        let keys_without_rowid: i32 = connection
            .query_row(
                "SELECT wr FROM pragma_table_list WHERE name = 'xmss_keys'",
                [],
                |row| row.get(0),
            )
            .expect("key table storage mode must be readable");
        assert_eq!(keys_without_rowid, 1);
    }

    #[test]
    fn persistent_lock_refuses_a_second_owner_and_survives_drop() {
        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let journal = XmssUsageJournal::provision(&path, [&expected_binding])
            .expect("journal provisioning must succeed");
        let persistent_lock_path = lockfile_path(&path);

        assert!(matches!(
            XmssUsageJournal::open(&path, [&expected_binding]),
            Err(XmssJournalError::JournalLocked(_))
        ));
        drop(journal);
        assert!(
            persistent_lock_path.exists(),
            "the persistent lock pathname must never be unlinked on drop"
        );
        XmssUsageJournal::open(&path, [&expected_binding])
            .expect("the persistent lock must be reusable after release");
    }

    #[test]
    fn invalid_and_mismatched_bindings_fail_closed() {
        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let journal = XmssUsageJournal::provision(&path, [&expected_binding])
            .expect("journal provisioning must succeed");

        let mut mismatches = Vec::new();
        let mut profile = expected_binding.clone();
        profile.profile_id = [9; 32];
        mismatches.push(profile);
        let mut allocation = expected_binding.clone();
        allocation.allocation_version = allocation.allocation_version.saturating_add(1);
        mismatches.push(allocation);
        let mut genesis = expected_binding.clone();
        genesis.genesis_validators_root = [9; 32];
        mismatches.push(genesis);
        let mut public_key = expected_binding.clone();
        public_key.public_key = [9; 32];
        mismatches.push(public_key);
        let mut range = expected_binding.clone();
        range.last_leaf = range.last_leaf.saturating_sub(1);
        mismatches.push(range);

        for mismatch in mismatches {
            assert!(matches!(
                journal.validate_binding(&mismatch),
                Err(XmssJournalError::BindingMismatch) | Err(XmssJournalError::UnknownKey)
            ));
        }
    }

    #[test]
    fn open_validates_active_bindings_but_allows_historical_keys() {
        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let historical_binding = XmssKeyBinding::lean_pq_devnet_v1(
            [8; 32],
            [3; 32],
            leaf(0, SigningDuty::RandaoReveal)..=leaf(1, SigningDuty::BeaconBlockProposal),
        )
        .expect("historical binding must be valid");
        drop(
            XmssUsageJournal::provision(&path, [&expected_binding, &historical_binding])
                .expect("journal provisioning must succeed"),
        );

        drop(
            XmssUsageJournal::open(&path, [&expected_binding])
                .expect("extra historical keys must be retained and accepted"),
        );
        let mut changed_genesis = expected_binding.clone();
        changed_genesis.genesis_validators_root = [9; 32];
        assert!(matches!(
            XmssUsageJournal::open(&path, [&changed_genesis]),
            Err(XmssJournalError::BindingMismatch)
        ));
        let absent_binding = XmssKeyBinding::lean_pq_devnet_v1(
            [7; 32],
            [3; 32],
            leaf(0, SigningDuty::RandaoReveal)..=leaf(1, SigningDuty::BeaconBlockProposal),
        )
        .expect("absent binding must be valid");
        assert!(matches!(
            XmssUsageJournal::open(&path, [&absent_binding]),
            Err(XmssJournalError::UnknownKey)
        ));
    }

    #[test]
    fn open_refuses_missing_lock_and_non_delete_journal_without_repair() {
        let dir = tempdir().expect("temporary directory must be created");
        let missing_lock_path = dir.path().join("missing-lock.sqlite");
        let expected_binding = binding();
        drop(
            XmssUsageJournal::provision(&missing_lock_path, [&expected_binding])
                .expect("journal provisioning must succeed"),
        );
        let persistent_lock_path = lockfile_path(&missing_lock_path);
        std::fs::remove_file(&persistent_lock_path).expect("test lockfile must be removable");
        assert!(matches!(
            XmssUsageJournal::open(&missing_lock_path, [&expected_binding]),
            Err(XmssJournalError::MissingLockfile(_))
        ));
        assert!(
            !persistent_lock_path.exists(),
            "normal open must not recreate the lockfile"
        );

        let wal_path = dir.path().join("wal.sqlite");
        drop(
            XmssUsageJournal::provision(&wal_path, [&expected_binding])
                .expect("journal provisioning must succeed"),
        );
        let connection = Connection::open(&wal_path).expect("test database must open");
        let mode: String = connection
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
            .expect("test must switch journal mode");
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        drop(connection);
        assert!(matches!(
            XmssUsageJournal::open(&wal_path, [&expected_binding]),
            Err(XmssJournalError::WrongJournalMode)
        ));
        let connection = Connection::open(&wal_path).expect("test database must reopen");
        let mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal mode must remain readable");
        assert_eq!(
            mode.to_ascii_lowercase(),
            "wal",
            "failed normal open must not silently convert the database"
        );
    }

    #[test]
    fn corrupt_truncated_and_wrong_version_journals_fail_without_recreation() {
        fn assert_failed_open_preserves_bytes(
            path: &Path,
            expected_binding: &XmssKeyBinding,
            expected_error: impl FnOnce(&XmssJournalError) -> bool,
        ) {
            let before = std::fs::read(path).expect("test journal must be readable");
            let error = XmssUsageJournal::open(path, [expected_binding])
                .err()
                .expect("invalid journal must fail to open");
            assert!(expected_error(&error), "unexpected open error: {error}");
            let after = std::fs::read(path).expect("failed open must not remove the journal");
            assert_eq!(before, after, "failed open must not recreate the journal");
        }

        let dir = tempdir().expect("temporary directory must be created");
        let expected_binding = binding();

        let corrupt_path = dir.path().join("corrupt.sqlite");
        std::fs::write(&corrupt_path, b"not a sqlite database")
            .expect("corrupt fixture must be written");
        let corrupt_lock_path = lockfile_path(&corrupt_path);
        std::fs::write(&corrupt_lock_path, b"").expect("persistent lock fixture must be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&corrupt_path, std::fs::Permissions::from_mode(0o600))
                .expect("corrupt fixture permissions must be restrictive");
            std::fs::set_permissions(&corrupt_lock_path, std::fs::Permissions::from_mode(0o600))
                .expect("corrupt lock permissions must be restrictive");
        }
        assert_failed_open_preserves_bytes(&corrupt_path, &expected_binding, |error| {
            matches!(error, XmssJournalError::Database(_))
        });

        let truncated_path = dir.path().join("truncated.sqlite");
        drop(
            XmssUsageJournal::provision(&truncated_path, [&expected_binding])
                .expect("journal provisioning must succeed"),
        );
        OpenOptions::new()
            .write(true)
            .open(&truncated_path)
            .and_then(|file| file.set_len(16))
            .expect("test journal must truncate");
        assert_failed_open_preserves_bytes(&truncated_path, &expected_binding, |error| {
            matches!(
                error,
                XmssJournalError::Database(_) | XmssJournalError::WrongApplicationId(_)
            )
        });

        for (name, pragma, value) in [
            (
                "application",
                "application_id",
                APPLICATION_ID.saturating_add(1),
            ),
            ("schema", "user_version", SCHEMA_VERSION.saturating_add(1)),
        ] {
            let path = dir.path().join(format!("wrong-{name}.sqlite"));
            drop(
                XmssUsageJournal::provision(&path, [&expected_binding])
                    .expect("journal provisioning must succeed"),
            );
            let connection = Connection::open(&path).expect("test database must open");
            connection
                .pragma_update(None, pragma, value)
                .expect("test version must be changed");
            drop(connection);
            assert_failed_open_preserves_bytes(&path, &expected_binding, |error| match pragma {
                "application_id" => matches!(error, XmssJournalError::WrongApplicationId(_)),
                _ => matches!(error, XmssJournalError::WrongSchemaVersion(_)),
            });
        }
    }

    #[test]
    fn database_failures_retain_a_local_diagnostic() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        std::fs::write(&path, b"not sqlite").expect("corrupt fixture must be written");
        std::fs::write(lockfile_path(&path), b"").expect("lock fixture must be written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("corrupt fixture permissions must be restrictive");
        std::fs::set_permissions(lockfile_path(&path), std::fs::Permissions::from_mode(0o600))
            .expect("lock fixture permissions must be restrictive");

        let error = XmssUsageJournal::open(&path, [])
            .err()
            .expect("corrupt database must fail");
        match error {
            XmssJournalError::Database(diagnostic) => assert!(!diagnostic.is_empty()),
            unexpected => panic!("unexpected error: {unexpected}"),
        }
    }

    #[test]
    fn altered_schema_with_unchanged_versions_is_rejected() {
        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        drop(
            XmssUsageJournal::provision(&path, [&expected_binding])
                .expect("journal provisioning must succeed"),
        );
        let connection = Connection::open(&path).expect("test database must open");
        let schema: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name = 'xmss_keys'",
                [],
                |row| row.get(0),
            )
            .expect("key schema must exist");
        let weakened_schema = schema.replace(" CHECK(length(profile_id) = 32)", "");
        assert_ne!(
            weakened_schema, schema,
            "test must remove a real constraint"
        );
        connection
            .pragma_update(None, "writable_schema", true)
            .and_then(|()| {
                connection.execute(
                    "UPDATE sqlite_schema SET sql = ?1 WHERE name = 'xmss_keys'",
                    [weakened_schema],
                )
            })
            .and_then(|_| connection.pragma_update(None, "writable_schema", false))
            .expect("test schema must be altered");
        drop(connection);

        assert!(matches!(
            XmssUsageJournal::open(&path, [&expected_binding]),
            Err(XmssJournalError::SchemaMismatch)
        ));
    }

    #[test]
    fn unexpected_trigger_that_deletes_tombstones_is_rejected() {
        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        drop(
            XmssUsageJournal::provision(&path, [&expected_binding])
                .expect("journal provisioning must succeed"),
        );
        let connection = Connection::open(&path).expect("test database must open");
        connection
            .execute_batch(
                "CREATE TRIGGER erase_xmss_tombstone AFTER INSERT ON reservations
                 BEGIN
                   DELETE FROM reservations
                   WHERE stable_key_id = NEW.stable_key_id
                     AND one_time_use_id = NEW.one_time_use_id;
                 END;",
            )
            .expect("malicious trigger fixture must be installed");
        drop(connection);

        assert!(matches!(
            XmssUsageJournal::open(&path, [&expected_binding]),
            Err(XmssJournalError::SchemaMismatch)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn provisioning_permissions_and_key_file_are_unchanged() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let key_path = dir.path().join("validator-key.json");
        std::fs::write(&key_path, b"immutable-key-bytes").expect("test key must be written");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o640))
            .expect("test key permissions must be set");
        let key_bytes = std::fs::read(&key_path).expect("test key must be readable");
        let expected_binding = binding();

        let journal = XmssUsageJournal::provision(&path, [&expected_binding])
            .expect("journal provisioning must succeed");
        journal
            .reserve(
                &expected_binding,
                leaf(0, SigningDuty::Attestation),
                [4; 32],
            )
            .expect("reservation must succeed");

        assert_eq!(
            std::fs::metadata(&path)
                .expect("journal metadata must exist")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(lockfile_path(&path))
                .expect("lock metadata must exist")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read(&key_path).expect("test key must remain"),
            key_bytes
        );
        assert_eq!(
            std::fs::metadata(&key_path)
                .expect("key metadata must remain")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }

    #[test]
    #[cfg(unix)]
    fn normal_open_rejects_insecure_database_or_lock_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        drop(
            XmssUsageJournal::provision(&path, [&expected_binding])
                .expect("journal provisioning must succeed"),
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("database permissions must change");
        assert!(matches!(
            XmssUsageJournal::open(&path, [&expected_binding]),
            Err(XmssJournalError::InsecurePermissions(_))
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("database permissions must be restored");

        let lock_path = lockfile_path(&path);
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o666))
            .expect("lock permissions must change");
        assert!(matches!(
            XmssUsageJournal::open(&path, [&expected_binding]),
            Err(XmssJournalError::InsecurePermissions(_))
        ));
    }

    #[test]
    #[cfg(unix)]
    fn normal_open_rejects_a_database_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempdir().expect("temporary directory must be created");
        let real_path = dir.path().join("real.sqlite");
        let symlink_path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        drop(
            XmssUsageJournal::provision(&real_path, [&expected_binding])
                .expect("journal provisioning must succeed"),
        );
        symlink(&real_path, &symlink_path).expect("database symlink must be created");
        let symlink_lock_path = lockfile_path(&symlink_path);
        std::fs::write(&symlink_lock_path, b"").expect("symlink-path lock fixture must be created");
        std::fs::set_permissions(&symlink_lock_path, std::fs::Permissions::from_mode(0o600))
            .expect("lock fixture permissions must be restrictive");

        assert!(XmssUsageJournal::open(&symlink_path, [&expected_binding]).is_err());
    }

    #[test]
    fn normal_open_rejects_a_lockfile_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        drop(
            XmssUsageJournal::provision(&path, [&expected_binding])
                .expect("journal provisioning must succeed"),
        );
        let lock_path = lockfile_path(&path);
        std::fs::remove_file(&lock_path).expect("provisioned lock must be removable in test");
        let symlink_target = dir.path().join("attacker-controlled-lock");
        std::fs::write(&symlink_target, b"").expect("symlink target must be created");
        std::fs::set_permissions(&symlink_target, std::fs::Permissions::from_mode(0o600))
            .expect("symlink target permissions must be restrictive");
        symlink(&symlink_target, &lock_path).expect("lock symlink must be created");

        assert!(XmssUsageJournal::open(&path, [&expected_binding]).is_err());
    }

    #[test]
    fn reservation_is_permanent_idempotent_and_restart_safe() {
        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let one_time_use_id = leaf(0, SigningDuty::Attestation);
        let signing_root = [4; 32];
        let journal = XmssUsageJournal::provision(&path, [&expected_binding])
            .expect("journal provisioning must succeed");

        assert_eq!(
            journal.reserve(&expected_binding, one_time_use_id, signing_root),
            Ok(Reservation::Fresh)
        );
        assert_eq!(
            journal.reserve(&expected_binding, one_time_use_id, signing_root),
            Ok(Reservation::SameRoot)
        );
        assert_eq!(
            journal.reserve(&expected_binding, one_time_use_id, [5; 32]),
            Err(XmssJournalError::ConflictingRoot)
        );
        drop(journal);

        let reopened =
            XmssUsageJournal::open(&path, [&expected_binding]).expect("journal must reopen");
        assert_eq!(
            reopened.reserve(&expected_binding, one_time_use_id, signing_root),
            Ok(Reservation::SameRoot)
        );
        assert_eq!(
            reopened.reserve(&expected_binding, one_time_use_id, [5; 32]),
            Err(XmssJournalError::ConflictingRoot)
        );
    }

    #[test]
    fn reservation_revalidates_binding_and_inclusive_range() {
        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let journal = XmssUsageJournal::provision(&path, [&expected_binding])
            .expect("journal provisioning must succeed");
        let in_range = leaf(0, SigningDuty::Attestation);
        let first_leaf = leaf(0, SigningDuty::RandaoReveal);
        let last_leaf = leaf(1, SigningDuty::BeaconBlockProposal);
        let out_of_range = leaf(2, SigningDuty::RandaoReveal);

        let mut changed_profile = expected_binding.clone();
        changed_profile.profile_id = [9; 32];
        let mut changed_allocation = expected_binding.clone();
        changed_allocation.allocation_version = 2;
        let mut changed_genesis = expected_binding.clone();
        changed_genesis.genesis_validators_root = [9; 32];
        let mut aliased_key_id = expected_binding.clone();
        aliased_key_id.stable_key_id = [9; 32];

        for mismatch in [
            changed_profile,
            changed_allocation,
            changed_genesis,
            aliased_key_id,
        ] {
            assert!(matches!(
                journal.reserve(&mismatch, in_range, [4; 32]),
                Err(XmssJournalError::BindingMismatch) | Err(XmssJournalError::UnknownKey)
            ));
        }
        assert_eq!(
            journal.reserve(&expected_binding, out_of_range, [4; 32]),
            Err(XmssJournalError::LeafOutsideBoundRange)
        );
        assert_eq!(
            journal.reserve(&expected_binding, first_leaf, [5; 32]),
            Ok(Reservation::Fresh)
        );
        assert_eq!(
            journal.reserve(&expected_binding, last_leaf, [6; 32]),
            Ok(Reservation::Fresh)
        );

        let maximum_v1_leaf = OneTimeUseId::for_lean_pq_devnet_v1(
            consensus_signature::LEAN_PQ_DEVNET_V1_MAX_SLOT,
            SigningDuty::sync_contribution_and_proof(3)
                .expect("last V1 duty must be constructible"),
        )
        .expect("maximum complete V1 leaf must be constructible");
        let maximum_binding =
            XmssKeyBinding::lean_pq_devnet_v1([8; 32], [3; 32], first_leaf..=maximum_v1_leaf)
                .expect("maximum V1 range binding must be valid");
        let maximum_path = dir.path().join("maximum.sqlite");
        drop(
            XmssUsageJournal::provision(&maximum_path, [&maximum_binding])
                .expect("maximum range must provision"),
        );
        let maximum_journal = XmssUsageJournal::open(&maximum_path, [&maximum_binding])
            .expect("maximum range must reopen");
        assert_eq!(
            maximum_journal.reserve(&maximum_binding, maximum_v1_leaf, [7; 32]),
            Ok(Reservation::Fresh)
        );
    }

    #[test]
    fn conflicting_concurrent_reservations_have_one_winner() {
        use std::sync::{Arc, Barrier};

        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let journal = Arc::new(
            XmssUsageJournal::provision(&path, [&expected_binding])
                .expect("journal provisioning must succeed"),
        );
        let one_time_use_id = leaf(0, SigningDuty::Attestation);
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for signing_root in [[4; 32], [5; 32]] {
            let journal = journal.clone();
            let binding = expected_binding.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                journal.reserve(&binding, one_time_use_id, signing_root)
            }));
        }
        barrier.wait();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().expect("reservation thread must not panic"))
            .collect::<Vec<_>>();

        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Ok(Reservation::Fresh))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(XmssJournalError::ConflictingRoot))
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_same_root_reservations_are_idempotent() {
        use std::sync::{Arc, Barrier};

        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let journal = Arc::new(
            XmssUsageJournal::provision(&path, [&expected_binding])
                .expect("journal provisioning must succeed"),
        );
        let one_time_use_id = leaf(0, SigningDuty::Attestation);
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let journal = journal.clone();
            let binding = expected_binding.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                journal.reserve(&binding, one_time_use_id, [4; 32])
            }));
        }
        barrier.wait();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().expect("reservation thread must not panic"))
            .collect::<Vec<_>>();

        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Ok(Reservation::Fresh))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Ok(Reservation::SameRoot))
                .count(),
            1
        );
    }

    #[test]
    fn subprocess_lock_and_crash_recovery_are_fail_closed() {
        fn run_helper(path: &Path, mode: &str, marker: Option<&Path>) -> std::process::ExitStatus {
            let mut command = std::process::Command::new(
                std::env::current_exe().expect("current test executable must be available"),
            );
            command
                .arg("--exact")
                .arg("authority::journal::tests::xmss_journal_subprocess_helper")
                .arg("--nocapture")
                .env(SUBPROCESS_DATABASE_ENV, path)
                .env(SUBPROCESS_MODE_ENV, mode);
            if let Some(marker) = marker {
                command.env(SUBPROCESS_MARKER_ENV, marker);
            }
            command
                .status()
                .expect("journal test subprocess must start")
        }

        let locked_dir = tempdir().expect("temporary directory must be created");
        let locked_path = locked_dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let locked_journal = XmssUsageJournal::provision(&locked_path, [&expected_binding])
            .expect("journal provisioning must succeed");
        assert!(run_helper(&locked_path, "expect-locked", None).success());
        drop(locked_journal);

        let post_commit_dir = tempdir().expect("temporary directory must be created");
        let post_commit_path = post_commit_dir.path().join(XMSS_USAGE_FILENAME);
        drop(
            XmssUsageJournal::provision(&post_commit_path, [&expected_binding])
                .expect("journal provisioning must succeed"),
        );
        assert!(!run_helper(&post_commit_path, "abort-after-commit", None).success());
        let journal = XmssUsageJournal::open(&post_commit_path, [&expected_binding])
            .expect("journal must recover after callback crash");
        let callback_leaf = leaf(0, SigningDuty::Attestation);
        assert_eq!(
            journal.reserve(&expected_binding, callback_leaf, [5; 32]),
            Err(XmssJournalError::ConflictingRoot)
        );
        assert_eq!(
            journal.reserve(&expected_binding, callback_leaf, [4; 32]),
            Ok(Reservation::SameRoot)
        );
        drop(journal);

        let pre_commit_dir = tempdir().expect("temporary directory must be created");
        let pre_commit_path = pre_commit_dir.path().join(XMSS_USAGE_FILENAME);
        drop(
            XmssUsageJournal::provision(&pre_commit_path, [&expected_binding])
                .expect("journal provisioning must succeed"),
        );
        let pre_commit_marker = pre_commit_dir.path().join("insert-reached.marker");
        assert!(
            !run_helper(
                &pre_commit_path,
                "abort-before-commit",
                Some(&pre_commit_marker),
            )
            .success()
        );
        assert!(
            pre_commit_marker.exists(),
            "child must prove it reached the hook after INSERT and before commit"
        );
        let journal = XmssUsageJournal::open(&pre_commit_path, [&expected_binding])
            .expect("journal must recover its rollback journal after transaction crash");
        assert_eq!(
            journal.reserve(
                &expected_binding,
                leaf(0, SigningDuty::AttestationSelectionProof),
                [7; 32],
            ),
            Ok(Reservation::Fresh),
            "an uncommitted insertion must not survive process death"
        );
    }

    #[test]
    fn xmss_journal_subprocess_helper() {
        let Some(path) = std::env::var_os(SUBPROCESS_DATABASE_ENV).map(PathBuf::from) else {
            return;
        };
        let mode = std::env::var(SUBPROCESS_MODE_ENV).expect("subprocess mode must be present");
        let expected_binding = binding();
        match mode.as_str() {
            "expect-locked" => assert!(matches!(
                XmssUsageJournal::open(&path, [&expected_binding]),
                Err(XmssJournalError::JournalLocked(_))
            )),
            "abort-after-commit" => {
                let journal = XmssUsageJournal::open(&path, [&expected_binding])
                    .expect("subprocess journal must open");
                let _ = journal.reserve_and_then(
                    &expected_binding,
                    leaf(0, SigningDuty::Attestation),
                    [4; 32],
                    |_| -> Result<(), ()> { std::process::abort() },
                );
            }
            "abort-before-commit" => {
                use std::io::Write;

                let journal = XmssUsageJournal::open(&path, [&expected_binding])
                    .expect("subprocess journal must open");
                let marker = PathBuf::from(
                    std::env::var_os(SUBPROCESS_MARKER_ENV)
                        .expect("pre-commit subprocess marker must be present"),
                );
                let _ = journal.reserve_and_then_with_commit_hook(
                    &expected_binding,
                    leaf(0, SigningDuty::AttestationSelectionProof),
                    [6; 32],
                    || -> Result<(), XmssJournalError> {
                        let mut marker_file = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&marker)
                            .expect("pre-commit marker must be created");
                        marker_file
                            .write_all(b"insert reached")
                            .and_then(|()| marker_file.sync_all())
                            .expect("pre-commit marker must be durable");
                        std::process::abort()
                    },
                    |_| Ok::<_, ()>(()),
                );
            }
            unexpected => panic!("unexpected subprocess mode: {unexpected}"),
        }
    }

    #[test]
    fn callback_runs_only_after_commit_and_can_reenter_journal() {
        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let journal = XmssUsageJournal::provision(&path, [&expected_binding])
            .expect("journal provisioning must succeed");
        let one_time_use_id = leaf(0, SigningDuty::Attestation);
        let signing_root = [4; 32];

        let result = journal.reserve_and_then(
            &expected_binding,
            one_time_use_id,
            signing_root,
            |reservation| {
                assert_eq!(reservation, Reservation::Fresh);
                assert_eq!(
                    journal.reserve(&expected_binding, one_time_use_id, signing_root),
                    Ok(Reservation::SameRoot),
                    "callback reentry proves the DB mutex and transaction were released"
                );
                Ok::<_, &'static str>("signed")
            },
        );

        assert_eq!(result, Ok("signed"));
    }

    #[test]
    fn pre_commit_failure_rolls_back_and_never_invokes_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let journal = XmssUsageJournal::provision(&path, [&expected_binding])
            .expect("journal provisioning must succeed");
        let one_time_use_id = leaf(0, SigningDuty::Attestation);
        let callback_called = AtomicBool::new(false);

        let result = journal.reserve_and_then_with_commit_hook(
            &expected_binding,
            one_time_use_id,
            [4; 32],
            || Err(database_invariant("injected pre-commit failure")),
            |_| {
                callback_called.store(true, Ordering::SeqCst);
                Ok::<_, ()>(())
            },
        );

        assert!(matches!(result, Err(ReserveAndThenError::Journal(_))));
        assert!(!callback_called.load(Ordering::SeqCst));
        assert_eq!(
            journal.reserve(&expected_binding, one_time_use_id, [5; 32]),
            Ok(Reservation::Fresh),
            "the inserted row must roll back when commit is not reached"
        );
    }

    #[test]
    fn post_commit_callback_failure_or_panic_burns_the_leaf() {
        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let journal = XmssUsageJournal::provision(&path, [&expected_binding])
            .expect("journal provisioning must succeed");
        let failed_leaf = leaf(0, SigningDuty::Attestation);
        let panicked_leaf = leaf(0, SigningDuty::AttestationSelectionProof);

        assert_eq!(
            journal.reserve_and_then(&expected_binding, failed_leaf, [4; 32], |_| {
                Err::<(), _>("signing failed")
            }),
            Err(ReserveAndThenError::Callback("signing failed"))
        );
        assert_eq!(
            journal.reserve(&expected_binding, failed_leaf, [5; 32]),
            Err(XmssJournalError::ConflictingRoot)
        );
        assert_eq!(
            journal.reserve(&expected_binding, failed_leaf, [4; 32]),
            Ok(Reservation::SameRoot)
        );

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = journal.reserve_and_then(
                &expected_binding,
                panicked_leaf,
                [6; 32],
                |_| -> Result<(), ()> { panic!("injected signer panic") },
            );
        }));
        assert!(panic.is_err());
        assert_eq!(
            journal.reserve(&expected_binding, panicked_leaf, [7; 32]),
            Err(XmssJournalError::ConflictingRoot)
        );
        assert_eq!(
            journal.reserve(&expected_binding, panicked_leaf, [6; 32]),
            Ok(Reservation::SameRoot)
        );
    }

    #[test]
    fn conflicting_root_never_invokes_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempdir().expect("temporary directory must be created");
        let path = dir.path().join(XMSS_USAGE_FILENAME);
        let expected_binding = binding();
        let journal = XmssUsageJournal::provision(&path, [&expected_binding])
            .expect("journal provisioning must succeed");
        let one_time_use_id = leaf(0, SigningDuty::Attestation);
        journal
            .reserve(&expected_binding, one_time_use_id, [4; 32])
            .expect("initial reservation must succeed");
        let callback_called = AtomicBool::new(false);

        let result = journal.reserve_and_then(&expected_binding, one_time_use_id, [5; 32], |_| {
            callback_called.store(true, Ordering::SeqCst);
            Ok::<_, ()>(())
        });

        assert!(matches!(
            result,
            Err(ReserveAndThenError::Journal(
                XmssJournalError::ConflictingRoot
            ))
        ));
        assert!(!callback_called.load(Ordering::SeqCst));
    }
}
