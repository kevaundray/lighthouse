mod journal;
pub(super) mod keystore;

use consensus_signature::pq::{PqSigningClaim, PqWireError};
use consensus_signature::{PqPublicKey, PqRawSignature};
use journal::{XmssJournalError, XmssKeyBinding, XmssUsageJournal};
use keystore::{AuthenticatedPqKeyMetadata, PqKeystore, PqKeystoreError, validate_pq_password};
use lean_multisig::SecretKey;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::{fs::File, os::fd::AsRawFd};
use zeroize::Zeroizing;

pub use journal::{XMSS_USAGE_FILENAME, XmssJournalError as PqUsageJournalError};

const UPSTREAM_MAGIC: &[u8; 4] = b"LMSI";
const UPSTREAM_VERSION: u8 = 1;
const UPSTREAM_RAW_KIND: u8 = 0;
const UPSTREAM_HEADER_LEN: usize = 6;
const LIGHTHOUSE_RAW_HEADER: &[u8; 7] = b"LHPQ\x01\x01\x00";

#[derive(Debug)]
pub enum PqSigningError {
    Keystore(PqKeystoreError),
    Journal(XmssJournalError),
    DuplicatePublicKey,
    UnknownPublicKey,
    InvalidSigningRequest,
    MalformedBackendSignature,
    BackendPanicked,
    SignerPoisoned,
    Wire(PqWireError),
    Backend(String),
}

impl std::fmt::Display for PqSigningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keystore(error) => write!(formatter, "PQ keystore failed: {error}"),
            Self::Journal(error) => write!(formatter, "PQ usage journal failed: {error}"),
            Self::DuplicatePublicKey => formatter.write_str("duplicate PQ public key"),
            Self::UnknownPublicKey => formatter.write_str("unknown PQ public key"),
            Self::InvalidSigningRequest => {
                formatter.write_str("PQ claim is outside the bound one-time-use range")
            }
            Self::MalformedBackendSignature => {
                formatter.write_str("PQ backend returned a malformed raw signature")
            }
            Self::BackendPanicked => formatter.write_str("PQ backend panicked while signing"),
            Self::SignerPoisoned => {
                formatter.write_str("PQ signer is poisoned after a backend panic")
            }
            Self::Wire(error) => write!(formatter, "invalid PQ raw signature envelope: {error}"),
            Self::Backend(error) => write!(formatter, "PQ backend signing failed: {error}"),
        }
    }
}

impl std::error::Error for PqSigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Keystore(error) => Some(error),
            Self::Journal(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::DuplicatePublicKey
            | Self::UnknownPublicKey
            | Self::InvalidSigningRequest
            | Self::MalformedBackendSignature
            | Self::BackendPanicked
            | Self::SignerPoisoned
            | Self::Backend(_) => None,
        }
    }
}

impl From<PqKeystoreError> for PqSigningError {
    fn from(error: PqKeystoreError) -> Self {
        Self::Keystore(error)
    }
}

impl From<XmssJournalError> for PqSigningError {
    fn from(error: XmssJournalError) -> Self {
        Self::Journal(error)
    }
}

/// An encrypted keystore and its password, consumed by authority startup.
///
/// Authentication is deliberately unavailable outside `PqSigningAuthority`, so bundle loading
/// cannot run the KDF before the authority has locked and validated its journal.
///
/// ```compile_fail
/// use pq_signing::PqKeyUnlock;
/// let _ = PqKeyUnlock::authenticate;
/// ```
pub struct PqKeyUnlock {
    keystore: PqKeystore,
    password: Zeroizing<Vec<u8>>,
}

impl PqKeyUnlock {
    pub fn new(keystore: PqKeystore, password: &[u8]) -> Result<Self, PqSigningError> {
        keystore.validate_metadata()?;
        validate_pq_password(password)?;
        Ok(Self {
            keystore,
            password: Zeroizing::new(password.to_vec()),
        })
    }

    /// Returns the bounded outer range after cheap profile/metadata validation.
    /// The authority authenticates this range against the derived key after opening the journal.
    pub fn one_time_use_range(&self) -> std::ops::RangeInclusive<u32> {
        self.keystore.one_time_use_range()
    }
}

/// Creates and durably initializes the journal for authenticated keys.
///
/// # Blocking
///
/// This performs synchronous SQLite and filesystem I/O, including durability barriers. It must
/// not run directly on a Tokio async worker. Validator-client code must dispatch the complete call
/// through Lighthouse's scoped blocking executor.
pub fn provision_usage_journal(
    path: &Path,
    genesis_validators_root: [u8; 32],
    metadata: &[AuthenticatedPqKeyMetadata],
) -> Result<(), PqSigningError> {
    let bindings = bindings_from_authenticated_metadata(genesis_validators_root, metadata)?;
    XmssUsageJournal::provision(path, &bindings)?.validate_all(&bindings)?;
    Ok(())
}

/// Opens and fully validates an existing journal without exposing a reservation handle.
///
/// # Blocking
///
/// This performs synchronous SQLite and filesystem I/O. It must not run directly on a Tokio async
/// worker. Validator-client code must dispatch the complete call through Lighthouse's scoped
/// blocking executor.
pub fn validate_usage_journal(
    path: &Path,
    genesis_validators_root: [u8; 32],
    metadata: &[AuthenticatedPqKeyMetadata],
) -> Result<(), PqSigningError> {
    let bindings = bindings_from_authenticated_metadata(genesis_validators_root, metadata)?;
    let journal = XmssUsageJournal::open(path, &bindings)?;
    journal.validate_all(&bindings)?;
    Ok(())
}

/// Creates and validates the journal relative to a held Linux directory descriptor.
///
/// The descriptor anchor prevents a concurrent parent-path replacement from redirecting journal
/// creation. This remains a non-signing facade and exposes no reservation handle.
#[cfg(target_os = "linux")]
pub fn provision_usage_journal_anchored(
    directory: &File,
    genesis_validators_root: [u8; 32],
    metadata: &[AuthenticatedPqKeyMetadata],
) -> Result<(), PqSigningError> {
    validate_anchor(directory)?;
    let path = anchored_journal_path(directory);
    let bindings = bindings_from_authenticated_metadata(genesis_validators_root, metadata)?;
    XmssUsageJournal::provision_anchored(&path, &bindings)?
        .validate_fresh_provisioning(&bindings)?;
    Ok(())
}

/// Validates the journal relative to a held Linux directory descriptor.
#[cfg(target_os = "linux")]
pub fn validate_usage_journal_anchored(
    directory: &File,
    genesis_validators_root: [u8; 32],
    metadata: &[AuthenticatedPqKeyMetadata],
) -> Result<(), PqSigningError> {
    validate_anchor(directory)?;
    let path = anchored_journal_path(directory);
    let bindings = bindings_from_authenticated_metadata(genesis_validators_root, metadata)?;
    XmssUsageJournal::open_anchored(&path, &bindings)?.validate_fresh_provisioning(&bindings)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn anchored_journal_path(directory: &File) -> std::path::PathBuf {
    std::path::PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        directory.as_raw_fd(),
        XMSS_USAGE_FILENAME
    ))
}

#[cfg(target_os = "linux")]
fn validate_anchor(directory: &File) -> Result<(), PqSigningError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = directory.metadata().map_err(|error| {
        PqSigningError::Journal(XmssJournalError::Filesystem(
            std::path::PathBuf::from("<directory-fd>"),
            error.to_string(),
        ))
    })?;
    if metadata.is_dir() && metadata.permissions().mode() & 0o777 == 0o700 {
        Ok(())
    } else {
        Err(PqSigningError::Journal(
            XmssJournalError::InsecurePermissions(std::path::PathBuf::from("<directory-fd>")),
        ))
    }
}

fn bindings_from_authenticated_metadata(
    genesis_validators_root: [u8; 32],
    metadata: &[AuthenticatedPqKeyMetadata],
) -> Result<Vec<XmssKeyBinding>, PqSigningError> {
    let mut public_keys = HashSet::with_capacity(metadata.len());
    metadata
        .iter()
        .map(|metadata| {
            let public_key = metadata.public_key().serialize();
            if !public_keys.insert(public_key) {
                return Err(PqSigningError::DuplicatePublicKey);
            }
            XmssKeyBinding::from_raw_range(
                public_key,
                genesis_validators_root,
                metadata.one_time_use_range(),
            )
            .map_err(PqSigningError::from)
        })
        .collect()
}

pub struct PqSigningAuthority {
    inner: Arc<AuthorityInner>,
}

struct AuthorityInner {
    // Per-key lock order:
    // 1. `operation_gate` serializes poison check through backend completion.
    // 2. The journal connection mutex is acquired and released while the gate remains held.
    // 3. Only after journal commit releases its connection mutex is `key` acquired.
    // The journal connection and live-key mutexes are therefore never held together.
    journal: XmssUsageJournal,
    keys: Vec<SigningKey>,
    public_keys: Vec<PqPublicKey>,
}

struct SigningKey {
    binding: XmssKeyBinding,
    range: std::ops::RangeInclusive<u32>,
    operation_gate: Mutex<KeyOperationState>,
    key: Mutex<SecretKey>,
    #[cfg(test)]
    panic_on_next_backend_sign: AtomicBool,
}

#[derive(Default)]
struct KeyOperationState {
    poisoned: bool,
}

impl PqSigningAuthority {
    /// Opens the blocking signing authority and sequentially decrypts all configured keys.
    ///
    /// # Blocking
    ///
    /// This acquires the persistent journal lock, performs synchronous SQLite/file I/O, and runs
    /// the password KDF for each key sequentially. It must not run directly on a Tokio async worker.
    /// Future validator-client code must dispatch the complete call through Lighthouse's scoped
    /// blocking executor.
    pub fn open(
        journal_path: &Path,
        genesis_validators_root: [u8; 32],
        unlocks: Vec<PqKeyUnlock>,
    ) -> Result<Self, PqSigningError> {
        Self::open_with_journal(genesis_validators_root, unlocks, |bindings| {
            XmssUsageJournal::open(journal_path, bindings)
        })
    }

    /// Opens the authority journal relative to one already-validated bundle directory handle.
    #[cfg(target_os = "linux")]
    pub fn open_anchored(
        directory: &File,
        genesis_validators_root: [u8; 32],
        unlocks: Vec<PqKeyUnlock>,
    ) -> Result<Self, PqSigningError> {
        validate_anchor(directory)?;
        let journal_path = anchored_journal_path(directory);
        Self::open_with_journal(genesis_validators_root, unlocks, |bindings| {
            XmssUsageJournal::open_anchored(&journal_path, bindings)
        })
    }

    fn open_with_journal(
        genesis_validators_root: [u8; 32],
        unlocks: Vec<PqKeyUnlock>,
        open_journal: impl FnOnce(&[XmssKeyBinding]) -> Result<XmssUsageJournal, XmssJournalError>,
    ) -> Result<Self, PqSigningError> {
        let mut seen = HashSet::with_capacity(unlocks.len());
        let mut public_keys = Vec::with_capacity(unlocks.len());
        let mut ranges = Vec::with_capacity(unlocks.len());
        let mut bindings = Vec::with_capacity(unlocks.len());

        // Validate public metadata, duplicates, and the existing journal before any expensive KDF.
        for unlock in &unlocks {
            unlock.keystore.validate_metadata()?;
            let public_key_bytes = *unlock.keystore.public_key();
            if !seen.insert(public_key_bytes) {
                return Err(PqSigningError::DuplicatePublicKey);
            }
            let range = unlock.keystore.one_time_use_range();
            bindings.push(XmssKeyBinding::from_raw_range(
                public_key_bytes,
                genesis_validators_root,
                range.clone(),
            )?);
            public_keys
                .push(PqPublicKey::deserialize(&public_key_bytes).map_err(PqSigningError::Wire)?);
            ranges.push(range);
        }
        let journal = open_journal(&bindings)?;

        let mut keys = Vec::with_capacity(unlocks.len());
        for ((unlock, binding), range) in unlocks.into_iter().zip(bindings).zip(ranges) {
            let key = unlock.keystore.decrypt_secret_key(&unlock.password)?;
            keys.push(SigningKey {
                binding,
                range,
                operation_gate: Mutex::new(KeyOperationState::default()),
                key: Mutex::new(key),
                #[cfg(test)]
                panic_on_next_backend_sign: AtomicBool::new(false),
            });
        }

        Ok(Self {
            inner: Arc::new(AuthorityInner {
                journal,
                keys,
                public_keys,
            }),
        })
    }

    pub fn public_keys(&self) -> &[PqPublicKey] {
        &self.inner.public_keys
    }

    pub fn signer(&self, public_key: &PqPublicKey) -> Result<PqSigner, PqSigningError> {
        let key_index = self
            .inner
            .public_keys
            .iter()
            .position(|candidate| candidate == public_key)
            .ok_or(PqSigningError::UnknownPublicKey)?;
        Ok(PqSigner {
            inner: Arc::clone(&self.inner),
            key_index,
        })
    }
}

#[derive(Clone)]
pub struct PqSigner {
    inner: Arc<AuthorityInner>,
    key_index: usize,
}

impl PqSigner {
    /// Durably burns the leaf before invoking the blocking upstream signer.
    ///
    /// # Blocking
    ///
    /// This synchronously commits the journal reservation and runs the PQ backend. It must not run
    /// directly on a Tokio async worker. Future validator-client code must dispatch this complete
    /// method through Lighthouse's scoped blocking executor so reservation and signing cannot be
    /// separated.
    pub fn sign(&self, claim: PqSigningClaim) -> Result<PqRawSignature, PqSigningError> {
        self.sign_with_return_hook_impl(claim, |_| {})
    }

    #[cfg(test)]
    fn inject_backend_panic_once(&self) {
        if let Some(signing_key) = self.inner.keys.get(self.key_index) {
            signing_key
                .panic_on_next_backend_sign
                .store(true, Ordering::SeqCst);
        }
    }

    #[cfg(test)]
    fn sign_with_return_hook(
        &self,
        claim: PqSigningClaim,
        before_return: impl FnOnce(&PqRawSignature),
    ) -> Result<PqRawSignature, PqSigningError> {
        self.sign_with_return_hook_impl(claim, before_return)
    }

    fn sign_with_return_hook_impl(
        &self,
        claim: PqSigningClaim,
        before_return: impl FnOnce(&PqRawSignature),
    ) -> Result<PqRawSignature, PqSigningError> {
        let signing_key = self
            .inner
            .keys
            .get(self.key_index)
            .ok_or(PqSigningError::UnknownPublicKey)?;
        let mut operation_state = signing_key.operation_gate.lock();
        if operation_state.poisoned {
            return Err(PqSigningError::SignerPoisoned);
        }
        if !signing_key
            .range
            .contains(&claim.one_time_use_id().as_u32())
        {
            return Err(PqSigningError::InvalidSigningRequest);
        }

        self.inner.journal.reserve(
            &signing_key.binding,
            claim.one_time_use_id(),
            *claim.signing_root(),
        )?;

        let backend_result = catch_unwind(AssertUnwindSafe(|| {
            let key = signing_key.key.lock();
            #[cfg(test)]
            if signing_key
                .panic_on_next_backend_sign
                .swap(false, Ordering::SeqCst)
            {
                panic!("injected PQ backend panic");
            }
            let backend_claim =
                lean_multisig::Claim::new(*claim.signing_root(), claim.one_time_use_id().as_u32());
            let signature = key
                .sign(&backend_claim)
                .map_err(|error| PqSigningError::Backend(error.to_string()))?;
            raw_signature_from_backend(&signature)
        }));
        let signature = match backend_result {
            Ok(result) => result?,
            Err(_) => {
                operation_state.poisoned = true;
                return Err(PqSigningError::BackendPanicked);
            }
        };
        drop(operation_state);
        before_return(&signature);
        Ok(signature)
    }
}

#[cfg(test)]
fn sign_after_reservation<T>(
    journal: &XmssUsageJournal,
    binding: &XmssKeyBinding,
    claim: &PqSigningClaim,
    sign: impl FnOnce() -> Result<T, PqSigningError>,
) -> Result<T, PqSigningError> {
    journal.reserve(binding, claim.one_time_use_id(), *claim.signing_root())?;
    sign()
}

#[cfg(test)]
fn sign_after_reservation_with_return_hook<T>(
    journal: &XmssUsageJournal,
    binding: &XmssKeyBinding,
    claim: &PqSigningClaim,
    sign: impl FnOnce() -> Result<T, PqSigningError>,
    before_return: impl FnOnce(&T),
) -> Result<T, PqSigningError> {
    journal.reserve(binding, claim.one_time_use_id(), *claim.signing_root())?;
    let result = sign()?;
    before_return(&result);
    Ok(result)
}

fn raw_signature_from_backend(
    signature: &lean_multisig::Signature,
) -> Result<PqRawSignature, PqSigningError> {
    let upstream = signature.to_bytes();
    if upstream.len() <= UPSTREAM_HEADER_LEN
        || upstream.get(..UPSTREAM_MAGIC.len()) != Some(UPSTREAM_MAGIC)
        || upstream.get(UPSTREAM_MAGIC.len()).copied() != Some(UPSTREAM_VERSION)
        || upstream.get(UPSTREAM_MAGIC.len() + 1).copied() != Some(UPSTREAM_RAW_KIND)
    {
        return Err(PqSigningError::MalformedBackendSignature);
    }
    let mut envelope = Vec::with_capacity(
        LIGHTHOUSE_RAW_HEADER
            .len()
            .saturating_add(upstream.len() - UPSTREAM_HEADER_LEN),
    );
    envelope.extend_from_slice(LIGHTHOUSE_RAW_HEADER);
    envelope.extend_from_slice(
        upstream
            .get(UPSTREAM_HEADER_LEN..)
            .ok_or(PqSigningError::MalformedBackendSignature)?,
    );
    PqRawSignature::from_bytes(&envelope).map_err(PqSigningError::Wire)
}

trait ValidateAllBindings {
    fn validate_all(&self, bindings: &[XmssKeyBinding]) -> Result<(), XmssJournalError>;
}

impl ValidateAllBindings for XmssUsageJournal {
    fn validate_all(&self, bindings: &[XmssKeyBinding]) -> Result<(), XmssJournalError> {
        for binding in bindings {
            self.validate_binding(binding)?;
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::journal::Reservation;
    use super::keystore::{reset_secret_key_decryptions, secret_key_decryptions};
    use super::*;
    use consensus_signature::{OneTimeUseId, SigningDuty};
    use fs2::FileExt;
    use std::fs::OpenOptions;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;

    const AUTHORITY_SUBPROCESS_DATABASE_ENV: &str = "LIGHTHOUSE_PQ_AUTHORITY_TEST_DATABASE";
    const AUTHORITY_SUBPROCESS_KEYSTORE_ENV: &str = "LIGHTHOUSE_PQ_AUTHORITY_TEST_KEYSTORE";
    const AUTHORITY_SUBPROCESS_MODE_ENV: &str = "LIGHTHOUSE_PQ_AUTHORITY_TEST_MODE";

    fn one_time_use_id(slot: u64, duty: SigningDuty) -> OneTimeUseId {
        OneTimeUseId::for_lean_pq_devnet_v1(slot, duty).expect("valid test signing ID")
    }

    fn fixture() -> (tempfile::TempDir, XmssUsageJournal, XmssKeyBinding) {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join(XMSS_USAGE_FILENAME);
        let binding =
            XmssKeyBinding::from_raw_range([2; 32], [3; 32], 0..=7).expect("valid binding");
        let journal = XmssUsageJournal::provision(&path, [&binding]).expect("journal");
        (directory, journal, binding)
    }

    fn pq_work_lock() -> std::fs::File {
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

    #[test]
    fn authority_locks_journal_before_one_authentication_per_key() {
        let _work_lock = pq_work_lock();
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join(XMSS_USAGE_FILENAME);
        let keystore = PqKeystore::from_seed([31; 32], 0..=7, b"password").expect("keystore");
        let binding = XmssKeyBinding::from_raw_range(
            *keystore.public_key(),
            [3; 32],
            keystore.one_time_use_range(),
        )
        .expect("binding");
        let owner = XmssUsageJournal::provision(&path, [&binding]).expect("journal owner");

        reset_secret_key_decryptions();
        let locked = PqSigningAuthority::open(
            &path,
            [3; 32],
            vec![PqKeyUnlock::new(keystore.clone(), b"wrong password").expect("unlock")],
        );
        assert!(matches!(
            locked,
            Err(PqSigningError::Journal(XmssJournalError::JournalLocked(_)))
        ));
        assert_eq!(
            secret_key_decryptions(),
            0,
            "locked journal must precede KDF"
        );

        drop(owner);
        reset_secret_key_decryptions();
        let authority = PqSigningAuthority::open(
            &path,
            [3; 32],
            vec![PqKeyUnlock::new(keystore, b"password").expect("unlock")],
        )
        .expect("authority");
        assert_eq!(authority.public_keys().len(), 1);
        assert_eq!(
            secret_key_decryptions(),
            1,
            "one successful key startup must authenticate exactly once"
        );
    }

    #[test]
    fn conflict_and_out_of_range_never_invoke_backend() {
        let (_directory, journal, binding) = fixture();
        let calls = AtomicUsize::new(0);
        let in_range = one_time_use_id(0, SigningDuty::Attestation);
        let first = PqSigningClaim::new([4; 32], in_range);
        sign_after_reservation(&journal, &binding, &first, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .expect("first reservation");

        let conflict = PqSigningClaim::new([5; 32], in_range);
        assert!(matches!(
            sign_after_reservation(&journal, &binding, &conflict, || {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }),
            Err(PqSigningError::Journal(XmssJournalError::ConflictingRoot))
        ));
        let out_of_range =
            PqSigningClaim::new([6; 32], one_time_use_id(1, SigningDuty::RandaoReveal));
        assert!(matches!(
            sign_after_reservation(&journal, &binding, &out_of_range, || {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }),
            Err(PqSigningError::Journal(
                XmssJournalError::LeafOutsideBoundRange
            ))
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn post_reservation_callback_failure_and_panic_burn_the_committed_leaf() {
        let (_directory, journal, binding) = fixture();
        let failed_id = one_time_use_id(0, SigningDuty::BeaconBlockProposal);
        let failed = PqSigningClaim::new([4; 32], failed_id);
        assert!(matches!(
            sign_after_reservation(&journal, &binding, &failed, || {
                Err::<(), _>(PqSigningError::Backend("injected".to_owned()))
            }),
            Err(PqSigningError::Backend(_))
        ));
        assert!(matches!(
            sign_after_reservation(
                &journal,
                &binding,
                &PqSigningClaim::new([5; 32], failed_id),
                || Ok(())
            ),
            Err(PqSigningError::Journal(XmssJournalError::ConflictingRoot))
        ));

        let panicked_id = one_time_use_id(0, SigningDuty::AttestationSelectionProof);
        let panicked = PqSigningClaim::new([6; 32], panicked_id);
        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            let _ = sign_after_reservation::<()>(&journal, &binding, &panicked, || {
                panic!("injected backend panic")
            });
        }));
        assert!(panic_result.is_err());
        assert!(matches!(
            sign_after_reservation(
                &journal,
                &binding,
                &PqSigningClaim::new([7; 32], panicked_id),
                || Ok(())
            ),
            Err(PqSigningError::Journal(XmssJournalError::ConflictingRoot))
        ));
    }

    #[test]
    fn public_sign_contains_backend_panic_and_poison_is_reset_only_by_restart() {
        let _work_lock = pq_work_lock();
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join(XMSS_USAGE_FILENAME);
        let password = b"password";
        let keystore = PqKeystore::from_seed([0x71; 32], 0..=7, password).expect("keystore");
        let restart_keystore = keystore.clone();
        let metadata = keystore.authenticate(password).expect("metadata");
        provision_usage_journal(&path, [3; 32], std::slice::from_ref(&metadata))
            .expect("provision journal");
        let authority = PqSigningAuthority::open(
            &path,
            [3; 32],
            vec![PqKeyUnlock::new(keystore, password).expect("unlock")],
        )
        .expect("authority");
        let signer = authority
            .signer(&authority.public_keys()[0])
            .expect("signer");
        signer.inject_backend_panic_once();

        let burned_id = one_time_use_id(0, SigningDuty::Attestation);
        let burned_claim = PqSigningClaim::new([4; 32], burned_id);
        let first = catch_unwind(AssertUnwindSafe(|| signer.sign(burned_claim)));
        assert!(matches!(first, Ok(Err(PqSigningError::BackendPanicked))));

        let unreserved_id = one_time_use_id(0, SigningDuty::AttestationSelectionProof);
        assert!(matches!(
            signer.sign(PqSigningClaim::new([5; 32], unreserved_id)),
            Err(PqSigningError::SignerPoisoned)
        ));
        drop(signer);
        drop(authority);

        let restarted = PqSigningAuthority::open(
            &path,
            [3; 32],
            vec![PqKeyUnlock::new(restart_keystore, password).expect("unlock")],
        )
        .expect("restart authority");
        let restarted_signer = restarted
            .signer(&restarted.public_keys()[0])
            .expect("restart signer");
        assert!(matches!(
            restarted_signer.sign(PqSigningClaim::new([6; 32], burned_id)),
            Err(PqSigningError::Journal(XmssJournalError::ConflictingRoot))
        ));
        restarted_signer
            .sign(burned_claim)
            .expect("same-root burned-leaf retry");
        restarted_signer
            .sign(PqSigningClaim::new([7; 32], unreserved_id))
            .expect("fresh leaf was not reserved by poisoned signer");
    }

    #[test]
    fn concurrent_call_waiting_on_panicked_backend_is_poisoned_before_reservation() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join(XMSS_USAGE_FILENAME);
        let key = SecretKey::from_seed([0x72; 32], 0..=7).expect("small key");
        let public_key = PqPublicKey::deserialize(&key.public_key()).expect("public key");
        let binding = XmssKeyBinding::from_raw_range(key.public_key(), [3; 32], key.slots())
            .expect("binding");
        let journal = XmssUsageJournal::provision(&path, [&binding]).expect("journal");
        let authority = PqSigningAuthority {
            inner: Arc::new(AuthorityInner {
                journal,
                keys: vec![SigningKey {
                    binding: binding.clone(),
                    range: key.slots(),
                    operation_gate: Mutex::new(KeyOperationState::default()),
                    key: Mutex::new(key),
                    panic_on_next_backend_sign: AtomicBool::new(false),
                }],
                public_keys: vec![public_key],
            }),
        };
        let signer = authority.signer(&public_key).expect("signer");
        signer.inject_backend_panic_once();
        let barrier = Arc::new(Barrier::new(3));
        let calls = [
            (
                PqSigningClaim::new([4; 32], one_time_use_id(0, SigningDuty::Attestation)),
                signer.clone(),
            ),
            (
                PqSigningClaim::new(
                    [5; 32],
                    one_time_use_id(0, SigningDuty::AttestationSelectionProof),
                ),
                signer.clone(),
            ),
        ];
        let threads = calls.map(|(claim, signer)| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                (claim, signer.sign(claim))
            })
        });
        barrier.wait();
        let results = threads.map(|thread| thread.join().expect("signing thread"));

        let panicked_claim = results
            .iter()
            .find_map(|(claim, result)| {
                matches!(result, Err(PqSigningError::BackendPanicked)).then_some(*claim)
            })
            .expect("one backend panic");
        let poisoned_claim = results
            .iter()
            .find_map(|(claim, result)| {
                matches!(result, Err(PqSigningError::SignerPoisoned)).then_some(*claim)
            })
            .expect("one poisoned waiter");
        drop(signer);
        drop(authority);

        let journal = XmssUsageJournal::open(&path, [&binding]).expect("reopen journal");
        assert_eq!(
            journal.reserve(&binding, panicked_claim.one_time_use_id(), [9; 32]),
            Err(XmssJournalError::ConflictingRoot)
        );
        assert_eq!(
            journal.reserve(&binding, poisoned_claim.one_time_use_id(), [9; 32]),
            Ok(Reservation::Fresh)
        );
    }

    #[test]
    fn subprocess_crashes_preserve_commit_boundary() {
        fn run_helper(path: &Path, mode: &str) -> std::process::ExitStatus {
            std::process::Command::new(std::env::current_exe().expect("current test executable"))
                .arg("--exact")
                .arg("authority::tests::signing_authority_subprocess_helper")
                .arg("--nocapture")
                .env(AUTHORITY_SUBPROCESS_DATABASE_ENV, path)
                .env(AUTHORITY_SUBPROCESS_MODE_ENV, mode)
                .status()
                .expect("authority test subprocess starts")
        }

        for (mode, id, committed) in [
            (
                "abort-before-commit",
                one_time_use_id(0, SigningDuty::RandaoReveal),
                false,
            ),
            (
                "abort-after-commit-before-sign",
                one_time_use_id(0, SigningDuty::BeaconBlockProposal),
                true,
            ),
            (
                "abort-after-sign-before-return",
                one_time_use_id(0, SigningDuty::Attestation),
                true,
            ),
        ] {
            let directory = tempdir().expect("temporary directory");
            let path = directory.path().join(XMSS_USAGE_FILENAME);
            let binding =
                XmssKeyBinding::from_raw_range([2; 32], [3; 32], 0..=7).expect("valid binding");
            drop(XmssUsageJournal::provision(&path, [&binding]).expect("journal"));
            assert!(!run_helper(&path, mode).success());

            let journal = XmssUsageJournal::open(&path, [&binding]).expect("reopen journal");
            let result = journal.reserve(&binding, id, [5; 32]);
            if committed {
                assert_eq!(result, Err(XmssJournalError::ConflictingRoot));
                assert_eq!(
                    journal.reserve(&binding, id, [4; 32]),
                    Ok(Reservation::SameRoot)
                );
            } else {
                assert_eq!(result, Ok(Reservation::Fresh));
            }
        }
    }

    #[test]
    fn signing_authority_subprocess_helper() {
        let Some(path) =
            std::env::var_os(AUTHORITY_SUBPROCESS_DATABASE_ENV).map(std::path::PathBuf::from)
        else {
            return;
        };
        let mode = std::env::var(AUTHORITY_SUBPROCESS_MODE_ENV).expect("subprocess mode");
        if mode == "real-sign-abort-before-return" {
            let json = std::env::var(AUTHORITY_SUBPROCESS_KEYSTORE_ENV).expect("keystore JSON");
            let keystore = PqKeystore::from_json_str(&json).expect("parse keystore");
            let authority = PqSigningAuthority::open(
                &path,
                [3; 32],
                vec![PqKeyUnlock::new(keystore, b"password").expect("unlock")],
            )
            .expect("open authority");
            let signer = authority
                .signer(&authority.public_keys()[0])
                .expect("signer");
            let claim = PqSigningClaim::new([4; 32], one_time_use_id(0, SigningDuty::Attestation));
            let _ = signer.sign_with_return_hook(claim, |_| std::process::abort());
            return;
        }
        let binding =
            XmssKeyBinding::from_raw_range([2; 32], [3; 32], 0..=7).expect("valid binding");
        let journal = XmssUsageJournal::open(&path, [&binding]).expect("open journal");
        match mode.as_str() {
            "abort-before-commit" => {
                let _ = journal.reserve_and_then_with_commit_hook(
                    &binding,
                    one_time_use_id(0, SigningDuty::RandaoReveal),
                    [4; 32],
                    || -> Result<(), XmssJournalError> { std::process::abort() },
                    |_| Ok::<_, ()>(()),
                );
            }
            "abort-after-commit-before-sign" => {
                let claim = PqSigningClaim::new(
                    [4; 32],
                    one_time_use_id(0, SigningDuty::BeaconBlockProposal),
                );
                let _ = sign_after_reservation(&journal, &binding, &claim, || -> Result<(), _> {
                    std::process::abort()
                });
            }
            "abort-after-sign-before-return" => {
                let claim =
                    PqSigningClaim::new([4; 32], one_time_use_id(0, SigningDuty::Attestation));
                let _ = sign_after_reservation_with_return_hook(
                    &journal,
                    &binding,
                    &claim,
                    || Ok::<_, PqSigningError>(()),
                    |_| std::process::abort(),
                );
            }
            unexpected => panic!("unexpected subprocess mode: {unexpected}"),
        }
    }

    #[test]
    fn real_backend_process_abort_after_sign_burns_leaf() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join(XMSS_USAGE_FILENAME);
        let keystore = PqKeystore::from_seed([8; 32], 0..=7, b"password").expect("keystore");
        let binding = XmssKeyBinding::from_raw_range(
            *keystore.public_key(),
            [3; 32],
            keystore.one_time_use_range(),
        )
        .expect("binding");
        drop(XmssUsageJournal::provision(&path, [&binding]).expect("journal"));

        let status =
            std::process::Command::new(std::env::current_exe().expect("current test executable"))
                .arg("--exact")
                .arg("authority::tests::signing_authority_subprocess_helper")
                .arg("--nocapture")
                .env(AUTHORITY_SUBPROCESS_DATABASE_ENV, &path)
                .env(
                    AUTHORITY_SUBPROCESS_MODE_ENV,
                    "real-sign-abort-before-return",
                )
                .env(
                    AUTHORITY_SUBPROCESS_KEYSTORE_ENV,
                    keystore.to_json_string().expect("keystore JSON"),
                )
                .status()
                .expect("authority test subprocess starts");
        assert!(!status.success());

        let journal = XmssUsageJournal::open(&path, [&binding]).expect("reopen journal");
        let id = one_time_use_id(0, SigningDuty::Attestation);
        assert_eq!(
            journal.reserve(&binding, id, [5; 32]),
            Err(XmssJournalError::ConflictingRoot)
        );
        assert_eq!(
            journal.reserve(&binding, id, [4; 32]),
            Ok(Reservation::SameRoot)
        );
    }
}
