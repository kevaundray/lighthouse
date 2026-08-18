//! Experimental encrypted persistence for the pinned leanMultisig XMSS key.
//!
//! This format reuses the encryption primitives from EIP-2335, but is not an EIP-2335 keystore:
//! its plaintext is a versioned XMSS-key envelope rather than an EIP-2333 BLS scalar.

use consensus_signature::PqPublicKey;
use eth2_keystore::json_keystore::{
    Aes128Ctr, ChecksumModule, Cipher, CipherModule, Crypto, EmptyMap, EmptyString, Kdf, KdfModule,
    Sha256Checksum,
};
use eth2_keystore::{
    DKLEN, Error as CryptoError, HASH_SIZE, IV_SIZE, SALT_SIZE, decrypt, default_kdf, encrypt,
    normalize_eip2335_password,
};
use lean_multisig::SecretKey;
use rand::{TryRngCore, rngs::OsRng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Read, Write};
use std::ops::RangeInclusive;
#[cfg(test)]
use std::{cell::Cell, thread_local};
use zeroize::Zeroizing;

#[cfg(test)]
thread_local! {
    static SECRET_KEY_DECRYPTIONS: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_secret_key_decryptions() {
    SECRET_KEY_DECRYPTIONS.set(0);
}

#[cfg(test)]
pub(super) fn secret_key_decryptions() -> usize {
    SECRET_KEY_DECRYPTIONS.get()
}

pub const PQ_FORMAT: &str = "lighthouse-pq-keystore";
pub const PQ_FORMAT_VERSION: u32 = 1;
pub const PQ_SCHEME: &str = "XMSS";
pub const PQ_PARAMETER_SET: &str = "lean-multisig-xmss-sha256-v1";
pub const PQ_BINDINGS_REVISION: &str = "c0ef8e621556581b2beb0c4f72f99c001a026fe6";
pub const PQ_BACKEND_REVISION: &str = "aed646200cf5ae3199c25c61f2bfe094582678ae";
pub const MAX_PQ_KEYSTORE_JSON_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PQ_PASSWORD_BYTES: usize = 4096;
pub const MAX_PQ_ONE_TIME_USE_IDS: u32 = 1120;
const MAX_PQ_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;

const INNER_MAGIC: &[u8; 8] = b"LHPQKEY\0";
const INNER_VERSION: u8 = 1;
const INNER_PREFIX_LEN: usize = INNER_MAGIC.len() + 1;
const FIXED_SCRYPT_N: u32 = 262_144;
const FIXED_SCRYPT_R: u32 = 8;
const FIXED_SCRYPT_P: u32 = 1;

#[derive(Debug)]
pub enum PqKeystoreError {
    EmptyPassword,
    EmptyEffectivePassword,
    PasswordTooLong,
    InvalidPasswordEncoding,
    InvalidOneTimeUseRange,
    Crypto(CryptoError),
    KeyConstruction(String),
    Json(String),
    Io(String),
    InputTooLarge,
    Entropy(String),
    UnsupportedFormat,
    UnsupportedVersion,
    UnsupportedScheme,
    UnsupportedParameterSet,
    UnsupportedBackendRevision,
    UnsupportedCryptoProfile,
    MalformedPlaintext,
    MalformedSecretKey,
    AuthenticatedMetadataMismatch,
    PublicKeyMismatch,
    OneTimeUseRangeMismatch,
}

impl std::fmt::Display for PqKeystoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPassword => formatter.write_str("PQ keystore password must not be empty"),
            Self::EmptyEffectivePassword => {
                formatter.write_str("PQ keystore password is empty after EIP-2335 normalization")
            }
            Self::PasswordTooLong => formatter.write_str("PQ keystore password exceeds size limit"),
            Self::InvalidPasswordEncoding => {
                formatter.write_str("PQ keystore password must be valid UTF-8")
            }
            Self::InvalidOneTimeUseRange => formatter.write_str("invalid PQ one-time-use range"),
            Self::Crypto(error) => write!(formatter, "PQ keystore cryptography failed: {error:?}"),
            Self::KeyConstruction(error) => {
                write!(formatter, "PQ key construction failed: {error}")
            }
            Self::Json(error) => write!(formatter, "PQ keystore JSON failed: {error}"),
            Self::Io(error) => write!(formatter, "PQ keystore I/O failed: {error}"),
            Self::InputTooLarge => formatter.write_str("PQ keystore input exceeds size limit"),
            Self::Entropy(error) => write!(formatter, "PQ keystore entropy failed: {error}"),
            Self::UnsupportedFormat => formatter.write_str("unsupported PQ keystore format"),
            Self::UnsupportedVersion => formatter.write_str("unsupported PQ keystore version"),
            Self::UnsupportedScheme => formatter.write_str("unsupported PQ signature scheme"),
            Self::UnsupportedParameterSet => formatter.write_str("unsupported PQ parameter set"),
            Self::UnsupportedBackendRevision => {
                formatter.write_str("unsupported PQ backend revision")
            }
            Self::UnsupportedCryptoProfile => {
                formatter.write_str("unsupported PQ keystore crypto profile")
            }
            Self::MalformedPlaintext => formatter.write_str("malformed PQ keystore plaintext"),
            Self::MalformedSecretKey => formatter.write_str("malformed PQ secret key"),
            Self::AuthenticatedMetadataMismatch => {
                formatter.write_str("PQ keystore authenticated metadata mismatch")
            }
            Self::PublicKeyMismatch => formatter.write_str("PQ public key mismatch"),
            Self::OneTimeUseRangeMismatch => formatter.write_str("PQ one-time-use range mismatch"),
        }
    }
}

impl std::error::Error for PqKeystoreError {}

impl From<CryptoError> for PqKeystoreError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

pub fn validate_pq_password(password: &[u8]) -> Result<(), PqKeystoreError> {
    if password.is_empty() {
        return Err(PqKeystoreError::EmptyPassword);
    }
    if password.len() > MAX_PQ_PASSWORD_BYTES {
        return Err(PqKeystoreError::PasswordTooLong);
    }
    let effective = normalize_eip2335_password(password)
        .map_err(|_| PqKeystoreError::InvalidPasswordEncoding)?;
    if effective.is_empty() {
        return Err(PqKeystoreError::EmptyEffectivePassword);
    }
    Ok(())
}

fn validate_one_time_use_range(range: &RangeInclusive<u32>) -> Result<(), PqKeystoreError> {
    let span = range
        .end()
        .checked_sub(*range.start())
        .and_then(|difference| difference.checked_add(1))
        .ok_or(PqKeystoreError::InvalidOneTimeUseRange)?;
    if span > MAX_PQ_ONE_TIME_USE_IDS {
        return Err(PqKeystoreError::InvalidOneTimeUseRange);
    }
    Ok(())
}

fn validate_key_inputs(
    range: &RangeInclusive<u32>,
    password: &[u8],
) -> Result<(), PqKeystoreError> {
    validate_pq_password(password)?;
    validate_one_time_use_range(range)
}

fn construct_key_after_preflight<F>(
    range: RangeInclusive<u32>,
    password: &[u8],
    construct: F,
) -> Result<SecretKey, PqKeystoreError>
where
    F: FnOnce(RangeInclusive<u32>) -> Result<SecretKey, PqKeystoreError>,
{
    validate_key_inputs(&range, password)?;
    construct(range)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicKeyBytes([u8; 32]);

impl Serialize for PublicKeyBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(serde::de::Error::custom(
                "PQ public key must be canonical lowercase 32-byte hex",
            ));
        }
        let bytes = hex::decode(encoded).map_err(serde::de::Error::custom)?;
        let bytes = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("PQ public key must be exactly 32 bytes"))?;
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OneTimeUseRange {
    start: u32,
    end: u32,
}

impl OneTimeUseRange {
    fn from_range(range: RangeInclusive<u32>) -> Self {
        Self {
            start: *range.start(),
            end: *range.end(),
        }
    }

    const fn as_range(&self) -> RangeInclusive<u32> {
        self.start..=self.end
    }
}

/// A Lighthouse-owned encrypted XMSS keystore for the exact pinned devnet backend.
///
/// The type intentionally has no public unbounded `Deserialize` implementation:
///
/// ```compile_fail
/// use pq_signing::PqKeystore;
/// use serde::Deserialize;
///
/// fn requires_deserialize<T: for<'de> Deserialize<'de>>() {}
/// requires_deserialize::<PqKeystore>();
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PqKeystore {
    crypto: Crypto,
    format: String,
    version: u32,
    scheme: String,
    parameter_set: String,
    bindings_revision: String,
    backend_revision: String,
    public_key: PublicKeyBytes,
    one_time_use_range: OneTimeUseRange,
}

/// Public key metadata whose encrypted copy and reconstructed key have been authenticated.
///
/// Fields are intentionally private so callers cannot manufacture journal bindings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPqKeyMetadata {
    public_key: PqPublicKey,
    one_time_use_range: RangeInclusive<u32>,
}

impl AuthenticatedPqKeyMetadata {
    pub const fn public_key(&self) -> &PqPublicKey {
        &self.public_key
    }

    pub fn one_time_use_range(&self) -> RangeInclusive<u32> {
        self.one_time_use_range.clone()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PqKeystoreJson {
    crypto: Crypto,
    format: String,
    version: u32,
    scheme: String,
    parameter_set: String,
    bindings_revision: String,
    backend_revision: String,
    public_key: PublicKeyBytes,
    one_time_use_range: OneTimeUseRange,
}

impl From<PqKeystoreJson> for PqKeystore {
    fn from(json: PqKeystoreJson) -> Self {
        Self {
            crypto: json.crypto,
            format: json.format,
            version: json.version,
            scheme: json.scheme,
            parameter_set: json.parameter_set,
            bindings_revision: json.bindings_revision,
            backend_revision: json.backend_revision,
            public_key: json.public_key,
            one_time_use_range: json.one_time_use_range,
        }
    }
}

impl PqKeystore {
    /// Generates a fresh upstream key and encrypts it with the fixed keystore profile.
    ///
    /// # Blocking
    ///
    /// This performs synchronous PQ key generation and the password KDF. It must not run directly
    /// on a Tokio async worker. Validator-client code must dispatch the complete call through
    /// Lighthouse's scoped blocking executor.
    pub fn generate(
        one_time_use_range: RangeInclusive<u32>,
        password: &[u8],
    ) -> Result<Self, PqKeystoreError> {
        let key = construct_key_after_preflight(one_time_use_range, password, |range| {
            let mut seed = Zeroizing::new([0; 32]);
            OsRng
                .try_fill_bytes(seed.as_mut())
                .map_err(|error| PqKeystoreError::Entropy(error.to_string()))?;
            SecretKey::from_seed(*seed, range)
                .map_err(|error| PqKeystoreError::KeyConstruction(error.to_string()))
        })?;
        Self::encrypt_key(&key, password)
    }

    /// Deterministically generates an upstream key and encrypts it with the fixed keystore profile.
    ///
    /// # Blocking
    ///
    /// This performs synchronous PQ key generation and the password KDF. It must not run directly
    /// on a Tokio async worker. Validator-client code must dispatch the complete call through
    /// Lighthouse's scoped blocking executor.
    pub fn from_seed(
        seed: [u8; 32],
        one_time_use_range: RangeInclusive<u32>,
        password: &[u8],
    ) -> Result<Self, PqKeystoreError> {
        let key = construct_key_after_preflight(one_time_use_range, password, |range| {
            SecretKey::from_seed(seed, range)
                .map_err(|error| PqKeystoreError::KeyConstruction(error.to_string()))
        })?;
        Self::encrypt_key(&key, password)
    }

    fn encrypt_key(secret_key: &SecretKey, password: &[u8]) -> Result<Self, PqKeystoreError> {
        validate_key_inputs(&secret_key.slots(), password)?;
        let metadata = Self::metadata(secret_key.public_key(), secret_key.slots());
        let secret_bytes = Zeroizing::new(secret_key.to_bytes());
        let plaintext = encode_plaintext(&metadata, &secret_bytes)?;
        let mut salt = [0; SALT_SIZE];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|error| PqKeystoreError::Entropy(error.to_string()))?;
        let mut iv = [0; IV_SIZE];
        OsRng
            .try_fill_bytes(&mut iv)
            .map_err(|error| PqKeystoreError::Entropy(error.to_string()))?;
        let kdf = default_kdf(salt.to_vec());
        let cipher = Cipher::Aes128Ctr(Aes128Ctr {
            iv: iv.to_vec().into(),
        });
        let (ciphertext, checksum) = encrypt(&plaintext, password, &kdf, &cipher)?;

        Ok(Self {
            crypto: Crypto {
                kdf: KdfModule {
                    function: kdf.function(),
                    params: kdf,
                    message: EmptyString,
                },
                checksum: ChecksumModule {
                    function: Sha256Checksum::function(),
                    params: EmptyMap,
                    message: checksum.to_vec().into(),
                },
                cipher: CipherModule {
                    function: cipher.function(),
                    params: cipher,
                    message: ciphertext.into(),
                },
            },
            format: metadata.format,
            version: metadata.version,
            scheme: metadata.scheme,
            parameter_set: metadata.parameter_set,
            bindings_revision: metadata.bindings_revision,
            backend_revision: metadata.backend_revision,
            public_key: metadata.public_key,
            one_time_use_range: metadata.one_time_use_range,
        })
    }

    fn metadata(public_key: [u8; 32], range: RangeInclusive<u32>) -> AuthenticatedMetadata {
        AuthenticatedMetadata {
            format: PQ_FORMAT.to_owned(),
            version: PQ_FORMAT_VERSION,
            scheme: PQ_SCHEME.to_owned(),
            parameter_set: PQ_PARAMETER_SET.to_owned(),
            bindings_revision: PQ_BINDINGS_REVISION.to_owned(),
            backend_revision: PQ_BACKEND_REVISION.to_owned(),
            public_key: PublicKeyBytes(public_key),
            one_time_use_range: OneTimeUseRange::from_range(range),
        }
    }

    fn outer_metadata(&self) -> AuthenticatedMetadata {
        AuthenticatedMetadata {
            format: self.format.clone(),
            version: self.version,
            scheme: self.scheme.clone(),
            parameter_set: self.parameter_set.clone(),
            bindings_revision: self.bindings_revision.clone(),
            backend_revision: self.backend_revision.clone(),
            public_key: self.public_key.clone(),
            one_time_use_range: self.one_time_use_range.clone(),
        }
    }

    pub(in crate::authority) fn decrypt_secret_key(
        &self,
        password: &[u8],
    ) -> Result<SecretKey, PqKeystoreError> {
        #[cfg(test)]
        SECRET_KEY_DECRYPTIONS.set(SECRET_KEY_DECRYPTIONS.get() + 1);
        self.validate_profile()?;
        let plaintext = decrypt(password, &self.crypto)?;
        validate_plaintext(plaintext.as_bytes(), &self.outer_metadata())
    }

    /// Decrypts and fully validates the key without exposing a live sign-capable handle.
    ///
    /// # Blocking
    ///
    /// This runs the password KDF and reconstructs the upstream PQ key synchronously. It must not
    /// run directly on a Tokio async worker. Validator-client code must dispatch the complete call
    /// through Lighthouse's scoped blocking executor.
    pub fn validate_password(&self, password: &[u8]) -> Result<(), PqKeystoreError> {
        validate_pq_password(password)?;
        self.decrypt_secret_key(password).map(drop)
    }

    /// Authenticates the encrypted key and returns only non-secret validated metadata.
    ///
    /// # Blocking
    ///
    /// This runs the password KDF and reconstructs the upstream PQ key synchronously. It must not
    /// run directly on a Tokio async worker. Validator-client code must dispatch the complete call
    /// through Lighthouse's scoped blocking executor.
    pub fn authenticate(
        &self,
        password: &[u8],
    ) -> Result<AuthenticatedPqKeyMetadata, PqKeystoreError> {
        validate_pq_password(password)?;
        let key = self.decrypt_secret_key(password)?;
        let metadata = AuthenticatedPqKeyMetadata {
            public_key: PqPublicKey::deserialize(&key.public_key())
                .map_err(|_| PqKeystoreError::MalformedSecretKey)?,
            one_time_use_range: key.slots(),
        };
        drop(key);
        Ok(metadata)
    }

    /// Validates all non-secret metadata and bounded crypto parameters without running the KDF.
    pub fn validate_metadata(&self) -> Result<(), PqKeystoreError> {
        self.validate_profile()
    }

    fn validate_profile(&self) -> Result<(), PqKeystoreError> {
        if self.format != PQ_FORMAT {
            return Err(PqKeystoreError::UnsupportedFormat);
        }
        if self.version != PQ_FORMAT_VERSION {
            return Err(PqKeystoreError::UnsupportedVersion);
        }
        if self.scheme != PQ_SCHEME {
            return Err(PqKeystoreError::UnsupportedScheme);
        }
        if self.parameter_set != PQ_PARAMETER_SET {
            return Err(PqKeystoreError::UnsupportedParameterSet);
        }
        if self.bindings_revision != PQ_BINDINGS_REVISION {
            return Err(PqKeystoreError::UnsupportedBackendRevision);
        }
        if self.backend_revision != PQ_BACKEND_REVISION {
            return Err(PqKeystoreError::UnsupportedBackendRevision);
        }
        validate_one_time_use_range(&self.one_time_use_range.as_range())?;

        let Kdf::Scrypt(scrypt) = &self.crypto.kdf.params else {
            return Err(PqKeystoreError::UnsupportedCryptoProfile);
        };
        let Cipher::Aes128Ctr(cipher) = &self.crypto.cipher.params;
        if self.crypto.kdf.function != self.crypto.kdf.params.function()
            || scrypt.dklen != DKLEN
            || scrypt.n != FIXED_SCRYPT_N
            || scrypt.r != FIXED_SCRYPT_R
            || scrypt.p != FIXED_SCRYPT_P
            || scrypt.salt.len() != SALT_SIZE
            || self.crypto.cipher.function != self.crypto.cipher.params.function()
            || cipher.iv.len() != IV_SIZE
            || self.crypto.checksum.function != Sha256Checksum::function()
            || self.crypto.checksum.message.len() != HASH_SIZE
            || self.crypto.cipher.message.len() > MAX_PQ_CIPHERTEXT_BYTES
        {
            return Err(PqKeystoreError::UnsupportedCryptoProfile);
        }
        Ok(())
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key.0
    }

    pub const fn one_time_use_range(&self) -> RangeInclusive<u32> {
        self.one_time_use_range.as_range()
    }

    pub fn to_json_string(&self) -> Result<String, PqKeystoreError> {
        serde_json::to_string(self).map_err(|error| PqKeystoreError::Json(error.to_string()))
    }

    pub fn from_json_str(json: &str) -> Result<Self, PqKeystoreError> {
        if json.len() > MAX_PQ_KEYSTORE_JSON_BYTES {
            return Err(PqKeystoreError::InputTooLarge);
        }
        serde_json::from_str::<PqKeystoreJson>(json)
            .map(Into::into)
            .map_err(|error| PqKeystoreError::Json(error.to_string()))
    }

    pub fn to_json_writer<W: Write>(&self, writer: W) -> Result<(), PqKeystoreError> {
        serde_json::to_writer(writer, self).map_err(|error| PqKeystoreError::Io(error.to_string()))
    }

    pub fn from_json_reader<R: Read>(reader: R) -> Result<Self, PqKeystoreError> {
        let limit = u64::try_from(MAX_PQ_KEYSTORE_JSON_BYTES)
            .map_err(|_| PqKeystoreError::InputTooLarge)?;
        let mut bytes = Vec::new();
        reader
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| PqKeystoreError::Io(error.to_string()))?;
        if bytes.len() > MAX_PQ_KEYSTORE_JSON_BYTES {
            return Err(PqKeystoreError::InputTooLarge);
        }
        serde_json::from_slice::<PqKeystoreJson>(&bytes)
            .map(Into::into)
            .map_err(|error| PqKeystoreError::Io(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticatedMetadata {
    format: String,
    version: u32,
    scheme: String,
    parameter_set: String,
    bindings_revision: String,
    backend_revision: String,
    public_key: PublicKeyBytes,
    one_time_use_range: OneTimeUseRange,
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PqKeystoreError> {
    let len = u32::try_from(bytes.len()).map_err(|_| PqKeystoreError::MalformedPlaintext)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn take_bytes<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], PqKeystoreError> {
    let len_bytes: [u8; 4] = input
        .get(..4)
        .ok_or(PqKeystoreError::MalformedPlaintext)?
        .try_into()
        .map_err(|_| PqKeystoreError::MalformedPlaintext)?;
    *input = input.get(4..).ok_or(PqKeystoreError::MalformedPlaintext)?;
    let len = usize::try_from(u32::from_le_bytes(len_bytes))
        .map_err(|_| PqKeystoreError::MalformedPlaintext)?;
    let value = input
        .get(..len)
        .ok_or(PqKeystoreError::MalformedPlaintext)?;
    *input = input
        .get(len..)
        .ok_or(PqKeystoreError::MalformedPlaintext)?;
    Ok(value)
}

fn encode_plaintext(
    metadata: &AuthenticatedMetadata,
    secret_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PqKeystoreError> {
    let mut output = Zeroizing::new(Vec::new());
    output.extend_from_slice(INNER_MAGIC);
    output.push(INNER_VERSION);
    push_bytes(&mut output, metadata.format.as_bytes())?;
    output.extend_from_slice(&metadata.version.to_le_bytes());
    push_bytes(&mut output, metadata.scheme.as_bytes())?;
    push_bytes(&mut output, metadata.parameter_set.as_bytes())?;
    push_bytes(&mut output, metadata.bindings_revision.as_bytes())?;
    push_bytes(&mut output, metadata.backend_revision.as_bytes())?;
    output.extend_from_slice(&metadata.public_key.0);
    output.extend_from_slice(&metadata.one_time_use_range.start.to_le_bytes());
    output.extend_from_slice(&metadata.one_time_use_range.end.to_le_bytes());
    push_bytes(&mut output, secret_bytes)?;
    Ok(output)
}

fn decode_plaintext(input: &[u8]) -> Result<(AuthenticatedMetadata, &[u8]), PqKeystoreError> {
    if input.get(..INNER_MAGIC.len()) != Some(INNER_MAGIC)
        || input.get(INNER_MAGIC.len()).copied() != Some(INNER_VERSION)
    {
        return Err(PqKeystoreError::MalformedPlaintext);
    }
    let mut rest = input
        .get(INNER_PREFIX_LEN..)
        .ok_or(PqKeystoreError::MalformedPlaintext)?;
    take_expected(&mut rest, PQ_FORMAT.as_bytes())?;
    let version = take_u32(&mut rest)?;
    take_expected(&mut rest, PQ_SCHEME.as_bytes())?;
    take_expected(&mut rest, PQ_PARAMETER_SET.as_bytes())?;
    take_expected(&mut rest, PQ_BINDINGS_REVISION.as_bytes())?;
    take_expected(&mut rest, PQ_BACKEND_REVISION.as_bytes())?;
    let public_key = take_fixed_32(&mut rest)?;
    let start = take_u32(&mut rest)?;
    let end = take_u32(&mut rest)?;
    let secret_bytes = take_bytes(&mut rest)?;
    if !rest.is_empty() {
        return Err(PqKeystoreError::MalformedPlaintext);
    }
    Ok((
        AuthenticatedMetadata {
            format: PQ_FORMAT.to_owned(),
            version,
            scheme: PQ_SCHEME.to_owned(),
            parameter_set: PQ_PARAMETER_SET.to_owned(),
            bindings_revision: PQ_BINDINGS_REVISION.to_owned(),
            backend_revision: PQ_BACKEND_REVISION.to_owned(),
            public_key: PublicKeyBytes(public_key),
            one_time_use_range: OneTimeUseRange { start, end },
        },
        secret_bytes,
    ))
}

fn validate_plaintext(
    plaintext: &[u8],
    outer_metadata: &AuthenticatedMetadata,
) -> Result<SecretKey, PqKeystoreError> {
    let (inner_metadata, secret_bytes) = decode_plaintext(plaintext)?;
    if &inner_metadata != outer_metadata {
        return Err(PqKeystoreError::AuthenticatedMetadataMismatch);
    }
    let secret_key =
        SecretKey::from_bytes(secret_bytes).map_err(|_| PqKeystoreError::MalformedSecretKey)?;
    if Zeroizing::new(secret_key.to_bytes()).as_slice() != secret_bytes {
        return Err(PqKeystoreError::MalformedSecretKey);
    }
    if secret_key.slots() != outer_metadata.one_time_use_range.as_range() {
        return Err(PqKeystoreError::OneTimeUseRangeMismatch);
    }
    if secret_key.public_key() != outer_metadata.public_key.0 {
        return Err(PqKeystoreError::PublicKeyMismatch);
    }
    Ok(secret_key)
}

fn take_expected(input: &mut &[u8], expected: &[u8]) -> Result<(), PqKeystoreError> {
    if take_bytes(input)? == expected {
        Ok(())
    } else {
        Err(PqKeystoreError::AuthenticatedMetadataMismatch)
    }
}

fn take_u32(input: &mut &[u8]) -> Result<u32, PqKeystoreError> {
    let bytes: [u8; 4] = input
        .get(..4)
        .ok_or(PqKeystoreError::MalformedPlaintext)?
        .try_into()
        .map_err(|_| PqKeystoreError::MalformedPlaintext)?;
    *input = input.get(4..).ok_or(PqKeystoreError::MalformedPlaintext)?;
    Ok(u32::from_le_bytes(bytes))
}

fn take_fixed_32(input: &mut &[u8]) -> Result<[u8; 32], PqKeystoreError> {
    let bytes = input.get(..32).ok_or(PqKeystoreError::MalformedPlaintext)?;
    *input = input.get(32..).ok_or(PqKeystoreError::MalformedPlaintext)?;
    bytes
        .try_into()
        .map_err(|_| PqKeystoreError::MalformedPlaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs2::FileExt;
    use std::cell::Cell;
    use std::fs::OpenOptions;

    fn framed_secret(metadata: &AuthenticatedMetadata, secret_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
        encode_plaintext(metadata, secret_bytes).expect("frame secret")
    }

    #[test]
    fn v1_input_limits_accept_boundaries_and_reject_invalid_values() {
        let maximum_password = vec![0x5a; MAX_PQ_PASSWORD_BYTES];
        let inverted = RangeInclusive::new(1, 0);
        assert!(validate_key_inputs(&(0..=1119), &maximum_password).is_ok());
        assert!(validate_key_inputs(&(u32::MAX - 1119..=u32::MAX), b"password").is_ok());

        assert!(matches!(
            validate_key_inputs(&inverted, b"password"),
            Err(PqKeystoreError::InvalidOneTimeUseRange)
        ));
        assert!(matches!(
            validate_key_inputs(&(0..=1120), b"password"),
            Err(PqKeystoreError::InvalidOneTimeUseRange)
        ));
        assert!(matches!(
            validate_key_inputs(&(0..=u32::MAX), b"password"),
            Err(PqKeystoreError::InvalidOneTimeUseRange)
        ));
        assert!(matches!(
            validate_key_inputs(&(0..=7), b""),
            Err(PqKeystoreError::EmptyPassword)
        ));
        assert!(matches!(
            validate_key_inputs(&(0..=7), &vec![0; MAX_PQ_PASSWORD_BYTES + 1]),
            Err(PqKeystoreError::PasswordTooLong)
        ));
    }

    #[test]
    fn invalid_inputs_do_not_reach_upstream_key_construction() {
        fn attempt(
            range: RangeInclusive<u32>,
            password: &[u8],
        ) -> (Result<SecretKey, PqKeystoreError>, bool) {
            let called = Cell::new(false);
            let result = construct_key_after_preflight(range, password, |_| {
                called.set(true);
                Err(PqKeystoreError::KeyConstruction(
                    "unexpected construction".into(),
                ))
            });
            (result, called.get())
        }

        let (oversized_range, called) = attempt(0..=1120, b"password");
        assert!(!called);
        assert!(matches!(
            oversized_range,
            Err(PqKeystoreError::InvalidOneTimeUseRange)
        ));

        let (inverted_range, called) = attempt(RangeInclusive::new(1, 0), b"password");
        assert!(!called);
        assert!(matches!(
            inverted_range,
            Err(PqKeystoreError::InvalidOneTimeUseRange)
        ));

        let (empty_password, called) = attempt(0..=7, b"");
        assert!(!called);
        assert!(matches!(
            empty_password,
            Err(PqKeystoreError::EmptyPassword)
        ));

        let oversized_password = vec![0; MAX_PQ_PASSWORD_BYTES + 1];
        let (oversized_password, called) = attempt(0..=7, &oversized_password);
        assert!(!called);
        assert!(matches!(
            oversized_password,
            Err(PqKeystoreError::PasswordTooLong)
        ));
    }

    #[test]
    fn invalid_utf8_password_does_not_reach_upstream_key_construction() {
        let called = Cell::new(false);
        let result = construct_key_after_preflight(0..=7, &[0xff], |_| {
            called.set(true);
            Err(PqKeystoreError::KeyConstruction(
                "unexpected construction".into(),
            ))
        });

        assert!(!called.get());
        assert!(matches!(
            result,
            Err(PqKeystoreError::InvalidPasswordEncoding)
        ));
    }

    #[test]
    fn control_only_password_does_not_reach_upstream_key_construction() {
        let called = Cell::new(false);
        let result = construct_key_after_preflight(0..=7, b"\0\x7f\xc2\x85", |_| {
            called.set(true);
            Err(PqKeystoreError::KeyConstruction(
                "unexpected construction".into(),
            ))
        });

        assert!(!called.get());
        assert!(matches!(
            result,
            Err(PqKeystoreError::EmptyEffectivePassword)
        ));
    }

    #[test]
    fn encryption_rejects_oversized_password_without_kdf() {
        let key = SecretKey::from_seed([0x10; 32], 0..=7).expect("small key");
        assert!(matches!(
            PqKeystore::encrypt_key(&key, &vec![0; MAX_PQ_PASSWORD_BYTES + 1]),
            Err(PqKeystoreError::PasswordTooLong)
        ));
    }

    #[test]
    fn well_framed_malformed_and_trailing_secret_payloads_are_rejected_exactly() {
        let key = SecretKey::from_seed([0x11; 32], 0..=7).expect("small key");
        let metadata = PqKeystore::metadata(key.public_key(), key.slots());
        let canonical = Zeroizing::new(key.to_bytes());

        let mut malformed = Zeroizing::new(canonical.to_vec());
        malformed[0] ^= 1;
        assert!(matches!(
            validate_plaintext(&framed_secret(&metadata, &malformed), &metadata),
            Err(PqKeystoreError::MalformedSecretKey)
        ));

        let mut trailing = Zeroizing::new(canonical.to_vec());
        trailing.push(0xff);
        assert!(matches!(
            validate_plaintext(&framed_secret(&metadata, &trailing), &metadata),
            Err(PqKeystoreError::MalformedSecretKey)
        ));
    }

    #[test]
    fn valid_secret_payload_with_same_range_but_other_identity_is_public_key_mismatch() {
        let expected = SecretKey::from_seed([0x21; 32], 0..=7).expect("expected key");
        let other = SecretKey::from_seed([0x22; 32], 0..=7).expect("other key");
        let metadata = PqKeystore::metadata(expected.public_key(), expected.slots());
        let other_bytes = Zeroizing::new(other.to_bytes());

        assert!(matches!(
            validate_plaintext(&framed_secret(&metadata, &other_bytes), &metadata),
            Err(PqKeystoreError::PublicKeyMismatch)
        ));
    }

    #[test]
    fn valid_secret_payload_with_other_range_is_range_mismatch() {
        let expected = SecretKey::from_seed([0x23; 32], 0..=7).expect("expected key");
        let other = SecretKey::from_seed([0x24; 32], 8..=15).expect("other key");
        let metadata = PqKeystore::metadata(expected.public_key(), expected.slots());
        let other_bytes = Zeroizing::new(other.to_bytes());

        assert!(matches!(
            validate_plaintext(&framed_secret(&metadata, &other_bytes), &metadata),
            Err(PqKeystoreError::OneTimeUseRangeMismatch)
        ));
    }

    #[test]
    fn private_decrypt_reconstructs_the_exact_upstream_key() {
        let path = std::env::temp_dir().join("lighthouse-pq-crypto-tests.lock");
        let work_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .expect("open PQ test lock");
        work_lock.lock_exclusive().expect("lock PQ test work");
        let original = SecretKey::from_seed([0x31; 32], 400..=407).expect("small key");
        let keystore = PqKeystore::encrypt_key(&original, b"password").expect("keystore");
        let restored = keystore.decrypt_secret_key(b"password").expect("decrypt");
        assert_eq!(restored.public_key(), original.public_key());
        assert_eq!(restored.slots(), original.slots());
        assert_eq!(restored.to_bytes(), original.to_bytes());
    }
}
