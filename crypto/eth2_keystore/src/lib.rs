//! Provides a JSON keystore for a BLS keypair, as specified by
//! [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

mod derived_key;
mod keystore;
#[cfg(feature = "pq-devnet")]
mod pq_keystore;

pub mod json_keystore;

pub use bls::ZeroizeHash;
pub use eth2_key_derivation::PlainText;
pub use keystore::{
    DKLEN, Error, HASH_SIZE, IV_SIZE, Keystore, KeystoreBuilder, SALT_SIZE, decrypt, default_kdf,
    encrypt, keypair_from_secret,
};
pub use uuid::Uuid;

#[cfg(feature = "pq-devnet")]
pub use pq_keystore::{
    MAX_PQ_KEYSTORE_JSON_BYTES, MAX_PQ_ONE_TIME_USE_IDS, MAX_PQ_PASSWORD_BYTES,
    PQ_BACKEND_REVISION, PQ_BINDINGS_REVISION, PQ_FORMAT, PQ_FORMAT_VERSION, PQ_PARAMETER_SET,
    PQ_SCHEME, PqKeystore, PqKeystoreBuilder, PqKeystoreError, validate_pq_password,
};
