//! Journal-owned signing authority for the experimental PQ devnet.
//!
//! # Blocking contract
//!
//! This crate is intentionally synchronous. Key generation, password KDFs, journal/file I/O, and
//! backend signing can block for a significant time. These operations must not run directly on a
//! Tokio async worker. Future validator-client integration must dispatch each complete authority
//! open or signing call through Lighthouse's scoped blocking executor; reservation and backend
//! signing must remain one indivisible dispatched operation.
//!
//! Sensitive construction and reservation primitives are deliberately absent:
//!
//! ```compile_fail
//! use pq_signing::PqKeystoreBuilder;
//! ```
//!
//! ```compile_fail
//! use pq_signing::journal::XmssUsageJournal;
//! ```
//!
//! ```compile_fail
//! use pq_signing::PqUnreservedSigningKey;
//! ```
//!
//! ```compile_fail
//! use pq_signing::PqKeystore;
//!
//! fn decrypt(keystore: &PqKeystore, password: &[u8]) {
//!     let _live_key = keystore.decrypt_secret_key(password);
//! }
//! ```

#![cfg_attr(not(feature = "pq-devnet"), allow(dead_code))]

#[cfg(feature = "pq-devnet")]
mod authority;

#[cfg(feature = "pq-devnet")]
pub use authority::keystore::{
    AuthenticatedPqKeyMetadata, MAX_PQ_KEYSTORE_JSON_BYTES, MAX_PQ_ONE_TIME_USE_IDS,
    MAX_PQ_PASSWORD_BYTES, PQ_BACKEND_REVISION, PQ_BINDINGS_REVISION, PQ_FORMAT, PQ_FORMAT_VERSION,
    PQ_PARAMETER_SET, PQ_SCHEME, PqKeystore, PqKeystoreError, validate_pq_password,
};

#[cfg(feature = "pq-devnet")]
pub use authority::{
    PqKeyUnlock, PqSigner, PqSigningAuthority, PqSigningError, PqUsageJournalError,
    XMSS_USAGE_FILENAME, provision_usage_journal, validate_usage_journal,
};
