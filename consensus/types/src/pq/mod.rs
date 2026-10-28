//! Post-quantum validator key registry types (EIP-8450).

mod pq_key_possession;
mod pq_key_registration;
mod pq_public_keys;
mod signed_pq_key_registration;

pub use pq_key_possession::PqKeyPossession;
pub use pq_key_registration::PqKeyRegistration;
pub use pq_public_keys::PqPublicKeys;
pub use signed_pq_key_registration::SignedPqKeyRegistration;

use ssz_types::FixedVector;
use typenum::{Sum, U32, U356, U2048};

/// `XMSS_SIGNATURE_SIZE`.
pub type U2404 = Sum<U2048, U356>;

/// A leanXMSS public key, as encoded by EIP-CRYPTO (`XMSS_PUBLIC_KEY_SIZE` = 32 bytes).
pub type XmssPublicKey = FixedVector<u8, U32>;
/// A leanXMSS signature, as encoded by EIP-CRYPTO (`XMSS_SIGNATURE_SIZE` = 2404 bytes).
pub type XmssSignature = FixedVector<u8, U2404>;
/// The root of a VRF tree (`VRF_HASH_SIZE` = 32 bytes).
pub type VrfRoot = FixedVector<u8, U32>;

/// Marks a validator with no registered keys.
pub const PQ_KEYS_VERSION_UNSET: u8 = 0;
/// Version 1 of EIP-CRYPTO.
pub const PQ_KEYS_VERSION_1: u8 = 1;
/// Leaf index at which the proof of possession is signed.
pub const PQ_POSSESSION_XMSS_INDEX: u32 = 0;
