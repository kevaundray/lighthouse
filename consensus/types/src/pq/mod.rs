//! Post-quantum validator key registry types (EIP-8450).
//!
//! EIP-8450 specifies only the interface of its hash-based primitives (`xmss.Verify`,
//! `xmss_signature_index` and `vrf.Verify`) and the byte sizes of their values. leanXMSS
//! verification is implemented by `lean_pq`.

mod pq_key_possession;
mod pq_key_registration;
mod pq_public_keys;
mod signed_pq_key_registration;

pub use pq_key_possession::PqKeyPossession;
pub use pq_key_registration::PqKeyRegistration;
pub use pq_public_keys::PqPublicKeys;
pub use signed_pq_key_registration::SignedPqKeyRegistration;

use crate::core::{Epoch, Hash256};
use ssz_types::FixedVector;
use typenum::{Sum, U32, U356, U2048};

/// The length of an `XMSSSignature`, 2404 bytes.
pub type U2404 = Sum<U2048, U356>;

/// A leanXMSS public key (`XMSSPublicKey`, `ByteVector[32]`).
pub type XmssPublicKey = FixedVector<u8, U32>;
/// A leanXMSS signature (`XMSSSignature`, `ByteVector[2404]`).
pub type XmssSignature = FixedVector<u8, U2404>;
/// The root of a VRF tree (`VRFRoot`, `Bytes32`).
pub type VrfRoot = Hash256;

/// Leaf index at which the proof of possession is signed.
pub const PQ_POSSESSION_XMSS_INDEX: u32 = 0;

/// `FAR_FUTURE_EPOCH`, the `pq_key_change_epochs` entry of a validator that has never registered
/// keys. A validator is registered (`is_pq_registered`) exactly when its entry differs from it.
///
/// It is `ChainSpec::far_future_epoch` on every network, which is not configurable.
pub const PQ_UNREGISTERED_CHANGE_EPOCH: Epoch = Epoch::new(u64::MAX);
