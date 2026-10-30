//! Post-quantum consensus key registry types (EIP-8450).
//!
//! EIP-8450 specifies only the interface of its hash-based primitives (`xmss.Verify`,
//! `xmss_signature_index` and `vrf.Verify`) and the byte sizes of their values. leanXMSS
//! verification is implemented by `lean_pq`.

mod pq_key_material;
mod pq_key_possession;
mod pq_key_registration;
mod signed_pq_key_registration;

pub use pq_key_material::PqKeyMaterial;
pub use pq_key_possession::PqKeyPossession;
pub use pq_key_registration::PqKeyRegistration;
pub use signed_pq_key_registration::SignedPqKeyRegistration;

use crate::{
    builder::BuilderIndex,
    core::{Epoch, Hash256, consts::gloas::BUILDER_INDEX_FLAG},
};
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

/// `FAR_FUTURE_EPOCH`, the never-registered marker of a validator: the `pq_key_change_epochs`
/// entry of a validator that has never registered keys, whose stored leanXMSS key is all-zero.
///
/// A builder's marker is its `deposit_epoch` instead, since builder indices are reused.
///
/// It is `ChainSpec::far_future_epoch` on every network, which is not configurable.
pub const PQ_UNREGISTERED_CHANGE_EPOCH: Epoch = Epoch::new(u64::MAX);

/// The registry entry named by the `index` of a `PqKeyRegistration`: a validator index, or a
/// builder index with `BUILDER_INDEX_FLAG` set (`is_builder_index`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqRegistryIndex {
    Validator(u64),
    Builder(BuilderIndex),
}

impl PqRegistryIndex {
    /// Decodes a validator index or a flagged builder index.
    pub fn new(index: u64) -> Self {
        if index & BUILDER_INDEX_FLAG != 0 {
            Self::Builder(index & !BUILDER_INDEX_FLAG)
        } else {
            Self::Validator(index)
        }
    }

    /// The index as it appears in a registration, with `BUILDER_INDEX_FLAG` set for a builder.
    pub fn as_u64(self) -> u64 {
        match self {
            Self::Validator(index) => index,
            Self::Builder(index) => index | BUILDER_INDEX_FLAG,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_index_round_trips_the_builder_flag() {
        assert_eq!(PqRegistryIndex::new(7), PqRegistryIndex::Validator(7));
        assert_eq!(
            PqRegistryIndex::new(BUILDER_INDEX_FLAG | 7),
            PqRegistryIndex::Builder(7)
        );
        for index in [0, 7, BUILDER_INDEX_FLAG, BUILDER_INDEX_FLAG | 7] {
            assert_eq!(PqRegistryIndex::new(index).as_u64(), index);
        }
    }
}
