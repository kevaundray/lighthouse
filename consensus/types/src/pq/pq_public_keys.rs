use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{
    fork::ForkName,
    pq::{PQ_KEYS_VERSION_UNSET, VrfRoot, XmssPublicKey},
};

/// The post-quantum keys of one validator, as stored in the registry.
///
/// The default value is the all-zero entry, of version `PQ_KEYS_VERSION_UNSET`.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Default, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
#[context_deserialize(ForkName)]
pub struct PqPublicKeys {
    /// Version of EIP-CRYPTO that the keys use, or 0 when no keys are registered.
    #[serde(with = "serde_utils::quoted_u8")]
    pub version: u8,
    /// leanXMSS public key.
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub xmss_public_key: XmssPublicKey,
    /// Root of the VRF tree.
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub vrf_root: VrfRoot,
}

impl PqPublicKeys {
    /// Returns `true` if this entry holds registered keys (`is_pq_registered`).
    pub fn is_registered(&self) -> bool {
        self.version != PQ_KEYS_VERSION_UNSET
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PqPublicKeys);

    #[test]
    fn serialized_size() {
        use ssz::Encode;
        assert_eq!(PqPublicKeys::default().as_ssz_bytes().len(), 65);
        assert!(!PqPublicKeys::default().is_registered());
    }
}
