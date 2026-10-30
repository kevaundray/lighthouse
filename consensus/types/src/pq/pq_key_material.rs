use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{
    fork::ForkName,
    pq::{VrfRoot, XmssPublicKey},
};

/// The post-quantum key material of one validator or builder, as stored in the registry.
///
/// The default value is the all-zero entry, held by every validator and builder that has never
/// registered keys. An entry is registered (`is_pq_registered`) exactly when its leanXMSS key is
/// not all-zero: a registration never carries the all-zero key.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Default, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
#[context_deserialize(ForkName)]
pub struct PqKeyMaterial {
    /// leanXMSS public key.
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub xmss_public_key: XmssPublicKey,
    /// Root of the VRF tree, or zero for a builder.
    pub vrf_root: VrfRoot,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PqKeyMaterial);

    #[test]
    fn serialized_size() {
        use ssz::Encode;
        // 32 + 32 bytes, as stated by EIP-8450.
        assert_eq!(<PqKeyMaterial as Encode>::ssz_fixed_len(), 64);
        assert_eq!(PqKeyMaterial::default().as_ssz_bytes(), vec![0; 64]);
    }
}
