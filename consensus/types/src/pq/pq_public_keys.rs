use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{
    fork::ForkName,
    pq::{VrfRoot, XmssPublicKey},
};

/// The post-quantum keys of one validator, as stored in the registry.
///
/// The default value is the all-zero entry, held by every validator that has never registered
/// keys. Whether a validator is registered is decided by its `pq_key_change_epochs` entry
/// (`is_pq_registered`), never by this value.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Default, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
#[context_deserialize(ForkName)]
pub struct PqPublicKeys {
    /// leanXMSS public key.
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub xmss_public_key: XmssPublicKey,
    /// Root of the VRF tree.
    pub vrf_root: VrfRoot,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PqPublicKeys);

    #[test]
    fn serialized_size() {
        use ssz::Encode;
        // 32 + 32 bytes, as stated by EIP-8450.
        assert_eq!(<PqPublicKeys as Encode>::ssz_fixed_len(), 64);
        assert_eq!(PqPublicKeys::default().as_ssz_bytes(), vec![0; 64]);
    }
}
