use bls::PublicKeyBytes;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{core::SignedRoot, fork::ForkName, pq::XmssPublicKey};

/// The message of a proof of possession: a leanXMSS key, bound to the BLS public key of the
/// validator or builder registering it.
///
/// The validator or builder is named by its BLS public key, which never changes and is known
/// before it has an index. The message does not depend on the rest of the registration, so a key
/// signs it only once.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct PqKeyPossession {
    pub pubkey: PublicKeyBytes,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub xmss_public_key: XmssPublicKey,
}

impl SignedRoot for PqKeyPossession {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PqKeyPossession);

    #[test]
    fn json_field_names() {
        let possession = PqKeyPossession {
            pubkey: PublicKeyBytes::empty(),
            xmss_public_key: XmssPublicKey::default(),
        };
        let json = serde_json::to_value(&possession).unwrap();
        let mut fields = json
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        fields.sort();
        assert_eq!(fields, ["pubkey", "xmss_public_key"]);
        assert_eq!(
            serde_json::from_value::<PqKeyPossession>(json).unwrap(),
            possession
        );
    }
}
