use bls::PublicKeyBytes;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{core::SignedRoot, fork::ForkName, pq::XmssPublicKey};

/// The message of a proof of possession: a leanXMSS key, bound to the BLS public key of the
/// validator registering it.
///
/// The validator is named by its BLS public key, which never changes and is known before the
/// validator has an index. The message does not depend on the rest of the registration, so a key
/// signs it only once.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct PqKeyPossession {
    pub validator_pubkey: PublicKeyBytes,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub xmss_public_key: XmssPublicKey,
}

impl SignedRoot for PqKeyPossession {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PqKeyPossession);
}
