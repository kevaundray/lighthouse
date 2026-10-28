use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{core::SignedRoot, fork::ForkName, pq::XmssPublicKey};

/// The message of a proof of possession: which validator, and which leanXMSS key.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct PqKeyPossession {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub xmss_public_key: XmssPublicKey,
}

impl SignedRoot for PqKeyPossession {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PqKeyPossession);
}
