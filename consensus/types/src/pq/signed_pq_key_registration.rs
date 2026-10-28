use bls::Signature;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{
    fork::ForkName,
    pq::{PqKeyRegistration, XmssSignature},
};

/// A registration as it appears in a beacon block.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct SignedPqKeyRegistration {
    /// Validator, keys, and last change being registered. The BLS signature signs it.
    pub message: PqKeyRegistration,
    /// Signature of the validator index and leanXMSS key by that key, at leaf index 0.
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub possession: XmssSignature,
    /// Signature of the registration by the validator's BLS signing key.
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedPqKeyRegistration);

    #[test]
    fn serialized_size() {
        use ssz::Encode;
        // 8 + 65 + 8 + 2404 + 96 bytes, as stated by EIP-8450.
        assert_eq!(<SignedPqKeyRegistration as Encode>::ssz_fixed_len(), 2581);
    }
}
