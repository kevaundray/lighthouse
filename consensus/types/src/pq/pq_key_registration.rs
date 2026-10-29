use bls::SecretKey;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{
    core::{ChainSpec, Domain, Epoch, Hash256, SignedRoot},
    fork::ForkName,
    pq::{PqPublicKeys, SignedPqKeyRegistration, XmssSignature},
};

/// The message of a registration: which validator or builder, which keys, and after which change.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct PqKeyRegistration {
    /// Validator index, or builder index with `BUILDER_INDEX_FLAG` set (see `PqRegistryIndex`).
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    pub public_keys: PqPublicKeys,
    /// Epoch of the last change, or the never-registered marker of the index: `FAR_FUTURE_EPOCH`
    /// for a validator, the deposit epoch for a builder.
    pub previous_change_epoch: Epoch,
}

impl SignedRoot for PqKeyRegistration {}

impl PqKeyRegistration {
    /// Authorize the registration with the BLS signing key of the validator or builder.
    ///
    /// The domain is computed with the genesis fork version, so the signature is valid across
    /// forks.
    pub fn sign(
        self,
        possession: XmssSignature,
        secret_key: &SecretKey,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> SignedPqKeyRegistration {
        let domain = spec.compute_domain(
            Domain::PqKeyRegistration,
            spec.genesis_fork_version,
            genesis_validators_root,
        );
        let message = self.signing_root(domain);
        SignedPqKeyRegistration {
            message: self,
            possession,
            signature: secret_key.sign(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PqKeyRegistration);

    /// The index field is `index`, carrying a flagged builder index as is.
    #[test]
    fn json_field_names() {
        let index = crate::core::consts::gloas::BUILDER_INDEX_FLAG | 3;
        let registration = PqKeyRegistration {
            index,
            public_keys: PqPublicKeys::default(),
            previous_change_epoch: Epoch::new(7),
        };
        let json = serde_json::to_value(&registration).unwrap();
        let mut fields = json
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        fields.sort();
        assert_eq!(fields, ["index", "previous_change_epoch", "public_keys"]);
        assert_eq!(json["index"], index.to_string());
        assert_eq!(
            serde_json::from_value::<PqKeyRegistration>(json).unwrap(),
            registration
        );
    }
}
