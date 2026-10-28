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

/// The message of a registration: which validator, which keys, and after which change.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct PqKeyRegistration {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub public_keys: PqPublicKeys,
    /// Epoch of the validator's last change, or `FAR_FUTURE_EPOCH` if it has never registered.
    pub previous_change_epoch: Epoch,
}

impl SignedRoot for PqKeyRegistration {}

impl PqKeyRegistration {
    /// Authorize the registration with the validator's BLS signing key.
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
}
