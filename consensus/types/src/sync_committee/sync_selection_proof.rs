use std::cmp;

#[cfg(not(feature = "pq-devnet"))]
use bls::{PublicKey, SecretKey};
use consensus_signature::IndividualSignature;
use ethereum_hashing::hash;
use safe_arith::{ArithError, SafeArith};
use serde::{Deserialize, Serialize};
use ssz::Encode;
use typenum::Unsigned;

use crate::core::{
    EthSpec,
    consts::altair::{SYNC_COMMITTEE_SUBNET_COUNT, TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE},
};
#[cfg(not(feature = "pq-devnet"))]
use crate::{
    core::{ChainSpec, Domain, Hash256, SignedRoot, Slot},
    fork::Fork,
    sync_committee::SyncAggregatorSelectionData,
};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SyncSelectionProof(IndividualSignature);

impl SyncSelectionProof {
    #[cfg(not(feature = "pq-devnet"))]
    pub fn new<E: EthSpec>(
        slot: Slot,
        subcommittee_index: u64,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Self {
        let domain = spec.get_domain(
            slot.epoch(E::slots_per_epoch()),
            Domain::SyncCommitteeSelectionProof,
            fork,
            genesis_validators_root,
        );
        let message = SyncAggregatorSelectionData {
            slot,
            subcommittee_index,
        }
        .signing_root(domain);

        Self(secret_key.sign(message))
    }

    /// Returns the "modulo" used for determining if a `SyncSelectionProof` elects an aggregator.
    pub fn modulo<E: EthSpec>() -> Result<u64, ArithError> {
        Ok(cmp::max(
            1,
            (E::SyncCommitteeSize::to_u64())
                .safe_div(SYNC_COMMITTEE_SUBNET_COUNT)?
                .safe_div(TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)?,
        ))
    }

    pub fn is_aggregator<E: EthSpec>(&self) -> Result<bool, ArithError> {
        self.is_aggregator_from_modulo(Self::modulo::<E>()?)
    }

    pub fn is_aggregator_from_modulo(&self, modulo: u64) -> Result<bool, ArithError> {
        let signature_hash = hash(&self.0.as_ssz_bytes());
        let signature_hash_int = u64::from_le_bytes(
            signature_hash
                .get(0..8)
                .expect("hash is 32 bytes")
                .try_into()
                .expect("first 8 bytes of signature should always convert to fixed array"),
        );

        signature_hash_int.safe_rem(modulo).map(|rem| rem == 0)
    }

    #[cfg(not(feature = "pq-devnet"))]
    pub fn verify<E: EthSpec>(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> bool {
        let domain = spec.get_domain(
            slot.epoch(E::slots_per_epoch()),
            Domain::SyncCommitteeSelectionProof,
            fork,
            genesis_validators_root,
        );
        let message = SyncAggregatorSelectionData {
            slot,
            subcommittee_index,
        }
        .signing_root(domain);

        self.0.verify(pubkey, message)
    }
}

impl From<SyncSelectionProof> for IndividualSignature {
    fn from(from: SyncSelectionProof) -> IndividualSignature {
        from.0
    }
}

impl From<IndividualSignature> for SyncSelectionProof {
    fn from(sig: IndividualSignature) -> Self {
        Self(sig)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::MainnetEthSpec;
    use eth2_interop_keypairs::keypair;
    use fixed_bytes::FixedBytesExtended;

    #[test]
    fn proof_sign_and_verify() {
        let slot = Slot::new(1000);
        let subcommittee_index = 12;
        let key = keypair(1);
        let fork = &Fork::default();
        let genesis_validators_root = Hash256::zero();
        let spec = &ChainSpec::mainnet();

        let proof = SyncSelectionProof::new::<MainnetEthSpec>(
            slot,
            subcommittee_index,
            &key.sk,
            fork,
            genesis_validators_root,
            spec,
        );
        assert!(proof.verify::<MainnetEthSpec>(
            slot,
            subcommittee_index,
            &key.pk,
            fork,
            genesis_validators_root,
            spec
        ));
    }
}
