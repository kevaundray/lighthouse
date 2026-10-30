use crate::OpPoolError;
use crate::OperationPool;
use crate::attestation_storage::AttestationMap;
use crate::bls_to_execution_changes::{BlsToExecutionChanges, ReceivedPreCapella};
use crate::pq_key_registrations::{PqKeyRegistrations, max_pool_len};
use crate::sync_aggregate_id::SyncAggregateId;
use educe::Educe;
use parking_lot::RwLock;
use ssz::{BYTES_PER_LENGTH_OFFSET, Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::SigVerifiedOp;
use std::collections::HashSet;
use std::mem;
use store::{DBColumn, Error as StoreError, StoreItem};
use superstruct::superstruct;
use tracing::warn;
use types::attestation::AttestationOnDisk;
use types::*;

type PersistedSyncContributions<E> = Vec<(SyncAggregateId, Vec<SyncCommitteeContribution<E>>)>;

/// SSZ-serializable version of `OperationPool`.
///
/// Operations are stored in arbitrary order, so it's not a good idea to compare instances
/// of this type (or its encoded form) for equality. Convert back to an `OperationPool` first.
#[superstruct(
    variants(V15, V20, V33),
    variant_attributes(derive(Educe, PartialEq, Debug, Encode, Decode), educe(Clone),),
    partial_getter_error(ty = "OpPoolError", expr = "OpPoolError::IncorrectOpPoolVariant")
)]
#[derive(PartialEq, Debug, Encode)]
#[ssz(enum_behaviour = "transparent")]
pub struct PersistedOperationPool<E: EthSpec> {
    #[superstruct(only(V15))]
    pub attestations_v15: Vec<(AttestationBase<E>, Vec<u64>)>,
    /// Attestations and their attesting indices.
    #[superstruct(only(V20, V33))]
    pub attestations: Vec<(AttestationOnDisk<E>, Vec<u64>)>,
    /// Mapping from sync contribution ID to sync contributions and aggregate.
    pub sync_contributions: PersistedSyncContributions<E>,
    #[superstruct(only(V15))]
    pub attester_slashings_v15: Vec<SigVerifiedOp<AttesterSlashingBase<E>, E>>,
    /// Attester slashings.
    #[superstruct(only(V20, V33))]
    pub attester_slashings: Vec<SigVerifiedOp<AttesterSlashing<E>, E>>,
    /// Proposer slashings with fork information.
    pub proposer_slashings: Vec<SigVerifiedOp<ProposerSlashing, E>>,
    /// Voluntary exits with fork information.
    pub voluntary_exits: Vec<SigVerifiedOp<SignedVoluntaryExit, E>>,
    /// BLS to Execution Changes
    pub bls_to_execution_changes: Vec<SigVerifiedOp<SignedBlsToExecutionChange, E>>,
    /// Validator indices with BLS to Execution Changes to be broadcast at the
    /// Capella fork.
    pub capella_bls_change_broadcast_indices: Vec<u64>,
    /// Verified post-quantum key registrations (EIP-8450), oldest first.
    #[superstruct(only(V33))]
    pub pq_key_registrations: Vec<SignedPqKeyRegistration>,
}

impl<E: EthSpec> PersistedOperationPool<E> {
    /// Convert an `OperationPool` into serializable form.
    pub fn from_operation_pool(operation_pool: &OperationPool<E>) -> Self {
        let attestations = operation_pool
            .attestations
            .read()
            .iter()
            .map(|att| {
                (
                    AttestationOnDisk::from(att.clone_as_attestation()),
                    att.indexed.attesting_indices().clone(),
                )
            })
            .collect();

        let sync_contributions = operation_pool
            .sync_contributions
            .read()
            .iter()
            .map(|(id, contribution)| (id.clone(), contribution.clone()))
            .collect();

        let attester_slashings = operation_pool
            .attester_slashings
            .read()
            .iter()
            .cloned()
            .collect();

        let proposer_slashings = operation_pool
            .proposer_slashings
            .read()
            .values()
            .cloned()
            .collect();

        let voluntary_exits = operation_pool
            .voluntary_exits
            .read()
            .values()
            .cloned()
            .collect();

        let bls_to_execution_changes = operation_pool
            .bls_to_execution_changes
            .read()
            .iter_fifo()
            .map(|bls_to_execution_change| (**bls_to_execution_change).clone())
            .collect();

        let capella_bls_change_broadcast_indices = operation_pool
            .bls_to_execution_changes
            .read()
            .iter_pre_capella_indices()
            .copied()
            .collect();

        let pq_key_registrations = operation_pool
            .pq_key_registrations
            .read()
            .iter_fifo()
            .cloned()
            .collect();

        PersistedOperationPool::V33(PersistedOperationPoolV33 {
            attestations,
            sync_contributions,
            attester_slashings,
            proposer_slashings,
            voluntary_exits,
            bls_to_execution_changes,
            capella_bls_change_broadcast_indices,
            pq_key_registrations,
        })
    }

    /// Reconstruct an `OperationPool`.
    pub fn into_operation_pool(mut self) -> Result<OperationPool<E>, OpPoolError> {
        let attester_slashings = match &self {
            PersistedOperationPool::V15(pool_v15) => RwLock::new(
                pool_v15
                    .attester_slashings_v15
                    .iter()
                    .map(|slashing| slashing.clone().into())
                    .collect(),
            ),
            PersistedOperationPool::V20(_) | PersistedOperationPool::V33(_) => {
                RwLock::new(self.attester_slashings()?.iter().cloned().collect())
            }
        };

        let proposer_slashings = RwLock::new(
            self.proposer_slashings()
                .iter()
                .cloned()
                .map(|slashing| (slashing.as_inner().proposer_index(), slashing))
                .collect(),
        );
        let voluntary_exits = RwLock::new(
            self.voluntary_exits()
                .iter()
                .cloned()
                .map(|exit| (exit.as_inner().message.validator_index, exit))
                .collect(),
        );
        let sync_contributions = RwLock::new(self.sync_contributions().iter().cloned().collect());
        let attestations = match &self {
            PersistedOperationPool::V15(pool_v15) => {
                let mut map = AttestationMap::default();
                for (att, attesting_indices) in
                    pool_v15
                        .attestations_v15
                        .iter()
                        .map(|(att, attesting_indices)| {
                            (Attestation::Base(att.clone()), attesting_indices.clone())
                        })
                {
                    map.insert(att, attesting_indices);
                }
                RwLock::new(map)
            }
            PersistedOperationPool::V20(_) | PersistedOperationPool::V33(_) => {
                let mut map = AttestationMap::default();
                for (att, attesting_indices) in
                    self.attestations()?.iter().map(|(att, attesting_indices)| {
                        (
                            AttestationRef::from(att.to_ref()).clone_as_attestation(),
                            attesting_indices.clone(),
                        )
                    })
                {
                    map.insert(att, attesting_indices);
                }
                RwLock::new(map)
            }
        };

        let mut bls_to_execution_changes = BlsToExecutionChanges::default();
        let persisted_changes = mem::take(self.bls_to_execution_changes_mut());
        let broadcast_indices: HashSet<_> =
            mem::take(self.capella_bls_change_broadcast_indices_mut())
                .into_iter()
                .collect();

        for bls_to_execution_change in persisted_changes {
            let received_pre_capella = if broadcast_indices
                .contains(&bls_to_execution_change.as_inner().message.validator_index)
            {
                ReceivedPreCapella::Yes
            } else {
                ReceivedPreCapella::No
            };
            bls_to_execution_changes.insert(bls_to_execution_change, received_pre_capella);
        }

        let mut pq_key_registrations = PqKeyRegistrations::default();
        if let Ok(persisted_registrations) = self.pq_key_registrations_mut() {
            for registration in mem::take(persisted_registrations) {
                pq_key_registrations.insert(registration, max_pool_len::<E>());
            }
        }

        let op_pool = OperationPool {
            attestations,
            sync_contributions,
            attester_slashings,
            proposer_slashings,
            voluntary_exits,
            bls_to_execution_changes: RwLock::new(bls_to_execution_changes),
            pq_key_registrations: RwLock::new(pq_key_registrations),
            payload_attestations: Default::default(),
            reward_cache: Default::default(),
            _phantom: Default::default(),
        };
        Ok(op_pool)
    }
}

impl<E: EthSpec> StoreItem for PersistedOperationPoolV15<E> {
    fn db_column() -> DBColumn {
        DBColumn::OpPool
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        PersistedOperationPoolV15::from_ssz_bytes(bytes).map_err(Into::into)
    }
}

impl<E: EthSpec> StoreItem for PersistedOperationPoolV20<E> {
    fn db_column() -> DBColumn {
        DBColumn::OpPool
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        PersistedOperationPoolV20::from_ssz_bytes(bytes).map_err(Into::into)
    }
}

impl<E: EthSpec> StoreItem for PersistedOperationPoolV33<E> {
    fn db_column() -> DBColumn {
        DBColumn::OpPool
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        PersistedOperationPoolV33::from_ssz_bytes(bytes).map_err(Into::into)
    }
}

/// The length of the fixed part of `PersistedOperationPoolV20`: an offset for each of its 7
/// variable-length fields.
const V20_FIXED_LEN: usize = 7 * BYTES_PER_LENGTH_OFFSET;
/// The length of the fixed part of `PersistedOperationPoolV33`: an offset for each of its 8
/// variable-length fields.
const V33_FIXED_LEN: usize = 8 * BYTES_PER_LENGTH_OFFSET;

/// `PersistedOperationPoolV33` with its post-quantum key registrations left as raw bytes, so that
/// a list in a pre-release layout can be dropped without losing the rest of the pool.
#[derive(Decode)]
struct PersistedOperationPoolV33RawPq<E: EthSpec> {
    attestations: Vec<(AttestationOnDisk<E>, Vec<u64>)>,
    sync_contributions: PersistedSyncContributions<E>,
    attester_slashings: Vec<SigVerifiedOp<AttesterSlashing<E>, E>>,
    proposer_slashings: Vec<SigVerifiedOp<ProposerSlashing, E>>,
    voluntary_exits: Vec<SigVerifiedOp<SignedVoluntaryExit, E>>,
    bls_to_execution_changes: Vec<SigVerifiedOp<SignedBlsToExecutionChange, E>>,
    capella_bls_change_broadcast_indices: Vec<u64>,
    pq_key_registrations: Vec<u8>,
}

/// Decode a `PersistedOperationPoolV33`. If its post-quantum key registrations do not decode
/// (e.g. they were written by a pre-release layout), they are dropped with a warning and the
/// rest of the pool is kept.
fn decode_v33<E: EthSpec>(bytes: &[u8]) -> Result<PersistedOperationPoolV33<E>, DecodeError> {
    let raw = PersistedOperationPoolV33RawPq::<E>::from_ssz_bytes(bytes)?;
    let pq_key_registrations = Vec::<SignedPqKeyRegistration>::from_ssz_bytes(
        &raw.pq_key_registrations,
    )
    .unwrap_or_else(|error| {
        warn!(
            ?error,
            "Dropping persisted PQ key registrations that do not decode"
        );
        vec![]
    });
    Ok(PersistedOperationPoolV33 {
        attestations: raw.attestations,
        sync_contributions: raw.sync_contributions,
        attester_slashings: raw.attester_slashings,
        proposer_slashings: raw.proposer_slashings,
        voluntary_exits: raw.voluntary_exits,
        bls_to_execution_changes: raw.bls_to_execution_changes,
        capella_bls_change_broadcast_indices: raw.capella_bls_change_broadcast_indices,
        pq_key_registrations,
    })
}

/// Deserialization for `PersistedOperationPool` decodes `PersistedOperationPool::V33`, or
/// `PersistedOperationPool::V20` for pools written before EIP-8450, and reports the decoding error
/// of the layout that was stored.
///
/// Every field of both layouts is variable-length, so the first SSZ offset equals the length of
/// the fixed part, which tells the layouts apart: `V20_FIXED_LEN` or `V33_FIXED_LEN`.
impl<E: EthSpec> StoreItem for PersistedOperationPool<E> {
    fn db_column() -> DBColumn {
        DBColumn::OpPool
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let pool = match ssz::read_offset(bytes)? {
            V33_FIXED_LEN => decode_v33(bytes).map(Self::V33),
            V20_FIXED_LEN => PersistedOperationPoolV20::from_ssz_bytes(bytes).map(Self::V20),
            first_offset => Err(DecodeError::BytesInvalid(format!(
                "unknown persisted op pool layout with first offset {first_offset}"
            ))),
        };
        pool.map_err(Into::into)
    }
}
