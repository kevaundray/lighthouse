//! Versioned allocation of stateful-signature one-time-use identifiers.

/// The number of XMSS leaves reserved for each Ethereum slot by `LeanPqDevnetV1`.
pub const LEAN_PQ_DEVNET_V1_LEAVES_PER_SLOT: u64 = 14;

/// The greatest Ethereum slot for which the full V1 duty row fits in a `u32` leaf range.
pub const LEAN_PQ_DEVNET_V1_MAX_SLOT: u64 = 306_783_377;

const MAX_SYNC_SUBCOMMITTEE_INDEX: u64 = 3;

/// A semantic validator duty that consumes one stateful-signature leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningDuty {
    RandaoReveal,
    BeaconBlockProposal,
    Attestation,
    AttestationSelectionProof,
    AggregateAndProof,
    SyncCommitteeMessage,
    SyncSelectionProof(SyncSubcommittee),
    SyncContributionAndProof(SyncSubcommittee),
}

impl SigningDuty {
    /// Constructs a sync-selection-proof duty for a V1 subcommittee.
    pub fn sync_selection_proof(subcommittee_index: u64) -> Result<Self, SigningIdError> {
        SyncSubcommittee::new(subcommittee_index).map(Self::SyncSelectionProof)
    }

    /// Constructs a sync-contribution-and-proof duty for a V1 subcommittee.
    pub fn sync_contribution_and_proof(subcommittee_index: u64) -> Result<Self, SigningIdError> {
        SyncSubcommittee::new(subcommittee_index).map(Self::SyncContributionAndProof)
    }

    fn offset(self) -> Result<u32, SigningIdError> {
        match self {
            Self::RandaoReveal => Ok(0),
            Self::BeaconBlockProposal => Ok(1),
            Self::Attestation => Ok(2),
            Self::AttestationSelectionProof => Ok(3),
            Self::AggregateAndProof => Ok(4),
            Self::SyncCommitteeMessage => Ok(5),
            Self::SyncSelectionProof(SyncSubcommittee(0)) => Ok(6),
            Self::SyncSelectionProof(SyncSubcommittee(1)) => Ok(7),
            Self::SyncSelectionProof(SyncSubcommittee(2)) => Ok(8),
            Self::SyncSelectionProof(SyncSubcommittee(3)) => Ok(9),
            Self::SyncContributionAndProof(SyncSubcommittee(0)) => Ok(10),
            Self::SyncContributionAndProof(SyncSubcommittee(1)) => Ok(11),
            Self::SyncContributionAndProof(SyncSubcommittee(2)) => Ok(12),
            Self::SyncContributionAndProof(SyncSubcommittee(3)) => Ok(13),
            Self::SyncSelectionProof(SyncSubcommittee(index))
            | Self::SyncContributionAndProof(SyncSubcommittee(index)) => Err(
                SigningIdError::UnsupportedSyncSubcommittee(u64::from(index)),
            ),
        }
    }
}

/// An index within the four sync subcommittees supported by the V1 profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncSubcommittee(u8);

impl SyncSubcommittee {
    fn new(index: u64) -> Result<Self, SigningIdError> {
        if index > MAX_SYNC_SUBCOMMITTEE_INDEX {
            return Err(SigningIdError::UnsupportedSyncSubcommittee(index));
        }

        u8::try_from(index)
            .map(Self)
            .map_err(|_| SigningIdError::UnsupportedSyncSubcommittee(index))
    }
}

/// A stateful-signature leaf identifier allocated to one semantic duty instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OneTimeUseId(u32);

impl OneTimeUseId {
    /// Allocates the V1 leaf for `duty` on `ethereum_slot`.
    pub fn for_lean_pq_devnet_v1(
        ethereum_slot: u64,
        duty: SigningDuty,
    ) -> Result<Self, SigningIdError> {
        if ethereum_slot > LEAN_PQ_DEVNET_V1_MAX_SLOT {
            return Err(SigningIdError::SlotOutOfRange(ethereum_slot));
        }

        let duty_offset = duty.offset()?;
        let leaf = ethereum_slot
            .checked_mul(LEAN_PQ_DEVNET_V1_LEAVES_PER_SLOT)
            .and_then(|base| base.checked_add(u64::from(duty_offset)))
            .and_then(|leaf| u32::try_from(leaf).ok())
            .ok_or(SigningIdError::SlotOutOfRange(ethereum_slot))?;

        Ok(Self(leaf))
    }

    /// Returns the backend leaf identifier.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// A failure to map an Ethereum duty to the frozen V1 XMSS range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningIdError {
    UnsupportedSyncSubcommittee(u64),
    SlotOutOfRange(u64),
}

impl std::fmt::Display for SigningIdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSyncSubcommittee(index) => {
                write!(formatter, "unsupported sync subcommittee index {index}")
            }
            Self::SlotOutOfRange(slot) => {
                write!(
                    formatter,
                    "Ethereum slot {slot} is outside the V1 XMSS range"
                )
            }
        }
    }
}

impl std::error::Error for SigningIdError {}
