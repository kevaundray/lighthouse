use crate::{ChainSpec, EthSpec};
use consensus_signature::{PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN, PQ_RAW_SIGNATURE_LEN};

pub const PQ_SIGNED_BLOCK_FIXED_ALLOWANCE_BYTES: usize = 1024 * 1024;
const GOSSIP_FRAMING_ALLOWANCE_BYTES: usize = 1024;
const MIN_GOSSIP_TRANSMIT_BYTES: usize = 1024 * 1024;

/// One checked size contract for PQ signed blocks across HTTP and gossipsub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqSignedBlockSizeLimits {
    max_ssz_bytes: usize,
    max_json_bytes: usize,
    max_compressed_bytes: usize,
    max_transmit_bytes: usize,
}

impl PqSignedBlockSizeLimits {
    pub fn checked<E: EthSpec>(spec: &ChainSpec) -> Option<Self> {
        let payload_bytes = usize::try_from(spec.max_payload_size).ok()?;
        let attestation_evidence_bytes =
            E::max_attestations_electra().checked_mul(PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN)?;
        let individual_signature_bytes = 2usize.checked_mul(PQ_RAW_SIGNATURE_LEN)?;
        let max_ssz_bytes = payload_bytes
            .checked_add(attestation_evidence_bytes)?
            .checked_add(individual_signature_bytes)?
            .checked_add(PQ_SIGNED_BLOCK_FIXED_ALLOWANCE_BYTES)?;
        let max_json_bytes = max_ssz_bytes
            .checked_mul(2)?
            .checked_add(PQ_SIGNED_BLOCK_FIXED_ALLOWANCE_BYTES)?;
        let max_compressed_bytes = 32usize
            .checked_add(max_ssz_bytes)?
            .checked_add(max_ssz_bytes.checked_div(6)?)?;
        let max_transmit_bytes = max_compressed_bytes
            .checked_add(GOSSIP_FRAMING_ALLOWANCE_BYTES)?
            .max(MIN_GOSSIP_TRANSMIT_BYTES);
        Some(Self {
            max_ssz_bytes,
            max_json_bytes,
            max_compressed_bytes,
            max_transmit_bytes,
        })
    }

    pub const fn max_ssz_bytes(self) -> usize {
        self.max_ssz_bytes
    }

    pub const fn max_json_bytes(self) -> usize {
        self.max_json_bytes
    }

    pub const fn max_compressed_bytes(self) -> usize {
        self.max_compressed_bytes
    }

    pub const fn max_transmit_bytes(self) -> usize {
        self.max_transmit_bytes
    }
}
