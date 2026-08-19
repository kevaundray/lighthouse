use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use tree_hash::TreeHash;

const MAGIC: &[u8; 4] = b"LHPQ";
const WIRE_VERSION: u8 = 1;
const PARAMETER_SET: u8 = 1;
const RAW_EVIDENCE_KIND: u8 = 0;
const AGGREGATE_EVIDENCE_KIND: u8 = 1;
const ABSENT_EVIDENCE_KIND: u8 = 2;
const HEADER_LEN: usize = MAGIC.len() + 3;
pub(crate) const RAW_PAYLOAD_LEN: usize = 1_208;
#[cfg(feature = "pq-devnet")]
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub(crate) const PQ_EVIDENCE_HEADER_LEN: usize = HEADER_LEN;

/// Exact byte length of a V1 PQ validator public key.
pub const PQ_PUBLIC_KEY_LEN: usize = 32;
/// Prime-field modulus used by the pinned V1 XMSS public-key encoding.
const PQ_PUBLIC_KEY_FIELD_MODULUS: u32 = 0x7f00_0001;
/// Exact byte length of the V1 PQ individual-signature encoding.
pub const PQ_RAW_SIGNATURE_LEN: usize = HEADER_LEN + RAW_PAYLOAD_LEN;
/// Maximum encoded byte length of V1 same-message evidence.
pub const PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN: usize = 512 * 1024;

/// A canonically encoded public key for the pinned V1 PQ parameter set.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PqPublicKey([u8; PQ_PUBLIC_KEY_LEN]);

impl PqPublicKey {
    /// Returns the canonical zero placeholder.
    pub const fn empty() -> Self {
        Self([0; PQ_PUBLIC_KEY_LEN])
    }

    /// Parses a public key after checking its exact byte length.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PqWireError> {
        let bytes =
            <[u8; PQ_PUBLIC_KEY_LEN]>::try_from(bytes).map_err(|_| PqWireError::InvalidLength {
                actual: bytes.len(),
                expected: PQ_PUBLIC_KEY_LEN,
            })?;
        if !public_key_bytes_are_canonical(&bytes) {
            return Err(PqWireError::NonCanonicalPublicKey);
        }
        Ok(Self(bytes))
    }

    /// Returns the fixed public-key bytes.
    pub const fn serialize(&self) -> [u8; PQ_PUBLIC_KEY_LEN] {
        self.0
    }

    /// Returns the fixed public-key bytes without copying.
    pub const fn as_serialized(&self) -> &[u8; PQ_PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Returns the canonical lower-case, `0x`-prefixed encoding.
    pub fn as_hex_string(&self) -> String {
        self.to_string()
    }

    #[cfg(all(feature = "pq-devnet", test))]
    pub(crate) const fn from_backend_bytes(bytes: [u8; PQ_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    #[cfg(feature = "pq-devnet")]
    pub(crate) const fn backend_bytes(&self) -> [u8; PQ_PUBLIC_KEY_LEN] {
        self.0
    }
}

/// Strict Lighthouse-owned V1 envelope for one raw XMSS signature.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PqRawSignature(Box<[u8; PQ_RAW_SIGNATURE_LEN]>);

/// Serialized form used to carry an individual signature across HTTP.
pub type SerializedIndividualSignature = PqRawSignature;

/// Serializes an individual signature without changing the strict PQ envelope.
pub fn serialize_individual_signature(signature: &PqRawSignature) -> SerializedIndividualSignature {
    signature.clone()
}

/// Decodes the already strictly parsed HTTP transport form into an individual signature.
pub fn decode_individual_signature(
    signature: &SerializedIndividualSignature,
) -> Result<PqRawSignature, crate::IndividualSignatureTransportError> {
    Ok(signature.clone())
}

/// PQ has no signature value that authorizes skipping RANDAO verification.
pub const fn is_verification_skip_placeholder(_signature: &PqRawSignature) -> bool {
    false
}

impl PqRawSignature {
    /// Parses only the raw individual-signature form of the V1 envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqWireError> {
        if bytes.len() != PQ_RAW_SIGNATURE_LEN {
            return Err(PqWireError::InvalidLength {
                actual: bytes.len(),
                expected: PQ_RAW_SIGNATURE_LEN,
            });
        }
        validate_header(bytes, RAW_EVIDENCE_KIND)?;
        let bytes = <[u8; PQ_RAW_SIGNATURE_LEN]>::try_from(bytes).map_err(|_| {
            PqWireError::InvalidLength {
                actual: bytes.len(),
                expected: PQ_RAW_SIGNATURE_LEN,
            }
        })?;
        Ok(Self(Box::new(bytes)))
    }

    /// Returns the exact V1 wire bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns a copy of the exact V1 wire bytes.
    pub fn serialize(&self) -> [u8; PQ_RAW_SIGNATURE_LEN] {
        *self.0
    }

    /// Returns the canonical non-verifying construction placeholder.
    pub fn empty() -> Self {
        Self::from_backend_payload([0; RAW_PAYLOAD_LEN])
    }

    pub(crate) fn from_backend_payload(payload: [u8; RAW_PAYLOAD_LEN]) -> Self {
        let mut bytes = [0; PQ_RAW_SIGNATURE_LEN];
        for (destination, source) in bytes.iter_mut().zip(b"LHPQ\x01\x01\x00") {
            *destination = *source;
        }
        for (destination, source) in bytes.iter_mut().skip(HEADER_LEN).zip(payload) {
            *destination = source;
        }
        Self(Box::new(bytes))
    }

    #[cfg(feature = "pq-devnet")]
    pub(crate) fn backend_payload(&self) -> [u8; RAW_PAYLOAD_LEN] {
        let mut payload = [0; RAW_PAYLOAD_LEN];
        for (destination, source) in payload.iter_mut().zip(self.0.iter().skip(HEADER_LEN)) {
            *destination = *source;
        }
        payload
    }
}

/// Bounded V1 evidence for one claim signed by zero, one, or multiple validators.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PqSameMessageEvidence(Vec<u8>);

impl PqSameMessageEvidence {
    /// Parses a structurally valid bounded V1 envelope.
    ///
    /// Aggregate payload bytes remain opaque here. Contextual proof validation belongs to the
    /// aggregate-verification boundary.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqWireError> {
        if bytes.len() > PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN {
            return Err(PqWireError::EvidenceTooLarge {
                actual: bytes.len(),
                max: PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN,
            });
        }
        validate_common_header(bytes)?;
        let evidence_kind =
            bytes
                .get(MAGIC.len() + 2)
                .copied()
                .ok_or(PqWireError::InvalidLength {
                    actual: bytes.len(),
                    expected: HEADER_LEN,
                })?;
        match evidence_kind {
            RAW_EVIDENCE_KIND => {
                PqRawSignature::from_bytes(bytes)?;
            }
            AGGREGATE_EVIDENCE_KIND if bytes.len() == HEADER_LEN => {
                return Err(PqWireError::InvalidAggregateLength(bytes.len()));
            }
            AGGREGATE_EVIDENCE_KIND => {}
            ABSENT_EVIDENCE_KIND if bytes.len() != HEADER_LEN => {
                return Err(PqWireError::InvalidAbsentLength(bytes.len()));
            }
            ABSENT_EVIDENCE_KIND => {}
            unsupported => return Err(PqWireError::UnsupportedEvidenceKind(unsupported)),
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Returns the canonical absent envelope.
    pub fn empty() -> Self {
        Self(b"LHPQ\x01\x01\x02".to_vec())
    }

    /// Returns the exact V1 envelope bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns true only for the canonical absent envelope.
    pub fn is_empty(&self) -> bool {
        self.0.as_slice() == b"LHPQ\x01\x01\x02"
    }

    /// Wraps a complete, already-validated upstream aggregate envelope.
    ///
    /// This is crate-private so locally generated aggregate evidence can only originate from the
    /// opaque backend signature returned by the owned prover.
    #[cfg(feature = "pq-devnet")]
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    pub(crate) fn from_backend_aggregate_envelope(envelope: Vec<u8>) -> Self {
        let mut bytes = Vec::with_capacity(HEADER_LEN.saturating_add(envelope.len()));
        bytes.extend_from_slice(b"LHPQ\x01\x01\x01");
        bytes.extend(envelope);
        Self(bytes)
    }

    /// Returns the opaque aggregate payload after requiring the aggregate outer kind.
    #[cfg(feature = "pq-devnet")]
    pub(crate) fn backend_aggregate_envelope(&self) -> Result<&[u8], PqWireError> {
        match self.0.get(MAGIC.len() + 2).copied() {
            Some(AGGREGATE_EVIDENCE_KIND) => self
                .0
                .get(HEADER_LEN..)
                .ok_or(PqWireError::InvalidAggregateLength(self.0.len())),
            Some(kind) => Err(PqWireError::WrongEvidenceKind(kind)),
            None => Err(PqWireError::InvalidLength {
                actual: self.0.len(),
                expected: HEADER_LEN,
            }),
        }
    }
}

impl From<&PqRawSignature> for PqSameMessageEvidence {
    fn from(signature: &PqRawSignature) -> Self {
        Self(signature.as_bytes().to_vec())
    }
}

/// Failure to decode a PQ consensus-signature wire value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqWireError {
    InvalidLength { actual: usize, expected: usize },
    EvidenceTooLarge { actual: usize, max: usize },
    BadMagic,
    UnsupportedWireVersion(u8),
    UnsupportedParameterSet(u8),
    WrongEvidenceKind(u8),
    UnsupportedEvidenceKind(u8),
    InvalidAggregateLength(usize),
    InvalidAbsentLength(usize),
    MissingHexPrefix,
    NonCanonicalHex,
    NonCanonicalPublicKey,
    InvalidHex,
}

impl fmt::Display for PqWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => {
                write!(
                    formatter,
                    "invalid PQ wire length {actual}, expected {expected}"
                )
            }
            Self::EvidenceTooLarge { actual, max } => {
                write!(
                    formatter,
                    "PQ evidence length {actual} exceeds maximum {max}"
                )
            }
            Self::BadMagic => formatter.write_str("invalid PQ evidence magic"),
            Self::UnsupportedWireVersion(version) => {
                write!(formatter, "unsupported PQ wire version {version}")
            }
            Self::UnsupportedParameterSet(parameter_set) => {
                write!(formatter, "unsupported PQ parameter set {parameter_set}")
            }
            Self::WrongEvidenceKind(kind) => {
                write!(formatter, "unexpected PQ evidence kind {kind}")
            }
            Self::UnsupportedEvidenceKind(kind) => {
                write!(formatter, "unsupported PQ evidence kind {kind}")
            }
            Self::InvalidAggregateLength(length) => {
                write!(formatter, "invalid PQ aggregate evidence length {length}")
            }
            Self::InvalidAbsentLength(length) => {
                write!(formatter, "invalid PQ absent evidence length {length}")
            }
            Self::MissingHexPrefix => formatter.write_str("PQ hex string must start with 0x"),
            Self::NonCanonicalHex => formatter.write_str("PQ hex string must use lowercase digits"),
            Self::NonCanonicalPublicKey => {
                formatter.write_str("PQ public key contains a non-canonical field element")
            }
            Self::InvalidHex => formatter.write_str("invalid PQ hex string"),
        }
    }
}

fn public_key_bytes_are_canonical(bytes: &[u8; PQ_PUBLIC_KEY_LEN]) -> bool {
    bytes.chunks_exact(4).all(|chunk| {
        <[u8; 4]>::try_from(chunk)
            .map(u32::from_le_bytes)
            .is_ok_and(|value| value < PQ_PUBLIC_KEY_FIELD_MODULUS)
    })
}

impl std::error::Error for PqWireError {}

fn validate_common_header(bytes: &[u8]) -> Result<(), PqWireError> {
    if bytes.len() < HEADER_LEN {
        return Err(PqWireError::InvalidLength {
            actual: bytes.len(),
            expected: HEADER_LEN,
        });
    }
    if bytes.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(PqWireError::BadMagic);
    }
    let wire_version = bytes
        .get(MAGIC.len())
        .copied()
        .ok_or(PqWireError::InvalidLength {
            actual: bytes.len(),
            expected: HEADER_LEN,
        })?;
    if wire_version != WIRE_VERSION {
        return Err(PqWireError::UnsupportedWireVersion(wire_version));
    }
    let parameter_set = bytes
        .get(MAGIC.len() + 1)
        .copied()
        .ok_or(PqWireError::InvalidLength {
            actual: bytes.len(),
            expected: HEADER_LEN,
        })?;
    if parameter_set != PARAMETER_SET {
        return Err(PqWireError::UnsupportedParameterSet(parameter_set));
    }
    Ok(())
}

fn validate_header(bytes: &[u8], expected_kind: u8) -> Result<(), PqWireError> {
    validate_common_header(bytes)?;
    let actual_kind = bytes
        .get(MAGIC.len() + 2)
        .copied()
        .ok_or(PqWireError::InvalidLength {
            actual: bytes.len(),
            expected: HEADER_LEN,
        })?;
    if actual_kind == expected_kind {
        Ok(())
    } else if matches!(
        actual_kind,
        RAW_EVIDENCE_KIND | AGGREGATE_EVIDENCE_KIND | ABSENT_EVIDENCE_KIND
    ) {
        Err(PqWireError::WrongEvidenceKind(actual_kind))
    } else {
        Err(PqWireError::UnsupportedEvidenceKind(actual_kind))
    }
}

#[derive(Clone, Copy)]
enum HexLength {
    Exact(usize),
    AtMost(usize),
}

fn decode_canonical_hex(value: &str, length: HexLength) -> Result<Vec<u8>, PqWireError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or(PqWireError::MissingHexPrefix)?;
    if !digits.len().is_multiple_of(2) {
        return Err(PqWireError::InvalidHex);
    }
    let byte_length = digits.len() / 2;
    match length {
        HexLength::Exact(expected) if byte_length != expected => {
            return Err(PqWireError::InvalidLength {
                actual: byte_length,
                expected,
            });
        }
        HexLength::AtMost(max) if byte_length > max => {
            return Err(PqWireError::EvidenceTooLarge {
                actual: byte_length,
                max,
            });
        }
        HexLength::Exact(_) | HexLength::AtMost(_) => {}
    }
    if digits.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(PqWireError::NonCanonicalHex);
    }
    hex::decode(digits).map_err(|_| PqWireError::InvalidHex)
}

fn deserialize_canonical_hex<'de, D, T>(
    deserializer: D,
    length: HexLength,
    parse: fn(&[u8]) -> Result<T, PqWireError>,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    struct CanonicalHexVisitor<T> {
        length: HexLength,
        parse: fn(&[u8]) -> Result<T, PqWireError>,
    }

    impl<'de, T> serde::de::Visitor<'de> for CanonicalHexVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a canonical lower-case 0x-prefixed PQ wire value")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let bytes = decode_canonical_hex(value, self.length).map_err(E::custom)?;
            (self.parse)(&bytes).map_err(E::custom)
        }
    }

    deserializer.deserialize_str(CanonicalHexVisitor { length, parse })
}

macro_rules! impl_fixed_ssz {
    ($type:ty, $len:expr, $bytes_method:ident, $parse:path) => {
        impl ssz::Encode for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }
            fn ssz_fixed_len() -> usize {
                $len
            }
            fn ssz_bytes_len(&self) -> usize {
                $len
            }
            fn ssz_append(&self, buffer: &mut Vec<u8>) {
                buffer.extend_from_slice(self.$bytes_method());
            }
        }

        impl ssz::Decode for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }
            fn ssz_fixed_len() -> usize {
                $len
            }
            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
                $parse(bytes).map_err(|error| ssz::DecodeError::BytesInvalid(error.to_string()))
            }
        }
    };
}

impl_fixed_ssz!(
    PqPublicKey,
    PQ_PUBLIC_KEY_LEN,
    as_serialized,
    PqPublicKey::deserialize
);
impl_fixed_ssz!(
    PqRawSignature,
    PQ_RAW_SIGNATURE_LEN,
    as_bytes,
    PqRawSignature::from_bytes
);

impl ssz::Encode for PqSameMessageEvidence {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_bytes_len(&self) -> usize {
        self.0.len()
    }
    fn ssz_append(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.0);
    }
}

impl ssz::Decode for PqSameMessageEvidence {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Self::from_bytes(bytes).map_err(|error| ssz::DecodeError::BytesInvalid(error.to_string()))
    }
}

macro_rules! impl_vector_tree_hash {
    ($type:ty, $len:expr, $bytes_method:ident) => {
        impl TreeHash for $type {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                tree_hash::TreeHashType::Vector
            }
            fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
                unreachable!("vector is not packed")
            }
            fn tree_hash_packing_factor() -> usize {
                unreachable!("vector is not packed")
            }
            fn tree_hash_root(&self) -> tree_hash::Hash256 {
                tree_hash::merkle_root(
                    self.$bytes_method(),
                    $len.div_ceil(tree_hash::BYTES_PER_CHUNK),
                )
            }
        }
    };
}

impl_vector_tree_hash!(PqPublicKey, PQ_PUBLIC_KEY_LEN, as_serialized);
impl_vector_tree_hash!(PqRawSignature, PQ_RAW_SIGNATURE_LEN, as_bytes);

impl TreeHash for PqSameMessageEvidence {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::List
    }
    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("list is not packed")
    }
    fn tree_hash_packing_factor() -> usize {
        unreachable!("list is not packed")
    }
    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        let limit = PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN.div_ceil(tree_hash::BYTES_PER_CHUNK);
        let root = tree_hash::merkle_root(&self.0, limit);
        tree_hash::mix_in_length(&root, self.0.len())
    }
}

macro_rules! impl_hex_traits {
    ($type:ty, $bytes_method:ident, $parse:path, $length:expr) => {
        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&serde_utils::hex::encode(self.$bytes_method()))
            }
        }
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, formatter)
            }
        }
        impl FromStr for $type {
            type Err = PqWireError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                $parse(&decode_canonical_hex(value, $length)?)
            }
        }
        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_string())
            }
        }
        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserialize_canonical_hex(deserializer, $length, $parse)
            }
        }
    };
}

impl_hex_traits!(
    PqPublicKey,
    as_serialized,
    PqPublicKey::deserialize,
    HexLength::Exact(PQ_PUBLIC_KEY_LEN)
);
impl_hex_traits!(
    PqRawSignature,
    as_bytes,
    PqRawSignature::from_bytes,
    HexLength::Exact(PQ_RAW_SIGNATURE_LEN)
);
impl_hex_traits!(
    PqSameMessageEvidence,
    as_bytes,
    PqSameMessageEvidence::from_bytes,
    HexLength::AtMost(PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN)
);

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for PqPublicKey {
    fn arbitrary(unstructured: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut bytes: [u8; PQ_PUBLIC_KEY_LEN] = unstructured.arbitrary()?;
        for chunk in bytes.chunks_exact_mut(4) {
            let word = <[u8; 4]>::try_from(&*chunk)
                .map(u32::from_le_bytes)
                .map_err(|_| arbitrary::Error::IncorrectFormat)?;
            chunk.copy_from_slice(&(word % PQ_PUBLIC_KEY_FIELD_MODULUS).to_le_bytes());
        }
        Ok(Self(bytes))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for PqRawSignature {
    fn arbitrary(unstructured: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let payload = unstructured.arbitrary()?;
        Ok(Self::from_backend_payload(payload))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for PqSameMessageEvidence {
    fn arbitrary(unstructured: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match unstructured.int_in_range(0..=2)? {
            0 => Ok(Self::empty()),
            1 => Ok(Self::from(&PqRawSignature::arbitrary(unstructured)?)),
            _ => {
                let available = unstructured
                    .len()
                    .min(PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN - HEADER_LEN);
                let payload_len = if available == 0 {
                    1
                } else {
                    unstructured.int_in_range(1..=available)?
                };
                let mut bytes = Vec::with_capacity(HEADER_LEN + payload_len);
                bytes.extend_from_slice(b"LHPQ\x01\x01\x01");
                if available == 0 {
                    bytes.push(0);
                } else {
                    bytes.extend_from_slice(unstructured.bytes(payload_len)?);
                }
                Ok(Self(bytes))
            }
        }
    }
}
