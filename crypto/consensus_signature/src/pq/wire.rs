const MAGIC: &[u8; 4] = b"LHPQ";
const WIRE_VERSION: u8 = 1;
const PARAMETER_SET: u8 = 1;
const RAW_EVIDENCE_KIND: u8 = 0;
const AGGREGATE_EVIDENCE_KIND: u8 = 1;
const ABSENT_EVIDENCE_KIND: u8 = 2;
const HEADER_LEN: usize = MAGIC.len() + 3;
pub(crate) const RAW_PAYLOAD_LEN: usize = 1_208;

/// Exact byte length of the V1 PQ individual-signature encoding.
pub const PQ_RAW_SIGNATURE_LEN: usize = HEADER_LEN + RAW_PAYLOAD_LEN;

/// Strict Lighthouse-owned V1 envelope for one raw XMSS signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqRawSignature(Box<[u8; PQ_RAW_SIGNATURE_LEN]>);

impl PqRawSignature {
    /// Parses only the raw individual-signature form of the V1 envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqWireError> {
        if bytes.len() < HEADER_LEN {
            return Err(PqWireError::InvalidLength {
                actual: bytes.len(),
                expected: PQ_RAW_SIGNATURE_LEN,
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
                expected: PQ_RAW_SIGNATURE_LEN,
            })?;
        if wire_version != WIRE_VERSION {
            return Err(PqWireError::UnsupportedWireVersion(wire_version));
        }
        let parameter_set =
            bytes
                .get(MAGIC.len() + 1)
                .copied()
                .ok_or(PqWireError::InvalidLength {
                    actual: bytes.len(),
                    expected: PQ_RAW_SIGNATURE_LEN,
                })?;
        if parameter_set != PARAMETER_SET {
            return Err(PqWireError::UnsupportedParameterSet(parameter_set));
        }
        let evidence_kind =
            bytes
                .get(MAGIC.len() + 2)
                .copied()
                .ok_or(PqWireError::InvalidLength {
                    actual: bytes.len(),
                    expected: PQ_RAW_SIGNATURE_LEN,
                })?;
        match evidence_kind {
            RAW_EVIDENCE_KIND => {}
            AGGREGATE_EVIDENCE_KIND | ABSENT_EVIDENCE_KIND => {
                return Err(PqWireError::WrongEvidenceKind(evidence_kind));
            }
            unsupported => return Err(PqWireError::UnsupportedEvidenceKind(unsupported)),
        }
        if bytes.len() != PQ_RAW_SIGNATURE_LEN {
            return Err(PqWireError::InvalidLength {
                actual: bytes.len(),
                expected: PQ_RAW_SIGNATURE_LEN,
            });
        }

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

    /// Returns the canonical placeholder used while constructing fixed-form objects.
    ///
    /// Its payload is structurally canonical but is not valid cryptographic evidence.
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

    pub(crate) fn backend_payload(&self) -> [u8; RAW_PAYLOAD_LEN] {
        let mut payload = [0; RAW_PAYLOAD_LEN];
        for (destination, source) in payload.iter_mut().zip(self.0.iter().skip(HEADER_LEN)) {
            *destination = *source;
        }
        payload
    }
}

/// Failure to decode an individual-signature field as the frozen V1 raw form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqWireError {
    InvalidLength { actual: usize, expected: usize },
    BadMagic,
    UnsupportedWireVersion(u8),
    UnsupportedParameterSet(u8),
    WrongEvidenceKind(u8),
    UnsupportedEvidenceKind(u8),
}

impl std::fmt::Display for PqWireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => {
                write!(
                    formatter,
                    "invalid PQ raw signature length {actual}, expected {expected}"
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
                write!(formatter, "PQ evidence kind {kind} is not a raw signature")
            }
            Self::UnsupportedEvidenceKind(kind) => {
                write!(formatter, "unsupported PQ evidence kind {kind}")
            }
        }
    }
}

impl std::error::Error for PqWireError {}
