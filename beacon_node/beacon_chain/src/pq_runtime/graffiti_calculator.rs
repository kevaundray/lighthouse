use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use types::{GRAFFITI_BYTES_LEN, Graffiti};

/// Configuration-only graffiti origin retained while local block production is omitted.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum GraffitiOrigin {
    UserSpecified(Graffiti),
    Calculated(Graffiti),
}

impl GraffitiOrigin {
    pub fn graffiti(&self) -> Graffiti {
        match self {
            Self::UserSpecified(graffiti) | Self::Calculated(graffiti) => *graffiti,
        }
    }
}

impl Default for GraffitiOrigin {
    fn default() -> Self {
        let version = lighthouse_version::VERSION.as_bytes();
        let len = std::cmp::min(version.len(), GRAFFITI_BYTES_LEN);
        let mut bytes = [0; GRAFFITI_BYTES_LEN];
        bytes[..len].copy_from_slice(&version[..len]);
        Self::Calculated(Graffiti::from(bytes))
    }
}

impl Debug for GraffitiOrigin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.graffiti().fmt(formatter)
    }
}
