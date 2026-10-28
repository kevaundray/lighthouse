use milhouse::ProgressiveList;
use rpds::HashTrieMapSync as HashTrieMap;

use crate::pq::{PqPublicKeys, XmssPublicKey};

type ValidatorIndex = usize;

/// Copies a key into a fixed-size array, so map entries need no heap allocation.
fn key_bytes(xmss_public_key: &XmssPublicKey) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (byte, key_byte) in bytes.iter_mut().zip(xmss_public_key.iter()) {
        *byte = *key_byte;
    }
    bytes
}

/// Map from registered leanXMSS public keys to the index of the validator that registered them
/// (EIP-8450).
///
/// The cache is not part of consensus. It is built lazily from `pq_public_keys` and then kept
/// exact by `BeaconState::set_pq_public_keys`, the only writer of registered keys. Appending
/// validators adds unset entries only, so it never invalidates the cache. The map is persistent,
/// so cloning a state shares it cheaply.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct PqPubkeyCache {
    /// `false` until the map reflects the state's `pq_public_keys`.
    initialized: bool,
    map: HashTrieMap<[u8; 32], ValidatorIndex>,
}

impl PqPubkeyCache {
    /// Returns an initialized cache with no registered keys.
    pub fn new_initialized() -> Self {
        Self {
            initialized: true,
            map: HashTrieMap::new_sync(),
        }
    }

    /// Builds the cache from the registry, or returns `None` if two validators registered the
    /// same leanXMSS key (which a valid state never contains).
    pub fn new(pq_public_keys: &ProgressiveList<PqPublicKeys>) -> Option<Self> {
        let mut cache = Self::new_initialized();
        for (index, entry) in pq_public_keys.iter().enumerate() {
            if entry.is_registered() && !cache.insert(&entry.xmss_public_key, index) {
                return None;
            }
        }
        Some(cache)
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the index of the validator that registered `xmss_public_key`.
    pub fn get(&self, xmss_public_key: &XmssPublicKey) -> Option<ValidatorIndex> {
        self.map.get(&key_bytes(xmss_public_key)).copied()
    }

    /// Records that `index` registered `xmss_public_key`.
    ///
    /// Returns `false` if another validator already holds the key.
    pub fn insert(&mut self, xmss_public_key: &XmssPublicKey, index: ValidatorIndex) -> bool {
        let key = key_bytes(xmss_public_key);
        match self.map.get(&key) {
            Some(owner) if *owner != index => false,
            _ => {
                self.map.insert_mut(key, index);
                true
            }
        }
    }

    /// Releases `xmss_public_key` if it is held by `index`.
    pub fn remove(&mut self, xmss_public_key: &XmssPublicKey, index: ValidatorIndex) {
        if self.get(xmss_public_key) == Some(index) {
            self.map.remove_mut(&key_bytes(xmss_public_key));
        }
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PqPubkeyCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq::PQ_KEYS_VERSION_1;

    fn key(byte: u8) -> XmssPublicKey {
        XmssPublicKey::new(vec![byte; 32]).unwrap()
    }

    fn entry(byte: u8) -> PqPublicKeys {
        PqPublicKeys {
            version: PQ_KEYS_VERSION_1,
            xmss_public_key: key(byte),
            vrf_root: <_>::default(),
        }
    }

    #[test]
    fn build_skips_unset_and_rejects_duplicates() {
        let list =
            ProgressiveList::try_from_iter([entry(1), PqPublicKeys::default(), entry(2)]).unwrap();
        let cache = PqPubkeyCache::new(&list).unwrap();
        assert_eq!(cache.get(&key(1)), Some(0));
        assert_eq!(cache.get(&key(2)), Some(2));
        assert_eq!(cache.get(&key(0)), None);

        let duplicates = ProgressiveList::try_from_iter([entry(1), entry(1)]).unwrap();
        assert!(PqPubkeyCache::new(&duplicates).is_none());
    }

    #[test]
    fn insert_and_remove_respect_owner() {
        let mut cache = PqPubkeyCache::new_initialized();
        assert!(cache.insert(&key(1), 3));
        assert!(cache.insert(&key(1), 3));
        assert!(!cache.insert(&key(1), 4));
        cache.remove(&key(1), 4);
        assert_eq!(cache.get(&key(1)), Some(3));
        cache.remove(&key(1), 3);
        assert_eq!(cache.get(&key(1)), None);
        assert!(cache.insert(&key(1), 4));
    }
}
