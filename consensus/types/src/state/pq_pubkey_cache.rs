use rpds::HashTrieMapSync as HashTrieMap;

use crate::pq::XmssPublicKey;

/// A validator index, or a builder index with `BUILDER_INDEX_FLAG` set (`PqRegistryIndex::as_u64`).
type RegistryIndex = u64;

/// Copies a key into a fixed-size array, so map entries need no heap allocation.
fn key_bytes(xmss_public_key: &XmssPublicKey) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (byte, key_byte) in bytes.iter_mut().zip(xmss_public_key.iter()) {
        *byte = *key_byte;
    }
    bytes
}

/// Map from registered leanXMSS public keys to the index of the validator or builder that
/// registered them (EIP-8450), with builder indices flagged.
///
/// It indexes exactly the validators and builders that are registered (`is_pq_registered`):
/// those whose stored leanXMSS key is not all-zero. The all-zero key, held by every unregistered
/// validator and builder, is never indexed. Exited validators and builders keep their keys until
/// their entry is reset.
///
/// The cache is not part of consensus. It is built lazily from
/// `BeaconState::registered_pq_key_material` and then kept exact by the writers of the registry:
/// `BeaconState::set_pq_key_material`, and `BeaconState::add_builder_to_registry`, which releases
/// the key of the builder whose index it reuses. Appending validators or builders adds
/// unregistered entries only. The map is persistent, so cloning a state shares it cheaply.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct PqPubkeyCache {
    /// `false` until the map reflects the state's registry.
    initialized: bool,
    map: HashTrieMap<[u8; 32], RegistryIndex>,
}

impl PqPubkeyCache {
    /// Returns an initialized cache with no registered keys.
    pub fn new_initialized() -> Self {
        Self {
            initialized: true,
            map: HashTrieMap::new_sync(),
        }
    }

    /// Builds the cache from the keys of the registered validators and builders, by registry index,
    /// or returns `None` if two of them registered the same leanXMSS key (which a valid state never
    /// contains).
    pub fn new<'a>(
        registered_keys: impl IntoIterator<Item = (RegistryIndex, &'a XmssPublicKey)>,
    ) -> Option<Self> {
        let mut cache = Self::new_initialized();
        for (index, xmss_public_key) in registered_keys {
            if !cache.insert(xmss_public_key, index) {
                return None;
            }
        }
        Some(cache)
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the registry index of the validator or builder that registered `xmss_public_key`.
    pub fn get(&self, xmss_public_key: &XmssPublicKey) -> Option<RegistryIndex> {
        self.map.get(&key_bytes(xmss_public_key)).copied()
    }

    /// Records that `index` registered `xmss_public_key`.
    ///
    /// Returns `false` if another validator or builder already holds the key.
    pub fn insert(&mut self, xmss_public_key: &XmssPublicKey, index: RegistryIndex) -> bool {
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
    pub fn remove(&mut self, xmss_public_key: &XmssPublicKey, index: RegistryIndex) {
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

    fn key(byte: u8) -> XmssPublicKey {
        XmssPublicKey::new(vec![byte; 32]).unwrap()
    }

    #[test]
    fn build_indexes_given_keys_and_rejects_duplicates() {
        let (one, two) = (key(1), key(2));
        let cache = PqPubkeyCache::new([(0, &one), (2, &two)]).unwrap();
        assert_eq!(cache.get(&key(1)), Some(0));
        assert_eq!(cache.get(&key(2)), Some(2));
        assert_eq!(cache.get(&key(0)), None);

        assert!(PqPubkeyCache::new([(0, &one), (1, &one)]).is_none());
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
