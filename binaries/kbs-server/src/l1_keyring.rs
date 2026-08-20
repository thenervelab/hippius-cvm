//! Config-driven L1 OrderTicket-signing keyring.
//!
//! Resolves a ticket `kid` to its Ed25519 verifying key from the
//! operator-provided `[[l1_keys]]` config table. kbs-core ships no
//! production `L1Keyring` — it is a §17 wiring seam — so this is it.
//!
//! An empty keyring is permitted: with no keys every OrderTicket fails
//! signature verification, which is the correct fail-closed posture.

use ed25519_dalek::VerifyingKey;
use kbs_core::ticket::L1Keyring;
use std::collections::HashMap;

/// In-memory `kid → VerifyingKey` map built from config. Holds only
/// public keys, so `Debug` exposes no secret material.
#[derive(Debug)]
pub struct ConfigL1Keyring {
    keys: HashMap<Vec<u8>, VerifyingKey>,
}

impl ConfigL1Keyring {
    /// Build from `(kid, verifying_key)` pairs. A duplicate `kid` is a
    /// configuration fault — fail closed.
    pub fn from_entries(entries: Vec<(Vec<u8>, VerifyingKey)>) -> Result<Self, String> {
        let mut keys = HashMap::with_capacity(entries.len());
        for (kid, vk) in entries {
            if keys.insert(kid.clone(), vk).is_some() {
                return Err(format!("duplicate L1 kid {}", hex::encode(&kid)));
            }
        }
        Ok(Self { keys })
    }

    /// Number of distinct L1 keys loaded.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// `true` when no L1 key is loaded (every ticket then fails closed).
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl L1Keyring for ConfigL1Keyring {
    fn verifying_key(&self, kid: &[u8]) -> Option<VerifyingKey> {
        self.keys.get(kid).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn vk(seed: u8) -> VerifyingKey {
        SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    #[test]
    fn resolves_known_kid_and_misses_unknown() {
        let kr = ConfigL1Keyring::from_entries(vec![(b"kid-a".to_vec(), vk(1))]).unwrap();
        assert_eq!(kr.len(), 1);
        assert!(!kr.is_empty());
        assert_eq!(kr.verifying_key(b"kid-a"), Some(vk(1)));
        assert_eq!(kr.verifying_key(b"kid-z"), None);
    }

    #[test]
    fn empty_keyring_resolves_nothing() {
        let kr = ConfigL1Keyring::from_entries(vec![]).unwrap();
        assert!(kr.is_empty());
        assert_eq!(kr.verifying_key(b"anything"), None);
    }

    #[test]
    fn duplicate_kid_is_rejected() {
        let err =
            ConfigL1Keyring::from_entries(vec![(b"dup".to_vec(), vk(1)), (b"dup".to_vec(), vk(2))])
                .expect_err("duplicate kid must fail closed");
        assert!(err.contains("duplicate"));
    }
}
