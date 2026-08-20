//! In-memory single-use challenge store.
//!
//! Each `issue` mints a fresh 32-byte CSPRNG nonce bound to the
//! requested scope + a short expiry. `consume` atomically verifies
//! (exists, unexpired, unspent, scope-equal) and spends — so a replay
//! of the same nonce fails. State is in-memory: the broker is a single
//! confidential pod and challenges are short-lived (~30 s); a restart
//! simply invalidates outstanding challenges (the KBS re-issues),
//! which is the fail-closed direction.

use std::collections::HashMap;
use std::sync::Mutex;

use hippius_types::vault_broker::BrokerScope;
use rand::RngCore;

use crate::error::BrokerError;
use crate::redeem::ChallengeStore;

struct Entry {
    scope: BrokerScope,
    expiry_unix: u64,
    spent: bool,
}

pub struct InMemoryChallenges {
    ttl_secs: u64,
    entries: Mutex<HashMap<[u8; 32], Entry>>,
}

impl InMemoryChallenges {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl_secs,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Drop expired + spent entries so the map can't grow unbounded
    /// under a flood of un-redeemed challenges. Called opportunistically
    /// from `issue` (cheap; the map is tiny in steady state).
    fn gc(map: &mut HashMap<[u8; 32], Entry>, now_unix: u64) {
        map.retain(|_, e| !e.spent && now_unix < e.expiry_unix);
    }
}

impl ChallengeStore for InMemoryChallenges {
    fn issue(&self, scope: &BrokerScope, now_unix: u64) -> Result<([u8; 32], u64), BrokerError> {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let expiry = now_unix.saturating_add(self.ttl_secs);
        let mut map = self
            .entries
            .lock()
            .map_err(|_| BrokerError::Config("challenge lock poisoned".into()))?;
        Self::gc(&mut map, now_unix);
        // Collision is astronomically improbable with a CSPRNG; if it
        // somehow occurs, fail closed rather than overwrite a live
        // challenge.
        if map.contains_key(&nonce) {
            return Err(BrokerError::Config("nonce collision".into()));
        }
        map.insert(
            nonce,
            Entry {
                scope: scope.clone(),
                expiry_unix: expiry,
                spent: false,
            },
        );
        Ok((nonce, expiry))
    }

    fn consume(
        &self,
        nonce: &[u8; 32],
        scope: &BrokerScope,
        now_unix: u64,
    ) -> Result<(), BrokerError> {
        let mut map = self
            .entries
            .lock()
            .map_err(|_| BrokerError::Config("challenge lock poisoned".into()))?;
        let entry = map
            .get_mut(nonce)
            .ok_or_else(|| BrokerError::Challenge("unknown challenge".into()))?;
        if entry.spent {
            return Err(BrokerError::Challenge("challenge already spent".into()));
        }
        if now_unix >= entry.expiry_unix {
            return Err(BrokerError::Challenge("challenge expired".into()));
        }
        if &entry.scope != scope {
            return Err(BrokerError::Challenge(
                "challenge scope does not match redeem scope".into(),
            ));
        }
        // Spend it — replay-proof.
        entry.spent = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> BrokerScope {
        BrokerScope {
            vm_id: "vm-1".into(),
            luks_path: "k/luks".into(),
            luks_version: 1,
            userdata_path: "k/ud".into(),
            userdata_version: 1,
            lifecycle_path: None,
            lifecycle_version: None,
        }
    }

    #[test]
    fn issue_then_consume_once() {
        let c = InMemoryChallenges::new(30);
        let (n, exp) = c.issue(&scope(), 100).unwrap();
        assert!(exp > 100);
        c.consume(&n, &scope(), 110).unwrap();
        // Replay fails.
        assert!(c.consume(&n, &scope(), 110).is_err());
    }

    #[test]
    fn consume_rejects_unknown_expired_and_scope_swap() {
        let c = InMemoryChallenges::new(30);
        // Unknown.
        assert!(c.consume(&[0u8; 32], &scope(), 100).is_err());
        // Expired.
        let (n, _) = c.issue(&scope(), 100).unwrap();
        assert!(c.consume(&n, &scope(), 1_000).is_err());
        // Scope swap.
        let (n2, _) = c.issue(&scope(), 100).unwrap();
        let mut other = scope();
        other.vm_id = "vm-evil".into();
        assert!(c.consume(&n2, &other, 110).is_err());
    }

    #[test]
    fn issued_nonces_are_unique() {
        let c = InMemoryChallenges::new(30);
        let (a, _) = c.issue(&scope(), 100).unwrap();
        let (b, _) = c.issue(&scope(), 100).unwrap();
        assert_ne!(a, b);
    }
}
