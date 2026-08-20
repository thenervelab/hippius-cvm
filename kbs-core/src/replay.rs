//! Anti-replay = atomic release-once state machine (ARCHITECTURE.md §7).
//!
//! Release-once is keyed STRICTLY by `(ticket_id, nonce)` — never by the
//! Vault path/version. `reserve` is atomic; `commit` durably spends. The
//! commit-BEFORE-emit ordering (at-most-once emission) is enforced by the
//! release orchestrator (§release): commit must be durable before any
//! response byte leaves the process.

use crate::error::{KbsError, Result};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReleaseKey {
    pub ticket_id: String,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Reserved,
    Spent,
}

pub trait ReleaseStore {
    /// Atomically reserve; `Err(Replay)` if already reserved or spent.
    fn reserve(&self, key: &ReleaseKey) -> Result<()>;
    /// Durably mark spent (the at-most-once commit point).
    fn commit(&self, key: &ReleaseKey) -> Result<()>;
    /// Release a reservation that never reached commit (failure path).
    fn rollback(&self, key: &ReleaseKey);
}

/// Reference in-memory store. A production store MUST be durable so a crash
/// after commit keeps the ticket/nonce spent (§7/§14).
#[derive(Default)]
pub struct InMemoryReleaseStore {
    map: Mutex<HashMap<ReleaseKey, Slot>>,
}

impl ReleaseStore for InMemoryReleaseStore {
    fn reserve(&self, key: &ReleaseKey) -> Result<()> {
        let mut g = self.map.lock().map_err(|_| KbsError::Replay)?;
        if g.contains_key(key) {
            return Err(KbsError::Replay);
        }
        g.insert(key.clone(), Slot::Reserved);
        Ok(())
    }

    fn commit(&self, key: &ReleaseKey) -> Result<()> {
        let mut g = self.map.lock().map_err(|_| KbsError::Replay)?;
        match g.get(key) {
            Some(Slot::Reserved) => {
                g.insert(key.clone(), Slot::Spent);
                Ok(())
            }
            Some(Slot::Spent) => Err(KbsError::Replay),
            None => Err(KbsError::Replay),
        }
    }

    fn rollback(&self, key: &ReleaseKey) {
        if let Ok(mut g) = self.map.lock() {
            if g.get(key) == Some(&Slot::Reserved) {
                g.remove(key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k() -> ReleaseKey {
        ReleaseKey {
            ticket_id: "tk".into(),
            nonce: vec![1, 2, 3],
        }
    }

    #[test]
    fn double_reserve_denied() {
        let s = InMemoryReleaseStore::default();
        s.reserve(&k()).unwrap();
        assert!(s.reserve(&k()).is_err());
    }

    #[test]
    fn commit_then_reserve_denied() {
        let s = InMemoryReleaseStore::default();
        s.reserve(&k()).unwrap();
        s.commit(&k()).unwrap();
        assert!(s.reserve(&k()).is_err());
        assert!(s.commit(&k()).is_err()); // no double commit
    }

    #[test]
    fn rollback_frees_only_reserved() {
        let s = InMemoryReleaseStore::default();
        s.reserve(&k()).unwrap();
        s.rollback(&k());
        s.reserve(&k()).unwrap(); // reusable after rollback (no secret emitted)
        s.commit(&k()).unwrap();
        s.rollback(&k()); // must NOT un-spend
        assert!(s.reserve(&k()).is_err());
    }
}
