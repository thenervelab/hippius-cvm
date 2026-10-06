//! Per-guest cap on concurrent relay connections.
//!
//! The listener's global [`super::MAX_INFLIGHT_GUEST_CONNS`] semaphore
//! bounds the host's task count, but on its own one guest could hold
//! every permit — opening connections faster than the idle timeout
//! reaps them — and shut every other tenant on the host out of the
//! relay. A CVM is untrusted toward its neighbours, so each source CID
//! also gets a small fixed share: [`super::MAX_CONNS_PER_GUEST`].
//!
//! The source CID of an AF_VSOCK connection is stamped by the host
//! kernel from the guest's virtio device, so a guest cannot spread its
//! connections across CIDs to dodge the cap.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// Counts in-flight connections per source CID against a fixed cap.
#[derive(Debug)]
pub struct PerCidLimiter {
    cap: usize,
    inflight: Mutex<HashMap<u32, usize>>,
}

/// One held slot for a CID — released when dropped.
#[derive(Debug)]
pub struct PerCidPermit {
    limiter: Arc<PerCidLimiter>,
    cid: u32,
}

impl PerCidLimiter {
    /// A limiter allowing at most `cap` concurrent connections per CID.
    pub fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            cap,
            inflight: Mutex::new(HashMap::new()),
        })
    }

    /// Take a slot for `cid`, or `None` when that CID is already at
    /// the cap.
    pub fn try_acquire(self: &Arc<Self>, cid: u32) -> Option<PerCidPermit> {
        let mut inflight = self.lock();
        let count = inflight.entry(cid).or_insert(0);
        if *count >= self.cap {
            return None;
        }
        *count += 1;
        Some(PerCidPermit {
            limiter: Arc::clone(self),
            cid,
        })
    }

    /// In-flight connections currently held for `cid`.
    pub fn inflight(&self, cid: u32) -> usize {
        self.lock().get(&cid).copied().unwrap_or(0)
    }

    /// The map only holds counters, each updated in one step, so a
    /// poisoned lock still guards a consistent map — recover it rather
    /// than wedge the accept loop.
    fn lock(&self) -> MutexGuard<'_, HashMap<u32, usize>> {
        self.inflight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for PerCidPermit {
    fn drop(&mut self) {
        let mut inflight = self.limiter.lock();
        if let Some(count) = inflight.get_mut(&self.cid) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inflight.remove(&self.cid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cid_is_refused_beyond_its_cap() {
        let limiter = PerCidLimiter::new(2);
        let a = limiter.try_acquire(5).unwrap();
        let _b = limiter.try_acquire(5).unwrap();
        assert!(
            limiter.try_acquire(5).is_none(),
            "a third concurrent connection from the same CID is refused"
        );
        drop(a);
        assert!(
            limiter.try_acquire(5).is_some(),
            "a released slot is reusable"
        );
    }

    #[test]
    fn one_cid_at_its_cap_does_not_block_another() {
        let limiter = PerCidLimiter::new(2);
        let _held: Vec<_> = (0..2).map(|_| limiter.try_acquire(5).unwrap()).collect();
        assert!(limiter.try_acquire(5).is_none());
        assert!(
            limiter.try_acquire(6).is_some(),
            "a neighbour guest still gets a connection"
        );
    }

    #[test]
    fn dropping_every_permit_clears_the_entry() {
        let limiter = PerCidLimiter::new(4);
        let permits: Vec<_> = (0..3).map(|_| limiter.try_acquire(9).unwrap()).collect();
        assert_eq!(limiter.inflight(9), 3);
        drop(permits);
        assert_eq!(limiter.inflight(9), 0);
        assert!(limiter.lock().is_empty(), "no stale per-CID entries remain");
    }
}
