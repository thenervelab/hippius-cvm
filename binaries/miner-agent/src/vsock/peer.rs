//! Per-CVM AF_VSOCK identity — context-id allocation + the CID → VmId
//! map the relay routes on (MA-4).
//!
//! ## Why a free-slot allocator, not a hash
//!
//! A guest CVM is reached over AF_VSOCK by a **context id** (CID). The
//! miner-agent assigns each tenant CVM a CID, pins it in the libvirt
//! `<vsock>` device, and — when that guest connects back — uses the
//! connection's source CID to recover *which* tenant it is.
//!
//! A tempting allocation is `cid = base + hash(vm_id) % range`. It is
//! rejected: two distinct `vm_id`s can hash to the same CID, and a
//! collision would silently route one tenant's relayed traffic under
//! the other tenant's identity — a cross-tenant confusion. [`CidAllocator`]
//! instead hands out the **lowest free CID** and records the mapping,
//! so:
//!
//! - **collision-free by construction** — a CID in use is never handed
//!   out again until released;
//! - **deterministic per `vm_id`** — [`CidAllocator::allocate`] is
//!   idempotent: a re-`allocate` of a `vm_id` that already holds a CID
//!   returns the *same* CID, so a retried launch is stable;
//! - **fail-closed** — an exhausted range returns an error and the
//!   launch aborts, rather than wrapping or colliding.
//!
//! CIDs `0`/`1`/`2` are reserved by the AF_VSOCK ABI (hypervisor /
//! local / host); guest CIDs start at [`MIN_GUEST_CID`].

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::error::{MinerAgentError, Result};
use crate::lifecycle::VmId;

/// Lowest CID assignable to a guest. `0` (hypervisor), `1` (local) and
/// `2` (host) are reserved by the AF_VSOCK ABI.
pub const MIN_GUEST_CID: u32 = 3;

/// Highest CID the allocator hands out. The range `3..=65535` is far
/// larger than the CVM count any single miner host runs, while keeping
/// an exhausted-range failure a bounded, testable condition rather
/// than a `u32`-wide scan.
pub const MAX_GUEST_CID: u32 = 65_535;

/// One connected tenant guest, as the relay sees it: the AF_VSOCK
/// context id the connection arrived on, resolved to the tenant
/// [`VmId`] the miner-agent assigned that CID at launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestPeer {
    /// The connection's source AF_VSOCK context id.
    pub cid: u32,
    /// The tenant CVM that CID belongs to.
    pub vm_id: VmId,
}

/// State behind the allocator lock — the two directions of the map.
#[derive(Default)]
struct CidState {
    /// `vm_id → cid` — makes [`CidAllocator::allocate`] idempotent.
    by_vm: HashMap<VmId, u32>,
    /// `cid → vm_id` — the relay's reverse lookup.
    by_cid: HashMap<u32, VmId>,
    /// CIDs the KERNEL has bound but this allocator did NOT hand out —
    /// e.g. an ORPHAN qemu that survived a `virsh destroy`/agent restart
    /// still holds `/dev/vhost-vsock` for its guest-cid. The allocator's
    /// in-memory view then diverges from reality and it can hand out a
    /// CID libvirt refuses with `failed to set guest cid: Address already
    /// in use`. When a launch hits that, [`CidAllocator::burn_and_realloc`]
    /// records the bad CID here so the scan skips it for the rest of this
    /// process lifetime. Cleared on nothing (a restart re-derives it).
    burned: HashSet<u32>,
    /// CIDs held on the word of a miner-local record the live domain XML
    /// has not yet confirmed (a re-adoption whose `dumpxml` failed). The
    /// mapping is kept so nobody else is handed the CID, but it is NOT an
    /// identity: [`CidAllocator::vm_id_for_cid`] does not resolve it, and
    /// [`CidAllocator::owner_of`] reports it as [`CidOwner::Unverified`].
    unverified: HashSet<u32>,
    /// Freshly allocated CIDs whose launch has not yet created the domain
    /// (see [`CidAllocator::allocate`]). Not an identity yet — lookups treat
    /// them like `unverified` — but, unlike a stale record, never proven
    /// wrong either: releasing one FREES it (a collision with an orphan
    /// surfaces at `create_domain`, which burns it there).
    pending_create: HashSet<u32>,
}

/// Who a CID belongs to, as far as the allocator can vouch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidOwner {
    /// Assigned at launch, or confirmed against the live domain XML.
    Verified(VmId),
    /// Reserved for this VM from a record the live XML has not confirmed:
    /// the guest behind the CID may be someone else. Hold, don't act.
    Unverified(VmId),
    /// Nobody.
    Unknown,
}

/// Allocates and tracks AF_VSOCK context ids for tenant CVMs.
///
/// Shared (`Arc`) between the [`crate::lifecycle::CvmLifecycle`] (which
/// allocates a CID per launch and releases it on stop / destroy) and
/// the vsock relay listener (which resolves an inbound connection's
/// CID back to a `VmId`).
pub struct CidAllocator {
    /// Inclusive lowest assignable CID.
    min: u32,
    /// Inclusive highest assignable CID.
    max: u32,
    state: Mutex<CidState>,
}

impl CidAllocator {
    /// An allocator over the production guest-CID range
    /// (`MIN_GUEST_CID..=MAX_GUEST_CID`).
    pub fn new() -> Self {
        Self::with_range(MIN_GUEST_CID, MAX_GUEST_CID)
    }

    /// An allocator over an explicit inclusive `[min, max]` range —
    /// tests use a tiny range to exercise the exhausted-range path.
    pub fn with_range(min: u32, max: u32) -> Self {
        Self {
            min,
            max,
            state: Mutex::new(CidState::default()),
        }
    }

    /// Assign a CID to `vm_id`, or return the one it already holds.
    ///
    /// A NEWLY assigned CID is held pending-create — [`CidOwner::Unverified`]
    /// to every lookup — until the
    /// launch's `create_domain` succeeds and marks it verified: until the
    /// kernel has bound it to this guest, an orphan qemu the allocator never
    /// tracked may still own it, and its frames must not be attributed to
    /// the launching tenant.
    ///
    /// Idempotent: a second `allocate` for a `vm_id` that is already
    /// mapped returns the same CID — a retried launch keeps a stable
    /// AF_VSOCK identity. Fail-closed (`VsockCid("exhausted")`) when no
    /// CID in the range is free.
    pub fn allocate(&self, vm_id: &VmId) -> Result<u32> {
        let mut state = self.lock()?;
        if let Some(&cid) = state.by_vm.get(vm_id) {
            return Ok(cid);
        }
        // Lowest free CID in range, skipping any `burned` by a prior
        // kernel-collision. The range is small and a launch is rare, so a
        // linear scan is well within budget.
        let cid = (self.min..=self.max)
            .find(|c| !state.by_cid.contains_key(c) && !state.burned.contains(c))
            .ok_or(MinerAgentError::VsockCid("exhausted"))?;
        state.by_vm.insert(vm_id.clone(), cid);
        state.by_cid.insert(cid, vm_id.clone());
        state.pending_create.insert(cid);
        Ok(cid)
    }

    /// Recover from a `failed to set guest cid: Address already in use`
    /// at domain-create: the kernel already has `bad_cid` bound (an orphan
    /// qemu the allocator never tracked). BURN `bad_cid` so it is never
    /// handed out again this process lifetime, drop `vm_id`'s mapping to
    /// it, and allocate a FRESH CID for the same vm. Returns the new CID.
    ///
    /// Fail-closed `VsockCid("exhausted")` if no non-burned CID remains.
    pub fn burn_and_realloc(&self, vm_id: &VmId, bad_cid: u32) -> Result<u32> {
        let mut state = self.lock()?;
        // Burn + release the bad CID's mapping (only if this vm held it).
        state.burned.insert(bad_cid);
        if state.by_vm.get(vm_id) == Some(&bad_cid) {
            state.by_vm.remove(vm_id);
        }
        if state.by_cid.get(&bad_cid) == Some(vm_id) {
            state.by_cid.remove(&bad_cid);
            state.unverified.remove(&bad_cid);
            state.pending_create.remove(&bad_cid);
        }
        // Fresh lowest free non-burned CID — unverified until created, like
        // any fresh allocation.
        let cid = (self.min..=self.max)
            .find(|c| !state.by_cid.contains_key(c) && !state.burned.contains(c))
            .ok_or(MinerAgentError::VsockCid("exhausted"))?;
        state.by_vm.insert(vm_id.clone(), cid);
        state.by_cid.insert(cid, vm_id.clone());
        state.pending_create.insert(cid);
        Ok(cid)
    }

    /// Release the CID held by `vm_id`, if any. Idempotent — releasing
    /// a `vm_id` that holds no CID is a no-op success.
    ///
    /// An UNVERIFIED CID is burned, not freed: it came from a record the
    /// live XML never confirmed, so stopping `vm_id` proves nothing about
    /// which guest — if any — the kernel gave it to.
    pub fn release(&self, vm_id: &VmId) -> Result<()> {
        let mut state = self.lock()?;
        if let Some(cid) = state.by_vm.remove(vm_id) {
            state.by_cid.remove(&cid);
            state.pending_create.remove(&cid);
            if state.unverified.remove(&cid) {
                state.burned.insert(cid);
            }
        }
        Ok(())
    }

    /// Reserve a SPECIFIC `cid` for `vm_id` — startup re-adoption of a
    /// CVM whose CID was assigned in a PRIOR agent lifetime (the domain
    /// survived a `skip_shutdown_teardown` restart). Unlike `allocate`,
    /// which hands out the lowest free CID, this pins the exact CID the
    /// running guest already uses so the vsock relay routes correctly.
    ///
    /// Idempotent when `vm_id` already holds exactly `cid`. Fail-closed:
    /// `reserve-out-of-range` if `cid` is outside `[min, max]`,
    /// `reserve-collision` if a DIFFERENT vm holds it, `reserve-vm-remap`
    /// if `vm_id` already holds a different CID.
    pub fn reserve(&self, vm_id: &VmId, cid: u32) -> Result<()> {
        if cid < self.min || cid > self.max {
            return Err(MinerAgentError::VsockCid("reserve-out-of-range"));
        }
        let mut state = self.lock()?;
        match state.by_cid.get(&cid) {
            Some(existing) if existing == vm_id => return Ok(()),
            Some(_) => return Err(MinerAgentError::VsockCid("reserve-collision")),
            None => {}
        }
        if let Some(&held) = state.by_vm.get(vm_id) {
            if held != cid {
                return Err(MinerAgentError::VsockCid("reserve-vm-remap"));
            }
        }
        state.by_vm.insert(vm_id.clone(), cid);
        state.by_cid.insert(cid, vm_id.clone());
        Ok(())
    }

    /// [`Self::reserve`], but the CID comes from a record the live domain
    /// XML could not confirm: hold it for `vm_id` (so it is never handed
    /// out) without vouching that `vm_id`'s guest is the one behind it.
    /// See [`CidOwner::Unverified`].
    pub fn reserve_unverified(&self, vm_id: &VmId, cid: u32) -> Result<()> {
        self.reserve(vm_id, cid)?;
        self.lock()?.unverified.insert(cid);
        Ok(())
    }

    /// The live domain XML confirmed `vm_id` runs on `cid`. Returns false
    /// (no change) unless `vm_id` holds exactly `cid`.
    pub fn mark_verified(&self, vm_id: &VmId, cid: u32) -> Result<bool> {
        let mut state = self.lock()?;
        if state.by_cid.get(&cid) != Some(vm_id) {
            return Ok(false);
        }
        state.unverified.remove(&cid);
        state.pending_create.remove(&cid);
        Ok(true)
    }

    /// The live domain XML says `vm_id` runs on `live`, not the `held`
    /// CID its record claimed: move the mapping to `live`, verified, and
    /// BURN `held` for the rest of this process lifetime.
    ///
    /// `live` may be BURNED (a launch collided with it while the record was
    /// wrong — the "orphan" that held it was this very guest); the XML is
    /// ground truth, so it is un-burned. Fail-closed `rekey-collision` if a
    /// DIFFERENT vm holds `live` — two records claiming one kernel CID is
    /// not something to resolve by guessing.
    pub fn rekey_verified(&self, vm_id: &VmId, held: u32, live: u32) -> Result<()> {
        if live < self.min || live > self.max {
            return Err(MinerAgentError::VsockCid("rekey-out-of-range"));
        }
        let mut state = self.lock()?;
        if state.by_vm.get(vm_id) != Some(&held) {
            return Err(MinerAgentError::VsockCid("rekey-not-held"));
        }
        if state.by_cid.get(&live).is_some_and(|owner| owner != vm_id) {
            return Err(MinerAgentError::VsockCid("rekey-collision"));
        }
        // `held` came from a record just proven WRONG — that proves nothing
        // about who (if anyone) the kernel gave it to. Burn it rather than
        // free it: a leaked CID is harmless, a reused one that a live guest
        // still holds is a cross-tenant attribution.
        state.by_cid.remove(&held);
        state.unverified.remove(&held);
        state.burned.insert(held);
        // `live` is bound to THIS guest (the caller observed the domain
        // running with it), so any earlier collision burn of it was this
        // guest too.
        state.burned.remove(&live);
        state.by_vm.insert(vm_id.clone(), live);
        state.by_cid.insert(live, vm_id.clone());
        state.unverified.remove(&live);
        Ok(())
    }

    /// Who `cid` belongs to — distinguishing a verified owner from one
    /// held on an unconfirmed record.
    pub fn owner_of(&self, cid: u32) -> Result<CidOwner> {
        let state = self.lock()?;
        Ok(match state.by_cid.get(&cid) {
            Some(vm) if state.unverified.contains(&cid) || state.pending_create.contains(&cid) => {
                CidOwner::Unverified(vm.clone())
            }
            Some(vm) => CidOwner::Verified(vm.clone()),
            None => CidOwner::Unknown,
        })
    }

    /// Resolve an inbound connection's source CID to the tenant CVM it
    /// belongs to. `Ok(None)` — a CID the allocator never handed out, or
    /// one held [`CidOwner::Unverified`] — is the relay's signal to reject
    /// the connection: an unconfirmed record is not an identity.
    pub fn vm_id_for_cid(&self, cid: u32) -> Result<Option<VmId>> {
        Ok(match self.owner_of(cid)? {
            CidOwner::Verified(vm) => Some(vm),
            CidOwner::Unverified(_) | CidOwner::Unknown => None,
        })
    }

    /// The CID currently assigned to `vm_id`, if any.
    pub fn cid_for_vm(&self, vm_id: &VmId) -> Result<Option<u32>> {
        Ok(self.lock()?.by_vm.get(vm_id).copied())
    }

    /// Lock the state, mapping a poisoned lock to a fail-closed error
    /// rather than panicking — the same discipline as `CvmLifecycle`.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, CidState>> {
        self.state.lock().map_err(|_| MinerAgentError::LockPoisoned)
    }
}

impl Default for CidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(id: &str) -> VmId {
        VmId::new(id).unwrap()
    }

    #[test]
    fn allocate_is_idempotent_per_vm_id() {
        let alloc = CidAllocator::new();
        let first = alloc.allocate(&vm("tenant-a")).unwrap();
        let again = alloc.allocate(&vm("tenant-a")).unwrap();
        assert_eq!(first, again, "same vm_id must keep the same CID");
    }

    #[test]
    fn distinct_vms_never_collide() {
        let alloc = CidAllocator::new();
        let a = alloc.allocate(&vm("tenant-a")).unwrap();
        let b = alloc.allocate(&vm("tenant-b")).unwrap();
        let c = alloc.allocate(&vm("tenant-c")).unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn allocation_starts_at_min_guest_cid() {
        // The first guest CID is MIN_GUEST_CID — 0/1/2 are ABI-reserved.
        let alloc = CidAllocator::new();
        assert_eq!(alloc.allocate(&vm("tenant-a")).unwrap(), MIN_GUEST_CID);
    }

    #[test]
    fn reverse_lookup_resolves_an_allocated_cid_once_created() {
        let alloc = CidAllocator::new();
        let cid = alloc.allocate(&vm("tenant-x")).unwrap();
        assert!(alloc.mark_verified(&vm("tenant-x"), cid).unwrap());
        assert_eq!(alloc.vm_id_for_cid(cid).unwrap(), Some(vm("tenant-x")));
    }

    #[test]
    fn a_fresh_cid_is_not_an_identity_until_its_domain_is_created() {
        // Until `create_domain` binds it, an orphan qemu the allocator never
        // tracked may own this CID — its frames must not be attributed to the
        // launching tenant (#1148).
        let alloc = CidAllocator::new();
        let cid = alloc.allocate(&vm("tenant-x")).unwrap();
        assert_eq!(alloc.vm_id_for_cid(cid).unwrap(), None);
        assert_eq!(
            alloc.owner_of(cid).unwrap(),
            CidOwner::Unverified(vm("tenant-x"))
        );
        let fresh = alloc.burn_and_realloc(&vm("tenant-x"), cid).unwrap();
        assert_eq!(
            alloc.vm_id_for_cid(fresh).unwrap(),
            None,
            "a re-allocation too"
        );
    }

    #[test]
    fn a_never_created_cid_is_freed_not_burned() {
        // A launch that failed before `create_domain` proved nothing bad
        // about its CID (unlike a stale re-adoption record, which burns).
        let alloc = CidAllocator::with_range(3, 3);
        let cid = alloc.allocate(&vm("tenant-a")).unwrap();
        alloc.release(&vm("tenant-a")).unwrap();
        assert_eq!(alloc.allocate(&vm("tenant-b")).unwrap(), cid);
    }

    #[test]
    fn unknown_cid_resolves_to_none() {
        let alloc = CidAllocator::new();
        alloc.allocate(&vm("tenant-x")).unwrap();
        assert_eq!(alloc.vm_id_for_cid(9999).unwrap(), None);
    }

    #[test]
    fn release_frees_the_cid_for_reuse() {
        let alloc = CidAllocator::new();
        let cid = alloc.allocate(&vm("tenant-a")).unwrap();
        alloc.release(&vm("tenant-a")).unwrap();
        assert_eq!(alloc.vm_id_for_cid(cid).unwrap(), None);
        // The freed slot is the lowest free CID again.
        assert_eq!(alloc.allocate(&vm("tenant-b")).unwrap(), cid);
    }

    #[test]
    fn release_is_idempotent() {
        let alloc = CidAllocator::new();
        alloc.release(&vm("never-allocated")).unwrap();
        alloc.allocate(&vm("tenant-a")).unwrap();
        alloc.release(&vm("tenant-a")).unwrap();
        alloc.release(&vm("tenant-a")).unwrap();
    }

    #[test]
    fn burn_and_realloc_skips_the_bad_cid_forever() {
        // vm-a gets the lowest CID (min). A create-collision on it burns
        // it + hands vm-a the NEXT CID; the burned CID is never reused,
        // even by a later vm.
        let alloc = CidAllocator::with_range(3, 5);
        let first = alloc.allocate(&vm("tenant-a")).unwrap();
        assert_eq!(first, 3);
        let fresh = alloc.burn_and_realloc(&vm("tenant-a"), first).unwrap();
        assert_eq!(fresh, 4, "realloc hands out the next free CID");
        // vm-a now maps to 4, not the burned 3.
        assert_eq!(alloc.cid_for_vm(&vm("tenant-a")).unwrap(), Some(4));
        assert_eq!(alloc.vm_id_for_cid(3).unwrap(), None);
        // A new vm skips the burned 3 → gets 5, never 3.
        assert_eq!(alloc.allocate(&vm("tenant-b")).unwrap(), 5);
        // Range exhausted (3 burned, 4+5 held) — fail-closed.
        assert!(matches!(
            alloc.allocate(&vm("tenant-c")),
            Err(MinerAgentError::VsockCid("exhausted"))
        ));
    }

    #[test]
    fn burn_and_realloc_exhausts_when_only_the_bad_cid_remained() {
        let alloc = CidAllocator::with_range(3, 3);
        let cid = alloc.allocate(&vm("tenant-a")).unwrap();
        // Burning the only CID leaves nothing to hand back.
        assert!(matches!(
            alloc.burn_and_realloc(&vm("tenant-a"), cid),
            Err(MinerAgentError::VsockCid("exhausted"))
        ));
    }

    #[test]
    fn exhausted_range_fails_closed() {
        // A range of exactly one CID: the second distinct vm_id fails.
        let alloc = CidAllocator::with_range(3, 3);
        assert_eq!(alloc.allocate(&vm("tenant-a")).unwrap(), 3);
        assert!(matches!(
            alloc.allocate(&vm("tenant-b")),
            Err(MinerAgentError::VsockCid("exhausted"))
        ));
        // The already-allocated vm_id still resolves (idempotent).
        assert_eq!(alloc.allocate(&vm("tenant-a")).unwrap(), 3);
    }

    #[test]
    fn reserve_pins_a_specific_cid_and_fails_closed_on_conflict() {
        let alloc = CidAllocator::new();
        // Re-adoption reserves the exact CID the running guest already uses.
        alloc.reserve(&vm("tenant-a"), 7).unwrap();
        assert_eq!(alloc.cid_for_vm(&vm("tenant-a")).unwrap(), Some(7));
        assert_eq!(alloc.vm_id_for_cid(7).unwrap(), Some(vm("tenant-a")));
        // Idempotent for the same (vm, cid).
        alloc.reserve(&vm("tenant-a"), 7).unwrap();
        // A DIFFERENT vm cannot take a held CID.
        assert!(matches!(
            alloc.reserve(&vm("tenant-b"), 7),
            Err(MinerAgentError::VsockCid("reserve-collision"))
        ));
        // A subsequent `allocate` skips the reserved CID.
        let other = alloc.allocate(&vm("tenant-c")).unwrap();
        assert_ne!(other, 7);
    }

    #[test]
    fn reserve_rejects_out_of_range_and_vm_remap() {
        let alloc = CidAllocator::with_range(3, 5);
        assert!(matches!(
            alloc.reserve(&vm("tenant-a"), 99),
            Err(MinerAgentError::VsockCid("reserve-out-of-range"))
        ));
        alloc.reserve(&vm("tenant-a"), 4).unwrap();
        // The same vm cannot be remapped to a different CID.
        assert!(matches!(
            alloc.reserve(&vm("tenant-a"), 5),
            Err(MinerAgentError::VsockCid("reserve-vm-remap"))
        ));
    }

    #[test]
    fn an_unverified_cid_is_held_but_is_not_an_identity() {
        let alloc = CidAllocator::with_range(3, 4);
        alloc.reserve_unverified(&vm("tenant-a"), 3).unwrap();
        // Not an identity: the relay's lookup does not resolve it…
        assert_eq!(alloc.vm_id_for_cid(3).unwrap(), None);
        assert_eq!(
            alloc.owner_of(3).unwrap(),
            CidOwner::Unverified(vm("tenant-a"))
        );
        // …but it is HELD: nobody else is handed it.
        assert_eq!(alloc.allocate(&vm("tenant-b")).unwrap(), 4);
        assert!(alloc.allocate(&vm("tenant-c")).is_err());
    }

    #[test]
    fn mark_verified_turns_a_held_cid_into_an_identity() {
        let alloc = CidAllocator::new();
        alloc.reserve_unverified(&vm("tenant-a"), 7).unwrap();
        assert!(!alloc.mark_verified(&vm("tenant-b"), 7).unwrap(), "not b's");
        assert_eq!(alloc.vm_id_for_cid(7).unwrap(), None);
        assert!(alloc.mark_verified(&vm("tenant-a"), 7).unwrap());
        assert_eq!(alloc.vm_id_for_cid(7).unwrap(), Some(vm("tenant-a")));
    }

    #[test]
    fn rekey_moves_to_the_live_cid_and_burns_the_recorded_one() {
        let alloc = CidAllocator::with_range(7, 10);
        alloc.reserve_unverified(&vm("tenant-a"), 7).unwrap();
        alloc.rekey_verified(&vm("tenant-a"), 7, 9).unwrap();
        assert_eq!(alloc.vm_id_for_cid(9).unwrap(), Some(vm("tenant-a")));
        assert_eq!(alloc.owner_of(7).unwrap(), CidOwner::Unknown);
        assert_eq!(alloc.cid_for_vm(&vm("tenant-a")).unwrap(), Some(9));
        // 7 was never proven free — a live guest may hold it. Never reuse.
        assert_eq!(alloc.allocate(&vm("tenant-b")).unwrap(), 8);
        assert_eq!(alloc.allocate(&vm("tenant-c")).unwrap(), 10);
        assert!(alloc.allocate(&vm("tenant-d")).is_err());
    }

    #[test]
    fn rekey_refuses_a_cid_another_vm_holds() {
        let alloc = CidAllocator::new();
        alloc.reserve_unverified(&vm("tenant-a"), 7).unwrap();
        alloc.reserve(&vm("tenant-b"), 9).unwrap();
        assert!(alloc.rekey_verified(&vm("tenant-a"), 7, 9).is_err());
        assert_eq!(alloc.vm_id_for_cid(9).unwrap(), Some(vm("tenant-b")));
        assert_eq!(
            alloc.owner_of(7).unwrap(),
            CidOwner::Unverified(vm("tenant-a"))
        );
    }

    #[test]
    fn releasing_an_unverified_cid_burns_it() {
        // Never proven to be tenant-a's — another live guest may hold it.
        let alloc = CidAllocator::with_range(3, 4);
        alloc.reserve_unverified(&vm("tenant-a"), 3).unwrap();
        alloc.release(&vm("tenant-a")).unwrap();
        assert_eq!(alloc.owner_of(3).unwrap(), CidOwner::Unknown);
        assert_eq!(alloc.allocate(&vm("tenant-b")).unwrap(), 4);
        assert!(alloc.allocate(&vm("tenant-c")).is_err());
    }

    #[test]
    fn releasing_a_verified_cid_frees_it() {
        let alloc = CidAllocator::with_range(3, 3);
        alloc.reserve_unverified(&vm("tenant-a"), 3).unwrap();
        alloc.mark_verified(&vm("tenant-a"), 3).unwrap();
        alloc.release(&vm("tenant-a")).unwrap();
        assert_eq!(alloc.allocate(&vm("tenant-b")).unwrap(), 3);
    }
}
