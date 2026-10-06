//! Per-VM monotonic boot counter — Phase 1 of audit follow-up
//! Review #2 (LUKS + dm-integrity is not anti-rollback).
//!
//! The threat: dm-integrity hmac-sha256 prevents a miner from inventing
//! NEW valid plaintext sectors, but it does NOT prevent replaying OLD
//! valid ciphertext for the same LUKS volume. A miner can snapshot the
//! qcow2 after boot N, let the tenant write to disk for boots N+1..M,
//! then restore the snapshot — the guest boots, cryptsetup unlocks
//! (the KEK is unchanged), and the tenant sees data from boot N.
//!
//! Phase 1 (this module) adds the AUDIT/SERVER groundwork:
//!   - [`BootCounterStore`] trait — per-`vm_id` monotonic u64.
//!   - [`FileBootCounterStore`] — in-memory cache + atomic JSON
//!     persistence (mirrors the [`FileVmStateStore`] pattern).
//!   - [`check_and_advance`] — the CAS the release path calls.
//!
//! Phase 2 (separate PR, see issue #TBD) wires the counter through
//! the [`crate::release::ReleaseRequest`] + the guest's persistent
//! storage so the counter is actually USED as a rollback gate. Until
//! Phase 2 lands, calling `check_and_advance` purely records the boot
//! event — the operator sees the counter advance in audit, but a
//! malicious miner is not yet refused.
//!
//! # Two copies, two ways to lose one
//!
//! The gate compares TWO durable values, held by two parties, and each
//! can be lost independently:
//!
//! | copy | lives on | lost by | recovery |
//! |---|---|---|---|
//! | KBS `stored` | `boot-counters.json` in the KBS state dir (an `emptyDir` on a Kata CVM) | pod restart | [`BootCounterStore::seed`] |
//! | guest `submitted` | `/var/lib/hippius-miner/state/<vm>.raw`, a 1 MiB plaintext ext4 on the MINER host | host rebuild, disk failure, a `state/` sweep, a migration that forgets to carry it | [`BootCounterStore::arm_resync`] |
//!
//! Either loss desynchronises the pair and the gate then fails closed
//! FOREVER — which for the tenant is indistinguishable from data
//! destruction, since the KEK is never released and the volume is never
//! opened again. The counter may never be walked DOWN (that is the
//! anti-rollback property itself), so neither recovery does: `seed`
//! re-establishes a wiped KBS row from the miner's file, and
//! `arm_resync` re-establishes a wiped GUEST file from the KBS's own
//! value — upward, one boot, operator-authenticated, audited. Both are
//! reachable only from the mTLS admin listener.
//!
//! What is deliberately NOT here: any path that lowers `stored`, and
//! any path a miner can drive. See [`BootCounterStore::arm_resync`] for
//! why an armed resync grants a hostile miner nothing it did not
//! already have, and [`crate::volume_stamp`] for the gate that actually
//! binds anti-rollback to the encrypted volume (this counter cannot:
//! nothing ties a miner-writable plaintext file to the ciphertext it is
//! meant to protect).

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::error::{KbsError, Result};
use crate::rollback::{
    decide_arm, ArmRollbackOutcome, LastRollback, RollbackArm, RollbackClear, RollbackRows,
    CLEAR_BY_BOOT, CLEAR_DISARMED, CLEAR_EXPIRED,
};

/// Largest counter [`BootCounterStore::seed`] will accept.
///
/// A boot counter advances once per SUCCESSFUL KEK release, i.e. once
/// per guest boot. A tenant VM rebooting four times a day, every day,
/// takes ~2.8 years to reach 4096; real values on this fleet are single
/// digits. The cap therefore has ~3 orders of magnitude of headroom over
/// anything plausible, while making `u64::MAX` unreachable.
///
/// Why cap at all: without it, one admin-listener request can set a
/// counter so high that the guest can never submit `stored + 1` from
/// its own disk again — the VM is bricked with no way back, because
/// `seed` is deliberately one-way. The cap converts that irreversible
/// brick into a 400 the operator sees immediately.
///
/// The asymmetry is deliberate. If a VM ever legitimately exceeds 4096
/// boots AND its KBS store is then wiped, this constant must be raised
/// to recover it — a code change, visible and reversible. Seeding
/// `u64::MAX` is neither. Erring low costs an edit; erring high costs a
/// tenant's disk.
pub const MAX_SEED_COUNTER: u64 = 4096;

/// Compile-time floor on the guard's usefulness: a cap raised to
/// something astronomical would leave every test below passing while
/// quietly re-opening the brick vector it exists to close. Enforced at
/// build time, not test time, so it cannot be edited past in a hurry.
const _: () = assert!(
    MAX_SEED_COUNTER <= 100_000,
    "the seed cap must stay low enough that an over-cap value is \
     recognisably implausible"
);

/// Outcome of an operator [`BootCounterStore::seed`].
///
/// The three refusal variants are DISTINCT on purpose: an operator
/// staring at a failed recovery must be able to tell "this VM was
/// already recovered" from "you sent an implausible number" from "someone
/// tried to rewind a live counter". Collapsing them into one code would
/// make the only genuinely alarming case (a rewind attempt) invisible in
/// the noise of the benign ones.
///
/// None of them is an `Err`: they are verdicts, returned as `Ok` so the
/// caller can distinguish a POLICY refusal (fail-closed, nothing
/// written) from "the store is broken" (a 500). Conflating them would
/// let an I/O fault masquerade as a rollback attempt and vice-versa.
///
/// Every refusal variant MUST leave the store byte-for-byte unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedOutcome {
    /// The counter was raised from an absent/0 row. `previous` is
    /// therefore always 0 — see [`BootCounterStore::seed`].
    Seeded { previous: u64 },
    /// The requested value was `<= stored`. The store is UNCHANGED.
    Refused { stored: u64 },
    /// `vm_id` already has a NON-ZERO counter, so the store was not
    /// wiped and this is not a recovery. The store is UNCHANGED.
    AlreadyRecovered { stored: u64 },
    /// The requested value exceeds [`MAX_SEED_COUNTER`]. The store is
    /// UNCHANGED.
    AboveCap { requested: u64, cap: u64 },
}

/// Outcome of an operator [`BootCounterStore::arm_resync`].
///
/// The recovery direction this arms is the MIRROR of [`SeedOutcome`]'s.
/// `seed` repairs a KBS that forgot; this repairs a GUEST that forgot:
/// the counter the guest submits comes from a 1 MiB plaintext ext4 on
/// the miner host (`/var/lib/hippius-miner/state/<vm>.raw`), which is
/// unreplicated and single-point-of-failure. Lose it and the guest
/// submits `1` forever while the KBS holds `N` — fail-closed, with no
/// way back, because [`BootCounterStore::seed`] deliberately refuses a
/// row that is not wiped and the counter may never be walked DOWN.
///
/// Arming does NOT move the counter and can never lower it. It permits
/// exactly one release whose submitted counter is not `stored + 1`, and
/// that release still commits `stored + 1` — the value the KBS echoes
/// back in the signed response, which the guest persists to its fresh
/// state disk, putting the two back in lockstep from the KBS's own
/// (never rewound) value. See [`BootCounterStore::arm_resync`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResyncOutcome {
    /// The arm is now set. `already_armed` distinguishes a fresh arm
    /// from a re-drive so a duplicate operator action is visible as
    /// such rather than looking like two separate incidents.
    Armed { stored: u64, already_armed: bool },
    /// `vm_id` has no committed counter, so nothing can be out of sync:
    /// a guest with no state disk submits `1`, which a `stored == 0`
    /// row accepts on the normal path. Refused rather than accepted as
    /// a no-op so an operator who armed the WRONG `vm_id` (a typo, a
    /// decommissioned VM) is told, instead of leaving a silent arm on a
    /// row that will later be a live VM's first boot.
    NothingToResync,
}

/// Stable, DISTINCT classifier for a refused [`BootCounterStore::
/// check_only`], embedded in the refusal text (which
/// [`crate::release::process_release`] records verbatim in the audit
/// sink and returns in the signed denial).
///
/// It exists so an operator can tell the ONE recoverable shape apart
/// from the two that are not:
///
/// - `boot-counter-lost` — the guest submitted `1` (its "I remember no
///   previous boot" value) against a non-zero stored counter. That is
///   the signature of a LOST state disk.
/// - `boot-counter-rewind` — the guest submitted an EARLIER value it
///   must once have known. A replayed state disk, or a guest bug.
/// - `boot-counter-skip` — the guest submitted past `stored + 1`. A
///   guest bug, or a KBS store that was rolled back under it.
///
/// ⚠️ This is a DIAGNOSTIC, not a trust decision. The state disk is
/// miner-writable, so a hostile miner can produce the `lost` signature
/// at will; nothing in the release path grants anything on the strength
/// of this classification. It exists to tell an operator WHERE to look,
/// and the only thing that acts on it is a human, through the
/// authenticated admin listener. Every one of the three refuses the
/// release identically, before any Vault read.
///
/// `submitted == 1 && stored == 1` is genuinely ambiguous (a lost disk
/// and a replay of the only boot so far are the same number); it is
/// reported as `lost` because that is the actionable reading and the
/// action it leads to — an armed resync — cannot lower the counter or
/// re-admit anything.
pub fn refusal_class(submitted: u64, stored: u64) -> &'static str {
    if stored > 0 && submitted == 1 {
        "boot-counter-lost"
    } else if submitted <= stored {
        "boot-counter-rewind"
    } else {
        "boot-counter-skip"
    }
}

/// Storage for the per-`vm_id` monotonic counter.
///
/// The release path uses this in TWO phases (see
/// [`crate::release::process_release`]):
///   1. [`check_only`](BootCounterStore::check_only) — verify the
///      submitted counter is exactly `stored + 1` WITHOUT persisting.
///      Runs early, before the Vault/broker read, so a rolled-back
///      boot is refused before any secret work begins.
///   2. [`commit`](BootCounterStore::commit) — persist the advance,
///      but ONLY after the release has durably succeeded.
///
/// Splitting the two is load-bearing: the guest only advances its own
/// on-disk counter when it receives a 200 (KEK released). If the KBS
/// persisted the advance at check time and the release then failed at
/// a LATER gate (Vault unreachable, broker denial, nonce race), the
/// KBS counter would run one ahead of the guest's disk forever — every
/// subsequent boot would resubmit the old value and be refused as a
/// rollback. Committing only on success keeps the two in lockstep.
pub trait BootCounterStore: Send + Sync {
    /// Validate the submitted counter WITHOUT persisting:
    /// - On first call for `vm_id`, the stored counter is 0;
    ///   `submitted` MUST be exactly 1 — the guest's first boot
    ///   submits "I have not seen any previous counter".
    /// - Otherwise `submitted` MUST be exactly `stored + 1`. A skip
    ///   (`submitted > stored + 1`) is a guest bug — fail-closed; a
    ///   rewind (`submitted <= stored`) is a rollback — fail-closed.
    ///
    /// On `Ok`, returns `submitted` (the value to [`commit`] once the
    /// release succeeds). The store is UNCHANGED either way — call
    /// [`commit`](BootCounterStore::commit) to persist.
    fn check_only(&self, vm_id: &str, submitted: u64) -> Result<u64>;

    /// Durably persist `value` as the new committed counter for
    /// `vm_id`. Called ONLY after a release has durably succeeded,
    /// with the value previously returned by [`check_only`]. Monotonic
    /// guard: refuses to persist a `value <= stored` (a concurrent
    /// release already advanced past it), which fails the release
    /// closed rather than rewinding the counter.
    ///
    /// All-or-nothing: when this returns `Err` — for ANY reason,
    /// including a failed disk write — the counter this store reports
    /// is unchanged, and it still matches what is durably stored. A
    /// partial application (memory advanced, disk not) would refuse
    /// every subsequent boot of that VM until the process restarted.
    ///
    /// A successful commit also CLEARS any
    /// [`arm_resync`](BootCounterStore::arm_resync) arm on `vm_id` —
    /// that is what makes the arm one-shot, and it clears an arm that
    /// was never used (a typo'd `vm_id`) at the VM's next normal boot
    /// rather than leaving it set indefinitely. The clear is persisted
    /// BEFORE the counter, so a failure between the two leaves the arm
    /// GONE and the counter untouched: the operator must arm again,
    /// which is the fail-safe direction (an operator re-running a
    /// recovery is a nuisance; an arm that silently outlives the
    /// release it was meant for is a lingering one-shot bypass).
    fn commit(&self, vm_id: &str, value: u64) -> Result<()>;

    /// Atomically check-and-persist in one step (the pre-split
    /// behaviour). Retained for the audit/admin paths + tests that do
    /// not need the two-phase guarantee. The release path uses
    /// [`check_only`] + [`commit`] instead.
    fn check_and_advance(&self, vm_id: &str, submitted: u64) -> Result<u64> {
        let v = self.check_only(vm_id, submitted)?;
        self.commit(vm_id, v)?;
        Ok(v)
    }

    /// Read the currently-committed counter for `vm_id`. Returns 0
    /// if this is the first time we have seen `vm_id`. Used by the
    /// admin endpoint vali queries before generating a launch
    /// cmdline (so vali knows what value the guest should submit).
    fn get(&self, vm_id: &str) -> Result<u64>;

    /// Operator DISASTER-RECOVERY write: restore a WIPED counter for
    /// `vm_id` to `value` in one step, without the `stored + 1` step
    /// constraint [`check_only`](BootCounterStore::check_only) enforces.
    ///
    /// Why it exists: the KBS state directory is an `emptyDir` on a
    /// Kata CVM — a pod restart wipes `boot-counters.json`, and the
    /// wiped store then expects 1 from EVERY VM while a guest that has
    /// booted N times submits N+1. Fail-closed means those VMs never
    /// unlock again. The authoritative value is recoverable from the
    /// miner-side per-VM state disk (`/var/lib/hippius-miner/state/
    /// <vm>.raw`, plain ext4 holding a `boot-counter` text file), so
    /// the operator re-establishes the wiped store from it.
    ///
    /// ## The three guards
    ///
    /// This is deliberately NOT a general "set the counter" power. All
    /// three guards run under the store's own lock, before any write, and
    /// every refusal MUST leave the store byte-for-byte unchanged. They
    /// are complementary, not redundant:
    ///
    /// 1. **Wiped-only** — `stored != 0` is
    ///    [`SeedOutcome::AlreadyRecovered`]. A legitimate recovery always
    ///    targets a wiped row; raising a LIVE counter has no legitimate
    ///    use. This is what keeps the endpoint from being a fleet-wide
    ///    denial-of-service: against a running VM it is INERT.
    /// 2. **Capped** — `value > `[`MAX_SEED_COUNTER`] is
    ///    [`SeedOutcome::AboveCap`]. Closes the remaining brick vector on
    ///    a wiped row (seed `u64::MAX`, guest can never reach
    ///    `stored + 1`, disk unrecoverable).
    /// 3. **Strictly monotonic** — `value <= stored` is
    ///    [`SeedOutcome::Refused`]. With guard 1 in place this is
    ///    reachable only for `value == 0` on a wiped row, but it is the
    ///    guard that states the actual security invariant, so it stays:
    ///    if guard 1 is ever relaxed, monotonicity is still what stops a
    ///    counter being walked BACK to re-admit a snapshot whose boot was
    ///    already burned.
    ///
    /// Consequence, and it is the fail-safe direction: re-running a
    /// recovery for a VM that was already seeded REFUSES (guard 1) rather
    /// than succeeding idempotently. A second seed is either a duplicate
    /// (harmless to refuse) or a disagreement about the true value
    /// (must not silently overwrite).
    ///
    /// Because guard 1 admits only `stored == 0`, a successful seed
    /// ALWAYS reports `previous: 0`.
    ///
    /// All-or-nothing, and load-bearing BECAUSE of guard 1: when this
    /// returns `Err` (a failed disk write, say) the counter must be
    /// exactly as it was, in memory and on disk. A half-applied seed
    /// would leave guard 1 seeing a non-zero row and refuse the
    /// operator's retry with `AlreadyRecovered` — locking them out of a
    /// recovery that never actually landed.
    ///
    /// This method is the ONLY way to move a counter other than the
    /// release path's `check_only` + `commit`; it does not, and must
    /// not, relax either of those.
    fn seed(&self, vm_id: &str, value: u64) -> Result<SeedOutcome>;

    /// Operator DISASTER-RECOVERY arm for the OTHER loss direction:
    /// the GUEST's copy of the counter is gone (the miner-side state
    /// disk was lost, the host was rebuilt, a `state/` sweep ran) while
    /// the KBS's is intact.
    ///
    /// Why it exists: [`seed`](BootCounterStore::seed) repairs a wiped
    /// KBS row from the miner's disk. There is no mirror for a wiped
    /// MINER disk — a guest with a blank state disk submits `1` while
    /// the KBS holds `N`, `check_only` refuses forever, and `seed`
    /// cannot help (it refuses a live row, and the counter may never be
    /// walked down). That made one unreplicated 1 MiB file on an
    /// UNTRUSTED host a permanent-data-loss primitive.
    ///
    /// What it does: sets a one-shot arm. It does NOT write the
    /// counter. The next release for `vm_id` whose submitted counter
    /// would otherwise be refused is admitted, and commits `stored + 1`
    /// — never the submitted value — so:
    ///
    /// - the counter still only ever moves UP, by exactly one, exactly
    ///   as a normal boot moves it. Nothing an operator can do here
    ///   re-admits a boot that was already burned;
    /// - the number the miner submits buys it nothing: the committed
    ///   value is a function of the KBS's own state alone;
    /// - the guest re-learns the truth for free — the release echoes
    ///   the committed counter in the SIGNED response and the guest
    ///   persists THAT to its fresh state disk, so the next boot is
    ///   back in lockstep with no operator arithmetic.
    ///
    /// ## Guards
    ///
    /// 1. **Live-row only** — `stored == 0` is
    ///    [`ResyncOutcome::NothingToResync`], written nothing. A VM the
    ///    KBS has never counted needs no resync (it accepts `1` on the
    ///    normal path), so arming one could only ever be a mistake, and
    ///    a silent arm on a row that later becomes a real VM's first
    ///    boot is exactly the lingering bypass this refuses to create.
    /// 2. **One-shot** — the arm is consumed by the release that uses
    ///    it and cleared by ANY successful [`commit`](BootCounterStore::
    ///    commit) for that `vm_id`, so it survives at most until the
    ///    VM's next successful boot.
    ///
    /// ## What arming does NOT grant
    ///
    /// The submitted counter is read from a file the miner can read AND
    /// write, so a miner can already submit whatever value it likes;
    /// the arm therefore hands it nothing it did not have. It does not
    /// touch — and cannot be used to bypass —
    /// [`crate::volume_stamp`], which is the gate that actually binds
    /// anti-rollback to the ENCRYPTED VOLUME. What is lost while an arm
    /// is set is one boot's worth of DETECTION on a signal that was
    /// never miner-proof to begin with.
    ///
    /// Reachable ONLY from the mTLS admin listener
    /// (`POST /v1/admin/vm/{vm_id}/arm-boot-counter-resync`), never from
    /// the guest-facing release/confirm routes — a miner must not be
    /// able to arm its own tenants.
    ///
    /// All-or-nothing, like every other mutator here: on `Err` the arm
    /// set is exactly what it was, in memory and on disk.
    fn arm_resync(&self, vm_id: &str) -> Result<ResyncOutcome>;

    /// Whether `vm_id` currently carries an
    /// [`arm_resync`](BootCounterStore::arm_resync) arm. Read by the
    /// release path ONLY after `check_only` has already refused, so the
    /// normal path is byte-identical when nothing is armed.
    fn resync_armed(&self, vm_id: &str) -> Result<bool>;

    // ── authorized rollback (A2) — see `crate::rollback` ─────────────
    //
    // The arms live in THIS store, behind the SAME lock as the counters,
    // so the one operation that must be atomic — consume the arm and
    // commit the counter — is one critical section by construction
    // (`commit_rollback`). The defaults make a store that does not
    // implement them fail CLOSED: no arm is ever reported, and every
    // mutator errors.

    /// The VM's arm (EXPIRED ones included — callers check expiry) and
    /// its last consumed rollback. Pure read.
    fn rollback_state(&self, _vm_id: &str) -> Result<(Option<RollbackArm>, Option<LastRollback>)> {
        Ok((None, None))
    }

    /// Store `arm` unless [`crate::rollback::decide_arm`] refuses it
    /// (a live arm, not a rollback against the CURRENT `stored`, or the
    /// rate limit), all decided under the counter lock. A refusal writes
    /// nothing.
    fn arm_rollback(
        &self,
        _arm: RollbackArm,
        _min_interval_s: u64,
        _now_unix: u64,
    ) -> Result<ArmRollbackOutcome> {
        Err(rollback_unsupported())
    }

    /// Remove `vm_id`'s arm iff it carries `restore_id`. `Ok(None)` when
    /// there was none (idempotent). The rate-limit memory is kept. With
    /// `note_at_unix`, the removal is recorded as the VM's `last_clear`
    /// (`rollback-disarmed`) in the SAME write; `None` for an arm taken
    /// back before it was ever reported armed.
    fn disarm_rollback(
        &self,
        _vm_id: &str,
        _restore_id: &str,
        _note_at_unix: Option<u64>,
    ) -> Result<Option<RollbackArm>> {
        Err(rollback_unsupported())
    }

    /// Remove `vm_id`'s arm whatever its id (lifecycle transitions),
    /// recording `reason` as its `last_clear` in the same write.
    fn clear_rollback_arm(
        &self,
        _vm_id: &str,
        _reason: &str,
        _now_unix: u64,
    ) -> Result<Option<RollbackArm>> {
        Ok(None)
    }

    /// Remove every arm expired at `now_unix`, recording each as its
    /// VM's `last_clear` (`rollback-expired`) — one write for all of
    /// them. Returns them for audit.
    fn purge_expired_rollback_arms(&self, _now_unix: u64) -> Result<Vec<RollbackArm>> {
        Ok(Vec::new())
    }

    /// The VM's last arm that left WITHOUT a consume, and why (`GET
    /// …/rollback` `last_clear`, so vali can tell a normal boot from an
    /// expiry, a disarm or a fence). Every clear records it atomically
    /// with the removal itself.
    fn rollback_last_clear(&self, _vm_id: &str) -> Result<Option<RollbackClear>> {
        Ok(None)
    }

    /// The authorized-rollback COMMIT: under the counter lock, re-check
    /// that `vm_id` still holds the unexpired arm `restore_id` and that
    /// `value == stored + 1`, then run `apply_stamp` (step (i), the stamp
    /// store's rollback — it must succeed first), then durably consume
    /// the arm (recording [`LastRollback`]) BEFORE committing the
    /// counter to `value` (step (ii)). Any resync arm is cleared too, as
    /// by [`BootCounterStore::commit`].
    ///
    /// Persist order and failures: the arms file is written before the
    /// counter file, so a failure between them leaves the arm CONSUMED
    /// and the counter unmoved — the operator re-arms; an arm can never
    /// outlive the release that used it. When `apply_stamp` fails nothing
    /// in this store changes.
    fn commit_rollback(
        &self,
        _vm_id: &str,
        _restore_id: &str,
        _value: u64,
        _now_unix: u64,
        _apply_stamp: &mut dyn FnMut(&RollbackArm) -> Result<()>,
    ) -> Result<RollbackArm> {
        Err(rollback_unsupported())
    }

    /// Run `f` with `vm_id`'s committed counter while holding the store
    /// lock, so what `f` reads elsewhere (the stamp store) is consistent
    /// with it: no rollback commit — which holds this lock across its
    /// stamp and counter writes — can land in between. Lock order:
    /// counter, then whatever `f` takes.
    fn with_counter_locked(&self, vm_id: &str, f: &mut dyn FnMut(u64) -> Result<()>) -> Result<()> {
        f(self.get(vm_id)?)
    }

    /// [`BootCounterStore::commit`], reporting the rollback arm a normal
    /// commit cleared (a VM that booted normally after being armed must
    /// not keep a one-shot rollback permission; `commit` clears it, and
    /// this variant tells the release path so it can audit it).
    fn commit_reporting(&self, vm_id: &str, value: u64) -> Result<Option<RollbackArm>> {
        self.commit(vm_id, value)?;
        Ok(None)
    }

    /// [`Self::commit_reporting`] with `guard` evaluated UNDER the store
    /// lock, after the monotonic check and before any write. The release
    /// path uses it to refuse a normal commit if an authorized rollback
    /// touched the stamp since the release read it — a rollback's stamp
    /// step runs under this same lock, so the two cannot interleave.
    /// With `clear_at_unix`, a rollback arm the commit clears is recorded
    /// as the VM's `last_clear` (`rollback-cleared-by-boot`) in the same
    /// write that removes it.
    fn commit_reporting_guarded(
        &self,
        vm_id: &str,
        value: u64,
        _clear_at_unix: Option<u64>,
        guard: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Option<RollbackArm>> {
        guard()?;
        self.commit_reporting(vm_id, value)
    }
}

fn rollback_unsupported() -> KbsError {
    KbsError::Policy("rollback arms are not supported by this boot-counter store".into())
}

fn lock_poisoned() -> KbsError {
    KbsError::Policy("boot-counter lock poisoned".into())
}

// Shared in-memory transitions of the rollback rows, used by BOTH store
// impls so the file store and the test double cannot disagree.

fn rb_arm(
    rows: &mut Rows,
    arm: RollbackArm,
    min_interval_s: u64,
    now_unix: u64,
) -> ArmRollbackOutcome {
    let stored = rows.counters.get(&arm.vm_id).copied().unwrap_or(0);
    if let Some(verdict) = decide_arm(&rows.rollback, stored, &arm, min_interval_s, now_unix) {
        return verdict;
    }
    let h = rows.rollback.history.entry(arm.vm_id.clone()).or_default();
    h.last_event_at_unix = h.last_event_at_unix.max(now_unix);
    rows.rollback.arms.insert(arm.vm_id.clone(), arm.clone());
    ArmRollbackOutcome::Armed(arm)
}

fn rb_note_clear(rows: &mut Rows, vm_id: &str, restore_id: &str, reason: &str, now_unix: u64) {
    rows.rollback
        .history
        .entry(vm_id.to_string())
        .or_default()
        .last_clear = Some(RollbackClear {
        restore_id: restore_id.to_string(),
        reason: reason.to_string(),
        at_unix: now_unix,
    });
}

fn rb_last_clear(rows: &Rows, vm_id: &str) -> Option<RollbackClear> {
    rows.rollback
        .history
        .get(vm_id)
        .and_then(|h| h.last_clear.clone())
}

fn rb_disarm(
    rows: &mut Rows,
    vm_id: &str,
    restore_id: &str,
    note_at_unix: Option<u64>,
) -> Option<RollbackArm> {
    if rows.rollback.arms.get(vm_id)?.restore_id != restore_id {
        return None;
    }
    let arm = rows.rollback.arms.remove(vm_id)?;
    if let Some(now) = note_at_unix {
        rb_note_clear(rows, vm_id, restore_id, CLEAR_DISARMED, now);
    }
    Some(arm)
}

/// Remove `vm_id`'s arm whatever its id; record `reason` when one went.
fn rb_clear(rows: &mut Rows, vm_id: &str, reason: &str, now_unix: u64) -> Option<RollbackArm> {
    let arm = rows.rollback.arms.remove(vm_id)?;
    rb_note_clear(rows, vm_id, &arm.restore_id, reason, now_unix);
    Some(arm)
}

fn rb_purge(rows: &mut Rows, now_unix: u64) -> Vec<RollbackArm> {
    let expired: Vec<String> = rows
        .rollback
        .arms
        .iter()
        .filter(|(_, a)| a.is_expired(now_unix))
        .map(|(k, _)| k.clone())
        .collect();
    expired
        .iter()
        .filter_map(|k| rb_clear(rows, k, CLEAR_EXPIRED, now_unix))
        .collect()
}

/// Re-validate the arm under the lock; returns it (still stored).
fn rb_check_for_commit(
    rows: &Rows,
    vm_id: &str,
    restore_id: &str,
    value: u64,
    now_unix: u64,
) -> Result<RollbackArm> {
    let arm = rows.rollback.arms.get(vm_id).cloned().ok_or_else(|| {
        KbsError::Policy(format!(
            "rollback-commit: vm_id={vm_id} has no live arm (consumed, disarmed or cleared \
             since the release was admitted) — fail closed"
        ))
    })?;
    if arm.restore_id != restore_id {
        return Err(KbsError::Policy(format!(
            "rollback-commit: vm_id={vm_id} arm was replaced ({} != {restore_id}) — fail closed",
            arm.restore_id
        )));
    }
    if arm.is_expired(now_unix) {
        return Err(KbsError::Policy(format!(
            "rollback-commit: vm_id={vm_id} arm {restore_id} expired — fail closed"
        )));
    }
    let stored = rows.counters.get(vm_id).copied().unwrap_or(0);
    // EXACTLY stored + 1: the arm path moves the counter the way one
    // normal boot does, never further.
    if Some(value) != stored.checked_add(1) {
        return Err(KbsError::Policy(format!(
            "rollback-commit: vm_id={vm_id} value={value} != stored+1 (stored={stored}) \
             (concurrent advance) — fail closed"
        )));
    }
    Ok(arm)
}

fn rb_consume(rows: &mut Rows, arm: &RollbackArm, value: u64, now_unix: u64) {
    rows.rollback.arms.remove(&arm.vm_id);
    let h = rows.rollback.history.entry(arm.vm_id.clone()).or_default();
    h.last_event_at_unix = h.last_event_at_unix.max(now_unix);
    h.consumed_restore_ids.push(arm.restore_id.clone());
    let excess = h
        .consumed_restore_ids
        .len()
        .saturating_sub(crate::rollback::MAX_CONSUMED_IDS);
    h.consumed_restore_ids.drain(..excess);
    h.last_rollback = Some(LastRollback {
        restore_id: arm.restore_id.clone(),
        manifest_sha256_hex: arm.manifest_sha256_hex.clone(),
        from_counter: arm.from_counter,
        to_counter: value,
        stamp: arm.to_stamp,
        consumed_at_unix: now_unix,
        requested_by: arm.requested_by.clone(),
    });
}

/// Both durable maps this store owns, behind ONE lock.
///
/// The resync arms could have been a second `Mutex`, but `commit` and
/// `arm_resync` each need a consistent view of BOTH (commit clears an
/// arm and advances a counter; arm_resync reads a counter and sets an
/// arm). One lock makes each of those a CAS by construction instead of
/// a documented lock ordering someone has to keep honouring.
#[derive(Debug, Default)]
struct Rows {
    counters: HashMap<String, u64>,
    /// `vm_id`s carrying a one-shot resync arm. A `BTreeSet` so the
    /// serialised bytes are deterministic.
    armed: BTreeSet<String>,
    /// Authorized-rollback arms + per-VM rate-limit memory
    /// (`crate::rollback`). Behind the SAME lock so the arm consume and
    /// the counter commit are one critical section.
    rollback: RollbackRows,
}

/// File-backed [`BootCounterStore`]. The on-disk format is a JSON
/// map `{vm_id: counter}` written atomically (tmp + rename) under a
/// `Mutex`. Same atomicity contract as [`crate::persist::FileVmStateStore`]
/// — production deployments back the file with a tamper-safe Tier-0
/// store (sealed dm-integrity volume on the KBS pod, or Vault KV-v2).
///
/// The resync arms live in a SEPARATE sibling file (`<stem>-resync.json`,
/// a JSON array of `vm_id`s) rather than as a richer row in the counter
/// file. That is deliberate and it is about DEPLOYMENT, not taste: the
/// counter file's shape is `{vm_id: u64}` and an older KBS binary
/// decodes it strictly, so widening the row would make a binary
/// rollback fail to `open` the store at all — the KBS would not start,
/// and every tenant would be locked out by a rollback that was supposed
/// to be the safe move. With a sibling file, an older binary simply
/// ignores it and behaves as it always did: strict, fail-closed. The
/// only thing lost across a rollback is the ability to CONSUME an arm.
///
/// The authorized-rollback arms (`crate::rollback`) follow the same
/// rule, in a THIRD sibling (`<stem>-rollback-arms.json`, a JSON object
/// `{arms, history}`): an older binary ignores it and simply cannot
/// consume an arm, which fails closed.
pub struct FileBootCounterStore {
    path: PathBuf,
    resync_path: PathBuf,
    rollback_path: PathBuf,
    cache: Mutex<Rows>,
}

impl FileBootCounterStore {
    /// Sibling path holding the resync arms: `boot-counters.json`
    /// ⇒ `boot-counters-resync.json`, in the same directory, so no new
    /// operator-facing config key exists to be forgotten in one
    /// environment and not another.
    fn resync_path_for(path: &std::path::Path) -> PathBuf {
        Self::sibling_path(path, "resync")
    }

    /// Sibling path holding the rollback arms: `boot-counters.json`
    /// ⇒ `boot-counters-rollback-arms.json`.
    fn rollback_path_for(path: &std::path::Path) -> PathBuf {
        Self::sibling_path(path, "rollback-arms")
    }

    fn sibling_path(path: &std::path::Path, suffix: &str) -> PathBuf {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("boot-counter");
        let sibling = format!("{stem}-{suffix}.json");
        match path.parent() {
            Some(dir) => dir.join(sibling),
            None => PathBuf::from(sibling),
        }
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let counters = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<HashMap<String, u64>>(&bytes)
                .map_err(|e| KbsError::Vault(format!("boot-counter decode: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(KbsError::Vault(format!("boot-counter read: {e}"))),
        };
        let resync_path = Self::resync_path_for(&path);
        // A missing arms file is the overwhelmingly common case (nothing
        // armed, or a store written by a binary that predates them) and
        // means "no arms". A CORRUPT one is refused exactly like a
        // corrupt counter file: fail to open rather than silently start
        // with a set we cannot vouch for.
        let armed = match fs::read(&resync_path) {
            Ok(bytes) => serde_json::from_slice::<BTreeSet<String>>(&bytes)
                .map_err(|e| KbsError::Vault(format!("boot-counter resync decode: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
            Err(e) => return Err(KbsError::Vault(format!("boot-counter resync read: {e}"))),
        };
        // Same discipline for the rollback arms: absent ⇒ none, corrupt ⇒
        // refuse to open rather than start with a set we cannot vouch for.
        let rollback_path = Self::rollback_path_for(&path);
        let rollback = match fs::read(&rollback_path) {
            Ok(bytes) => serde_json::from_slice::<RollbackRows>(&bytes)
                .map_err(|e| KbsError::Vault(format!("boot-counter rollback decode: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => RollbackRows::default(),
            Err(e) => return Err(KbsError::Vault(format!("boot-counter rollback read: {e}"))),
        };
        Ok(Self {
            path,
            resync_path,
            rollback_path,
            cache: Mutex::new(Rows {
                counters,
                armed,
                rollback,
            }),
        })
    }

    /// Run `f` over the rows and persist the ROLLBACK part if `f`
    /// changed it — all-or-nothing like the other two files: on a failed
    /// write the in-memory rollback rows are restored, so memory and the
    /// file always agree. A no-op writes nothing.
    fn mutate_rollback_locked<T>(
        &self,
        rows: &mut Rows,
        f: impl FnOnce(&mut Rows) -> T,
    ) -> Result<T> {
        let before = rows.rollback.clone();
        let out = f(rows);
        if rows.rollback == before {
            return Ok(out);
        }
        let bytes = match serde_json::to_vec(&rows.rollback) {
            Ok(b) => b,
            Err(e) => {
                rows.rollback = before;
                return Err(KbsError::Vault(format!(
                    "boot-counter rollback encode: {e}"
                )));
            }
        };
        if let Err(e) = Self::atomic_write(&self.rollback_path, &bytes, "boot-counter rollback") {
            rows.rollback = before;
            return Err(e);
        }
        Ok(out)
    }

    /// Write `vm_id -> value` through to disk, keeping the in-memory
    /// cache and the file IN SYNC even when the write fails.
    ///
    /// This is the only way either mutating path may touch the cache.
    /// The naive shape — `cache.insert(..); self.persist_locked(&cache)?`
    /// — leaves the cache advanced and the file behind whenever the
    /// persist fails (disk full, I/O error, rename failure: all
    /// reachable). That split-brain is worse than the failure it
    /// reports:
    ///
    /// - `seed` returns 500, the operator concludes nothing happened,
    ///   and their retry hits guard 1 (`stored != 0`) with a 409
    ///   `seed-already-recovered` — they are locked out of the recovery
    ///   by a write that never landed, until the pod restarts.
    /// - `commit` returns an error, so the release fails and the guest
    ///   never advances its own on-disk counter — but the KBS cache DID
    ///   advance, so every subsequent boot submits one less than the
    ///   cache expects and is refused as a rollback. A transient disk
    ///   error locks the tenant out until the pod restarts (and the
    ///   restart silently "fixes" it by reloading the older file, which
    ///   is how such a bug survives a long time).
    ///
    /// So: on failure, restore the previous mapping (or remove the row
    /// if there was none) before propagating. `persist_locked` writes
    /// via tmp+rename, so a failed write leaves the FILE untouched;
    /// rolling the cache back is what makes the pair consistent.
    ///
    /// Invariant: when this returns `Err`, the in-memory value and the
    /// on-disk value are both exactly what they were before the call.
    fn insert_and_persist_locked(&self, rows: &mut Rows, vm_id: &str, value: u64) -> Result<()> {
        let previous = rows.counters.insert(vm_id.to_string(), value);
        if let Err(e) = self.persist_locked(&rows.counters) {
            match previous {
                Some(p) => rows.counters.insert(vm_id.to_string(), p),
                None => rows.counters.remove(vm_id),
            };
            return Err(e);
        }
        Ok(())
    }

    /// Set or clear `vm_id`'s resync arm, keeping the in-memory set and
    /// the arms file in sync even when the write fails — the same
    /// all-or-nothing discipline (and for the same reason) as
    /// [`Self::insert_and_persist_locked`]. A no-op change writes
    /// nothing, so the steady state (nothing armed) never touches the
    /// disk.
    fn set_armed_and_persist_locked(
        &self,
        rows: &mut Rows,
        vm_id: &str,
        armed: bool,
    ) -> Result<()> {
        let changed = if armed {
            rows.armed.insert(vm_id.to_string())
        } else {
            rows.armed.remove(vm_id)
        };
        if !changed {
            return Ok(());
        }
        if let Err(e) = self.persist_armed_locked(&rows.armed) {
            // Undo the in-memory change so the set and the file agree.
            if armed {
                rows.armed.remove(vm_id);
            } else {
                rows.armed.insert(vm_id.to_string());
            }
            return Err(e);
        }
        Ok(())
    }

    fn persist_locked(&self, counters: &HashMap<String, u64>) -> Result<()> {
        let bytes = serde_json::to_vec(counters)
            .map_err(|e| KbsError::Vault(format!("boot-counter encode: {e}")))?;
        Self::atomic_write(&self.path, &bytes, "boot-counter")
    }

    fn persist_armed_locked(&self, armed: &BTreeSet<String>) -> Result<()> {
        let bytes = serde_json::to_vec(armed)
            .map_err(|e| KbsError::Vault(format!("boot-counter resync encode: {e}")))?;
        Self::atomic_write(&self.resync_path, &bytes, "boot-counter resync")
    }

    /// tmp + fsync + rename, so a crash between the write and the
    /// rename leaves the live file byte-identical to what it was.
    pub(crate) fn atomic_write(path: &std::path::Path, bytes: &[u8], what: &str) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| KbsError::Vault(format!("{what}: no parent dir")))?;
        // Use a sibling tmp file so we don't race with another writer.
        let tmp = parent.join(format!(
            ".{}.tmp",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("boot-counter"),
        ));
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| KbsError::Vault(format!("{what} open tmp: {e}")))?;
            f.write_all(bytes)
                .map_err(|e| KbsError::Vault(format!("{what} write tmp: {e}")))?;
            f.sync_all()
                .map_err(|e| KbsError::Vault(format!("{what} fsync tmp: {e}")))?;
        }
        fs::rename(&tmp, path).map_err(|e| KbsError::Vault(format!("{what} rename: {e}")))?;
        // Best-effort fsync the parent directory so the rename hits
        // disk durably. A failure here is non-fatal — the rename
        // syscall is atomic on supported filesystems even without it.
        if let Ok(parent) = OpenOptions::new().read(true).open(parent) {
            let _ = parent.sync_all();
        }
        Ok(())
    }
}

impl BootCounterStore for FileBootCounterStore {
    fn check_only(&self, vm_id: &str, submitted: u64) -> Result<u64> {
        let rows = self
            .cache
            .lock()
            .map_err(|_| KbsError::Policy("boot-counter lock poisoned".into()))?;
        let stored = rows.counters.get(vm_id).copied().unwrap_or(0);
        let expected = stored
            .checked_add(1)
            .ok_or_else(|| KbsError::Policy("boot-counter overflow".into()))?;
        if submitted != expected {
            let class = refusal_class(submitted, stored);
            return Err(KbsError::Policy(format!(
                "{class}: vm_id={vm_id} submitted={submitted} expected={expected} \
                 (stored={stored}) — rollback or skip detected"
            )));
        }
        Ok(submitted)
    }

    fn commit(&self, vm_id: &str, value: u64) -> Result<()> {
        self.commit_reporting(vm_id, value).map(|_| ())
    }

    fn commit_reporting(&self, vm_id: &str, value: u64) -> Result<Option<RollbackArm>> {
        self.commit_reporting_guarded(vm_id, value, None, &mut || Ok(()))
    }

    fn commit_reporting_guarded(
        &self,
        vm_id: &str,
        value: u64,
        clear_at_unix: Option<u64>,
        guard: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Option<RollbackArm>> {
        let mut rows = self.cache.lock().map_err(|_| lock_poisoned())?;
        let stored = rows.counters.get(vm_id).copied().unwrap_or(0);
        if value <= stored {
            return Err(KbsError::Policy(format!(
                "boot-counter commit: vm_id={vm_id} value={value} <= stored={stored} \
                 (concurrent advance) — fail closed"
            )));
        }
        guard()?;
        // Disarm FIRST (both kinds): see the trait doc. If the counter
        // write then fails the arm is gone and the counter unmoved, so
        // the operator re-arms — rather than an arm outliving the
        // release it was minted for. A rollback arm is cleared by a
        // NORMAL boot for the same reason: it was minted for one
        // specific release, and a VM that booted another way since is
        // no longer in the state the arm was granted for.
        let cleared = self.mutate_rollback_locked(&mut rows, |r| match clear_at_unix {
            Some(now) => rb_clear(r, vm_id, CLEAR_BY_BOOT, now),
            None => r.rollback.arms.remove(vm_id),
        })?;
        self.set_armed_and_persist_locked(&mut rows, vm_id, false)?;
        self.insert_and_persist_locked(&mut rows, vm_id, value)?;
        Ok(cleared)
    }

    fn get(&self, vm_id: &str) -> Result<u64> {
        let rows = self
            .cache
            .lock()
            .map_err(|_| KbsError::Policy("boot-counter lock poisoned".into()))?;
        Ok(rows.counters.get(vm_id).copied().unwrap_or(0))
    }

    fn seed(&self, vm_id: &str, value: u64) -> Result<SeedOutcome> {
        // Guard 2 (cap) needs no state, so it runs before the lock.
        if value > MAX_SEED_COUNTER {
            return Ok(SeedOutcome::AboveCap {
                requested: value,
                cap: MAX_SEED_COUNTER,
            });
        }
        let mut rows = self
            .cache
            .lock()
            .map_err(|_| KbsError::Policy("boot-counter lock poisoned".into()))?;
        let stored = rows.counters.get(vm_id).copied().unwrap_or(0);
        // Guards 1 and 3 return WITHOUT touching the cache or the file.
        // Holding the lock across the checks + the write is what makes
        // this a CAS rather than a TOCTOU.
        if stored != 0 {
            return Ok(SeedOutcome::AlreadyRecovered { stored });
        }
        if value <= stored {
            return Ok(SeedOutcome::Refused { stored });
        }
        // A failed persist must leave the cache untouched too, or the
        // operator is locked out of their own retry by guard 1.
        self.insert_and_persist_locked(&mut rows, vm_id, value)?;
        Ok(SeedOutcome::Seeded { previous: stored })
    }

    fn arm_resync(&self, vm_id: &str) -> Result<ResyncOutcome> {
        let mut rows = self
            .cache
            .lock()
            .map_err(|_| KbsError::Policy("boot-counter lock poisoned".into()))?;
        let stored = rows.counters.get(vm_id).copied().unwrap_or(0);
        // Guard 1: nothing to resync against a row the KBS never
        // counted. Returns WITHOUT touching the set or the file.
        if stored == 0 {
            return Ok(ResyncOutcome::NothingToResync);
        }
        let already_armed = rows.armed.contains(vm_id);
        self.set_armed_and_persist_locked(&mut rows, vm_id, true)?;
        Ok(ResyncOutcome::Armed {
            stored,
            already_armed,
        })
    }

    fn resync_armed(&self, vm_id: &str) -> Result<bool> {
        let rows = self
            .cache
            .lock()
            .map_err(|_| KbsError::Policy("boot-counter lock poisoned".into()))?;
        Ok(rows.armed.contains(vm_id))
    }

    fn rollback_state(&self, vm_id: &str) -> Result<(Option<RollbackArm>, Option<LastRollback>)> {
        let rows = self.cache.lock().map_err(|_| lock_poisoned())?;
        Ok(rb_state(&rows, vm_id))
    }

    fn with_counter_locked(&self, vm_id: &str, f: &mut dyn FnMut(u64) -> Result<()>) -> Result<()> {
        let rows = self.cache.lock().map_err(|_| lock_poisoned())?;
        f(rows.counters.get(vm_id).copied().unwrap_or(0))
    }

    fn arm_rollback(
        &self,
        arm: RollbackArm,
        min_interval_s: u64,
        now_unix: u64,
    ) -> Result<ArmRollbackOutcome> {
        let mut rows = self.cache.lock().map_err(|_| lock_poisoned())?;
        self.mutate_rollback_locked(&mut rows, |r| rb_arm(r, arm, min_interval_s, now_unix))
    }

    fn disarm_rollback(
        &self,
        vm_id: &str,
        restore_id: &str,
        note_at_unix: Option<u64>,
    ) -> Result<Option<RollbackArm>> {
        let mut rows = self.cache.lock().map_err(|_| lock_poisoned())?;
        self.mutate_rollback_locked(&mut rows, |r| rb_disarm(r, vm_id, restore_id, note_at_unix))
    }

    fn clear_rollback_arm(
        &self,
        vm_id: &str,
        reason: &str,
        now_unix: u64,
    ) -> Result<Option<RollbackArm>> {
        let mut rows = self.cache.lock().map_err(|_| lock_poisoned())?;
        self.mutate_rollback_locked(&mut rows, |r| rb_clear(r, vm_id, reason, now_unix))
    }

    fn purge_expired_rollback_arms(&self, now_unix: u64) -> Result<Vec<RollbackArm>> {
        let mut rows = self.cache.lock().map_err(|_| lock_poisoned())?;
        self.mutate_rollback_locked(&mut rows, |r| rb_purge(r, now_unix))
    }

    fn rollback_last_clear(&self, vm_id: &str) -> Result<Option<RollbackClear>> {
        let rows = self.cache.lock().map_err(|_| lock_poisoned())?;
        Ok(rb_last_clear(&rows, vm_id))
    }

    fn commit_rollback(
        &self,
        vm_id: &str,
        restore_id: &str,
        value: u64,
        now_unix: u64,
        apply_stamp: &mut dyn FnMut(&RollbackArm) -> Result<()>,
    ) -> Result<RollbackArm> {
        let mut rows = self.cache.lock().map_err(|_| lock_poisoned())?;
        let arm = rb_check_for_commit(&rows, vm_id, restore_id, value, now_unix)?;
        // (i) the stamp store — under THIS lock, after the arm was
        // re-validated, so no stale or concurrent release can lower the
        // stamp for an arm that is no longer live.
        apply_stamp(&arm)?;
        // (ii) consume (persisted first), then the counter.
        self.mutate_rollback_locked(&mut rows, |r| rb_consume(r, &arm, value, now_unix))?;
        self.set_armed_and_persist_locked(&mut rows, vm_id, false)?;
        self.insert_and_persist_locked(&mut rows, vm_id, value)?;
        Ok(arm)
    }
}

fn rb_state(rows: &Rows, vm_id: &str) -> (Option<RollbackArm>, Option<LastRollback>) {
    (
        rows.rollback.arms.get(vm_id).cloned(),
        rows.rollback
            .history
            .get(vm_id)
            .and_then(|h| h.last_rollback.clone()),
    )
}

/// In-memory test double. Mirrors [`FileBootCounterStore`]'s semantics
/// without touching disk. Used by every release-path test that does
/// not care about the on-disk format. Production code MUST use the
/// file-backed impl.
#[derive(Default)]
pub struct InMemoryBootCounterStore {
    inner: Mutex<Rows>,
}

impl BootCounterStore for InMemoryBootCounterStore {
    fn check_only(&self, vm_id: &str, submitted: u64) -> Result<u64> {
        let g = self
            .inner
            .lock()
            .map_err(|_| KbsError::Policy("boot-counter lock poisoned".into()))?;
        let stored = g.counters.get(vm_id).copied().unwrap_or(0);
        let expected = stored
            .checked_add(1)
            .ok_or_else(|| KbsError::Policy("boot-counter overflow".into()))?;
        if submitted != expected {
            let class = refusal_class(submitted, stored);
            return Err(KbsError::Policy(format!(
                "{class}: vm_id={vm_id} submitted={submitted} expected={expected} \
                 (stored={stored})"
            )));
        }
        Ok(submitted)
    }

    fn commit(&self, vm_id: &str, value: u64) -> Result<()> {
        self.commit_reporting(vm_id, value).map(|_| ())
    }

    fn commit_reporting(&self, vm_id: &str, value: u64) -> Result<Option<RollbackArm>> {
        self.commit_reporting_guarded(vm_id, value, None, &mut || Ok(()))
    }

    fn commit_reporting_guarded(
        &self,
        vm_id: &str,
        value: u64,
        clear_at_unix: Option<u64>,
        guard: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Option<RollbackArm>> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let stored = g.counters.get(vm_id).copied().unwrap_or(0);
        if value <= stored {
            return Err(KbsError::Policy(format!(
                "boot-counter commit: vm_id={vm_id} value={value} <= stored={stored} \
                 (concurrent advance)"
            )));
        }
        guard()?;
        // A successful commit consumes any arm (resync AND rollback) —
        // same contract as the file-backed store, or the double would
        // hide a missing disarm.
        g.armed.remove(vm_id);
        let cleared = match clear_at_unix {
            Some(now) => rb_clear(&mut g, vm_id, CLEAR_BY_BOOT, now),
            None => g.rollback.arms.remove(vm_id),
        };
        g.counters.insert(vm_id.to_string(), value);
        Ok(cleared)
    }

    fn get(&self, vm_id: &str) -> Result<u64> {
        let g = self
            .inner
            .lock()
            .map_err(|_| KbsError::Policy("boot-counter lock poisoned".into()))?;
        Ok(g.counters.get(vm_id).copied().unwrap_or(0))
    }

    fn seed(&self, vm_id: &str, value: u64) -> Result<SeedOutcome> {
        // Same three guards, same order, as FileBootCounterStore — the
        // double is only useful as a test double if it refuses the same
        // things the production impl refuses.
        if value > MAX_SEED_COUNTER {
            return Ok(SeedOutcome::AboveCap {
                requested: value,
                cap: MAX_SEED_COUNTER,
            });
        }
        let mut g = self
            .inner
            .lock()
            .map_err(|_| KbsError::Policy("boot-counter lock poisoned".into()))?;
        let stored = g.counters.get(vm_id).copied().unwrap_or(0);
        if stored != 0 {
            return Ok(SeedOutcome::AlreadyRecovered { stored });
        }
        if value <= stored {
            return Ok(SeedOutcome::Refused { stored });
        }
        g.counters.insert(vm_id.to_string(), value);
        Ok(SeedOutcome::Seeded { previous: stored })
    }

    fn arm_resync(&self, vm_id: &str) -> Result<ResyncOutcome> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| KbsError::Policy("boot-counter lock poisoned".into()))?;
        let stored = g.counters.get(vm_id).copied().unwrap_or(0);
        if stored == 0 {
            return Ok(ResyncOutcome::NothingToResync);
        }
        let already_armed = !g.armed.insert(vm_id.to_string());
        Ok(ResyncOutcome::Armed {
            stored,
            already_armed,
        })
    }

    fn resync_armed(&self, vm_id: &str) -> Result<bool> {
        let g = self
            .inner
            .lock()
            .map_err(|_| KbsError::Policy("boot-counter lock poisoned".into()))?;
        Ok(g.armed.contains(vm_id))
    }

    fn rollback_state(&self, vm_id: &str) -> Result<(Option<RollbackArm>, Option<LastRollback>)> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(rb_state(&g, vm_id))
    }

    fn with_counter_locked(&self, vm_id: &str, f: &mut dyn FnMut(u64) -> Result<()>) -> Result<()> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        f(g.counters.get(vm_id).copied().unwrap_or(0))
    }

    fn arm_rollback(
        &self,
        arm: RollbackArm,
        min_interval_s: u64,
        now_unix: u64,
    ) -> Result<ArmRollbackOutcome> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(rb_arm(&mut g, arm, min_interval_s, now_unix))
    }

    fn disarm_rollback(
        &self,
        vm_id: &str,
        restore_id: &str,
        note_at_unix: Option<u64>,
    ) -> Result<Option<RollbackArm>> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(rb_disarm(&mut g, vm_id, restore_id, note_at_unix))
    }

    fn clear_rollback_arm(
        &self,
        vm_id: &str,
        reason: &str,
        now_unix: u64,
    ) -> Result<Option<RollbackArm>> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(rb_clear(&mut g, vm_id, reason, now_unix))
    }

    fn purge_expired_rollback_arms(&self, now_unix: u64) -> Result<Vec<RollbackArm>> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(rb_purge(&mut g, now_unix))
    }

    fn rollback_last_clear(&self, vm_id: &str) -> Result<Option<RollbackClear>> {
        let g = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(rb_last_clear(&g, vm_id))
    }

    fn commit_rollback(
        &self,
        vm_id: &str,
        restore_id: &str,
        value: u64,
        now_unix: u64,
        apply_stamp: &mut dyn FnMut(&RollbackArm) -> Result<()>,
    ) -> Result<RollbackArm> {
        let mut g = self.inner.lock().map_err(|_| lock_poisoned())?;
        let arm = rb_check_for_commit(&g, vm_id, restore_id, value, now_unix)?;
        apply_stamp(&arm)?;
        rb_consume(&mut g, &arm, value, now_unix);
        g.armed.remove(vm_id);
        g.counters.insert(vm_id.to_string(), value);
        Ok(arm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn first_boot_must_submit_exactly_one() {
        let s = InMemoryBootCounterStore::default();
        assert!(s.check_and_advance("vm-1", 0).is_err());
        assert!(s.check_and_advance("vm-1", 2).is_err());
        assert_eq!(s.check_and_advance("vm-1", 1).unwrap(), 1);
        assert_eq!(s.get("vm-1").unwrap(), 1);
    }

    #[test]
    fn subsequent_boots_must_strictly_increment_by_one() {
        let s = InMemoryBootCounterStore::default();
        assert_eq!(s.check_and_advance("vm-2", 1).unwrap(), 1);
        assert_eq!(s.check_and_advance("vm-2", 2).unwrap(), 2);
        // Skips fail — the guest is supposed to read the previous
        // value from durable storage and submit prev+1.
        assert!(s.check_and_advance("vm-2", 4).is_err());
        // Rewinds fail — a miner rolled back the disk OR the guest
        // is buggy.
        assert!(s.check_and_advance("vm-2", 2).is_err());
        // After both failures the store is unchanged, so the next
        // legitimate submission still works.
        assert_eq!(s.check_and_advance("vm-2", 3).unwrap(), 3);
    }

    #[test]
    fn per_vm_id_isolation() {
        let s = InMemoryBootCounterStore::default();
        assert_eq!(s.check_and_advance("vm-a", 1).unwrap(), 1);
        assert_eq!(s.check_and_advance("vm-a", 2).unwrap(), 2);
        // vm-b is starting fresh — its counter is independent.
        assert_eq!(s.check_and_advance("vm-b", 1).unwrap(), 1);
        assert_eq!(s.get("vm-a").unwrap(), 2);
        assert_eq!(s.get("vm-b").unwrap(), 1);
    }

    #[test]
    fn file_backed_persists_across_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counter.json");
        {
            let s = FileBootCounterStore::open(&path).unwrap();
            s.check_and_advance("vm-x", 1).unwrap();
            s.check_and_advance("vm-x", 2).unwrap();
            s.check_and_advance("vm-y", 1).unwrap();
        }
        // Re-open and verify the cache rehydrated.
        let s = FileBootCounterStore::open(&path).unwrap();
        assert_eq!(s.get("vm-x").unwrap(), 2);
        assert_eq!(s.get("vm-y").unwrap(), 1);
        // Rollback attempt fails even across re-opens.
        assert!(s.check_and_advance("vm-x", 1).is_err());
        assert!(s.check_and_advance("vm-x", 2).is_err());
        // Legitimate next boot succeeds.
        assert_eq!(s.check_and_advance("vm-x", 3).unwrap(), 3);
    }

    #[test]
    fn second_handle_over_same_file_is_stale_until_reopen() {
        // RA-L-NEW-2 rationale, made executable: `FileBootCounterStore`
        // caches in memory and `get()` reads the cache, so a SECOND
        // handle opened over the same file freezes at ITS open-time
        // snapshot and does NOT observe advances made through the first
        // handle. This is exactly why the KBS admin readout must SHARE
        // the release path's handle (one `Arc`) rather than open its own.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counter.json");

        let release = FileBootCounterStore::open(&path).unwrap();
        release.check_and_advance("vm-x", 1).unwrap();

        // A separate admin-style handle opened now sees the value 1…
        let admin_separate = FileBootCounterStore::open(&path).unwrap();
        assert_eq!(admin_separate.get("vm-x").unwrap(), 1);

        // …but a later release advance is INVISIBLE to that stale handle.
        release.check_and_advance("vm-x", 2).unwrap();
        assert_eq!(
            admin_separate.get("vm-x").unwrap(),
            1,
            "a separate handle serves its stale open-time snapshot (the bug)"
        );

        // The FIX: a SHARED handle (one Arc) always reflects advances —
        // this is what wiring.rs now passes to build_admin_state.
        let shared = Arc::new(release);
        let admin_shared = Arc::clone(&shared);
        shared.check_and_advance("vm-x", 3).unwrap();
        assert_eq!(
            admin_shared.get("vm-x").unwrap(),
            3,
            "the shared handle reflects the latest advance"
        );
    }

    #[test]
    fn check_only_does_not_persist() {
        // The two-phase guarantee: check_only validates but leaves the
        // store untouched, so a release that fails AFTER the check (and
        // never reaches commit) does not advance the counter.
        let s = InMemoryBootCounterStore::default();
        assert_eq!(s.check_only("vm-1", 1).unwrap(), 1);
        // No commit happened — still fresh, a re-check of 1 still OK.
        assert_eq!(s.get("vm-1").unwrap(), 0);
        assert_eq!(s.check_only("vm-1", 1).unwrap(), 1);
        // The guest's NEXT boot (release failed last time) resubmits 1
        // and is still accepted — no spurious rollback rejection.
        assert!(s.check_only("vm-1", 2).is_err());
    }

    #[test]
    fn commit_advances_and_is_monotonic() {
        let s = InMemoryBootCounterStore::default();
        s.check_only("vm-1", 1).unwrap();
        s.commit("vm-1", 1).unwrap();
        assert_eq!(s.get("vm-1").unwrap(), 1);
        // Re-committing the same or a lower value is refused (a
        // concurrent release already advanced past it).
        assert!(s.commit("vm-1", 1).is_err());
        assert!(s.commit("vm-1", 0).is_err());
        // The next legitimate boot: check 2 then commit 2.
        assert_eq!(s.check_only("vm-1", 2).unwrap(), 2);
        s.commit("vm-1", 2).unwrap();
        assert_eq!(s.get("vm-1").unwrap(), 2);
    }

    #[test]
    fn failed_release_then_retry_succeeds_file_backed() {
        // End-to-end of the bug fix on the durable store: a guest boots,
        // the KBS checks the counter (ok) but the release fails before
        // commit; the guest reboots and resubmits the SAME value, which
        // must still be accepted (the counter never advanced).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counter.json");
        let s = FileBootCounterStore::open(&path).unwrap();
        // Boot 1, release fails after check (no commit).
        assert_eq!(s.check_only("vm-x", 1).unwrap(), 1);
        assert_eq!(s.get("vm-x").unwrap(), 0);
        // Boot 2 (retry): same submitted value, accepted + committed.
        assert_eq!(s.check_only("vm-x", 1).unwrap(), 1);
        s.commit("vm-x", 1).unwrap();
        assert_eq!(s.get("vm-x").unwrap(), 1);
        // Survives reopen.
        drop(s);
        let s = FileBootCounterStore::open(&path).unwrap();
        assert_eq!(s.get("vm-x").unwrap(), 1);
    }

    #[test]
    fn file_backed_open_returns_empty_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let s = FileBootCounterStore::open(&path).unwrap();
        assert_eq!(s.get("any-vm").unwrap(), 0);
    }

    // ── operator seed (disaster recovery after a state-dir wipe) ────

    #[test]
    fn seed_from_absent_raises_the_counter_and_get_reflects_it() {
        // CLAIM: seeding an absent (== 0) counter to N succeeds and
        // `get` then returns N. This is the whole recovery path: a
        // wiped `boot-counters.json` is re-established from the
        // miner-side state disk.
        for_each_store(|s| {
            assert_eq!(s.get("vm-seed").unwrap(), 0);
            assert_eq!(
                s.seed("vm-seed", 7).unwrap(),
                SeedOutcome::Seeded { previous: 0 }
            );
            assert_eq!(s.get("vm-seed").unwrap(), 7);
        });
    }

    #[test]
    fn seed_leaves_the_check_gate_intact_at_stored_plus_one() {
        // CLAIM: after seeding to N the anti-rollback gate is EXACTLY
        // where it would be had the VM booted N times — N+1 is the only
        // accepted submission. A seed that widened the gate (or that
        // silently advanced/rewound the store) breaks this.
        for_each_store(|s| {
            assert!(matches!(
                s.seed("vm-gate", 5).unwrap(),
                SeedOutcome::Seeded { .. }
            ));
            // The replayed value the miner already burned: refused.
            assert!(s.check_only("vm-gate", 5).is_err());
            // A skip: refused.
            assert!(s.check_only("vm-gate", 7).is_err());
            // The legitimate next boot: accepted.
            assert_eq!(s.check_only("vm-gate", 6).unwrap(), 6);
        });
    }

    #[test]
    fn seed_onto_a_live_counter_is_refused_in_every_direction_and_writes_nothing() {
        // CLAIM (guard 1, the DoS closure): once a counter is non-zero
        // the endpoint is INERT. Not just downward — an UPWARD seed is
        // refused too, which is what stops admin-listener access from
        // bricking a running tenant by jumping its counter out of reach.
        // Asserting only the refusal would pass under a mutant that
        // refuses AND still mutates, so every branch asserts `get`.
        for_each_store(|s| {
            s.seed("vm-live", 9).unwrap();
            assert_eq!(s.get("vm-live").unwrap(), 9);

            // Lower, equal, higher, and the old brick vector: all refused
            // with the SAME distinct verdict, all leaving 9 in place.
            for attempt in [3u64, 9, 10, MAX_SEED_COUNTER] {
                assert_eq!(
                    s.seed("vm-live", attempt).unwrap(),
                    SeedOutcome::AlreadyRecovered { stored: 9 },
                    "attempt {attempt}"
                );
                assert_eq!(s.get("vm-live").unwrap(), 9, "attempt {attempt}");
            }

            // …and the gate still sits at 9, i.e. no refusal leaked a
            // partial write that would re-admit a burned boot or push the
            // gate somewhere the guest's disk can never reach.
            assert!(s.check_only("vm-live", 4).is_err());
            assert_eq!(s.check_only("vm-live", 10).unwrap(), 10);

            // Boundary: a counter of 1 — a VM that has booted EXACTLY
            // once, the most common live state there is — is live too.
            // Guard 1 keys on "non-zero", not on "large".
            s.check_and_advance("vm-once", 1).unwrap();
            assert_eq!(
                s.seed("vm-once", MAX_SEED_COUNTER).unwrap(),
                SeedOutcome::AlreadyRecovered { stored: 1 }
            );
            assert_eq!(s.get("vm-once").unwrap(), 1);
        });
    }

    #[test]
    fn re_running_a_recovery_refuses_rather_than_overwriting() {
        // CLAIM: seeding the SAME value twice is not idempotent — the
        // second call is refused. Deliberate and fail-safe: a repeat is
        // either a duplicate (harmless to refuse) or a disagreement about
        // the true value (must not silently overwrite).
        for_each_store(|s| {
            assert_eq!(
                s.seed("vm-again", 7).unwrap(),
                SeedOutcome::Seeded { previous: 0 }
            );
            assert_eq!(
                s.seed("vm-again", 7).unwrap(),
                SeedOutcome::AlreadyRecovered { stored: 7 }
            );
            assert_eq!(s.get("vm-again").unwrap(), 7);
        });
    }

    #[test]
    fn seed_above_the_cap_is_refused_and_writes_nothing() {
        // CLAIM (guard 2): an implausible value cannot be written even
        // onto a WIPED row. Without this, one request sets a counter the
        // guest can never reach from its own disk — an irreversible brick,
        // because `seed` is deliberately one-way.
        for_each_store(|s| {
            for attempt in [MAX_SEED_COUNTER + 1, u64::MAX] {
                assert_eq!(
                    s.seed("vm-cap", attempt).unwrap(),
                    SeedOutcome::AboveCap {
                        requested: attempt,
                        cap: MAX_SEED_COUNTER,
                    },
                    "attempt {attempt}"
                );
                assert_eq!(s.get("vm-cap").unwrap(), 0, "attempt {attempt}");
            }
            // Still a virgin VM: first boot submits 1 and is accepted.
            assert_eq!(s.check_only("vm-cap", 1).unwrap(), 1);

            // Precedence, pinned: on a LIVE row an over-cap value still
            // reports the cap (the cheap stateless check runs first), so
            // the operator is told what is actually wrong with the number
            // they sent rather than only that the row is occupied.
            s.seed("vm-cap", 5).unwrap();
            assert_eq!(
                s.seed("vm-cap", MAX_SEED_COUNTER + 1).unwrap(),
                SeedOutcome::AboveCap {
                    requested: MAX_SEED_COUNTER + 1,
                    cap: MAX_SEED_COUNTER,
                }
            );
            assert_eq!(s.get("vm-cap").unwrap(), 5);
        });
    }

    #[test]
    fn seed_at_exactly_the_cap_is_accepted() {
        // CLAIM: the cap is inclusive — pins the boundary so a `>=`/`>`
        // slip is a test failure rather than a silently narrower endpoint.
        // (That the constant itself stays SMALL is enforced at compile
        // time next to its definition, not here.)
        for_each_store(|s| {
            assert_eq!(
                s.seed("vm-atcap", MAX_SEED_COUNTER).unwrap(),
                SeedOutcome::Seeded { previous: 0 }
            );
            assert_eq!(s.get("vm-atcap").unwrap(), MAX_SEED_COUNTER);
        });
    }

    #[test]
    fn seed_zero_on_a_fresh_vm_is_refused_and_writes_nothing() {
        // CLAIM (guard 3, at its one reachable input): with guard 1 in
        // place the monotonic rule can only ever fire for `0` on a wiped
        // row — and it does. It must not create a row either: an explicit
        // `{vm: 0}` entry is indistinguishable from absent today, but a
        // future reader must not see a value the operator never
        // legitimately established.
        for_each_store(|s| {
            assert_eq!(
                s.seed("vm-zero", 0).unwrap(),
                SeedOutcome::Refused { stored: 0 }
            );
            assert_eq!(s.get("vm-zero").unwrap(), 0);
            // Still a virgin VM: first boot submits 1 and is accepted.
            assert_eq!(s.check_only("vm-zero", 1).unwrap(), 1);
        });

        // …and "no row" means literally no row ON DISK. `get` cannot see
        // the difference (absent and 0 both read as 0), so the raw file is
        // the only place a refusal that still wrote would show up.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counter.json");
        let s = FileBootCounterStore::open(&path).unwrap();
        assert_eq!(
            s.seed("vm-zero", 0).unwrap(),
            SeedOutcome::Refused { stored: 0 }
        );
        let on_disk: HashMap<String, u64> = match fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).unwrap(),
            // Not writing the file at all is the strongest form of "no row".
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => panic!("unexpected read error: {e}"),
        };
        assert!(
            on_disk.is_empty(),
            "a refused seed must not create a row on disk, got {on_disk:?}"
        );
    }

    #[test]
    fn seed_persists_and_every_refusal_is_fail_closed_on_disk_too() {
        // CLAIM: all of it survives a process restart — the accepted seed
        // is durable, and NEITHER refusal (already-recovered, above-cap)
        // left a trace in the file, not just in the in-memory cache.
        // Re-opening the store is the only way to see what hit disk.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counter.json");
        {
            let s = FileBootCounterStore::open(&path).unwrap();
            // A refusal on a wiped row must not create the file's row.
            assert_eq!(
                s.seed("vm-disk", MAX_SEED_COUNTER + 1).unwrap(),
                SeedOutcome::AboveCap {
                    requested: MAX_SEED_COUNTER + 1,
                    cap: MAX_SEED_COUNTER,
                }
            );
            assert_eq!(
                s.seed("vm-disk", 4).unwrap(),
                SeedOutcome::Seeded { previous: 0 }
            );
        }
        {
            // Fresh handle == fresh process: reads the file.
            let s = FileBootCounterStore::open(&path).unwrap();
            assert_eq!(s.get("vm-disk").unwrap(), 4);
            assert_eq!(
                s.seed("vm-disk", 2).unwrap(),
                SeedOutcome::AlreadyRecovered { stored: 4 }
            );
        }
        // Re-open AGAIN: the rejected 2 must not be on disk.
        let s = FileBootCounterStore::open(&path).unwrap();
        assert_eq!(s.get("vm-disk").unwrap(), 4);
        // And the raw bytes agree — no schema smuggling, exactly one row.
        let parsed: HashMap<String, u64> =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(parsed.get("vm-disk").copied(), Some(4));
        assert_eq!(parsed.len(), 1);
    }

    /// A store whose parent directory does not exist: `open` succeeds
    /// (a missing file just means an empty store) but every `persist`
    /// fails for real, inside `persist_locked`, at the tmp-file open.
    /// No mock, no injected seam — the actual write path fails the way
    /// a full or read-only disk fails, which is the point: the bug being
    /// tested lives in the interaction between the write and the cache.
    fn unwritable_store(dir: &std::path::Path) -> (FileBootCounterStore, PathBuf, PathBuf) {
        let missing = dir.join("not-created-yet");
        let path = missing.join("boot-counter.json");
        let s = FileBootCounterStore::open(&path).unwrap();
        (s, missing, path)
    }

    #[test]
    fn a_failed_seed_persist_leaves_no_trace_and_does_not_lock_out_the_retry() {
        // CLAIM: `seed` is all-or-nothing. When the disk write fails the
        // cache must NOT keep the value, or guard 1 sees a non-zero row
        // and refuses the operator's retry with `AlreadyRecovered` — a
        // write that never landed would lock them out of the recovery
        // until the pod restarted.
        let dir = tempfile::tempdir().unwrap();
        let (s, missing, path) = unwritable_store(dir.path());

        assert!(
            s.seed("vm-io", 5).is_err(),
            "a failed persist must be reported, not swallowed"
        );
        // In-memory: unchanged.
        assert_eq!(s.get("vm-io").unwrap(), 0, "cache must be rolled back");
        // On disk: unchanged (nothing was ever written).
        assert!(!path.exists());
        assert_eq!(
            FileBootCounterStore::open(&path)
                .unwrap()
                .get("vm-io")
                .unwrap(),
            0,
            "a fresh handle must agree with the cache"
        );
        // The gate is untouched: this is still a virgin VM.
        assert_eq!(s.check_only("vm-io", 1).unwrap(), 1);

        // The operator fixes the disk and retries the SAME value: it
        // must SUCCEED. Under the old insert-then-persist shape this is
        // a 409 `seed-already-recovered` forever.
        fs::create_dir_all(&missing).unwrap();
        assert_eq!(
            s.seed("vm-io", 5).unwrap(),
            SeedOutcome::Seeded { previous: 0 },
            "the retry after a transient write failure must work"
        );
        assert_eq!(s.get("vm-io").unwrap(), 5);
        assert_eq!(
            FileBootCounterStore::open(&path)
                .unwrap()
                .get("vm-io")
                .unwrap(),
            5
        );
    }

    #[test]
    fn a_failed_commit_persist_leaves_the_counter_exactly_where_it_was() {
        // CLAIM: same all-or-nothing invariant on the RELEASE path, and
        // the rollback must RESTORE the previous value, not drop the row
        // (the seed test only covers the absent-row case). A cache left
        // running ahead of the file refuses every later boot of this VM
        // as a rollback until the process restarts.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counter.json");
        let s = FileBootCounterStore::open(&path).unwrap();
        s.check_and_advance("vm-c", 1).unwrap();
        s.check_and_advance("vm-c", 2).unwrap();
        assert_eq!(s.get("vm-c").unwrap(), 2);

        // Make the real write fail, mid-life, with a row already present.
        fs::remove_dir_all(dir.path()).unwrap();
        assert!(s.commit("vm-c", 3).is_err());

        // The previous value is restored — not removed, not advanced.
        assert_eq!(s.get("vm-c").unwrap(), 2, "commit must roll back to 2");
        // And the release gate still expects the same boot as before, so
        // the guest's retry of the SAME boot is accepted.
        assert!(s.check_only("vm-c", 4).is_err());
        assert_eq!(s.check_only("vm-c", 3).unwrap(), 3);

        // Once the disk is back, the very same commit lands.
        fs::create_dir_all(dir.path()).unwrap();
        s.commit("vm-c", 3).unwrap();
        assert_eq!(s.get("vm-c").unwrap(), 3);
        assert_eq!(
            FileBootCounterStore::open(&path)
                .unwrap()
                .get("vm-c")
                .unwrap(),
            3
        );
    }

    #[test]
    fn a_failed_persist_does_not_disturb_other_vms() {
        // CLAIM: the rollback is per-row. `persist_locked` serialises the
        // WHOLE map, so a naive "reload from disk to undo" would also
        // discard other VMs' committed counters.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counter.json");
        let s = FileBootCounterStore::open(&path).unwrap();
        s.check_and_advance("vm-keep", 1).unwrap();

        fs::remove_dir_all(dir.path()).unwrap();
        assert!(s.seed("vm-new", 9).is_err());

        assert_eq!(s.get("vm-keep").unwrap(), 1, "neighbour must survive");
        assert_eq!(s.get("vm-new").unwrap(), 0);
    }

    #[test]
    fn seed_is_per_vm_and_does_not_disturb_neighbours() {
        for_each_store(|s| {
            s.check_and_advance("vm-a", 1).unwrap();
            s.seed("vm-b", 42).unwrap();
            assert_eq!(s.get("vm-a").unwrap(), 1);
            assert_eq!(s.get("vm-b").unwrap(), 42);
            // vm-a's gate is untouched by vm-b's seed.
            assert_eq!(s.check_only("vm-a", 2).unwrap(), 2);
        });
    }

    // ── refusal classification (lost vs rewind vs skip) ─────────────

    #[test]
    fn a_lost_counter_is_classified_apart_from_a_rollback_attempt() {
        // CLAIM: the three refusal shapes get DISTINCT, stable
        // classifiers, and the one that matters — "the guest submitted
        // 1 against a live counter", the signature of a LOST state disk
        // — is not buried under the rollback code. An operator decides
        // whether to arm a resync off this string; if `lost` and
        // `rewind` collapsed into one, the decision would be blind.
        //
        // `submitted == 1 && stored == 1` is inherently ambiguous and is
        // reported as `lost`: that is the actionable reading, and the
        // action it leads to cannot lower the counter.
        assert_eq!(refusal_class(1, 5), "boot-counter-lost");
        assert_eq!(refusal_class(1, 1), "boot-counter-lost");
        assert_eq!(refusal_class(3, 5), "boot-counter-rewind");
        assert_eq!(refusal_class(5, 5), "boot-counter-rewind");
        assert_eq!(refusal_class(0, 0), "boot-counter-rewind");
        assert_eq!(refusal_class(9, 5), "boot-counter-skip");
        assert_eq!(refusal_class(3, 0), "boot-counter-skip");
    }

    #[test]
    fn the_refusal_text_carries_the_classifier_and_the_arithmetic() {
        // CLAIM: the class is IN the message, not just computable from
        // it. `release::process_release` records the refusal string
        // verbatim in the audit sink and returns it in the signed
        // denial, so this string is the whole operator-facing signal.
        for_each_store(|s| {
            s.check_and_advance("vm-cls", 1).unwrap();
            s.check_and_advance("vm-cls", 2).unwrap();

            let lost = s.check_only("vm-cls", 1).unwrap_err().to_string();
            assert!(lost.contains("boot-counter-lost"), "{lost}");
            assert!(lost.contains("submitted=1"), "{lost}");
            assert!(lost.contains("expected=3"), "{lost}");
            assert!(lost.contains("stored=2"), "{lost}");

            let rewind = s.check_only("vm-cls", 2).unwrap_err().to_string();
            assert!(rewind.contains("boot-counter-rewind"), "{rewind}");

            let skip = s.check_only("vm-cls", 9).unwrap_err().to_string();
            assert!(skip.contains("boot-counter-skip"), "{skip}");

            // Classifying changed no verdict: all three are still
            // refusals and the store is where it was.
            assert_eq!(s.get("vm-cls").unwrap(), 2);
        });
    }

    // ── operator resync arm (recovery for a LOST miner state disk) ──

    #[test]
    fn arming_does_not_move_the_counter_and_does_not_open_the_store_gate() {
        // CLAIM: `arm_resync` is not a counter write and not a relaxation
        // of the store's CAS. It records an operator's intent; the
        // release path is the only place that acts on it. If arming
        // itself made `check_only` permissive, EVERY later gate that
        // consults the store would be silently relaxed too.
        for_each_store(|s| {
            s.check_and_advance("vm-arm", 1).unwrap();
            s.check_and_advance("vm-arm", 2).unwrap();

            assert_eq!(
                s.arm_resync("vm-arm").unwrap(),
                ResyncOutcome::Armed {
                    stored: 2,
                    already_armed: false
                }
            );
            assert!(s.resync_armed("vm-arm").unwrap());
            // The counter did NOT move.
            assert_eq!(s.get("vm-arm").unwrap(), 2);
            // …and the CAS is exactly as strict as it was.
            assert!(s.check_only("vm-arm", 1).is_err());
            assert!(s.check_only("vm-arm", 2).is_err());
            assert!(s.check_only("vm-arm", 9).is_err());
            assert_eq!(s.check_only("vm-arm", 3).unwrap(), 3);
        });
    }

    #[test]
    fn arming_a_never_counted_vm_is_refused_and_leaves_no_arm() {
        // CLAIM (guard 1): a `stored == 0` row needs no resync — a guest
        // with no state disk submits 1, which that row accepts on the
        // normal path. Refusing keeps a typo'd vm_id from leaving a
        // silent one-shot arm sitting on a row that later becomes some
        // real VM's first boot.
        for_each_store(|s| {
            assert_eq!(
                s.arm_resync("vm-never").unwrap(),
                ResyncOutcome::NothingToResync
            );
            assert!(!s.resync_armed("vm-never").unwrap());
            assert_eq!(s.get("vm-never").unwrap(), 0);
            // Still a virgin VM: first boot submits 1 and is accepted.
            assert_eq!(s.check_only("vm-never", 1).unwrap(), 1);
        });
    }

    #[test]
    fn re_arming_reports_already_armed_and_changes_nothing() {
        // CLAIM: arming is idempotent but not SILENT — a re-drive is
        // reported as such so the admin chain does not read as two
        // separate incidents (and so `applied` stays honest).
        for_each_store(|s| {
            s.check_and_advance("vm-again", 1).unwrap();
            assert_eq!(
                s.arm_resync("vm-again").unwrap(),
                ResyncOutcome::Armed {
                    stored: 1,
                    already_armed: false
                }
            );
            assert_eq!(
                s.arm_resync("vm-again").unwrap(),
                ResyncOutcome::Armed {
                    stored: 1,
                    already_armed: true
                }
            );
            assert_eq!(s.get("vm-again").unwrap(), 1);
        });
    }

    #[test]
    fn a_successful_commit_consumes_the_arm() {
        // CLAIM: the arm is ONE-SHOT. It is cleared by any successful
        // commit for that VM — the release that used it, or (for a
        // mis-armed VM) that VM's next ordinary boot. An arm that
        // outlived its release would be a lingering bypass nobody is
        // watching.
        for_each_store(|s| {
            s.check_and_advance("vm-1shot", 1).unwrap();
            s.arm_resync("vm-1shot").unwrap();
            assert!(s.resync_armed("vm-1shot").unwrap());

            s.check_only("vm-1shot", 2).unwrap();
            s.commit("vm-1shot", 2).unwrap();

            assert!(
                !s.resync_armed("vm-1shot").unwrap(),
                "the arm must not survive a successful commit"
            );
            assert_eq!(s.get("vm-1shot").unwrap(), 2);
        });
    }

    #[test]
    fn a_refused_commit_does_not_consume_the_arm() {
        // CLAIM: only a SUCCESSFUL commit consumes the arm. A release
        // that is denied after the counter check never reaches commit,
        // and a commit refused as non-monotonic wrote nothing — in
        // neither case did the operator's recovery happen, so the arm
        // must still be there for the retry.
        for_each_store(|s| {
            s.check_and_advance("vm-keep-arm", 1).unwrap();
            s.check_and_advance("vm-keep-arm", 2).unwrap();
            s.arm_resync("vm-keep-arm").unwrap();

            assert!(s.commit("vm-keep-arm", 2).is_err(), "not > stored");
            assert!(s.commit("vm-keep-arm", 1).is_err(), "below stored");

            assert!(s.resync_armed("vm-keep-arm").unwrap());
            assert_eq!(s.get("vm-keep-arm").unwrap(), 2);
        });
    }

    #[test]
    fn arms_are_per_vm() {
        for_each_store(|s| {
            s.check_and_advance("vm-a", 1).unwrap();
            s.check_and_advance("vm-b", 1).unwrap();
            s.arm_resync("vm-a").unwrap();
            assert!(s.resync_armed("vm-a").unwrap());
            assert!(!s.resync_armed("vm-b").unwrap());
            // Committing for the NEIGHBOUR must not consume a's arm.
            s.commit("vm-b", 2).unwrap();
            assert!(s.resync_armed("vm-a").unwrap());
        });
    }

    #[test]
    fn arms_persist_across_a_restart_and_live_in_a_sibling_file() {
        // CLAIM (durability): the KBS can restart between the operator's
        // arm and the guest's next boot, so the arm has to survive a
        // reopen like the counter does.
        //
        // CLAIM (compatibility, and this is the load-bearing half): the
        // COUNTER file's shape is UNCHANGED — still `{vm_id: u64}`. An
        // older KBS binary decodes that map strictly, so had the arm
        // been added as a richer row, rolling the binary back would make
        // `open` fail and the KBS refuse to start, locking out every
        // tenant on the safe move. Asserting the raw bytes is the only
        // way this stays true.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counters.json");
        let sibling = dir.path().join("boot-counters-resync.json");
        {
            let s = FileBootCounterStore::open(&path).unwrap();
            s.check_and_advance("vm-p", 1).unwrap();
            s.check_and_advance("vm-p", 2).unwrap();
            s.arm_resync("vm-p").unwrap();
        }
        // The counter file is still exactly the legacy shape.
        let counters: HashMap<String, u64> =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(counters.get("vm-p").copied(), Some(2));
        assert_eq!(counters.len(), 1);
        // The arm went to the sibling.
        let armed: Vec<String> = serde_json::from_slice(&fs::read(&sibling).unwrap()).unwrap();
        assert_eq!(armed, vec!["vm-p".to_string()]);

        // Fresh handle == fresh process.
        let s = FileBootCounterStore::open(&path).unwrap();
        assert!(s.resync_armed("vm-p").unwrap());
        assert_eq!(s.get("vm-p").unwrap(), 2);
        // And the consumption is durable too.
        s.commit("vm-p", 3).unwrap();
        let s = FileBootCounterStore::open(&path).unwrap();
        assert!(!s.resync_armed("vm-p").unwrap());
        assert_eq!(s.get("vm-p").unwrap(), 3);
    }

    #[test]
    fn a_store_with_no_arms_file_opens_clean_and_unarmed() {
        // CLAIM: the arms file is optional. A state dir written by a
        // binary that predates arms (or a fresh one) opens with nothing
        // armed — fail-closed, i.e. strict.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counters.json");
        fs::write(&path, br#"{"vm-old":4}"#).unwrap();
        let s = FileBootCounterStore::open(&path).unwrap();
        assert_eq!(s.get("vm-old").unwrap(), 4);
        assert!(!s.resync_armed("vm-old").unwrap());
        assert!(s.check_only("vm-old", 1).is_err());
    }

    #[test]
    fn a_corrupt_arms_file_refuses_to_open_rather_than_starting_unarmed() {
        // CLAIM: same discipline as a corrupt counter file — refuse to
        // open. Silently starting with an empty arm set would be
        // fail-closed for the gate but would also silently discard an
        // operator's in-flight recovery; either way the operator must be
        // told, not guessed at.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counters.json");
        fs::write(&path, br#"{"vm-x":1}"#).unwrap();
        fs::write(dir.path().join("boot-counters-resync.json"), b"{not json").unwrap();
        assert!(FileBootCounterStore::open(&path).is_err());
    }

    #[test]
    fn a_failed_arm_persist_leaves_no_arm_in_memory_either() {
        // CLAIM: `arm_resync` is all-or-nothing. A cache left armed
        // after a failed write would report an arm the file does not
        // have — the operator sees success, and a KBS restart silently
        // revokes the recovery they think they made.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counters.json");
        let s = FileBootCounterStore::open(&path).unwrap();
        s.check_and_advance("vm-io", 1).unwrap();

        fs::remove_dir_all(dir.path()).unwrap();
        assert!(s.arm_resync("vm-io").is_err());
        assert!(
            !s.resync_armed("vm-io").unwrap(),
            "a failed persist must not leave the arm in the cache"
        );

        // Once the disk is back the very same arm lands.
        fs::create_dir_all(dir.path()).unwrap();
        assert!(matches!(
            s.arm_resync("vm-io").unwrap(),
            ResyncOutcome::Armed {
                already_armed: false,
                ..
            }
        ));
        assert!(s.resync_armed("vm-io").unwrap());
    }

    #[test]
    fn a_commit_that_cannot_persist_the_disarm_leaves_the_counter_alone() {
        // CLAIM: the disarm is persisted BEFORE the counter, and a
        // failure there aborts the commit outright. The alternative —
        // advance the counter, fail to clear the arm — would leave a
        // consumed arm still armed: a one-shot bypass that already fired
        // and is still loaded.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counters.json");
        let s = FileBootCounterStore::open(&path).unwrap();
        s.check_and_advance("vm-dis", 1).unwrap();
        s.arm_resync("vm-dis").unwrap();

        fs::remove_dir_all(dir.path()).unwrap();
        assert!(s.commit("vm-dis", 2).is_err());
        assert_eq!(s.get("vm-dis").unwrap(), 1, "the counter must not move");
        assert!(
            s.resync_armed("vm-dis").unwrap(),
            "a failed disarm must roll back, or the operator's recovery is lost"
        );
    }

    #[test]
    fn the_disarm_is_persisted_before_the_counter_not_after() {
        // CLAIM: the ORDER of the two writes inside `commit` is
        // load-bearing, and this is the only case that can tell them
        // apart — the arms file is unwritable while the counter file is
        // fine. (The test above removes the whole directory, so both
        // writes fail together and either order passes it.)
        //
        // Disarm-then-commit: the commit aborts, the counter does not
        // move, the arm survives, and the operator's next attempt is a
        // clean retry.
        //
        // Commit-then-disarm: the counter WOULD advance and the arm
        // would still be set — a one-shot bypass that has already fired
        // and is still loaded, on a VM nobody is looking at any more
        // because its boot succeeded.
        //
        // The injection is real, not a mock: a DIRECTORY sitting on the
        // arms file's tmp path makes exactly that one `open(..)` fail
        // with EISDIR while the counter file's own tmp path is
        // untouched.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counters.json");
        let s = FileBootCounterStore::open(&path).unwrap();
        s.check_and_advance("vm-ord", 1).unwrap();
        s.arm_resync("vm-ord").unwrap();

        fs::create_dir(dir.path().join(".boot-counters-resync.json.tmp")).unwrap();

        assert!(s.commit("vm-ord", 2).is_err(), "the commit must abort");
        assert_eq!(
            s.get("vm-ord").unwrap(),
            1,
            "the counter must NOT advance when the disarm could not be persisted"
        );
        assert_eq!(
            FileBootCounterStore::open(&path)
                .unwrap()
                .get("vm-ord")
                .unwrap(),
            1,
            "and not on disk either"
        );
        assert!(s.resync_armed("vm-ord").unwrap(), "the arm survives");
    }

    /// Run a store-contract assertion against BOTH implementations —
    /// the in-memory double and the file-backed production store must
    /// agree, or a test-only relaxation could hide a real hole.
    fn for_each_store(f: impl Fn(&dyn BootCounterStore)) {
        f(&InMemoryBootCounterStore::default());
        let dir = tempfile::tempdir().unwrap();
        let file = FileBootCounterStore::open(dir.path().join("boot-counter.json")).unwrap();
        f(&file);
    }

    #[test]
    fn file_backed_atomic_write_does_not_corrupt_on_partial_persist() {
        // Sanity check: the persist path uses tmp+rename, so a crash
        // between open(tmp) and rename leaves the live file intact.
        // We can't simulate the crash here, but we CAN verify the
        // file's contents after a successful advance match an
        // independently-encoded snapshot.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counter.json");
        let s = FileBootCounterStore::open(&path).unwrap();
        s.check_and_advance("vm-z", 1).unwrap();
        let bytes = fs::read(&path).unwrap();
        let parsed: HashMap<String, u64> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.get("vm-z").copied(), Some(1));
    }

    // ── authorized rollback (A2) arms ────────────────────────────────

    /// Every clear records its reason in the SAME write as the removal:
    /// expiry (one write for all), disarm, lifecycle, normal boot — and it
    /// survives a reopen. A take-back (`note_at_unix: None`) records none.
    #[test]
    fn every_arm_clear_records_last_clear_atomically_and_durably() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counters.json");
        let reason = |s: &FileBootCounterStore, vm: &str| {
            s.rollback_last_clear(vm)
                .unwrap()
                .map(|c| (c.restore_id, c.reason, c.at_unix))
        };
        {
            let s = FileBootCounterStore::open(&path).unwrap();
            for vm in ["vm-e", "vm-d", "vm-l", "vm-b", "vm-t"] {
                s.seed(vm, 5).unwrap();
                s.arm_rollback(rb_arm_for(vm, "r", 3, 100), 1800, 100)
                    .unwrap();
            }
            let purged = s.purge_expired_rollback_arms(100_000).unwrap();
            assert_eq!(purged.len(), 5, "every arm expired");
        }
        let s = FileBootCounterStore::open(&path).unwrap();
        assert_eq!(
            reason(&s, "vm-e"),
            Some(("r".into(), CLEAR_EXPIRED.into(), 100_000))
        );
        for vm in ["vm-d", "vm-l", "vm-b", "vm-t"] {
            s.arm_rollback(rb_arm_for(vm, "r2", 3, 200_000), 1800, 200_000)
                .unwrap();
        }
        s.disarm_rollback("vm-d", "r2", Some(200_001))
            .unwrap()
            .unwrap();
        s.clear_rollback_arm("vm-l", "rollback-lifecycle-activate", 200_002)
            .unwrap()
            .unwrap();
        s.commit_reporting_guarded("vm-b", 6, Some(200_003), &mut || Ok(()))
            .unwrap()
            .unwrap();
        s.disarm_rollback("vm-t", "r2", None).unwrap().unwrap();
        drop(s);
        let s = FileBootCounterStore::open(&path).unwrap();
        assert_eq!(
            reason(&s, "vm-d"),
            Some(("r2".into(), CLEAR_DISARMED.into(), 200_001))
        );
        assert_eq!(
            reason(&s, "vm-l"),
            Some(("r2".into(), "rollback-lifecycle-activate".into(), 200_002))
        );
        assert_eq!(
            reason(&s, "vm-b"),
            Some(("r2".into(), CLEAR_BY_BOOT.into(), 200_003))
        );
        assert_eq!(
            reason(&s, "vm-t"),
            Some(("r".into(), CLEAR_EXPIRED.into(), 100_000)),
            "a take-back records nothing new"
        );
    }

    fn rb_arm_for(vm: &str, restore_id: &str, from_counter: u64, now: u64) -> RollbackArm {
        RollbackArm {
            vm_id: vm.into(),
            restore_id: restore_id.into(),
            manifest_sha256_hex: "ab".repeat(32),
            new_gen: 2,
            dest: "aa".into(),
            from_counter,
            to_stamp: 1,
            checkpoint_sha256_hex: "cd".repeat(32),
            armed_at_unix: now,
            expires_at_unix: now + 600,
            requested_by: "tenant:1".into(),
            armed_by: String::new(),
        }
    }

    #[test]
    fn rollback_arms_live_in_a_sibling_file_and_the_counter_file_keeps_its_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counters.json");
        {
            let s = FileBootCounterStore::open(&path).unwrap();
            s.seed("vm-1", 5).unwrap();
            assert!(matches!(
                s.arm_rollback(rb_arm_for("vm-1", "r", 3, 100), 1800, 100)
                    .unwrap(),
                ArmRollbackOutcome::Armed(_)
            ));
        }
        // An OLDER binary decodes the counter file strictly as
        // `{vm_id: u64}` — it must still do so with an arm pending.
        let counters: HashMap<String, u64> =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(counters.get("vm-1"), Some(&5));
        assert!(dir.path().join("boot-counters-rollback-arms.json").exists());
        // The arm survives a restart.
        let s = FileBootCounterStore::open(&path).unwrap();
        assert_eq!(s.rollback_state("vm-1").unwrap().0.unwrap().restore_id, "r");
        assert_eq!(s.get("vm-1").unwrap(), 5);
    }

    #[test]
    fn a_corrupt_rollback_arms_file_refuses_to_open() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("boot-counters-rollback-arms.json"),
            b"{nope",
        )
        .unwrap();
        assert!(FileBootCounterStore::open(dir.path().join("boot-counters.json")).is_err());
    }

    #[test]
    fn a_failed_arm_write_leaves_no_arm_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-counters.json");
        let s = FileBootCounterStore::open(&path).unwrap();
        s.seed("vm-1", 5).unwrap();
        let blocker = dir.path().join(".boot-counters-rollback-arms.json.tmp");
        fs::create_dir(&blocker).unwrap();
        assert!(s
            .arm_rollback(rb_arm_for("vm-1", "r", 3, 100), 1800, 100)
            .is_err());
        assert!(s.rollback_state("vm-1").unwrap().0.is_none());
        fs::remove_dir(&blocker).unwrap();
        // …and the failed attempt did not start the rate-limit clock.
        assert!(matches!(
            s.arm_rollback(rb_arm_for("vm-1", "r", 3, 101), 1800, 101)
                .unwrap(),
            ArmRollbackOutcome::Armed(_)
        ));
    }

    #[test]
    fn commit_rollback_consumes_once_and_commits_stored_plus_one_in_both_stores() {
        for_each_store(|s| {
            s.seed("vm-1", 5).unwrap();
            s.arm_rollback(rb_arm_for("vm-1", "r", 3, 100), 1800, 100)
                .unwrap();
            let mut applied = 0;
            let arm = s
                .commit_rollback("vm-1", "r", 6, 101, &mut |_| {
                    applied += 1;
                    Ok(())
                })
                .unwrap();
            assert_eq!(arm.restore_id, "r");
            assert_eq!(applied, 1);
            assert_eq!(s.get("vm-1").unwrap(), 6);
            let (live, last) = s.rollback_state("vm-1").unwrap();
            assert!(live.is_none());
            assert_eq!(last.unwrap().to_counter, 6);
            // Second use: refused, and the stamp step does NOT run.
            let mut applied2 = 0;
            assert!(s
                .commit_rollback("vm-1", "r", 7, 102, &mut |_| {
                    applied2 += 1;
                    Ok(())
                })
                .is_err());
            assert_eq!(applied2, 0);
            assert_eq!(s.get("vm-1").unwrap(), 6);
        });
    }

    #[test]
    fn commit_rollback_refuses_a_non_monotonic_value_and_an_expired_arm_before_the_stamp_step() {
        for_each_store(|s| {
            s.seed("vm-1", 5).unwrap();
            s.arm_rollback(rb_arm_for("vm-1", "r", 3, 100), 1800, 100)
                .unwrap();
            let mut ran = false;
            assert!(s
                .commit_rollback("vm-1", "r", 5, 101, &mut |_| {
                    ran = true;
                    Ok(())
                })
                .is_err());
            assert!(s
                .commit_rollback("vm-1", "r", 6, 700, &mut |_| {
                    ran = true;
                    Ok(())
                })
                .is_err());
            assert!(s
                .commit_rollback("vm-1", "other", 6, 101, &mut |_| {
                    ran = true;
                    Ok(())
                })
                .is_err());
            assert!(
                !ran,
                "the stamp must never be lowered for an arm that does not commit"
            );
            assert_eq!(s.get("vm-1").unwrap(), 5);
            assert!(s.rollback_state("vm-1").unwrap().0.is_some());
        });
    }

    #[test]
    fn commit_rollback_commits_exactly_stored_plus_one_never_a_skip() {
        for_each_store(|s| {
            s.seed("vm-1", 5).unwrap();
            s.arm_rollback(rb_arm_for("vm-1", "r", 3, 100), 1800, 100)
                .unwrap();
            let mut ran = false;
            assert!(s
                .commit_rollback("vm-1", "r", 7, 101, &mut |_| {
                    ran = true;
                    Ok(())
                })
                .is_err());
            assert!(!ran);
            assert_eq!(s.get("vm-1").unwrap(), 5);
        });
    }

    #[test]
    fn a_consumed_restore_id_is_never_armed_again() {
        for_each_store(|s| {
            s.seed("vm-1", 5).unwrap();
            s.arm_rollback(rb_arm_for("vm-1", "r", 3, 100), 1800, 100)
                .unwrap();
            s.commit_rollback("vm-1", "r", 6, 101, &mut |_| Ok(()))
                .unwrap();
            // Long after the rate limit, the SAME id is refused…
            assert_eq!(
                s.arm_rollback(rb_arm_for("vm-1", "r", 3, 10_000), 1800, 10_000)
                    .unwrap(),
                ArmRollbackOutcome::RestoreIdConsumed
            );
            assert!(s.rollback_state("vm-1").unwrap().0.is_none());
            // …a fresh one is not.
            assert!(matches!(
                s.arm_rollback(rb_arm_for("vm-1", "r2", 3, 10_000), 1800, 10_000)
                    .unwrap(),
                ArmRollbackOutcome::Armed(_)
            ));
        });
    }

    #[test]
    fn a_failed_stamp_step_leaves_the_arm_and_the_counter_alone() {
        for_each_store(|s| {
            s.seed("vm-1", 5).unwrap();
            s.arm_rollback(rb_arm_for("vm-1", "r", 3, 100), 1800, 100)
                .unwrap();
            assert!(s
                .commit_rollback("vm-1", "r", 6, 101, &mut |_| Err(KbsError::Policy(
                    "stamp store down".into()
                )))
                .is_err());
            assert_eq!(s.get("vm-1").unwrap(), 5);
            assert!(s.rollback_state("vm-1").unwrap().0.is_some());
            assert!(s.rollback_state("vm-1").unwrap().1.is_none());
        });
    }

    #[test]
    fn two_racing_commits_of_one_arm_consume_it_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let s = Arc::new(FileBootCounterStore::open(dir.path().join("bc.json")).unwrap());
        s.seed("vm-1", 5).unwrap();
        s.arm_rollback(rb_arm_for("vm-1", "r", 3, 100), 1800, 100)
            .unwrap();
        let applied = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let s = Arc::clone(&s);
                let applied = Arc::clone(&applied);
                std::thread::spawn(move || {
                    s.commit_rollback("vm-1", "r", 6, 101, &mut |_| {
                        applied.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(())
                    })
                    .is_ok()
                })
            })
            .collect();
        let wins = handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .filter(|ok| *ok)
            .count();
        assert_eq!(wins, 1);
        assert_eq!(applied.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(s.get("vm-1").unwrap(), 6);
    }

    #[test]
    fn a_normal_commit_clears_the_rollback_arm_and_reports_it() {
        for_each_store(|s| {
            s.seed("vm-1", 5).unwrap();
            s.arm_rollback(rb_arm_for("vm-1", "r", 3, 100), 1800, 100)
                .unwrap();
            let cleared = s.commit_reporting("vm-1", 6).unwrap();
            assert_eq!(cleared.unwrap().restore_id, "r");
            assert!(s.rollback_state("vm-1").unwrap().0.is_none());
            assert!(s.commit_reporting("vm-1", 7).unwrap().is_none());
        });
    }

    #[test]
    fn purge_removes_only_expired_arms() {
        for_each_store(|s| {
            s.seed("vm-1", 5).unwrap();
            s.seed("vm-2", 5).unwrap();
            s.arm_rollback(rb_arm_for("vm-1", "a", 3, 100), 1800, 100)
                .unwrap();
            s.arm_rollback(rb_arm_for("vm-2", "b", 3, 400), 1800, 400)
                .unwrap();
            let purged = s.purge_expired_rollback_arms(700).unwrap();
            assert_eq!(purged.len(), 1);
            assert_eq!(purged[0].vm_id, "vm-1");
            assert!(s.rollback_state("vm-2").unwrap().0.is_some());
        });
    }

    /// PROPERTY: over any interleaving of arm / disarm / clear / purge /
    /// normal commit / rollback commit (with arbitrary values), the counter
    /// never decreases and no arm is ever consumed twice. Deterministic
    /// pseudo-random driver (xorshift), both store impls.
    #[test]
    fn property_counter_never_decreases_and_no_arm_is_consumed_twice() {
        let total_consumed = std::sync::atomic::AtomicUsize::new(0);
        for seed in 1..=12u64 {
            for_each_store(|s| {
                let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
                let mut rnd = |n: u64| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x % n
                };
                s.seed("vm", 3).unwrap();
                let mut last = s.get("vm").unwrap();
                let mut consumed: BTreeSet<String> = BTreeSet::new();
                let mut next_id = 0u64;
                let mut now = 1_000u64;
                for _ in 0..150 {
                    now += rnd(400);
                    match rnd(7) {
                        0 | 1 => {
                            next_id += 1;
                            let stored = s.get("vm").unwrap();
                            let a = rb_arm_for("vm", &format!("r{next_id}"), rnd(stored + 2), now);
                            let _ = s.arm_rollback(a, rnd(2) * 600, now);
                        }
                        2 => {
                            let id = format!("r{}", rnd(next_id + 1));
                            let _ = s.disarm_rollback("vm", &id, Some(1));
                        }
                        3 => {
                            let _ = s.clear_rollback_arm("vm", "rollback-lifecycle-activate", 1);
                            let _ = s.purge_expired_rollback_arms(now);
                        }
                        4 => {
                            let v = s.get("vm").unwrap() + rnd(3);
                            let _ = s.commit_reporting("vm", v.saturating_sub(1));
                        }
                        _ => {
                            let id = s
                                .rollback_state("vm")
                                .unwrap()
                                .0
                                .map(|a| a.restore_id)
                                .unwrap_or_else(|| format!("r{}", rnd(next_id + 1)));
                            let v = s.get("vm").unwrap() + rnd(2);
                            if let Ok(arm) = s.commit_rollback("vm", &id, v, now, &mut |_| Ok(())) {
                                assert!(
                                    consumed.insert(arm.restore_id.clone()),
                                    "arm {} consumed twice",
                                    arm.restore_id
                                );
                                total_consumed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                    let now_counter = s.get("vm").unwrap();
                    assert!(
                        now_counter >= last,
                        "counter decreased {last} -> {now_counter}"
                    );
                    last = now_counter;
                }
            });
        }
        // Not vacuous: the driver really did consume arms.
        assert!(total_consumed.load(std::sync::atomic::Ordering::Relaxed) > 10);
    }
}
