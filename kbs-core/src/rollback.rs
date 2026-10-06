//! Authorized rollback (A2, "restore a VM to an EARLIER boot").
//!
//! # What this is for
//!
//! The two anti-rollback gates — the boot counter
//! ([`crate::boot_counter`], `submitted == stored + 1`) and the confirmed
//! volume stamp ([`crate::volume_stamp`], the guest refuses `S < E`) —
//! exist to stop a MINER from booting an older copy of a tenant's disk.
//! They stop the TENANT too: restoring a backup taken before the last
//! reboot is, byte for byte, the attack they refuse. This module is the
//! one authenticated exception: vali, on behalf of the tenant, arms a
//! ONE-SHOT permission that admits exactly one release of exactly one
//! restore point, and that release re-establishes the stamp that point
//! was taken under.
//!
//! # The pieces
//!
//! - **Checkpoint** ([`sign_checkpoint`] / [`verify_checkpoint`]) — after
//!   every backup run vali asks the KBS to sign its current
//!   `{boot_counter, volume_stamp, volume_stamp_timeline_id,
//!   unconfirmed_releases, generation}` for the VM (a V2 checkpoint; a V1
//!   one, signed before stamp protocol v2, still verifies but is never
//!   armed — `checkpoint-not-timeline-bound`) with the PERSISTENT
//!   response key (the Vault-backed
//!   `signing-key` Secret, so it survives a KBS restart). vali keeps it
//!   in the run's manifest. The stamp a rollback lowers to (`E_T`) comes
//!   ONLY from here — never from a value vali or a miner types in.
//! - **Arm** ([`process_authorize_rollback`]) — mTLS admin only. The KBS
//!   verifies its OWN signature, that the checkpoint is for this VM, that
//!   it was STAMPED (`volume_stamp > 0`: a stamp of 0 tells the guest to
//!   ADOPT whatever disk it finds, so it can bind nothing —
//!   `checkpoint-unstamped`; the checkpoint route still signs such a
//!   state, and vali decides not to offer it), that the point's
//!   `manifest.json` bytes hash to the arm's manifest sha and embed this
//!   very checkpoint and VM (`manifest-mismatch`), that it is strictly in
//!   the past (`C_T < stored`), and that the lifecycle row is EXACTLY
//!   `Migrating{new_gen, dest}` (vali has already run `activate`). One
//!   live arm per VM, a per-VM rate limit, a TTL of at most an hour. Stored in the boot-counter store's SIBLING file (see
//!   [`crate::boot_counter::FileBootCounterStore`]) so the consume and
//!   the counter commit share one lock.
//! - **Release** (`crate::release::run`, gate 5b) — consulted ONLY after
//!   the strict CAS refused a REWIND (`submitted <= stored`), and admits
//!   iff [`arm_admits`]: unexpired, ticket gen == `arm.new_gen`, attested
//!   chip == `arm.dest`, `submitted == arm.from_counter + 1`, the guest
//!   ATTESTED stamp protocol v2 in its REPORT_DATA, and the arm's
//!   checkpoint timeline was recorded. The response (V2 domain) then
//!   carries `expected_volume_stamp = E_T`, a `volume_stamp_transition`
//!   from the checkpoint's timeline to a FRESH random one, and a confirm
//!   token for `E_T + 1` on that fresh timeline under a BUMPED per-VM
//!   token epoch.
//! - **Commit** — under the boot-counter lock, after re-validating the
//!   arm AND re-reading the lifecycle row it is bound to: (i) the stamp
//!   store sets `confirmed := E_T`, `unconfirmed := 0`, the new token
//!   epoch, the fresh timeline, and a durable UNDO record of the row and
//!   timeline it replaced; then (ii)
//!   the arm is consumed and the counter commits exactly `stored + 1`
//!   (never lowered). A MANDATORY `rollback-consume-intent` audit row
//!   (ticket id, attested chip, the arm) precedes the commit: if the
//!   admin chain cannot take it, the release is refused before anything
//!   is spent. Only after gate 11d (the final lifecycle re-check) passes
//!   does the release FINALIZE the rollback (drop the undo record, record
//!   it `delivered`) and answer. If 11d denies — an `activate`/fence
//!   landed meanwhile — or the finalize cannot be written, the stamp is
//!   put back (compensation, recorded `reverted`) and nothing is
//!   released.
//! - **Status** (`GET …/rollback`) — the live arm, the last consumed
//!   rollback with `delivered`/`reverted` (both false ⇒ in flight; read
//!   from the stamp store's resolution, which is written in the SAME
//!   write as the undo record's removal, so it never claims a delivery
//!   the store did not finalize), and `last_clear {restore_id, reason,
//!   at}`: the last arm that left WITHOUT a consume, and why
//!   (`rollback-cleared-by-boot`, `rollback-expired`,
//!   `rollback-disarmed`, `rollback-lifecycle-<op>`).
//!
//! # Why a miner cannot use it
//!
//! It cannot create an arm: the four routes live on the mTLS admin
//! listener only AND each demands a verified client identity per request
//! (403 otherwise, even on a listener opted into plaintext). An arm is
//! bound to a generation and chip only vali's `activate` sets, admits one
//! submitted counter value, expires, is consumed by the first release it
//! admits, and its `restore_id` can never be armed again. Tokens minted
//! on the abandoned timeline die with the epoch bump, so a captured
//! confirm cannot re-advance the restored stamp.
//!
//! # The abandoned timeline (blocker B1) — why stamp protocol v2
//!
//! After the rollback the restored VM writes `E_T + 1, E_T + 2, …` — the
//! numbers the ABANDONED (pre-rollback) timeline's disks already carry.
//! With a bare number a miner could later present an abandoned disk and
//! undo the rollback. So the in-volume stamp is the pair `(timeline,
//! value)` (`crate::volume_stamp::GUEST_STAMP_PROTOCOL_V2`), the rollback
//! release moves the VM to a timeline never issued before, and every later
//! release expects that timeline: an abandoned disk is refused by the
//! guest's gate whatever its value. A VM on a non-zero timeline releases
//! only to a guest that attested v2 (`volume-stamp-timeline-requires-v2`),
//! so no v1 guest — however the miner provokes a fallback to one — ever
//! compares the value alone. A lost rollback response fails closed: the
//! restored disk is still on the old timeline, every later release
//! expects the new one, and only a NEW authorized rollback (to yet
//! another fresh timeline) recovers it.
//!
//! **A KBS restart.** The stamp store lives on an emptyDir: a pod restart
//! wipes it, and every VM is back at `E = 0` on the zero timeline. Left
//! at that, every VM would count `1, 2, …` on the zero timeline again, so
//! every zero-timeline disk — including every disk a pre-restart rollback
//! abandoned while the VM was still on the zero timeline — would become
//! acceptable again once `E` caught up with its value: B1 reopened for
//! good, not "until the next confirm". So a v2 release at `E = 0`
//! (`crate::release`, gate 5c') moves the VM to a FRESH random timeline,
//! durably before replying, with the transition `zero → T_fresh`; the
//! guest adopts (as at any `E = 0`), stamps `(T_fresh, 1)` and confirms on
//! `T_fresh`. From that confirm on, every disk of any earlier timeline is
//! refused whatever its value. What remains is the `E = 0` window itself:
//! between the restart and the VM's first confirm after it, the guest
//! adopts whatever disk it is given (an inherent property of a store that
//! can be lost, see "Honest limits"). A lost response costs nothing: the
//! next release is still at `E = 0` and draws another fresh timeline, and
//! the lost one's token never confirms (its timeline is not current).
//!
//! # Honest limits
//!
//! **The rollback release admits one boot past the checkpoint.** The
//! submitted counter comes from a miner-writable file, so what actually
//! binds the rollback boot is the guest's in-volume check: `timeline ==
//! T_ck` (the checkpoint's timeline) and `S ∈ {E_T, E_T + 1}`. `S = E_T`
//! is a disk of the checkpoint's own boot; `S = E_T + 1` is a disk of
//! EXACTLY ONE boot after it — the boot that released with `E = E_T` and
//! stamped `E_T + 1` before its root was mounted, so every tenant byte it
//! wrote sits on such a disk. The rollback release accepts that disk too.
//! When `T_ck` is the VM's CURRENT timeline — always for a first rollback,
//! and for any rollback to a point taken since the last one — and the VM
//! is exactly one boot past the checkpoint, that is the VM's current,
//! NOT-rolled-back disk: a malicious host can simply not restore anything,
//! and vali records (and the KBS reports `delivered`) a rollback that did
//! not happen. In every other case it needs a copy of a disk of that one
//! boot, which the host can always have kept. Nothing leaks: the disk is
//! the tenant's own, unlocked only by the attested guest of this VM, and
//! no disk of any other timeline, of an earlier boot, or of two or more
//! boots later is admitted. Likewise the host can present ANOTHER backup
//! point of the checkpoint's boot than the one vali chose (a point the
//! tenant also owns). It can do nothing without an arm. Closing this needs
//! a per-BOOT timeline (every release moving the VM to a fresh one), which
//! is out of scope here.
//!
//! The fresh timeline of a v2 release at `E = 0` (above) narrows this in
//! exactly one case: when the KBS store was wiped AFTER the checkpoint's
//! boot and BEFORE the next one, that next boot released at `E = 0` and
//! moved its disk to a fresh timeline before any tenant byte was written —
//! so no disk of `(T_ck, E_T + 1)` exists and the window is the
//! checkpoint's own boot only. (Such a checkpoint's arm is itself gone
//! with the wipe; vali must arm it again.) In every other case the window
//! is unchanged.
//!
//! **A KBS pod restart** wipes the stamp store (E = 0 ⇒ the guest ADOPTS
//! whatever it finds, timeline included) and the token epochs and
//! timelines with it — that restart opens the stamp gate for every VM
//! until its next confirm, with or without this module; the fresh
//! timeline above is what stops it from re-opening older disks after
//! that confirm. A KBS BINARY rollback to a version without timelines
//! likewise releases a rolled-back VM on the value alone (it ignores the
//! timelines file): do not roll the KBS binary back past stamp protocol v2
//! after an authorized rollback.
//!
//! # Failures and crashes between (i) and delivery
//!
//! The undo record is what makes every partial outcome safe. While it
//! exists, [`reconcile_pending`] — run at the start of every release,
//! on every rollback admin call, after every lifecycle clear, and at
//! startup — decides:
//! - the arm is still live (e.g. (ii) failed before the consume): KEEP.
//!   The restored guest's retry is admitted by the same arm and completes
//!   under a further epoch; any OTHER release of the VM is refused
//!   (`volume-stamp-rollback-pending`) instead of reading a provisional
//!   stamp;
//! - the arm was consumed less than [`IN_FLIGHT_GRACE_S`] ago: the
//!   release is between its commit and its finalize — KEEP;
//! - otherwise (disarmed, expired, cleared by a lifecycle transition, or
//!   consumed by a release that crashed or was denied): REVERT the row to
//!   the recorded value. The epoch is never moved back.
//!
//! So nothing in any of those windows hands out a KEK the arm did not
//! authorize, and no lowered stamp outlives its authorisation.
//!
//! The counter is the one thing a failure can leave advanced (a denied
//! release after (ii)): it never moves down, so the ORIGINAL disk then
//! needs an operator `arm-boot-counter-resync` — an availability cost,
//! fail-closed, and audited.
//!
//! A NORMAL release that read the stamp before a rollback's stamp step
//! landed cannot slip through either: its counter commit re-checks, under
//! the same boot-counter lock the stamp step runs under, that no rollback
//! is pending and the token epoch it minted under is still current.
//!
//! # Accepted residuals (documented, not closed)
//!
//! - A process crash AFTER the finalize but before the response bytes
//!   leave: the stamp stays at `E_T`, the arm is consumed, the counter
//!   advanced. That is exactly the state of a DELIVERED rollback whose
//!   confirm the miner dropped — a state the miner can always produce —
//!   so it grants nothing new. (A normal release has the same property
//!   today: counter committed, response lost.) `GET …/rollback` then
//!   reports `delivered: true`: the flag means "finalized and handed to
//!   the transport", never "received by the guest".
//! - Expiry and the in-flight grace are measured with the release's
//!   request-start time and the host wall clock: a release that starts
//!   just before expiry can still commit within its own duration, and a
//!   wall clock moved backwards across a restart could keep an arm alive
//!   longer. Both are bounded by one release / by operator clock hygiene.
//! - A pod restart wipes the stamp store, the token epochs, the arms and
//!   the rate-limit memory (emptyDir inside the CVM). The stamp gate is
//!   then open for every VM until its next confirm (E = 0 ⇒ ADOPT), with
//!   or without this module — and, for a v2 guest, the release at E = 0
//!   moves the VM to a fresh timeline, so that confirm closes every
//!   earlier timeline again (see "A KBS restart" above); arms are simply
//!   gone (fail closed), and vali enforces its own rate limit and keeps
//!   its own `RollbackEvent` rows.

use std::collections::BTreeMap;

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hippius_types::rollback::{
    AdminAuthorizeRollbackRequest, AdminLastRollback, AdminRollbackArm,
    AdminRollbackCheckpointResponse, AdminRollbackClear, AdminRollbackErrorResponse,
    AdminRollbackStatusResponse, RollbackCheckpoint, MAX_CHECKPOINT_LEN, MAX_POINT_MANIFEST_LEN,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::admin_audit::{AdminAuditRecord, FileAdminAuditSink};
use crate::boot_counter::BootCounterStore;
use crate::error::{KbsError, Result};
use crate::lifecycle::{VmState, VmStateStore};
use crate::volume_stamp::{
    guest_stamp_protocol_is_rollback_capable, kbs_owns_volume_stamp, ResolvedRollback,
    RollbackResolution, VolumeStampStore,
};

/// `rollback.min_interval_s` default: one rollback per VM per 30 min.
pub const DEFAULT_MIN_INTERVAL_S: u64 = 1800;
/// `rollback.max_ttl_s` default, and its hard ceiling (user requirement:
/// an arm lives at most one hour).
pub const DEFAULT_MAX_TTL_S: u64 = 3600;
/// Shortest arm TTL accepted.
pub const MIN_TTL_S: u64 = 60;
/// Longest `restore_id` accepted.
pub const MAX_RESTORE_ID_LEN: usize = 128;
/// Longest `dest_platform_id_hex` accepted (a 64-byte SNP chip id).
pub const MAX_DEST_PLATFORM_ID_HEX_LEN: usize = 128;
/// Longest `requested_by` accepted.
pub const MAX_REQUESTED_BY_LEN: usize = 256;
/// How many consumed `restore_id`s each VM remembers; a remembered id is
/// never armed again. vali mints a fresh id per restore job, and the
/// per-VM rate limit caps consumes at one per `min_interval_s`, so this
/// covers far more history than any re-drive of a finished job. The
/// memory lives in the state dir and is wiped with it.
pub const MAX_CONSUMED_IDS: usize = 256;
/// How long after its consume a rollback whose undo record is still
/// pending counts as IN FLIGHT (the release that consumed it is between
/// its commit and its finalize, milliseconds apart). Past this, a
/// pending record with no live arm is a failed or crashed release and
/// [`reconcile_pending`] reverts it.
/// Measured from the release's own request time, so it must also cover
/// that release's Vault/broker round trips before its commit.
pub const IN_FLIGHT_GRACE_S: u64 = 300;

/// The operator-tunable part of the rollback gate (`[rollback]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackPolicy {
    /// Minimum seconds between two rollbacks of one VM, measured from
    /// the later of the last ARM and the last CONSUME.
    pub min_interval_s: u64,
    /// Longest arm TTL a request may ask for (`MIN_TTL_S..=max_ttl_s`).
    pub max_ttl_s: u64,
}

impl Default for RollbackPolicy {
    fn default() -> Self {
        Self {
            min_interval_s: DEFAULT_MIN_INTERVAL_S,
            max_ttl_s: DEFAULT_MAX_TTL_S,
        }
    }
}

impl RollbackPolicy {
    /// Refuse a policy that would violate the user's binding limits.
    pub fn validate(&self) -> core::result::Result<(), String> {
        if !(MIN_TTL_S..=DEFAULT_MAX_TTL_S).contains(&self.max_ttl_s) {
            return Err(format!(
                "rollback.max_ttl_s must be in {MIN_TTL_S}..={DEFAULT_MAX_TTL_S}, got {}",
                self.max_ttl_s
            ));
        }
        if self.min_interval_s == 0 {
            return Err("rollback.min_interval_s must be > 0".into());
        }
        Ok(())
    }
}

/// One armed rollback, as stored in the sibling arms file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackArm {
    pub vm_id: String,
    pub restore_id: String,
    pub manifest_sha256_hex: String,
    pub new_gen: u64,
    /// Lowercase hex chip id — compared verbatim with the attested node.
    pub dest: String,
    /// `C_T`.
    pub from_counter: u64,
    /// `E_T`.
    pub to_stamp: u64,
    /// sha256 of the verified checkpoint bytes, ties the arm (and its
    /// audit rows) to the exact signed statement it was built from.
    pub checkpoint_sha256_hex: String,
    pub armed_at_unix: u64,
    pub expires_at_unix: u64,
    pub requested_by: String,
    /// SAN of the admin client that armed it ("" when unauthenticated).
    pub armed_by: String,
}

impl RollbackArm {
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at_unix
    }

    /// Same restore point, same target, same person: a re-drive of an
    /// arm that already exists (C-4's 200), as opposed to a different
    /// request reusing the id.
    pub fn same_binding(&self, other: &RollbackArm) -> bool {
        self.vm_id == other.vm_id
            && self.restore_id == other.restore_id
            && self.manifest_sha256_hex == other.manifest_sha256_hex
            && self.new_gen == other.new_gen
            && self.dest == other.dest
            && self.from_counter == other.from_counter
            && self.to_stamp == other.to_stamp
            && self.checkpoint_sha256_hex == other.checkpoint_sha256_hex
            && self.requested_by == other.requested_by
    }

    pub fn to_wire(&self) -> AdminRollbackArm {
        AdminRollbackArm {
            vm_id: self.vm_id.clone(),
            restore_id: self.restore_id.clone(),
            point_manifest_sha256_hex: self.manifest_sha256_hex.clone(),
            new_gen: self.new_gen,
            dest_platform_id_hex: self.dest.clone(),
            from_counter: self.from_counter,
            to_stamp: self.to_stamp,
            armed_at_unix: self.armed_at_unix,
            expires_at_unix: self.expires_at_unix,
            requested_by: self.requested_by.clone(),
        }
    }
}

/// The last consumed rollback of a VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LastRollback {
    pub restore_id: String,
    pub manifest_sha256_hex: String,
    pub from_counter: u64,
    pub to_counter: u64,
    pub stamp: u64,
    pub consumed_at_unix: u64,
    pub requested_by: String,
}

impl LastRollback {
    /// `resolution` is the stamp store's
    /// [`VolumeStampStore::rollback_resolution`]; it describes THIS
    /// rollback only when it names the same `restore_id`.
    pub fn to_wire(&self, resolution: Option<&ResolvedRollback>) -> AdminLastRollback {
        let how = resolution
            .filter(|r| r.restore_id == self.restore_id)
            .map(|r| r.resolution);
        AdminLastRollback {
            restore_id: self.restore_id.clone(),
            manifest_sha256_hex: self.manifest_sha256_hex.clone(),
            from_counter: self.from_counter,
            to_counter: self.to_counter,
            stamp: self.stamp,
            consumed_at_unix: self.consumed_at_unix,
            requested_by: self.requested_by.clone(),
            delivered: how == Some(RollbackResolution::Delivered),
            reverted: how == Some(RollbackResolution::Reverted),
        }
    }
}

/// The last arm of a VM that left the store WITHOUT being consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackClear {
    pub restore_id: String,
    /// One of the `CLEAR_*` reasons.
    pub reason: String,
    pub at_unix: u64,
}

impl RollbackClear {
    pub fn to_wire(&self) -> AdminRollbackClear {
        AdminRollbackClear {
            restore_id: self.restore_id.clone(),
            reason: self.reason.clone(),
            at: self.at_unix,
        }
    }
}

/// `last_clear.reason`: a normal (non-rollback) boot of the VM committed.
pub const CLEAR_BY_BOOT: &str = "rollback-cleared-by-boot";
/// `last_clear.reason`: the arm's TTL ran out.
pub const CLEAR_EXPIRED: &str = "rollback-expired";
/// `last_clear.reason`: `DELETE …/authorize-rollback/{restore_id}`.
pub const CLEAR_DISARMED: &str = "rollback-disarmed";
/// `last_clear.reason` prefix: `rollback-lifecycle-<op>` for `activate`,
/// `decommission`, `tombstone`.
pub const CLEAR_LIFECYCLE_PREFIX: &str = "rollback-lifecycle-";

/// Per-VM rate-limit memory. Survives disarm, expiry and lifecycle
/// clears (only a store wipe forgets it).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackHistory {
    /// The later of the last arm and the last consume.
    pub last_event_at_unix: u64,
    pub last_rollback: Option<LastRollback>,
    /// The last [`MAX_CONSUMED_IDS`] consumed `restore_id`s. One tenant
    /// request is one rollback: a re-driven `authorize-rollback` for a
    /// remembered consumed id is refused.
    #[serde(default)]
    pub consumed_restore_ids: Vec<String>,
    /// The last arm cleared without a consume (`GET …/rollback`
    /// `last_clear`).
    #[serde(default)]
    pub last_clear: Option<RollbackClear>,
}

/// The whole content of the sibling arms file. `BTreeMap`s so the bytes
/// are deterministic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRows {
    pub arms: BTreeMap<String, RollbackArm>,
    pub history: BTreeMap<String, RollbackHistory>,
}

/// Verdict of [`BootCounterStore::arm_rollback`]. Every variant but
/// `Armed` leaves the store byte-for-byte unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArmRollbackOutcome {
    Armed(RollbackArm),
    /// The same `restore_id` is live with the same binding — idempotent.
    AlreadyArmed(RollbackArm),
    /// Another live arm (or the same id with a different binding).
    ArmExists {
        restore_id: String,
    },
    /// `from_counter >= stored`: nothing to roll back to.
    NotARollback {
        stored: u64,
    },
    /// This `restore_id` was already consumed once.
    RestoreIdConsumed,
    RateLimited {
        retry_after_s: u64,
    },
}

/// Shared arm-time decision, used by both store impls under their lock
/// so they can never disagree. `None` ⇒ the caller stores `arm`.
pub(crate) fn decide_arm(
    rows: &RollbackRows,
    stored: u64,
    arm: &RollbackArm,
    min_interval_s: u64,
    now_unix: u64,
) -> Option<ArmRollbackOutcome> {
    if let Some(live) = rows
        .arms
        .get(&arm.vm_id)
        .filter(|a| !a.is_expired(now_unix))
    {
        return Some(if live.same_binding(arm) {
            ArmRollbackOutcome::AlreadyArmed(live.clone())
        } else {
            ArmRollbackOutcome::ArmExists {
                restore_id: live.restore_id.clone(),
            }
        });
    }
    if arm.from_counter >= stored {
        return Some(ArmRollbackOutcome::NotARollback { stored });
    }
    if let Some(h) = rows.history.get(&arm.vm_id) {
        if h.consumed_restore_ids
            .iter()
            .any(|id| id == &arm.restore_id)
        {
            return Some(ArmRollbackOutcome::RestoreIdConsumed);
        }
        let next_allowed = h.last_event_at_unix.saturating_add(min_interval_s);
        if now_unix < next_allowed {
            return Some(ArmRollbackOutcome::RateLimited {
                retry_after_s: next_allowed - now_unix,
            });
        }
    }
    None
}

/// Why an existing arm did not admit a release. Stable strings — they
/// land in the audit log as `rollback-refused(<reason>)`.
pub fn arm_admits(
    arm: &RollbackArm,
    ticket_gen: u64,
    attested_node: &str,
    submitted: u64,
    stored: u64,
    now_unix: u64,
) -> core::result::Result<(), &'static str> {
    if arm.is_expired(now_unix) {
        return Err("arm-expired");
    }
    if submitted > stored {
        // Not a rewind: the arm path never widens a skip.
        return Err("not-a-rewind");
    }
    if ticket_gen != arm.new_gen {
        return Err("wrong-generation");
    }
    if attested_node != arm.dest {
        return Err("wrong-chip");
    }
    if Some(submitted) != arm.from_counter.checked_add(1) {
        return Err("wrong-counter");
    }
    Ok(())
}

// ─── checkpoint signing ──────────────────────────────────────────────

/// Sign `cp` with the KBS response key. Returns `(cbor, signature)`.
pub fn sign_checkpoint(key: &SigningKey, cp: &RollbackCheckpoint) -> Result<(Vec<u8>, [u8; 64])> {
    let body = cp.canonical()?;
    let sig = key.sign(&body).to_bytes();
    Ok((body, sig))
}

/// Verify a checkpoint the KBS signed earlier: signature FIRST (strict
/// Ed25519 over the exact bytes), then the strict decode (domain, field
/// set, canonical encoding). Anything else a key signed — a release
/// response, a denial, an evidence bundle — fails the decode.
pub fn verify_checkpoint(vk: &VerifyingKey, cbor: &[u8], sig: &[u8]) -> Result<RollbackCheckpoint> {
    let sig = Signature::from_slice(sig)
        .map_err(|e| KbsError::Crypto(format!("checkpoint sig decode: {e}")))?;
    vk.verify_strict(cbor, &sig)
        .map_err(|e| KbsError::Crypto(format!("checkpoint sig invalid: {e}")))?;
    Ok(RollbackCheckpoint::decode(cbor)?)
}

// ─── admin verdicts ──────────────────────────────────────────────────

/// Discriminated failure of a rollback admin route. `reason()` strings
/// are C-4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackErr {
    BadRequest(&'static str),
    BadCheckpointSignature,
    CheckpointVmMismatch,
    NotARollback {
        stored: u64,
    },
    RowNotActivated,
    ArmExists,
    RateLimited {
        retry_after_s: u64,
    },
    TtlOutOfRange,
    NoVmRow,
    NoBootCounter,
    /// Checkpoint of a VM whose row is `Decommissioning`/`Destroyed`.
    VmFenced,
    /// A re-drive of a `restore_id` that was already consumed.
    RestoreIdConsumed,
    /// A rollback is applied but not yet delivered (or not yet
    /// reconciled): no checkpoint can describe the VM right now.
    RollbackPending,
    /// The rollback routes require a VERIFIED admin client cert, even on
    /// a listener configured to serve plaintext.
    ClientCertRequired,
    /// The checkpoint's confirmed stamp is 0: the guest ADOPTS any disk
    /// at stamp 0, so such a checkpoint can bind nothing — never armed.
    CheckpointUnstamped,
    /// `point_manifest_b64` does not hash to `point_manifest_sha256_hex`,
    /// or does not embed this `checkpoint_cbor_hex` and VM.
    ManifestMismatch,
    /// A V1 checkpoint (signed before stamp protocol v2): it names no
    /// volume-stamp timeline, so a rollback to it could not tell the
    /// restored disk from an abandoned one. It still VERIFIES; it is
    /// never armed.
    CheckpointNotTimelineBound,
    /// VM's recorded guest stamp protocol
    /// ([`VolumeStampStore::guest_stamp_protocol`]) is below
    /// [`crate::volume_stamp::GUEST_STAMP_PROTOCOL_ROLLBACK_MIN`]: its
    /// stamp is not timeline-bound, so a lowered `E` would admit a volume
    /// of ANY boot epoch that carries the same number. Never armed.
    GuestNotRollbackCapable,
    // ── transport-level refusals (the route prologue / body decode) ──
    /// The admin gateway's shared token bucket is empty.
    GatewayRateLimited,
    BodyTooLarge,
    ClockUnavailable,
    /// The KBS runs without a rollback context.
    Unavailable,
    CheckpointBodyDecode,
    AuthorizeBodyDecode,
    /// The mandatory intent audit row could not be written.
    AuditUnavailable,
    Internal(String),
}

impl RollbackErr {
    pub fn status_code(&self) -> u16 {
        match self {
            RollbackErr::BadRequest(_)
            | RollbackErr::BadCheckpointSignature
            | RollbackErr::CheckpointVmMismatch
            | RollbackErr::ManifestMismatch
            | RollbackErr::TtlOutOfRange => 400,
            RollbackErr::CheckpointBodyDecode | RollbackErr::AuthorizeBodyDecode => 400,
            RollbackErr::NoVmRow => 404,
            RollbackErr::BodyTooLarge => 413,
            RollbackErr::RateLimited { .. } | RollbackErr::GatewayRateLimited => 429,
            RollbackErr::Unavailable => 503,
            RollbackErr::NotARollback { .. }
            | RollbackErr::RowNotActivated
            | RollbackErr::ArmExists
            | RollbackErr::NoBootCounter
            | RollbackErr::VmFenced
            | RollbackErr::RestoreIdConsumed
            | RollbackErr::CheckpointUnstamped
            | RollbackErr::GuestNotRollbackCapable
            | RollbackErr::CheckpointNotTimelineBound
            | RollbackErr::RollbackPending => 409,
            RollbackErr::ClientCertRequired => 403,
            RollbackErr::ClockUnavailable
            | RollbackErr::AuditUnavailable
            | RollbackErr::Internal(_) => 500,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            RollbackErr::BadRequest(r) => r,
            RollbackErr::BadCheckpointSignature => "bad-checkpoint-signature",
            RollbackErr::CheckpointVmMismatch => "checkpoint-vm-mismatch",
            RollbackErr::NotARollback { .. } => "not-a-rollback",
            RollbackErr::RowNotActivated => "row-not-activated",
            RollbackErr::ArmExists => "arm-exists",
            RollbackErr::RateLimited { .. } => "rollback-rate-limited",
            RollbackErr::TtlOutOfRange => "ttl-out-of-range",
            RollbackErr::NoVmRow => "no-vm-row",
            RollbackErr::NoBootCounter => "no-boot-counter",
            RollbackErr::VmFenced => "vm-fenced",
            RollbackErr::RestoreIdConsumed => "restore-id-consumed",
            RollbackErr::RollbackPending => "rollback-pending",
            RollbackErr::ClientCertRequired => "admin-client-cert-required",
            RollbackErr::CheckpointUnstamped => "checkpoint-unstamped",
            RollbackErr::ManifestMismatch => "manifest-mismatch",
            RollbackErr::GuestNotRollbackCapable => "guest-not-rollback-capable",
            RollbackErr::CheckpointNotTimelineBound => "checkpoint-not-timeline-bound",
            RollbackErr::GatewayRateLimited => "rate-limited",
            RollbackErr::BodyTooLarge => "body-too-large",
            RollbackErr::ClockUnavailable => "clock-unavailable",
            RollbackErr::Unavailable => "rollback-unavailable",
            RollbackErr::CheckpointBodyDecode => "checkpoint-body-decode",
            RollbackErr::AuthorizeBodyDecode => "authorize-body-decode",
            RollbackErr::AuditUnavailable => "audit-unavailable",
            RollbackErr::Internal(_) => "internal-error",
        }
    }

    pub fn retry_after_s(&self) -> Option<u64> {
        match self {
            RollbackErr::RateLimited { retry_after_s } => Some(*retry_after_s),
            // The gateway bucket refills within a second.
            RollbackErr::GatewayRateLimited => Some(1),
            _ => None,
        }
    }

    /// The JSON error body every rollback route answers with (C-4). The
    /// HTTP status is [`Self::status_code`].
    pub fn to_wire(&self, url_vm_id: &str) -> AdminRollbackErrorResponse {
        AdminRollbackErrorResponse {
            reason: self.reason().to_string(),
            vm_id: Some(url_vm_id.to_string()),
            retry_after_s: self.retry_after_s(),
        }
    }
}

fn internal(what: &str, e: KbsError) -> RollbackErr {
    RollbackErr::Internal(format!("{what}: {e}"))
}

/// A freshly signed checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointOk {
    pub checkpoint: RollbackCheckpoint,
    pub cbor: Vec<u8>,
    pub signature: [u8; 64],
    pub signer_pubkey: [u8; 32],
}

impl CheckpointOk {
    /// The `rollback-checkpoint` 200 body (C-4).
    pub fn to_wire(&self) -> AdminRollbackCheckpointResponse {
        AdminRollbackCheckpointResponse {
            checkpoint: self.checkpoint.to_wire(),
            checkpoint_cbor_hex: hex::encode(&self.cbor),
            signature_hex: hex::encode(self.signature),
            signer_pubkey_hex: hex::encode(self.signer_pubkey),
        }
    }
}

/// Whether `authorize-rollback` can arm `vm_id` at all (C-4
/// `rollback_capable`): the KBS owns its volume stamp (not M2), and its
/// last attested release reported a timeline-bound stamp protocol.
pub fn rollback_capable(
    vm_id: &str,
    vm_states: &dyn VmStateStore,
    stamps: &dyn VolumeStampStore,
) -> core::result::Result<bool, RollbackErr> {
    let mode = vm_states
        .key_mode(vm_id)
        .map_err(|e| internal("vm_states.key_mode", e))?;
    let protocol = stamps
        .guest_stamp_protocol(vm_id)
        .map_err(|e| internal("volume_stamp.guest_stamp_protocol", e))?;
    Ok(kbs_owns_volume_stamp(mode) && guest_stamp_protocol_is_rollback_capable(protocol))
}

/// The `GET …/rollback` 200 body (C-4), from what the stores hold. Pure:
/// the route reads the stores and hands the values here. An expired arm
/// is never reported live (the route purges them first; this covers a
/// read racing an expiry).
pub fn rollback_status(
    arm: Option<&RollbackArm>,
    last: Option<&LastRollback>,
    resolution: Option<&ResolvedRollback>,
    last_clear: Option<&RollbackClear>,
    rollback_capable: bool,
    now_unix: u64,
) -> AdminRollbackStatusResponse {
    AdminRollbackStatusResponse {
        arm: arm.filter(|a| !a.is_expired(now_unix)).map(|a| a.to_wire()),
        last_rollback: last.map(|l| l.to_wire(resolution)),
        last_clear: last_clear.map(|c| c.to_wire()),
        rollback_capable,
    }
}

/// `POST /v1/admin/vm/{vm_id}/rollback-checkpoint`.
///
/// A VM whose stamp was never confirmed (`volume_stamp == 0`) still gets
/// its checkpoint — the statement is true, and vali decides what to do
/// with it — but `authorize-rollback` refuses to arm it
/// (`checkpoint-unstamped`).
///
/// Reads the three stores without a common lock: a checkpoint is a
/// snapshot taken AFTER the backup it describes was captured, and the
/// value that matters to a later arm is `boot_counter`, which vali
/// cross-checks against the counter inside that backup.
pub fn process_rollback_checkpoint(
    url_vm_id: &str,
    vm_states: &dyn VmStateStore,
    counters: &dyn BootCounterStore,
    stamps: &dyn VolumeStampStore,
    signing_key: &SigningKey,
    now_unix: u64,
) -> core::result::Result<CheckpointOk, RollbackErr> {
    if url_vm_id.is_empty() {
        return Err(RollbackErr::BadRequest("vm-id-empty"));
    }
    let generation = match vm_states.get(url_vm_id) {
        Ok(VmState::Active { gen, .. }) => gen,
        Ok(VmState::Migrating { new_gen, .. }) => new_gen,
        Ok(VmState::Decommissioning) | Ok(VmState::Destroyed { .. }) => {
            return Err(RollbackErr::VmFenced)
        }
        Err(KbsError::Lifecycle(_)) => return Err(RollbackErr::NoVmRow),
        Err(e) => return Err(internal("vm_states.get", e)),
    };
    // A rollback whose undo record is dead is reverted first; one still
    // live or in flight makes the VM's stamp provisional — refuse.
    reconcile_pending(url_vm_id, counters, stamps, None, now_unix)
        .map_err(|e| internal("reconcile_pending", e))?;
    // Counter and stamp read under the COUNTER lock, so a rollback commit
    // (which holds it across its stamp and counter writes) cannot land
    // between the two reads and pair one boot's counter with another's
    // stamp.
    let mut read: Option<(u64, u64, u64, bool, [u8; 32])> = None;
    counters
        .with_counter_locked(url_vm_id, &mut |stored| {
            // Row, pending status and timeline in ONE stamp-store critical
            // section: a concurrent revert must not tear them apart.
            let (e, u, pending, timeline) = stamps.checkpoint_read(url_vm_id)?;
            read = Some((stored, e, u, pending.is_some(), timeline));
            Ok(())
        })
        .map_err(|e| internal("checkpoint read", e))?;
    let (boot_counter, volume_stamp, unconfirmed_releases, pending, timeline) =
        read.ok_or_else(|| RollbackErr::Internal("checkpoint read: no value".into()))?;
    if pending {
        return Err(RollbackErr::RollbackPending);
    }
    if boot_counter == 0 {
        return Err(RollbackErr::NoBootCounter);
    }
    let checkpoint = RollbackCheckpoint {
        vm_id: url_vm_id.to_string(),
        boot_counter,
        volume_stamp,
        unconfirmed_releases,
        generation,
        issued_at_unix: now_unix,
        // Every checkpoint is V2: it names the timeline the VM's disk is
        // on, which is what a rollback to it must expect.
        volume_stamp_timeline_id: Some(timeline),
    };
    let (cbor, signature) =
        sign_checkpoint(signing_key, &checkpoint).map_err(|e| internal("sign checkpoint", e))?;
    Ok(CheckpointOk {
        checkpoint,
        cbor,
        signature,
        signer_pubkey: signing_key.verifying_key().to_bytes(),
    })
}

/// A successful `authorize-rollback`. `fresh == false` ⇒ the same
/// `restore_id` was already armed with the same binding (HTTP 200).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeOk {
    pub arm: RollbackArm,
    pub fresh: bool,
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_restore_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_RESTORE_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

fn valid_requested_by(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_REQUESTED_BY_LEN && !s.chars().any(char::is_control)
}

/// The point's `manifest.json` bytes bind the arm: they hash to the
/// claimed sha, and are a JSON object naming this VM at top level and
/// carrying, under `kbs_rollback_checkpoint.checkpoint_cbor_hex`, the
/// EXACT checkpoint bytes being armed. So the manifest sha recorded in
/// the arm and the audit log names a restore point that really is the
/// point this checkpoint was taken for.
pub fn manifest_binds(
    manifest: &[u8],
    manifest_sha256_hex: &str,
    vm_id: &str,
    checkpoint_cbor_hex: &str,
) -> bool {
    if hex::encode(Sha256::digest(manifest)) != manifest_sha256_hex {
        return false;
    }
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(manifest) else {
        return false;
    };
    doc.get("vm_id").and_then(|v| v.as_str()) == Some(vm_id)
        && doc
            .get("kbs_rollback_checkpoint")
            .and_then(|c| c.get("checkpoint_cbor_hex"))
            .and_then(|v| v.as_str())
            == Some(checkpoint_cbor_hex)
}

fn row_is_activated(state: &VmState, new_gen: u64, dest: &str) -> bool {
    matches!(state, VmState::Migrating { new_gen: g, dest: d, .. } if *g == new_gen && d == dest)
}

/// The side-effect-free shape checks of `authorize-rollback`: every
/// field bounded and well-formed, the manifest decoded (≤
/// [`MAX_POINT_MANIFEST_LEN`]). Returns the manifest bytes. The admin
/// route runs this BEFORE it writes the intent audit row, so a malformed
/// body never lands its (possibly huge) fields in the hash chain; the
/// arm path runs it again.
pub fn validate_authorize_request(
    url_vm_id: &str,
    req: &AdminAuthorizeRollbackRequest,
) -> core::result::Result<Vec<u8>, RollbackErr> {
    if url_vm_id.is_empty() {
        return Err(RollbackErr::BadRequest("vm-id-empty"));
    }
    if !valid_restore_id(&req.restore_id) {
        return Err(RollbackErr::BadRequest("bad-restore-id"));
    }
    if req.point_manifest_sha256_hex.len() != 64 || !is_lower_hex(&req.point_manifest_sha256_hex) {
        return Err(RollbackErr::BadRequest("bad-manifest-sha256"));
    }
    if !is_lower_hex(&req.dest_platform_id_hex)
        || !req.dest_platform_id_hex.len().is_multiple_of(2)
        || req.dest_platform_id_hex.len() > MAX_DEST_PLATFORM_ID_HEX_LEN
    {
        return Err(RollbackErr::BadRequest("bad-dest-platform-id"));
    }
    if !valid_requested_by(&req.requested_by) {
        return Err(RollbackErr::BadRequest("bad-requested-by"));
    }
    if req.new_gen == 0 {
        return Err(RollbackErr::BadRequest("bad-new-gen"));
    }
    // Bounded BEFORE any decode: the checkpoint body is at most
    // MAX_CHECKPOINT_LEN bytes, the signature exactly 64.
    if req.checkpoint_cbor_hex.len() > 2 * MAX_CHECKPOINT_LEN || req.signature_hex.len() != 2 * 64 {
        return Err(RollbackErr::BadCheckpointSignature);
    }
    // Cap BEFORE decoding: base64 is 4 bytes per 3.
    if req.point_manifest_b64.len() > MAX_POINT_MANIFEST_LEN.div_ceil(3) * 4 {
        return Err(RollbackErr::BadRequest("bad-point-manifest"));
    }
    let manifest = base64::engine::general_purpose::STANDARD
        .decode(&req.point_manifest_b64)
        .map_err(|_| RollbackErr::BadRequest("bad-point-manifest"))?;
    if manifest.is_empty() || manifest.len() > MAX_POINT_MANIFEST_LEN {
        return Err(RollbackErr::BadRequest("bad-point-manifest"));
    }
    Ok(manifest)
}

/// `POST /v1/admin/vm/{vm_id}/authorize-rollback`.
///
/// Order of checks: request shape (incl. the manifest's size and
/// base64) → signature/domain → vm match → guest stamp protocol
/// (`guest-not-rollback-capable`) → stamped → manifest binding →
/// TTL → lifecycle row → (under the counter lock) live arm / not-a-rollback /
/// rate limit → store → row re-check. Every refusal writes nothing.
#[allow(clippy::too_many_arguments)]
pub fn process_authorize_rollback(
    url_vm_id: &str,
    req: &AdminAuthorizeRollbackRequest,
    vm_states: &dyn VmStateStore,
    counters: &dyn BootCounterStore,
    stamps: &dyn VolumeStampStore,
    kbs_vk: &VerifyingKey,
    policy: &RollbackPolicy,
    armed_by: Option<&str>,
    now_unix: u64,
) -> core::result::Result<AuthorizeOk, RollbackErr> {
    let manifest = validate_authorize_request(url_vm_id, req)?;

    // The KBS's OWN signature over the checkpoint: the only thing that
    // makes `from_counter` / `to_stamp` trustworthy.
    let cbor =
        hex::decode(&req.checkpoint_cbor_hex).map_err(|_| RollbackErr::BadCheckpointSignature)?;
    let sig = hex::decode(&req.signature_hex).map_err(|_| RollbackErr::BadCheckpointSignature)?;
    let checkpoint =
        verify_checkpoint(kbs_vk, &cbor, &sig).map_err(|_| RollbackErr::BadCheckpointSignature)?;
    if checkpoint.vm_id != url_vm_id {
        return Err(RollbackErr::CheckpointVmMismatch);
    }
    // Only a guest whose volume stamp is bound to its TIMELINE can be
    // rolled back soundly: with a v1 stamp a lowered `E_T` admits ANY
    // volume of the VM stamped `E_T`/`E_T + 1`, whichever boot wrote it.
    // And only a stamp the KBS owns can be restored (not M2's).
    if !rollback_capable(url_vm_id, vm_states, stamps)? {
        return Err(RollbackErr::GuestNotRollbackCapable);
    }
    // The restored disk's TIMELINE: the one release the arm admits expects
    // it, and moves the VM off it to a fresh one (stamp protocol v2). A V1
    // checkpoint names none, so it cannot tell the restored point from any
    // abandoned disk of the same VM — never armed.
    let from_timeline = checkpoint
        .volume_stamp_timeline_id
        .ok_or(RollbackErr::CheckpointNotTimelineBound)?;
    // A stamp of 0 makes the guest ADOPT whatever disk it is given: an
    // arm built on it would admit ANY disk of the epoch, not the point.
    if checkpoint.volume_stamp == 0 {
        return Err(RollbackErr::CheckpointUnstamped);
    }
    if !manifest_binds(
        &manifest,
        &req.point_manifest_sha256_hex,
        url_vm_id,
        &req.checkpoint_cbor_hex,
    ) {
        return Err(RollbackErr::ManifestMismatch);
    }
    if !(MIN_TTL_S..=policy.max_ttl_s.min(DEFAULT_MAX_TTL_S)).contains(&req.ttl_s) {
        return Err(RollbackErr::TtlOutOfRange);
    }

    match vm_states.get(url_vm_id) {
        Ok(state) if row_is_activated(&state, req.new_gen, &req.dest_platform_id_hex) => {}
        Ok(_) | Err(KbsError::Lifecycle(_)) => return Err(RollbackErr::RowNotActivated),
        Err(e) => return Err(internal("vm_states.get", e)),
    }

    let arm = RollbackArm {
        vm_id: url_vm_id.to_string(),
        restore_id: req.restore_id.clone(),
        manifest_sha256_hex: req.point_manifest_sha256_hex.clone(),
        new_gen: req.new_gen,
        dest: req.dest_platform_id_hex.clone(),
        from_counter: checkpoint.boot_counter,
        to_stamp: checkpoint.volume_stamp,
        checkpoint_sha256_hex: hex::encode(Sha256::digest(&cbor)),
        armed_at_unix: now_unix,
        expires_at_unix: now_unix.saturating_add(req.ttl_s),
        requested_by: req.requested_by.clone(),
        armed_by: armed_by.unwrap_or("").to_string(),
    };
    let outcome = counters
        .arm_rollback(arm, policy.min_interval_s, now_unix)
        .map_err(|e| internal("boot_counter.arm_rollback", e))?;
    let ok = match outcome {
        ArmRollbackOutcome::Armed(arm) => AuthorizeOk { arm, fresh: true },
        ArmRollbackOutcome::AlreadyArmed(arm) => AuthorizeOk { arm, fresh: false },
        ArmRollbackOutcome::ArmExists { .. } => return Err(RollbackErr::ArmExists),
        ArmRollbackOutcome::NotARollback { stored } => {
            return Err(RollbackErr::NotARollback { stored })
        }
        ArmRollbackOutcome::RestoreIdConsumed => return Err(RollbackErr::RestoreIdConsumed),
        ArmRollbackOutcome::RateLimited { retry_after_s } => {
            return Err(RollbackErr::RateLimited { retry_after_s })
        }
    };

    // The arm's checkpoint timeline, where the release path reads it. A
    // failure takes a fresh arm back out (nothing may admit a release it
    // cannot bind); until it lands, the release path refuses the arm
    // (`arm-timeline-missing`) — fail closed, never unbound.
    if let Err(e) = stamps.record_arm_timeline(url_vm_id, &ok.arm.restore_id, &from_timeline) {
        if ok.fresh {
            counters
                .disarm_rollback(url_vm_id, &ok.arm.restore_id, None)
                .map_err(|e| internal("boot_counter.disarm_rollback", e))?;
        }
        return Err(internal("volume_stamp.record_arm_timeline", e));
    }

    // Re-check the row AFTER storing: a concurrent `activate` may have
    // moved the fence between the check above and the store (and cleared
    // arms BEFORE this one landed). Such an arm could never admit a
    // release — its generation is no longer releasable — but it would
    // block the VM's next arm until it expired, so take it back out.
    let still = match vm_states.get(url_vm_id) {
        Ok(state) => row_is_activated(&state, ok.arm.new_gen, &ok.arm.dest),
        Err(KbsError::Lifecycle(_)) => false,
        Err(e) => return Err(internal("vm_states.get (recheck)", e)),
    };
    if !still {
        if ok.fresh {
            counters
                .disarm_rollback(url_vm_id, &ok.arm.restore_id, None)
                .map_err(|e| internal("boot_counter.disarm_rollback", e))?;
        }
        return Err(RollbackErr::RowNotActivated);
    }
    Ok(ok)
}

// ─── pending-rollback reconciliation ─────────────────────────────────

/// What [`reconcile_pending`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// Nothing pending.
    Clean,
    /// Pending, and still covered: its arm is live, or its release is in
    /// flight (consumed less than [`IN_FLIGHT_GRACE_S`] ago).
    Kept { restore_id: String },
    /// Pending with nothing covering it: the stamp row was put back.
    Reverted(crate::volume_stamp::PendingRollback),
}

/// Revert a pending rollback of `vm_id` whose authorisation is gone.
///
/// A rollback's stamp step (i) is applied under the boot-counter lock,
/// then the arm is consumed and the counter committed, then — only after
/// the final lifecycle re-check — the release finalizes it. Anything that
/// stops that sequence short (an I/O error, a crash, a concurrent
/// `activate`/fence that makes gate 11d deny) leaves an undo record. This
/// is what makes such a record harmless: once its arm is disarmed,
/// cleared, expired or consumed-but-not-delivered, the stamp goes back
/// to what it was, so a lowered stamp never outlives the permission that
/// lowered it.
///
/// Called at the start of every release (before any stamp read), on
/// every rollback admin call, after every lifecycle clear, and once at
/// startup for every pending VM. A no-op (a read of an empty map) when
/// nothing is pending, so a VM that was never rolled back sees no change.
pub fn reconcile_pending(
    vm_id: &str,
    counters: &dyn BootCounterStore,
    stamps: &dyn VolumeStampStore,
    audit: Option<&FileAdminAuditSink>,
    now_unix: u64,
) -> Result<ReconcileOutcome> {
    let Some(pending) = stamps.pending_rollback(vm_id)? else {
        return Ok(ReconcileOutcome::Clean);
    };
    let (arm, last) = counters.rollback_state(vm_id)?;
    let arm_covers = arm
        .as_ref()
        .is_some_and(|a| a.restore_id == pending.restore_id && !a.is_expired(now_unix));
    let in_flight = last.as_ref().is_some_and(|l| {
        l.restore_id == pending.restore_id
            && now_unix < l.consumed_at_unix.saturating_add(IN_FLIGHT_GRACE_S)
    });
    if arm_covers || in_flight {
        return Ok(ReconcileOutcome::Kept {
            restore_id: pending.restore_id,
        });
    }
    match stamps.revert_rollback(vm_id, &pending.restore_id)? {
        Some(reverted) => {
            let detail = format!(
                "reverted confirmed={} unconfirmed={} (applied_epoch={} stays; the rollback's \
                 authorisation is gone and it was never delivered)",
                reverted.prev_confirmed, reverted.prev_unconfirmed_releases, reverted.applied_epoch
            );
            record_rollback_event_best_effort(
                audit,
                &RollbackAuditEvent {
                    op: "rollback-reverted",
                    url_vm_id: vm_id,
                    restore_id: Some(&reverted.restore_id),
                    applied: true,
                    status_code: 200,
                    reason: &detail,
                    peer_san: None,
                    peer_serial: None,
                    body_sha256: [0u8; 32],
                },
                now_unix,
            );
            Ok(ReconcileOutcome::Reverted(reverted))
        }
        None => Ok(ReconcileOutcome::Clean),
    }
}

/// [`reconcile_pending`] for every VM with a pending record (startup).
pub fn reconcile_all_pending(
    counters: &dyn BootCounterStore,
    stamps: &dyn VolumeStampStore,
    audit: Option<&FileAdminAuditSink>,
    now_unix: u64,
) -> Result<Vec<(String, ReconcileOutcome)>> {
    let mut out = Vec::new();
    for vm in stamps.pending_rollback_vms()? {
        let o = reconcile_pending(&vm, counters, stamps, audit, now_unix)?;
        out.push((vm, o));
    }
    Ok(out)
}

// ─── audit ───────────────────────────────────────────────────────────

/// One rollback event for the hash-chained admin log.
///
/// Mapping onto the fixed [`AdminAuditRecord`] schema (the chain's
/// canonical shape is not widened): `ticket_id` carries the
/// `restore_id`, and `reason` carries either the refusal reason or, on a
/// success, a `key=value` detail line (from/to values, gen, chip,
/// manifest, requested_by). `body_sha256` is the request body's hash on
/// admin routes and the arm's checkpoint hash on release-path events.
#[derive(Debug, Clone)]
pub struct RollbackAuditEvent<'a> {
    /// `authorize-rollback-intent`, `authorize-rollback`,
    /// `rollback-disarm`, `rollback-status`, `rollback-checkpoint`,
    /// `rollback-consume-intent`, `rollback-consume`, `rollback-refused`,
    /// `rollback-expired`, `rollback-lifecycle-clear`,
    /// `rollback-cleared-by-boot`, `rollback-commit-failed`,
    /// `rollback-reverted`. Release-path rows carry `ticket_id=` and
    /// `attested_chip=` in `reason`.
    pub op: &'static str,
    pub url_vm_id: &'a str,
    pub restore_id: Option<&'a str>,
    pub applied: bool,
    pub status_code: u16,
    pub reason: &'a str,
    pub peer_san: Option<&'a str>,
    pub peer_serial: Option<&'a str>,
    pub body_sha256: [u8; 32],
}

/// Append a rollback event to the admin chain.
pub fn record_rollback_event(
    audit: &FileAdminAuditSink,
    ev: &RollbackAuditEvent,
    now_unix: u64,
) -> Result<[u8; 32]> {
    let record = AdminAuditRecord {
        op: ev.op,
        url_vm_id: ev.url_vm_id,
        ticket_id: ev.restore_id,
        vm_id: Some(ev.url_vm_id),
        applied: ev.applied,
        status_code: ev.status_code,
        reason: Some(ev.reason).filter(|r| !r.is_empty()),
        peer_san: ev.peer_san,
        peer_serial: ev.peer_serial,
        body_sha256: &ev.body_sha256,
    };
    audit.append(&record, now_unix)
}

/// Detail line for an arm (armed, expired, cleared, disarmed).
pub fn arm_detail(arm: &RollbackArm) -> String {
    format!(
        "from_counter={} to_stamp={} new_gen={} dest={} manifest={} checkpoint={} \
         expires_at={} requested_by={} armed_by={}",
        arm.from_counter,
        arm.to_stamp,
        arm.new_gen,
        arm.dest,
        arm.manifest_sha256_hex,
        arm.checkpoint_sha256_hex,
        arm.expires_at_unix,
        arm.requested_by,
        arm.armed_by,
    )
}

/// Hash of the arm's checkpoint, as the `body_sha256` of release-path
/// events.
pub fn arm_checkpoint_sha(arm: &RollbackArm) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(b) = hex::decode(&arm.checkpoint_sha256_hex) {
        if b.len() == 32 {
            out.copy_from_slice(&b);
        }
    }
    out
}

/// Best-effort append for paths that must not fail on an audit error
/// (the release path after its commits, lifecycle clears after the
/// fence already applied). A failure is reported on stderr, never
/// swallowed silently.
pub fn record_rollback_event_best_effort(
    audit: Option<&FileAdminAuditSink>,
    ev: &RollbackAuditEvent,
    now_unix: u64,
) {
    let Some(audit) = audit else {
        return;
    };
    if let Err(e) = record_rollback_event(audit, ev, now_unix) {
        use std::io::Write;
        let mut err = std::io::stderr().lock();
        let _ = writeln!(
            err,
            "kbs-core::rollback: admin-audit append failed for {} vm_id={}: {e}",
            ev.op, ev.url_vm_id
        );
    }
}

/// Purge every expired arm and audit each one (`rollback-expired`).
/// Called at the top of every rollback admin route and every lifecycle
/// route. Returns the purged arms.
pub fn purge_expired_and_audit(
    counters: &dyn BootCounterStore,
    audit: Option<&FileAdminAuditSink>,
    now_unix: u64,
) -> Result<Vec<RollbackArm>> {
    let purged = counters.purge_expired_rollback_arms(now_unix)?;
    for arm in &purged {
        let detail = arm_detail(arm);
        record_rollback_event_best_effort(
            audit,
            &RollbackAuditEvent {
                op: "rollback-expired",
                url_vm_id: &arm.vm_id,
                restore_id: Some(&arm.restore_id),
                applied: true,
                status_code: 200,
                reason: &detail,
                peer_san: None,
                peer_serial: None,
                body_sha256: arm_checkpoint_sha(arm),
            },
            now_unix,
        );
    }
    Ok(purged)
}

/// Clear `vm_id`'s arm after a lifecycle transition (`activate`,
/// `decommission`, `tombstone`) and audit it as
/// `rollback-lifecycle-clear` with `reason = "lifecycle-<op> …"`.
/// Best-effort: the fence already applied, and an arm that outlives it
/// can no longer admit anything (its generation is no longer releasable),
/// so a failed clear is reported, not propagated.
pub fn clear_for_lifecycle(
    counters: &dyn BootCounterStore,
    audit: Option<&FileAdminAuditSink>,
    vm_id: &str,
    lifecycle_op: &str,
    peer_san: Option<&str>,
    peer_serial: Option<&str>,
    now_unix: u64,
) -> Option<RollbackArm> {
    match counters.clear_rollback_arm(
        vm_id,
        &format!("{CLEAR_LIFECYCLE_PREFIX}{lifecycle_op}"),
        now_unix,
    ) {
        Ok(Some(arm)) => {
            let detail = format!("lifecycle-{lifecycle_op} {}", arm_detail(&arm));
            record_rollback_event_best_effort(
                audit,
                &RollbackAuditEvent {
                    op: "rollback-lifecycle-clear",
                    url_vm_id: vm_id,
                    restore_id: Some(&arm.restore_id),
                    applied: true,
                    status_code: 200,
                    reason: &detail,
                    peer_san,
                    peer_serial,
                    body_sha256: arm_checkpoint_sha(&arm),
                },
                now_unix,
            );
            Some(arm)
        }
        Ok(None) => None,
        Err(e) => {
            use std::io::Write;
            let mut err = std::io::stderr().lock();
            let _ = writeln!(
                err,
                "kbs-core::rollback: lifecycle-{lifecycle_op} could not clear the rollback arm \
                 of vm_id={vm_id}: {e} (the arm can no longer admit a release; it expires on \
                 its own)"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_counter::InMemoryBootCounterStore;
    use crate::lifecycle::VmState;
    use crate::volume_stamp::InMemoryVolumeStampStore;
    use std::collections::HashMap;
    use std::sync::Mutex;

    pub(crate) struct MapStates(pub Mutex<HashMap<String, VmState>>);
    impl VmStateStore for MapStates {
        fn key_mode(&self, _vm: &str) -> Result<hippius_types::guardian::KeyMode> {
            Ok(hippius_types::guardian::KeyMode::Hippius)
        }
        fn get(&self, vm_id: &str) -> Result<VmState> {
            self.0
                .lock()
                .unwrap()
                .get(vm_id)
                .cloned()
                .ok_or_else(|| KbsError::Lifecycle("no state for vm_id".into()))
        }
    }

    const DEST: &str = "aabbccdd";

    fn migrating(new_gen: u64, dest: &str) -> VmState {
        VmState::Migrating {
            old_gen: new_gen - 1,
            new_gen,
            source: "11223344".into(),
            dest: dest.into(),
            lease_id: "lease".into(),
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn checkpoint_for(vm: &str, counter: u64, stamp: u64) -> RollbackCheckpoint {
        RollbackCheckpoint {
            vm_id: vm.into(),
            boot_counter: counter,
            volume_stamp: stamp,
            unconfirmed_releases: 0,
            generation: 1,
            issued_at_unix: 1000,
            volume_stamp_timeline_id: Some(crate::volume_stamp::ZERO_TIMELINE),
        }
    }

    /// A `manifest.json` shaped like vali's, embedding `cbor_hex`.
    fn manifest_for(vm: &str, cbor_hex: &str) -> Vec<u8> {
        serde_json::to_vec_pretty(&serde_json::json!({
            "format": 1,
            "vm_id": vm,
            "boot_counter": 3,
            "kbs_rollback_checkpoint": {
                "checkpoint": {"vm_id": vm},
                "checkpoint_cbor_hex": cbor_hex,
                "signature_hex": "00",
            },
        }))
        .unwrap()
    }

    fn with_manifest(req: &mut AdminAuthorizeRollbackRequest, manifest: &[u8]) {
        req.point_manifest_b64 = base64::engine::general_purpose::STANDARD.encode(manifest);
        req.point_manifest_sha256_hex = hex::encode(Sha256::digest(manifest));
    }

    fn request(
        cp: &RollbackCheckpoint,
        sk: &SigningKey,
        restore_id: &str,
    ) -> AdminAuthorizeRollbackRequest {
        let (cbor, sig) = sign_checkpoint(sk, cp).unwrap();
        let manifest = manifest_for("vm-1", &hex::encode(&cbor));
        AdminAuthorizeRollbackRequest {
            checkpoint_cbor_hex: hex::encode(cbor),
            signature_hex: hex::encode(sig),
            point_manifest_sha256_hex: hex::encode(Sha256::digest(&manifest)),
            point_manifest_b64: base64::engine::general_purpose::STANDARD.encode(&manifest),
            new_gen: 2,
            dest_platform_id_hex: DEST.into(),
            restore_id: restore_id.into(),
            ttl_s: 600,
            requested_by: "tenant:42".into(),
        }
    }

    struct Fx {
        states: MapStates,
        counters: InMemoryBootCounterStore,
        stamps: InMemoryVolumeStampStore,
        sk: SigningKey,
    }

    /// TEST-ONLY: record that `vm_id`'s guest speaks the timeline-bound
    /// stamp protocol (v2), which no guest reports yet — without it
    /// nothing can be armed. Every fixture that expects an arm to land
    /// goes through here; the negative tests below leave it out.
    pub(crate) fn mark_rollback_capable_for_test(stamps: &dyn VolumeStampStore, vm_id: &str) {
        stamps
            .record_guest_stamp_protocol(
                vm_id,
                crate::volume_stamp::GUEST_STAMP_PROTOCOL_ROLLBACK_MIN,
            )
            .unwrap();
    }

    fn fx(stored: u64) -> Fx {
        let states = MapStates(Mutex::new(HashMap::new()));
        states
            .0
            .lock()
            .unwrap()
            .insert("vm-1".into(), migrating(2, DEST));
        let counters = InMemoryBootCounterStore::default();
        if stored > 0 {
            counters.seed("vm-1", stored).unwrap();
        }
        let stamps = InMemoryVolumeStampStore::default();
        mark_rollback_capable_for_test(&stamps, "vm-1");
        Fx {
            states,
            counters,
            stamps,
            sk: key(),
        }
    }

    fn authorize(
        f: &Fx,
        req: &AdminAuthorizeRollbackRequest,
        now: u64,
    ) -> core::result::Result<AuthorizeOk, RollbackErr> {
        process_authorize_rollback(
            "vm-1",
            req,
            &f.states,
            &f.counters,
            &f.stamps,
            &f.sk.verifying_key(),
            &RollbackPolicy::default(),
            Some("spiffe://hippius.network/vali"),
            now,
        )
    }

    #[test]
    fn a_valid_arm_is_stored_with_the_checkpoint_values() {
        let f = fx(5);
        let req = request(&checkpoint_for("vm-1", 3, 2), &f.sk, "r-1");
        let ok = authorize(&f, &req, 10_000).unwrap();
        assert!(ok.fresh);
        assert_eq!(ok.arm.from_counter, 3);
        assert_eq!(ok.arm.to_stamp, 2);
        assert_eq!(ok.arm.expires_at_unix, 10_600);
        assert_eq!(f.counters.rollback_state("vm-1").unwrap().0, Some(ok.arm));
        // Arming never moves the counter.
        assert_eq!(f.counters.get("vm-1").unwrap(), 5);
    }

    /// The rollback-capability gate: a VM with NO recorded protocol (every
    /// VM today) and one recorded at v1 are both refused 409
    /// `guest-not-rollback-capable`, and the refusal stores nothing.
    #[test]
    fn a_guest_without_a_timeline_bound_stamp_is_never_armed() {
        for record in [None, Some(crate::volume_stamp::GUEST_STAMP_PROTOCOL_V1)] {
            let mut f = fx(5);
            f.stamps = InMemoryVolumeStampStore::default();
            if let Some(p) = record {
                f.stamps.record_guest_stamp_protocol("vm-1", p).unwrap();
            }
            let req = request(&checkpoint_for("vm-1", 3, 2), &f.sk, "r-1");
            let err = authorize(&f, &req, 10_000).unwrap_err();
            assert_eq!(
                err,
                RollbackErr::GuestNotRollbackCapable,
                "record={record:?}"
            );
            assert_eq!(err.status_code(), 409);
            assert_eq!(err.reason(), "guest-not-rollback-capable");
            let (arm, last) = f.counters.rollback_state("vm-1").unwrap();
            assert_eq!((arm, last), (None, None), "record={record:?}");
        }
    }

    /// M2 (customer-held keys): the guardian owns the stamp, so even a
    /// v2 guest is not rollback-capable at the KBS — refused, and
    /// reported `rollback_capable: false`.
    #[test]
    fn an_m2_vm_is_never_rollback_capable() {
        struct M2(MapStates);
        impl VmStateStore for M2 {
            fn get(&self, vm_id: &str) -> Result<VmState> {
                self.0.get(vm_id)
            }
            fn key_mode(&self, _vm: &str) -> Result<hippius_types::guardian::KeyMode> {
                Ok(hippius_types::guardian::KeyMode::Customer)
            }
        }
        let f = fx(5);
        let m2 = M2(MapStates(Mutex::new(f.states.0.lock().unwrap().clone())));
        assert_eq!(rollback_capable("vm-1", &m2, &f.stamps), Ok(false));
        assert_eq!(rollback_capable("vm-1", &f.states, &f.stamps), Ok(true));
        let req = request(&checkpoint_for("vm-1", 3, 2), &f.sk, "r-1");
        let out = process_authorize_rollback(
            "vm-1",
            &req,
            &m2,
            &f.counters,
            &f.stamps,
            &f.sk.verifying_key(),
            &RollbackPolicy::default(),
            None,
            10_000,
        );
        assert_eq!(out, Err(RollbackErr::GuestNotRollbackCapable));
        assert_eq!(f.counters.rollback_state("vm-1").unwrap().0, None);
    }

    /// A VM whose guest went BACK to v1 (the latest release wins) is no
    /// longer armable, and the status route reports it.
    #[test]
    fn a_guest_that_went_back_to_v1_is_no_longer_armable() {
        let f = fx(5);
        f.stamps
            .record_guest_stamp_protocol("vm-1", crate::volume_stamp::GUEST_STAMP_PROTOCOL_V1)
            .unwrap();
        let req = request(&checkpoint_for("vm-1", 3, 2), &f.sk, "r-1");
        assert_eq!(
            authorize(&f, &req, 10_000),
            Err(RollbackErr::GuestNotRollbackCapable)
        );
        assert_eq!(rollback_capable("vm-1", &f.states, &f.stamps), Ok(false));
        mark_rollback_capable_for_test(&f.stamps, "vm-1");
        assert_eq!(rollback_capable("vm-1", &f.states, &f.stamps), Ok(true));
        assert!(!rollback_status(None, None, None, None, false, 10_000).rollback_capable);
        assert!(rollback_status(None, None, None, None, true, 10_000).rollback_capable);
    }

    #[test]
    fn a_checkpoint_signed_by_another_key_is_refused() {
        let f = fx(5);
        let forged = request(
            &checkpoint_for("vm-1", 3, 2),
            &SigningKey::from_bytes(&[9u8; 32]),
            "r-1",
        );
        assert_eq!(
            authorize(&f, &forged, 10_000),
            Err(RollbackErr::BadCheckpointSignature)
        );
        assert_eq!(f.counters.rollback_state("vm-1").unwrap().0, None);
    }

    #[test]
    fn a_tampered_checkpoint_is_refused() {
        let f = fx(5);
        let mut req = request(&checkpoint_for("vm-1", 3, 2), &f.sk, "r-1");
        // Re-encode a checkpoint with a LOWER stamp, keep the old signature.
        let (cbor, _) = sign_checkpoint(&f.sk, &checkpoint_for("vm-1", 3, 0)).unwrap();
        req.checkpoint_cbor_hex = hex::encode(cbor);
        assert_eq!(
            authorize(&f, &req, 10_000),
            Err(RollbackErr::BadCheckpointSignature)
        );
        // A single flipped byte in the signed bytes.
        let mut req = request(&checkpoint_for("vm-1", 3, 2), &f.sk, "r-1");
        let mut raw = hex::decode(&req.checkpoint_cbor_hex).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        req.checkpoint_cbor_hex = hex::encode(raw);
        assert_eq!(
            authorize(&f, &req, 10_000),
            Err(RollbackErr::BadCheckpointSignature)
        );
        assert_eq!(f.counters.rollback_state("vm-1").unwrap().0, None);
    }

    #[test]
    fn a_checkpoint_for_another_vm_is_refused() {
        let f = fx(5);
        let req = request(&checkpoint_for("vm-2", 3, 2), &f.sk, "r-1");
        assert_eq!(
            authorize(&f, &req, 10_000),
            Err(RollbackErr::CheckpointVmMismatch)
        );
        assert_eq!(f.counters.rollback_state("vm-1").unwrap().0, None);
    }

    /// B2: a stamp of 0 makes the guest ADOPT any disk, so it binds
    /// nothing. The checkpoint route still signs it (vali decides); the
    /// arm refuses it, and writes nothing.
    #[test]
    fn an_unstamped_checkpoint_is_signed_but_never_armed() {
        let f = fx(5);
        let stamps = InMemoryVolumeStampStore::default();
        let ok = process_rollback_checkpoint("vm-1", &f.states, &f.counters, &stamps, &f.sk, 777)
            .unwrap();
        assert_eq!(
            ok.checkpoint.volume_stamp, 0,
            "still issued, visibly unstamped"
        );
        let req = request(&checkpoint_for("vm-1", 3, 0), &f.sk, "r-1");
        let err = authorize(&f, &req, 10_000).unwrap_err();
        assert_eq!(err, RollbackErr::CheckpointUnstamped);
        assert_eq!(
            (err.status_code(), err.reason()),
            (409, "checkpoint-unstamped")
        );
        assert_eq!(f.counters.rollback_state("vm-1").unwrap().0, None);
        // Nor did it touch the rate limit: a stamped point arms at once.
        authorize(
            &f,
            &request(&checkpoint_for("vm-1", 3, 1), &f.sk, "r-2"),
            10_001,
        )
        .unwrap();
    }

    /// The manifest bytes must hash to the claimed sha AND carry this very
    /// checkpoint and VM.
    #[test]
    fn a_manifest_that_does_not_bind_the_checkpoint_is_refused() {
        let f = fx(5);
        let cp = checkpoint_for("vm-1", 3, 2);
        let good = request(&cp, &f.sk, "r-1");
        let other_cbor = hex::encode(
            sign_checkpoint(&f.sk, &checkpoint_for("vm-1", 2, 1))
                .unwrap()
                .0,
        );

        // Right bytes, wrong claimed sha.
        let mut wrong_sha = good.clone();
        wrong_sha.point_manifest_sha256_hex = "ab".repeat(32);
        // Consistent sha, but the manifest embeds ANOTHER checkpoint.
        let mut other_point = good.clone();
        with_manifest(&mut other_point, &manifest_for("vm-1", &other_cbor));
        // Consistent sha, the right checkpoint, another VM's manifest.
        let mut other_vm = good.clone();
        with_manifest(
            &mut other_vm,
            &manifest_for("vm-2", &good.checkpoint_cbor_hex),
        );
        // Consistent sha, no checkpoint at all / not JSON / upper-case hex.
        let mut no_cp = good.clone();
        with_manifest(&mut no_cp, br#"{"vm_id":"vm-1"}"#);
        let mut not_json = good.clone();
        with_manifest(&mut not_json, b"not json");
        let mut upper = good.clone();
        with_manifest(
            &mut upper,
            &manifest_for("vm-1", &good.checkpoint_cbor_hex.to_uppercase()),
        );
        for (what, req) in [
            ("wrong sha", wrong_sha),
            ("other point", other_point),
            ("other vm", other_vm),
            ("no checkpoint", no_cp),
            ("not json", not_json),
            ("upper-case hex", upper),
        ] {
            let err = authorize(&f, &req, 10_000).unwrap_err();
            assert_eq!(err, RollbackErr::ManifestMismatch, "{what}");
            assert_eq!(
                (err.status_code(), err.reason()),
                (400, "manifest-mismatch")
            );
        }
        assert_eq!(f.counters.rollback_state("vm-1").unwrap().0, None);
        authorize(&f, &good, 10_000).unwrap();
    }

    #[test]
    fn a_missing_undecodable_or_oversized_manifest_is_a_bad_request() {
        let f = fx(5);
        let cp = checkpoint_for("vm-1", 3, 2);
        let good = request(&cp, &f.sk, "r-1");
        let mut empty = good.clone();
        empty.point_manifest_b64 = String::new();
        let mut not_b64 = good.clone();
        not_b64.point_manifest_b64 = "!!!".into();
        let mut huge = good.clone();
        with_manifest(&mut huge, &vec![b' '; MAX_POINT_MANIFEST_LEN + 1]);
        for req in [empty, not_b64, huge] {
            assert_eq!(
                authorize(&f, &req, 10_000),
                Err(RollbackErr::BadRequest("bad-point-manifest"))
            );
        }
        // Exactly at the cap is accepted (padding a real manifest).
        let mut at_cap = manifest_for("vm-1", &good.checkpoint_cbor_hex);
        at_cap.resize(MAX_POINT_MANIFEST_LEN, b' ');
        let mut req = good.clone();
        with_manifest(&mut req, &at_cap);
        authorize(&f, &req, 10_000).unwrap();
    }

    /// `delivered`/`reverted` describe the LAST rollback only when the
    /// stamp store's resolution names that same restore; an older
    /// resolution never marks a newer, in-flight rollback delivered.
    #[test]
    fn a_resolution_only_describes_its_own_restore() {
        let last = LastRollback {
            restore_id: "r-2".into(),
            manifest_sha256_hex: "ab".repeat(32),
            from_counter: 3,
            to_counter: 6,
            stamp: 2,
            consumed_at_unix: 10,
            requested_by: "tenant:1".into(),
        };
        let res = |id: &str, how| ResolvedRollback {
            restore_id: id.into(),
            resolution: how,
        };
        let flags = |r: Option<&ResolvedRollback>| {
            let w = last.to_wire(r);
            (w.delivered, w.reverted)
        };
        assert_eq!(flags(None), (false, false));
        assert_eq!(
            flags(Some(&res("r-1", RollbackResolution::Delivered))),
            (false, false)
        );
        assert_eq!(
            flags(Some(&res("r-2", RollbackResolution::Delivered))),
            (true, false)
        );
        assert_eq!(
            flags(Some(&res("r-2", RollbackResolution::Reverted))),
            (false, true)
        );
    }

    #[test]
    fn a_non_rollback_is_refused_at_equal_and_above() {
        let f = fx(5);
        for c in [5, 6] {
            let req = request(&checkpoint_for("vm-1", c, 2), &f.sk, "r-1");
            assert_eq!(
                authorize(&f, &req, 10_000),
                Err(RollbackErr::NotARollback { stored: 5 })
            );
        }
        assert_eq!(f.counters.rollback_state("vm-1").unwrap().0, None);
    }

    #[test]
    fn the_row_must_be_exactly_migrating_to_the_requested_gen_and_dest() {
        let f = fx(5);
        let cp = checkpoint_for("vm-1", 3, 2);
        let mut req = request(&cp, &f.sk, "r-1");
        req.new_gen = 3;
        assert_eq!(
            authorize(&f, &req, 10_000),
            Err(RollbackErr::RowNotActivated)
        );
        let mut req = request(&cp, &f.sk, "r-1");
        req.dest_platform_id_hex = "aabbccde".into();
        assert_eq!(
            authorize(&f, &req, 10_000),
            Err(RollbackErr::RowNotActivated)
        );
        f.states.0.lock().unwrap().insert(
            "vm-1".into(),
            VmState::Active {
                gen: 2,
                host: DEST.into(),
                lease_id: "lease".into(),
            },
        );
        let req = request(&cp, &f.sk, "r-1");
        assert_eq!(
            authorize(&f, &req, 10_000),
            Err(RollbackErr::RowNotActivated)
        );
        assert_eq!(f.counters.rollback_state("vm-1").unwrap().0, None);
    }

    /// A lifecycle row that moves between the check and the store: the
    /// fresh arm is taken back out rather than left blocking the VM.
    #[test]
    fn an_arm_whose_row_moved_while_storing_is_taken_back() {
        struct Moving(std::sync::atomic::AtomicUsize);
        impl VmStateStore for Moving {
            fn key_mode(&self, _vm: &str) -> Result<hippius_types::guardian::KeyMode> {
                Ok(hippius_types::guardian::KeyMode::Hippius)
            }
            fn get(&self, _vm: &str) -> Result<VmState> {
                let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(if n == 0 {
                    migrating(2, DEST)
                } else {
                    migrating(3, DEST)
                })
            }
        }
        let f = fx(5);
        let req = request(&checkpoint_for("vm-1", 3, 2), &f.sk, "r-1");
        let out = process_authorize_rollback(
            "vm-1",
            &req,
            &Moving(std::sync::atomic::AtomicUsize::new(0)),
            &f.counters,
            &f.stamps,
            &f.sk.verifying_key(),
            &RollbackPolicy::default(),
            None,
            10_000,
        );
        assert_eq!(out, Err(RollbackErr::RowNotActivated));
        assert_eq!(f.counters.rollback_state("vm-1").unwrap().0, None);
    }

    #[test]
    fn ttl_outside_60_to_max_is_refused() {
        let f = fx(5);
        let cp = checkpoint_for("vm-1", 3, 2);
        for ttl in [0, 59, 3601, u64::MAX] {
            let mut req = request(&cp, &f.sk, "r-1");
            req.ttl_s = ttl;
            assert_eq!(
                authorize(&f, &req, 10_000),
                Err(RollbackErr::TtlOutOfRange),
                "ttl={ttl}"
            );
        }
        for ttl in [60, 3600] {
            let f = fx(5);
            let mut req = request(&cp, &f.sk, "r-1");
            req.ttl_s = ttl;
            authorize(&f, &req, 10_000).unwrap();
        }
    }

    #[test]
    fn same_restore_id_is_idempotent_and_another_is_arm_exists() {
        let f = fx(5);
        let cp = checkpoint_for("vm-1", 3, 2);
        let first = authorize(&f, &request(&cp, &f.sk, "r-1"), 10_000).unwrap();
        let again = authorize(&f, &request(&cp, &f.sk, "r-1"), 10_010).unwrap();
        assert!(!again.fresh);
        assert_eq!(again.arm, first.arm);
        assert_eq!(
            authorize(&f, &request(&cp, &f.sk, "r-2"), 10_020),
            Err(RollbackErr::ArmExists)
        );
        // Same id, different binding (another point) is NOT a re-drive.
        let other = checkpoint_for("vm-1", 2, 1);
        assert_eq!(
            authorize(&f, &request(&other, &f.sk, "r-1"), 10_030),
            Err(RollbackErr::ArmExists)
        );
        assert_eq!(
            f.counters.rollback_state("vm-1").unwrap().0,
            Some(first.arm)
        );
    }

    #[test]
    fn a_second_arm_inside_the_interval_is_rate_limited_even_after_a_disarm() {
        let f = fx(5);
        let cp = checkpoint_for("vm-1", 3, 2);
        authorize(&f, &request(&cp, &f.sk, "r-1"), 10_000).unwrap();
        f.counters
            .disarm_rollback("vm-1", "r-1", Some(10_050))
            .unwrap();
        assert_eq!(
            authorize(&f, &request(&cp, &f.sk, "r-2"), 10_100),
            Err(RollbackErr::RateLimited {
                retry_after_s: 1700
            })
        );
        assert_eq!(f.counters.rollback_state("vm-1").unwrap().0, None);
        authorize(&f, &request(&cp, &f.sk, "r-2"), 11_800).unwrap();
    }

    #[test]
    fn arm_admits_every_condition_independently() {
        let arm = RollbackArm {
            vm_id: "vm-1".into(),
            restore_id: "r".into(),
            manifest_sha256_hex: "00".repeat(32),
            new_gen: 2,
            dest: DEST.into(),
            from_counter: 3,
            to_stamp: 2,
            checkpoint_sha256_hex: "00".repeat(32),
            armed_at_unix: 0,
            expires_at_unix: 100,
            requested_by: "t".into(),
            armed_by: String::new(),
        };
        assert_eq!(arm_admits(&arm, 2, DEST, 4, 5, 99), Ok(()));
        assert_eq!(arm_admits(&arm, 2, DEST, 4, 5, 100), Err("arm-expired"));
        assert_eq!(arm_admits(&arm, 3, DEST, 4, 5, 99), Err("wrong-generation"));
        assert_eq!(arm_admits(&arm, 2, "aabbccde", 4, 5, 99), Err("wrong-chip"));
        assert_eq!(arm_admits(&arm, 2, DEST, 3, 5, 99), Err("wrong-counter"));
        assert_eq!(arm_admits(&arm, 2, DEST, 5, 5, 99), Err("wrong-counter"));
        assert_eq!(arm_admits(&arm, 2, DEST, 6, 5, 99), Err("not-a-rewind"));
    }

    #[test]
    fn checkpoint_route_signs_the_three_stores_and_refuses_the_edges() {
        let f = fx(5);
        let stamps = InMemoryVolumeStampStore::default();
        stamps.confirm("vm-1", 1).unwrap();
        stamps.note_release("vm-1").unwrap();
        let ok = process_rollback_checkpoint("vm-1", &f.states, &f.counters, &stamps, &f.sk, 777)
            .unwrap();
        assert_eq!(ok.checkpoint.boot_counter, 5);
        assert_eq!(ok.checkpoint.volume_stamp, 1);
        assert_eq!(ok.checkpoint.unconfirmed_releases, 1);
        assert_eq!(ok.checkpoint.generation, 2);
        assert_eq!(
            verify_checkpoint(&f.sk.verifying_key(), &ok.cbor, &ok.signature).unwrap(),
            ok.checkpoint
        );
        assert_eq!(
            process_rollback_checkpoint("vm-x", &f.states, &f.counters, &stamps, &f.sk, 1),
            Err(RollbackErr::NoVmRow)
        );
        let f0 = fx(0);
        assert_eq!(
            process_rollback_checkpoint("vm-1", &f0.states, &f0.counters, &stamps, &f0.sk, 1),
            Err(RollbackErr::NoBootCounter)
        );
    }

    #[test]
    fn a_release_response_or_an_evidence_bundle_never_verifies_as_a_checkpoint() {
        use crate::crypto::{sign_denial, sign_response, KbsResponse, RELEASE_DOMAIN};
        let sk = key();
        let resp = KbsResponse {
            domain: RELEASE_DOMAIN.into(),
            v: 1,
            ticket_id: "t".into(),
            tenant_id: "tn".into(),
            vm_id: "vm-1".into(),
            vm_generation: 2,
            kbs_nonce: vec![0; 32],
            measurement: vec![0; 48],
            kbs_kid: vec![1],
            hpke_suite_id: 1,
            allowed_userdata_digest: vec![0; 32],
            luks: Some(hippius_types::release::WrappedSecret {
                secret_type: "luks".into(),
                secret_path: "p".into(),
                secret_version: 1,
                enc: vec![1],
                ct: vec![2],
            }),
            userdata: hippius_types::release::WrappedSecret {
                secret_type: "userdata".into(),
                secret_path: "p".into(),
                secret_version: 1,
                enc: vec![1],
                ct: vec![2],
            },
            lifecycle_key: None,
            boot_counter: 4,
            expected_volume_stamp: 3,
            volume_stamp_token: None,
            volume_stamp_transition: None,
        };
        let signed = sign_response(&sk, &resp).unwrap();
        assert!(verify_checkpoint(&sk.verifying_key(), &signed.body, &signed.sig).is_err());
        let denial = sign_denial(&sk, Some("t"), Some("vm-1"), "x").unwrap();
        assert!(verify_checkpoint(&sk.verifying_key(), &denial.body, &denial.sig).is_err());

        let bundle = hippius_types::evidence_bundle::EvidenceBundle {
            schema_version: hippius_types::evidence_bundle::EVIDENCE_BUNDLE_SCHEMA_VERSION,
            vm_id: "vm-1".into(),
            tenant_id: "tn".into(),
            ticket_id: "t".into(),
            granted_at_unix: 5,
            measurement: [0; 48],
            allowlist_epoch: 1,
            allowlist_manifest_digest: [0; 32],
            snp_report_bytes: vec![0; 1184],
            vcek_chain_pem: vec![1],
            ticket_cose_bytes: vec![1],
            kbs_signer_pubkey: sk.verifying_key().to_bytes(),
        };
        let body = bundle.canonical().unwrap();
        let sig = sk.sign(&body).to_bytes();
        assert!(verify_checkpoint(&sk.verifying_key(), &body, &sig).is_err());
    }

    #[test]
    fn a_checkpoint_never_verifies_as_a_release_response_or_an_evidence_bundle() {
        use crate::crypto::{verify_response, SignedResponse};
        let sk = key();
        let (cbor, sig) = sign_checkpoint(&sk, &checkpoint_for("vm-1", 3, 2)).unwrap();
        let as_resp = SignedResponse {
            body: cbor.clone(),
            sig: sig.to_vec(),
        };
        assert!(verify_response(&sk.verifying_key(), &as_resp).is_err());
        assert!(hippius_types::evidence_bundle::EvidenceBundle::decode(&cbor).is_err());
    }

    /// Every checkpoint the KBS signs is V2 and names the VM's CURRENT
    /// timeline (here one an earlier rollback moved it to), and an arm
    /// built from it records that timeline for the release path.
    #[test]
    fn the_checkpoint_names_the_current_timeline_and_the_arm_records_it() {
        let (states, counters, stamps) = world_v2_for_timeline_test();
        stamps
            .apply_rollback("vm-1", 3, 1, "restore-old", &[0x9a; 32])
            .unwrap();
        stamps.finalize_rollback("vm-1", "restore-old").unwrap();
        let cp =
            process_rollback_checkpoint("vm-1", &states, &counters, &stamps, &key(), 2000).unwrap();
        assert_eq!(cp.checkpoint.volume_stamp_timeline_id, Some([0x9a; 32]));
        assert_eq!(
            cp.to_wire().checkpoint.domain,
            hippius_types::rollback::ROLLBACK_CHECKPOINT_DOMAIN_V2
        );
        assert_eq!(
            verify_checkpoint(&key().verifying_key(), &cp.cbor, &cp.signature).unwrap(),
            cp.checkpoint
        );
    }

    fn world_v2_for_timeline_test() -> (
        TimelineStates,
        crate::boot_counter::InMemoryBootCounterStore,
        crate::volume_stamp::InMemoryVolumeStampStore,
    ) {
        let counters = crate::boot_counter::InMemoryBootCounterStore::default();
        counters.seed("vm-1", 4).unwrap();
        (
            TimelineStates,
            counters,
            crate::volume_stamp::InMemoryVolumeStampStore::default(),
        )
    }

    struct TimelineStates;
    impl VmStateStore for TimelineStates {
        fn get(&self, _vm: &str) -> Result<VmState> {
            Ok(VmState::Active {
                gen: 1,
                host: "aa".into(),
                lease_id: "lease".into(),
            })
        }
        fn key_mode(&self, _vm: &str) -> Result<hippius_types::guardian::KeyMode> {
            Ok(hippius_types::guardian::KeyMode::Hippius)
        }
    }
}
