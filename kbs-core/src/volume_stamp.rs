//! Per-VM CONFIRMED volume stamp — the anti-rollback reference that
//! only moves when a guest has actually stamped its encrypted volume.
//!
//! # Why this exists (and why the boot counter could not do the job)
//!
//! [`crate::boot_counter`] closes "roll back the STATE DISK": the guest
//! submits `stored + 1`, so replaying an old counter is refused. It does
//! NOT close "roll back the OVERLAY while keeping the CURRENT counter" —
//! the counter lives on `/dev/vdd`, a plaintext ext4 the miner can read
//! AND write, and nothing binds it to the ciphertext it protects. The
//! guest submits a current counter over a stale volume, the CAS passes,
//! and dm-integrity is satisfied (old ciphertext is authentic), so the
//! tenant's disk is silently reverted.
//!
//! The obvious fix — keep a copy of the counter inside the encrypted
//! volume and compare it to the state disk after unlock — is WRONG, and
//! the way it is wrong is worse than the bug:
//!
//! > The boot counter advances on every successful RELEASE, not on every
//! > successful BOOT. [`crate::release`] commits it as soon as the release
//! > is durably committed; it has no idea whether the guest ever finishes
//! > booting. A boot that dies anywhere between the KEK release and the
//! > in-guest comparison therefore leaves the counter one ahead of the
//! > volume, and the gap GROWS BY ONE PER ABORTED BOOT. Since the host
//! > controls the VM's lifetime (boot it, let it take the KEK, kill it,
//! > repeat), any fixed tolerance `S` is exhausted after `S + 1` kill
//! > cycles — after which the volume can never be opened again, on ANY
//! > host, because the KBS counter is authoritative and nothing can
//! > re-stamp the volume. That converts a silent rollback into a trivial,
//! > permanent, unrecoverable DESTRUCTION primitive.
//!
//! So the value the volume is compared against must be one that moves
//! ONLY when a volume was actually stamped. That is what this module
//! stores, and the only thing that advances it is an explicit,
//! authenticated confirmation from the guest AFTER it has written the
//! stamp (see [`confirm`] and the `/v1/kbs/volume-stamp/confirm` route).
//!
//! # The protocol
//!
//! Let `E` be the stored confirmed stamp (0 = never confirmed).
//!
//! 1. Release echoes `E` to the guest in the SIGNED `KbsResponse`
//!    (`expected_volume_stamp`) together with a single-use, HPKE-wrapped
//!    authenticator for `E + 1` (see [`stamp_token`]).
//! 2. The guest reads the stamp `S` stored inside its encrypted volume
//!    and REFUSES the boot when `S < E` (rolled-back overlay).
//! 3. The guest writes `E + 1` into the volume, then calls confirm with
//!    the token. Only that call advances the store to `E + 1`.
//!
//! An aborted boot confirms nothing, so `E` does not move and no gap
//! accumulates — the property the naive design lacked. The guest never
//! writes beyond `E + 1`, so the only legitimate divergence is `S == E + 1`
//! (a crash between the volume write and the confirm), which is bounded
//! at ONE by construction and cannot grow.
//!
//! # Threat note — why a token and not just attestation
//!
//! A confirmation that anyone can make is a REMOTE BRICK: pushing `E`
//! ahead of a volume that was never stamped makes the next boot refuse,
//! permanently. Requiring a fresh SNP report would NOT be enough either:
//! in golden mode the launch measurement is SHARED across same-distro
//! tenants, so a miner running its own golden VM can produce a valid
//! report, and it already holds the (public) COSE ticket it relays. The
//! authenticator therefore has to be something only the ATTESTED GUEST OF
//! THIS SPECIFIC RELEASE can hold — hence a token HPKE-sealed to the
//! X25519 key carried in that guest's own attestation report.
//!
//! # Suppressed-confirm detection — the miner IS the transport
//!
//! The guest treats a failed confirm as non-fatal (a fatal confirm would
//! hand the miner a trivial DoS). But the confirm travels guest → miner
//! → KBS, so **the miner decides whether any confirm is ever delivered**.
//! Trace what "non-fatal" means if a miner drops every confirm from a
//! VM's very first boot: `E` stays frozen at `0` forever, EVERY boot
//! takes the guest's `E == 0` "adopt" branch (there is no prior
//! expectation to violate), and the anti-rollback gate is disabled —
//! silently, because the only trace is a WARNING line in a log the miner
//! also controls. For a VM whose `E` already advanced past `0`, the gate
//! is not fully disabled, but it freezes at that value and the accept
//! window becomes `{E, E+1}` for as long as the miner keeps dropping
//! confirms — an unbounded rollback horizon, not a bounded one.
//!
//! Requiring the GUEST to notice suppression cannot close this — the
//! guest has no channel to the KBS that the miner doesn't also control.
//! But the miner cannot suppress the RELEASE: it needs the release to
//! get the KEK at all, so there is no VM without one. That makes the
//! release the signal the KBS can use to detect suppression without
//! depending on the miner delivering anything.
//!
//! [`VolumeStampStore::note_release`] durably counts releases granted
//! since the last successful confirm; [`VolumeStampStore::confirm`]
//! resets that count to `0`; [`crate::release::run`] refuses a release
//! outright once the count exceeds [`MAX_UNCONFIRMED_RELEASES`] (a
//! distinct, audited denial — see the release-path doc comment at the
//! call site). This turns "a miner suppresses confirms and keeps silent
//! rollback forever" into "a miner can suppress a couple of times, then
//! the VM stops getting KEKs and an operator has to look at it" — a
//! miner can always deny service, but it can no longer deny service AND
//! keep silent rollback.
//!
//! Refusing the release must not itself deadlock: only a confirm resets
//! the count, and a refused release means no boot, which means no
//! confirm, so recovery cannot depend on the guest. The ONLY other way
//! to clear the count is [`VolumeStampStore::admin_reset_unconfirmed`],
//! exposed as an AUTHENTICATED ADMIN action —
//! `POST /v1/admin/vm/{vm_id}/reset-volume-stamp-suppression`
//! (`kbs_core::admin::process_admin_reset_volume_stamp_suppression`),
//! served ONLY on the mTLS admin listener (pinned to an operator CA) and
//! NEVER reachable from the guest-facing release or confirm routes — a
//! miner must not be able to clear its own suppression.
//!
//! That last clause is a TEST, not a comment: the route is registered
//! only on `kbs_transport::build_admin_router` (served exclusively
//! through `kbs_server::admin_tls`, which drops any connection failing
//! client-cert verification before the router is reached, #894), and
//! `kbs-transport/tests/transport.rs::guest_router_does_not_expose_the_admin_suppression_reset`
//! asserts the guest-facing router 404s on it. Adding a route to the
//! wrong router is a one-line mistake with no compile-time signal, so it
//! is pinned rather than inspected.
//!
//! One non-obvious property of that placement, pinned by
//! `release::tests::suppressed_confirms_are_bounded_and_only_an_admin_reset_clears_them`:
//! a suppression refusal does NOT burn a boot counter. Gate 5b only
//! `check_only`s (it does not persist) and the boot-counter commit lives
//! at gate 11c, which a 5c refusal never reaches. If a refusal DID
//! advance the KBS boot counter, a miner could walk that counter away
//! from the guest's on-disk value just by provoking suppression
//! refusals, and every later boot would then be denied as a rollback —
//! converting a recoverable availability stop into exactly the permanent
//! brick this module exists to avoid. Keep the two gates in that order.
//!
//! # Observability — why ARMING the gate needs a READ path
//!
//! The gate ships DISABLED (`maxUnconfirmedReleases: 0`) and the chart
//! documents a 4-step cutover to arm it, whose step 3 is "verify
//! confirms are arriving fleet-wide". That step was not performable:
//! every path that touched this store was a WRITE — the guest's
//! confirm, the release path's [`VolumeStampStore::note_release`], the
//! admin [`VolumeStampStore::admin_reset_unconfirmed`] — and the store
//! lives on an emptyDir inside a Kata CVM where `kubectl exec` does not
//! work, so there was no out-of-band read either. The operator was asked
//! to confirm a condition nothing could observe, which leaves only
//! arming blind — and arming blind against a fleet holding one
//! never-confirming VM is a self-inflicted tenant outage, because a
//! refused release means no boot and the guest can never clear it.
//!
//! [`VolumeStampStore::snapshot`] + [`arming_readiness`] are that read
//! path, surfaced as `GET /v1/admin/volume-stamp?bound=N` on the admin
//! listener (`kbs_transport::admin_handler::
//! handle_get_volume_stamp_report`). Three properties are load-bearing:
//!
//! - The read is PURE. A read that cleared a streak would hand anyone
//!   who can reach the listener the capability
//!   [`VolumeStampStore::admin_reset_unconfirmed`] is deliberately
//!   fenced behind an audited operator write.
//! - It is evaluated against the bound the operator INTENDS to arm at,
//!   not the live one — while the gate is disabled there is no live
//!   bound, so a live-bound report is unconditionally green.
//! - It reports BOTH counters, because they answer different questions:
//!   `confirmed == 0` means this VM's confirm path has never once
//!   worked (arming leaves the gate inert for it and eventually refuses
//!   it), while a climbing `unconfirmed_releases` on a VM with
//!   `confirmed >= 1` means confirms USED to arrive and stopped. A
//!   report that collapsed them into one verdict could not tell an
//!   operator which of those two problems they have.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{KbsError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Releases tolerated since the last successful confirm before the KBS
/// refuses to grant another one (suppressed-confirm gate, see the module
/// docs above).
///
/// The steady state is exactly ONE unconfirmed release per boot: a
/// release grants the KEK (count 0 → 1), the guest boots, writes the
/// stamp, and confirms (count 1 → 0). So the bound MUST be `> 1` or every
/// normal boot would trip it. It is set to 3 — one full boot cycle of
/// slack beyond the steady state — so a single legitimate hiccup (the
/// guest crashes between unlock and stamp-write, one dropped packet on
/// the vsock relay) does not refuse a release, while still being small
/// enough that an operator notices quickly rather than after months of
/// silent suppression. Raising it trades faster operator response for
/// more tolerance of transient noise; it does not change the fact that
/// SOME bound is required (see the module docs — an unbounded count is
/// the same "freeze E and admit anything back to it" failure mode the
/// naive in-volume-vs-boot-counter design had).
pub const MAX_UNCONFIRMED_RELEASES: u64 = 3;

/// The guest volume-stamp protocol every guest speaks today: a stamp
/// `S` in the encrypted volume, compared against `E` (see the module
/// docs). It binds nothing to a TIMELINE: an older backup of the same
/// VM carries a smaller `S` and is refused, but so is every rollback —
/// and a lowered `E` admits any volume stamped `E` or `E + 1`, whichever
/// boot epoch wrote it.
///
/// Recorded per VM ([`VolumeStampStore::guest_stamp_protocol`]); a VM
/// with no record speaks this one.
pub const GUEST_STAMP_PROTOCOL_V1: u8 = 1;

/// "Stamp protocol v2": the in-volume stamp is the pair `(timeline_id,
/// value)`. A guest ATTESTS it in its SNP `REPORT_DATA`
/// (`hippius_types::report_data::tenant_stamp_v2`) — the only place the
/// KBS reads it from — and receives a `HIPPIUS_KBS_RELEASE_V2` response
/// carrying a `volume_stamp_transition {expected, target}`. It accepts its
/// volume only on the expected timeline, writes `(target, E + 1)`, and
/// confirms WITH the timeline ([`confirm_timeline`]).
///
/// # Why a timeline (blocker B1 of A2)
///
/// An authorized rollback sets `E := E_T`. The restored timeline then
/// writes `E_T + 1, E_T + 2, …` — the very numbers the ABANDONED
/// (pre-rollback) timeline's disks already carry, so with a bare number a
/// miner could present an abandoned disk later and undo the rollback. The
/// rollback release therefore moves the VM to a fresh random timeline no
/// release ever issued before, and every later release expects it: an
/// abandoned disk carries the old timeline and is refused WHATEVER its
/// value.
pub const GUEST_STAMP_PROTOCOL_V2: u8 = 2;

/// The first guest stamp protocol whose stamp is TIMELINE-bound
/// ([`GUEST_STAMP_PROTOCOL_V2`]). An authorized rollback
/// (`crate::rollback`) re-establishes an OLD stamp, so it is only sound
/// for a guest that can tell that old stamp's timeline apart from any
/// other volume carrying the same number: `authorize-rollback` refuses
/// (`guest-not-rollback-capable`) unless the VM's recorded protocol is at
/// least this, and so does the release that would consume an arm.
pub const GUEST_STAMP_PROTOCOL_ROLLBACK_MIN: u8 = GUEST_STAMP_PROTOCOL_V2;

/// The timeline of every VM never rolled back under stamp protocol v2
/// (and of every legacy, plain-integer in-volume stamp).
pub const ZERO_TIMELINE: [u8; 32] = [0u8; 32];

/// Whether the KBS owns the volume-stamp anti-rollback for a VM in `mode`.
///
/// In M2 (`customer`) the customer's key guardian owns it (it releases
/// the only key share, so it is the only party whose stamp binds
/// anything). The KBS then neither notes the release — so the
/// suppressed-confirm counter, and with it `max_unconfirmed_releases`,
/// never counts a release whose guest confirms to the guardian and never
/// to the KBS — nor mints a stamp token, and an authorized rollback has
/// no KBS stamp to restore.
pub fn kbs_owns_volume_stamp(mode: hippius_types::guardian::KeyMode) -> bool {
    use hippius_types::guardian::KeyMode;
    match mode {
        KeyMode::Hippius | KeyMode::Split => true,
        KeyMode::Customer => false,
    }
}

/// Whether a VM whose guest speaks `protocol` may be armed for an
/// authorized rollback. The ONE place that decision is made.
pub fn guest_stamp_protocol_is_rollback_capable(protocol: u8) -> bool {
    protocol >= GUEST_STAMP_PROTOCOL_ROLLBACK_MIN
}

/// Domain separator for the MAC key derived from the KBS signing seed.
const MAC_KEY_DOMAIN: &[u8] = b"HIPPIUS_KBS_VOLUME_STAMP_MAC_V1";
/// Domain separator for the token message itself.
const TOKEN_DOMAIN: &[u8] = b"HIPPIUS_KBS_VOLUME_STAMP_CONFIRM_V1";
/// Domain separator for a token minted under a NON-ZERO per-VM token
/// epoch (see [`stamp_token_epoch`]). A distinct tag rather than an
/// epoch field appended to the V1 message, so no epoch-0 token can ever
/// collide with an epoch-N one.
const TOKEN_EPOCH_DOMAIN: &[u8] = b"HIPPIUS_KBS_VOLUME_STAMP_CONFIRM_V2";
/// Domain separator for a stamp-protocol-v2 token: bound to the TARGET
/// timeline as well ([`stamp_token_timeline`]). Never equal to a V1/V2
/// token for any input.
const TOKEN_TIMELINE_DOMAIN: &[u8] = b"HIPPIUS_KBS_VOLUME_STAMP_CONFIRM_V3";

/// Derive the volume-stamp MAC key from the KBS Ed25519 signing seed.
///
/// Deriving rather than configuring a second key keeps the operator
/// surface unchanged (no new secret to provision, rotate or lose) and
/// makes the token automatically follow a signing-key rotation. The seed
/// is uniformly random 32 bytes, so a domain-separated SHA-256 over it is
/// a sound KDF, and the derived key is used ONLY as an HMAC key — it is
/// never used to sign, so no cross-protocol confusion with the response
/// signature is possible.
pub fn stamp_mac_key(signing_seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MAC_KEY_DOMAIN);
    h.update(signing_seed);
    h.finalize().into()
}

/// The single-use confirmation authenticator for advancing `vm_id`'s
/// stamp to `target`.
///
/// Recomputable from the MAC key alone, so the KBS stores NOTHING per
/// release — the confirm handler re-derives and compares in constant
/// time. Replay is harmless: a token authorises exactly one `target`,
/// and [`VolumeStampStore::confirm`] only accepts `stored + 1`, so
/// re-presenting a spent token is refused by the CAS.
///
/// The `vm_id` length is folded in explicitly so no two distinct
/// `(vm_id, target)` pairs can produce the same message.
pub fn stamp_token(mac_key: &[u8; 32], vm_id: &str, target: u64) -> [u8; 32] {
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(TOKEN_DOMAIN);
    mac.update(&(vm_id.len() as u64).to_be_bytes());
    mac.update(vm_id.as_bytes());
    mac.update(&target.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// The confirm token for `(vm_id, target)` under the VM's current token
/// EPOCH.
///
/// The epoch exists for the authorized rollback (`crate::rollback`): a
/// rollback LOWERS the confirmed stamp to `E_T`, so a token minted on the
/// abandoned timeline for `(vm_id, E_T + 1)` — which the miner saw in
/// clear when that guest confirmed — would otherwise confirm again and
/// push the restored expectation past the restored volume. Every
/// rollback bumps the VM's epoch, and a token only confirms under the
/// epoch it was minted in.
///
/// Epoch `0` (every VM that was never rolled back) is BYTE-IDENTICAL to
/// [`stamp_token`], so nothing changes for them. The guest treats the
/// token as 32 opaque bytes it hands back to the confirm route, so the
/// epoch needs no guest change.
pub fn stamp_token_epoch(mac_key: &[u8; 32], vm_id: &str, target: u64, epoch: u64) -> [u8; 32] {
    if epoch == 0 {
        return stamp_token(mac_key, vm_id, target);
    }
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(TOKEN_EPOCH_DOMAIN);
    mac.update(&(vm_id.len() as u64).to_be_bytes());
    mac.update(vm_id.as_bytes());
    mac.update(&target.to_be_bytes());
    mac.update(&epoch.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// The confirm token a stamp-protocol-v2 release mints: for advancing
/// `vm_id` to `target` ON `timeline`, under token `epoch`. It only
/// confirms through [`confirm_timeline`] naming the same timeline, and
/// only while that is the VM's current timeline — so a token minted for
/// one timeline can never advance another.
pub fn stamp_token_timeline(
    mac_key: &[u8; 32],
    vm_id: &str,
    target: u64,
    epoch: u64,
    timeline: &[u8; 32],
) -> [u8; 32] {
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(TOKEN_TIMELINE_DOMAIN);
    mac.update(&(vm_id.len() as u64).to_be_bytes());
    mac.update(vm_id.as_bytes());
    mac.update(&target.to_be_bytes());
    mac.update(&epoch.to_be_bytes());
    mac.update(timeline);
    mac.finalize().into_bytes().into()
}

/// READ-ONLY projection of one durable row, for the admin observability
/// path ([`VolumeStampStore::snapshot`]).
///
/// This is the ONLY shape in which the store's contents leave the KBS.
/// It is deliberately the whole row and nothing more: both counters are
/// needed to answer the question the cutover asks (see
/// [`arming_readiness`]), and adding anything derived here rather than
/// in a pure function would put policy in a data type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeStampStatus {
    /// The VM this row belongs to.
    pub vm_id: String,
    /// Last CONFIRMED stamp. `0` = this VM has NEVER confirmed.
    pub confirmed: u64,
    /// Releases granted since the last confirm (or since the last
    /// [`VolumeStampStore::admin_reset_unconfirmed`]).
    pub unconfirmed_releases: u64,
}

impl VolumeStampStatus {
    /// Has this VM EVER landed a confirm?
    ///
    /// This is the distinction a bare "is it currently suppressed?"
    /// check cannot make, and it is the one that matters for arming.
    /// A VM at `confirmed == 0` with `unconfirmed_releases == 1` looks
    /// perfectly healthy against any bound `> 1` — it is one release
    /// into its steady state — but it has never once proven the confirm
    /// path works for it, so its anti-rollback expectation is frozen at
    /// `0` and the gate is, for that VM, doing nothing. `confirmed >= 1`
    /// is the only positive evidence that a guest actually reached
    /// `/v1/kbs/volume-stamp/confirm` through its miner.
    ///
    /// Note it is NOT possible to tell "confirmed once, long ago" from
    /// "confirmed on the most recent boot" by `confirmed` alone — the
    /// stamp is a count, not a timestamp. `unconfirmed_releases` is what
    /// separates them: a VM that confirms every boot sits at `0` (idle)
    /// or `1` (one release in flight), while a VM whose confirms stopped
    /// arriving after an early success has `confirmed >= 1` AND a count
    /// that keeps climbing. Both fields are therefore reported, never
    /// collapsed into one verdict.
    pub fn has_ever_confirmed(&self) -> bool {
        self.confirmed > 0
    }

    /// Would this VM's NEXT release be refused if the suppressed-confirm
    /// gate were armed at `bound`?
    ///
    /// Mirrors `crate::release::run` gate 5c EXACTLY, including its
    /// off-by-one: the release path calls
    /// [`VolumeStampStore::note_release`] FIRST (which increments) and
    /// only then compares `unconfirmed_releases > bound`. So the row
    /// this function sees is the PRE-increment value, and the predicate
    /// is `stored + 1 > bound`, i.e. `stored >= bound`.
    ///
    /// Getting this wrong in the safe-looking direction (`stored >
    /// bound`) would report "0 VMs would be refused" for a fleet in
    /// which every VM sitting exactly at `bound` is refused on its very
    /// next boot — a green light straight into the outage the report
    /// exists to prevent.
    ///
    /// `saturating_add` rather than `checked_add`: at `u64::MAX` the
    /// real `note_release` errors out and the release fails anyway, so
    /// "would be refused" is the truthful answer, not an overflow.
    pub fn would_refuse_next_release(&self, bound: u64) -> bool {
        self.unconfirmed_releases.saturating_add(1) > bound
    }
}

/// Fleet-wide answer to "may I arm the suppressed-confirm gate?".
///
/// Produced by [`arming_readiness`] from a [`VolumeStampStore::snapshot`]
/// and a PROSPECTIVE bound. Pure — no I/O, no clock, no store — so the
/// verdict is a function of the rows alone and is testable without a
/// server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmingReadiness {
    /// The bound the rows were evaluated AGAINST — the value the
    /// operator is proposing to arm at, NOT necessarily the one the
    /// process is running with.
    pub evaluated_bound: u64,
    /// How many VMs the store knows about. A row exists for every
    /// `vm_id` that has ever been granted a release, because
    /// [`VolumeStampStore::note_release`] creates it — so this IS the
    /// fleet as far as the KBS is concerned, not a subset that opted in.
    pub vms: usize,
    /// VMs at `confirmed == 0`. Non-zero means arming would leave the
    /// gate inert for those VMs until they eventually trip it.
    pub never_confirmed: usize,
    /// VMs whose NEXT release would be refused the moment the gate is
    /// armed at `evaluated_bound`. Non-zero means arming is an
    /// immediate, self-inflicted outage of exactly that many tenants.
    pub would_refuse_now: usize,
    /// The two conditions together. `true` ⇒ every VM the KBS has ever
    /// released for has confirmed at least once AND none of them is
    /// close enough to the bound to be refused on its next boot. This is
    /// the cutover's step 3 in one boolean.
    pub ready_to_arm: bool,
}

/// Evaluate a snapshot against a PROSPECTIVE bound — the cutover's
/// step 3 ("verify confirms are arriving fleet-wide").
///
/// Why the bound is a parameter and not read from config: while the gate
/// is disabled there IS no armed bound, so evaluating against the live
/// setting would answer "0 VMs would be refused" unconditionally — a
/// report that is green precisely because the thing it is checking is
/// off. The operator asks about the bound they intend to arm at.
pub fn arming_readiness(rows: &[VolumeStampStatus], evaluated_bound: u64) -> ArmingReadiness {
    let never_confirmed = rows.iter().filter(|r| !r.has_ever_confirmed()).count();
    let would_refuse_now = rows
        .iter()
        .filter(|r| r.would_refuse_next_release(evaluated_bound))
        .count();
    ArmingReadiness {
        evaluated_bound,
        vms: rows.len(),
        never_confirmed,
        would_refuse_now,
        ready_to_arm: never_confirmed == 0 && would_refuse_now == 0,
    }
}

/// Per-`vm_id` durable row: the CONFIRMED stamp plus how many releases
/// have been granted since the last successful confirm. Both fields move
/// together, under the same lock and the same persisted write, so a
/// release-vs-confirm race can never desync them (e.g. a confirm that
/// resets the count while a concurrent release's increment is in flight
/// would otherwise be able to under-count the suppression it exists to
/// catch).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
struct StampRow {
    confirmed: u64,
    unconfirmed_releases: u64,
}

/// Per-`vm_id` CONFIRMED volume stamp, plus the suppressed-confirm
/// counter that lets the release path detect a miner dropping every
/// confirm (see the module docs).
///
/// Deliberately narrower than [`crate::boot_counter::BootCounterStore`]:
/// there is no `check_only`/`commit` split on the confirm side because
/// there is nothing to two-phase — the confirm IS the commit, and it
/// happens after the guest has already made the durable change (the
/// in-volume stamp) that it reports. There is likewise no `seed`: a
/// store that reads 0 is already treated as "no expectation" by the
/// release path, which is the self-healing recovery for a lost/rebuilt
/// store.
pub trait VolumeStampStore: Send + Sync {
    /// The last CONFIRMED stamp for `vm_id`. `0` = never confirmed
    /// (fresh VM, a VM predating this gate, or a rebuilt KBS store).
    fn get(&self, vm_id: &str) -> Result<u64>;

    /// Record that a release is about to grant a KEK for `vm_id`
    /// without (yet) a confirm resetting the suppression counter.
    /// Durably increments `unconfirmed_releases` and returns
    /// `(confirmed, unconfirmed_releases)` — BOTH read in the SAME
    /// step as the increment, so the release path's bound check can't
    /// race a concurrent confirm or admin reset.
    ///
    /// This is the detection primitive from the module docs: the
    /// release is the signal a miner cannot suppress (it needs the
    /// release to get the KEK at all), so counting releases — not
    /// confirms — is what makes suppression visible to the KBS without
    /// depending on the miner ever delivering a confirm. This method
    /// never refuses; it only records and reports. The release path
    /// (`crate::release::run`) is what compares the returned count
    /// against [`MAX_UNCONFIRMED_RELEASES`] and decides to deny.
    fn note_release(&self, vm_id: &str) -> Result<(u64, u64)>;

    /// Advance `vm_id`'s confirmed stamp to `value` AND reset its
    /// unconfirmed-releases counter to `0`, in the SAME durable step.
    ///
    /// CAS on the confirmed stamp: `value` MUST be exactly
    /// `stored + 1`. A rewind (`value <= stored`) and a skip
    /// (`value > stored + 1`) are both refused, fail-closed, without
    /// touching the store (neither field moves).
    ///
    /// Idempotence note: a retried confirm whose value has already been
    /// stored is refused as a rewind rather than silently accepted. The
    /// guest treats that refusal as success-equivalent (its stamp is
    /// already at the confirmed value), so a dropped ack costs nothing.
    fn confirm(&self, vm_id: &str, value: u64) -> Result<u64>;

    /// ADMIN-ONLY recovery: reset `vm_id`'s unconfirmed-releases counter
    /// to `0` WITHOUT touching the confirmed stamp. Returns the count
    /// that was cleared (`0` if the VM was not blocked — a harmless
    /// no-op, not an error).
    ///
    /// This is the ONLY way to clear the suppression counter other than
    /// a real confirm. It must NEVER be reachable from the guest-facing
    /// release or confirm routes — see the module docs on why the
    /// recovery has to be an authenticated admin action rather than
    /// anything the miner (which controls both routes' transport) could
    /// trigger itself.
    fn admin_reset_unconfirmed(&self, vm_id: &str) -> Result<u64>;

    /// ADMIN-ONLY OBSERVABILITY: a READ-ONLY snapshot of every row,
    /// sorted by `vm_id`.
    ///
    /// ## Why this exists
    ///
    /// The chart's cutover for arming this gate has a step 3 — "verify
    /// confirms are arriving fleet-wide" — that was not performable:
    /// `note_release` and `confirm` both write, `admin_reset_unconfirmed`
    /// writes, and NOTHING read the counters back. The store lives on an
    /// emptyDir inside a Kata CVM where `kubectl exec` does not work, so
    /// there was no out-of-band path either. The operator was asked to
    /// confirm a condition the system gave them no way to observe, and
    /// arming without it is exactly the "arming blind" the cutover warns
    /// against. This is that read path, and nothing more.
    ///
    /// ## What it must NOT be
    ///
    /// A read primitive, strictly. It MUST NOT create a row, MUST NOT
    /// create the backing file, MUST NOT touch `confirmed`, and MUST NOT
    /// reset or advance `unconfirmed_releases`. An implementation that
    /// mutated on read would hand anyone who can reach the admin
    /// listener the ability to clear a VM's suppression streak by
    /// polling — precisely the capability
    /// [`Self::admin_reset_unconfirmed`] is fenced behind an
    /// authenticated operator action to deny. Pinned by
    /// `tests::snapshot_is_a_pure_read_*`.
    ///
    /// Sorted so the fleet report is deterministic across calls (the
    /// backing `HashMap` is not) — an operator diffing two readouts is
    /// looking for a counter that moved, not for a reordering.
    fn snapshot(&self) -> Result<Vec<VolumeStampStatus>>;

    /// `(confirmed, unconfirmed_releases)` of one VM (`(0, 0)` when
    /// absent). Pure read, like [`Self::snapshot`].
    fn row(&self, vm_id: &str) -> Result<(u64, u64)> {
        Ok(self
            .snapshot()?
            .into_iter()
            .find(|r| r.vm_id == vm_id)
            .map(|r| (r.confirmed, r.unconfirmed_releases))
            .unwrap_or((0, 0)))
    }

    /// The VM's confirm-token epoch (see [`stamp_token_epoch`]); `0`
    /// for a VM that was never rolled back.
    fn token_epoch(&self, _vm_id: &str) -> Result<u64> {
        Ok(0)
    }

    /// [`Self::confirm`], additionally refusing unless the VM's token
    /// epoch is still `epoch` — checked under the SAME lock as the CAS,
    /// so a token verified against one epoch can never land after a
    /// rollback moved the VM to the next.
    fn confirm_at_epoch(&self, vm_id: &str, value: u64, epoch: u64) -> Result<u64> {
        if epoch != 0 {
            return Err(KbsError::Policy(
                "volume-stamp: this store has no token epochs — fail closed".into(),
            ));
        }
        self.confirm(vm_id, value)
    }

    /// The VM's current volume-stamp TIMELINE ([`ZERO_TIMELINE`] when none
    /// was ever set — every VM never rolled back under v2). Pure read.
    fn timeline(&self, _vm_id: &str) -> Result<[u8; 32]> {
        Ok(ZERO_TIMELINE)
    }

    /// STAMP PROTOCOL v2, a release at `E == 0` (a fresh VM, or a row a
    /// KBS restart wiped): move `vm_id` to `new_timeline`, a timeline no
    /// release ever issued, so every volume stamped on ANY earlier
    /// timeline — the zero timeline every VM counts from after a wipe,
    /// and every disk a pre-wipe rollback abandoned — is refused once the
    /// VM confirms on the new one (the re-opened B1 hole of a KBS
    /// restart, see `crate::rollback`).
    ///
    /// Refuses — touching nothing — unless, under the SAME locks as the
    /// confirm CAS, the confirmed stamp is still `0` (a confirm that
    /// landed since the release read it would otherwise be re-bound to a
    /// timeline its volume was never moved to), no rollback is pending
    /// (its undo record owns the timeline), and `new_timeline` is neither
    /// zero nor the current one. `Ok` only once the move is DURABLE: the
    /// release replies after this, and a response whose timeline a crash
    /// could still undo would be a confirm that never lands — harmless at
    /// `E == 0`, but never built on. A store without timelines refuses.
    fn adopt_fresh_timeline(&self, _vm_id: &str, _new_timeline: &[u8; 32]) -> Result<()> {
        Err(KbsError::Policy(
            "volume-stamp: this store has no timelines — fail closed".into(),
        ))
    }

    /// The confirm CAS of stamp protocol v2: refuse unless the VM's token
    /// epoch is still `epoch`, its current timeline is `timeline`, and
    /// `value == confirmed + 1` — all under ONE lock. [`Self::confirm_at_epoch`]
    /// (the v1 confirm) is this with [`ZERO_TIMELINE`]: a v1 token can
    /// never confirm a VM that moved to another timeline.
    fn confirm_at(&self, vm_id: &str, value: u64, epoch: u64, timeline: &[u8; 32]) -> Result<u64> {
        if *timeline != ZERO_TIMELINE {
            return Err(KbsError::Policy(
                "volume-stamp: this store has no timelines — fail closed".into(),
            ));
        }
        self.confirm_at_epoch(vm_id, value, epoch)
    }

    /// Record the timeline of the checkpoint an authorized-rollback arm
    /// `restore_id` was built from (the `expected` timeline of the one
    /// release it admits). One entry per VM — one live arm per VM — and
    /// only the entry naming the arm's `restore_id` counts
    /// ([`Self::arm_timeline`]). A store without timelines refuses.
    fn record_arm_timeline(&self, _vm_id: &str, _restore_id: &str, _t: &[u8; 32]) -> Result<()> {
        Err(KbsError::Policy(
            "volume-stamp: this store cannot record an arm timeline — fail closed".into(),
        ))
    }

    /// The timeline [`Self::record_arm_timeline`] recorded for `restore_id`,
    /// `None` when none (the arm then admits nothing — fail closed).
    fn arm_timeline(&self, _vm_id: &str, _restore_id: &str) -> Result<Option<[u8; 32]>> {
        Ok(None)
    }

    /// `(confirmed, unconfirmed_releases, pending, timeline)` read in ONE
    /// critical section (the checkpoint signs them together).
    fn checkpoint_read(
        &self,
        vm_id: &str,
    ) -> Result<(u64, u64, Option<PendingRollback>, [u8; 32])> {
        let (e, u, p) = self.row_and_pending(vm_id)?;
        Ok((e, u, p, self.timeline(vm_id)?))
    }

    /// Authorized-rollback step (i): set `confirmed := confirmed`,
    /// `unconfirmed_releases := 0`, move the token epoch to `new_epoch`
    /// (which MUST exceed the current one — epochs never repeat, so a
    /// dead token never comes back to life), and record a durable
    /// [`PendingRollback`] holding the row as it was, keyed by
    /// `restore_id`. A retry of the same `restore_id` keeps the FIRST
    /// recorded row; a pending rollback of ANOTHER `restore_id` refuses.
    ///
    /// The pending record is the undo log: until the release that
    /// applied it calls [`Self::finalize_rollback`] (after every other
    /// gate passed), [`crate::rollback::reconcile_pending`] reverts the
    /// row whenever the arm that authorised it is gone — so a failure or
    /// a crash anywhere between here and the response can never leave a
    /// lowered stamp without a delivered, audited rollback.
    ///
    /// The VM's TIMELINE moves to `new_timeline` (never a timeline it held
    /// before: the caller draws it fresh), and the timeline it replaced is
    /// kept as the undo record's `prev` (the FIRST one, for a retry).
    ///
    /// Persist order: the sidecar (epoch + undo record) FIRST, then the
    /// timeline, then the row. A failure after the sidecar leaves old
    /// tokens dead, a pending record that reconciliation reverts, and the
    /// stamp unchanged. The reverse would briefly pair a lowered stamp
    /// with the old epoch (the window in which a captured abandoned-
    /// timeline token confirms) and with no undo record.
    fn apply_rollback(
        &self,
        _vm_id: &str,
        _confirmed: u64,
        _new_epoch: u64,
        _restore_id: &str,
        _new_timeline: &[u8; 32],
    ) -> Result<()> {
        Err(KbsError::Policy(
            "volume-stamp: this store cannot apply a rollback — fail closed".into(),
        ))
    }

    /// The undo record of a rollback applied but not yet finalized.
    fn pending_rollback(&self, _vm_id: &str) -> Result<Option<PendingRollback>> {
        Ok(None)
    }

    /// `(confirmed, unconfirmed_releases, pending)` read in ONE critical
    /// section (the checkpoint signs them together).
    fn row_and_pending(&self, vm_id: &str) -> Result<(u64, u64, Option<PendingRollback>)> {
        let (e, u) = self.row(vm_id)?;
        Ok((e, u, self.pending_rollback(vm_id)?))
    }

    /// Every VM with a pending rollback (startup reconciliation).
    fn pending_rollback_vms(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Drop the undo record of `restore_id`: the rollback is delivered.
    /// Records [`RollbackResolution::Delivered`] for it in the SAME write
    /// (see [`Self::rollback_resolution`]). `Ok(None)` when there was
    /// none for that id (nothing written).
    fn finalize_rollback(
        &self,
        _vm_id: &str,
        _restore_id: &str,
    ) -> Result<Option<PendingRollback>> {
        Ok(None)
    }

    /// Undo the rollback `restore_id`: the row goes back to the recorded
    /// `(prev_confirmed, prev_unconfirmed_releases)` — written FIRST, so
    /// a crash before the record is dropped only repeats an idempotent
    /// revert — then the timeline goes back to the one it replaced, and
    /// the record is dropped. The token epoch is NOT moved back: tokens
    /// minted for the rolled-back row stay dead; the abandoned target
    /// timeline is never issued again. The record is replaced by
    /// [`RollbackResolution::Reverted`] in the same write.
    fn revert_rollback(&self, _vm_id: &str, _restore_id: &str) -> Result<Option<PendingRollback>> {
        Ok(None)
    }

    /// How the VM's last applied rollback ended: finalized (its key went
    /// out) or reverted. Written atomically with the undo record's
    /// removal, so it can never claim a delivery the store did not
    /// finalize. `None` while one is pending, or when none ever ended.
    fn rollback_resolution(&self, _vm_id: &str) -> Result<Option<ResolvedRollback>> {
        Ok(None)
    }

    /// The guest volume-stamp protocol last RECORDED for `vm_id` from an
    /// attested release ([`GUEST_STAMP_PROTOCOL_V1`] when nothing was
    /// ever recorded — every VM today). Pure read.
    fn guest_stamp_protocol(&self, _vm_id: &str) -> Result<u8> {
        Ok(GUEST_STAMP_PROTOCOL_V1)
    }

    /// Record the guest stamp protocol an ATTESTED release reported for
    /// `vm_id` (`crate::release`'s `attested_guest_stamp_protocol`). The
    /// latest release wins in both directions: a guest re-launched on an
    /// older image that speaks v1 again moves the record back down, so a
    /// rollback is never armed on the strength of a guest that is gone.
    /// Writes nothing when the value is unchanged (the release hot path
    /// records on every release). `0` is not a protocol — refused.
    ///
    /// A store without the sibling file can only hold the default: it
    /// accepts [`GUEST_STAMP_PROTOCOL_V1`] (nothing to write) and refuses
    /// anything else, fail closed.
    fn record_guest_stamp_protocol(&self, vm_id: &str, protocol: u8) -> Result<()> {
        validate_guest_stamp_protocol(vm_id, protocol)?;
        if protocol == GUEST_STAMP_PROTOCOL_V1 {
            return Ok(());
        }
        Err(KbsError::Policy(format!(
            "volume-stamp: this store cannot record guest stamp protocol {protocol} for \
             vm_id={vm_id} — fail closed"
        )))
    }
}

fn validate_guest_stamp_protocol(vm_id: &str, protocol: u8) -> Result<()> {
    if protocol == 0 {
        return Err(KbsError::Policy(format!(
            "volume-stamp: guest stamp protocol 0 for vm_id={vm_id} is not a protocol"
        )));
    }
    Ok(())
}

/// Apply a record to the protocol map: an entry only for a non-default
/// protocol (absent ⇒ [`GUEST_STAMP_PROTOCOL_V1`]). `true` when it changed.
fn set_guest_stamp_protocol(map: &mut BTreeMap<String, u8>, vm_id: &str, protocol: u8) -> bool {
    let current = map.get(vm_id).copied().unwrap_or(GUEST_STAMP_PROTOCOL_V1);
    if current == protocol {
        return false;
    }
    if protocol == GUEST_STAMP_PROTOCOL_V1 {
        map.remove(vm_id);
    } else {
        map.insert(vm_id.to_string(), protocol);
    }
    true
}

/// How an applied rollback left the pending state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RollbackResolution {
    /// [`VolumeStampStore::finalize_rollback`]: every release gate passed.
    Delivered,
    /// [`VolumeStampStore::revert_rollback`]: the stamp was put back.
    Reverted,
}

/// The last resolved rollback of a VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRollback {
    pub restore_id: String,
    pub resolution: RollbackResolution,
}

/// Undo record of an applied-but-not-finalized authorized rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRollback {
    pub restore_id: String,
    pub prev_confirmed: u64,
    pub prev_unconfirmed_releases: u64,
    pub applied_epoch: u64,
}

/// The stamp store's SIBLING state (never in the row file — see
/// [`FileVolumeStampStore`]): per-VM token epochs and pending-rollback
/// undo records.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StampSidecar {
    #[serde(default)]
    epochs: HashMap<String, u64>,
    #[serde(default)]
    pending: HashMap<String, PendingRollback>,
    /// Per VM, how its last pending rollback ended.
    #[serde(default)]
    resolved: HashMap<String, ResolvedRollback>,
}

/// Move `vm_id`'s pending record of `restore_id` to `resolved`.
fn resolve(side: &mut StampSidecar, vm_id: &str, restore_id: &str, how: RollbackResolution) {
    side.pending.remove(vm_id);
    side.resolved.insert(
        vm_id.to_string(),
        ResolvedRollback {
            restore_id: restore_id.to_string(),
            resolution: how,
        },
    );
}

/// Pure planning step of [`VolumeStampStore::apply_rollback`], shared by
/// both impls: the new sidecar and row, or a refusal. Touches nothing.
fn plan_apply(
    rows: &HashMap<String, StampRow>,
    side: &StampSidecar,
    vm_id: &str,
    confirmed: u64,
    new_epoch: u64,
    restore_id: &str,
) -> Result<(StampSidecar, StampRow)> {
    let current = side.epochs.get(vm_id).copied().unwrap_or(0);
    if new_epoch <= current {
        return Err(stale_epoch(vm_id, new_epoch, current));
    }
    let mut next = side.clone();
    let record = match side.pending.get(vm_id) {
        Some(p) if p.restore_id == restore_id => PendingRollback {
            applied_epoch: new_epoch,
            ..p.clone()
        },
        Some(p) => {
            return Err(KbsError::Policy(format!(
                "volume-stamp: vm_id={vm_id} already has a pending rollback ({}) — refusing \
                 {restore_id}, fail closed",
                p.restore_id
            )))
        }
        None => {
            let row = rows.get(vm_id).copied().unwrap_or_default();
            PendingRollback {
                restore_id: restore_id.to_string(),
                prev_confirmed: row.confirmed,
                prev_unconfirmed_releases: row.unconfirmed_releases,
                applied_epoch: new_epoch,
            }
        }
    };
    next.epochs.insert(vm_id.to_string(), new_epoch);
    next.pending.insert(vm_id.to_string(), record);
    Ok((
        next,
        StampRow {
            confirmed,
            unconfirmed_releases: 0,
        },
    ))
}

/// The stamp store's THIRD sibling (`<stem>-timelines.json`): stamp
/// protocol v2 timelines. Never in the row file or the token-epochs file,
/// whose shapes an older binary decodes strictly (`deny_unknown_fields`):
/// an older binary ignores this file, which only matters for a VM that was
/// rolled back under v2 (see [`FileVolumeStampStore`]).
///
/// Ids are lowercase hex (64 chars). A VM absent from `current` is on
/// [`ZERO_TIMELINE`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimelineSidecar {
    /// Per VM, its current timeline (only non-zero ones are stored).
    #[serde(default)]
    current: BTreeMap<String, String>,
    /// Per VM, the timeline an applied rollback replaced (its undo).
    /// Meaningful only while the token-epochs sidecar holds a pending
    /// record with the same `restore_id`; a stale one is replaced by the
    /// next rollback.
    #[serde(default)]
    undo: BTreeMap<String, TimelineUndo>,
    /// Per VM, the checkpoint timeline of its (one) live arm.
    #[serde(default)]
    arms: BTreeMap<String, ArmTimeline>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimelineUndo {
    restore_id: String,
    prev: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArmTimeline {
    restore_id: String,
    timeline: String,
}

fn parse_timeline(hex_id: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_id)
        .map_err(|e| KbsError::Vault(format!("volume-stamp timeline decode: {e}")))?;
    if hex_id.len() != 64 || hex::encode(&bytes) != hex_id {
        return Err(KbsError::Vault(
            "volume-stamp timeline decode: not 64 lowercase hex chars".into(),
        ));
    }
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| KbsError::Vault("volume-stamp timeline decode: not 32 bytes".into()))
}

impl TimelineSidecar {
    /// Every id well-formed; `current` never stores the zero timeline.
    fn validate(&self) -> Result<()> {
        for (vm, t) in &self.current {
            if parse_timeline(t)? == ZERO_TIMELINE {
                return Err(KbsError::Vault(format!(
                    "volume-stamp timelines: vm_id={vm} stores the zero timeline"
                )));
            }
        }
        for u in self.undo.values() {
            parse_timeline(&u.prev)?;
        }
        for a in self.arms.values() {
            parse_timeline(&a.timeline)?;
        }
        Ok(())
    }

    fn current(&self, vm_id: &str) -> Result<[u8; 32]> {
        match self.current.get(vm_id) {
            Some(t) => parse_timeline(t),
            None => Ok(ZERO_TIMELINE),
        }
    }

    fn set_current(&mut self, vm_id: &str, t: &[u8; 32]) {
        if *t == ZERO_TIMELINE {
            self.current.remove(vm_id);
        } else {
            self.current.insert(vm_id.to_string(), hex::encode(t));
        }
    }

    fn arm(&self, vm_id: &str, restore_id: &str) -> Result<Option<[u8; 32]>> {
        match self.arms.get(vm_id) {
            Some(a) if a.restore_id == restore_id => parse_timeline(&a.timeline).map(Some),
            _ => Ok(None),
        }
    }
}

/// Pure planning step of the TIMELINE half of
/// [`VolumeStampStore::apply_rollback`]: move `vm_id` to `new_timeline`
/// and record the timeline it replaced — keeping the FIRST one recorded
/// when this is a retry of the same pending `restore_id` (the current
/// timeline is then the retry's own earlier target, not the VM's).
fn plan_timeline_apply(
    side: &StampSidecar,
    tl: &TimelineSidecar,
    vm_id: &str,
    restore_id: &str,
    new_timeline: &[u8; 32],
) -> Result<TimelineSidecar> {
    let current = tl.current(vm_id)?;
    if *new_timeline == ZERO_TIMELINE || *new_timeline == current {
        return Err(KbsError::Policy(format!(
            "volume-stamp: vm_id={vm_id} a rollback must move to a NEW timeline — fail closed"
        )));
    }
    let retry = side
        .pending
        .get(vm_id)
        .is_some_and(|p| p.restore_id == restore_id);
    let prev = match tl.undo.get(vm_id) {
        Some(u) if retry && u.restore_id == restore_id => u.prev.clone(),
        _ => hex::encode(current),
    };
    let mut next = tl.clone();
    next.undo.insert(
        vm_id.to_string(),
        TimelineUndo {
            restore_id: restore_id.to_string(),
            prev,
        },
    );
    next.set_current(vm_id, new_timeline);
    Ok(next)
}

/// Pure planning step of [`VolumeStampStore::adopt_fresh_timeline`],
/// shared by both impls: the new timelines sidecar, or a refusal.
fn plan_fresh_timeline(
    row: StampRow,
    side: &StampSidecar,
    tl: &TimelineSidecar,
    vm_id: &str,
    new_timeline: &[u8; 32],
) -> Result<TimelineSidecar> {
    if row.confirmed != 0 {
        return Err(KbsError::Policy(format!(
            "volume-stamp: vm_id={vm_id} confirmed stamp is {} — only an unconfirmed (E = 0) VM \
             moves to a fresh timeline; fail closed",
            row.confirmed
        )));
    }
    if side.pending.contains_key(vm_id) {
        return Err(KbsError::Policy(format!(
            "volume-stamp: vm_id={vm_id} has a pending rollback — its timeline is not ours to \
             move; fail closed"
        )));
    }
    if *new_timeline == ZERO_TIMELINE || *new_timeline == tl.current(vm_id)? {
        return Err(KbsError::Policy(format!(
            "volume-stamp: vm_id={vm_id} a fresh timeline must be NEW and non-zero — fail closed"
        )));
    }
    let mut next = tl.clone();
    next.set_current(vm_id, new_timeline);
    Ok(next)
}

/// Pure planning step of the TIMELINE half of
/// [`VolumeStampStore::revert_rollback`]: back to the recorded timeline.
/// `None` when there is nothing to revert for `restore_id` (the timeline
/// step never ran).
fn plan_timeline_revert(
    tl: &TimelineSidecar,
    vm_id: &str,
    restore_id: &str,
) -> Result<Option<TimelineSidecar>> {
    let Some(u) = tl.undo.get(vm_id).filter(|u| u.restore_id == restore_id) else {
        return Ok(None);
    };
    let prev = parse_timeline(&u.prev)?;
    let mut next = tl.clone();
    next.undo.remove(vm_id);
    next.set_current(vm_id, &prev);
    Ok(Some(next))
}

/// File-backed store: a JSON map `{vm_id: StampRow}` written atomically
/// (tmp + fsync + rename) under a `Mutex`. Same atomicity contract and
/// the same rollback-on-persist-failure discipline as
/// [`crate::boot_counter::FileBootCounterStore`].
///
/// The per-VM confirm-token EPOCHS (see [`stamp_token_epoch`]) live in a
/// SIBLING file, `<stem>-token-epochs.json` (`{epochs, pending}`), never in
/// the row: the row file's shape is what an older KBS binary decodes
/// strictly, and widening it would make a binary rollback fail to open
/// the store. An older binary ignores the sibling and mints epoch-0
/// tokens, which only makes confirms of rolled-back VMs fail (non-fatal
/// in the guest) — fail closed.
///
/// Lock order: `cache` BEFORE `epochs`, everywhere both are held.
///
/// The per-VM guest stamp protocol
/// ([`VolumeStampStore::guest_stamp_protocol`]) lives in a SECOND
/// sibling, `<stem>-guest-stamp-protocol.json` (`{vm_id: protocol}`, only
/// the VMs whose protocol is not [`GUEST_STAMP_PROTOCOL_V1`]), for the
/// same reason: neither the row file nor the token-epochs file changes
/// shape, and an older binary that ignores it reads every VM as v1 —
/// which only makes `authorize-rollback` refuse (fail closed). Its lock
/// is never held together with the other two.
///
/// The stamp-protocol-v2 TIMELINES live in a THIRD sibling,
/// `<stem>-timelines.json` ([`TimelineSidecar`]), for the same reason.
/// Lock order: `cache`, then `epochs`, then `timelines`. An older binary
/// ignores it and would release a VM rolled back under v2 as if it were
/// on the zero timeline (the stamp value alone) — the B1 hole this file
/// closes reopens for such a VM until the binary is rolled forward, so a
/// KBS binary rollback must not follow an authorized rollback.
pub struct FileVolumeStampStore {
    path: PathBuf,
    epochs_path: PathBuf,
    protocols_path: PathBuf,
    timelines_path: PathBuf,
    cache: Mutex<HashMap<String, StampRow>>,
    epochs: Mutex<StampSidecar>,
    protocols: Mutex<ProtocolRecords>,
    timelines: Mutex<TimelineSidecar>,
    /// Set (under the `timelines` lock) when a timelines rename landed but
    /// its directory fsync failed, and at open (what was loaded may be such
    /// a rename). Every later timeline mutation — and the finalize/revert
    /// that would drop a pending record — first retries the fsync and fails
    /// until it succeeds, so nothing is built on a rename a crash could
    /// still undo.
    timelines_unsynced: std::sync::atomic::AtomicBool,
}

/// The protocol sibling's cache, and whether its last rename is still
/// waiting for a successful directory fsync.
struct ProtocolRecords {
    map: BTreeMap<String, u8>,
    /// Set when a rename landed but its directory fsync failed. Every
    /// later record call — including one that changes nothing — retries
    /// the fsync first and fails until it succeeds, so a retried release
    /// can never be admitted on a record a crash could still undo.
    unsynced: bool,
}

impl FileVolumeStampStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let cache = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<HashMap<String, StampRow>>(&bytes)
                .map_err(|e| KbsError::Vault(format!("volume-stamp decode: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(KbsError::Vault(format!("volume-stamp read: {e}"))),
        };
        let epochs_path = Self::epochs_path_for(&path);
        let epochs = match fs::read(&epochs_path) {
            Ok(bytes) => serde_json::from_slice::<StampSidecar>(&bytes)
                .map_err(|e| KbsError::Vault(format!("volume-stamp epochs decode: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StampSidecar::default(),
            Err(e) => return Err(KbsError::Vault(format!("volume-stamp epochs read: {e}"))),
        };
        let protocols_path = Self::sibling_path_for(&path, "guest-stamp-protocol");
        let protocols = match fs::read(&protocols_path) {
            Ok(bytes) => serde_json::from_slice::<BTreeMap<String, u8>>(&bytes)
                .map_err(|e| KbsError::Vault(format!("volume-stamp guest protocol decode: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => {
                return Err(KbsError::Vault(format!(
                    "volume-stamp guest protocol read: {e}"
                )))
            }
        };
        if let Some((vm, p)) = protocols.iter().find(|(_, p)| **p == 0) {
            return Err(KbsError::Vault(format!(
                "volume-stamp guest protocol: vm_id={vm} holds {p}, not a protocol"
            )));
        }
        // Absent ⇒ every VM on the zero timeline; corrupt ⇒ refuse to open.
        let timelines_path = Self::sibling_path_for(&path, "timelines");
        let timelines = match fs::read(&timelines_path) {
            Ok(bytes) => serde_json::from_slice::<TimelineSidecar>(&bytes)
                .map_err(|e| KbsError::Vault(format!("volume-stamp timelines decode: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => TimelineSidecar::default(),
            Err(e) => return Err(KbsError::Vault(format!("volume-stamp timelines read: {e}"))),
        };
        timelines.validate()?;
        Ok(Self {
            path,
            epochs_path,
            protocols_path,
            timelines_path,
            cache: Mutex::new(cache),
            epochs: Mutex::new(epochs),
            timelines: Mutex::new(timelines),
            timelines_unsynced: std::sync::atomic::AtomicBool::new(true),
            // Whatever was loaded may be a rename a previous process
            // could not make durable: the first record call of this
            // process syncs the directory before it trusts the cache.
            protocols: Mutex::new(ProtocolRecords {
                map: protocols,
                unsynced: true,
            }),
        })
    }

    /// `volume-stamps.json` ⇒ `volume-stamps-<suffix>.json`.
    fn sibling_path_for(path: &std::path::Path, suffix: &str) -> PathBuf {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("volume-stamp");
        let sibling = format!("{stem}-{suffix}.json");
        match path.parent() {
            Some(dir) => dir.join(sibling),
            None => PathBuf::from(sibling),
        }
    }

    /// `volume-stamps.json` ⇒ `volume-stamps-token-epochs.json`.
    fn epochs_path_for(path: &std::path::Path) -> PathBuf {
        Self::sibling_path_for(path, "token-epochs")
    }

    /// Write the timelines sibling and make the rename DURABLE: a lost
    /// timeline rename fails OPEN (a missing file reads as the zero
    /// timeline), so unlike the row and epochs files a failed directory
    /// fsync is an error here. `Err(Unrenamed)` ⇒ the file is unchanged;
    /// `Err(Unsynced)` ⇒ it holds `tl` but may not survive a crash — the
    /// caller makes memory follow the file and refuses its operation.
    fn persist_timelines_locked(&self, tl: &TimelineSidecar) -> TimelineWrite {
        const WHAT: &str = "volume-stamp timelines";
        let bytes = match serde_json::to_vec(tl) {
            Ok(b) => b,
            Err(e) => {
                return TimelineWrite::Unrenamed(KbsError::Vault(format!("{WHAT} encode: {e}")))
            }
        };
        if let Err(e) = atomic_write(&self.timelines_path, &bytes, WHAT) {
            return TimelineWrite::Unrenamed(e);
        }
        match sync_parent_dir(&self.timelines_path, WHAT) {
            Ok(()) => TimelineWrite::Durable,
            Err(e) => TimelineWrite::Unsynced(e),
        }
    }

    /// Persist `next` and make `*tl` follow what the FILE now holds. An
    /// unsynced rename is remembered ([`Self::ensure_timelines_synced`]).
    /// Caller holds the `timelines` lock.
    fn commit_timelines_locked(
        &self,
        tl: &mut TimelineSidecar,
        next: TimelineSidecar,
    ) -> Result<()> {
        self.ensure_timelines_synced()?;
        match self.persist_timelines_locked(&next) {
            TimelineWrite::Durable => {
                *tl = next;
                Ok(())
            }
            TimelineWrite::Unsynced(e) => {
                *tl = next;
                self.timelines_unsynced
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                Err(e)
            }
            TimelineWrite::Unrenamed(e) => Err(e),
        }
    }

    /// Make an earlier unsynced timelines rename durable, or fail. Caller
    /// holds the `timelines` lock.
    fn ensure_timelines_synced(&self) -> Result<()> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.timelines_unsynced.load(SeqCst) {
            sync_parent_dir(&self.timelines_path, "volume-stamp timelines")?;
            self.timelines_unsynced.store(false, SeqCst);
        }
        Ok(())
    }

    fn persist_epochs_locked(&self, epochs: &StampSidecar) -> Result<()> {
        let bytes = serde_json::to_vec(epochs)
            .map_err(|e| KbsError::Vault(format!("volume-stamp epochs encode: {e}")))?;
        atomic_write(&self.epochs_path, &bytes, "volume-stamp epochs")
    }

    /// Write `vm_id -> row` through to disk, keeping the in-memory
    /// cache and the file IN SYNC even when the write fails.
    ///
    /// The naive `cache.insert(..); persist(..)?` leaves the cache
    /// advanced and the file behind on any persist error — and for THIS
    /// store that split-brain is a tenant lockout: the cache would expect
    /// `stored + 1` from a guest whose next boot re-reads the older
    /// on-disk value and re-confirms the same number, which the CAS then
    /// refuses as a rewind. So on failure, restore the previous mapping
    /// before propagating.
    ///
    /// Invariant: when this returns `Err`, the in-memory value and the
    /// on-disk value are both exactly what they were before the call —
    /// BOTH fields of the row, since `confirmed` and
    /// `unconfirmed_releases` move together.
    fn insert_and_persist_locked(
        &self,
        cache: &mut HashMap<String, StampRow>,
        vm_id: &str,
        row: StampRow,
    ) -> Result<()> {
        let previous = cache.insert(vm_id.to_string(), row);
        if let Err(e) = self.persist_locked(cache) {
            match previous {
                Some(p) => cache.insert(vm_id.to_string(), p),
                None => cache.remove(vm_id),
            };
            return Err(e);
        }
        Ok(())
    }

    fn persist_locked(&self, cache: &HashMap<String, StampRow>) -> Result<()> {
        let bytes = serde_json::to_vec(cache)
            .map_err(|e| KbsError::Vault(format!("volume-stamp encode: {e}")))?;
        atomic_write(&self.path, &bytes, "volume-stamp")
    }
}

/// Outcome of a timelines write ([`FileVolumeStampStore::persist_timelines_locked`]).
enum TimelineWrite {
    Durable,
    Unsynced(KbsError),
    Unrenamed(KbsError),
}

/// fsync `path`'s directory, failing loudly (unlike [`atomic_write`]'s
/// best-effort sync) — for a record whose loss after a crash would widen
/// what the KBS admits.
fn sync_parent_dir(path: &std::path::Path, what: &str) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .open(dir_of(path))
        .and_then(|d| d.sync_all())
        .map_err(|e| KbsError::Vault(format!("{what} fsync dir: {e}")))
}

/// The directory holding `path`: `.` for a bare file name (whose
/// `parent()` is the EMPTY path, which cannot be opened).
fn dir_of(path: &std::path::Path) -> &std::path::Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    }
}

/// tmp + fsync + rename, so a crash between the write and the rename
/// leaves the live file byte-identical to what it was.
fn atomic_write(path: &std::path::Path, bytes: &[u8], what: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| KbsError::Vault(format!("{what}: no parent dir")))?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("volume-stamp"),
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
    if let Ok(parent) = OpenOptions::new().read(true).open(parent) {
        let _ = parent.sync_all();
    }
    Ok(())
}

impl VolumeStampStore for FileVolumeStampStore {
    fn get(&self, vm_id: &str) -> Result<u64> {
        let cache = self
            .cache
            .lock()
            .map_err(|_| KbsError::Policy("volume-stamp lock poisoned".into()))?;
        Ok(cache.get(vm_id).copied().unwrap_or_default().confirmed)
    }

    fn note_release(&self, vm_id: &str) -> Result<(u64, u64)> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| KbsError::Policy("volume-stamp lock poisoned".into()))?;
        let mut row = cache.get(vm_id).copied().unwrap_or_default();
        row.unconfirmed_releases = row.unconfirmed_releases.checked_add(1).ok_or_else(|| {
            KbsError::Policy("volume-stamp: unconfirmed-releases overflow".into())
        })?;
        self.insert_and_persist_locked(&mut cache, vm_id, row)?;
        Ok((row.confirmed, row.unconfirmed_releases))
    }

    fn confirm(&self, vm_id: &str, value: u64) -> Result<u64> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| KbsError::Policy("volume-stamp lock poisoned".into()))?;
        let row = cache.get(vm_id).copied().unwrap_or_default();
        let expected = row
            .confirmed
            .checked_add(1)
            .ok_or_else(|| KbsError::Policy("volume-stamp overflow".into()))?;
        // Holding the lock across the check AND the write is what makes
        // this a CAS rather than a TOCTOU.
        if value != expected {
            return Err(KbsError::Policy(format!(
                "volume-stamp confirm: vm_id={vm_id} value={value} expected={expected} \
                 (stored={}) — rewind or skip, fail closed",
                row.confirmed
            )));
        }
        let new_row = StampRow {
            confirmed: value,
            // The reset — a real confirm is the ONLY thing that clears
            // this counter besides an admin action.
            unconfirmed_releases: 0,
        };
        self.insert_and_persist_locked(&mut cache, vm_id, new_row)?;
        Ok(value)
    }

    fn admin_reset_unconfirmed(&self, vm_id: &str) -> Result<u64> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| KbsError::Policy("volume-stamp lock poisoned".into()))?;
        let mut row = cache.get(vm_id).copied().unwrap_or_default();
        let previous = row.unconfirmed_releases;
        if previous == 0 {
            // Nothing to clear — a harmless no-op, not an error.
            return Ok(0);
        }
        row.unconfirmed_releases = 0;
        self.insert_and_persist_locked(&mut cache, vm_id, row)?;
        Ok(previous)
    }

    /// Read-only: takes the lock, copies, sorts, releases. Never calls
    /// `insert_and_persist_locked`, so it can neither write the file nor
    /// create it — a `snapshot()` against a store whose file does not
    /// exist yet returns an empty vec and leaves the path absent.
    fn snapshot(&self) -> Result<Vec<VolumeStampStatus>> {
        let cache = self
            .cache
            .lock()
            .map_err(|_| KbsError::Policy("volume-stamp lock poisoned".into()))?;
        Ok(rows_from(&cache))
    }

    fn row(&self, vm_id: &str) -> Result<(u64, u64)> {
        let cache = self.cache.lock().map_err(|_| poisoned())?;
        let r = cache.get(vm_id).copied().unwrap_or_default();
        Ok((r.confirmed, r.unconfirmed_releases))
    }

    fn token_epoch(&self, vm_id: &str) -> Result<u64> {
        let side = self.epochs.lock().map_err(|_| poisoned())?;
        Ok(side.epochs.get(vm_id).copied().unwrap_or(0))
    }

    fn confirm_at_epoch(&self, vm_id: &str, value: u64, epoch: u64) -> Result<u64> {
        self.confirm_at(vm_id, value, epoch, &ZERO_TIMELINE)
    }

    fn timeline(&self, vm_id: &str) -> Result<[u8; 32]> {
        self.timelines
            .lock()
            .map_err(|_| poisoned())?
            .current(vm_id)
    }

    fn confirm_at(&self, vm_id: &str, value: u64, epoch: u64, timeline: &[u8; 32]) -> Result<u64> {
        // Lock order: cache, epochs, timelines. All held across the epoch
        // and timeline checks AND the CAS write.
        let mut cache = self.cache.lock().map_err(|_| poisoned())?;
        let side = self.epochs.lock().map_err(|_| poisoned())?;
        let tl = self.timelines.lock().map_err(|_| poisoned())?;
        let current = side.epochs.get(vm_id).copied().unwrap_or(0);
        if current != epoch {
            return Err(stale_epoch(vm_id, epoch, current));
        }
        check_timeline(vm_id, &tl.current(vm_id)?, timeline)?;
        let row = cache.get(vm_id).copied().unwrap_or_default();
        let new_row = confirm_cas(vm_id, row, value)?;
        self.insert_and_persist_locked(&mut cache, vm_id, new_row)?;
        Ok(value)
    }

    fn adopt_fresh_timeline(&self, vm_id: &str, new_timeline: &[u8; 32]) -> Result<()> {
        // Lock order: cache, epochs, timelines — the confirm CAS's, so a
        // confirm can never land between the `E == 0` check and the move.
        let cache = self.cache.lock().map_err(|_| poisoned())?;
        let side = self.epochs.lock().map_err(|_| poisoned())?;
        let mut tl = self.timelines.lock().map_err(|_| poisoned())?;
        let row = cache.get(vm_id).copied().unwrap_or_default();
        let next = plan_fresh_timeline(row, &side, &tl, vm_id, new_timeline)?;
        // Durable (renamed AND directory-fsynced) before `Ok`.
        self.commit_timelines_locked(&mut tl, next)
    }

    fn record_arm_timeline(&self, vm_id: &str, restore_id: &str, t: &[u8; 32]) -> Result<()> {
        let mut tl = self.timelines.lock().map_err(|_| poisoned())?;
        // A retry of an entry whose rename was never made durable must not
        // succeed on the cache alone.
        self.ensure_timelines_synced()?;
        let entry = ArmTimeline {
            restore_id: restore_id.to_string(),
            timeline: hex::encode(t),
        };
        if tl.arms.get(vm_id) == Some(&entry) {
            return Ok(());
        }
        let mut next = tl.clone();
        next.arms.insert(vm_id.to_string(), entry);
        self.commit_timelines_locked(&mut tl, next)
    }

    fn arm_timeline(&self, vm_id: &str, restore_id: &str) -> Result<Option<[u8; 32]>> {
        self.timelines
            .lock()
            .map_err(|_| poisoned())?
            .arm(vm_id, restore_id)
    }

    fn checkpoint_read(
        &self,
        vm_id: &str,
    ) -> Result<(u64, u64, Option<PendingRollback>, [u8; 32])> {
        let cache = self.cache.lock().map_err(|_| poisoned())?;
        let side = self.epochs.lock().map_err(|_| poisoned())?;
        let tl = self.timelines.lock().map_err(|_| poisoned())?;
        let r = cache.get(vm_id).copied().unwrap_or_default();
        Ok((
            r.confirmed,
            r.unconfirmed_releases,
            side.pending.get(vm_id).cloned(),
            tl.current(vm_id)?,
        ))
    }

    fn apply_rollback(
        &self,
        vm_id: &str,
        confirmed: u64,
        new_epoch: u64,
        restore_id: &str,
        new_timeline: &[u8; 32],
    ) -> Result<()> {
        let mut cache = self.cache.lock().map_err(|_| poisoned())?;
        let mut side = self.epochs.lock().map_err(|_| poisoned())?;
        let mut tl = self.timelines.lock().map_err(|_| poisoned())?;
        let (next, row) = plan_apply(&cache, &side, vm_id, confirmed, new_epoch, restore_id)?;
        let next_tl = plan_timeline_apply(&side, &tl, vm_id, restore_id, new_timeline)?;
        // Sidecar FIRST, then the timeline, then the row (see the trait
        // doc); memory follows each file.
        self.persist_epochs_locked(&next)?;
        *side = next;
        self.commit_timelines_locked(&mut tl, next_tl)?;
        self.insert_and_persist_locked(&mut cache, vm_id, row)
    }

    fn pending_rollback(&self, vm_id: &str) -> Result<Option<PendingRollback>> {
        let side = self.epochs.lock().map_err(|_| poisoned())?;
        Ok(side.pending.get(vm_id).cloned())
    }

    fn row_and_pending(&self, vm_id: &str) -> Result<(u64, u64, Option<PendingRollback>)> {
        let cache = self.cache.lock().map_err(|_| poisoned())?;
        let side = self.epochs.lock().map_err(|_| poisoned())?;
        let r = cache.get(vm_id).copied().unwrap_or_default();
        Ok((
            r.confirmed,
            r.unconfirmed_releases,
            side.pending.get(vm_id).cloned(),
        ))
    }

    fn pending_rollback_vms(&self) -> Result<Vec<String>> {
        let side = self.epochs.lock().map_err(|_| poisoned())?;
        let mut v: Vec<String> = side.pending.keys().cloned().collect();
        v.sort();
        Ok(v)
    }

    fn finalize_rollback(&self, vm_id: &str, restore_id: &str) -> Result<Option<PendingRollback>> {
        let _cache = self.cache.lock().map_err(|_| poisoned())?;
        let mut side = self.epochs.lock().map_err(|_| poisoned())?;
        match side.pending.get(vm_id) {
            Some(p) if p.restore_id == restore_id => {}
            _ => return Ok(None),
        }
        // Never drop the undo record over a timeline a crash could undo.
        {
            let _tl = self.timelines.lock().map_err(|_| poisoned())?;
            self.ensure_timelines_synced()?;
        }
        let dropped = side.pending.get(vm_id).cloned();
        let mut next = side.clone();
        resolve(&mut next, vm_id, restore_id, RollbackResolution::Delivered);
        self.persist_epochs_locked(&next)?;
        *side = next;
        Ok(dropped)
    }

    fn revert_rollback(&self, vm_id: &str, restore_id: &str) -> Result<Option<PendingRollback>> {
        let mut cache = self.cache.lock().map_err(|_| poisoned())?;
        let mut side = self.epochs.lock().map_err(|_| poisoned())?;
        let record = match side.pending.get(vm_id) {
            Some(p) if p.restore_id == restore_id => p.clone(),
            _ => return Ok(None),
        };
        // Row FIRST, then the timeline: a crash before the record is
        // dropped repeats this (idempotent) revert on the next
        // reconciliation.
        self.insert_and_persist_locked(
            &mut cache,
            vm_id,
            StampRow {
                confirmed: record.prev_confirmed,
                unconfirmed_releases: record.prev_unconfirmed_releases,
            },
        )?;
        let mut tl = self.timelines.lock().map_err(|_| poisoned())?;
        // A retry after an unsynced timeline revert finds no undo left:
        // the pending record is only dropped once that rename is durable.
        self.ensure_timelines_synced()?;
        if let Some(next_tl) = plan_timeline_revert(&tl, vm_id, restore_id)? {
            self.commit_timelines_locked(&mut tl, next_tl)?;
        }
        let mut next = side.clone();
        resolve(&mut next, vm_id, restore_id, RollbackResolution::Reverted);
        self.persist_epochs_locked(&next)?;
        *side = next;
        Ok(Some(record))
    }

    fn rollback_resolution(&self, vm_id: &str) -> Result<Option<ResolvedRollback>> {
        let side = self.epochs.lock().map_err(|_| poisoned())?;
        Ok(side.resolved.get(vm_id).cloned())
    }

    fn guest_stamp_protocol(&self, vm_id: &str) -> Result<u8> {
        let rec = self.protocols.lock().map_err(|_| poisoned())?;
        Ok(rec
            .map
            .get(vm_id)
            .copied()
            .unwrap_or(GUEST_STAMP_PROTOCOL_V1))
    }

    fn record_guest_stamp_protocol(&self, vm_id: &str, protocol: u8) -> Result<()> {
        const WHAT: &str = "volume-stamp guest protocol";
        validate_guest_stamp_protocol(vm_id, protocol)?;
        let mut rec = self.protocols.lock().map_err(|_| poisoned())?;
        // An earlier rename not yet durable: make it so before anything
        // is admitted on the strength of the cache.
        if rec.unsynced {
            sync_parent_dir(&self.protocols_path, WHAT)?;
            rec.unsynced = false;
        }
        let mut next = rec.map.clone();
        if !set_guest_stamp_protocol(&mut next, vm_id, protocol) {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&next)
            .map_err(|e| KbsError::Vault(format!("{WHAT} encode: {e}")))?;
        // A failure BEFORE the rename leaves file and cache as they were.
        atomic_write(&self.protocols_path, &bytes, WHAT)?;
        // Renamed: the file now says `next`, so the cache follows it —
        // then the rename must be made DURABLE, or the caller is refused
        // (now and on every retry until it is): a crash could otherwise
        // bring back a v2 record the latest (v1) release replaced.
        rec.map = next;
        rec.unsynced = true;
        sync_parent_dir(&self.protocols_path, WHAT)?;
        rec.unsynced = false;
        Ok(())
    }
}

fn poisoned() -> KbsError {
    KbsError::Policy("volume-stamp lock poisoned".into())
}

/// The confirm's timeline must be the VM's current one.
fn check_timeline(vm_id: &str, current: &[u8; 32], presented: &[u8; 32]) -> Result<()> {
    if current != presented {
        return Err(KbsError::Policy(format!(
            "volume-stamp: vm_id={vm_id} confirm names timeline {} but the VM is on {} — a \
             token of another timeline never confirms; fail closed (the expectation is \
             UNCHANGED)",
            hex::encode(presented),
            hex::encode(current)
        )));
    }
    Ok(())
}

fn stale_epoch(vm_id: &str, epoch: u64, current: u64) -> KbsError {
    KbsError::Policy(format!(
        "volume-stamp: vm_id={vm_id} token epoch {epoch} is not current ({current}) — a rollback \
         moved this VM to a new timeline; fail closed (the expectation is UNCHANGED)"
    ))
}

/// The confirm CAS on one row, shared by every confirm path.
fn confirm_cas(vm_id: &str, row: StampRow, value: u64) -> Result<StampRow> {
    let expected = row
        .confirmed
        .checked_add(1)
        .ok_or_else(|| KbsError::Policy("volume-stamp overflow".into()))?;
    if value != expected {
        return Err(KbsError::Policy(format!(
            "volume-stamp confirm: vm_id={vm_id} value={value} expected={expected} \
             (stored={}) — rewind or skip, fail closed",
            row.confirmed
        )));
    }
    Ok(StampRow {
        confirmed: value,
        unconfirmed_releases: 0,
    })
}

/// Shared read-only projection used by both store impls, so the file
/// store and the in-memory test double can never diverge on what a
/// snapshot means.
fn rows_from(map: &HashMap<String, StampRow>) -> Vec<VolumeStampStatus> {
    let mut rows: Vec<VolumeStampStatus> = map
        .iter()
        .map(|(vm_id, row)| VolumeStampStatus {
            vm_id: vm_id.clone(),
            confirmed: row.confirmed,
            unconfirmed_releases: row.unconfirmed_releases,
        })
        .collect();
    rows.sort_by(|a, b| a.vm_id.cmp(&b.vm_id));
    rows
}

/// In-memory test double. Mirrors [`FileVolumeStampStore`]'s semantics
/// without touching disk. Production code MUST use the file-backed impl.
#[derive(Default)]
pub struct InMemoryVolumeStampStore {
    inner: Mutex<HashMap<String, StampRow>>,
    epochs: Mutex<StampSidecar>,
    protocols: Mutex<BTreeMap<String, u8>>,
    timelines: Mutex<TimelineSidecar>,
}

impl VolumeStampStore for InMemoryVolumeStampStore {
    fn get(&self, vm_id: &str) -> Result<u64> {
        let m = self
            .inner
            .lock()
            .map_err(|_| KbsError::Policy("volume-stamp lock poisoned".into()))?;
        Ok(m.get(vm_id).copied().unwrap_or_default().confirmed)
    }

    fn note_release(&self, vm_id: &str) -> Result<(u64, u64)> {
        let mut m = self
            .inner
            .lock()
            .map_err(|_| KbsError::Policy("volume-stamp lock poisoned".into()))?;
        let row = m.entry(vm_id.to_string()).or_default();
        row.unconfirmed_releases = row.unconfirmed_releases.checked_add(1).ok_or_else(|| {
            KbsError::Policy("volume-stamp: unconfirmed-releases overflow".into())
        })?;
        Ok((row.confirmed, row.unconfirmed_releases))
    }

    fn confirm(&self, vm_id: &str, value: u64) -> Result<u64> {
        let mut m = self
            .inner
            .lock()
            .map_err(|_| KbsError::Policy("volume-stamp lock poisoned".into()))?;
        let row = m.get(vm_id).copied().unwrap_or_default();
        let expected = row
            .confirmed
            .checked_add(1)
            .ok_or_else(|| KbsError::Policy("volume-stamp overflow".into()))?;
        if value != expected {
            return Err(KbsError::Policy(format!(
                "volume-stamp confirm: vm_id={vm_id} value={value} expected={expected} \
                 (stored={}) — rewind or skip, fail closed",
                row.confirmed
            )));
        }
        m.insert(
            vm_id.to_string(),
            StampRow {
                confirmed: value,
                unconfirmed_releases: 0,
            },
        );
        Ok(value)
    }

    fn admin_reset_unconfirmed(&self, vm_id: &str) -> Result<u64> {
        let mut m = self
            .inner
            .lock()
            .map_err(|_| KbsError::Policy("volume-stamp lock poisoned".into()))?;
        let mut row = m.get(vm_id).copied().unwrap_or_default();
        let previous = row.unconfirmed_releases;
        if previous == 0 {
            // Nothing to clear — a harmless no-op, not an error. Mirrors
            // `FileVolumeStampStore`: no row is created for a vm_id that
            // was never seen.
            return Ok(0);
        }
        row.unconfirmed_releases = 0;
        m.insert(vm_id.to_string(), row);
        Ok(previous)
    }

    fn snapshot(&self) -> Result<Vec<VolumeStampStatus>> {
        let m = self
            .inner
            .lock()
            .map_err(|_| KbsError::Policy("volume-stamp lock poisoned".into()))?;
        Ok(rows_from(&m))
    }

    fn token_epoch(&self, vm_id: &str) -> Result<u64> {
        let e = self.epochs.lock().map_err(|_| poisoned())?;
        Ok(e.epochs.get(vm_id).copied().unwrap_or(0))
    }

    fn confirm_at_epoch(&self, vm_id: &str, value: u64, epoch: u64) -> Result<u64> {
        self.confirm_at(vm_id, value, epoch, &ZERO_TIMELINE)
    }

    fn timeline(&self, vm_id: &str) -> Result<[u8; 32]> {
        self.timelines
            .lock()
            .map_err(|_| poisoned())?
            .current(vm_id)
    }

    fn confirm_at(&self, vm_id: &str, value: u64, epoch: u64, timeline: &[u8; 32]) -> Result<u64> {
        let mut m = self.inner.lock().map_err(|_| poisoned())?;
        let e = self.epochs.lock().map_err(|_| poisoned())?;
        let tl = self.timelines.lock().map_err(|_| poisoned())?;
        let current = e.epochs.get(vm_id).copied().unwrap_or(0);
        if current != epoch {
            return Err(stale_epoch(vm_id, epoch, current));
        }
        check_timeline(vm_id, &tl.current(vm_id)?, timeline)?;
        let row = m.get(vm_id).copied().unwrap_or_default();
        let new_row = confirm_cas(vm_id, row, value)?;
        m.insert(vm_id.to_string(), new_row);
        Ok(value)
    }

    fn adopt_fresh_timeline(&self, vm_id: &str, new_timeline: &[u8; 32]) -> Result<()> {
        let m = self.inner.lock().map_err(|_| poisoned())?;
        let e = self.epochs.lock().map_err(|_| poisoned())?;
        let mut tl = self.timelines.lock().map_err(|_| poisoned())?;
        let row = m.get(vm_id).copied().unwrap_or_default();
        *tl = plan_fresh_timeline(row, &e, &tl, vm_id, new_timeline)?;
        Ok(())
    }

    fn record_arm_timeline(&self, vm_id: &str, restore_id: &str, t: &[u8; 32]) -> Result<()> {
        self.timelines.lock().map_err(|_| poisoned())?.arms.insert(
            vm_id.to_string(),
            ArmTimeline {
                restore_id: restore_id.to_string(),
                timeline: hex::encode(t),
            },
        );
        Ok(())
    }

    fn arm_timeline(&self, vm_id: &str, restore_id: &str) -> Result<Option<[u8; 32]>> {
        self.timelines
            .lock()
            .map_err(|_| poisoned())?
            .arm(vm_id, restore_id)
    }

    fn checkpoint_read(
        &self,
        vm_id: &str,
    ) -> Result<(u64, u64, Option<PendingRollback>, [u8; 32])> {
        let m = self.inner.lock().map_err(|_| poisoned())?;
        let e = self.epochs.lock().map_err(|_| poisoned())?;
        let tl = self.timelines.lock().map_err(|_| poisoned())?;
        let r = m.get(vm_id).copied().unwrap_or_default();
        Ok((
            r.confirmed,
            r.unconfirmed_releases,
            e.pending.get(vm_id).cloned(),
            tl.current(vm_id)?,
        ))
    }

    fn apply_rollback(
        &self,
        vm_id: &str,
        confirmed: u64,
        new_epoch: u64,
        restore_id: &str,
        new_timeline: &[u8; 32],
    ) -> Result<()> {
        let mut m = self.inner.lock().map_err(|_| poisoned())?;
        let mut e = self.epochs.lock().map_err(|_| poisoned())?;
        let mut tl = self.timelines.lock().map_err(|_| poisoned())?;
        let (next, row) = plan_apply(&m, &e, vm_id, confirmed, new_epoch, restore_id)?;
        let next_tl = plan_timeline_apply(&e, &tl, vm_id, restore_id, new_timeline)?;
        *e = next;
        *tl = next_tl;
        m.insert(vm_id.to_string(), row);
        Ok(())
    }

    fn pending_rollback(&self, vm_id: &str) -> Result<Option<PendingRollback>> {
        let e = self.epochs.lock().map_err(|_| poisoned())?;
        Ok(e.pending.get(vm_id).cloned())
    }

    fn row_and_pending(&self, vm_id: &str) -> Result<(u64, u64, Option<PendingRollback>)> {
        let m = self.inner.lock().map_err(|_| poisoned())?;
        let e = self.epochs.lock().map_err(|_| poisoned())?;
        let r = m.get(vm_id).copied().unwrap_or_default();
        Ok((
            r.confirmed,
            r.unconfirmed_releases,
            e.pending.get(vm_id).cloned(),
        ))
    }

    fn pending_rollback_vms(&self) -> Result<Vec<String>> {
        let e = self.epochs.lock().map_err(|_| poisoned())?;
        let mut v: Vec<String> = e.pending.keys().cloned().collect();
        v.sort();
        Ok(v)
    }

    fn finalize_rollback(&self, vm_id: &str, restore_id: &str) -> Result<Option<PendingRollback>> {
        let mut e = self.epochs.lock().map_err(|_| poisoned())?;
        let dropped = match e.pending.get(vm_id) {
            Some(p) if p.restore_id == restore_id => p.clone(),
            _ => return Ok(None),
        };
        resolve(&mut e, vm_id, restore_id, RollbackResolution::Delivered);
        Ok(Some(dropped))
    }

    fn revert_rollback(&self, vm_id: &str, restore_id: &str) -> Result<Option<PendingRollback>> {
        let mut m = self.inner.lock().map_err(|_| poisoned())?;
        let mut e = self.epochs.lock().map_err(|_| poisoned())?;
        let record = match e.pending.get(vm_id) {
            Some(p) if p.restore_id == restore_id => p.clone(),
            _ => return Ok(None),
        };
        m.insert(
            vm_id.to_string(),
            StampRow {
                confirmed: record.prev_confirmed,
                unconfirmed_releases: record.prev_unconfirmed_releases,
            },
        );
        let mut tl = self.timelines.lock().map_err(|_| poisoned())?;
        if let Some(next_tl) = plan_timeline_revert(&tl, vm_id, restore_id)? {
            *tl = next_tl;
        }
        resolve(&mut e, vm_id, restore_id, RollbackResolution::Reverted);
        Ok(Some(record))
    }

    fn rollback_resolution(&self, vm_id: &str) -> Result<Option<ResolvedRollback>> {
        let e = self.epochs.lock().map_err(|_| poisoned())?;
        Ok(e.resolved.get(vm_id).cloned())
    }

    fn guest_stamp_protocol(&self, vm_id: &str) -> Result<u8> {
        let map = self.protocols.lock().map_err(|_| poisoned())?;
        Ok(map.get(vm_id).copied().unwrap_or(GUEST_STAMP_PROTOCOL_V1))
    }

    fn record_guest_stamp_protocol(&self, vm_id: &str, protocol: u8) -> Result<()> {
        validate_guest_stamp_protocol(vm_id, protocol)?;
        let mut map = self.protocols.lock().map_err(|_| poisoned())?;
        set_guest_stamp_protocol(&mut map, vm_id, protocol);
        Ok(())
    }
}

/// The `/v1/kbs/volume-stamp/confirm` operation.
///
/// Verifies the presented token in CONSTANT TIME against the value
/// re-derived from the MAC key, then applies the CAS. A bad token is
/// refused BEFORE the store is touched, so an attacker who cannot
/// produce a token cannot move the expectation — which is the whole
/// point (see the module docs: an unauthenticated confirm is a permanent
/// remote brick). On success this is also the ONLY thing (besides an
/// admin reset) that clears [`VolumeStampStore::note_release`]'s
/// suppressed-confirm counter — see the module docs' "Suppressed-confirm
/// detection" section.
pub fn confirm(
    store: &dyn VolumeStampStore,
    mac_key: &[u8; 32],
    vm_id: &str,
    value: u64,
    presented_token: &[u8],
) -> Result<u64> {
    // The token is only valid under the epoch it was minted in; the
    // store re-checks that epoch under the CAS lock, so a rollback
    // landing between this read and the write refuses the confirm.
    let epoch = store.token_epoch(vm_id)?;
    let want = stamp_token_epoch(mac_key, vm_id, value, epoch);
    // ct_eq over equal-length slices; a length mismatch short-circuits
    // (the length of the expected token is public).
    let ok = presented_token.len() == want.len() && bool::from(presented_token.ct_eq(&want[..]));
    if !ok {
        return Err(KbsError::Policy(format!(
            "volume-stamp confirm: vm_id={vm_id} value={value} — bad or absent token, \
             fail closed (the expectation is UNCHANGED)"
        )));
    }
    store.confirm_at_epoch(vm_id, value, epoch)
}

/// The stamp-protocol-v2 `/v1/kbs/volume-stamp/confirm` operation: the
/// confirm names the TIMELINE it stamped, the token must be the one minted
/// for exactly that `(vm_id, value, epoch, timeline)` (constant-time), and
/// the store's CAS ([`VolumeStampStore::confirm_at`]) re-checks, under one
/// lock, that the timeline and epoch are still current and `value` is
/// exactly `confirmed + 1`. A bad token or a refused CAS leaves the store
/// untouched.
pub fn confirm_timeline(
    store: &dyn VolumeStampStore,
    mac_key: &[u8; 32],
    vm_id: &str,
    value: u64,
    presented_token: &[u8],
    timeline: &[u8; 32],
) -> Result<u64> {
    let epoch = store.token_epoch(vm_id)?;
    let want = stamp_token_timeline(mac_key, vm_id, value, epoch, timeline);
    let ok = presented_token.len() == want.len() && bool::from(presented_token.ct_eq(&want[..]));
    if !ok {
        return Err(KbsError::Policy(format!(
            "volume-stamp confirm: vm_id={vm_id} value={value} — bad or absent timeline-bound \
             token, fail closed (the expectation is UNCHANGED)"
        )));
    }
    store.confirm_at(vm_id, value, epoch, timeline)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; 32] {
        [7u8; 32]
    }

    /// A distinct non-zero timeline per `n`.
    fn tl(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn fresh_vm_reads_zero() {
        let s = InMemoryVolumeStampStore::default();
        assert_eq!(s.get("abc").unwrap(), 0);
    }

    #[test]
    fn confirm_advances_only_by_one() {
        let s = InMemoryVolumeStampStore::default();
        assert_eq!(s.confirm("abc", 1).unwrap(), 1);
        assert_eq!(s.get("abc").unwrap(), 1);
        // skip refused
        assert!(s.confirm("abc", 3).is_err());
        assert_eq!(s.get("abc").unwrap(), 1);
        // rewind refused
        assert!(s.confirm("abc", 1).is_err());
        assert_eq!(s.get("abc").unwrap(), 1);
        // the one legal advance
        assert_eq!(s.confirm("abc", 2).unwrap(), 2);
    }

    #[test]
    fn stamps_are_per_vm() {
        let s = InMemoryVolumeStampStore::default();
        s.confirm("a", 1).unwrap();
        assert_eq!(s.get("a").unwrap(), 1);
        assert_eq!(s.get("b").unwrap(), 0);
        s.confirm("b", 1).unwrap();
        assert_eq!(s.get("a").unwrap(), 1);
    }

    #[test]
    fn token_is_deterministic_and_bound_to_vm_and_target() {
        let k = stamp_mac_key(&seed());
        let t = stamp_token(&k, "abc", 5);
        assert_eq!(t, stamp_token(&k, "abc", 5));
        assert_ne!(t, stamp_token(&k, "abc", 6));
        assert_ne!(t, stamp_token(&k, "abd", 5));
        // A different signing seed yields a different key and token.
        let k2 = stamp_mac_key(&[9u8; 32]);
        assert_ne!(t, stamp_token(&k2, "abc", 5));
    }

    #[test]
    fn vm_id_length_is_folded_in_so_concatenations_do_not_collide() {
        let k = stamp_mac_key(&seed());
        // Without the length prefix, ("ab","c") and ("a","bc") style
        // splits could collide; assert distinct ids stay distinct.
        assert_ne!(stamp_token(&k, "ab", 1), stamp_token(&k, "a", 1));
    }

    #[test]
    fn confirm_requires_a_valid_token_and_leaves_the_store_untouched_otherwise() {
        let s = InMemoryVolumeStampStore::default();
        let k = stamp_mac_key(&seed());
        // Wrong token → refused, expectation UNCHANGED (no remote brick).
        assert!(confirm(&s, &k, "abc", 1, &[0u8; 32]).is_err());
        assert_eq!(s.get("abc").unwrap(), 0);
        // Empty token → refused.
        assert!(confirm(&s, &k, "abc", 1, &[]).is_err());
        assert_eq!(s.get("abc").unwrap(), 0);
        // A token minted for a DIFFERENT vm cannot move this one.
        let other = stamp_token(&k, "zzz", 1);
        assert!(confirm(&s, &k, "abc", 1, &other).is_err());
        assert_eq!(s.get("abc").unwrap(), 0);
        // A token minted for a different TARGET cannot move it either.
        let wrong_target = stamp_token(&k, "abc", 2);
        assert!(confirm(&s, &k, "abc", 1, &wrong_target).is_err());
        assert_eq!(s.get("abc").unwrap(), 0);
        // The right token works.
        let good = stamp_token(&k, "abc", 1);
        assert_eq!(confirm(&s, &k, "abc", 1, &good).unwrap(), 1);
        assert_eq!(s.get("abc").unwrap(), 1);
    }

    #[test]
    fn replaying_a_spent_token_is_refused_by_the_cas() {
        let s = InMemoryVolumeStampStore::default();
        let k = stamp_mac_key(&seed());
        let good = stamp_token(&k, "abc", 1);
        assert_eq!(confirm(&s, &k, "abc", 1, &good).unwrap(), 1);
        // Same token again: authentic, but the CAS refuses the rewind.
        assert!(confirm(&s, &k, "abc", 1, &good).is_err());
        assert_eq!(s.get("abc").unwrap(), 1);
    }

    #[test]
    fn file_store_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamp.json");
        {
            let s = FileVolumeStampStore::open(&path).unwrap();
            s.confirm("abc", 1).unwrap();
            s.confirm("abc", 2).unwrap();
        }
        let s2 = FileVolumeStampStore::open(&path).unwrap();
        assert_eq!(s2.get("abc").unwrap(), 2);
        // And the CAS still applies across the reload.
        assert!(s2.confirm("abc", 2).is_err());
        assert_eq!(s2.confirm("abc", 3).unwrap(), 3);
    }

    #[test]
    fn file_store_refusals_write_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamp.json");
        let s = FileVolumeStampStore::open(&path).unwrap();
        assert!(s.confirm("abc", 5).is_err());
        // Nothing was created for a refused CAS.
        assert_eq!(
            FileVolumeStampStore::open(&path)
                .unwrap()
                .get("abc")
                .unwrap(),
            0
        );
    }

    #[test]
    fn a_persist_failure_rolls_the_cache_back() {
        // Point the store at a path whose parent does not exist, so the
        // tmp-file write fails; the cache must NOT be left advanced.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone").join("volume-stamp.json");
        let s = FileVolumeStampStore::open(&path).unwrap();
        assert!(s.confirm("abc", 1).is_err());
        assert_eq!(
            s.get("abc").unwrap(),
            0,
            "a failed persist left the cache advanced — the tenant is now locked out"
        );
    }

    // ── guest stamp protocol (rollback capability) ─────────────────────

    #[test]
    fn guest_stamp_protocol_defaults_to_v1_and_latest_record_wins() {
        for_each_store(|s| {
            assert_eq!(
                s.guest_stamp_protocol("abc").unwrap(),
                GUEST_STAMP_PROTOCOL_V1
            );
            s.record_guest_stamp_protocol("abc", 2).unwrap();
            assert_eq!(s.guest_stamp_protocol("abc").unwrap(), 2);
            assert_eq!(s.guest_stamp_protocol("other").unwrap(), 1);
            // A guest re-launched on a v1 image moves it back down.
            s.record_guest_stamp_protocol("abc", 1).unwrap();
            assert_eq!(s.guest_stamp_protocol("abc").unwrap(), 1);
            assert!(s.record_guest_stamp_protocol("abc", 0).is_err());
            assert_eq!(s.guest_stamp_protocol("abc").unwrap(), 1);
        });
    }

    #[test]
    fn only_protocol_two_and_up_is_rollback_capable() {
        assert!(!guest_stamp_protocol_is_rollback_capable(0));
        assert!(!guest_stamp_protocol_is_rollback_capable(1));
        assert!(guest_stamp_protocol_is_rollback_capable(2));
        assert!(guest_stamp_protocol_is_rollback_capable(3));
    }

    /// The protocol lives in its OWN sibling: recording it never touches
    /// the row file or the token-epochs file, a v1 record on a VM with no
    /// entry writes nothing at all (the release hot path), and the value
    /// survives a reopen.
    #[test]
    fn guest_stamp_protocol_is_a_sibling_that_never_widens_the_other_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        let sib = dir.path().join("volume-stamps-guest-stamp-protocol.json");
        let s = FileVolumeStampStore::open(&path).unwrap();
        s.confirm("abc", 1).unwrap();
        let rows_before = fs::read(&path).unwrap();
        s.record_guest_stamp_protocol("abc", 1).unwrap();
        assert!(!sib.exists(), "a v1 record on an absent VM wrote a file");
        s.record_guest_stamp_protocol("abc", 2).unwrap();
        assert_eq!(fs::read(&path).unwrap(), rows_before);
        assert!(!dir.path().join("volume-stamps-token-epochs.json").exists());
        assert_eq!(fs::read(&sib).unwrap(), br#"{"abc":2}"#);
        let reopened = FileVolumeStampStore::open(&path).unwrap();
        assert_eq!(reopened.guest_stamp_protocol("abc").unwrap(), 2);
        assert_eq!(reopened.get("abc").unwrap(), 1);
        reopened.record_guest_stamp_protocol("abc", 1).unwrap();
        assert_eq!(fs::read(&sib).unwrap(), b"{}");
        // The row file an older binary decodes strictly is still exactly
        // `{vm_id: row}`.
        let rows: HashMap<String, StampRow> =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn a_failed_protocol_write_leaves_the_record_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        let s = FileVolumeStampStore::open(&path).unwrap();
        fs::create_dir(
            dir.path()
                .join(".volume-stamps-guest-stamp-protocol.json.tmp"),
        )
        .unwrap();
        assert!(s.record_guest_stamp_protocol("abc", 2).is_err());
        assert_eq!(s.guest_stamp_protocol("abc").unwrap(), 1);
    }

    /// The rename landed but the directory cannot be synced: the caller
    /// is refused (a crash could bring the old record back), while the
    /// cache follows the file it can no longer un-rename.
    #[cfg(unix)]
    #[test]
    fn an_unsyncable_protocol_rename_refuses_the_caller_until_it_is_durable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        let s = FileVolumeStampStore::open(&path).unwrap();
        // A fresh process syncs once on its first record.
        s.record_guest_stamp_protocol("abc", 1).unwrap();
        // write+search but no read: tmp create and rename work, opening
        // the directory to fsync it does not.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o300)).unwrap();
        if fs::File::open(dir.path()).is_ok() {
            // Privileged runner: permissions are not enforced.
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let out = s.record_guest_stamp_protocol("abc", 2);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(out.is_err());
        assert_eq!(s.guest_stamp_protocol("abc").unwrap(), 2);
        assert_eq!(
            fs::read(dir.path().join("volume-stamps-guest-stamp-protocol.json")).unwrap(),
            br#"{"abc":2}"#
        );
        s.record_guest_stamp_protocol("abc", 2).unwrap();

        // The security-relevant direction: a durable v2 replaced by v1,
        // the fsync fails — and a RETRY of the same v1 record (which
        // changes nothing in the cache) must keep failing until the
        // rename is durable, never succeed on the cache alone.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o300)).unwrap();
        assert!(s.record_guest_stamp_protocol("abc", 1).is_err());
        assert_eq!(s.guest_stamp_protocol("abc").unwrap(), 1);
        assert!(
            s.record_guest_stamp_protocol("abc", 1).is_err(),
            "a retry succeeded on a rename that is not yet durable"
        );
        // Nor after a process restart that reopens the visible v1 file.
        drop(s);
        let s = FileVolumeStampStore::open(&path).unwrap();
        assert_eq!(s.guest_stamp_protocol("abc").unwrap(), 1);
        assert!(
            s.record_guest_stamp_protocol("abc", 1).is_err(),
            "a reopened store trusted a rename that is not yet durable"
        );
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        s.record_guest_stamp_protocol("abc", 1).unwrap();
    }

    /// The timelines rename must be DURABLE (a lost one fails open): when
    /// the directory cannot be fsynced the rollback's stamp step is
    /// refused BEFORE the row is lowered, memory follows the renamed file
    /// (so the pending record's revert restores the replaced timeline),
    /// and nothing is lowered under the old timeline.
    #[test]
    fn an_unsyncable_timeline_rename_refuses_the_rollback_before_the_row_moves() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        let s = FileVolumeStampStore::open(&path).unwrap();
        s.confirm("abc", 1).unwrap();
        s.confirm("abc", 2).unwrap();
        // A fresh process syncs once on its first timeline write.
        s.record_arm_timeline("other", "warm", &tl(1)).unwrap();
        // write+search but no read: tmp create and rename work, opening
        // the directory to fsync it does not.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o300)).unwrap();
        if fs::File::open(dir.path()).is_ok() {
            // Privileged runner: permissions are not enforced.
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let out = s.apply_rollback("abc", 1, 1, "r", &tl(0x79));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            out.is_err(),
            "an unsynced timeline rename must refuse the stamp step"
        );
        assert_eq!(s.row("abc").unwrap(), (2, 0), "the row was not lowered");
        assert_eq!(
            s.timeline("abc").unwrap(),
            tl(0x79),
            "memory follows the renamed file"
        );
        assert!(s.pending_rollback("abc").unwrap().is_some());
        s.revert_rollback("abc", "r").unwrap().unwrap();
        assert_eq!(s.timeline("abc").unwrap(), ZERO_TIMELINE);
        assert_eq!(s.row("abc").unwrap(), (2, 0));
    }

    /// An unsynced timeline REVERT keeps the pending record, and the retry
    /// (which finds no undo left) still refuses until the rename is
    /// durable — never dropping the record over a timeline a crash could
    /// undo. Likewise a retried arm timeline.
    #[test]
    fn an_unsynced_timeline_revert_keeps_refusing_until_it_is_durable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        let s = FileVolumeStampStore::open(&path).unwrap();
        s.confirm("abc", 1).unwrap();
        s.apply_rollback("abc", 0, 1, "r", &tl(0x7a)).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o300)).unwrap();
        if fs::File::open(dir.path()).is_ok() {
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        assert!(s.revert_rollback("abc", "r").is_err());
        assert!(s.pending_rollback("abc").unwrap().is_some());
        assert!(
            s.revert_rollback("abc", "r").is_err(),
            "a retry must not drop the record over an unsynced timeline"
        );
        assert!(s.finalize_rollback("abc", "r").is_err());
        assert!(s.record_arm_timeline("abc", "x", &tl(1)).is_err());
        assert!(s.pending_rollback("abc").unwrap().is_some());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        s.revert_rollback("abc", "r").unwrap();
        assert!(s.pending_rollback("abc").unwrap().is_none());
        assert_eq!(s.timeline("abc").unwrap(), ZERO_TIMELINE);
        assert_eq!(s.row("abc").unwrap(), (1, 0));
    }

    /// A bare relative store path (`volume-stamps.json`) has an EMPTY
    /// parent; the strict dir sync must use `.` or every release would
    /// be refused.
    #[test]
    fn a_bare_file_name_syncs_the_current_directory() {
        use std::path::Path;
        assert_eq!(dir_of(Path::new("volume-stamps.json")), Path::new("."));
        assert_eq!(
            dir_of(Path::new("/var/lib/kbs/x.json")),
            Path::new("/var/lib/kbs")
        );
        assert_eq!(dir_of(Path::new("state/x.json")), Path::new("state"));
        sync_parent_dir(Path::new("volume-stamps.json"), "t").unwrap();
    }

    #[test]
    fn a_zero_protocol_on_disk_refuses_to_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        fs::write(
            dir.path().join("volume-stamps-guest-stamp-protocol.json"),
            br#"{"abc":0}"#,
        )
        .unwrap();
        assert!(FileVolumeStampStore::open(&path).is_err());
    }

    // ── suppressed-confirm detection (note_release / admin_reset) ──────

    #[test]
    fn note_release_increments_and_leaves_confirmed_untouched() {
        for_each_store(|s| {
            assert_eq!(s.note_release("abc").unwrap(), (0, 1));
            assert_eq!(s.note_release("abc").unwrap(), (0, 2));
            assert_eq!(s.note_release("abc").unwrap(), (0, 3));
            // `confirmed` never moves from `note_release` alone — only
            // `confirm` (or an admin action, for the OTHER field) can
            // move anything.
            assert_eq!(s.get("abc").unwrap(), 0);
        });
    }

    #[test]
    fn confirm_resets_the_unconfirmed_releases_counter() {
        for_each_store(|s| {
            s.note_release("abc").unwrap();
            s.note_release("abc").unwrap();
            s.note_release("abc").unwrap();
            assert_eq!(s.note_release("abc").unwrap(), (0, 4));
            // A real confirm resets the count to 0 IN THE SAME STEP as
            // advancing the confirmed stamp.
            assert_eq!(s.confirm("abc", 1).unwrap(), 1);
            assert_eq!(s.note_release("abc").unwrap(), (1, 1));
        });
    }

    #[test]
    fn a_refused_confirm_does_not_reset_the_unconfirmed_releases_counter() {
        // CLAIM: only a SUCCESSFUL confirm resets the count. A rewind/skip
        // attempt against the confirmed stamp must not give a miner a
        // side-channel to clear its own suppression counter without a
        // real, CAS-accepted confirm.
        for_each_store(|s| {
            s.note_release("abc").unwrap();
            s.note_release("abc").unwrap();
            assert!(s.confirm("abc", 99).is_err(), "not stored+1, refused");
            assert_eq!(
                s.note_release("abc").unwrap(),
                (0, 3),
                "the refused confirm must not have reset the counter"
            );
        });
    }

    #[test]
    fn admin_reset_unconfirmed_clears_the_count_without_touching_confirmed() {
        for_each_store(|s| {
            s.note_release("abc").unwrap();
            s.note_release("abc").unwrap();
            s.note_release("abc").unwrap();
            s.confirm("abc", 1).unwrap();
            s.note_release("abc").unwrap();
            s.note_release("abc").unwrap();
            assert_eq!(s.get("abc").unwrap(), 1);
            // Admin reset clears ONLY the suppression counter — the
            // confirmed stamp (the actual anti-rollback reference) is
            // untouched, so this can never be used to un-brick a
            // legitimate rollback refusal, only to un-block a suppressed
            // VM.
            assert_eq!(s.admin_reset_unconfirmed("abc").unwrap(), 2);
            assert_eq!(s.get("abc").unwrap(), 1, "confirmed must be untouched");
            assert_eq!(
                s.note_release("abc").unwrap(),
                (1, 1),
                "the count resumed from 0, not from where it left off"
            );
        });
    }

    #[test]
    fn admin_reset_unconfirmed_on_an_unblocked_vm_is_a_harmless_no_op() {
        for_each_store(|s| {
            // Never released at all.
            assert_eq!(s.admin_reset_unconfirmed("never-seen").unwrap(), 0);
            assert_eq!(s.get("never-seen").unwrap(), 0);
            // Released once and confirmed — count is already 0.
            s.note_release("abc").unwrap();
            s.confirm("abc", 1).unwrap();
            assert_eq!(s.admin_reset_unconfirmed("abc").unwrap(), 0);
            assert_eq!(s.get("abc").unwrap(), 1);
        });
    }

    #[test]
    fn note_release_and_admin_reset_are_per_vm() {
        for_each_store(|s| {
            s.note_release("a").unwrap();
            s.note_release("a").unwrap();
            s.note_release("b").unwrap();
            assert_eq!(s.note_release("a").unwrap(), (0, 3));
            assert_eq!(s.admin_reset_unconfirmed("b").unwrap(), 1);
            // `a`'s count is untouched by `b`'s reset.
            assert_eq!(s.note_release("a").unwrap(), (0, 4));
        });
    }

    #[test]
    fn file_store_unconfirmed_releases_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamp.json");
        {
            let s = FileVolumeStampStore::open(&path).unwrap();
            s.note_release("abc").unwrap();
            s.note_release("abc").unwrap();
        }
        let s2 = FileVolumeStampStore::open(&path).unwrap();
        assert_eq!(s2.note_release("abc").unwrap(), (0, 3));
    }

    #[test]
    fn a_persist_failure_on_note_release_rolls_the_cache_back() {
        // Same all-or-nothing discipline as `confirm`'s persist-failure
        // test, on the OTHER mutating method.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone").join("volume-stamp.json");
        let s = FileVolumeStampStore::open(&path).unwrap();
        assert!(s.note_release("abc").is_err());
        assert_eq!(
            s.get("abc").unwrap(),
            0,
            "a failed persist must not leave the row advanced"
        );
    }

    /// Run a store-contract assertion against BOTH implementations — the
    /// in-memory double and the file-backed production store must agree.
    /// Mirrors `boot_counter`'s `for_each_store` helper.
    fn for_each_store(f: impl Fn(&dyn VolumeStampStore)) {
        f(&InMemoryVolumeStampStore::default());
        let dir = tempfile::tempdir().unwrap();
        let file = FileVolumeStampStore::open(dir.path().join("volume-stamp.json")).unwrap();
        f(&file);
    }

    // ── snapshot: the admin READ path (cutover step 3) ───────────────

    #[test]
    fn snapshot_reflects_note_release_and_confirm() {
        for_each_store(|s| {
            assert!(
                s.snapshot().unwrap().is_empty(),
                "a store nobody has released for has no rows"
            );

            // Two releases, no confirm — the suppression shape.
            s.note_release("vm-suppressed").unwrap();
            s.note_release("vm-suppressed").unwrap();
            // One release then a confirm — the healthy shape.
            s.note_release("vm-healthy").unwrap();
            s.confirm("vm-healthy", 1).unwrap();

            let rows = s.snapshot().unwrap();
            assert_eq!(rows.len(), 2);
            // Sorted by vm_id — deterministic across calls.
            assert_eq!(rows[0].vm_id, "vm-healthy");
            assert_eq!(rows[1].vm_id, "vm-suppressed");

            // The counts are the REAL ones, not zeros or placeholders:
            // a snapshot that ignored `note_release` would report 0 here.
            assert_eq!(rows[0].confirmed, 1);
            assert_eq!(rows[0].unconfirmed_releases, 0);
            assert_eq!(rows[1].confirmed, 0);
            assert_eq!(rows[1].unconfirmed_releases, 2);
        });
    }

    #[test]
    fn snapshot_tracks_every_further_note_release() {
        // Kills "snapshot reads a stale copy taken at open time" — the
        // exact bug RA-L-NEW-2 hit on the boot-counter admin handle.
        for_each_store(|s| {
            for expected in 1..=5u64 {
                s.note_release("vm-a").unwrap();
                let rows = s.snapshot().unwrap();
                assert_eq!(rows.len(), 1);
                assert_eq!(
                    rows[0].unconfirmed_releases, expected,
                    "snapshot must reflect the CURRENT count, not a cached one"
                );
            }
        });
    }

    #[test]
    fn snapshot_is_a_pure_read_and_never_mutates() {
        for_each_store(|s| {
            s.note_release("vm-a").unwrap();
            s.note_release("vm-a").unwrap();
            s.note_release("vm-a").unwrap();
            s.note_release("vm-b").unwrap();
            s.confirm("vm-b", 1).unwrap();

            let before = s.snapshot().unwrap();
            // Poll it hard: a snapshot that incremented, reset a streak,
            // or advanced a stamp would show up here.
            for _ in 0..50 {
                let _ = s.snapshot().unwrap();
            }
            let after = s.snapshot().unwrap();
            assert_eq!(before, after, "snapshot MUST NOT mutate the store");
            assert_eq!(after[0].vm_id, "vm-a");
            assert_eq!(after[0].unconfirmed_releases, 3);
            assert_eq!(after[1].confirmed, 1);
            assert_eq!(after[1].unconfirmed_releases, 0);

            // And the gate still sees what it saw: the next release is
            // the 4th, not the 1st. If snapshot had cleared the streak
            // this would read (0, 1).
            assert_eq!(s.note_release("vm-a").unwrap(), (0, 4));
        });
    }

    #[test]
    fn snapshot_is_a_pure_read_and_never_creates_the_file() {
        // The file store's write path is `insert_and_persist_locked`,
        // which CREATES the file. A snapshot that went anywhere near it
        // would leave a file behind on a store that has never been
        // written — the cheapest possible signal that the read path is
        // not a read path.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamp.json");
        let s = FileVolumeStampStore::open(&path).unwrap();
        assert!(s.snapshot().unwrap().is_empty());
        assert!(
            !path.exists(),
            "snapshot must not create the backing file: {}",
            path.display()
        );

        // With rows present the file exists, but snapshot must not
        // rewrite it — compare bytes, not just contents.
        s.note_release("vm-a").unwrap();
        let bytes_before = std::fs::read(&path).unwrap();
        for _ in 0..20 {
            let _ = s.snapshot().unwrap();
        }
        assert_eq!(
            bytes_before,
            std::fs::read(&path).unwrap(),
            "snapshot must not rewrite the backing file"
        );
    }

    #[test]
    fn snapshot_survives_a_reopen_of_the_file_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamp.json");
        {
            let s = FileVolumeStampStore::open(&path).unwrap();
            s.note_release("vm-a").unwrap();
            s.note_release("vm-a").unwrap();
            s.note_release("vm-b").unwrap();
            s.confirm("vm-b", 1).unwrap();
        }
        let rows = FileVolumeStampStore::open(&path)
            .unwrap()
            .snapshot()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                VolumeStampStatus {
                    vm_id: "vm-a".into(),
                    confirmed: 0,
                    unconfirmed_releases: 2,
                },
                VolumeStampStatus {
                    vm_id: "vm-b".into(),
                    confirmed: 1,
                    unconfirmed_releases: 0,
                },
            ]
        );
    }

    // ── the arming verdict ───────────────────────────────────────────

    #[test]
    fn never_confirmed_is_distinguishable_from_confirmed_once_long_ago() {
        // THE distinction the cutover needs and that a bare "is it
        // suppressed right now?" check cannot make.
        let never = VolumeStampStatus {
            vm_id: "never".into(),
            confirmed: 0,
            unconfirmed_releases: 1,
        };
        let long_ago = VolumeStampStatus {
            vm_id: "long-ago".into(),
            confirmed: 1,
            unconfirmed_releases: 9,
        };
        let healthy = VolumeStampStatus {
            vm_id: "healthy".into(),
            confirmed: 12,
            unconfirmed_releases: 1,
        };

        // Same `unconfirmed_releases`, opposite verdicts on "has this
        // VM's confirm path ever worked".
        assert!(!never.has_ever_confirmed());
        assert!(healthy.has_ever_confirmed());
        assert_eq!(never.unconfirmed_releases, healthy.unconfirmed_releases);

        // `confirmed >= 1` alone is NOT health: "confirmed once, long
        // ago" also passes it and is caught by the OTHER counter.
        assert!(long_ago.has_ever_confirmed());
        assert!(long_ago.would_refuse_next_release(MAX_UNCONFIRMED_RELEASES));
        assert!(!healthy.would_refuse_next_release(MAX_UNCONFIRMED_RELEASES));

        let r = arming_readiness(&[never, long_ago, healthy], MAX_UNCONFIRMED_RELEASES);
        assert_eq!(r.vms, 3);
        assert_eq!(r.never_confirmed, 1);
        assert_eq!(r.would_refuse_now, 1);
        assert!(!r.ready_to_arm);
    }

    #[test]
    fn would_refuse_next_release_matches_gate_5c_exactly() {
        // Gate 5c increments FIRST (`note_release`) and then compares
        // `count > bound`. So a row stored at exactly `bound` IS refused
        // on its next release. The naive `stored > bound` would call
        // that fleet ready and arm straight into an outage.
        let bound = 3u64;
        let at_bound = VolumeStampStatus {
            vm_id: "at-bound".into(),
            confirmed: 5,
            unconfirmed_releases: bound,
        };
        assert!(
            at_bound.would_refuse_next_release(bound),
            "a row sitting AT the bound is refused on its next release"
        );
        let below = VolumeStampStatus {
            unconfirmed_releases: bound - 1,
            ..at_bound.clone()
        };
        assert!(!below.would_refuse_next_release(bound));

        // Cross-check against the real store + the real comparison the
        // release path makes, so this can never drift from gate 5c.
        for_each_store(|s| {
            for _ in 0..bound {
                s.note_release("vm").unwrap();
            }
            let row = s.snapshot().unwrap().remove(0);
            assert!(row.would_refuse_next_release(bound));
            // What gate 5c actually computes on the next release:
            let (_confirmed, count) = s.note_release("vm").unwrap();
            assert!(
                count > bound,
                "prediction and gate 5c must agree: count={count} bound={bound}"
            );
        });
    }

    #[test]
    fn arming_readiness_is_green_only_on_a_fully_confirming_fleet() {
        let rows = vec![
            VolumeStampStatus {
                vm_id: "a".into(),
                confirmed: 4,
                unconfirmed_releases: 0,
            },
            VolumeStampStatus {
                vm_id: "b".into(),
                confirmed: 1,
                unconfirmed_releases: 1,
            },
        ];
        let r = arming_readiness(&rows, MAX_UNCONFIRMED_RELEASES);
        assert_eq!(r.evaluated_bound, MAX_UNCONFIRMED_RELEASES);
        assert_eq!((r.vms, r.never_confirmed, r.would_refuse_now), (2, 0, 0));
        assert!(r.ready_to_arm);

        // An empty fleet is vacuously ready — and says so with vms == 0,
        // so an operator cannot mistake "nothing to check" for "checked".
        let empty = arming_readiness(&[], MAX_UNCONFIRMED_RELEASES);
        assert_eq!(empty.vms, 0);
        assert!(empty.ready_to_arm);
    }

    #[test]
    fn arming_readiness_evaluates_the_prospective_bound_not_the_live_one() {
        // The whole point of taking the bound as a parameter: while the
        // gate is DISABLED there is no live bound to evaluate against,
        // and the verdict must still be able to be red.
        let rows = vec![VolumeStampStatus {
            vm_id: "a".into(),
            confirmed: 2,
            unconfirmed_releases: 3,
        }];
        assert!(!arming_readiness(&rows, 3).ready_to_arm);
        assert!(arming_readiness(&rows, 4).ready_to_arm);
    }

    // ── token epochs (authorized rollback) ───────────────────────────

    #[test]
    fn epoch_zero_is_byte_identical_to_the_legacy_token_and_epochs_never_collide() {
        let k = stamp_mac_key(&seed());
        assert_eq!(
            stamp_token_epoch(&k, "abc", 5, 0),
            stamp_token(&k, "abc", 5)
        );
        let e1 = stamp_token_epoch(&k, "abc", 5, 1);
        let e2 = stamp_token_epoch(&k, "abc", 5, 2);
        assert_ne!(e1, stamp_token(&k, "abc", 5));
        assert_ne!(e1, e2);
        assert_ne!(e1, stamp_token_epoch(&k, "abc", 6, 1));
        assert_ne!(e1, stamp_token_epoch(&k, "abd", 5, 1));
    }

    #[test]
    fn apply_rollback_lowers_the_stamp_resets_the_count_and_kills_old_tokens() {
        for_each_store(|s| {
            let k = stamp_mac_key(&seed());
            for v in 1..=7 {
                s.confirm("abc", v).unwrap();
            }
            s.note_release("abc").unwrap();
            // A token of the CURRENT timeline for a target the rollback
            // will make legal again (6 = E_T + 1 below).
            let old = stamp_token(&k, "abc", 6);
            s.apply_rollback("abc", 5, 1, "r", &tl(65)).unwrap();
            assert_eq!(s.row("abc").unwrap(), (5, 0));
            assert_eq!(s.token_epoch("abc").unwrap(), 1);
            assert!(
                confirm(s, &k, "abc", 6, &old).is_err(),
                "old-epoch token must be dead"
            );
            assert_eq!(s.get("abc").unwrap(), 5);
            // The rollback moved the VM to a new timeline: even the
            // new-epoch v1 token is dead; only the token bound to that
            // timeline confirms, and only naming it.
            let v1_new_epoch = stamp_token_epoch(&k, "abc", 6, 1);
            assert!(confirm(s, &k, "abc", 6, &v1_new_epoch).is_err());
            let new = stamp_token_timeline(&k, "abc", 6, 1, &tl(65));
            assert!(confirm_timeline(s, &k, "abc", 6, &new, &tl(66)).is_err());
            assert_eq!(s.get("abc").unwrap(), 5);
            assert_eq!(confirm_timeline(s, &k, "abc", 6, &new, &tl(65)).unwrap(), 6);
        });
    }

    #[test]
    fn apply_rollback_requires_a_strictly_higher_epoch_and_writes_nothing_otherwise() {
        for_each_store(|s| {
            s.confirm("abc", 1).unwrap();
            s.apply_rollback("abc", 0, 2, "r", &tl(66)).unwrap();
            s.confirm("abc", 1).unwrap();
            for stale in [0, 1, 2] {
                assert!(s.apply_rollback("abc", 0, stale, "r", &tl(67)).is_err());
            }
            assert_eq!(s.row("abc").unwrap(), (1, 0));
            assert_eq!(s.token_epoch("abc").unwrap(), 2);
        });
    }

    #[test]
    fn revert_restores_the_first_recorded_row_keeps_the_epoch_and_finalize_forgets_it() {
        for_each_store(|s| {
            for v in 1..=7 {
                s.confirm("abc", v).unwrap();
            }
            s.note_release("abc").unwrap();
            s.apply_rollback("abc", 5, 1, "r", &tl(68)).unwrap();
            // A retry of the same rollback keeps the FIRST undo row.
            s.apply_rollback("abc", 5, 2, "r", &tl(69)).unwrap();
            assert!(s.apply_rollback("abc", 5, 3, "other", &tl(70)).is_err());
            assert_eq!(s.pending_rollback_vms().unwrap(), vec!["abc".to_string()]);
            assert!(s.revert_rollback("abc", "other").unwrap().is_none());
            let r = s.revert_rollback("abc", "r").unwrap().unwrap();
            assert_eq!((r.prev_confirmed, r.prev_unconfirmed_releases), (7, 1));
            assert_eq!(s.row("abc").unwrap(), (7, 1));
            assert_eq!(s.token_epoch("abc").unwrap(), 2);
            assert!(s.pending_rollback("abc").unwrap().is_none());
            assert_eq!(
                s.rollback_resolution("abc").unwrap(),
                Some(ResolvedRollback {
                    restore_id: "r".into(),
                    resolution: RollbackResolution::Reverted
                })
            );
            // Finalize: the undo record goes, the row stays.
            s.apply_rollback("abc", 4, 3, "r2", &tl(71)).unwrap();
            assert!(s.finalize_rollback("abc", "nope").unwrap().is_none());
            // A miss resolves nothing: the last resolution is still `r`'s.
            assert_eq!(
                s.rollback_resolution("abc").unwrap().unwrap().restore_id,
                "r"
            );
            assert!(s.finalize_rollback("abc", "r2").unwrap().is_some());
            assert!(s.pending_rollback("abc").unwrap().is_none());
            assert_eq!(s.row("abc").unwrap(), (4, 0));
            assert_eq!(
                s.rollback_resolution("abc").unwrap(),
                Some(ResolvedRollback {
                    restore_id: "r2".into(),
                    resolution: RollbackResolution::Delivered
                })
            );
            assert!(s.rollback_resolution("other-vm").unwrap().is_none());
        });
    }

    #[test]
    fn a_resolution_survives_a_reopen_of_the_file_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        {
            let s = FileVolumeStampStore::open(&path).unwrap();
            s.apply_rollback("abc", 2, 1, "r", &tl(72)).unwrap();
            s.finalize_rollback("abc", "r").unwrap().unwrap();
        }
        let s = FileVolumeStampStore::open(&path).unwrap();
        assert_eq!(
            s.rollback_resolution("abc").unwrap(),
            Some(ResolvedRollback {
                restore_id: "r".into(),
                resolution: RollbackResolution::Delivered
            })
        );
    }

    #[test]
    fn confirm_at_a_stale_epoch_is_refused_and_leaves_the_row() {
        for_each_store(|s| {
            s.apply_rollback("abc", 3, 1, "r", &tl(73)).unwrap();
            assert!(s.confirm_at("abc", 4, 0, &tl(73)).is_err());
            assert_eq!(s.row("abc").unwrap(), (3, 0));
            // Right epoch, but the v1 (zero-timeline) CAS: refused.
            assert!(s.confirm_at_epoch("abc", 4, 1).is_err());
            assert_eq!(s.row("abc").unwrap(), (3, 0));
            assert_eq!(s.confirm_at("abc", 4, 1, &tl(73)).unwrap(), 4);
        });
    }

    #[test]
    fn epochs_live_in_a_sibling_file_the_row_file_keeps_its_shape_and_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        {
            let s = FileVolumeStampStore::open(&path).unwrap();
            s.apply_rollback("abc", 4, 3, "r", &tl(74)).unwrap();
        }
        // The row file is exactly what an older binary decodes.
        let rows: HashMap<String, StampRow> =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(rows["abc"].confirmed, 4);
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["abc"].as_object().unwrap().len(), 2, "row not widened");
        assert!(dir.path().join("volume-stamps-token-epochs.json").exists());
        let s = FileVolumeStampStore::open(&path).unwrap();
        assert_eq!(s.token_epoch("abc").unwrap(), 3);
        assert_eq!(s.row("abc").unwrap(), (4, 0));
    }

    /// Timelines live in a THIRD sibling; the row file and the
    /// token-epochs file keep exactly the shapes an older binary decodes
    /// (`deny_unknown_fields`), and the timelines survive a restart.
    #[test]
    fn timelines_live_in_a_third_sibling_and_never_widen_the_other_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        {
            let s = FileVolumeStampStore::open(&path).unwrap();
            s.confirm("abc", 1).unwrap();
            s.apply_rollback("abc", 1, 1, "r", &tl(0x71)).unwrap();
            s.record_arm_timeline("abc", "r-next", &tl(0x72)).unwrap();
        }
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["abc"].as_object().unwrap().len(), 2, "row not widened");
        let side: StampSidecar = serde_json::from_slice(
            &fs::read(dir.path().join("volume-stamps-token-epochs.json")).unwrap(),
        )
        .expect("the epochs file still decodes with its strict pre-v2 type");
        assert_eq!(side.epochs["abc"], 1);
        assert!(dir.path().join("volume-stamps-timelines.json").exists());
        let s = FileVolumeStampStore::open(&path).unwrap();
        assert_eq!(s.timeline("abc").unwrap(), tl(0x71));
        assert_eq!(s.arm_timeline("abc", "r-next").unwrap(), Some(tl(0x72)));
        assert_eq!(s.arm_timeline("abc", "r-other").unwrap(), None);
        assert_eq!(s.timeline("never").unwrap(), ZERO_TIMELINE);
    }

    /// A corrupt timelines file refuses to open (never "every VM on the
    /// zero timeline", which would re-admit abandoned disks), and so does
    /// one that stores the zero timeline explicitly.
    #[test]
    fn a_corrupt_timelines_file_refuses_to_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        let tpath = dir.path().join("volume-stamps-timelines.json");
        for bad in [
            "{".to_string(),
            r#"{"current":{"abc":"zz"}}"#.to_string(),
            format!(r#"{{"current":{{"abc":"{}"}}}}"#, "AB".repeat(32)),
            format!(r#"{{"current":{{"abc":"{}"}}}}"#, "00".repeat(32)),
            r#"{"current":{},"extra":1}"#.to_string(),
        ] {
            fs::write(&tpath, &bad).unwrap();
            assert!(FileVolumeStampStore::open(&path).is_err(), "{bad}");
        }
    }

    /// The v2 confirm CAS: the token AND the timeline must be the VM's
    /// current ones; a refusal leaves the row untouched.
    #[test]
    fn a_confirm_naming_another_timeline_is_refused_and_leaves_the_row() {
        for_each_store(|s| {
            let k = stamp_mac_key(&seed());
            s.apply_rollback("abc", 3, 1, "r", &tl(0x73)).unwrap();
            let tok = stamp_token_timeline(&k, "abc", 4, 1, &tl(0x73));
            // Right token, wrong timeline named.
            assert!(confirm_timeline(s, &k, "abc", 4, &tok, &tl(0x74)).is_err());
            // A token minted for another timeline, naming the current one.
            let other = stamp_token_timeline(&k, "abc", 4, 1, &tl(0x74));
            assert!(confirm_timeline(s, &k, "abc", 4, &other, &tl(0x73)).is_err());
            // The store-level CAS alone refuses the wrong timeline too.
            assert!(s.confirm_at("abc", 4, 1, &tl(0x74)).is_err());
            assert_eq!(s.row("abc").unwrap(), (3, 0));
            assert_eq!(
                confirm_timeline(s, &k, "abc", 4, &tok, &tl(0x73)).unwrap(),
                4
            );
            // …and exactly value + 1.
            let skip = stamp_token_timeline(&k, "abc", 6, 1, &tl(0x73));
            assert!(confirm_timeline(s, &k, "abc", 6, &skip, &tl(0x73)).is_err());
            assert_eq!(s.get("abc").unwrap(), 4);
        });
    }

    /// Revert puts the REPLACED timeline back (the first one recorded,
    /// across a retry of the same restore id); the abandoned target is
    /// never current again. A rollback can never "move" to the zero or
    /// the current timeline.
    #[test]
    fn revert_restores_the_first_replaced_timeline_and_a_move_must_be_new() {
        for_each_store(|s| {
            s.apply_rollback("abc", 5, 1, "r", &tl(0x75)).unwrap();
            s.finalize_rollback("abc", "r").unwrap();
            assert_eq!(s.timeline("abc").unwrap(), tl(0x75));
            // A second rollback, applied twice (a retry), then reverted.
            s.apply_rollback("abc", 2, 2, "r2", &tl(0x76)).unwrap();
            s.apply_rollback("abc", 2, 3, "r2", &tl(0x77)).unwrap();
            assert_eq!(s.timeline("abc").unwrap(), tl(0x77));
            s.revert_rollback("abc", "r2").unwrap().unwrap();
            assert_eq!(
                s.timeline("abc").unwrap(),
                tl(0x75),
                "the FIRST replaced one"
            );
            assert_eq!(s.row("abc").unwrap(), (5, 0));
            // Moves that are not moves.
            assert!(s.apply_rollback("abc", 1, 4, "r3", &ZERO_TIMELINE).is_err());
            assert!(s.apply_rollback("abc", 1, 5, "r4", &tl(0x75)).is_err());
            assert_eq!(s.timeline("abc").unwrap(), tl(0x75));
            assert_eq!(s.row("abc").unwrap(), (5, 0));
        });
    }

    /// The checkpoint read takes the timeline in the same critical section.
    #[test]
    fn the_checkpoint_read_carries_the_timeline() {
        for_each_store(|s| {
            assert_eq!(s.checkpoint_read("abc").unwrap().3, ZERO_TIMELINE);
            s.apply_rollback("abc", 5, 1, "r", &tl(0x78)).unwrap();
            let (e, u, p, t) = s.checkpoint_read("abc").unwrap();
            assert_eq!((e, u, p.is_some(), t), (5, 0, true, tl(0x78)));
        });
    }

    /// Persist order is epoch FIRST: if the row write then fails, old
    /// tokens are already dead and the stamp is unchanged — never a
    /// lowered stamp under the old epoch.
    #[test]
    fn a_failed_row_write_after_the_epoch_leaves_the_stamp_unchanged_and_old_tokens_dead() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        let s = FileVolumeStampStore::open(&path).unwrap();
        for v in 1..=7 {
            s.confirm("abc", v).unwrap();
        }
        let blocker = dir.path().join(".volume-stamps.json.tmp");
        fs::create_dir(&blocker).unwrap();
        assert!(s.apply_rollback("abc", 5, 1, "r", &tl(75)).is_err());
        assert_eq!(s.get("abc").unwrap(), 7, "stamp NOT lowered");
        assert_eq!(s.token_epoch("abc").unwrap(), 1, "epoch already moved");
        fs::remove_dir(&blocker).unwrap();
        let k = stamp_mac_key(&seed());
        assert!(confirm(&s, &k, "abc", 8, &stamp_token(&k, "abc", 8)).is_err());
        let reopened = FileVolumeStampStore::open(&path).unwrap();
        assert_eq!(reopened.token_epoch("abc").unwrap(), 1);
        assert_eq!(reopened.get("abc").unwrap(), 7);
    }

    #[test]
    fn a_failed_epoch_write_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        let s = FileVolumeStampStore::open(&path).unwrap();
        s.confirm("abc", 1).unwrap();
        let blocker = dir.path().join(".volume-stamps-token-epochs.json.tmp");
        fs::create_dir(&blocker).unwrap();
        assert!(s.apply_rollback("abc", 0, 1, "r", &tl(76)).is_err());
        assert_eq!(s.token_epoch("abc").unwrap(), 0);
        assert_eq!(s.row("abc").unwrap(), (1, 0));
        // The timeline is written AFTER the epochs sidecar: it has not moved.
        assert_eq!(s.timeline("abc").unwrap(), ZERO_TIMELINE);
        drop(s);
        let s = FileVolumeStampStore::open(&path).unwrap();
        assert_eq!(s.timeline("abc").unwrap(), ZERO_TIMELINE);
    }

    /// S2 — `adopt_fresh_timeline`: only an UNCONFIRMED (`E = 0`) VM with
    /// no pending rollback moves, only to a new non-zero timeline; every
    /// refusal leaves the timeline as it was. After the move a confirm on
    /// the timeline it replaced is refused (the token of a lost response
    /// never lands), and one on the new timeline advances `E`.
    #[test]
    fn only_an_unconfirmed_vm_adopts_a_fresh_timeline() {
        for_each_store(|s| {
            let k = stamp_mac_key(&seed());
            // Refused: the zero timeline, and the current one.
            assert!(s.adopt_fresh_timeline("abc", &ZERO_TIMELINE).is_err());
            s.adopt_fresh_timeline("abc", &tl(0x81)).unwrap();
            assert_eq!(s.timeline("abc").unwrap(), tl(0x81));
            assert!(s.adopt_fresh_timeline("abc", &tl(0x81)).is_err());
            // A second E = 0 move (the first response was lost).
            s.adopt_fresh_timeline("abc", &tl(0x82)).unwrap();
            let lost = stamp_token_timeline(&k, "abc", 1, 0, &tl(0x81));
            assert!(confirm_timeline(s, &k, "abc", 1, &lost, &tl(0x81)).is_err());
            assert_eq!(
                s.row("abc").unwrap(),
                (0, 0),
                "the lost token moved nothing"
            );
            let live = stamp_token_timeline(&k, "abc", 1, 0, &tl(0x82));
            assert_eq!(
                confirm_timeline(s, &k, "abc", 1, &live, &tl(0x82)).unwrap(),
                1
            );
            // E = 1: a confirm landed — no fresh timeline any more.
            assert!(s.adopt_fresh_timeline("abc", &tl(0x83)).is_err());
            assert_eq!(s.timeline("abc").unwrap(), tl(0x82));
            // A pending rollback owns the timeline, even at E = 0.
            s.apply_rollback("rb", 0, 1, "r", &tl(0x84)).unwrap();
            assert!(s.adopt_fresh_timeline("rb", &tl(0x85)).is_err());
            assert_eq!(s.timeline("rb").unwrap(), tl(0x84));
        });
    }

    /// The fresh timeline is DURABLE when `adopt_fresh_timeline` returns:
    /// it survives a restart. A failed write refuses and changes nothing.
    #[test]
    fn a_fresh_timeline_survives_a_restart_and_a_failed_write_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        {
            let s = FileVolumeStampStore::open(&path).unwrap();
            s.adopt_fresh_timeline("abc", &tl(0x91)).unwrap();
        }
        let s = FileVolumeStampStore::open(&path).unwrap();
        assert_eq!(s.timeline("abc").unwrap(), tl(0x91));
        let blocker = dir.path().join(".volume-stamps-timelines.json.tmp");
        fs::create_dir(&blocker).unwrap();
        assert!(s.adopt_fresh_timeline("abc", &tl(0x92)).is_err());
        assert_eq!(s.timeline("abc").unwrap(), tl(0x91));
        fs::remove_dir(&blocker).unwrap();
        let s = FileVolumeStampStore::open(&path).unwrap();
        assert_eq!(s.timeline("abc").unwrap(), tl(0x91));
    }

    /// A failed TIMELINE write (after the epochs sidecar landed) leaves the
    /// stamp unchanged and a pending record whose revert is a no-op for the
    /// timeline — never a lowered stamp on the old timeline, never a moved
    /// timeline without its undo record.
    #[test]
    fn a_failed_timeline_write_leaves_the_stamp_and_the_timeline_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume-stamps.json");
        let s = FileVolumeStampStore::open(&path).unwrap();
        s.confirm("abc", 1).unwrap();
        let blocker = dir.path().join(".volume-stamps-timelines.json.tmp");
        fs::create_dir(&blocker).unwrap();
        assert!(s.apply_rollback("abc", 0, 1, "r", &tl(77)).is_err());
        assert_eq!(s.row("abc").unwrap(), (1, 0), "stamp unchanged");
        assert_eq!(s.timeline("abc").unwrap(), ZERO_TIMELINE);
        assert!(s.pending_rollback("abc").unwrap().is_some());
        fs::remove_dir(&blocker).unwrap();
        s.revert_rollback("abc", "r").unwrap().unwrap();
        assert_eq!(s.row("abc").unwrap(), (1, 0));
        assert_eq!(s.timeline("abc").unwrap(), ZERO_TIMELINE);
        assert!(s.pending_rollback("abc").unwrap().is_none());
    }
}
