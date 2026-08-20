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

use std::collections::HashMap;
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

/// Domain separator for the MAC key derived from the KBS signing seed.
const MAC_KEY_DOMAIN: &[u8] = b"HIPPIUS_KBS_VOLUME_STAMP_MAC_V1";
/// Domain separator for the token message itself.
const TOKEN_DOMAIN: &[u8] = b"HIPPIUS_KBS_VOLUME_STAMP_CONFIRM_V1";

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
}

/// File-backed store: a JSON map `{vm_id: StampRow}` written atomically
/// (tmp + fsync + rename) under a `Mutex`. Same atomicity contract and
/// the same rollback-on-persist-failure discipline as
/// [`crate::boot_counter::FileBootCounterStore`].
pub struct FileVolumeStampStore {
    path: PathBuf,
    cache: Mutex<HashMap<String, StampRow>>,
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
        Ok(Self {
            path,
            cache: Mutex::new(cache),
        })
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
        let parent = self
            .path
            .parent()
            .ok_or_else(|| KbsError::Vault("volume-stamp: no parent dir".into()))?;
        let tmp = parent.join(format!(
            ".{}.tmp",
            self.path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("volume-stamp"),
        ));
        let bytes = serde_json::to_vec(cache)
            .map_err(|e| KbsError::Vault(format!("volume-stamp encode: {e}")))?;
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| KbsError::Vault(format!("volume-stamp open tmp: {e}")))?;
            f.write_all(&bytes)
                .map_err(|e| KbsError::Vault(format!("volume-stamp write tmp: {e}")))?;
            f.sync_all()
                .map_err(|e| KbsError::Vault(format!("volume-stamp fsync tmp: {e}")))?;
        }
        fs::rename(&tmp, &self.path)
            .map_err(|e| KbsError::Vault(format!("volume-stamp rename: {e}")))?;
        if let Ok(parent) = OpenOptions::new().read(true).open(parent) {
            let _ = parent.sync_all();
        }
        Ok(())
    }
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
    let want = stamp_token(mac_key, vm_id, value);
    // ct_eq over equal-length slices; a length mismatch short-circuits
    // (the length of the expected token is public).
    let ok = presented_token.len() == want.len() && bool::from(presented_token.ct_eq(&want[..]));
    if !ok {
        return Err(KbsError::Policy(format!(
            "volume-stamp confirm: vm_id={vm_id} value={value} — bad or absent token, \
             fail closed (the expectation is UNCHANGED)"
        )));
    }
    store.confirm(vm_id, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; 32] {
        [7u8; 32]
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
}
