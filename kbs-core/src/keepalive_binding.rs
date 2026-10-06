//! Binds a `vm_id`'s keepalives to the guest the KBS RELEASED to.
//!
//! ## The hole this closes
//!
//! A keepalive proves "an allowlisted SEV-SNP guest is running", and its
//! `REPORT_DATA` names a `vm_id` — but the GUEST chooses `REPORT_DATA`.
//! The measurement check is allowlist membership, which every VM of a
//! golden image shares, and the report's CHIP_ID was never compared with
//! the VM's placement. So root inside ONE running allowlisted guest could
//! fetch nonces and mint valid KBS-signed live attestations for ANY other
//! `vm_id` — on any host. That fakes uptime (miner payments) and fakes
//! "N concurrent VMs" (capacity proof) from a single rented VM.
//!
//! ## The binding
//!
//! Every SEV-SNP report carries two values the guest cannot choose:
//! `CHIP_ID` (the host CPU) and `REPORT_ID` (assigned by the PSP firmware
//! when the guest is launched, constant for that guest's life, different
//! for every other guest). At every successful §20 release — first boot,
//! reboot, reboot-recovery relaunch, §25 destination — the KBS records
//! the `(chip_id, report_id)` of the guest it released the disk key to,
//! under the ticket's `vm_id`. A keepalive for that `vm_id` must then
//! come from exactly that guest. A different guest — even on the same
//! chip, even with the same image — has a different `REPORT_ID` and is
//! refused.
//!
//! ## Modes ([`BindingMode`])
//!
//! The per-VM record lives in the KBS state, which a KBS restart wipes
//! (see `kbs_restart_survivable`). A VM that booted before the restart
//! has no record until its next release, so the rollout needs a
//! transition mode:
//!
//! - `Off`: legacy — v1 bodies, no binding (the pre-rollout default).
//! - `Record`: v2 bodies. A recorded binding is ENFORCED. A VM with no
//!   record is served, and its body names the guest that asked
//!   (`BindingSource::FirstUse`), which proof consumers ignore. Nothing is
//!   pinned from a keepalive: a pin would let any guest that races a
//!   victim's `vm_id` after a restart lock the victim out until its next
//!   release.
//! - `Enforce`: v2 bodies; no record ⇒ refused.
//!
//! A mismatch against a record is refused in both `Record` and `Enforce`.
//!
//! ## Ordering
//!
//! A record is written after the release has committed, outside its
//! transaction, so two releases of one `vm_id` could record out of order.
//! Each record carries the release's position — `(vm_generation,
//! boot_counter)` as COMMITTED by the release and signed into its
//! response (never the counter the miner submitted), which the release
//! path only ever advances — and an older release never overwrites a
//! newer record.
//! A pre-counter guest (no `submitted_boot_counter`) releases at counter
//! `0` every time, so its same-generation releases tie and the last
//! record written wins; every current guest submits a counter.
//!
//! ## Surviving a KBS restart
//!
//! Exactly like the boot counter (`crate::boot_counter`), the records
//! have two ways to be lost and two recoveries:
//!
//! | lost by | recovery |
//! |---|---|
//! | process restart | [`FileKeepaliveBindings`] — `keepalive-bindings.json` in the state dir, written through on every change |
//! | pod restart (the state dir is an `emptyDir` in a Kata CVM, wiped) | [`KeepaliveBindingStore::seed`] from the admin listener, with the `(CHIP_ID, REPORT_ID)` vali last saw in a KBS-signed, release-bound live attestation |
//!
//! A seed only ever fills an EMPTY row (it never overwrites what a
//! release recorded) and carries position `(0, 0)`, so the guest's next
//! real release always supersedes it.
//!
//! ## A release whose guest cannot be recorded
//!
//! The record is written after the release commits. If that write fails
//! (the report does not parse, the disk write fails), the record on file
//! still names the PREVIOUS guest — which is no longer the one the KBS
//! released to. So the VM is poisoned ([`KeepaliveBindingStore::poison`]):
//! the stale record is dropped and every keepalive for the VM is refused,
//! in `Record` and `Enforce` alike. The tombstone carries the failed
//! release's position `(vm_generation, boot_counter)`; only a release at
//! or after it clears the poison (a delayed record from an OLDER release
//! is refused and leaves the VM poisoned). A seed never clears it: after
//! a failed record the only guest vali could vouch for is the old one,
//! since the new guest's keepalives were refused. A tombstone written
//! without a position (the round-3 file format) is read as
//! [`UNORDERED_TOMBSTONE`] and never lifted except by a pod restart
//! wiping the state dir. When the signed response itself cannot be
//! verified there is no trustworthy `vm_id` to poison; that failure is
//! audited only (it is unreachable in practice — the KBS verifies a
//! response it signed a moment earlier).
//!
//! ## Accepted residuals
//!
//! - A keepalive that has already passed the binding check when a new
//!   release commits can still mint ONE more attestation for the old
//!   guest. The window is a single in-flight request; the next keepalive
//!   sees the new record.
//! - A pre-counter legacy guest releases at `(generation, 0)` every time,
//!   so its same-generation releases tie; a stalled record from an older
//!   release can then overwrite a newer one. Every current guest submits
//!   a boot counter, so this only affects legacy images.
//! - A tombstone whose write FAILED lives in memory only: a process
//!   restart before any later successful write reloads the previous
//!   on-disk record, and the previous guest is bound again. The failure
//!   is surfaced loudly (`poison` returns an error that says the tombstone
//!   is NOT durable, and the transport audits it).

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use hippius_types::live_attestation::{BindingSource, CHIP_ID_LEN, REPORT_ID_LEN};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;

use crate::error::{KbsError, Result};

/// `enforce` mode's post-restart grace window, evaluated for one request.
///
/// A pod replacement wipes the binding records (the Kata CVM state dir),
/// so until `vali_kbs_recover` re-seeds them every running VM has NO
/// record and strict `enforce` would refuse its keepalives. Inside the
/// window, and ONLY for a VM with no record, `enforce` serves the
/// requesting guest as `first-use` (exactly `record` mode's answer). A VM
/// WITH a record — released or re-seeded — is enforced strictly
/// whatever the window says, so the window never weakens a binding.
///
/// The window is counted from the KBS state EPOCH ([`grace_epoch_start`]),
/// not from process start: a crash-looping KBS keeps its state dir and
/// therefore its epoch, and cannot reopen the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EnforceGrace {
    /// When the window closes. `None` ⇒ no window (strict enforce).
    pub closes_at_unix: Option<u64>,
    /// The request's own clock.
    pub now_unix: u64,
}

impl EnforceGrace {
    pub fn is_open(&self) -> bool {
        self.closes_at_unix.is_some_and(|c| self.now_unix < c)
    }
}

/// File (in the KBS state dir) holding the unix second this state dir
/// was first used by a KBS process — the pod-replacement epoch.
pub const GRACE_EPOCH_FILE: &str = "keepalive-grace-epoch";

/// The binding records' file name in the KBS state dir.
pub const BINDINGS_FILE: &str = "keepalive-bindings.json";

/// The state epoch: read [`GRACE_EPOCH_FILE`] if this state dir has one,
/// else stamp it with `now_unix` (a fresh state dir IS a new pod — the
/// Kata CVM wipes it on replacement) and return that. A process restart
/// inside the same pod finds the file and gets the ORIGINAL epoch back.
/// A corrupt file is an error: refusing to start beats guessing an epoch
/// that could reopen the window.
pub fn grace_epoch_start(state_dir: &std::path::Path, now_unix: u64) -> Result<u64> {
    let path = state_dir.join(GRACE_EPOCH_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => text.trim().parse::<u64>().map_err(|e| {
            KbsError::Vault(format!(
                "{GRACE_EPOCH_FILE} is corrupt ({e}): refusing to guess"
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Only a state dir with NO binding records either is fresh (a
            // pod replacement wipes both). Records without an epoch file —
            // the epoch deleted, or a state dir from before this code —
            // is NOT a new pod: stamp epoch 0, closing the window for good
            // on this state dir rather than opening a new one.
            let epoch = if state_dir.join(BINDINGS_FILE).exists() {
                0
            } else {
                now_unix
            };
            crate::boot_counter::FileBootCounterStore::atomic_write(
                &path,
                epoch.to_string().as_bytes(),
                GRACE_EPOCH_FILE,
            )?;
            Ok(epoch)
        }
        Err(e) => Err(KbsError::Vault(format!("{GRACE_EPOCH_FILE} read: {e}"))),
    }
}

/// The attested guest identity of one SEV-SNP report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestIdentity {
    pub chip_id: [u8; CHIP_ID_LEN],
    pub report_id: [u8; REPORT_ID_LEN],
}

/// The guest a keepalive body is bound to, and where that came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    pub guest: GuestIdentity,
    pub source: BindingSource,
}

/// Where a release sits in its VM's history: `(vm_generation,
/// boot_counter)`, compared lexicographically. A release without a
/// submitted counter (a pre-counter guest) is counter `0`.
pub type ReleaseOrder = (u64, u64);

/// A release-time record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseRecord {
    pub guest: GuestIdentity,
    pub order: ReleaseOrder,
}

/// How keepalives are bound (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BindingMode {
    #[default]
    Off,
    Record,
    Enforce,
}

impl BindingMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(BindingMode::Off),
            "record" => Some(BindingMode::Record),
            "enforce" => Some(BindingMode::Enforce),
            _ => None,
        }
    }
}

/// Read the guest identity out of a raw SNP report.
///
/// Call it ONLY on bytes the [`crate::snp::AttestationVerifier`] has
/// already verified in the same request: this parses, it does not
/// verify. An all-zero `REPORT_ID` is refused — it would bind nothing.
pub fn guest_identity(raw_snp_report: &[u8]) -> Result<GuestIdentity> {
    let report = AttestationReport::from_bytes(raw_snp_report)
        .map_err(|e| KbsError::Attestation(format!("SNP report parse: {e}")))?;
    if report.report_id.iter().all(|&b| b == 0) {
        return Err(KbsError::Attestation(
            "SNP report carries no REPORT_ID".into(),
        ));
    }
    Ok(GuestIdentity {
        chip_id: report.chip_id,
        report_id: report.report_id,
    })
}

/// The position a seeded record carries: before every real release, so
/// the guest's next release always supersedes it.
pub const SEED_ORDER: ReleaseOrder = (0, 0);

/// Outcome of [`KeepaliveBindingStore::seed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedOutcome {
    /// The row was empty; the guest is now on record at [`SEED_ORDER`].
    Seeded,
    /// A record already names this SAME guest (a retried seed, or the
    /// guest's own release got there first). Nothing was written.
    AlreadyMatching,
    /// A record names a DIFFERENT guest. Nothing was written.
    Conflict,
    /// The VM is poisoned (a release committed but its guest could not
    /// be recorded). Nothing was written: the only guest vali could vouch
    /// for is the OLD one — the new guest's keepalives were refused, so
    /// there are no samples of it — so a seed must never clear poison.
    /// Only a real release at or after the tombstone's position does.
    Poisoned,
}

/// Position assumed for a tombstone written without one (the round-3
/// file format): no real release can be at or after it, so it is never
/// cleared by a release or a seed — only by a pod restart wiping the
/// state dir. The most conservative reading: that format was never
/// deployed, and a tombstone we cannot place must not be lifted by a
/// release that may be the stale one.
pub const UNORDERED_TOMBSTONE: ReleaseOrder = (u64::MAX, u64::MAX);

/// Per-`vm_id` release records.
pub trait KeepaliveBindingStore: Send + Sync {
    fn get(&self, vm_id: &str) -> Result<Option<ReleaseRecord>>;
    /// Record `record` unless the one on file is from a LATER release, or
    /// the VM is poisoned at a LATER release than `record` (a delayed
    /// older record must not lift the poison). Returns whether `record`
    /// is now the one on file; `false` ⇒ nothing written. Must be atomic
    /// (compare and write under one lock). A write clears the poison mark
    /// — only ever at or after the tombstone's position (`>=`, so a
    /// pre-counter guest at `(g, 0)` is not blocked for good).
    fn put_if_newer(&self, vm_id: &str, record: ReleaseRecord) -> Result<bool>;
    /// Re-establish a record a pod restart wiped (admin listener only).
    /// Fills an EMPTY row at [`SEED_ORDER`]; never overwrites a record.
    /// An all-zero `CHIP_ID` or `REPORT_ID` is refused — it binds nothing.
    /// A poisoned VM is refused ([`SeedOutcome::Poisoned`]).
    fn seed(&self, vm_id: &str, guest: GuestIdentity) -> Result<SeedOutcome>;
    /// A release for `vm_id` committed but its guest could not be
    /// recorded: drop the (now stale) record and mark the VM so its
    /// keepalives are refused until a record is written again. The file
    /// store makes the mark a durable tombstone in the same atomic write
    /// that drops the record; the in-memory store keeps it in memory.
    ///
    /// `order` is the position of the release that failed to record; a
    /// later poison keeps the later position.
    ///
    /// Returns an error when the mark could not be made durable (the file
    /// store's write failed); the VM is still refused in this process.
    fn poison(&self, vm_id: &str, order: ReleaseOrder) -> Result<()>;
    fn is_poisoned(&self, vm_id: &str) -> Result<bool>;
    /// The guest the VM's record named before a later release recorded
    /// another one (see `Rows::previous`).
    fn previous(&self, vm_id: &str) -> Result<Option<GuestIdentity>>;
    /// Poison mark, record and previous guest, read atomically.
    fn lookup(&self, vm_id: &str) -> Result<Lookup>;
}

fn refuse_unbound(guest: &GuestIdentity) -> Result<()> {
    if guest.report_id.iter().all(|&b| b == 0) {
        return Err(KbsError::Attestation(
            "a keepalive binding needs a non-zero REPORT_ID".into(),
        ));
    }
    if guest.chip_id.iter().all(|&b| b == 0) {
        return Err(KbsError::Attestation(
            "a keepalive binding needs a non-zero CHIP_ID".into(),
        ));
    }
    Ok(())
}

/// What both stores hold under their one lock.
#[derive(Default)]
struct Rows {
    records: HashMap<String, ReleaseRecord>,
    /// vm_id → the position of the release that failed to record.
    poisoned: HashMap<String, ReleaseOrder>,
    /// vm_id → the guest the record named before a later release recorded
    /// ANOTHER guest. A keepalive from it is the VM's own superseded guest
    /// still running (its REPORT_ID is the PSP's, released to once for this
    /// vm_id): refused with a reason a T4 detector can trust
    /// ([`SUPERSEDED_GUEST`]), unlike a foreign guest's.
    previous: HashMap<String, GuestIdentity>,
}

/// Everything `check_keepalive` reads about one vm_id, read under ONE
/// lock: a poison landing between separate reads could otherwise make a
/// mismatching guest look like "no record" (first-use).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lookup {
    pub poisoned: bool,
    pub record: Option<ReleaseRecord>,
    pub previous: Option<GuestIdentity>,
}

impl Rows {
    fn lookup(&self, vm_id: &str) -> Lookup {
        Lookup {
            poisoned: self.poisoned.contains_key(vm_id),
            record: self.records.get(vm_id).copied(),
            previous: self.previous.get(vm_id).copied(),
        }
    }
}

/// The refusal reason of a keepalive from the guest released for the VM
/// BEFORE its current one.
pub const SUPERSEDED_GUEST: &str = "superseded-guest";

impl Rows {
    /// May a record at `order` be written for `vm_id`? Not over a record
    /// from a later release, and not under a tombstone from a later one.
    /// An [`UNORDERED_TOMBSTONE`] admits nothing, not even a record at
    /// its own (representable) position.
    fn may_write(&self, vm_id: &str, order: ReleaseOrder) -> bool {
        let older_than_record = self.records.get(vm_id).is_some_and(|r| r.order > order);
        let under_tombstone = self
            .poisoned
            .get(vm_id)
            .is_some_and(|t| *t == UNORDERED_TOMBSTONE || *t > order);
        !older_than_record && !under_tombstone
    }

    /// Poison `vm_id` for the release at `order`. A record from a LATER
    /// release already on file wins: that release recorded its guest, so
    /// a delayed poison from an earlier one must not erase it. Returns
    /// whether anything changed.
    fn mark_poisoned(&mut self, vm_id: &str, order: ReleaseOrder) -> bool {
        if self.records.get(vm_id).is_some_and(|r| r.order > order) {
            return false;
        }
        // The dropped record's guest is the one a later release replaces:
        // it becomes the previous guest, as a recorded replacement would.
        if let Some(dropped) = self.records.remove(vm_id) {
            self.previous.insert(vm_id.to_string(), dropped.guest);
        }
        let slot = self.poisoned.entry(vm_id.to_string()).or_insert(order);
        *slot = (*slot).max(order);
        true
    }

    /// Write `record`, remembering the guest it replaces when that is
    /// another one.
    fn insert_record(&mut self, vm_id: &str, record: ReleaseRecord) -> Option<ReleaseRecord> {
        let replaced = self.records.insert(vm_id.to_string(), record);
        if let Some(old) = replaced {
            if old.guest != record.guest {
                self.previous.insert(vm_id.to_string(), old.guest);
            }
        }
        replaced
    }

    fn seed_outcome(&self, vm_id: &str, guest: &GuestIdentity) -> Option<SeedOutcome> {
        self.records.get(vm_id).map(|on_file| {
            if on_file.guest == *guest {
                SeedOutcome::AlreadyMatching
            } else {
                SeedOutcome::Conflict
            }
        })
    }
}

/// In-memory store. The KBS's other per-VM keepalive state (the
/// live-attestation chain) is in-memory too; a restart loses both, which
/// is exactly what [`BindingMode::Record`] exists to survive.
#[derive(Default)]
pub struct InMemoryKeepaliveBindings {
    rows: Mutex<Rows>,
}

impl KeepaliveBindingStore for InMemoryKeepaliveBindings {
    fn get(&self, vm_id: &str) -> Result<Option<ReleaseRecord>> {
        let g = self.rows.lock().map_err(|_| KbsError::Replay)?;
        Ok(g.records.get(vm_id).copied())
    }

    fn put_if_newer(&self, vm_id: &str, record: ReleaseRecord) -> Result<bool> {
        let mut g = self.rows.lock().map_err(|_| KbsError::Replay)?;
        if !g.may_write(vm_id, record.order) {
            return Ok(false);
        }
        g.insert_record(vm_id, record);
        g.poisoned.remove(vm_id);
        Ok(true)
    }

    fn seed(&self, vm_id: &str, guest: GuestIdentity) -> Result<SeedOutcome> {
        refuse_unbound(&guest)?;
        let mut g = self.rows.lock().map_err(|_| KbsError::Replay)?;
        if g.poisoned.contains_key(vm_id) {
            return Ok(SeedOutcome::Poisoned);
        }
        if let Some(outcome) = g.seed_outcome(vm_id, &guest) {
            return Ok(outcome);
        }
        g.records.insert(
            vm_id.to_string(),
            ReleaseRecord {
                guest,
                order: SEED_ORDER,
            },
        );
        Ok(SeedOutcome::Seeded)
    }

    fn poison(&self, vm_id: &str, order: ReleaseOrder) -> Result<()> {
        let mut g = self.rows.lock().map_err(|_| KbsError::Replay)?;
        g.mark_poisoned(vm_id, order);
        Ok(())
    }

    fn is_poisoned(&self, vm_id: &str) -> Result<bool> {
        let g = self.rows.lock().map_err(|_| KbsError::Replay)?;
        Ok(g.poisoned.contains_key(vm_id))
    }

    fn previous(&self, vm_id: &str) -> Result<Option<GuestIdentity>> {
        let g = self.rows.lock().map_err(|_| KbsError::Replay)?;
        Ok(g.previous.get(vm_id).copied())
    }

    fn lookup(&self, vm_id: &str) -> Result<Lookup> {
        let g = self.rows.lock().map_err(|_| KbsError::Replay)?;
        Ok(g.lookup(vm_id))
    }
}

/// One value of `keepalive-bindings.json` (keyed by `vm_id`): a record,
/// or a poison tombstone `{"poisoned": true}`. Untagged, so a file with
/// records only — every file written before tombstones existed — reads
/// unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum EntryOnDisk {
    Record(RecordOnDisk),
    Poisoned(TombstoneOnDisk),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TombstoneOnDisk {
    poisoned: bool,
    /// The previous guest (`Rows::previous`), kept across a poison.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_chip_id_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_report_id_hex: Option<String>,
    /// The failed release's position. Absent in the round-3 format ⇒
    /// [`UNORDERED_TOMBSTONE`]. Both present or both absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot_counter: Option<u64>,
}

impl TombstoneOnDisk {
    fn at(order: ReleaseOrder, previous: Option<&GuestIdentity>) -> Self {
        Self {
            poisoned: true,
            previous_chip_id_hex: previous.map(|p| hex::encode(p.chip_id)),
            previous_report_id_hex: previous.map(|p| hex::encode(p.report_id)),
            generation: Some(order.0),
            boot_counter: Some(order.1),
        }
    }

    fn order(&self, vm: &str) -> Result<ReleaseOrder> {
        if !self.poisoned {
            return Err(KbsError::Vault(format!(
                "keepalive-binding corrupt row: vm_id={vm} poisoned=false"
            )));
        }
        match (self.generation, self.boot_counter) {
            (Some(g), Some(c)) => Ok((g, c)),
            (None, None) => Ok(UNORDERED_TOMBSTONE),
            _ => Err(KbsError::Vault(format!(
                "keepalive-binding corrupt row: vm_id={vm} tombstone has half a position"
            ))),
        }
    }
}

/// One record row of `keepalive-bindings.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordOnDisk {
    chip_id_hex: String,
    report_id_hex: String,
    generation: u64,
    boot_counter: u64,
    /// The previous guest (`Rows::previous`). Absent in files written
    /// before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_chip_id_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_report_id_hex: Option<String>,
}

impl RecordOnDisk {
    fn from_record(r: &ReleaseRecord, previous: Option<&GuestIdentity>) -> Self {
        Self {
            chip_id_hex: hex::encode(r.guest.chip_id),
            report_id_hex: hex::encode(r.guest.report_id),
            generation: r.order.0,
            boot_counter: r.order.1,
            previous_chip_id_hex: previous.map(|p| hex::encode(p.chip_id)),
            previous_report_id_hex: previous.map(|p| hex::encode(p.report_id)),
        }
    }

    fn identity(chip_hex: &str, report_hex: &str) -> Result<GuestIdentity> {
        let decode = |what: &str, h: &str| {
            hex::decode(h).map_err(|e| KbsError::Vault(format!("keepalive-binding {what}: {e}")))
        };
        let chip_id: [u8; CHIP_ID_LEN] = decode("chip_id", chip_hex)?
            .try_into()
            .map_err(|_| KbsError::Vault("keepalive-binding chip_id length".into()))?;
        let report_id: [u8; REPORT_ID_LEN] = decode("report_id", report_hex)?
            .try_into()
            .map_err(|_| KbsError::Vault("keepalive-binding report_id length".into()))?;
        Ok(GuestIdentity { chip_id, report_id })
    }

    fn previous_guest(&self) -> Result<Option<GuestIdentity>> {
        Self::previous_of(&self.previous_chip_id_hex, &self.previous_report_id_hex)
    }

    fn previous_of(
        chip: &Option<String>,
        report: &Option<String>,
    ) -> Result<Option<GuestIdentity>> {
        match (chip, report) {
            (None, None) => Ok(None),
            (Some(c), Some(r)) => {
                let guest = Self::identity(c, r)?;
                refuse_unbound(&guest)
                    .map_err(|e| KbsError::Vault(format!("keepalive-binding corrupt row: {e}")))?;
                Ok(Some(guest))
            }
            _ => Err(KbsError::Vault(
                "keepalive-binding corrupt row: half a previous guest".into(),
            )),
        }
    }

    fn to_record(&self) -> Result<ReleaseRecord> {
        let guest = Self::identity(&self.chip_id_hex, &self.report_id_hex)?;
        // Nothing legitimate ever wrote an all-zero id (both writers
        // refuse one), so one on disk is corruption, not a record.
        refuse_unbound(&guest)
            .map_err(|e| KbsError::Vault(format!("keepalive-binding corrupt row: {e}")))?;
        Ok(ReleaseRecord {
            guest,
            order: (self.generation, self.boot_counter),
        })
    }
}

/// File-backed store: `keepalive-bindings.json` in the KBS state dir,
/// written through (tmp + fsync + rename) on every change, so a PROCESS
/// restart keeps every record. A POD restart wipes the state dir; that
/// is what [`KeepaliveBindingStore::seed`] recovers from. Poison marks
/// are durable tombstones in the same file, written in the same atomic
/// write that drops (or replaces) the VM's record, so a restarted process
/// keeps refusing a poisoned VM.
pub struct FileKeepaliveBindings {
    path: PathBuf,
    cache: Mutex<Rows>,
}

impl FileKeepaliveBindings {
    /// Load the file. Missing ⇒ empty store; corrupt ⇒ refuse to open
    /// (a set we cannot vouch for must not silently become "nothing on
    /// record", which `Record` mode would serve as first-use).
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let mut rows = Rows::default();
        match fs::read(&path) {
            Ok(bytes) => {
                let entries = serde_json::from_slice::<HashMap<String, EntryOnDisk>>(&bytes)
                    .map_err(|e| KbsError::Vault(format!("keepalive-binding decode: {e}")))?;
                for (vm, entry) in entries {
                    match entry {
                        EntryOnDisk::Record(r) => {
                            if let Some(p) = r.previous_guest()? {
                                rows.previous.insert(vm.clone(), p);
                            }
                            rows.records.insert(vm, r.to_record()?);
                        }
                        EntryOnDisk::Poisoned(t) => {
                            let order = t.order(&vm)?;
                            if let Some(p) = RecordOnDisk::previous_of(
                                &t.previous_chip_id_hex,
                                &t.previous_report_id_hex,
                            )? {
                                rows.previous.insert(vm.clone(), p);
                            }
                            rows.poisoned.insert(vm, order);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(KbsError::Vault(format!("keepalive-binding read: {e}"))),
        }
        Ok(Self {
            path,
            cache: Mutex::new(rows),
        })
    }

    /// Write every record AND every tombstone — one atomic file, so a
    /// record and the tombstone it replaces (or that replaces it) can
    /// never be half-written.
    fn persist_locked(&self, rows: &Rows) -> Result<()> {
        let mut on_disk: HashMap<&String, EntryOnDisk> = rows
            .records
            .iter()
            .map(|(vm, r)| {
                (
                    vm,
                    EntryOnDisk::Record(RecordOnDisk::from_record(r, rows.previous.get(vm))),
                )
            })
            .collect();
        for (vm, order) in &rows.poisoned {
            on_disk.insert(
                vm,
                EntryOnDisk::Poisoned(TombstoneOnDisk::at(*order, rows.previous.get(vm))),
            );
        }
        let bytes = serde_json::to_vec(&on_disk)
            .map_err(|e| KbsError::Vault(format!("keepalive-binding encode: {e}")))?;
        crate::boot_counter::FileBootCounterStore::atomic_write(
            &self.path,
            &bytes,
            "keepalive-binding",
        )
    }

    /// Write `vm_id -> record` through to disk, clearing the VM's
    /// tombstone in the SAME write. On failure the cache is restored
    /// (record and tombstone), so the cache and the file stay identical —
    /// the same invariant as the boot counter's `insert_and_persist_locked`.
    fn insert_and_persist_locked(
        &self,
        rows: &mut Rows,
        vm_id: &str,
        record: ReleaseRecord,
    ) -> Result<()> {
        let previous_guest = rows.previous.get(vm_id).copied();
        let previous = rows.insert_record(vm_id, record);
        let was_poisoned = rows.poisoned.remove(vm_id);
        if let Err(e) = self.persist_locked(rows) {
            match previous {
                Some(p) => rows.records.insert(vm_id.to_string(), p),
                None => rows.records.remove(vm_id),
            };
            match previous_guest {
                Some(g) => rows.previous.insert(vm_id.to_string(), g),
                None => rows.previous.remove(vm_id),
            };
            if let Some(order) = was_poisoned {
                rows.poisoned.insert(vm_id.to_string(), order);
            }
            return Err(e);
        }
        Ok(())
    }
}

impl KeepaliveBindingStore for FileKeepaliveBindings {
    fn get(&self, vm_id: &str) -> Result<Option<ReleaseRecord>> {
        let g = self.cache.lock().map_err(|_| KbsError::Replay)?;
        Ok(g.records.get(vm_id).copied())
    }

    fn put_if_newer(&self, vm_id: &str, record: ReleaseRecord) -> Result<bool> {
        let mut g = self.cache.lock().map_err(|_| KbsError::Replay)?;
        if !g.may_write(vm_id, record.order) {
            return Ok(false);
        }
        self.insert_and_persist_locked(&mut g, vm_id, record)?;
        Ok(true)
    }

    fn seed(&self, vm_id: &str, guest: GuestIdentity) -> Result<SeedOutcome> {
        refuse_unbound(&guest)?;
        let mut g = self.cache.lock().map_err(|_| KbsError::Replay)?;
        if g.poisoned.contains_key(vm_id) {
            return Ok(SeedOutcome::Poisoned);
        }
        if let Some(outcome) = g.seed_outcome(vm_id, &guest) {
            return Ok(outcome);
        }
        self.insert_and_persist_locked(
            &mut g,
            vm_id,
            ReleaseRecord {
                guest,
                order: SEED_ORDER,
            },
        )?;
        Ok(SeedOutcome::Seeded)
    }

    fn poison(&self, vm_id: &str, order: ReleaseOrder) -> Result<()> {
        let mut g = self.cache.lock().map_err(|_| KbsError::Replay)?;
        // In memory first, and kept whatever the disk does: this process
        // refuses the VM from now on. A later release already recorded ⇒
        // nothing to poison, nothing to write.
        if !g.mark_poisoned(vm_id, order) {
            return Ok(());
        }
        // One atomic write replaces the record with the tombstone. If it
        // fails, say so: the refusal then holds only until a restart,
        // which would reload the stale record.
        self.persist_locked(&g).map_err(|e| {
            KbsError::Vault(format!(
                "keepalive-binding tombstone NOT durable for vm_id={vm_id} (refused in this \
                 process only): {e}"
            ))
        })
    }

    fn is_poisoned(&self, vm_id: &str) -> Result<bool> {
        let g = self.cache.lock().map_err(|_| KbsError::Replay)?;
        Ok(g.poisoned.contains_key(vm_id))
    }

    fn previous(&self, vm_id: &str) -> Result<Option<GuestIdentity>> {
        let g = self.cache.lock().map_err(|_| KbsError::Replay)?;
        Ok(g.previous.get(vm_id).copied())
    }

    fn lookup(&self, vm_id: &str) -> Result<Lookup> {
        let g = self.cache.lock().map_err(|_| KbsError::Replay)?;
        Ok(g.lookup(vm_id))
    }
}

/// Record the release-time guest for `vm_id` from the report the release
/// just verified. Returns whether it is now the record on file.
pub fn record_release(
    store: &dyn KeepaliveBindingStore,
    vm_id: &str,
    order: ReleaseOrder,
    raw_snp_report: &[u8],
) -> Result<bool> {
    let guest = guest_identity(raw_snp_report)?;
    store.put_if_newer(vm_id, ReleaseRecord { guest, order })
}

/// The transport's post-release step: read the `vm_id`, generation and
/// COMMITTED boot counter out of the response the release just signed
/// (verified under the KBS's own key), and record the guest it released
/// to. Returns the `vm_id`.
pub fn record_after_release(
    store: &dyn KeepaliveBindingStore,
    kbs_verifying_key: &ed25519_dalek::VerifyingKey,
    signed: &hippius_types::release::SignedResponse,
    raw_snp_report: &[u8],
) -> Result<String> {
    // An unverifiable response names no vm_id we can trust, so there is
    // nothing to invalidate: the error is returned (and audited by the
    // caller) and every record stays as it was. Unreachable in practice —
    // the KBS verifies a response it signed a moment earlier.
    let resp = crate::crypto::verify_response(kbs_verifying_key, signed)?;
    let order = (resp.vm_generation, resp.boot_counter);
    if let Err(e) = record_release(store, &resp.vm_id, order, raw_snp_report) {
        // The release committed to a NEW guest we could not record. The
        // old record now names a guest that is no longer the one released
        // to — it must not stay authoritative. Poison the VM: its
        // keepalives are refused until a record is written again.
        if let Err(p) = store.poison(&resp.vm_id, order) {
            return Err(KbsError::Vault(format!("{e}; and {p}")));
        }
        return Err(e);
    }
    Ok(resp.vm_id)
}

/// The keepalive-side check. Returns the binding the signed body must
/// state, or refuses. `Off` never gets here (the caller skips it).
pub fn check_keepalive(
    store: &dyn KeepaliveBindingStore,
    mode: BindingMode,
    vm_id: &str,
    raw_snp_report: &[u8],
    grace: EnforceGrace,
) -> Result<Binding> {
    let presented = guest_identity(raw_snp_report)?;
    let row = store.lookup(vm_id)?;
    if row.poisoned {
        return Err(KbsError::Attestation(
            "keepalive binding for this vm_id was invalidated: its last release could not be \
             recorded"
                .into(),
        ));
    }
    let Some(on_record) = row.record else {
        return match mode {
            BindingMode::Record => Ok(Binding {
                guest: presented,
                source: BindingSource::FirstUse,
            }),
            BindingMode::Enforce if grace.is_open() => {
                // Only a VM with NO record reaches here; a bound VM is
                // enforced strictly above/below whatever the window says.
                // Logged so the recovery re-seed can be cross-checked.
                eprintln!(
                    "kbs-core::keepalive_binding: WARN first-use binding admitted in the \
                     post-restart grace window (later checks may still refuse it): vm_id={vm_id} \
                     chip_id={} report_id={} (window closes at {})",
                    hex::encode(presented.chip_id),
                    hex::encode(presented.report_id),
                    grace.closes_at_unix.unwrap_or(0),
                );
                Ok(Binding {
                    guest: presented,
                    source: BindingSource::FirstUse,
                })
            }
            BindingMode::Enforce | BindingMode::Off => Err(KbsError::Attestation(
                "no released guest on record for this vm_id".into(),
            )),
        };
    };
    // Constant-time is not needed (both values are public report
    // fields), but a single comparison of both keeps the refusal shape
    // identical whichever half differs.
    if on_record.guest != presented {
        if row.previous == Some(presented) {
            return Err(KbsError::Attestation(format!(
                "{SUPERSEDED_GUEST}: the guest released for this vm_id before its current one \
                 still runs"
            )));
        }
        return Err(KbsError::Attestation(
            "keepalive guest is not the guest released for this vm_id".into(),
        ));
    }
    Ok(Binding {
        guest: on_record.guest,
        source: BindingSource::Release,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A syntactically valid SNP report with the given identity (tests
    /// only — the verifier is mocked, so nothing checks its signature).
    pub(crate) fn raw_report(chip: u8, report: u8) -> Vec<u8> {
        use sev::parser::Encoder;
        let r = AttestationReport {
            version: 4,
            chip_id: [chip; CHIP_ID_LEN],
            report_id: [report; REPORT_ID_LEN],
            cpuid_fam_id: Some(0x1A),
            cpuid_mod_id: Some(0x02),
            cpuid_step: Some(0x01),
            ..AttestationReport::default()
        };
        let mut buf = Vec::new();
        r.encode(&mut buf, ()).expect("serialise report");
        buf
    }

    #[test]
    fn identity_is_read_from_the_report() {
        let id = guest_identity(&raw_report(0x11, 0x22)).unwrap();
        assert_eq!(id.chip_id, [0x11; CHIP_ID_LEN]);
        assert_eq!(id.report_id, [0x22; REPORT_ID_LEN]);
    }

    #[test]
    fn a_report_without_a_report_id_binds_nothing() {
        assert!(guest_identity(&raw_report(0x11, 0x00)).is_err());
        assert!(guest_identity(b"not a report").is_err());
    }

    #[test]
    fn the_released_guest_passes_and_any_other_guest_is_refused() {
        let store = InMemoryKeepaliveBindings::default();
        record_release(&store, "vm-a", (1, 1), &raw_report(0x11, 0x22)).unwrap();
        for mode in [BindingMode::Record, BindingMode::Enforce] {
            let b = check_keepalive(
                &store,
                mode,
                "vm-a",
                &raw_report(0x11, 0x22),
                EnforceGrace::default(),
            )
            .unwrap();
            assert_eq!(b.source, BindingSource::Release);
            // THE attack: another guest on the SAME chip minting for vm-a.
            assert!(check_keepalive(
                &store,
                mode,
                "vm-a",
                &raw_report(0x11, 0x33),
                EnforceGrace::default()
            )
            .is_err());
            // Same REPORT_ID on another chip (impossible in practice) too.
            assert!(check_keepalive(
                &store,
                mode,
                "vm-a",
                &raw_report(0x44, 0x22),
                EnforceGrace::default()
            )
            .is_err());
        }
    }

    #[test]
    fn a_new_release_moves_the_binding() {
        let store = InMemoryKeepaliveBindings::default();
        record_release(&store, "vm-a", (1, 1), &raw_report(0x11, 0x22)).unwrap();
        // reboot (next counter) / §25 (next generation)
        record_release(&store, "vm-a", (1, 2), &raw_report(0x55, 0x66)).unwrap();
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-a",
            &raw_report(0x11, 0x22),
            EnforceGrace::default()
        )
        .is_err());
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-a",
            &raw_report(0x55, 0x66),
            EnforceGrace::default()
        )
        .is_ok());
        record_release(&store, "vm-a", (2, 0), &raw_report(0x77, 0x88)).unwrap();
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-a",
            &raw_report(0x77, 0x88),
            EnforceGrace::default()
        )
        .is_ok());
    }

    #[test]
    fn an_older_release_recorded_late_does_not_win() {
        let store = InMemoryKeepaliveBindings::default();
        assert!(record_release(&store, "vm-a", (1, 3), &raw_report(0x11, 0x33)).unwrap());
        // Release (1,2) committed first but its record stalled.
        assert!(!record_release(&store, "vm-a", (1, 2), &raw_report(0x11, 0x22)).unwrap());
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-a",
            &raw_report(0x11, 0x33),
            EnforceGrace::default()
        )
        .is_ok());
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-a",
            &raw_report(0x11, 0x22),
            EnforceGrace::default()
        )
        .is_err());
    }

    #[test]
    fn without_a_record_enforce_refuses_and_record_pins_nothing() {
        let store = InMemoryKeepaliveBindings::default();
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-b",
            &raw_report(1, 2),
            EnforceGrace::default()
        )
        .is_err());
        let first = check_keepalive(
            &store,
            BindingMode::Record,
            "vm-b",
            &raw_report(1, 2),
            EnforceGrace::default(),
        )
        .unwrap();
        assert_eq!(first.source, BindingSource::FirstUse);
        assert_eq!(first.guest.report_id, [2; REPORT_ID_LEN]);
        // A squatter's keepalive pins nothing: the real guest still gets
        // served (and is named) — no lock-out after a KBS restart.
        let real = check_keepalive(
            &store,
            BindingMode::Record,
            "vm-b",
            &raw_report(1, 3),
            EnforceGrace::default(),
        )
        .unwrap();
        assert_eq!(real.source, BindingSource::FirstUse);
        assert_eq!(real.guest.report_id, [3; REPORT_ID_LEN]);
        assert!(store.get("vm-b").unwrap().is_none());
        // A release makes the binding proven and exclusive.
        record_release(&store, "vm-b", (1, 1), &raw_report(1, 3)).unwrap();
        let proven = check_keepalive(
            &store,
            BindingMode::Record,
            "vm-b",
            &raw_report(1, 3),
            EnforceGrace::default(),
        )
        .unwrap();
        assert_eq!(proven.source, BindingSource::Release);
        assert!(check_keepalive(
            &store,
            BindingMode::Record,
            "vm-b",
            &raw_report(1, 2),
            EnforceGrace::default()
        )
        .is_err());
    }

    fn signed_release(
        sk: &ed25519_dalek::SigningKey,
        gen: u64,
        counter: u64,
    ) -> hippius_types::release::SignedResponse {
        use hippius_types::release::{KbsResponse, WrappedSecret};
        let secret = |t: &str| WrappedSecret {
            secret_type: t.into(),
            secret_path: "p".into(),
            secret_version: 1,
            enc: vec![1],
            ct: vec![2],
        };
        let resp = KbsResponse {
            domain: hippius_types::release::RELEASE_DOMAIN.into(),
            v: 1,
            ticket_id: "tk".into(),
            tenant_id: "t".into(),
            vm_id: "abc".into(),
            vm_generation: gen,
            kbs_nonce: vec![1u8; 32],
            measurement: vec![7u8; 48],
            kbs_kid: b"kbs-kid".to_vec(),
            hpke_suite_id: hippius_types::release::HPKE_SUITE_ID,
            allowed_userdata_digest: vec![9u8; 32],
            luks: Some(secret("luks")),
            userdata: secret("userdata"),
            lifecycle_key: None,
            boot_counter: counter,
            expected_volume_stamp: 0,
            volume_stamp_token: None,
            volume_stamp_transition: None,
        };
        crate::crypto::sign_response(sk, &resp).unwrap()
    }

    #[test]
    fn a_release_records_its_guest_at_the_committed_position() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let store = InMemoryKeepaliveBindings::default();
        let signed = signed_release(&sk, 5, 3);
        let vm = record_after_release(
            &store,
            &sk.verifying_key(),
            &signed,
            &raw_report(0x11, 0x22),
        )
        .unwrap();
        assert_eq!(vm, "abc");
        let rec = store.get("abc").unwrap().unwrap();
        assert_eq!(rec.guest.report_id, [0x22; REPORT_ID_LEN]);
        // The order is what the release COMMITTED and signed.
        assert_eq!(rec.order, (5, 3));
        // A response not signed by this KBS records nothing.
        let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let forged = signed_release(&other, 9, 9);
        assert!(record_after_release(
            &store,
            &sk.verifying_key(),
            &forged,
            &raw_report(0x11, 0x99)
        )
        .is_err());
        assert_eq!(
            store.get("abc").unwrap().unwrap().guest.report_id,
            [0x22; REPORT_ID_LEN]
        );
    }

    fn guest(chip: u8, report: u8) -> GuestIdentity {
        GuestIdentity {
            chip_id: [chip; CHIP_ID_LEN],
            report_id: [report; REPORT_ID_LEN],
        }
    }

    fn refusal(store: &dyn KeepaliveBindingStore, vm: &str, chip: u8, report: u8) -> String {
        check_keepalive(
            store,
            BindingMode::Enforce,
            vm,
            &raw_report(chip, report),
            EnforceGrace::default(),
        )
        .unwrap_err()
        .to_string()
    }

    /// After a later release records another guest, the VM's PREVIOUS
    /// released guest is refused as `superseded-guest` (a T4 signal: its
    /// REPORT_ID was released to once for this vm_id), any other guest
    /// with the generic reason — in memory and across a process restart.
    #[test]
    fn the_previous_released_guest_is_refused_as_superseded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keepalive-bindings.json");
        let mem = InMemoryKeepaliveBindings::default();
        let file = FileKeepaliveBindings::open(&path).unwrap();
        for store in [&mem as &dyn KeepaliveBindingStore, &file] {
            record_release(store, "vm-a", (1, 1), &raw_report(0x11, 0x22)).unwrap();
            assert!(!refusal(store, "vm-a", 0x11, 0x33).contains(SUPERSEDED_GUEST));
            // The same guest re-released keeps no "previous" of itself.
            record_release(store, "vm-a", (1, 2), &raw_report(0x11, 0x22)).unwrap();
            assert_eq!(store.previous("vm-a").unwrap(), None);
            record_release(store, "vm-a", (1, 3), &raw_report(0x11, 0x44)).unwrap();
            assert!(refusal(store, "vm-a", 0x11, 0x22).contains(SUPERSEDED_GUEST));
            assert!(!refusal(store, "vm-a", 0x11, 0x33).contains(SUPERSEDED_GUEST));
        }
        drop(file);
        let reopened = FileKeepaliveBindings::open(&path).unwrap();
        assert!(refusal(&reopened, "vm-a", 0x11, 0x22).contains(SUPERSEDED_GUEST));
        // A file written before the field existed opens unchanged.
        let old = dir.path().join("old.json");
        std::fs::write(
            &old,
            format!(
                r#"{{"vm-b":{{"chip_id_hex":"{}","report_id_hex":"{}","generation":1,"boot_counter":1}}}}"#,
                hex::encode([0x11u8; CHIP_ID_LEN]),
                hex::encode([0x22u8; REPORT_ID_LEN]),
            ),
        )
        .unwrap();
        let legacy = FileKeepaliveBindings::open(&old).unwrap();
        assert_eq!(legacy.previous("vm-b").unwrap(), None);
    }

    /// A poison drops the record: its guest becomes the previous one, so
    /// the release that lifts the poison has the right previous guest —
    /// across a restart while poisoned too.
    #[test]
    fn a_poison_keeps_the_dropped_guest_as_previous() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keepalive-bindings.json");
        {
            let store = FileKeepaliveBindings::open(&path).unwrap();
            record_release(&store, "vm-a", (1, 1), &raw_report(0x11, 0x22)).unwrap(); // A
            record_release(&store, "vm-a", (1, 2), &raw_report(0x11, 0x33)).unwrap(); // B
            store.poison("vm-a", (1, 3)).unwrap();
        } // restart while poisoned
        let store = FileKeepaliveBindings::open(&path).unwrap();
        assert!(store.is_poisoned("vm-a").unwrap());
        record_release(&store, "vm-a", (1, 3), &raw_report(0x11, 0x44)).unwrap(); // C
        assert!(
            refusal(&store, "vm-a", 0x11, 0x33).contains(SUPERSEDED_GUEST),
            "B"
        );
        assert!(
            !refusal(&store, "vm-a", 0x11, 0x22).contains(SUPERSEDED_GUEST),
            "A"
        );
    }

    #[test]
    fn records_survive_a_process_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keepalive-bindings.json");
        {
            let store = FileKeepaliveBindings::open(&path).unwrap();
            record_release(&store, "vm-a", (3, 7), &raw_report(0x11, 0x22)).unwrap();
            record_release(&store, "vm-b", (1, 1), &raw_report(0x44, 0x55)).unwrap();
        } // the process goes away
        let reopened = FileKeepaliveBindings::open(&path).unwrap();
        assert_eq!(reopened.get("vm-a").unwrap().unwrap().order, (3, 7));
        let ok = check_keepalive(
            &reopened,
            BindingMode::Enforce,
            "vm-a",
            &raw_report(0x11, 0x22),
            EnforceGrace::default(),
        )
        .unwrap();
        assert_eq!(ok.source, BindingSource::Release);
        assert!(check_keepalive(
            &reopened,
            BindingMode::Enforce,
            "vm-a",
            &raw_report(0x11, 0x33),
            EnforceGrace::default()
        )
        .is_err());
        assert!(check_keepalive(
            &reopened,
            BindingMode::Enforce,
            "vm-b",
            &raw_report(0x44, 0x55),
            EnforceGrace::default()
        )
        .is_ok());
        // The ordering survives too: an older release still cannot win.
        assert!(!record_release(&reopened, "vm-a", (3, 6), &raw_report(0x11, 0x99)).unwrap());
    }

    #[test]
    fn a_missing_file_is_empty_and_a_corrupt_one_refuses_to_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keepalive-bindings.json");
        assert!(FileKeepaliveBindings::open(&path)
            .unwrap()
            .get("vm-a")
            .unwrap()
            .is_none());
        fs::write(&path, b"{not json").unwrap();
        assert!(FileKeepaliveBindings::open(&path).is_err());
        fs::write(&path, br#"{"vm-a":{"chip_id_hex":"11","report_id_hex":"22","generation":1,"boot_counter":1}}"#)
            .unwrap();
        assert!(
            FileKeepaliveBindings::open(&path).is_err(),
            "short ids must not load"
        );
        for (chip, report) in [
            ("00".repeat(64), "22".repeat(32)),
            ("11".repeat(64), "00".repeat(32)),
        ] {
            let row = format!(
                r#"{{"vm-a":{{"chip_id_hex":"{chip}","report_id_hex":"{report}","generation":1,"boot_counter":1}}}}"#
            );
            fs::write(&path, row).unwrap();
            assert!(
                FileKeepaliveBindings::open(&path).is_err(),
                "an all-zero id is corruption"
            );
        }
    }

    #[test]
    fn a_failed_persist_leaves_cache_and_file_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("not-created-yet")
            .join("keepalive-bindings.json");
        let store = FileKeepaliveBindings::open(&path).unwrap();
        assert!(record_release(&store, "vm-a", (1, 1), &raw_report(0x11, 0x22)).is_err());
        assert!(
            store.get("vm-a").unwrap().is_none(),
            "cache must be rolled back"
        );
        assert!(store.seed("vm-a", guest(0x11, 0x22)).is_err());
        assert!(
            store.get("vm-a").unwrap().is_none(),
            "a failed seed must not block the retry"
        );
        assert!(!path.exists());
        // The disk comes back: the retry of the same seed succeeds.
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        assert_eq!(
            store.seed("vm-a", guest(0x11, 0x22)).unwrap(),
            SeedOutcome::Seeded
        );
        assert!(FileKeepaliveBindings::open(&path)
            .unwrap()
            .get("vm-a")
            .unwrap()
            .is_some());
    }

    #[test]
    fn a_failed_overwrite_restores_the_previous_record() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("state");
        fs::create_dir_all(&sub).unwrap();
        let path = sub.join("keepalive-bindings.json");
        let store = FileKeepaliveBindings::open(&path).unwrap();
        record_release(&store, "vm-a", (1, 1), &raw_report(0x11, 0x22)).unwrap();
        // Make the directory vanish so the next write fails for real.
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&sub).unwrap();
        assert!(record_release(&store, "vm-a", (1, 2), &raw_report(0x11, 0x33)).is_err());
        let still = store.get("vm-a").unwrap().unwrap();
        assert_eq!(
            (still.guest.report_id, still.order),
            ([0x22; REPORT_ID_LEN], (1, 1))
        );
    }

    fn seed_contract(store: &dyn KeepaliveBindingStore) {
        // Empty row: seeded, and the seeded guest is the bound one.
        assert_eq!(
            store.seed("vm-s", guest(0x11, 0x22)).unwrap(),
            SeedOutcome::Seeded
        );
        assert_eq!(store.get("vm-s").unwrap().unwrap().order, SEED_ORDER);
        let b = check_keepalive(
            store,
            BindingMode::Enforce,
            "vm-s",
            &raw_report(0x11, 0x22),
            EnforceGrace::default(),
        )
        .unwrap();
        assert_eq!(b.source, BindingSource::Release);
        assert!(check_keepalive(
            store,
            BindingMode::Enforce,
            "vm-s",
            &raw_report(0x11, 0x33),
            EnforceGrace::default()
        )
        .is_err());
        // A retried seed of the SAME guest is a matched no-op.
        assert_eq!(
            store.seed("vm-s", guest(0x11, 0x22)).unwrap(),
            SeedOutcome::AlreadyMatching
        );
        assert_eq!(store.get("vm-s").unwrap().unwrap().order, SEED_ORDER);
        // A seed of a DIFFERENT guest never overwrites.
        assert_eq!(
            store.seed("vm-s", guest(0x11, 0x44)).unwrap(),
            SeedOutcome::Conflict
        );
        assert_eq!(
            store.get("vm-s").unwrap().unwrap().guest.report_id,
            [0x22; REPORT_ID_LEN]
        );
        // The next real release (any real position) supersedes the seed.
        assert!(record_release(store, "vm-s", (1, 0), &raw_report(0x11, 0x55)).unwrap());
        assert_eq!(
            store.get("vm-s").unwrap().unwrap().guest.report_id,
            [0x55; REPORT_ID_LEN]
        );
        // A release on record is never overwritten by a seed.
        assert_eq!(
            store.seed("vm-s", guest(0x11, 0x66)).unwrap(),
            SeedOutcome::Conflict
        );
        // …and a seed naming the released guest is a matched no-op that
        // keeps the release's position.
        assert_eq!(
            store.seed("vm-s", guest(0x11, 0x55)).unwrap(),
            SeedOutcome::AlreadyMatching
        );
        assert_eq!(store.get("vm-s").unwrap().unwrap().order, (1, 0));
        assert_eq!(
            store.get("vm-s").unwrap().unwrap().guest.report_id,
            [0x55; REPORT_ID_LEN]
        );
        // An all-zero REPORT_ID or CHIP_ID binds nothing.
        assert!(store.seed("vm-z", guest(0x11, 0x00)).is_err());
        assert!(store.seed("vm-z", guest(0x00, 0x22)).is_err());
        assert!(store.get("vm-z").unwrap().is_none());
    }

    fn poison_contract(store: &dyn KeepaliveBindingStore) {
        record_release(store, "vm-p", (1, 1), &raw_report(0x11, 0x22)).unwrap();
        // The (1, 2) release committed but its guest could not be recorded.
        store.poison("vm-p", (1, 2)).unwrap();
        assert!(store.is_poisoned("vm-p").unwrap());
        assert!(
            store.get("vm-p").unwrap().is_none(),
            "the stale record is dropped"
        );
        // Refused in BOTH modes — the old guest above all, but also any
        // guest (Record would otherwise serve it as first-use).
        for mode in [BindingMode::Record, BindingMode::Enforce] {
            for report in [0x22, 0x33] {
                let err = check_keepalive(
                    store,
                    mode,
                    "vm-p",
                    &raw_report(0x11, report),
                    EnforceGrace::default(),
                )
                .unwrap_err()
                .to_string();
                assert!(err.contains("invalidated"), "{mode:?}: {err}");
            }
        }
        // Other VMs are untouched.
        record_release(store, "vm-q", (1, 1), &raw_report(0x11, 0x44)).unwrap();
        assert!(check_keepalive(
            store,
            BindingMode::Enforce,
            "vm-q",
            &raw_report(0x11, 0x44),
            EnforceGrace::default()
        )
        .is_ok());
        // THE race: a delayed record from the OLDER (1, 1) release is
        // refused and leaves the VM poisoned.
        assert!(!record_release(store, "vm-p", (1, 1), &raw_report(0x11, 0x22)).unwrap());
        assert!(store.is_poisoned("vm-p").unwrap());
        assert!(store.get("vm-p").unwrap().is_none());
        // A seed never clears poison — not even of a plausible guest.
        assert_eq!(
            store.seed("vm-p", guest(0x11, 0x22)).unwrap(),
            SeedOutcome::Poisoned
        );
        assert!(store.is_poisoned("vm-p").unwrap());
        assert!(store.get("vm-p").unwrap().is_none());
        // A release AT the tombstone's position (`>=`) clears it and binds
        // the new guest.
        assert!(record_release(store, "vm-p", (1, 2), &raw_report(0x11, 0x33)).unwrap());
        assert!(!store.is_poisoned("vm-p").unwrap());
        assert!(check_keepalive(
            store,
            BindingMode::Enforce,
            "vm-p",
            &raw_report(0x11, 0x33),
            EnforceGrace::default()
        )
        .is_ok());
        assert!(check_keepalive(
            store,
            BindingMode::Enforce,
            "vm-p",
            &raw_report(0x11, 0x22),
            EnforceGrace::default()
        )
        .is_err());
        // A NEWER release clears it too; a second poison keeps the later
        // of the two positions.
        store.poison("vm-p", (2, 5)).unwrap();
        store.poison("vm-p", (1, 9)).unwrap();
        assert!(!record_release(store, "vm-p", (2, 4), &raw_report(0x11, 0x55)).unwrap());
        assert!(record_release(store, "vm-p", (3, 0), &raw_report(0x11, 0x55)).unwrap());
        assert!(!store.is_poisoned("vm-p").unwrap());
        assert!(check_keepalive(
            store,
            BindingMode::Record,
            "vm-p",
            &raw_report(0x11, 0x55),
            EnforceGrace::default()
        )
        .is_ok());
    }

    fn refused_everywhere(store: &dyn KeepaliveBindingStore, vm_id: &str) {
        for mode in [BindingMode::Record, BindingMode::Enforce] {
            for report in [0x22, 0x33] {
                let err = check_keepalive(
                    store,
                    mode,
                    vm_id,
                    &raw_report(0x11, report),
                    EnforceGrace::default(),
                )
                .unwrap_err()
                .to_string();
                assert!(err.contains("invalidated"), "{mode:?}: {err}");
            }
        }
    }

    #[test]
    fn a_tombstone_survives_a_restart_until_a_release_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keepalive-bindings.json");
        {
            let store = FileKeepaliveBindings::open(&path).unwrap();
            record_release(&store, "vm-t", (1, 1), &raw_report(0x11, 0x22)).unwrap();
            record_release(&store, "vm-u", (1, 1), &raw_report(0x11, 0x44)).unwrap();
            store.poison("vm-t", (1, 2)).unwrap();
        } // process restart
        {
            let store = FileKeepaliveBindings::open(&path).unwrap();
            assert!(store.is_poisoned("vm-t").unwrap());
            assert!(
                store.get("vm-t").unwrap().is_none(),
                "the stale record did not come back"
            );
            refused_everywhere(&store, "vm-t");
            // Other VMs untouched.
            assert!(check_keepalive(
                &store,
                BindingMode::Enforce,
                "vm-u",
                &raw_report(0x11, 0x44),
                EnforceGrace::default()
            )
            .is_ok());
            // A delayed OLDER record is refused …
            assert!(!record_release(&store, "vm-t", (1, 1), &raw_report(0x11, 0x22)).unwrap());
            // … and a seed is refused.
            assert_eq!(
                store.seed("vm-t", guest(0x11, 0x22)).unwrap(),
                SeedOutcome::Poisoned
            );
        } // restart: still poisoned, the refused writes left no trace
        {
            let store = FileKeepaliveBindings::open(&path).unwrap();
            assert!(store.is_poisoned("vm-t").unwrap());
            assert!(store.get("vm-t").unwrap().is_none());
            refused_everywhere(&store, "vm-t");
            // The (1, 2) release's own record clears it — in the same write.
            assert!(record_release(&store, "vm-t", (1, 2), &raw_report(0x11, 0x33)).unwrap());
        } // restart again
        let store = FileKeepaliveBindings::open(&path).unwrap();
        assert!(!store.is_poisoned("vm-t").unwrap());
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-t",
            &raw_report(0x11, 0x33),
            EnforceGrace::default()
        )
        .is_ok());
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-t",
            &raw_report(0x11, 0x22),
            EnforceGrace::default()
        )
        .is_err());
    }

    #[test]
    fn a_round3_tombstone_without_a_position_opens_and_is_never_lifted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keepalive-bindings.json");
        fs::write(&path, br#"{"vm-a":{"poisoned":true}}"#).unwrap();
        let store = FileKeepaliveBindings::open(&path).unwrap();
        assert!(store.is_poisoned("vm-a").unwrap());
        refused_everywhere(&store, "vm-a");
        assert!(
            !record_release(&store, "vm-a", (u64::MAX - 1, 0), &raw_report(0x11, 0x22)).unwrap()
        );
        // Not even a record at the sentinel's own position lifts it.
        assert!(
            !record_release(&store, "vm-a", UNORDERED_TOMBSTONE, &raw_report(0x11, 0x22)).unwrap()
        );
        assert!(store.is_poisoned("vm-a").unwrap());
        assert_eq!(
            store.seed("vm-a", guest(0x11, 0x22)).unwrap(),
            SeedOutcome::Poisoned
        );
        // Half a position is corrupt.
        fs::write(&path, br#"{"vm-a":{"poisoned":true,"generation":3}}"#).unwrap();
        assert!(FileKeepaliveBindings::open(&path).is_err());
        // A positioned tombstone round-trips.
        fs::write(
            &path,
            br#"{"vm-a":{"poisoned":true,"generation":3,"boot_counter":4}}"#,
        )
        .unwrap();
        let store = FileKeepaliveBindings::open(&path).unwrap();
        assert!(!record_release(&store, "vm-a", (3, 3), &raw_report(0x11, 0x22)).unwrap());
        assert!(record_release(&store, "vm-a", (3, 4), &raw_report(0x11, 0x22)).unwrap());
    }

    #[test]
    fn a_delayed_poison_never_erases_a_later_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keepalive-bindings.json");
        let file = FileKeepaliveBindings::open(&path).unwrap();
        let mem = InMemoryKeepaliveBindings::default();
        let stores: [&dyn KeepaliveBindingStore; 2] = [&file, &mem];
        for store in stores {
            // Release (1,3) recorded; the poison for the earlier (1,2)
            // arrives late.
            assert!(record_release(store, "vm-a", (1, 3), &raw_report(0x11, 0x33)).unwrap());
            store.poison("vm-a", (1, 2)).unwrap();
            assert!(!store.is_poisoned("vm-a").unwrap());
            assert!(check_keepalive(
                store,
                BindingMode::Enforce,
                "vm-a",
                &raw_report(0x11, 0x33),
                EnforceGrace::default()
            )
            .is_ok());
            // A poison at or after the record still takes effect.
            store.poison("vm-a", (1, 3)).unwrap();
            assert!(store.is_poisoned("vm-a").unwrap());
        }
        let reopened = FileKeepaliveBindings::open(&path).unwrap();
        assert!(reopened.is_poisoned("vm-a").unwrap());
    }

    #[test]
    fn a_file_without_tombstones_opens_and_a_false_tombstone_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keepalive-bindings.json");
        // Exactly what round-2 code wrote: records only.
        let row = format!(
            r#"{{"vm-a":{{"chip_id_hex":"{}","report_id_hex":"{}","generation":2,"boot_counter":3}}}}"#,
            "11".repeat(64),
            "22".repeat(32)
        );
        fs::write(&path, row).unwrap();
        let store = FileKeepaliveBindings::open(&path).unwrap();
        assert_eq!(store.get("vm-a").unwrap().unwrap().order, (2, 3));
        assert!(!store.is_poisoned("vm-a").unwrap());
        fs::write(&path, br#"{"vm-a":{"poisoned":false}}"#).unwrap();
        assert!(FileKeepaliveBindings::open(&path).is_err());
        fs::write(&path, br#"{"vm-a":{"poisoned":true,"extra":1}}"#).unwrap();
        assert!(FileKeepaliveBindings::open(&path).is_err());
    }

    #[test]
    fn a_failed_tombstone_persist_is_an_error_and_still_refuses_in_process() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("state");
        fs::create_dir_all(&sub).unwrap();
        let path = sub.join("keepalive-bindings.json");
        let store = FileKeepaliveBindings::open(&path).unwrap();
        record_release(&store, "vm-f", (1, 1), &raw_report(0x11, 0x22)).unwrap();
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&sub).unwrap();
        let err = store.poison("vm-f", (1, 2)).unwrap_err().to_string();
        assert!(err.contains("NOT durable"), "{err}");
        assert!(store.is_poisoned("vm-f").unwrap());
        assert!(store.get("vm-f").unwrap().is_none());
        refused_everywhere(&store, "vm-f");
        // And a release that fails to persist does not clear it.
        assert!(record_release(&store, "vm-f", (1, 2), &raw_report(0x11, 0x33)).is_err());
        assert!(store.is_poisoned("vm-f").unwrap());
        refused_everywhere(&store, "vm-f");
    }

    #[test]
    fn a_poisoned_vm_is_refused_until_its_next_record() {
        poison_contract(&InMemoryKeepaliveBindings::default());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keepalive-bindings.json");
        let store = FileKeepaliveBindings::open(&path).unwrap();
        poison_contract(&store);
        // The file dropped the stale record when it was poisoned.
        store.poison("vm-q", (1, 2)).unwrap();
        assert!(FileKeepaliveBindings::open(&path)
            .unwrap()
            .get("vm-q")
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_release_whose_guest_cannot_be_recorded_poisons_the_vm() {
        // The release commits for a NEW guest, but its report cannot be
        // parsed into an identity: the old guest must not stay bound.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let store = InMemoryKeepaliveBindings::default();
        let first = signed_release(&sk, 5, 1);
        record_after_release(&store, &sk.verifying_key(), &first, &raw_report(0x11, 0x22)).unwrap();
        let second = signed_release(&sk, 5, 2);
        assert!(record_after_release(&store, &sk.verifying_key(), &second, b"garbage").is_err());
        assert!(store.is_poisoned("abc").unwrap());
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "abc",
            &raw_report(0x11, 0x22),
            EnforceGrace::default()
        )
        .is_err());
        // An UNVERIFIABLE response names no vm_id: nothing is poisoned.
        let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let store2 = InMemoryKeepaliveBindings::default();
        record_release(&store2, "abc", (5, 1), &raw_report(0x11, 0x22)).unwrap();
        assert!(record_after_release(
            &store2,
            &sk.verifying_key(),
            &signed_release(&other, 5, 2),
            b"garbage"
        )
        .is_err());
        assert!(!store2.is_poisoned("abc").unwrap());
        // The next good release clears it.
        let third = signed_release(&sk, 5, 3);
        record_after_release(&store, &sk.verifying_key(), &third, &raw_report(0x11, 0x33)).unwrap();
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "abc",
            &raw_report(0x11, 0x33),
            EnforceGrace::default()
        )
        .is_ok());
    }

    #[test]
    fn seed_fills_only_an_empty_row_and_the_next_release_supersedes_it() {
        seed_contract(&InMemoryKeepaliveBindings::default());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keepalive-bindings.json");
        seed_contract(&FileKeepaliveBindings::open(&path).unwrap());
        // …and the file agrees after a restart.
        let reopened = FileKeepaliveBindings::open(&path).unwrap();
        assert_eq!(
            reopened.get("vm-s").unwrap().unwrap().guest.report_id,
            [0x55; REPORT_ID_LEN]
        );
    }

    fn open_window(now: u64) -> EnforceGrace {
        EnforceGrace {
            closes_at_unix: Some(1_000),
            now_unix: now,
        }
    }

    #[test]
    fn the_grace_window_serves_only_unbound_vms_and_only_while_open() {
        let store = InMemoryKeepaliveBindings::default();
        // Unbound VM, window open ⇒ first-use (named, unpinned).
        let b = check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-new",
            &raw_report(1, 2),
            open_window(999),
        )
        .unwrap();
        assert_eq!(b.source, BindingSource::FirstUse);
        assert!(
            store.get("vm-new").unwrap().is_none(),
            "the window pins nothing"
        );
        // …closed (at, and after, the close instant) ⇒ refused.
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-new",
            &raw_report(1, 2),
            open_window(1_000)
        )
        .is_err());
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-new",
            &raw_report(1, 2),
            EnforceGrace::default()
        )
        .is_err());
        // A BOUND VM is enforced strictly inside the window: another guest
        // is refused, the released one passes as `release`.
        record_release(&store, "vm-a", (1, 1), &raw_report(0x11, 0x22)).unwrap();
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-a",
            &raw_report(0x11, 0x33),
            open_window(10)
        )
        .is_err());
        let ok = check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-a",
            &raw_report(0x11, 0x22),
            open_window(10),
        )
        .unwrap();
        assert_eq!(ok.source, BindingSource::Release);
        // A poisoned VM stays refused inside the window.
        store.poison("vm-a", (1, 2)).unwrap();
        assert!(check_keepalive(
            &store,
            BindingMode::Enforce,
            "vm-a",
            &raw_report(0x11, 0x22),
            open_window(10)
        )
        .is_err());
        // Record mode is unaffected by the window.
        assert_eq!(
            check_keepalive(
                &store,
                BindingMode::Record,
                "vm-x",
                &raw_report(1, 9),
                EnforceGrace::default()
            )
            .unwrap()
            .source,
            BindingSource::FirstUse
        );
    }

    #[test]
    fn the_grace_epoch_survives_a_process_restart_and_a_fresh_state_dir_starts_a_new_one() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(grace_epoch_start(dir.path(), 100).unwrap(), 100);
        // Same pod, later process (a crash loop): the ORIGINAL epoch.
        assert_eq!(grace_epoch_start(dir.path(), 5_000).unwrap(), 100);
        // A pod replacement wipes the dir ⇒ a new epoch.
        let fresh = tempfile::tempdir().unwrap();
        assert_eq!(grace_epoch_start(fresh.path(), 9_000).unwrap(), 9_000);
        // Records but no epoch file (the epoch deleted, not a new pod):
        // the window is closed for good, not reopened.
        let kept = tempfile::tempdir().unwrap();
        fs::write(kept.path().join(BINDINGS_FILE), b"{}").unwrap();
        assert_eq!(grace_epoch_start(kept.path(), 9_000).unwrap(), 0);
        assert_eq!(grace_epoch_start(kept.path(), 9_500).unwrap(), 0);
        // A corrupt epoch refuses rather than guessing.
        fs::write(dir.path().join(GRACE_EPOCH_FILE), b"not-a-number").unwrap();
        assert!(grace_epoch_start(dir.path(), 5_000).is_err());
    }

    #[test]
    fn modes_parse() {
        assert_eq!(BindingMode::parse("off"), Some(BindingMode::Off));
        assert_eq!(BindingMode::parse("record"), Some(BindingMode::Record));
        assert_eq!(BindingMode::parse("enforce"), Some(BindingMode::Enforce));
        assert_eq!(BindingMode::parse("on"), None);
    }
}
