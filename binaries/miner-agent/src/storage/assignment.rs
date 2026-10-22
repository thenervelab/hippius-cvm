//! Dedicated disks given to VMs (docs/design/disk-tier-verification.md
//! §4.2, §5.2, §6.1, §7.1) — the agent side, inside its sandbox.
//!
//! A launch order's `extra_disks` names whole physical disks by their
//! declared `/dev/disk/by-id/` basename and a slot (`x0`..`x23`). This
//! module decides whether the VM may have them, records which it has, and
//! frees them on §24.
//!
//! ## Records (under the agent's state root, written durably)
//! - `vm-dedicated/<vm_id>`: the VM's disks, `slot → disk_id + identity`
//!   (the WWID/serial bound when the disk was accepted). Written before the
//!   domain is defined; removed only by §24 (after the disks are queued for
//!   release). A relaunch, a power start, a guest upgrade and the
//!   reboot-watcher's restart re-attach EXACTLY these disks after
//!   re-checking each one's identity; a mismatch refuses the start.
//! - `dedicated-release/<disk_id>`: a disk §24 freed and the privileged
//!   helper has not yet wiped. Reported `unavailable`
//!   (`disk-release-pending`) until the wipe is done and the collector
//!   sees the disk clean again.
//!
//! ## What touches the device
//! Nothing here: the agent runs with `PrivateDevices=yes` and sees no
//! block device. libvirt/QEMU open `/dev/disk/by-id/<id>` themselves. The
//! exclusive hold (`O_EXCL` + a udev rule hiding the disk from the host)
//! and the release wipe run in privileged oneshot/template units the agent
//! starts ([`SystemdHelper`], implemented in [`super::dedicated_helper`]),
//! which re-check every condition themselves against these records.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hippius_types::storage_report::{
    is_valid_dedicated_disk_id, DedicatedDiskReport, DedicatedDiskState,
};
use serde::{Deserialize, Serialize};

use crate::config::StorageDesiredStateConfig;
use crate::error::{MinerAgentError, Result};
use crate::lifecycle::cvm_handle::VmId;
use crate::orders::types::ExtraDisk;

use super::dedicated::{self, DiskFacts, FactsSource, IdentityMap, IdentityStore};

/// Per-VM records, under the state root.
pub const VM_DIR: &str = "vm-dedicated";
/// Disks waiting for their release wipe, under the state root.
pub const RELEASE_DIR: &str = "dedicated-release";
/// At most this many dedicated disks on one VM.
pub const MAX_EXTRA_DISKS: usize = 8;
/// Slots are `x0`..=`x<MAX_SLOT>`.
pub const MAX_SLOT: usize = 23;
/// The only `kind`.
pub const KIND_DEDICATED: &str = "dedicated";
/// First guest device name of a dedicated disk: `vda`..`vde` are the OS,
/// rootfs, verity, state and data disks.
const FIRST_EXTRA_DEV: u8 = b'f';

/// The slot index of `x<N>` (`N` in 0..=23, no leading zero).
pub fn slot_index(slot: &str) -> Option<usize> {
    let digits = slot.strip_prefix('x')?;
    if digits.is_empty()
        || digits.len() > 2
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return None;
    }
    digits.parse::<usize>().ok().filter(|n| *n <= MAX_SLOT)
}

/// `[concat!(prefix, ":x0"), …, concat!(prefix, ":x23")]`: refusal classes
/// stay `&'static str` (the order-rejection discipline).
macro_rules! per_slot {
    ($p:literal) => {
        [
            concat!($p, ":x0"),
            concat!($p, ":x1"),
            concat!($p, ":x2"),
            concat!($p, ":x3"),
            concat!($p, ":x4"),
            concat!($p, ":x5"),
            concat!($p, ":x6"),
            concat!($p, ":x7"),
            concat!($p, ":x8"),
            concat!($p, ":x9"),
            concat!($p, ":x10"),
            concat!($p, ":x11"),
            concat!($p, ":x12"),
            concat!($p, ":x13"),
            concat!($p, ":x14"),
            concat!($p, ":x15"),
            concat!($p, ":x16"),
            concat!($p, ":x17"),
            concat!($p, ":x18"),
            concat!($p, ":x19"),
            concat!($p, ":x20"),
            concat!($p, ":x21"),
            concat!($p, ":x22"),
            concat!($p, ":x23"),
        ]
    };
}

/// Why one slot's disk is refused (409 unless noted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotRefusal {
    /// Not a declared dedicated disk.
    Unknown,
    /// Declared `draining`: takes no new VM.
    Draining,
    /// Given to another VM.
    Assigned,
    /// Freed by §24, its wipe not done yet.
    Releasing,
    /// The by-id name now points at another device.
    Replaced,
    /// The device vanished or is offline.
    Failed,
    /// Any other inventory refusal (a signature, too small, in use, not
    /// yet bound to an identity, the helper not installed, …).
    Unavailable,
    /// A re-attach found another device behind the recorded name.
    Mismatch,
    /// The host holds the device (mounted, claimed by md/dm/LVM).
    Busy,
    /// The privileged hold could not be taken for another reason (503).
    HoldFailed,
}

impl SlotRefusal {
    /// The class for slot `index`.
    pub fn class(self, index: usize) -> &'static str {
        const UNKNOWN: [&str; 24] = per_slot!("dedicated-disk-unknown");
        const DRAINING: [&str; 24] = per_slot!("dedicated-disk-draining");
        const ASSIGNED: [&str; 24] = per_slot!("dedicated-disk-assigned");
        const RELEASING: [&str; 24] = per_slot!("dedicated-disk-releasing");
        const REPLACED: [&str; 24] = per_slot!("dedicated-disk-replaced");
        const FAILED: [&str; 24] = per_slot!("dedicated-disk-failed");
        const UNAVAILABLE: [&str; 24] = per_slot!("dedicated-disk-unavailable");
        const MISMATCH: [&str; 24] = per_slot!("dedicated-disk-mismatch");
        const BUSY: [&str; 24] = per_slot!("dedicated-disk-busy");
        const HOLD_FAILED: [&str; 24] = per_slot!("dedicated-hold-failed");
        let table = match self {
            Self::Unknown => &UNKNOWN,
            Self::Draining => &DRAINING,
            Self::Assigned => &ASSIGNED,
            Self::Releasing => &RELEASING,
            Self::Replaced => &REPLACED,
            Self::Failed => &FAILED,
            Self::Unavailable => &UNAVAILABLE,
            Self::Mismatch => &MISMATCH,
            Self::Busy => &BUSY,
            Self::HoldFailed => &HOLD_FAILED,
        };
        table[index.min(MAX_SLOT)]
    }

    /// The refusal as the lifecycle error for slot `index`.
    pub fn error(self, index: usize) -> MinerAgentError {
        match self {
            Self::HoldFailed => MinerAgentError::DedicatedUnavailable(self.class(index)),
            _ => MinerAgentError::DedicatedRefused(self.class(index)),
        }
    }
}

/// `true` when `cmdline` carries the measured `hippius.dedicated=` token:
/// the VM was launched with dedicated disks.
pub fn cmdline_is_pinned(cmdline: &str) -> bool {
    cmdline
        .split_ascii_whitespace()
        .any(|t| t.starts_with("hippius.dedicated="))
}

/// [`cmdline_slots`]'s refusal.
const MALFORMED: &str = "cmdline-malformed";

/// The slots the measured `hippius.dedicated=x0:<GiB>,x1:<GiB>,…` token
/// names: `Ok(None)` without the token, `Err` when it is malformed (twice,
/// empty, a bad slot, a size that is not a positive integer, a slot twice).
pub fn cmdline_slots(cmdline: &str) -> std::result::Result<Option<BTreeSet<usize>>, &'static str> {
    let mut tokens = cmdline
        .split_ascii_whitespace()
        .filter_map(|t| t.strip_prefix("hippius.dedicated="));
    let Some(value) = tokens.next() else {
        return Ok(None);
    };
    if tokens.next().is_some() || value.is_empty() {
        return Err(MALFORMED);
    }
    let mut slots = BTreeSet::new();
    for entry in value.split(',') {
        let (slot, gib) = entry.split_once(':').ok_or(MALFORMED)?;
        let index = slot_index(slot).ok_or(MALFORMED)?;
        if !gib.bytes().all(|b| b.is_ascii_digit()) {
            return Err(MALFORMED);
        }
        let gib: u64 = gib.parse().map_err(|_| MALFORMED)?;
        if gib == 0 || !slots.insert(index) {
            return Err(MALFORMED);
        }
    }
    Ok(Some(slots))
}

/// The order's disks are the ones the MEASURED cmdline anchors: the
/// `hippius.dedicated=` token is present exactly when the order carries
/// dedicated disks, and names exactly their slots (400
/// `dedicated-invalid/cmdline-*`). A disk outside the measured list would
/// reach the guest outside the contract it attests to.
pub fn check_anchor(cmdline: &str, extra: &[ExtraDisk]) -> Result<()> {
    let ordered: BTreeSet<usize> = extra.iter().filter_map(|d| slot_index(&d.slot)).collect();
    match cmdline_slots(cmdline) {
        Err(code) => Err(MinerAgentError::DedicatedInvalid(code)),
        Ok(None) if extra.is_empty() => Ok(()),
        Ok(None) => Err(MinerAgentError::DedicatedInvalid("cmdline-missing")),
        Ok(Some(_)) if extra.is_empty() => {
            Err(MinerAgentError::DedicatedInvalid("cmdline-without-disks"))
        }
        Ok(Some(measured)) if measured != ordered => {
            Err(MinerAgentError::DedicatedInvalid("cmdline-slots"))
        }
        Ok(Some(_)) => Ok(()),
    }
}

/// Check the order's list on its own (400 `dedicated-invalid/<check>`):
/// slots `x0`..`x23`, kind `dedicated`, a valid by-id name, no slot or disk
/// twice, at most [`MAX_EXTRA_DISKS`].
pub fn validate_shape(extra: &[ExtraDisk]) -> Result<()> {
    if extra.len() > MAX_EXTRA_DISKS {
        return Err(MinerAgentError::DedicatedInvalid("too-many"));
    }
    let mut slots = BTreeSet::new();
    let mut disks = BTreeSet::new();
    for d in extra {
        let Some(index) = slot_index(&d.slot) else {
            return Err(MinerAgentError::DedicatedInvalid("slot"));
        };
        if d.kind != KIND_DEDICATED {
            return Err(MinerAgentError::DedicatedInvalid("kind"));
        }
        if !is_valid_dedicated_disk_id(&d.disk_id) {
            return Err(MinerAgentError::DedicatedInvalid("disk-id"));
        }
        if !slots.insert(index) {
            return Err(MinerAgentError::DedicatedInvalid("slot-duplicate"));
        }
        if !disks.insert(d.disk_id.as_str()) {
            return Err(MinerAgentError::DedicatedInvalid("disk-duplicate"));
        }
    }
    Ok(())
}

/// One disk a VM holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignedDisk {
    pub slot: String,
    pub disk_id: String,
    /// The WWID / serial bound when the disk was accepted.
    pub identity: String,
}

/// `vm-dedicated/<vm_id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmDedicatedRecord {
    /// In slot order.
    pub disks: Vec<AssignedDisk>,
}

/// `dedicated-release/<disk_id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRecord {
    /// The VM §24 freed it from (for the operator).
    pub vm_id: String,
    pub slot: String,
    pub identity: String,
}

/// A record that exists but cannot be used: never treated as absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable;

pub fn vm_record_path(state_root: &Path, vm_id: &str) -> PathBuf {
    state_root.join(VM_DIR).join(vm_id)
}

pub fn release_record_path(state_root: &Path, disk_id: &str) -> PathBuf {
    state_root.join(RELEASE_DIR).join(disk_id)
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
) -> std::result::Result<Option<T>, Unreadable> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| Unreadable),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Unreadable),
    }
}

fn write_json<T: Serialize>(dir: &Path, path: &Path, value: &T) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    crate::lifecycle::vm_pool::write_durable(dir, path, &bytes)
}

fn remove_durable(dir: &Path, path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => std::fs::File::open(dir)?.sync_all(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn read_vm(
    state_root: &Path,
    vm_id: &str,
) -> std::result::Result<Option<VmDedicatedRecord>, Unreadable> {
    read_json(&vm_record_path(state_root, vm_id))
}

pub fn write_vm(state_root: &Path, vm_id: &str, record: &VmDedicatedRecord) -> std::io::Result<()> {
    write_json(
        &state_root.join(VM_DIR),
        &vm_record_path(state_root, vm_id),
        record,
    )
}

pub fn remove_vm(state_root: &Path, vm_id: &str) -> std::io::Result<()> {
    remove_durable(&state_root.join(VM_DIR), &vm_record_path(state_root, vm_id))
}

pub fn read_release(
    state_root: &Path,
    disk_id: &str,
) -> std::result::Result<Option<ReleaseRecord>, Unreadable> {
    read_json(&release_record_path(state_root, disk_id))
}

pub fn write_release(
    state_root: &Path,
    disk_id: &str,
    record: &ReleaseRecord,
) -> std::io::Result<()> {
    write_json(
        &state_root.join(RELEASE_DIR),
        &release_record_path(state_root, disk_id),
        record,
    )
}

pub fn remove_release(state_root: &Path, disk_id: &str) -> std::io::Result<()> {
    remove_durable(
        &state_root.join(RELEASE_DIR),
        &release_record_path(state_root, disk_id),
    )
}

/// The record names in `dir` that `valid` accepts (a missing dir is
/// empty; an unreadable one is [`Unreadable`]). Anything else there — the
/// temp file of an interrupted write, an editor's `foo~` — is skipped (and
/// logged unless hidden): it is no record, and must not wedge every
/// dedicated-disk decision on the host.
fn names(dir: &Path, valid: fn(&str) -> bool) -> std::result::Result<Vec<String>, Unreadable> {
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            let mut out = Vec::new();
            for entry in entries {
                let name = entry.map_err(|_| Unreadable)?.file_name();
                let Some(name) = name.to_str() else {
                    eprintln!(
                        "hippius-miner-agent: dedicated: non-UTF-8 entry in {} skipped",
                        dir.display()
                    );
                    continue;
                };
                if name.starts_with('.') {
                    continue;
                }
                if !valid(name) {
                    eprintln!(
                        "hippius-miner-agent: dedicated: {} in {} is not a record name, skipped",
                        name.escape_debug(),
                        dir.display()
                    );
                    continue;
                }
                out.push(name.to_string());
            }
            out.sort();
            Ok(out)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(Unreadable),
    }
}

fn is_record_vm_id(name: &str) -> bool {
    VmId::new(name).is_ok()
}

/// Who holds a dedicated disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    Vm {
        vm: String,
        slot: String,
        identity: String,
    },
    Releasing {
        identity: String,
    },
}

/// Every disk a record names, by disk id. A VM record wins over a release
/// record for the same disk (it cannot be released while a VM holds it).
pub fn owners(state_root: &Path) -> std::result::Result<BTreeMap<String, Owner>, Unreadable> {
    let mut out = BTreeMap::new();
    for disk_id in names(&state_root.join(RELEASE_DIR), is_valid_dedicated_disk_id)? {
        let record = read_release(state_root, &disk_id)?.ok_or(Unreadable)?;
        out.insert(
            disk_id,
            Owner::Releasing {
                identity: record.identity,
            },
        );
    }
    for vm in names(&state_root.join(VM_DIR), is_record_vm_id)? {
        let record = read_vm(state_root, &vm)?.ok_or(Unreadable)?;
        for d in record.disks {
            if !is_valid_dedicated_disk_id(&d.disk_id) {
                eprintln!(
                    "hippius-miner-agent: dedicated: vm {vm} record names an invalid disk id, \
                     entry skipped"
                );
                continue;
            }
            out.insert(
                d.disk_id,
                Owner::Vm {
                    vm: vm.clone(),
                    slot: d.slot,
                    identity: d.identity,
                },
            );
        }
    }
    Ok(out)
}

/// Fold the records into the inventory's reports: a disk a VM holds is
/// `assigned` (with the VM) unless it vanished (`failed`) or another device
/// answers to its name (`replaced`); a disk awaiting its wipe is
/// `unavailable` (`disk-release-pending`) unless it failed or was replaced.
/// A held disk the declaration no longer lists is still reported.
///
/// `facts`: the collector's report (`Err`: unusable, every disk keeps the
/// inventory's verdict and a held one stays `assigned`).
pub fn apply_owners(
    reports: &mut Vec<DedicatedDiskReport>,
    owners: &BTreeMap<String, Owner>,
    facts: std::result::Result<&DiskFacts, &'static str>,
) {
    for (disk_id, owner) in owners {
        if !reports.iter().any(|r| &r.id == disk_id) {
            reports.push(DedicatedDiskReport {
                id: disk_id.clone(),
                size_mb: 0,
                state: DedicatedDiskState::Unavailable,
                vm: String::new(),
                error: String::new(),
            });
        }
        let Some(report) = reports.iter_mut().find(|r| &r.id == disk_id) else {
            continue;
        };
        let identity = match owner {
            Owner::Vm { identity, .. } | Owner::Releasing { identity } => identity,
        };
        let fact = facts.ok().map(|f| f.disks.get(disk_id));
        if let Some(fact) = fact {
            if let Some(f) = fact {
                report.size_mb = f.size_mb;
            }
            match fact {
                Some(f) if f.identity.as_ref().is_some_and(|now| now != identity) => {
                    report.state = DedicatedDiskState::Replaced;
                    report.vm.clear();
                    report.error.clear();
                    continue;
                }
                None => {
                    report.state = DedicatedDiskState::Failed;
                    report.vm.clear();
                    report.error = "disk-not-found".into();
                    continue;
                }
                Some(f) if f.offline => {
                    report.state = DedicatedDiskState::Failed;
                    report.vm.clear();
                    report.error = "disk-offline".into();
                    continue;
                }
                _ => {}
            }
        }
        match owner {
            Owner::Vm { vm, .. } => {
                report.state = DedicatedDiskState::Assigned;
                report.vm = vm.clone();
                // A guest-written signature is expected; only an unusable
                // facts file is worth saying.
                report.error = facts.err().map(str::to_string).unwrap_or_default();
            }
            Owner::Releasing { .. } => {
                report.state = DedicatedDiskState::Unavailable;
                report.vm.clear();
                report.error = "disk-release-pending".into();
            }
        }
    }
    reports.sort_by(|a, b| a.id.cmp(&b.id));
}

/// A dedicated disk to attach: its slot and by-id name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachDisk {
    pub slot: String,
    pub disk_id: String,
}

impl AttachDisk {
    /// The guest device name for the `n`-th attached disk (`vdf`, …).
    pub fn target_dev(n: usize) -> String {
        let n = u8::try_from(n).unwrap_or(u8::MAX);
        let letter = FIRST_EXTRA_DEV.saturating_add(n).min(b'z');
        format!("vd{}", letter as char)
    }

    /// `/dev/disk/by-id/<disk_id>`.
    pub fn source(&self) -> PathBuf {
        Path::new("/dev/disk/by-id").join(&self.disk_id)
    }
}

/// The privileged side ([`super::dedicated_helper`]), reached through
/// systemd units outside the agent's sandbox. Codes are the helper's
/// closed set ([`super::dedicated_helper::CODES`]).
pub trait DedicatedHelper: Send + Sync {
    /// Whether the helper units are installed on this host.
    fn installed(&self) -> bool;
    /// Hold `disk_id` exclusively for the VM whose record names it.
    fn hold(&self, disk_id: &str) -> std::result::Result<(), &'static str>;
    /// Drop the hold (a disk not held is success).
    fn unhold(&self, disk_id: &str) -> std::result::Result<(), &'static str>;
    /// Zero the head and tail of `disk_id` (its release record must exist,
    /// no VM may name it) and verify no signature is left. For a disk no
    /// record names it only drops a leftover udev rule
    /// (`release-not-pending`).
    fn release(&self, disk_id: &str) -> std::result::Result<(), &'static str>;
    /// The disks a hold's udev rule is installed for.
    fn rule_ids(&self) -> Vec<String> {
        Vec::new()
    }
}

/// The helper's systemd template units.
pub const HOLD_UNIT: &str = "hippius-miner-dedicated-hold@";
pub const RELEASE_UNIT: &str = "hippius-miner-dedicated-release@";

/// [`DedicatedHelper`] through `systemctl` (the agent's sandbox allows
/// starting units; the units run outside it).
#[derive(Debug, Clone)]
pub struct SystemdHelper {
    /// Where the template units are installed.
    pub unit_dir: PathBuf,
    /// Where the helper writes its per-disk result.
    pub run_dir: PathBuf,
    /// Where the hold installs its udev rules (read only here).
    pub udev_rules_dir: PathBuf,
    /// `systemctl` (tests: a script).
    pub systemctl: PathBuf,
}

impl Default for SystemdHelper {
    fn default() -> Self {
        Self {
            unit_dir: PathBuf::from("/etc/systemd/system"),
            run_dir: PathBuf::from(super::dedicated_helper::RESULT_DIR),
            udev_rules_dir: PathBuf::from(super::dedicated_helper::UDEV_RULES_DIR),
            systemctl: PathBuf::from("systemctl"),
        }
    }
}

/// How long the agent waits for `systemctl` beyond the unit's own
/// `TimeoutStartSec` / `TimeoutStopSec`: systemd gives up first, the agent
/// reads its verdict.
const SYSTEMCTL_MARGIN_SECS: u64 = 15;

fn systemctl(
    systemctl: &Path,
    verb: &str,
    unit: &str,
    unit_timeout_secs: u64,
) -> std::result::Result<bool, &'static str> {
    let mut child = std::process::Command::new(systemctl)
        .args([verb, unit])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| "helper-failed")?;
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(unit_timeout_secs + SYSTEMCTL_MARGIN_SECS);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("helper-timeout");
            }
        }
    }
}

impl SystemdHelper {
    fn unit(prefix: &str, disk_id: &str) -> std::result::Result<String, &'static str> {
        // The instance is the raw by-id name (`%i`): only `[A-Za-z0-9._:-]`.
        if !is_valid_dedicated_disk_id(disk_id) {
            return Err("helper-bad-disk-id");
        }
        Ok(format!("{prefix}{disk_id}.service"))
    }

    /// Start `unit` and read the helper's verdict, written by this run.
    /// The unit's exit status decides; its verdict file only names why it
    /// failed (a file from an earlier run never turns a failure into a
    /// success, nor a success into a failure).
    fn run(
        &self,
        unit: &str,
        result: &Path,
        unit_timeout_secs: u64,
    ) -> std::result::Result<(), &'static str> {
        let started = std::time::SystemTime::now();
        if systemctl(&self.systemctl, "start", unit, unit_timeout_secs)? {
            return Ok(());
        }
        match super::dedicated_helper::read_result(result, started) {
            Some(code) if !code.is_empty() => Err(code),
            _ => Err("helper-failed"),
        }
    }
}

impl DedicatedHelper for SystemdHelper {
    fn installed(&self) -> bool {
        [HOLD_UNIT, RELEASE_UNIT]
            .iter()
            .all(|u| self.unit_dir.join(format!("{u}.service")).is_file())
    }

    fn hold(&self, disk_id: &str) -> std::result::Result<(), &'static str> {
        if !self.installed() {
            return Err("helper-missing");
        }
        let unit = Self::unit(HOLD_UNIT, disk_id)?;
        self.run(
            &unit,
            &super::dedicated_helper::result_path(&self.run_dir, disk_id, "hold"),
            super::dedicated_helper::HOLD_UNIT_TIMEOUT_SECS,
        )
    }

    fn unhold(&self, disk_id: &str) -> std::result::Result<(), &'static str> {
        let unit = Self::unit(HOLD_UNIT, disk_id)?;
        if systemctl(
            &self.systemctl,
            "stop",
            &unit,
            super::dedicated_helper::HOLD_UNIT_TIMEOUT_SECS,
        )? {
            Ok(())
        } else {
            Err("helper-failed")
        }
    }

    fn release(&self, disk_id: &str) -> std::result::Result<(), &'static str> {
        if !self.installed() {
            return Err("helper-missing");
        }
        let unit = Self::unit(RELEASE_UNIT, disk_id)?;
        self.run(
            &unit,
            &super::dedicated_helper::result_path(&self.run_dir, disk_id, "release"),
            super::dedicated_helper::RELEASE_UNIT_TIMEOUT_SECS,
        )
    }

    fn rule_ids(&self) -> Vec<String> {
        super::dedicated_helper::rule_ids(&self.udev_rules_dir)
    }
}

/// What [`DedicatedDisks::prepare`] decided for one launch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prepared {
    /// The disks to attach, in slot order (a disk that vanished from a VM
    /// that already had it is left out: the guest sees its slot missing).
    pub attach: Vec<AttachDisk>,
    /// This launch wrote the VM's record: a failure before the domain is
    /// started takes it back ([`DedicatedDisks::rollback`]).
    pub created: bool,
}

/// Where the decisions read the host and the records.
pub struct DedicatedDisks {
    facts: Box<dyn FactsSource>,
    helper: Box<dyn DedicatedHelper>,
    identities: std::sync::Arc<IdentityStore>,
    /// One claim at a time: two launches never take the same free disk,
    /// and a `storage-config` apply ([`super::remote`]) shares it, so a
    /// disk is never claimed from a declaration the route is replacing.
    lock: std::sync::Arc<Mutex<()>>,
    /// Per-VM: a launch, a destroy and a reboot-watcher restart of a VM
    /// with dedicated disks never interleave ([`Self::vm_ops`]).
    vm_ops: Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
}

impl std::fmt::Debug for DedicatedDisks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DedicatedDisks").finish_non_exhaustive()
    }
}

impl Default for DedicatedDisks {
    fn default() -> Self {
        Self::new(
            Box::new(dedicated::FileFacts::default()),
            Box::new(SystemdHelper::default()),
            std::sync::Arc::default(),
        )
    }
}

/// The storage the decisions run against: the state root and the set in
/// force (read under the claim lock, so a `storage-config` apply is
/// either wholly before or wholly after a claim).
pub struct Ctx<'a> {
    pub state_root: &'a Path,
    pub storage: &'a super::state::StorageState,
}

impl DedicatedDisks {
    pub fn new(
        facts: Box<dyn FactsSource>,
        helper: Box<dyn DedicatedHelper>,
        identities: std::sync::Arc<IdentityStore>,
    ) -> Self {
        Self {
            facts,
            helper,
            identities,
            lock: std::sync::Arc::default(),
            vm_ops: Mutex::default(),
        }
    }

    /// The claim lock, for the `storage-config` route to hold across its
    /// check of held disks and its commit.
    pub fn assignment_lock(&self) -> std::sync::Arc<Mutex<()>> {
        std::sync::Arc::clone(&self.lock)
    }

    /// The VM's operations lock: held by a launch (from its dedicated-disk
    /// decision to its end, rollback included), a destroy and a
    /// reboot-watcher restart of a VM that has or asks for dedicated disks.
    pub async fn vm_ops(&self, vm_id: &VmId) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut map = self
                .vm_ops
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Locks nobody holds or waits for go: the map stays as small as
            // the operations in flight.
            map.retain(|_, lock| std::sync::Arc::strong_count(lock) > 1);
            std::sync::Arc::clone(map.entry(vm_id.as_str().to_string()).or_default())
        };
        lock.lock_owned().await
    }

    pub fn helper(&self) -> &dyn DedicatedHelper {
        self.helper.as_ref()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The VM's record (`Err`: unreadable — the caller refuses, 503).
    pub fn record(&self, state_root: &Path, vm_id: &VmId) -> Result<Option<VmDedicatedRecord>> {
        read_vm(state_root, vm_id.as_str()).map_err(|Unreadable| {
            MinerAgentError::DedicatedUnavailable("dedicated-record-unreadable")
        })
    }

    /// Refuse an operation a pinned VM may not undergo (§25 migration, a
    /// storage move, a backup, a restore): 409 `dedicated-pinned`.
    pub fn check_not_pinned(&self, state_root: &Path, vm_id: &VmId) -> Result<()> {
        match self.record(state_root, vm_id)? {
            Some(_) => Err(MinerAgentError::DedicatedRefused("dedicated-pinned")),
            None => Ok(()),
        }
    }

    /// Decide the dedicated disks of a launch of `vm_id` asking for
    /// `extra` (already [`validate_shape`]d). Blocking (it may start the
    /// collector): run it off the async workers.
    ///
    /// - The VM has a record: the order must name exactly its disks
    ///   (`dedicated-order-mismatch` otherwise) and each is re-checked
    ///   against fresh facts: another device behind the name refuses the
    ///   start (`dedicated-disk-mismatch:<slot>`), one the host holds is
    ///   `dedicated-disk-busy:<slot>`, one gone or offline is left out.
    /// - No record and `extra` is empty: nothing to do.
    /// - No record: a relaunch (`require_existing`) may not claim disks;
    ///   a first launch claims declared, `active`, `free`, identity-bound
    ///   disks no record names, and writes the record before returning.
    pub fn prepare(
        &self,
        ctx: &Ctx<'_>,
        vm_id: &VmId,
        extra: &[ExtraDisk],
        require_existing: bool,
    ) -> Result<Prepared> {
        let existing = self.record(ctx.state_root, vm_id)?;
        if existing.is_none() && extra.is_empty() {
            return Ok(Prepared::default());
        }
        if existing.is_none() && require_existing {
            return Err(MinerAgentError::DedicatedRefused(
                "dedicated-order-mismatch",
            ));
        }
        // Fresh facts, outside the claim lock (the collector can take
        // seconds).
        self.facts.refresh();
        let facts = self.facts.facts();
        let _claim = self.lock();
        // Re-read under the lock: a concurrent launch of the same VM may
        // have written it.
        match self.record(ctx.state_root, vm_id)? {
            Some(record) => {
                // The host's own filesystems (`/`, the state root, every
                // pool) at the time of the start: a recorded disk that now
                // carries one directly (a filesystem on the bare disk) is
                // never handed to the guest. One on a partition or LVM of it
                // makes the exclusive hold fail before the start instead.
                let set = ctx.storage.current();
                let system = super::system_devs(ctx.state_root, &set.pools);
                self.reattach(&record, extra, facts.as_ref().map_err(|e| *e), &system)
            }
            None if extra.is_empty() => Ok(Prepared::default()),
            None => self.claim(ctx, vm_id, extra, facts.as_ref().map_err(|e| *e)),
        }
    }

    fn reattach(
        &self,
        record: &VmDedicatedRecord,
        extra: &[ExtraDisk],
        facts: std::result::Result<&DiskFacts, &'static str>,
        system_devs: &BTreeSet<String>,
    ) -> Result<Prepared> {
        let wanted: BTreeSet<(&str, &str)> = extra
            .iter()
            .map(|d| (d.slot.as_str(), d.disk_id.as_str()))
            .collect();
        let held: BTreeSet<(&str, &str)> = record
            .disks
            .iter()
            .map(|d| (d.slot.as_str(), d.disk_id.as_str()))
            .collect();
        if wanted != held {
            return Err(MinerAgentError::DedicatedRefused(
                "dedicated-order-mismatch",
            ));
        }
        let facts = facts
            .map_err(|_| MinerAgentError::DedicatedUnavailable("dedicated-facts-unavailable"))?;
        let mut attach = Vec::new();
        for d in &record.disks {
            let index = slot_index(&d.slot).unwrap_or(MAX_SLOT);
            match facts.disks.get(&d.disk_id) {
                None => {
                    eprintln!(
                        "hippius-miner-agent: dedicated: slot {} disk {} not found — started \
                         without it (the guest sees the slot missing)",
                        d.slot, d.disk_id
                    );
                }
                Some(f) if f.identity.as_deref() != Some(d.identity.as_str()) => {
                    return Err(SlotRefusal::Mismatch.error(index));
                }
                Some(f) if f.offline => {
                    eprintln!(
                        "hippius-miner-agent: dedicated: slot {} disk {} offline — started \
                         without it (the guest sees the slot missing)",
                        d.slot, d.disk_id
                    );
                }
                // Mounted, swap, claimed by md/dm/LVM, or `/`, the state
                // root or a pool directly on it. (A partition of it in use
                // makes the exclusive hold fail before the start.)
                Some(f)
                    if matches!(f.error.as_str(), "disk-in-use" | "disk-holder-busy")
                        || f.dev.as_ref().is_some_and(|d| system_devs.contains(d)) =>
                {
                    return Err(SlotRefusal::Busy.error(index));
                }
                Some(_) => attach.push(AttachDisk {
                    slot: d.slot.clone(),
                    disk_id: d.disk_id.clone(),
                }),
            }
        }
        Ok(Prepared {
            attach,
            created: false,
        })
    }

    fn claim(
        &self,
        ctx: &Ctx<'_>,
        vm_id: &VmId,
        extra: &[ExtraDisk],
        facts: std::result::Result<&DiskFacts, &'static str>,
    ) -> Result<Prepared> {
        let facts = facts
            .map_err(|_| MinerAgentError::DedicatedUnavailable("dedicated-facts-unavailable"))?;
        let set = ctx.storage.current();
        let declared = set.dedicated.as_slice();
        let system_devs = super::system_devs(ctx.state_root, &set.pools);
        let owners = owners(ctx.state_root).map_err(|Unreadable| {
            MinerAgentError::DedicatedUnavailable("dedicated-record-unreadable")
        })?;
        // The identities bound so far: a disk is given only once its
        // identity is on disk (the heartbeat that offered it bound it).
        let bound: IdentityMap = {
            let mut guard = self.identities.lock();
            let loaded = guard.get_or_insert_with(|| IdentityMap::load(ctx.state_root));
            loaded.clone().ok_or(MinerAgentError::DedicatedUnavailable(
                "dedicated-identities-unreadable",
            ))?
        };
        let mut scratch = bound.clone();
        let reports = dedicated::inventory(declared, Ok(facts), &system_devs, &mut scratch);
        let helper_installed = self.helper.installed();
        let mut sorted: Vec<&ExtraDisk> = extra.iter().collect();
        sorted.sort_by_key(|d| slot_index(&d.slot));
        let mut disks = Vec::new();
        for d in &sorted {
            let index = slot_index(&d.slot).unwrap_or(MAX_SLOT);
            let Some(cfg) = declared.iter().find(|c| c.id == d.disk_id) else {
                return Err(SlotRefusal::Unknown.error(index));
            };
            match owners.get(&d.disk_id) {
                Some(Owner::Vm { .. }) => return Err(SlotRefusal::Assigned.error(index)),
                Some(Owner::Releasing { .. }) => return Err(SlotRefusal::Releasing.error(index)),
                None => {}
            }
            let report = reports.iter().find(|r| r.id == d.disk_id);
            match report.map(|r| r.state) {
                Some(DedicatedDiskState::Free) => {}
                Some(DedicatedDiskState::Replaced) => {
                    return Err(SlotRefusal::Replaced.error(index))
                }
                Some(DedicatedDiskState::Failed) => return Err(SlotRefusal::Failed.error(index)),
                Some(DedicatedDiskState::Draining) => {
                    return Err(SlotRefusal::Draining.error(index))
                }
                _ => return Err(SlotRefusal::Unavailable.error(index)),
            }
            if cfg.state != StorageDesiredStateConfig::Active || !helper_installed {
                return Err(SlotRefusal::Unavailable.error(index));
            }
            let Some(identity) = bound.disks.get(&d.disk_id) else {
                return Err(SlotRefusal::Unavailable.error(index));
            };
            disks.push(AssignedDisk {
                slot: d.slot.clone(),
                disk_id: d.disk_id.clone(),
                identity: identity.clone(),
            });
        }
        let record = VmDedicatedRecord { disks };
        write_vm(ctx.state_root, vm_id.as_str(), &record)
            .map_err(|_| MinerAgentError::DedicatedUnavailable("dedicated-record-store"))?;
        Ok(Prepared {
            attach: record
                .disks
                .iter()
                .map(|d| AttachDisk {
                    slot: d.slot.clone(),
                    disk_id: d.disk_id.clone(),
                })
                .collect(),
            created: true,
        })
    }

    /// Hold every disk of `attach` (the privileged hold unit, `O_EXCL`).
    /// Blocking.
    pub fn hold_all(&self, attach: &[AttachDisk]) -> Result<()> {
        for d in attach {
            let index = slot_index(&d.slot).unwrap_or(MAX_SLOT);
            match self.helper.hold(&d.disk_id) {
                Ok(()) => {}
                Err("hold-busy") => return Err(SlotRefusal::Busy.error(index)),
                Err("hold-identity-mismatch") => return Err(SlotRefusal::Mismatch.error(index)),
                Err(code) => {
                    eprintln!(
                        "hippius-miner-agent: dedicated: hold of slot {} disk {} failed: {code}",
                        d.slot, d.disk_id
                    );
                    return Err(SlotRefusal::HoldFailed.error(index));
                }
            }
        }
        Ok(())
    }

    /// The record `prepare` wrote is still the one this launch attaches:
    /// a concurrent failed launch of the same VM may have taken it back.
    pub fn confirm(&self, state_root: &Path, vm_id: &VmId, prepared: &Prepared) -> Result<()> {
        if prepared.attach.is_empty() && !prepared.created {
            return Ok(());
        }
        let record =
            self.record(state_root, vm_id)?
                .ok_or(MinerAgentError::DedicatedUnavailable(
                    "dedicated-record-lost",
                ))?;
        let held: BTreeSet<(&str, &str)> = record
            .disks
            .iter()
            .map(|d| (d.slot.as_str(), d.disk_id.as_str()))
            .collect();
        if prepared
            .attach
            .iter()
            .all(|d| held.contains(&(d.slot.as_str(), d.disk_id.as_str())))
        {
            Ok(())
        } else {
            Err(MinerAgentError::DedicatedUnavailable(
                "dedicated-record-lost",
            ))
        }
    }

    /// Take back a record a launch created and never started a domain
    /// with: no guest saw the disks, so they are free again with no wipe.
    /// Blocking.
    pub fn rollback(&self, state_root: &Path, vm_id: &VmId, prepared: &Prepared) {
        if !prepared.created {
            return;
        }
        // The holds first, while the record still keeps every other launch
        // off these disks (and outside the claim lock: a `systemctl stop`
        // can be slow). A hold that would not stop keeps the record: the
        // disks stay assigned until §24 rather than held for nobody.
        for d in &prepared.attach {
            if let Err(code) = self.helper.unhold(&d.disk_id) {
                eprintln!(
                    "hippius-miner-agent: dedicated: unhold of {} after a failed launch: {code} \
                     (vm {} keeps its disks until §24)",
                    d.disk_id,
                    vm_id.as_str()
                );
                return;
            }
        }
        // Then the record, under the claim lock, and again any hold the
        // periodic re-hold started meanwhile (it read the record before it
        // went): no claim can take these disks while the lock is held, so
        // this never stops a new owner's hold. An inactive unit stops at
        // once.
        {
            let _claim = self.lock();
            if remove_vm(state_root, vm_id.as_str()).is_err() {
                eprintln!(
                    "hippius-miner-agent: dedicated: vm {} record not taken back after a failed \
                     launch (its disks stay assigned until §24)",
                    vm_id.as_str()
                );
                return;
            }
            for d in &prepared.attach {
                if let Err(code) = self.helper.unhold(&d.disk_id) {
                    eprintln!(
                        "hippius-miner-agent: dedicated: second unhold of {}: {code}",
                        d.disk_id
                    );
                }
            }
        }
        // The udev rules the holds kept (they saw the record), now nobody's.
        self.sweep_rules(state_root);
    }

    /// Drop the udev rules a dead hold left for disks no record names any
    /// more (through the release unit, which only removes the rule for such
    /// a disk). Blocking.
    pub fn sweep_rules(&self, state_root: &Path) {
        let ids = self.helper.rule_ids();
        if ids.is_empty() {
            return;
        }
        for id in ids {
            // Under the claim lock no launch can take the disk: a hold for
            // a disk nobody owns (a re-hold that raced a rollback) is
            // stopped without touching a new owner's.
            {
                let _claim = self.lock();
                match owners(state_root) {
                    Ok(owners) if !owners.contains_key(&id) => {}
                    _ => continue,
                }
                if let Err(code) = self.helper.unhold(&id) {
                    eprintln!("hippius-miner-agent: dedicated: unhold of unowned {id}: {code}");
                }
            }
            {
                match self.helper.release(&id) {
                    Err("release-not-pending") | Ok(()) => {}
                    Err(code) => eprintln!(
                        "hippius-miner-agent: dedicated: stale udev rule of {id} not removed: {code}"
                    ),
                }
            }
        }
    }

    /// §24: queue every disk of `vm_id` for its release wipe (durably),
    /// then remove the VM's record. Only after the domain is proven down.
    /// Returns the queued disks, for the caller to wipe off its own path
    /// ([`Self::drain_disks`]). Blocking (file writes only). `Err` only
    /// when the queueing failed (the record is then kept, and a retried
    /// destroy redoes it).
    pub fn release_vm(&self, state_root: &Path, vm_id: &VmId) -> Result<Vec<String>> {
        {
            let _claim = self.lock();
            let Some(record) = self.record(state_root, vm_id)? else {
                return Ok(Vec::new());
            };
            for d in &record.disks {
                write_release(
                    state_root,
                    &d.disk_id,
                    &ReleaseRecord {
                        vm_id: vm_id.as_str().to_string(),
                        slot: d.slot.clone(),
                        identity: d.identity.clone(),
                    },
                )
                .map_err(|_| MinerAgentError::DedicatedUnavailable("dedicated-record-store"))?;
            }
            remove_vm(state_root, vm_id.as_str())
                .map_err(|_| MinerAgentError::DedicatedUnavailable("dedicated-record-store"))?;
            Ok(record.disks.into_iter().map(|d| d.disk_id).collect())
        }
    }

    /// Wipe the disks awaiting release (`only`: just those); a wiped one
    /// leaves the queue and the collector re-reads the host. Returns how
    /// many were wiped. Blocking (each wipe is the release unit's run).
    pub fn drain_disks(&self, state_root: &Path, only: Option<&[String]>) -> usize {
        let Ok(pending) = names(&state_root.join(RELEASE_DIR), is_valid_dedicated_disk_id) else {
            eprintln!("hippius-miner-agent: dedicated: {RELEASE_DIR} unreadable");
            return 0;
        };
        let mut wiped = 0;
        for disk_id in pending {
            if only.is_some_and(|o| !o.contains(&disk_id)) {
                continue;
            }
            // Never a disk a VM holds (a record written meanwhile), and the
            // hold stopped under the claim lock: a disk another drain wiped
            // and a launch claimed since keeps its new owner's hold.
            {
                let _claim = self.lock();
                match owners(state_root) {
                    Ok(o) if matches!(o.get(&disk_id), Some(Owner::Releasing { .. })) => {}
                    _ => continue,
                }
                if let Err(code) = self.helper.unhold(&disk_id) {
                    eprintln!("hippius-miner-agent: dedicated: unhold of {disk_id} failed: {code}");
                    continue;
                }
            }
            match self.helper.release(&disk_id) {
                Ok(()) => {
                    let _claim = self.lock();
                    if remove_release(state_root, &disk_id).is_err() {
                        eprintln!(
                            "hippius-miner-agent: dedicated: {disk_id} wiped, release record \
                             not removed"
                        );
                        continue;
                    }
                    wiped += 1;
                    eprintln!("hippius-miner-agent: dedicated: {disk_id} released and wiped");
                }
                Err(code) => {
                    eprintln!(
                        "hippius-miner-agent: dedicated: release wipe of {disk_id} failed: {code} \
                         (retried)"
                    );
                }
            }
        }
        if wiped > 0 {
            self.facts.refresh();
        }
        wiped
    }

    /// Make sure every disk a VM record names is held (agent start: a hold
    /// unit may have died). Best effort, logged. Blocking.
    pub fn hold_recorded(&self, state_root: &Path) {
        let Ok(owners) = owners(state_root) else {
            eprintln!("hippius-miner-agent: dedicated: records unreadable; holds not checked");
            return;
        };
        for (disk_id, owner) in owners {
            if let Owner::Vm { vm, .. } = owner {
                if let Err(code) = self.helper.hold(&disk_id) {
                    eprintln!(
                        "hippius-miner-agent: dedicated: hold of {disk_id} (vm {vm}) failed: {code}"
                    );
                }
            }
        }
    }

    /// The reboot-watcher's restart of `vm_id`'s persistent definition
    /// (the same XML, so the same disks): re-check each disk's identity on
    /// fresh facts and its hold before `virsh start`. Any doubt refuses
    /// the restart (vali's relaunch then decides). Blocking.
    pub fn check_before_restart(&self, state_root: &Path, vm_id: &VmId) -> Result<()> {
        let Some(record) = self.record(state_root, vm_id)? else {
            return Ok(());
        };
        self.facts.refresh();
        let facts = self
            .facts
            .facts()
            .map_err(|_| MinerAgentError::DedicatedUnavailable("dedicated-facts-unavailable"))?;
        for d in &record.disks {
            let index = slot_index(&d.slot).unwrap_or(MAX_SLOT);
            match facts.disks.get(&d.disk_id) {
                Some(f) if f.identity.as_deref() == Some(d.identity.as_str()) && !f.offline => {}
                Some(f) if f.identity.as_deref() != Some(d.identity.as_str()) => {
                    return Err(SlotRefusal::Mismatch.error(index));
                }
                _ => return Err(SlotRefusal::Failed.error(index)),
            }
        }
        let attach: Vec<AttachDisk> = record
            .disks
            .iter()
            .map(|d| AttachDisk {
                slot: d.slot.clone(),
                disk_id: d.disk_id.clone(),
            })
            .collect();
        self.hold_all(&attach)
    }
}

/// How often [`run`] retries the release wipes.
const DRAIN_EVERY: std::time::Duration = std::time::Duration::from_secs(300);

/// Now and every [`DRAIN_EVERY`] until `cancel`: hold every recorded disk
/// again (a hold unit that died is restarted; `systemctl start` of a live
/// one is a no-op), then retry the pending release wipes.
pub async fn run(
    lifecycle: std::sync::Arc<crate::lifecycle::CvmLifecycle>,
    cancel: tokio_util::sync::CancellationToken,
) {
    loop {
        lifecycle.hold_recorded_dedicated().await;
        lifecycle.sweep_dedicated_rules().await;
        let wiped = lifecycle.drain_dedicated_releases().await;
        if wiped > 0 {
            eprintln!("hippius-miner-agent: dedicated: {wiped} released disk(s) wiped");
        }
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(DRAIN_EVERY) => {}
        }
    }
}

#[cfg(test)]
mod tests;
