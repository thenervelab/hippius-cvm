//! The `storage` section (§18.9 inventory, §18.3 health): every block
//! device with what it is or could become, and the disk health
//! advisories.
//!
//! - The inventory ([`devices`]) reads sysfs, the udev database,
//!   `/dev/disk/by-id` links and `/proc/1/mountinfo` only: no device I/O.
//!   A filesystem's size is a `statvfs` of a declared pool path or the
//!   state root only, never of an arbitrary mount (a network mount can
//!   hang it), and never of a network filesystem.
//! - The classification ([`classify`]) needs the agent's own view of its
//!   storage ([`StorageView`], from its config and the applied
//!   `storage-config` document).
//! - The advisories ([`health`]) come from `smartctl` / `nvme` (bounded,
//!   per device and overall) and from the kernel's cached md state and
//!   the mount table.
//!
//! Privacy (§18.10.3): a dm device is reported by its kernel name `dm-N`
//! only, never its dm name (which can embed a VM id); by-id names are the
//! crate's physical families only ([`hippius_host_inventory::is_disk_id`]);
//! an advisory sample is a fixed template, never tool output.

pub mod classify;
pub mod counters;
pub mod devices;
pub mod health;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hippius_host_inventory::{
    Advisory, AdvisoryCode, AdvisorySubject, Device, DeviceKind, DeviceRole, FsInfo, MdInfo,
    Severity, StorageSection, Transport, MAX_NAME_LEN, MAX_PATH_LEN, MAX_TEXT_LEN,
};

use super::{clean_text, CommandRunner, HostPaths, Tally};
use crate::config::Config;
use crate::storage::pools::DEFAULT_POOL_ID;
use classify::Class;
pub use counters::Counters;
use devices::{HostDisks, Raw};
use health::{Finding, Probe, ProbeKind, Target};

/// One pool the agent declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewPool {
    pub id: String,
    pub path: PathBuf,
}

/// The agent's own view of its storage: what the classification needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StorageView {
    /// `[storage] state_disk_root`.
    pub state_root: PathBuf,
    /// Every pool in force (the applied `storage-config` document's, else
    /// the local config's, `default` included).
    pub pools: Vec<ViewPool>,
    /// The declared dedicated disks' by-id names.
    pub dedicated: Vec<String>,
}

impl StorageView {
    /// What `serve` would run with: an invalid storage declaration
    /// dropped, the applied `storage-config` document if it still fits
    /// ([`crate::storage::remote::boot_set`], read-only).
    pub fn from_config(config: &Config) -> Self {
        use crate::storage::remote::{boot_set, LocalStorage};
        let mut effective = config.clone();
        effective.drop_invalid_storage();
        let local = LocalStorage::from_config(&effective);
        let (pools, dedicated, _) = boot_set(&local);
        Self {
            state_root: local.state_root.clone(),
            pools: pools
                .iter()
                .map(|p| ViewPool {
                    id: p.id.clone(),
                    path: p.path.clone(),
                })
                .collect(),
            dedicated: dedicated.into_iter().map(|d| d.id).collect(),
        }
    }
}

/// What a storage collection takes besides the host.
pub struct StorageInputs<'a> {
    /// `None`: the agent config could not be read (no pool, state root or
    /// dedicated disk is known; the section is `partial`).
    pub view: Option<&'a StorageView>,
    /// The previous run's [`Counters`] (default on a first run).
    pub previous: &'a Counters,
    /// No SMART tool may still run past it (the run's deadline less its
    /// write margin); the probe also stops [`health::SMART_BUDGET`] after
    /// it starts.
    pub deadline: std::time::Instant,
    /// Less than this left before `deadline` when the probe would start:
    /// no section at all ([`NoProbeTime`]).
    pub min_probe_window: Duration,
    pub clock: &'a dyn super::Clock,
    /// The kernel run's pending events ([`super::kernel`]), folded into
    /// the advisories.
    pub kernel: &'a [super::kernel::KernelEvent],
}

/// Less than [`StorageInputs::min_probe_window`] was left for the probe:
/// the run collects nothing (a `full` run exits non-zero to be retried).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoProbeTime;

/// Filesystems never `statvfs`ed, nor anything under them: a dead server
/// (or an automount that never completes) hangs the call.
fn network_fs(fstype: &str) -> bool {
    const NETWORK: [&str; 13] = [
        "autofs",
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "smbfs",
        "ceph",
        "glusterfs",
        "9p",
        "afs",
        "lustre",
        "gpfs",
        "beegfs",
    ];
    NETWORK.contains(&fstype) || fstype.starts_with("fuse")
}

/// A type udev or mountinfo names (`ext4`, `crypto_LUKS`,
/// `linux_raid_member`): a fixed vocabulary, anything else dropped.
fn fs_type_name(s: &str) -> Option<String> {
    let ok = !s.is_empty()
        && s.len() <= MAX_NAME_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    ok.then(|| s.to_string())
}

/// How long one `statvfs` may take before it is given up (the thread is
/// left behind, detached).
pub const STATVFS_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a size was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatSkip {
    /// The path is not a plain directory chain (a symlink on the way
    /// could lead `statvfs` anywhere).
    NotPlain,
    TimedOut,
    Failed,
}

/// `statvfs` of `path` under the host root, `(size, available)` bytes,
/// bounded by `timeout` in a detached thread. Refused when any component
/// of the path is a symlink.
fn statvfs(paths: &HostPaths, path: &Path, timeout: Duration) -> Result<(u64, u64), StatSkip> {
    let rel = path.strip_prefix("/").unwrap_or(path);
    let mut at = paths.host_root.clone();
    for c in rel.components() {
        at.push(c);
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            _ => return Err(StatSkip::NotPlain),
        }
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(crate::lifecycle::disk_space::fs_bytes(&at));
    });
    match rx.recv_timeout(timeout) {
        Ok(Some(sizes)) => Ok(sizes),
        Ok(None) => Err(StatSkip::Failed),
        Err(_) => Err(StatSkip::TimedOut),
    }
}

/// `(size, available)` per device, from the pool paths and the state
/// root on it.
/// Only a path whose every mount on the way is local is `statvfs`ed.
fn fs_sizes(
    paths: &HostPaths,
    disks: &HostDisks,
    view: Option<&StorageView>,
    timeout: Duration,
    tally: &mut Tally,
) -> BTreeMap<String, (u64, u64)> {
    let mut out = BTreeMap::new();
    let Some(view) = view else { return out };
    let wanted = std::iter::once(&view.state_root).chain(view.pools.iter().map(|p| &p.path));
    for path in wanted {
        let Some(m) = disks.mount_of(path) else {
            continue;
        };
        let Some(dev) = &m.device else { continue };
        if out.contains_key(dev) || disks.mounts_above(path).any(|m| network_fs(&m.fstype)) {
            continue;
        }
        match statvfs(paths, path, timeout) {
            Ok(sizes) => {
                out.insert(dev.clone(), sizes);
            }
            Err(StatSkip::TimedOut) => tally.timed_out(),
            Err(StatSkip::NotPlain | StatSkip::Failed) => {}
        }
    }
    out
}

/// The mount points of a device, shortest first.
fn mounts_of(disks: &HostDisks, name: &str) -> Vec<String> {
    let mut mounts: Vec<String> = disks
        .mounts
        .iter()
        // A bind mount (of a subdirectory) is the same filesystem again.
        .filter(|m| m.device.as_deref() == Some(name) && m.root == "/")
        .filter_map(|m| m.mount_point.to_str().map(str::to_string))
        .filter(|m| {
            m.starts_with('/')
                && m.len() <= MAX_PATH_LEN
                && m.bytes().all(|b| (0x20..0x7f).contains(&b))
        })
        .collect();
    mounts.sort_by(|a, b| (a.matches('/').count(), a).cmp(&(b.matches('/').count(), b)));
    mounts.dedup();
    mounts
}

fn device(
    raw: &Raw,
    class: Option<&Class>,
    disks: &HostDisks,
    sizes: &BTreeMap<String, (u64, u64)>,
) -> Device {
    let mounts = mounts_of(disks, &raw.name);
    let fs_type = raw
        .udev
        .fs_type
        .as_deref()
        .and_then(fs_type_name)
        .or_else(|| {
            disks
                .mounts
                .iter()
                .find(|m| m.device.as_deref() == Some(raw.name.as_str()))
                .and_then(|m| fs_type_name(&m.fstype))
        });
    let size = sizes.get(&raw.name);
    let fs = fs_type.map(|fs_type| FsInfo {
        fs_type,
        uuid_present: raw.udev.fs_uuid.is_some(),
        size_bytes: size.map(|s| s.0),
        available_bytes: size.map(|s| s.1),
    });
    let text = |s: &Option<String>, max| s.as_deref().and_then(|s| clean_text(s.as_bytes(), max));
    let md = raw.md.as_ref().map(|md| MdInfo {
        level: text(&md.level, MAX_NAME_LEN).unwrap_or_else(|| "unknown".into()),
        state: text(&md.state, MAX_NAME_LEN).unwrap_or_else(|| "unknown".into()),
        degraded: md.degraded,
        members: raw.slaves.clone(),
    });
    let (role, reasons, pool_ids) = match class {
        Some(c) => (
            c.role,
            c.reasons.iter().copied().collect(),
            c.pool_ids.iter().cloned().collect(),
        ),
        None => (DeviceRole::Ineligible, Vec::new(), Vec::new()),
    };
    Device {
        name: raw.name.clone(),
        kind: raw.kind,
        size_bytes: raw.size_bytes,
        ids: raw.ids.clone(),
        model: text(&raw.model, MAX_TEXT_LEN),
        transport: raw.transport,
        rotational_hint: raw.rotational,
        removable: raw.removable,
        read_only: raw.read_only,
        behind_controller: raw.controller.as_ref().map(|c| c.label.clone()),
        partitions: raw.partitions.clone(),
        holders: raw.holders.clone(),
        md,
        fs,
        mounts,
        role,
        pool_ids,
        reasons,
    }
}

/// What a device's health advisories attach to (§18.3): a declared
/// dedicated disk by its by-id name; the one pool a disk alone backs
/// (directly or through its partitions); else the device by kernel name.
fn subject_of(raw: &Raw, class: Option<&Class>) -> (AdvisorySubject, String) {
    if let Some(id) = class.and_then(|c| c.dedicated_id.clone()) {
        return (AdvisorySubject::DedicatedDisk, id);
    }
    if let Some(c) = class.filter(|c| c.role == DeviceRole::PoolBacking && c.pool_ids.len() == 1) {
        if let Some(pool) = c.pool_ids.iter().next() {
            return (AdvisorySubject::Pool, pool.clone());
        }
    }
    (AdvisorySubject::Device, raw.name.clone())
}

/// The devices to probe for SMART, in name order: whole physical disks
/// (every NVMe namespace: the health log is the controller's, each
/// namespace reports it under its own subject); no USB, removable,
/// virtual, virtio or remote device.
fn targets(disks: &HostDisks, classes: &BTreeMap<String, Class>) -> Vec<Target> {
    let mut out = Vec::new();
    for raw in disks.devices.values() {
        if raw.kind != DeviceKind::Disk
            || raw.removable
            || raw.virtual_path
            || raw.remote
            || matches!(raw.transport, Transport::Usb | Transport::Virtio)
            || ["sr", "mmcblk", "xvd", "pmem"]
                .iter()
                .any(|p| raw.name.starts_with(p))
        {
            continue;
        }
        let class = classes.get(&raw.name);
        let (subject_kind, subject) = subject_of(raw, class);
        let counter_key = raw
            .ids
            .first()
            .cloned()
            .unwrap_or_else(|| format!("kernel:{}", raw.name));
        let kind = match (&raw.controller, raw.transport) {
            (Some(c), _) if c.raid_mode => ProbeKind::ControllerVd {
                label: c.label.clone(),
                vd: raw
                    .scsi_target
                    .map_or_else(|| raw.name.clone(), |t| t.to_string()),
                megaraid: c.megaraid,
                scsi_host: raw.scsi_host,
            },
            (_, Transport::Nvme) => ProbeKind::Nvme,
            (_, Transport::Sata | Transport::Sas | Transport::Scsi) => ProbeKind::Ata {
                rotational_hint: raw.rotational,
            },
            _ => ProbeKind::Unknown,
        };
        out.push(Target {
            name: raw.name.clone(),
            subject_kind,
            subject,
            counter_key,
            kind,
        });
    }
    out
}

fn finding(kind: AdvisorySubject, subject: &str, code: AdvisoryCode, sev: Severity) -> Finding {
    Finding {
        subject_kind: kind,
        subject: subject.to_string(),
        code,
        severity: sev,
        count: 1,
        value: 0,
        sample: None,
    }
}

/// `md_degraded` / `md_rebuilding` from the kernel's cached md state.
fn md_findings(disks: &HostDisks) -> Vec<Finding> {
    let mut out = Vec::new();
    for raw in disks.devices.values() {
        let Some(md) = &raw.md else { continue };
        let level = md
            .level
            .as_deref()
            .and_then(|l| clean_text(l.as_bytes(), MAX_NAME_LEN))
            .unwrap_or_else(|| "md".into());
        if md.degraded > 0 {
            let n = md.degraded;
            out.push(Finding {
                count: u64::from(n),
                value: i64::from(n),
                sample: health::sample(&format!("{level} array degraded, {n} member(s) missing")),
                ..finding(
                    AdvisorySubject::Md,
                    &raw.name,
                    AdvisoryCode::MdDegraded,
                    Severity::Critical,
                )
            });
        }
        let action = md.sync_action.as_deref().unwrap_or("idle");
        if matches!(action, "recover" | "resync" | "reshape") {
            let pct =
                md.sync_completed
                    .filter(|(_, total)| *total > 0)
                    .map_or(0, |(done, total)| {
                        i64::try_from(u128::from(done.min(total)) * 100 / u128::from(total))
                            .unwrap_or(0)
                    });
            out.push(Finding {
                value: pct,
                sample: health::sample(&format!("{action} {pct}% complete")),
                ..finding(
                    AdvisorySubject::Md,
                    &raw.name,
                    AdvisoryCode::MdRebuilding,
                    Severity::Info,
                )
            });
        }
    }
    out
}

/// `mount_missing` (a pool that must be a filesystem of its own — every
/// pool but `default`, which may sit on `/` — is no mount point) and
/// `mount_ro` (a pool's filesystem is mounted read-only).
fn mount_findings(disks: &HostDisks, view: &StorageView) -> Vec<Finding> {
    let mut out = Vec::new();
    for pool in &view.pools {
        if pool.id != DEFAULT_POOL_ID && !disks.is_mount_point(&pool.path) {
            out.push(Finding {
                sample: health::sample("pool path is not a mount point"),
                ..finding(
                    AdvisorySubject::Pool,
                    &pool.id,
                    AdvisoryCode::MountMissing,
                    Severity::Critical,
                )
            });
            continue;
        }
        if disks.mount_of(&pool.path).is_some_and(|m| m.read_only) {
            out.push(Finding {
                sample: health::sample("pool filesystem mounted read-only"),
                ..finding(
                    AdvisorySubject::Pool,
                    &pool.id,
                    AdvisoryCode::MountRo,
                    Severity::Critical,
                )
            });
        }
    }
    out
}

/// How long one `btrfs device stats` may take.
pub const BTRFS_TIMEOUT: Duration = Duration::from_secs(10);

/// The per-counter totals of `btrfs device stats` output
/// (`[/dev/sdb].write_io_errs   0`, …): write, read, flush, corruption,
/// generation. `None` when no counter line parses.
pub(crate) fn parse_btrfs_stats(output: &str) -> Option<[u64; 5]> {
    const NAMES: [&str; 5] = [
        "write_io_errs",
        "read_io_errs",
        "flush_io_errs",
        "corruption_errs",
        "generation_errs",
    ];
    let mut totals = [0u64; 5];
    let mut any = false;
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some(counter) = key.rsplit_once('.').map(|(_, c)| c) else {
            continue;
        };
        let (Some(i), Ok(v)) = (
            NAMES.iter().position(|n| *n == counter),
            value.parse::<u64>(),
        ) else {
            continue;
        };
        totals[i] = totals[i].saturating_add(v);
        any = true;
    }
    any.then_some(totals)
}

/// `btrfs_device_errors` (warning, any counter above zero) for every pool
/// on a btrfs mount: one `btrfs device stats -c` per mount, bounded, only
/// while the probe window stays intact. The sample carries counts only,
/// never a device path.
fn btrfs_findings(
    runner: &dyn CommandRunner,
    disks: &HostDisks,
    view: Option<&StorageView>,
    inputs: &StorageInputs<'_>,
    tally: &mut Tally,
) -> Vec<Finding> {
    let Some(view) = view else { return Vec::new() };
    // Mount point → the pools on it.
    let mut mounts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pool in &view.pools {
        let Some(m) = disks.mount_of(&pool.path) else {
            continue;
        };
        let Some(mp) = m.mount_point.to_str() else {
            continue;
        };
        if m.fstype == "btrfs" && mp.starts_with('/') {
            mounts
                .entry(mp.to_string())
                .or_default()
                .push(pool.id.clone());
        }
    }
    let mut out = Vec::new();
    for (mp, pools) in mounts {
        let left = inputs
            .deadline
            .saturating_duration_since(inputs.clock.now());
        if left < inputs.min_probe_window.saturating_add(BTRFS_TIMEOUT) {
            tally.timed_out();
            break;
        }
        let run = runner.run_bounded(
            "btrfs",
            &["device", "stats", "-c", &mp],
            BTRFS_TIMEOUT,
            true,
        );
        let (code, severity, count, value, text) = match &run {
            Ok(text) => match parse_btrfs_stats(text) {
                Some(t) if t.iter().any(|v| *v > 0) => {
                    tally.ok();
                    let total = t.iter().fold(0u64, |a, v| a.saturating_add(*v));
                    (
                        AdvisoryCode::BtrfsDeviceErrors,
                        Severity::Warning,
                        total,
                        i64::try_from(total).unwrap_or(i64::MAX),
                        format!(
                            "btrfs device errors: write {}, read {}, flush {}, corruption {}, generation {}",
                            t[0], t[1], t[2], t[3], t[4]
                        ),
                    )
                }
                Some(_) => {
                    tally.ok();
                    continue;
                }
                None => {
                    tally.failed();
                    continue;
                }
            },
            Err(super::CommandError::Timeout) => {
                tally.timed_out();
                (
                    AdvisoryCode::CollectorTimeout,
                    Severity::Warning,
                    1,
                    0,
                    format!(
                        "btrfs device stats timed out after {} s",
                        BTRFS_TIMEOUT.as_secs()
                    ),
                )
            }
            Err(e) => {
                tally.command::<()>(&Err(*e));
                continue;
            }
        };
        for pool in pools {
            out.push(Finding {
                count,
                value,
                sample: health::sample(&text),
                ..finding(AdvisorySubject::Pool, &pool, code, severity)
            });
        }
    }
    out
}

/// The kernel run's pending events as advisories: each device mapped to
/// its subject like a SMART one ([`subject_of`]), a device no longer
/// present kept by its kernel name; events landing on one subject and
/// code merged (counts summed, the widest times, the latest sample).
fn kernel_advisories(
    disks: &HostDisks,
    classes: &BTreeMap<String, Class>,
    events: &[super::kernel::KernelEvent],
) -> Vec<Advisory> {
    let mut merged: BTreeMap<(u8, String, u8), Advisory> = BTreeMap::new();
    for e in events {
        let (kind, subject) = match disks.devices.get(&e.device) {
            Some(raw) => subject_of(raw, classes.get(&e.device)),
            None => (AdvisorySubject::Device, e.device.clone()),
        };
        let a = Advisory {
            subject_kind: kind,
            subject,
            code: e.code,
            severity: super::kernel::severity(e.code),
            count: e.count,
            value: 0,
            first_seen_unix: e.first_seen_unix,
            last_seen_unix: e.last_seen_unix.max(e.first_seen_unix),
            sample: health::sample(&e.sample),
        };
        match merged.entry(a.key()) {
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(a);
            }
            std::collections::btree_map::Entry::Occupied(mut o) => {
                let m = o.get_mut();
                m.count = m.count.saturating_add(a.count);
                m.first_seen_unix = m.first_seen_unix.min(a.first_seen_unix);
                if a.last_seen_unix >= m.last_seen_unix {
                    m.last_seen_unix = a.last_seen_unix;
                    m.sample = a.sample;
                }
            }
        }
    }
    merged.into_values().collect()
}

/// Collect the storage section, and the [`Counters`] to keep for the
/// next run. The SMART probe is its last step (only the bookkeeping
/// follows), bounded by [`StorageInputs::deadline`] measured just before
/// it starts, after the sysfs read and every `statvfs`.
pub fn collect_storage(
    paths: &HostPaths,
    runner: &dyn CommandRunner,
    inputs: &StorageInputs<'_>,
    now_unix: i64,
) -> Result<(StorageSection, Counters), NoProbeTime> {
    let mut tally = Tally::default();
    let clean = |s: &str| clean_text(s.as_bytes(), MAX_TEXT_LEN);
    let disks = devices::read_host(paths, &mut tally, &clean);
    let view = inputs.view;
    let (classes, unknown) = classify::classify(&disks, view);
    let sizes = fs_sizes(paths, &disks, view, STATVFS_TIMEOUT, &mut tally);
    let devices: Vec<Device> = disks
        .devices
        .values()
        .map(|raw| device(raw, classes.get(&raw.name), &disks, &sizes))
        .collect();

    // btrfs device stats of the btrfs pool mounts, only while the probe
    // window stays intact (each call bounded).
    let btrfs = btrfs_findings(runner, &disks, view, inputs, &mut tally);

    let start = inputs.clock.now();
    if inputs.deadline.saturating_duration_since(start) < inputs.min_probe_window {
        return Err(NoProbeTime);
    }
    let deadline = inputs.deadline.min(start + health::SMART_BUDGET);
    let probe =
        Probe::new(runner, inputs.clock, deadline, inputs.previous).run(&targets(&disks, &classes));
    tally.merge(probe.tally);
    let mut findings = probe.findings;
    findings.extend(btrfs);
    findings.extend(md_findings(&disks));
    if let Some(view) = view {
        findings.extend(mount_findings(&disks, view));
    }
    // What the classification could not prove: nothing was offered, and
    // the section says why.
    let no_view = unknown.contains(&classify::Unknown::NoView);
    let no_root = unknown.contains(&classify::Unknown::RootUnresolved);
    let no_boot = unknown.contains(&classify::Unknown::BootUnresolved);
    let why = match (no_view, no_root) {
        (false, false) if no_boot => Some("boot partition unresolved: nothing offerable"),
        (true, true) => {
            Some("agent config unreadable and root filesystem unresolved: nothing offerable")
        }
        (true, false) => Some("agent config unreadable: pool and dedicated roles unknown"),
        (false, true) => Some("root filesystem unresolved: nothing offerable"),
        (false, false) => None,
    };
    if let Some(why) = why {
        tally.failed();
        findings.push(Finding {
            sample: health::sample(why),
            ..finding(
                AdvisorySubject::Collector,
                "",
                AdvisoryCode::CollectorPartial,
                Severity::Info,
            )
        });
    }
    let mut advisories: Vec<Advisory> = findings
        .into_iter()
        .map(|f| Advisory {
            subject_kind: f.subject_kind,
            subject: f.subject,
            code: f.code,
            severity: f.severity,
            count: f.count,
            value: f.value,
            first_seen_unix: now_unix,
            last_seen_unix: now_unix,
            sample: f.sample,
        })
        .collect();
    let mut next = Counters {
        devices: probe.next,
        ..Counters::default()
    };
    next.stamp(&mut advisories, inputs.previous, now_unix);
    // The kernel's own times (first / last seen in the journal), not the
    // run's.
    advisories.extend(kernel_advisories(&disks, &classes, inputs.kernel));
    let section = StorageSection {
        status: tally.status(),
        devices,
        advisories,
        advisories_truncated: false,
        devices_truncated: false,
    };
    Ok((section, next))
}

#[cfg(test)]
pub(crate) mod tests;
