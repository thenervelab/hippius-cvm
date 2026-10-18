//! The block devices as the kernel and udev already know them: sysfs
//! (`/sys/block/*` and their partitions), the udev database, the
//! `/dev/disk/by-id` links, `/proc/1/mountinfo` and `/proc/swaps`
//! (§18.9.1).
//!
//! **No device I/O**: nothing here opens a device node or reads an
//! attribute that issues a command (`device/rescan`, VPD re-reads); every
//! file read is kernel-cached state. A device-mapper NAME is read only to
//! resolve a `/dev/mapper/<name>` mount or swap source to its `dm-N`; it
//! never leaves this module.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use hippius_host_inventory::{is_disk_id, is_kernel_name, is_pci_address, DeviceKind, Transport};

use super::super::{dir_names, link_name, read_trimmed, HostPaths, Source, Tally};
use crate::storage::dedicated;
use crate::storage::pools::{parse_mountinfo_sources, MountEntry};

/// What the udev database recorded for a device (its own blkid builtin,
/// at add / change time).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Udev {
    /// The device has an entry at all. Without one nothing is known about
    /// its signatures: never proof that it carries none.
    pub(crate) found: bool,
    pub(crate) fs_type: Option<String>,
    /// `ID_FS_UUID`: what a multi-device filesystem's members share. Kept
    /// in the collector, never reported (only its presence is).
    pub(crate) fs_uuid: Option<String>,
    pub(crate) part_table: bool,
    pub(crate) wwn: Option<String>,
    /// The partition entry or its filesystem says "boot" (an ESP or BIOS
    /// boot type, a boot / ESP flag, an `EFI*` / `ESP` label): see
    /// [`is_boot_entry`].
    pub(crate) boot: bool,
    /// `ID_PART_ENTRY_UUID` (PARTUUID) and `ID_FS_LABEL`, to match
    /// `/etc/fstab`. Kept in the collector, never reported.
    pub(crate) part_uuid: Option<String>,
    pub(crate) fs_label: Option<String>,
    /// `ID_PART_ENTRY_TYPE` was recorded: only then can a partition be
    /// proven not to be a boot partition.
    pub(crate) part_entry_typed: bool,
}

/// The GPT type GUIDs of an EFI system partition and a BIOS boot
/// (`bios_grub`) partition.
const ESP_GUID: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
const BIOS_BOOT_GUID: &str = "21686148-6449-6e6f-744e-656564454649";
/// The Boot Loader Specification's extended boot partition (`/boot`).
const XBOOTLDR_GUID: &str = "bc13c2ff-59e6-4262-a352-b275fd6f7172";

/// GPT attribute bit 2 (legacy BIOS bootable); the MBR active flag.
const GPT_LEGACY_BOOTABLE: u64 = 1 << 2;
const MBR_ACTIVE: u64 = 0x80;

/// A number as udev prints a partition entry field (`0x80`, `128`).
fn entry_number(s: &str) -> Option<u64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// `EFI…` / `ESP`, case-insensitive.
fn boot_label(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    s.starts_with("efi") || s == "esp"
}

/// Whether udev's partition entry or filesystem fields mark a boot
/// partition: the ESP or BIOS boot type GUID, the MBR type `0xef`, a
/// boot flag (GPT attribute bit 2; MBR active `0x80`), an `EFI*` / `ESP`
/// partition or filesystem label.
fn is_boot_entry(fields: &BTreeMap<&str, &str>) -> bool {
    let get = |k: &str| fields.get(k).copied();
    let scheme = get("ID_PART_ENTRY_SCHEME").map(str::to_ascii_lowercase);
    let by_type = get("ID_PART_ENTRY_TYPE").is_some_and(|t| {
        let t = t.to_ascii_lowercase();
        t == ESP_GUID || t == BIOS_BOOT_GUID || t == XBOOTLDR_GUID || entry_number(&t) == Some(0xef)
    });
    let by_flags = get("ID_PART_ENTRY_FLAGS")
        .and_then(entry_number)
        .is_some_and(|f| match scheme.as_deref() {
            Some("gpt") => f & GPT_LEGACY_BOOTABLE != 0,
            Some("dos") => f & MBR_ACTIVE != 0,
            _ => f & (GPT_LEGACY_BOOTABLE | MBR_ACTIVE) != 0,
        });
    let by_label = get("ID_PART_ENTRY_NAME").is_some_and(boot_label)
        || get("ID_FS_LABEL").is_some_and(boot_label);
    by_type || by_flags || by_label
}

/// `md/*` of an md array.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MdRaw {
    pub(crate) level: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) degraded: u32,
    /// `md/sync_action` (`idle`, `recover`, `resync`, `reshape`, `check`…).
    pub(crate) sync_action: Option<String>,
    /// `md/sync_completed`: `(done, total)` sectors.
    pub(crate) sync_completed: Option<(u64, u64)>,
}

/// One block device as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Raw {
    pub(crate) name: String,
    pub(crate) kind: DeviceKind,
    /// `major:minor`.
    pub(crate) dev: Option<String>,
    pub(crate) size_bytes: u64,
    pub(crate) removable: bool,
    pub(crate) read_only: bool,
    pub(crate) rotational: Option<bool>,
    /// `device/model` as the kernel cached it (uncleaned).
    pub(crate) model: Option<String>,
    pub(crate) vendor: Option<String>,
    pub(crate) transport: Transport,
    /// sysfs places it under a virtual or virtio device.
    pub(crate) virtual_path: bool,
    /// sysfs places it behind a network transport (an iSCSI `sessionN`,
    /// a Fibre Channel `rport-…`): someone else's storage.
    pub(crate) remote: bool,
    pub(crate) controller: Option<Controller>,
    /// The SCSI host (`hostN`) and target (`H:C:T:L` → `T`) it sits on.
    pub(crate) scsi_host: Option<u32>,
    pub(crate) scsi_target: Option<u32>,
    /// A partition's whole device.
    pub(crate) parent: Option<String>,
    pub(crate) partitions: Vec<String>,
    pub(crate) holders: Vec<String>,
    pub(crate) slaves: Vec<String>,
    pub(crate) md: Option<MdRaw>,
    pub(crate) udev: Udev,
    /// `/dev/disk/by-id` names of a physical device ([`is_disk_id`]),
    /// sorted.
    pub(crate) ids: Vec<String>,
}

/// The RAID controller a device sits behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Controller {
    /// What to call it: the virtual disk's model (`PERC H330 Mini`), else
    /// the controller driver.
    pub(crate) label: String,
    /// The device is a controller VIRTUAL disk (its model says so): the
    /// controller is in RAID mode for it.
    pub(crate) raid_mode: bool,
    /// A MegaRAID / PERC (`megaraid_sas`): SMART passthrough is
    /// `-d megaraid,N`.
    pub(crate) megaraid: bool,
}

/// One mountinfo line, resolved to a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mount {
    pub(crate) mount_point: PathBuf,
    /// The directory of the filesystem mounted there (`/`, or a bind
    /// mount's own path).
    pub(crate) root: String,
    /// The kernel name of the device mounted there; `None` for a virtual
    /// or network filesystem (or a device not in sysfs).
    pub(crate) device: Option<String>,
    pub(crate) fstype: String,
    pub(crate) read_only: bool,
}

/// Everything the storage section reads from the host, before
/// classification.
#[derive(Debug, Clone, Default)]
pub(crate) struct HostDisks {
    pub(crate) devices: BTreeMap<String, Raw>,
    /// mountinfo order (a later line is on top of an earlier one).
    pub(crate) mounts: Vec<Mount>,
    /// The devices in use as swap.
    pub(crate) swaps: BTreeSet<String>,
    /// Devices `/etc/fstab` mounts on a boot path ([`BOOT_PATHS`]),
    /// mounted now or not.
    pub(crate) boot_configured: BTreeSet<String>,
    /// A boot path is configured (an fstab entry, an automount) but its
    /// device could not be identified: nothing can be proven not to be
    /// a boot partition.
    pub(crate) boot_unresolved: bool,
}

/// Where a boot partition is mounted.
pub(crate) const BOOT_PATHS: [&str; 3] = ["/boot", "/boot/efi", "/efi"];

/// The device an `/etc/fstab` spec names (`UUID=`, `PARTUUID=`,
/// `LABEL=`, their `/dev/disk/by-*` links, `/dev/<name>`,
/// `/dev/mapper/<name>`): EVERY device matching it (dd-cloned ESPs share
/// a filesystem UUID and label). Empty: not identifiable from what udev
/// and sysfs recorded.
fn fstab_devices(
    spec: &str,
    devices: &BTreeMap<String, Raw>,
    dm_names: &BTreeMap<String, String>,
) -> Vec<String> {
    let find = |f: &dyn Fn(&Udev) -> bool| -> Vec<String> {
        devices
            .values()
            .filter(|d| f(&d.udev))
            .map(|d| d.name.clone())
            .collect()
    };
    let eq = |a: &Option<String>, b: &str| a.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(b));
    let tagged = |tag: &str, value: &str| -> Vec<String> {
        match tag {
            "UUID" => find(&|u| eq(&u.fs_uuid, value)),
            "PARTUUID" => find(&|u| eq(&u.part_uuid, value)),
            "LABEL" => find(&|u| u.fs_label.as_deref() == Some(value)),
            _ => Vec::new(),
        }
    };
    if let Some((tag, value)) = spec.split_once('=') {
        return tagged(tag, value.trim_matches('"'));
    }
    for (prefix, tag) in [
        ("/dev/disk/by-uuid/", "UUID"),
        ("/dev/disk/by-partuuid/", "PARTUUID"),
        ("/dev/disk/by-label/", "LABEL"),
    ] {
        if let Some(value) = spec.strip_prefix(prefix) {
            return tagged(tag, value);
        }
    }
    resolve_source(spec, dm_names)
        .filter(|d| devices.contains_key(d))
        .into_iter()
        .collect()
}

/// The boot-path entries of an fstab: `(spec, mount point)`.
fn fstab_boot_entries(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some((
                f.next()?.to_string(),
                f.next()?.trim_end_matches('/').to_string(),
            ))
        })
        .filter(|(_, mp)| BOOT_PATHS.contains(&mp.as_str()))
        .collect()
}

/// Vendor / model words of a RAID controller's virtual disk.
const RAID_MODEL_WORDS: [&str; 5] = [
    "perc",
    "megaraid",
    "logical volume",
    "serveraid",
    "smart array",
];

/// The PCI drivers of a RAID controller.
const RAID_DRIVERS: [&str; 4] = ["megaraid_sas", "hpsa", "smartpqi", "aacraid"];

/// The device families with no hardware below them.
fn kind_of(name: &str) -> DeviceKind {
    if name.starts_with("dm-") {
        DeviceKind::Dm
    } else if name.starts_with("md") {
        DeviceKind::Md
    } else if ["loop", "nbd", "rbd", "zram", "zd", "bcache", "drbd"]
        .iter()
        .any(|p| name.starts_with(p))
    {
        DeviceKind::Virtual
    } else {
        DeviceKind::Disk
    }
}

fn flag(dir: &Path, attr: &str) -> Option<bool> {
    match read_trimmed(&dir.join(attr)).as_deref() {
        Some("1") => Some(true),
        Some("0") => Some(false),
        _ => None,
    }
}

fn sectors_bytes(dir: &Path) -> u64 {
    read_trimmed(&dir.join("size"))
        .and_then(|s| s.parse::<u64>().ok())
        .map_or(0, |s| s.saturating_mul(512))
}

/// The kernel names listed in `dir` (`holders/`, `slaves/`).
fn kernel_links(dir: &Path) -> Vec<String> {
    dir_names(dir)
        .into_iter()
        .filter(|n| is_kernel_name(n))
        .collect()
}

/// `E:KEY=VALUE` lines of a udev database entry.
pub(crate) fn parse_udev(text: &str) -> Udev {
    let mut u = Udev {
        found: true,
        ..Udev::default()
    };
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.strip_prefix("E:").and_then(|l| l.split_once('=')) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        fields.insert(key, value);
        match key {
            "ID_FS_TYPE" => u.fs_type = Some(value.to_string()),
            "ID_FS_UUID" => u.fs_uuid = Some(value.to_string()),
            "ID_PART_TABLE_TYPE" => u.part_table = true,
            "ID_WWN" => u.wwn = Some(value.to_string()),
            "ID_PART_ENTRY_UUID" => u.part_uuid = Some(value.to_string()),
            "ID_FS_LABEL" => u.fs_label = Some(value.to_string()),
            "ID_PART_ENTRY_TYPE" => u.part_entry_typed = true,
            _ => {}
        }
    }
    u.boot = is_boot_entry(&fields);
    u
}

/// The transport from where sysfs places the device (`real`, its
/// resolved `/sys/devices/…` path) and what its SCSI layer says.
fn transport_of(name: &str, kind: DeviceKind, real: &Path, dir: &Path) -> Transport {
    match kind {
        DeviceKind::Md => return Transport::Md,
        DeviceKind::Dm => return Transport::Dm,
        DeviceKind::Virtual => return Transport::Unknown,
        _ => {}
    }
    let components: Vec<String> = real
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let any = |f: &dyn Fn(&str) -> bool| components.iter().any(|c| f(c));
    if any(&|c| c.starts_with("usb")) {
        Transport::Usb
    } else if any(&|c| c.starts_with("virtio")) || name.starts_with("vd") {
        Transport::Virtio
    } else if name.starts_with("nvme") || any(&|c| c == "nvme") {
        Transport::Nvme
    } else if any(&|c| {
        c.strip_prefix("ata")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    }) || read_trimmed(&dir.join("device/vendor")).as_deref() == Some("ATA")
    {
        Transport::Sata
    } else if any(&|c| c.starts_with("end_device-") || c.starts_with("expander-")) {
        Transport::Sas
    } else if any(&|c| {
        c.strip_prefix("host")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    }) {
        Transport::Scsi
    } else {
        Transport::Unknown
    }
}

/// An iSCSI session or a Fibre Channel remote port on the device's path.
fn remote_path(real: &Path) -> bool {
    real.components().any(|c| {
        let c = c.as_os_str().to_string_lossy();
        c.starts_with("rport-")
            || c.strip_prefix("session")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// `hostN` and the `T` of `H:C:T:L` on the device's path.
fn scsi_address(real: &Path) -> (Option<u32>, Option<u32>) {
    let mut host = None;
    let mut target = None;
    for c in real.components() {
        let c = c.as_os_str().to_string_lossy();
        if let Some(n) = c.strip_prefix("host").and_then(|n| n.parse().ok()) {
            host = Some(n);
        }
        let parts: Vec<&str> = c.split(':').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u32>().is_ok()) {
            target = parts[2].parse().ok();
        }
    }
    (host, target)
}

/// The driver of the nearest PCI device above `real`.
fn pci_driver(real: &Path) -> Option<String> {
    real.ancestors()
        .find(|a| {
            a.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(is_pci_address)
        })
        .and_then(|pci| link_name(&pci.join("driver")))
}

fn controller_of(
    model: Option<&str>,
    vendor: Option<&str>,
    real: &Path,
    clean: impl Fn(&str) -> Option<String>,
) -> Option<Controller> {
    let says_raid = |s: Option<&str>| {
        s.is_some_and(|s| {
            let s = s.to_ascii_lowercase();
            RAID_MODEL_WORDS.iter().any(|w| s.contains(w))
        })
    };
    let raid_mode = says_raid(model) || says_raid(vendor);
    let driver = pci_driver(real).filter(|d| RAID_DRIVERS.contains(&d.as_str()));
    if !raid_mode && driver.is_none() {
        return None;
    }
    let megaraid = driver.as_deref() == Some("megaraid_sas")
        || ["perc", "megaraid"]
            .iter()
            .any(|w| model.is_some_and(|m| m.to_ascii_lowercase().contains(w)));
    // A virtual disk is named by its model (`PERC H330 Mini`); a disk the
    // controller passes through (JBOD) by the controller's driver: its
    // model is the physical disk's.
    let label = if raid_mode {
        model.and_then(&clean).or_else(|| vendor.and_then(&clean))
    } else {
        None
    }
    .or(driver)
    .unwrap_or_else(|| "raid".to_string());
    Some(Controller {
        label,
        raid_mode,
        megaraid,
    })
}

fn md_raw(dir: &Path) -> MdRaw {
    let md = dir.join("md");
    MdRaw {
        level: read_trimmed(&md.join("level")),
        state: read_trimmed(&md.join("array_state")),
        degraded: read_trimmed(&md.join("degraded"))
            .and_then(|d| d.parse().ok())
            .unwrap_or(0),
        sync_action: read_trimmed(&md.join("sync_action")),
        sync_completed: read_trimmed(&md.join("sync_completed")).and_then(|s| {
            let (done, total) = s.split_once('/')?;
            Some((done.trim().parse().ok()?, total.trim().parse().ok()?))
        }),
    }
}

/// `/dev/disk/by-id` → `{kernel name: [ids]}`: the links of a physical
/// device only ([`is_disk_id`], never `dm-name-…`), partitions' links
/// (`…-partN`) left out. Only the links are read.
fn by_id(dir: &Path) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in dir_names(dir) {
        if !is_disk_id(&id) || dedicated::is_partition_name(&id) {
            continue;
        }
        let Some(target) = link_name(&dir.join(&id)) else {
            continue;
        };
        if is_kernel_name(&target) {
            out.entry(target).or_default().push(id);
        }
    }
    out
}

/// A `/dev/…` source (mount or swap) to a kernel name, through the dm
/// names for `/dev/mapper/<name>`.
fn resolve_source(source: &str, dm_names: &BTreeMap<String, String>) -> Option<String> {
    if let Some(name) = source.strip_prefix("/dev/mapper/") {
        return dm_names.get(name).cloned();
    }
    let name = source.strip_prefix("/dev/")?;
    is_kernel_name(name).then(|| name.to_string())
}

/// One device directory (`/sys/block/<name>` or a partition under it).
fn read_device(
    name: &str,
    dir: &Path,
    kind: DeviceKind,
    parent: Option<&Raw>,
    paths: &HostPaths,
    ids: &BTreeMap<String, Vec<String>>,
    clean: &dyn Fn(&str) -> Option<String>,
) -> Raw {
    let dev = read_trimmed(&dir.join("dev"));
    let udev = dev
        .as_ref()
        .and_then(|d| read_trimmed(&paths.udev_data.join(format!("b{d}"))))
        .map(|t| parse_udev(&t))
        .unwrap_or_default();
    let mut raw = Raw {
        name: name.to_string(),
        kind,
        dev,
        size_bytes: sectors_bytes(dir),
        removable: false,
        read_only: flag(dir, "ro").unwrap_or(false),
        rotational: None,
        model: None,
        vendor: None,
        transport: Transport::Unknown,
        virtual_path: false,
        remote: false,
        controller: None,
        scsi_host: None,
        scsi_target: None,
        parent: parent.map(|p| p.name.clone()),
        partitions: Vec::new(),
        holders: kernel_links(&dir.join("holders")),
        slaves: kernel_links(&dir.join("slaves")),
        md: None,
        udev,
        ids: ids.get(name).cloned().unwrap_or_default(),
    };
    if let Some(p) = parent {
        raw.removable = p.removable;
        raw.transport = p.transport;
        raw.virtual_path = p.virtual_path;
        raw.remote = p.remote;
        raw.read_only |= p.read_only;
        return raw;
    }
    let real = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    raw.removable = flag(dir, "removable").unwrap_or(false);
    raw.rotational = flag(dir, "queue/rotational");
    raw.model = read_trimmed(&dir.join("device/model"));
    raw.vendor = read_trimmed(&dir.join("device/vendor"));
    raw.transport = transport_of(name, kind, &real, dir);
    raw.virtual_path = dedicated::is_virtual_device(dir);
    raw.remote = remote_path(&real);
    if kind == DeviceKind::Disk {
        raw.controller = controller_of(raw.model.as_deref(), raw.vendor.as_deref(), &real, clean);
        (raw.scsi_host, raw.scsi_target) = scsi_address(&real);
    }
    if kind == DeviceKind::Md {
        raw.md = Some(md_raw(dir));
    }
    raw
}

/// Read every block device, its mounts and swaps. A missing `/sys/block`,
/// udev database or mountinfo is a fault of the section ([`Tally`]).
pub(crate) fn read_host(
    paths: &HostPaths,
    tally: &mut Tally,
    clean: &dyn Fn(&str) -> Option<String>,
) -> HostDisks {
    let block = paths.sys.join("block");
    tally.note(block.is_dir());
    tally.note(paths.udev_data.is_dir());
    let ids = by_id(&paths.by_id);
    let mut devices = BTreeMap::new();
    let mut dm_names: BTreeMap<String, String> = BTreeMap::new();
    for name in dir_names(&block) {
        if !is_kernel_name(&name) {
            continue;
        }
        let dir = block.join(&name);
        let kind = kind_of(&name);
        let mut whole = read_device(&name, &dir, kind, None, paths, &ids, clean);
        // An unattached loop / nbd: nothing there.
        if kind == DeviceKind::Virtual && whole.size_bytes == 0 {
            continue;
        }
        if kind == DeviceKind::Dm {
            if let Some(dm_name) = read_trimmed(&dir.join("dm/name")) {
                dm_names.insert(dm_name, name.clone());
            }
        }
        for part in dedicated::partition_names(&dir, &name) {
            if !is_kernel_name(&part) {
                continue;
            }
            let p = read_device(
                &part,
                &dir.join(&part),
                DeviceKind::Partition,
                Some(&whole),
                paths,
                &ids,
                clean,
            );
            whole.partitions.push(part.clone());
            devices.insert(part, p);
        }
        devices.insert(name, whole);
    }
    let by_dev: BTreeMap<String, String> = devices
        .values()
        .filter_map(|d| Some((d.dev.clone()?, d.name.clone())))
        .collect();
    let mountinfo = match Source::read(&paths.proc.join("1/mountinfo")) {
        Source::Found(t) => Some(t),
        _ => Source::read(&paths.proc.join("self/mountinfo")).found(),
    };
    tally.note(mountinfo.is_some());
    let mounts: Vec<Mount> = mountinfo
        .as_deref()
        .map(parse_mountinfo_sources)
        .unwrap_or_default()
        .into_iter()
        .map(|m: MountEntry| Mount {
            device: by_dev
                .get(&m.dev)
                .cloned()
                .or_else(|| resolve_source(&m.source, &dm_names))
                .filter(|d| devices.contains_key(d)),
            mount_point: m.mount_point,
            root: m.root,
            fstype: m.fstype,
            read_only: m.read_only,
        })
        .collect();
    let swaps = tally
        .optional(Source::read(&paths.proc.join("swaps")))
        .map(|text| {
            text.lines()
                .skip(1)
                .filter_map(|l| l.split_whitespace().next())
                .filter_map(|s| resolve_source(s, &dm_names))
                .filter(|d| devices.contains_key(d))
                .collect()
        })
        .unwrap_or_default();
    // Boot paths: what fstab configures there (mounted or not), and an
    // automount there whose device nothing names.
    let mut boot_configured = BTreeSet::new();
    let mut boot_unresolved = false;
    let mut resolved_paths: BTreeSet<String> = BTreeSet::new();
    if let Some(text) = tally.optional(Source::read(&paths.fstab)) {
        for (spec, mp) in fstab_boot_entries(&text) {
            let found = fstab_devices(&spec, &devices, &dm_names);
            if found.is_empty() {
                boot_unresolved = true;
            } else {
                boot_configured.extend(found);
                resolved_paths.insert(mp);
            }
        }
    }
    let typed_boot = devices
        .values()
        .any(|d| d.kind == DeviceKind::Partition && d.udev.boot);
    for m in &mounts {
        let Some(mp) = m.mount_point.to_str() else {
            continue;
        };
        if !BOOT_PATHS.contains(&mp) {
            continue;
        }
        if m.device.is_some() {
            resolved_paths.insert(mp.to_string());
        }
    }
    for m in &mounts {
        let Some(mp) = m.mount_point.to_str() else {
            continue;
        };
        // systemd-gpt-auto mounts the ESP / XBOOTLDR by its type GUID:
        // a typed boot partition identifies it.
        if m.fstype == "autofs"
            && BOOT_PATHS.contains(&mp)
            && !resolved_paths.contains(mp)
            && !typed_boot
        {
            boot_unresolved = true;
        }
    }
    HostDisks {
        devices,
        mounts,
        swaps,
        boot_configured,
        boot_unresolved,
    }
}

impl HostDisks {
    /// The mount `path` is on: the deepest mount point holding it, the
    /// last such line among equals (the one visible there).
    pub(crate) fn mount_of(&self, path: &Path) -> Option<&Mount> {
        self.mounts
            .iter()
            .enumerate()
            .filter(|(_, m)| path.starts_with(&m.mount_point))
            .max_by_key(|(i, m)| (m.mount_point.components().count(), *i))
            .map(|(_, m)| m)
    }

    /// Every mount whose mount point is on `path`'s prefix chain (`/`,
    /// `/mnt`, `/mnt/x` for `/mnt/x/pool`).
    pub(crate) fn mounts_above<'a>(&'a self, path: &'a Path) -> impl Iterator<Item = &'a Mount> {
        self.mounts
            .iter()
            .filter(move |m| path.starts_with(&m.mount_point))
    }

    /// Whether `/` resolves to a block device of this host. When it does
    /// not (a ZFS root, `/dev/root` on an anonymous device, no mountinfo)
    /// nothing can be proven not to be the system.
    pub(crate) fn root_resolved(&self) -> bool {
        self.mount_of(Path::new("/"))
            .is_some_and(|m| m.mount_point == Path::new("/") && m.device.is_some())
    }

    /// Whether `path` is itself a mount point.
    pub(crate) fn is_mount_point(&self, path: &Path) -> bool {
        self.mounts.iter().any(|m| m.mount_point == path)
    }
}
