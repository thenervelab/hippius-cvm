//! Fixture hosts for the storage section: `sys/block` links into a
//! `sys/devices` tree, the udev database, `/dev/disk/by-id` links,
//! mountinfo and swaps under a temp dir, and canned tool output. No test
//! touches a device or a tool of the machine it runs on.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use hippius_host_inventory::{
    is_disk_id, Advisory, AdvisoryCode, AdvisorySubject, Device, DeviceKind, DeviceRole,
    IneligibleReason as R, SectionStatus, Sections, Severity, StorageSection, Transport,
    MAX_ADVISORIES, MAX_DEVICES,
};

use super::super::fixture::{Host, Runner};
use super::super::{normalize_and_check, CommandError, CommandRunner, Mode};
use super::health::{self, SMART_BUDGET};
use super::*;

const TIB: u64 = 1024 * 1024 * 1024 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;
const NOW: i64 = 1_800_000_000;

// ─── fixture building ────────────────────────────────────────────────

/// A whole device `name` at `sys/<devpath>/block/<name>`, linked from
/// `sys/block/<name>`. Returns its directory.
fn block(h: &Host, name: &str, devpath: &str, dev: &str, bytes: u64) -> String {
    let dir = format!("sys/{devpath}/block/{name}");
    h.write(&format!("{dir}/dev"), format!("{dev}\n"));
    h.write(&format!("{dir}/size"), format!("{}\n", bytes / 512));
    h.write(&format!("{dir}/ro"), "0\n");
    h.write(&format!("{dir}/removable"), "0\n");
    h.symlink(
        &format!("sys/block/{name}"),
        &format!("../{devpath}/block/{name}"),
    );
    dir
}

/// A partition `name` of the disk at `disk`.
fn part(h: &Host, disk: &str, name: &str, dev: &str, bytes: u64) -> String {
    let dir = format!("{disk}/{name}");
    h.write(&format!("{dir}/partition"), "1\n");
    h.write(&format!("{dir}/dev"), format!("{dev}\n"));
    h.write(&format!("{dir}/size"), format!("{}\n", bytes / 512));
    h.write(&format!("{dir}/ro"), "0\n");
    dir
}

fn attr(h: &Host, dir: &str, rel: &str, value: &str) {
    h.write(&format!("{dir}/{rel}"), format!("{value}\n"));
}

fn holder(h: &Host, dir: &str, holder: &str) {
    h.mkdir(&format!("{dir}/holders/{holder}"));
}

fn slave(h: &Host, dir: &str, slave: &str) {
    h.mkdir(&format!("{dir}/slaves/{slave}"));
}

fn udev(h: &Host, dev: &str, lines: &str) {
    h.write(&format!("run/udev/data/b{dev}"), lines);
}

fn by_id(h: &Host, id: &str, name: &str) {
    h.symlink(&format!("dev/disk/by-id/{id}"), &format!("../../{name}"));
}

fn mountinfo(h: &Host, lines: &str) {
    h.write("proc/1/mountinfo", lines);
}

/// A directory under the fixture's host root (a pool path, the state
/// root), so its `statvfs` answers.
fn host_dir(h: &Host, path: &str) {
    h.mkdir(&format!("root{path}"));
}

fn view(state_root: &str, pools: &[(&str, &str)], dedicated: &[&str]) -> StorageView {
    StorageView {
        state_root: PathBuf::from(state_root),
        pools: pools
            .iter()
            .map(|(id, path)| ViewPool {
                id: (*id).to_string(),
                path: PathBuf::from(path),
            })
            .collect(),
        dedicated: dedicated.iter().map(|d| (*d).to_string()).collect(),
    }
}

const SATA0: &str = "devices/pci0000:00/0000:00:11.5/ata1/host0/target0:0:0/0:0:0:0";
const SATA1: &str = "devices/pci0000:00/0000:00:11.5/ata2/host1/target1:0:0/1:0:0:0";
const USB: &str = "devices/pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.0/host2/target2:0:0/2:0:0:0";
const NVME0: &str = "devices/pci0000:40/0000:40:01.1/0000:41:00.0/nvme/nvme0";
const NVME1: &str = "devices/pci0000:40/0000:40:01.2/0000:42:00.0/nvme/nvme1";
const VIRTUAL: &str = "devices/virtual";

pub(crate) const SDB_WWN: &str = "wwn-0x5000c500a1b2c3d4";

/// The NVMe host: `md127` (raid1 over `nvme0n1` + `nvme1n1`, ext4) holds
/// the pool `nvme0` at `/mnt/hippius-data`; `sda` (SATA, `sda1`
/// `/boot/efi`, `sda2` `/`, the `default` pool and the state root);
/// `sdb` a bare 4 TiB SATA HDD; `sdc` a USB stick; `loop1` a snap.
pub(crate) fn nvme_md_host(h: &Host) -> StorageView {
    for (name, path, dev, serial) in [
        ("nvme0n1", NVME0, "259:0", "S64HNE0R100001"),
        ("nvme1n1", NVME1, "259:1", "S64HNE0R100002"),
    ] {
        let d = block(h, name, path, dev, 3_840_000_000_000);
        attr(h, &d, "queue/rotational", "0");
        attr(h, &d, "device/model", "SAMSUNG MZQL23T8HCLS-00A07");
        holder(h, &d, "md127");
        udev(
            h,
            dev,
            "E:ID_FS_TYPE=linux_raid_member\nE:ID_FS_UUID=1111\nE:ID_SERIAL=x\n",
        );
        by_id(
            h,
            &format!("nvme-SAMSUNG_MZQL23T8HCLS-00A07_{serial}"),
            name,
        );
        by_id(
            h,
            &format!("nvme-SAMSUNG_MZQL23T8HCLS-00A07_{serial}_1"),
            name,
        );
    }
    let md = block(h, "md127", VIRTUAL, "9:127", 3_840_000_000_000);
    attr(h, &md, "queue/rotational", "0");
    slave(h, &md, "nvme0n1");
    slave(h, &md, "nvme1n1");
    attr(h, &md, "md/level", "raid1");
    attr(h, &md, "md/array_state", "clean");
    attr(h, &md, "md/degraded", "0");
    attr(h, &md, "md/sync_action", "idle");
    attr(h, &md, "md/sync_completed", "none");
    udev(h, "9:127", "E:ID_FS_TYPE=ext4\nE:ID_FS_UUID=2222\n");
    by_id(h, "md-uuid-aaaa:bbbb", "md127");

    let sda = block(h, "sda", SATA0, "8:0", 480 * GIB);
    attr(h, &sda, "queue/rotational", "0");
    attr(h, &sda, "device/model", "INTEL SSDSC2KB48");
    attr(h, &sda, "device/vendor", "ATA");
    udev(h, "8:0", "E:ID_PART_TABLE_TYPE=gpt\nE:ID_WWN=0x55cd2e41\n");
    part(h, &sda, "sda1", "8:1", GIB);
    part(h, &sda, "sda2", "8:2", 470 * GIB);
    udev(h, "8:1", "E:ID_FS_TYPE=vfat\n");
    udev(h, "8:2", "E:ID_FS_TYPE=ext4\nE:ID_FS_UUID=3333\n");
    by_id(h, "ata-INTEL_SSDSC2KB480G8_PHYF000001", "sda");
    by_id(h, "ata-INTEL_SSDSC2KB480G8_PHYF000001-part1", "sda1");
    by_id(h, "wwn-0x55cd2e41", "sda");

    let sdb = block(h, "sdb", SATA1, "8:16", 4 * TIB);
    attr(h, &sdb, "queue/rotational", "1");
    attr(h, &sdb, "device/model", "ST4000NM0035-1V4");
    attr(h, &sdb, "device/vendor", "ATA");
    udev(h, "8:16", "E:ID_WWN=0x5000c500a1b2c3d4\n");
    by_id(h, "ata-ST4000NM0035-1V4107_ZC10000A", "sdb");
    by_id(h, SDB_WWN, "sdb");

    let sdc = block(h, "sdc", USB, "8:32", 32 * GIB);
    attr(h, &sdc, "removable", "1");
    attr(h, &sdc, "device/model", "Ultra Fit");
    attr(h, &sdc, "device/vendor", "SanDisk");
    part(h, &sdc, "sdc1", "8:33", 32 * GIB);
    udev(h, "8:32", "E:ID_PART_TABLE_TYPE=dos\n");
    udev(h, "8:33", "E:ID_FS_TYPE=vfat\n");
    by_id(h, "usb-SanDisk_Ultra_Fit_0101-0:0", "sdc");

    block(h, "loop0", VIRTUAL, "7:0", 0);
    block(h, "loop1", VIRTUAL, "7:1", 64 * 1024 * 1024);
    // Not a kernel-name family the crate carries: dropped.
    block(h, "ram0", VIRTUAL, "1:0", 16 * 1024 * 1024);

    mountinfo(
        h,
        "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n\
         23 22 8:1 / /boot/efi rw,relatime shared:2 - vfat /dev/sda1 rw\n\
         24 22 9:127 / /mnt/hippius-data rw,relatime shared:3 - ext4 /dev/md127 rw\n\
         25 22 0:22 / /proc rw,nosuid - proc proc rw\n\
         26 22 0:45 / /mnt/nfs rw - nfs4 server:/export rw\n\
         27 22 7:1 / /snap/core rw - squashfs /dev/loop1 ro\n",
    );
    h.write("proc/swaps", "Filename Type Size Used Priority\n");
    host_dir(h, "/var/lib/hippius-miner");
    host_dir(h, "/mnt/hippius-data");
    view(
        "/var/lib/hippius-miner",
        &[
            ("default", "/var/lib/hippius-miner"),
            ("nvme0", "/mnt/hippius-data"),
        ],
        &[],
    )
}

// ─── canned tool output ──────────────────────────────────────────────

/// `smartctl -j` of a SATA HDD: everything §18.3 reads, plus text that
/// must never leave the collector.
fn smart_ata(
    passed: bool,
    reallocated: u64,
    pending: u64,
    offline: u64,
    crc: u64,
    temp: i64,
    rotation: u64,
) -> String {
    format!(
        r#"{{"json_format_version":[1,0],
  "smartctl":{{"version":[7,4],"exit_status":{exit},
    "messages":[{{"string":"RAW-TOOL-LINE do not forward","severity":"warning"}}]}},
  "device":{{"name":"/dev/sdb","type":"sat","protocol":"ATA"}},
  "model_name":"ST4000NM0035-1V4107","serial_number":"ZC10000A-SMART-SERIAL",
  "rotation_rate":{rotation},
  "smart_status":{{"passed":{passed}}},
  "ata_smart_attributes":{{"revision":10,"table":[
    {{"id":1,"name":"Raw_Read_Error_Rate","raw":{{"value":123456,"string":"123456"}}}},
    {{"id":5,"name":"Reallocated_Sector_Ct","raw":{{"value":{reallocated},"string":"{reallocated}"}}}},
    {{"id":197,"name":"Current_Pending_Sector","raw":{{"value":{pending},"string":"{pending}"}}}},
    {{"id":198,"name":"Offline_Uncorrectable","raw":{{"value":{offline},"string":"{offline}"}}}},
    {{"id":199,"name":"UDMA_CRC_Error_Count","raw":{{"value":{crc},"string":"{crc}"}}}}]}},
  "power_on_time":{{"hours":30000}},
  "temperature":{{"current":{temp}}},
  "ata_smart_error_log":{{"summary":{{"revision":1,"count":0}}}}}}"#,
        exit = if passed { 0 } else { 8 },
    )
}

fn healthy_ata() -> String {
    smart_ata(true, 0, 0, 0, 0, 35, 7200)
}

/// `nvme smart-log -o json` (temperature in kelvin).
fn nvme_log(warning: u64, kelvin: u64, spare: u64, thresh: u64, used: u64, media: u64) -> String {
    format!(
        r#"{{"critical_warning":{warning},"temperature":{kelvin},"avail_spare":{spare},
  "spare_thresh":{thresh},"percent_used":{used},"endurance_grp_critical_warning_summary":0,
  "data_units_read":123,"data_units_written":456,"media_errors":{media},
  "num_err_log_entries":0,"warning_temp_time":0,"critical_comp_time":0}}"#
    )
}

fn healthy_nvme() -> String {
    nvme_log(0, 310, 100, 10, 3, 0)
}

const SMARTCTL_SDA: &str = "smartctl -j -H -A -l error -n standby,0 /dev/sda";
const SMARTCTL_SDB: &str = "smartctl -j -H -A -l error -n standby,0 /dev/sdb";
const SMARTCTL_SDC: &str = "smartctl -j -H -A -l error -n standby,0 /dev/sdc";
const NVME0_LOG: &str = "nvme smart-log -o json /dev/nvme0n1";
const NVME1_LOG: &str = "nvme smart-log -o json /dev/nvme1n1";

/// Every tool of the NVMe host answering healthy.
fn healthy_runner() -> Runner {
    let ata = healthy_ata();
    let nvme = healthy_nvme();
    Runner::default()
        .with(SMARTCTL_SDA, Ok(&smart_ata(true, 0, 0, 0, 0, 30, 0)))
        .with(SMARTCTL_SDB, Ok(&ata))
        .with(NVME0_LOG, Ok(&nvme))
        .with(NVME1_LOG, Ok(&nvme))
}

// ─── helpers ─────────────────────────────────────────────────────────

fn collect_with(
    h: &Host,
    runner: &dyn CommandRunner,
    view: Option<&StorageView>,
    previous: &Counters,
    budget: Duration,
) -> (StorageSection, Counters) {
    let inputs = StorageInputs {
        view,
        previous,
        deadline: std::time::Instant::now() + budget,
        min_probe_window: Duration::ZERO,
        clock: &super::super::SystemClock,
        kernel: &[],
    };
    let (section, counters) = collect_storage(&h.paths(), runner, &inputs, NOW).unwrap();
    (checked(section), counters)
}

fn collect(h: &Host, runner: &dyn CommandRunner, view: &StorageView) -> StorageSection {
    collect_with(h, runner, Some(view), &Counters::default(), SMART_BUDGET).0
}

/// The section normalized and validated through the crate, as the agent
/// will.
fn checked(section: StorageSection) -> StorageSection {
    let c = normalize_and_check(
        Sections {
            storage: Some(section),
            ..Sections::default()
        },
        Mode::Counters,
        NOW,
    );
    assert_eq!(c.valid, Ok(()));
    c.sections.storage.unwrap()
}

fn dev<'a>(s: &'a StorageSection, name: &str) -> &'a Device {
    s.devices
        .iter()
        .find(|d| d.name == name)
        .unwrap_or_else(|| panic!("{name} not in {:?}", names(s)))
}

fn names(s: &StorageSection) -> Vec<&str> {
    s.devices.iter().map(|d| d.name.as_str()).collect()
}

fn adv<'a>(s: &'a StorageSection, subject: &str, code: AdvisoryCode) -> Option<&'a Advisory> {
    s.advisories
        .iter()
        .find(|a| a.subject == subject && a.code == code)
}

fn codes(s: &StorageSection) -> Vec<(AdvisorySubject, &str, AdvisoryCode, Severity)> {
    s.advisories
        .iter()
        .map(|a| (a.subject_kind, a.subject.as_str(), a.code, a.severity))
        .collect()
}

fn reasons(d: &Device) -> Vec<R> {
    d.reasons.clone()
}

/// Nothing in `s` is offered: no device a dashboard could suggest wiping
/// or declaring.
fn assert_never_offered(s: &StorageSection) {
    for d in &s.devices {
        assert!(
            !matches!(
                d.role,
                DeviceRole::EligibleDedicated | DeviceRole::EligiblePool | DeviceRole::NeedsPrep
            ),
            "{} is {:?}",
            d.name,
            d.role
        );
    }
}

/// `name` is neither `eligible_dedicated` nor `needs_prep`.
fn assert_not_free(s: &StorageSection, name: &str) {
    let d = dev(s, name);
    assert!(
        !matches!(
            d.role,
            DeviceRole::EligibleDedicated | DeviceRole::NeedsPrep
        ),
        "{name} is {:?} {:?}",
        d.role,
        d.reasons
    );
}

// ─── inventory and classification ────────────────────────────────────

#[test]
fn nvme_md_host_inventory_and_roles() {
    let h = Host::new();
    let v = nvme_md_host(&h);
    let s = collect(&h, &healthy_runner(), &v);
    assert_eq!(s.status, SectionStatus::Ok, "{:?}", s.advisories);
    assert_eq!(
        names(&s),
        ["loop1", "md127", "nvme0n1", "nvme1n1", "sda", "sda1", "sda2", "sdb", "sdc", "sdc1"],
        "loop0 (empty) and ram0 (no crate family) dropped"
    );

    let md = dev(&s, "md127");
    assert_eq!(md.kind, DeviceKind::Md);
    assert_eq!(md.transport, Transport::Md);
    assert_eq!(md.role, DeviceRole::PoolBacking);
    assert_eq!(md.pool_ids, ["nvme0"]);
    assert_eq!(md.mounts, ["/mnt/hippius-data"]);
    assert!(md.ids.is_empty(), "md-uuid- is no physical family");
    let info = md.md.as_ref().unwrap();
    assert_eq!(
        (info.level.as_str(), info.state.as_str(), info.degraded),
        ("raid1", "clean", 0)
    );
    assert_eq!(info.members, ["nvme0n1", "nvme1n1"]);
    let fs = md.fs.as_ref().unwrap();
    assert_eq!(fs.fs_type, "ext4");
    assert!(fs.uuid_present);
    assert!(fs.size_bytes.is_some() && fs.available_bytes.is_some());

    for n in ["nvme0n1", "nvme1n1"] {
        let d = dev(&s, n);
        assert_eq!(d.transport, Transport::Nvme);
        assert_eq!(d.role, DeviceRole::Member, "{n}");
        assert_eq!(d.pool_ids, ["nvme0"], "{n} backs the pool through md127");
        assert_eq!(reasons(d), [R::HolderBusy]);
        assert_eq!(d.holders, ["md127"]);
        assert_eq!(d.rotational_hint, Some(false));
        assert_eq!(d.ids.len(), 2);
        assert_eq!(d.fs.as_ref().unwrap().fs_type, "linux_raid_member");
    }

    let sda = dev(&s, "sda");
    assert_eq!(sda.transport, Transport::Sata);
    assert_eq!(sda.role, DeviceRole::System);
    assert_eq!(sda.partitions, ["sda1", "sda2"]);
    assert_eq!(
        sda.ids,
        ["ata-INTEL_SSDSC2KB480G8_PHYF000001", "wwn-0x55cd2e41"],
        "a partition's link is left out"
    );
    assert_eq!(sda.pool_ids, ["default"]);
    let sda2 = dev(&s, "sda2");
    assert_eq!(sda2.kind, DeviceKind::Partition);
    assert_eq!(sda2.role, DeviceRole::System);
    assert_eq!(
        sda2.transport,
        Transport::Sata,
        "a partition takes its disk's"
    );
    assert_eq!(sda2.mounts, ["/"]);
    assert!(sda2.fs.as_ref().unwrap().size_bytes.is_some(), "state root");
    let sda1 = dev(&s, "sda1");
    assert_eq!(sda1.role, DeviceRole::System);
    assert!(sda1.ids.is_empty(), "no `-partN` link: {:?}", sda1.ids);
    assert_eq!(sda1.fs.as_ref().unwrap().size_bytes, None, "not a pool fs");

    let sdb = dev(&s, "sdb");
    assert_eq!(sdb.role, DeviceRole::EligibleDedicated);
    assert!(sdb.reasons.is_empty());
    assert_eq!(sdb.rotational_hint, Some(true));
    assert_eq!(sdb.model.as_deref(), Some("ST4000NM0035-1V4"));

    let sdc = dev(&s, "sdc");
    assert_eq!(sdc.transport, Transport::Usb);
    assert!(sdc.removable);
    assert_eq!(sdc.role, DeviceRole::Ineligible);
    for r in [R::Removable, R::Usb, R::HasPartitions, R::TooSmall] {
        assert!(sdc.reasons.contains(&r), "{r:?} in {:?}", sdc.reasons);
    }
    assert_eq!(dev(&s, "sdc1").role, DeviceRole::Ineligible);

    let loop1 = dev(&s, "loop1");
    assert_eq!(loop1.kind, DeviceKind::Virtual);
    assert_eq!(loop1.role, DeviceRole::Ineligible);
    assert!(loop1.reasons.contains(&R::Virtual));

    // A healthy host raises only the power-on hours (info).
    for a in &s.advisories {
        assert_eq!(a.code, AdvisoryCode::PowerOnHours, "{a:?}");
        assert_eq!(a.severity, Severity::Info);
    }
}

#[test]
fn a_declared_dedicated_disk_is_dedicated_free_and_its_advisories_use_its_by_id() {
    let h = Host::new();
    let mut v = nvme_md_host(&h);
    v.dedicated = vec![SDB_WWN.to_string()];
    let runner = healthy_runner().with(SMARTCTL_SDB, Ok(&smart_ata(true, 4, 0, 0, 0, 35, 7200)));
    let s = collect(&h, &runner, &v);
    let sdb = dev(&s, "sdb");
    assert_eq!(sdb.role, DeviceRole::DedicatedFree);
    assert!(sdb.reasons.is_empty());
    let a = adv(&s, SDB_WWN, AdvisoryCode::ReallocatedSectors).unwrap();
    assert_eq!(a.subject_kind, AdvisorySubject::DedicatedDisk);
    assert_eq!(a.severity, Severity::Warning);
}

#[test]
fn two_pools_on_one_filesystem_and_mount_signals() {
    let h = Host::new();
    let mut v = nvme_md_host(&h);
    v.pools = vec![
        ViewPool {
            id: "default".into(),
            path: "/var/lib/hippius-miner".into(),
        },
        ViewPool {
            id: "fast".into(),
            path: "/mnt/hippius-data/fast".into(),
        },
        ViewPool {
            id: "bulk".into(),
            path: "/mnt/hippius-data/bulk".into(),
        },
    ];
    let s = collect(&h, &healthy_runner(), &v);
    let md = dev(&s, "md127");
    assert_eq!(md.role, DeviceRole::PoolBacking);
    assert_eq!(md.pool_ids, ["bulk", "fast"]);
    // Neither is a filesystem of its own: both `mount_missing`; `default`
    // may sit on `/`.
    for p in ["bulk", "fast"] {
        let a = adv(&s, p, AdvisoryCode::MountMissing).unwrap();
        assert_eq!(
            (a.subject_kind, a.severity),
            (AdvisorySubject::Pool, Severity::Critical)
        );
    }
    assert!(adv(&s, "default", AdvisoryCode::MountMissing).is_none());

    // A read-only pool filesystem.
    let h = Host::new();
    let v = nvme_md_host(&h);
    mountinfo(
        &h,
        "22 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n\
         24 22 9:127 / /mnt/hippius-data ro,relatime - ext4 /dev/md127 ro\n",
    );
    let s = collect(&h, &healthy_runner(), &v);
    let a = adv(&s, "nvme0", AdvisoryCode::MountRo).unwrap();
    assert_eq!(a.severity, Severity::Critical);
    assert!(adv(&s, "nvme0", AdvisoryCode::MountMissing).is_none());
    assert!(adv(&s, "default", AdvisoryCode::MountRo).is_none());
}

#[test]
fn md_degraded_and_rebuilding() {
    let h = Host::new();
    let v = nvme_md_host(&h);
    let md = format!("sys/{VIRTUAL}/block/md127");
    attr(&h, &md, "md/degraded", "1");
    attr(&h, &md, "md/sync_action", "recover");
    attr(&h, &md, "md/sync_completed", "1875000000 / 3750000000");
    let s = collect(&h, &healthy_runner(), &v);
    let d = adv(&s, "md127", AdvisoryCode::MdDegraded).unwrap();
    assert_eq!(
        (d.subject_kind, d.severity, d.value),
        (AdvisorySubject::Md, Severity::Critical, 1)
    );
    let r = adv(&s, "md127", AdvisoryCode::MdRebuilding).unwrap();
    assert_eq!((r.severity, r.value), (Severity::Info, 50));
    assert_eq!(r.sample.as_deref(), Some("recover 50% complete"));
    assert_eq!(dev(&s, "md127").md.as_ref().unwrap().degraded, 1);
}

/// The PERC host: `sda` (holding `/`) and `sdb` are "PERC H330 Mini"
/// virtual disks on a `megaraid_sas` controller; its scan lists
/// `megaraid,0` and `megaraid,1`.
fn perc_host(h: &Host) -> StorageView {
    let ctrl = "devices/pci0000:00/0000:00:03.1/0000:03:00.0";
    h.symlink(
        &format!("sys/{ctrl}/driver"),
        "../../../../bus/pci/drivers/megaraid_sas",
    );
    for (name, target, dev, bytes) in [("sda", 0, "8:0", 480 * GIB), ("sdb", 1, "8:16", 2 * TIB)] {
        let path = format!("{ctrl}/host0/target0:2:{target}/0:2:{target}:0");
        let d = block(h, name, &path, dev, bytes);
        attr(h, &d, "queue/rotational", "1");
        attr(h, &d, "device/model", "PERC H330 Mini");
        attr(h, &d, "device/vendor", "DELL");
        by_id(
            h,
            &format!("scsi-36d0946606d5f2a002c9b0d6e1c4a0f0{target}"),
            name,
        );
    }
    // A disk the controller passes through (JBOD): its own model.
    let jbod = block(
        h,
        "sdc",
        &format!("{ctrl}/host0/target0:0:4/0:0:4:0"),
        "8:32",
        4 * TIB,
    );
    attr(h, &jbod, "device/model", "SAMSUNG MZ7LH3T8");
    attr(h, &jbod, "device/vendor", "ATA");
    udev(h, "8:32", "E:ID_WWN=0x5002538e00000001\n");
    by_id(h, "wwn-0x5002538e00000001", "sdc");
    let sda = format!("sys/{ctrl}/host0/target0:2:0/0:2:0:0/block/sda");
    part(h, &sda, "sda1", "8:1", 479 * GIB);
    udev(h, "8:0", "E:ID_PART_TABLE_TYPE=gpt\n");
    udev(h, "8:1", "E:ID_FS_TYPE=ext4\n");
    mountinfo(h, "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n");
    view(
        "/var/lib/hippius-miner",
        &[("default", "/var/lib/hippius-miner")],
        &[],
    )
}

const SCAN_OPEN: &str = r#"{"smartctl":{"exit_status":0},"devices":[
  {"name":"/dev/sda","info_name":"/dev/sda","type":"scsi","protocol":"SCSI"},
  {"name":"/dev/bus/0","info_name":"/dev/bus/0 [megaraid_disk_00]","type":"megaraid,0","protocol":"ATA"},
  {"name":"/dev/bus/0","info_name":"/dev/bus/0 [megaraid_disk_01]","type":"megaraid,1","protocol":"ATA"},
  {"name":"/dev/../etc/x","type":"megaraid,2"},
  {"name":"/dev/bus/0","type":"megaraid,1;rm"}]}"#;

/// The scan: SCSI-class only (smartctl 7.5 refuses `-d megaraid` as a
/// scan type; `-d scsi` lists the controller's disks, never opens an NVMe,
/// and sends a direct SATA /dev/sdX one IDENTIFY).
const SCAN_CMD: &str = "smartctl --scan-open -d scsi -j";
/// The former scan, and what smartctl 7.5 answers it (a Dell PowerEdge host).
const OLD_SCAN_CMD: &str = "smartctl --scan-open -d megaraid -j";
const OLD_SCAN_75: &str = r#"{"json_format_version":[1,0],"smartctl":{"version":[7,5],"svn_revision":"5714","exit_status":1,"messages":[{"string":"Invalid type 'megaraid', valid arguments are: by-id, ata, scsi, sat, nvme","severity":"error"}]}}"#;
/// smartctl 7.5 (svn 5714) `--scan-open -d scsi -j` on the PERC H330 Mini
/// of a Dell PowerEdge host: the virtual disk and the two SATA SSDs
/// behind it, SAT-tunnelled.
const SCAN_OPEN_75: &str = r#"{"json_format_version":[1,0],"smartctl":{"version":[7,5],"svn_revision":"5714","exit_status":0},"devices":[
  {"name":"/dev/sda","info_name":"/dev/sda","type":"scsi","protocol":"SCSI"},
  {"name":"/dev/bus/0","info_name":"/dev/bus/0 [megaraid_disk_00] [SAT]","type":"sat+megaraid,0","protocol":"ATA"},
  {"name":"/dev/bus/0","info_name":"/dev/bus/0 [megaraid_disk_01] [SAT]","type":"sat+megaraid,1","protocol":"ATA"}]}"#;
/// The same host's plain `--scan-open -j`: `/dev/sda` with its open error.
const PLAIN_SCAN_OPEN_75: &str = r#"{"json_format_version":[1,0],"smartctl":{"version":[7,5],"svn_revision":"5714","exit_status":0},"devices":[
  {"name":"/dev/sda","info_name":"/dev/sda","type":"scsi","protocol":"SCSI","open_error":"DELL or MegaRaid controller, please try adding '-d megaraid,N'"},
  {"name":"/dev/bus/0","info_name":"/dev/bus/0 [megaraid_disk_00] [SAT]","type":"sat+megaraid,0","protocol":"ATA"},
  {"name":"/dev/bus/0","info_name":"/dev/bus/0 [megaraid_disk_01] [SAT]","type":"sat+megaraid,1","protocol":"ATA"}]}"#;
/// The same scan without `-j`.
const SCAN_OPEN_75_TEXT: &str = "/dev/sda -d scsi # /dev/sda, SCSI device
/dev/bus/0 -d sat+megaraid,0 # /dev/bus/0 [megaraid_disk_00] [SAT], ATA device
/dev/bus/0 -d sat+megaraid,1 # /dev/bus/0 [megaraid_disk_01] [SAT], ATA device
";
const SAT_PD0: &str = "smartctl -j -H -A -l error -n standby,0 -d sat+megaraid,0 /dev/bus/0";
const SAT_PD1: &str = "smartctl -j -H -A -l error -n standby,0 -d sat+megaraid,1 /dev/bus/0";

#[test]
fn smartctl_7_5_sat_megaraid_disks_are_probed_behind_the_perc() {
    let h = Host::new();
    let v = perc_host(&h);
    let runner = Runner::default()
        // A regression to the former scan gets smartctl 7.5's refusal.
        .with(OLD_SCAN_CMD, Ok(OLD_SCAN_75))
        .with(SCAN_CMD, Ok(SCAN_OPEN_75))
        .with(SAT_PD0, Ok(&smart_ata(true, 2, 0, 0, 0, 30, 0)))
        .with(SAT_PD1, Ok(&healthy_ata()))
        .with(SMARTCTL_SDC, Ok(&healthy_ata()));
    let s = collect(&h, &runner, &v);
    let pd0 = adv(
        &s,
        "ctrl:PERC H330 Mini:pd0",
        AdvisoryCode::ReallocatedSectors,
    )
    .unwrap();
    assert_eq!(
        (pd0.subject_kind, pd0.value),
        (AdvisorySubject::Controller, 2)
    );
    assert!(adv(&s, "ctrl:PERC H330 Mini:pd1", AdvisoryCode::PowerOnHours).is_some());
    assert!(
        s.advisories
            .iter()
            .all(|a| a.code != AdvisoryCode::SmartUnavailableBehindController),
        "{:?}",
        codes(&s)
    );
}

/// Records every command line run, in order.
struct Lines {
    inner: Runner,
    log: std::sync::Mutex<Vec<String>>,
}

impl CommandRunner for Lines {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, CommandError> {
        let line = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>();
        self.log.lock().unwrap().push(line.join(" "));
        self.inner.run(program, args)
    }
}

#[test]
fn the_scan_is_exactly_the_scsi_one_and_only_on_a_megaraid_host() {
    let h = Host::new();
    let v = perc_host(&h);
    let runner = Lines {
        inner: Runner::default()
            .with(SCAN_CMD, Ok(SCAN_OPEN_75))
            .with(SAT_PD0, Ok(&healthy_ata()))
            .with(SAT_PD1, Ok(&healthy_ata()))
            .with(SMARTCTL_SDC, Ok(&healthy_ata())),
        log: std::sync::Mutex::new(Vec::new()),
    };
    collect(&h, &runner, &v);
    let scans: Vec<String> = runner
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains("--scan"))
        .cloned()
        .collect();
    assert_eq!(scans, [SCAN_CMD]);
    // No MegaRAID virtual disk: no scan at all.
    let h = Host::new();
    let v = nvme_md_host(&h);
    let runner = Lines {
        inner: healthy_runner(),
        log: std::sync::Mutex::new(Vec::new()),
    };
    collect(&h, &runner, &v);
    let log = runner.log.lock().unwrap();
    assert!(!log.is_empty(), "the probe ran");
    assert!(log.iter().all(|l| !l.contains("--scan")), "{log:?}");
}

#[test]
fn a_scan_timeout_is_one_controller_timeout() {
    let h = Host::new();
    let v = perc_host(&h);
    let runner = Runner::default()
        .with(SCAN_CMD, Err(CommandError::Timeout))
        .with(SAT_PD0, Ok(&healthy_ata()))
        .with(SMARTCTL_SDC, Ok(&healthy_ata()));
    let s = collect(&h, &runner, &v);
    assert_eq!(s.status, SectionStatus::Timeout);
    let timeouts: Vec<&str> = s
        .advisories
        .iter()
        .filter(|a| a.code == AdvisoryCode::CollectorTimeout)
        .map(|a| a.subject.as_str())
        .collect();
    assert_eq!(timeouts, ["ctrl:PERC H330 Mini:scan"]);
    let t = adv(
        &s,
        "ctrl:PERC H330 Mini:scan",
        AdvisoryCode::CollectorTimeout,
    )
    .unwrap();
    assert_eq!(
        (t.subject_kind, t.severity, t.sample.as_deref()),
        (
            AdvisorySubject::Controller,
            Severity::Warning,
            Some("smartctl --scan-open timed out after 60 s")
        )
    );
    // No disk behind it was probed; each VD says so.
    assert!(s.advisories.iter().all(|a| !a.subject.contains(":pd")));
    for vd in ["0", "1"] {
        assert!(adv(
            &s,
            &format!("ctrl:PERC H330 Mini:{vd}"),
            AdvisoryCode::SmartUnavailableBehindController
        )
        .is_some());
    }
}

#[test]
fn the_scan_parser_reads_7_4_and_7_5_json_and_text() {
    let e = |device: &str, n: u32, dtype: &str| health::ScanEntry {
        device: device.into(),
        n,
        dtype: dtype.into(),
    };
    let sat = vec![
        e("/dev/bus/0", 0, "sat+megaraid,0"),
        e("/dev/bus/0", 1, "sat+megaraid,1"),
    ];
    assert_eq!(health::parse_scan(SCAN_OPEN_75).unwrap(), sat);
    assert_eq!(health::parse_scan(PLAIN_SCAN_OPEN_75).unwrap(), sat);
    assert_eq!(health::parse_scan(SCAN_OPEN_75_TEXT).unwrap(), sat);
    // 7.4-shaped (`megaraid,N`), the unsafe entries dropped.
    assert_eq!(
        health::parse_scan(SCAN_OPEN).unwrap(),
        vec![
            e("/dev/bus/0", 0, "megaraid,0"),
            e("/dev/bus/0", 1, "megaraid,1")
        ]
    );
    assert_eq!(
        health::parse_scan(
            "/dev/bus/0 -d megaraid,3 # /dev/bus/0 [megaraid_disk_03], SCSI device\n"
        )
        .unwrap(),
        vec![e("/dev/bus/0", 3, "megaraid,3")]
    );
    // The first type listed for a disk wins; no type outside the list.
    let mixed = "/dev/bus/0 -d sat+megaraid,0\n/dev/bus/0 -d megaraid,0\n\
                 /dev/sg1 -d cciss,0\n/dev/sdb -d sat\n/dev/bus/0 -d usbjmicron+megaraid,2\n\
                 /dev/bus/0 -d sat+megaraid,1234\n";
    assert_eq!(
        health::parse_scan(mixed).unwrap(),
        vec![e("/dev/bus/0", 0, "sat+megaraid,0")]
    );
    // An entry smartctl could not open is dropped, passthrough or not.
    let open_error = r#"{"devices":[
      {"name":"/dev/bus/0","type":"sat+megaraid,2","open_error":"open failed"},
      {"name":"/dev/bus/0","type":"sat+megaraid,3"}]}"#;
    assert_eq!(
        health::parse_scan(open_error).unwrap(),
        vec![e("/dev/bus/0", 3, "sat+megaraid,3")]
    );
    assert_eq!(
        health::parse_scan("# /dev/bus/0 -d sat+megaraid,2 # open failed\n").unwrap_or_default(),
        vec![]
    );
    // Only `/dev/bus/<digits>` or `/dev/sd[a-z]{1,4}`.
    let paths = "/dev/sdb -d megaraid,4\n/dev/sdabcd -d megaraid,5\n/dev/sdabcde -d megaraid,6\n\
                 /dev/sg1 -d megaraid,7\n/dev/bus/x -d megaraid,8\n/dev/bus/1234 -d megaraid,9\n\
                 /dev/bus/12 -d megaraid,10\n/dev/sd1 -d megaraid,11\n/dev/nvme0 -d megaraid,12\n";
    assert_eq!(
        health::parse_scan(paths).unwrap(),
        vec![
            e("/dev/bus/12", 10, "megaraid,10"),
            e("/dev/sdabcd", 5, "megaraid,5"),
            e("/dev/sdb", 4, "megaraid,4"),
        ]
    );
    // smartctl 7.5's answer to the former scan, and junk text, are malformed.
    assert!(health::parse_scan(OLD_SCAN_75).is_err());
    assert!(
        health::parse_scan("Invalid type 'megaraid', valid arguments are: by-id, ata\n").is_err()
    );
    assert_eq!(health::parse_scan("").unwrap(), vec![]);
}

const PD0: &str = "smartctl -j -H -A -l error -n standby,0 -d megaraid,0 /dev/bus/0";
const PD1: &str = "smartctl -j -H -A -l error -n standby,0 -d megaraid,1 /dev/bus/0";

#[test]
fn perc_host_passthrough_and_behind_controller() {
    let h = Host::new();
    let v = perc_host(&h);
    let open_failed = r#"{"smartctl":{"exit_status":2,"messages":[{"string":"open failed"}]}}"#;
    let runner = Runner::default()
        .with(SCAN_CMD, Ok(SCAN_OPEN))
        .with(PD0, Ok(&smart_ata(true, 3, 0, 0, 0, 30, 0)))
        .with(PD1, Ok(open_failed))
        .with(SMARTCTL_SDC, Ok(&smart_ata(true, 0, 0, 0, 0, 30, 0)));
    let s = collect(&h, &runner, &v);

    let jbod = dev(&s, "sdc");
    assert_eq!(jbod.behind_controller.as_deref(), Some("megaraid_sas"));
    assert_eq!(jbod.transport, Transport::Sata);
    assert_eq!(jbod.role, DeviceRole::EligibleDedicated, "{jbod:?}");
    assert!(
        adv(&s, "sdc", AdvisoryCode::PowerOnHours).is_some(),
        "probed on its own"
    );

    let sda = dev(&s, "sda");
    assert_eq!(sda.behind_controller.as_deref(), Some("PERC H330 Mini"));
    assert_eq!(sda.transport, Transport::Scsi);
    assert_eq!(sda.role, DeviceRole::System);
    let sdb = dev(&s, "sdb");
    assert_eq!(sdb.role, DeviceRole::Ineligible);
    assert!(
        sdb.reasons.contains(&R::BehindControllerRaidMode),
        "{sdb:?}"
    );

    // The working physical disk reports its own SMART.
    let pd0 = adv(
        &s,
        "ctrl:PERC H330 Mini:pd0",
        AdvisoryCode::ReallocatedSectors,
    )
    .unwrap();
    assert_eq!(
        (pd0.subject_kind, pd0.severity, pd0.value),
        (AdvisorySubject::Controller, Severity::Warning, 3)
    );
    // The failing one: one `smart_unavailable_behind_controller` per VD.
    for vd in ["0", "1"] {
        let a = adv(
            &s,
            &format!("ctrl:PERC H330 Mini:{vd}"),
            AdvisoryCode::SmartUnavailableBehindController,
        )
        .unwrap();
        assert_eq!(a.severity, Severity::Info);
        assert_eq!(
            a.sample.as_deref(),
            Some("SMART passthrough unavailable behind PERC H330 Mini")
        );
    }
    // Only the scan's own `megaraid,N` entries were probed: the runner
    // knows no other command, and nothing else was raised.
    assert!(codes(&s)
        .iter()
        .all(|(k, subject, ..)| *k == AdvisorySubject::Controller || *subject == "sdc"));

    // Every passthrough working: no behind-controller advisory.
    let runner = Runner::default()
        .with(SCAN_CMD, Ok(SCAN_OPEN))
        .with(PD0, Ok(&healthy_ata()))
        .with(PD1, Ok(&healthy_ata()))
        .with(SMARTCTL_SDC, Ok(&healthy_ata()));
    let s = collect(&h, &runner, &v);
    assert!(s
        .advisories
        .iter()
        .all(|a| a.code != AdvisoryCode::SmartUnavailableBehindController));
    assert!(adv(&s, "ctrl:PERC H330 Mini:pd1", AdvisoryCode::PowerOnHours).is_some());

    // The first passthrough timing out ends the passthrough: `megaraid,1`
    // is not run (the runner would answer it), every VD is unavailable.
    let runner = Runner::default()
        .with(SCAN_CMD, Ok(SCAN_OPEN))
        .with(PD0, Err(CommandError::Timeout))
        .with(PD1, Ok(&healthy_ata()))
        .with(SMARTCTL_SDC, Ok(&healthy_ata()));
    let s = collect(&h, &runner, &v);
    assert_eq!(s.status, SectionStatus::Timeout);
    let t = adv(
        &s,
        "ctrl:PERC H330 Mini:pd0",
        AdvisoryCode::CollectorTimeout,
    )
    .unwrap();
    assert_eq!(t.severity, Severity::Warning);
    assert!(s.advisories.iter().all(|a| !a.subject.ends_with(":pd1")));
    for vd in ["0", "1"] {
        assert!(adv(
            &s,
            &format!("ctrl:PERC H330 Mini:{vd}"),
            AdvisoryCode::SmartUnavailableBehindController
        )
        .is_some());
    }
}

/// LVM: `nvme0n1p2` is the PV of `dm-0` (`/`) and `dm-1` (swap); `sdb`
/// the PV of a VM's LV `dm-2` named `hippius--vg-vm_abc123`; `sdc` has a
/// mounted xfs partition no pool uses; `sdd` is formatted whole and holds
/// the pool `hdd`.
fn lvm_host(h: &Host) -> StorageView {
    let n = block(h, "nvme0n1", NVME0, "259:0", 960 * GIB);
    attr(h, &n, "device/model", "Micron_7450");
    by_id(h, "nvme-Micron_7450_MTFDKBA960TFR_2222", "nvme0n1");
    udev(h, "259:0", "E:ID_PART_TABLE_TYPE=gpt\n");
    part(h, &n, "nvme0n1p1", "259:1", GIB);
    let p2 = part(h, &n, "nvme0n1p2", "259:2", 950 * GIB);
    holder(h, &p2, "dm-0");
    holder(h, &p2, "dm-1");
    udev(h, "259:1", "E:ID_FS_TYPE=ext4\n");
    udev(h, "259:2", "E:ID_FS_TYPE=LVM2_member\n");
    for (dm, dev, name) in [
        ("dm-0", "253:0", "ubuntu--vg-root"),
        ("dm-1", "253:1", "ubuntu--vg-swap"),
        ("dm-2", "253:2", "hippius--vg-vm_abc123"),
    ] {
        let d = block(h, dm, VIRTUAL, dev, 100 * GIB);
        attr(h, &d, "dm/name", name);
        attr(h, &d, "dm/uuid", &format!("LVM-{name}"));
        udev(
            h,
            dev,
            &format!("E:DM_NAME={name}\nE:ID_FS_TYPE=crypto_LUKS\nS:mapper/{name}\n"),
        );
        by_id(h, &format!("dm-name-{name}"), dm);
        by_id(h, &format!("dm-uuid-LVM-{name}"), dm);
    }
    let dm0 = format!("sys/{VIRTUAL}/block/dm-0");
    slave(h, &dm0, "nvme0n1p2");
    udev(h, "253:0", "E:DM_NAME=ubuntu--vg-root\nE:ID_FS_TYPE=ext4\n");
    udev(h, "253:1", "E:DM_NAME=ubuntu--vg-swap\nE:ID_FS_TYPE=swap\n");

    let sdb = block(h, "sdb", SATA1, "8:16", 4 * TIB);
    attr(h, &sdb, "device/vendor", "ATA");
    holder(h, &sdb, "dm-2");
    udev(h, "8:16", "E:ID_FS_TYPE=LVM2_member\n");
    by_id(h, "ata-WDC_WUH721414ALE6L4_9MG0AAAA", "sdb");

    let sdc_path = "devices/pci0000:00/0000:00:11.5/ata3/host2/target2:0:0/2:0:0:0";
    let sdc = block(h, "sdc", sdc_path, "8:32", 2 * TIB);
    part(h, &sdc, "sdc1", "8:33", TIB);
    part(h, &sdc, "sdc2", "8:34", TIB);
    udev(h, "8:32", "E:ID_PART_TABLE_TYPE=gpt\n");
    udev(h, "8:33", "E:ID_FS_TYPE=xfs\nE:ID_FS_UUID=4444\n");
    udev(
        h,
        "8:34",
        &format!("E:ID_PART_ENTRY_NUMBER=2\nE:ID_PART_ENTRY_TYPE={BASIC_DATA}\n"),
    );
    by_id(h, "ata-WDC_WD20EFRX_WD-CCC", "sdc");

    let sdd_path = "devices/pci0000:00/0000:00:11.5/ata4/host3/target3:0:0/3:0:0:0";
    let sdd = block(h, "sdd", sdd_path, "8:48", 8 * TIB);
    attr(h, &sdd, "queue/rotational", "1");
    udev(h, "8:48", "E:ID_FS_TYPE=ext4\nE:ID_FS_UUID=5555\n");
    by_id(h, "ata-ST8000NM_ZA1DDDDD", "sdd");

    mountinfo(
        h,
        "22 1 253:0 / / rw,relatime - ext4 /dev/mapper/ubuntu--vg-root rw\n\
         23 22 259:1 / /boot rw,relatime - ext4 /dev/nvme0n1p1 rw\n\
         24 22 8:33 / /srv/scratch rw,relatime - xfs /dev/sdc1 rw\n\
         25 22 8:48 / /var/lib/hippius-miner/pools/hdd rw,relatime - ext4 /dev/sdd rw\n",
    );
    h.write(
        "proc/swaps",
        "Filename Type Size Used Priority\n/dev/mapper/ubuntu--vg-swap partition 8388604 0 -2\n",
    );
    host_dir(h, "/var/lib/hippius-miner/pools/hdd");
    view(
        "/var/lib/hippius-miner",
        &[
            ("default", "/var/lib/hippius-miner"),
            ("hdd", "/var/lib/hippius-miner/pools/hdd"),
        ],
        &[],
    )
}

#[test]
fn lvm_host_system_member_eligible_pool_and_a_pool_subject() {
    let h = Host::new();
    let v = lvm_host(&h);
    let runner = lvm_runner(&smart_ata(true, 0, 5, 0, 0, 40, 7200));
    let s = collect(&h, &runner, &v);

    let dm0 = dev(&s, "dm-0");
    assert_eq!(dm0.kind, DeviceKind::Dm);
    assert_eq!(dm0.role, DeviceRole::System);
    assert_eq!(dm0.mounts, ["/"]);
    assert_eq!(dm0.pool_ids, ["default"]);
    assert_eq!(dev(&s, "dm-1").role, DeviceRole::System, "swap");
    assert!(dev(&s, "dm-1").reasons.contains(&R::Swap));
    let pv = dev(&s, "nvme0n1p2");
    assert_eq!(pv.role, DeviceRole::Member);
    assert_eq!(reasons(pv), [R::HolderBusy, R::System]);
    assert_eq!(pv.holders, ["dm-0", "dm-1"]);
    assert_eq!(dev(&s, "nvme0n1").role, DeviceRole::System);
    assert_eq!(dev(&s, "nvme0n1p1").role, DeviceRole::System, "/boot");

    let sdb = dev(&s, "sdb");
    assert_eq!(sdb.role, DeviceRole::Member);
    assert_eq!(reasons(sdb), [R::HolderBusy]);
    let vm_lv = dev(&s, "dm-2");
    assert_eq!(vm_lv.role, DeviceRole::Ineligible);
    // A closed LUKS volume: a member's signature, never free.
    assert_eq!(reasons(vm_lv), [R::HasSignature, R::HolderBusy, R::Virtual]);
    assert!(vm_lv.ids.is_empty(), "no dm-name-/dm-uuid- link");

    let sdc1 = dev(&s, "sdc1");
    assert_eq!(sdc1.role, DeviceRole::EligiblePool);
    assert_eq!(sdc1.mounts, ["/srv/scratch"]);
    assert_eq!(sdc1.fs.as_ref().unwrap().size_bytes, None, "not statvfs'ed");
    let sdc = dev(&s, "sdc");
    assert_eq!(sdc.role, DeviceRole::Ineligible);
    assert_eq!(reasons(sdc), [R::HasPartitions, R::Mounted]);
    assert_eq!(dev(&s, "sdc2").role, DeviceRole::NeedsPrep);

    let sdd = dev(&s, "sdd");
    assert_eq!(sdd.role, DeviceRole::PoolBacking);
    assert_eq!(sdd.pool_ids, ["hdd"]);
    assert!(sdd.fs.as_ref().unwrap().size_bytes.is_some());
    // Its disk alone backs `hdd`: its SMART attaches to the pool.
    let a = adv(&s, "hdd", AdvisoryCode::PendingSectors).unwrap();
    assert_eq!(
        (a.subject_kind, a.severity, a.value),
        (AdvisorySubject::Pool, Severity::Critical, 5)
    );
    assert!(adv(&s, "", AdvisoryCode::CollectorMissingTools).is_none());
    assert_eq!(s.status, SectionStatus::Ok);
}

/// Every tool of the LVM host, `sdd` answering `sdd_smart`.
fn lvm_runner(sdd_smart: &str) -> Runner {
    let ata = healthy_ata();
    Runner::default()
        .with("smartctl -j -H -A -l error -n standby,0 /dev/sdb", Ok(&ata))
        .with("smartctl -j -H -A -l error -n standby,0 /dev/sdc", Ok(&ata))
        .with(
            "smartctl -j -H -A -l error -n standby,0 /dev/sdd",
            Ok(sdd_smart),
        )
        .with("nvme smart-log -o json /dev/nvme0n1", Ok(&healthy_nvme()))
}

#[test]
fn privacy_no_dm_name_no_raw_tool_text_and_physical_ids_only() {
    let h = Host::new();
    let v = lvm_host(&h);
    let s = collect(&h, &lvm_runner(&smart_ata(false, 9, 1, 1, 0, 60, 7200)), &v);
    assert!(adv(&s, "hdd", AdvisoryCode::SmartOverallFailed).is_some());
    let json = serde_json::to_string(&s).unwrap();
    for leaked in [
        "hippius--vg",
        "vm_abc123",
        "ubuntu--vg",
        "dm-name-",
        "dm-uuid-",
        "mapper",
        "ZC10000A-SMART-SERIAL",
        "RAW-TOOL-LINE",
        "ST4000NM0035-1V4107",
        "Raw_Read_Error_Rate",
    ] {
        assert!(!json.contains(leaked), "{leaked} in {json}");
    }
    for d in &s.devices {
        for id in &d.ids {
            assert!(is_disk_id(id), "{id}");
            assert!(
                ["wwn-", "nvme-", "ata-", "scsi-", "usb-"]
                    .iter()
                    .any(|p| id.starts_with(p)),
                "{id}"
            );
        }
    }
    for a in &s.advisories {
        let sample = a.sample.as_deref().unwrap_or("");
        assert!(sample.len() <= 120 && sample.is_ascii(), "{sample}");
    }
}

// ─── SMART / NVMe thresholds ─────────────────────────────────────────

fn ata(json: &str) -> health::AtaReading {
    match health::parse_smartctl(json).unwrap() {
        health::Smart::Reading(r) => r,
        other => panic!("{other:?}"),
    }
}

fn sig(signals: &[health::Signal]) -> Vec<(AdvisoryCode, Severity, i64)> {
    signals
        .iter()
        .map(|s| (s.code, s.severity, s.value))
        .collect()
}

#[test]
fn ata_thresholds_first_run_rising_and_temperatures() {
    use AdvisoryCode as C;
    use Severity as S;
    let r = ata(&smart_ata(false, 12, 2, 1, 7, 56, 7200));
    let (signals, keep) = health::ata_signals(&r, None, None);
    assert_eq!(
        sig(&signals),
        [
            (C::SmartOverallFailed, S::Critical, 0),
            (C::ReallocatedSectors, S::Warning, 12),
            (C::PendingSectors, S::Critical, 2),
            (C::OfflineUncorrectable, S::Critical, 1),
            // No previous run: the CRC count is not "rising".
            (C::TemperatureHigh, S::Warning, 56),
            (C::PowerOnHours, S::Info, 30000),
        ]
    );
    assert_eq!(signals[1].sample.as_deref(), Some("reallocated 12 sectors"));
    assert_eq!(keep.get("reallocated"), Some(&12));
    assert_eq!(keep.get("udma_crc"), Some(&7));

    // Rising since the previous run.
    let prev: health::CounterMapByKey = BTreeMap::from([(
        "k".to_string(),
        BTreeMap::from([("reallocated".to_string(), 10), ("udma_crc".to_string(), 3)]),
    )]);
    let (signals, _) = health::ata_signals(&r, None, prev.get("k"));
    let s = sig(&signals);
    assert!(s.contains(&(C::ReallocatedSectors, S::Critical, 12)));
    assert!(s.contains(&(C::UdmaCrcErrors, S::Warning, 7)));
    let realloc = signals
        .iter()
        .find(|s| s.code == C::ReallocatedSectors)
        .unwrap();
    assert_eq!(
        realloc.sample.as_deref(),
        Some("reallocated 12 sectors, up from 10")
    );
    // Unchanged: warning again, no CRC signal.
    let same = BTreeMap::from([("reallocated".to_string(), 12), ("udma_crc".to_string(), 7)]);
    let (signals, _) = health::ata_signals(&r, None, Some(&same));
    let s = sig(&signals);
    assert!(s.contains(&(C::ReallocatedSectors, S::Warning, 12)));
    assert!(!s.iter().any(|(c, ..)| *c == C::UdmaCrcErrors));

    // Temperature: 55 °C for a spinning disk, 70 °C for solid state.
    let hot = |t: i64, rotation: u64, hint: Option<bool>| {
        let r = ata(&smart_ata(true, 0, 0, 0, 0, t, rotation));
        sig(&health::ata_signals(&r, hint, None).0)
            .iter()
            .any(|(c, ..)| *c == C::TemperatureHigh)
    };
    assert!(hot(55, 7200, None));
    assert!(!hot(54, 7200, None));
    assert!(!hot(60, 0, None));
    assert!(hot(70, 0, None));
    // No rotation rate: the sysfs hint decides.
    let no_rate = |t: i64, hint: Option<bool>| {
        let r = health::AtaReading {
            temperature_c: Some(t),
            ..health::AtaReading::default()
        };
        !health::ata_signals(&r, hint, None).0.is_empty()
    };
    assert!(no_rate(60, Some(true)));
    assert!(!no_rate(60, Some(false)));

    // A healthy disk: power-on hours only.
    let (signals, _) = health::ata_signals(&ata(&healthy_ata()), None, None);
    assert_eq!(sig(&signals), [(C::PowerOnHours, S::Info, 30000)]);

    // SAS: the grown defect list is the reallocation count.
    let sas = r#"{"smartctl":{"exit_status":0},"smart_status":{"passed":true},
      "scsi_grown_defect_list":4,"temperature":{"current":40},"power_on_time":{"hours":10}}"#;
    let (signals, _) = health::ata_signals(&ata(sas), Some(true), None);
    assert!(sig(&signals).contains(&(C::ReallocatedSectors, S::Warning, 4)));
}

#[test]
fn nvme_thresholds() {
    use AdvisoryCode as C;
    use Severity as S;
    let r = health::parse_nvme_cli(&nvme_log(4, 345, 5, 10, 85, 2)).unwrap();
    assert_eq!(r.temperature_c, Some(72), "kelvin to celsius");
    let (signals, keep) = health::nvme_signals(&r, None);
    assert_eq!(
        sig(&signals),
        [
            (C::NvmeCriticalWarning, S::Critical, 4),
            (C::NvmeMediaErrors, S::Warning, 2),
            (C::NvmeSpareLow, S::Critical, 5),
            (C::NvmeWearHigh, S::Warning, 85),
            (C::TemperatureHigh, S::Warning, 72),
        ]
    );
    assert_eq!(keep.get("media_errors"), Some(&2));
    let prev = BTreeMap::from([("media_errors".to_string(), 1)]);
    let (signals, _) = health::nvme_signals(&r, Some(&prev));
    assert!(sig(&signals).contains(&(C::NvmeMediaErrors, S::Critical, 2)));
    let worn = health::parse_nvme_cli(&nvme_log(0, 300, 100, 10, 100, 0)).unwrap();
    assert_eq!(
        sig(&health::nvme_signals(&worn, None).0),
        [(C::NvmeWearHigh, S::Critical, 100)]
    );
    let fine = health::parse_nvme_cli(&nvme_log(0, 340, 10, 10, 79, 0)).unwrap();
    assert!(
        health::nvme_signals(&fine, None).0.is_empty(),
        "spare = thresh, 79 %, 67 C"
    );
    // nvme-cli's verbose form of the warning, and `percentage_used`.
    let verbose = r#"{"critical_warning":{"value":1},"temperature":300,"percentage_used":90}"#;
    let r = health::parse_nvme_cli(verbose).unwrap();
    assert_eq!((r.critical_warning, r.percentage_used), (1, Some(90)));
}

#[test]
fn rising_through_the_state_file_and_first_seen() {
    let h = Host::new();
    let v = nvme_md_host(&h);
    let runner = healthy_runner().with(SMARTCTL_SDB, Ok(&smart_ata(true, 2, 0, 0, 0, 35, 7200)));
    let (first, state) = collect_with(&h, &runner, Some(&v), &Counters::default(), SMART_BUDGET);
    let a = adv(&first, "sdb", AdvisoryCode::ReallocatedSectors).unwrap();
    assert_eq!(a.severity, Severity::Warning, "first run: never rising");
    assert_eq!((a.first_seen_unix, a.last_seen_unix), (NOW, NOW));
    assert_eq!(state.devices[SDB_WWN_KEY]["reallocated"], 2);

    // Through the file, as the subcommand does.
    let dir = h.dir.path().join("out");
    state.save(&dir).unwrap();
    let previous = Counters::load(&dir);
    assert_eq!(previous, state);

    let runner = healthy_runner().with(SMARTCTL_SDB, Ok(&smart_ata(true, 5, 0, 0, 0, 35, 7200)));
    let inputs = StorageInputs {
        view: Some(&v),
        previous: &previous,
        deadline: std::time::Instant::now() + SMART_BUDGET,
        min_probe_window: Duration::ZERO,
        clock: &super::super::SystemClock,
        kernel: &[],
    };
    let (second, next) = collect_storage(&h.paths(), &runner, &inputs, NOW + 3600).unwrap();
    let second = checked(second);
    let a = adv(&second, "sdb", AdvisoryCode::ReallocatedSectors).unwrap();
    assert_eq!(a.severity, Severity::Critical);
    assert_eq!(
        a.sample.as_deref(),
        Some("reallocated 5 sectors, up from 2")
    );
    assert_eq!(
        (a.first_seen_unix, a.last_seen_unix),
        (NOW, NOW + 3600),
        "first seen kept"
    );
    assert_eq!(next.devices[SDB_WWN_KEY]["reallocated"], 5);

    // A corrupt or missing file is a first run.
    std::fs::write(dir.join(".storage-counters.json"), b"{not json").unwrap();
    assert_eq!(Counters::load(&dir), Counters::default());
    assert_eq!(
        Counters::load(&h.dir.path().join("nowhere")),
        Counters::default()
    );
}

/// `sdb`'s counter key: its first by-id name.
const SDB_WWN_KEY: &str = "ata-ST4000NM0035-1V4107_ZC10000A";

#[test]
fn nvme_falls_back_to_smartctl_and_missing_tools_are_info() {
    let h = Host::new();
    let v = nvme_md_host(&h);
    let fallback = r#"{"smartctl":{"exit_status":0},"smart_status":{"passed":true},
      "nvme_smart_health_information_log":{"critical_warning":0,"temperature":41,
      "available_spare":100,"available_spare_threshold":10,"percentage_used":95,
      "media_errors":0}}"#;
    let runner = Runner::default()
        .with(SMARTCTL_SDA, Ok(&healthy_ata()))
        .with(SMARTCTL_SDB, Ok(&healthy_ata()))
        .with("smartctl -j -H -A -d nvme /dev/nvme0n1", Ok(fallback))
        .with("smartctl -j -H -A -d nvme /dev/nvme1n1", Ok(fallback));
    let s = collect(&h, &runner, &v);
    let wear = adv(&s, "nvme0n1", AdvisoryCode::NvmeWearHigh).unwrap();
    assert_eq!((wear.severity, wear.value), (Severity::Warning, 95));
    let missing = adv(&s, "", AdvisoryCode::CollectorMissingTools).unwrap();
    assert_eq!(
        (missing.subject_kind, missing.severity),
        (AdvisorySubject::Collector, Severity::Info)
    );
    assert_eq!(missing.sample.as_deref(), Some("nvme-cli not installed"));
    assert_eq!(s.status, SectionStatus::Ok, "a missing tool is no fault");

    // No tool at all.
    let s = collect(&h, &Runner::default(), &v);
    let missing = adv(&s, "", AdvisoryCode::CollectorMissingTools).unwrap();
    assert_eq!(
        missing.sample.as_deref(),
        Some("nvme-cli and smartctl not installed")
    );
    assert_eq!(s.advisories.len(), 1, "{:?}", s.advisories);
    assert_eq!(s.status, SectionStatus::Ok);
    assert!(!s.devices.is_empty());
}

#[test]
fn malformed_tool_json_is_collector_partial_never_a_panic() {
    let h = Host::new();
    let v = nvme_md_host(&h);
    let runner = healthy_runner()
        .with(SMARTCTL_SDB, Ok("{not json"))
        .with(NVME0_LOG, Ok("[1,2,3]"))
        .with("smartctl -j -H -A -d nvme /dev/nvme0n1", Ok("\u{0}garbage"))
        .with(NVME1_LOG, Ok(r#"{"temperature": "hot"}"#))
        .with(
            "smartctl -j -H -A -d nvme /dev/nvme1n1",
            Ok("{\"smartctl\": 7"),
        )
        .with(SMARTCTL_SDA, Ok("{}"));
    let s = collect(&h, &runner, &v);
    assert_eq!(s.status, SectionStatus::Partial);
    for subject in ["sdb", "nvme0n1", "nvme1n1"] {
        let a = adv(&s, subject, AdvisoryCode::CollectorPartial).unwrap();
        assert_eq!(
            (a.subject_kind, a.severity),
            (AdvisorySubject::Device, Severity::Info),
            "{subject}"
        );
    }
    // An object with no reading (a disk in standby): skipped.
    assert!(s.advisories.iter().all(|a| a.subject != "sda"));
    // Odd shapes of each parser.
    for text in [
        "",
        "null",
        "{\"ata_smart_attributes\":{\"table\":7}}",
        "\"x\"",
    ] {
        let _ = health::parse_smartctl(text);
        let _ = health::parse_nvme_cli(text);
        let _ = health::parse_smartctl_nvme(text);
        let _ = health::parse_scan(text);
    }
    assert!(health::parse_scan(SCAN_OPEN).unwrap().len() == 2);
}

#[test]
fn a_tool_timeout_and_the_budget() {
    let h = Host::new();
    let v = nvme_md_host(&h);
    let runner = healthy_runner().with(SMARTCTL_SDB, Err(CommandError::Timeout));
    let s = collect(&h, &runner, &v);
    assert_eq!(s.status, SectionStatus::Timeout);
    let a = adv(&s, "sdb", AdvisoryCode::CollectorTimeout).unwrap();
    assert_eq!(a.subject_kind, AdvisorySubject::Device);
    assert_eq!(a.sample.as_deref(), Some("smartctl timed out after 30 s"));

    // The budget spent: every device skipped, one collector advisory.
    let (s, _) = collect_with(
        &h,
        &healthy_runner(),
        Some(&v),
        &Counters::default(),
        Duration::ZERO,
    );
    assert_eq!(s.status, SectionStatus::Timeout);
    let a = adv(&s, "", AdvisoryCode::CollectorTimeout).unwrap();
    assert_eq!((a.subject_kind, a.count), (AdvisorySubject::Collector, 4));
    assert!(s
        .advisories
        .iter()
        .all(|a| a.code == AdvisoryCode::CollectorTimeout));
}

#[test]
fn smartctl_reports_a_failing_disk_with_a_non_zero_exit() {
    // The runner's any-exit path: the JSON of a failing disk (exit bit 3).
    let h = Host::new();
    let v = nvme_md_host(&h);
    let runner = healthy_runner().with(SMARTCTL_SDB, Ok(&smart_ata(false, 0, 0, 0, 0, 30, 7200)));
    let s = collect(&h, &runner, &v);
    let a = adv(&s, "sdb", AdvisoryCode::SmartOverallFailed).unwrap();
    assert_eq!(a.severity, Severity::Critical);
    // exit bits 0–1: the device could not be opened.
    let runner = healthy_runner().with(
        SMARTCTL_SDB,
        Ok(r#"{"smartctl":{"exit_status":2},"device":{"name":"/dev/sdb"}}"#),
    );
    let s = collect(&h, &runner, &v);
    let a = adv(&s, "sdb", AdvisoryCode::SmartUnavailable).unwrap();
    assert_eq!(a.severity, Severity::Info);
}

#[test]
fn without_the_agent_config_the_section_is_partial() {
    let h = Host::new();
    nvme_md_host(&h);
    let (s, _) = collect_with(
        &h,
        &healthy_runner(),
        None,
        &Counters::default(),
        SMART_BUDGET,
    );
    assert_eq!(s.status, SectionStatus::Partial);
    let a = adv(&s, "", AdvisoryCode::CollectorPartial).unwrap();
    assert_eq!(
        a.sample.as_deref(),
        Some("agent config unreadable: pool and dedicated roles unknown")
    );
    // Fail closed: with no pool known, the pool's array is not offered
    // as a new pool, the bare disk not as a dedicated disk.
    let md = dev(&s, "md127");
    assert_eq!(md.role, DeviceRole::Ineligible);
    assert!(md.reasons.contains(&R::System), "{:?}", md.reasons);
    assert_eq!(dev(&s, "sdb").role, DeviceRole::Ineligible);
    assert_never_offered(&s);
    assert_eq!(dev(&s, "sda2").role, DeviceRole::System);
}

#[test]
fn an_empty_host_is_unavailable_and_valid() {
    let h = Host::new();
    let (s, _) = collect_with(
        &h,
        &Runner::default(),
        Some(&StorageView::default()),
        &Counters::default(),
        SMART_BUDGET,
    );
    assert_eq!(s.status, SectionStatus::Unavailable);
    assert!(s.devices.is_empty());
}

// ─── caps ────────────────────────────────────────────────────────────

/// Answers every `nvme smart-log` with a worn, erroring drive.
struct Worn;

impl CommandRunner for Worn {
    fn run(&self, program: &str, _args: &[&str]) -> Result<String, CommandError> {
        match program {
            "nvme" => Ok(nvme_log(0, 300, 100, 10, 85, 3)),
            _ => Err(CommandError::NotFound),
        }
    }
}

#[test]
fn a_300_device_host_hits_the_caps_and_still_validates() {
    let h = Host::new();
    for i in 0..300 {
        let name = format!("nvme{i}n1");
        let path = format!("devices/pci0000:00/0000:00:01.0/nvme/nvme{i}");
        let d = block(&h, &name, &path, &format!("259:{i}"), 4 * TIB);
        udev(&h, &format!("259:{i}"), "E:ID_SERIAL=x\n");
        attr(
            &h,
            &d,
            "device/model",
            "VENDOR NVME MODEL WITH A RATHER LONG NAME",
        );
        for k in 0..3 {
            by_id(
                &h,
                &format!(
                    "nvme-VENDOR_NVME_MODEL_WITH_A_RATHER_LONG_NAME_SERIAL{i:06}_{k}_{}",
                    "x".repeat(20)
                ),
                &name,
            );
        }
    }
    mountinfo(&h, "22 1 259:0 / / rw - ext4 /dev/nvme0n1 rw\n");
    let v = StorageView::default();
    let inputs = StorageInputs {
        view: Some(&v),
        previous: &Counters::default(),
        deadline: std::time::Instant::now() + SMART_BUDGET,
        min_probe_window: Duration::ZERO,
        clock: &super::super::SystemClock,
        kernel: &[],
    };
    let (section, _) = collect_storage(&h.paths(), &Worn, &inputs, NOW).unwrap();
    assert_eq!(section.devices.len(), 300);
    assert_eq!(section.advisories.len(), 600);
    let s = checked(section);
    assert!(s.devices.len() <= MAX_DEVICES);
    assert!(s.devices_truncated);
    assert_eq!(s.advisories.len(), MAX_ADVISORIES);
    assert!(s.advisories_truncated);
    assert!(s.advisories.iter().all(|a| a.severity == Severity::Warning));
    assert!(s
        .devices
        .iter()
        .all(|d| d.role == DeviceRole::EligibleDedicated || d.name == "nvme0n1"));
}

// ─── fail closed ─────────────────────────────────────────────────────

#[test]
fn a_device_without_a_udev_entry_is_never_free() {
    let h = Host::new();
    let v = nvme_md_host(&h);
    std::fs::remove_file(h.dir.path().join("run/udev/data/b8:16")).unwrap();
    let s = collect(&h, &healthy_runner(), &v);
    assert_not_free(&s, "sdb");
    assert_eq!(dev(&s, "sdb").role, DeviceRole::Ineligible);
    assert!(dev(&s, "sdb").reasons.contains(&R::HasSignature));

    // No udev database at all: the section is partial too.
    std::fs::remove_dir_all(h.dir.path().join("run/udev")).unwrap();
    let s = collect(&h, &healthy_runner(), &v);
    assert_eq!(s.status, SectionStatus::Partial);
    assert_never_offered(&s);
}

/// `sda2` holds `/` (btrfs, UUID `root-fs`); unused disks carrying a
/// stack member's signature with nothing holding them, a second member
/// of the root btrfs, an inactive md, and two positive controls.
fn member_host(h: &Host) -> StorageView {
    let sata = |i: usize| {
        format!("devices/pci0000:00/0000:00:11.5/ata{i}/host{i}/target{i}:0:0/{i}:0:0:0")
    };
    let sda = block(h, "sda", &sata(1), "8:0", 480 * GIB);
    udev(h, "8:0", "E:ID_PART_TABLE_TYPE=gpt\n");
    part(h, &sda, "sda1", "8:1", GIB);
    part(h, &sda, "sda2", "8:2", 400 * GIB);
    // Siblings on the system disk: BIOS boot (no fs), inactive swap.
    part(h, &sda, "sda3", "8:3", GIB);
    part(h, &sda, "sda4", "8:4", 8 * GIB);
    udev(h, "8:1", "E:ID_FS_TYPE=vfat\n");
    udev(h, "8:2", "E:ID_FS_TYPE=btrfs\nE:ID_FS_UUID=root-fs\n");
    udev(
        h,
        "8:3",
        "E:ID_PART_ENTRY_TYPE=21686148-6449-6e6f-744e-656564454649\n",
    );
    udev(h, "8:4", "E:ID_FS_TYPE=swap\nE:ID_FS_UUID=sw\n");
    by_id(h, "ata-SYS_1", "sda");
    for (n, (name, dev, fs)) in [
        ("sdb", "8:16", "E:ID_FS_TYPE=zfs_member\nE:ID_FS_UUID=z\n"),
        (
            "sdc",
            "8:32",
            "E:ID_FS_TYPE=linux_raid_member\nE:ID_FS_UUID=r\n",
        ),
        ("sdd", "8:48", "E:ID_FS_TYPE=bcache\n"),
        ("sde", "8:64", "E:ID_FS_TYPE=crypto_LUKS\nE:ID_FS_UUID=l\n"),
        ("sdf", "8:80", "E:ID_FS_TYPE=btrfs\nE:ID_FS_UUID=root-fs\n"),
        ("sdg", "8:96", "E:ID_FS_TYPE=ext4\nE:ID_FS_UUID=g\n"),
        ("sdh", "8:112", "E:ID_PART_TABLE_TYPE=gpt\n"),
        ("sdi", "8:128", "E:ID_PART_TABLE_TYPE=gpt\n"),
    ]
    .into_iter()
    .enumerate()
    {
        let d = block(h, name, &sata(n + 2), dev, 4 * TIB);
        udev(h, dev, fs);
        by_id(h, &format!("ata-DISK_{name}"), name);
        if name == "sdh" {
            part(h, &d, "sdh1", "8:113", 4 * TIB);
            udev(
                h,
                "8:113",
                &format!("E:ID_PART_ENTRY_NUMBER=1\nE:ID_PART_ENTRY_TYPE={BASIC_DATA}\n"),
            );
        }
        if name == "sdi" {
            part(h, &d, "sdi1", "8:129", 4 * TIB);
            udev(h, "8:129", "E:ID_FS_TYPE=crypto_LUKS\nE:ID_FS_UUID=pl\n");
        }
    }
    let md = block(h, "md0", VIRTUAL, "9:0", 4 * TIB);
    attr(h, &md, "md/array_state", "inactive");
    attr(h, &md, "md/level", "raid1");
    udev(h, "9:0", "E:MD_LEVEL=raid1\n");
    mountinfo(
        h,
        "22 1 0:31 / / rw,relatime - btrfs /dev/sda2 rw,subvol=/@\n\
         23 22 8:1 / /boot/efi rw - vfat /dev/sda1 rw\n",
    );
    view(
        "/var/lib/hippius-miner",
        &[("default", "/var/lib/hippius-miner")],
        &[],
    )
}

#[test]
fn stack_members_without_holders_are_never_free() {
    let h = Host::new();
    let v = member_host(&h);
    let s = collect(&h, &Runner::default(), &v);
    // btrfs reports an anonymous device: `/` resolves through its source.
    assert_eq!(dev(&s, "sda2").role, DeviceRole::System);
    for (name, extra) in [
        ("sdb", R::HolderBusy), // an exported ZFS pool
        ("sdc", R::HolderBusy), // a stopped md array's member
        ("sdd", R::HolderBusy), // a bcache backing device
        ("sde", R::HolderBusy), // a closed LUKS volume
        ("md0", R::HolderBusy), // an inactive array
    ] {
        assert_not_free(&s, name);
        let d = dev(&s, name);
        assert_eq!(d.role, DeviceRole::Ineligible, "{name}");
        assert!(
            d.reasons.contains(&R::HasSignature),
            "{name} {:?}",
            d.reasons
        );
        assert!(d.reasons.contains(&extra), "{name} {:?}", d.reasons);
    }
    // The second device of the root btrfs is the system.
    assert_eq!(dev(&s, "sdf").role, DeviceRole::System);
    // A disk whose partition is a closed LUKS volume.
    assert_not_free(&s, "sdi");
    assert_not_free(&s, "sdi1");
    // System-disk siblings: BIOS boot, inactive swap.
    for name in ["sda3", "sda4"] {
        assert_not_free(&s, name);
        let d = dev(&s, name);
        assert_eq!(d.role, DeviceRole::Ineligible, "{name}");
        assert!(d.reasons.contains(&R::System), "{name} {:?}", d.reasons);
    }
    assert!(dev(&s, "sda4").reasons.contains(&R::Swap));
    // Positive controls: a plain single-device fs, a bare partition table
    // over an empty partition.
    assert_eq!(dev(&s, "sdg").role, DeviceRole::NeedsPrep);
    assert_eq!(dev(&s, "sdh").role, DeviceRole::NeedsPrep);
    assert_eq!(dev(&s, "sdh1").role, DeviceRole::NeedsPrep);
}

#[test]
fn an_unresolved_root_offers_nothing() {
    // A ZFS root: `/` is no block device of the host.
    let h = Host::new();
    let v = nvme_md_host(&h);
    mountinfo(
        &h,
        "22 1 0:25 / / rw,relatime - zfs rpool/ROOT/ubuntu rw\n\
         24 22 9:127 / /srv/data rw,relatime - ext4 /dev/md127 rw\n",
    );
    let s = collect(&h, &healthy_runner(), &v);
    assert_eq!(s.status, SectionStatus::Partial);
    assert_never_offered(&s);
    assert_eq!(dev(&s, "sdb").role, DeviceRole::Ineligible);
    assert!(dev(&s, "sdb").reasons.contains(&R::System));
    let a = adv(&s, "", AdvisoryCode::CollectorPartial).unwrap();
    assert_eq!(
        a.sample.as_deref(),
        Some("root filesystem unresolved: nothing offerable")
    );

    // No mountinfo at all.
    std::fs::remove_file(h.dir.path().join("proc/1/mountinfo")).unwrap();
    let s = collect(&h, &healthy_runner(), &v);
    assert_eq!(s.status, SectionStatus::Partial);
    assert_never_offered(&s);
}

#[test]
fn statvfs_skips_autofs_and_symlinked_pool_paths() {
    let h = Host::new();
    let mut v = nvme_md_host(&h);
    // `sdb` mounted by an automount under `/mnt/auto`, a pool on it.
    mountinfo(
        &h,
        "22 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n\
         24 22 9:127 / /mnt/hippius-data rw,relatime - ext4 /dev/md127 rw\n\
         30 22 0:50 / /mnt/auto rw - autofs systemd-1 rw\n\
         31 30 8:16 / /mnt/auto/data rw - ext4 /dev/sdb rw\n",
    );
    udev(&h, "8:16", "E:ID_FS_TYPE=ext4\nE:ID_FS_UUID=b\n");
    host_dir(&h, "/mnt/auto/data");
    v.pools.push(ViewPool {
        id: "auto".into(),
        path: "/mnt/auto/data".into(),
    });
    // The `nvme0` pool path is a symlink on the host.
    let link = h.dir.path().join("root/mnt/hippius-data");
    std::fs::remove_dir(&link).unwrap();
    std::os::unix::fs::symlink(h.dir.path().join("root/var"), &link).unwrap();
    let s = collect(&h, &healthy_runner(), &v);
    let sdb = dev(&s, "sdb");
    assert_eq!(sdb.role, DeviceRole::PoolBacking);
    assert_eq!(sdb.fs.as_ref().unwrap().size_bytes, None, "under autofs");
    assert_eq!(
        dev(&s, "md127").fs.as_ref().unwrap().size_bytes,
        None,
        "symlinked pool path"
    );
    assert!(dev(&s, "sda2").fs.as_ref().unwrap().size_bytes.is_some());
}

#[test]
fn remote_disks_are_virtual_and_not_probed() {
    let h = Host::new();
    let v = nvme_md_host(&h);
    for (name, dev_no, path) in [
        (
            "sdd",
            "8:48",
            "devices/platform/host5/session3/target5:0:0/5:0:0:0",
        ),
        (
            "sde",
            "8:64",
            "devices/pci0000:00/0000:00:02.0/0000:05:00.0/host6/rport-6:0-0/target6:0:0/6:0:0:0",
        ),
    ] {
        block(&h, name, path, dev_no, 4 * TIB);
        udev(&h, dev_no, "E:ID_WWN=0x1\n");
        by_id(&h, &format!("scsi-REMOTE_{name}"), name);
    }
    let s = collect(&h, &healthy_runner(), &v);
    for name in ["sdd", "sde"] {
        assert_not_free(&s, name);
        assert!(dev(&s, name).reasons.contains(&R::Virtual), "{name}");
        // Not probed: the runner knows no smartctl for it.
        assert!(s.advisories.iter().all(|a| a.subject != name), "{name}");
    }
    assert!(adv(&s, "", AdvisoryCode::CollectorMissingTools).is_none());
}

#[test]
fn a_concurrent_run_waits_then_skips() {
    use nix::fcntl::{Flock, FlockArg};
    let h = Host::new();
    let v = nvme_md_host(&h);
    let out = h.dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let file = std::fs::File::create(out.join(super::super::LOCK_NAME)).unwrap();
    let held = Flock::lock(file, FlockArg::LockExclusiveNonblock).unwrap();
    let started = std::time::Instant::now();
    let summary = super::super::run_collect_locked(
        Mode::Counters,
        &h.paths(),
        &healthy_runner(),
        NOW,
        &out,
        Some(&v),
        Duration::from_millis(300),
        std::time::Instant::now(),
        &super::super::SystemClock,
    )
    .unwrap();
    assert_eq!(summary.skipped, Some(super::super::Skip::LockHeld));
    assert!(summary.written.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert_eq!(super::super::dir_names(&out), [super::super::LOCK_NAME]);
    drop(held);
    let summary = super::super::run_collect_locked(
        Mode::Counters,
        &h.paths(),
        &healthy_runner(),
        NOW,
        &out,
        Some(&v),
        Duration::from_millis(300),
        std::time::Instant::now(),
        &super::super::SystemClock,
    )
    .unwrap();
    assert_eq!(summary.skipped, None);
    assert_eq!(
        summary.written,
        ["memory", "storage", "sensors", "software"]
    );

    // A busy `full` run fails (the unit retries it); a busy `counters`
    // run skips.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(out.join(super::super::LOCK_NAME))
        .unwrap();
    let held = Flock::lock(file, FlockArg::LockExclusiveNonblock).unwrap();
    for (mode, outcome) in [
        (Mode::Full, super::super::BusyOutcome::Fail),
        (Mode::Counters, super::super::BusyOutcome::Skip),
    ] {
        let summary = super::super::run_collect_locked(
            mode,
            &h.paths(),
            &healthy_runner(),
            NOW,
            &out,
            Some(&v),
            Duration::from_millis(100),
            std::time::Instant::now(),
            &super::super::SystemClock,
        )
        .unwrap();
        assert_eq!(
            summary.skipped,
            Some(super::super::Skip::LockHeld),
            "{mode:?}"
        );
        assert!(summary.written.is_empty(), "{mode:?}");
        assert_eq!(super::super::on_skip(mode), outcome, "{mode:?}");
    }
    drop(held);
}

/// What a run started `start` after process start does when the lock is
/// held `held` longer, as `run_collect_locked` decides it: `Err` = it does
/// nothing; `Ok((waited, budget))` = it probes with `budget` after
/// waiting `waited`.
fn plan(
    mode: Mode,
    start: Duration,
    held: Duration,
) -> Result<(Duration, Duration), super::super::Skip> {
    use super::super::{RunDeadline, Skip};
    let wait = RunDeadline::lock_wait(mode, start);
    if held > wait {
        return Err(Skip::LockHeld);
    }
    RunDeadline::smart_budget(start + held)
        .map(|budget| (held, budget))
        .ok_or(Skip::NoTime)
}

#[test]
fn the_lock_wait_and_the_probe_fit_one_deadline() {
    use super::super::{
        on_skip, BusyOutcome, RunDeadline, Skip, MIN_PROBE_WINDOW, RUN_DEADLINE, UNIT_TIMEOUT,
        WRITE_MARGIN,
    };
    let min = |m: u64| Duration::from_secs(m * 60);
    let bound = RUN_DEADLINE - WRITE_MARGIN;
    assert_eq!(RUN_DEADLINE + Duration::from_secs(60), UNIT_TIMEOUT);

    // (a) The lock free at once: the whole SMART budget.
    assert_eq!(
        plan(Mode::Full, Duration::ZERO, Duration::ZERO),
        Ok((Duration::ZERO, SMART_BUDGET))
    );
    // (b) Held 5 min: the budget shrinks to what is left (13 - 5 = 8).
    assert_eq!(
        plan(Mode::Full, Duration::ZERO, min(5)),
        Ok((min(5), min(8)))
    );
    // (c) Held up to the deadline: nothing probed, and a `full` run
    // exits non-zero (the unit retries), a `counters` run 0.
    assert_eq!(
        plan(Mode::Full, Duration::ZERO, RUN_DEADLINE),
        Err(Skip::LockHeld)
    );
    assert_eq!(on_skip(Mode::Full), BusyOutcome::Fail);
    assert_eq!(on_skip(Mode::Counters), BusyOutcome::Skip);
    // A lock taken with under the window left: nothing probed either.
    assert_eq!(
        RunDeadline::smart_budget(bound - MIN_PROBE_WINDOW + Duration::from_secs(1)),
        None
    );
    assert_eq!(
        plan(Mode::Counters, min(12), Duration::ZERO),
        Err(Skip::NoTime)
    );

    // Every start offset and lock-hold time: what runs fits the bound,
    // never starts a probe under the window, never waits past its cap.
    for mode in [Mode::Full, Mode::Counters] {
        for start in (0..=16 * 60).step_by(10).map(Duration::from_secs) {
            assert!(RunDeadline::lock_wait(mode, start) <= RunDeadline::lock_wait_cap(mode));
            for held in (0..=16 * 60).step_by(10).map(Duration::from_secs) {
                if let Ok((waited, budget)) = plan(mode, start, held) {
                    assert!(
                        start + waited + budget <= bound,
                        "{mode:?} start {start:?} held {held:?} budget {budget:?}"
                    );
                    assert!(waited + budget <= RUN_DEADLINE);
                    assert!(budget >= MIN_PROBE_WINDOW && budget <= SMART_BUDGET);
                }
            }
        }
    }
}

#[test]
fn a_run_without_probe_time_does_nothing() {
    // Started 12.5 min ago, the lock free: under 2 min of probe time left.
    let Some(started) = std::time::Instant::now().checked_sub(Duration::from_secs(12 * 60 + 30))
    else {
        return; // the clock cannot go that far back on this machine
    };
    let h = Host::new();
    let v = nvme_md_host(&h);
    let out = h.dir.path().join("out");
    for mode in [Mode::Full, Mode::Counters] {
        let summary = super::super::run_collect(
            mode,
            &h.paths(),
            &healthy_runner(),
            NOW,
            &out,
            Some(&v),
            started,
        )
        .unwrap();
        assert_eq!(
            summary.skipped,
            Some(super::super::Skip::NoTime),
            "{mode:?}"
        );
        assert!(summary.written.is_empty());
        assert_eq!(
            super::super::dir_names(&out),
            [super::super::LOCK_NAME],
            "nothing written"
        );
    }
}

#[test]
fn the_lock_is_never_taken_through_a_symlink() {
    let h = Host::new();
    let v = nvme_md_host(&h);
    let out = h.dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let target = h.dir.path().join("elsewhere");
    std::os::unix::fs::symlink(&target, out.join(super::super::LOCK_NAME)).unwrap();
    let r = super::super::run_collect_locked(
        Mode::Counters,
        &h.paths(),
        &healthy_runner(),
        NOW,
        &out,
        Some(&v),
        Duration::from_millis(100),
        std::time::Instant::now(),
        &super::super::SystemClock,
    );
    assert!(r.is_err(), "O_NOFOLLOW");
    assert!(!target.exists(), "nothing created through the link");
    assert_eq!(super::super::dir_names(&out), [super::super::LOCK_NAME]);
}

#[test]
fn only_plain_filesystems_are_ever_needs_prep() {
    let h = Host::new();
    let v = member_host(&h);
    let sata = |i: usize| {
        format!("devices/pci0000:00/0000:00:12.0/ata{i}/host{i}/target{i}:0:0/{i}:0:0:0")
    };
    let cases = [
        ("sdj", "8:144", "nvidia_raid_member"),
        ("sdk", "8:160", "LVM1_member"),
        ("sdl", "8:176", "foo_bar"),
        ("sdm", "8:192", "BitLocker"),
        ("sdn", "8:208", "vdo"),
        ("sdo", "8:224", "xfs"),
        ("sdp", "8:240", "ntfs"),
    ];
    for (n, (name, dev_no, fs)) in cases.iter().enumerate() {
        block(&h, name, &sata(n + 20), dev_no, 4 * TIB);
        udev(&h, dev_no, &format!("E:ID_FS_TYPE={fs}\n"));
        by_id(&h, &format!("ata-DISK_{name}"), name);
    }
    // A partition carrying an unknown type blocks its disk too.
    let d = block(&h, "sdq", &sata(40), "65:0", 4 * TIB);
    udev(&h, "65:0", "E:ID_PART_TABLE_TYPE=gpt\n");
    part(&h, &d, "sdq1", "65:1", 4 * TIB);
    udev(&h, "65:1", "E:ID_FS_TYPE=foo_bar\n");
    by_id(&h, "ata-DISK_sdq", "sdq");
    let s = collect(&h, &Runner::default(), &v);
    for name in ["sdj", "sdk", "sdl", "sdm", "sdn", "sdq", "sdq1"] {
        assert_not_free(&s, name);
        let d = dev(&s, name);
        assert_eq!(d.role, DeviceRole::Ineligible, "{name}");
        assert!(
            d.reasons.contains(&R::HasSignature) && d.reasons.contains(&R::HolderBusy),
            "{name} {:?}",
            d.reasons
        );
    }
    // Plain filesystems: preparation can be offered.
    for name in ["sdo", "sdp"] {
        assert_eq!(dev(&s, name).role, DeviceRole::NeedsPrep, "{name}");
    }
    // swap keeps its own reason.
    assert!(dev(&s, "sda4").reasons.contains(&R::Swap));
}

#[test]
fn lows_bind_mounts_namespaces_temperature_only_and_the_state_cap() {
    let h = Host::new();
    let v = nvme_md_host(&h);
    // A bind mount of a subdirectory is not listed again.
    mountinfo(
        &h,
        "22 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n\
         24 22 9:127 / /mnt/hippius-data rw,relatime - ext4 /dev/md127 rw\n\
         28 22 9:127 /sub /var/lib/bound rw,relatime - ext4 /dev/md127 rw\n",
    );
    // A second namespace on `nvme0`: probed under its own subject.
    let ns2 = block(&h, "nvme0n2", NVME0, "259:5", TIB);
    attr(&h, &ns2, "queue/rotational", "0");
    udev(&h, "259:5", "E:ID_FS_TYPE=ext4\n");
    let runner = healthy_runner()
        .with(
            "nvme smart-log -o json /dev/nvme0n2",
            Ok(&nvme_log(1, 300, 100, 10, 1, 0)),
        )
        // Temperature only, no SMART status: still a reading.
        .with(
            SMARTCTL_SDB,
            Ok(r#"{"smartctl":{"exit_status":0},"temperature":{"current":60}}"#),
        );
    let s = collect(&h, &runner, &v);
    assert_eq!(dev(&s, "md127").mounts, ["/mnt/hippius-data"]);
    let w = adv(&s, "nvme0n2", AdvisoryCode::NvmeCriticalWarning).unwrap();
    assert_eq!(w.severity, Severity::Critical);
    let t = adv(&s, "sdb", AdvisoryCode::TemperatureHigh).unwrap();
    assert_eq!((t.severity, t.value), (Severity::Warning, 60), "HDD hint");

    // The state file: never read past 64 KiB, never written past it.
    let dir = h.dir.path().join("state");
    std::fs::create_dir_all(&dir).unwrap();
    let mut big = Counters::default();
    for i in 0..5000 {
        big.first_seen.insert(format!("4/{i}/subject-{i:08}"), NOW);
    }
    big.devices
        .insert("k".into(), BTreeMap::from([("reallocated".into(), 1)]));
    big.save(&dir).unwrap();
    let file = dir.join(".storage-counters.json");
    let len = std::fs::metadata(&file).unwrap().len();
    assert!(len <= 64 * 1024, "{len}");
    let loaded = Counters::load(&dir);
    assert_eq!(loaded.devices, big.devices, "subjects kept over first_seen");
    std::fs::write(&file, vec![b' '; 70 * 1024]).unwrap();
    assert_eq!(Counters::load(&dir), Counters::default());
}

// ─── the probe ends by the deadline (a fake clock) ───────────────────

/// A clock that moves only when a tool "runs".
struct FakeClock(std::sync::Mutex<std::time::Instant>);

impl FakeClock {
    fn new() -> Self {
        Self(std::sync::Mutex::new(std::time::Instant::now()))
    }
    fn advance(&self, d: Duration) -> std::time::Instant {
        let mut t = self.0.lock().unwrap();
        *t += d;
        *t
    }
}

impl super::super::Clock for FakeClock {
    fn now(&self) -> std::time::Instant {
        *self.0.lock().unwrap()
    }
}

/// Every tool takes its whole timeout on the fake clock. `nvme` fails
/// (slowly), its smartctl fallback answers; smartctl answers an ATA
/// disk; any other tool (`ip`, `ethtool`, the version probes) answers
/// nothing after its bound. Every run is logged with when it ended.
struct SlowRunner<'a> {
    clock: &'a FakeClock,
    log: std::sync::Mutex<Vec<(String, std::time::Instant)>>,
}

impl SlowRunner<'_> {
    fn ran(&self, program: &str, took: Duration) {
        let end = self.clock.advance(took);
        self.log.lock().unwrap().push((program.to_string(), end));
    }
}

impl CommandRunner for SlowRunner<'_> {
    fn run(&self, program: &str, _args: &[&str]) -> Result<String, CommandError> {
        self.ran(program, super::super::COMMAND_TIMEOUT);
        Err(CommandError::Timeout)
    }

    fn run_bounded(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
        _any_exit: bool,
    ) -> Result<String, CommandError> {
        self.ran(program, timeout);
        match program {
            "nvme" => Err(CommandError::Failed),
            "smartctl" if args.contains(&"nvme") => Ok(r#"{"smartctl":{"exit_status":0},
              "nvme_smart_health_information_log":{"critical_warning":0,"temperature":40,
              "available_spare":100,"available_spare_threshold":10,"percentage_used":1,
              "media_errors":0}}"#
                .to_string()),
            "smartctl" => Ok(healthy_ata()),
            _ => Err(CommandError::NotFound),
        }
    }
}

/// 12 NVMe namespaces, 8 SATA disks, a NIC (so the network section runs
/// tools), `/` on `sda`.
fn slow_host(h: &Host) -> StorageView {
    super::super::network::tests::nic_tree(h);
    for i in 0..12 {
        let name = format!("nvme{i}n1");
        let d = block(
            h,
            &name,
            &format!("devices/pci0000:00/0000:00:01.{i}/nvme/nvme{i}"),
            &format!("259:{i}"),
            4 * TIB,
        );
        attr(h, &d, "queue/rotational", "0");
        udev(h, &format!("259:{i}"), "E:ID_SERIAL=x\n");
    }
    for (i, letter) in "abcdefgh".chars().enumerate() {
        let name = format!("sd{letter}");
        let d = block(
            h,
            &name,
            &format!("devices/pci0000:00/0000:00:11.5/ata{i}/host{i}/target{i}:0:0/{i}:0:0:0"),
            &format!("8:{}", i * 16),
            4 * TIB,
        );
        attr(h, &d, "device/vendor", "ATA");
        udev(h, &format!("8:{}", i * 16), "E:ID_SERIAL=x\n");
    }
    mountinfo(h, "22 1 8:0 / / rw - ext4 /dev/sda rw\n");
    view(
        "/var/lib/hippius-miner",
        &[("default", "/var/lib/hippius-miner")],
        &[],
    )
}

fn is_probe_tool(program: &str) -> bool {
    matches!(program, "smartctl" | "nvme")
}

#[test]
fn every_probe_tool_ends_by_the_deadline_and_nothing_runs_after_the_probe() {
    use super::super::{collect, RunDeadline, MIN_PROBE_WINDOW};
    let clock = FakeClock::new();
    let started = super::super::Clock::now(&clock);
    let h = Host::new();
    let v = slow_host(&h);
    let runner = SlowRunner {
        clock: &clock,
        log: std::sync::Mutex::new(Vec::new()),
    };
    // A run whose lock came 4 min in: 9 min left to the probe deadline.
    clock.advance(Duration::from_secs(4 * 60));
    let previous = Counters::default();
    let deadline = RunDeadline::probe_deadline(started);
    let inputs = StorageInputs {
        view: Some(&v),
        previous: &previous,
        deadline,
        min_probe_window: MIN_PROBE_WINDOW,
        clock: &clock,
        kernel: &[],
    };
    let (sections, _) = collect(Mode::Full, &h.paths(), &runner, NOW, &inputs).unwrap();
    let log = runner.log.lock().unwrap().clone();
    let first_probe = log.iter().position(|(p, _)| is_probe_tool(p)).unwrap();
    assert!(
        first_probe > 0,
        "the other sections' tools ran first: {log:?}"
    );
    assert!(
        log[first_probe..].iter().all(|(p, _)| is_probe_tool(p)),
        "no other tool after the probe started: {log:?}"
    );
    for (program, end) in &log[first_probe..] {
        assert!(*end <= deadline, "{program} ended past the deadline");
    }
    // Not everything fitted (12 × 60 s + 8 × 30 s > 9 min): the rest is
    // the collector's budget advisory, and some NVMe went through its
    // fallback (primary then smartctl, both full-length).
    let s = checked(sections.storage.unwrap());
    let skipped = adv(&s, "", AdvisoryCode::CollectorTimeout).unwrap();
    assert!(skipped.count > 0);
    assert!(log
        .windows(2)
        .any(|w| w[0].0 == "nvme" && w[1].0 == "smartctl"));
    let probed = log[first_probe..].len();
    assert!(probed >= 2, "{log:?}");
    assert_eq!(s.status, SectionStatus::Timeout);
}

#[test]
fn too_little_time_before_the_probe_collects_and_writes_nothing() {
    use super::super::{run_collect_locked, Skip, LOCK_NAME, RUN_DEADLINE, WRITE_MARGIN};
    let clock = FakeClock::new();
    let started = super::super::Clock::now(&clock);
    let h = Host::new();
    let v = slow_host(&h);
    let runner = SlowRunner {
        clock: &clock,
        log: std::sync::Mutex::new(Vec::new()),
    };
    // The lock comes with 2 min 10 s left: enough at lock time; the other
    // sections' tools (5 s each) then eat the window before the probe.
    clock.advance(RUN_DEADLINE - WRITE_MARGIN - Duration::from_secs(130));
    let out = h.dir.path().join("out");
    let summary = run_collect_locked(
        Mode::Full,
        &h.paths(),
        &runner,
        NOW,
        &out,
        Some(&v),
        Duration::ZERO,
        started,
        &clock,
    )
    .unwrap();
    assert_eq!(summary.skipped, Some(Skip::NoTime));
    assert_eq!(
        super::super::on_skip(Mode::Full),
        super::super::BusyOutcome::Fail
    );
    let log = runner.log.lock().unwrap().clone();
    assert!(!log.is_empty(), "the other sections ran");
    assert!(
        log.iter().all(|(p, _)| !is_probe_tool(p)),
        "no probe: {log:?}"
    );
    assert_eq!(
        super::super::dir_names(&out),
        [LOCK_NAME],
        "nothing written"
    );
}

// ─── boot partitions ─────────────────────────────────────────────────

const BASIC_DATA: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";

/// `/` on `sda1`; disks each holding one boot-partition variant, and a
/// positive control (`sdg`). Nothing but `/` is mounted.
fn boot_host(h: &Host, fstab: &str) -> StorageView {
    let sata = |i: usize| {
        format!("devices/pci0000:00/0000:00:11.5/ata{i}/host{i}/target{i}:0:0/{i}:0:0:0")
    };
    let sda = block(h, "sda", &sata(1), "8:0", 480 * GIB);
    udev(h, "8:0", "E:ID_PART_TABLE_TYPE=gpt\n");
    part(h, &sda, "sda1", "8:1", 479 * GIB);
    udev(h, "8:1", "E:ID_FS_TYPE=ext4\nE:ID_PART_ENTRY_SCHEME=gpt\n");
    let gpt = |t: &str| format!("E:ID_PART_ENTRY_SCHEME=gpt\nE:ID_PART_ENTRY_TYPE={t}\n");
    let disks: [(&str, usize, String, String); 8] = [
        // An ESP-only disk, unmounted.
        ("sdb", 2, "E:ID_PART_TABLE_TYPE=gpt\n".into(),
         format!("{}E:ID_FS_TYPE=vfat\nE:ID_FS_UUID=B1\n", gpt("C12A7328-F81F-11D2-BA4B-00A0C93EC93B"))),
        // bios_grub (no filesystem), with a plain sibling.
        ("sdc", 3, "E:ID_PART_TABLE_TYPE=gpt\n".into(), gpt("21686148-6449-6e6f-744e-656564454649")),
        // MBR type 0xef.
        ("sdd", 4, "E:ID_PART_TABLE_TYPE=dos\n".into(),
         "E:ID_PART_ENTRY_SCHEME=dos\nE:ID_PART_ENTRY_TYPE=0xef\nE:ID_FS_TYPE=vfat\n".into()),
        // An otherwise plain vfat labelled EFI_SYSPART (a hosting provider's RAID1 boot).
        ("sde", 5, "E:ID_PART_TABLE_TYPE=gpt\n".into(),
         format!("{}E:ID_FS_TYPE=vfat\nE:ID_FS_LABEL=EFI_SYSPART\n", gpt(BASIC_DATA))),
        // Named only by an fstab `UUID=` entry for /boot/efi.
        ("sdf", 6, "E:ID_PART_TABLE_TYPE=gpt\n".into(),
         format!("{}E:ID_FS_TYPE=vfat\nE:ID_FS_UUID=ABCD-1234\n", gpt(BASIC_DATA))),
        // Positive control: a plain unlabelled vfat data partition.
        ("sdg", 7, "E:ID_PART_TABLE_TYPE=gpt\n".into(),
         format!("{}E:ID_FS_TYPE=vfat\nE:ID_FS_UUID=DATA-0001\n", gpt(BASIC_DATA))),
        // MBR active flag.
        ("sdh", 8, "E:ID_PART_TABLE_TYPE=dos\n".into(),
         "E:ID_PART_ENTRY_SCHEME=dos\nE:ID_PART_ENTRY_TYPE=0x83\nE:ID_PART_ENTRY_FLAGS=0x80\nE:ID_FS_TYPE=ext4\n".into()),
        // GPT legacy-BIOS-bootable attribute (bit 2).
        ("sdi", 9, "E:ID_PART_TABLE_TYPE=gpt\n".into(),
         format!("{}E:ID_PART_ENTRY_FLAGS=0x4\nE:ID_FS_TYPE=ext4\n", gpt(BASIC_DATA))),
    ];
    for (name, i, disk_udev, part_udev) in &disks {
        let major = 8 + i;
        let d = block(h, name, &sata(*i), &format!("{major}:0"), 4 * TIB);
        udev(h, &format!("{major}:0"), disk_udev);
        by_id(h, &format!("ata-DISK_{name}"), name);
        part(h, &d, &format!("{name}1"), &format!("{major}:1"), GIB);
        udev(h, &format!("{major}:1"), part_udev);
        if *name == "sdc" {
            part(h, &d, "sdc2", &format!("{major}:2"), TIB);
            udev(
                h,
                &format!("{major}:2"),
                &format!("{}E:ID_FS_TYPE=ext4\n", gpt(BASIC_DATA)),
            );
        }
    }
    mountinfo(h, "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n");
    h.write("root/etc/fstab", fstab);
    view(
        "/var/lib/hippius-miner",
        &[("default", "/var/lib/hippius-miner")],
        &[],
    )
}

const FSTAB: &str = "# /etc/fstab\n\
UUID=3333 / ext4 errors=remount-ro 0 1\n\
UUID=ABCD-1234  /boot/efi  vfat  umask=0077  0  1\n\
/swap.img none swap sw 0 0\n";

/// `name` is `ineligible` for the `system` reason.
fn assert_system_ineligible(s: &StorageSection, name: &str) {
    let d = dev(s, name);
    assert_eq!(d.role, DeviceRole::Ineligible, "{name} {:?}", d.reasons);
    assert!(d.reasons.contains(&R::System), "{name} {:?}", d.reasons);
}

#[test]
fn boot_partitions_and_their_disks_are_never_offered() {
    let h = Host::new();
    let v = boot_host(&h, FSTAB);
    let s = collect(&h, &Runner::default(), &v);
    for name in [
        "sdb", "sdb1", // ESP-only disk, unmounted
        "sdc", "sdc1", "sdc2", // bios_grub, and its sibling
        "sdd", "sdd1", // MBR 0xef
        "sde", "sde1", // EFI_SYSPART label
        "sdf", "sdf1", // fstab UUID= for /boot/efi only
        "sdh", "sdh1", // MBR active
        "sdi", "sdi1", // GPT legacy bootable
    ] {
        assert_system_ineligible(&s, name);
    }
    // The positive control.
    assert_eq!(dev(&s, "sdg1").role, DeviceRole::NeedsPrep);
    assert_eq!(dev(&s, "sdg").role, DeviceRole::NeedsPrep);
    assert_eq!(s.status, SectionStatus::Ok, "{:?}", s.advisories);
    // Without the fstab entry, `sdf1` is a plain vfat like the control.
    let h = Host::new();
    let v = boot_host(&h, "");
    let s = collect(&h, &Runner::default(), &v);
    assert_eq!(dev(&s, "sdf1").role, DeviceRole::NeedsPrep);
    assert_system_ineligible(&s, "sdb1");
}

#[test]
fn an_unidentifiable_boot_path_offers_nothing() {
    // An fstab spec nothing on the host matches.
    let h = Host::new();
    let v = boot_host(&h, "PARTLABEL=gone /boot/efi vfat defaults 0 1\n");
    let s = collect(&h, &Runner::default(), &v);
    assert_eq!(s.status, SectionStatus::Partial);
    assert_never_offered(&s);
    let a = adv(&s, "", AdvisoryCode::CollectorPartial).unwrap();
    assert_eq!(
        a.sample.as_deref(),
        Some("boot partition unresolved: nothing offerable")
    );

    // An automount on /boot/efi: resolved by a typed ESP (`sdb1`) ...
    let h = Host::new();
    let v = boot_host(&h, "");
    mountinfo(
        &h,
        "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         30 22 0:50 / /boot/efi rw - autofs systemd-1 rw\n",
    );
    let s = collect(&h, &Runner::default(), &v);
    assert_eq!(s.status, SectionStatus::Ok);
    assert_eq!(dev(&s, "sdg1").role, DeviceRole::NeedsPrep);
    // ... else nothing is offerable.
    let h = Host::new();
    let v = boot_host(&h, "");
    udev(&h, "10:1", "E:ID_FS_TYPE=vfat\n");
    for dev_no in ["11:1", "12:1", "13:1", "16:1", "17:1"] {
        udev(&h, dev_no, "E:ID_FS_TYPE=ext4\n");
    }
    mountinfo(
        &h,
        "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         30 22 0:50 / /boot/efi rw - autofs systemd-1 rw\n",
    );
    let s = collect(&h, &Runner::default(), &v);
    assert_eq!(s.status, SectionStatus::Partial);
    assert_never_offered(&s);
}

// ─── no positive proof of "not boot" ─────────────────────────────────

#[test]
fn an_efi_labelled_array_and_everything_under_it_are_never_offered() {
    let h = Host::new();
    let v = boot_host(&h, "");
    // md0 (vfat, EFI_SYSPART) over sdj1 + sdk1, not mounted, no fstab.
    let sata = |i: usize| {
        format!("devices/pci0000:00/0000:00:12.0/ata{i}/host{i}/target{i}:0:0/{i}:0:0:0")
    };
    for (i, name) in [(30, "sdj"), (31, "sdk")] {
        let d = block(&h, name, &sata(i), &format!("65:{}", i * 2), 4 * TIB);
        udev(&h, &format!("65:{}", i * 2), "E:ID_PART_TABLE_TYPE=gpt\n");
        by_id(&h, &format!("ata-DISK_{name}"), name);
        let p = part(
            &h,
            &d,
            &format!("{name}1"),
            &format!("65:{}", i * 2 + 1),
            GIB,
        );
        holder(&h, &p, "md0");
        udev(
            &h,
            &format!("65:{}", i * 2 + 1),
            &format!("E:ID_PART_ENTRY_TYPE={BASIC_DATA}\nE:ID_FS_TYPE=linux_raid_member\nE:ID_FS_UUID=arr\n"),
        );
    }
    let md = block(&h, "md0", VIRTUAL, "9:0", GIB);
    slave(&h, &md, "sdj1");
    slave(&h, &md, "sdk1");
    attr(&h, &md, "md/level", "raid1");
    attr(&h, &md, "md/array_state", "clean");
    udev(
        &h,
        "9:0",
        "E:ID_FS_TYPE=vfat\nE:ID_FS_LABEL=EFI_SYSPART\nE:ID_FS_UUID=E1\n",
    );
    let s = collect(&h, &Runner::default(), &v);
    for name in ["md0", "sdj1", "sdk1", "sdj", "sdk"] {
        assert_not_free(&s, name);
        assert_system_ineligible(&s, name);
    }
    // Not labelled: a running array with a plain vfat is preparable.
    let h = Host::new();
    let v = boot_host(&h, "");
    let md = block(&h, "md0", VIRTUAL, "9:0", GIB);
    attr(&h, &md, "md/array_state", "clean");
    udev(&h, "9:0", "E:ID_FS_TYPE=vfat\nE:ID_FS_UUID=E1\n");
    let s = collect(&h, &Runner::default(), &v);
    assert_eq!(dev(&s, "md0").role, DeviceRole::NeedsPrep);
}

#[test]
fn an_untyped_partition_and_its_disk_are_never_needs_prep() {
    let h = Host::new();
    let v = boot_host(&h, "");
    // `sdg1` (the positive control) loses its type GUID: only vfat left.
    udev(&h, "15:1", "E:ID_FS_TYPE=vfat\n");
    let s = collect(&h, &Runner::default(), &v);
    for name in ["sdg1", "sdg"] {
        assert_not_free(&s, name);
        assert!(
            dev(&s, name).reasons.contains(&R::HasSignature),
            "{name} {:?}",
            dev(&s, name).reasons
        );
    }
    // The control itself, typed basic data, still is.
    let h = Host::new();
    let v = boot_host(&h, "");
    let s = collect(&h, &Runner::default(), &v);
    assert_eq!(dev(&s, "sdg1").role, DeviceRole::NeedsPrep);
    assert_eq!(dev(&s, "sdg").role, DeviceRole::NeedsPrep);
}

#[test]
fn every_device_matching_a_boot_fstab_spec_is_marked() {
    // Two dd-cloned ESPs (no type, label or flag of their own beyond
    // basic data) share the vfat UUID fstab names for /boot/efi.
    let h = Host::new();
    let v = boot_host(&h, FSTAB);
    udev(
        &h,
        "15:1",
        &format!("E:ID_PART_ENTRY_TYPE={BASIC_DATA}\nE:ID_FS_TYPE=vfat\nE:ID_FS_UUID=ABCD-1234\n"),
    );
    let s = collect(&h, &Runner::default(), &v);
    for name in ["sdf1", "sdf", "sdg1", "sdg"] {
        assert_system_ineligible(&s, name);
    }
}

// ─── btrfs (HW5b) ────────────────────────────────────────────────────

const BTRFS_CMD: &str = "btrfs device stats -c /mnt/hippius-data";

/// The NVMe host with `md127` as a btrfs pool mount.
fn btrfs_host(h: &Host) -> StorageView {
    let v = nvme_md_host(h);
    udev(h, "9:127", "E:ID_FS_TYPE=btrfs\nE:ID_FS_UUID=2222\n");
    mountinfo(
        h,
        "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n\
         23 22 8:1 / /boot/efi rw,relatime shared:2 - vfat /dev/sda1 rw\n\
         24 22 9:127 / /mnt/hippius-data rw,relatime shared:3 - btrfs /dev/md127 rw\n",
    );
    v
}

#[test]
fn btrfs_device_errors_on_a_btrfs_pool() {
    let h = Host::new();
    let v = btrfs_host(&h);
    let stats = "\
[/dev/nvme0n1].write_io_errs    3
[/dev/nvme0n1].read_io_errs     0
[/dev/nvme0n1].flush_io_errs    0
[/dev/nvme0n1].corruption_errs  2
[/dev/nvme0n1].generation_errs  0
[/dev/nvme1n1].write_io_errs    1
[/dev/nvme1n1].read_io_errs     0
[/dev/nvme1n1].flush_io_errs    0
[/dev/nvme1n1].corruption_errs  0
[/dev/nvme1n1].generation_errs  0
";
    let s = collect(&h, &healthy_runner().with(BTRFS_CMD, Ok(stats)), &v);
    let a = adv(&s, "nvme0", AdvisoryCode::BtrfsDeviceErrors).unwrap();
    assert_eq!(
        (a.subject_kind, a.severity, a.count, a.value),
        (AdvisorySubject::Pool, Severity::Warning, 6, 6)
    );
    assert_eq!(
        a.sample.as_deref(),
        Some("btrfs device errors: write 4, read 0, flush 0, corruption 2, generation 0")
    );
    assert!(!serde_json::to_string(&s).unwrap().contains("/dev/nvme"));

    // All zero: nothing raised.
    let zero = stats
        .replace(" 3\n", " 0\n")
        .replace(" 2\n", " 0\n")
        .replace(" 1\n", " 0\n");
    let s = collect(&h, &healthy_runner().with(BTRFS_CMD, Ok(&zero)), &v);
    assert!(adv(&s, "nvme0", AdvisoryCode::BtrfsDeviceErrors).is_none());
    assert_eq!(s.status, SectionStatus::Ok);
    // A timeout: the pool says so, the section is a timeout.
    let s = collect(
        &h,
        &healthy_runner().with(BTRFS_CMD, Err(CommandError::Timeout)),
        &v,
    );
    let t = adv(&s, "nvme0", AdvisoryCode::CollectorTimeout).unwrap();
    assert_eq!(
        t.sample.as_deref(),
        Some("btrfs device stats timed out after 10 s")
    );
    assert_eq!(s.status, SectionStatus::Timeout);
    // Not a btrfs pool: never run (the runner would answer).
    let h = Host::new();
    let v = nvme_md_host(&h);
    let s = collect(&h, &healthy_runner().with(BTRFS_CMD, Ok(stats)), &v);
    assert!(adv(&s, "nvme0", AdvisoryCode::BtrfsDeviceErrors).is_none());
}

#[test]
fn btrfs_is_skipped_when_it_would_eat_the_probe_window() {
    let h = Host::new();
    let v = btrfs_host(&h);
    let runner = healthy_runner().with(BTRFS_CMD, Ok("[/dev/x].write_io_errs 5\n"));
    let previous = Counters::default();
    // The probe window plus a little: no room for a 10 s btrfs call.
    let inputs = StorageInputs {
        view: Some(&v),
        previous: &previous,
        deadline: std::time::Instant::now() + Duration::from_secs(125),
        min_probe_window: Duration::from_secs(120),
        clock: &super::super::SystemClock,
        kernel: &[],
    };
    let (s, _) = collect_storage(&h.paths(), &runner, &inputs, NOW).unwrap();
    assert!(adv(&s, "nvme0", AdvisoryCode::BtrfsDeviceErrors).is_none());
    assert_eq!(s.status, SectionStatus::Timeout);
}

// ─── the run order (HW5b) ────────────────────────────────────────────

/// Records the program of every run, in order.
struct Recorder {
    inner: Runner,
    log: std::sync::Mutex<Vec<String>>,
}

impl CommandRunner for Recorder {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, CommandError> {
        self.log.lock().unwrap().push(program.to_string());
        self.inner.run(program, args)
    }
}

#[test]
fn sensors_and_ipmi_run_before_storage_and_the_probe_last() {
    let h = Host::new();
    let v = btrfs_host(&h);
    super::super::sensors::tests::hwmon_tree(&h);
    h.write("dev/ipmi0", "");
    let runner = Recorder {
        inner: healthy_runner()
            .with(
                "ipmitool sdr type Power Supply",
                Ok(super::super::sensors::tests::SDR_PSU),
            )
            .with(
                "ipmitool mc info",
                Ok(super::super::sensors::tests::MC_INFO),
            )
            .with(BTRFS_CMD, Ok("[/dev/md127].write_io_errs 0\n")),
        log: std::sync::Mutex::new(Vec::new()),
    };
    let previous = Counters::default();
    let inputs = StorageInputs {
        view: Some(&v),
        previous: &previous,
        deadline: std::time::Instant::now() + SMART_BUDGET,
        min_probe_window: Duration::ZERO,
        clock: &super::super::SystemClock,
        kernel: &[],
    };
    let (sections, _) =
        super::super::collect(Mode::Full, &h.paths(), &runner, NOW, &inputs).unwrap();
    let log = runner.log.lock().unwrap().clone();
    let pos = |p: &str| log.iter().position(|x| x == p);
    let last = |p: &str| log.iter().rposition(|x| x == p);
    let first_probe = log
        .iter()
        .position(|x| x == "smartctl" || x == "nvme")
        .unwrap();
    assert!(last("ipmitool").unwrap() < pos("btrfs").unwrap(), "{log:?}");
    assert!(pos("btrfs").unwrap() < first_probe, "{log:?}");
    assert!(
        log[first_probe..]
            .iter()
            .all(|x| x == "smartctl" || x == "nvme"),
        "nothing after the probe: {log:?}"
    );
    // All eight sections: the run checks as a real `full` report.
    let checked = normalize_and_check(sections, Mode::Full, NOW);
    assert_eq!(checked.valid, Ok(()));
    let s = &checked.sections;
    assert!(s.sensors.as_ref().is_some_and(|x| x.psus.len() == 3));
    assert_eq!(
        s.system.as_ref().and_then(|x| x.bmc_firmware.as_deref()),
        Some("7.10")
    );
}
