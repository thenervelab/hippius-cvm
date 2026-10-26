//! The disk evidence a receipt carries (docs/design/disk-tier-verification.md
//! §3, §4.2): `disk_io`, the guest's block-device counters over the receipt
//! window, and `disk_probe`, a probe VM's benchmark result.
//!
//! - `disk_io` is the delta of `/sys/block/vd*/stat` between two receipts,
//!   keyed by the device's virtio serial (`hippius-<slot>`, empty when the
//!   disk has none). The serial comes from udev's
//!   `/dev/disk/by-id/virtio-<serial>` links, never from
//!   `/sys/block/<dev>/serial`: reading that issues a request to the
//!   device, which a stuck disk never answers, and the receipt loop must
//!   never wait on a disk. The first window after start has no baseline and
//!   carries none; a window in which any counter went backwards (a device
//!   reset or replaced under the same name) carries none either. A device
//!   seen at only one end of the window is left out.
//! - `disk_probe` is `/run/hippius/disk-probe/result.cbor`, written by the
//!   probe binary in a vali probe VM. It is attached to every receipt while
//!   present and naming this VM; anything else is ignored.
//!
//! - dedicated-disk slot verdicts: the initramfs opener
//!   (`hippius-guest-release --open-dedicated-disks`) leaves one line per
//!   anchored slot in `/run/hippius/dedicated/slots`. A slot it refused is
//!   reported `mismatch` (on its device), one it could not find `missing`
//!   (no device, zero counters), and so is an opened slot whose device has
//!   since disappeared; an opened slot is its device, `ok`. An integrity
//!   slot whose first-boot wipe is running (guest release 8; the booted
//!   OS's `--dedicated-init-wipe` keeps the line's `init-<percent>` reason
//!   current) is `initializing` on its device, with `init_percent`. Every slot rides
//!   every receipt, the first one included (zero counters when there is no
//!   window), and survives a window dropped for a counter going backwards.
//!
//! Both are optional evidence: a value that would not encode is dropped
//! rather than failing the receipt (the receipt loop also retries without
//! them), so billing never depends on them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hippius_types::disk_stats::{
    slot_of_serial, validate_disk_io, DiskIoDelta, DiskIoState, DiskProbeResult, MAX_DEV_LEN,
    MAX_DISK_IO_DEVICES, MAX_SERIAL_LEN, SLOT_SERIAL_PREFIX,
};

/// Where the probe binary leaves its result.
pub const PROBE_RESULT_PATH: &str = "/run/hippius/disk-probe/result.cbor";

/// Where the initramfs opener leaves the dedicated slots' states.
pub const SLOTS_STATE_PATH: &str = "/run/hippius/dedicated/slots";

/// The largest slot-state file read (8 slots fit in well under 1 KiB).
const MAX_SLOTS_STATE_BYTES: u64 = 4096;

/// The largest probe result read (the worst case encodes well under it).
const MAX_PROBE_RESULT_BYTES: u64 = 16 * 1024;

/// What the `/sys/block/<dev>/stat` fields are (Documentation/block/stat.rst).
const STAT_FIELDS: usize = 11;

/// The disk evidence for one receipt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiskEvidence {
    pub io: Option<Vec<DiskIoDelta>>,
    pub probe: Option<DiskProbeResult>,
}

/// One reading of every device: `dev → (serial, stat fields)`.
pub type Snapshot = BTreeMap<String, (String, [u64; STAT_FIELDS])>;

/// A source of [`DiskEvidence`]. [`sample`](Self::sample) reads the window
/// ending now without moving it; [`commit`](Self::commit) moves it, once
/// the receipt carrying the sample is signed (a failed interval keeps its
/// window, like the receipt's own).
pub trait DiskEvidenceSource {
    fn sample(&self) -> (DiskEvidence, Snapshot);
    fn commit(&self, snapshot: Snapshot);
}

/// No disk evidence (tests, and a guest without `/sys/block`).
#[derive(Debug, Default)]
pub struct NoDiskEvidence;

impl DiskEvidenceSource for NoDiskEvidence {
    fn sample(&self) -> (DiskEvidence, Snapshot) {
        (DiskEvidence::default(), Snapshot::new())
    }
    fn commit(&self, _snapshot: Snapshot) {}
}

/// The guest's own devices and probe result.
#[derive(Debug)]
pub struct SysDiskEvidence {
    sys_block: PathBuf,
    by_id: PathBuf,
    probe_result: PathBuf,
    slots_state: PathBuf,
    vm_id: String,
    previous: Mutex<Option<Snapshot>>,
}

impl SysDiskEvidence {
    /// The real `/sys/block` and probe result, for `vm_id`.
    pub fn new(vm_id: String) -> Self {
        Self::with_paths(
            PathBuf::from("/sys/block"),
            PathBuf::from("/dev/disk/by-id"),
            PathBuf::from(PROBE_RESULT_PATH),
            vm_id,
        )
        .with_slots_state(PathBuf::from(SLOTS_STATE_PATH))
    }

    /// Over other paths (tests).
    pub fn with_paths(
        sys_block: PathBuf,
        by_id: PathBuf,
        probe_result: PathBuf,
        vm_id: String,
    ) -> Self {
        Self {
            sys_block,
            by_id,
            probe_result,
            slots_state: PathBuf::new(),
            vm_id,
            previous: Mutex::new(None),
        }
    }

    /// Read dedicated slot verdicts from `path` (none by default).
    pub fn with_slots_state(mut self, path: PathBuf) -> Self {
        self.slots_state = path;
        self
    }
}

impl DiskEvidenceSource for SysDiskEvidence {
    fn sample(&self) -> (DiskEvidence, Snapshot) {
        let now = read_snapshot(&self.sys_block, &self.by_id);
        let io = self
            .previous
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(|before| deltas(before, &now));
        let io = with_slot_verdicts(io, &now, &read_slot_verdicts(&self.slots_state));
        let probe = read_probe(&self.probe_result, &self.vm_id);
        (DiskEvidence { io, probe }, now)
    }

    fn commit(&self, snapshot: Snapshot) {
        *self
            .previous
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(snapshot);
    }
}

fn is_dev_name(name: &str) -> bool {
    name.starts_with("vd")
        && name.len() <= MAX_DEV_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// `dev → serial` from udev's `virtio-<serial>` links in `by_id`, for
/// serials that name a slot. No device I/O: links and their targets only.
fn virtio_serials(by_id: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(by_id) else {
        return out;
    };
    for entry in entries.flatten() {
        let Some(serial) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.strip_prefix("virtio-"))
            .map(str::to_string)
        else {
            continue;
        };
        if serial.len() > MAX_SERIAL_LEN || slot_of_serial(&serial).is_none() {
            continue;
        }
        let Some(dev) = std::fs::read_link(entry.path())
            .ok()
            .and_then(|t| t.file_name().and_then(|n| n.to_str()).map(str::to_string))
        else {
            continue;
        };
        out.insert(dev, serial);
    }
    out
}

fn parse_stat(text: &str) -> Option<[u64; STAT_FIELDS]> {
    let mut out = [0u64; STAT_FIELDS];
    let mut fields = text.split_whitespace();
    for slot in &mut out {
        *slot = fields.next()?.parse().ok()?;
    }
    Some(out)
}

/// Every virtio disk under `sys_block` with a readable `stat`, with its
/// slot serial from `by_id`.
pub fn read_snapshot(sys_block: &Path, by_id: &Path) -> Snapshot {
    let serials = virtio_serials(by_id);
    let mut out = Snapshot::new();
    let Ok(entries) = std::fs::read_dir(sys_block) else {
        return out;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_dev_name(&name) {
            continue;
        }
        let dir = sys_block.join(&name);
        let Some(stat) = std::fs::read_to_string(dir.join("stat"))
            .ok()
            .and_then(|t| parse_stat(&t))
        else {
            continue;
        };
        let serial = serials.get(&name).cloned().unwrap_or_default();
        out.insert(name, (serial, stat));
    }
    out
}

/// The window's deltas, `None` when there are none or a counter went
/// backwards anywhere. At most [`MAX_DISK_IO_DEVICES`], the first by name.
pub fn deltas(before: &Snapshot, now: &Snapshot) -> Option<Vec<DiskIoDelta>> {
    let mut out = Vec::new();
    for (dev, (serial, b)) in before {
        let Some((now_serial, n)) = now.get(dev) else {
            continue;
        };
        // Another disk under the same name: no window for it.
        if now_serial != serial {
            continue;
        }
        // Fields: 0 r_ios, 2 r_sectors, 3 r_ticks, 4 w_ios, 6 w_sectors,
        // 7 w_ticks, 8 in_flight (a gauge), 9 io_ticks, 10 time_in_queue.
        let d = |i: usize| n[i].checked_sub(b[i]);
        out.push(DiskIoDelta {
            dev: dev.clone(),
            serial: serial.clone(),
            state: DiskIoState::Ok,
            r_ios: d(0)?,
            r_sectors: d(2)?,
            r_ticks_ms: d(3)?,
            w_ios: d(4)?,
            w_sectors: d(6)?,
            w_ticks_ms: d(7)?,
            io_ticks_ms: d(9)?,
            tiq_ms: d(10)?,
            inflight: n[8],
            init_percent: None,
        });
    }
    // Two devices claiming one slot serial cannot both be that slot.
    let mut seen = std::collections::BTreeSet::new();
    let dup: std::collections::BTreeSet<String> = out
        .iter()
        .filter(|d| !d.serial.is_empty() && !seen.insert(d.serial.clone()))
        .map(|d| d.serial.clone())
        .collect();
    for d in &mut out {
        if dup.contains(&d.serial) {
            d.serial.clear();
        }
    }
    out.truncate(MAX_DISK_IO_DEVICES);
    if out.is_empty() || validate_disk_io(&out).is_err() {
        return None;
    }
    Some(out)
}

/// A dedicated slot's verdict from the opener's state file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotVerdict {
    /// `hippius-<slot>`.
    pub serial: String,
    pub state: SlotVerdictState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotVerdictState {
    Attached,
    Missing,
    Mismatch,
    /// The first-boot integrity wipe is running; its progress (0..=100)
    /// when the line's reason carries one (`init-<percent>`).
    Initializing(Option<u8>),
}

/// The progress an `initializing` line's reason carries: `init-<0..=100>`
/// (no leading zero). Anything else is no progress, never a guess.
fn init_percent_of(reason: &str) -> Option<u8> {
    let n = reason.strip_prefix("init-")?;
    if n.is_empty() || n.len() > 3 || (n.len() > 1 && n.starts_with('0')) {
        return None;
    }
    n.parse::<u8>().ok().filter(|p| *p <= 100)
}

/// Parse the opener's state file (`<slot> <state> <gib> <dev|-> <reason>`
/// per line, after a `#` header). Lines that do not parse are skipped:
/// the file is guest-root-writable evidence, never trusted for more than
/// what the receipt carries anyway.
pub fn parse_slot_verdicts(text: &str) -> Vec<SlotVerdict> {
    let mut out: Vec<SlotVerdict> = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split(' ').collect();
        let [slot, state, _gib, _dev, reason] = f.as_slice() else {
            continue;
        };
        let serial = format!("{SLOT_SERIAL_PREFIX}{slot}");
        if *slot == "os" || slot_of_serial(&serial).is_none() {
            continue;
        }
        let state = match *state {
            "attached" => SlotVerdictState::Attached,
            "missing" => SlotVerdictState::Missing,
            "mismatch" => SlotVerdictState::Mismatch,
            "initializing" => SlotVerdictState::Initializing(init_percent_of(reason)),
            _ => continue,
        };
        if out.iter().any(|v| v.serial == serial) {
            continue;
        }
        out.push(SlotVerdict { serial, state });
    }
    out
}

/// The verdicts at `path`, if it is a small regular file.
pub fn read_slot_verdicts(path: &Path) -> Vec<SlotVerdict> {
    if path.as_os_str().is_empty() {
        return Vec::new();
    }
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Vec::new();
    };
    if !meta.is_file() || meta.len() > MAX_SLOTS_STATE_BYTES {
        return Vec::new();
    }
    std::fs::read_to_string(path)
        .map(|t| parse_slot_verdicts(&t))
        .unwrap_or_default()
}

fn zero_counters(
    dev: String,
    serial: String,
    state: DiskIoState,
    init_percent: Option<u8>,
) -> DiskIoDelta {
    DiskIoDelta {
        dev,
        serial,
        state,
        r_ios: 0,
        r_sectors: 0,
        r_ticks_ms: 0,
        w_ios: 0,
        w_sectors: 0,
        w_ticks_ms: 0,
        io_ticks_ms: 0,
        tiq_ms: 0,
        inflight: 0,
        init_percent,
    }
}

/// Fold the slot verdicts into the window's deltas (`io`, maybe none):
///
/// - `mismatch`: the slot's device (found by serial in `now`) carries
///   `state = mismatch`, with zero counters when the window has none for
///   it; no device any more ⇒ `missing`;
/// - `missing`: a `missing` entry (no device, zero counters), replacing
///   any device that has since appeared under the serial (the guest never
///   opened it);
/// - `attached`: its device `ok` (zero counters when the window has none
///   for it, so the first receipt already names every slot); gone ⇒
///   `missing`;
/// - `initializing`: its device `initializing` with the line's
///   `init_percent` (counters as usual: the wipe's writes); gone ⇒
///   `missing`.
///
/// The result keeps the wire's order and limits; a list that would not
/// validate falls back to the plain deltas.
pub fn with_slot_verdicts(
    io: Option<Vec<DiskIoDelta>>,
    now: &Snapshot,
    verdicts: &[SlotVerdict],
) -> Option<Vec<DiskIoDelta>> {
    if verdicts.is_empty() {
        return io;
    }
    let mut list = io.clone().unwrap_or_default();
    let dev_of = |serial: &str| {
        now.iter()
            .find(|(_, (s, _))| s == serial)
            .map(|(d, _)| d.clone())
    };
    let mut add = Vec::new();
    for v in verdicts {
        let dev = dev_of(&v.serial);
        let (state, init_percent) = match (v.state, &dev) {
            (SlotVerdictState::Attached, Some(_)) => (DiskIoState::Ok, None),
            (SlotVerdictState::Mismatch, Some(_)) => (DiskIoState::Mismatch, None),
            (SlotVerdictState::Initializing(p), Some(_)) => (DiskIoState::Initializing, p),
            _ => (DiskIoState::Missing, None),
        };
        if state != DiskIoState::Missing {
            if let Some(d) = list.iter_mut().find(|d| d.serial == v.serial) {
                d.state = state;
                d.init_percent = init_percent;
                continue;
            }
            // No counters for it in this window (the first receipt, or a
            // window dropped for a counter going backwards): the verdict
            // still goes out, on its device, with zero counters.
            if let Some(dev) = dev {
                add.push(zero_counters(dev, v.serial.clone(), state, init_percent));
            }
            continue;
        }
        list.retain(|d| d.serial != v.serial);
        add.push(zero_counters(
            String::new(),
            v.serial.clone(),
            DiskIoState::Missing,
            None,
        ));
    }
    // Verdicts first when the list is full: they are what vali acts on.
    let room = MAX_DISK_IO_DEVICES.saturating_sub(add.len());
    if list.len() > room {
        let (mut keep, rest): (Vec<_>, Vec<_>) =
            list.into_iter().partition(|d| d.state != DiskIoState::Ok);
        keep.extend(rest.into_iter().take(room.saturating_sub(keep.len())));
        list = keep;
    }
    list.extend(add);
    list.sort_by(|a, b| {
        (a.dev.as_str(), a.serial.as_str()).cmp(&(b.dev.as_str(), b.serial.as_str()))
    });
    list.truncate(MAX_DISK_IO_DEVICES);
    if list.is_empty() || validate_disk_io(&list).is_err() {
        return io;
    }
    Some(list)
}

/// The probe result at `path`, if it is a small regular file holding a
/// valid result for `vm_id`.
pub fn read_probe(path: &Path, vm_id: &str) -> Option<DiskProbeResult> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_PROBE_RESULT_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).ok()?;
    let result = DiskProbeResult::from_value(&value).ok()?;
    (result.vm_id == vm_id && result.to_value().is_ok()).then_some(result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hippius_types::disk_stats::DiskProbeTarget;

    /// `root/sys/<name>/stat`, and udev's `root/by-id/virtio-<serial>`
    /// link to `../../<name>` when it has a serial. A `serial` file that
    /// would hang is never read: it is not even written.
    fn dev(root: &Path, name: &str, serial: Option<&str>, stat: &str) {
        let d = root.join("sys").join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("stat"), stat).unwrap();
        std::fs::create_dir_all(root.join("by-id")).unwrap();
        if let Some(s) = serial {
            let link = root.join("by-id").join(format!("virtio-{s}"));
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(format!("../../{name}"), link).unwrap();
        }
    }

    const ZERO: &str = "0 0 0 0 0 0 0 0 0 0 0";

    #[test]
    fn the_first_window_has_no_baseline_then_deltas_follow() {
        let sys = tempfile::tempdir().unwrap();
        dev(sys.path(), "vda", Some("hippius-os"), ZERO);
        dev(sys.path(), "loop0", None, ZERO);
        dev(sys.path(), "sda", None, ZERO);
        let src = SysDiskEvidence::with_paths(
            sys.path().join("sys"),
            sys.path().join("by-id"),
            sys.path().join("none"),
            "vm-1".into(),
        );
        let (ev, snap) = src.sample();
        assert_eq!(ev, DiskEvidence::default());
        assert_eq!(snap.keys().collect::<Vec<_>>(), ["vda"]);
        src.commit(snap);
        dev(
            sys.path(),
            "vda",
            Some("hippius-os"),
            "10 1 80 7 20 2 160 9 3 30 40",
        );
        // Sampling twice without a commit is the same window.
        for _ in 0..2 {
            let (ev, _) = src.sample();
            let io = ev.io.unwrap();
            assert_eq!(
                io,
                [DiskIoDelta {
                    dev: "vda".into(),
                    serial: "hippius-os".into(),
                    state: DiskIoState::Ok,
                    r_ios: 10,
                    r_sectors: 80,
                    r_ticks_ms: 7,
                    w_ios: 20,
                    w_sectors: 160,
                    w_ticks_ms: 9,
                    io_ticks_ms: 30,
                    tiq_ms: 40,
                    inflight: 3,
                    init_percent: None,
                }]
            );
        }
    }

    fn snap(entries: &[(&str, &str, [u64; STAT_FIELDS])]) -> Snapshot {
        entries
            .iter()
            .map(|(d, s, f)| ((*d).to_string(), ((*s).to_string(), *f)))
            .collect()
    }

    #[test]
    fn a_counter_going_backwards_drops_the_whole_window() {
        let before = snap(&[("vda", "", [5; 11]), ("vdb", "", [5; 11])]);
        let mut back = [6; 11];
        back[4] = 4;
        let now = snap(&[("vda", "", [6; 11]), ("vdb", "", back)]);
        assert_eq!(deltas(&before, &now), None);
    }

    #[test]
    fn a_device_at_one_end_only_or_renamed_is_left_out() {
        let before = snap(&[
            ("vda", "hippius-os", [1; 11]),
            ("vdb", "hippius-x0", [1; 11]),
        ]);
        let now = snap(&[
            ("vda", "hippius-os", [2; 11]),
            ("vdb", "hippius-x1", [2; 11]),
            ("vdc", "", [2; 11]),
        ]);
        let io = deltas(&before, &now).unwrap();
        assert_eq!(io.len(), 1);
        assert_eq!(io[0].dev, "vda");
        // Nothing in common: no list at all.
        assert_eq!(deltas(&snap(&[]), &now), None);
    }

    #[test]
    fn more_devices_than_a_receipt_holds_keeps_the_first_by_name() {
        let names: Vec<String> = (0..20)
            .map(|i| format!("vd{}", (b'a' + i) as char))
            .collect();
        let before: Snapshot = names
            .iter()
            .map(|n| (n.clone(), (String::new(), [0; 11])))
            .collect();
        let now: Snapshot = names
            .iter()
            .map(|n| (n.clone(), (String::new(), [1; 11])))
            .collect();
        let io = deltas(&before, &now).unwrap();
        assert_eq!(io.len(), MAX_DISK_IO_DEVICES);
        assert_eq!(io[0].dev, "vda");
        assert_eq!(
            io[MAX_DISK_IO_DEVICES - 1].dev,
            names[MAX_DISK_IO_DEVICES - 1]
        );
        assert!(validate_disk_io(&io).is_ok());
    }

    #[test]
    fn a_serial_that_is_no_slot_or_claimed_twice_is_dropped() {
        let sys = tempfile::tempdir().unwrap();
        dev(sys.path(), "vda", Some("WD-123456"), ZERO);
        dev(sys.path(), "vdb", Some("hippius-x0"), ZERO);
        dev(sys.path(), "vdd", Some("hippius-x1"), ZERO);
        // A partition's link does not name a slot.
        std::os::unix::fs::symlink(
            "../../vdb1",
            sys.path().join("by-id/virtio-hippius-x0-part1"),
        )
        .unwrap();
        let s = read_snapshot(&sys.path().join("sys"), &sys.path().join("by-id"));
        assert_eq!(s["vda"].0, "");
        assert_eq!(s["vdb"].0, "hippius-x0");
        assert_eq!(s["vdd"].0, "hippius-x1");
        // Two devices claiming one slot serial: neither is that slot.
        let mut twice = s.clone();
        twice.get_mut("vdd").unwrap().0 = "hippius-x0".into();
        let io = deltas(&twice, &twice).unwrap();
        assert!(io.iter().all(|d| d.serial.is_empty()));
    }

    fn verdicts(text: &str) -> Vec<SlotVerdict> {
        parse_slot_verdicts(text)
    }

    #[test]
    fn the_opener_state_file_parses_and_junk_is_skipped() {
        let v = verdicts(
            "# hippius-dedicated-disks state v1\nx0 attached 22300 vdb -\nx1 missing 22300 - absent\n\
             x2 mismatch 1000 vdd uuid-mismatch\nos attached 1 vda -\nx24 missing 1000 - absent\n\
             x3 exploded 1000 vde -\nx4 attached\nx0 missing 1 - again\n",
        );
        assert_eq!(
            v,
            [
                SlotVerdict {
                    serial: "hippius-x0".into(),
                    state: SlotVerdictState::Attached
                },
                SlotVerdict {
                    serial: "hippius-x1".into(),
                    state: SlotVerdictState::Missing
                },
                SlotVerdict {
                    serial: "hippius-x2".into(),
                    state: SlotVerdictState::Mismatch
                },
            ]
        );
    }

    #[test]
    fn slot_verdicts_ride_the_first_receipt_and_every_later_one() {
        let sys = tempfile::tempdir().unwrap();
        dev(sys.path(), "vda", Some("hippius-os"), ZERO);
        dev(sys.path(), "vdb", Some("hippius-x0"), ZERO);
        dev(sys.path(), "vdc", Some("hippius-x2"), ZERO);
        let state = sys.path().join("slots");
        std::fs::write(
            &state,
            "# hippius-dedicated-disks state v1\nx0 attached 22300 vdb -\nx1 missing 22300 - absent\nx2 mismatch 1000 vdc uuid-mismatch\n",
        )
        .unwrap();
        let src = SysDiskEvidence::with_paths(
            sys.path().join("sys"),
            sys.path().join("by-id"),
            sys.path().join("none"),
            "vm-1".into(),
        )
        .with_slots_state(state.clone());
        // First window: no counters yet, every slot is there.
        let (ev, snap) = src.sample();
        let io = ev.io.unwrap();
        assert_eq!(
            io.iter()
                .map(|d| (d.dev.as_str(), d.serial.as_str(), d.state))
                .collect::<Vec<_>>(),
            [
                ("", "hippius-x1", DiskIoState::Missing),
                ("vdb", "hippius-x0", DiskIoState::Ok),
                ("vdc", "hippius-x2", DiskIoState::Mismatch),
            ]
        );
        assert!(io.iter().all(|d| d.w_ios == 0 && d.r_ios == 0));
        assert!(validate_disk_io(&io).is_ok());
        src.commit(snap);
        // Next window: counters for every device, the mismatch kept on its
        // device, the attached slot plain `ok`.
        dev(
            sys.path(),
            "vdb",
            Some("hippius-x0"),
            "1 0 8 1 2 0 16 1 0 2 2",
        );
        let (ev, snap) = src.sample();
        let io = ev.io.unwrap();
        assert_eq!(
            io.iter()
                .map(|d| (d.dev.as_str(), d.serial.as_str(), d.state))
                .collect::<Vec<_>>(),
            [
                ("", "hippius-x1", DiskIoState::Missing),
                ("vda", "hippius-os", DiskIoState::Ok),
                ("vdb", "hippius-x0", DiskIoState::Ok),
                ("vdc", "hippius-x2", DiskIoState::Mismatch),
            ]
        );
        assert_eq!(io[2].r_ios, 1);
        src.commit(snap);
        // The attached disk vanishes: now `missing`.
        std::fs::remove_dir_all(sys.path().join("sys/vdb")).unwrap();
        std::fs::remove_file(sys.path().join("by-id/virtio-hippius-x0")).unwrap();
        let (ev, _) = src.sample();
        let io = ev.io.unwrap();
        assert!(io.iter().any(|d| d.serial == "hippius-x0"
            && d.state == DiskIoState::Missing
            && d.dev.is_empty()));
        assert!(validate_disk_io(&io).is_ok());
    }

    #[test]
    fn an_initializing_slot_rides_on_its_device_with_its_percent() {
        let v = verdicts(
            "x0 initializing 1000 vdb init-42\nx1 initializing 1000 vdc init-0\n\
             x2 initializing 1000 vdd -\nx3 initializing 1000 vde init-101\n\
             x4 initializing 1000 vdf init-042\nx5 initializing 1000 - init-7\n",
        );
        assert_eq!(
            v.iter().map(|v| v.state).collect::<Vec<_>>(),
            [
                SlotVerdictState::Initializing(Some(42)),
                SlotVerdictState::Initializing(Some(0)),
                SlotVerdictState::Initializing(None),
                SlotVerdictState::Initializing(None),
                SlotVerdictState::Initializing(None),
                SlotVerdictState::Initializing(Some(7)),
            ]
        );
        // On its device (the wipe's writes are its counters); a slot whose
        // device is gone is `missing`, never `initializing`.
        let before = snap(&[("vdb", "hippius-x0", [0; 11])]);
        let now = snap(&[
            ("vdb", "hippius-x0", [5; 11]),
            ("vdc", "hippius-x1", [1; 11]),
        ]);
        let out = with_slot_verdicts(deltas(&before, &now), &now, &v).unwrap();
        assert!(validate_disk_io(&out).is_ok());
        let got: Vec<_> = out
            .iter()
            .map(|d| (d.dev.as_str(), d.serial.as_str(), d.state, d.init_percent))
            .collect();
        assert_eq!(
            got,
            [
                ("", "hippius-x2", DiskIoState::Missing, None),
                ("", "hippius-x3", DiskIoState::Missing, None),
                ("", "hippius-x4", DiskIoState::Missing, None),
                ("", "hippius-x5", DiskIoState::Missing, None),
                ("vdb", "hippius-x0", DiskIoState::Initializing, Some(42)),
                ("vdc", "hippius-x1", DiskIoState::Initializing, Some(0)),
            ]
        );
        assert_eq!(out[4].w_ios, 5, "counters as usual");
        // Once the wipe is done the same slot is plain `ok`, no percent.
        let done = with_slot_verdicts(None, &now, &verdicts("x0 attached 1000 vdb -\n")).unwrap();
        assert_eq!(
            (done[0].state, done[0].init_percent),
            (DiskIoState::Ok, None)
        );
    }

    #[test]
    fn a_device_appearing_under_a_missing_slot_stays_missing() {
        let now = snap(&[
            ("vda", "hippius-os", [1; 11]),
            ("vdb", "hippius-x1", [1; 11]),
        ]);
        let before = snap(&[
            ("vda", "hippius-os", [0; 11]),
            ("vdb", "hippius-x1", [0; 11]),
        ]);
        let io = deltas(&before, &now);
        let v = verdicts("x1 missing 1000 - absent\n");
        let out = with_slot_verdicts(io, &now, &v).unwrap();
        assert_eq!(
            out.iter()
                .map(|d| (d.dev.as_str(), d.serial.as_str(), d.state))
                .collect::<Vec<_>>(),
            [
                ("", "hippius-x1", DiskIoState::Missing),
                ("vda", "hippius-os", DiskIoState::Ok),
            ]
        );
    }

    #[test]
    fn verdicts_survive_a_window_dropped_and_win_when_the_list_is_full() {
        // A counter went backwards: no deltas, the verdict still goes out.
        let now = snap(&[("vdb", "hippius-x0", [1; 11])]);
        let out =
            with_slot_verdicts(None, &now, &verdicts("x0 mismatch 1000 vdb no-header\n")).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].state, DiskIoState::Mismatch);
        // No verdicts: the deltas untouched.
        assert_eq!(with_slot_verdicts(None, &now, &[]), None);
        // 16 plain devices + 2 missing verdicts: both verdicts kept.
        let names: Vec<String> = (0..16)
            .map(|i| format!("vd{}", (b'a' + i) as char))
            .collect();
        let full: Vec<DiskIoDelta> = names
            .iter()
            .map(|n| zero_counters(n.clone(), String::new(), DiskIoState::Ok, None))
            .collect();
        let out = with_slot_verdicts(
            Some(full),
            &Snapshot::new(),
            &verdicts("x0 missing 1000 - absent\nx1 missing 1000 - absent\n"),
        )
        .unwrap();
        assert_eq!(out.len(), MAX_DISK_IO_DEVICES);
        assert_eq!(
            out.iter()
                .filter(|d| d.state == DiskIoState::Missing)
                .count(),
            2
        );
        assert!(validate_disk_io(&out).is_ok());
    }

    #[test]
    fn a_slot_state_file_that_is_a_symlink_or_huge_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, "x0 missing 1000 - absent\n").unwrap();
        assert_eq!(read_slot_verdicts(&real).len(), 1);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_slot_verdicts(&link).is_empty());
        std::fs::write(&real, "x0 missing 1000 - absent\n".repeat(400)).unwrap();
        assert!(read_slot_verdicts(&real).is_empty());
        assert!(read_slot_verdicts(&dir.path().join("none")).is_empty());
        assert!(read_slot_verdicts(Path::new("")).is_empty());
    }

    fn probe(vm_id: &str) -> DiskProbeResult {
        DiskProbeResult {
            run_id: [1; 16],
            nonce: [2; 32],
            vm_id: vm_id.into(),
            vcpus: 2,
            kernel: "6.8.0".into(),
            release_version: 5,
            started_at: 10,
            finished_at: 20,
            targets: vec![DiskProbeTarget {
                slot: "os".into(),
                profile: "v1".into(),
                metrics: vec![("seq_read_mbps".into(), 900)],
                hist_qd1: vec![0; hippius_types::disk_stats::HIST_BUCKETS],
                error: String::new(),
            }],
        }
    }

    fn write_probe(path: &Path, p: &DiskProbeResult) {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&p.to_value().unwrap(), &mut bytes).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn a_probe_result_for_this_vm_is_attached_anything_else_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("result.cbor");
        assert_eq!(read_probe(&path, "vm-1"), None);
        write_probe(&path, &probe("vm-1"));
        assert_eq!(read_probe(&path, "vm-1"), Some(probe("vm-1")));
        // Another VM's result.
        assert_eq!(read_probe(&path, "vm-2"), None);
        // Garbage, and a file too large.
        std::fs::write(&path, b"\xff\x00").unwrap();
        assert_eq!(read_probe(&path, "vm-1"), None);
        std::fs::write(&path, vec![0u8; MAX_PROBE_RESULT_BYTES as usize + 1]).unwrap();
        assert_eq!(read_probe(&path, "vm-1"), None);
        // A symlink is not followed.
        let real = dir.path().join("real.cbor");
        write_probe(&real, &probe("vm-1"));
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        assert_eq!(read_probe(&path, "vm-1"), None);
    }
}
