//! Disk evidence carried in a tenant guest's `ServedDeliveryReceipt`
//! (docs/design/disk-tier-verification.md §3, §4.2).
//!
//! Two OPTIONAL receipt keys, each emitted only when present, so a receipt
//! without them is byte-identical to before:
//!
//! - `disk_io` — per-device `/sys/block/<dev>/stat` deltas over the
//!   receipt window, keyed by the device's virtio serial so vali maps it
//!   to a disk slot. Passive evidence: in-VM root controls it, so vali
//!   only ever uses it to schedule a probe. A dedicated-disk slot the
//!   guest refused (`mismatch`) or could not find (`missing`) is reported
//!   here too, and so is one whose first-boot integrity wipe is still
//!   running (`initializing`, with an optional `init_percent`).
//! - `disk_probe` — the result of a vali-owned probe VM's benchmark, one
//!   entry per disk it measured. vali accepts it only from a VM it
//!   launched as a probe, bound by `run_id` + `nonce` + `vm_id`.
//!
//! Integers only (no floats in canonical CBOR), every list bounded and in
//! a fixed order, every string charset-checked: a malformed value fails at
//! encode, so no signature over one can exist, and the same checks run on
//! decode. The types deliberately have no serde impls: the only encoding
//! is the canonical one (`disk_io_to_value`, `DiskProbeResult::to_value`).

#[allow(unused_imports)]
// per-module slice of the alloc prelude — not every module needs every item
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use ciborium::value::Value;

use crate::map_decode::{
    array_at, bytes_at, charset, exact_map, is_valid_error_code, kv, text_at, u32_at, u64_at,
};
use crate::{HippiusTypesError, Result};

/// At most this many devices in one `disk_io` list: a golden VM's four
/// base devices (OS overlay, verity base and hash, state disk), up to 8
/// dedicated disks, and room for the seed disk and slot verdicts.
pub const MAX_DISK_IO_DEVICES: usize = 16;
/// A kernel block-device name (`vda`, `vdb`, …): `[a-z0-9]{1,16}`.
pub const MAX_DEV_LEN: usize = 16;
/// A virtio-blk serial is at most 20 bytes.
pub const MAX_SERIAL_LEN: usize = 20;
/// The OS disk plus at most 8 dedicated disks per probe run.
pub const MAX_PROBE_TARGETS: usize = 9;
/// At most this many metrics per probe target.
pub const MAX_PROBE_METRICS: usize = 16;
pub const MAX_METRIC_KEY_LEN: usize = 32;
pub const MAX_PROFILE_LEN: usize = 8;
pub const MAX_KERNEL_LEN: usize = 64;
pub const MAX_PROBE_VM_ID_LEN: usize = 128;
/// The QD1 latency histogram: log2-µs buckets.
pub const HIST_BUCKETS: usize = 32;
/// Dedicated-disk slots are `x0`..`x23`.
pub const MAX_DEDICATED_SLOT: u8 = 23;

fn schema(msg: impl Into<String>) -> HippiusTypesError {
    HippiusTypesError::Cbor(msg.into())
}

/// What the guest found at a disk slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskIoState {
    /// A device the guest reads counters from.
    Ok,
    /// A dedicated slot whose LUKS header is not the one the guest
    /// recorded: the guest refused to open or format it.
    Mismatch,
    /// A dedicated slot named on the measured cmdline with no device.
    Missing,
    /// A dedicated integrity slot whose first-boot wipe is still running:
    /// not yet handed to the tenant. The only state that may carry
    /// `init_percent`.
    Initializing,
}

impl DiskIoState {
    pub fn as_str(self) -> &'static str {
        match self {
            DiskIoState::Ok => "ok",
            DiskIoState::Mismatch => "mismatch",
            DiskIoState::Missing => "missing",
            DiskIoState::Initializing => "initializing",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "ok" => Ok(DiskIoState::Ok),
            "mismatch" => Ok(DiskIoState::Mismatch),
            "missing" => Ok(DiskIoState::Missing),
            "initializing" => Ok(DiskIoState::Initializing),
            _ => Err(schema("disk_io: unknown state")),
        }
    }
}

/// One device's `/sys/block/<dev>/stat` deltas over the receipt window
/// (`inflight` is the instantaneous gauge at the window's end).
///
/// A `missing` slot has no device: `dev` is empty, `serial` names the slot
/// and every counter is zero. `init_percent` (0..=100) is set only on an
/// `initializing` slot, and is encoded only when set, so an entry without
/// it is byte-identical to before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskIoDelta {
    pub dev: String,
    pub serial: String,
    pub state: DiskIoState,
    pub r_ios: u64,
    pub r_sectors: u64,
    pub r_ticks_ms: u64,
    pub w_ios: u64,
    pub w_sectors: u64,
    pub w_ticks_ms: u64,
    pub io_ticks_ms: u64,
    pub tiq_ms: u64,
    pub inflight: u64,
    pub init_percent: Option<u8>,
}

/// The optional key of an `initializing` entry.
const INIT_PERCENT_KEY: &str = "init_percent";

const DISK_IO_KEYS: [&str; 12] = [
    "dev",
    "serial",
    "state",
    "r_ios",
    "r_sectors",
    "r_ticks_ms",
    "w_ios",
    "w_sectors",
    "w_ticks_ms",
    "io_ticks_ms",
    "tiq_ms",
    "inflight",
];

fn is_dev_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// The virtual serial vali gives a slot's disk: `hippius-<slot>`.
pub const SLOT_SERIAL_PREFIX: &str = "hippius-";

/// The slot a `hippius-<slot>` serial names, if it is one.
pub fn slot_of_serial(serial: &str) -> Option<&str> {
    serial
        .strip_prefix(SLOT_SERIAL_PREFIX)
        .filter(|slot| is_valid_slot(slot))
}

/// `true` for a dedicated slot's serial: `hippius-x0`..`hippius-x23`.
fn is_dedicated_slot_serial(serial: &str) -> bool {
    slot_of_serial(serial).is_some_and(|slot| slot != "os")
}

impl DiskIoDelta {
    fn counters(&self) -> [(&'static str, u64); 9] {
        [
            ("r_ios", self.r_ios),
            ("r_sectors", self.r_sectors),
            ("r_ticks_ms", self.r_ticks_ms),
            ("w_ios", self.w_ios),
            ("w_sectors", self.w_sectors),
            ("w_ticks_ms", self.w_ticks_ms),
            ("io_ticks_ms", self.io_ticks_ms),
            ("tiq_ms", self.tiq_ms),
            ("inflight", self.inflight),
        ]
    }

    fn validate(&self) -> Result<()> {
        // A serial is empty (a disk with no slot serial) or names a slot,
        // so vali can always map a device to exactly one slot.
        if !self.serial.is_empty()
            && (self.serial.len() > MAX_SERIAL_LEN || slot_of_serial(&self.serial).is_none())
        {
            return Err(schema("disk_io: bad serial"));
        }
        // `missing` / `mismatch` are dedicated-slot verdicts: they name one.
        if self.state != DiskIoState::Ok && !is_dedicated_slot_serial(&self.serial) {
            return Err(schema(
                "disk_io: a slot verdict needs a dedicated slot serial",
            ));
        }
        if self.init_percent.is_some_and(|p| p > 100) {
            return Err(schema("disk_io: init_percent above 100"));
        }
        if self.init_percent.is_some() && self.state != DiskIoState::Initializing {
            return Err(schema("disk_io: init_percent on a slot not initializing"));
        }
        if self.state == DiskIoState::Missing {
            if !self.dev.is_empty() {
                return Err(schema("disk_io: a missing slot has no dev"));
            }
            if self.counters().iter().any(|(_, v)| *v != 0) {
                return Err(schema("disk_io: a missing slot has no counters"));
            }
        } else if !charset(&self.dev, 1, MAX_DEV_LEN, is_dev_byte) {
            return Err(schema("disk_io: bad dev"));
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        let mut entries = vec![
            kv("dev", Value::Text(self.dev.clone())),
            kv("serial", Value::Text(self.serial.clone())),
            kv("state", Value::Text(self.state.as_str().into())),
        ];
        entries.extend(
            self.counters()
                .iter()
                .map(|(k, v)| kv(k, Value::Integer((*v).into()))),
        );
        if let Some(p) = self.init_percent {
            entries.push(kv(INIT_PERCENT_KEY, Value::Integer(p.into())));
        }
        Value::Map(entries)
    }

    fn from_value(v: &Value) -> Result<Self> {
        let has_percent = matches!(v, Value::Map(m)
            if m.iter().any(|(k, _)| matches!(k, Value::Text(n) if n == INIT_PERCENT_KEY)));
        let e = if has_percent {
            let mut keys = DISK_IO_KEYS.to_vec();
            keys.push(INIT_PERCENT_KEY);
            exact_map(v, &keys, "disk_io entry")
        } else {
            exact_map(v, &DISK_IO_KEYS, "disk_io entry")
        }
        .map_err(schema)?;
        let u = |k: &str| u64_at(e, k).map_err(schema);
        let out = DiskIoDelta {
            dev: text_at(e, "dev").map_err(schema)?,
            serial: text_at(e, "serial").map_err(schema)?,
            state: DiskIoState::parse(&text_at(e, "state").map_err(schema)?)?,
            r_ios: u("r_ios")?,
            r_sectors: u("r_sectors")?,
            r_ticks_ms: u("r_ticks_ms")?,
            w_ios: u("w_ios")?,
            w_sectors: u("w_sectors")?,
            w_ticks_ms: u("w_ticks_ms")?,
            io_ticks_ms: u("io_ticks_ms")?,
            tiq_ms: u("tiq_ms")?,
            inflight: u("inflight")?,
            init_percent: if has_percent {
                let p = u(INIT_PERCENT_KEY)?;
                Some(u8::try_from(p).map_err(|_| schema("disk_io: init_percent above 100"))?)
            } else {
                None
            },
        };
        out.validate()?;
        Ok(out)
    }
}

/// Validate a whole `disk_io` list: 1..=[`MAX_DISK_IO_DEVICES`] entries,
/// each well-formed, strictly increasing by `(dev, serial)` (so one list
/// has exactly one encoding), no device and no slot serial twice (only a
/// `missing` slot has no device, so several may share the empty `dev`).
/// An empty list is not a list: a receipt without devices omits the key.
pub fn validate_disk_io(list: &[DiskIoDelta]) -> Result<()> {
    if list.is_empty() || list.len() > MAX_DISK_IO_DEVICES {
        return Err(schema("disk_io: 1..=16 entries"));
    }
    for d in list {
        d.validate()?;
    }
    for pair in list.windows(2) {
        if (pair[0].dev.as_str(), pair[0].serial.as_str())
            >= (pair[1].dev.as_str(), pair[1].serial.as_str())
        {
            return Err(schema("disk_io: not strictly sorted by (dev, serial)"));
        }
    }
    for (i, d) in list.iter().enumerate() {
        let rest = &list[i + 1..];
        if !d.serial.is_empty() && rest.iter().any(|o| o.serial == d.serial) {
            return Err(schema("disk_io: a slot serial appears twice"));
        }
        if !d.dev.is_empty() && rest.iter().any(|o| o.dev == d.dev) {
            return Err(schema("disk_io: a device appears twice"));
        }
    }
    Ok(())
}

/// The canonical `disk_io` value. Fails on an invalid list.
pub fn disk_io_to_value(list: &[DiskIoDelta]) -> Result<Value> {
    validate_disk_io(list)?;
    Ok(Value::Array(
        list.iter().map(DiskIoDelta::to_value).collect(),
    ))
}

/// Decode and validate a `disk_io` value.
pub fn disk_io_from_value(v: &Value) -> Result<Vec<DiskIoDelta>> {
    let Value::Array(items) = v else {
        return Err(schema("disk_io: not an array"));
    };
    if items.len() > MAX_DISK_IO_DEVICES {
        return Err(schema("disk_io: 1..=16 entries"));
    }
    let list = items
        .iter()
        .map(DiskIoDelta::from_value)
        .collect::<Result<Vec<_>>>()?;
    validate_disk_io(&list)?;
    Ok(list)
}

/// `true` for `os` and `x0`..`x23`.
pub fn is_valid_slot(slot: &str) -> bool {
    if slot == "os" {
        return true;
    }
    let Some(n) = slot.strip_prefix('x') else {
        return false;
    };
    // No leading zero, so every slot has exactly one spelling.
    if n.is_empty() || (n.len() > 1 && n.starts_with('0')) || !n.bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    n.parse::<u8>().is_ok_and(|i| i <= MAX_DEDICATED_SLOT)
}

/// One disk a probe measured.
///
/// - `slot`     `os` (the OS disk, on a pool) or `x<N>` (a dedicated disk).
/// - `profile`  the benchmark profile it ran (`v1`, `d1`, …); vali grades
///   only profiles it knows.
/// - `metrics`  `(name, value)` pairs, strictly sorted by name. Integers in
///   the unit the name carries (`_mbps`, `_iops`, `_us`, …).
/// - `hist_qd1` the QD1 4 KiB read latency histogram, [`HIST_BUCKETS`]
///   log2-µs buckets.
/// - `error`    `""`, or a machine code for a target the probe could not
///   finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskProbeTarget {
    pub slot: String,
    pub profile: String,
    pub metrics: Vec<(String, u64)>,
    pub hist_qd1: Vec<u32>,
    pub error: String,
}

const TARGET_KEYS: [&str; 5] = ["error", "hist_qd1", "metrics", "profile", "slot"];

fn is_metric_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
}

fn is_profile_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

impl DiskProbeTarget {
    fn validate(&self) -> Result<()> {
        if !is_valid_slot(&self.slot) {
            return Err(schema("disk_probe: bad slot"));
        }
        if !charset(&self.profile, 1, MAX_PROFILE_LEN, is_profile_byte) {
            return Err(schema("disk_probe: bad profile"));
        }
        if self.metrics.len() > MAX_PROBE_METRICS {
            return Err(schema("disk_probe: too many metrics"));
        }
        for (name, _) in &self.metrics {
            if !charset(name, 1, MAX_METRIC_KEY_LEN, is_metric_byte) {
                return Err(schema("disk_probe: bad metric name"));
            }
        }
        for pair in self.metrics.windows(2) {
            if pair[0].0 >= pair[1].0 {
                return Err(schema("disk_probe: metrics not strictly sorted"));
            }
        }
        if self.hist_qd1.len() != HIST_BUCKETS {
            return Err(schema("disk_probe: hist_qd1 needs 32 buckets"));
        }
        if !is_valid_error_code(&self.error) {
            return Err(schema("disk_probe: bad error code"));
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            kv("error", Value::Text(self.error.clone())),
            kv(
                "hist_qd1",
                Value::Array(
                    self.hist_qd1
                        .iter()
                        .map(|b| Value::Integer((*b).into()))
                        .collect(),
                ),
            ),
            kv(
                "metrics",
                Value::Map(
                    self.metrics
                        .iter()
                        .map(|(k, v)| kv(k, Value::Integer((*v).into())))
                        .collect(),
                ),
            ),
            kv("profile", Value::Text(self.profile.clone())),
            kv("slot", Value::Text(self.slot.clone())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self> {
        let e = exact_map(v, &TARGET_KEYS, "disk_probe target").map_err(schema)?;
        let metrics = match crate::map_decode::get(e, "metrics").map_err(schema)? {
            Value::Map(m) if m.len() <= MAX_PROBE_METRICS => {
                let mut out = Vec::with_capacity(m.len());
                for (k, val) in m {
                    let (Value::Text(name), Value::Integer(i)) = (k, val) else {
                        return Err(schema("disk_probe: metric is not text -> integer"));
                    };
                    let value = u64::try_from(*i).map_err(|_| schema("disk_probe: metric < 0"))?;
                    out.push((name.clone(), value));
                }
                // The canonical encoder orders keys by encoded bytes
                // (length first); the list order is by name.
                out.sort();
                out
            }
            _ => return Err(schema("disk_probe: metrics is not a bounded map")),
        };
        let hist_qd1 = array_at(e, "hist_qd1")
            .map_err(schema)?
            .iter()
            .map(|b| match b {
                Value::Integer(i) => u32::try_from(*i).map_err(|_| schema("hist_qd1: not a u32")),
                _ => Err(schema("hist_qd1: not an integer")),
            })
            .collect::<Result<Vec<_>>>()?;
        let out = DiskProbeTarget {
            slot: text_at(e, "slot").map_err(schema)?,
            profile: text_at(e, "profile").map_err(schema)?,
            metrics,
            hist_qd1,
            error: text_at(e, "error").map_err(schema)?,
        };
        out.validate()?;
        Ok(out)
    }
}

/// A probe VM's benchmark result (design §3.2, §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskProbeResult {
    /// vali's `DiskProbeRun.run_id`.
    pub run_id: [u8; 16],
    /// vali's per-run nonce; it also seeds the probe's offsets.
    pub nonce: [u8; 32],
    /// The probe VM; equal to the receipt's `vm_id`.
    pub vm_id: String,
    pub vcpus: u32,
    /// `uname -r` of the probe guest, printable ASCII.
    pub kernel: String,
    /// The guest component release the probe binary came from.
    pub release_version: u32,
    pub started_at: u64,
    pub finished_at: u64,
    /// One entry per disk, strictly sorted by slot name, 1..=9.
    pub targets: Vec<DiskProbeTarget>,
}

const PROBE_KEYS: [&str; 9] = [
    "finished_at",
    "kernel",
    "nonce",
    "release_version",
    "run_id",
    "started_at",
    "targets",
    "vcpus",
    "vm_id",
];

impl DiskProbeResult {
    pub fn validate(&self) -> Result<()> {
        if self.vm_id.is_empty()
            || self.vm_id.len() > MAX_PROBE_VM_ID_LEN
            || !self.vm_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(schema("disk_probe: bad vm_id"));
        }
        if !charset(&self.kernel, 0, MAX_KERNEL_LEN, |b| {
            (0x20..=0x7e).contains(&b)
        }) {
            return Err(schema("disk_probe: bad kernel"));
        }
        if self.finished_at < self.started_at {
            return Err(schema("disk_probe: finished_at < started_at"));
        }
        if self.targets.is_empty() || self.targets.len() > MAX_PROBE_TARGETS {
            return Err(schema("disk_probe: 1..=9 targets"));
        }
        for t in &self.targets {
            t.validate()?;
        }
        for pair in self.targets.windows(2) {
            if pair[0].slot >= pair[1].slot {
                return Err(schema("disk_probe: targets not strictly sorted by slot"));
            }
        }
        Ok(())
    }

    /// The canonical `disk_probe` value. Fails on an invalid result.
    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        Ok(Value::Map(vec![
            kv("finished_at", Value::Integer(self.finished_at.into())),
            kv("kernel", Value::Text(self.kernel.clone())),
            kv("nonce", Value::Bytes(self.nonce.to_vec())),
            kv(
                "release_version",
                Value::Integer(self.release_version.into()),
            ),
            kv("run_id", Value::Bytes(self.run_id.to_vec())),
            kv("started_at", Value::Integer(self.started_at.into())),
            kv(
                "targets",
                Value::Array(self.targets.iter().map(DiskProbeTarget::to_value).collect()),
            ),
            kv("vcpus", Value::Integer(self.vcpus.into())),
            kv("vm_id", Value::Text(self.vm_id.clone())),
        ]))
    }

    /// Decode and validate a `disk_probe` value.
    pub fn from_value(v: &Value) -> Result<Self> {
        let e = exact_map(v, &PROBE_KEYS, "disk_probe").map_err(schema)?;
        let run_id: [u8; 16] = bytes_at(e, "run_id")
            .map_err(schema)?
            .try_into()
            .map_err(|_| schema("disk_probe: run_id is not 16 bytes"))?;
        let nonce: [u8; 32] = bytes_at(e, "nonce")
            .map_err(schema)?
            .try_into()
            .map_err(|_| schema("disk_probe: nonce is not 32 bytes"))?;
        let targets = array_at(e, "targets").map_err(schema)?;
        if targets.len() > MAX_PROBE_TARGETS {
            return Err(schema("disk_probe: 1..=9 targets"));
        }
        let out = DiskProbeResult {
            run_id,
            nonce,
            vm_id: text_at(e, "vm_id").map_err(schema)?,
            vcpus: u32_at(e, "vcpus").map_err(schema)?,
            kernel: text_at(e, "kernel").map_err(schema)?,
            release_version: u32_at(e, "release_version").map_err(schema)?,
            started_at: u64_at(e, "started_at").map_err(schema)?,
            finished_at: u64_at(e, "finished_at").map_err(schema)?,
            targets: targets
                .iter()
                .map(DiskProbeTarget::from_value)
                .collect::<Result<Vec<_>>>()?,
        };
        out.validate()?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::to_canonical_vec;

    pub(crate) fn io(dev: &str, serial: &str) -> DiskIoDelta {
        DiskIoDelta {
            dev: dev.into(),
            serial: serial.into(),
            state: DiskIoState::Ok,
            r_ios: 10,
            r_sectors: 800,
            r_ticks_ms: 4,
            w_ios: 5,
            w_sectors: 400,
            w_ticks_ms: 9,
            io_ticks_ms: 12,
            tiq_ms: 13,
            inflight: 1,
            init_percent: None,
        }
    }

    fn target(slot: &str) -> DiskProbeTarget {
        DiskProbeTarget {
            slot: slot.into(),
            profile: "v1".into(),
            metrics: vec![("qd1_p50_us".into(), 90), ("seq_read_mbps".into(), 2000)],
            hist_qd1: vec![0; HIST_BUCKETS],
            error: String::new(),
        }
    }

    fn probe() -> DiskProbeResult {
        DiskProbeResult {
            run_id: [1; 16],
            nonce: [2; 32],
            vm_id: "hipc-1-abcd".into(),
            vcpus: 2,
            kernel: "6.8.0-110-generic".into(),
            release_version: 5,
            started_at: 100,
            finished_at: 400,
            targets: vec![target("os"), target("x0")],
        }
    }

    fn round_trip_io(list: &[DiskIoDelta]) -> Vec<DiskIoDelta> {
        let bytes = to_canonical_vec(&disk_io_to_value(list).unwrap()).unwrap();
        let v: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        disk_io_from_value(&v).unwrap()
    }

    #[test]
    fn disk_io_round_trips() {
        let list = vec![io("vda", ""), io("vdb", "hippius-x0")];
        assert_eq!(round_trip_io(&list), list);
    }

    #[test]
    fn a_missing_slot_round_trips() {
        let mut missing = io("", "hippius-x1");
        missing.state = DiskIoState::Missing;
        for c in [
            &mut missing.r_ios,
            &mut missing.r_sectors,
            &mut missing.r_ticks_ms,
            &mut missing.w_ios,
            &mut missing.w_sectors,
            &mut missing.w_ticks_ms,
            &mut missing.io_ticks_ms,
            &mut missing.tiq_ms,
            &mut missing.inflight,
        ] {
            *c = 0;
        }
        let list = vec![missing, io("vda", "")];
        assert_eq!(round_trip_io(&list), list);
    }

    #[test]
    fn disk_io_bounds_are_enforced() {
        assert!(validate_disk_io(&[]).is_err());
        let seventeen: Vec<_> = (0..17).map(|i| io(&format!("vd{i:02}"), "")).collect();
        assert!(validate_disk_io(&seventeen).is_err());
        assert!(validate_disk_io(&seventeen[..16]).is_ok());
        // One device, one entry.
        assert!(validate_disk_io(&[io("vda", ""), io("vda", "hippius-x0")]).is_err());
        // Unsorted / duplicate.
        assert!(validate_disk_io(&[io("vdb", ""), io("vda", "")]).is_err());
        assert!(validate_disk_io(&[io("vda", ""), io("vda", "")]).is_err());
        // Charsets.
        assert!(validate_disk_io(&[io("VDA", "")]).is_err());
        assert!(validate_disk_io(&[io("", "")]).is_err());
        assert!(validate_disk_io(&[io(&"v".repeat(17), "")]).is_err());
        assert!(validate_disk_io(&[io("vda", "a b")]).is_err());
        assert!(validate_disk_io(&[io("vda", &"s".repeat(21))]).is_err());
        // A serial names a slot or nothing.
        assert!(validate_disk_io(&[io("vda", "not-a-slot")]).is_err());
        assert!(validate_disk_io(&[io("vda", "hippius-x24")]).is_err());
        assert!(validate_disk_io(&[io("vda", "hippius-os")]).is_ok());
        // One slot serial, one device.
        assert!(validate_disk_io(&[io("vdb", "hippius-x0"), io("vdc", "hippius-x0")]).is_err());
        assert!(validate_disk_io(&[io("vda", ""), io("vdb", "")]).is_ok());
    }

    #[test]
    fn a_slot_verdict_names_a_dedicated_slot() {
        for serial in ["", "hippius-os", "not-a-slot"] {
            let mut m = io("vdc", serial);
            m.state = DiskIoState::Mismatch;
            assert!(validate_disk_io(&[m]).is_err(), "{serial:?}");
        }
        let mut m = io("vdc", "hippius-x3");
        m.state = DiskIoState::Mismatch;
        assert!(validate_disk_io(&[m]).is_ok());
    }

    #[test]
    fn a_missing_slot_carries_nothing_else() {
        let mut m = io("", "hippius-x1");
        m.state = DiskIoState::Missing;
        assert!(
            validate_disk_io(&[m.clone()]).is_err(),
            "counters must be zero"
        );
        let mut with_dev = io("vdc", "hippius-x1");
        with_dev.state = DiskIoState::Missing;
        assert!(validate_disk_io(&[with_dev]).is_err());
    }

    #[test]
    fn an_initializing_slot_round_trips_with_and_without_its_percent() {
        let mut init = io("vdb", "hippius-x0");
        init.state = DiskIoState::Initializing;
        assert_eq!(round_trip_io(&[init.clone()]), vec![init.clone()]);
        for p in [0u8, 42, 100] {
            init.init_percent = Some(p);
            assert_eq!(round_trip_io(&[init.clone()]), vec![init.clone()]);
        }
        // An entry without the key encodes exactly as before.
        let plain = io("vdb", "hippius-x0");
        let Value::Map(m) = plain.to_value() else {
            panic!()
        };
        assert_eq!(m.len(), DISK_IO_KEYS.len());
    }

    #[test]
    fn init_percent_belongs_to_an_initializing_dedicated_slot_only() {
        let mut over = io("vdb", "hippius-x0");
        over.state = DiskIoState::Initializing;
        over.init_percent = Some(101);
        assert!(validate_disk_io(&[over]).is_err());
        for state in [DiskIoState::Ok, DiskIoState::Mismatch] {
            let mut m = io("vdb", "hippius-x0");
            m.state = state;
            m.init_percent = Some(5);
            assert!(validate_disk_io(&[m]).is_err(), "{state:?}");
        }
        // `initializing` is a dedicated-slot verdict, on a device.
        for serial in ["", "hippius-os"] {
            let mut m = io("vdb", serial);
            m.state = DiskIoState::Initializing;
            assert!(validate_disk_io(&[m]).is_err(), "{serial:?}");
        }
        let mut no_dev = io("", "hippius-x0");
        no_dev.state = DiskIoState::Initializing;
        assert!(validate_disk_io(&[no_dev]).is_err());
        // Decoding: a percent above 100, or on another state, is refused.
        let mut init = io("vdb", "hippius-x0");
        init.state = DiskIoState::Initializing;
        let Value::Map(mut m) = init.to_value() else {
            panic!()
        };
        m.push(kv(INIT_PERCENT_KEY, Value::Integer(300.into())));
        assert!(disk_io_from_value(&Value::Array(vec![Value::Map(m)])).is_err());
        let Value::Map(mut m) = io("vdb", "hippius-x0").to_value() else {
            panic!()
        };
        m.push(kv(INIT_PERCENT_KEY, Value::Integer(3.into())));
        assert!(disk_io_from_value(&Value::Array(vec![Value::Map(m)])).is_err());
    }

    #[test]
    fn disk_io_decode_rejects_extra_or_missing_keys() {
        let Value::Map(mut entries) = io("vda", "").to_value() else {
            panic!()
        };
        entries.push(kv("extra", Value::Integer(1.into())));
        assert!(disk_io_from_value(&Value::Array(vec![Value::Map(entries.clone())])).is_err());
        entries.pop();
        entries.pop();
        assert!(disk_io_from_value(&Value::Array(vec![Value::Map(entries)])).is_err());
    }

    #[test]
    fn slots() {
        for ok in ["os", "x0", "x9", "x10", "x23"] {
            assert!(is_valid_slot(ok), "{ok}");
        }
        for bad in ["", "x", "x24", "x00", "x01", "y0", "OS", "x-1", "x1a"] {
            assert!(!is_valid_slot(bad), "{bad}");
        }
    }

    #[test]
    fn disk_probe_round_trips() {
        let p = probe();
        let bytes = to_canonical_vec(&p.to_value().unwrap()).unwrap();
        let v: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(DiskProbeResult::from_value(&v).unwrap(), p);
    }

    #[test]
    fn disk_probe_bounds_are_enforced() {
        let mut p = probe();
        p.targets.clear();
        assert!(p.validate().is_err());
        let mut p = probe();
        p.targets = (0..10)
            .map(|i| target(if i == 0 { "os" } else { "x1" }))
            .collect();
        assert!(p.validate().is_err());
        let mut p = probe();
        p.targets.reverse();
        assert!(p.validate().is_err(), "targets sorted by slot");
        let mut p = probe();
        p.finished_at = 1;
        assert!(p.validate().is_err());
        let mut p = probe();
        p.kernel = "k".repeat(65);
        assert!(p.validate().is_err());
        let mut p = probe();
        p.vm_id = String::new();
        assert!(p.validate().is_err());
        let mut p = probe();
        p.targets[0].hist_qd1.pop();
        assert!(p.validate().is_err());
        let mut p = probe();
        p.targets[0].metrics.reverse();
        assert!(p.validate().is_err(), "metrics sorted by name");
        let mut p = probe();
        p.targets[0].metrics = (0..17).map(|i| (format!("m{i:02}"), 1)).collect();
        assert!(p.validate().is_err());
        let mut p = probe();
        p.targets[0].metrics[0].0 = "Bad-Name".into();
        assert!(p.validate().is_err());
        let mut p = probe();
        p.targets[0].slot = "x24".into();
        assert!(p.validate().is_err());
        let mut p = probe();
        p.targets[0].profile = "V1".into();
        assert!(p.validate().is_err());
        let mut p = probe();
        p.targets[0].error = "Not A Code".into();
        assert!(p.validate().is_err());
    }

    #[test]
    fn disk_probe_decode_rejects_wrong_lengths() {
        let Value::Map(mut entries) = probe().to_value().unwrap() else {
            panic!()
        };
        for (k, v) in entries.iter_mut() {
            if matches!(k, Value::Text(n) if n == "nonce") {
                *v = Value::Bytes(vec![0; 31]);
            }
        }
        assert!(DiskProbeResult::from_value(&Value::Map(entries)).is_err());
    }
}
