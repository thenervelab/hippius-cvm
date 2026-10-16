//! The storage a miner reports in a `v7` heartbeat
//! (docs/design/disk-tier-verification.md §4.1, §4.2, §9): its storage
//! pools (where OS disks live), its dedicated physical disks, and the
//! storage-config revision it has applied.
//!
//! All of it is an UNTRUSTED self-report. vali uses the pool sizes only as
//! down-only clamps and never takes a tier from a declared class; a pool
//! or disk is placeable only once vali has probed it.
//!
//! The `Serialize` impls exist for the verifier's JSON echo only. The wire
//! encoding is [`StorageReport::to_entries`], inside the heartbeat's
//! canonical map; never serde-encode these types into a signed body.

#[allow(unused_imports)]
// per-module slice of the alloc prelude — not every module needs every item
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use ciborium::value::Value;
use serde::Serialize;

use crate::map_decode::{
    array_at, bool_at, charset, exact_map, is_slug_byte, is_valid_error_code, kv, text_at, u32_at,
    u64_at,
};

/// At most this many pools per miner.
pub const MAX_DISK_POOLS: usize = 4;
pub const MAX_POOL_ID_LEN: usize = 32;
/// At most this many dedicated disks per miner.
pub const MAX_DEDICATED_DISKS: usize = 24;
/// A `/dev/disk/by-id/` basename.
pub const MAX_DEDICATED_DISK_ID_LEN: usize = 96;
pub const MAX_ASSIGNED_VM_ID_LEN: usize = 128;

/// Why a storage report is malformed. A closed vocabulary of
/// `&'static str`, like the rest of the heartbeat format.
pub type ReportResult<T> = core::result::Result<T, &'static str>;

macro_rules! wire_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $variant:ident => $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
        pub enum $name {
            $($(#[$vm])* #[serde(rename = $s)] $variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $($name::$variant => $s),+ }
            }

            pub fn parse(s: &str) -> Option<Self> {
                match s { $($s => Some($name::$variant),)+ _ => None }
            }
        }
    };
}

wire_enum! {
    /// What the miner SAYS a pool is — a hint, never a tier.
    PoolClass {
        /// No class declared (the implicit `default` pool).
        Undeclared => "",
        Nvme => "nvme",
        Ssd => "ssd",
        Hdd => "hdd",
    }
}

wire_enum! {
    /// A pool's state on the host.
    PoolState {
        Active => "active",
        /// Takes no new disks; removed once empty.
        Draining => "draining",
        /// Its mount vanished or changed: launches to it are refused.
        Unavailable => "unavailable",
    }
}

wire_enum! {
    /// A dedicated disk's state on the host.
    DedicatedDiskState {
        Free => "free",
        Assigned => "assigned",
        /// The device vanished or the kernel marked it offline.
        Failed => "failed",
        Draining => "draining",
        /// The by-id name now points at another physical device.
        Replaced => "replaced",
        Unavailable => "unavailable",
    }
}

/// One storage pool, as the miner reports it. Sizes in GiB (rounded
/// down); `total_gb == 0` = unknown, which leaves `available_gb`
/// unconstrained (the `v4` convention).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskPoolReport {
    pub id: String,
    pub class: PoolClass,
    pub total_gb: u32,
    pub available_gb: u32,
    pub budget_gb: u32,
    /// The disk the agent has reserved on this pool for its VMs.
    pub committed_gb: u32,
    pub os_disks: bool,
    pub state: PoolState,
    /// `""`, or the machine code of the pool's last validation refusal.
    pub error: String,
}

const POOL_KEYS: [&str; 9] = [
    "available_gb",
    "budget_gb",
    "class",
    "committed_gb",
    "error",
    "id",
    "os_disks",
    "state",
    "total_gb",
];

/// `true` for a pool id: `[a-z0-9-]{1,32}`.
pub fn is_valid_pool_id(id: &str) -> bool {
    charset(id, 1, MAX_POOL_ID_LEN, is_slug_byte)
}

impl DiskPoolReport {
    fn validate(&self) -> ReportResult<()> {
        if !is_valid_pool_id(&self.id) {
            return Err("pool-id");
        }
        if self.total_gb != 0 && self.available_gb > self.total_gb {
            return Err("pool-available-above-total");
        }
        if !is_valid_error_code(&self.error) {
            return Err("pool-error-code");
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            kv("available_gb", Value::Integer(self.available_gb.into())),
            kv("budget_gb", Value::Integer(self.budget_gb.into())),
            kv("class", Value::Text(self.class.as_str().into())),
            kv("committed_gb", Value::Integer(self.committed_gb.into())),
            kv("error", Value::Text(self.error.clone())),
            kv("id", Value::Text(self.id.clone())),
            kv("os_disks", Value::Bool(self.os_disks)),
            kv("state", Value::Text(self.state.as_str().into())),
            kv("total_gb", Value::Integer(self.total_gb.into())),
        ])
    }

    fn from_value(v: &Value) -> ReportResult<Self> {
        let e = exact_map(v, &POOL_KEYS, "pool").map_err(|_| "pool-shape")?;
        let bad = |_| "pool-shape";
        let out = DiskPoolReport {
            id: text_at(e, "id").map_err(bad)?,
            class: PoolClass::parse(&text_at(e, "class").map_err(bad)?).ok_or("pool-class")?,
            total_gb: u32_at(e, "total_gb").map_err(bad)?,
            available_gb: u32_at(e, "available_gb").map_err(bad)?,
            budget_gb: u32_at(e, "budget_gb").map_err(bad)?,
            committed_gb: u32_at(e, "committed_gb").map_err(bad)?,
            os_disks: bool_at(e, "os_disks").map_err(bad)?,
            state: PoolState::parse(&text_at(e, "state").map_err(bad)?).ok_or("pool-state")?,
            error: text_at(e, "error").map_err(bad)?,
        };
        out.validate()?;
        Ok(out)
    }
}

/// One dedicated physical disk, as the miner reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DedicatedDiskReport {
    /// The `/dev/disk/by-id/` basename (`wwn-0x…`, `ata-…`, …).
    pub id: String,
    /// The kernel's size of the whole disk, MiB.
    pub size_mb: u64,
    pub state: DedicatedDiskState,
    /// The VM holding it — non-empty exactly when `assigned`. For
    /// reconciliation only: vali is authoritative for assignment.
    pub vm: String,
    /// `""`, or the machine code of the disk's last validation refusal.
    pub error: String,
}

const DEDICATED_KEYS: [&str; 5] = ["error", "id", "size_mb", "state", "vm"];

fn is_by_id_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':')
}

fn is_vm_id_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

/// The `/dev/disk/by-id/` families a dedicated disk may be declared by:
/// stable hardware ids only (`wwn-` preferred), never a path-based or
/// transport-specific name.
pub const DEDICATED_DISK_ID_PREFIXES: [&str; 4] = ["wwn-", "ata-", "scsi-", "nvme-"];

/// `true` for a dedicated disk id: a by-id basename of 1..=96 bytes of
/// `[A-Za-z0-9._:-]` in one of [`DEDICATED_DISK_ID_PREFIXES`] with
/// something after the prefix, never a partition (`-partN`).
pub fn is_valid_dedicated_disk_id(id: &str) -> bool {
    charset(id, 1, MAX_DEDICATED_DISK_ID_LEN, is_by_id_byte)
        && DEDICATED_DISK_ID_PREFIXES
            .iter()
            .any(|p| id.len() > p.len() && id.starts_with(p))
        && !id
            .rsplit_once("-part")
            .is_some_and(|(_, n)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

impl DedicatedDiskReport {
    fn validate(&self) -> ReportResult<()> {
        if !is_valid_dedicated_disk_id(&self.id) {
            return Err("dedicated-disk-id");
        }
        let assigned = self.state == DedicatedDiskState::Assigned;
        if assigned == self.vm.is_empty() {
            return Err("dedicated-disk-vm");
        }
        if !charset(&self.vm, 0, MAX_ASSIGNED_VM_ID_LEN, is_vm_id_byte) {
            return Err("dedicated-disk-vm");
        }
        if !is_valid_error_code(&self.error) {
            return Err("dedicated-disk-error-code");
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            kv("error", Value::Text(self.error.clone())),
            kv("id", Value::Text(self.id.clone())),
            kv("size_mb", Value::Integer(self.size_mb.into())),
            kv("state", Value::Text(self.state.as_str().into())),
            kv("vm", Value::Text(self.vm.clone())),
        ])
    }

    fn from_value(v: &Value) -> ReportResult<Self> {
        let e =
            exact_map(v, &DEDICATED_KEYS, "dedicated disk").map_err(|_| "dedicated-disk-shape")?;
        let bad = |_| "dedicated-disk-shape";
        let out = DedicatedDiskReport {
            id: text_at(e, "id").map_err(bad)?,
            size_mb: u64_at(e, "size_mb").map_err(bad)?,
            state: DedicatedDiskState::parse(&text_at(e, "state").map_err(bad)?)
                .ok_or("dedicated-disk-state")?,
            vm: text_at(e, "vm").map_err(bad)?,
            error: text_at(e, "error").map_err(bad)?,
        };
        out.validate()?;
        Ok(out)
    }
}

/// The `v7` storage report: pools, dedicated disks, and the
/// storage-config revision the agent has applied (`0` = none).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StorageReport {
    /// 1..=[`MAX_DISK_POOLS`], strictly sorted by id.
    pub disk_pools: Vec<DiskPoolReport>,
    /// 0..=[`MAX_DEDICATED_DISKS`], strictly sorted by id.
    pub dedicated_disks: Vec<DedicatedDiskReport>,
    pub storage_config_revision: u64,
}

impl StorageReport {
    /// Every invariant of a well-formed `v7` report.
    pub fn validate(&self) -> ReportResult<()> {
        if self.disk_pools.is_empty() || self.disk_pools.len() > MAX_DISK_POOLS {
            return Err("pool-count");
        }
        for p in &self.disk_pools {
            p.validate()?;
        }
        if self.disk_pools.windows(2).any(|w| w[0].id >= w[1].id) {
            return Err("pool-order");
        }
        if self.dedicated_disks.len() > MAX_DEDICATED_DISKS {
            return Err("dedicated-disk-count");
        }
        for d in &self.dedicated_disks {
            d.validate()?;
        }
        if self.dedicated_disks.windows(2).any(|w| w[0].id >= w[1].id) {
            return Err("dedicated-disk-order");
        }
        Ok(())
    }

    /// The three `v7` heartbeat map entries.
    pub fn to_entries(&self) -> ReportResult<[(Value, Value); 3]> {
        self.validate()?;
        Ok([
            kv(
                "dedicated_disks",
                Value::Array(
                    self.dedicated_disks
                        .iter()
                        .map(DedicatedDiskReport::to_value)
                        .collect(),
                ),
            ),
            kv(
                "disk_pools",
                Value::Array(
                    self.disk_pools
                        .iter()
                        .map(DiskPoolReport::to_value)
                        .collect(),
                ),
            ),
            kv(
                "storage_config_revision",
                Value::Integer(self.storage_config_revision.into()),
            ),
        ])
    }

    /// Decode and validate the report from a `v7` heartbeat body's map
    /// entries (the three keys must be present; the caller has already
    /// checked the body's key count).
    pub fn from_entries(entries: &[(Value, Value)]) -> ReportResult<Self> {
        let pools = array_at(entries, "disk_pools").map_err(|_| "pool-shape")?;
        if pools.len() > MAX_DISK_POOLS {
            return Err("pool-count");
        }
        let disks = array_at(entries, "dedicated_disks").map_err(|_| "dedicated-disk-shape")?;
        if disks.len() > MAX_DEDICATED_DISKS {
            return Err("dedicated-disk-count");
        }
        let out = StorageReport {
            disk_pools: pools
                .iter()
                .map(DiskPoolReport::from_value)
                .collect::<ReportResult<Vec<_>>>()?,
            dedicated_disks: disks
                .iter()
                .map(DedicatedDiskReport::from_value)
                .collect::<ReportResult<Vec<_>>>()?,
            storage_config_revision: u64_at(entries, "storage_config_revision")
                .map_err(|_| "storage-config-revision")?,
        };
        out.validate()?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::to_canonical_vec;

    fn pool(id: &str) -> DiskPoolReport {
        DiskPoolReport {
            id: id.into(),
            class: PoolClass::Nvme,
            total_gb: 3500,
            available_gb: 2900,
            budget_gb: 3000,
            committed_gb: 400,
            os_disks: true,
            state: PoolState::Active,
            error: String::new(),
        }
    }

    fn disk(id: &str) -> DedicatedDiskReport {
        DedicatedDiskReport {
            id: id.into(),
            size_mb: 17_166_336,
            state: DedicatedDiskState::Free,
            vm: String::new(),
            error: String::new(),
        }
    }

    fn report() -> StorageReport {
        let mut assigned = disk("wwn-0x5000c500a1b2c3d5");
        assigned.state = DedicatedDiskState::Assigned;
        assigned.vm = "hipc-1-abcd".into();
        StorageReport {
            disk_pools: vec![pool("default"), pool("hdd0")],
            dedicated_disks: vec![disk("ata-ST18000NM_ZR5ABC"), assigned],
            storage_config_revision: 3,
        }
    }

    fn round_trip(r: &StorageReport) -> StorageReport {
        let bytes = to_canonical_vec(&Value::Map(r.to_entries().unwrap().to_vec())).unwrap();
        let v: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let Value::Map(entries) = v else { panic!() };
        StorageReport::from_entries(&entries).unwrap()
    }

    #[test]
    fn round_trips() {
        let r = report();
        assert_eq!(round_trip(&r), r);
        let mut no_disks = report();
        no_disks.dedicated_disks.clear();
        assert_eq!(round_trip(&no_disks), no_disks);
    }

    #[test]
    fn pool_bounds() {
        let mut r = report();
        r.disk_pools.clear();
        assert_eq!(r.validate(), Err("pool-count"));
        r.disk_pools = ["a", "b", "c", "d", "e"].iter().map(|i| pool(i)).collect();
        assert_eq!(r.validate(), Err("pool-count"));
        r.disk_pools.pop();
        assert!(r.validate().is_ok());
        r.disk_pools.swap(0, 1);
        assert_eq!(r.validate(), Err("pool-order"));
        r.disk_pools = vec![pool("a"), pool("a")];
        assert_eq!(r.validate(), Err("pool-order"));
    }

    #[test]
    fn pool_fields() {
        for bad in ["", "Default", "a_b", &"p".repeat(33)] {
            let mut r = report();
            r.disk_pools = vec![pool(bad)];
            assert_eq!(r.validate(), Err("pool-id"), "{bad:?}");
        }
        let mut r = report();
        r.disk_pools[0].available_gb = 3501;
        assert_eq!(r.validate(), Err("pool-available-above-total"));
        r.disk_pools[0].total_gb = 0; // unknown total: unconstrained
        assert!(r.validate().is_ok());
        r.disk_pools[0].error = "Pool Not A Mount".into();
        assert_eq!(r.validate(), Err("pool-error-code"));
        r.disk_pools[0].error = "pool-not-a-mount".into();
        assert!(r.validate().is_ok());
    }

    #[test]
    fn dedicated_bounds_and_fields() {
        let mut r = report();
        r.dedicated_disks = (0..25).map(|i| disk(&format!("wwn-0x{i:02}"))).collect();
        assert_eq!(r.validate(), Err("dedicated-disk-count"));
        r.dedicated_disks.pop();
        assert!(r.validate().is_ok());
        r.dedicated_disks.swap(0, 1);
        assert_eq!(r.validate(), Err("dedicated-disk-order"));

        for bad in [
            "",
            "wwn-0x1-part1",
            "sda/1",
            "a b",
            "sda",
            "..",
            "wwn-",
            "usb-Generic_Flash-0:0",
            "dm-name-vg0-data",
            &format!("wwn-{}", "d".repeat(93)),
        ] {
            let mut r = report();
            r.dedicated_disks = vec![disk(bad)];
            assert_eq!(r.validate(), Err("dedicated-disk-id"), "{bad:?}");
        }
        assert!(is_valid_dedicated_disk_id("nvme-eui.0025388b91c0a1b2"));
        assert!(is_valid_dedicated_disk_id("scsi-35000c500a1b2c3d4"));
        assert!(is_valid_dedicated_disk_id("ata-ST18000NM000J_ZR5ABCDE"));
        assert!(is_valid_dedicated_disk_id("wwn-0x5000c500a1b2c3d4-partx"));
        assert!(is_valid_dedicated_disk_id(&format!(
            "wwn-{}",
            "d".repeat(92)
        )));

        // vm ⇔ assigned.
        let mut r = report();
        r.dedicated_disks[0].vm = "vm-a".into();
        assert_eq!(r.validate(), Err("dedicated-disk-vm"));
        let mut r = report();
        r.dedicated_disks[1].vm = String::new();
        assert_eq!(r.validate(), Err("dedicated-disk-vm"));
        let mut r = report();
        r.dedicated_disks[1].vm = "vm a".into();
        assert_eq!(r.validate(), Err("dedicated-disk-vm"));
    }

    #[test]
    fn decode_rejects_unknown_enum_values_and_keys() {
        let Value::Map(mut entries) = Value::Map(report().to_entries().unwrap().to_vec()) else {
            panic!()
        };
        // Swap the first pool's state for an unknown one.
        for (k, v) in entries.iter_mut() {
            if matches!(k, Value::Text(n) if n == "disk_pools") {
                let Value::Array(pools) = v else { panic!() };
                let Value::Map(p) = &mut pools[0] else {
                    panic!()
                };
                for (pk, pv) in p.iter_mut() {
                    if matches!(pk, Value::Text(n) if n == "state") {
                        *pv = Value::Text("broken".into());
                    }
                }
                p.push(kv("extra", Value::Bool(true)));
            }
        }
        assert!(StorageReport::from_entries(&entries).is_err());
    }
}
