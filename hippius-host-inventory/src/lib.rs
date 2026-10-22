//! `hippius-host-inventory` — the miner **host inventory** — a read-only, owner-facing picture of the
//! machine (system, CPU, memory, storage + disk health, network, PCI,
//! sensors, software) the miner-agent reports in its own signed envelope
//! (disk-tier design §18.10, "the Hardware tab").
//!
//! Its own crate, not a `hippius-types` module: the guest UKIs link
//! `hippius-types`, so every change there moves their measured initrd
//! (the UKI KATs). Nothing in a guest needs this report.
//!
//! ## Trust
//!
//! Everything here is an UNTRUSTED self-report. vali shows it to the node's
//! owner and nothing else: it never sets a tier, never places, cordons,
//! pays, strikes or bills from it. What vali knows from attestation (the
//! SNP generation, the platform TCB) comes from its attested sources, never
//! from this report.
//!
//! ## Transport
//!
//! A separate low-frequency envelope, not a heartbeat block (the
//! `hippius_types::graceful_exit` precedent): the heartbeat is the
//! liveness-critical channel, and a full inventory is 15–40 KB against its
//! 16 KiB cap. The agent signs a [`HostInventory`] body with the SAME
//! Ed25519 identity key as its heartbeats; vali verifies the
//! [`SignedHostInventory`] envelope against the registered miner key,
//! enforces a monotonic `sequence` and a `±300 s` skew window.
//!
//! Every section is optional: a `full` report carries all of them, a
//! `change` report the ones whose content changed, a `counters` report the
//! sections holding fast-moving counters (`memory` for EDAC, `storage` for
//! the disk advisories, `sensors`, `software` for the uptime) — WHOLE
//! sections, since a section is replaced as a whole. A section absent from
//! a report is UNCHANGED, never removed; a `change` / `counters` report
//! carries at least one.
//!
//! `sequence` is per miner, independent of the heartbeat's, strictly
//! increasing across agent restarts (the agent persists it, as the
//! heartbeat's): vali accepts only a higher one.
//!
//! ## Privacy (§18.10.3)
//!
//! Serials (system, DIMM, disk by-id names) are carried for the owner
//! only. No MAC address, no IP address (an interface reports its role),
//! no hostname, no BMC credentials, no raw log line (a disk advisory's
//! `sample` is rebuilt from a fixed template by the collector; vali still
//! treats it as untrusted text), no VM name. Loopback and virtual
//! interfaces are not listed (counted). Kernel names, pool ids and
//! controller subjects are charset-checked, so no free-form dm name (which
//! can embed a VM id) passes.
//!
//! ## Encoding
//!
//! Canonical CBOR (RFC 8949 §4.2.1) of the serde form, every struct
//! `deny_unknown_fields`, every enum closed, every list and string
//! bounded ([`HostInventory::validate`]), every keyed list sorted and
//! distinct by its key, no floats. ALWAYS decode through
//! [`HostInventory::decode`] / [`SignedHostInventory::decode`], never a
//! bare serde decode: they re-encode and compare, which is what makes the
//! encoding unique (ciborium's serde decoder alone accepts other forms).
//!
//! The whole body is at most [`MAX_BODY_BYTES`]. The item caps alone do
//! not bound it (a host with many disks and long by-id names), so the
//! encoder trims the storage inventory to fit
//! ([`HostInventory::canonical_fitted`]): VM-owned virtual and dm devices
//! first, then partitions that are no pool, then the rest, flagging
//! `devices_truncated`. [`HostInventory::normalize`] puts a collected
//! body in its one valid order.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

extern crate alloc;

#[allow(unused_imports)]
// per-module slice of the alloc prelude — not every module needs every item
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use ciborium::value::Value;
use serde::{Deserialize, Serialize};

use hippius_types::cbor::{assert_canonical, to_canonical_vec};

/// Replay-domain separator, distinct from every other signed domain.
pub const DOMAIN: &str = "HIPPIUS_MINER_HOST_INVENTORY_V1";

/// Wire-format version. An unknown value fails closed.
pub const SCHEMA_VERSION: u8 = 1;

/// Length of an Ed25519 signature — the `sig` field of the envelope.
pub const SIGNATURE_LEN: usize = 64;

/// The whole `{body, sig}` envelope is at most this many bytes: vali's
/// request-body cap (`DATA_UPLOAD_MAX_MEMORY_SIZE`, 64 KiB), so a report
/// that encodes is never refused by the transport.
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// The canonical body is at most this many bytes (enforced at encode, by
/// vali, and by the Edge): the envelope cap less the signature and the
/// envelope's own CBOR framing (two keys, two byte-string heads).
pub const MAX_BODY_BYTES: usize = MAX_ENVELOPE_BYTES - 128;

pub const MAX_MINER_ID_LEN: usize = 64;
/// A free-text field the host reports (a model, a vendor, a version).
pub const MAX_TEXT_LEN: usize = 128;
/// A serial number (owner-only).
pub const MAX_SERIAL_LEN: usize = 64;
/// A device / interface / sensor name (`nvme0n1`, `eno1`, `Tctl`).
pub const MAX_NAME_LEN: usize = 32;
/// A mount path.
pub const MAX_PATH_LEN: usize = 128;
/// A `/dev/disk/by-id/` basename.
pub const MAX_DISK_ID_LEN: usize = 96;
/// A rebuilt advisory sample.
pub const MAX_SAMPLE_LEN: usize = 120;

pub const MAX_DIMMS: usize = 64;
pub const MAX_DEVICES: usize = 192;
pub const MAX_DEVICE_IDS: usize = 8;
pub const MAX_DEVICE_LINKS: usize = 16;
pub const MAX_DEVICE_MOUNTS: usize = 8;
/// Every pool a miner may declare (`hippius_types::storage_report`).
pub const MAX_POOLS_PER_DEVICE: usize = hippius_types::storage_report::MAX_DISK_POOLS;
pub const MAX_REASONS: usize = 16;
pub const MAX_ADVISORIES: usize = 64;
pub const MAX_NICS: usize = 32;
pub const MAX_PCI_DEVICES: usize = 64;
pub const MAX_SENSORS: usize = 64;
pub const MAX_CPU_FLAGS: usize = 16;

/// Why a host inventory is malformed — a closed vocabulary of
/// `&'static str` (the verifier echoes it as its `error_class` detail).
pub type InventoryResult<T> = core::result::Result<T, &'static str>;

// ─── envelope ────────────────────────────────────────────────────────

/// The `{body, sig}` envelope the agent posts. `body` is the canonical
/// [`HostInventory`] bytes; `sig` the Ed25519 signature over them by the
/// miner's identity key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedHostInventory {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl SignedHostInventory {
    /// The canonical `{body, sig}` bytes.
    pub fn canonical(&self) -> InventoryResult<Vec<u8>> {
        if self.sig.len() != SIGNATURE_LEN {
            return Err("host-inventory-signature-length");
        }
        if self.body.len() > MAX_BODY_BYTES {
            return Err("host-inventory-too-large");
        }
        let v = Value::Map(alloc::vec![
            (Value::Text("body".into()), Value::Bytes(self.body.clone())),
            (Value::Text("sig".into()), Value::Bytes(self.sig.clone())),
        ]);
        to_canonical_vec(&v).map_err(|_| "host-inventory-encode")
    }

    /// Decode an envelope: canonical, typed, and re-encoded byte for byte.
    pub fn decode(bytes: &[u8]) -> InventoryResult<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err("host-inventory-too-large");
        }
        assert_canonical(bytes).map_err(|_| "host-inventory-not-canonical")?;
        let env: Self =
            ciborium::de::from_reader(bytes).map_err(|_| "host-inventory-envelope-decode")?;
        if env.canonical()? != bytes {
            return Err("host-inventory-not-canonical");
        }
        Ok(env)
    }
}

// ─── body ────────────────────────────────────────────────────────────

/// Why the agent sent this report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    /// Agent start, then every 24 h: every section.
    Full,
    /// A section's content changed: the changed sections only.
    Change,
    /// Every 6 h: the fast-moving counters (EDAC, sensors, advisories,
    /// uptime).
    Counters,
}

/// The body the agent signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInventory {
    /// MUST be [`SCHEMA_VERSION`].
    pub schema_version: u8,
    /// MUST be [`DOMAIN`].
    pub domain: String,
    /// The `vali` registry key of the miner.
    pub miner_id: String,
    /// The miner's wall clock at build time, Unix seconds.
    pub timestamp_unix: i64,
    /// Per-miner monotonic counter (replay defence).
    pub sequence: u64,
    pub report: ReportKind,
    pub sections: Sections,
}

/// The report's sections; an absent one is unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sections {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemorySection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci: Option<PciSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensors: Option<SensorsSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software: Option<SoftwareSection>,
}

/// How the collector fared on a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionStatus {
    Ok,
    /// Some sources answered, some did not.
    Partial,
    /// The collector's bound expired: the section carries what it read.
    Timeout,
    /// Nothing to read (no IPMI, no EDAC driver, …).
    Unavailable,
}

// ─── system ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSection {
    pub status: SectionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// Owner-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board_vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board_product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bios_vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bios_version: Option<String>,
    /// As the firmware reports it (`MM/DD/YYYY` or ISO); display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bios_date: Option<String>,
    pub bmc_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipmi_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bmc_firmware: Option<String>,
}

// ─── cpu ─────────────────────────────────────────────────────────────

/// `/sys/devices/system/cpu/smt/control`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtControl {
    On,
    Off,
    Forceoff,
    Notsupported,
    Notimplemented,
}

/// The CPU flags worth showing (an allowlist; everything else is dropped).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuFlag {
    Sev,
    SevEs,
    SevSnp,
    Avx2,
    Avx512f,
    Aes,
    Sha,
    Vaes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuSection {
    pub status: SectionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub family: u32,
    pub model_id: u32,
    pub stepping: u32,
    pub sockets: u32,
    pub cores: u32,
    pub threads: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smt_control: Option<SmtControl>,
    pub smt_active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_mhz: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_mhz: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub microcode: Option<String>,
    /// `kvm_amd` module parameters: SEV / SEV-ES / SEV-SNP enabled.
    pub sev: bool,
    pub sev_es: bool,
    pub sev_snp: bool,
    /// Sorted, distinct.
    pub flags: Vec<CpuFlag>,
}

// ─── memory ──────────────────────────────────────────────────────────

/// A DIMM's error correction (SMBIOS type 16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EccType {
    None,
    Parity,
    SingleBit,
    MultiBit,
    Crc,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dimm {
    /// SMBIOS `Bank Locator` (`P0 CHANNEL A`): many boards repeat
    /// `locator` across banks, so a DIMM is keyed by the pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bank_locator: Option<String>,
    pub locator: String,
    pub size_mib: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed_mts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured_mts: Option<u32>,
    pub ecc: EccType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part: Option<String>,
    /// Owner-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
}

/// EDAC corrected / uncorrected counts of one DIMM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DimmErrors {
    /// The EDAC `dimm_label` — host-unique (`mc#0csrow#0channel#0`, a
    /// GHES bank/device label), the key of `per_dimm`.
    pub locator: String,
    pub ce: u64,
    pub ue: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edac {
    pub ce_total: u64,
    pub ue_total: u64,
    pub per_dimm: Vec<DimmErrors>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySection {
    pub status: SectionStatus,
    pub total_mib: u64,
    pub dimms: Vec<Dimm>,
    /// `None`: no EDAC driver loaded (nothing to report, not zero).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edac: Option<Edac>,
}

// ─── storage ─────────────────────────────────────────────────────────

/// What a block device is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Disk,
    Partition,
    Md,
    Dm,
    /// loop / zram / nbd / rbd.
    Virtual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Nvme,
    Sata,
    Sas,
    Scsi,
    Usb,
    Virtio,
    Md,
    Dm,
    Unknown,
}

/// What a device is, or could become (§18.9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRole {
    /// Holds `/`, `/boot`, swap, or a stack that does. Never offerable.
    System,
    /// Backs a declared pool (`pool_ids`).
    PoolBacking,
    /// Backs the state root / staging.
    StateRoot,
    DedicatedAssigned,
    DedicatedFree,
    /// A component of an md / LVM / dm-crypt stack.
    Member,
    /// An unused whole disk: offerable as a dedicated disk.
    EligibleDedicated,
    /// A mounted filesystem that is no pool yet: declarable as one.
    EligiblePool,
    /// Unused, but needs local preparation (a signature, partitions).
    NeedsPrep,
    Ineligible,
}

/// Why a device is not (yet) offerable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IneligibleReason {
    HasPartitions,
    HasSignature,
    Mounted,
    Swap,
    HolderBusy,
    TooSmall,
    Removable,
    Usb,
    Virtual,
    BehindControllerRaidMode,
    ReadOnly,
    System,
    DuplicateIdentity,
    NoStableId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdInfo {
    /// `raid0`, `raid1`, … as the kernel names it.
    pub level: String,
    /// `md/array_state` (`clean`, `active`, …).
    pub state: String,
    pub degraded: u32,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsInfo {
    /// The filesystem type udev recorded (`ext4`, `xfs`, …).
    pub fs_type: String,
    pub uuid_present: bool,
    /// statvfs of its mount (no device I/O); none when not mounted. What
    /// a pool on it could take is vali's to derive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available_bytes: Option<u64>,
}

/// One block device, from sysfs and the udev database only (no I/O to
/// the device).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// The kernel name (`nvme0n1`, `sdb`, `md127`, `dm-3`).
    pub name: String,
    pub kind: DeviceKind,
    pub size_bytes: u64,
    /// Its stable `/dev/disk/by-id/` names. Owner-only.
    pub ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub transport: Transport,
    /// `queue/rotational` — a hint the host can lie about (RAID hides it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotational_hint: Option<bool>,
    pub removable: bool,
    pub read_only: bool,
    /// The RAID controller the device sits behind, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behind_controller: Option<String>,
    pub partitions: Vec<String>,
    pub holders: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub md: Option<MdInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs: Option<FsInfo>,
    pub mounts: Vec<String>,
    pub role: DeviceRole,
    /// The pools whose directory sits on this device's filesystem (a pool
    /// is a directory: several can share one). Sorted, distinct.
    pub pool_ids: Vec<String>,
    /// Sorted, distinct.
    pub reasons: Vec<IneligibleReason>,
}

/// What a disk advisory is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisorySubject {
    Pool,
    DedicatedDisk,
    /// A controller virtual disk (`ctrl:<model>:<vd>`).
    Controller,
    Md,
    /// A device by kernel name.
    Device,
    /// The collector itself.
    Collector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// A disk health signal (§18.3), a closed list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryCode {
    SmartOverallFailed,
    ReallocatedSectors,
    PendingSectors,
    OfflineUncorrectable,
    UdmaCrcErrors,
    TemperatureHigh,
    PowerOnHours,
    NvmeCriticalWarning,
    NvmeMediaErrors,
    NvmeSpareLow,
    NvmeWearHigh,
    SmartUnavailableBehindController,
    SmartUnavailable,
    KernelIoError,
    KernelTimeoutReset,
    KernelMediumError,
    FsError,
    FsRemountedRo,
    MdDegraded,
    MdRebuilding,
    BtrfsDeviceErrors,
    MountMissing,
    MountRo,
    CollectorMissingTools,
    CollectorTimeout,
    CollectorStale,
    CollectorPartial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    pub subject_kind: AdvisorySubject,
    /// The pool id, the disk by-id name, `ctrl:<model>:<vd>`, the md or
    /// device kernel name; `""` for the collector.
    pub subject: String,
    pub code: AdvisoryCode,
    pub severity: Severity,
    /// Kernel-log codes: occurrences since `first_seen` within the
    /// collector's 24 h retention window. Device counters: the current
    /// value.
    pub count: u64,
    /// A metric value where meaningful (sectors, %, °C), else 0.
    pub value: i64,
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
    /// Rebuilt from a fixed template by the collector — never a raw log
    /// line. Printable ASCII, at most [`MAX_SAMPLE_LEN`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSection {
    pub status: SectionStatus,
    pub devices: Vec<Device>,
    pub advisories: Vec<Advisory>,
    /// More advisories than [`MAX_ADVISORIES`]: the most severe kept.
    pub advisories_truncated: bool,
    /// The device list was trimmed to fit the body cap
    /// ([`HostInventory::canonical_fitted`]).
    pub devices_truncated: bool,
}

// ─── network ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Duplex {
    Full,
    Half,
    Unknown,
}

/// What an interface is used for — reported instead of its addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NicRole {
    /// Has a global unicast address.
    Public,
    /// In 100.64.0.0/10.
    Netbird,
    Private,
    /// No address.
    Unused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nic {
    pub name: String,
    /// The PCI address (`0000:41:00.0`); none for a virtual one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware: Option<String>,
    pub state: LinkState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed_mbps: Option<u32>,
    pub duplex: Duplex,
    pub mtu: u32,
    pub role: NicRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetbirdInterface {
    pub state: LinkState,
    pub mtu: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSection {
    pub status: SectionStatus,
    /// Physical interfaces.
    pub nics: Vec<Nic>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netbird: Option<NetbirdInterface>,
    /// Bridges, taps, `virbr*`: counted, never named.
    pub virtual_interfaces: u32,
}

// ─── pci ─────────────────────────────────────────────────────────────

/// The PCI classes worth showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PciKind {
    /// Class 0x03.
    Gpu,
    /// Class 0x12.
    Accelerator,
    /// Class 0x0104.
    RaidController,
    /// Class 0x0107.
    SasHba,
    /// Class 0x0108.
    NvmeController,
    /// Class 0x02.
    Nic,
}

/// A storage controller's mode, as far as the host can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerMode {
    Raid,
    Hba,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PciDevice {
    /// `0000:01:00.0`.
    pub address: String,
    pub kind: PciKind,
    pub vendor_id: u16,
    pub device_id: u16,
    /// From `pci.ids`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numa_node: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iommu_group: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_width: Option<u32>,
    /// `current_link_speed` as sysfs prints it (`16.0 GT/s PCIe`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_speed: Option<String>,
    /// Storage controllers only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ControllerMode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PciSection {
    pub status: SectionStatus,
    pub devices: Vec<PciDevice>,
}

// ─── sensors ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Temperature {
    /// Where the reading comes from ([`is_sensor_chip`]): the hwmon
    /// `name` and its index (`k10temp.0`, `nvme.3`) or `ipmi`. Every NVMe
    /// reports a `Composite`, every socket a `Tctl`, so a reading is keyed
    /// by `(chip, label)`.
    pub chip: String,
    /// An allowlisted label (`Tctl`, `Package id 0`, `Composite`, …).
    pub label: String,
    pub millicelsius: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fan {
    /// As [`Temperature::chip`].
    pub chip: String,
    pub label: String,
    pub rpm: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PsuState {
    Ok,
    Failed,
    Absent,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Psu {
    pub label: String,
    pub state: PsuState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensorsSection {
    pub status: SectionStatus,
    pub temperatures: Vec<Temperature>,
    pub fans: Vec<Fan>,
    pub psus: Vec<Psu>,
}

// ─── software ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareSection {
    pub status: SectionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    /// `/etc/os-release` `NAME` and `VERSION_ID` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qemu_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub libvirt_version: Option<String>,
    pub uptime_s: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_boot_unix: Option<i64>,
    /// The agent auto-updater's state, as the host's files show it.
    /// Absent: not collected (the collector runs without
    /// `--report-auto-update`, or could not read the files). An older
    /// decoder refuses the key (`deny_unknown_fields`), so vali accepts it
    /// before any agent sends it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_update: Option<AutoUpdateStatus>,
}

/// Why auto-update is off on a host, in the order the checks run: the
/// first that applies is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoUpdateDisabledReason {
    /// `/var/lib/hippius-miner/.no-auto-update` exists.
    NoAutoUpdateFile,
    /// `AUTO_UPDATE_DISABLED=true` in `/etc/hippius-miner/auto-update.env`
    /// (ansible `miner_auto_update_enabled: false`).
    DisabledInEnv,
    /// `hippius-miner-update.timer` is not enabled (never installed, or
    /// disabled): no run ever fires.
    TimerDisabled,
}

/// The miner-agent auto-updater (`hippius-miner-update`), read from its
/// files — never by running it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoUpdateStatus {
    /// No opt-out in force and the timer is enabled.
    pub enabled: bool,
    /// Present exactly when `enabled` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<AutoUpdateDisabledReason>,
    /// When a timer run last read the release list (unix seconds). Absent
    /// when no run has recorded one yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_check_unix: Option<i64>,
    /// The newest release that failed its health check on this host
    /// (`.update-failed-<tag>`) and is newer than the agent reporting:
    /// the updater never retries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_tag: Option<String>,
}

/// The latest instant a reported time may name: 9999-12-31T23:59:59Z,
/// the last second every consumer's calendar type holds.
pub const MAX_UNIX_TIME: i64 = 253_402_300_799;

/// `true` for a miner-agent release tag exactly as the updater accepts
/// it: `vYYYY.MM.DD` or `vYYYY.MM.DD.N`, N = 1..999 without a leading
/// zero.
pub fn is_release_tag(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix('v') else {
        return false;
    };
    let mut parts = rest.split('.');
    let digits = |p: Option<&str>, n: usize| {
        p.is_some_and(|p| p.len() == n && p.bytes().all(|b| b.is_ascii_digit()))
    };
    if !(digits(parts.next(), 4) && digits(parts.next(), 2) && digits(parts.next(), 2)) {
        return false;
    }
    match (parts.next(), parts.next()) {
        (None, _) => true,
        (Some(n), None) => {
            (1..=3).contains(&n.len())
                && n.bytes().all(|b| b.is_ascii_digit())
                && !n.starts_with('0')
        }
        _ => false,
    }
}

// ─── validation ──────────────────────────────────────────────────────

fn printable(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn text(s: &str, max: usize, err: &'static str) -> InventoryResult<()> {
    if printable(s, max) {
        Ok(())
    } else {
        Err(err)
    }
}

fn opt_text(s: &Option<String>, max: usize, err: &'static str) -> InventoryResult<()> {
    match s {
        Some(s) => text(s, max, err),
        None => Ok(()),
    }
}

/// A kernel block device name of a known family — `sd[a-z]{1,4}[N]`,
/// `vd…`, `xvd…`, `nvme<N>n<N>[p<N>]`, `nvme<N>c<N>n<N>` (a multipath
/// path), `md<N>[p<N>]`, `dm-<N>`, `loop<N>[p<N>]`, `nbd<N>[p<N>]`,
/// `rbd<N>[p<N>]`, `mmcblk<N>[p<N>]`, `zd<N>[p<N>]` (a ZFS zvol),
/// `zram<N>`, `sr<N>`, `bcache<N>`, `drbd<N>`, `pmem<N>` — never a
/// device-mapper NAME (which can embed a VM id). The collector drops a
/// device of any other family (and a link to one).
pub fn is_kernel_name(s: &str) -> bool {
    fn digits(s: &str) -> Option<&str> {
        let end = s
            .bytes()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(s.len());
        (end > 0).then(|| &s[end..])
    }
    fn letters(s: &str) -> Option<&str> {
        let end = s
            .bytes()
            .position(|b| !b.is_ascii_lowercase())
            .unwrap_or(s.len());
        (end > 0).then(|| &s[end..])
    }
    /// `<N>` then optionally `p<N>`, and nothing else.
    fn number_part(s: &str) -> bool {
        match digits(s) {
            Some("") => true,
            Some(rest) => rest
                .strip_prefix('p')
                .and_then(digits)
                .is_some_and(str::is_empty),
            None => false,
        }
    }
    if s.is_empty() || s.len() > MAX_NAME_LEN {
        return false;
    }
    for disk in ["xvd", "sd", "vd"] {
        if let Some(rest) = s.strip_prefix(disk) {
            let tail = letters(rest);
            return rest.len() - tail.map_or(rest.len(), str::len) <= 4
                && tail.is_some_and(|r| r.is_empty() || digits(r) == Some(""));
        }
    }
    if let Some(rest) = s.strip_prefix("nvme") {
        let Some(rest) = digits(rest) else {
            return false;
        };
        if let Some(path) = rest.strip_prefix('c') {
            return digits(path)
                .and_then(|r| r.strip_prefix('n'))
                .and_then(digits)
                == Some("");
        }
        return rest.strip_prefix('n').is_some_and(number_part);
    }
    if let Some(rest) = s.strip_prefix("dm-") {
        return digits(rest) == Some("");
    }
    for family in ["mmcblk", "loop", "nbd", "rbd", "md", "zd"] {
        if let Some(rest) = s.strip_prefix(family) {
            return number_part(rest);
        }
    }
    for family in ["zram", "sr", "bcache", "drbd", "pmem"] {
        if let Some(rest) = s.strip_prefix(family) {
            return digits(rest) == Some("");
        }
    }
    false
}

/// The `/dev/disk/by-id/` families of a physical device. The `dm-name-`,
/// `dm-uuid-`, `md-name-`, `lvm-pv-uuid-` links are refused: they carry
/// the free-form names [`is_kernel_name`] keeps out.
const DISK_ID_PREFIXES: [&str; 8] = [
    "wwn-",
    "nvme-",
    "ata-",
    "scsi-",
    "usb-",
    "virtio-",
    "mmc-",
    "ieee1394-",
];

/// A by-id name of a physical device ([`DISK_ID_PREFIXES`]), printable,
/// at most [`MAX_DISK_ID_LEN`].
pub fn is_disk_id(s: &str) -> bool {
    DISK_ID_PREFIXES.iter().any(|p| s.starts_with(p)) && printable(s, MAX_DISK_ID_LEN)
}

/// A sensor source: `ipmi`, or a hwmon `name` (`[a-z0-9_]`) then `.` and
/// its index — at most [`MAX_NAME_LEN`].
pub fn is_sensor_chip(s: &str) -> bool {
    if s == "ipmi" {
        return true;
    }
    let Some((name, index)) = s.rsplit_once('.') else {
        return false;
    };
    s.len() <= MAX_NAME_LEN
        && !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !index.is_empty()
        && index.bytes().all(|b| b.is_ascii_digit())
}

/// A PCI address: `DDDD:BB:DD.F` (hex).
pub fn is_pci_address(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 12
        && b[4] == b':'
        && b[7] == b':'
        && b[10] == b'.'
        && b.iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 4 | 7 | 10) || c.is_ascii_hexdigit())
}

fn kernel_names(list: &[String], err: &'static str) -> InventoryResult<()> {
    if list.len() > MAX_DEVICE_LINKS || !list.iter().all(|n| is_kernel_name(n)) {
        return Err(err);
    }
    Ok(())
}

fn sorted_distinct_by<T, K: Ord>(list: &[T], key: impl Fn(&T) -> K) -> bool {
    list.windows(2).all(|w| key(&w[0]) < key(&w[1]))
}

fn sorted_distinct<T: Ord>(list: &[T]) -> bool {
    list.windows(2).all(|w| w[0] < w[1])
}

// ─── list keys ───────────────────────────────────────────────────────
//
// What every keyed list is sorted and distinct by. The enum parts sort by
// DECLARATION ORDER (`as u8`): reordering a variant changes which bodies
// are valid, so variants are only ever appended.

impl Dimm {
    pub fn key(&self) -> (Option<String>, String) {
        (self.bank_locator.clone(), self.locator.clone())
    }
}

impl Advisory {
    pub fn key(&self) -> (u8, String, u8) {
        (
            self.subject_kind as u8,
            self.subject.clone(),
            self.code as u8,
        )
    }
}

impl Temperature {
    pub fn key(&self) -> (String, String) {
        (self.chip.clone(), self.label.clone())
    }
}

impl Fan {
    pub fn key(&self) -> (String, String) {
        (self.chip.clone(), self.label.clone())
    }
}

impl Device {
    /// Trimming order to fit a cap, lowest first: VM-owned virtual and dm
    /// devices, partitions that are no pool, the rest, then what backs or
    /// could become a pool or a dedicated disk.
    fn trim_rank(&self) -> u8 {
        let offerable = matches!(
            self.role,
            DeviceRole::PoolBacking
                | DeviceRole::StateRoot
                | DeviceRole::EligiblePool
                | DeviceRole::DedicatedAssigned
                | DeviceRole::DedicatedFree
                | DeviceRole::EligibleDedicated
        );
        match self.kind {
            DeviceKind::Virtual => 0,
            DeviceKind::Dm => 1,
            DeviceKind::Partition if !offerable => 2,
            _ if !offerable => 3,
            _ => 4,
        }
    }
}

impl StorageSection {
    /// Drop the device to trim first ([`Device::trim_rank`], the last by
    /// name among equals). `false` once the list is empty.
    fn trim_one(&mut self) -> bool {
        let victim = self
            .devices
            .iter()
            .enumerate()
            .rev()
            .min_by_key(|(_, d)| d.trim_rank())
            .map(|(i, _)| i);
        let Some(i) = victim else {
            return false;
        };
        self.devices.remove(i);
        self.devices_truncated = true;
        true
    }
}

/// Cut `list` to `max`; whether anything was cut.
fn cap<T>(list: &mut Vec<T>, max: usize) -> bool {
    let cut = list.len() > max;
    list.truncate(max);
    cut
}

fn sort_dedup_by<T, K: Ord>(list: &mut Vec<T>, key: impl Fn(&T) -> K) {
    list.sort_by_key(|t| key(t));
    list.dedup_by(|a, b| key(a) == key(b));
}

impl SystemSection {
    fn validate(&self) -> InventoryResult<()> {
        for (s, max) in [
            (&self.vendor, MAX_TEXT_LEN),
            (&self.product, MAX_TEXT_LEN),
            (&self.serial, MAX_SERIAL_LEN),
            (&self.board_vendor, MAX_TEXT_LEN),
            (&self.board_product, MAX_TEXT_LEN),
            (&self.bios_vendor, MAX_TEXT_LEN),
            (&self.bios_version, MAX_TEXT_LEN),
            (&self.bios_date, MAX_TEXT_LEN),
            (&self.ipmi_version, MAX_TEXT_LEN),
            (&self.bmc_firmware, MAX_TEXT_LEN),
        ] {
            opt_text(s, max, "host-inventory-system-text")?;
        }
        Ok(())
    }
}

impl CpuSection {
    fn validate(&self) -> InventoryResult<()> {
        opt_text(&self.model, MAX_TEXT_LEN, "host-inventory-cpu-text")?;
        opt_text(&self.microcode, MAX_NAME_LEN, "host-inventory-cpu-text")?;
        if self.flags.len() > MAX_CPU_FLAGS || !sorted_distinct(&self.flags) {
            return Err("host-inventory-cpu-flags");
        }
        Ok(())
    }
}

impl MemorySection {
    fn validate(&self) -> InventoryResult<()> {
        if self.dimms.len() > MAX_DIMMS || !sorted_distinct_by(&self.dimms, Dimm::key) {
            return Err("host-inventory-dimms");
        }
        for d in &self.dimms {
            opt_text(&d.bank_locator, MAX_NAME_LEN, "host-inventory-dimm")?;
            text(&d.locator, MAX_NAME_LEN, "host-inventory-dimm")?;
            opt_text(&d.mem_type, MAX_NAME_LEN, "host-inventory-dimm")?;
            opt_text(&d.manufacturer, MAX_TEXT_LEN, "host-inventory-dimm")?;
            opt_text(&d.part, MAX_TEXT_LEN, "host-inventory-dimm")?;
            opt_text(&d.serial, MAX_SERIAL_LEN, "host-inventory-dimm")?;
        }
        if let Some(edac) = &self.edac {
            if edac.per_dimm.len() > MAX_DIMMS
                || !sorted_distinct_by(&edac.per_dimm, |d| d.locator.clone())
            {
                return Err("host-inventory-edac");
            }
            for d in &edac.per_dimm {
                text(&d.locator, MAX_NAME_LEN, "host-inventory-edac")?;
            }
        }
        Ok(())
    }
}

impl Device {
    fn validate(&self) -> InventoryResult<()> {
        const E: &str = "host-inventory-device";
        if !is_kernel_name(&self.name) {
            return Err(E);
        }
        if self.ids.len() > MAX_DEVICE_IDS {
            return Err(E);
        }
        if !self.ids.iter().all(|id| is_disk_id(id)) {
            return Err(E);
        }
        opt_text(&self.model, MAX_TEXT_LEN, E)?;
        opt_text(&self.behind_controller, MAX_TEXT_LEN, E)?;
        kernel_names(&self.partitions, E)?;
        kernel_names(&self.holders, E)?;
        if let Some(md) = &self.md {
            text(&md.level, MAX_NAME_LEN, E)?;
            text(&md.state, MAX_NAME_LEN, E)?;
            kernel_names(&md.members, E)?;
        }
        if let Some(fs) = &self.fs {
            text(&fs.fs_type, MAX_NAME_LEN, E)?;
        }
        if self.mounts.len() > MAX_DEVICE_MOUNTS {
            return Err(E);
        }
        for m in &self.mounts {
            if !m.starts_with('/') {
                return Err(E);
            }
            text(m, MAX_PATH_LEN, E)?;
        }
        if self.pool_ids.len() > MAX_POOLS_PER_DEVICE
            || !sorted_distinct(&self.pool_ids)
            || !self
                .pool_ids
                .iter()
                .all(|p| hippius_types::storage_report::is_valid_pool_id(p))
        {
            return Err(E);
        }
        if self.reasons.len() > MAX_REASONS || !sorted_distinct(&self.reasons) {
            return Err(E);
        }
        Ok(())
    }
}

impl Advisory {
    fn validate(&self) -> InventoryResult<()> {
        const E: &str = "host-inventory-advisory";
        let subject_ok = match self.subject_kind {
            AdvisorySubject::Collector => self.subject.is_empty(),
            AdvisorySubject::Pool => hippius_types::storage_report::is_valid_pool_id(&self.subject),
            AdvisorySubject::Device | AdvisorySubject::Md => is_kernel_name(&self.subject),
            AdvisorySubject::DedicatedDisk => is_disk_id(&self.subject),
            // `ctrl:<model>:<vd>`.
            AdvisorySubject::Controller => {
                self.subject.starts_with("ctrl:") && printable(&self.subject, MAX_DISK_ID_LEN)
            }
        };
        if !subject_ok {
            return Err(E);
        }
        if self.last_seen_unix < self.first_seen_unix {
            return Err(E);
        }
        opt_text(&self.sample, MAX_SAMPLE_LEN, E)
    }
}

impl StorageSection {
    fn validate(&self) -> InventoryResult<()> {
        if self.devices.len() > MAX_DEVICES
            || !sorted_distinct_by(&self.devices, |d| d.name.clone())
        {
            return Err("host-inventory-devices");
        }
        self.devices.iter().try_for_each(Device::validate)?;
        if self.advisories.len() > MAX_ADVISORIES
            || !sorted_distinct_by(&self.advisories, Advisory::key)
        {
            return Err("host-inventory-advisories");
        }
        self.advisories.iter().try_for_each(Advisory::validate)
    }
}

impl NetworkSection {
    fn validate(&self) -> InventoryResult<()> {
        const E: &str = "host-inventory-nic";
        if self.nics.len() > MAX_NICS || !sorted_distinct_by(&self.nics, |n| n.name.clone()) {
            return Err(E);
        }
        for n in &self.nics {
            text(&n.name, MAX_NAME_LEN, E)?;
            if n.pci.as_deref().is_some_and(|p| !is_pci_address(p)) {
                return Err(E);
            }
            opt_text(&n.model, MAX_TEXT_LEN, E)?;
            opt_text(&n.driver, MAX_NAME_LEN, E)?;
            opt_text(&n.firmware, MAX_TEXT_LEN, E)?;
        }
        Ok(())
    }
}

impl PciSection {
    fn validate(&self) -> InventoryResult<()> {
        const E: &str = "host-inventory-pci";
        if self.devices.len() > MAX_PCI_DEVICES
            || !sorted_distinct_by(&self.devices, |d| d.address.clone())
        {
            return Err(E);
        }
        for d in &self.devices {
            if !is_pci_address(&d.address) {
                return Err(E);
            }
            opt_text(&d.name, MAX_TEXT_LEN, E)?;
            opt_text(&d.driver, MAX_NAME_LEN, E)?;
            opt_text(&d.link_speed, MAX_NAME_LEN, E)?;
            let storage = matches!(d.kind, PciKind::RaidController | PciKind::SasHba);
            if d.mode.is_some() && !storage {
                return Err(E);
            }
        }
        Ok(())
    }
}

impl SensorsSection {
    fn validate(&self) -> InventoryResult<()> {
        const E: &str = "host-inventory-sensor";
        if self.temperatures.len() > MAX_SENSORS
            || self.fans.len() > MAX_SENSORS
            || self.psus.len() > MAX_SENSORS
            || !sorted_distinct_by(&self.temperatures, Temperature::key)
            || !sorted_distinct_by(&self.fans, Fan::key)
            || !sorted_distinct_by(&self.psus, |p| p.label.clone())
        {
            return Err(E);
        }
        let reading = |chip: &str, label: &str| {
            if !is_sensor_chip(chip) {
                return Err(E);
            }
            text(label, MAX_NAME_LEN, E)
        };
        self.temperatures
            .iter()
            .try_for_each(|t| reading(&t.chip, &t.label))?;
        self.fans
            .iter()
            .try_for_each(|f| reading(&f.chip, &f.label))?;
        self.psus
            .iter()
            .try_for_each(|p| text(&p.label, MAX_NAME_LEN, E))
    }
}

impl SoftwareSection {
    fn validate(&self) -> InventoryResult<()> {
        const E: &str = "host-inventory-software";
        for s in [
            &self.kernel,
            &self.os_name,
            &self.os_version_id,
            &self.agent_version,
            &self.qemu_version,
            &self.libvirt_version,
        ] {
            opt_text(s, MAX_TEXT_LEN, E)?;
        }
        if let Some(a) = &self.auto_update {
            const A: &str = "host-inventory-auto-update";
            if a.enabled == a.disabled_reason.is_some() {
                return Err(A);
            }
            if a.last_check_unix
                .is_some_and(|t| !(0..=MAX_UNIX_TIME).contains(&t))
            {
                return Err(A);
            }
            if a.failed_tag.as_deref().is_some_and(|t| !is_release_tag(t)) {
                return Err(A);
            }
        }
        Ok(())
    }
}

impl HostInventory {
    /// Every invariant of a well-formed body. Run by [`Self::canonical`]
    /// (nothing impossible is ever signed) and [`Self::decode`].
    pub fn validate(&self) -> InventoryResult<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err("host-inventory-schema-version");
        }
        if self.domain != DOMAIN {
            return Err("host-inventory-domain");
        }
        if self.miner_id.is_empty() || self.miner_id.len() > MAX_MINER_ID_LEN {
            return Err("host-inventory-miner-id");
        }
        let s = &self.sections;
        if let Some(x) = &s.system {
            x.validate()?;
        }
        if let Some(x) = &s.cpu {
            x.validate()?;
        }
        if let Some(x) = &s.memory {
            x.validate()?;
        }
        if let Some(x) = &s.storage {
            x.validate()?;
        }
        if let Some(x) = &s.network {
            x.validate()?;
        }
        if let Some(x) = &s.pci {
            x.validate()?;
        }
        if let Some(x) = &s.sensors {
            x.validate()?;
        }
        if let Some(x) = &s.software {
            x.validate()?;
        }
        let any = s.system.is_some()
            || s.cpu.is_some()
            || s.memory.is_some()
            || s.storage.is_some()
            || s.network.is_some()
            || s.pci.is_some()
            || s.sensors.is_some()
            || s.software.is_some();
        if !any {
            return Err("host-inventory-empty");
        }
        if self.report == ReportKind::Full
            && (s.system.is_none()
                || s.cpu.is_none()
                || s.memory.is_none()
                || s.storage.is_none()
                || s.network.is_none()
                || s.pci.is_none()
                || s.sensors.is_none()
                || s.software.is_none())
        {
            return Err("host-inventory-full-incomplete");
        }
        Ok(())
    }

    /// The canonical-CBOR body: the signature preimage. At most
    /// [`MAX_BODY_BYTES`].
    pub fn canonical(&self) -> InventoryResult<Vec<u8>> {
        self.validate()?;
        let value = Value::serialized(self).map_err(|_| "host-inventory-encode")?;
        let bytes = to_canonical_vec(&value).map_err(|_| "host-inventory-encode")?;
        if bytes.len() > MAX_BODY_BYTES {
            return Err("host-inventory-too-large");
        }
        Ok(bytes)
    }

    /// Put a collected body in its one valid order, and fit the storage
    /// caps: what an item check refuses is dropped (a device or link of
    /// an unknown family, a by-id link that is no [`is_disk_id`], a
    /// reading of no [`is_sensor_chip`]); every keyed list sorted by its
    /// key (an exact key duplicate dropped, the first kept); the most
    /// severe advisories kept past [`MAX_ADVISORIES`]
    /// (`advisories_truncated`); devices past [`MAX_DEVICES`] trimmed
    /// ([`Device::trim_rank`]), and a device's ids (sorted), links and
    /// mounts past their caps cut (`devices_truncated`). The collector's
    /// other lists and strings are its own to bound.
    pub fn normalize(&mut self) {
        let s = &mut self.sections;
        if let Some(cpu) = s.cpu.as_mut() {
            cpu.flags.sort();
            cpu.flags.dedup();
        }
        if let Some(memory) = s.memory.as_mut() {
            sort_dedup_by(&mut memory.dimms, Dimm::key);
            if let Some(edac) = memory.edac.as_mut() {
                sort_dedup_by(&mut edac.per_dimm, |d| d.locator.clone());
            }
        }
        if let Some(storage) = s.storage.as_mut() {
            storage.devices.retain(|d| is_kernel_name(&d.name));
            sort_dedup_by(&mut storage.devices, |d| d.name.clone());
            while storage.devices.len() > MAX_DEVICES && storage.trim_one() {}
            let mut cut = false;
            for d in &mut storage.devices {
                d.reasons.sort();
                d.reasons.dedup();
                d.pool_ids
                    .retain(|p| hippius_types::storage_report::is_valid_pool_id(p));
                d.pool_ids.sort();
                d.pool_ids.dedup();
                cut |= cap(&mut d.pool_ids, MAX_POOLS_PER_DEVICE);
                d.ids.retain(|id| is_disk_id(id));
                d.ids.sort();
                cut |= cap(&mut d.ids, MAX_DEVICE_IDS);
                for links in [&mut d.partitions, &mut d.holders] {
                    links.retain(|n| is_kernel_name(n));
                    cut |= cap(links, MAX_DEVICE_LINKS);
                }
                if let Some(md) = d.md.as_mut() {
                    md.members.retain(|n| is_kernel_name(n));
                    cut |= cap(&mut md.members, MAX_DEVICE_LINKS);
                }
                cut |= cap(&mut d.mounts, MAX_DEVICE_MOUNTS);
            }
            storage.devices_truncated |= cut;
            // A duplicate keeps its most severe report.
            storage
                .advisories
                .sort_by_key(|a| (a.key(), core::cmp::Reverse(a.severity as u8)));
            storage.advisories.dedup_by(|a, b| a.key() == b.key());
            if storage.advisories.len() > MAX_ADVISORIES {
                // Most severe first, then the most recent.
                storage.advisories.sort_by_key(|a| {
                    (
                        core::cmp::Reverse(a.severity as u8),
                        core::cmp::Reverse(a.last_seen_unix),
                    )
                });
                storage.advisories.truncate(MAX_ADVISORIES);
                storage.advisories_truncated = true;
                storage.advisories.sort_by_key(Advisory::key);
            }
        }
        if let Some(network) = s.network.as_mut() {
            sort_dedup_by(&mut network.nics, |n| n.name.clone());
        }
        if let Some(pci) = s.pci.as_mut() {
            sort_dedup_by(&mut pci.devices, |d| d.address.clone());
        }
        if let Some(sensors) = s.sensors.as_mut() {
            sensors.temperatures.retain(|t| is_sensor_chip(&t.chip));
            sensors.fans.retain(|f| is_sensor_chip(&f.chip));
            sort_dedup_by(&mut sensors.temperatures, Temperature::key);
            sort_dedup_by(&mut sensors.fans, Fan::key);
            sort_dedup_by(&mut sensors.psus, |p| p.label.clone());
        }
    }

    /// [`Self::normalize`], then [`Self::canonical`], trimming the storage
    /// inventory until the body fits [`MAX_BODY_BYTES`]
    /// ([`Device::trim_rank`]: VM-owned virtual / dm devices, then
    /// partitions that are no pool, then the rest — the last by name among
    /// equals), `devices_truncated` set. Any other encode error, or a body
    /// still too large without devices, is returned; `self` keeps what was
    /// trimmed either way.
    pub fn canonical_fitted(&mut self) -> InventoryResult<Vec<u8>> {
        self.normalize();
        loop {
            match self.canonical() {
                Err("host-inventory-too-large") => {}
                other => return other,
            }
            let trimmed = self
                .sections
                .storage
                .as_mut()
                .is_some_and(StorageSection::trim_one);
            if !trimmed {
                return Err("host-inventory-too-large");
            }
        }
    }

    /// Decode a signed body: canonical, typed, valid, and re-encoded
    /// byte for byte (one encoding only).
    pub fn decode(bytes: &[u8]) -> InventoryResult<Self> {
        if bytes.len() > MAX_BODY_BYTES {
            return Err("host-inventory-too-large");
        }
        assert_canonical(bytes).map_err(|_| "host-inventory-not-canonical")?;
        let body: Self =
            ciborium::de::from_reader(bytes).map_err(|_| "host-inventory-body-decode")?;
        if body.canonical()? != bytes {
            return Err("host-inventory-not-canonical");
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn minimal() -> HostInventory {
        HostInventory {
            schema_version: SCHEMA_VERSION,
            domain: DOMAIN.into(),
            miner_id: "miner-a".into(),
            timestamp_unix: 1_700_000_000,
            sequence: 1,
            report: ReportKind::Change,
            sections: Sections {
                software: Some(SoftwareSection {
                    status: SectionStatus::Ok,
                    kernel: Some("7.0.0".into()),
                    os_name: None,
                    os_version_id: None,
                    agent_version: None,
                    qemu_version: None,
                    libvirt_version: None,
                    uptime_s: 5,
                    last_boot_unix: None,
                    auto_update: None,
                }),
                ..Sections::default()
            },
        }
    }

    pub(super) fn device(name: &str) -> Device {
        Device {
            name: name.into(),
            kind: DeviceKind::Disk,
            size_bytes: 1,
            ids: vec![],
            model: None,
            transport: Transport::Nvme,
            rotational_hint: None,
            removable: false,
            read_only: false,
            behind_controller: None,
            partitions: vec![],
            holders: vec![],
            md: None,
            fs: None,
            mounts: vec![],
            role: DeviceRole::Ineligible,
            pool_ids: vec![],
            reasons: vec![IneligibleReason::HasPartitions],
        }
    }

    pub(super) fn with_storage(devices: Vec<Device>, advisories: Vec<Advisory>) -> HostInventory {
        let mut r = minimal();
        r.sections.storage = Some(StorageSection {
            status: SectionStatus::Ok,
            devices,
            advisories,
            advisories_truncated: false,
            devices_truncated: false,
        });
        r
    }

    #[test]
    fn a_body_round_trips_through_its_one_encoding() {
        let body = minimal().canonical().unwrap();
        assert_canonical(&body).unwrap();
        assert_eq!(HostInventory::decode(&body).unwrap(), minimal());
        // Absent sections are absent, not null.
        let v: Value = ciborium::de::from_reader(body.as_slice()).unwrap();
        let Value::Map(top) = v else { panic!() };
        let sections = &top
            .iter()
            .find(|(k, _)| k == &Value::Text("sections".into()))
            .unwrap()
            .1;
        let Value::Map(s) = sections else { panic!() };
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn header_fields_fail_closed() {
        let mut r = minimal();
        r.schema_version = 2;
        assert_eq!(r.canonical(), Err("host-inventory-schema-version"));
        let mut r = minimal();
        r.domain = "HIPPIUS_MINER_HEARTBEAT_V1".into();
        assert_eq!(r.canonical(), Err("host-inventory-domain"));
        let mut r = minimal();
        r.miner_id = String::new();
        assert_eq!(r.canonical(), Err("host-inventory-miner-id"));
    }

    #[test]
    fn a_full_report_carries_every_section() {
        let mut r = minimal();
        r.report = ReportKind::Full;
        assert_eq!(r.canonical(), Err("host-inventory-full-incomplete"));
    }

    fn with_auto_update(a: AutoUpdateStatus) -> HostInventory {
        let mut r = minimal();
        r.sections.software.as_mut().unwrap().auto_update = Some(a);
        r
    }

    fn auto_update_on() -> AutoUpdateStatus {
        AutoUpdateStatus {
            enabled: true,
            disabled_reason: None,
            last_check_unix: Some(1_700_000_000),
            failed_tag: Some("v2026.10.21.1".into()),
        }
    }

    #[test]
    fn release_tags_are_the_updaters_shape() {
        for ok in ["v2026.10.08", "v2026.10.08.1", "v2026.10.08.999"] {
            assert!(is_release_tag(ok), "{ok}");
        }
        for bad in [
            "",
            "dev",
            "2026.10.08",
            "v2026.10.8",
            "v26.10.08",
            "v2026.10.08.0",
            "v2026.10.08.01",
            "v2026.10.08.1000",
            "v2026.10.08.",
            "v2026.10.08.1.2",
            "v2026.10.08-rc1",
            "v2026.1a.08",
        ] {
            assert!(!is_release_tag(bad), "{bad}");
        }
    }

    #[test]
    fn auto_update_round_trips_and_is_optional() {
        let r = with_auto_update(auto_update_on());
        let bytes = r.canonical().unwrap();
        assert_eq!(HostInventory::decode(&bytes).unwrap(), r);
        let off = AutoUpdateStatus {
            enabled: false,
            disabled_reason: Some(AutoUpdateDisabledReason::TimerDisabled),
            last_check_unix: None,
            failed_tag: None,
        };
        let r = with_auto_update(off);
        assert_eq!(HostInventory::decode(&r.canonical().unwrap()).unwrap(), r);
        // Absent: the body is byte for byte what an older encoder made.
        let plain = minimal().canonical().unwrap();
        let v: Value = ciborium::de::from_reader(plain.as_slice()).unwrap();
        assert!(!format!("{v:?}").contains("auto_update"));
    }

    #[test]
    fn auto_update_reason_matches_enabled() {
        let mut a = auto_update_on();
        a.disabled_reason = Some(AutoUpdateDisabledReason::NoAutoUpdateFile);
        assert_eq!(
            with_auto_update(a).canonical(),
            Err("host-inventory-auto-update")
        );
        let mut a = auto_update_on();
        a.enabled = false;
        assert_eq!(
            with_auto_update(a).canonical(),
            Err("host-inventory-auto-update")
        );
    }

    #[test]
    fn auto_update_times_and_tags_are_checked() {
        let mut a = auto_update_on();
        a.last_check_unix = Some(-1);
        assert_eq!(
            with_auto_update(a).canonical(),
            Err("host-inventory-auto-update")
        );
        let mut a = auto_update_on();
        a.last_check_unix = Some(0);
        assert!(with_auto_update(a).canonical().is_ok());
        let mut a = auto_update_on();
        a.last_check_unix = Some(MAX_UNIX_TIME);
        assert!(with_auto_update(a).canonical().is_ok());
        let mut a = auto_update_on();
        a.last_check_unix = Some(MAX_UNIX_TIME + 1);
        assert_eq!(
            with_auto_update(a).canonical(),
            Err("host-inventory-auto-update")
        );
        let mut a = auto_update_on();
        a.failed_tag = Some("dev".into());
        assert_eq!(
            with_auto_update(a).canonical(),
            Err("host-inventory-auto-update")
        );
    }

    #[test]
    fn auto_update_refuses_unknown_keys() {
        let mut r = with_auto_update(auto_update_on());
        r.sections.software.as_mut().unwrap().auto_update = None;
        let mut v = Value::serialized(&r).unwrap();
        // sections.software.auto_update = {enabled: true, extra: 1}
        let Value::Map(top) = &mut v else { panic!() };
        let sections = top
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("sections"))
            .unwrap();
        let Value::Map(secs) = &mut sections.1 else {
            panic!()
        };
        let software = secs
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("software"))
            .unwrap();
        let Value::Map(sw) = &mut software.1 else {
            panic!()
        };
        sw.push((
            Value::Text("auto_update".into()),
            Value::Map(vec![
                (Value::Text("enabled".into()), Value::Bool(true)),
                (Value::Text("extra".into()), Value::Integer(1.into())),
            ]),
        ));
        let bytes = to_canonical_vec(&v).unwrap();
        assert!(HostInventory::decode(&bytes).is_err());
    }

    #[test]
    fn strings_are_bounded_printable_ascii() {
        let mut r = minimal();
        r.sections.software.as_mut().unwrap().kernel = Some("x".repeat(MAX_TEXT_LEN + 1));
        assert!(r.canonical().is_err());
        let mut r = minimal();
        r.sections.software.as_mut().unwrap().kernel = Some("bad\nline".into());
        assert!(r.canonical().is_err());
        let mut r = minimal();
        r.sections.software.as_mut().unwrap().kernel = Some(String::new());
        assert!(r.canonical().is_err(), "absent, never empty");
    }

    #[test]
    fn storage_lists_are_bounded_unique_and_sorted() {
        assert!(with_storage(vec![device("sda"), device("sdb")], vec![])
            .canonical()
            .is_ok());
        assert_eq!(
            with_storage(vec![device("sda"), device("sda")], vec![]).canonical(),
            Err("host-inventory-devices")
        );
        let mut unsorted = device("sda");
        unsorted.reasons = vec![IneligibleReason::Mounted, IneligibleReason::HasPartitions];
        assert_eq!(
            with_storage(vec![unsorted], vec![]).canonical(),
            Err("host-inventory-device")
        );
        assert_eq!(
            with_storage(vec![device("sdb"), device("sda")], vec![]).canonical(),
            Err("host-inventory-devices"),
            "sorted by name"
        );
        // A dm NAME (it can embed a VM id) is not a kernel name.
        for name in ["hippius-vm-a1b2", "crypt_VM.42", "luks-1", "nvme0", "sda1x"] {
            assert!(
                with_storage(vec![device(name)], vec![])
                    .canonical()
                    .is_err(),
                "{name}"
            );
        }
        for name in [
            "sda",
            "sdab1",
            "vdb",
            "nvme0n1",
            "nvme1n1p2",
            "md127",
            "md0p1",
            "dm-3",
            "loop0",
            "zram0",
            "mmcblk0p1",
            "sdzzz",
            "nvme0c0n1",
            "zd0",
            "zd16p1",
            "bcache0",
            "drbd1",
            "pmem0",
        ] {
            assert!(is_kernel_name(name), "{name}");
        }
        for name in [
            "sdtenantabc",
            "nvme0c0n1p1",
            "nvme0c0",
            "zdp1",
            "bcache",
            "dm-0p1",
        ] {
            assert!(!is_kernel_name(name), "{name}");
        }
        // A by-id link of a dm / md stack carries its free-form name.
        for id in [
            "dm-name-tenant_vm7",
            "dm-uuid-CRYPT-LUKS2-x-vm7",
            "md-name-host:0",
            "x",
        ] {
            let mut d = device("sda");
            d.ids = vec![id.into()];
            assert!(with_storage(vec![d], vec![]).canonical().is_err(), "{id}");
        }
        let mut d = device("sda");
        d.ids = vec!["nvme-eui.0025385b71b0a1b2".into(), "wwn-0x5000c5".into()];
        assert!(with_storage(vec![d], vec![]).canonical().is_ok());
        let mut holder = device("sda");
        holder.holders = vec!["luks-Tenant_1".into()];
        assert!(with_storage(vec![holder], vec![]).canonical().is_err());
        let mut bad_pool = device("sda");
        bad_pool.pool_ids = vec!["NVMe".into()];
        assert!(with_storage(vec![bad_pool.clone()], vec![])
            .canonical()
            .is_err());
        bad_pool.pool_ids = vec!["hdd0".into(), "default".into()];
        assert!(with_storage(vec![bad_pool.clone()], vec![])
            .canonical()
            .is_err());
        bad_pool.pool_ids = vec!["default".into(), "hdd0".into()];
        assert!(with_storage(vec![bad_pool.clone()], vec![])
            .canonical()
            .is_ok());
        bad_pool.pool_ids = vec!["NVMe".into()];
        assert!(with_storage(vec![bad_pool], vec![]).canonical().is_err());
        let mut relative = device("sda");
        relative.mounts = vec!["mnt".into()];
        assert!(with_storage(vec![relative], vec![]).canonical().is_err());
        let too_many: Vec<Device> = (0..=MAX_DEVICES)
            .map(|i| device(&alloc::format!("d{i}")))
            .collect();
        assert_eq!(
            with_storage(too_many, vec![]).canonical(),
            Err("host-inventory-devices")
        );
    }

    #[test]
    fn advisories_are_well_formed() {
        let advisory = |kind, subject: &str, sample: Option<&str>| Advisory {
            subject_kind: kind,
            subject: subject.into(),
            code: AdvisoryCode::KernelIoError,
            severity: Severity::Critical,
            count: 3,
            value: 0,
            first_seen_unix: 10,
            last_seen_unix: 20,
            sample: sample.map(Into::into),
        };
        assert!(with_storage(
            vec![],
            vec![advisory(
                AdvisorySubject::Device,
                "sdb",
                Some("I/O error, dev sdb, sector 1234567 op READ")
            )]
        )
        .canonical()
        .is_ok());
        assert!(with_storage(
            vec![],
            vec![advisory(AdvisorySubject::Collector, "x", None)]
        )
        .canonical()
        .is_err());
        assert!(with_storage(
            vec![],
            vec![advisory(
                AdvisorySubject::Device,
                "sdb",
                Some(&"x".repeat(121))
            )]
        )
        .canonical()
        .is_err());
        let mut backwards = advisory(AdvisorySubject::Device, "sdb", None);
        backwards.first_seen_unix = 30;
        assert!(with_storage(vec![], vec![backwards]).canonical().is_err());
    }

    #[test]
    fn a_controller_mode_belongs_to_a_storage_controller() {
        let mut r = minimal();
        r.sections.pci = Some(PciSection {
            status: SectionStatus::Ok,
            devices: vec![PciDevice {
                address: "0000:41:00.0".into(),
                kind: PciKind::Nic,
                vendor_id: 0x14e4,
                device_id: 0x16d8,
                name: None,
                driver: None,
                numa_node: None,
                iommu_group: None,
                link_width: None,
                link_speed: None,
                mode: Some(ControllerMode::Hba),
            }],
        });
        assert_eq!(r.canonical(), Err("host-inventory-pci"));
    }

    #[test]
    fn decode_refuses_anything_but_the_one_encoding() {
        let body = minimal().canonical().unwrap();
        // An unknown key in a section.
        let mut v: Value = ciborium::de::from_reader(body.as_slice()).unwrap();
        if let Value::Map(top) = &mut v {
            for (k, val) in top.iter_mut() {
                if k == &Value::Text("sections".into()) {
                    if let Value::Map(s) = val {
                        if let Value::Map(sw) = &mut s[0].1 {
                            sw.push((Value::Text("hostname".into()), Value::Text("h".into())));
                        }
                    }
                }
            }
        }
        let extra = to_canonical_vec(&v).unwrap();
        assert_eq!(
            HostInventory::decode(&extra),
            Err("host-inventory-body-decode")
        );
        // An unknown enum value.
        let swapped = to_canonical_vec(
            &ciborium::de::from_reader::<Value, _>(minimal().canonical().unwrap().as_slice())
                .map(|v| replace_text(v, "change", "sometimes"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            HostInventory::decode(&swapped),
            Err("host-inventory-body-decode")
        );
        // Not canonical (the keys out of order).
        let Value::Map(mut top) = ciborium::de::from_reader::<Value, _>(body.as_slice()).unwrap()
        else {
            panic!()
        };
        top.reverse();
        let mut raw = Vec::new();
        ciborium::ser::into_writer(&Value::Map(top), &mut raw).unwrap();
        assert_eq!(
            HostInventory::decode(&raw),
            Err("host-inventory-not-canonical")
        );
        // Too large.
        assert_eq!(
            HostInventory::decode(&vec![0u8; MAX_BODY_BYTES + 1]),
            Err("host-inventory-too-large")
        );
    }

    fn replace_text(v: Value, from: &str, to: &str) -> Value {
        match v {
            Value::Text(t) if t == from => Value::Text(to.into()),
            Value::Map(m) => Value::Map(
                m.into_iter()
                    .map(|(k, v)| (k, replace_text(v, from, to)))
                    .collect(),
            ),
            Value::Array(a) => {
                Value::Array(a.into_iter().map(|v| replace_text(v, from, to)).collect())
            }
            other => other,
        }
    }

    #[test]
    fn the_envelope_is_bounded_and_canonical() {
        let body = minimal().canonical().unwrap();
        let env = SignedHostInventory {
            body: body.clone(),
            sig: vec![7u8; SIGNATURE_LEN],
        };
        let bytes = env.canonical().unwrap();
        assert_eq!(SignedHostInventory::decode(&bytes).unwrap(), env);
        let short = SignedHostInventory {
            body,
            sig: vec![7u8; 63],
        };
        assert_eq!(short.canonical(), Err("host-inventory-signature-length"));
        assert_eq!(
            SignedHostInventory::decode(&vec![0u8; MAX_ENVELOPE_BYTES + 1]),
            Err("host-inventory-too-large")
        );
        // The largest body still makes an envelope within the cap.
        let largest = SignedHostInventory {
            body: vec![0u8; MAX_BODY_BYTES],
            sig: vec![7u8; SIGNATURE_LEN],
        };
        assert!(largest.canonical().unwrap().len() <= MAX_ENVELOPE_BYTES);
    }
}

#[cfg(test)]
mod more_tests {
    use super::tests::{device, with_storage};
    use super::*;
    use alloc::format;
    use alloc::vec;

    fn report(sections: Sections) -> HostInventory {
        HostInventory {
            schema_version: SCHEMA_VERSION,
            domain: DOMAIN.into(),
            miner_id: "miner-a".into(),
            timestamp_unix: 1,
            sequence: 1,
            report: ReportKind::Change,
            sections,
        }
    }

    fn big_device(i: usize, kind: DeviceKind) -> Device {
        let long = |p: &str| format!("{p}{}", "x".repeat(MAX_DISK_ID_LEN - p.len()));
        Device {
            name: format!(
                "sd{}{}",
                (b'a' + (i / 26) as u8) as char,
                (b'a' + (i % 26) as u8) as char
            ),
            kind,
            size_bytes: u64::MAX,
            ids: (0..MAX_DEVICE_IDS)
                .map(|j| long(&format!("wwn-{j}-")))
                .collect(),
            model: Some("m".repeat(MAX_TEXT_LEN)),
            transport: Transport::Sas,
            rotational_hint: Some(true),
            removable: false,
            read_only: false,
            behind_controller: Some("c".repeat(MAX_TEXT_LEN)),
            partitions: (0..MAX_DEVICE_LINKS)
                .map(|j| format!("md{}", i * 100 + j))
                .collect(),
            holders: vec![],
            md: None,
            fs: None,
            mounts: vec![],
            role: DeviceRole::Ineligible,
            pool_ids: vec![],
            reasons: vec![IneligibleReason::HasPartitions],
        }
    }

    #[test]
    fn an_empty_report_is_refused() {
        assert_eq!(
            report(Sections::default()).canonical(),
            Err("host-inventory-empty")
        );
    }

    #[test]
    fn the_worst_case_inventory_is_trimmed_to_fit() {
        let mut devices: Vec<Device> = (0..MAX_DEVICES)
            .map(|i| {
                big_device(
                    i,
                    if i % 2 == 0 {
                        DeviceKind::Disk
                    } else {
                        DeviceKind::Partition
                    },
                )
            })
            .collect();
        devices.sort_by(|a, b| a.name.cmp(&b.name));
        let mut r = report(Sections {
            storage: Some(StorageSection {
                status: SectionStatus::Ok,
                devices,
                advisories: vec![],
                advisories_truncated: false,
                devices_truncated: false,
            }),
            ..Sections::default()
        });
        assert_eq!(r.canonical(), Err("host-inventory-too-large"));
        let bytes = r.canonical_fitted().unwrap();
        assert!(bytes.len() <= MAX_BODY_BYTES);
        let storage = r.sections.storage.as_ref().unwrap();
        assert!(storage.devices_truncated);
        // Partitions went first.
        assert!(storage.devices.iter().all(|d| d.kind == DeviceKind::Disk));
        assert_eq!(HostInventory::decode(&bytes).unwrap(), r);
    }

    #[test]
    fn advisory_subjects_follow_their_kind() {
        let advisory = |kind, subject: &str| Advisory {
            subject_kind: kind,
            subject: subject.into(),
            code: AdvisoryCode::MdDegraded,
            severity: Severity::Critical,
            count: 1,
            value: 0,
            first_seen_unix: 1,
            last_seen_unix: 1,
            sample: None,
        };
        let check = |a: Advisory| {
            report(Sections {
                storage: Some(StorageSection {
                    status: SectionStatus::Ok,
                    devices: vec![],
                    advisories: vec![a],
                    advisories_truncated: false,
                    devices_truncated: false,
                }),
                ..Sections::default()
            })
            .canonical()
        };
        assert!(check(advisory(AdvisorySubject::Md, "md0")).is_ok());
        assert!(check(advisory(AdvisorySubject::Md, "vg-tenant_vm7")).is_err());
        assert!(check(advisory(AdvisorySubject::Pool, "nvme0")).is_ok());
        assert!(check(advisory(AdvisorySubject::Pool, "NVMe 0")).is_err());
        assert!(check(advisory(
            AdvisorySubject::Controller,
            "ctrl:PERC H330 Mini:0"
        ))
        .is_ok());
        assert!(check(advisory(AdvisorySubject::Controller, "PERC")).is_err());
        assert!(check(advisory(AdvisorySubject::DedicatedDisk, "wwn-0x5000c5")).is_ok());
        assert!(check(advisory(AdvisorySubject::DedicatedDisk, "dm-name-vm7")).is_err());
    }

    #[test]
    fn keyed_lists_are_sorted_and_distinct() {
        let psu = |label: &str| Psu {
            label: label.into(),
            state: PsuState::Ok,
        };
        let sensors = |psus| {
            report(Sections {
                sensors: Some(SensorsSection {
                    status: SectionStatus::Ok,
                    temperatures: vec![],
                    fans: vec![],
                    psus,
                }),
                ..Sections::default()
            })
            .canonical()
        };
        assert!(sensors(vec![psu("PSU1"), psu("PSU2")]).is_ok());
        assert!(sensors(vec![psu("PSU2"), psu("PSU1")]).is_err());
        assert!(sensors(vec![psu("PSU1"), psu("PSU1")]).is_err());

        // Every NVMe reports a `Composite`: keyed by (chip, label).
        let temp = |chip: &str, label: &str| Temperature {
            chip: chip.into(),
            label: label.into(),
            millicelsius: 40_000,
        };
        let temps = |temperatures| {
            report(Sections {
                sensors: Some(SensorsSection {
                    status: SectionStatus::Ok,
                    temperatures,
                    fans: vec![],
                    psus: vec![],
                }),
                ..Sections::default()
            })
            .canonical()
        };
        assert!(temps(vec![
            temp("nvme.0", "Composite"),
            temp("nvme.1", "Composite")
        ])
        .is_ok());
        assert!(temps(vec![
            temp("nvme.0", "Composite"),
            temp("nvme.0", "Composite")
        ])
        .is_err());
        for chip in [
            "nvme",
            "Nvme.0",
            "nvme.",
            ".0",
            "k10temp-pci-00c3",
            "vm7 .0",
        ] {
            assert!(temps(vec![temp(chip, "Tctl")]).is_err(), "{chip}");
        }
        assert!(temps(vec![temp("ipmi", "Inlet Temp")]).is_ok());

        // Boards repeat `DIMM 0` across banks: keyed by (bank, locator).
        let dimm = |bank: &str, locator: &str| Dimm {
            bank_locator: Some(bank.into()),
            locator: locator.into(),
            size_mib: 1,
            mem_type: None,
            speed_mts: None,
            configured_mts: None,
            ecc: EccType::Unknown,
            manufacturer: None,
            part: None,
            serial: None,
        };
        let memory = |dimms| {
            report(Sections {
                memory: Some(MemorySection {
                    status: SectionStatus::Ok,
                    total_mib: 1,
                    dimms,
                    edac: None,
                }),
                ..Sections::default()
            })
            .canonical()
        };
        assert!(memory(vec![
            dimm("P0 CHANNEL A", "DIMM 0"),
            dimm("P0 CHANNEL B", "DIMM 0")
        ])
        .is_ok());
        assert!(memory(vec![
            dimm("P0 CHANNEL A", "DIMM 0"),
            dimm("P0 CHANNEL A", "DIMM 0")
        ])
        .is_err());
    }

    #[test]
    fn devices_are_trimmed_vm_owned_first_then_non_pool_partitions() {
        let dev = |name: &str, kind, role| Device {
            kind,
            role,
            ..device(name)
        };
        let mut storage = StorageSection {
            status: SectionStatus::Ok,
            devices: vec![
                dev("dm-0", DeviceKind::Dm, DeviceRole::Member),
                dev("loop0", DeviceKind::Virtual, DeviceRole::Ineligible),
                dev("sda", DeviceKind::Disk, DeviceRole::Member),
                dev("sda1", DeviceKind::Partition, DeviceRole::PoolBacking),
                dev("sda2", DeviceKind::Partition, DeviceRole::Ineligible),
                dev("sdb", DeviceKind::Disk, DeviceRole::EligibleDedicated),
            ],
            advisories: vec![],
            advisories_truncated: false,
            devices_truncated: false,
        };
        let mut order = vec![];
        while let Some(before) = Some(storage.devices.clone()).filter(|d| !d.is_empty()) {
            assert!(storage.trim_one());
            let gone = before
                .iter()
                .find(|d| !storage.devices.contains(d))
                .unwrap();
            order.push(gone.name.clone());
        }
        assert!(!storage.trim_one());
        assert!(storage.devices_truncated);
        assert_eq!(order, ["loop0", "dm-0", "sda2", "sda", "sdb", "sda1"]);
    }

    #[test]
    fn normalize_orders_and_fits_a_collected_body() {
        let mut devices: Vec<Device> = (0..MAX_DEVICES + 3)
            .map(|i| Device {
                kind: DeviceKind::Virtual,
                ..device(&alloc::format!("loop{i}"))
            })
            .collect();
        devices.reverse();
        devices[0].holders = (0..MAX_DEVICE_LINKS + 4)
            .map(|i| alloc::format!("dm-{i}"))
            .collect();
        devices[0].reasons = vec![IneligibleReason::Virtual, IneligibleReason::HasPartitions];
        let mut sda = device("sda");
        sda.ids = vec![
            "wwn-0x5000c5".into(),
            "lvm-pv-uuid-abc".into(),
            "ata-M_S".into(),
        ];
        devices.push(sda);
        devices.push(device("vg-tenant_vm7"));
        let advisory = |i: usize, severity| Advisory {
            subject_kind: AdvisorySubject::Device,
            subject: alloc::format!("sd{}", (b'a' + (i % 26) as u8) as char),
            code: [
                AdvisoryCode::KernelIoError,
                AdvisoryCode::PendingSectors,
                AdvisoryCode::ReallocatedSectors,
            ][i / 26],
            severity,
            count: 1,
            value: 0,
            first_seen_unix: 0,
            last_seen_unix: i as i64,
            sample: None,
        };
        // 78 distinct, past the cap; one duplicated as critical.
        let mut advisories: Vec<Advisory> = (0..78).map(|i| advisory(i, Severity::Info)).collect();
        advisories.push(advisory(77, Severity::Critical));
        let mut r = with_storage(devices, advisories);
        assert!(r.canonical().is_err());
        r.normalize();
        let bytes = r.canonical().unwrap();
        let storage = r.sections.storage.as_ref().unwrap();
        assert!(storage.devices_truncated && storage.advisories_truncated);
        assert_eq!(storage.devices.len(), MAX_DEVICES);
        // The disk outranks the loop devices.
        let sda = storage.devices.iter().find(|d| d.name == "sda").unwrap();
        assert_eq!(sda.ids, ["ata-M_S", "wwn-0x5000c5"]);
        assert!(storage.devices.iter().all(|d| d.name != "vg-tenant_vm7"));
        assert!(storage
            .devices
            .iter()
            .all(|d| d.holders.len() <= MAX_DEVICE_LINKS));
        assert_eq!(storage.advisories.len(), MAX_ADVISORIES);
        // The duplicate kept its critical report, and the cut kept it.
        assert!(storage
            .advisories
            .iter()
            .any(|a| a.severity == Severity::Critical
                && a.key() == advisory(77, Severity::Info).key()));
        assert_eq!(HostInventory::decode(&bytes).unwrap(), r);
    }

    #[test]
    fn pci_addresses_are_checked() {
        assert!(is_pci_address("0000:41:00.0"));
        assert!(!is_pci_address("41:00.0"));
        assert!(!is_pci_address("0000:41:00:0"));
        assert!(!is_pci_address("zzzz:41:00.0"));
    }
}
