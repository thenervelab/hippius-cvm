//! `--open-dedicated-disks` — open a VM's dedicated physical disks
//! (docs/design/disk-tier-verification.md §4.2, G3).
//!
//! Runs in the golden initramfs (`hippius_golden_open_dedicated` in
//! `hippius-golden-overlay.sh`), after the KBS release and after the
//! guest-keyed OS volume is open, and BEFORE the KEK keyfile is shredded.
//! It is the only code that ever sees a dedicated disk's key, and that key
//! never leaves this process except down a pipe to `cryptsetup`.
//!
//! ## Inputs (all measured or guest-private)
//!
//! - the measured cmdline: `hippius.dedicated=x0:<GiB>,x1:<GiB>,…` (the
//!   anchor; absent ⇒ this mode does nothing at all) and `hippius.vm_id=`;
//! - the released KEK (the 32-byte tmpfs keyfile the OS volume was opened
//!   with — in the customer-held key modes, the combined KEK);
//! - the record on the guest-keyed OS volume, next to the anti-rollback
//!   stamp ([`RECORD_NAME`]): which slots this VM formatted, with their
//!   LUKS UUIDs.
//!
//! ## What it does per anchored slot
//!
//! 1. Find `/dev/disk/by-id/virtio-hippius-<slot>` (the virtual serial
//!    vali gives the disk). Absent ⇒ `missing`; boot continues.
//! 2. Refuse a partition, a device in use, a device two slots resolve to,
//!    or one smaller than the anchored size class ⇒ `mismatch`.
//! 3. Key: `HKDF-SHA256(ikm = KEK, salt = "hippius-dedicated-disk-v1",
//!    info = vm_id ‖ slot)`, 64 bytes, used as the LUKS2 VOLUME key
//!    (aes-xts-plain64, 512-bit).
//! 4. A slot with no record (or a record still `formatting`) and no
//!    signature at all on the device: record `formatting` + a fresh UUID
//!    first, then `luksFormat --uuid` (no integrity: instant), then open,
//!    then record `ready`. A slot recorded `ready` must carry the recorded
//!    UUID: a different or absent header is `mismatch`, never reformatted.
//! 5. Copy the header into guest RAM, require the copy to carry the
//!    recorded UUID and to be a header this guest writes (one plain
//!    aes-xts-plain64 crypt segment, no requirements, no tokens), open as
//!    `/dev/mapper/hippius-<slot>` BY VOLUME KEY from that copy, then check
//!    what the kernel actually activated (`cryptsetup status`): LUKS2,
//!    aes-xts-plain64, 512-bit, no integrity, on the device we chose.
//!    Anything else is refused or closed again ⇒ `mismatch`.
//!
//! Never a filesystem, never a RAID: those are the customer's.
//!
//! ## Why open by volume key
//!
//! The LUKS2 header is unauthenticated and the miner can rewrite it. A
//! keyslot is the classic hole (CVE-2025-59054 family): a forged keyslot
//! with a null area cipher "decrypts" to a volume key the forger chose,
//! the forged digest accepts it, and the guest would encrypt under a key
//! the miner knows. Opening by volume key skips keyslots entirely: the
//! header's digest must accept OUR derived key, which the miner cannot
//! compute for an unknown key. What the miner can still forge is the
//! segment layout (a `cipher_null` or `linear` segment, or a reencryption
//! "in progress" that maps part of the disk through such a segment): the
//! metadata check on the copy the activation reads, and the
//! post-activation check, close that. The keyslot
//! `luksFormat` must create is keyed with the same derived bytes, so it
//! wraps nothing that is not already the key.
//!
//! ## Outputs
//!
//! One line per slot in the state file (tmpfs, `/run/hippius/dedicated/
//! slots`): `<slot> <state> <size_gib> <dev|-> <reason>`, read by the
//! telemetry agent (receipt `disk_io` slot verdicts) and `hippius-disks`.
//! Diagnostics on stderr carry slots, states and reason codes, never key
//! bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hippius_types::disk_stats::{is_valid_slot, SLOT_SERIAL_PREFIX};
use hippius_types::guardian::MAX_CMDLINE_LEN;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// The measured anchor's cmdline key.
pub const ANCHOR_KEY: &str = "hippius.dedicated";
/// At most this many dedicated disks per VM (the frozen contract's 1..8).
pub const MAX_SLOTS: usize = 8;
/// The smallest size class sold (GiB).
pub const MIN_GIB: u64 = 1000;
/// A sanity ceiling (1 PiB in GiB): a size class above it is a vali bug.
pub const MAX_GIB: u64 = 1 << 20;
/// HKDF salt (domain separation from every other use of the KEK).
pub const HKDF_SALT: &[u8] = b"hippius-dedicated-disk-v1";
/// The derived key is the LUKS2 volume key: aes-xts-plain64, 512-bit.
pub const SLOT_KEY_LEN: usize = 64;
/// The record, at the root of the guest-keyed OS volume (next to the
/// anti-rollback stamp: not reachable through the tenant's merged root).
pub const RECORD_NAME: &str = ".hippius-dedicated-disks";
const RECORD_MAGIC: &str = "hippius-dedicated-disks v1";
const STATE_MAGIC: &str = "# hippius-dedicated-disks state v1";
/// How long the opener waits for an anchored slot's device to appear.
pub const DEVICE_WAIT: Duration = Duration::from_secs(15);
/// How much of a device the blank check reads (the LUKS2 secondary header
/// can sit at up to 4 MiB; everything else we look for is below that).
const HEAD_LEN: usize = (4 << 20) + 4096;
/// The data offset and encryption sector size every slot is formatted
/// with, PINNED rather than left to cryptsetup's topology autodetection:
/// a re-format of a `formatting` slot must reproduce the exact layout
/// (same offset, same sector size, same derived key) so it can never
/// shift or zero a data sector. Checked again on every open.
pub const DATA_OFFSET_BYTES: u64 = 16 << 20;
pub const SECTOR_SIZE: u64 = 4096;

/// How much of a device's END the blank check reads: GPT backup, md 0.90 /
/// 1.0 superblocks and ZFS labels L2/L3 all sit in the last 512 KiB.
const TAIL_LEN: usize = 1 << 20;

/// One anchored slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorSlot {
    pub slot: String,
    pub gib: u64,
}

/// What the measured cmdline says about dedicated disks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anchor {
    /// No anchor token: this VM has no dedicated disk (or an initrd
    /// older than the vali that would send one).
    Absent,
    /// A well-formed anchor and the VM id the keys are derived under.
    Valid {
        slots: Vec<AnchorSlot>,
        vm_id: String,
    },
    /// Present but malformed: no slot is touched.
    Malformed(&'static str),
}

/// `x[0-9]{1,2}` that is also a slot the receipt wire can carry
/// (`hippius_types::disk_stats::is_valid_slot`: no leading zero, ≤ x23).
fn anchor_slot_ok(slot: &str) -> bool {
    let Some(n) = slot.strip_prefix('x') else {
        return false;
    };
    (1..=2).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()) && is_valid_slot(slot)
}

fn parse_gib(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 7 || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let v: u64 = s.parse().ok()?;
    (MIN_GIB..=MAX_GIB).contains(&v).then_some(v)
}

/// Parse the anchor strictly. Any doubt is [`Anchor::Malformed`]: the
/// guest never guesses which disk is which or how large it must be.
pub fn parse_anchor(cmdline: &str) -> Anchor {
    let line = cmdline.strip_suffix('\n').unwrap_or(cmdline);
    let tokens: Vec<&str> = line.split_ascii_whitespace().collect();
    let is_anchor = |t: &&str| t.split_once('=').map_or(*t, |(k, _)| k) == ANCHOR_KEY;
    let anchors: Vec<&str> = tokens.iter().copied().filter(is_anchor).collect();
    let value = match anchors.as_slice() {
        [] => return Anchor::Absent,
        [one] => match one.split_once('=') {
            Some((_, v)) => v,
            None => return Anchor::Malformed("anchor-no-value"),
        },
        _ => return Anchor::Malformed("anchor-repeated"),
    };
    // An honest vali never mints a cmdline the kernel cuts (see
    // `MAX_MEASURED_CMDLINE_LEN`); one at the limit whose LAST token is
    // the anchor may have lost its tail ("x1:2230" of "x1:22300").
    if line.len() >= MAX_CMDLINE_LEN && tokens.last().is_some_and(is_anchor) {
        return Anchor::Malformed("anchor-maybe-truncated");
    }
    let entries: Vec<&str> = value.split(',').collect();
    if entries.is_empty() || entries.len() > MAX_SLOTS {
        return Anchor::Malformed("anchor-count");
    }
    let mut slots = Vec::with_capacity(entries.len());
    let mut seen = BTreeSet::new();
    for e in entries {
        let Some((slot, gib)) = e.split_once(':') else {
            return Anchor::Malformed("anchor-entry");
        };
        if !anchor_slot_ok(slot) {
            return Anchor::Malformed("anchor-slot");
        }
        let Some(gib) = parse_gib(gib) else {
            return Anchor::Malformed("anchor-size");
        };
        if !seen.insert(slot) {
            return Anchor::Malformed("anchor-slot-repeated");
        }
        slots.push(AnchorSlot {
            slot: slot.to_string(),
            gib,
        });
    }
    let vm_ids: Vec<&str> = tokens
        .iter()
        .filter_map(|t| t.strip_prefix("hippius.vm_id="))
        .collect();
    let vm_id = match vm_ids.as_slice() {
        [one] if !one.is_empty() && one.len() <= 128 => (*one).to_string(),
        [] => return Anchor::Malformed("anchor-no-vm-id"),
        _ => return Anchor::Malformed("anchor-bad-vm-id"),
    };
    Anchor::Valid { slots, vm_id }
}

/// The slot's volume key: `HKDF-SHA256(ikm = kek, salt =
/// "hippius-dedicated-disk-v1", info = vm_id ‖ slot)`, 64 bytes.
///
/// `vm_id ‖ slot` is unambiguous: a slot is `x` + digits, so the last `x`
/// of the info string is where the slot starts.
pub fn slot_key(kek: &[u8], vm_id: &str, slot: &str) -> Zeroizing<[u8; SLOT_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), kek);
    let mut info = Zeroizing::new(Vec::with_capacity(vm_id.len() + slot.len()));
    info.extend_from_slice(vm_id.as_bytes());
    info.extend_from_slice(slot.as_bytes());
    let mut out = Zeroizing::new([0u8; SLOT_KEY_LEN]);
    // 64 ≤ 255 × 32: expand cannot fail for this length.
    if hk.expand(&info, out.as_mut()).is_err() {
        out.as_mut().fill(0);
    }
    out
}

/// Where a slot stands in the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordState {
    /// The UUID was chosen and recorded; `luksFormat` may not have
    /// finished. Nothing was ever opened under it.
    Formatting,
    /// Formatted and opened at least once: only this UUID is accepted.
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEntry {
    pub state: RecordState,
    pub uuid: String,
    pub size_gib: u64,
}

/// `slot → entry`. Entries are never removed: a slot is never reused.
pub type Record = BTreeMap<String, RecordEntry>;

/// Lowercase canonical UUID text (8-4-4-4-12 hex).
pub fn valid_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

/// Parse the record strictly; any malformed line refuses the whole file.
pub fn parse_record(text: &str) -> Result<Record, &'static str> {
    let mut lines = text.lines();
    if lines.next() != Some(RECORD_MAGIC) {
        return Err("record-magic");
    }
    let mut out = Record::new();
    for line in lines {
        let f: Vec<&str> = line.split(' ').collect();
        let [slot, state, uuid, size] = f.as_slice() else {
            return Err("record-line");
        };
        if !anchor_slot_ok(slot) || !valid_uuid(uuid) {
            return Err("record-line");
        }
        let state = match *state {
            "formatting" => RecordState::Formatting,
            "ready" => RecordState::Ready,
            _ => return Err("record-state"),
        };
        let size_gib = parse_gib(size).ok_or("record-size")?;
        let entry = RecordEntry {
            state,
            uuid: (*uuid).to_string(),
            size_gib,
        };
        if out.insert((*slot).to_string(), entry).is_some() {
            return Err("record-slot-repeated");
        }
    }
    Ok(out)
}

pub fn render_record(record: &Record) -> String {
    let mut s = format!("{RECORD_MAGIC}\n");
    for (slot, e) in record {
        let state = match e.state {
            RecordState::Formatting => "formatting",
            RecordState::Ready => "ready",
        };
        s.push_str(&format!("{slot} {state} {} {}\n", e.uuid, e.size_gib));
    }
    s
}

/// A slot's verdict, as the receipt carries it (`disk_io` state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    Attached,
    Missing,
    Mismatch,
}

impl SlotState {
    pub fn as_str(self) -> &'static str {
        match self {
            SlotState::Attached => "attached",
            SlotState::Missing => "missing",
            SlotState::Mismatch => "mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub slot: String,
    pub state: SlotState,
    /// The anchored size class (0 when the anchor itself was refused).
    pub gib: u64,
    /// The kernel device name (`vdb`), when one was found.
    pub dev: Option<String>,
    /// A closed reason code (`-` when attached).
    pub reason: &'static str,
}

/// The state file the telemetry agent and `hippius-disks` read.
pub fn render_state(outcomes: &[Outcome]) -> String {
    let mut s = format!("{STATE_MAGIC}\n");
    for o in outcomes {
        s.push_str(&format!(
            "{} {} {} {} {}\n",
            o.slot,
            o.state.as_str(),
            o.gib,
            o.dev.as_deref().unwrap_or("-"),
            o.reason
        ));
    }
    s
}

/// Why an open did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenFail {
    /// The header is not one this guest writes (or not the recorded one).
    Header(String),
    /// cryptsetup refused (the header does not accept our key, or I/O).
    Refused(String),
}

/// What the opener needs to know about a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevInfo {
    pub size_bytes: u64,
    pub is_partition: bool,
    pub in_use: bool,
}

/// The host side of the opener: devices, cryptsetup and the record. A
/// trait so the decisions are unit-tested without root.
pub trait Host {
    /// The canonical block device `virtio-hippius-<slot>` resolves to.
    fn resolve(&self, slot: &str) -> Option<PathBuf>;
    fn info(&self, dev: &Path) -> Result<DevInfo, String>;
    /// `len` bytes at `offset` (fewer at the end of the device).
    fn read_at(&self, dev: &Path, offset: u64, len: usize) -> Result<Vec<u8>, String>;
    /// The LUKS UUID, or `None` when the device carries no LUKS header.
    fn luks_uuid(&self, dev: &Path) -> Option<String>;
    fn mapper_exists(&self, name: &str) -> bool;
    fn format(&mut self, dev: &Path, uuid: &str, slot: &str, key: &[u8]) -> Result<(), String>;
    /// Open `dev` as `name` by volume key, from a header that carries
    /// `uuid` and passes [`check_header_json`] — checked on the very bytes
    /// the activation reads.
    fn open(&mut self, dev: &Path, name: &str, key: &[u8], uuid: &str) -> Result<(), OpenFail>;
    /// Check the ACTIVE mapping (what the kernel loaded, not the header).
    fn verify_active(&self, name: &str, dev: &Path) -> Result<(), String>;
    /// Remove the mapping; `false` when it is still there afterwards.
    fn close(&mut self, name: &str) -> bool;
    fn new_uuid(&mut self) -> Result<String, String>;
    fn write_record(&mut self, record: &Record) -> Result<(), String>;
}

/// The device-mapper name of a slot: `hippius-<slot>`.
pub fn mapper_name(slot: &str) -> String {
    format!("{SLOT_SERIAL_PREFIX}{slot}")
}

fn dev_name(dev: &Path) -> Option<String> {
    dev.file_name().and_then(|n| n.to_str()).map(str::to_string)
}

/// A known on-disk signature in `head` (a device's first bytes), if any.
/// The agent refuses to declare a disk with a signature (`blkid -p`); this
/// is the guest's own check before it formats anything, so a miner cannot
/// make the guest format a disk that holds data.
pub fn find_signature(head: &[u8]) -> Option<&'static str> {
    let at = |off: usize, magic: &[u8]| head.get(off..off + magic.len()) == Some(magic);
    const LUKS1_2: &[u8] = b"LUKS\xba\xbe";
    const LUKS2_2ND: &[u8] = b"SKUL\xba\xbe";
    if at(0, LUKS1_2) {
        return Some("luks");
    }
    for off in [
        0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000,
    ] {
        if at(off, LUKS2_2ND) {
            return Some("luks");
        }
    }
    // GPT header at LBA 1, for every logical block size from 512 B to 64 KiB.
    if (9..=16).any(|shift| at(1 << shift, b"EFI PART")) {
        return Some("gpt");
    }
    let checks: [(usize, &[u8], &'static str); 10] = [
        (510, b"\x55\xaa", "mbr"),
        (1080, b"\x53\xef", "ext"),
        (0, b"XFSB", "xfs"),
        (0x10040, b"_BHRfS_M", "btrfs"),
        (4096, b"\xfc\x4e\x2b\xa9", "md"),
        (0, b"\xfc\x4e\x2b\xa9", "md"),
        (0, b"hsqs", "squashfs"),
        (0, b"verity\0\0", "verity"),
        (4086, b"SWAPSPACE2", "swap"),
        (0x400, b"\x10\x20\xf5\xf2", "f2fs"),
    ];
    for (off, magic, name) in checks {
        if at(off, magic) {
            return Some(name);
        }
    }
    // LVM2 PV label: "LABELONE" in one of the first four sectors.
    for sector in 0..4 {
        if at(sector * 512, b"LABELONE") {
            return Some("lvm");
        }
    }
    // ZFS: the uberblock magic (either byte order) in the uberblock ring of
    // label 0 (at 0) or label 1 (at 256 KiB); each ring starts 128 KiB into
    // its 256 KiB label.
    let zfs_le = 0x00ba_b10c_u64.to_le_bytes();
    let zfs_be = 0x00ba_b10c_u64.to_be_bytes();
    for label in [0usize, 256 << 10] {
        let mut off = label + (128 << 10);
        while off + 8 <= label + (256 << 10) {
            if at(off, &zfs_le) || at(off, &zfs_be) {
                return Some("zfs");
            }
            off += 1024;
        }
    }
    None
}

/// A known signature in `tail`, the last `tail.len()` bytes of a device
/// of `size` bytes: what lives at the END of a disk (mdadm 1.0 and 0.90
/// superblocks, the GPT backup header, ZFS labels L2/L3).
pub fn find_tail_signature(tail: &[u8], size: u64) -> Option<&'static str> {
    let base = size.checked_sub(tail.len() as u64)?;
    let at = |abs: u64, magic: &[u8]| {
        abs.checked_sub(base)
            .and_then(|o| usize::try_from(o).ok())
            .and_then(|o| tail.get(o..o + magic.len()))
            == Some(magic)
    };
    const MD_MAGIC: &[u8] = b"\xfc\x4e\x2b\xa9";
    // md 1.0: 8-12 KiB from the end, 4 KiB aligned.
    if let Some(sb) = (size / 512).checked_sub(16).map(|s| (s & !7) * 512) {
        if at(sb, MD_MAGIC) {
            return Some("md");
        }
    }
    // md 0.90: the last 64 KiB-aligned 64 KiB block; host-endian, so the
    // magic of a member made on a big-endian host is byte-swapped.
    if let Some(sb) = (size & !0xffff).checked_sub(0x10000) {
        if at(sb, MD_MAGIC) || at(sb, b"\xa9\x2b\x4e\xfc") {
            return Some("md");
        }
    }
    // GPT backup header in the last LBA, for every logical block size from
    // 512 B to 64 KiB.
    for shift in 9..=16u32 {
        if size
            .checked_sub(1 << shift)
            .is_some_and(|o| at(o, b"EFI PART"))
        {
            return Some("gpt");
        }
    }
    // ZFS labels L2 and L3 (each 256 KiB, uberblock ring from +128 KiB).
    let label_end = size & !((256 << 10) - 1);
    let zfs_le = 0x00ba_b10c_u64.to_le_bytes();
    let zfs_be = 0x00ba_b10c_u64.to_be_bytes();
    for label in [512u64 << 10, 256 << 10] {
        let Some(start) = label_end.checked_sub(label) else {
            continue;
        };
        let mut off = start + (128 << 10);
        while off + 8 <= start + (256 << 10) {
            if at(off, &zfs_le) || at(off, &zfs_be) {
                return Some("zfs");
            }
            off += 1024;
        }
    }
    None
}

fn mismatch(slot: &AnchorSlot, dev: Option<String>, reason: &'static str) -> Outcome {
    Outcome {
        slot: slot.slot.clone(),
        state: SlotState::Mismatch,
        gib: slot.gib,
        dev,
        reason,
    }
}

/// Open by volume key, then hold the live mapping to what we asked for.
fn open_verified<H: Host>(
    host: &mut H,
    slot: &AnchorSlot,
    dev: &Path,
    key: &[u8],
    uuid: &str,
) -> Result<(), &'static str> {
    let name = mapper_name(&slot.slot);
    host.open(dev, &name, key, uuid).map_err(|e| match e {
        OpenFail::Header(e) => {
            eprintln!(
                "hippius-guest-release: dedicated {}: header refused: {e}",
                slot.slot
            );
            "bad-header"
        }
        OpenFail::Refused(e) => {
            eprintln!("hippius-guest-release: dedicated {}: open: {e}", slot.slot);
            "open-failed"
        }
    })?;
    if let Err(e) = host.verify_active(&name, dev) {
        eprintln!(
            "hippius-guest-release: dedicated {}: active mapping refused: {e}",
            slot.slot
        );
        host.close(&name);
        return Err("bad-mapping");
    }
    Ok(())
}

/// First format of a slot whose UUID is already recorded `formatting`.
fn format_recorded<H: Host>(
    host: &mut H,
    record: &mut Record,
    slot: &AnchorSlot,
    dev: &Path,
    uuid: &str,
    key: &[u8],
) -> Result<(), &'static str> {
    host.format(dev, uuid, &slot.slot, key).map_err(|e| {
        eprintln!(
            "hippius-guest-release: dedicated {}: luksFormat: {e}",
            slot.slot
        );
        "format-failed"
    })?;
    if host.luks_uuid(dev).as_deref() != Some(uuid) {
        return Err("format-failed");
    }
    open_verified(host, slot, dev, key, uuid)?;
    promote(host, record, slot)
}

/// `formatting` → `ready` once the slot opened. The mapping is handed to
/// the tenant ONLY once `ready` is durable: `formatting` means "nothing was
/// ever opened under this UUID", the premise that lets a later boot format
/// a header-less device again. A failed write closes the mapping again.
fn promote<H: Host>(
    host: &mut H,
    record: &mut Record,
    slot: &AnchorSlot,
) -> Result<(), &'static str> {
    let Some(e) = record.get_mut(&slot.slot) else {
        return Err("record-write-failed");
    };
    if e.state == RecordState::Ready {
        return Ok(());
    }
    e.state = RecordState::Ready;
    if let Err(err) = host.write_record(record) {
        eprintln!(
            "hippius-guest-release: dedicated {}: record update: {err}",
            slot.slot
        );
        if let Some(e) = record.get_mut(&slot.slot) {
            e.state = RecordState::Formatting;
        }
        if !host.close(&mapper_name(&slot.slot)) {
            // Still mapped under a `formatting` record. Not worth a failed
            // boot: a later re-format of a header-less device writes the
            // same header (same UUID, same derived volume key, same data
            // offset) and touches no data sector, so nothing written
            // through this mapping is lost.
            eprintln!(
                "hippius-guest-release: dedicated {}: WARNING could not close the mapping after a failed record write",
                slot.slot
            );
            return Err("record-write-failed-mapped");
        }
        return Err("record-write-failed");
    }
    Ok(())
}

/// May the guest put a NEW header on this device? Only when it carries no
/// LUKS header (cryptsetup's view) AND no signature at all (ours).
fn blank<H: Host>(host: &H, dev: &Path, size: u64) -> Result<(), &'static str> {
    if host.luks_uuid(dev).is_some() {
        return Err("not-blank");
    }
    let head = host.read_at(dev, 0, HEAD_LEN).map_err(|_| "unreadable")?;
    let tail_off = size.saturating_sub(TAIL_LEN as u64);
    let tail = host
        .read_at(dev, tail_off, TAIL_LEN)
        .map_err(|_| "unreadable")?;
    if tail.len() as u64 != size - tail_off {
        return Err("unreadable");
    }
    match find_signature(&head).or_else(|| find_tail_signature(&tail, size)) {
        Some(sig) => {
            eprintln!("hippius-guest-release: dedicated: refusing to format a device with a {sig} signature");
            Err("not-blank")
        }
        None => Ok(()),
    }
}

fn open_slot<H: Host>(
    host: &mut H,
    record: &mut Record,
    slot: &AnchorSlot,
    dev: &Path,
    size: u64,
    key: &[u8],
) -> Result<(), &'static str> {
    match record.get(&slot.slot).cloned() {
        Some(RecordEntry {
            state: RecordState::Ready,
            uuid,
            ..
        }) => match host.luks_uuid(dev) {
            None => Err("no-header"),
            Some(u) if u != uuid => Err("uuid-mismatch"),
            Some(_) => open_verified(host, slot, dev, key, &uuid),
        },
        Some(RecordEntry {
            state: RecordState::Formatting,
            uuid,
            ..
        }) => match host.luks_uuid(dev) {
            // The format finished; only the promotion was lost.
            Some(u) if u == uuid => {
                open_verified(host, slot, dev, key, &uuid)?;
                promote(host, record, slot)
            }
            Some(_) => Err("uuid-mismatch"),
            // Never formatted (or the header never landed): nothing was
            // ever opened under this UUID, so formatting again loses
            // nothing.
            None => {
                blank(host, dev, size)?;
                format_recorded(host, record, slot, dev, &uuid, key)
            }
        },
        None => {
            blank(host, dev, size)?;
            let uuid = host.new_uuid().map_err(|_| "uuid-failed")?;
            if !valid_uuid(&uuid) {
                return Err("uuid-failed");
            }
            // Recorded BEFORE the header exists: a header with this UUID
            // is then always ours, whatever happens next.
            record.insert(
                slot.slot.clone(),
                RecordEntry {
                    state: RecordState::Formatting,
                    uuid: uuid.clone(),
                    size_gib: slot.gib,
                },
            );
            if let Err(e) = host.write_record(record) {
                eprintln!(
                    "hippius-guest-release: dedicated {}: record write: {e}",
                    slot.slot
                );
                record.remove(&slot.slot);
                return Err("record-write-failed");
            }
            format_recorded(host, record, slot, dev, &uuid, key)
        }
    }
}

/// Process every anchored slot. `record` is `Err` when the record exists
/// but cannot be read: no slot is then formatted or opened.
pub fn process<H: Host>(
    host: &mut H,
    slots: &[AnchorSlot],
    vm_id: &str,
    kek: &[u8],
    record: Result<Record, &'static str>,
) -> Vec<Outcome> {
    let mut record = match record {
        Ok(r) => r,
        Err(reason) => {
            return slots
                .iter()
                .map(|s| {
                    let dev = host.resolve(&s.slot);
                    let state = if dev.is_some() {
                        SlotState::Mismatch
                    } else {
                        SlotState::Missing
                    };
                    Outcome {
                        slot: s.slot.clone(),
                        state,
                        gib: s.gib,
                        dev: dev.as_deref().and_then(dev_name),
                        reason: if dev.is_some() { reason } else { "absent" },
                    }
                })
                .collect();
        }
    };
    let resolved: Vec<Option<PathBuf>> = slots.iter().map(|s| host.resolve(&s.slot)).collect();
    let mut seen: BTreeMap<PathBuf, usize> = BTreeMap::new();
    for d in resolved.iter().flatten() {
        *seen.entry(d.clone()).or_default() += 1;
    }
    let mut out = Vec::with_capacity(slots.len());
    for (slot, dev) in slots.iter().zip(resolved) {
        let Some(dev) = dev else {
            out.push(Outcome {
                slot: slot.slot.clone(),
                state: SlotState::Missing,
                gib: slot.gib,
                dev: None,
                reason: "absent",
            });
            continue;
        };
        let name = dev_name(&dev);
        if seen.get(&dev).copied().unwrap_or(0) > 1 {
            out.push(mismatch(slot, name, "duplicate"));
            continue;
        }
        let info = match host.info(&dev) {
            Ok(i) => i,
            Err(_) => {
                out.push(mismatch(slot, name, "unreadable"));
                continue;
            }
        };
        if info.is_partition {
            out.push(mismatch(slot, name, "not-whole-disk"));
            continue;
        }
        if info.size_bytes < slot.gib.saturating_mul(1 << 30) {
            out.push(mismatch(slot, name, "too-small"));
            continue;
        }
        if info.in_use || host.mapper_exists(&mapper_name(&slot.slot)) {
            out.push(mismatch(slot, name, "in-use"));
            continue;
        }
        let key = slot_key(kek, vm_id, &slot.slot);
        match open_slot(host, &mut record, slot, &dev, info.size_bytes, key.as_ref()) {
            Ok(()) => out.push(Outcome {
                slot: slot.slot.clone(),
                state: SlotState::Attached,
                gib: slot.gib,
                dev: name,
                reason: "-",
            }),
            Err(reason) => out.push(mismatch(slot, name, reason)),
        }
    }
    out
}

/// A malformed anchor: report every device carrying a dedicated slot
/// serial as `mismatch` (nothing is opened), so vali sees the refusal.
pub fn refused_anchor_outcomes(by_id: &Path, reason: &'static str) -> Vec<Outcome> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(by_id) else {
        return out;
    };
    let mut found: BTreeMap<String, Option<String>> = BTreeMap::new();
    for e in entries.flatten() {
        let Some(slot) = e
            .file_name()
            .to_str()
            .and_then(|n| n.strip_prefix("virtio-"))
            .and_then(|s| s.strip_prefix(SLOT_SERIAL_PREFIX))
            .map(str::to_string)
        else {
            continue;
        };
        if slot == "os" || !is_valid_slot(&slot) {
            continue;
        }
        let dev = std::fs::canonicalize(e.path())
            .ok()
            .as_deref()
            .and_then(dev_name);
        found.insert(slot, dev);
    }
    for (slot, dev) in found {
        let state = if dev.is_some() {
            SlotState::Mismatch
        } else {
            SlotState::Missing
        };
        out.push(Outcome {
            slot,
            state,
            gib: 0,
            dev,
            reason,
        });
    }
    out
}

// ── The real host ───────────────────────────────────────────────────

/// Devices under `/dev/disk/by-id`, sysfs under `/sys/class/block`, the
/// real `cryptsetup`, the record at `<volume_root>/.hippius-dedicated-disks`.
pub struct SysHost {
    pub by_id: PathBuf,
    pub sys_block: PathBuf,
    pub volume_root: PathBuf,
    pub cryptsetup: PathBuf,
    /// A guest-RAM (tmpfs) directory for the verified header copy.
    pub scratch: PathBuf,
}

/// The key on the child's stdin, read through `/proc/self/fd/0` (an
/// initramfs has `/proc`, not necessarily `/dev/stdin`).
const STDIN_PATH: &str = "/proc/self/fd/0";

fn run_with_key(mut cmd: Command, key_bytes: &[u8]) -> Result<(), String> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn: {}", e.kind()))?;
    let write = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(key_bytes).map_err(|e| e.kind()),
        None => Err(std::io::ErrorKind::BrokenPipe),
    };
    let status = child.wait().map_err(|e| format!("wait: {}", e.kind()))?;
    if let Err(kind) = write {
        return Err(format!("key pipe: {kind}"));
    }
    if !status.success() {
        return Err(format!("cryptsetup exit {:?}", status.code()));
    }
    Ok(())
}

/// The LUKS2 metadata (`cryptsetup luksDump --dump-json-metadata`) of a
/// header this guest would have written: one `crypt` segment,
/// aes-xts-plain64, no integrity, no requirements (no reencryption in
/// flight: a half-reencrypted device activates part of itself under the
/// OLD segment, which a forger would make `linear` or `cipher_null`), only
/// plain `luks2` keyslots, one digest, no tokens. Pure, for the tests.
pub fn check_header_json(text: &str) -> Result<(), String> {
    use serde_json::Value;
    let v: Value = serde_json::from_str(text).map_err(|_| "metadata: not JSON".to_string())?;
    let obj = |k: &str| v.get(k).and_then(Value::as_object);
    let segments = obj("segments").ok_or("metadata: no segments")?;
    let [(id, seg)] = segments.iter().collect::<Vec<_>>()[..] else {
        return Err(format!("metadata: {} segments", segments.len()));
    };
    let field = |k: &str| seg.get(k).and_then(Value::as_str);
    let offset = DATA_OFFSET_BYTES.to_string();
    if id != "0"
        || field("type") != Some("crypt")
        || field("encryption") != Some("aes-xts-plain64")
        || field("offset") != Some(offset.as_str())
        || seg.get("sector_size").and_then(Value::as_u64) != Some(SECTOR_SIZE)
        || seg.get("integrity").is_some()
        || seg
            .get("flags")
            .is_some_and(|f| f.as_array().is_some_and(|a| !a.is_empty()))
    {
        return Err(format!(
            "metadata: segment {id} is not the plain aes-xts-plain64 crypt segment this guest formats"
        ));
    }
    if let Some(cfg) = obj("config") {
        let mandatory = cfg
            .get("requirements")
            .and_then(|r| r.get("mandatory"))
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if mandatory != 0 || cfg.get("requirements").is_some_and(|r| !r.is_object()) {
            return Err("metadata: requirements set (reencryption?)".into());
        }
    }
    let keyslots = obj("keyslots").ok_or("metadata: no keyslots")?;
    if keyslots
        .values()
        .any(|k| k.get("type").and_then(Value::as_str) != Some("luks2"))
    {
        return Err("metadata: a keyslot that is not plain luks2".into());
    }
    if obj("digests").map_or(0, |d| d.len()) != 1 {
        return Err("metadata: not exactly one digest".into());
    }
    if obj("tokens").is_some_and(|t| !t.is_empty()) {
        return Err("metadata: tokens present".into());
    }
    Ok(())
}

/// The fields of `cryptsetup status <name>` the opener holds a live
/// mapping to. Pure, for the tests.
pub fn check_status(text: &str, dev: &Path) -> Result<(), String> {
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.trim().split_once(':') {
            fields.insert(k.trim(), v.trim());
        }
    }
    let bad = |k: &str| format!("{k}={}", fields.get(k).unwrap_or(&"<none>"));
    let want = |k: &str, v: &str| -> Result<(), String> {
        (fields.get(k) == Some(&v))
            .then_some(())
            .ok_or_else(|| bad(k))
    };
    // A number and its unit, in either spelling: cryptsetup 2.7 prints
    // `512 bits` / `4096` / `32768 sectors`, 2.8 prints `512 [bits]` /
    // `4096 [bytes]` / `32768 [512-byte units] (16777216 [bytes])`.
    let want_num = |k: &str, n: u64, units: &[&str]| -> Result<(), String> {
        let v = fields.get(k).ok_or_else(|| bad(k))?;
        let (num, rest) = v.split_once(' ').unwrap_or((v, ""));
        let rest = rest.trim();
        let unit_ok = units
            .iter()
            .any(|u| rest == *u || (!u.is_empty() && rest.starts_with(&format!("{u} ("))));
        (num == n.to_string() && unit_ok)
            .then_some(())
            .ok_or_else(|| bad(k))
    };
    want("type", "LUKS2")?;
    want("cipher", "aes-xts-plain64")?;
    want_num("keysize", 512, &["bits", "[bits]"])?;
    want("device", &dev.display().to_string())?;
    want_num("sector size", SECTOR_SIZE, &["", "[bytes]"])?;
    want_num(
        "offset",
        DATA_OFFSET_BYTES / 512,
        &["sectors", "[512-byte units]"],
    )?;
    // An authenticated segment, a reencryption in flight, or hardware
    // (OPAL) encryption is not what this guest formats.
    for k in ["integrity", "reencryption", "encryption", "OPAL keysize"] {
        if fields.contains_key(k) {
            return Err(format!("unexpected `{k}`"));
        }
    }
    Ok(())
}

impl SysHost {
    fn open_from_copy(
        &self,
        dev: &Path,
        name: &str,
        key: &[u8],
        uuid: &str,
        copy: &Path,
    ) -> Result<(), OpenFail> {
        let status = Command::new(&self.cryptsetup)
            .arg("luksHeaderBackup")
            .arg(dev)
            .arg("--header-backup-file")
            .arg(copy)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| OpenFail::Refused(format!("luksHeaderBackup: {}", e.kind())))?;
        if !status.success() {
            return Err(OpenFail::Header("luksHeaderBackup failed".into()));
        }
        if self.luks_uuid(copy).as_deref() != Some(uuid) {
            return Err(OpenFail::Header(
                "the copied header is not the recorded one".into(),
            ));
        }
        let dump = Command::new(&self.cryptsetup)
            .args(["luksDump", "--dump-json-metadata"])
            .arg(copy)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| OpenFail::Refused(format!("luksDump: {}", e.kind())))?;
        if !dump.status.success() {
            return Err(OpenFail::Header("luksDump failed".into()));
        }
        check_header_json(&String::from_utf8_lossy(&dump.stdout)).map_err(OpenFail::Header)?;
        let mut cmd = Command::new(&self.cryptsetup);
        cmd.args(["open", "--type", "luks2", "--header"])
            .arg(copy)
            .args(["--volume-key-file", STDIN_PATH])
            .arg(dev)
            .arg(name);
        run_with_key(cmd, key).map_err(OpenFail::Refused)
    }
}

impl Host for SysHost {
    fn resolve(&self, slot: &str) -> Option<PathBuf> {
        let link = self
            .by_id
            .join(format!("virtio-{SLOT_SERIAL_PREFIX}{slot}"));
        let dev = std::fs::canonicalize(link).ok()?;
        let meta = std::fs::metadata(&dev).ok()?;
        meta.file_type().is_block_device().then_some(dev)
    }

    fn info(&self, dev: &Path) -> Result<DevInfo, String> {
        let name = dev_name(dev).ok_or("no name")?;
        let sys = self.sys_block.join(&name);
        let sectors: u64 = std::fs::read_to_string(sys.join("size"))
            .map_err(|e| format!("size: {}", e.kind()))?
            .trim()
            .parse()
            .map_err(|_| "size: not a number".to_string())?;
        let in_use = std::fs::read_dir(sys.join("holders"))
            .map_err(|e| format!("holders: {}", e.kind()))?
            .next()
            .is_some();
        Ok(DevInfo {
            size_bytes: sectors.saturating_mul(512),
            is_partition: sys.join("partition").exists(),
            in_use,
        })
    }

    fn read_at(&self, dev: &Path, offset: u64, len: usize) -> Result<Vec<u8>, String> {
        use std::io::{Seek, SeekFrom};
        let mut f = std::fs::File::open(dev).map_err(|e| format!("open: {}", e.kind()))?;
        f.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("seek: {}", e.kind()))?;
        let mut buf = Vec::with_capacity(len);
        f.take(len as u64)
            .read_to_end(&mut buf)
            .map_err(|e| format!("read: {}", e.kind()))?;
        Ok(buf)
    }

    fn luks_uuid(&self, dev: &Path) -> Option<String> {
        let out = Command::new(&self.cryptsetup)
            .arg("luksUUID")
            .arg(dev)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8(out.stdout).ok()?;
        let s = s.trim().to_ascii_lowercase();
        // A LUKS header whose UUID we cannot read is still a header: an
        // empty string never equals a recorded UUID and blocks a format.
        Some(if valid_uuid(&s) { s } else { String::new() })
    }

    fn mapper_exists(&self, name: &str) -> bool {
        Path::new("/dev/mapper").join(name).exists()
    }

    fn format(&mut self, dev: &Path, uuid: &str, slot: &str, key: &[u8]) -> Result<(), String> {
        let mut cmd = Command::new(&self.cryptsetup);
        cmd.args([
            "luksFormat",
            "--batch-mode",
            "--type",
            "luks2",
            "--cipher",
            "aes-xts-plain64",
            "--key-size",
            "512",
            "--hash",
            "sha256",
            // The keyslot passphrase is the 512-bit key itself: no
            // stretching buys anything, and argon2's memory cost in an
            // initramfs would only risk an OOM.
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
            // The layout, pinned (see DATA_OFFSET_BYTES): 16 MiB of header
            // + keyslots, data from 16 MiB (`--offset` is in 512-byte
            // sectors), 4096-byte encryption sectors.
            "--luks2-metadata-size",
            "16k",
            "--luks2-keyslots-size",
            "16744448",
            "--offset",
            "32768",
            "--sector-size",
            "4096",
            "--uuid",
            uuid,
            "--label",
            &mapper_name(slot),
            "--volume-key-file",
            STDIN_PATH,
            "--key-file",
            STDIN_PATH,
            "--keyfile-size",
            "64",
        ])
        .arg(dev);
        // Both files are the same 64 bytes: whichever cryptsetup reads
        // first takes the first copy.
        let mut both = Zeroizing::new(Vec::with_capacity(2 * key.len()));
        both.extend_from_slice(key);
        both.extend_from_slice(key);
        run_with_key(cmd, &both)
    }

    fn open(&mut self, dev: &Path, name: &str, key: &[u8], uuid: &str) -> Result<(), OpenFail> {
        // The host can rewrite the header between any two reads, so the
        // checks and the activation must see the SAME bytes: copy the
        // header into guest RAM, check the copy, activate from the copy
        // (the #296 detached-header pattern).
        let copy = self.scratch.join(format!(".header-{name}"));
        let _ = std::fs::remove_file(&copy);
        let result = self.open_from_copy(dev, name, key, uuid, &copy);
        let _ = std::fs::remove_file(&copy);
        result
    }

    fn verify_active(&self, name: &str, dev: &Path) -> Result<(), String> {
        let out = Command::new(&self.cryptsetup)
            .args(["status", name])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| format!("status: {}", e.kind()))?;
        if !out.status.success() {
            return Err("status: not active".into());
        }
        check_status(&String::from_utf8_lossy(&out.stdout), dev)
    }

    fn close(&mut self, name: &str) -> bool {
        let _ = Command::new(&self.cryptsetup)
            .args(["close", name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        !self.mapper_exists(name)
    }

    fn new_uuid(&mut self) -> Result<String, String> {
        let s = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
            .map_err(|e| format!("uuid: {}", e.kind()))?;
        Ok(s.trim().to_ascii_lowercase())
    }

    fn write_record(&mut self, record: &Record) -> Result<(), String> {
        write_atomic(
            &self.volume_root.join(RECORD_NAME),
            render_record(record).as_bytes(),
            0o600,
        )
    }
}

/// tmp + fsync + rename + fsync(dir).
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let dir = path.parent().ok_or("no parent")?;
    let name = path.file_name().and_then(|n| n.to_str()).ok_or("no name")?;
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|e| format!("create: {}", e.kind()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("write: {}", e.kind()))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| format!("rename: {}", e.kind()))?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("sync dir: {}", e.kind()))?;
    Ok(())
}

/// Read the record: absent ⇒ empty; present but unreadable or malformed
/// ⇒ `Err` (no slot is formatted or opened).
pub fn load_record(volume_root: &Path) -> Result<Record, &'static str> {
    let path = volume_root.join(RECORD_NAME);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Record::new()),
        Err(_) => return Err("record-unreadable"),
        Ok(m) if !m.is_file() || m.len() > 64 * 1024 => return Err("record-unreadable"),
        Ok(_) => {}
    }
    let text = std::fs::read_to_string(&path).map_err(|_| "record-unreadable")?;
    parse_record(&text)
}

/// Wait (bounded) until every anchored slot's link exists.
pub fn wait_for_slots(host: &SysHost, slots: &[AnchorSlot], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while slots.iter().any(|s| host.resolve(&s.slot).is_none()) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The 32-byte KEK keyfile.
pub fn read_kek(path: &Path) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut f = std::fs::File::open(path).map_err(|_| "kek-unreadable")?;
    let mut buf = Zeroizing::new(Vec::with_capacity(33));
    Read::by_ref(&mut f)
        .take(33)
        .read_to_end(&mut buf)
        .map_err(|_| "kek-unreadable")?;
    if buf.len() != 32 {
        return Err("kek-length");
    }
    Ok(buf)
}

/// The whole mode. `Err` only when the state file cannot be written.
pub fn run(
    cmdline: &str,
    kek_file: &Path,
    host: &mut SysHost,
    state_out: &Path,
) -> Result<Vec<Outcome>, String> {
    let outcomes = match parse_anchor(cmdline) {
        Anchor::Absent => {
            eprintln!(
                "hippius-guest-release: dedicated: no anchor on the cmdline — nothing to open"
            );
            return Ok(Vec::new());
        }
        Anchor::Malformed(reason) => {
            eprintln!("hippius-guest-release: dedicated: anchor REFUSED ({reason}) — no dedicated disk is opened");
            refused_anchor_outcomes(&host.by_id, reason)
        }
        Anchor::Valid { slots, vm_id } => {
            if let Err(e) = std::fs::create_dir_all(&host.scratch) {
                eprintln!(
                    "hippius-guest-release: dedicated: scratch dir: {}",
                    e.kind()
                );
            }
            wait_for_slots(host, &slots, DEVICE_WAIT);
            match read_kek(kek_file) {
                Ok(kek) => {
                    let record = load_record(&host.volume_root);
                    process(host, &slots, &vm_id, &kek, record)
                }
                Err(reason) => {
                    eprintln!(
                        "hippius-guest-release: dedicated: {reason} — no dedicated disk is opened"
                    );
                    process(host, &slots, &vm_id, &[], Err(reason))
                }
            }
        }
    };
    for o in &outcomes {
        eprintln!(
            "hippius-guest-release: dedicated {}: {} ({}, {} GiB, dev {})",
            o.slot,
            o.state.as_str(),
            o.reason,
            o.gib,
            o.dev.as_deref().unwrap_or("-")
        );
    }
    if let Some(dir) = state_out.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("state dir: {}", e.kind()))?;
    }
    write_atomic(state_out, render_state(&outcomes).as_bytes(), 0o644)?;
    Ok(outcomes)
}

#[cfg(test)]
#[path = "dedicated_tests.rs"]
mod tests;
