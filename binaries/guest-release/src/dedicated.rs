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
//! - the measured cmdline: `hippius.dedicated=x0:<GiB>,x1:<GiB>:i,…` (the
//!   anchor; absent ⇒ this mode does nothing at all; `:i` marks an
//!   integrity slot, guest release 8) and `hippius.vm_id=`;
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
//! ## Integrity slots (`:i`, guest release 8)
//!
//! Same flow, with LUKS2 AEAD (aes-xts-plain64 + hmac-sha256, the OS
//! overlay's family) and a 96-byte key under its own salt
//! ([`integrity_slot_key`]). dm-integrity needs every sector written once
//! before it reads back, which takes about an hour on a large disk, so the
//! initramfs only formats (`--integrity-no-wipe`, instant), opens the slot
//! as `hippius-<slot>-init` with no journal, writes its first and last
//! [`PRIME_BYTES`] while udev is paused (so no probe ever reads an
//! unwritten sector), and reports it `initializing`. The booted OS's
//! `--dedicated-init-wipe` ([`crate::dedicated_init`]) writes the rest
//! THROUGH THAT MAPPING, records `ready`, switches it to the journal and
//! renames it `hippius-<slot>`. The key never leaves this process: the
//! hand-over to userspace is the open device-mapper mapping, which is
//! exactly what the tenant gets anyway. The record stays `formatting` until
//! the wipe is done, so an interrupted wipe starts again from scratch on
//! the next boot and a finished one is never redone.
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
/// HKDF salt of an integrity slot's key: a domain of its own, so the two
/// derivations never share bytes (HKDF output is prefix-stable in `L`).
pub const HKDF_SALT_INTEGRITY: &[u8] = b"hippius-dedicated-disk-aead-v1";
/// An integrity slot's LUKS2 volume key: the aes-xts-plain64 512-bit key
/// followed by the hmac-sha256 256-bit key (cryptsetup's layout for
/// `--integrity hmac-sha256`; the keyslot reports 768 bits).
pub const INTEGRITY_KEY_LEN: usize = 96;
/// The anchor suffix of an integrity slot (`x0:22300:i`).
pub const INTEGRITY_SUFFIX: &str = "i";
/// The device-mapper name suffix of an integrity slot while its first-boot
/// wipe runs: `hippius-<slot>-init`, never a name the tenant's config uses.
pub const INIT_SUFFIX: &str = "-init";
/// The file next to the state file naming the slots handed to the booted
/// OS's wipe (one slot per line); its presence starts the wipe unit.
pub const INIT_LIST_NAME: &str = "init";
/// How much of an integrity slot's mapping the initramfs writes at each
/// end before udev may look at it: every signature blkid, mdadm, LVM or
/// ZFS probe for sits in the first or last few MiB.
pub const PRIME_BYTES: u64 = 8 << 20;
/// The record, at the root of the guest-keyed OS volume (next to the
/// anti-rollback stamp: not reachable through the tenant's merged root).
pub const RECORD_NAME: &str = ".hippius-dedicated-disks";
const RECORD_MAGIC: &str = "hippius-dedicated-disks v1";
pub const STATE_MAGIC: &str = "# hippius-dedicated-disks state v1";
/// Where the opener leaves the slot states (the shell step's
/// `HIPPIUS_DEDICATED_STATE`), read by telemetry and `hippius-disks`.
pub const DEFAULT_STATE_PATH: &str = "/run/hippius/dedicated/slots";
/// The guest-keyed OS volume's device (`HIPPIUS_GOLDEN_UPPER_MAPPER`):
/// the booted OS's wipe mounts it, in its private mount namespace, to
/// reach the record.
pub const UPPER_DEVICE: &str = "/dev/mapper/hippius-upper";
/// Where that wipe mounts it.
pub const INIT_VOLUME_MOUNT: &str = "/run/hippius/dedicated/.volume";
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
    /// `:i`: LUKS2 with AEAD integrity (guest release 8).
    pub integrity: bool,
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

fn parse_gib(s: &str, min_gib: u64) -> Option<u64> {
    if s.is_empty() || s.len() > 7 || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let v: u64 = s.parse().ok()?;
    (min_gib..=MAX_GIB).contains(&v).then_some(v)
}

/// Parse the anchor strictly. Any doubt is [`Anchor::Malformed`]: the
/// guest never guesses which disk is which or how large it must be.
#[cfg(test)]
pub fn parse_anchor(cmdline: &str) -> Anchor {
    parse_anchor_min(cmdline, MIN_GIB)
}

/// [`parse_anchor`] with the smallest size class as a parameter: the
/// end-to-end test (`--dedicated-test-min-gib`, never passed at boot) runs
/// on loop devices far below [`MIN_GIB`].
pub fn parse_anchor_min(cmdline: &str, min_gib: u64) -> Anchor {
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
        // `<slot>:<GiB>` or `<slot>:<GiB>:i`, nothing else.
        let parts: Vec<&str> = e.split(':').collect();
        let (slot, gib, mode) = match parts.as_slice() {
            [slot, gib] => (*slot, *gib, None),
            [slot, gib, mode] => (*slot, *gib, Some(*mode)),
            _ => return Anchor::Malformed("anchor-entry"),
        };
        if !anchor_slot_ok(slot) {
            return Anchor::Malformed("anchor-slot");
        }
        let Some(gib) = parse_gib(gib, min_gib) else {
            return Anchor::Malformed("anchor-size");
        };
        let integrity = match mode {
            None => false,
            Some(INTEGRITY_SUFFIX) => true,
            Some(_) => return Anchor::Malformed("anchor-mode"),
        };
        if !seen.insert(slot) {
            return Anchor::Malformed("anchor-slot-repeated");
        }
        slots.push(AnchorSlot {
            slot: slot.to_string(),
            gib,
            integrity,
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

/// An integrity slot's volume key: `HKDF-SHA256(ikm = kek, salt =
/// "hippius-dedicated-disk-aead-v1", info = vm_id ‖ slot)`, 96 bytes
/// (aes-xts-plain64 512-bit ‖ hmac-sha256 256-bit).
pub fn integrity_slot_key(
    kek: &[u8],
    vm_id: &str,
    slot: &str,
) -> Zeroizing<[u8; INTEGRITY_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT_INTEGRITY), kek);
    let mut info = Zeroizing::new(Vec::with_capacity(vm_id.len() + slot.len()));
    info.extend_from_slice(vm_id.as_bytes());
    info.extend_from_slice(slot.as_bytes());
    let mut out = Zeroizing::new([0u8; INTEGRITY_KEY_LEN]);
    // 96 ≤ 255 × 32: expand cannot fail for this length.
    if hk.expand(&info, out.as_mut()).is_err() {
        out.as_mut().fill(0);
    }
    out
}

/// The volume key of `slot`, by its mode.
fn key_for(kek: &[u8], vm_id: &str, slot: &AnchorSlot) -> Zeroizing<Vec<u8>> {
    if slot.integrity {
        Zeroizing::new(integrity_slot_key(kek, vm_id, &slot.slot).to_vec())
    } else {
        Zeroizing::new(slot_key(kek, vm_id, &slot.slot).to_vec())
    }
}

/// Where a slot stands in the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordState {
    /// The UUID was chosen and recorded; `luksFormat` may not have
    /// finished. Nothing was ever handed to the tenant under it (for an
    /// integrity slot: its wipe has not finished).
    Formatting,
    /// Formatted and opened at least once: only this UUID is accepted.
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEntry {
    pub state: RecordState,
    pub uuid: String,
    pub size_gib: u64,
    /// An integrity slot (a 5th field, `integrity`; a plain slot's line is
    /// exactly what guest release 6/7 writes and reads).
    pub integrity: bool,
}

/// The record line field of an integrity slot.
const RECORD_INTEGRITY: &str = "integrity";

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
#[cfg(test)]
pub fn parse_record(text: &str) -> Result<Record, &'static str> {
    parse_record_min(text, MIN_GIB)
}

/// [`parse_record`] with the smallest size class as a parameter (the
/// end-to-end test's seam, see [`parse_anchor_min`]).
pub fn parse_record_min(text: &str, min_gib: u64) -> Result<Record, &'static str> {
    let mut lines = text.lines();
    if lines.next() != Some(RECORD_MAGIC) {
        return Err("record-magic");
    }
    let mut out = Record::new();
    for line in lines {
        let f: Vec<&str> = line.split(' ').collect();
        let (slot, state, uuid, size, integrity) = match f.as_slice() {
            [slot, state, uuid, size] => (slot, state, uuid, size, false),
            [slot, state, uuid, size, RECORD_INTEGRITY] => (slot, state, uuid, size, true),
            _ => return Err("record-line"),
        };
        if !anchor_slot_ok(slot) || !valid_uuid(uuid) {
            return Err("record-line");
        }
        let state = match *state {
            "formatting" => RecordState::Formatting,
            "ready" => RecordState::Ready,
            _ => return Err("record-state"),
        };
        let size_gib = parse_gib(size, min_gib).ok_or("record-size")?;
        let entry = RecordEntry {
            state,
            uuid: (*uuid).to_string(),
            size_gib,
            integrity,
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
        s.push_str(&format!("{slot} {state} {} {}", e.uuid, e.size_gib));
        if e.integrity {
            s.push_str(&format!(" {RECORD_INTEGRITY}"));
        }
        s.push('\n');
    }
    s
}

/// A slot's verdict, as the receipt carries it (`disk_io` state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    Attached,
    Missing,
    Mismatch,
    /// An integrity slot handed to the booted OS's wipe (its reason
    /// carries the progress, `init-<percent>`), not yet to the tenant.
    Initializing,
}

impl SlotState {
    pub fn as_str(self) -> &'static str {
        match self {
            SlotState::Attached => "attached",
            SlotState::Missing => "missing",
            SlotState::Mismatch => "mismatch",
            SlotState::Initializing => "initializing",
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
    /// `luksFormat` with the pinned layout; `integrity` adds AEAD
    /// (hmac-sha256) WITHOUT cryptsetup's wipe (the booted OS writes every
    /// sector through the mapping, see [`crate::dedicated_init`]).
    fn format(
        &mut self,
        dev: &Path,
        uuid: &str,
        slot: &str,
        key: &[u8],
        integrity: bool,
    ) -> Result<(), String>;
    /// Open `dev` as `name` by volume key, from a header that carries
    /// `uuid` and passes [`check_header_json`] for `mode` — checked on the
    /// very bytes the activation reads.
    fn open(
        &mut self,
        dev: &Path,
        name: &str,
        key: &[u8],
        uuid: &str,
        mode: OpenMode,
    ) -> Result<(), OpenFail>;
    /// Check the ACTIVE mapping (what the kernel loaded, not the header),
    /// its size included ([`mapped_size_ok`] for a `gib` size class).
    fn verify_active(&self, name: &str, dev: &Path, mode: OpenMode, gib: u64)
        -> Result<(), String>;
    /// Remove the mapping; `false` when it is still there afterwards.
    fn close(&mut self, name: &str) -> bool;
    /// Stop udev's event queue; `false` when it is not paused (no udev).
    fn pause_udev(&mut self) -> bool;
    /// Start it again.
    fn resume_udev(&mut self) -> Result<(), String>;
    /// Write zeros through the mapping `name`, [`PRIME_BYTES`] at each
    /// end, so whatever probes it next reads valid sectors there.
    fn prime(&mut self, name: &str) -> Result<(), String>;
    fn new_uuid(&mut self) -> Result<String, String>;
    fn write_record(&mut self, record: &Record) -> Result<(), String>;
}

/// How a slot is activated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// LUKS2 aes-xts-plain64, no integrity (guest release 6+).
    Plain,
    /// LUKS2 AEAD (aes-xts-plain64 + hmac-sha256), journaled: an integrity
    /// slot whose first-boot wipe is done.
    Integrity,
    /// The same volume without a journal, as `hippius-<slot>-init`: the
    /// mapping the booted OS wipes through (cryptsetup's own wipe runs
    /// journal-less too: journaling zeros only doubles the writes).
    IntegrityInit,
}

impl OpenMode {
    pub fn integrity(self) -> bool {
        self != OpenMode::Plain
    }
}

/// The device-mapper name of a slot: `hippius-<slot>`.
pub fn mapper_name(slot: &str) -> String {
    format!("{SLOT_SERIAL_PREFIX}{slot}")
}

/// The device-mapper name of an integrity slot while its first-boot wipe
/// runs: `hippius-<slot>-init`.
pub fn init_mapper_name(slot: &str) -> String {
    format!("{SLOT_SERIAL_PREFIX}{slot}{INIT_SUFFIX}")
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

fn open_fail_reason(slot: &AnchorSlot, e: OpenFail) -> &'static str {
    match e {
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
    }
}

/// Open by volume key as `hippius-<slot>`, then hold the live mapping to
/// what we asked for (plain, or an integrity slot whose wipe is done).
fn open_verified<H: Host>(
    host: &mut H,
    slot: &AnchorSlot,
    dev: &Path,
    key: &[u8],
    uuid: &str,
) -> Result<(), &'static str> {
    let name = mapper_name(&slot.slot);
    let mode = if slot.integrity {
        OpenMode::Integrity
    } else {
        OpenMode::Plain
    };
    host.open(dev, &name, key, uuid, mode)
        .map_err(|e| open_fail_reason(slot, e))?;
    if let Err(e) = host.verify_active(&name, dev, mode, slot.gib) {
        eprintln!(
            "hippius-guest-release: dedicated {}: active mapping refused: {e}",
            slot.slot
        );
        host.close(&name);
        return Err("bad-mapping");
    }
    Ok(())
}

/// Open a freshly formatted integrity slot as `hippius-<slot>-init` (no
/// journal) for the booted OS's wipe. udev is paused from just before the
/// mapping exists until its two ends are written, so no probe (blkid, md,
/// LVM, ZFS) ever reads a sector without a valid tag: the kernel would log
/// an AEAD error for each, and an integrity error must only ever mean
/// tampering. Any failure closes the mapping again (still paused).
fn open_init<H: Host>(
    host: &mut H,
    slot: &AnchorSlot,
    dev: &Path,
    key: &[u8],
    uuid: &str,
) -> Result<(), &'static str> {
    let name = init_mapper_name(&slot.slot);
    let paused = host.pause_udev();
    let result = (|| {
        host.open(dev, &name, key, uuid, OpenMode::IntegrityInit)
            .map_err(|e| open_fail_reason(slot, e))?;
        if let Err(e) = host.verify_active(&name, dev, OpenMode::IntegrityInit, slot.gib) {
            eprintln!(
                "hippius-guest-release: dedicated {}: active mapping refused: {e}",
                slot.slot
            );
            host.close(&name);
            return Err("bad-mapping");
        }
        if let Err(e) = host.prime(&name) {
            eprintln!(
                "hippius-guest-release: dedicated {}: priming the ends: {e}",
                slot.slot
            );
            host.close(&name);
            return Err("prime-failed");
        }
        Ok(())
    })();
    if paused {
        if let Err(e) = host.resume_udev() {
            // The shell step restarts the queue again after this binary
            // exits (idempotent), so a stuck queue never outlives it.
            eprintln!("hippius-guest-release: dedicated: WARN udev queue not restarted: {e}");
        }
    }
    result
}

/// Format an integrity slot (the UUID already recorded `formatting`) and
/// open it for the wipe. The record stays `formatting`: only the booted
/// OS's wipe, once every sector is written, records `ready`.
fn format_init<H: Host>(
    host: &mut H,
    slot: &AnchorSlot,
    dev: &Path,
    uuid: &str,
    key: &[u8],
) -> Result<SlotState, &'static str> {
    host.format(dev, uuid, &slot.slot, key, true).map_err(|e| {
        eprintln!(
            "hippius-guest-release: dedicated {}: luksFormat --integrity: {e}",
            slot.slot
        );
        "format-failed"
    })?;
    if host.luks_uuid(dev).as_deref() != Some(uuid) {
        return Err("format-failed");
    }
    open_init(host, slot, dev, key, uuid)?;
    Ok(SlotState::Initializing)
}

/// First format of a plain slot whose UUID is already recorded
/// `formatting`.
fn format_recorded<H: Host>(
    host: &mut H,
    record: &mut Record,
    slot: &AnchorSlot,
    dev: &Path,
    uuid: &str,
    key: &[u8],
) -> Result<SlotState, &'static str> {
    host.format(dev, uuid, &slot.slot, key, false)
        .map_err(|e| {
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
    promote(host, record, slot)?;
    Ok(SlotState::Attached)
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

/// A slot with no record entry yet: record `formatting` + a fresh UUID
/// BEFORE the header exists (a header with this UUID is then always ours,
/// whatever happens next), then format.
fn first_format<H: Host>(
    host: &mut H,
    record: &mut Record,
    slot: &AnchorSlot,
    dev: &Path,
    size: u64,
    key: &[u8],
) -> Result<SlotState, &'static str> {
    blank(host, dev, size)?;
    let uuid = host.new_uuid().map_err(|_| "uuid-failed")?;
    if !valid_uuid(&uuid) {
        return Err("uuid-failed");
    }
    record.insert(
        slot.slot.clone(),
        RecordEntry {
            state: RecordState::Formatting,
            uuid: uuid.clone(),
            size_gib: slot.gib,
            integrity: slot.integrity,
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
    if slot.integrity {
        format_init(host, slot, dev, &uuid, key)
    } else {
        format_recorded(host, record, slot, dev, &uuid, key)
    }
}

fn open_slot<H: Host>(
    host: &mut H,
    record: &mut Record,
    slot: &AnchorSlot,
    dev: &Path,
    size: u64,
    key: &[u8],
) -> Result<SlotState, &'static str> {
    let Some(entry) = record.get(&slot.slot).cloned() else {
        return first_format(host, record, slot, dev, size, key);
    };
    // The measured anchor and the guest's own record must agree on what
    // this slot is: a plain slot is never reopened as an integrity one or
    // the other way round (each mode's header check refuses the other's
    // header anyway).
    if entry.integrity != slot.integrity {
        return Err("mode-mismatch");
    }
    let header = host.luks_uuid(dev);
    match (entry.state, header) {
        (_, Some(u)) if u != entry.uuid => Err("uuid-mismatch"),
        (RecordState::Ready, None) => Err("no-header"),
        (RecordState::Ready, Some(_)) => {
            open_verified(host, slot, dev, key, &entry.uuid)?;
            Ok(SlotState::Attached)
        }
        // An integrity slot whose wipe never finished: nothing was ever
        // handed to the tenant under this UUID, so it starts again from
        // scratch — a fresh format over our own header (same UUID, same
        // derived key) and a full wipe.
        (RecordState::Formatting, Some(_)) if slot.integrity => {
            format_init(host, slot, dev, &entry.uuid, key)
        }
        // A plain slot: the format finished; only the promotion was lost.
        (RecordState::Formatting, Some(_)) => {
            open_verified(host, slot, dev, key, &entry.uuid)?;
            promote(host, record, slot)?;
            Ok(SlotState::Attached)
        }
        // Never formatted (or the header never landed): nothing was ever
        // opened under this UUID, so formatting again loses nothing.
        (RecordState::Formatting, None) => {
            blank(host, dev, size)?;
            if slot.integrity {
                format_init(host, slot, dev, &entry.uuid, key)
            } else {
                format_recorded(host, record, slot, dev, &entry.uuid, key)
            }
        }
    }
}

/// The reason an `initializing` slot starts with (0 % done).
pub const INIT_START_REASON: &str = "init-0";

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
        if info.in_use
            || host.mapper_exists(&mapper_name(&slot.slot))
            || host.mapper_exists(&init_mapper_name(&slot.slot))
        {
            out.push(mismatch(slot, name, "in-use"));
            continue;
        }
        let key = key_for(kek, vm_id, slot);
        match open_slot(host, &mut record, slot, &dev, info.size_bytes, key.as_ref()) {
            Ok(state) => out.push(Outcome {
                slot: slot.slot.clone(),
                state,
                gib: slot.gib,
                dev: name,
                reason: if state == SlotState::Initializing {
                    INIT_START_REASON
                } else {
                    "-"
                },
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
    /// `udevadm` (the initramfs has it on every golden base).
    pub udevadm: PathBuf,
    /// The smallest size class accepted (the e2e test's seam).
    pub min_gib: u64,
    /// udev's event queue is stopped by us: device-mapper calls must not
    /// wait for udev (`DM_DISABLE_UDEV=1`) or they would never return.
    pub udev_paused: bool,
}

impl SysHost {
    /// The real paths, with the given volume root and scratch dir.
    pub fn new(by_id: PathBuf, volume_root: PathBuf, scratch: PathBuf) -> Self {
        SysHost {
            by_id,
            sys_block: PathBuf::from("/sys/class/block"),
            volume_root,
            cryptsetup: PathBuf::from("cryptsetup"),
            scratch,
            udevadm: PathBuf::from("udevadm"),
            min_gib: MIN_GIB,
            udev_paused: false,
        }
    }

    /// `cryptsetup`, not waiting for udev while its queue is stopped.
    fn cryptsetup_cmd(&self) -> Command {
        let mut cmd = Command::new(&self.cryptsetup);
        if self.udev_paused {
            cmd.env("DM_DISABLE_UDEV", "1");
        }
        cmd
    }
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
/// plain `luks2` keyslots, one digest, no tokens. With `integrity`, the
/// segment must instead carry exactly the AEAD this guest formats
/// (`hmac(sha256)`, no journal crypto). Pure, for the tests.
pub fn check_header_json(text: &str, integrity: bool) -> Result<(), String> {
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
        // The segment runs to the end of the device: a fixed `size` would
        // let the host shrink the slot under its size class.
        || field("size") != Some("dynamic")
        || field("iv_tweak") != Some("0")
        || seg.get("sector_size").and_then(Value::as_u64) != Some(SECTOR_SIZE)
        || !segment_integrity_ok(seg.get("integrity"), integrity)
        || seg
            .get("flags")
            .is_some_and(|f| f.as_array().is_some_and(|a| !a.is_empty()))
    {
        return Err(format!(
            "metadata: segment {id} is not the {} crypt segment this guest formats",
            if integrity {
                "aes-xts-plain64 + hmac(sha256)"
            } else {
                "plain aes-xts-plain64"
            }
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

/// A segment's `integrity` object: absent for a plain slot; for an
/// integrity slot exactly `{"type": "hmac(sha256)", "journal_encryption":
/// "none", "journal_integrity": "none"}` (what `luksFormat --integrity
/// hmac-sha256` writes; a journal key is never configured).
fn segment_integrity_ok(v: Option<&serde_json::Value>, integrity: bool) -> bool {
    use serde_json::Value;
    let Some(v) = v else {
        return !integrity;
    };
    let Some(o) = v.as_object().filter(|_| integrity) else {
        return false;
    };
    let field = |k: &str| o.get(k).and_then(Value::as_str);
    o.len() == 3
        && field("type") == Some("hmac(sha256)")
        && field("journal_encryption") == Some("none")
        && field("journal_integrity") == Some("none")
}

fn status_fields(text: &str) -> BTreeMap<&str, &str> {
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.trim().split_once(':') {
            fields.insert(k.trim(), v.trim());
        }
    }
    fields
}

/// `<n> <unit>` in either spelling: cryptsetup 2.7 prints `512 bits` /
/// `4096`, 2.8 prints `512 [bits]` / `4096 [bytes]` / `32768 [512-byte
/// units] (16777216 [bytes])`.
fn num_with_unit(v: &str, n: u64, units: &[&str]) -> bool {
    let (num, rest) = v.split_once(' ').unwrap_or((v, ""));
    let rest = rest.trim();
    let unit_ok = units
        .iter()
        .any(|u| rest == *u || (!u.is_empty() && rest.starts_with(&format!("{u} ("))));
    num == n.to_string() && unit_ok
}

/// The fields of `cryptsetup status <name>` the opener holds a live
/// INTEGRITY mapping to: LUKS2, aes-xts-plain64 with a 768-bit volume key
/// (512 cipher + 256 hmac), `hmac(sha256)` integrity, 4096-byte sectors,
/// on `dev` or on its dm-integrity layer `<name>_dif` (cryptsetup reports
/// one or the other by version; [`check_integrity_topology`] pins the
/// stack itself). Pure, for the tests.
pub fn check_status_integrity(text: &str, name: &str, dev: &Path) -> Result<(), String> {
    let fields = status_fields(text);
    let bad = |k: &str| format!("{k}={}", fields.get(k).unwrap_or(&"<none>"));
    let want = |k: &str, v: &str| -> Result<(), String> {
        (fields.get(k) == Some(&v))
            .then_some(())
            .ok_or_else(|| bad(k))
    };
    let want_num = |k: &str, n: u64, units: &[&str]| -> Result<(), String> {
        fields
            .get(k)
            .is_some_and(|v| num_with_unit(v, n, units))
            .then_some(())
            .ok_or_else(|| bad(k))
    };
    want("type", "LUKS2")?;
    want("cipher", "aes-xts-plain64")?;
    want_num("keysize", 768, &["bits", "[bits]"])?;
    want("integrity", "hmac(sha256)")?;
    if fields.contains_key("integrity keysize") {
        want_num("integrity keysize", 256, &["bits", "[bits]"])?;
    }
    if fields.contains_key("integrity tag size") {
        want_num("integrity tag size", 32, &["bytes", "[bytes]"])?;
    }
    want_num("sector size", SECTOR_SIZE, &["", "[bytes]"])?;
    let dif = format!("/dev/mapper/{name}_dif");
    let device = fields.get("device").copied().unwrap_or("");
    if device != dev.display().to_string() && device != dif {
        return Err(bad("device"));
    }
    for k in ["reencryption", "encryption", "OPAL keysize"] {
        if fields.contains_key(k) {
            return Err(format!("unexpected `{k}`"));
        }
    }
    Ok(())
}

/// Is an active mapping of `bytes` the whole of a `gib` slot? The device
/// is at least `gib × 2^30` (checked before anything opens), the data
/// starts at [`DATA_OFFSET_BYTES`] and runs to the end (`"size":
/// "dynamic"`), so a plain slot maps at least `gib × 2^30 − 16 MiB`. An
/// integrity slot loses its tags (32 bytes per 4 KiB, 0.8 %) and a journal
/// (at most 0.8 % or 64 MiB) on top, so it must map at least 97 % of that:
/// the dm-integrity superblock that sizes it is host-writable, and a
/// smaller figure is a host shrinking the slot under what it is sold as.
pub fn mapped_size_ok(bytes: u64, gib: u64, integrity: bool) -> bool {
    let floor = gib
        .saturating_mul(1 << 30)
        .saturating_sub(DATA_OFFSET_BYTES);
    if integrity {
        bytes >= floor / 100 * 97
    } else {
        bytes >= floor
    }
}

/// `major:minor` of a Linux `dev_t` (glibc's and musl's encoding).
pub fn dev_major_minor(rdev: u64) -> (u64, u64) {
    let major = ((rdev >> 8) & 0xfff) | ((rdev >> 32) & 0xffff_f000);
    let minor = (rdev & 0xff) | ((rdev >> 12) & 0xffff_ff00);
    (major, minor)
}

/// The kernel name (`dm-3`, `vdb`) of the block device at `path`: the
/// target of a udev symlink, or — for a node libdevmapper made itself
/// (`DM_DISABLE_UDEV=1`, the opener's paused activation) — through
/// `/sys/dev/block/<major>:<minor>`. `sys_block` is `/sys/class/block`.
pub fn kernel_name(sys_block: &Path, path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let canon = std::fs::canonicalize(path).ok()?;
    if let Some(n) = dev_name(&canon).filter(|n| sys_block.join(n).exists()) {
        return Some(n);
    }
    let meta = std::fs::metadata(&canon).ok()?;
    if !meta.file_type().is_block_device() {
        return None;
    }
    let (major, minor) = dev_major_minor(meta.rdev());
    let link = sys_block.join(format!("../../dev/block/{major}:{minor}"));
    let target = std::fs::read_link(link).ok()?;
    dev_name(&target)
}

/// The device-mapper stack under `/dev/mapper/<name>` (`sys_block` =
/// `/sys/class/block`): the crypt mapping sits on exactly one device, the
/// dm-integrity layer `<name>_dif`, which sits on exactly `dev`.
pub fn check_integrity_topology(
    sys_block: &Path,
    mapper: &Path,
    name: &str,
    dev: &Path,
) -> Result<(), String> {
    let kname = |p: &Path| {
        kernel_name(sys_block, p).ok_or_else(|| format!("{} does not resolve", p.display()))
    };
    let only_slave = |k: &str| -> Result<String, String> {
        let names: Vec<String> = std::fs::read_dir(sys_block.join(k).join("slaves"))
            .map_err(|e| format!("{k}/slaves: {}", e.kind()))?
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .collect();
        match names.as_slice() {
            [one] => Ok(one.clone()),
            _ => Err(format!("{k} sits on {} devices", names.len())),
        }
    };
    let top = kname(&mapper.join(name))?;
    let dif = only_slave(&top)?;
    let dif_name = std::fs::read_to_string(sys_block.join(&dif).join("dm/name"))
        .map_err(|e| format!("{dif}/dm/name: {}", e.kind()))?;
    if dif_name.trim() != format!("{name}_dif") {
        return Err(format!("{top} sits on `{}`", dif_name.trim()));
    }
    let under = only_slave(&dif)?;
    if Some(under.as_str()) != dev_name(dev).as_deref() {
        return Err(format!("{dif} sits on {under}"));
    }
    Ok(())
}

/// The fields of `cryptsetup status <name>` the opener holds a live
/// mapping to. Pure, for the tests.
pub fn check_status(text: &str, dev: &Path) -> Result<(), String> {
    let fields = status_fields(text);
    let bad = |k: &str| format!("{k}={}", fields.get(k).unwrap_or(&"<none>"));
    let want = |k: &str, v: &str| -> Result<(), String> {
        (fields.get(k) == Some(&v))
            .then_some(())
            .ok_or_else(|| bad(k))
    };
    let want_num = |k: &str, n: u64, units: &[&str]| -> Result<(), String> {
        fields
            .get(k)
            .is_some_and(|v| num_with_unit(v, n, units))
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
        mode: OpenMode,
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
        check_header_json(&String::from_utf8_lossy(&dump.stdout), mode.integrity())
            .map_err(OpenFail::Header)?;
        let mut cmd = self.cryptsetup_cmd();
        cmd.args(["open", "--type", "luks2", "--header"])
            .arg(copy)
            .args(["--volume-key-file", STDIN_PATH]);
        if mode == OpenMode::IntegrityInit {
            cmd.arg("--integrity-no-journal");
        }
        cmd.arg(dev).arg(name);
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

    fn format(
        &mut self,
        dev: &Path,
        uuid: &str,
        slot: &str,
        key: &[u8],
        integrity: bool,
    ) -> Result<(), String> {
        let mut cmd = self.cryptsetup_cmd();
        cmd.args(format_args(uuid, slot, key.len(), integrity))
            .arg(dev);
        // Both files are the same bytes: whichever cryptsetup reads first
        // takes the first copy.
        let mut both = Zeroizing::new(Vec::with_capacity(2 * key.len()));
        both.extend_from_slice(key);
        both.extend_from_slice(key);
        run_with_key(cmd, &both)
    }

    fn open(
        &mut self,
        dev: &Path,
        name: &str,
        key: &[u8],
        uuid: &str,
        mode: OpenMode,
    ) -> Result<(), OpenFail> {
        // The host can rewrite the header between any two reads, so the
        // checks and the activation must see the SAME bytes: copy the
        // header into guest RAM, check the copy, activate from the copy
        // (the #296 detached-header pattern).
        let copy = self.scratch.join(format!(".header-{name}"));
        let _ = std::fs::remove_file(&copy);
        let result = self.open_from_copy(dev, name, key, uuid, &copy, mode);
        let _ = std::fs::remove_file(&copy);
        result
    }

    fn verify_active(
        &self,
        name: &str,
        dev: &Path,
        mode: OpenMode,
        gib: u64,
    ) -> Result<(), String> {
        let mapper = Path::new("/dev/mapper").join(name);
        let k = kernel_name(&self.sys_block, &mapper).ok_or("mapping: no kernel device")?;
        let sectors: u64 = std::fs::read_to_string(self.sys_block.join(&k).join("size"))
            .map_err(|e| format!("{k}/size: {}", e.kind()))?
            .trim()
            .parse()
            .map_err(|_| format!("{k}/size: not a number"))?;
        let bytes = sectors.saturating_mul(512);
        if !mapped_size_ok(bytes, gib, mode.integrity()) {
            return Err(format!(
                "mapping is {bytes} bytes, short of a {gib} GiB slot"
            ));
        }
        let out = Command::new(&self.cryptsetup)
            .args(["status", name])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| format!("status: {}", e.kind()))?;
        if !out.status.success() {
            return Err("status: not active".into());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        if !mode.integrity() {
            return check_status(&text, dev);
        }
        check_status_integrity(&text, name, dev)?;
        check_integrity_topology(&self.sys_block, Path::new("/dev/mapper"), name, dev)
    }

    fn close(&mut self, name: &str) -> bool {
        let _ = self
            .cryptsetup_cmd()
            .args(["close", name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        !self.mapper_exists(name)
    }

    fn pause_udev(&mut self) -> bool {
        let ok = Command::new(&self.udevadm)
            .args(["control", "--stop-exec-queue"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            eprintln!("hippius-guest-release: dedicated: udev not paused (no udevd?) — opening without a pause");
        }
        // A queue a failed resume left stopped stays "paused" for us.
        self.udev_paused = self.udev_paused || ok;
        ok
    }

    fn resume_udev(&mut self) -> Result<(), String> {
        let status = Command::new(&self.udevadm)
            .args(["control", "--start-exec-queue"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("udevadm: {}", e.kind()))?;
        if !status.success() {
            // Still (maybe) stopped: every later device-mapper call of
            // this run keeps `DM_DISABLE_UDEV=1`, or it would wait for a
            // queue that never runs and hang the boot.
            return Err(format!("udevadm exit {:?}", status.code()));
        }
        self.udev_paused = false;
        Ok(())
    }

    fn prime(&mut self, name: &str) -> Result<(), String> {
        crate::wipe::zero_ends(&Path::new("/dev/mapper").join(name), PRIME_BYTES)
            .map_err(|e| e.to_string())
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

/// The `luksFormat` arguments (before the device) for a slot. Pure, for
/// the tests: the layout is PINNED, the same for both modes.
pub fn format_args(uuid: &str, slot: &str, key_len: usize, integrity: bool) -> Vec<String> {
    let mut a: Vec<String> = [
        "luksFormat",
        "--batch-mode",
        "--type",
        "luks2",
        "--cipher",
        "aes-xts-plain64",
        // The CIPHER key: with `--integrity hmac-sha256` cryptsetup adds
        // the 256-bit hmac key to it (a 768-bit volume key).
        "--key-size",
        "512",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    if integrity {
        // The OS overlay's AEAD (hippius_golden_format_upper), and its
        // reason for `--integrity-no-wipe`: the wipe is ours, through the
        // mapping, with parallel writers — here in the booted OS so it
        // never holds the boot (crate::dedicated_init).
        a.extend(
            ["--integrity", "hmac-sha256", "--integrity-no-wipe"]
                .iter()
                .map(|s| (*s).to_string()),
        );
    }
    a.extend(
        [
            "--hash",
            "sha256",
            // The keyslot passphrase is the volume key itself: no
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
        ]
        .iter()
        .map(|s| (*s).to_string()),
    );
    a.push(uuid.to_string());
    a.push("--label".into());
    a.push(mapper_name(slot));
    a.extend(
        [
            "--volume-key-file",
            STDIN_PATH,
            "--key-file",
            STDIN_PATH,
            "--keyfile-size",
        ]
        .iter()
        .map(|s| (*s).to_string()),
    );
    a.push(key_len.to_string());
    a
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
pub fn load_record(volume_root: &Path, min_gib: u64) -> Result<Record, &'static str> {
    let path = volume_root.join(RECORD_NAME);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Record::new()),
        Err(_) => return Err("record-unreadable"),
        Ok(m) if !m.is_file() || m.len() > 64 * 1024 => return Err("record-unreadable"),
        Ok(_) => {}
    }
    let text = std::fs::read_to_string(&path).map_err(|_| "record-unreadable")?;
    parse_record_min(&text, min_gib)
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
    let outcomes = match parse_anchor_min(cmdline, host.min_gib) {
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
                    let record = load_record(&host.volume_root, host.min_gib);
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
    // The integrity slots handed to the booted OS's wipe: the list's
    // presence starts `hippius-dedicated-init.service`. Written before the
    // state file, removed when there are none (a stale list from an
    // earlier run of this boot never survives).
    let list = init_list_path(state_out);
    let init: String = outcomes
        .iter()
        .filter(|o| o.state == SlotState::Initializing)
        .map(|o| format!("{}\n", o.slot))
        .collect();
    if init.is_empty() {
        match std::fs::remove_file(&list) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("init list: {}", e.kind())),
        }
    } else {
        write_atomic(&list, init.as_bytes(), 0o600)?;
    }
    write_atomic(state_out, render_state(&outcomes).as_bytes(), 0o644)?;
    Ok(outcomes)
}

/// The init list next to the state file (`<dir>/init`).
pub fn init_list_path(state_out: &Path) -> PathBuf {
    state_out
        .parent()
        .unwrap_or_else(|| Path::new("/run/hippius/dedicated"))
        .join(INIT_LIST_NAME)
}

#[cfg(test)]
#[path = "dedicated_tests.rs"]
mod tests;
