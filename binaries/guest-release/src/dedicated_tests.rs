//! Tests for `--open-dedicated-disks` (see `dedicated.rs`).

use super::*;
use std::cell::RefCell;

// ── the anchor ─────────────────────────────────────────────────────

fn valid(slots: &[(&str, u64)], vm: &str) -> Anchor {
    Anchor::Valid {
        slots: slots
            .iter()
            .map(|(s, g)| AnchorSlot {
                slot: (*s).to_string(),
                gib: *g,
            })
            .collect(),
        vm_id: vm.to_string(),
    }
}

#[test]
fn no_anchor_is_absent() {
    assert_eq!(parse_anchor("ro quiet hippius.vm_id=v\n"), Anchor::Absent);
    // A lookalike key is not the anchor.
    assert_eq!(
        parse_anchor("hippius.dedicated_x=1 hippius.vm_id=v"),
        Anchor::Absent
    );
}

#[test]
fn a_well_formed_anchor_parses_in_order() {
    assert_eq!(
        parse_anchor("ro hippius.dedicated=x0:22300,x1:1000,x23:16000 hippius.vm_id=vm-7\n"),
        valid(&[("x0", 22300), ("x1", 1000), ("x23", 16000)], "vm-7")
    );
    // Eight slots is the ceiling; any slot numbers, never reused.
    let eight: Vec<String> = (10..18).map(|i| format!("x{i}:1000")).collect();
    let line = format!("hippius.dedicated={} hippius.vm_id=v", eight.join(","));
    assert!(matches!(parse_anchor(&line), Anchor::Valid { slots, .. } if slots.len() == 8));
}

#[test]
fn every_malformed_anchor_is_refused_never_guessed() {
    let vm = " hippius.vm_id=v";
    let cases: &[(&str, &str)] = &[
        ("hippius.dedicated", "anchor-no-value"),
        ("hippius.dedicated=", "anchor-entry"),
        (
            "hippius.dedicated=x0:1000 hippius.dedicated=x1:1000",
            "anchor-repeated",
        ),
        ("hippius.dedicated=x0:1000,", "anchor-entry"),
        ("hippius.dedicated=x0", "anchor-entry"),
        ("hippius.dedicated=x0:999", "anchor-size"),
        ("hippius.dedicated=x0:01000", "anchor-size"),
        ("hippius.dedicated=x0:1000.5", "anchor-size"),
        ("hippius.dedicated=x0:-1000", "anchor-size"),
        ("hippius.dedicated=x0:99999999", "anchor-size"),
        ("hippius.dedicated=x0:1048577", "anchor-size"),
        ("hippius.dedicated=os:1000", "anchor-slot"),
        ("hippius.dedicated=x00:1000", "anchor-slot"),
        ("hippius.dedicated=x01:1000", "anchor-slot"),
        ("hippius.dedicated=x24:1000", "anchor-slot"),
        ("hippius.dedicated=x100:1000", "anchor-slot"),
        ("hippius.dedicated=X0:1000", "anchor-slot"),
        ("hippius.dedicated=x:1000", "anchor-slot"),
        ("hippius.dedicated=x0:1000,x0:2000", "anchor-slot-repeated"),
        ("hippius.dedicated=x0:1000:1", "anchor-size"),
    ];
    for (tok, why) in cases {
        assert_eq!(
            parse_anchor(&format!("ro {tok}{vm}")),
            Anchor::Malformed(why),
            "{tok}"
        );
    }
    let nine: Vec<String> = (0..9).map(|i| format!("x{i}:1000")).collect();
    assert_eq!(
        parse_anchor(&format!("hippius.dedicated={}{vm}", nine.join(","))),
        Anchor::Malformed("anchor-count")
    );
    // The keys need the VM id, exactly once.
    assert_eq!(
        parse_anchor("hippius.dedicated=x0:1000"),
        Anchor::Malformed("anchor-no-vm-id")
    );
    assert_eq!(
        parse_anchor("hippius.dedicated=x0:1000 hippius.vm_id=a hippius.vm_id=b"),
        Anchor::Malformed("anchor-bad-vm-id")
    );
    assert_eq!(
        parse_anchor("hippius.dedicated=x0:1000 hippius.vm_id="),
        Anchor::Malformed("anchor-bad-vm-id")
    );
}

#[test]
fn an_anchor_the_kernel_may_have_cut_is_refused() {
    let pad = "a".repeat(MAX_CMDLINE_LEN);
    let at_limit = |tail: &str| {
        let mut s = format!("hippius.vm_id=v {pad}");
        s.truncate(MAX_CMDLINE_LEN - tail.len() - 1);
        format!("{s} {tail}")
    };
    let cut = at_limit("hippius.dedicated=x0:2230");
    assert_eq!(cut.len(), MAX_CMDLINE_LEN);
    assert_eq!(
        parse_anchor(&cut),
        Anchor::Malformed("anchor-maybe-truncated")
    );
    // At the limit but followed by another token: complete.
    let mut s = format!("hippius.dedicated=x0:2230 hippius.vm_id=v {pad}");
    s.truncate(MAX_CMDLINE_LEN);
    assert!(matches!(parse_anchor(&s), Anchor::Valid { .. }));
}

// ── the key ────────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Fixed vectors, computed independently (RFC 5869 by hand with Python's
/// `hmac` + `hashlib`) and documented in disk-tier-verification.md §4.2:
/// ikm = 0x00..0x1f, salt = "hippius-dedicated-disk-v1", L = 64.
#[test]
fn the_slot_key_matches_the_documented_hkdf_vectors() {
    let kek: Vec<u8> = (0u8..32).collect();
    assert_eq!(
        hex(slot_key(&kek, "vm-0123456789abcdef", "x0").as_ref()),
        "7dceb685bcecdde450d2c8d64193bde1f16264e39a7060270024c9dd70b2589f\
         3b994e95f31ee59cf9255eba17c4014226d0c933e4bb27a3a736a6cd1b18c73e"
    );
    assert_eq!(
        hex(slot_key(&kek, "vm-0123456789abcdef", "x1").as_ref()),
        "ee60213aa0bf9c26f1ba1027c7fb6decea40908be6ca9627627761af82f89266\
         0caf7c6cdc409b97781da83d2c6b849679a287e7104608b2475bcb738136329b"
    );
    assert_eq!(
        hex(slot_key(&kek, "vm-fedcba9876543210", "x0").as_ref()),
        "31c71b9a34687fcbeff70ec582288be65aaf506be25a1a619c0484a4990d4557\
         469c354439785c1649a036b1eb7d4dc2983a297124493ded1ade1bb74e844cb7"
    );
}

// ── the record ─────────────────────────────────────────────────────

const U0: &str = "11111111-2222-4333-8444-555555555555";
const U1: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

#[test]
fn the_record_round_trips_and_is_strict() {
    let mut r = Record::new();
    r.insert(
        "x0".into(),
        RecordEntry {
            state: RecordState::Ready,
            uuid: U0.into(),
            size_gib: 22300,
        },
    );
    r.insert(
        "x1".into(),
        RecordEntry {
            state: RecordState::Formatting,
            uuid: U1.into(),
            size_gib: 1000,
        },
    );
    let text = render_record(&r);
    assert_eq!(
        text,
        format!("hippius-dedicated-disks v1\nx0 ready {U0} 22300\nx1 formatting {U1} 1000\n")
    );
    assert_eq!(parse_record(&text), Ok(r));
    assert_eq!(
        parse_record("hippius-dedicated-disks v1\n"),
        Ok(Record::new())
    );
    for bad in [
        "",
        "hippius-dedicated-disks v2\n",
        &format!("hippius-dedicated-disks v1\nx0 ready {U0}\n"),
        &format!("hippius-dedicated-disks v1\nx0 open {U0} 1000\n"),
        &format!(
            "hippius-dedicated-disks v1\nx0 ready {} 1000\n",
            U1.to_uppercase()
        ),
        &format!("hippius-dedicated-disks v1\nx0  ready {U0} 1000\n"),
        &format!("hippius-dedicated-disks v1\nx0 ready {U0} 1000\nx0 ready {U1} 1000\n"),
        &format!("hippius-dedicated-disks v1\nos ready {U0} 1000\n"),
    ] {
        assert!(parse_record(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn uuid_text_is_canonical_lowercase() {
    assert!(valid_uuid(U0));
    assert!(!valid_uuid("11111111222243338444555555555555"));
    assert!(!valid_uuid("11111111-2222-4333-8444-55555555555g"));
    assert!(!valid_uuid(""));
}

// ── signatures ─────────────────────────────────────────────────────

#[test]
fn a_blank_head_has_no_signature_and_every_known_one_is_seen() {
    assert_eq!(find_signature(&vec![0u8; HEAD_LEN]), None);
    let put = |off: usize, magic: &[u8], want: &str| {
        let mut h = vec![0u8; HEAD_LEN];
        h[off..off + magic.len()].copy_from_slice(magic);
        assert_eq!(find_signature(&h), Some(want), "{want} at {off}");
    };
    put(0, b"LUKS\xba\xbe", "luks");
    put(0x4000, b"SKUL\xba\xbe", "luks");
    put(0x400000, b"SKUL\xba\xbe", "luks");
    put(512, b"EFI PART", "gpt");
    put(4096, b"EFI PART", "gpt");
    put(65536, b"EFI PART", "gpt");
    put(
        (256 << 10) + (128 << 10) + 7 * 1024,
        &0x00ba_b10c_u64.to_be_bytes(),
        "zfs",
    );
    put(1080, b"\x53\xef", "ext");
    put(0, b"XFSB", "xfs");
    put(0x10040, b"_BHRfS_M", "btrfs");
    put(4096, b"\xfc\x4e\x2b\xa9", "md");
    put(1024, b"LABELONE", "lvm");
    put(4086, b"SWAPSPACE2", "swap");
    put(
        (128 << 10) + 3 * 1024,
        &0x00ba_b10c_u64.to_le_bytes(),
        "zfs",
    );
    // A short read (tiny device) is not a panic.
    assert_eq!(find_signature(b"LUKS"), None);
}

#[test]
fn the_active_mapping_must_be_what_we_asked_for() {
    let dev = Path::new("/dev/vdb");
    let good = "/dev/mapper/hippius-x0 is active.\n  type:    LUKS2\n  cipher:  aes-xts-plain64\n  keysize: 512 bits\n  key location: keyring\n  device:  /dev/vdb\n  sector size:  4096\n  offset:  32768 sectors\n  size:    100 sectors\n  mode:    read/write\n";
    assert_eq!(check_status(good, dev), Ok(()));
    assert!(check_status(&good.replace("aes-xts-plain64", "cipher_null-ecb"), dev).is_err());
    assert!(check_status(&good.replace("512 bits", "256 bits"), dev).is_err());
    assert!(check_status(&good.replace("/dev/vdb", "/dev/vdc"), dev).is_err());
    assert!(check_status(&good.replace("LUKS2", "PLAIN"), dev).is_err());
    assert!(check_status(
        &good.replace("sector size:  4096", "sector size:  512"),
        dev
    )
    .is_err());
    assert!(check_status(&good.replace("32768 sectors", "65536 sectors"), dev).is_err());
    assert!(check_status(&format!("{good}  integrity: hmac(sha256)\n"), dev).is_err());
    assert!(check_status("", dev).is_err());
    // cryptsetup 2.8 spells the units differently (src/cryptsetup.c
    // action_status at v2.8.0).
    let good28 = "/dev/mapper/hippius-x0 is active.\n  type:    LUKS2\n  cipher:  aes-xts-plain64\n  keysize: 512 [bits]\n  key location: keyring\n  device:  /dev/vdb\n  sector size:  4096 [bytes]\n  offset:  32768 [512-byte units] (16777216 [bytes])\n  size:    100 [512-byte units] (51200 [bytes])\n  mode:    read/write\n";
    assert_eq!(check_status(good28, dev), Ok(()));
    assert!(check_status(&good28.replace("512 [bits]", "256 [bits]"), dev).is_err());
    assert!(check_status(&good28.replace("4096 [bytes]", "512 [bytes]"), dev).is_err());
    assert!(check_status(&good28.replace("32768 [512-byte", "65536 [512-byte"), dev).is_err());
    assert!(check_status(&format!("{good28}  reencryption:  in-progress\n"), dev).is_err());
    assert!(check_status(
        &format!("{good28}  encryption: dm-crypt over HW OPAL\n"),
        dev
    )
    .is_err());
    assert!(check_status(&good28.replace("512 [bits]", "512 [bitsy]"), dev).is_err());
}

// ── the decisions, on a fake host ──────────────────────────────────

#[derive(Debug, Clone)]
struct FakeDev {
    size: u64,
    partition: bool,
    in_use: bool,
    luks: Option<String>,
    head: Vec<u8>,
    /// The device's last bytes.
    tail: Vec<u8>,
    /// The key the header accepts (set by format).
    key: Option<Vec<u8>>,
    /// The cipher the header's segment says (what `open` activates).
    cipher: &'static str,
    /// The metadata check passes.
    header_ok: bool,
    unreadable: bool,
}

impl FakeDev {
    fn blank(gib: u64) -> Self {
        FakeDev {
            size: gib << 30,
            partition: false,
            in_use: false,
            luks: None,
            head: vec![0; 8192],
            tail: vec![0; 4096],
            key: None,
            cipher: "aes-xts-plain64",
            header_ok: true,
            unreadable: false,
        }
    }
}

#[derive(Default)]
struct Fake {
    links: BTreeMap<String, PathBuf>,
    devs: BTreeMap<PathBuf, FakeDev>,
    mappers: BTreeMap<String, PathBuf>,
    uuids: Vec<String>,
    record: Option<Record>,
    fail_record_write: bool,
    /// Succeed this many record writes, then fail.
    fail_record_write_after: Option<usize>,
    /// `cryptsetup close` leaves the mapping in place.
    stuck_close: bool,
    fail_format: bool,
    log: RefCell<Vec<String>>,
}

impl Fake {
    fn with(devs: &[(&str, &str, FakeDev)]) -> Self {
        let mut f = Fake {
            uuids: vec![U0.into(), U1.into()],
            ..Fake::default()
        };
        for (slot, dev, d) in devs {
            let p = PathBuf::from(format!("/dev/{dev}"));
            f.links.insert((*slot).into(), p.clone());
            f.devs.insert(p, d.clone());
        }
        f
    }
    fn dev(&self, name: &str) -> &FakeDev {
        &self.devs[&PathBuf::from(format!("/dev/{name}"))]
    }
    fn formats(&self) -> usize {
        self.log
            .borrow()
            .iter()
            .filter(|l| l.starts_with("format"))
            .count()
    }
}

impl Host for Fake {
    fn resolve(&self, slot: &str) -> Option<PathBuf> {
        self.links.get(slot).cloned()
    }
    fn info(&self, dev: &Path) -> Result<DevInfo, String> {
        let d = &self.devs[dev];
        if d.unreadable {
            return Err("io".into());
        }
        Ok(DevInfo {
            size_bytes: d.size,
            is_partition: d.partition,
            in_use: d.in_use,
        })
    }
    fn read_at(&self, dev: &Path, offset: u64, len: usize) -> Result<Vec<u8>, String> {
        let d = &self.devs[dev];
        // A sparse device: `head` at 0, `tail` ending at `size`, zeros between.
        let mut out = vec![0u8; len.min(usize::try_from(d.size.saturating_sub(offset)).unwrap())];
        for (i, b) in out.iter_mut().enumerate() {
            let abs = offset + i as u64;
            if let Some(v) = d.head.get(abs as usize) {
                *b = *v;
            }
            if let Some(t) = (abs + d.tail.len() as u64).checked_sub(d.size) {
                *b = d.tail[t as usize];
            }
        }
        Ok(out)
    }
    fn luks_uuid(&self, dev: &Path) -> Option<String> {
        self.devs[dev].luks.clone()
    }
    fn mapper_exists(&self, name: &str) -> bool {
        self.mappers.contains_key(name)
    }
    fn format(&mut self, dev: &Path, uuid: &str, slot: &str, key: &[u8]) -> Result<(), String> {
        self.log.borrow_mut().push(format!("format {slot} {uuid}"));
        if self.fail_format {
            return Err("boom".into());
        }
        let d = self.devs.get_mut(dev).ok_or("no dev")?;
        d.luks = Some(uuid.into());
        d.key = Some(key.to_vec());
        Ok(())
    }
    fn open(&mut self, dev: &Path, name: &str, key: &[u8], uuid: &str) -> Result<(), OpenFail> {
        self.log.borrow_mut().push(format!("open {name}"));
        let d = &self.devs[dev];
        if d.luks.as_deref() != Some(uuid) || !d.header_ok {
            return Err(OpenFail::Header("forged".into()));
        }
        if d.key.as_deref() != Some(key) {
            return Err(OpenFail::Refused("digest".into()));
        }
        self.mappers.insert(name.into(), dev.to_path_buf());
        Ok(())
    }
    fn verify_active(&self, name: &str, dev: &Path) -> Result<(), String> {
        let d = &self.devs[&self.mappers[name]];
        if self.mappers[name] != dev || d.cipher != "aes-xts-plain64" {
            return Err("cipher".into());
        }
        Ok(())
    }
    fn close(&mut self, name: &str) -> bool {
        self.log.borrow_mut().push(format!("close {name}"));
        if self.stuck_close {
            return false;
        }
        self.mappers.remove(name);
        true
    }
    fn new_uuid(&mut self) -> Result<String, String> {
        if self.uuids.is_empty() {
            return Err("none".into());
        }
        Ok(self.uuids.remove(0))
    }
    fn write_record(&mut self, record: &Record) -> Result<(), String> {
        if self.fail_record_write {
            return Err("ro".into());
        }
        if let Some(n) = self.fail_record_write_after.as_mut() {
            if *n == 0 {
                return Err("full".into());
            }
            *n -= 1;
        }
        self.record = Some(record.clone());
        Ok(())
    }
}

const KEK: [u8; 32] = [7; 32];

fn anchor(slots: &[(&str, u64)]) -> Vec<AnchorSlot> {
    slots
        .iter()
        .map(|(s, g)| AnchorSlot {
            slot: (*s).into(),
            gib: *g,
        })
        .collect()
}

fn states(out: &[Outcome]) -> Vec<(String, SlotState, &'static str)> {
    out.iter()
        .map(|o| (o.slot.clone(), o.state, o.reason))
        .collect()
}

fn st(slot: &str, s: SlotState, r: &'static str) -> (String, SlotState, &'static str) {
    (slot.into(), s, r)
}

fn boot(f: &mut Fake, slots: &[AnchorSlot]) -> Vec<Outcome> {
    let rec = f.record.clone().unwrap_or_default();
    // Every boot starts with no mapping open.
    f.mappers.clear();
    process(f, slots, "vm-1", &KEK, Ok(rec))
}

#[test]
fn first_boot_formats_records_then_later_boots_open_by_uuid() {
    let mut f = Fake::with(&[
        ("x0", "vdb", FakeDev::blank(22300)),
        ("x1", "vdc", FakeDev::blank(1000)),
    ]);
    let slots = anchor(&[("x0", 22300), ("x1", 1000)]);
    let out = boot(&mut f, &slots);
    assert_eq!(
        states(&out),
        [
            st("x0", SlotState::Attached, "-"),
            st("x1", SlotState::Attached, "-")
        ]
    );
    assert_eq!(out[0].dev.as_deref(), Some("vdb"));
    let rec = f.record.clone().unwrap();
    assert_eq!(rec["x0"].state, RecordState::Ready);
    assert_eq!(rec["x0"].uuid, U0);
    assert_eq!(rec["x0"].size_gib, 22300);
    assert_eq!(rec["x1"].uuid, U1);
    // The header accepts the derived key, per slot.
    assert_eq!(
        f.dev("vdb").key.as_deref(),
        Some(&slot_key(&KEK, "vm-1", "x0")[..])
    );
    assert_ne!(f.dev("vdb").key, f.dev("vdc").key);
    assert_eq!(f.formats(), 2);

    // Reboot: same disks, opened, never reformatted.
    let out = boot(&mut f, &slots);
    assert!(out.iter().all(|o| o.state == SlotState::Attached));
    assert_eq!(f.formats(), 2);
}

#[test]
fn a_recorded_slot_with_another_or_no_header_is_mismatch_never_reformatted() {
    let mut f = Fake::with(&[
        ("x0", "vdb", FakeDev::blank(1000)),
        ("x1", "vdc", FakeDev::blank(1000)),
    ]);
    let slots = anchor(&[("x0", 1000), ("x1", 1000)]);
    boot(&mut f, &slots);
    // The miner swaps in a blank disk for x0 and another LUKS disk for x1.
    let p0 = PathBuf::from("/dev/vdb");
    let p1 = PathBuf::from("/dev/vdc");
    f.devs.insert(p0, FakeDev::blank(1000));
    let mut foreign = FakeDev::blank(1000);
    foreign.luks = Some("99999999-2222-4333-8444-555555555555".into());
    f.devs.insert(p1, foreign);
    let out = boot(&mut f, &slots);
    assert_eq!(
        states(&out),
        [
            st("x0", SlotState::Mismatch, "no-header"),
            st("x1", SlotState::Mismatch, "uuid-mismatch")
        ]
    );
    assert_eq!(f.formats(), 2);
    assert!(f.mappers.is_empty());
}

#[test]
fn swapped_slots_are_both_mismatch() {
    let mut f = Fake::with(&[
        ("x0", "vdb", FakeDev::blank(1000)),
        ("x1", "vdc", FakeDev::blank(1000)),
    ]);
    let slots = anchor(&[("x0", 1000), ("x1", 1000)]);
    boot(&mut f, &slots);
    f.links.insert("x0".into(), PathBuf::from("/dev/vdc"));
    f.links.insert("x1".into(), PathBuf::from("/dev/vdb"));
    let out = boot(&mut f, &slots);
    assert_eq!(
        states(&out),
        [
            st("x0", SlotState::Mismatch, "uuid-mismatch"),
            st("x1", SlotState::Mismatch, "uuid-mismatch")
        ]
    );
}

#[test]
fn a_copied_uuid_without_our_key_does_not_open() {
    let mut f = Fake::with(&[("x0", "vdb", FakeDev::blank(1000))]);
    let slots = anchor(&[("x0", 1000)]);
    boot(&mut f, &slots);
    // The miner forges a header with the recorded UUID (it is plaintext).
    f.devs.get_mut(&PathBuf::from("/dev/vdb")).unwrap().key = Some(vec![1; 64]);
    let out = boot(&mut f, &slots);
    assert_eq!(states(&out), [st("x0", SlotState::Mismatch, "open-failed")]);
}

#[test]
fn a_header_this_guest_never_writes_is_refused_before_activation() {
    let mut f = Fake::with(&[("x0", "vdb", FakeDev::blank(1000))]);
    let slots = anchor(&[("x0", 1000)]);
    boot(&mut f, &slots);
    f.devs
        .get_mut(&PathBuf::from("/dev/vdb"))
        .unwrap()
        .header_ok = false;
    let out = boot(&mut f, &slots);
    assert_eq!(states(&out), [st("x0", SlotState::Mismatch, "bad-header")]);
    assert!(f.mappers.is_empty());
}

/// A real `luksDump --dump-json-metadata` of a header the opener formats
/// (cryptsetup 2.7, the exact `luksFormat` flags of `SysHost::format`).
const GOOD_HEADER: &str = r#"{
  "keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},
    "area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},
    "kdf":{"type":"pbkdf2","hash":"sha256","iterations":1000,"salt":"kzssVgYGqQlB/Sjxn6t1RlkNmjrizQgbd9mNn9qvcVA="}}},
  "tokens":{},
  "segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":4096}},
  "digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":1000,
    "salt":"8vnNshDNp2pUCP6a5wuDutIS2Rli7OPudejJtto2KQA=","digest":"sYaxPgDptAV6Ma0ldCQIqzXD8PIIWccl18P8MlgheuA="}},
  "config":{"json_size":"12288","keyslots_size":"16744448"}
}"#;

#[test]
fn only_a_header_this_guest_writes_passes_the_metadata_check() {
    assert_eq!(check_header_json(GOOD_HEADER), Ok(()));
    let bad = [
        // another cipher, or none
        GOOD_HEADER.replacen(
            r#""encryption":"aes-xts-plain64","sector_size""#,
            r#""encryption":"cipher_null-ecb","sector_size""#,
            1,
        ),
        // authenticated (integrity) segment
        GOOD_HEADER.replacen(
            r#""sector_size":4096}"#,
            r#""sector_size":4096,"integrity":{"type":"hmac(sha256)"}}"#,
            1,
        ),
        // a linear segment
        GOOD_HEADER.replacen(r#""type":"crypt""#, r#""type":"linear""#, 1),
        // two segments (a reencryption in flight)
        GOOD_HEADER.replacen(
            r#""segments":{"0":{"#,
            r#""segments":{"1":{"type":"linear","offset":"0","size":"dynamic"},"0":{"#,
            1,
        ),
        // mandatory requirements
        GOOD_HEADER.replacen(
            r#""keyslots_size":"16744448""#,
            r#""keyslots_size":"16744448","requirements":{"mandatory":["online-reencrypt-v2"]}"#,
            1,
        ),
        // a reencrypt keyslot
        GOOD_HEADER.replacen(
            r#""type":"luks2","key_size""#,
            r#""type":"reencrypt","key_size""#,
            1,
        ),
        // a token (plugins)
        GOOD_HEADER.replacen(
            r#""tokens":{}"#,
            r#""tokens":{"0":{"type":"systemd-tpm2","keyslots":["0"]}}"#,
            1,
        ),
        // another data offset or sector size
        GOOD_HEADER.replacen(r#""offset":"16777216""#, r#""offset":"33554432""#, 1),
        GOOD_HEADER.replacen(r#""sector_size":4096"#, r#""sector_size":512"#, 1),
        // segment flags
        GOOD_HEADER.replacen(
            r#""iv_tweak":"0""#,
            r#""iv_tweak":"0","flags":["backup-final"]"#,
            1,
        ),
        // no digest
        GOOD_HEADER.replacen(r#""digests":{"0":"#, r#""digests":{},"x":{"0":"#, 1),
        "not json".to_string(),
    ];
    for (i, b) in bad.iter().enumerate() {
        assert_ne!(b, GOOD_HEADER, "case {i} did not mutate");
        assert!(check_header_json(b).is_err(), "case {i} accepted");
    }
}

#[test]
fn a_forged_null_cipher_segment_is_closed_again() {
    let mut f = Fake::with(&[("x0", "vdb", FakeDev::blank(1000))]);
    let slots = anchor(&[("x0", 1000)]);
    boot(&mut f, &slots);
    f.devs.get_mut(&PathBuf::from("/dev/vdb")).unwrap().cipher = "cipher_null-ecb";
    let out = boot(&mut f, &slots);
    assert_eq!(states(&out), [st("x0", SlotState::Mismatch, "bad-mapping")]);
    assert!(f.mappers.is_empty());
    assert!(f.log.borrow().iter().any(|l| l == "close hippius-x0"));
}

#[test]
fn an_absent_slot_is_missing_and_the_others_still_open() {
    let mut f = Fake::with(&[("x1", "vdc", FakeDev::blank(1000))]);
    let out = boot(&mut f, &anchor(&[("x0", 1000), ("x1", 1000)]));
    assert_eq!(
        states(&out),
        [
            st("x0", SlotState::Missing, "absent"),
            st("x1", SlotState::Attached, "-")
        ]
    );
    assert_eq!(out[0].dev, None);
    // A missing slot is never recorded.
    assert!(!f.record.clone().unwrap().contains_key("x0"));
}

#[test]
fn a_device_smaller_than_its_anchor_is_refused() {
    let mut small = FakeDev::blank(1000);
    small.size = (2000u64 << 30) - 512;
    let mut f = Fake::with(&[("x0", "vdb", small)]);
    let out = boot(&mut f, &anchor(&[("x0", 2000)]));
    assert_eq!(states(&out), [st("x0", SlotState::Mismatch, "too-small")]);
    assert_eq!(f.formats(), 0);
    // Exactly the anchored size is enough.
    f.devs.get_mut(&PathBuf::from("/dev/vdb")).unwrap().size = 2000u64 << 30;
    assert_eq!(
        boot(&mut f, &anchor(&[("x0", 2000)]))[0].state,
        SlotState::Attached
    );
}

#[test]
fn partitions_busy_duplicate_and_unreadable_devices_are_refused() {
    let mut part = FakeDev::blank(1000);
    part.partition = true;
    let mut busy = FakeDev::blank(1000);
    busy.in_use = true;
    let mut bad = FakeDev::blank(1000);
    bad.unreadable = true;
    let mut f = Fake::with(&[
        ("x0", "vdb", part),
        ("x1", "vdc", busy),
        ("x2", "vdd", bad),
        ("x3", "vde", FakeDev::blank(1000)),
    ]);
    f.links.insert("x4".into(), PathBuf::from("/dev/vde"));
    let out = boot(
        &mut f,
        &anchor(&[
            ("x0", 1000),
            ("x1", 1000),
            ("x2", 1000),
            ("x3", 1000),
            ("x4", 1000),
        ]),
    );
    assert_eq!(
        states(&out),
        [
            st("x0", SlotState::Mismatch, "not-whole-disk"),
            st("x1", SlotState::Mismatch, "in-use"),
            st("x2", SlotState::Mismatch, "unreadable"),
            st("x3", SlotState::Mismatch, "duplicate"),
            st("x4", SlotState::Mismatch, "duplicate"),
        ]
    );
    assert_eq!(f.formats(), 0);
}

#[test]
fn a_device_with_any_signature_is_never_formatted() {
    let mut used = FakeDev::blank(1000);
    used.head[1080..1082].copy_from_slice(b"\x53\xef");
    let mut luks = FakeDev::blank(1000);
    luks.luks = Some(U1.into());
    let mut f = Fake::with(&[("x0", "vdb", used), ("x1", "vdc", luks)]);
    let out = boot(&mut f, &anchor(&[("x0", 1000), ("x1", 1000)]));
    assert_eq!(
        states(&out),
        [
            st("x0", SlotState::Mismatch, "not-blank"),
            st("x1", SlotState::Mismatch, "not-blank")
        ]
    );
    assert_eq!(f.formats(), 0);
    assert_eq!(f.record.clone().unwrap_or_default(), Record::new());
}

#[test]
fn signatures_at_the_end_of_a_device_are_seen() {
    let size: u64 = (1000u64 << 30) + 12345 * 512;
    let tail_len = 1 << 20;
    let put = |abs: u64, magic: &[u8], want: &str| {
        let mut t = vec![0u8; tail_len];
        let o = (abs - (size - tail_len as u64)) as usize;
        t[o..o + magic.len()].copy_from_slice(magic);
        assert_eq!(find_tail_signature(&t, size), Some(want), "{want}");
    };
    assert_eq!(find_tail_signature(&vec![0u8; tail_len], size), None);
    put((((size / 512) - 16) & !7) * 512, b"\xfc\x4e\x2b\xa9", "md");
    put((size & !0xffff) - 0x10000, b"\xfc\x4e\x2b\xa9", "md");
    put(size - 512, b"EFI PART", "gpt");
    put(size - 4096, b"EFI PART", "gpt");
    put(size - 8192, b"EFI PART", "gpt");
    put((size & !0xffff) - 0x10000, b"\xa9\x2b\x4e\xfc", "md");
    let label_end = size & !((256u64 << 10) - 1);
    put(
        label_end - (256 << 10) + (128 << 10) + 5 * 1024,
        &0x00ba_b10c_u64.to_le_bytes(),
        "zfs",
    );
    put(
        label_end - (512 << 10) + (128 << 10),
        &0x00ba_b10c_u64.to_be_bytes(),
        "zfs",
    );
    // A device shorter than the tail window is not a panic.
    assert_eq!(find_tail_signature(&vec![0u8; tail_len], 4096), None);
}

#[test]
fn an_md_member_with_its_superblock_at_the_end_is_never_formatted() {
    let mut md10 = FakeDev::blank(1000);
    let size = md10.size;
    let sb = (((size / 512) - 16) & !7) * 512;
    md10.tail = vec![0; 16384];
    let o = (sb + 16384 - size) as usize;
    md10.tail[o..o + 4].copy_from_slice(b"\xfc\x4e\x2b\xa9");
    let mut f = Fake::with(&[("x0", "vdb", md10)]);
    let out = boot(&mut f, &anchor(&[("x0", 1000)]));
    assert_eq!(states(&out), [st("x0", SlotState::Mismatch, "not-blank")]);
    assert_eq!(f.formats(), 0);
}

#[test]
fn a_slot_is_handed_over_only_once_ready_is_durable() {
    let mut f = Fake::with(&[("x0", "vdb", FakeDev::blank(1000))]);
    let slots = anchor(&[("x0", 1000)]);
    // The formatting record lands, the promotion write fails.
    f.fail_record_write_after = Some(1);
    let out = boot(&mut f, &slots);
    assert_eq!(
        states(&out),
        [st("x0", SlotState::Mismatch, "record-write-failed")]
    );
    assert!(
        f.mappers.is_empty(),
        "the mapping was left open under a formatting record"
    );
    assert_eq!(
        f.record.clone().unwrap()["x0"].state,
        RecordState::Formatting
    );
    // A close that does not take is reported, not hidden.
    let mut g = Fake::with(&[("x0", "vdb", FakeDev::blank(1000))]);
    g.fail_record_write_after = Some(1);
    g.stuck_close = true;
    let out = process(&mut g, &slots, "vm-1", &KEK, Ok(Record::new()));
    assert_eq!(
        states(&out),
        [st("x0", SlotState::Mismatch, "record-write-failed-mapped")]
    );
    // Next boot: the recorded header opens and is promoted.
    f.fail_record_write_after = None;
    let out = boot(&mut f, &slots);
    assert_eq!(states(&out), [st("x0", SlotState::Attached, "-")]);
    assert_eq!(f.record.clone().unwrap()["x0"].state, RecordState::Ready);
    assert_eq!(f.formats(), 1);
}

#[test]
fn no_format_without_the_formatting_record_first() {
    let mut f = Fake::with(&[("x0", "vdb", FakeDev::blank(1000))]);
    f.fail_record_write = true;
    let out = boot(&mut f, &anchor(&[("x0", 1000)]));
    assert_eq!(
        states(&out),
        [st("x0", SlotState::Mismatch, "record-write-failed")]
    );
    assert_eq!(f.formats(), 0);
}

#[test]
fn an_interrupted_first_format_resumes_with_the_recorded_uuid() {
    let mut f = Fake::with(&[("x0", "vdb", FakeDev::blank(1000))]);
    let slots = anchor(&[("x0", 1000)]);
    f.fail_format = true;
    let out = boot(&mut f, &slots);
    assert_eq!(
        states(&out),
        [st("x0", SlotState::Mismatch, "format-failed")]
    );
    assert_eq!(
        f.record.clone().unwrap()["x0"].state,
        RecordState::Formatting
    );
    // Next boot: still no header ⇒ formatted with the SAME uuid.
    f.fail_format = false;
    let out = boot(&mut f, &slots);
    assert_eq!(states(&out), [st("x0", SlotState::Attached, "-")]);
    assert_eq!(f.dev("vdb").luks.as_deref(), Some(U0));
    assert_eq!(f.record.clone().unwrap()["x0"].state, RecordState::Ready);
}

#[test]
fn a_lost_promotion_is_finished_on_the_next_boot_without_formatting() {
    let mut f = Fake::with(&[("x0", "vdb", FakeDev::blank(1000))]);
    let slots = anchor(&[("x0", 1000)]);
    boot(&mut f, &slots);
    // Roll the record back to `formatting` (the promotion write was lost).
    let mut rec = f.record.clone().unwrap();
    rec.get_mut("x0").unwrap().state = RecordState::Formatting;
    f.record = Some(rec);
    let out = boot(&mut f, &slots);
    assert_eq!(states(&out), [st("x0", SlotState::Attached, "-")]);
    assert_eq!(f.formats(), 1);
    assert_eq!(f.record.clone().unwrap()["x0"].state, RecordState::Ready);
    // `formatting` + a FOREIGN header: mismatch, untouched.
    let mut rec = f.record.clone().unwrap();
    rec.get_mut("x0").unwrap().state = RecordState::Formatting;
    rec.get_mut("x0").unwrap().uuid = U1.into();
    f.record = Some(rec);
    let out = boot(&mut f, &slots);
    assert_eq!(
        states(&out),
        [st("x0", SlotState::Mismatch, "uuid-mismatch")]
    );
    assert_eq!(f.formats(), 1);
}

#[test]
fn formatting_record_with_our_header_that_will_not_open_is_never_reformatted() {
    let mut f = Fake::with(&[("x0", "vdb", FakeDev::blank(1000))]);
    let slots = anchor(&[("x0", 1000)]);
    boot(&mut f, &slots);
    let mut rec = f.record.clone().unwrap();
    rec.get_mut("x0").unwrap().state = RecordState::Formatting;
    f.record = Some(rec);
    f.devs.get_mut(&PathBuf::from("/dev/vdb")).unwrap().key = Some(vec![2; 64]);
    let out = boot(&mut f, &slots);
    assert_eq!(states(&out), [st("x0", SlotState::Mismatch, "open-failed")]);
    assert_eq!(f.formats(), 1);
}

#[test]
fn an_unreadable_record_opens_and_formats_nothing() {
    let mut f = Fake::with(&[("x0", "vdb", FakeDev::blank(1000))]);
    let out = process(
        &mut f,
        &anchor(&[("x0", 1000), ("x1", 1000)]),
        "vm-1",
        &KEK,
        Err("record-magic"),
    );
    assert_eq!(
        states(&out),
        [
            st("x0", SlotState::Mismatch, "record-magic"),
            st("x1", SlotState::Missing, "absent")
        ]
    );
    assert_eq!(f.formats(), 0);
    assert!(f.log.borrow().is_empty());
}

#[test]
fn a_slot_already_mapped_is_refused() {
    let mut f = Fake::with(&[("x0", "vdb", FakeDev::blank(1000))]);
    f.mappers
        .insert("hippius-x0".into(), PathBuf::from("/dev/vdz"));
    let out = process(
        &mut f,
        &anchor(&[("x0", 1000)]),
        "vm-1",
        &KEK,
        Ok(Record::new()),
    );
    assert_eq!(states(&out), [st("x0", SlotState::Mismatch, "in-use")]);
}

#[test]
fn the_state_file_is_one_line_per_slot() {
    let out = vec![
        Outcome {
            slot: "x0".into(),
            state: SlotState::Attached,
            gib: 22300,
            dev: Some("vdb".into()),
            reason: "-",
        },
        Outcome {
            slot: "x1".into(),
            state: SlotState::Missing,
            gib: 22300,
            dev: None,
            reason: "absent",
        },
    ];
    assert_eq!(
        render_state(&out),
        "# hippius-dedicated-disks state v1\nx0 attached 22300 vdb -\nx1 missing 22300 - absent\n"
    );
}

// ── the real host's file handling (no root needed) ─────────────────

#[test]
fn a_refused_anchor_reports_every_slot_device_as_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let by_id = dir.path();
    let target = dir.path().join("vdb");
    std::fs::write(&target, b"").unwrap();
    std::os::unix::fs::symlink(&target, by_id.join("virtio-hippius-x0")).unwrap();
    std::os::unix::fs::symlink(&target, by_id.join("virtio-hippius-os")).unwrap();
    std::os::unix::fs::symlink(&target, by_id.join("virtio-hippius-x0-part1")).unwrap();
    std::os::unix::fs::symlink(dir.path().join("gone"), by_id.join("virtio-hippius-x3")).unwrap();
    std::os::unix::fs::symlink(&target, by_id.join("virtio-WD-1234")).unwrap();
    let out = refused_anchor_outcomes(by_id, "anchor-slot");
    assert_eq!(
        states(&out),
        [
            st("x0", SlotState::Mismatch, "anchor-slot"),
            st("x3", SlotState::Missing, "anchor-slot")
        ]
    );
    assert_eq!(out[0].dev.as_deref(), Some("vdb"));
    assert_eq!(out[0].gib, 0);
}

#[test]
fn the_record_on_disk_absent_is_empty_and_garbage_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(load_record(dir.path()), Ok(Record::new()));
    std::fs::write(dir.path().join(RECORD_NAME), "nope\n").unwrap();
    assert_eq!(load_record(dir.path()), Err("record-magic"));
    std::fs::remove_file(dir.path().join(RECORD_NAME)).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", dir.path().join(RECORD_NAME)).unwrap();
    assert_eq!(load_record(dir.path()), Err("record-unreadable"));
    std::fs::remove_file(dir.path().join(RECORD_NAME)).unwrap();
    let mut r = Record::new();
    r.insert(
        "x2".into(),
        RecordEntry {
            state: RecordState::Ready,
            uuid: U0.into(),
            size_gib: 1000,
        },
    );
    write_atomic(
        &dir.path().join(RECORD_NAME),
        render_record(&r).as_bytes(),
        0o600,
    )
    .unwrap();
    assert_eq!(load_record(dir.path()), Ok(r));
}

#[test]
fn the_kek_file_must_be_32_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("kek");
    std::fs::write(&p, [1u8; 32]).unwrap();
    assert_eq!(read_kek(&p).unwrap().as_slice(), &[1u8; 32]);
    std::fs::write(&p, [1u8; 33]).unwrap();
    assert_eq!(read_kek(&p).unwrap_err(), "kek-length");
    std::fs::write(&p, [1u8; 31]).unwrap();
    assert_eq!(read_kek(&p).unwrap_err(), "kek-length");
    assert_eq!(
        read_kek(&dir.path().join("none")).unwrap_err(),
        "kek-unreadable"
    );
}

#[test]
fn run_without_an_anchor_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("dedicated/slots");
    let mut host = SysHost {
        by_id: dir.path().join("by-id"),
        sys_block: dir.path().join("sys"),
        volume_root: dir.path().to_path_buf(),
        cryptsetup: PathBuf::from("/nonexistent/cryptsetup"),
        scratch: dir.path().join("dedicated"),
    };
    let out = run(
        "ro hippius.vm_id=v",
        &dir.path().join("kek"),
        &mut host,
        &state,
    )
    .unwrap();
    assert!(out.is_empty());
    assert!(!state.exists());
    assert!(!dir.path().join(RECORD_NAME).exists());
}
