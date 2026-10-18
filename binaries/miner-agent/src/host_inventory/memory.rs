//! The `memory` section: the total from `/proc/meminfo`, the DIMMs from
//! the SMBIOS table (type 17, its ECC type from the type 16 array it
//! names), the EDAC error counters from sysfs.

use hippius_host_inventory::{
    Dimm, DimmErrors, EccType, Edac, MemorySection, MAX_DIMMS, MAX_NAME_LEN, MAX_SERIAL_LEN,
    MAX_TEXT_LEN,
};

use super::smbios::{self, Structure};
use super::{clean_text, dir_names, read_trimmed, HostPaths, Source, Tally};

/// `MemTotal` in MiB.
fn total_mib(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_ascii_whitespace().nth(1)?.parse().ok()?;
    Some(kb / 1024)
}

/// Type 16 `Memory Error Correction` (0x06).
fn ecc(array: Option<&Structure<'_>>) -> EccType {
    match array.and_then(|a| a.byte(0x06)) {
        Some(3) => EccType::None,
        Some(4) => EccType::Parity,
        Some(5) => EccType::SingleBit,
        Some(6) => EccType::MultiBit,
        Some(7) => EccType::Crc,
        _ => EccType::Unknown,
    }
}

/// Type 17 `Memory Type` (0x12).
fn mem_type(code: u8) -> Option<&'static str> {
    Some(match code {
        0x0F => "SDRAM",
        0x12 => "DDR",
        0x13 => "DDR2",
        0x18 => "DDR3",
        0x1A => "DDR4",
        0x1B => "LPDDR",
        0x1C => "LPDDR2",
        0x1D => "LPDDR3",
        0x1E => "LPDDR4",
        0x20 => "HBM",
        0x21 => "HBM2",
        0x22 => "DDR5",
        0x23 => "LPDDR5",
        0x24 => "HBM3",
        _ => return None,
    })
}

/// Type 17 size in MiB: `Size` (0x0C) — 0 no module, 0xFFFF installed
/// but unknown (0), 0x7FFF see `Extended Size` (0x1C, MiB, bit 31
/// reserved; 0 when the record predates it), bit 15 set KiB units (rounded
/// up, so a module under 1 MiB is 1). `None`: no module installed.
fn size_mib(dev: &Structure<'_>) -> Option<u32> {
    Some(match dev.word(0x0C)? {
        0 => return None,
        0xFFFF => 0,
        0x7FFF => dev.dword(0x1C).map_or(0, |e| e & 0x7FFF_FFFF),
        s if s & 0x8000 != 0 => u32::from(s & 0x7FFF).div_ceil(1024),
        s => u32::from(s),
    })
}

/// A type 17 speed in MT/s: the word at `offset` — 0 unknown, 0xFFFF see
/// the extended dword at `ext` (bit 31 reserved).
fn speed(dev: &Structure<'_>, offset: usize, ext: usize) -> Option<u32> {
    match dev.word(offset)? {
        0 => None,
        0xFFFF => dev.dword(ext).map(|e| e & 0x7FFF_FFFF).filter(|&e| e > 0),
        s => Some(u32::from(s)),
    }
}

/// Type 17 `Memory Technology` (0x28, SMBIOS 3.2+): NVDIMM-N / -F / -P
/// and Intel persistent memory are storage, not system RAM.
fn is_persistent(dev: &Structure<'_>) -> bool {
    matches!(dev.byte(0x28), Some(0x04..=0x07))
}

/// Type 16 `Use` (0x05): anything but system memory (0x03) — video,
/// flash, NVRAM, cache — is no DIMM of the host's RAM.
fn is_system_memory(array: Option<&Structure<'_>>) -> bool {
    array.and_then(|a| a.byte(0x05)).is_none_or(|u| u == 0x03)
}

/// `base#tag`, `base` cut so the whole fits [`MAX_NAME_LEN`].
fn tagged(base: &str, tag: &str) -> String {
    let mut b = base.to_string();
    b.truncate(MAX_NAME_LEN.saturating_sub(tag.len() + 1));
    format!("{}#{tag}", b.trim_end())
}

/// Which of `keys` occur more than once.
fn shared<K: Ord>(keys: &[K]) -> Vec<bool> {
    let mut counts = std::collections::BTreeMap::new();
    for k in keys {
        *counts.entry(k).or_insert(0u32) += 1;
    }
    keys.iter()
        .map(|k| counts.get(k).is_some_and(|&c| c > 1))
        .collect()
}

/// Rename, with `tag(index)`, every item whose key another item shares.
fn make_unique<T, K: Ord>(
    items: &mut [T],
    key: impl Fn(&T) -> K,
    mut rename: impl FnMut(&mut T, usize),
) {
    let keys: Vec<K> = items.iter().map(&key).collect();
    for (i, (item, dup)) in items.iter_mut().zip(shared(&keys)).enumerate() {
        if dup {
            rename(item, i);
        }
    }
}

/// Every installed DIMM of `table`, sorted by key, at most [`MAX_DIMMS`];
/// whether the cap cut any. Records only a firmware copy apart are
/// reported once; DIMMs that merely share a `(bank, locator)` key are all
/// reported, their locators tagged with their SMBIOS handle.
fn dimms(table: &smbios::Table<'_>) -> (Vec<Dimm>, bool) {
    let mut out: Vec<(u16, Dimm)> = table
        .of_kind(smbios::TYPE_MEMORY_DEVICE)
        .enumerate()
        .filter_map(|(i, dev)| {
            let array = dev
                .word(0x04)
                .and_then(|h| table.by_handle(h))
                .filter(|a| a.kind == smbios::TYPE_MEMORY_ARRAY);
            if is_persistent(dev) || !is_system_memory(array) {
                return None;
            }
            let size_mib = size_mib(dev)?;
            let text =
                |offset: usize, max: usize| dev.string(offset).and_then(|s| clean_text(s, max));
            Some((
                dev.handle,
                Dimm {
                    bank_locator: text(0x11, MAX_NAME_LEN),
                    // The key needs one: a slot the firmware left unnamed is
                    // named by its record order.
                    locator: text(0x10, MAX_NAME_LEN).unwrap_or_else(|| format!("slot{i}")),
                    size_mib,
                    mem_type: dev.byte(0x12).and_then(mem_type).map(str::to_string),
                    speed_mts: speed(dev, 0x15, 0x54),
                    configured_mts: speed(dev, 0x20, 0x58),
                    ecc: ecc(array),
                    manufacturer: text(0x17, MAX_TEXT_LEN),
                    part: text(0x1A, MAX_TEXT_LEN),
                    serial: text(0x18, MAX_SERIAL_LEN),
                },
            ))
        })
        .collect();
    // An exact duplicate record is the only thing dropped.
    out.sort_by(|a, b| a.1.key().cmp(&b.1.key()).then(a.0.cmp(&b.0)));
    let mut seen: Vec<Dimm> = Vec::new();
    out.retain(|(_, d)| {
        let dup = seen.contains(d);
        if !dup {
            seen.push(d.clone());
        }
        !dup
    });
    make_unique(
        &mut out,
        |(_, d)| d.key(),
        |(handle, d), _| d.locator = tagged(&d.locator, &format!("{handle:04x}")),
    );
    // A firmware that reuses a handle: tag by position.
    make_unique(
        &mut out,
        |(_, d)| d.key(),
        |(_, d), i| d.locator = tagged(&d.locator, &format!("{i}")),
    );
    let mut out: Vec<Dimm> = out.into_iter().map(|(_, d)| d).collect();
    out.sort_by_key(Dimm::key);
    let cut = out.len() > MAX_DIMMS;
    out.truncate(MAX_DIMMS);
    (out, cut)
}

/// A counter file; a missing or unparsable one is a fault, and 0.
fn count(path: &std::path::Path, tally: &mut Tally) -> u64 {
    let v = read_trimmed(path).and_then(|s| s.parse().ok());
    tally.note(v.is_some());
    v.unwrap_or(0)
}

/// The EDAC counters, `None` when no memory controller is registered.
/// A label two DIMMs share (the firmware's, or after the cut) falls back
/// to `mc<N>/dimm<M>`.
fn edac(paths: &HostPaths, tally: &mut Tally) -> Option<Edac> {
    let mc_root = paths.sys.join("devices/system/edac/mc");
    let controllers: Vec<String> = dir_names(&mc_root)
        .into_iter()
        .filter(|n| {
            n.strip_prefix("mc")
                .is_some_and(|i| !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit()))
        })
        .collect();
    if controllers.is_empty() {
        return None;
    }
    let mut edac = Edac {
        ce_total: 0,
        ue_total: 0,
        per_dimm: Vec::new(),
    };
    let mut entries: Vec<(String, DimmErrors)> = Vec::new();
    for mc in &controllers {
        let dir = mc_root.join(mc);
        edac.ce_total = edac
            .ce_total
            .saturating_add(count(&dir.join("ce_count"), tally));
        edac.ue_total = edac
            .ue_total
            .saturating_add(count(&dir.join("ue_count"), tally));
        for dimm in dir_names(&dir)
            .into_iter()
            .filter(|n| n.starts_with("dimm"))
        {
            let d = dir.join(&dimm);
            let fallback = format!("{mc}/{dimm}");
            let label = read_trimmed(&d.join("dimm_label"))
                .and_then(|l| clean_text(l.as_bytes(), MAX_NAME_LEN))
                .unwrap_or_else(|| fallback.clone());
            let errors = DimmErrors {
                locator: label,
                ce: count(&d.join("dimm_ce_count"), tally),
                ue: count(&d.join("dimm_ue_count"), tally),
            };
            entries.push((fallback, errors));
        }
    }
    make_unique(
        &mut entries,
        |(_, e)| e.locator.clone(),
        |(fallback, e), _| {
            e.locator =
                clean_text(fallback.as_bytes(), MAX_NAME_LEN).unwrap_or_else(|| fallback.clone())
        },
    );
    make_unique(
        &mut entries,
        |(_, e)| e.locator.clone(),
        |(_, e), i| e.locator = tagged(&e.locator, &format!("{i}")),
    );
    edac.per_dimm = entries.into_iter().map(|(_, e)| e).collect();
    edac.per_dimm.sort_by(|a, b| a.locator.cmp(&b.locator));
    if edac.per_dimm.len() > MAX_DIMMS {
        edac.per_dimm.truncate(MAX_DIMMS);
        tally.failed();
    }
    Some(edac)
}

pub fn collect_memory(paths: &HostPaths) -> MemorySection {
    let mut tally = Tally::default();
    let total_mib = tally
        .required(Source::read(&paths.proc.join("meminfo")))
        .and_then(|m| total_mib(&m))
        .unwrap_or(0);
    let table = std::fs::read(&paths.dmi_table).ok();
    tally.note(table.is_some());
    let parsed = table.as_deref().map(smbios::parse).unwrap_or_default();
    if parsed.truncated {
        tally.failed();
    }
    let (dimms, cut) = dimms(&parsed);
    if cut {
        tally.failed();
    }
    let edac = edac(paths, &mut tally);
    MemorySection {
        status: tally.status(),
        total_mib,
        dimms,
        edac,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::fixture::Host;
    use super::super::smbios::tests::{memory_device, sample_table, structure};
    use super::*;
    use hippius_host_inventory::SectionStatus;

    pub(crate) fn meminfo_and_edac(h: &Host) {
        h.write(
            "proc/meminfo",
            "MemTotal:       263852468 kB\nMemFree:        1000 kB\n",
        );
        let mc = "sys/devices/system/edac/mc";
        h.write(&format!("{mc}/mc0/ce_count"), "3\n");
        h.write(&format!("{mc}/mc0/ue_count"), "0\n");
        h.write(
            &format!("{mc}/mc0/dimm0/dimm_label"),
            "CPU_SrcID#0_MC#0_Chan#0_DIMM#0\n",
        );
        h.write(&format!("{mc}/mc0/dimm0/dimm_ce_count"), "3\n");
        h.write(&format!("{mc}/mc0/dimm0/dimm_ue_count"), "0\n");
        h.write(&format!("{mc}/mc1/ce_count"), "1\n");
        h.write(&format!("{mc}/mc1/ue_count"), "2\n");
        h.write(&format!("{mc}/mc1/dimm4/dimm_label"), "\n");
        h.write(&format!("{mc}/mc1/dimm4/dimm_ce_count"), "1\n");
        h.write(&format!("{mc}/mc1/dimm4/dimm_ue_count"), "2\n");
        h.write(&format!("{mc}/power"), "");
    }

    #[test]
    fn reads_dimms_from_smbios_and_edac_from_sysfs() {
        let h = Host::new();
        meminfo_and_edac(&h);
        h.write("DMI", sample_table());
        let m = collect_memory(&h.paths());
        assert_eq!(m.status, SectionStatus::Ok);
        assert_eq!(m.total_mib, 257_668);
        // The empty slot is skipped.
        assert_eq!(
            m.dimms,
            [Dimm {
                bank_locator: Some("P0 CHANNEL A".into()),
                locator: "DIMM 0".into(),
                size_mib: 131_072,
                mem_type: Some("DDR5".into()),
                speed_mts: Some(5600),
                configured_mts: Some(4800),
                ecc: EccType::MultiBit,
                manufacturer: Some("Samsung".into()),
                part: Some("M321R8GA0BB0-CQK".into()),
                serial: Some("S3R1AL01".into()),
            }]
        );
        let edac = m.edac.unwrap();
        assert_eq!((edac.ce_total, edac.ue_total), (4, 2));
        assert_eq!(
            edac.per_dimm,
            [
                DimmErrors {
                    locator: "CPU_SrcID#0_MC#0_Chan#0_DIMM#0".into(),
                    ce: 3,
                    ue: 0
                },
                DimmErrors {
                    locator: "mc1/dimm4".into(),
                    ce: 1,
                    ue: 2
                },
            ]
        );
    }

    #[test]
    fn size_and_speed_encodings() {
        let parse_one = |bytes: Vec<u8>| -> (Option<u32>, Option<u32>) {
            let t = smbios::parse(&bytes);
            let d = t.structures.first().unwrap();
            (size_mib(d), speed(d, 0x15, 0x54))
        };
        // Plain MiB, plain speed.
        assert_eq!(
            parse_one(memory_device(1, 0, 16_384, 0, 3200)),
            (Some(16_384), Some(3200))
        );
        // KiB units (bit 15).
        assert_eq!(
            parse_one(memory_device(1, 0, 0x8000 | 2048, 0, 0)),
            (Some(2), None)
        );
        // Extended size; extended speed.
        assert_eq!(
            parse_one(memory_device(1, 0, 0x7FFF, 0x8000_0000 | 65_536, 0xFFFF)),
            (Some(65_536), Some(5600))
        );
        // Installed, size unknown: 0; empty: none.
        assert_eq!(parse_one(memory_device(1, 0, 0xFFFF, 0, 0)).0, Some(0));
        assert_eq!(parse_one(memory_device(1, 0, 0, 0, 0)).0, None);
        // Under 1 MiB in KiB rounds up.
        assert_eq!(
            parse_one(memory_device(1, 0, 0x8000 | 512, 0, 0)).0,
            Some(1)
        );
        // An SMBIOS 2.3 record (no extended fields): 0x7FFF is an unknown
        // size, 0xFFFF speed reads nothing.
        let mut short = vec![0u8; 0x1B - 4];
        short[0x0C - 4..0x0E - 4].copy_from_slice(&0x7FFFu16.to_le_bytes());
        short[0x15 - 4..0x17 - 4].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert_eq!(parse_one(structure(17, 1, &short, &[])), (Some(0), None));
    }

    #[test]
    fn a_dimm_without_strings_or_array_is_still_reported() {
        let mut f = vec![0u8; 0x5C - 4];
        f[0x0C - 4..0x0E - 4].copy_from_slice(&8192u16.to_le_bytes());
        f[0x04 - 4..0x06 - 4].copy_from_slice(&0x4242u16.to_le_bytes());
        // String indexes pointing past the (empty) set.
        f[0x10 - 4] = 3;
        f[0x17 - 4] = 9;
        let bytes = structure(17, 7, &f, &[]);
        let (d, _) = dimms(&smbios::parse(&bytes));
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].locator, "slot0");
        assert_eq!(d[0].ecc, EccType::Unknown);
        assert_eq!(d[0].manufacturer, None);
        assert_eq!(d[0].mem_type, None);
    }

    #[test]
    fn dimm_strings_are_cleaned() {
        let mut f = vec![0u8; 0x5C - 4];
        f[0x0C - 4..0x0E - 4].copy_from_slice(&8192u16.to_le_bytes());
        f[0x10 - 4] = 1;
        f[0x17 - 4] = 2;
        f[0x18 - 4] = 3;
        f[0x1A - 4] = 4;
        let long = "L".repeat(80);
        let bytes = structure(
            17,
            7,
            &f,
            &[&long, "Unknown", "Not Specified", "NO DIMM\u{7f}"],
        );
        let d = &dimms(&smbios::parse(&bytes)).0[0];
        assert_eq!(d.locator.len(), MAX_NAME_LEN);
        assert_eq!(d.manufacturer, None);
        assert_eq!(d.serial, None);
        assert_eq!(d.part.as_deref(), Some("NO DIMM"));
    }

    #[test]
    fn missing_sources_degrade() {
        let h = Host::new();
        let m = collect_memory(&h.paths());
        assert_eq!(m.status, SectionStatus::Unavailable);
        assert_eq!(m.total_mib, 0);
        assert!(m.dimms.is_empty());
        assert_eq!(m.edac, None, "no EDAC driver: none, not zero");
        h.write("proc/meminfo", "MemTotal: 2048 kB\n");
        h.mkdir("sys/devices/system/edac/mc");
        let m = collect_memory(&h.paths());
        assert_eq!(m.status, SectionStatus::Partial, "no DMI table");
        assert_eq!(m.total_mib, 2);
        assert_eq!(m.edac, None, "an mc dir without controllers");
        // A truncated table: what was read, and partial.
        let mut t = sample_table();
        t.truncate(t.len() / 2 + 3);
        h.write("DMI", t);
        assert_eq!(collect_memory(&h.paths()).status, SectionStatus::Partial);
    }

    /// A type 16 array with ECC code `ecc` and use `usage`.
    fn array(handle: u16, usage: u8, ecc: u8) -> Vec<u8> {
        let mut a = vec![0u8; 0x17 - 4];
        a[0x05 - 4] = usage;
        a[0x06 - 4] = ecc;
        structure(16, handle, &a, &[])
    }

    /// Set the little-endian `bytes` at structure offset `off`.
    fn patch(record: &mut [u8], off: usize, bytes: &[u8]) {
        record[off..off + bytes.len()].copy_from_slice(bytes);
    }

    #[test]
    fn ddr4_single_bit_ecc_and_extended_configured_speed() {
        let mut dev = memory_device(0x1100, 0x1000, 32_768, 0, 3200);
        patch(&mut dev, 0x12, &[0x1A]);
        patch(&mut dev, 0x20, &0xFFFFu16.to_le_bytes());
        patch(&mut dev, 0x58, &4400u32.to_le_bytes());
        let mut t = array(0x1000, 3, 5);
        t.extend(dev);
        let (d, cut) = dimms(&smbios::parse(&t));
        assert!(!cut);
        assert_eq!(d[0].mem_type.as_deref(), Some("DDR4"));
        assert_eq!(d[0].ecc, EccType::SingleBit);
        assert_eq!(d[0].speed_mts, Some(3200));
        assert_eq!(d[0].configured_mts, Some(4400));
        let mut t = array(0x1000, 3, 3);
        t.extend(memory_device(0x1100, 0x1000, 1024, 0, 0));
        assert_eq!(dimms(&smbios::parse(&t)).0[0].ecc, EccType::None);
    }

    #[test]
    fn persistent_memory_and_non_system_arrays_are_skipped() {
        let mut nvdimm = memory_device(0x1100, 0x1000, 1024, 0, 0);
        patch(&mut nvdimm, 0x28, &[0x04]);
        let mut dram = memory_device(0x1101, 0x1000, 1024, 0, 0);
        patch(&mut dram, 0x28, &[0x03]);
        let at = dram.windows(6).position(|w| w == b"DIMM 0").unwrap();
        dram[at + 5] = b'1';
        let mut t = array(0x1000, 3, 6);
        t.extend(nvdimm);
        t.extend(dram);
        // An array used for video memory.
        t.extend(array(0x2000, 0x04, 6));
        t.extend(memory_device(0x2100, 0x2000, 1024, 0, 0));
        let (d, _) = dimms(&smbios::parse(&t));
        let locators: Vec<&str> = d.iter().map(|d| d.locator.as_str()).collect();
        assert_eq!(locators, ["DIMM 1"]);
    }

    #[test]
    fn dimms_sharing_a_key_are_all_reported() {
        let mut t = array(0x1000, 3, 6);
        // Two DIMMs, the same strings, different sizes: both reported.
        t.extend(memory_device(0x1100, 0x1000, 1024, 0, 0));
        t.extend(memory_device(0x1101, 0x1000, 2048, 0, 0));
        // An exact copy of the first record (another handle): once.
        t.extend(memory_device(0x1102, 0x1000, 1024, 0, 0));
        let (d, _) = dimms(&smbios::parse(&t));
        let mut seen: Vec<(String, u32)> =
            d.iter().map(|d| (d.locator.clone(), d.size_mib)).collect();
        seen.sort();
        assert_eq!(
            seen,
            [
                ("DIMM 0#1100".to_string(), 1024),
                ("DIMM 0#1101".to_string(), 2048)
            ]
        );
        // A long locator is cut so the tag fits.
        let long = "L".repeat(40);
        let mut f = vec![0u8; 0x5C - 4];
        f[0x0C - 4..0x0E - 4].copy_from_slice(&1024u16.to_le_bytes());
        f[0x10 - 4] = 1;
        let mut t = structure(17, 0xA, &f, &[&long]);
        f[0x0C - 4..0x0E - 4].copy_from_slice(&2048u16.to_le_bytes());
        t.extend(structure(17, 0xB, &f, &[&long]));
        let (d, _) = dimms(&smbios::parse(&t));
        assert_eq!(d.len(), 2);
        assert!(d.iter().all(|d| d.locator.len() <= MAX_NAME_LEN));
        assert_ne!(d[0].locator, d[1].locator);
        // The result is a valid section.
        let section = MemorySection {
            status: SectionStatus::Ok,
            total_mib: 1,
            dimms: d,
            edac: None,
        };
        assert!(crate::host_inventory::normalize_and_check(
            hippius_host_inventory::Sections {
                memory: Some(section),
                ..Default::default()
            },
            crate::host_inventory::Mode::Counters,
            1
        )
        .valid
        .is_ok());
    }

    #[test]
    fn the_slot_fallback_is_unique() {
        let mut f = vec![0u8; 0x5C - 4];
        f[0x0C - 4..0x0E - 4].copy_from_slice(&1024u16.to_le_bytes());
        let mut t = structure(17, 1, &f, &[]);
        f[0x0C - 4..0x0E - 4].copy_from_slice(&2048u16.to_le_bytes());
        t.extend(structure(17, 2, &f, &[]));
        let (d, _) = dimms(&smbios::parse(&t));
        let locators: Vec<&str> = d.iter().map(|d| d.locator.as_str()).collect();
        assert_eq!(locators, ["slot0", "slot1"]);
    }

    #[test]
    fn edac_labels_colliding_after_the_cut_are_all_reported() {
        let h = Host::new();
        let mc = "sys/devices/system/edac/mc/mc0";
        h.write(&format!("{mc}/ce_count"), "0\n");
        h.write(&format!("{mc}/ue_count"), "0\n");
        let common = "X".repeat(MAX_NAME_LEN);
        for (dimm, ce) in [("dimm0", 5), ("dimm1", 7)] {
            h.write(
                &format!("{mc}/{dimm}/dimm_label"),
                format!("{common}{dimm}\n"),
            );
            h.write(&format!("{mc}/{dimm}/dimm_ce_count"), format!("{ce}\n"));
            h.write(&format!("{mc}/{dimm}/dimm_ue_count"), "0\n");
        }
        let mut tally = Tally::default();
        let e = edac(&h.paths(), &mut tally).unwrap();
        assert_eq!(tally.status(), SectionStatus::Ok);
        let got: Vec<(&str, u64)> = e
            .per_dimm
            .iter()
            .map(|d| (d.locator.as_str(), d.ce))
            .collect();
        assert_eq!(got, [("mc0/dimm0", 5), ("mc0/dimm1", 7)]);
    }

    #[test]
    fn an_unreadable_edac_counter_is_partial() {
        let h = Host::new();
        meminfo_and_edac(&h);
        h.write("DMI", sample_table());
        h.write("sys/devices/system/edac/mc/mc1/ue_count", "garbage\n");
        let m = collect_memory(&h.paths());
        assert_eq!(m.status, SectionStatus::Partial);
        assert_eq!(m.edac.unwrap().ue_total, 0);
    }
}
