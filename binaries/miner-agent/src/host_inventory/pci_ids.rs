//! Device names from `pci.ids` (the `hwdata` / `pciutils` database), read
//! in one streaming pass for just the ids asked for — no `lspci` exec, no
//! whole-file map.
//!
//! ```text
//! 1000  Broadcom / LSI
//! \t0097  SAS3008 PCI-Express Fusion-MPT SAS-3
//! \t\t1028 1f45  12Gbps HBA          (a subsystem: ignored)
//! C 00  Unclassified device          (the class list: the pass stops)
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Read};
use std::path::PathBuf;

use hippius_host_inventory::MAX_TEXT_LEN;

use super::clean_text;

/// The pass reads at most this much of the file (`pci.ids` is ~1.4 MB).
pub const MAX_PCI_IDS_BYTES: u64 = 8 * 1024 * 1024;

/// `(vendor, device)` → `"<vendor name> <device name>"` (the vendor name
/// alone when the device is not listed), cut to [`MAX_TEXT_LEN`]. Reads
/// the first readable candidate; an id it does not list is absent.
pub fn names(
    candidates: &[PathBuf],
    wanted: &BTreeSet<(u16, u16)>,
) -> BTreeMap<(u16, u16), String> {
    if wanted.is_empty() {
        return BTreeMap::new();
    }
    for path in candidates {
        if let Ok(file) = std::fs::File::open(path) {
            return names_from(
                std::io::BufReader::new(file.take(MAX_PCI_IDS_BYTES)),
                wanted,
            );
        }
    }
    BTreeMap::new()
}

/// A `hhhh  name` line's id and name.
fn id_line(line: &[u8]) -> Option<(u16, &[u8])> {
    let id = std::str::from_utf8(line.get(..4)?).ok()?;
    let id = u16::from_str_radix(id, 16).ok()?;
    let name = line.get(4..)?;
    Some((id, name))
}

fn names_from(
    mut reader: impl BufRead,
    wanted: &BTreeSet<(u16, u16)>,
) -> BTreeMap<(u16, u16), String> {
    let vendors: BTreeSet<u16> = wanted.iter().map(|(v, _)| *v).collect();
    let mut vendor_names: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
    let mut device_names: BTreeMap<(u16, u16), Vec<u8>> = BTreeMap::new();
    let mut current: Option<u16> = None;
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let l = line.strip_suffix(b"\n").unwrap_or(&line);
        if l.starts_with(b"C ") {
            break;
        }
        if l.is_empty() || l.starts_with(b"#") || l.starts_with(b"\t\t") {
            continue;
        }
        if let Some(rest) = l.strip_prefix(b"\t") {
            let Some(vendor) = current else { continue };
            if let Some((device, name)) = id_line(rest) {
                if wanted.contains(&(vendor, device)) {
                    device_names.insert((vendor, device), name.to_vec());
                    if device_names.len() == wanted.len() {
                        break;
                    }
                }
            }
            continue;
        }
        current = id_line(l).and_then(|(vendor, name)| {
            vendors.contains(&vendor).then(|| {
                vendor_names.insert(vendor, name.to_vec());
                vendor
            })
        });
    }
    wanted
        .iter()
        .filter_map(|&(v, d)| {
            let vendor = clean_text(vendor_names.get(&v)?, MAX_TEXT_LEN)?;
            let device = device_names
                .get(&(v, d))
                .and_then(|n| clean_text(n, MAX_TEXT_LEN));
            let name = match device {
                Some(device) => format!("{vendor} {device}"),
                None => vendor,
            };
            clean_text(name.as_bytes(), MAX_TEXT_LEN).map(|n| ((v, d), n))
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const EXCERPT: &str = "\
#\tList of PCI ID's
#
# Syntax:
# vendor  vendor_name
#\tdevice  device_name\t\t\t\t<-- single tab
1000  Broadcom / LSI
\t0016  MegaRAID Tri-Mode SAS3508
\t\t1028 1fc9  PERC H840 Adapter
\t0097  SAS3008 PCI-Express Fusion-MPT SAS-3
10de  NVIDIA Corporation
\t2330  GH100 [H100 SXM5 80GB]
144d  Samsung Electronics Co Ltd
\ta80a  NVMe SSD Controller PM9A1/PM9A3/980PRO
14e4  Broadcom Inc. and subsidiaries
\t16d8  BCM57416 NetXtreme-E Dual-Media 10G RDMA Ethernet Controller
\t\t14e4 4163  NetXtreme-E Dual-port 10GBASE-T Ethernet OCP 2.0 Adapter (BCM957416M4163C)
1af4  Red Hat, Inc.
C 00  Unclassified device
\t00  Non-VGA unclassified device
";

    fn lookup(wanted: &[(u16, u16)]) -> BTreeMap<(u16, u16), String> {
        names_from(EXCERPT.as_bytes(), &wanted.iter().copied().collect())
    }

    #[test]
    fn finds_vendor_and_device_names() {
        let n = lookup(&[(0x1000, 0x0016), (0x14e4, 0x16d8), (0x10de, 0x2330)]);
        assert_eq!(
            n[&(0x1000, 0x0016)],
            "Broadcom / LSI MegaRAID Tri-Mode SAS3508"
        );
        assert_eq!(
            n[&(0x10de, 0x2330)],
            "NVIDIA Corporation GH100 [H100 SXM5 80GB]"
        );
        assert!(n[&(0x14e4, 0x16d8)].starts_with("Broadcom Inc. and subsidiaries BCM57416"));
        assert!(n[&(0x14e4, 0x16d8)].len() <= MAX_TEXT_LEN);
    }

    #[test]
    fn an_unknown_device_names_its_vendor_and_an_unknown_vendor_nothing() {
        let n = lookup(&[(0x1af4, 0x1041), (0xdead, 0xbeef)]);
        assert_eq!(
            n.get(&(0x1af4, 0x1041)).map(String::as_str),
            Some("Red Hat, Inc.")
        );
        assert_eq!(n.get(&(0xdead, 0xbeef)), None);
        // A subsystem line never names a device; the class list is not read.
        let n = lookup(&[(0x1028, 0x1fc9), (0x1000, 0x0000)]);
        assert_eq!(n.get(&(0x1028, 0x1fc9)), None);
        assert_eq!(
            n.get(&(0x1000, 0x0000)).map(String::as_str),
            Some("Broadcom / LSI")
        );
    }

    #[test]
    fn junk_and_missing_files_are_harmless() {
        let junk: Vec<u8> = b"zz\n\t\n\tqq\n\x00\x01\x02\n1000\n\t0016\n\xff\xfe  bad\n".to_vec();
        let n = names_from(junk.as_slice(), &[(0x1000, 0x0016)].into_iter().collect());
        assert!(n.is_empty());
        let n = names(
            &[PathBuf::from("/nonexistent/pci.ids")],
            &[(0x1000, 0x0016)].into_iter().collect(),
        );
        assert!(n.is_empty());
    }
}
