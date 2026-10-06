//! What the guest was actually given: online vCPUs and RAM.
//!
//! SEV-SNP measures the vCPU count (one VMSA per vCPU) but not the
//! memory size — the VMM announces that through the firmware memory map,
//! outside the launch digest. So the keepalive reads both here and folds
//! them into the PSP-signed report (`REPORT_DATA`, schema-v3 live
//! attestation); vali compares them with the VM's flavor.
//!
//! Four figures, each read from the kernel's view (`root` is `/` in
//! production, a fixture directory in tests):
//!
//! - `vcpus_online` — `sys/devices/system/cpu/online` (`0-3,6`). A host
//!   that never runs a measured vCPU leaves it offline.
//! - `mem_firmware_kib` — the `System RAM` ranges of
//!   `sys/firmware/memmap`: the RAM the VMM announced, before the kernel
//!   reserves any of it. `0` when the kernel exposes no firmware map
//!   (`CONFIG_FIRMWARE_MEMMAP=n`); vali then judges `mem_total_kib`.
//! - `mem_total_kib` — `MemTotal` of `proc/meminfo`: what the tenant
//!   sees. Lower than the firmware figure by the kernel's own boot-time
//!   reservations (the `struct page` array, and under SEV the swiotlb
//!   bounce buffer — 6 % of RAM, capped at 1 GiB), so it needs a looser
//!   threshold.
//! - `mem_unaccepted_kib` — `Unaccepted` of `proc/meminfo`: announced RAM
//!   the guest has not accepted (PVALIDATEd) yet, i.e. that the host has
//!   not had to back. OVMF leaves RAM above 4 GiB unaccepted and Linux
//!   accepts it on first use, unless the measured cmdline says
//!   `accept_memory=eager`. `0` when the line is absent (a kernel without
//!   unaccepted-memory support, which the firmware then fully accepted).
//!
//! Every parse is strict: a figure that cannot be read fails the tick
//! rather than attest a guessed value.

use hippius_types::live_attestation::GuestResources;
use std::path::Path;
use thiserror::Error;

/// Closed-vocabulary read failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResourcesError {
    #[error("cpu-online")]
    CpuOnline,
    #[error("meminfo")]
    MemInfo,
    #[error("firmware-memmap")]
    FirmwareMemmap,
}

/// Read the four figures under `root`.
pub fn read(root: &Path) -> Result<GuestResources, ResourcesError> {
    let online = std::fs::read_to_string(root.join("sys/devices/system/cpu/online"))
        .map_err(|_| ResourcesError::CpuOnline)?;
    let meminfo =
        std::fs::read_to_string(root.join("proc/meminfo")).map_err(|_| ResourcesError::MemInfo)?;
    Ok(GuestResources {
        vcpus_online: parse_cpu_list(&online).ok_or(ResourcesError::CpuOnline)?,
        mem_firmware_kib: firmware_ram_kib(&root.join("sys/firmware/memmap"))?,
        mem_total_kib: parse_mem_total_kib(&meminfo).ok_or(ResourcesError::MemInfo)?,
        mem_unaccepted_kib: parse_meminfo_kib(&meminfo, "Unaccepted:")
            .unwrap_or(Ok(0))
            .map_err(|()| ResourcesError::MemInfo)?,
    })
}

/// Count the CPUs of a kernel cpu-list (`0-3,6,8-9` ⇒ 7). `None` on any
/// malformed range, and on an empty list (a running guest has one CPU).
fn parse_cpu_list(list: &str) -> Option<u32> {
    let list = list.trim();
    if list.is_empty() {
        return None;
    }
    let mut count: u32 = 0;
    for part in list.split(',') {
        let n = match part.split_once('-') {
            Some((lo, hi)) => {
                let lo: u32 = lo.parse().ok()?;
                let hi: u32 = hi.parse().ok()?;
                hi.checked_sub(lo)?.checked_add(1)?
            }
            None => {
                part.parse::<u32>().ok()?;
                1
            }
        };
        count = count.checked_add(n)?;
    }
    Some(count)
}

/// `MemTotal:       16337812 kB` ⇒ `16337812`; absent or zero ⇒ `None`.
fn parse_mem_total_kib(meminfo: &str) -> Option<u64> {
    match parse_meminfo_kib(meminfo, "MemTotal:") {
        Some(Ok(v)) if v > 0 => Some(v),
        _ => None,
    }
}

/// The kB value of the `/proc/meminfo` line starting with `label`:
/// `None` when there is no such line, `Some(Err(()))` when it is not
/// `<label> <decimal> kB`.
fn parse_meminfo_kib(meminfo: &str, label: &str) -> Option<Result<u64, ()>> {
    let line = meminfo.lines().find(|l| l.starts_with(label))?;
    let mut words = line[label.len()..].split_whitespace();
    let value = words.next().and_then(|w| w.parse::<u64>().ok());
    Some(match (value, words.next(), words.next()) {
        (Some(v), Some("kB"), None) => Ok(v),
        _ => Err(()),
    })
}

/// Sum of the `System RAM` entries of a firmware memory map
/// (`<dir>/<n>/{start,end,type}`, `end` inclusive, hex). `Ok(0)` when the
/// directory does not exist; an entry that exists but cannot be read is
/// an error, never skipped.
fn firmware_ram_kib(dir: &Path) -> Result<u64, ResourcesError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err(ResourcesError::FirmwareMemmap),
    };
    let mut bytes: u64 = 0;
    for entry in entries {
        let path = entry.map_err(|_| ResourcesError::FirmwareMemmap)?.path();
        let read = |name: &str| {
            std::fs::read_to_string(path.join(name)).map_err(|_| ResourcesError::FirmwareMemmap)
        };
        if read("type")?.trim() != "System RAM" {
            continue;
        }
        let start = parse_hex(&read("start")?).ok_or(ResourcesError::FirmwareMemmap)?;
        let end = parse_hex(&read("end")?).ok_or(ResourcesError::FirmwareMemmap)?;
        let len = end
            .checked_sub(start)
            .and_then(|d| d.checked_add(1))
            .ok_or(ResourcesError::FirmwareMemmap)?;
        bytes = bytes
            .checked_add(len)
            .ok_or(ResourcesError::FirmwareMemmap)?;
    }
    Ok(bytes / 1024)
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A fixture root shaped like a 4 vCPU / 16 GiB SEV-SNP guest:
    /// low RAM below the PCI hole, the rest above 4 GiB, a reserved
    /// firmware range that must not count.
    fn guest_root(
        online: &str,
        memtotal: &str,
        memmap: Option<&[(&str, &str, &str)]>,
    ) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let p = root.path();
        fs::create_dir_all(p.join("sys/devices/system/cpu")).unwrap();
        fs::write(p.join("sys/devices/system/cpu/online"), online).unwrap();
        fs::create_dir_all(p.join("proc")).unwrap();
        fs::write(
            p.join("proc/meminfo"),
            format!("{memtotal}\nMemFree:         1000 kB\nUnaccepted:      2048 kB\n"),
        )
        .unwrap();
        if let Some(entries) = memmap {
            for (i, (start, end, kind)) in entries.iter().enumerate() {
                let d = p.join(format!("sys/firmware/memmap/{i}"));
                fs::create_dir_all(&d).unwrap();
                fs::write(d.join("start"), format!("{start}\n")).unwrap();
                fs::write(d.join("end"), format!("{end}\n")).unwrap();
                fs::write(d.join("type"), format!("{kind}\n")).unwrap();
            }
        }
        root
    }

    const LARGE_MAP: &[(&str, &str, &str)] = &[
        ("0x0", "0x9ffff", "System RAM"),
        ("0x100000", "0x7fffffff", "System RAM"),
        ("0x80000000", "0x80ffffff", "Reserved"),
        ("0x100000000", "0x47fffffff", "System RAM"),
    ];

    #[test]
    fn reads_a_large_guest() {
        let root = guest_root("0-3\n", "MemTotal:       15337812 kB", Some(LARGE_MAP));
        let r = read(root.path()).unwrap();
        assert_eq!(r.vcpus_online, 4);
        assert_eq!(r.mem_total_kib, 15_337_812);
        assert_eq!(r.mem_unaccepted_kib, 2048);
        // 640 KiB + (2 GiB - 1 MiB) + 14 GiB; the reserved range is out.
        assert_eq!(
            r.mem_firmware_kib,
            640 + (2 * 1024 * 1024 - 1024) + 14 * 1024 * 1024
        );
    }

    #[test]
    fn a_missing_firmware_map_is_zero_not_an_error() {
        let root = guest_root("0", "MemTotal:        3900000 kB", None);
        let r = read(root.path()).unwrap();
        assert_eq!(r.mem_firmware_kib, 0);
        assert_eq!(r.vcpus_online, 1);
    }

    #[test]
    fn no_unaccepted_line_is_zero_but_a_garbled_one_fails() {
        let root = tempfile::tempdir().unwrap();
        let p = root.path();
        fs::create_dir_all(p.join("sys/devices/system/cpu")).unwrap();
        fs::write(p.join("sys/devices/system/cpu/online"), "0\n").unwrap();
        fs::create_dir_all(p.join("proc")).unwrap();
        fs::write(p.join("proc/meminfo"), "MemTotal:  3900000 kB\n").unwrap();
        assert_eq!(read(p).unwrap().mem_unaccepted_kib, 0);
        fs::write(
            p.join("proc/meminfo"),
            "MemTotal:  3900000 kB\nUnaccepted:  lots kB\n",
        )
        .unwrap();
        assert_eq!(read(p), Err(ResourcesError::MemInfo));
    }

    #[test]
    fn cpu_lists() {
        assert_eq!(parse_cpu_list("0-3,6,8-9\n"), Some(7));
        assert_eq!(parse_cpu_list("0"), Some(1));
        assert_eq!(parse_cpu_list(""), None);
        assert_eq!(parse_cpu_list("3-1"), None);
        assert_eq!(parse_cpu_list("0-x"), None);
        assert_eq!(parse_cpu_list("0,,2"), None);
    }

    #[test]
    fn mem_total_is_strict() {
        assert_eq!(parse_mem_total_kib("MemTotal:  42 kB\n"), Some(42));
        assert_eq!(parse_mem_total_kib("MemTotal:  42 MB\n"), None);
        assert_eq!(parse_mem_total_kib("MemTotal:  0 kB\n"), None);
        assert_eq!(parse_mem_total_kib("MemFree:  42 kB\n"), None);
    }

    #[test]
    fn an_unreadable_figure_fails_the_read() {
        let root = guest_root("", "MemTotal:  1 kB", None);
        assert_eq!(read(root.path()), Err(ResourcesError::CpuOnline));
        let root = guest_root("0-1", "garbage", None);
        assert_eq!(read(root.path()), Err(ResourcesError::MemInfo));
        let root = guest_root(
            "0-1",
            "MemTotal:  1 kB",
            Some(&[("0x100000", "0xfffff", "System RAM")]),
        );
        assert_eq!(read(root.path()), Err(ResourcesError::FirmwareMemmap));
    }
}
