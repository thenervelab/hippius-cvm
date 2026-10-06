//! SEV-ES ASID accounting from the cgroup-v2 `misc` controller
//! (capacity v2 §2.3).
//!
//! Every SEV-SNP guest holds one SEV-ES ASID for its whole life. The
//! kernel exposes the host-wide pool on the root cgroup:
//!
//! - `/sys/fs/cgroup/misc.capacity` — e.g. `sev 907\nsev_es 99\n`
//! - `/sys/fs/cgroup/misc.current`  — e.g. `sev 0\nsev_es 2\n`
//!
//! When the pool is exhausted, a launch fails deep inside
//! `sev_common_kvm_init` — AFTER vali minted the ticket and the KBS
//! registered the VM, where vali cannot cleanly re-place. Reading the
//! pool lets the tenant preflight refuse early
//! ([`AsidUsage::admits_tenant`]) and lets the heartbeat declare it to
//! vali (a down-only clamp there).
//!
//! Any read or parse problem yields `0` = unknown, which disables the
//! gate and declares "unknown" — never a fabricated number.

use std::path::PathBuf;

/// The `misc` resource name SNP guests draw their ASID from.
pub const SEV_ES_KEY: &str = "sev_es";

/// Default location of the root cgroup's `misc` files.
pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// ASIDs held back from tenants: one for the host-attestor or a §25
/// migration destination / reboot relaunch overlap.
pub const TENANT_ASID_RESERVE: u32 = 1;

/// A snapshot of the host's SEV-ES ASID pool. `0` = unknown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AsidUsage {
    /// `misc.capacity sev_es`.
    pub capacity: u32,
    /// `misc.current sev_es`.
    pub used: u32,
}

impl AsidUsage {
    /// Whether one more TENANT guest may start while still leaving
    /// [`TENANT_ASID_RESERVE`] ASIDs free: refuses when
    /// `used + 1 > capacity - reserve`. An unknown capacity (`0`)
    /// admits — no reading, no gate.
    pub fn admits_tenant(&self) -> bool {
        if self.capacity == 0 {
            return true;
        }
        let tenant_ceiling = self.capacity.saturating_sub(TENANT_ASID_RESERVE);
        self.used.saturating_add(1) <= tenant_ceiling
    }

    /// The pair as a coherent declaration for the heartbeat: an
    /// impossible reading (`used > capacity` with a known capacity) is
    /// declared fully unknown rather than sent — the heartbeat schema
    /// rejects it, and a miner must never stop heartbeating over a
    /// strange kernel counter.
    pub fn coherent(self) -> Self {
        if self.capacity != 0 && self.used > self.capacity {
            return Self::default();
        }
        self
    }
}

/// The value of `key` in a cgroup `misc.*` flat-keyed file
/// (`"<key> <value>\n"` lines). A missing key, a non-numeric value
/// (e.g. `max`) or an empty file yields `0` (unknown). Values beyond
/// `u32` saturate.
pub fn parse_misc_value(raw: &str, key: &str) -> u32 {
    raw.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some(k), Some(v), None) if k == key => Some(v),
                _ => None,
            }
        })
        .next()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

/// The seam the preflight gate and the heartbeat read the pool through.
pub trait AsidSource: Send + Sync {
    /// Read the current pool. Never fails: unknown is `0`.
    fn read(&self) -> AsidUsage;
}

/// Production [`AsidSource`] — reads `misc.capacity` / `misc.current`
/// under a cgroup-v2 root.
#[derive(Debug, Clone)]
pub struct SysfsAsidSource {
    root: PathBuf,
}

impl SysfsAsidSource {
    /// A reader rooted at `root` (tests point it at a fixture dir).
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl Default for SysfsAsidSource {
    fn default() -> Self {
        Self::new(PathBuf::from(DEFAULT_CGROUP_ROOT))
    }
}

impl AsidSource for SysfsAsidSource {
    fn read(&self) -> AsidUsage {
        let value = |file: &str| {
            std::fs::read_to_string(self.root.join(file))
                .map(|raw| parse_misc_value(&raw, SEV_ES_KEY))
                .unwrap_or(0)
        };
        AsidUsage {
            capacity: value("misc.capacity"),
            used: value("misc.current"),
        }
    }
}

/// A fixed [`AsidSource`] — for tests and for hosts where the reading
/// is known in advance.
#[derive(Debug, Clone, Copy, Default)]
pub struct FixedAsidSource(pub AsidUsage);

impl AsidSource for FixedAsidSource {
    fn read(&self) -> AsidUsage {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPACITY: &str = "sev 907\nsev_es 99\n";
    const CURRENT: &str = "sev 0\nsev_es 2\n";

    #[test]
    fn parses_the_real_host_files() {
        assert_eq!(parse_misc_value(CAPACITY, SEV_ES_KEY), 99);
        assert_eq!(parse_misc_value(CURRENT, SEV_ES_KEY), 2);
        // `sev` is a different key — never confused with `sev_es`.
        assert_eq!(parse_misc_value(CAPACITY, "sev"), 907);
    }

    #[test]
    fn missing_key_or_garbage_is_unknown() {
        assert_eq!(parse_misc_value("", SEV_ES_KEY), 0);
        assert_eq!(parse_misc_value("sev 907\n", SEV_ES_KEY), 0);
        assert_eq!(parse_misc_value("sev_es max\n", SEV_ES_KEY), 0);
        assert_eq!(parse_misc_value("sev_es -1\n", SEV_ES_KEY), 0);
        assert_eq!(parse_misc_value("sev_es 1 2\n", SEV_ES_KEY), 0);
        assert_eq!(parse_misc_value("sev_es_x 5\n", SEV_ES_KEY), 0);
    }

    #[test]
    fn oversize_value_saturates() {
        assert_eq!(
            parse_misc_value("sev_es 99999999999\n", SEV_ES_KEY),
            u32::MAX
        );
    }

    #[test]
    fn sysfs_reader_reads_the_fixture_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("misc.capacity"), CAPACITY).unwrap();
        std::fs::write(dir.path().join("misc.current"), CURRENT).unwrap();
        let usage = SysfsAsidSource::new(dir.path().to_path_buf()).read();
        assert_eq!(
            usage,
            AsidUsage {
                capacity: 99,
                used: 2
            }
        );
    }

    #[test]
    fn sysfs_reader_missing_files_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            SysfsAsidSource::new(dir.path().to_path_buf()).read(),
            AsidUsage::default()
        );
        // Only `misc.current` present — capacity unknown, used known.
        std::fs::write(dir.path().join("misc.current"), CURRENT).unwrap();
        assert_eq!(
            SysfsAsidSource::new(dir.path().to_path_buf()).read(),
            AsidUsage {
                capacity: 0,
                used: 2
            }
        );
    }

    #[test]
    fn tenant_gate_refuses_at_the_exact_boundary() {
        // capacity 99, reserve 1 ⇒ tenants may hold at most 98.
        let at = |used| AsidUsage { capacity: 99, used };
        assert!(at(0).admits_tenant());
        assert!(at(97).admits_tenant(), "the 98th ASID is still a tenant's");
        assert!(!at(98).admits_tenant(), "the 99th is the reserve");
        assert!(!at(99).admits_tenant());
        assert!(!at(200).admits_tenant());
    }

    #[test]
    fn tenant_gate_tiny_pools() {
        assert!(!AsidUsage {
            capacity: 1,
            used: 0
        }
        .admits_tenant());
        assert!(AsidUsage {
            capacity: 2,
            used: 0
        }
        .admits_tenant());
        assert!(!AsidUsage {
            capacity: 2,
            used: 1
        }
        .admits_tenant());
    }

    #[test]
    fn unknown_capacity_never_gates() {
        assert!(AsidUsage {
            capacity: 0,
            used: 0
        }
        .admits_tenant());
        assert!(AsidUsage {
            capacity: 0,
            used: u32::MAX
        }
        .admits_tenant());
    }

    #[test]
    fn coherent_drops_an_impossible_reading() {
        let ok = AsidUsage {
            capacity: 99,
            used: 99,
        };
        assert_eq!(ok.coherent(), ok);
        assert_eq!(
            AsidUsage {
                capacity: 99,
                used: 100
            }
            .coherent(),
            AsidUsage::default()
        );
        let unknown_cap = AsidUsage {
            capacity: 0,
            used: 5,
        };
        assert_eq!(unknown_cap.coherent(), unknown_cap);
    }
}
