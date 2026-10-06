//! SEV-SNP host health for the `v5` heartbeat.
//!
//! The kernel hands a destroyed guest's SEV-ES ASID back to the pool only
//! through `SNP_DF_FLUSH`, which it issues the first time the free pool is
//! empty — after roughly one pool's worth of launches since boot. Before
//! the flush it runs `WBINVD` on every ONLINE CPU, and the firmware
//! refuses the flush (`WBINVD_REQUIRED`, dmesg `SEV-SNP: DF_FLUSH failed,
//! ret=-5, error=0xe`) while a CPU it counted at `SNP_INIT` is offline —
//! e.g. SMT turned off from the OS after boot. From then on every new
//! guest fails `sev_common_kvm_init` with `EBUSY` until the host reboots.
//!
//! Four readings let vali alert on that before and when it happens:
//!
//! - `snp_enabled` — `/sys/module/kvm_amd/parameters/sev_snp`;
//! - `cpus_offline` — PRESENT cpus that are not online (`present` minus
//!   `online` under `/sys/devices/system/cpu`). Not the kernel's `offline`
//!   list: it can also hold hotplug slots no CPU sits in (and IDs past
//!   `kernel_max`), which never break the flush;
//! - `snp_launches_since_boot` — guest starts this agent issued since the
//!   host booted ([`record_domain_start`]), persisted across agent
//!   restarts and keyed by the kernel `boot_id`;
//! - `df_flush_failures` — `DF_FLUSH failed` lines in this boot's kernel
//!   journal. The count only grows within a boot, so the highest value read
//!   is kept: a journal that cannot be read (or has rotated the lines away)
//!   never turns a broken host back into a healthy-looking one.
//!
//! Every reading degrades to `false` / `0` rather than failing: a miner
//! must never stop heartbeating over a strange host file.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use hippius_types::heartbeat::HostHealthDeclaration;

/// Default sysfs root.
pub const DEFAULT_SYS_ROOT: &str = "/sys";

/// Default kernel boot-id file.
pub const DEFAULT_BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// The kernel line `sev_flush_asids` prints when the firmware refuses
/// `DF_FLUSH` (`arch/x86/kvm/svm/sev.c`), for SEV and SEV-SNP alike.
pub const DF_FLUSH_FAILED_MARKER: &str = "DF_FLUSH failed";

/// The journal query never holds up a heartbeat longer than this.
const JOURNAL_TIMEOUT: Duration = Duration::from_secs(10);

/// File name of the launch counter under the agent's state dir.
pub const LAUNCH_COUNTER_FILE: &str = "snp-launches-since-boot";

/// The inclusive ranges of a kernel cpu list (`""`, `"24-47"`,
/// `"1,3-5,8"`), sorted and merged. `None` for a malformed list; an
/// inverted range holds nothing.
fn cpu_list_ranges(raw: &str) -> Option<Vec<(u64, u64)>> {
    let mut ranges = Vec::new();
    let raw = raw.trim();
    if raw.is_empty() {
        return Some(ranges);
    }
    for part in raw.split(',') {
        let (lo, hi) = match part.split_once('-') {
            Some((lo, hi)) => (lo.parse::<u64>().ok()?, hi.parse::<u64>().ok()?),
            None => {
                let cpu = part.parse::<u64>().ok()?;
                (cpu, cpu)
            }
        };
        if hi >= lo {
            ranges.push((lo, hi));
        }
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        match merged.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => merged.push((lo, hi)),
        }
    }
    Some(merged)
}

fn ranges_len(ranges: &[(u64, u64)]) -> u64 {
    ranges.iter().fold(0u64, |n, (lo, hi)| {
        n.saturating_add((hi - lo).saturating_add(1))
    })
}

/// Number of CPUs in the `present` list that are not in the `online` one.
/// Either list malformed counts `0`.
pub fn present_cpus_offline(present: &str, online: &str) -> u32 {
    let (Some(present), Some(online)) = (cpu_list_ranges(present), cpu_list_ranges(online)) else {
        return 0;
    };
    // Both lists are sorted and merged: walk them together to count the
    // present CPUs that are also online.
    let mut both: u64 = 0;
    let (mut i, mut j) = (0, 0);
    while i < present.len() && j < online.len() {
        let lo = present[i].0.max(online[j].0);
        let hi = present[i].1.min(online[j].1);
        if lo <= hi {
            both = both.saturating_add((hi - lo).saturating_add(1));
        }
        if present[i].1 < online[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    u32::try_from(ranges_len(&present).saturating_sub(both)).unwrap_or(u32::MAX)
}

/// `true` for the kernel's boolean module-parameter spellings of "on".
fn param_is_on(raw: &str) -> bool {
    matches!(raw.trim(), "Y" | "y" | "1")
}

/// The `DF_FLUSH failed` lines in `journal` output.
pub fn count_df_flush_failures(journal: &str) -> u32 {
    let n = journal
        .lines()
        .filter(|line| line.contains(DF_FLUSH_FAILED_MARKER))
        .count();
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Guest starts since the host booted, persisted as `"<boot_id> <count>\n"`
/// so an agent restart keeps counting and a reboot starts over.
#[derive(Debug)]
pub struct LaunchCounter {
    path: PathBuf,
    boot_id: String,
    count: Mutex<u32>,
}

impl LaunchCounter {
    /// Open the counter at `path` for the boot identified by `boot_id`.
    /// A file from another boot, or one that does not parse, starts at 0.
    pub fn open(path: PathBuf, boot_id: String) -> Self {
        let count = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| {
                let mut parts = raw.split_whitespace();
                match (parts.next(), parts.next(), parts.next()) {
                    (Some(id), Some(n), None) if id == boot_id => n.parse::<u32>().ok(),
                    _ => None,
                }
            })
            .unwrap_or(0);
        Self {
            path,
            boot_id,
            count: Mutex::new(count),
        }
    }

    /// The current count.
    pub fn count(&self) -> u32 {
        *self.count.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Count one guest start and persist it. A failed write is logged and
    /// the in-memory count still advances.
    pub fn record(&self) {
        let mut count = self.count.lock().unwrap_or_else(|e| e.into_inner());
        *count = count.saturating_add(1);
        if let Err(e) = self.persist(*count) {
            eprintln!(
                "hippius-miner-agent: host-health: launch counter not persisted: {}",
                e.kind()
            );
        }
    }

    /// Write `<path>.new` then rename it over `path`, so a full disk can
    /// never leave a truncated counter behind.
    fn persist(&self, count: u32) -> std::io::Result<()> {
        let tmp = self.path.with_extension("new");
        std::fs::write(&tmp, format!("{} {count}\n", self.boot_id))?;
        std::fs::rename(&tmp, &self.path)
    }
}

/// The process-wide counter [`record_domain_start`] feeds.
static LAUNCH_COUNTER: OnceLock<LaunchCounter> = OnceLock::new();

/// Install the process-wide launch counter: `<state_dir>/`
/// [`LAUNCH_COUNTER_FILE`], keyed by the current kernel boot id. Called
/// once at startup; a second call is ignored. Without a readable boot id
/// nothing is installed and the count reads `0` (unknown).
pub fn install_launch_counter(
    state_dir: &Path,
    boot_id_path: &Path,
) -> Option<&'static LaunchCounter> {
    let boot_id = std::fs::read_to_string(boot_id_path)
        .ok()?
        .trim()
        .to_string();
    if boot_id.is_empty() {
        return None;
    }
    let counter = LaunchCounter::open(state_dir.join(LAUNCH_COUNTER_FILE), boot_id);
    Some(LAUNCH_COUNTER.get_or_init(|| counter))
}

/// Count one SEV-SNP guest start (each one may draw a fresh ASID). Called
/// right before every `virsh start` the agent issues, whether or not the
/// start then succeeds. A no-op until [`install_launch_counter`] ran.
pub fn record_domain_start() {
    if let Some(counter) = LAUNCH_COUNTER.get() {
        counter.record();
    }
}

/// The seam the `v5` heartbeat reads host health through.
#[async_trait]
pub trait HostHealthSource: Send + Sync {
    /// Read the host. Never fails: an unreadable value is `false` / `0`.
    async fn read(&self) -> HostHealthDeclaration;
}

/// Production [`HostHealthSource`] — sysfs, the launch counter and the
/// kernel journal.
#[derive(Debug, Clone)]
pub struct SysHostHealthSource {
    sys_root: PathBuf,
    journalctl: PathBuf,
    /// Highest `DF_FLUSH failed` count read so far. The agent process lives
    /// within one boot, so it never has to go back down.
    df_flush_seen: Arc<AtomicU32>,
}

impl Default for SysHostHealthSource {
    fn default() -> Self {
        Self::new(PathBuf::from(DEFAULT_SYS_ROOT), PathBuf::from("journalctl"))
    }
}

impl SysHostHealthSource {
    /// A source reading sysfs under `sys_root` and the journal through
    /// `journalctl` (tests point both at fixtures).
    pub fn new(sys_root: PathBuf, journalctl: PathBuf) -> Self {
        Self {
            sys_root,
            journalctl,
            df_flush_seen: Arc::new(AtomicU32::new(0)),
        }
    }

    fn read_sys(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.sys_root.join(rel)).ok()
    }

    /// The highest `DF_FLUSH failed` count seen this boot: the journal's
    /// current count, or the last one when the journal cannot be read.
    async fn df_flush_failures(&self) -> u32 {
        match self.journal_df_flush_failures().await {
            Some(n) => self.df_flush_seen.fetch_max(n, Ordering::Relaxed).max(n),
            None => self.df_flush_seen.load(Ordering::Relaxed),
        }
    }

    /// `DF_FLUSH failed` lines in this boot's kernel journal. `journalctl
    /// --grep` exits 1 with no output when nothing matches, which is a real
    /// zero; any other failure is logged and is `None`.
    async fn journal_df_flush_failures(&self) -> Option<u32> {
        let run = tokio::process::Command::new(&self.journalctl)
            .args(["-k", "-b", "0", "-q", "--no-pager", "-o", "cat", "--grep"])
            .arg(DF_FLUSH_FAILED_MARKER)
            .kill_on_drop(true)
            .output();
        let out = match tokio::time::timeout(JOURNAL_TIMEOUT, run).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                eprintln!(
                    "hippius-miner-agent: host-health: journalctl spawn failed: {}",
                    e.kind()
                );
                return None;
            }
            Err(_) => {
                eprintln!("hippius-miner-agent: host-health: journalctl timed out");
                return None;
            }
        };
        let no_match =
            out.status.code() == Some(1) && out.stdout.is_empty() && out.stderr.is_empty();
        if !out.status.success() && !no_match {
            eprintln!(
                "hippius-miner-agent: host-health: journalctl failed (status {:?})",
                out.status.code()
            );
            return None;
        }
        Some(count_df_flush_failures(&String::from_utf8_lossy(
            &out.stdout,
        )))
    }
}

#[async_trait]
impl HostHealthSource for SysHostHealthSource {
    async fn read(&self) -> HostHealthDeclaration {
        HostHealthDeclaration {
            snp_enabled: self
                .read_sys("module/kvm_amd/parameters/sev_snp")
                .is_some_and(|raw| param_is_on(&raw)),
            cpus_offline: match (
                self.read_sys("devices/system/cpu/present"),
                self.read_sys("devices/system/cpu/online"),
            ) {
                (Some(present), Some(online)) => present_cpus_offline(&present, &online),
                _ => 0,
            },
            snp_launches_since_boot: LAUNCH_COUNTER.get().map_or(0, LaunchCounter::count),
            df_flush_failures: self.df_flush_failures().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn cpu_list_ranges_reads_the_kernel_formats() {
        let count = |raw: &str| cpu_list_ranges(raw).map(|r| ranges_len(&r));
        assert_eq!(count(""), Some(0));
        assert_eq!(count("\n"), Some(0));
        assert_eq!(count("24-47\n"), Some(24));
        assert_eq!(count("3"), Some(1));
        assert_eq!(count("1,3-5,8"), Some(5));
        assert_eq!(count("5-3"), Some(0));
        assert_eq!(count("x-3"), None);
        assert_eq!(count("1,zz"), None);
        assert_eq!(count("0,,2"), None);
        assert_eq!(count("0-"), None);
        assert_eq!(
            count(&format!("0-{}", u64::MAX)),
            Some(u64::MAX),
            "a full-width range saturates instead of overflowing"
        );
    }

    #[test]
    fn present_cpus_offline_ignores_empty_hotplug_slots() {
        // All present CPUs online, 64 possible-but-absent slots: the
        // kernel's `offline` would say 64, nothing is actually offline.
        assert_eq!(present_cpus_offline("0-47\n", "0-47\n"), 0);
        // SMT siblings offlined from the OS on a 24-core / 48-thread host.
        assert_eq!(present_cpus_offline("0-47\n", "0-23\n"), 24);
        // Scattered, unsorted, overlapping and adjacent ranges.
        assert_eq!(present_cpus_offline("0-3,8-11", "0,2-3,9"), 4);
        assert_eq!(present_cpus_offline("4-7,0-3", "0-1,1-2,3"), 4);
        // An online CPU outside `present` never makes the count negative.
        assert_eq!(present_cpus_offline("0-3", "0-7"), 0);
        // Malformed input degrades to 0.
        assert_eq!(present_cpus_offline("0-x", "0"), 0);
        assert_eq!(present_cpus_offline("0-3", "zz"), 0);
    }

    #[test]
    fn df_flush_failures_counts_only_the_kernel_marker() {
        let journal = "kvm_amd: SEV-SNP: DF_FLUSH failed, ret=-5, error=0xe\n\
                       kvm_amd: something else\n\
                       kvm_amd: SEV-SNP: DF_FLUSH failed, ret=-5, error=0xe\n";
        assert_eq!(count_df_flush_failures(journal), 2);
        assert_eq!(count_df_flush_failures(""), 0);
    }

    #[test]
    fn the_launch_counter_survives_a_restart_and_resets_on_a_new_boot() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(LAUNCH_COUNTER_FILE);
        let c = LaunchCounter::open(path.clone(), "boot-a".into());
        assert_eq!(c.count(), 0);
        c.record();
        c.record();
        assert_eq!(c.count(), 2);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "boot-a 2\n");
        // An agent restart within the same boot keeps counting.
        assert_eq!(
            LaunchCounter::open(path.clone(), "boot-a".into()).count(),
            2
        );
        // A reboot starts over.
        assert_eq!(
            LaunchCounter::open(path.clone(), "boot-b".into()).count(),
            0
        );
        // A corrupt file starts over too.
        std::fs::write(&path, "garbage").unwrap();
        assert_eq!(LaunchCounter::open(path, "boot-a".into()).count(), 0);
    }

    #[test]
    fn an_unwritable_counter_still_counts_in_memory() {
        let dir = tempdir().unwrap();
        let c = LaunchCounter::open(dir.path().join("missing").join("f"), "b".into());
        c.record();
        assert_eq!(c.count(), 1);
    }

    fn fixture(snp: &str, present: &str, online: &str) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let params = dir.path().join("module/kvm_amd/parameters");
        std::fs::create_dir_all(&params).unwrap();
        std::fs::write(params.join("sev_snp"), snp).unwrap();
        let cpu = dir.path().join("devices/system/cpu");
        std::fs::create_dir_all(&cpu).unwrap();
        std::fs::write(cpu.join("present"), present).unwrap();
        std::fs::write(cpu.join("online"), online).unwrap();
        dir
    }

    /// A stand-in `journalctl` that prints `stdout` and exits `code`.
    fn fake_journalctl(dir: &Path, stdout: &str, code: i32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("journalctl");
        std::fs::write(
            &path,
            format!("#!/bin/sh\nprintf '{stdout}'\nexit {code}\n"),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[tokio::test]
    async fn reads_an_smt_off_host_whose_flush_failed() {
        let sys = fixture("Y\n", "0-47\n", "0-23\n");
        let source = SysHostHealthSource::new(
            sys.path().to_path_buf(),
            fake_journalctl(
                sys.path(),
                "kvm_amd: SEV-SNP: DF_FLUSH failed, ret=-5, error=0xe\\n",
                0,
            ),
        );
        let h = source.read().await;
        assert!(h.snp_enabled);
        assert_eq!(h.cpus_offline, 24);
        assert_eq!(h.df_flush_failures, 1);
    }

    #[tokio::test]
    async fn empty_hotplug_slots_are_not_offline_cpus() {
        // 48 threads, all online; the firmware advertises 64 more slots.
        let sys = fixture("Y\n", "0-47\n", "0-47\n");
        std::fs::write(sys.path().join("devices/system/cpu/offline"), "48-111\n").unwrap();
        let source =
            SysHostHealthSource::new(sys.path().to_path_buf(), fake_journalctl(sys.path(), "", 1));
        assert_eq!(source.read().await.cpus_offline, 0);
    }

    #[tokio::test]
    async fn no_journal_match_is_a_real_zero() {
        let sys = fixture("N\n", "0-47\n", "0-47\n");
        let source =
            SysHostHealthSource::new(sys.path().to_path_buf(), fake_journalctl(sys.path(), "", 1));
        let h = source.read().await;
        assert!(!h.snp_enabled);
        assert_eq!(h.cpus_offline, 0);
        assert_eq!(h.df_flush_failures, 0);
    }

    #[tokio::test]
    async fn an_unreadable_host_reads_all_zero() {
        let dir = tempdir().unwrap();
        let source =
            SysHostHealthSource::new(dir.path().join("missing"), dir.path().join("no-journalctl"));
        let h = source.read().await;
        assert!(!h.snp_enabled);
        assert_eq!(h.cpus_offline, 0);
        assert_eq!(h.df_flush_failures, 0);
    }

    #[tokio::test]
    async fn a_failed_journal_read_keeps_the_count_already_seen() {
        let sys = fixture("Y\n", "0-47\n", "0-23\n");
        let journalctl = fake_journalctl(sys.path(), "DF_FLUSH failed\\nDF_FLUSH failed\\n", 0);
        let source = SysHostHealthSource::new(sys.path().to_path_buf(), journalctl.clone());
        assert_eq!(source.read().await.df_flush_failures, 2);
        // The journal breaks: the host is still broken.
        std::fs::write(&journalctl, "#!/bin/sh\necho boom >&2\nexit 2\n").unwrap();
        assert_eq!(source.read().await.df_flush_failures, 2);
        // The lines rotate away: the count never goes back down this boot.
        std::fs::write(&journalctl, "#!/bin/sh\nexit 1\n").unwrap();
        assert_eq!(source.read().await.df_flush_failures, 2);
    }
}
