//! Host inventory collector (disk-tier design §18.10.2).
//!
//! The `host-inventory-collect` oneshot reads the host — sysfs, procfs,
//! the SMBIOS table, `pci.ids`, a few distro tools with a bound — and
//! leaves one `<section>.json` per section of the `hippius-host-inventory`
//! wire format under `/run/hippius-miner/inventory`. It runs OUTSIDE the
//! agent's sandbox (which shows no device and no DMI table); the agent
//! reads the files, signs and posts them. Nothing here writes to a device
//! or changes host state.
//!
//! Every reading degrades rather than failing: a missing source is a
//! `None` field and a `partial` / `unavailable` section status, never an
//! error and never a panic. Strings are cut to the crate's printable-ASCII
//! bounds here ([`clean_text`]), so a strange firmware string is trimmed or
//! dropped, never refused at vali.
//!
//! Privacy (§18.10.3): no MAC address, no IP address (an interface reports
//! its role), no hostname; virtual interfaces are counted, never named.
//!
//! Part 1: system, cpu, memory, software, network, pci. Part 2a: the
//! storage inventory and its SMART / NVMe / RAID advisories ([`storage`]).
//! Sensors, IPMI firmware and the kernel journal come later.

pub mod auto_update;
pub mod cpu;
pub mod kernel;
pub mod memory;
pub mod network;
pub mod pci;
pub mod pci_ids;
pub mod poster;
pub mod sensors;
pub mod smbios;
pub mod software;
pub mod storage;
pub mod system;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hippius_host_inventory::{
    HostInventory, InventoryResult, ReportKind, SectionStatus, Sections, DOMAIN, SCHEMA_VERSION,
};
use serde::Serialize;

pub use cpu::collect_cpu;
pub use memory::collect_memory;
pub use network::collect_network;
pub use pci::collect_pci;
pub use sensors::collect_sensors;
pub use software::collect_software;
pub use storage::{collect_storage, NoProbeTime, StorageInputs, StorageView};
pub use system::collect_system;

/// Where the collector leaves its sections, and the agent reads them.
pub const INVENTORY_DIR: &str = "/run/hippius-miner/inventory";

/// How long one tool (`ethtool`, `ip`, `qemu-system-x86_64 --version`, …)
/// may take before its reading is given up.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// A tool's stdout past this is not read (every parser wants a few lines).
const MAX_COMMAND_OUTPUT: u64 = 256 * 1024;

/// Where the collector reads the host. Real paths by default; fixtures in
/// tests.
#[derive(Debug, Clone)]
pub struct HostPaths {
    pub sys: PathBuf,
    pub proc: PathBuf,
    /// `os-release` candidates, the first readable one wins.
    pub os_release: Vec<PathBuf>,
    /// The raw SMBIOS structure table (root-only).
    pub dmi_table: PathBuf,
    /// `pci.ids` candidates, the first readable one wins.
    pub pci_ids: Vec<PathBuf>,
    /// Its presence alone says a BMC is reachable in-band.
    pub ipmi_device: PathBuf,
    /// `/dev/disk/by-id` (read as links only, never opened).
    pub by_id: PathBuf,
    /// udev's database (`b<major>:<minor>` per block device).
    pub udev_data: PathBuf,
    /// The host's `/`: a pool path or the state root is `statvfs`ed under
    /// it.
    pub host_root: PathBuf,
    /// `/etc/fstab`: what is configured on a boot path, mounted or not.
    pub fstab: PathBuf,
    /// The auto-updater's files (`software.auto_update`); `None`: not
    /// reported (`host-inventory-collect` without `--report-auto-update`).
    pub auto_update: Option<auto_update::AutoUpdatePaths>,
}

impl Default for HostPaths {
    fn default() -> Self {
        Self {
            sys: PathBuf::from("/sys"),
            proc: PathBuf::from("/proc"),
            os_release: vec![
                PathBuf::from("/etc/os-release"),
                PathBuf::from("/usr/lib/os-release"),
            ],
            dmi_table: PathBuf::from("/sys/firmware/dmi/tables/DMI"),
            pci_ids: vec![
                PathBuf::from("/usr/share/misc/pci.ids"),
                PathBuf::from("/usr/share/hwdata/pci.ids"),
            ],
            ipmi_device: PathBuf::from("/dev/ipmi0"),
            by_id: PathBuf::from("/dev/disk/by-id"),
            udev_data: PathBuf::from("/run/udev/data"),
            host_root: PathBuf::from("/"),
            fstab: PathBuf::from("/etc/fstab"),
            auto_update: None,
        }
    }
}

// ─── reading ─────────────────────────────────────────────────────────

/// One source file, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Found(String),
    /// Not there: the feature is absent (no cpufreq driver, no EDAC).
    Missing,
    /// There, but unreadable (permissions, I/O).
    Failed,
}

impl Source {
    pub fn read(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => Self::Found(String::from_utf8_lossy(&bytes).trim().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::Missing,
            Err(_) => Self::Failed,
        }
    }

    pub fn found(self) -> Option<String> {
        match self {
            Self::Found(s) => Some(s),
            _ => None,
        }
    }
}

/// A file's trimmed content, any failure `None`.
pub(crate) fn read_trimmed(path: &Path) -> Option<String> {
    Source::read(path).found()
}

/// The basename of a symlink's target (`device/driver` → `bnxt_en`).
pub(crate) fn link_name(path: &Path) -> Option<String> {
    std::fs::read_link(path)
        .ok()?
        .file_name()?
        .to_str()
        .map(str::to_string)
}

/// The names in a directory, sorted (an unreadable one is empty).
pub(crate) fn dir_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// `0x14e4` (sysfs `vendor`, `device`) as a number.
pub(crate) fn parse_hex_u32(s: &str) -> Option<u32> {
    let s = s.trim();
    u32::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok()
}

/// Firmware placeholders that mean "nobody filled this in".
const PLACEHOLDERS: [&str; 18] = [
    "to be filled by o.e.m.",
    "to be filled by oem",
    "default string",
    "not specified",
    "not applicable",
    "not available",
    "system serial number",
    "system product name",
    "system manufacturer",
    "system version",
    "base board serial number",
    "chassis serial number",
    "o.e.m.",
    "oem",
    "unknown",
    "none",
    "n/a",
    "0123456789",
];

/// `raw` as the crate accepts a host string: printable ASCII only (any
/// other byte dropped), trimmed, at most `max` bytes, never empty, never a
/// firmware placeholder ([`PLACEHOLDERS`]; all-`0xFF` bytes clean to
/// nothing). `None` when nothing is left.
pub fn clean_text(raw: &[u8], max: usize) -> Option<String> {
    let printable: String = raw
        .iter()
        .filter(|b| (0x20..0x7f).contains(*b))
        .map(|&b| char::from(b))
        .collect();
    let mut s = printable.trim().to_string();
    // ASCII only, so any byte index is a char boundary.
    s.truncate(max);
    let s = s.trim_end();
    if s.is_empty() || PLACEHOLDERS.contains(&s.to_ascii_lowercase().as_str()) {
        return None;
    }
    Some(s.to_string())
}

/// What a section read: the status follows from it.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Tally {
    ok: u32,
    failed: u32,
    timed_out: bool,
}

impl Tally {
    pub(crate) fn ok(&mut self) {
        self.ok += 1;
    }

    pub(crate) fn failed(&mut self) {
        self.failed += 1;
    }

    pub(crate) fn note(&mut self, ok: bool) {
        if ok {
            self.ok();
        } else {
            self.failed();
        }
    }

    /// A bound expired: the section carries what it read.
    pub(crate) fn timed_out(&mut self) {
        self.timed_out = true;
    }

    /// Add what `other` read.
    pub(crate) fn merge(&mut self, other: Tally) {
        self.ok = self.ok.saturating_add(other.ok);
        self.failed = self.failed.saturating_add(other.failed);
        self.timed_out |= other.timed_out;
    }

    pub(crate) fn command<T>(&mut self, r: &Result<T, CommandError>) {
        match r {
            Ok(_) => self.ok(),
            // The tool is not installed: nothing to report, not a fault.
            Err(CommandError::NotFound) => {}
            Err(CommandError::Failed) => self.failed(),
            Err(CommandError::Timeout) => self.timed_out = true,
        }
    }

    /// A source file the section needs: missing or unreadable is a fault.
    pub(crate) fn required(&mut self, s: Source) -> Option<String> {
        match s {
            Source::Found(v) => {
                self.ok();
                Some(v)
            }
            _ => {
                self.failed();
                None
            }
        }
    }

    /// A source file whose absence means the feature is absent: only an
    /// unreadable one is a fault.
    pub(crate) fn optional(&mut self, s: Source) -> Option<String> {
        match s {
            Source::Found(v) => Some(v),
            Source::Missing => None,
            Source::Failed => {
                self.failed();
                None
            }
        }
    }

    pub(crate) fn status(&self) -> SectionStatus {
        if self.timed_out {
            SectionStatus::Timeout
        } else if self.ok == 0 {
            SectionStatus::Unavailable
        } else if self.failed > 0 {
            SectionStatus::Partial
        } else {
            SectionStatus::Ok
        }
    }
}

// ─── tools ───────────────────────────────────────────────────────────

/// Why a tool gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandError {
    /// Not installed.
    NotFound,
    /// It ran and failed (a non-zero exit, a spawn error).
    Failed,
    /// It outlived [`COMMAND_TIMEOUT`] and was killed.
    Timeout,
}

/// Runs a host tool and returns its stdout. A trait so tests inject the
/// output.
pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, CommandError>;

    /// [`Self::run`] bounded by `timeout` instead of the runner's own.
    /// `any_exit`: the stdout whatever the exit status, for a tool that
    /// reports its verdict in its output and its exit bits (`smartctl`
    /// exits non-zero for a failing disk, with the JSON that says so).
    fn run_bounded(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
        any_exit: bool,
    ) -> Result<String, CommandError> {
        let _ = (timeout, any_exit);
        self.run(program, args)
    }

    /// [`Self::run_bounded`], and the tool's exit code when it exited
    /// non-zero (`None`: it exited 0, was killed, never ran — or the
    /// runner does not know). For a log line saying how a tool failed;
    /// never its output.
    fn run_bounded_status(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
        any_exit: bool,
    ) -> (Result<String, CommandError>, Option<i32>) {
        (self.run_bounded(program, args, timeout, any_exit), None)
    }

    /// [`Self::run_bounded`] (exit 0 required) for a tool whose output
    /// can be longer than the stdout cap: at the cap the tool is stopped
    /// (its process group killed) and what was read is the answer, not a
    /// failure (a journal past a log storm: the rest is read next run).
    fn run_capped(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<String, CommandError> {
        self.run_bounded(program, args, timeout, false)
    }
}

/// The real tools, each bounded by `timeout` (killed past it), `LC_ALL=C`,
/// no stdin, stderr discarded, stdout capped at [`MAX_COMMAND_OUTPUT`].
#[derive(Debug, Clone, Copy)]
pub struct SystemRunner {
    pub timeout: Duration,
}

impl Default for SystemRunner {
    fn default() -> Self {
        Self {
            timeout: COMMAND_TIMEOUT,
        }
    }
}

/// The tools' `PATH`: the system directories only, never the caller's.
const TOOL_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// How the tool's own process ended.
enum Exit {
    Status(std::process::ExitStatus),
    TimedOut,
    WaitFailed,
    /// `stop_at_cap`: the output reached the cap; the tool was stopped.
    Capped,
}

/// SIGKILL every process of the group `pgid` (the tool and anything it
/// left behind). A group already gone is fine.
fn kill_group(pgid: Option<nix::unistd::Pid>) {
    if let Some(pgid) = pgid {
        let _ = nix::sys::signal::killpg(pgid, nix::sys::signal::Signal::SIGKILL);
    }
}

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, CommandError> {
        exec(program, args, self.timeout, false, false)
    }

    fn run_bounded(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
        any_exit: bool,
    ) -> Result<String, CommandError> {
        exec(program, args, timeout, any_exit, false)
    }

    fn run_bounded_status(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
        any_exit: bool,
    ) -> (Result<String, CommandError>, Option<i32>) {
        exec_status(program, args, timeout, any_exit, false)
    }

    fn run_capped(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<String, CommandError> {
        exec(program, args, timeout, false, true)
    }
}

/// [`SystemRunner`]'s one run: `program` bounded by `timeout`; a non-zero
/// exit is [`CommandError::Failed`] unless `any_exit`. `stop_at_cap`: at
/// [`MAX_COMMAND_OUTPUT`] the tool is stopped and the bytes read are the
/// answer.
fn exec(
    program: &str,
    args: &[&str],
    timeout: Duration,
    any_exit: bool,
    stop_at_cap: bool,
) -> Result<String, CommandError> {
    exec_status(program, args, timeout, any_exit, stop_at_cap).0
}

/// [`exec`], and the tool's exit code when it exited non-zero.
fn exec_status(
    program: &str,
    args: &[&str],
    timeout: Duration,
    any_exit: bool,
    stop_at_cap: bool,
) -> (Result<String, CommandError>, Option<i32>) {
    use std::os::unix::process::CommandExt;
    // Its own process group, so a timeout reaches the grandchildren
    // too: one of them holding stdout would otherwise keep the pipe
    // (and the reader) open past the deadline.
    let child = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", TOOL_PATH)
        .env("LC_ALL", "C")
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (Err(CommandError::NotFound), None)
        }
        Err(_) => return (Err(CommandError::Failed), None),
    };
    let pgid = i32::try_from(child.id())
        .ok()
        .map(nix::unistd::Pid::from_raw);
    // Read stdout as it comes (a full pipe would stall the tool until
    // the deadline), and drain what is past the cap. The result comes
    // back over a channel with a bound: a reader still blocked past it
    // is detached, never joined.
    let (tx, rx) = std::sync::mpsc::channel::<(Vec<u8>, bool)>();
    if let Some(out) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut out = out;
            let mut kept = Vec::new();
            let _ = (&mut out).take(MAX_COMMAND_OUTPUT).read_to_end(&mut kept);
            let capped = kept.len() as u64 >= MAX_COMMAND_OUTPUT;
            if !(stop_at_cap && capped) {
                let _ = std::io::copy(&mut out, &mut std::io::sink());
            }
            let _ = tx.send((kept, capped));
        });
    }
    let deadline = std::time::Instant::now() + timeout;
    // What the reader sent before the tool exited (`stop_at_cap` only).
    let mut early: Option<(Vec<u8>, bool)> = None;
    let exit = loop {
        if stop_at_cap && early.is_none() {
            if let Ok((kept, capped)) = rx.try_recv() {
                early = Some((kept, capped));
                if capped {
                    break Exit::Capped;
                }
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break Exit::Status(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => break Exit::TimedOut,
            Err(_) => break Exit::WaitFailed,
        }
    };
    // The tool is done (or given up): whatever it left running in its
    // group goes with it, which also closes the pipe for the reader.
    kill_group(pgid);
    if matches!(exit, Exit::TimedOut | Exit::WaitFailed | Exit::Capped) {
        let _ = child.kill();
        // SIGKILL cannot end a process in an uninterruptible wait (a
        // tool stuck on a wedged driver's lock): reap it within a
        // bound, else hand it to a detached reaper, never block here.
        let reap_by = std::time::Instant::now() + Duration::from_millis(500);
        let reaped = loop {
            match child.try_wait() {
                Ok(None) if std::time::Instant::now() < reap_by => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => break false,
                _ => break true,
            }
        };
        if !reaped {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let stdout = match early {
        Some(read) => Ok(read),
        None => rx.recv_timeout(remaining.max(Duration::from_millis(500))),
    };
    // A capped read is a success however the tool then ended: it may
    // die of SIGPIPE once the reader stops, before the loop above saw the
    // cap.
    if let (true, Ok((out, true))) = (stop_at_cap, &stdout) {
        return (Ok(String::from_utf8_lossy(out).into_owned()), None);
    }
    let stdout = stdout.map(|(kept, _)| kept);
    let code = match &exit {
        Exit::Status(s) if !s.success() => s.code(),
        _ => None,
    };
    let result = match (exit, stdout) {
        (Exit::Capped, Ok(out)) => Ok(String::from_utf8_lossy(&out).into_owned()),
        (Exit::Capped, Err(_)) => Err(CommandError::Failed),
        (Exit::TimedOut, _) => Err(CommandError::Timeout),
        (Exit::WaitFailed, _) => Err(CommandError::Failed),
        (Exit::Status(s), Ok(out)) if s.success() || (any_exit && s.code().is_some()) => {
            Ok(String::from_utf8_lossy(&out).into_owned())
        }
        (Exit::Status(s), Err(_)) if s.success() || any_exit => Err(CommandError::Timeout),
        (Exit::Status(_), _) => Err(CommandError::Failed),
    };
    (result, code)
}

// ─── the oneshot ─────────────────────────────────────────────────────

/// Which sections a run collects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// All eight sections.
    Full,
    /// The fast-moving counters: memory (EDAC), sensors, storage (the
    /// disk advisories; a section is replaced whole, so with its
    /// inventory), software (uptime).
    Counters,
}

/// Collect the sections of `mode`, and the storage [`storage::Counters`]
/// to keep for the next run. Storage comes LAST, its SMART probe the last
/// step of all (bounded by the run's deadline): every other section, and
/// every other tool (`ip`, `ethtool`, the version probes), runs before
/// it. [`NoProbeTime`]: nothing is returned, so nothing gets written.
pub fn collect(
    mode: Mode,
    paths: &HostPaths,
    runner: &dyn CommandRunner,
    now_unix: i64,
    storage: &StorageInputs<'_>,
) -> Result<(Sections, storage::Counters), NoProbeTime> {
    // Sensors and IPMI before storage: the SMART probe stays last.
    let sensors = collect_sensors(paths, runner);
    for line in &sensors.notes {
        eprintln!("{line}");
    }
    if sensors.dropped > 0 {
        eprintln!(
            "hippius-miner-agent: host-inventory-collect: sensors: {} reading(s) dropped \
             (unlisted label or past the cap)",
            sensors.dropped
        );
    }
    let mut sections = match mode {
        Mode::Counters => Sections {
            memory: Some(collect_memory(paths)),
            sensors: Some(sensors.section),
            software: Some(collect_software(paths, runner, now_unix)),
            ..Sections::default()
        },
        Mode::Full => Sections {
            system: Some(collect_system(paths, runner)),
            cpu: Some(collect_cpu(paths)),
            memory: Some(collect_memory(paths)),
            sensors: Some(sensors.section),
            software: Some(collect_software(paths, runner, now_unix)),
            network: Some(collect_network(paths, runner)),
            pci: Some(collect_pci(paths)),
            ..Sections::default()
        },
    };
    let (storage_section, counters) = collect_storage(paths, runner, storage, now_unix)?;
    sections.storage = Some(storage_section);
    Ok((sections, counters))
}

/// The time source of a run (a fake one in tests).
pub trait Clock: Send + Sync {
    fn now(&self) -> std::time::Instant;
}

/// The monotonic clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}

/// Put `sections` in their one valid order and fit the caps
/// ([`HostInventory::canonical_fitted`]: normalize, validate, trim the
/// storage inventory to the body cap) inside a stand-in body, so a
/// collector bug fails here, loudly, rather than at vali. The body's
/// header is the agent's to fill: only the sections are checked, under
/// the longest miner id (the fit is never looser than the agent's).
///
/// A `Full` run carries all eight sections: it is checked as a real
/// `full` report.
pub fn normalize_and_check(sections: Sections, mode: Mode, now_unix: i64) -> CheckedSections {
    let mut body = HostInventory {
        schema_version: SCHEMA_VERSION,
        domain: DOMAIN.to_string(),
        miner_id: "x".repeat(hippius_host_inventory::MAX_MINER_ID_LEN),
        timestamp_unix: now_unix,
        sequence: 0,
        report: match mode {
            Mode::Full => ReportKind::Full,
            Mode::Counters => ReportKind::Counters,
        },
        sections,
    };
    let valid = body.canonical_fitted().map(|_| ());
    CheckedSections {
        sections: body.sections,
        valid,
    }
}

/// Normalized sections and what [`HostInventory::validate`] made of them.
#[derive(Debug, Clone)]
pub struct CheckedSections {
    pub sections: Sections,
    pub valid: InventoryResult<()>,
}

/// Write each present section as `<dir>/<section>.json`, atomically.
/// Returns the names written.
pub fn write_sections(sections: &Sections, dir: &Path) -> std::io::Result<Vec<&'static str>> {
    let mut written = Vec::new();
    let mut put = |name: &'static str, value: Option<&dyn ErasedSection>| -> std::io::Result<()> {
        if let Some(v) = value {
            save_json(dir, name, &v.to_json()?)?;
            written.push(name);
        }
        Ok(())
    };
    put("system", sections.system.as_ref().map(|s| s as _))?;
    put("cpu", sections.cpu.as_ref().map(|s| s as _))?;
    put("memory", sections.memory.as_ref().map(|s| s as _))?;
    put("storage", sections.storage.as_ref().map(|s| s as _))?;
    put("network", sections.network.as_ref().map(|s| s as _))?;
    put("pci", sections.pci.as_ref().map(|s| s as _))?;
    put("sensors", sections.sensors.as_ref().map(|s| s as _))?;
    put("software", sections.software.as_ref().map(|s| s as _))?;
    Ok(written)
}

/// A section, serialized.
trait ErasedSection {
    fn to_json(&self) -> std::io::Result<Vec<u8>>;
}

impl<T: Serialize> ErasedSection for T {
    fn to_json(&self) -> std::io::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(std::io::Error::other)
    }
}

/// `bytes` to `<dir>/<name>.json`: a temp file in `dir`, fsync, rename,
/// then fsync `dir` (the rename is durable only once the directory is).
fn save_json(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(dir.join(format!("{name}.json")))
        .map_err(|e| e.error)?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// What a `host-inventory-collect` run did.
#[derive(Debug, Clone)]
pub struct CollectSummary {
    /// Why the run did nothing: nothing collected, nothing written
    /// ([`on_skip`] says what the exit is).
    pub skipped: Option<Skip>,
    pub written: Vec<&'static str>,
    /// The validation of the written sections (they are written either
    /// way; the error class is logged).
    pub valid: InventoryResult<()>,
}

/// The oneshot: collect `mode`, normalize and check, write every section
/// to `dir`, then the storage counters for the next run
/// ([`storage::Counters`], `<dir>/.storage-counters.json`). `view` is the
/// agent's storage view (`None`: its config could not be read).
///
/// `started` is when the process started: the whole run — lock wait,
/// collection, SMART probe, write — fits [`RUN_DEADLINE`] from it.
pub fn run_collect(
    mode: Mode,
    paths: &HostPaths,
    runner: &dyn CommandRunner,
    now_unix: i64,
    dir: &Path,
    view: Option<&StorageView>,
    started: std::time::Instant,
) -> std::io::Result<CollectSummary> {
    let wait = RunDeadline::lock_wait(mode, started.elapsed());
    run_collect_locked(
        mode,
        paths,
        runner,
        now_unix,
        dir,
        view,
        wait,
        started,
        &SystemClock,
    )
}

// ─── the run's time budget (coupled to the unit) ─────────────────────
//
// The collector runs as the oneshot `hippius-host-inventory@<mode>`
// (HW7). Every bound here is derived from [`UNIT_TIMEOUT`], and the HW7
// units MUST match it:
//
//   TimeoutStartSec=15min      (= UNIT_TIMEOUT: systemd kills a run past
//                               it, mid-probe, and its report is lost)
//   Restart=on-failure
//   RestartSec=300
//   StartLimitIntervalSec=1h
//   StartLimitBurst=3          (or more: room for the retries)
//
// The real bound: a run, counted from PROCESS START, spends at most
// [`RUN_DEADLINE`] (14 min) on its lock wait, its collection and its
// SMART probe together: `elapsed + lock wait + SMART budget ≤
// RUN_DEADLINE − WRITE_MARGIN` (13 min), leaving the write margin and
// one more minute before the unit's timeout. A run that cannot get the
// lock, or gets it with less than [`MIN_PROBE_WINDOW`] of probe time
// left, writes nothing: a `full` run then exits non-zero ([`on_skip`])
// and the unit retries it; a `counters` run exits 0 (its next tick is
// 6 h away at most, and its sections are refreshed by every `full`).

/// The units' `TimeoutStartSec=`.
pub const UNIT_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Kept free at the end of a run for normalizing and writing the
/// sections.
pub const WRITE_MARGIN: Duration = Duration::from_secs(60);

/// The whole run, from process start: the unit timeout less a minute.
pub const RUN_DEADLINE: Duration = Duration::from_secs(UNIT_TIMEOUT.as_secs() - 60);

/// The least SMART budget a run starts its probe with; less left after
/// the lock and the run does nothing ([`Skip::NoTime`]).
pub const MIN_PROBE_WINDOW: Duration = Duration::from_secs(2 * 60);

/// How long a `counters` run waits for another (a `full` and a `counters`
/// run overlapping) at most.
pub const LOCK_WAIT: Duration = Duration::from_secs(60);

/// The run's time budget, as pure functions of the time already spent
/// (`elapsed` since process start), so it is tested without a clock.
pub struct RunDeadline;

impl RunDeadline {
    /// The most a `mode` run ever waits for the lock: a `full` run
    /// (daily: a skipped one is a day without it) a whole SMART probe of
    /// the other run and some; a `counters` run [`LOCK_WAIT`].
    pub fn lock_wait_cap(mode: Mode) -> Duration {
        match mode {
            Mode::Full => storage::health::SMART_BUDGET + Duration::from_secs(120),
            Mode::Counters => LOCK_WAIT,
        }
    }

    /// Time left for the probe at `elapsed`: to [`RUN_DEADLINE`] less the
    /// [`WRITE_MARGIN`].
    fn left(elapsed: Duration) -> Duration {
        RUN_DEADLINE
            .saturating_sub(WRITE_MARGIN)
            .saturating_sub(elapsed)
    }

    /// The lock wait, `elapsed` into the run: its cap, but a lock taken at
    /// its very end still leaves [`MIN_PROBE_WINDOW`].
    pub fn lock_wait(mode: Mode, elapsed: Duration) -> Duration {
        Self::lock_wait_cap(mode).min(Self::left(elapsed).saturating_sub(MIN_PROBE_WINDOW))
    }

    /// The absolute instant no SMART tool may outlive, for a run started
    /// at `started`: `started + RUN_DEADLINE − WRITE_MARGIN`.
    pub fn probe_deadline(started: std::time::Instant) -> std::time::Instant {
        started + RUN_DEADLINE.saturating_sub(WRITE_MARGIN)
    }

    /// The SMART probe's budget, `elapsed` into the run with the lock
    /// held: what is left, capped at
    /// [`SMART_BUDGET`](storage::health::SMART_BUDGET) (the devices past
    /// a shortened one are `collector_timeout`). `None`: less than
    /// [`MIN_PROBE_WINDOW`] left, the run does nothing.
    pub fn smart_budget(elapsed: Duration) -> Option<Duration> {
        let left = Self::left(elapsed);
        (left >= MIN_PROBE_WINDOW).then(|| storage::health::SMART_BUDGET.min(left))
    }
}

/// Why a run did nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// Another run held the lock past [`RunDeadline::lock_wait`].
    LockHeld,
    /// The lock came too late: less than [`MIN_PROBE_WINDOW`] was left
    /// for the probe before [`RUN_DEADLINE`].
    NoTime,
}

/// What a run that did nothing does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusyOutcome {
    /// Exit 0: the next timer tick comes soon (`counters`).
    Skip,
    /// Exit non-zero, so the unit's `Restart=on-failure` retries it
    /// (`full`: otherwise lost for a day).
    Fail,
}

/// The exit of a `mode` run that did nothing, whatever the [`Skip`].
pub fn on_skip(mode: Mode) -> BusyOutcome {
    match mode {
        Mode::Full => BusyOutcome::Fail,
        Mode::Counters => BusyOutcome::Skip,
    }
}

/// The run lock, `<dir>/.collect.lock`.
pub const LOCK_NAME: &str = ".collect.lock";

/// What a `--mode kernel` run did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelOutcome {
    /// A `full` / `counters` run held the lock: skipped (exit 0).
    Busy,
    /// Past the kernel run's deadline before the journal could be read.
    NoTime,
    /// `journalctl` is not installed.
    NoJournal,
    /// `journalctl` failed or timed out: the cursor is kept and its
    /// failure counted; after `MAX_CURSOR_FAILURES` in a row the next run
    /// resumes by time (`--since`).
    JournalFault(CommandError),
    Read(kernel::JournalStats),
}

/// The `--mode kernel` run: under the collector's run lock (waited for
/// [`kernel::KERNEL_LOCK_WAIT`]), read the journal past the saved cursor
/// within [`kernel::KERNEL_RUN_DEADLINE`] of `started`, fold the matches
/// into the pending events and save the cursor with them, atomically.
/// No section is written: the next `full` / `counters` run reports them.
pub fn run_kernel(
    paths: &HostPaths,
    runner: &dyn CommandRunner,
    now_unix: i64,
    dir: &Path,
    started: std::time::Instant,
    clock: &dyn Clock,
    lock_wait: Duration,
) -> std::io::Result<KernelOutcome> {
    let Some(_lock) = lock_dir(dir, lock_wait)? else {
        return Ok(KernelOutcome::Busy);
    };
    let left = kernel::KERNEL_RUN_DEADLINE
        .saturating_sub(clock.now().saturating_duration_since(started))
        .saturating_sub(Duration::from_secs(5));
    if left.is_zero() {
        return Ok(KernelOutcome::NoTime);
    }
    let mut state = kernel::KernelState::load(dir);
    let read = kernel::read_journal(
        paths,
        runner,
        &mut state,
        left.min(kernel::JOURNAL_TIMEOUT),
        now_unix,
    );
    let outcome = match read {
        Ok(stats) => KernelOutcome::Read(stats),
        Err(CommandError::NotFound) => KernelOutcome::NoJournal,
        Err(e) => KernelOutcome::JournalFault(e),
    };
    // Saved whatever happened: a dropped stale cursor must stick too.
    state.save(dir)?;
    Ok(outcome)
}

/// An exclusive `flock` on `<dir>/.collect.lock`, held for the whole run,
/// waited for at most `wait`. `None`: another run holds it.
fn lock_dir(
    dir: &Path,
    wait: Duration,
) -> std::io::Result<Option<nix::fcntl::Flock<std::fs::File>>> {
    use nix::fcntl::{Flock, FlockArg};
    std::fs::create_dir_all(dir)?;
    let deadline = std::time::Instant::now() + wait;
    loop {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            // Never through a link planted at the lock's path.
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(dir.join(LOCK_NAME))?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => return Ok(Some(lock)),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => return Ok(None),
            Err((_, e)) => return Err(std::io::Error::from(e)),
        }
    }
}

/// [`run_collect`] waiting at most `wait` for the run lock. Too little
/// time left ([`RunDeadline::smart_budget`] at lock time, or the
/// [`MIN_PROBE_WINDOW`] at [`RunDeadline::probe_deadline`] right before
/// the probe): [`Skip::NoTime`], nothing written.
#[allow(clippy::too_many_arguments)]
pub fn run_collect_locked(
    mode: Mode,
    paths: &HostPaths,
    runner: &dyn CommandRunner,
    now_unix: i64,
    dir: &Path,
    view: Option<&StorageView>,
    wait: Duration,
    started: std::time::Instant,
    clock: &dyn Clock,
) -> std::io::Result<CollectSummary> {
    let skipped = |why| {
        Ok(CollectSummary {
            skipped: Some(why),
            written: Vec::new(),
            valid: Ok(()),
        })
    };
    let Some(_lock) = lock_dir(dir, wait)? else {
        return skipped(Skip::LockHeld);
    };
    // At lock time: too little left already, nothing is collected.
    if RunDeadline::smart_budget(clock.now().saturating_duration_since(started)).is_none() {
        return skipped(Skip::NoTime);
    }
    let previous = storage::Counters::load(dir);
    // The kernel run's events within their retention window, read under
    // the same lock and never cleared here ([`kernel`] explains the
    // hand-off).
    let kernel_events = kernel::KernelState::load(dir).live_events(now_unix);
    let inputs = StorageInputs {
        view,
        previous: &previous,
        deadline: RunDeadline::probe_deadline(started),
        min_probe_window: MIN_PROBE_WINDOW,
        clock,
        kernel: &kernel_events,
    };
    // Right before the probe (after every other section): checked again;
    // nothing collected is written when it fails.
    let Ok((sections, counters)) = collect(mode, paths, runner, now_unix, &inputs) else {
        return skipped(Skip::NoTime);
    };
    let checked = normalize_and_check(sections, mode, now_unix);
    let written = write_sections(&checked.sections, dir)?;
    counters.save(dir)?;
    Ok(CollectSummary {
        skipped: None,
        written,
        valid: checked.valid,
    })
}

#[cfg(test)]
pub(crate) mod fixture {
    use super::*;
    use std::collections::BTreeMap;

    /// A fixture host under a temp dir: `sys/`, `proc/`, `os-release`,
    /// `DMI`, `pci.ids`.
    pub(crate) struct Host {
        pub(crate) dir: tempfile::TempDir,
    }

    impl Host {
        pub(crate) fn new() -> Self {
            let h = Self {
                dir: tempfile::tempdir().unwrap(),
            };
            for d in ["sys", "proc", "dev"] {
                std::fs::create_dir_all(h.dir.path().join(d)).unwrap();
            }
            h
        }

        pub(crate) fn paths(&self) -> HostPaths {
            let r = self.dir.path();
            HostPaths {
                sys: r.join("sys"),
                proc: r.join("proc"),
                os_release: vec![r.join("os-release"), r.join("usr-lib-os-release")],
                dmi_table: r.join("DMI"),
                pci_ids: vec![r.join("missing-pci.ids"), r.join("pci.ids")],
                ipmi_device: r.join("dev/ipmi0"),
                by_id: r.join("dev/disk/by-id"),
                udev_data: r.join("run/udev/data"),
                host_root: r.join("root"),
                fstab: r.join("root/etc/fstab"),
                auto_update: None,
            }
        }

        /// Write `content` at `rel` (parents created).
        pub(crate) fn write(&self, rel: &str, content: impl AsRef<[u8]>) {
            let p = self.dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        }

        pub(crate) fn mkdir(&self, rel: &str) {
            std::fs::create_dir_all(self.dir.path().join(rel)).unwrap();
        }

        /// A symlink at `rel` to `target` (taken as is).
        pub(crate) fn symlink(&self, rel: &str, target: &str) {
            let p = self.dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            let _ = std::fs::remove_file(&p);
            std::os::unix::fs::symlink(target, p).unwrap();
        }
    }

    /// Canned tool output, keyed by `program arg arg…`; anything else is
    /// "not installed".
    /// The exit code a command's canned failure reports, if any.
    #[derive(Default)]
    pub(crate) struct Runner(
        pub(crate) BTreeMap<String, Result<String, CommandError>>,
        pub(crate) BTreeMap<String, i32>,
    );

    impl Runner {
        pub(crate) fn with(mut self, cmd: &str, out: Result<&str, CommandError>) -> Self {
            self.0.insert(cmd.to_string(), out.map(str::to_string));
            // A later answer replaces an earlier `exits`, code included.
            self.1.remove(cmd);
            self
        }

        /// `cmd` fails with exit code `code`.
        pub(crate) fn exits(mut self, cmd: &str, code: i32) -> Self {
            self.0.insert(cmd.to_string(), Err(CommandError::Failed));
            self.1.insert(cmd.to_string(), code);
            self
        }
    }

    impl CommandRunner for Runner {
        fn run(&self, program: &str, args: &[&str]) -> Result<String, CommandError> {
            let key = std::iter::once(program)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            self.0
                .get(&key)
                .cloned()
                .unwrap_or(Err(CommandError::NotFound))
        }

        fn run_bounded_status(
            &self,
            program: &str,
            args: &[&str],
            timeout: Duration,
            any_exit: bool,
        ) -> (Result<String, CommandError>, Option<i32>) {
            let key = std::iter::once(program)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            (
                self.run_bounded(program, args, timeout, any_exit),
                self.1.get(&key).copied(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{Host, Runner};
    use super::*;
    use hippius_host_inventory::{
        CpuSection, MemorySection, NetworkSection, PciSection, SensorsSection, SoftwareSection,
        StorageSection, SystemSection,
    };

    #[test]
    fn clean_text_bounds_and_drops_placeholders() {
        assert_eq!(
            clean_text(b"  Dell Inc.\n", 128).as_deref(),
            Some("Dell Inc.")
        );
        for p in [
            "To Be Filled By O.E.M.",
            "Default string",
            "Not Specified",
            "System Serial Number",
            "",
            "   ",
        ] {
            assert_eq!(clean_text(p.as_bytes(), 128), None, "{p:?}");
        }
        assert_eq!(clean_text(&[0xff; 16], 128), None, "all-0xFF");
        assert_eq!(
            clean_text(b"Su\x01per\xc3\xa9Micro\x7f", 128).as_deref(),
            Some("SuperMicro"),
            "non-printable bytes dropped"
        );
        let long = "x".repeat(300);
        assert_eq!(clean_text(long.as_bytes(), 64).unwrap().len(), 64);
        // A cut never leaves a trailing blank.
        assert_eq!(clean_text(b"abc   def", 4).as_deref(), Some("abc"));
    }

    #[test]
    fn tally_status() {
        let mut t = Tally::default();
        assert_eq!(t.status(), SectionStatus::Unavailable);
        t.ok();
        assert_eq!(t.status(), SectionStatus::Ok);
        t.failed();
        assert_eq!(t.status(), SectionStatus::Partial);
        t.command::<()>(&Err(CommandError::NotFound));
        assert_eq!(t.status(), SectionStatus::Partial);
        t.command::<()>(&Err(CommandError::Timeout));
        assert_eq!(t.status(), SectionStatus::Timeout);
    }

    #[test]
    fn system_runner_reads_stdout_and_bounds_the_tool() {
        let r = SystemRunner::default();
        assert_eq!(r.run("echo", &["hi"]).unwrap(), "hi\n");
        assert_eq!(
            r.run("hippius-no-such-tool-xyz", &[]),
            Err(CommandError::NotFound)
        );
        assert_eq!(r.run("false", &[]), Err(CommandError::Failed));
        let quick = SystemRunner {
            timeout: Duration::from_millis(200),
        };
        let started = std::time::Instant::now();
        assert_eq!(quick.run("sleep", &["10"]), Err(CommandError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(5));
        // A background grandchild holding stdout neither stalls the run
        // nor outlives it.
        let second = SystemRunner {
            timeout: Duration::from_secs(1),
        };
        let started = std::time::Instant::now();
        assert_eq!(
            second.run("sh", &["-c", "sleep 30 & echo hi"]).unwrap(),
            "hi\n"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        let started = std::time::Instant::now();
        assert_eq!(
            second.run("sh", &["-c", "sleep 30 & sleep 30"]),
            Err(CommandError::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        // `any_exit`: the stdout of a non-zero exit (smartctl's failing
        // disk), a run bound of its own.
        let script = ["-c", "echo verdict; exit 72"];
        assert_eq!(r.run("sh", &script), Err(CommandError::Failed));
        assert_eq!(
            r.run_bounded("sh", &script, Duration::from_secs(5), true)
                .unwrap(),
            "verdict\n"
        );
        assert_eq!(
            r.run_bounded("sh", &script, Duration::from_secs(5), false),
            Err(CommandError::Failed)
        );
        // The exit code of a failure, for its log line; none on success.
        assert_eq!(
            r.run_bounded_status("sh", &script, Duration::from_secs(5), false),
            (Err(CommandError::Failed), Some(72))
        );
        assert_eq!(
            r.run_bounded_status("sh", &["-c", "echo ok"], Duration::from_secs(5), false),
            (Ok("ok\n".to_string()), None)
        );
        assert_eq!(
            r.run_bounded_status("hippius-no-such-tool", &[], Duration::from_secs(5), false),
            (Err(CommandError::NotFound), None)
        );
        let started = std::time::Instant::now();
        assert_eq!(
            r.run_bounded("sleep", &["10"], Duration::from_millis(200), true),
            Err(CommandError::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        // `run_capped`: an endless output stops at the cap, as a success,
        // well within the bound; a short one is read whole.
        let started = std::time::Instant::now();
        let out = r
            .run_capped(
                "sh",
                &["-c", "while :; do echo xxxxxxxxxxxxxxx; done"],
                Duration::from_secs(10),
            )
            .unwrap();
        assert_eq!(out.len() as u64, MAX_COMMAND_OUTPUT);
        assert!(started.elapsed() < Duration::from_secs(5));
        // A tool that dies of SIGPIPE once the reader stops (`yes`)
        // still reads as the capped success, never a failure.
        for _ in 0..20 {
            let out = r.run_capped("yes", &[], Duration::from_secs(10)).unwrap();
            assert_eq!(out.len() as u64, MAX_COMMAND_OUTPUT);
        }
        assert_eq!(
            r.run_capped("sh", &["-c", "echo short"], Duration::from_secs(5))
                .unwrap(),
            "short\n"
        );
        assert_eq!(
            r.run_capped("false", &[], Duration::from_secs(5)),
            Err(CommandError::Failed)
        );
        // The caller's environment is not passed on.
        assert_eq!(
            r.run("sh", &["-c", "echo \"$PATH|$HOME|$LC_ALL\""])
                .unwrap(),
            format!("{TOOL_PATH}||C\n")
        );
        // More output than a pipe holds does not stall the tool.
        let out = r
            .run("sh", &["-c", "head -c 400000 /dev/zero | tr '\\0' x"])
            .unwrap();
        assert_eq!(out.len() as u64, MAX_COMMAND_OUTPUT);
    }

    #[test]
    fn the_subcommand_writes_every_section_atomically_and_validly() {
        let h = Host::new();
        cpu::tests::genoa(&h);
        memory::tests::meminfo_and_edac(&h);
        h.write("DMI", smbios::tests::sample_table());
        network::tests::nic_tree(&h);
        pci::tests::pci_tree(&h);
        software::tests::software_tree(&h);
        system::tests::dmi_id(&h);
        sensors::tests::hwmon_tree(&h);
        let runner = software::tests::runner(Runner::default());
        let out = h.dir.path().join("out/inventory");

        let view = storage::tests::nvme_md_host(&h);
        let s = run_collect(
            Mode::Full,
            &h.paths(),
            &runner,
            1_800_000_000,
            &out,
            Some(&view),
            std::time::Instant::now(),
        )
        .unwrap();
        assert_eq!(s.valid, Ok(()));
        assert_eq!(
            s.written,
            ["system", "cpu", "memory", "storage", "network", "pci", "sensors", "software"]
        );
        let names = dir_names(&out);
        assert_eq!(
            names,
            [
                ".collect.lock",
                ".storage-counters.json",
                "cpu.json",
                "memory.json",
                "network.json",
                "pci.json",
                "sensors.json",
                "software.json",
                "storage.json",
                "system.json"
            ],
            "no temp file left behind"
        );
        let read = |n: &str| std::fs::read(out.join(n)).unwrap();
        let system: SystemSection = serde_json::from_slice(&read("system.json")).unwrap();
        assert_eq!(system.vendor.as_deref(), Some("Dell Inc."));
        let cpu: CpuSection = serde_json::from_slice(&read("cpu.json")).unwrap();
        assert_eq!(cpu.threads, 2);
        let memory: MemorySection = serde_json::from_slice(&read("memory.json")).unwrap();
        assert_eq!(memory.dimms.len(), 1);
        let network: NetworkSection = serde_json::from_slice(&read("network.json")).unwrap();
        assert_eq!(network.nics.len(), 1);
        let pci: PciSection = serde_json::from_slice(&read("pci.json")).unwrap();
        assert_eq!(pci.devices.len(), 4);
        let software: SoftwareSection = serde_json::from_slice(&read("software.json")).unwrap();
        assert_eq!(software.uptime_s, 3600);
        let storage: StorageSection = serde_json::from_slice(&read("storage.json")).unwrap();
        assert!(storage.devices.iter().any(|d| d.name == "md127"));
        let sensors: SensorsSection = serde_json::from_slice(&read("sensors.json")).unwrap();
        assert_eq!(sensors.temperatures.len(), 2);
        let counters: storage::Counters =
            serde_json::from_slice(&read(".storage-counters.json")).unwrap();
        assert!(!counters.first_seen.is_empty(), "{counters:?}");

        // The eight sections, re-assembled, make a valid FULL body.
        let body = HostInventory {
            schema_version: SCHEMA_VERSION,
            domain: DOMAIN.to_string(),
            miner_id: "m".into(),
            timestamp_unix: 1,
            sequence: 1,
            report: ReportKind::Full,
            sections: Sections {
                system: Some(system),
                cpu: Some(cpu),
                memory: Some(memory),
                storage: Some(storage),
                network: Some(network),
                pci: Some(pci),
                sensors: Some(sensors),
                software: Some(software),
            },
        };
        assert_eq!(body.validate(), Ok(()));
        assert!(body.canonical().is_ok());

        // A counters run rewrites memory, storage and software only.
        let s = run_collect(
            Mode::Counters,
            &h.paths(),
            &runner,
            1_800_000_100,
            &out,
            Some(&view),
            std::time::Instant::now(),
        )
        .unwrap();
        assert_eq!(s.valid, Ok(()));
        assert_eq!(s.written, ["memory", "storage", "sensors", "software"]);
        assert_eq!(dir_names(&out).len(), 10);
        // Owner-only, like the facts the storage collector leaves.
        use std::os::unix::fs::PermissionsExt;
        for name in dir_names(&out) {
            let mode = std::fs::metadata(out.join(&name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
    }

    /// A `full` run is checked as a real `full` report: all eight
    /// sections, or the check says what is missing.
    #[test]
    fn a_full_run_is_checked_as_a_full_report() {
        let h = Host::new();
        let previous = storage::Counters::default();
        let inputs = StorageInputs {
            view: None,
            previous: &previous,
            deadline: std::time::Instant::now() + storage::health::SMART_BUDGET,
            min_probe_window: Duration::ZERO,
            clock: &SystemClock,
            kernel: &[],
        };
        let (mut sections, _) =
            collect(Mode::Full, &h.paths(), &Runner::default(), 1, &inputs).unwrap();
        assert!(sections.sensors.is_some());
        assert_eq!(
            normalize_and_check(sections.clone(), Mode::Full, 1).valid,
            Ok(())
        );
        sections.sensors = None;
        assert_eq!(
            normalize_and_check(sections, Mode::Full, 1).valid,
            Err("host-inventory-full-incomplete")
        );
    }

    #[test]
    fn an_empty_host_still_writes_valid_sections() {
        let h = Host::new();
        let out = h.dir.path().join("out");
        let s = run_collect(
            Mode::Full,
            &h.paths(),
            &Runner::default(),
            1_800_000_000,
            &out,
            None,
            std::time::Instant::now(),
        )
        .unwrap();
        assert_eq!(s.valid, Ok(()));
        assert_eq!(s.written.len(), 8);
        let cpu: CpuSection =
            serde_json::from_slice(&std::fs::read(out.join("cpu.json")).unwrap()).unwrap();
        assert_eq!(cpu.status, SectionStatus::Unavailable);
    }

    #[test]
    fn an_invalid_section_is_written_and_its_error_class_returned() {
        let h = Host::new();
        let previous = storage::Counters::default();
        let inputs = StorageInputs {
            view: None,
            previous: &previous,
            deadline: std::time::Instant::now() + storage::health::SMART_BUDGET,
            min_probe_window: Duration::ZERO,
            clock: &SystemClock,
            kernel: &[],
        };
        let (mut sections, _) =
            collect(Mode::Counters, &h.paths(), &Runner::default(), 1, &inputs).unwrap();
        if let Some(sw) = sections.software.as_mut() {
            sw.kernel = Some("bad\nkernel".into());
        }
        let checked = normalize_and_check(sections, Mode::Counters, 1);
        assert_eq!(checked.valid, Err("host-inventory-software"));
        let out = h.dir.path().join("out");
        assert_eq!(
            write_sections(&checked.sections, &out).unwrap(),
            ["memory", "storage", "sensors", "software"]
        );
    }
}
