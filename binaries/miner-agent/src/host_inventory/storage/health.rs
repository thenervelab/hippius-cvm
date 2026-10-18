//! Disk health advisories from SMART (`smartctl -j`), the NVMe health log
//! (`nvme smart-log -o json`, `smartctl -d nvme` as the fallback) and
//! the controller passthrough (`smartctl --scan-open`, `-d megaraid,N`),
//! with the §18.3 thresholds.
//!
//! Every tool run is bounded ([`SMART_TIMEOUT`]) and the whole probe by
//! a budget; a device past it is skipped (`collector_timeout`). A tool
//! that is not installed is `collector_missing_tools` (info), never an
//! error. Only typed fields are taken from a tool's JSON: the advisory
//! `sample` is rebuilt from a fixed template, so no tool text (a serial,
//! a firmware message) leaves the collector. Arbitrary `-d` types are
//! never probed: only the `megaraid,N` devices the controller's own scan
//! lists.
//!
//! A "rising" counter compares with the previous run's
//! ([`super::counters::Counters`]): no previous run, no rising.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use hippius_host_inventory::{AdvisoryCode, AdvisorySubject, Severity, MAX_SAMPLE_LEN};
use serde_json::Value;

use super::super::{clean_text, CommandError, CommandRunner, Tally};
use super::counters::{CounterMap, Counters};

/// How long one `smartctl` / `nvme` run may take.
pub const SMART_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the whole SMART probe of a run may take at most; the run's
/// own deadline (`host_inventory::RUN_DEADLINE`) may leave it less. The
/// devices past it are skipped.
pub const SMART_BUDGET: Duration = Duration::from_secs(10 * 60);

/// `temperature_high` thresholds, °C.
const HDD_TEMP_WARN_C: i64 = 55;
const SSD_TEMP_WARN_C: i64 = 70;
/// `nvme_wear_high`, `percentage_used`.
const WEAR_WARN_PCT: u64 = 80;
const WEAR_CRIT_PCT: u64 = 100;

/// The ATA attribute ids read.
const ATTR_REALLOCATED: u64 = 5;
const ATTR_PENDING: u64 = 197;
const ATTR_OFFLINE_UNCORRECTABLE: u64 = 198;
const ATTR_UDMA_CRC: u64 = 199;

/// The counters a "rising" check compares across runs.
const C_REALLOCATED: &str = "reallocated";
const C_UDMA_CRC: &str = "udma_crc";
const C_MEDIA_ERRORS: &str = "media_errors";

/// One signal of one subject, before its times are stamped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding {
    pub(crate) subject_kind: AdvisorySubject,
    pub(crate) subject: String,
    pub(crate) code: AdvisoryCode,
    pub(crate) severity: Severity,
    pub(crate) count: u64,
    pub(crate) value: i64,
    pub(crate) sample: Option<String>,
}

/// A signal, its subject still to be attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Signal {
    pub(crate) code: AdvisoryCode,
    pub(crate) severity: Severity,
    pub(crate) count: u64,
    pub(crate) value: i64,
    pub(crate) sample: Option<String>,
}

/// A template, as an advisory sample: printable ASCII, at most
/// [`MAX_SAMPLE_LEN`].
pub(crate) fn sample(text: &str) -> Option<String> {
    clean_text(text.as_bytes(), MAX_SAMPLE_LEN)
}

fn signed(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn signal(code: AdvisoryCode, severity: Severity, count: u64, value: i64, text: &str) -> Signal {
    Signal {
        code,
        severity,
        count,
        value,
        sample: sample(text),
    }
}

/// A tool's JSON that could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// What `smartctl -j` said about a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Smart<T> {
    /// It could not open or identify the device (exit bits 0–1).
    Unavailable,
    /// It answered, but with no health reading (a disk in standby).
    NoData,
    Reading(T),
}

/// An ATA / SCSI SMART reading.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AtaReading {
    pub(crate) passed: Option<bool>,
    pub(crate) reallocated: Option<u64>,
    pub(crate) pending: Option<u64>,
    pub(crate) offline_uncorrectable: Option<u64>,
    pub(crate) udma_crc: Option<u64>,
    pub(crate) temperature_c: Option<i64>,
    pub(crate) power_on_hours: Option<u64>,
    /// `rotation_rate`: 0 = solid state.
    pub(crate) rotation_rate: Option<u64>,
}

/// An NVMe health log reading.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NvmeReading {
    pub(crate) critical_warning: u64,
    pub(crate) temperature_c: Option<i64>,
    pub(crate) avail_spare: Option<u64>,
    pub(crate) spare_thresh: Option<u64>,
    pub(crate) percentage_used: Option<u64>,
    pub(crate) media_errors: Option<u64>,
}

fn object(text: &str) -> Result<serde_json::Map<String, Value>, Malformed> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(Malformed),
    }
}

/// `smartctl.exit_status` bits 0–1: the command line or the device open
/// failed (bits 2–7 are the disk's own status, carried by the JSON).
fn smartctl_open_failed(map: &serde_json::Map<String, Value>) -> bool {
    map.get("smartctl")
        .and_then(|s| s.get("exit_status"))
        .and_then(Value::as_u64)
        .is_some_and(|s| s & 0b11 != 0)
}

fn u64_at(v: &Value, path: &[&str]) -> Option<u64> {
    path.iter().try_fold(v, |v, k| v.get(*k))?.as_u64()
}

fn i64_at(v: &Value, path: &[&str]) -> Option<i64> {
    path.iter().try_fold(v, |v, k| v.get(*k))?.as_i64()
}

/// `smartctl -j -H -A -l error` of an ATA or SCSI device.
pub(crate) fn parse_smartctl(text: &str) -> Result<Smart<AtaReading>, Malformed> {
    let map = object(text)?;
    if smartctl_open_failed(&map) {
        return Ok(Smart::Unavailable);
    }
    let v = Value::Object(map);
    let attr = |id: u64| -> Option<u64> {
        v.get("ata_smart_attributes")?
            .get("table")?
            .as_array()?
            .iter()
            .find(|a| a.get("id").and_then(Value::as_u64) == Some(id))
            .and_then(|a| u64_at(a, &["raw", "value"]))
    };
    let r = AtaReading {
        passed: v
            .get("smart_status")
            .and_then(|s| s.get("passed"))
            .and_then(Value::as_bool),
        reallocated: attr(ATTR_REALLOCATED).or_else(|| u64_at(&v, &["scsi_grown_defect_list"])),
        pending: attr(ATTR_PENDING),
        offline_uncorrectable: attr(ATTR_OFFLINE_UNCORRECTABLE),
        udma_crc: attr(ATTR_UDMA_CRC),
        temperature_c: i64_at(&v, &["temperature", "current"]),
        power_on_hours: u64_at(&v, &["power_on_time", "hours"]),
        rotation_rate: u64_at(&v, &["rotation_rate"]),
    };
    let rotation_rate = r.rotation_rate;
    if (AtaReading {
        rotation_rate,
        ..AtaReading::default()
    }) == r
    {
        return Ok(Smart::NoData);
    }
    Ok(Smart::Reading(r))
}

/// A number, or nvme-cli's verbose `{"value": n}`.
fn number(v: Option<&Value>) -> Option<u64> {
    let v = v?;
    v.as_u64()
        .or_else(|| v.get("value").and_then(Value::as_u64))
}

/// `nvme smart-log -o json` (temperatures in kelvin).
pub(crate) fn parse_nvme_cli(text: &str) -> Result<NvmeReading, Malformed> {
    let map = object(text)?;
    let critical_warning = number(map.get("critical_warning")).ok_or(Malformed)?;
    let kelvin = number(map.get("temperature")).and_then(|k| i64::try_from(k).ok());
    Ok(NvmeReading {
        critical_warning,
        temperature_c: kelvin.filter(|k| *k > 0).map(|k| k - 273),
        avail_spare: number(map.get("avail_spare")),
        spare_thresh: number(map.get("spare_thresh")),
        percentage_used: number(map.get("percent_used"))
            .or_else(|| number(map.get("percentage_used"))),
        media_errors: number(map.get("media_errors")),
    })
}

/// `smartctl -j -H -A -d nvme` (temperatures in °C).
pub(crate) fn parse_smartctl_nvme(text: &str) -> Result<Smart<NvmeReading>, Malformed> {
    let map = object(text)?;
    if smartctl_open_failed(&map) {
        return Ok(Smart::Unavailable);
    }
    let Some(log) = map.get("nvme_smart_health_information_log") else {
        return Ok(Smart::NoData);
    };
    Ok(Smart::Reading(NvmeReading {
        critical_warning: number(log.get("critical_warning")).ok_or(Malformed)?,
        temperature_c: log.get("temperature").and_then(Value::as_i64),
        avail_spare: number(log.get("available_spare")),
        spare_thresh: number(log.get("available_spare_threshold")),
        percentage_used: number(log.get("percentage_used")),
        media_errors: number(log.get("media_errors")),
    }))
}

/// `smartctl --scan-open -j`: the `(device, N)` of every `megaraid,N`
/// entry. Only a plain `/dev/…` path is kept (it is passed to smartctl).
pub(crate) fn parse_scan(text: &str) -> Result<Vec<(String, u32)>, Malformed> {
    let map = object(text)?;
    let devices = map
        .get("devices")
        .and_then(Value::as_array)
        .ok_or(Malformed)?;
    let mut out: BTreeSet<(String, u32)> = BTreeSet::new();
    for d in devices {
        let (Some(name), Some(kind)) = (
            d.get("name").and_then(Value::as_str),
            d.get("type").and_then(Value::as_str),
        ) else {
            continue;
        };
        let Some(n) = kind
            .strip_prefix("megaraid,")
            .filter(|n| !n.is_empty() && n.len() <= 3 && n.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let safe = name.strip_prefix("/dev/").is_some_and(|rest| {
            !rest.is_empty()
                && !rest.contains("..")
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'/')
        });
        if safe {
            out.insert((name.to_string(), n));
        }
    }
    Ok(out.into_iter().collect())
}

/// Rising: above the previous run's value (none: not rising).
fn rising(prev: Option<&CounterMap>, key: &str, now: u64) -> Option<u64> {
    prev.and_then(|p| p.get(key))
        .copied()
        .filter(|was| now > *was)
}

/// The §18.3 ATA / SAS signals of a reading, and the counters to keep.
pub(crate) fn ata_signals(
    r: &AtaReading,
    rotational_hint: Option<bool>,
    prev: Option<&CounterMap>,
) -> (Vec<Signal>, CounterMap) {
    use AdvisoryCode as C;
    use Severity as S;
    let mut out = Vec::new();
    let mut keep = CounterMap::new();
    if r.passed == Some(false) {
        out.push(signal(
            C::SmartOverallFailed,
            S::Critical,
            1,
            0,
            "SMART overall-health self-assessment failed",
        ));
    }
    if let Some(n) = r.reallocated {
        keep.insert(C_REALLOCATED.into(), n);
        if n > 0 {
            let (severity, text) = match rising(prev, C_REALLOCATED, n) {
                Some(was) => (
                    S::Critical,
                    format!("reallocated {n} sectors, up from {was}"),
                ),
                None => (S::Warning, format!("reallocated {n} sectors")),
            };
            out.push(signal(C::ReallocatedSectors, severity, n, signed(n), &text));
        }
    }
    if let Some(n) = r.pending.filter(|n| *n > 0) {
        out.push(signal(
            C::PendingSectors,
            S::Critical,
            n,
            signed(n),
            &format!("{n} sectors pending reallocation"),
        ));
    }
    if let Some(n) = r.offline_uncorrectable.filter(|n| *n > 0) {
        out.push(signal(
            C::OfflineUncorrectable,
            S::Critical,
            n,
            signed(n),
            &format!("{n} offline uncorrectable sectors"),
        ));
    }
    if let Some(n) = r.udma_crc {
        keep.insert(C_UDMA_CRC.into(), n);
        if let Some(was) = rising(prev, C_UDMA_CRC, n) {
            out.push(signal(
                C::UdmaCrcErrors,
                S::Warning,
                n,
                signed(n),
                &format!("UDMA CRC errors rose from {was} to {n}"),
            ));
        }
    }
    if let Some(t) = r.temperature_c {
        let ssd = match r.rotation_rate {
            Some(rate) => rate == 0,
            None => rotational_hint != Some(true),
        };
        let threshold = if ssd {
            SSD_TEMP_WARN_C
        } else {
            HDD_TEMP_WARN_C
        };
        if t >= threshold {
            out.push(signal(
                C::TemperatureHigh,
                S::Warning,
                1,
                t,
                &format!("temperature {t} C, threshold {threshold} C"),
            ));
        }
    }
    if let Some(h) = r.power_on_hours {
        out.push(signal(
            C::PowerOnHours,
            S::Info,
            h,
            signed(h),
            &format!("powered on {h} hours"),
        ));
    }
    (out, keep)
}

/// The §18.3 NVMe signals of a reading, and the counters to keep.
pub(crate) fn nvme_signals(
    r: &NvmeReading,
    prev: Option<&CounterMap>,
) -> (Vec<Signal>, CounterMap) {
    use AdvisoryCode as C;
    use Severity as S;
    let mut out = Vec::new();
    let mut keep = CounterMap::new();
    if r.critical_warning != 0 {
        let bits = r.critical_warning;
        out.push(signal(
            C::NvmeCriticalWarning,
            S::Critical,
            1,
            signed(bits),
            &format!("critical warning bits 0x{bits:02x}"),
        ));
    }
    if let Some(n) = r.media_errors {
        keep.insert(C_MEDIA_ERRORS.into(), n);
        if n > 0 {
            let (severity, text) = match rising(prev, C_MEDIA_ERRORS, n) {
                Some(was) => (S::Critical, format!("{n} media errors, up from {was}")),
                None => (S::Warning, format!("{n} media errors")),
            };
            out.push(signal(C::NvmeMediaErrors, severity, n, signed(n), &text));
        }
    }
    if let (Some(spare), Some(thresh)) = (r.avail_spare, r.spare_thresh) {
        if spare < thresh {
            out.push(signal(
                C::NvmeSpareLow,
                S::Critical,
                1,
                signed(spare),
                &format!("available spare {spare}% below threshold {thresh}%"),
            ));
        }
    }
    if let Some(used) = r.percentage_used.filter(|u| *u >= WEAR_WARN_PCT) {
        let severity = if used >= WEAR_CRIT_PCT {
            S::Critical
        } else {
            S::Warning
        };
        out.push(signal(
            C::NvmeWearHigh,
            severity,
            1,
            signed(used),
            &format!("{used}% of rated endurance used"),
        ));
    }
    if let Some(t) = r.temperature_c.filter(|t| *t >= SSD_TEMP_WARN_C) {
        out.push(signal(
            C::TemperatureHigh,
            S::Warning,
            1,
            t,
            &format!("temperature {t} C, threshold {SSD_TEMP_WARN_C} C"),
        ));
    }
    (out, keep)
}

// ─── the probe ───────────────────────────────────────────────────────

/// How a device is probed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProbeKind {
    /// `smartctl` on the device itself.
    Ata { rotational_hint: Option<bool> },
    /// `nvme smart-log`, `smartctl -d nvme` as the fallback.
    Nvme,
    /// A controller virtual disk: its SMART is the physical disks'.
    ControllerVd {
        label: String,
        vd: String,
        megaraid: bool,
        scsi_host: Option<u32>,
    },
    /// No known way to read its health.
    Unknown,
}

/// One device to probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// The kernel name (`/dev/<name>` is what the tools are given).
    pub(crate) name: String,
    /// What its health advisories attach to.
    pub(crate) subject_kind: AdvisorySubject,
    pub(crate) subject: String,
    /// Its counters' key across runs (a stable by-id name when it has
    /// one).
    pub(crate) counter_key: String,
    pub(crate) kind: ProbeKind,
}

/// `ctrl:<label>:<suffix>`, within the crate's subject bound.
fn ctrl_subject(label: &str, suffix: &str) -> String {
    let label = clean_text(label.replace(':', " ").as_bytes(), 64).unwrap_or_else(|| "raid".into());
    format!("ctrl:{label}:{suffix}")
}

/// The SMART probe of one run.
pub(crate) struct Probe<'a> {
    runner: &'a dyn CommandRunner,
    clock: &'a dyn super::super::Clock,
    /// No tool may still be running past it.
    deadline: Instant,
    prev: &'a Counters,
    pub(crate) next: CounterMapByKey,
    pub(crate) findings: Vec<Finding>,
    skipped: u64,
    missing: BTreeSet<&'static str>,
    /// The tools that were needed (and so whose absence matters).
    pub(crate) tally: Tally,
}

/// The counters of every probed subject.
pub(crate) type CounterMapByKey = BTreeMap<String, CounterMap>;

impl<'a> Probe<'a> {
    /// A probe whose every tool ends by `deadline` (as `clock` tells it).
    pub(crate) fn new(
        runner: &'a dyn CommandRunner,
        clock: &'a dyn super::super::Clock,
        deadline: Instant,
        prev: &'a Counters,
    ) -> Self {
        Self {
            runner,
            clock,
            deadline,
            prev,
            next: BTreeMap::new(),
            findings: Vec::new(),
            skipped: 0,
            missing: BTreeSet::new(),
            tally: Tally::default(),
        }
    }

    fn push(&mut self, kind: AdvisorySubject, subject: &str, s: Signal) {
        self.findings.push(Finding {
            subject_kind: kind,
            subject: subject.to_string(),
            code: s.code,
            severity: s.severity,
            count: s.count,
            value: s.value,
            sample: s.sample,
        });
    }

    /// Whether `tools` more runs of up to [`SMART_TIMEOUT`] each still end
    /// by the deadline (else the device is counted as skipped): a tool is
    /// never started that could outlive it.
    fn spend(&mut self, tools: u32) -> bool {
        if self.clock.now() + SMART_TIMEOUT * tools > self.deadline {
            self.skipped += 1;
            return false;
        }
        true
    }

    /// Run `program` (`any_exit` for smartctl), noting a missing tool and
    /// the section's status.
    fn tool(
        &mut self,
        program: &'static str,
        args: &[&str],
        any_exit: bool,
    ) -> Result<String, CommandError> {
        if self.missing.contains(program) {
            return Err(CommandError::NotFound);
        }
        let r = self
            .runner
            .run_bounded(program, args, SMART_TIMEOUT, any_exit);
        self.tally.command(&r);
        if r == Err(CommandError::NotFound) {
            self.missing.insert(program);
        }
        r
    }

    /// Keep the previous run's counters of a subject not read this run
    /// (a transient failure does not reset its baseline).
    fn carry(&mut self, key: &str) {
        if let Some(c) = self.prev.devices.get(key) {
            self.next.insert(key.to_string(), c.clone());
        }
    }

    fn failure(&mut self, t: &Target, e: CommandError, tool: &str) {
        let (kind, subject) = (AdvisorySubject::Device, t.name.as_str());
        match e {
            CommandError::Timeout => self.push(
                kind,
                subject,
                signal(
                    AdvisoryCode::CollectorTimeout,
                    Severity::Warning,
                    1,
                    0,
                    &format!("{tool} timed out after {} s", SMART_TIMEOUT.as_secs()),
                ),
            ),
            CommandError::Failed => self.push(
                kind,
                subject,
                signal(
                    AdvisoryCode::SmartUnavailable,
                    Severity::Info,
                    1,
                    0,
                    &format!("{tool} could not read the device"),
                ),
            ),
            CommandError::NotFound => {}
        }
    }

    fn malformed(&mut self, kind: AdvisorySubject, subject: &str, tool: &str) {
        self.tally.failed();
        self.push(
            kind,
            subject,
            signal(
                AdvisoryCode::CollectorPartial,
                Severity::Info,
                1,
                0,
                &format!("unreadable {tool} output"),
            ),
        );
    }

    fn unavailable(&mut self, kind: AdvisorySubject, subject: &str) {
        self.push(
            kind,
            subject,
            signal(
                AdvisoryCode::SmartUnavailable,
                Severity::Info,
                1,
                0,
                "SMART data unavailable for this device",
            ),
        );
    }

    fn ata(&mut self, t: &Target, rotational_hint: Option<bool>) {
        if !self.spend(1) {
            return self.carry(&t.counter_key);
        }
        let dev = format!("/dev/{}", t.name);
        let out = self.tool(
            "smartctl",
            &["-j", "-H", "-A", "-l", "error", "-n", "standby,0", &dev],
            true,
        );
        let text = match out {
            Ok(text) => text,
            Err(e) => {
                self.failure(t, e, "smartctl");
                return self.carry(&t.counter_key);
            }
        };
        match parse_smartctl(&text) {
            Ok(Smart::Reading(r)) => {
                let (signals, keep) =
                    ata_signals(&r, rotational_hint, self.prev.devices.get(&t.counter_key));
                for s in signals {
                    self.push(t.subject_kind, &t.subject, s);
                }
                self.next.insert(t.counter_key.clone(), keep);
            }
            Ok(Smart::NoData) => self.carry(&t.counter_key),
            Ok(Smart::Unavailable) => {
                self.unavailable(t.subject_kind, &t.subject);
                self.carry(&t.counter_key);
            }
            Err(Malformed) => {
                self.malformed(AdvisorySubject::Device, &t.name, "smartctl");
                self.carry(&t.counter_key);
            }
        }
    }

    fn nvme(&mut self, t: &Target) {
        // The primary, and the fallback that may follow it.
        if !self.spend(2) {
            return self.carry(&t.counter_key);
        }
        let dev = format!("/dev/{}", t.name);
        let primary = self.tool("nvme", &["smart-log", "-o", "json", &dev], false);
        let mut malformed = None;
        match primary {
            Ok(text) => match parse_nvme_cli(&text) {
                Ok(r) => return self.nvme_reading(t, &r),
                Err(Malformed) => malformed = Some("nvme"),
            },
            // Bounded once is enough: no second tool after a timeout.
            Err(CommandError::Timeout) => {
                self.failure(t, CommandError::Timeout, "nvme");
                return self.carry(&t.counter_key);
            }
            Err(_) => {}
        }
        let fallback = self.tool("smartctl", &["-j", "-H", "-A", "-d", "nvme", &dev], true);
        match fallback.map(|text| parse_smartctl_nvme(&text)) {
            Ok(Ok(Smart::Reading(r))) => self.nvme_reading(t, &r),
            Ok(Ok(Smart::NoData)) => self.carry(&t.counter_key),
            Ok(Ok(Smart::Unavailable)) => {
                self.unavailable(t.subject_kind, &t.subject);
                self.carry(&t.counter_key);
            }
            Ok(Err(Malformed)) => {
                self.malformed(AdvisorySubject::Device, &t.name, "smartctl");
                self.carry(&t.counter_key);
            }
            Err(e) => {
                match malformed {
                    Some(tool) => self.malformed(AdvisorySubject::Device, &t.name, tool),
                    None => self.failure(t, e, "smartctl"),
                }
                self.carry(&t.counter_key);
            }
        }
    }

    fn nvme_reading(&mut self, t: &Target, r: &NvmeReading) {
        let (signals, keep) = nvme_signals(r, self.prev.devices.get(&t.counter_key));
        for s in signals {
            self.push(t.subject_kind, &t.subject, s);
        }
        self.next.insert(t.counter_key.clone(), keep);
    }

    /// The physical disks behind MegaRAID virtual disks `vds`, through the
    /// controller's own scan. Any passthrough that fails (or no scan) is
    /// one `smart_unavailable_behind_controller` per virtual disk; the
    /// first that times out ends the passthrough for this run.
    fn megaraid(&mut self, vds: &[(String, String, Option<u32>)]) {
        if vds.is_empty() {
            return;
        }
        let mut failed = !self.spend(1);
        let scan = if failed {
            Vec::new()
        } else {
            // The controller's own devices only: `-d megaraid` scans
            // MegaRAID, nothing else is opened.
            match self.tool("smartctl", &["--scan-open", "-d", "megaraid", "-j"], true) {
                Ok(text) => parse_scan(&text).unwrap_or_else(|Malformed| {
                    self.tally.failed();
                    Vec::new()
                }),
                Err(_) => Vec::new(),
            }
        };
        if scan.is_empty() {
            failed = true;
        }
        // A passthrough that times out stalls the controller's firmware on
        // some hosts: the rest of its disks are not probed this run.
        let mut stalled = false;
        for (dev, n) in &scan {
            // The physical disk sits behind the controller of the VD on
            // the same SCSI host (`/dev/bus/<host>`), else the first.
            let host: Option<u32> = dev.strip_prefix("/dev/bus/").and_then(|h| h.parse().ok());
            let label = vds
                .iter()
                .find(|(_, _, h)| host.is_some() && *h == host)
                .or_else(|| vds.first())
                .map(|(label, _, _)| label.clone())
                .unwrap_or_default();
            let subject = ctrl_subject(&label, &format!("pd{n}"));
            if stalled || !self.spend(1) {
                failed = true;
                self.carry(&subject);
                continue;
            }
            let d = format!("megaraid,{n}");
            let out = self.tool(
                "smartctl",
                &[
                    "-j",
                    "-H",
                    "-A",
                    "-l",
                    "error",
                    "-n",
                    "standby,0",
                    "-d",
                    &d,
                    dev,
                ],
                true,
            );
            let reading = match out {
                Ok(text) => parse_smartctl(&text),
                Err(CommandError::Timeout) => {
                    self.push(
                        AdvisorySubject::Controller,
                        &subject,
                        signal(
                            AdvisoryCode::CollectorTimeout,
                            Severity::Warning,
                            1,
                            0,
                            &format!("smartctl timed out after {} s", SMART_TIMEOUT.as_secs()),
                        ),
                    );
                    failed = true;
                    stalled = true;
                    self.carry(&subject);
                    continue;
                }
                Err(_) => Ok(Smart::Unavailable),
            };
            match reading {
                Ok(Smart::Reading(r)) => {
                    let (signals, keep) = ata_signals(&r, None, self.prev.devices.get(&subject));
                    for s in signals {
                        self.push(AdvisorySubject::Controller, &subject, s);
                    }
                    self.next.insert(subject, keep);
                }
                Ok(Smart::NoData) => self.carry(&subject),
                Ok(Smart::Unavailable) => {
                    failed = true;
                    self.carry(&subject);
                }
                Err(Malformed) => {
                    failed = true;
                    self.malformed(AdvisorySubject::Controller, &subject, "smartctl");
                    self.carry(&subject);
                }
            }
        }
        if failed {
            for (label, vd, _) in vds {
                self.behind_controller(label, vd);
            }
        }
    }

    fn behind_controller(&mut self, label: &str, vd: &str) {
        let text = format!("SMART passthrough unavailable behind {label}");
        self.push(
            AdvisorySubject::Controller,
            &ctrl_subject(label, vd),
            signal(
                AdvisoryCode::SmartUnavailableBehindController,
                Severity::Info,
                1,
                0,
                &text,
            ),
        );
    }

    /// Probe every target, then the collector's own signals.
    pub(crate) fn run(mut self, targets: &[Target]) -> Self {
        let mut megaraid_vds = Vec::new();
        for t in targets {
            match &t.kind {
                ProbeKind::Ata { rotational_hint } => self.ata(t, *rotational_hint),
                ProbeKind::Nvme => self.nvme(t),
                ProbeKind::ControllerVd {
                    label,
                    vd,
                    megaraid: true,
                    scsi_host,
                } => megaraid_vds.push((label.clone(), vd.clone(), *scsi_host)),
                ProbeKind::ControllerVd { label, vd, .. } => self.behind_controller(label, vd),
                ProbeKind::Unknown => self.unavailable(t.subject_kind, &t.subject),
            }
        }
        self.megaraid(&megaraid_vds);
        if self.skipped > 0 {
            self.tally.timed_out();
            let n = self.skipped;
            self.push(
                AdvisorySubject::Collector,
                "",
                signal(
                    AdvisoryCode::CollectorTimeout,
                    Severity::Warning,
                    n,
                    0,
                    &format!("probe budget exhausted, {n} device(s) skipped"),
                ),
            );
        }
        if !self.missing.is_empty() {
            let names: Vec<&str> = self
                .missing
                .iter()
                .map(|p| match *p {
                    "nvme" => "nvme-cli",
                    other => other,
                })
                .collect();
            let text = format!("{} not installed", names.join(" and "));
            self.push(
                AdvisorySubject::Collector,
                "",
                signal(
                    AdvisoryCode::CollectorMissingTools,
                    Severity::Info,
                    signed_count(names.len()),
                    0,
                    &text,
                ),
            );
        }
        self
    }
}

fn signed_count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}
