//! The `sensors` section: temperatures and fans from hwmon
//! (`/sys/class/hwmon/hwmon*/`), power supplies from the local BMC's SDR
//! (`ipmitool sdr type "Power Supply"`, in-band, only when `/dev/ipmi0`
//! exists).
//!
//! A reading is keyed by `(chip, label)`: the chip is the hwmon `name`
//! (sanitized to `[a-z0-9_]`) and its `hwmonN` index, or `ipmi`. A label
//! passes a closed allowlist ([`label_allowed`]); anything else is
//! dropped and counted — a driver label is host text, and only the known
//! shapes are worth a dashboard row. A sensor without a label file is
//! named by its channel (`temp2`, `fan1`), text the collector writes
//! itself.
//!
//! No hwmon and no BMC is an `unavailable` section; an IPMI fault
//! (`ipmitool` failing or timing out) makes it `partial` / `timeout`,
//! never an error, and is logged on stderr (the command, how it failed and
//! its exit code; never its output), as is a missing `ipmitool` on a host
//! with `/dev/ipmi0`. A BMC power-supply name is never copied: it becomes
//! `PSU<n>` from its first number, else from the sensor's entity instance
//! (`10.<n>`, entity 10 = power supply: an iDRAC names them all `Status`).

use std::time::Duration;

use hippius_host_inventory::{
    is_sensor_chip, Fan, Psu, PsuState, SensorsSection, Temperature, MAX_NAME_LEN, MAX_SENSORS,
};

use super::{dir_names, read_trimmed, CommandError, CommandRunner, HostPaths, Tally};

/// How long one `ipmitool` call may take.
pub const IPMI_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the whole hwmon walk may take before it is given up (its
/// thread left behind).
pub const HWMON_TIMEOUT: Duration = Duration::from_secs(10);

/// hwmon chips that are a drive: reading one asks the drive (a dying one
/// can stall), and SMART already reports its temperature.
const DRIVE_CHIPS: [&str; 2] = ["nvme", "drivetemp"];

/// The sensors section, and how many readings were dropped (an
/// unlisted label, past the cap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorsReport {
    pub section: SensorsSection,
    pub dropped: u32,
    /// Lines for stderr: how an `ipmitool` run failed (never its output).
    pub notes: Vec<String>,
}

/// `<digits>` exactly.
fn number(s: &str) -> bool {
    !s.is_empty() && s.len() <= 3 && s.bytes().all(|b| b.is_ascii_digit())
}

/// The closed list of labels a reading may carry: what the common drivers
/// name their channels (k10temp, coretemp, nvme, amdgpu, drivetemp, …),
/// and the collector's own `temp<N>` / `fan<N>` for unlabelled channels.
pub fn label_allowed(label: &str) -> bool {
    const EXACT: [&str; 10] = [
        "Tctl",
        "Tdie",
        "Composite",
        "edge",
        "junction",
        "mem",
        "CPU",
        "SYSTIN",
        "CPUTIN",
        "Tccd",
    ];
    if EXACT.contains(&label) {
        return true;
    }
    let prefixed = |prefix: &str| label.strip_prefix(prefix).is_some_and(number);
    [
        "Tccd",
        "Package id ",
        "Core ",
        "Sensor ",
        "fan",
        "temp",
        "Fan ",
    ]
    .iter()
    .any(|p| prefixed(p))
}

/// The hwmon `name` as a chip name: lowercase `[a-z0-9_]`, other bytes as
/// `_`, short enough for `<name>.<index>` to fit the crate's bound.
fn chip(name: &str, index: &str) -> Option<String> {
    let max = MAX_NAME_LEN.saturating_sub(index.len() + 1);
    let clean: String = name
        .trim()
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(max)
        .collect();
    let chip = format!("{clean}.{index}");
    is_sensor_chip(&chip).then_some(chip)
}

/// `temp3_input` → `("temp", "3")`.
fn channel<'a>(file: &'a str, kind: &str) -> Option<&'a str> {
    let n = file.strip_prefix(kind)?.strip_suffix("_input")?;
    number(n).then_some(n)
}

/// One hwmon walk: readings, labels dropped, whether any chip exists.
type Walk = (Vec<Temperature>, Vec<Fan>, u32, bool);

/// Every hwmon temperature and fan, labels allowlisted, bounded by
/// [`HWMON_TIMEOUT`] (a stalled walk is a timeout, nothing read).
fn hwmon(paths: &HostPaths, tally: &mut Tally, dropped: &mut u32) -> (Vec<Temperature>, Vec<Fan>) {
    let root = paths.sys.join("class/hwmon");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(walk(&root));
    });
    match rx.recv_timeout(HWMON_TIMEOUT) {
        Ok((temps, fans, d, _any)) => {
            // A chip with no readable sensor is nothing read.
            if !temps.is_empty() || !fans.is_empty() {
                tally.ok();
            }
            *dropped = dropped.saturating_add(d);
            (temps, fans)
        }
        Err(_) => {
            tally.timed_out();
            (Vec::new(), Vec::new())
        }
    }
}

fn walk(root: &std::path::Path) -> Walk {
    let mut temps = Vec::new();
    let mut fans = Vec::new();
    let mut dropped = 0u32;
    let entries = dir_names(root);
    let any = !entries.is_empty();
    for entry in entries {
        let Some(index) = entry.strip_prefix("hwmon").filter(|i| number(i)) else {
            continue;
        };
        let dir = root.join(&entry);
        let Some(name) = read_trimmed(&dir.join("name")) else {
            continue;
        };
        if DRIVE_CHIPS.contains(&name.trim()) {
            continue;
        }
        let Some(chip) = chip(&name, index) else {
            continue;
        };
        for file in dir_names(&dir) {
            for kind in ["temp", "fan"] {
                let Some(n) = channel(&file, kind) else {
                    continue;
                };
                let label = read_trimmed(&dir.join(format!("{kind}{n}_label")))
                    .unwrap_or_else(|| format!("{kind}{n}"));
                if !label_allowed(&label) {
                    dropped = dropped.saturating_add(1);
                    continue;
                }
                // An unreadable or absurd value is no reading (a channel
                // the driver cannot read right now).
                let Some(raw) = read_trimmed(&dir.join(&file)).and_then(|v| v.parse::<i64>().ok())
                else {
                    continue;
                };
                if kind == "temp" {
                    if let Ok(millicelsius) = i32::try_from(raw) {
                        temps.push(Temperature {
                            chip: chip.clone(),
                            label,
                            millicelsius,
                        });
                    }
                } else if let Ok(rpm) = u32::try_from(raw) {
                    fans.push(Fan {
                        chip: chip.clone(),
                        label,
                        rpm,
                    });
                }
            }
        }
    }
    (temps, fans, dropped, any)
}

/// The supply number of an SDR row: the sensor name's first number
/// (`PS2 Status`), else the instance of a power-supply entity (`10.2`; a
/// Dell iDRAC names every supply's sensor `Status`). `None`: no supply
/// (`PS Redundancy | 77h | ns | 7.1 | …` is the system board's).
fn psu_number(name: &str, entity: &str) -> Option<String> {
    let digits: String = name
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    if !digits.is_empty() {
        return number(&digits).then_some(digits);
    }
    let instance = entity.strip_prefix("10.")?;
    number(instance).then(|| instance.to_string())
}

/// `ipmitool sdr type "Power Supply"` lines:
/// `PS1 Status | C8h | ok | 10.1 | Presence detected` (an iDRAC:
/// `Status | 85h | ok | 10.1 | Presence detected`). The discrete status
/// sensors (`… Status`) say what a supply's state is and win over the
/// rest (`PS Redundancy`); when the BMC has none, every numbered sensor
/// is read.
///
/// `ns` (no reading) is `unknown`, whatever the text: an iDRAC's
/// `Status | 86h | ns | 10.2 | Disabled` is a sensor the BMC does not
/// scan, which says neither that the bay is empty nor that a supply in
/// it failed — `absent` would claim the first, and only a reading may.
pub(crate) fn parse_psus(output: &str) -> Vec<Psu> {
    let rows: Vec<Vec<&str>> = output
        .lines()
        .map(|l| l.split('|').map(str::trim).collect::<Vec<&str>>())
        .filter(|c| c.len() == 5)
        .collect();
    let has_status = rows
        .iter()
        .any(|c| c[0].to_ascii_lowercase().contains("status"));
    let mut out: Vec<Psu> = Vec::new();
    for cols in &rows {
        let [name, _id, status, entity, reading] = cols.as_slice() else {
            continue;
        };
        if has_status && !name.to_ascii_lowercase().contains("status") {
            continue;
        }
        let Some(digits) = psu_number(name, entity) else {
            continue;
        };
        let label = format!("PSU{digits}");
        let reading = reading.to_ascii_lowercase();
        let state = if ["failure", "ac lost", "predictive", "fault"]
            .iter()
            .any(|w| reading.contains(w))
        {
            PsuState::Failed
        } else if status.eq_ignore_ascii_case("ns") {
            // No reading: nothing known.
            PsuState::Unknown
        } else if reading.contains("absent") || reading.contains("not present") {
            PsuState::Absent
        } else if reading.contains("presence detected") {
            PsuState::Ok
        } else {
            PsuState::Unknown
        };
        // Two status sensors of one supply (`PS1 Status` and an
        // entity-numbered `Status | … | 10.1`): the worse state wins, never
        // the first. Without status sensors the first numbered one stands:
        // a reading (`220 Watts`) says nothing of the state, so its
        // `unknown` must not override a `Presence detected`.
        match out.iter_mut().find(|p| p.label == label) {
            Some(p) if has_status && severity(state) > severity(p.state) => p.state = state,
            Some(_) => {}
            None => out.push(Psu { label, state }),
        }
    }
    out
}

/// How bad a supply state is, to merge two sensors of one supply:
/// failed > unknown > absent > ok.
fn severity(state: PsuState) -> u8 {
    match state {
        PsuState::Ok => 0,
        PsuState::Absent => 1,
        PsuState::Unknown => 2,
        PsuState::Failed => 3,
    }
}

/// `ipmitool mc info`'s `Firmware Revision` value.
pub(crate) fn parse_firmware(output: &str) -> Option<String> {
    let value = output.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim() == "Firmware Revision").then(|| v.trim().to_string())
    })?;
    super::clean_text(value.as_bytes(), hippius_host_inventory::MAX_TEXT_LEN)
}

/// One in-band `ipmitool` run (the caller checked `/dev/ipmi0` exists, so
/// a BMC is expected): a failure is noted for stderr
/// ([`ipmi_failure_line`]) in `notes`. A missing tool is noted only when
/// `note_missing` (the sensors section's run, once per collector run: the
/// system section's `mc info` would say it again).
fn ipmitool(
    runner: &dyn CommandRunner,
    args: &[&str],
    notes: &mut Vec<String>,
    note_missing: bool,
) -> Result<String, CommandError> {
    let (out, code) = runner.run_bounded_status("ipmitool", args, IPMI_TIMEOUT, false);
    match &out {
        Err(CommandError::NotFound) if !note_missing => {}
        Err(e) => notes.push(ipmi_failure_line(args, *e, code)),
        Ok(_) => {}
    }
    out
}

/// The log line of a failed `ipmitool <args>`: how it failed and its exit
/// code. Never the tool's output (host text).
pub(crate) fn ipmi_failure_line(args: &[&str], e: CommandError, code: Option<i32>) -> String {
    let how = match e {
        CommandError::NotFound => "not installed although /dev/ipmi0 exists".to_string(),
        CommandError::Timeout => format!("timed out after {} s", IPMI_TIMEOUT.as_secs()),
        CommandError::Failed => match code {
            Some(c) => format!("failed (exit status {c})"),
            None => "failed (no exit status: killed or not started)".to_string(),
        },
    };
    format!(
        "hippius-miner-agent: host-inventory-collect: ipmitool {}: {how}",
        args.join(" ")
    )
}

/// Collect the sensors section.
pub fn collect_sensors(paths: &HostPaths, runner: &dyn CommandRunner) -> SensorsReport {
    let mut tally = Tally::default();
    let mut dropped = 0u32;
    let (mut temperatures, mut fans) = hwmon(paths, &mut tally, &mut dropped);
    let mut psus = Vec::new();
    let mut notes = Vec::new();
    if paths.ipmi_device.exists() {
        let sdr = ipmitool(runner, &["sdr", "type", "Power Supply"], &mut notes, true);
        match &sdr {
            Ok(out) => {
                psus = parse_psus(out);
                tally.ok();
            }
            // No ipmitool: hwmon only, nothing wrong.
            Err(CommandError::NotFound) => {}
            Err(_) => tally.command(&sdr),
        }
    }
    for list_len in [temperatures.len(), fans.len(), psus.len()] {
        dropped = dropped.saturating_add(
            u32::try_from(list_len.saturating_sub(MAX_SENSORS)).unwrap_or(u32::MAX),
        );
    }
    temperatures.sort_by_key(Temperature::key);
    temperatures.dedup_by(|a, b| a.key() == b.key());
    temperatures.truncate(MAX_SENSORS);
    fans.sort_by_key(Fan::key);
    fans.dedup_by(|a, b| a.key() == b.key());
    fans.truncate(MAX_SENSORS);
    psus.truncate(MAX_SENSORS);
    SensorsReport {
        section: SensorsSection {
            status: tally.status(),
            temperatures,
            fans,
            psus,
        },
        dropped,
        notes,
    }
}

/// The BMC firmware revision (`ipmitool mc info`), when a BMC is local;
/// a fault is `Err` for the caller's status.
pub fn bmc_firmware(
    paths: &HostPaths,
    runner: &dyn CommandRunner,
) -> Result<Option<String>, CommandError> {
    let mut notes = Vec::new();
    let r = bmc_firmware_noted(paths, runner, &mut notes);
    for line in notes {
        eprintln!("{line}");
    }
    r
}

/// [`bmc_firmware`], its failure noted in `notes` (a missing `ipmitool` is
/// not: the sensors section notes it once per run).
pub(crate) fn bmc_firmware_noted(
    paths: &HostPaths,
    runner: &dyn CommandRunner,
    notes: &mut Vec<String>,
) -> Result<Option<String>, CommandError> {
    if !paths.ipmi_device.exists() {
        return Ok(None);
    }
    match ipmitool(runner, &["mc", "info"], notes, false) {
        Ok(out) => Ok(parse_firmware(&out)),
        Err(CommandError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::fixture::{Host, Runner};
    use super::*;
    use hippius_host_inventory::SectionStatus;

    /// `hwmon0` k10temp (Tctl, Tccd1, an unlisted label), `hwmon1` nvme
    /// (Composite, Sensor 1, Sensor 2), `hwmon2` a fan chip with an
    /// unlabelled fan and a vendor label.
    pub(crate) fn hwmon_tree(h: &Host) {
        let d = "sys/class/hwmon";
        h.write(&format!("{d}/hwmon0/name"), "k10temp\n");
        h.write(&format!("{d}/hwmon0/temp1_input"), "48250\n");
        h.write(&format!("{d}/hwmon0/temp1_label"), "Tctl\n");
        h.write(&format!("{d}/hwmon0/temp3_input"), "41000\n");
        h.write(&format!("{d}/hwmon0/temp3_label"), "Tccd1\n");
        h.write(&format!("{d}/hwmon0/temp5_input"), "39000\n");
        h.write(
            &format!("{d}/hwmon0/temp5_label"),
            "Vendor Secret Probe X\n",
        );
        h.write(&format!("{d}/hwmon1/name"), "nvme\n");
        h.write(&format!("{d}/hwmon1/temp1_input"), "37850\n");
        h.write(&format!("{d}/hwmon1/temp1_label"), "Composite\n");
        h.write(&format!("{d}/hwmon1/temp2_input"), "37850\n");
        h.write(&format!("{d}/hwmon1/temp2_label"), "Sensor 1\n");
        h.write(&format!("{d}/hwmon1/temp3_input"), "garbage\n");
        h.write(&format!("{d}/hwmon1/temp3_label"), "Sensor 2\n");
        h.write(&format!("{d}/hwmon2/name"), "Nct-6779 (ISA)\n");
        h.write(&format!("{d}/hwmon2/fan1_input"), "1200\n");
        h.write(&format!("{d}/hwmon2/fan2_input"), "900\n");
        h.write(&format!("{d}/hwmon2/fan2_label"), "Chassis Intake Left\n");
        // A drive's chip: never read (SMART reports it).
        h.write(&format!("{d}/hwmon3/name"), "drivetemp\n");
        h.write(&format!("{d}/hwmon3/temp1_input"), "35000\n");
        // Not a hwmonN directory.
        h.write(&format!("{d}/other/name"), "x\n");
    }

    pub(crate) const SDR_PSU: &str = "\
PS1 Status       | C8h | ok  | 10.1 | Presence detected
PS2 Status       | C9h | ok  | 10.2 | Presence detected, Power Supply AC lost
PS3 Status       | CAh | ns  | 10.3 | No Reading
PS Redundancy    | 77h | ok  | 7.1  | Fully Redundant
PS1 Input Power  | 70h | ok  | 10.1 | 220 Watts
";

    pub(crate) const MC_INFO: &str = "\
Device ID                 : 32
Device Revision           : 1
Firmware Revision         : 7.10
IPMI Version              : 2.0
Manufacturer ID           : 674
";

    const SDR_CMD: &str = "ipmitool sdr type Power Supply";

    #[test]
    fn reads_hwmon_with_allowlisted_labels() {
        let h = Host::new();
        hwmon_tree(&h);
        let r = collect_sensors(&h.paths(), &Runner::default());
        assert_eq!(r.section.status, SectionStatus::Ok);
        let temps: Vec<(&str, &str, i32)> = r
            .section
            .temperatures
            .iter()
            .map(|t| (t.chip.as_str(), t.label.as_str(), t.millicelsius))
            .collect();
        // The nvme and drivetemp chips are drives: not read.
        assert_eq!(
            temps,
            [("k10temp.0", "Tccd1", 41000), ("k10temp.0", "Tctl", 48250)]
        );
        let fans: Vec<(&str, &str, u32)> = r
            .section
            .fans
            .iter()
            .map(|f| (f.chip.as_str(), f.label.as_str(), f.rpm))
            .collect();
        assert_eq!(fans, [("nct_6779__isa_.2", "fan1", 1200)]);
        // "Vendor Secret Probe X", "Chassis Intake Left": dropped, counted.
        assert_eq!(r.dropped, 2);
        let json = serde_json::to_string(&r.section).unwrap();
        assert!(!json.contains("Vendor") && !json.contains("Chassis"));
        assert!(r.section.psus.is_empty(), "no /dev/ipmi0, no ipmitool run");
    }

    #[test]
    fn labels_are_a_closed_list() {
        for ok in [
            "Tctl",
            "Tdie",
            "Tccd8",
            "Package id 0",
            "Core 17",
            "Composite",
            "Sensor 2",
            "edge",
            "junction",
            "mem",
            "fan3",
            "temp9",
        ] {
            assert!(label_allowed(ok), "{ok}");
        }
        for no in [
            "",
            "Core",
            "Core x",
            "Package id 1234",
            "vm_abc123",
            "/dev/sda",
            "Tctl ",
            "temp1a",
        ] {
            assert!(!label_allowed(no), "{no:?}");
        }
    }

    #[test]
    fn ipmi_power_supplies_and_firmware() {
        let h = Host::new();
        hwmon_tree(&h);
        h.write("dev/ipmi0", "");
        let runner = Runner::default()
            .with(SDR_CMD, Ok(SDR_PSU))
            .with("ipmitool mc info", Ok(MC_INFO));
        let r = collect_sensors(&h.paths(), &runner);
        assert_eq!(r.section.status, SectionStatus::Ok);
        let psus: Vec<(&str, PsuState)> = r
            .section
            .psus
            .iter()
            .map(|p| (p.label.as_str(), p.state))
            .collect();
        assert_eq!(
            psus,
            [
                ("PSU1", PsuState::Ok),
                ("PSU2", PsuState::Failed),
                ("PSU3", PsuState::Unknown),
            ]
        );
        let json = serde_json::to_string(&r.section).unwrap();
        assert!(!json.contains("Redundancy") && !json.contains("Status"));
        assert_eq!(
            bmc_firmware(&h.paths(), &runner),
            Ok(Some("7.10".to_string()))
        );
    }

    #[test]
    fn no_bmc_or_no_ipmitool_is_hwmon_only_and_ok() {
        let h = Host::new();
        hwmon_tree(&h);
        // No /dev/ipmi0: ipmitool is never run (the runner would answer).
        let runner = Runner::default().with(SDR_CMD, Ok(SDR_PSU));
        let r = collect_sensors(&h.paths(), &runner);
        assert!(r.section.psus.is_empty());
        assert_eq!(r.section.status, SectionStatus::Ok);
        assert_eq!(bmc_firmware(&h.paths(), &runner), Ok(None));
        // /dev/ipmi0 but no ipmitool installed.
        h.write("dev/ipmi0", "");
        let r = collect_sensors(&h.paths(), &Runner::default());
        assert_eq!(r.section.status, SectionStatus::Ok);
        assert_eq!(bmc_firmware(&h.paths(), &Runner::default()), Ok(None));
    }

    #[test]
    fn an_ipmi_fault_is_partial_or_timeout_never_an_error() {
        let h = Host::new();
        hwmon_tree(&h);
        h.write("dev/ipmi0", "");
        let timeout = Runner::default()
            .with(SDR_CMD, Err(CommandError::Timeout))
            .with("ipmitool mc info", Err(CommandError::Timeout));
        let r = collect_sensors(&h.paths(), &timeout);
        assert_eq!(r.section.status, SectionStatus::Timeout);
        assert_eq!(r.section.temperatures.len(), 2, "hwmon still read");
        assert_eq!(
            bmc_firmware(&h.paths(), &timeout),
            Err(CommandError::Timeout)
        );
        let failed = Runner::default().with(SDR_CMD, Err(CommandError::Failed));
        let r = collect_sensors(&h.paths(), &failed);
        assert_eq!(r.section.status, SectionStatus::Partial);
    }

    #[test]
    fn psu_states_and_bmcs_without_status_sensors() {
        let states = |sdr: &str| -> Vec<(String, PsuState)> {
            parse_psus(sdr)
                .into_iter()
                .map(|p| (p.label, p.state))
                .collect()
        };
        // Discrete status sensors win over the numbered readings.
        assert_eq!(
            states(
                "PS1 Status | C8h | ok | 10.1 | Presence detected, Failure detected\n\
                 PS2 Status | C9h | ok | 10.2 | Presence detected, Predictive failure\n\
                 PS3 Status | CAh | ok | 10.3 | 0x01\n\
                 PS4 Status | CBh | ok | 10.4 | Not Present\n\
                 PS1 Current 1 | 78h | ok | 10.1 | 0.60 Amps\n"
            ),
            [
                ("PSU1".to_string(), PsuState::Failed),
                ("PSU2".to_string(), PsuState::Failed),
                ("PSU3".to_string(), PsuState::Unknown),
                ("PSU4".to_string(), PsuState::Absent),
            ]
        );
        // A BMC with no status sensor: every numbered one, once.
        assert_eq!(
            states(
                "PSU1 Input | 70h | ok | 10.1 | Presence detected\n\
                 PSU1 Power | 71h | ok | 10.1 | 220 Watts\n\
                 PSU2 Input | 72h | ns | 10.2 | No Reading\n"
            ),
            [
                ("PSU1".to_string(), PsuState::Ok),
                ("PSU2".to_string(), PsuState::Unknown),
            ]
        );
    }

    /// Every allowlisted label passes the crate's full-body validation.
    #[test]
    fn allowlisted_labels_validate_in_a_full_body() {
        use hippius_host_inventory::{HostInventory, ReportKind, Sections, DOMAIN, SCHEMA_VERSION};
        let temperatures: Vec<Temperature> = [
            "Package id 0",
            "Package id 12",
            "Core 117",
            "Tccd8",
            "Sensor 3",
            "Composite",
            "temp9",
        ]
        .iter()
        .map(|l| Temperature {
            chip: "coretemp.0".into(),
            label: (*l).to_string(),
            millicelsius: 50000,
        })
        .collect();
        assert!(temperatures.iter().all(|t| label_allowed(&t.label)));
        let mut body = HostInventory {
            schema_version: SCHEMA_VERSION,
            domain: DOMAIN.to_string(),
            miner_id: "m".into(),
            timestamp_unix: 1,
            sequence: 1,
            report: ReportKind::Change,
            sections: Sections {
                sensors: Some(SensorsSection {
                    status: SectionStatus::Ok,
                    temperatures,
                    fans: vec![],
                    psus: vec![],
                }),
                ..Sections::default()
            },
        };
        body.normalize();
        assert_eq!(body.validate(), Ok(()));
    }

    #[test]
    fn a_chip_with_no_readable_sensor_is_unavailable() {
        let h = Host::new();
        h.write("sys/class/hwmon/hwmon0/name", "acpitz\n");
        h.write("sys/class/hwmon/hwmon0/temp1_input", "garbage\n");
        let r = collect_sensors(&h.paths(), &Runner::default());
        assert_eq!(r.section.status, SectionStatus::Unavailable);
    }

    #[test]
    fn nothing_to_read_is_unavailable() {
        let h = Host::new();
        let r = collect_sensors(&h.paths(), &Runner::default());
        assert_eq!(r.section.status, SectionStatus::Unavailable);
        assert!(r.section.temperatures.is_empty());
    }

    /// A Dell PowerEdge iDRAC: every supply's sensor is named
    /// `Status`, numbered only by its entity instance.
    const IDRAC_SDR: &str = "\
PS Redundancy    | 77h | ns  | 7.1 | No Reading
Status           | 85h | ok  | 10.1 | Presence detected
Status           | 86h | ns  | 10.2 | Disabled
";
    /// The same iDRAC's `ipmitool mc info` (spacing as it prints it).
    const IDRAC_MC_INFO: &str = "\
Device ID                 : 32
Device Revision           : 1
Firmware Revision         : 7.30
IPMI Version              : 2.0
Manufacturer ID           : 674
Manufacturer Name         : DELL Inc
Product ID                : 256 (0x0100)
Product Name              : Unknown (0x100)
Device Available          : yes
Provides Device SDRs      : yes
Additional Device Support :
    Sensor Device
    SDR Repository Device
Aux Firmware Rev Info     :
    0x00
    0x1e
";

    #[test]
    fn a_dell_idrac_s_supplies_and_firmware() {
        let psus: Vec<(String, PsuState)> = parse_psus(IDRAC_SDR)
            .into_iter()
            .map(|p| (p.label, p.state))
            .collect();
        // `Status` lines win over `PS Redundancy`; `ns` (`Disabled`) is
        // unknown, not absent.
        assert_eq!(
            psus,
            vec![
                ("PSU1".to_string(), PsuState::Ok),
                ("PSU2".to_string(), PsuState::Unknown)
            ]
        );
        // A name's own number still wins over the entity; an entity that
        // is not a power supply numbers nothing.
        let named = parse_psus(
            "PS3 Status | C8h | ok | 10.1 | Presence detected\n\
                                Status | 85h | ok | 7.4 | Presence detected\n",
        );
        assert_eq!(
            named.iter().map(|p| p.label.as_str()).collect::<Vec<_>>(),
            ["PSU3"]
        );

        assert_eq!(parse_firmware(IDRAC_MC_INFO).as_deref(), Some("7.30"));
        assert_eq!(
            parse_firmware("Firmware Revision:7.30\n").as_deref(),
            Some("7.30")
        );
        assert_eq!(
            parse_firmware("Firmware Revision \t :   7.30  \n").as_deref(),
            Some("7.30")
        );

        let h = Host::new();
        h.write("dev/ipmi0", "");
        let runner = Runner::default()
            .with(SDR_CMD, Ok(IDRAC_SDR))
            .with("ipmitool mc info", Ok(IDRAC_MC_INFO));
        let r = collect_sensors(&h.paths(), &runner);
        assert_eq!(r.section.status, SectionStatus::Ok);
        assert_eq!(r.section.psus.len(), 2);
        assert_eq!(bmc_firmware(&h.paths(), &runner), Ok(Some("7.30".into())));
    }

    #[test]
    fn a_failing_ipmitool_is_partial_and_logged_with_its_exit_status() {
        let h = Host::new();
        hwmon_tree(&h);
        h.write("dev/ipmi0", "");
        let failing = Runner::default()
            .exits(SDR_CMD, 1)
            .exits("ipmitool mc info", 1);
        // Through the collector: its notes carry the exit status (which
        // only `run_bounded_status` knows), never the tool's output.
        let r = collect_sensors(&h.paths(), &failing);
        assert_eq!(r.section.status, SectionStatus::Partial);
        assert!(r.section.psus.is_empty());
        assert_eq!(
            r.notes,
            [
                "hippius-miner-agent: host-inventory-collect: ipmitool sdr type Power Supply: \
              failed (exit status 1)"
            ]
        );
        let mut notes = Vec::new();
        assert_eq!(
            bmc_firmware_noted(&h.paths(), &failing, &mut notes),
            Err(CommandError::Failed)
        );
        assert_eq!(
            notes,
            ["hippius-miner-agent: host-inventory-collect: ipmitool mc info: failed (exit status 1)"]
        );
        let timeout = Runner::default().with(SDR_CMD, Err(CommandError::Timeout));
        assert_eq!(
            collect_sensors(&h.paths(), &timeout).notes,
            [
                "hippius-miner-agent: host-inventory-collect: ipmitool sdr type Power Supply: \
              timed out after 10 s"
            ]
        );
        assert!(
            ipmi_failure_line(&["mc", "info"], CommandError::Failed, None)
                .ends_with("failed (no exit status: killed or not started)")
        );
        // A later `.with` replaces an `exits`, its code included.
        let fixed = Runner::default()
            .exits("ipmitool mc info", 1)
            .with("ipmitool mc info", Err(CommandError::Failed));
        assert_eq!(
            fixed.run_bounded_status("ipmitool", &["mc", "info"], IPMI_TIMEOUT, false),
            (Err(CommandError::Failed), None)
        );
    }

    #[test]
    fn a_missing_ipmitool_beside_dev_ipmi0_is_logged_once_per_run() {
        let h = Host::new();
        hwmon_tree(&h);
        h.write("dev/ipmi0", "");
        let none = Runner::default();
        let r = collect_sensors(&h.paths(), &none);
        assert_eq!(
            r.section.status,
            SectionStatus::Ok,
            "a missing tool is no fault"
        );
        assert_eq!(
            r.notes,
            [
                "hippius-miner-agent: host-inventory-collect: ipmitool sdr type Power Supply: \
              not installed although /dev/ipmi0 exists"
            ]
        );
        // The system section's `mc info` does not say it again.
        let mut notes = Vec::new();
        assert_eq!(bmc_firmware_noted(&h.paths(), &none, &mut notes), Ok(None));
        assert!(notes.is_empty());
        // No /dev/ipmi0: nothing run, nothing noted.
        let h = Host::new();
        hwmon_tree(&h);
        assert!(collect_sensors(&h.paths(), &none).notes.is_empty());
    }

    #[test]
    fn two_sensors_of_one_supply_keep_the_worse_state() {
        let state = |sdr: &str| -> Vec<(String, PsuState)> {
            parse_psus(sdr)
                .into_iter()
                .map(|p| (p.label, p.state))
                .collect()
        };
        for sdr in [
            "PS1 Status | C8h | ok | 10.1 | Presence detected\n\
             Status     | 85h | ok | 10.1 | Presence detected, Failure detected\n",
            "Status     | 85h | ok | 10.1 | Presence detected, Failure detected\n\
             PS1 Status | C8h | ok | 10.1 | Presence detected\n",
        ] {
            assert_eq!(
                state(sdr),
                [("PSU1".to_string(), PsuState::Failed)],
                "{sdr}"
            );
        }
        // unknown beats absent beats ok.
        assert_eq!(
            state(
                "PS1 Status | C8h | ok | 10.1 | Not Present\n\
                 Status     | 85h | ns | 10.1 | Disabled\n"
            ),
            [("PSU1".to_string(), PsuState::Unknown)]
        );
        assert_eq!(
            state(
                "PS1 Status | C8h | ok | 10.1 | Presence detected\n\
                 Status     | 85h | ok | 10.1 | Not Present\n"
            ),
            [("PSU1".to_string(), PsuState::Absent)]
        );
    }
}
