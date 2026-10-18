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
//! never an error. A BMC power-supply name is never copied: it becomes
//! `PSU<n>` from its first number.

use std::collections::BTreeSet;
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

/// `ipmitool sdr type "Power Supply"` lines:
/// `PS1 Status | C8h | ok | 10.1 | Presence detected`. The discrete
/// status sensors (`… Status`) say what a supply's state is; when the BMC
/// has none, every numbered sensor is read.
pub(crate) fn parse_psus(output: &str) -> Vec<Psu> {
    let rows: Vec<Vec<&str>> = output
        .lines()
        .map(|l| l.split('|').map(str::trim).collect::<Vec<&str>>())
        .filter(|c| c.len() == 5)
        .collect();
    let has_status = rows
        .iter()
        .any(|c| c[0].to_ascii_lowercase().contains("status"));
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for cols in &rows {
        let [name, _id, status, _entity, reading] = cols.as_slice() else {
            continue;
        };
        if has_status && !name.to_ascii_lowercase().contains("status") {
            continue;
        }
        // `PSU<n>` from the sensor name's first number; a sensor with no
        // number (`PS Redundancy`) is no supply.
        let digits: String = name
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(char::is_ascii_digit)
            .collect();
        if digits.is_empty() || digits.len() > 3 {
            continue;
        }
        let label = format!("PSU{digits}");
        if !seen.insert(label.clone()) {
            continue;
        }
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
        out.push(Psu { label, state });
    }
    out
}

/// `ipmitool mc info`'s `Firmware Revision` value.
pub(crate) fn parse_firmware(output: &str) -> Option<String> {
    let value = output.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim() == "Firmware Revision").then(|| v.trim().to_string())
    })?;
    super::clean_text(value.as_bytes(), hippius_host_inventory::MAX_TEXT_LEN)
}

/// Collect the sensors section.
pub fn collect_sensors(paths: &HostPaths, runner: &dyn CommandRunner) -> SensorsReport {
    let mut tally = Tally::default();
    let mut dropped = 0u32;
    let (mut temperatures, mut fans) = hwmon(paths, &mut tally, &mut dropped);
    let mut psus = Vec::new();
    if paths.ipmi_device.exists() {
        let sdr = runner.run_bounded(
            "ipmitool",
            &["sdr", "type", "Power Supply"],
            IPMI_TIMEOUT,
            false,
        );
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
    }
}

/// The BMC firmware revision (`ipmitool mc info`), when a BMC is local;
/// a fault is `Err` for the caller's status.
pub fn bmc_firmware(
    paths: &HostPaths,
    runner: &dyn CommandRunner,
) -> Result<Option<String>, CommandError> {
    if !paths.ipmi_device.exists() {
        return Ok(None);
    }
    match runner.run_bounded("ipmitool", &["mc", "info"], IPMI_TIMEOUT, false) {
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
}
