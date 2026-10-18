//! The `system` section: vendor, product, serial, board, BIOS from
//! `/sys/class/dmi/id`; the BMC from `/dev/ipmi0` and the SMBIOS type 38
//! record; the BMC firmware from `ipmitool mc info` (local in-band, only
//! with `/dev/ipmi0`, bounded; a fault makes the section partial or
//! timeout, never an error).

use hippius_host_inventory::{SystemSection, MAX_SERIAL_LEN, MAX_TEXT_LEN};

use super::{clean_text, sensors, smbios, CommandRunner, HostPaths, Source, Tally};

/// The IPMI spec revision of an SMBIOS type 38 record: the byte at 0x05
/// (0x04 is the interface type), BCD major/minor nibbles (`0x20` → `2.0`).
/// `None` for a zero revision.
fn ipmi_version(record: &smbios::Structure<'_>) -> Option<String> {
    let rev = record.byte(0x05).filter(|&b| b != 0)?;
    Some(format!("{}.{}", rev >> 4, rev & 0x0F))
}

pub fn collect_system(paths: &HostPaths, runner: &dyn CommandRunner) -> SystemSection {
    let mut tally = Tally::default();
    let dmi_id = paths.sys.join("class/dmi/id");
    tally.note(dmi_id.is_dir());
    let mut field = |name: &str, max: usize| {
        tally
            .optional(Source::read(&dmi_id.join(name)))
            .and_then(|s| clean_text(s.as_bytes(), max))
    };
    let vendor = field("sys_vendor", MAX_TEXT_LEN);
    let product = field("product_name", MAX_TEXT_LEN);
    let serial = field("product_serial", MAX_SERIAL_LEN);
    let board_vendor = field("board_vendor", MAX_TEXT_LEN);
    let board_product = field("board_name", MAX_TEXT_LEN);
    let bios_vendor = field("bios_vendor", MAX_TEXT_LEN);
    let bios_version = field("bios_version", MAX_TEXT_LEN);
    let bios_date = field("bios_date", MAX_TEXT_LEN);

    let table = std::fs::read(&paths.dmi_table).ok();
    tally.note(table.is_some());
    let parsed = table.as_deref().map(smbios::parse).unwrap_or_default();
    let ipmi = parsed.of_kind(smbios::TYPE_IPMI_DEVICE).next();
    let firmware = sensors::bmc_firmware(paths, runner);
    match &firmware {
        Ok(Some(_)) => tally.ok(),
        // No BMC, or no ipmitool: nothing to report.
        Ok(None) => {}
        Err(e) => tally.command::<()>(&Err(*e)),
    }
    SystemSection {
        status: tally.status(),
        vendor,
        product,
        serial,
        board_vendor,
        board_product,
        bios_vendor,
        bios_version,
        bios_date,
        bmc_present: paths.ipmi_device.exists() || ipmi.is_some(),
        ipmi_version: ipmi.and_then(ipmi_version),
        bmc_firmware: firmware.ok().flatten(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::fixture::{Host, Runner};
    use super::*;
    use hippius_host_inventory::SectionStatus;

    pub(crate) fn dmi_id(h: &Host) {
        for (f, v) in [
            ("sys_vendor", "Dell Inc.\n"),
            ("product_name", "PowerEdge R6615\n"),
            ("product_serial", "ABC1234\n"),
            ("board_vendor", "Dell Inc.\n"),
            ("board_name", "0R7VTV\n"),
            ("bios_vendor", "Dell Inc.\n"),
            ("bios_version", "1.6.10\n"),
            ("bios_date", "03/21/2024\n"),
        ] {
            h.write(&format!("sys/class/dmi/id/{f}"), v);
        }
    }

    #[test]
    fn reads_dmi_id_and_the_bmc_from_type_38() {
        let h = Host::new();
        dmi_id(&h);
        h.write("DMI", smbios::tests::sample_table());
        let s = collect_system(&h.paths(), &Runner::default());
        assert_eq!(s.status, SectionStatus::Ok);
        assert_eq!(s.vendor.as_deref(), Some("Dell Inc."));
        assert_eq!(s.product.as_deref(), Some("PowerEdge R6615"));
        assert_eq!(s.serial.as_deref(), Some("ABC1234"));
        assert_eq!(s.board_product.as_deref(), Some("0R7VTV"));
        assert_eq!(s.bios_version.as_deref(), Some("1.6.10"));
        assert_eq!(s.bios_date.as_deref(), Some("03/21/2024"));
        assert!(s.bmc_present);
        assert_eq!(s.ipmi_version.as_deref(), Some("2.0"));
        assert_eq!(s.bmc_firmware, None);
    }

    #[test]
    fn placeholders_and_junk_become_none_and_long_strings_are_cut() {
        let h = Host::new();
        h.write("sys/class/dmi/id/sys_vendor", "To Be Filled By O.E.M.\n");
        h.write("sys/class/dmi/id/product_name", "Default string\n");
        h.write("sys/class/dmi/id/product_serial", "System Serial Number\n");
        h.write("sys/class/dmi/id/board_vendor", [0xffu8; 8]);
        h.write("sys/class/dmi/id/board_name", b"X13\x01SWA\xe2\x80\x93TF\n");
        h.write("sys/class/dmi/id/bios_vendor", "Not Specified");
        h.write("sys/class/dmi/id/bios_version", "v".repeat(400));
        h.write("sys/class/dmi/id/bios_date", "");
        let s = collect_system(&h.paths(), &Runner::default());
        assert_eq!(s.vendor, None);
        assert_eq!(s.product, None);
        assert_eq!(s.serial, None);
        assert_eq!(s.board_vendor, None);
        assert_eq!(s.board_product.as_deref(), Some("X13SWATF"));
        assert_eq!(s.bios_vendor, None);
        assert_eq!(s.bios_version.as_deref().map(str::len), Some(MAX_TEXT_LEN));
        assert_eq!(s.bios_date, None);
        // No DMI table, no /dev/ipmi0: no BMC, and the section is partial.
        assert!(!s.bmc_present);
        assert_eq!(s.ipmi_version, None);
        assert_eq!(s.status, SectionStatus::Partial);
    }

    #[test]
    fn a_long_serial_is_cut_to_the_serial_bound() {
        let h = Host::new();
        h.write("sys/class/dmi/id/product_serial", "S".repeat(100));
        let s = collect_system(&h.paths(), &Runner::default());
        assert_eq!(s.serial.unwrap().len(), MAX_SERIAL_LEN);
    }

    #[test]
    fn dev_ipmi0_alone_means_a_bmc() {
        let h = Host::new();
        h.write("dev/ipmi0", "");
        let s = collect_system(&h.paths(), &Runner::default());
        assert!(s.bmc_present);
        assert_eq!(s.ipmi_version, None);
        assert_eq!(s.status, SectionStatus::Unavailable);
    }

    #[test]
    fn the_bmc_firmware_comes_from_ipmitool_when_a_bmc_is_local() {
        let h = Host::new();
        dmi_id(&h);
        h.write("DMI", smbios::tests::sample_table());
        h.write("dev/ipmi0", "");
        let runner = Runner::default().with("ipmitool mc info", Ok(sensors::tests::MC_INFO));
        let s = collect_system(&h.paths(), &runner);
        assert_eq!(s.bmc_firmware.as_deref(), Some("7.10"));
        assert_eq!(s.status, SectionStatus::Ok);
        // A timeout: the section says so, the rest is read.
        let runner =
            Runner::default().with("ipmitool mc info", Err(super::super::CommandError::Timeout));
        let s = collect_system(&h.paths(), &runner);
        assert_eq!(s.bmc_firmware, None);
        assert_eq!(s.status, SectionStatus::Timeout);
        assert_eq!(s.vendor.as_deref(), Some("Dell Inc."));
    }
}
