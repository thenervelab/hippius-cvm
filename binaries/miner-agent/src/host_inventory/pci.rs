//! The `pci` section: GPUs, accelerators, RAID / SAS / NVMe controllers
//! and NICs from `/sys/bus/pci/devices`, named from `pci.ids`. Every other
//! class (bridges, USB, SATA, …) is skipped, and so are SR-IOV virtual
//! functions (a NIC can expose hundreds; they are the VMs', not the
//! host's hardware).

use std::collections::BTreeSet;
use std::path::Path;

use hippius_host_inventory::{
    is_pci_address, ControllerMode, PciDevice, PciKind, PciSection, MAX_NAME_LEN, MAX_PCI_DEVICES,
};

use super::{
    clean_text, dir_names, link_name, parse_hex_u32, pci_ids, read_trimmed, HostPaths, Tally,
};

/// The kind of a 24-bit PCI class code, `None` for a class not shown.
pub(crate) fn kind(class: u32) -> Option<PciKind> {
    match (class >> 16, class >> 8) {
        (0x03, _) => Some(PciKind::Gpu),
        (0x12, _) => Some(PciKind::Accelerator),
        (_, 0x0104) => Some(PciKind::RaidController),
        (_, 0x0107) => Some(PciKind::SasHba),
        (_, 0x0108) => Some(PciKind::NvmeController),
        (0x02, _) => Some(PciKind::Nic),
        _ => None,
    }
}

/// A storage controller's mode from its driver.
fn mode(kind: PciKind, driver: Option<&str>) -> Option<ControllerMode> {
    matches!(kind, PciKind::RaidController | PciKind::SasHba).then(|| match driver {
        Some("megaraid_sas") => ControllerMode::Raid,
        Some("mpt3sas" | "mpt2sas") => ControllerMode::Hba,
        _ => ControllerMode::Unknown,
    })
}

/// A sysfs `vendor` / `device` file as a 16-bit id.
pub(crate) fn id16(path: &Path) -> Option<u16> {
    read_trimmed(path)
        .and_then(|s| parse_hex_u32(&s))
        .and_then(|v| u16::try_from(v).ok())
}

pub fn collect_pci(paths: &HostPaths) -> PciSection {
    let mut tally = Tally::default();
    let root = paths.sys.join("bus/pci/devices");
    tally.note(root.is_dir());
    let mut devices = Vec::new();
    for address in dir_names(&root).into_iter().filter(|a| is_pci_address(a)) {
        let dir = root.join(&address);
        if dir.join("physfn").exists() {
            continue;
        }
        let Some(kind) = read_trimmed(&dir.join("class"))
            .and_then(|c| parse_hex_u32(&c))
            .and_then(kind)
        else {
            continue;
        };
        let (Some(vendor_id), Some(device_id)) =
            (id16(&dir.join("vendor")), id16(&dir.join("device")))
        else {
            // A device of a shown class whose ids cannot be read.
            tally.failed();
            continue;
        };
        let driver =
            link_name(&dir.join("driver")).and_then(|d| clean_text(d.as_bytes(), MAX_NAME_LEN));
        let number = |name: &str| read_trimmed(&dir.join(name)).and_then(|s| s.parse::<i64>().ok());
        devices.push(PciDevice {
            mode: mode(kind, driver.as_deref()),
            address,
            kind,
            vendor_id,
            device_id,
            name: None,
            driver,
            numa_node: number("numa_node").and_then(|n| u32::try_from(n).ok()),
            iommu_group: link_name(&dir.join("iommu_group")).and_then(|g| g.parse().ok()),
            link_width: number("current_link_width")
                .and_then(|n| u32::try_from(n).ok())
                .filter(|&w| w > 0),
            link_speed: read_trimmed(&dir.join("current_link_speed"))
                .filter(|s| !s.starts_with("Unknown"))
                .and_then(|s| clean_text(s.as_bytes(), MAX_NAME_LEN)),
        });
    }
    devices.sort_by(|a, b| a.address.cmp(&b.address));
    if devices.len() > MAX_PCI_DEVICES {
        devices.truncate(MAX_PCI_DEVICES);
        tally.failed();
    }
    let wanted: BTreeSet<(u16, u16)> = devices.iter().map(|d| (d.vendor_id, d.device_id)).collect();
    let names = pci_ids::names(&paths.pci_ids, &wanted);
    for d in &mut devices {
        d.name = names.get(&(d.vendor_id, d.device_id)).cloned();
    }
    PciSection {
        status: tally.status(),
        devices,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::fixture::Host;
    use super::super::pci_ids::tests::EXCERPT;
    use super::*;
    use hippius_host_inventory::SectionStatus;

    /// One device under `sys/bus/pci/devices/<address>`.
    pub(crate) fn device(
        h: &Host,
        address: &str,
        class: &str,
        vendor: &str,
        device: &str,
        driver: Option<&str>,
    ) {
        let d = format!("sys/bus/pci/devices/{address}");
        h.write(&format!("{d}/class"), format!("{class}\n"));
        h.write(&format!("{d}/vendor"), format!("{vendor}\n"));
        h.write(&format!("{d}/device"), format!("{device}\n"));
        if let Some(driver) = driver {
            h.symlink(
                &format!("{d}/driver"),
                &format!("../../../../bus/pci/drivers/{driver}"),
            );
        }
    }

    /// A megaraid_sas controller, an NVMe controller, a GPU, the eno1 NIC
    /// and a host bridge (skipped), plus `pci.ids`.
    pub(crate) fn pci_tree(h: &Host) {
        h.write("pci.ids", EXCERPT);
        let raid = "0000:01:00.0";
        device(
            h,
            raid,
            "0x010400",
            "0x1000",
            "0x0016",
            Some("megaraid_sas"),
        );
        let d = format!("sys/bus/pci/devices/{raid}");
        h.write(&format!("{d}/numa_node"), "1\n");
        h.symlink(
            &format!("{d}/iommu_group"),
            "../../../../kernel/iommu_groups/42",
        );
        h.write(&format!("{d}/current_link_width"), "8\n");
        h.write(&format!("{d}/current_link_speed"), "16.0 GT/s PCIe\n");
        device(
            h,
            "0000:02:00.0",
            "0x010802",
            "0x144d",
            "0xa80a",
            Some("nvme"),
        );
        h.write("sys/bus/pci/devices/0000:02:00.0/numa_node", "-1\n");
        h.write(
            "sys/bus/pci/devices/0000:02:00.0/current_link_speed",
            "Unknown\n",
        );
        device(h, "0000:c1:00.0", "0x030200", "0x10de", "0x2330", None);
        device(
            h,
            "0000:41:00.0",
            "0x020000",
            "0x14e4",
            "0x16d8",
            Some("bnxt_en"),
        );
        device(h, "0000:00:00.0", "0x060000", "0x1022", "0x14a4", None);
    }

    #[test]
    fn reads_the_shown_classes_and_skips_the_rest() {
        let h = Host::new();
        pci_tree(&h);
        // An SR-IOV virtual function of the NIC: skipped.
        device(
            &h,
            "0000:41:00.4",
            "0x020000",
            "0x14e4",
            "0x16dc",
            Some("bnxt_en"),
        );
        h.symlink("sys/bus/pci/devices/0000:41:00.4/physfn", "../0000:41:00.0");
        // Not a PCI address: skipped.
        device(&h, "pci0000:00", "0x020000", "0x14e4", "0x16d8", None);
        let p = collect_pci(&h.paths());
        assert_eq!(p.status, SectionStatus::Ok);
        let addrs: Vec<&str> = p.devices.iter().map(|d| d.address.as_str()).collect();
        assert_eq!(
            addrs,
            [
                "0000:01:00.0",
                "0000:02:00.0",
                "0000:41:00.0",
                "0000:c1:00.0"
            ]
        );

        let raid = &p.devices[0];
        assert_eq!(raid.kind, PciKind::RaidController);
        assert_eq!((raid.vendor_id, raid.device_id), (0x1000, 0x0016));
        assert_eq!(
            raid.name.as_deref(),
            Some("Broadcom / LSI MegaRAID Tri-Mode SAS3508")
        );
        assert_eq!(raid.driver.as_deref(), Some("megaraid_sas"));
        assert_eq!(raid.mode, Some(ControllerMode::Raid));
        assert_eq!(raid.numa_node, Some(1));
        assert_eq!(raid.iommu_group, Some(42));
        assert_eq!(raid.link_width, Some(8));
        assert_eq!(raid.link_speed.as_deref(), Some("16.0 GT/s PCIe"));

        let nvme = &p.devices[1];
        assert_eq!(nvme.kind, PciKind::NvmeController);
        assert_eq!(nvme.mode, None, "a mode is for RAID / HBA only");
        assert_eq!(nvme.numa_node, None, "-1 is none");
        assert_eq!(nvme.link_speed, None);
        assert_eq!(p.devices[2].kind, PciKind::Nic);
        let gpu = &p.devices[3];
        assert_eq!(gpu.kind, PciKind::Gpu);
        assert_eq!(gpu.driver, None);
        assert_eq!(
            gpu.name.as_deref(),
            Some("NVIDIA Corporation GH100 [H100 SXM5 80GB]")
        );
    }

    #[test]
    fn classes_and_modes() {
        assert_eq!(kind(0x030000), Some(PciKind::Gpu));
        assert_eq!(kind(0x120000), Some(PciKind::Accelerator));
        assert_eq!(kind(0x010700), Some(PciKind::SasHba));
        assert_eq!(kind(0x010601), None, "SATA AHCI");
        assert_eq!(kind(0x060400), None, "PCI bridge");
        assert_eq!(kind(0x0c0330), None, "USB");
        assert_eq!(
            mode(PciKind::SasHba, Some("mpt3sas")),
            Some(ControllerMode::Hba)
        );
        assert_eq!(
            mode(PciKind::RaidController, Some("smartpqi")),
            Some(ControllerMode::Unknown)
        );
        assert_eq!(mode(PciKind::Nic, Some("megaraid_sas")), None);
    }

    #[test]
    fn devices_past_the_cap_make_the_section_partial() {
        let h = Host::new();
        for i in 0..(MAX_PCI_DEVICES + 1) {
            device(
                &h,
                &format!("0000:{i:02x}:00.0"),
                "0x030000",
                "0x10de",
                "0x2330",
                None,
            );
        }
        let p = collect_pci(&h.paths());
        assert_eq!(p.devices.len(), MAX_PCI_DEVICES);
        assert_eq!(p.status, SectionStatus::Partial);
        // At the cap exactly: ok.
        let h = Host::new();
        for i in 0..MAX_PCI_DEVICES {
            device(
                &h,
                &format!("0000:{i:02x}:00.0"),
                "0x030000",
                "0x10de",
                "0x2330",
                None,
            );
        }
        assert_eq!(collect_pci(&h.paths()).status, SectionStatus::Ok);
    }

    #[test]
    fn the_device_list_is_capped_and_unreadable_ids_degrade() {
        let h = Host::new();
        for i in 0..(MAX_PCI_DEVICES + 5) {
            device(
                &h,
                &format!("0000:{:02x}:00.0", i),
                "0x020000",
                "0x14e4",
                "0x16d8",
                None,
            );
        }
        let d = "sys/bus/pci/devices/0000:ff:00.0";
        h.write(&format!("{d}/class"), "0x010802\n");
        h.write(&format!("{d}/vendor"), "garbage\n");
        let p = collect_pci(&h.paths());
        assert_eq!(p.devices.len(), MAX_PCI_DEVICES);
        assert_eq!(p.status, SectionStatus::Partial);
        // No pci.ids anywhere: no names, nothing else lost.
        assert!(p.devices.iter().all(|d| d.name.is_none()));
        assert_eq!(
            collect_pci(&Host::new().paths()).status,
            SectionStatus::Unavailable
        );
    }
}
