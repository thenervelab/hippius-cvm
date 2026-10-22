//! Known-answer test for the §18.10 host inventory wire format.
//!
//! Freezes, in `test_vectors/host_inventory/`:
//!
//! - `host_inventory_body_full.cbor` — the canonical body of the pinned
//!   `full` report (every section);
//! - `signed_host_inventory_full.cbor` — its `{body, sig}` envelope,
//!   signed by a fixed test Ed25519 key (deterministic);
//! - `host_inventory_body_counters.cbor` / `signed_host_inventory_counters.cbor`
//!   — a `counters` report (memory, storage advisories, sensors, software);
//! - `host_inventory_body_auto_update.cbor` / `signed_host_inventory_auto_update.cbor`
//!   — the same `counters` report with `software.auto_update` (off, with
//!   a failed tag). The two vectors above carry no `auto_update` and stay
//!   byte-identical to what an encoder without the field produced.
//!
//! vali's verifier tests and any parallel encoder must reproduce these
//! bytes. A failure is drift: fix the implementation, never silently
//! regenerate. Regenerate deliberately — `test_vectors/host_inventory/REGENERATE.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::{Signer, SigningKey};
use hippius_host_inventory::*;
use std::path::PathBuf;

/// Pinned test Ed25519 signing-key seed (synthetic, fixed).
const KAT_SEED: [u8; 32] = [0x5Du8; 32];

fn vector(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test_vectors/host_inventory")
        .join(name)
}

fn s(v: &str) -> String {
    v.to_string()
}

pub fn kat_full() -> HostInventory {
    HostInventory {
        schema_version: SCHEMA_VERSION,
        domain: DOMAIN.into(),
        miner_id: "miner-kat-1".into(),
        timestamp_unix: 1_792_200_000,
        sequence: 3,
        report: ReportKind::Full,
        sections: Sections {
            system: Some(SystemSection {
                status: SectionStatus::Ok,
                vendor: Some(s("Dell Inc.")),
                product: Some(s("PowerEdge R6515")),
                serial: Some(s("KATSERIAL1")),
                board_vendor: Some(s("Dell Inc.")),
                board_product: Some(s("0R4CNN")),
                bios_vendor: Some(s("Dell Inc.")),
                bios_version: Some(s("2.24.1")),
                bios_date: Some(s("05/12/2025")),
                bmc_present: true,
                ipmi_version: Some(s("2.0")),
                bmc_firmware: Some(s("7.30")),
            }),
            cpu: Some(CpuSection {
                status: SectionStatus::Ok,
                model: Some(s("AMD EPYC 9254 24-Core Processor")),
                family: 25,
                model_id: 17,
                stepping: 1,
                sockets: 1,
                cores: 24,
                threads: 24,
                smt_control: Some(SmtControl::Off),
                smt_active: false,
                base_mhz: Some(2900),
                max_mhz: Some(4150),
                microcode: Some(s("0x0a10113e")),
                sev: true,
                sev_es: true,
                sev_snp: true,
                flags: vec![CpuFlag::Sev, CpuFlag::SevEs, CpuFlag::SevSnp, CpuFlag::Avx2],
            }),
            memory: Some(kat_memory()),
            storage: Some(kat_storage()),
            network: Some(NetworkSection {
                status: SectionStatus::Ok,
                nics: vec![Nic {
                    name: s("eno1"),
                    pci: Some(s("0000:41:00.0")),
                    model: Some(s("Broadcom BCM57416")),
                    driver: Some(s("bnxt_en")),
                    firmware: Some(s("226.0.145.0")),
                    state: LinkState::Up,
                    speed_mbps: Some(10_000),
                    duplex: Duplex::Full,
                    mtu: 1500,
                    role: NicRole::Public,
                }],
                netbird: Some(NetbirdInterface {
                    state: LinkState::Up,
                    mtu: 1280,
                }),
                virtual_interfaces: 14,
            }),
            pci: Some(PciSection {
                status: SectionStatus::Ok,
                devices: vec![PciDevice {
                    address: s("0000:01:00.0"),
                    kind: PciKind::RaidController,
                    vendor_id: 0x1000,
                    device_id: 0x0097,
                    name: Some(s("Broadcom / LSI SAS3008")),
                    driver: Some(s("megaraid_sas")),
                    numa_node: Some(0),
                    iommu_group: Some(12),
                    link_width: Some(8),
                    link_speed: Some(s("8.0 GT/s PCIe")),
                    mode: Some(ControllerMode::Raid),
                }],
            }),
            sensors: Some(kat_sensors()),
            software: Some(kat_software()),
        },
    }
}

fn kat_memory() -> MemorySection {
    MemorySection {
        status: SectionStatus::Ok,
        total_mib: 386_000,
        dimms: vec![Dimm {
            bank_locator: Some(s("P0 CHANNEL A")),
            locator: s("DIMM 0"),
            size_mib: 32_768,
            mem_type: Some(s("DDR5")),
            speed_mts: Some(4800),
            configured_mts: Some(4800),
            ecc: EccType::MultiBit,
            manufacturer: Some(s("Samsung")),
            part: Some(s("M321R4GA3BB6-CQKET")),
            serial: Some(s("KATDIMM01")),
        }],
        edac: Some(Edac {
            ce_total: 2,
            ue_total: 0,
            per_dimm: vec![DimmErrors {
                locator: s("mc#0csrow#0channel#0"),
                ce: 2,
                ue: 0,
            }],
        }),
    }
}

fn kat_storage() -> StorageSection {
    StorageSection {
        status: SectionStatus::Partial,
        devices: vec![
            Device {
                name: s("md127"),
                kind: DeviceKind::Md,
                size_bytes: 3_840_000_000_000,
                ids: vec![],
                model: None,
                transport: Transport::Md,
                rotational_hint: None,
                removable: false,
                read_only: false,
                behind_controller: None,
                partitions: vec![],
                holders: vec![],
                md: Some(MdInfo {
                    level: s("raid1"),
                    state: s("clean"),
                    degraded: 0,
                    members: vec![s("nvme0n1"), s("nvme1n1")],
                }),
                fs: Some(FsInfo {
                    fs_type: s("ext4"),
                    uuid_present: true,
                    size_bytes: Some(3_779_000_000_000),
                    available_bytes: Some(3_590_000_000_000),
                }),
                mounts: vec![s("/mnt/hippius-data")],
                role: DeviceRole::PoolBacking,
                pool_ids: vec![s("default"), s("nvme0")],
                reasons: vec![],
            },
            Device {
                name: s("sdb"),
                kind: DeviceKind::Disk,
                size_bytes: 18_000_207_937_536,
                ids: vec![s("wwn-0x5000c500a1b2c3d4"), s("ata-KATMODEL_KATSERIAL2")],
                model: Some(s("KATMODEL")),
                transport: Transport::Sata,
                rotational_hint: Some(true),
                removable: false,
                read_only: false,
                behind_controller: None,
                partitions: vec![],
                holders: vec![],
                md: None,
                fs: None,
                mounts: vec![],
                role: DeviceRole::EligibleDedicated,
                pool_ids: vec![],
                reasons: vec![],
            },
        ],
        advisories: vec![Advisory {
            subject_kind: AdvisorySubject::Controller,
            subject: s("ctrl:PERC H330 Mini:0"),
            code: AdvisoryCode::SmartUnavailableBehindController,
            severity: Severity::Info,
            count: 1,
            value: 0,
            first_seen_unix: 1_792_100_000,
            last_seen_unix: 1_792_199_000,
            sample: None,
        }],
        advisories_truncated: false,
        devices_truncated: false,
    }
}

fn kat_sensors() -> SensorsSection {
    SensorsSection {
        status: SectionStatus::Ok,
        temperatures: vec![Temperature {
            chip: s("k10temp.0"),
            label: s("Tctl"),
            millicelsius: 54_250,
        }],
        fans: vec![Fan {
            chip: s("ipmi"),
            label: s("Fan1"),
            rpm: 9000,
        }],
        psus: vec![Psu {
            label: s("PSU1"),
            state: PsuState::Ok,
        }],
    }
}

fn kat_software() -> SoftwareSection {
    SoftwareSection {
        status: SectionStatus::Ok,
        kernel: Some(s("7.0.0-15-generic")),
        os_name: Some(s("Ubuntu")),
        os_version_id: Some(s("26.04")),
        agent_version: Some(s("v2026.10.17")),
        qemu_version: Some(s("10.1.0")),
        libvirt_version: Some(s("12.0.0")),
        uptime_s: 1_234_567,
        last_boot_unix: Some(1_790_965_433),
        auto_update: None,
    }
}

pub fn kat_auto_update() -> HostInventory {
    let mut body = HostInventory {
        sequence: 5,
        ..kat_counters()
    };
    if let Some(sw) = body.sections.software.as_mut() {
        sw.auto_update = Some(AutoUpdateStatus {
            enabled: false,
            disabled_reason: Some(AutoUpdateDisabledReason::NoAutoUpdateFile),
            last_check_unix: Some(1_792_200_000),
            failed_tag: Some(s("v2026.10.18.1")),
        });
    }
    body
}

pub fn kat_counters() -> HostInventory {
    HostInventory {
        sequence: 4,
        timestamp_unix: 1_792_221_600,
        report: ReportKind::Counters,
        sections: Sections {
            memory: Some(kat_memory()),
            storage: Some(kat_storage()),
            sensors: Some(kat_sensors()),
            software: Some(kat_software()),
            ..Sections::default()
        },
        ..kat_full()
    }
}

fn signed(body: &HostInventory) -> SignedHostInventory {
    let body = body.canonical().expect("encode KAT body");
    let sig = SigningKey::from_bytes(&KAT_SEED).sign(&body);
    SignedHostInventory {
        body,
        sig: sig.to_bytes().to_vec(),
    }
}

fn cases() -> [(&'static str, HostInventory); 3] {
    [
        ("full", kat_full()),
        ("counters", kat_counters()),
        ("auto_update", kat_auto_update()),
    ]
}

#[test]
fn the_bodies_and_envelopes_match_the_frozen_vectors() {
    for (name, body) in cases() {
        let produced = body.canonical().unwrap();
        let expected = std::fs::read(vector(&format!("host_inventory_body_{name}.cbor")))
            .expect("vector missing — see test_vectors/host_inventory/REGENERATE.md");
        assert_eq!(produced, expected, "{name} body drifted");
        let env = signed(&body).canonical().unwrap();
        let expected =
            std::fs::read(vector(&format!("signed_host_inventory_{name}.cbor"))).unwrap();
        assert_eq!(env, expected, "{name} envelope drifted");
    }
}

#[test]
fn the_vectors_decode_and_verify() {
    let vk = SigningKey::from_bytes(&KAT_SEED).verifying_key();
    let expected_vk = std::fs::read_to_string(vector("kat_vk.hex")).unwrap();
    assert_eq!(hex::encode(vk.to_bytes()), expected_vk.trim());
    for (name, body) in cases() {
        let bytes = std::fs::read(vector(&format!("signed_host_inventory_{name}.cbor"))).unwrap();
        let env = SignedHostInventory::decode(&bytes).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&env.sig).unwrap();
        vk.verify_strict(&env.body, &sig).unwrap();
        assert_eq!(HostInventory::decode(&env.body).unwrap(), body, "{name}");
    }
}

#[test]
fn a_full_report_fits_well_under_the_cap() {
    let body = kat_full().canonical().unwrap();
    assert!(body.len() < MAX_BODY_BYTES / 8, "{} bytes", body.len());
}

#[test]
#[ignore]
fn regenerate_committed_vectors() {
    for (name, body) in cases() {
        std::fs::write(
            vector(&format!("host_inventory_body_{name}.cbor")),
            body.canonical().unwrap(),
        )
        .unwrap();
        std::fs::write(
            vector(&format!("signed_host_inventory_{name}.cbor")),
            signed(&body).canonical().unwrap(),
        )
        .unwrap();
    }
    let vk = SigningKey::from_bytes(&KAT_SEED).verifying_key();
    std::fs::write(
        vector("kat_vk.hex"),
        format!("{}\n", hex::encode(vk.to_bytes())),
    )
    .unwrap();
}
