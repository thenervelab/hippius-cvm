//! Known-answer test for the SEV-SNP libvirt domain XML.
//!
//! Freezes `QemuConfig::to_libvirt_xml` against a pinned document for
//! a fixed input so an accidental edit to the template — or to the
//! SEV-SNP launch-security block — fails CI loudly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use hippius_miner_agent::snp_config::{install_for_tests, SnpCpuConfig};
use hippius_miner_agent::{DomainUuid, QemuConfig, VmId};

/// Issue #116 — `QemuConfig::to_libvirt_xml` now reads the SEV-SNP
/// C-bit position + physical-address reduction from
/// `snp_config::global()`, which probes the host CPU via `CPUID
/// 0x8000001f`. CI runners (and most dev hosts) are not AMD EPYCs,
/// so the probe would fail and `to_libvirt_xml` would panic. We
/// pre-seed the process-global cache with the Genoa / Turin values
/// (the entire current fleet) so the KAT runs deterministically and
/// matches the hardcoded numbers it pins on the next two lines.
///
/// Idempotent — `OnceLock::set` short-circuits after the first
/// successful set; tests in different modules of the same process
/// all converge on the same `51 / 1` value (no test in the
/// workspace wants a different shape).
fn seed_snp_probe() {
    install_for_tests(SnpCpuConfig {
        cbitpos: 51,
        reduced_phys_bits: 1,
    });
}

/// The pinned domain XML for [`kat_config`].
const EXPECTED_XML: &str = "\
<domain type='kvm'>
  <name>hippius-tenant-kat-cvm</name>
  <uuid>00000000-0000-4000-8000-000000000000</uuid>
  <memory unit='MiB'>2048</memory>
  <currentMemory unit='MiB'>2048</currentMemory>
  <memoryBacking>
    <source type='memfd'/>
    <access mode='shared'/>
  </memoryBacking>
  <vcpu placement='static'>2</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <loader type='rom'>/var/lib/hippius-miner/ovmf/ovmf.fd</loader>
    <kernel>/var/lib/hippius-miner/staging/vmlinuz</kernel>
    <initrd>/var/lib/hippius-miner/staging/initrd.cpio</initrd>
    <cmdline>quiet panic=0 console=ttyS0</cmdline>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='host-passthrough'/>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <launchSecurity type='sev-snp' kernelHashes='yes'>
    <cbitpos>51</cbitpos>
    <reducedPhysBits>1</reducedPhysBits>
    <policy>0x30000</policy>
  </launchSecurity>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='/var/lib/hippius-miner/cvm/kat-cvm.img'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='/var/lib/hippius-miner/staging/rootfs.img'/>
      <target dev='vdb' bus='virtio'/>
      <readonly/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='/var/lib/hippius-miner/staging/rootfs.verity'/>
      <target dev='vdc' bus='virtio'/>
      <readonly/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='/var/lib/hippius-miner/state/kat-cvm.raw'/>
      <target dev='vdd' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <serial type='pty'>
      <target type='isa-serial' port='0'/>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <memballoon model='none'/>
    <vsock model='virtio'>
      <cid auto='no' address='5'/>
    </vsock>
  </devices>
</domain>
";

fn kat_config() -> QemuConfig {
    seed_snp_probe();
    QemuConfig {
        vm_id: VmId::new("kat-cvm").unwrap(),
        domain_uuid: DomainUuid::parse("00000000-0000-4000-8000-000000000000").unwrap(),
        ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf/ovmf.fd"),
        kernel_path: PathBuf::from("/var/lib/hippius-miner/staging/vmlinuz"),
        initrd_path: PathBuf::from("/var/lib/hippius-miner/staging/initrd.cpio"),
        cmdline: "quiet panic=0 console=ttyS0".to_string(),
        luks_disk_path: PathBuf::from("/var/lib/hippius-miner/cvm/kat-cvm.img"),
        luks_disk_size_gb: 10,
        rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/staging/rootfs.img"),
        rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/staging/rootfs.verity"),
        state_disk_path: PathBuf::from("/var/lib/hippius-miner/state/kat-cvm.raw"),
        data_disk_path: None,
        data_disk_size_gb: 0,
        cpu_count: 2,
        memory_mb: 2048,
        golden: false,
        cid: 5,
    }
}

#[test]
fn domain_xml_matches_known_answer() {
    assert_eq!(
        kat_config().to_libvirt_xml(),
        EXPECTED_XML,
        "the libvirt domain XML changed — if intentional, re-pin \
         EXPECTED_XML and re-review the SEV-SNP launch parameters"
    );
}

#[test]
fn domain_xml_always_pins_sev_snp() {
    // The struct cannot describe a non-confidential domain, and
    // `kernelHashes='yes'` keeps the guest's measurement equal to the
    // pre-flight digest.
    let xml = kat_config().to_libvirt_xml();
    assert!(xml.contains("<launchSecurity type='sev-snp' kernelHashes='yes'>"));
}

#[test]
fn domain_xml_escapes_a_hostile_path() {
    // A path carrying XML metacharacters must not break out of its
    // element — no XML injection via a launch path.
    let mut cfg = kat_config();
    cfg.kernel_path = PathBuf::from("/var/lib/hippius-miner/x'<inject>");
    let xml = cfg.to_libvirt_xml();
    assert!(xml.contains("x&apos;&lt;inject&gt;"));
    assert!(!xml.contains("<inject>"));
    assert!(!xml.contains("x'<inject>"));
}

#[test]
fn validate_then_render_is_consistent() {
    let cfg = kat_config();
    assert!(cfg.validate().is_ok());
    assert_eq!(
        cfg.domain_name().unwrap().as_str(),
        "hippius-tenant-kat-cvm"
    );
}
