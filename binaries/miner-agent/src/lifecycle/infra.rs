//! The diskless **blackbox host-attestor** Infra CVM (PR-7).
//!
//! This is the miner-agent's parallel to the tenant launch path — a
//! SINGLE, singleton, *diskless* SEV-SNP domain that boots the measured
//! blackbox UKI (PR-6) as `kernel + initrd-as-root`, with NO tenant
//! concerns at all: no data disk, no vsock CID, no KEK / OrderTicket /
//! KBS-proxy, no cloud-init, no netbird. It exists only so a later PR
//! (PR-9) can auto-spawn it on miner-join and vali can prove "THIS
//! physical CPU is up running our measured stack" (see the blackbox
//! attestor master plan's TRUST CEILING).
//!
//! ## Ships INERT
//!
//! Nothing here auto-launches: [`CvmLifecycle::launch_infra`] is only
//! reached via [`run_infra_supervisor`], which the `serve` loop spawns
//! **only** when the operator opts in through the `[host_attestor]`
//! config table (absent / `enabled=false` by default). No vali trigger
//! exists until PR-9. The tenant launch path is byte-for-byte unchanged.
//!
//! ## Diskless libvirt XML (R5)
//!
//! [`InfraDomainConfig::to_libvirt_xml`] renders a domain that shares
//! the tenant SNP posture (memfd backing, `launchSecurity type='sev-snp'
//! kernelHashes='yes'`, the same probed `cbitpos` / `reducedPhysBits` /
//! policy) but carries **NO `<disk>`** — the UKI's initramfs *is* the
//! root filesystem — and **no `<interface>`**: the attestor talks to the
//! host over vsock only (its initramfs has no network driver), so a NIC
//! on the shared guest bridge would only give a tenant something to
//! impersonate. 1 vCPU / 512 MiB.
//!
//! ## `<vsock>` device (PR-10b, S1)
//!
//! The domain DOES carry a `<vsock>` device pinned to a real, unique
//! guest CID allocated from the shared [`crate::vsock::peer::CidAllocator`]
//! (mirroring the tenant path). Without it the diskless attestor guest has
//! no virtio-vsock transport at all — it could neither PULL a fresh
//! vali-minted enrollment nonce (PR-10 challenge, DOWN) nor PUSH its
//! enrollment / liveness beacons (the UP relay). The `<vsock>` device is a
//! **runtime** device, NOT a measured launch input: the SEV-SNP launch
//! digest covers only OVMF + kernel + initrd + cmdline + vCPU count (see
//! [`super::launch_digest`]), so attaching it keeps the fleet-wide blackbox
//! measurement byte-identical — the operator/CI-pinned measurement is
//! unchanged, and the fail-closed pin assert still passes.
//!
//! ## Fail-closed measurement pin
//!
//! Before the domain is ever defined, [`CvmLifecycle::launch_infra`]
//! locally recomputes the SEV-SNP launch digest over the exact UKI it is
//! about to boot (the same `compute_launch_digest` the tenant path uses)
//! and asserts it equals an operator/vali-supplied sha256 pin. A
//! tampered local UKI therefore cannot boot under the attestor identity
//! — the launch is refused before any `virsh` call.

use std::path::PathBuf;
use std::time::Duration;

use super::cvm_handle::{DomainUuid, VmId};
use super::libvirt_driver::DomainId;
use super::qemu_config::{self, QemuConfig};
use super::CvmLifecycle;
use crate::error::{MinerAgentError, Result};

/// The singleton Infra CVM id — there is exactly ONE host-attestor per
/// miner host. A stable id means re-adopt + the supervisor always
/// address the same domain.
pub const INFRA_VM_ID: &str = "host-attestor";

/// The libvirt domain-name prefix for the Infra domain. Deliberately
/// distinct from the tenant `hippius-tenant-` prefix so the two can
/// never collide in libvirt's name table.
pub const INFRA_DOMAIN_PREFIX: &str = "hippius-infra-";

/// vCPUs for the Infra host-attestor — fixed at 1 (the attestor does
/// almost nothing: derive a key, answer nonces, beacon).
pub const INFRA_CPU_COUNT: u8 = 1;

/// Guest RAM (MiB) for the Infra host-attestor — fixed at 512.
pub const INFRA_MEMORY_MB: u32 = 512;

/// Poll gap for the supervision loop — how often it re-checks that the
/// Infra domain is still running.
const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Initial backoff after an Infra launch/relaunch failure. Doubles up
/// to [`SUPERVISOR_MAX_BACKOFF`] so a persistently-broken host-attestor
/// UKI does not hot-loop `virsh`.
const SUPERVISOR_MIN_BACKOFF: Duration = Duration::from_secs(5);

/// Ceiling for the supervision backoff.
const SUPERVISOR_MAX_BACKOFF: Duration = Duration::from_secs(300);

/// The inputs a caller supplies to launch (and re-supervise) the Infra
/// host-attestor domain.
///
/// Carries only the measured boot tuple (OVMF + the blackbox UKI's
/// kernel/initrd/cmdline) plus the sha256 measurement pin. NO tenant
/// fields exist — there is no disk and no ticket here by design. The
/// vsock CID is NOT an order input: like the tenant path, it is allocated
/// by the lifecycle under the handle lock at launch (a runtime device,
/// unmeasured), never supplied by the caller.
///
/// Not `Debug`: the `cmdline` is treated with the same no-log discipline
/// as the tenant [`crate::orders::LaunchOrder`].
#[derive(Clone)]
pub struct InfraLaunchOrder {
    /// Pinned, SEV-SNP-capable OVMF firmware (the same file the tenant
    /// path measures against).
    pub ovmf_path: PathBuf,
    /// The blackbox UKI's guest kernel (a measured launch input).
    pub kernel_path: PathBuf,
    /// The blackbox UKI's initrd — booted AS the root filesystem
    /// (diskless; a measured launch input).
    pub initrd_path: PathBuf,
    /// The blackbox UKI's kernel command line (a measured launch input;
    /// PR-6 fixes it to `"quiet panic=0 console=ttyS0"`).
    pub cmdline: String,
    /// Lowercase-hex SEV-SNP launch digest the local `compute_launch_
    /// digest` MUST reproduce before the domain is defined. Operator /
    /// vali supplied (a later PR pins it from the CI-built measurement);
    /// a mismatch fails the launch closed.
    pub expected_measurement_hex: String,
}

/// The diskless Infra domain configuration + its libvirt XML builder.
///
/// The parallel to [`QemuConfig`] for the Infra profile. Kept separate
/// so the tenant XML builder never has to carry diskless / no-vsock
/// branches — the two shapes stay independently auditable.
pub struct InfraDomainConfig {
    /// Always [`INFRA_VM_ID`].
    pub vm_id: VmId,
    /// libvirt domain UUID embedded in the XML.
    pub domain_uuid: DomainUuid,
    /// Pinned OVMF firmware.
    pub ovmf_path: PathBuf,
    /// Blackbox UKI guest kernel.
    pub kernel_path: PathBuf,
    /// Blackbox UKI initrd (root filesystem).
    pub initrd_path: PathBuf,
    /// Blackbox UKI kernel command line.
    pub cmdline: String,
    /// The AF_VSOCK context id pinned into the `<vsock>` device (PR-10b,
    /// S1). Placeholder-initialised by [`Self::from_order`]; the real,
    /// unique CID is assigned from the shared
    /// [`crate::vsock::peer::CidAllocator`] under the handle lock in
    /// [`super::CvmLifecycle::launch_infra`], exactly as the tenant path
    /// assigns its CID. A runtime device — NOT folded into the SEV-SNP
    /// launch digest, so it never perturbs the pinned measurement.
    pub cid: u32,
}

impl InfraDomainConfig {
    /// Build the config for `order`, pinning the singleton id + the
    /// fixed 1 vCPU / 512 MiB shape.
    ///
    /// `cid` is a placeholder here ([`crate::vsock::peer::MIN_GUEST_CID`]);
    /// `launch_infra` overwrites it with the allocator-assigned CID before
    /// the XML is ever rendered — mirroring the tenant `launch` path, where
    /// the real CID is likewise taken under the handle lock.
    pub fn from_order(order: &InfraLaunchOrder) -> Result<Self> {
        Ok(Self {
            vm_id: VmId::new(INFRA_VM_ID)?,
            domain_uuid: DomainUuid::generate()?,
            ovmf_path: order.ovmf_path.clone(),
            kernel_path: order.kernel_path.clone(),
            initrd_path: order.initrd_path.clone(),
            cmdline: order.cmdline.clone(),
            cid: crate::vsock::peer::MIN_GUEST_CID,
        })
    }

    /// The libvirt domain name (`hippius-infra-host-attestor`).
    pub fn domain_name(&self) -> Result<DomainId> {
        DomainId::new(&self.domain_name_string())
    }

    fn domain_name_string(&self) -> String {
        format!("{INFRA_DOMAIN_PREFIX}{}", self.vm_id)
    }

    /// Reject a config that cannot be launched safely. Mirrors the
    /// tenant [`QemuConfig::validate`] posture: primes the host SNP
    /// probe (so a failure surfaces here, not mid-XML) and validates the
    /// measured boot inputs. There are no disks / CID to validate.
    pub fn validate(&self) -> Result<()> {
        // Prime + propagate the host SEV-SNP launch-parameter probe.
        crate::snp_config::global()?;
        if self.cmdline.is_empty() {
            return Err(MinerAgentError::LaunchInput("cmdline-empty"));
        }
        if self.cmdline.contains('\0') {
            return Err(MinerAgentError::LaunchInput("cmdline-nul"));
        }
        qemu_config::validate_input_path(&self.ovmf_path, "ovmf-path")?;
        qemu_config::validate_input_path(&self.kernel_path, "kernel-path")?;
        qemu_config::validate_input_path(&self.initrd_path, "initrd-path")?;
        Ok(())
    }

    /// A throwaway [`QemuConfig`] carrying just the measured boot tuple,
    /// used ONLY to drive the shared [`super::LaunchDigestComputer`]
    /// (which reads only OVMF / kernel / initrd / cmdline / cpu_count —
    /// never the disk fields). The disk / cid placeholders never reach
    /// libvirt: the Infra domain renders its own [`Self::to_libvirt_xml`].
    pub fn to_digest_qemu_config(&self) -> Result<QemuConfig> {
        Ok(QemuConfig {
            vm_id: VmId::new(INFRA_VM_ID)?,
            domain_uuid: self.domain_uuid.clone(),
            ovmf_path: self.ovmf_path.clone(),
            kernel_path: self.kernel_path.clone(),
            initrd_path: self.initrd_path.clone(),
            cmdline: self.cmdline.clone(),
            // Placeholders — never rendered, never validated. The digest
            // computer ignores every disk field.
            luks_disk_path: PathBuf::from("/var/lib/hippius-miner/infra-unused.img"),
            luks_disk_size_gb: 1,
            rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/infra-unused.img"),
            rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/infra-unused.img"),
            state_disk_path: PathBuf::from("/var/lib/hippius-miner/state/infra-unused.raw"),
            data_disk_path: None,
            data_disk_size_gb: 0,
            cpu_count: INFRA_CPU_COUNT,
            memory_mb: INFRA_MEMORY_MB,
            // The diskless Infra attestor is never golden.
            golden: false,
            // The launch digest ignores the CID (only OVMF/kernel/initrd/
            // cmdline/vcpus are folded in); carry the real one for parity.
            cid: self.cid,
            net: None,
        })
    }

    /// Render the diskless Infra domain XML for `virsh define`.
    ///
    /// Shares the tenant SNP posture (memfd backing, `launchSecurity
    /// type='sev-snp' kernelHashes='yes'`, probed cbitpos/reducedPhysBits,
    /// the `0x30000` no-debug/no-migrate policy) but carries NO `<disk>`
    /// (the UKI initramfs is the root). It DOES carry a `<vsock>` device
    /// pinned to [`Self::cid`] (PR-10b, S1) so the diskless attestor guest
    /// can dial the host miner-agent — a runtime device that is NOT folded
    /// into the launch digest, so the fleet-wide measurement is unchanged.
    /// 1 vCPU / 512 MiB.
    pub fn to_libvirt_xml(&self) -> String {
        const FAIL_CLOSED_SNP: crate::snp_config::SnpCpuConfig = crate::snp_config::SnpCpuConfig {
            cbitpos: 0,
            reduced_phys_bits: 0,
        };
        let snp = crate::snp_config::global().unwrap_or(&FAIL_CLOSED_SNP);
        let name = qemu_config::xml_escape(&self.domain_name_string());
        let uuid = qemu_config::xml_escape(self.domain_uuid.as_str());
        let ovmf = qemu_config::xml_escape(&self.ovmf_path.to_string_lossy());
        let kernel = qemu_config::xml_escape(&self.kernel_path.to_string_lossy());
        let initrd = qemu_config::xml_escape(&self.initrd_path.to_string_lossy());
        let cmdline = qemu_config::xml_escape(&self.cmdline);
        format!(
            "<domain type='kvm'>\n  \
             <name>{name}</name>\n  \
             <uuid>{uuid}</uuid>\n  \
             <memory unit='MiB'>{memory}</memory>\n  \
             <currentMemory unit='MiB'>{memory}</currentMemory>\n  \
             <memoryBacking>\n    \
             <source type='memfd'/>\n    \
             <access mode='shared'/>\n  \
             </memoryBacking>\n  \
             <vcpu placement='static'>{cpu}</vcpu>\n  \
             <os>\n    \
             <type arch='x86_64' machine='q35'>hvm</type>\n    \
             <loader type='rom'>{ovmf}</loader>\n    \
             <kernel>{kernel}</kernel>\n    \
             <initrd>{initrd}</initrd>\n    \
             <cmdline>{cmdline}</cmdline>\n  \
             </os>\n  \
             <features>\n    <acpi/>\n    <apic/>\n  </features>\n  \
             <cpu mode='host-passthrough'/>\n  \
             <clock offset='utc'/>\n  \
             <on_poweroff>destroy</on_poweroff>\n  \
             <on_reboot>restart</on_reboot>\n  \
             <on_crash>destroy</on_crash>\n  \
             <launchSecurity type='sev-snp' kernelHashes='yes'>\n    \
             <cbitpos>{cbitpos}</cbitpos>\n    \
             <reducedPhysBits>{reduced}</reducedPhysBits>\n    \
             <policy>{policy}</policy>\n  \
             </launchSecurity>\n  \
             <devices>\n    \
             <serial type='pty'>\n      \
             <target type='isa-serial' port='0'/>\n    \
             </serial>\n    \
             <console type='pty'>\n      \
             <target type='serial' port='0'/>\n    \
             </console>\n    \
             <memballoon model='none'/>\n    \
             <vsock model='virtio'>\n      \
             <cid auto='no' address='{cid}'/>\n    \
             </vsock>\n  \
             </devices>\n\
             </domain>\n",
            name = name,
            uuid = uuid,
            memory = INFRA_MEMORY_MB,
            cpu = INFRA_CPU_COUNT,
            ovmf = ovmf,
            kernel = kernel,
            initrd = initrd,
            cmdline = cmdline,
            cbitpos = snp.cbitpos,
            reduced = snp.reduced_phys_bits,
            policy = qemu_config::SEV_SNP_POLICY,
            cid = self.cid,
        )
    }
}

/// Supervise the singleton Infra host-attestor domain: launch it once,
/// then keep it running (relaunch-on-exit with capped backoff) until
/// `cancel` fires.
///
/// **Default-inert:** the `serve` loop only spawns this when the operator
/// opts in via `[host_attestor]`. Absent that, the Infra domain is never
/// launched and this loop never runs — tenant behaviour is untouched.
///
/// Fail-open per iteration: a launch or query failure is logged and
/// retried after a backoff; it never aborts the process. On cancel the
/// loop returns promptly (it re-checks the token between waits) — the
/// serve loop's `shutdown_all` then stops the Infra domain like any other.
pub async fn run_infra_supervisor(
    lifecycle: std::sync::Arc<CvmLifecycle>,
    order: InfraLaunchOrder,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut backoff = SUPERVISOR_MIN_BACKOFF;
    loop {
        if cancel.is_cancelled() {
            return;
        }
        // Is the Infra domain already tracked + running? Re-adopt at
        // startup may have restored it; a prior iteration may have
        // launched it. Only (re)launch when it is genuinely absent.
        let running = lifecycle.infra_is_running().await;
        if running {
            backoff = SUPERVISOR_MIN_BACKOFF;
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(SUPERVISOR_POLL_INTERVAL) => {}
            }
            continue;
        }
        match lifecycle.launch_infra(order.clone()).await {
            Ok(_) => {
                eprintln!("hippius-miner-agent: infra-supervisor — host-attestor launched");
                backoff = SUPERVISOR_MIN_BACKOFF;
            }
            Err(err) => {
                eprintln!(
                    "hippius-miner-agent: infra-supervisor — host-attestor launch failed \
                     ({err}); retrying after backoff"
                );
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(SUPERVISOR_MAX_BACKOFF);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snp_config::{install_for_tests, SnpCpuConfig};

    fn seed_snp_probe() {
        install_for_tests(SnpCpuConfig {
            cbitpos: 51,
            reduced_phys_bits: 1,
        });
    }

    fn fixture_order() -> InfraLaunchOrder {
        InfraLaunchOrder {
            ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf/ovmf.fd"),
            kernel_path: PathBuf::from("/var/lib/hippius-miner/staging/attestor-vmlinuz"),
            initrd_path: PathBuf::from("/var/lib/hippius-miner/staging/attestor-initrd"),
            cmdline: "quiet panic=0 console=ttyS0".to_string(),
            expected_measurement_hex: "aa".repeat(48),
        }
    }

    fn fixture_config() -> InfraDomainConfig {
        seed_snp_probe();
        InfraDomainConfig {
            vm_id: VmId::new(INFRA_VM_ID).unwrap(),
            domain_uuid: DomainUuid::parse("11111111-2222-4333-8444-555555555555").unwrap(),
            ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf/ovmf.fd"),
            kernel_path: PathBuf::from("/var/lib/hippius-miner/staging/attestor-vmlinuz"),
            initrd_path: PathBuf::from("/var/lib/hippius-miner/staging/attestor-initrd"),
            cmdline: "quiet panic=0 console=ttyS0".to_string(),
            cid: 4,
        }
    }

    #[test]
    fn infra_domain_name_uses_the_infra_prefix() {
        assert_eq!(
            fixture_config().domain_name().unwrap().as_str(),
            "hippius-infra-host-attestor"
        );
    }

    #[test]
    fn infra_xml_is_diskless_but_has_a_vsock_with_the_assigned_cid() {
        let xml = fixture_config().to_libvirt_xml();
        // The Infra profile stays DISKLESS (the UKI initramfs is the root)…
        assert!(
            !xml.contains("<disk"),
            "infra domain must be diskless: {xml}"
        );
        // …but PR-10b (S1) attaches a `<vsock>` pinned to the assigned CID
        // so the diskless attestor guest can dial the host (challenge DOWN +
        // enroll/beacon UP). `fixture_config` pins CID 4.
        assert!(
            xml.contains("<vsock model='virtio'>"),
            "infra domain must carry a vsock device: {xml}"
        );
        assert!(
            xml.contains("<cid auto='no' address='4'/>"),
            "infra vsock must pin the assigned CID: {xml}"
        );
        // vsock-only: no NIC on the guest bridge.
        assert!(
            !xml.contains("<interface"),
            "infra domain must have no NIC: {xml}"
        );
        // But it IS a confidential SNP guest.
        assert!(xml.contains("<launchSecurity type='sev-snp' kernelHashes='yes'>"));
        assert!(xml.contains("<policy>0x30000</policy>"));
    }

    #[test]
    fn infra_xml_vsock_cid_tracks_the_config_field() {
        // A different CID renders into the device verbatim — the allocator-
        // assigned value the lifecycle threads through at launch.
        let mut cfg = fixture_config();
        cfg.cid = 9;
        let xml = cfg.to_libvirt_xml();
        assert!(xml.contains("<cid auto='no' address='9'/>"), "{xml}");
        // A vsock CID is NOT a launch-digest input, so the guest kernel
        // cmdline (which IS measured) is unchanged by attaching it.
        assert!(xml.contains("<cmdline>quiet panic=0 console=ttyS0</cmdline>"));
    }

    #[test]
    fn infra_xml_pins_one_vcpu_and_512_mib() {
        let xml = fixture_config().to_libvirt_xml();
        assert!(
            xml.contains("<vcpu placement='static'>1</vcpu>"),
            "1 vCPU: {xml}"
        );
        assert!(
            xml.contains("<memory unit='MiB'>512</memory>"),
            "512 MiB: {xml}"
        );
        assert!(xml.contains("<currentMemory unit='MiB'>512</currentMemory>"));
    }

    #[test]
    fn infra_xml_carries_the_measured_boot_tuple() {
        let xml = fixture_config().to_libvirt_xml();
        assert!(xml.contains("<kernel>/var/lib/hippius-miner/staging/attestor-vmlinuz</kernel>"));
        assert!(xml.contains("<initrd>/var/lib/hippius-miner/staging/attestor-initrd</initrd>"));
        assert!(xml.contains("<cmdline>quiet panic=0 console=ttyS0</cmdline>"));
        assert!(xml.contains("<loader type='rom'>/var/lib/hippius-miner/ovmf/ovmf.fd</loader>"));
    }

    #[test]
    fn infra_xml_uses_memfd_backing_for_snp() {
        let xml = fixture_config().to_libvirt_xml();
        assert!(xml.contains("<source type='memfd'/>"));
        assert!(xml.contains("<access mode='shared'/>"));
    }

    #[test]
    fn from_order_pins_the_singleton_shape() {
        seed_snp_probe();
        let cfg = InfraDomainConfig::from_order(&fixture_order()).unwrap();
        assert_eq!(cfg.vm_id.as_str(), INFRA_VM_ID);
        let digest_cfg = cfg.to_digest_qemu_config().unwrap();
        assert_eq!(digest_cfg.cpu_count, 1);
        assert_eq!(digest_cfg.memory_mb, 512);
    }

    #[test]
    fn validate_rejects_a_relative_kernel_path() {
        seed_snp_probe();
        let mut cfg = fixture_config();
        cfg.kernel_path = PathBuf::from("relative/vmlinuz");
        assert!(matches!(
            cfg.validate(),
            Err(MinerAgentError::LaunchInput("kernel-path"))
        ));
    }

    #[test]
    fn validate_rejects_an_empty_cmdline() {
        seed_snp_probe();
        let mut cfg = fixture_config();
        cfg.cmdline = String::new();
        assert!(matches!(
            cfg.validate(),
            Err(MinerAgentError::LaunchInput("cmdline-empty"))
        ));
    }
}
