//! [`QemuConfig`] — the SEV-SNP launch configuration and the libvirt
//! domain XML built from it.
//!
//! ## Launch model (PR-MA-3, Option A)
//!
//! The guest boots via QEMU **direct kernel boot**: a pinned OVMF
//! firmware plus a *separate* kernel, initrd and cmdline. That is the
//! exact tuple `sev::measurement::snp::snp_calc_launch_digest` (and
//! therefore the §F PR-F3 allowlist measurement) is computed over —
//! see [`super::launch_digest`]. The monolithic UKI PE is the
//! *distribution* artifact; the miner is handed its already-extracted
//! components (extraction / separate fetch is MA-5).
//!
//! ## Safety
//!
//! Every value interpolated into the XML is [`xml_escape`]d, so no
//! path or cmdline can break out of its element or attribute. The
//! `<launchSecurity type='sev-snp'>` block is **always** emitted —
//! this struct cannot describe a non-confidential domain. The LUKS
//! data-disk path is validated absolute, traversal-free and under
//! `/var/lib/hippius-miner/` (symlink-escape checked via
//! `canonicalize`).

use std::path::{Component, Path, PathBuf};

use super::cvm_handle::{DomainUuid, VmId};
use super::libvirt_driver::DomainId;
use crate::error::{MinerAgentError, Result};

/// Filesystem root the miner-agent owns. The per-VM LUKS data disk
/// must resolve to a path under it — never an arbitrary host path.
///
/// `pub(crate)` so [`super::state_disk`] can compute its per-VM
/// state-disk paths under the same root the validators enforce.
pub(crate) const MINER_ROOT: &str = "/var/lib/hippius-miner";

/// AMD SEV-SNP guest policy (libvirt `<policy>`), as the SNP `GUEST_
/// POLICY` bitfield: bit 16 `SMT` = 1 (SMT hosts allowed), bit 17 is
/// reserved and the SNP ABI **requires** it set, bit 18 `MIGRATE_MA`
/// = 0 (no migration agent) and bit 19 `DEBUG` = 0 (no debugging).
/// `0x10000` — bit 17 clear — is rejected by SNP firmware; `0x30000`
/// is the minimum valid no-debug, no-migrate policy.
pub(super) const SEV_SNP_POLICY: &str = "0x30000";

// Issue #116 (closed by this commit): the SEV C-bit position +
// physical-address reduction used to be hardcoded here to `51 / 1`
// — correct for Milan / Genoa / Bergamo / Siena / Turin EPYCs, but a
// silent default on a measured primitive (cf. `feedback_no_silent_
// defaults_measured_primitives.md`). We now probe both from
// `CPUID 0x8000001f` at launch admission via
// `crate::snp_config::SnpCpuConfig::probe` and substitute the live
// values below; see `snp_config` for the wire layout, the
// fail-closed posture, and the lockstep with the AMD SP's own
// measurement.

/// The SEV-SNP launch configuration for one tenant CVM.
///
/// Intentionally derives neither `Debug` nor `Clone`: the kernel
/// `cmdline` can carry sensitive launch parameters if misconfigured
/// upstream, so the type must not be formattable into a log line
/// (the §20 no-secret-logging discipline, as `MinerIdentity` does).
pub struct QemuConfig {
    /// Tenant id — the domain name is `hippius-tenant-<vm_id>`.
    pub vm_id: VmId,
    /// libvirt domain UUID embedded in the XML.
    pub domain_uuid: DomainUuid,
    /// Pinned, SEV-SNP-capable OVMF firmware.
    pub ovmf_path: PathBuf,
    /// Guest kernel (a measured launch input).
    pub kernel_path: PathBuf,
    /// Guest initrd (a measured launch input).
    pub initrd_path: PathBuf,
    /// Guest kernel command line (a measured launch input).
    pub cmdline: String,
    /// Per-VM LUKS data disk image — must be under `/var/lib/hippius-miner/`.
    pub luks_disk_path: PathBuf,
    /// Size of the LUKS data disk in GiB (used to create it if absent;
    /// not rendered into the XML — the image file carries its size).
    pub luks_disk_size_gb: u32,
    /// Read-only dm-verity rootfs **data** image (the squashfs the
    /// §F tenant-uki build produces as `rootfs.img`). Attached to the
    /// guest at `/dev/vdb` (read-only) so the in-guest agent-initramfs
    /// `stages::verity` opener can pair it with the hash backing
    /// device. NOT a measured launch input — verity covers integrity
    /// via the `dm-verity.root=` cmdline token (which IS measured).
    pub rootfs_data_path: PathBuf,
    /// Read-only dm-verity rootfs **hash tree** (`rootfs.verity` from
    /// the §F tenant-uki build). Attached to the guest at `/dev/vdc`
    /// (read-only). The dm-verity superblock at the start of this
    /// file carries a pointer to the data device — set at format
    /// time by `veritysetup format`.
    pub rootfs_hash_path: PathBuf,
    /// Per-VM 1 MiB ext4 state disk (Phase 2B of audit follow-up
    /// Review #2). Attached to the guest at `/dev/vdd`; the keyscript
    /// mounts it before invoking `hippius-guest-release` so the
    /// boot counter persists across reboots.
    ///
    /// Provisioned just-in-time by
    /// [`super::state_disk::ensure_state_disk`] before the libvirt
    /// `define` — the path lives under `MINER_ROOT/state/` and is
    /// guaranteed to exist by the time `to_libvirt_xml` runs.
    pub state_disk_path: PathBuf,
    /// #365 — per-VM tenant **data disk**, attached at `/dev/vde` when
    /// present. A blank sparse raw image the miner creates at
    /// [`Self::data_disk_size_gb`]; the guest formats it fresh (LUKS2 +
    /// dm-integrity, guest-held key) at first boot. `None` for older
    /// vali deploys / flavors that requested no data disk — then no vde
    /// `<disk>` is rendered. NOT a measured launch input: it is blank
    /// and guest-keyed, so it does not enter the SEV-SNP launch digest.
    ///
    /// Provisioned just-in-time by [`super::data_disk::ensure_data_disk`]
    /// before the libvirt `define`, under `MINER_ROOT/data/`.
    pub data_disk_path: Option<PathBuf>,
    /// Size of the tenant data disk in GiB (the flavor's `disk_gb`).
    /// Used to create the image if absent; not rendered into the XML —
    /// the image file carries its size, and the guest re-checks it
    /// against the measured `hippius.disk_gb=` cmdline token. Zero ⇒ no
    /// data disk (paired with `data_disk_path: None`).
    pub data_disk_size_gb: u32,
    /// vCPU count.
    pub cpu_count: u8,
    /// Guest RAM in MiB.
    pub memory_mb: u32,
    /// GOLDEN-mode launch (golden-bake PR4). `false` is the LEGACY
    /// per-VM LUKS `/dev/vda` path — byte-identical to the pre-golden
    /// behaviour. `true` means the OS is the SHARED read-only dm-verity
    /// base (`rootfs_data_path`/`rootfs_hash_path` on vdb/vdc) and
    /// [`Self::luks_disk_path`] is a BLANK per-VM guest-keyed overlay
    /// UPPER (vda) the miner derives under its OWN storage root
    /// ([`super::golden::overlay_disk_path`]) and the guest formats
    /// fresh at first boot. The flag is derived from the SNP-MEASURED
    /// cmdline (`super::golden::is_golden_cmdline`), so it is
    /// tamper-evident. It changes ONLY how [`Self::validate`] checks the
    /// vda path (internally-derived vs order-supplied), never the XML —
    /// the blank overlay renders `raw` via the same `probe_image_format`.
    pub golden: bool,
    /// AF_VSOCK context id for the guest ↔ miner-agent relay (MA-4).
    /// Assigned by [`crate::vsock::peer::CidAllocator`] at launch and
    /// pinned into the libvirt `<vsock>` device; the guest connects
    /// back on it and the miner-agent maps it to this `vm_id`.
    pub cid: u32,
}

impl QemuConfig {
    /// The libvirt domain name for this CVM.
    pub fn domain_name(&self) -> Result<DomainId> {
        DomainId::new(&self.domain_name_string())
    }

    /// The domain name as a plain string (`hippius-tenant-<vm_id>`).
    fn domain_name_string(&self) -> String {
        format!("hippius-tenant-{}", self.vm_id)
    }

    /// Reject a config that cannot be launched safely. All
    /// sub-classifiers are compile-time constants — no path or value
    /// is ever echoed.
    pub fn validate(&self) -> Result<()> {
        // Probe the host SEV-SNP launch parameters at admission so a
        // failure surfaces here (`MinerAgentError::SnpProbe`) instead
        // of mid-flight inside `to_libvirt_xml`. The probe caches in
        // a process-global `OnceLock`; subsequent validates are
        // O(1). Issue #116.
        crate::snp_config::global()?;
        if self.cpu_count == 0 {
            return Err(MinerAgentError::LaunchInput("cpu-zero"));
        }
        if self.memory_mb == 0 {
            return Err(MinerAgentError::LaunchInput("memory-zero"));
        }
        if self.luks_disk_size_gb == 0 {
            return Err(MinerAgentError::LaunchInput("disk-size-zero"));
        }
        if self.cmdline.is_empty() {
            return Err(MinerAgentError::LaunchInput("cmdline-empty"));
        }
        if self.cmdline.contains('\0') {
            return Err(MinerAgentError::LaunchInput("cmdline-nul"));
        }
        // The AF_VSOCK CID must be a guest CID — 0/1/2 are ABI-reserved
        // (hypervisor / local / host). A reserved CID in the `<vsock>`
        // device would make libvirt refuse the domain.
        if self.cid < crate::vsock::peer::MIN_GUEST_CID {
            return Err(MinerAgentError::LaunchInput("cid-reserved"));
        }
        validate_input_path(&self.ovmf_path, "ovmf-path")?;
        validate_input_path(&self.kernel_path, "kernel-path")?;
        validate_input_path(&self.initrd_path, "initrd-path")?;
        validate_input_path(&self.rootfs_data_path, "rootfs-data-path")?;
        validate_input_path(&self.rootfs_hash_path, "rootfs-hash-path")?;
        if self.golden {
            // GOLDEN vda = the per-VM guest-keyed overlay UPPER, a blank
            // sparse disk the miner DERIVES under its own process-owned
            // storage root (`golden::overlay_disk_path`), NOT an
            // order-supplied path — so the MINER_ROOT prefix check that
            // guards an untrusted-input LUKS path is moot here (the same
            // rationale the internally-derived state/data disks use).
            // Validate it as a derived path: absolute, traversal-free,
            // UTF-8, no NUL. The blank overlay carries no shared master
            // key (invariant b) — the guest luksFormats it in-SNP.
            validate_input_path(&self.luks_disk_path, "golden-overlay-path")?;
        } else {
            validate_luks_path(&self.luks_disk_path)?;
        }
        validate_state_disk_path(&self.state_disk_path)?;
        // #365 — the data disk is optional. When present, path + size
        // must agree (both set) and the path must be a sane absolute,
        // traversal-free path (it is internally derived under a
        // process-owned root, like the state disk, so a prefix check is
        // moot — but a buggy override surfaces loudly here).
        match (&self.data_disk_path, self.data_disk_size_gb) {
            (Some(path), size) if size > 0 => validate_input_path(path, "data-disk-path")?,
            (None, 0) => {}
            // path-without-size or size-without-path is a wiring bug.
            _ => return Err(MinerAgentError::LaunchInput("data-disk-mismatch")),
        }
        Ok(())
    }

    /// Render the libvirt domain XML for `virsh define`.
    ///
    /// Every interpolated value is XML-escaped; the
    /// `<launchSecurity type='sev-snp' kernelHashes='yes'>` block is
    /// unconditional. `kernelHashes='yes'` is **required** for a
    /// direct-kernel-boot SNP guest — it folds the kernel / initrd /
    /// cmdline hashes into the firmware launch measurement, so the
    /// guest's attested digest equals the pre-flight digest
    /// [`super::launch_digest`] computes (the §F allowlist value).
    /// Without it the measurement would cover OVMF alone.
    ///
    /// The `<vsock>` device (MA-4) pins the assigned [`Self::cid`] with
    /// `auto='no'` — the guest connects back to the miner-agent on it
    /// for the control-plane relay. The CID is a `u32` literal, not a
    /// path or operator string, so it needs no escaping. The vsock
    /// device is a runtime device, NOT a measured launch input — it
    /// does not enter the SEV-SNP launch digest.
    pub fn to_libvirt_xml(&self) -> String {
        // Read the host SEV-SNP launch parameters from the
        // process-global cache. `validate()` is REQUIRED to have
        // run first (it primes the cache + propagates a probe
        // failure as `MinerAgentError::SnpProbe`); the lifecycle's
        // launch path always calls `validate()` before
        // `to_libvirt_xml`.
        //
        // A missing cache here is a programmer bug (a caller that
        // skipped `validate`). We fall back to the structurally
        // invalid `cbitpos=0` value so libvirt's SEV-SNP launch
        // refuses the domain with a loud error, instead of silently
        // emitting a different default. This keeps the
        // `feedback_no_silent_defaults_measured_primitives` rule:
        // the value never silently masquerades as a CPU-correct one.
        // Reachable only from a test or a programmer error; the
        // happy path always goes through `validate`.
        const FAIL_CLOSED_SNP: crate::snp_config::SnpCpuConfig = crate::snp_config::SnpCpuConfig {
            cbitpos: 0,
            reduced_phys_bits: 0,
        };
        let snp = crate::snp_config::global().unwrap_or(&FAIL_CLOSED_SNP);
        let name = xml_escape(&self.domain_name_string());
        let uuid = xml_escape(self.domain_uuid.as_str());
        let ovmf = xml_escape(&self.ovmf_path.to_string_lossy());
        let kernel = xml_escape(&self.kernel_path.to_string_lossy());
        let initrd = xml_escape(&self.initrd_path.to_string_lossy());
        let cmdline = xml_escape(&self.cmdline);
        let disk = xml_escape(&self.luks_disk_path.to_string_lossy());
        let rootfs_data = xml_escape(&self.rootfs_data_path.to_string_lossy());
        let rootfs_hash = xml_escape(&self.rootfs_hash_path.to_string_lossy());
        let state_disk = xml_escape(&self.state_disk_path.to_string_lossy());
        // Detect the on-disk image format for the per-VM data disk
        // (the only one of the three that may legitimately be qcow2 —
        // the §F UKI rootfs.img/.verity pair is always raw). Without
        // this the BYO base-OS bake's qcow2 was being treated as raw,
        // so the guest's `/dev/vda` exposed qcow2 magic bytes at
        // offset 0 and `cryptsetup luksOpen` could never find the
        // LUKS header. The detection probes the first 4 bytes of the
        // file directly rather than trusting a filename suffix.
        let disk_format = probe_image_format(&self.luks_disk_path);
        // #365 — render the tenant data disk as `vde` only when present.
        // It is always a raw image (the guest's fresh `luksFormat`
        // writes a LUKS2 header at offset 0, never qcow2 magic), so the
        // driver type is fixed `raw` — no `probe_image_format` needed.
        //
        // `cache='writeback'` (vs `none` on every other disk): the dominant
        // first-boot cost is the guest's full dm-integrity tag wipe of this
        // disk (~8 min for 64 GiB under SNP). With `cache='none'` (O_DIRECT)
        // every virtio write waits synchronously for the md-RAID flush — a
        // vmexit per I/O, expensive under SNP. `writeback` lets the host
        // page-cache absorb the writes and flush async, roughly halving the
        // format time (benchmarked on a live miner). SECURITY-NEUTRAL: the guest's
        // dm-crypt+integrity stack encrypts every byte BEFORE virtio, so the
        // host page cache only ever holds ciphertext — never plaintext, never
        // the key. `no-flush` stays implicit-false, so the guest's fsync / FS
        // journal still controls durability (a host power-loss only risks
        // un-fsync'd in-flight writes — the standard writeback trade-off).
        // Cache mode is a host I/O option, NOT folded into the SNP launch
        // measurement (only OVMF+kernel+initrd+cmdline are) → no impact on
        // attestation or the §22 allowlist.
        let data_disk_xml = match &self.data_disk_path {
            Some(path) => format!(
                "<disk type='file' device='disk'>\n      \
                 <driver name='qemu' type='raw' cache='writeback'/>\n      \
                 <source file='{src}'/>\n      \
                 <target dev='vde' bus='virtio'/>\n    \
                 </disk>\n    ",
                src = xml_escape(&path.to_string_lossy()),
            ),
            None => String::new(),
        };
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
             <disk type='file' device='disk'>\n      \
             <driver name='qemu' type='{disk_format}' cache='none'/>\n      \
             <source file='{disk}'/>\n      \
             <target dev='vda' bus='virtio'/>\n    \
             </disk>\n    \
             <disk type='file' device='disk'>\n      \
             <driver name='qemu' type='raw' cache='none'/>\n      \
             <source file='{rootfs_data}'/>\n      \
             <target dev='vdb' bus='virtio'/>\n      \
             <readonly/>\n    \
             </disk>\n    \
             <disk type='file' device='disk'>\n      \
             <driver name='qemu' type='raw' cache='none'/>\n      \
             <source file='{rootfs_hash}'/>\n      \
             <target dev='vdc' bus='virtio'/>\n      \
             <readonly/>\n    \
             </disk>\n    \
             <disk type='file' device='disk'>\n      \
             <driver name='qemu' type='raw' cache='none'/>\n      \
             <source file='{state_disk}'/>\n      \
             <target dev='vdd' bus='virtio'/>\n    \
             </disk>\n    \
             {data_disk_xml}\
             <interface type='network'>\n      \
             <source network='default'/>\n      \
             <model type='virtio'/>\n    \
             </interface>\n    \
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
            memory = self.memory_mb,
            cpu = self.cpu_count,
            ovmf = ovmf,
            kernel = kernel,
            initrd = initrd,
            cmdline = cmdline,
            cbitpos = snp.cbitpos,
            reduced = snp.reduced_phys_bits,
            policy = SEV_SNP_POLICY,
            disk = disk,
            disk_format = disk_format,
            rootfs_data = rootfs_data,
            rootfs_hash = rootfs_hash,
            state_disk = state_disk,
            data_disk_xml = data_disk_xml,
            cid = self.cid,
        )
    }
}

/// Read + validate a kernel cmdline file.
///
/// Matches `hippius-uki-measure`'s `cmdline_append` byte-for-byte (one
/// trailing `\n` stripped) so the digest this miner pre-computes is
/// identical to the §F allowlist measurement. Fails closed on a
/// non-UTF-8, empty, or NUL-bearing cmdline.
pub fn load_cmdline(path: &Path) -> Result<String> {
    let raw = std::fs::read(path)?;
    let text = String::from_utf8(raw).map_err(|_| MinerAgentError::LaunchInput("cmdline-utf8"))?;
    let trimmed = text.strip_suffix('\n').unwrap_or(&text);
    if trimmed.is_empty() {
        return Err(MinerAgentError::LaunchInput("cmdline-empty"));
    }
    if trimmed.contains('\0') {
        return Err(MinerAgentError::LaunchInput("cmdline-nul"));
    }
    Ok(trimmed.to_string())
}

/// Escape the five XML metacharacters so a value cannot break out of
/// its element text or single-quoted attribute.
pub(super) fn xml_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Validate a read-input path: absolute, traversal-free, UTF-8, no NUL.
pub(super) fn validate_input_path(path: &Path, field: &'static str) -> Result<()> {
    if !path.is_absolute() {
        return Err(MinerAgentError::LaunchInput(field));
    }
    for component in path.components() {
        match component {
            Component::ParentDir | Component::CurDir => {
                return Err(MinerAgentError::LaunchInput(field));
            }
            Component::Normal(part) => match part.to_str() {
                Some(s) if !s.contains('\0') => {}
                _ => return Err(MinerAgentError::LaunchInput(field)),
            },
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    Ok(())
}

/// Validate the LUKS data-disk path: a read-input path that
/// additionally resolves under `/var/lib/hippius-miner/`. The
/// `starts_with` test is component-wise (so `…-miner-evil` does not
/// match); when the path — or its parent directory — exists it is
/// `canonicalize`d and the prefix re-asserted, defeating a symlink
/// planted inside the miner root.
fn validate_luks_path(path: &Path) -> Result<()> {
    validate_input_path(path, "luks-path")?;
    if !path.starts_with(MINER_ROOT) {
        return Err(MinerAgentError::LaunchInput("luks-path-outside-root"));
    }
    let resolve = if path.exists() {
        Some(path.to_path_buf())
    } else {
        match path.parent() {
            Some(parent) if parent.exists() => Some(parent.to_path_buf()),
            _ => None,
        }
    };
    if let Some(target) = resolve {
        let canonical = target
            .canonicalize()
            .map_err(|_| MinerAgentError::LaunchInput("luks-path-canonicalize"))?;
        if !canonical.starts_with(MINER_ROOT) {
            return Err(MinerAgentError::LaunchInput("luks-path-outside-root"));
        }
    }
    Ok(())
}

/// Validate the per-VM state-disk path (Phase 2B). Lighter than
/// `validate_luks_path`: the state disk path is derived internally
/// by [`super::CvmLifecycle`] from a process-owned root (default
/// `MINER_ROOT`, tests override) — NOT from an order field — so an
/// untrusted-input prefix check is moot. We still require absolute /
/// traversal-free / UTF-8 / no-NUL so a buggy override in tests
/// surfaces as `LaunchInput("state-disk-path")` rather than a
/// confusing libvirt XML rendering error.
fn validate_state_disk_path(path: &Path) -> Result<()> {
    validate_input_path(path, "state-disk-path")
}

/// Probe the first 4 bytes of `path` and return the libvirt `<driver
/// type='…'>` attribute value. Recognises `QFI\xfb` as qcow2; falls
/// back to `raw` on every other case (including read errors, missing
/// files, and unknown magics). The return is a static string so it
/// can be interpolated into the XML template without allocation.
///
/// Why probe the file rather than trust a filename suffix: the
/// miner-agent stages images under operator-controlled paths, so
/// extension-based dispatch could be spoofed; the magic is a
/// stronger signal that survives renames.
fn probe_image_format(path: &Path) -> &'static str {
    use std::io::Read;
    let mut buf = [0u8; 4];
    let Ok(mut f) = std::fs::File::open(path) else {
        return "raw";
    };
    match f.read_exact(&mut buf) {
        Ok(()) if buf == *b"QFI\xfb" => "qcow2",
        _ => "raw",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snp_config::{install_for_tests, SnpCpuConfig};

    /// Seed the process-global SNP probe cache with the Genoa/Turin
    /// values the workspace fleet uses (`cbitpos=51, reduced=1`).
    /// Idempotent — `OnceLock::set` short-circuits after the first
    /// successful set, so calling this from multiple tests in the
    /// same process is safe. All tests in the workspace agree on
    /// the values: the cache is set-once, so the FIRST test to call
    /// this wins, and we deliberately pin everywhere on the same
    /// `51 / 1` shape.
    fn seed_snp_probe() {
        install_for_tests(SnpCpuConfig {
            cbitpos: 51,
            reduced_phys_bits: 1,
        });
    }

    fn fixture() -> QemuConfig {
        seed_snp_probe();
        QemuConfig {
            vm_id: VmId::new("tenant-cvm-01").unwrap(),
            domain_uuid: DomainUuid::parse("11111111-2222-4333-8444-555555555555").unwrap(),
            ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf/ovmf.fd"),
            kernel_path: PathBuf::from("/var/lib/hippius-miner/staging/vmlinuz"),
            initrd_path: PathBuf::from("/var/lib/hippius-miner/staging/initrd.cpio"),
            cmdline: "quiet panic=0 console=ttyS0".to_string(),
            luks_disk_path: PathBuf::from("/var/lib/hippius-miner/cvm/tenant-cvm-01.img"),
            luks_disk_size_gb: 10,
            rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/staging/rootfs.img"),
            rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/staging/rootfs.verity"),
            state_disk_path: PathBuf::from("/var/lib/hippius-miner/state/tenant-cvm-01.raw"),
            data_disk_path: Some(PathBuf::from(
                "/var/lib/hippius-miner/data/tenant-cvm-01.img",
            )),
            data_disk_size_gb: 64,
            cpu_count: 2,
            memory_mb: 2048,
            golden: false,
            cid: 7,
        }
    }

    /// A GOLDEN-mode fixture (golden-bake PR4): vda = a per-VM overlay
    /// upper the miner derived under its storage root; no separate vde;
    /// the OS is the shared dm-verity base on vdb/vdc.
    fn golden_fixture() -> QemuConfig {
        let mut cfg = fixture();
        cfg.golden = true;
        cfg.luks_disk_path = PathBuf::from("/var/lib/hippius-miner/overlay/tenant-cvm-01.img");
        cfg.luks_disk_size_gb = 64;
        cfg.data_disk_path = None;
        cfg.data_disk_size_gb = 0;
        cfg
    }

    #[test]
    fn xml_always_pins_sev_snp_launch_security() {
        let xml = fixture().to_libvirt_xml();
        assert!(xml.contains("<launchSecurity type='sev-snp' kernelHashes='yes'>"));
        assert!(xml.contains("<policy>0x30000</policy>"));
        // The probed cbitpos (`51` on every current EPYC SKU; the
        // test seeds this value via `install_for_tests`). When a
        // future SKU drives a different probed value, this assertion
        // moves in lockstep with the seed in `seed_snp_probe`.
        assert!(xml.contains("<cbitpos>51</cbitpos>"));
        assert!(xml.contains("<reducedPhysBits>1</reducedPhysBits>"));
    }

    #[test]
    fn xml_pins_memfd_memory_backing_for_snp() {
        // Without `<memoryBacking type='memfd' shared='yes'>`, current
        // Linux + QEMU (≥ 6.x host kernel, recent KVM) silently parks
        // SEV-SNP guest vCPUs at the entry point — qemu starts, libvirt
        // shows `running`, but the guest never executes a single
        // instruction, so there is zero serial / earlyprintk output and
        // no vsock listener. The miner-agent's `reboot-watcher` then
        // keeps retrying ticket push with `ticket-delivery/connect-
        // timeout` until the operator gives up.
        //
        // memfd backing + shared access is what lets KVM map the GHCB
        // (Guest-Hypervisor Communication Block) pages between the host
        // and the SNP guest. Without it, the very first GHCB hypercall
        // (which Linux issues during early boot's CPU feature probe) is
        // unhandled and the vCPU never advances.
        let xml = fixture().to_libvirt_xml();
        assert!(
            xml.contains("<memoryBacking>"),
            "SEV-SNP guests require memfd memory backing: xml={xml}"
        );
        assert!(xml.contains("<source type='memfd'/>"));
        assert!(xml.contains("<access mode='shared'/>"));
    }

    #[test]
    fn xml_uses_probed_snp_cbitpos() {
        // The XML's `<cbitpos>` MUST come from `snp_config::global()`,
        // not a hardcoded literal. We can't substitute a different
        // value at test time (the cache is set-once and seeded above
        // by `fixture()`), so we instead assert the value FLOWS via
        // the probe path: render the XML and parse the cbitpos back
        // out, then compare to `snp_config::global()`.
        let xml = fixture().to_libvirt_xml();
        let expected = crate::snp_config::global().expect("seeded by fixture");
        assert!(
            xml.contains(&format!("<cbitpos>{}</cbitpos>", expected.cbitpos)),
            "XML cbitpos != probed cbitpos: xml={xml}"
        );
        assert!(
            xml.contains(&format!(
                "<reducedPhysBits>{}</reducedPhysBits>",
                expected.reduced_phys_bits
            )),
            "XML reducedPhysBits != probed reduced_phys_bits"
        );
    }

    #[test]
    fn xml_renders_the_assigned_vsock_cid() {
        // The `<vsock>` device pins the CID the allocator assigned —
        // `auto='no'` so libvirt does not pick its own.
        let xml = fixture().to_libvirt_xml();
        assert!(xml.contains("<vsock model='virtio'>"));
        assert!(xml.contains("<cid auto='no' address='7'/>"));
    }

    #[test]
    fn validate_rejects_a_reserved_cid() {
        // CIDs 0/1/2 are ABI-reserved — never a guest CID.
        for reserved in [0u32, 1, 2] {
            let mut cfg = fixture();
            cfg.cid = reserved;
            assert!(matches!(
                cfg.validate(),
                Err(MinerAgentError::LaunchInput("cid-reserved"))
            ));
        }
    }

    #[test]
    fn xml_escapes_interpolated_values() {
        let mut cfg = fixture();
        cfg.cmdline = "a<b&c>d\"e'f".to_string();
        let xml = cfg.to_libvirt_xml();
        assert!(xml.contains("<cmdline>a&lt;b&amp;c&gt;d&quot;e&apos;f</cmdline>"));
        // The raw metacharacters never reach the rendered document.
        assert!(!xml.contains("a<b&c>d"));
    }

    #[test]
    fn validate_accepts_the_fixture() {
        assert!(fixture().validate().is_ok());
    }

    #[test]
    fn validate_rejects_luks_disk_outside_miner_root() {
        let mut cfg = fixture();
        cfg.luks_disk_path = PathBuf::from("/etc/shadow");
        assert!(matches!(
            cfg.validate(),
            Err(MinerAgentError::LaunchInput("luks-path-outside-root"))
        ));
    }

    #[test]
    fn validate_rejects_path_traversal() {
        let mut cfg = fixture();
        cfg.luks_disk_path = PathBuf::from("/var/lib/hippius-miner/../../etc/shadow");
        assert!(matches!(
            cfg.validate(),
            Err(MinerAgentError::LaunchInput("luks-path"))
        ));
    }

    #[test]
    fn validate_rejects_lookalike_root_prefix() {
        // `/var/lib/hippius-miner-evil` shares a string prefix but not
        // a path-component prefix — component-wise `starts_with` must
        // reject it.
        let mut cfg = fixture();
        cfg.luks_disk_path = PathBuf::from("/var/lib/hippius-miner-evil/disk.img");
        assert!(matches!(
            cfg.validate(),
            Err(MinerAgentError::LaunchInput("luks-path-outside-root"))
        ));
    }

    #[test]
    fn validate_rejects_relative_and_zero_fields() {
        let mut cfg = fixture();
        cfg.ovmf_path = PathBuf::from("relative/ovmf.fd");
        assert!(cfg.validate().is_err());

        let mut cfg = fixture();
        cfg.cpu_count = 0;
        assert!(matches!(
            cfg.validate(),
            Err(MinerAgentError::LaunchInput("cpu-zero"))
        ));

        let mut cfg = fixture();
        cfg.memory_mb = 0;
        assert!(matches!(
            cfg.validate(),
            Err(MinerAgentError::LaunchInput("memory-zero"))
        ));
    }

    #[test]
    fn domain_name_is_prefixed() {
        assert_eq!(
            fixture().domain_name().unwrap().as_str(),
            "hippius-tenant-tenant-cvm-01"
        );
    }

    #[test]
    fn xml_attaches_state_disk_as_vdd() {
        // Phase 2B: the per-VM 1 MiB ext4 state disk MUST be
        // exposed to the guest at `/dev/vdd` (the keyscript's
        // hardcoded mount target). The XML must carry the raw
        // driver type so libvirt does NOT probe a non-existent
        // qcow2 magic at offset 0.
        let xml = fixture().to_libvirt_xml();
        assert!(
            xml.contains("<source file='/var/lib/hippius-miner/state/tenant-cvm-01.raw'/>"),
            "state-disk source path missing from XML: {xml}"
        );
        assert!(
            xml.contains("<target dev='vdd' bus='virtio'/>"),
            "state disk not attached as vdd: {xml}"
        );
    }

    #[test]
    fn xml_attaches_data_disk_as_vde() {
        // #365: the tenant data disk MUST be exposed at `/dev/vde`
        // (the guest first-boot unit's target), raw driver type so
        // libvirt does not probe a non-existent qcow2 magic.
        let xml = fixture().to_libvirt_xml();
        assert!(
            xml.contains("<source file='/var/lib/hippius-miner/data/tenant-cvm-01.img'/>"),
            "data-disk source path missing from XML: {xml}"
        );
        assert!(
            xml.contains("<target dev='vde' bus='virtio'/>"),
            "data disk not attached as vde: {xml}"
        );
        // The data disk uses cache='writeback' (every other disk is
        // 'none') to cut the first-boot dm-integrity wipe time — see the
        // data_disk_xml comment. Security-neutral (host caches ciphertext).
        // Pin it so it can't silently regress.
        assert!(
            xml.contains(
                "<driver name='qemu' type='raw' cache='writeback'/>\n      \
                 <source file='/var/lib/hippius-miner/data/tenant-cvm-01.img'/>"
            ),
            "data disk must use cache='writeback': {xml}"
        );
        // vde must come AFTER vdd in the device list.
        let vdd = xml.find("vdd").expect("vdd present");
        let vde = xml.find("vde").expect("vde present");
        assert!(vdd < vde, "vde must follow vdd");
    }

    #[test]
    fn xml_omits_vde_when_no_data_disk() {
        // Older vali deploys (no data_disk_size_gb) → no vde rendered.
        let mut cfg = fixture();
        cfg.data_disk_path = None;
        cfg.data_disk_size_gb = 0;
        assert!(cfg.validate().is_ok());
        let xml = cfg.to_libvirt_xml();
        assert!(!xml.contains("vde"), "vde must be absent: {xml}");
        // The other four disks are unaffected.
        assert!(xml.contains("<target dev='vdd' bus='virtio'/>"));
    }

    #[test]
    fn validate_rejects_data_disk_path_size_mismatch() {
        // path without size, or size without path, is a wiring bug.
        let mut cfg = fixture();
        cfg.data_disk_size_gb = 0; // path Some, size 0
        assert!(matches!(
            cfg.validate(),
            Err(MinerAgentError::LaunchInput("data-disk-mismatch"))
        ));

        let mut cfg = fixture();
        cfg.data_disk_path = None; // size 64, path None
        assert!(matches!(
            cfg.validate(),
            Err(MinerAgentError::LaunchInput("data-disk-mismatch"))
        ));
    }

    #[test]
    fn golden_config_validates_derived_overlay_vda() {
        // GOLDEN vda is the miner-derived overlay upper under the storage
        // root; validate() must accept it via the derived-path check (no
        // MINER_ROOT prefix requirement — but still absolute/traversal-free).
        let cfg = golden_fixture();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn golden_config_rejects_traversal_overlay_vda() {
        let mut cfg = golden_fixture();
        cfg.luks_disk_path = PathBuf::from("/var/lib/hippius-miner/overlay/../../etc/shadow");
        assert!(matches!(
            cfg.validate(),
            Err(MinerAgentError::LaunchInput("golden-overlay-path"))
        ));
    }

    #[test]
    fn golden_renders_blank_vda_raw_and_omits_vde() {
        // The blank overlay upper probes as `raw` (no qcow2 magic) and
        // golden attaches NO separate vde (the overlay IS the writable
        // space). vdb/vdc stay the RO shared dm-verity base.
        let cfg = golden_fixture();
        let xml = cfg.to_libvirt_xml();
        assert!(
            xml.contains("<source file='/var/lib/hippius-miner/overlay/tenant-cvm-01.img'/>"),
            "golden vda overlay path missing: {xml}"
        );
        assert!(!xml.contains("vde"), "golden must not attach a vde: {xml}");
        // The RO shared base is still vdb/vdc.
        assert!(xml.contains("<target dev='vdb' bus='virtio'/>"));
        assert!(xml.contains("<target dev='vdc' bus='virtio'/>"));
    }

    #[test]
    fn validate_rejects_relative_state_disk_path() {
        // The state disk path is internally generated under a
        // process-owned root, but we still pin the absolute-path
        // sanity check so a buggy override (e.g. a test passing a
        // relative tmpdir) surfaces as `LaunchInput("state-disk-path")`
        // instead of a confusing libvirt rendering error.
        let mut cfg = fixture();
        cfg.state_disk_path = PathBuf::from("relative/state.raw");
        assert!(matches!(
            cfg.validate(),
            Err(MinerAgentError::LaunchInput("state-disk-path"))
        ));
    }
}
