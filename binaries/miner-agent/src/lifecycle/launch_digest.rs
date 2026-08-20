//! Pre-flight SEV-SNP launch-digest computation.
//!
//! Before any domain is defined the lifecycle computes the digest the
//! KBS will independently re-derive from the running guest's SNP
//! attestation report. Computing it up front lets the miner-agent log
//! exactly what it is about to launch and gives an early, fail-closed
//! checkpoint — a launch never proceeds past a digest failure.
//!
//! ## Must equal the §F allowlist measurement
//!
//! The digest is computed by `sev::measurement::snp::
//! snp_calc_launch_digest` over the **(OVMF, kernel, initrd, cmdline)**
//! tuple — the same call, same inputs and same pinned launch
//! parameters `binaries/uki-measure --features snp` (PR-F3) uses to
//! produce the `snp_launch_digest_v1` value the §22 offline allowlist
//! is signed over. `binaries/miner-agent`'s known-answer test reuses
//! `test_vectors/snp/` and asserts byte-equality with PR-F3's frozen
//! digest.
//!
//! ## Feature-gated, like `uki-measure`
//!
//! `sev::measurement` is Linux-only and pulls `openssl`, so the real
//! computation lives behind the non-default `snp` feature. The
//! lifecycle state machine takes the computation as an injected
//! [`LaunchDigestComputer`] dependency, so its tests run on any host
//! with [`MockLaunchDigest`]; only the digest known-answer test needs
//! the Linux `--features snp` lane.

use super::cvm_handle::LAUNCH_DIGEST_LEN;
use super::qemu_config::QemuConfig;
use crate::error::{MinerAgentError, Result};

/// Computes the pre-flight SEV-SNP launch digest for a [`QemuConfig`].
///
/// Injected into the lifecycle so production uses the real `sev`-crate
/// computation ([`SevLaunchDigest`]) while tests use a deterministic
/// double ([`MockLaunchDigest`]).
pub trait LaunchDigestComputer: Send + Sync {
    /// Compute the 48-byte launch digest, or fail closed.
    fn compute(&self, config: &QemuConfig) -> Result<[u8; LAUNCH_DIGEST_LEN]>;
}

/// Production computer — the real AMD SEV-SNP launch digest.
pub struct SevLaunchDigest;

impl LaunchDigestComputer for SevLaunchDigest {
    fn compute(&self, config: &QemuConfig) -> Result<[u8; LAUNCH_DIGEST_LEN]> {
        compute_launch_digest(config)
    }
}

/// Test double — yields a fixed digest, or a fixed `sev-compute`
/// failure, so the lifecycle's digest-handling (including the
/// fail-closed-before-`virsh` path) is exercised on any host.
pub struct MockLaunchDigest {
    digest: Option<[u8; LAUNCH_DIGEST_LEN]>,
}

impl MockLaunchDigest {
    /// A computer that always returns `digest`.
    pub fn fixed(digest: [u8; LAUNCH_DIGEST_LEN]) -> Self {
        Self {
            digest: Some(digest),
        }
    }

    /// A computer that always fails — drives the fail-closed path.
    pub fn failing() -> Self {
        Self { digest: None }
    }
}

impl LaunchDigestComputer for MockLaunchDigest {
    fn compute(&self, _config: &QemuConfig) -> Result<[u8; LAUNCH_DIGEST_LEN]> {
        self.digest
            .ok_or(MinerAgentError::LaunchDigest("sev-compute"))
    }
}

/// Compute the SEV-SNP launch digest for `config`.
///
/// Built with `--features snp` this is the real `sev`-crate
/// computation; without it the call fails closed
/// (`cvm-launch-digest/feature-disabled`) — a genuine SEV-SNP launch
/// is only possible on a Linux SEV-SNP host, where the feature is on.
///
/// The digest depends on `config.cpu_count` — the vCPU count is
/// folded into the VMSA. The §F PR-F3 allowlist value is pinned at
/// **1 vCPU**; a multi-vCPU CVM yields a different (still correct)
/// digest, which the §22 allowlist must carry an entry for.
#[cfg(feature = "snp")]
pub fn compute_launch_digest(config: &QemuConfig) -> Result<[u8; LAUNCH_DIGEST_LEN]> {
    snp_impl::compute(config)
}

/// Fail-closed stub for builds without `--features snp`.
#[cfg(not(feature = "snp"))]
pub fn compute_launch_digest(_config: &QemuConfig) -> Result<[u8; LAUNCH_DIGEST_LEN]> {
    Err(MinerAgentError::LaunchDigest("feature-disabled"))
}

/// Test-only: compute the launch digest for an **explicit** host
/// generation rather than deriving it from the build host's CPUID.
///
/// The production [`compute_launch_digest`] reads the host's real
/// generation, so its result depends on the silicon it runs on — which
/// is correct in prod but makes the §F known-answer test irreproducible
/// on a non-SNP CI box. The KAT calls this with a fixed generation so it
/// asserts the exact same Genoa (and Turin) digest on any host.
///
/// `doc(hidden)` marks the test-only intent; it is `pub` only so the
/// `--features snp` integration KAT (`tests/launch_digest_test.rs`) can
/// reach it.
#[cfg(feature = "snp")]
#[doc(hidden)]
pub fn compute_launch_digest_for_generation(
    config: &QemuConfig,
    gen: sev::Generation,
) -> Result<[u8; LAUNCH_DIGEST_LEN]> {
    let vcpu_type = snp_impl::vcpu_type_for_generation(gen)?;
    snp_impl::compute_with_vcpu_type(config, vcpu_type)
}

/// The real `sev`-crate computation — isolated so the `sev` crate is
/// referenced only under `cfg(feature = "snp")` (Linux-only).
#[cfg(feature = "snp")]
mod snp_impl {
    use super::QemuConfig;
    use crate::error::{MinerAgentError, Result};
    use crate::lifecycle::cvm_handle::LAUNCH_DIGEST_LEN;

    use sev::measurement::snp::{snp_calc_launch_digest, SnpMeasurementArgs};
    use sev::measurement::vcpu_types::CpuType;
    use sev::measurement::vmsa::GuestFeatures;
    use sev::Generation;

    /// SEV-SNP guest-features bitmap. MUST equal `SNP_GUEST_FEATURES`
    /// in `packer/kbs-uki/uki/Makefile` (`0x1` = SNPActive).
    const SNP_GUEST_FEATURES: u64 = 0x1;

    /// The vCPU model folded into the BSP VMSA — and so into the launch
    /// digest — **must** match the real silicon QEMU `-cpu host` writes
    /// into the VMSA's RDX register on the host the guest actually boots
    /// on. AMD-SP measures the genuine VMSA bytes, so a mismatch moves
    /// our predicted digest off the §F allowlist value and the KBS
    /// fail-closes `measurement not in ticket's allowed set`.
    ///
    /// We therefore derive the model from the **host's own CPUID**
    /// (`Generation::identify_host_generation`, leaf 0x8000_0001 EAX) —
    /// a hardware fact, never attacker-controlled input. A Genoa host
    /// yields the byte-identical Genoa digest as before; a
    /// Turin host (EPYC 9255) yields the Turin digest
    /// (`CpuType::EpycTurin`, the genuine `cpu_sig(26, 2, 1)` =
    /// `0x00B00F21` read off the silicon — see `vendor/sev`). Any other
    /// / unknown generation fails closed rather than guessing a wrong
    /// (silently-rejected, or worse) measurement.
    ///
    /// MUST equal the `SNP_VCPU_TYPE` the matching-generation UKI build
    /// (`packer/*/uki/Makefile`) measured for its allowlist entry — vali
    /// auto-pins per launch, so the first launch on a generation pins
    /// that generation's measurement.
    fn host_vcpu_type() -> Result<CpuType> {
        let gen = Generation::identify_host_generation()
            .map_err(|_| MinerAgentError::LaunchDigest("vcpu-generation"))?;
        vcpu_type_for_generation(gen)
    }

    /// Map a host SEV generation to the QEMU `-cpu host` vCPU model whose
    /// signature the silicon writes into the BSP VMSA. Pure (no I/O) so
    /// it is unit-testable off a real SNP host; `host_vcpu_type` supplies
    /// the genuine host generation from CPUID.
    ///
    /// Fail-closed default: only the two generations in the SNP fleet
    /// (Genoa, Turin) map; anything else is rejected rather than measured
    /// against the wrong allowlist entry.
    pub(super) fn vcpu_type_for_generation(gen: Generation) -> Result<CpuType> {
        match gen {
            Generation::Genoa => Ok(CpuType::EpycGenoa),
            Generation::Turin => Ok(CpuType::EpycTurin),
            // Milan (the only other snp-visible variant) and any future
            // unrecognised generation fail closed.
            _ => Err(MinerAgentError::LaunchDigest("vcpu-generation")),
        }
    }

    /// Compute the 48-byte launch digest for the **host's own**
    /// generation — the production path. The vCPU model is derived from
    /// host CPUID (`host_vcpu_type`), never an input.
    pub(super) fn compute(config: &QemuConfig) -> Result<[u8; LAUNCH_DIGEST_LEN]> {
        compute_with_vcpu_type(config, host_vcpu_type()?)
    }

    /// Compute the 48-byte launch digest for an explicitly-supplied vCPU
    /// model, mirroring `uki-measure`'s `SnpMeasurementArgs` mapping
    /// exactly. Used by `compute` (host-derived model) and by the
    /// known-answer test (a fixed generation, so the KAT is reproducible
    /// off any build host — it must not depend on the test host's
    /// silicon being Genoa or Turin).
    pub(super) fn compute_with_vcpu_type(
        config: &QemuConfig,
        vcpu_type: CpuType,
    ) -> Result<[u8; LAUNCH_DIGEST_LEN]> {
        let args = SnpMeasurementArgs {
            vcpus: u32::from(config.cpu_count),
            vcpu_type,
            ovmf_file: config.ovmf_path.clone(),
            guest_features: GuestFeatures(SNP_GUEST_FEATURES),
            kernel_file: Some(config.kernel_path.clone()),
            initrd_file: Some(config.initrd_path.clone()),
            append: Some(config.cmdline.as_str()),
            // `None` → measure the OVMF file's bytes (not a supplied
            // hash); `None` vmm_type → QEMU, the miner launch path.
            ovmf_hash_str: None,
            vmm_type: None,
        };
        let digest = snp_calc_launch_digest(args)
            .map_err(|_| MinerAgentError::LaunchDigest("sev-compute"))?;
        let digest_hex = digest.get_hex_ld();
        let bytes =
            hex::decode(digest_hex).map_err(|_| MinerAgentError::LaunchDigest("digest-shape"))?;
        bytes
            .try_into()
            .map_err(|_| MinerAgentError::LaunchDigest("digest-shape"))
    }

    #[cfg(test)]
    mod tests {
        use super::vcpu_type_for_generation;
        use crate::error::MinerAgentError;
        use sev::measurement::vcpu_types::CpuType;
        use sev::Generation;

        /// Real EPYC 9255 (Turin) silicon: family=26 (0x1A), model=2.
        /// `Generation::identify_cpu` classifies this as Turin, and the
        /// mapping must fold the genuine `cpu_sig(26, 2, 1)` = 0x00B00F21
        /// via `CpuType::EpycTurin`.
        #[test]
        fn turin_host_selects_epyc_turin() {
            let gen = Generation::identify_cpu(0x1A, 0x02).unwrap();
            let cpu = vcpu_type_for_generation(gen).unwrap();
            assert_eq!(cpu, CpuType::EpycTurin);
            assert_eq!(cpu.sig(), 0x00B0_0F21);
        }

        /// Real EPYC 9254 (Genoa) silicon: family=25 (0x19), model=17.
        /// Must still select Genoa and the byte-identical Genoa sig — no
        /// regression for existing Genoa hosts / the live §22 allowlist.
        #[test]
        fn genoa_host_selects_epyc_genoa_unchanged() {
            let gen = Generation::identify_cpu(0x19, 0x11).unwrap();
            let cpu = vcpu_type_for_generation(gen).unwrap();
            assert_eq!(cpu, CpuType::EpycGenoa);
            assert_eq!(cpu.sig(), 0x00A1_0F11);
        }

        /// A Milan host is not part of the SNP fleet — fail closed rather
        /// than measure against a Genoa/Turin allowlist entry.
        #[test]
        fn milan_host_fails_closed() {
            let gen = Generation::identify_cpu(0x19, 0x01).unwrap();
            assert!(matches!(
                vcpu_type_for_generation(gen),
                Err(MinerAgentError::LaunchDigest("vcpu-generation"))
            ));
        }

        /// SECURITY ANCHOR: the Turin vCPU signature folded into the VMSA
        /// MUST be the genuine EPYC 9255 silicon value `0x00B00F21`
        /// (family=26, model=2, stepping=1) read off a Turin host's CPUID —
        /// NOT upstream sev's generic `cpu_sig(26, 0, 0)` = `0x00B00F00`
        /// placeholder, which is 0x21 off and would fail-close every
        /// Turin KBS release. This guards the patched `vendor/sev` value.
        #[test]
        fn turin_cpu_sig_is_the_genuine_silicon_value() {
            use sev::measurement::vcpu_types::cpu_sig;
            assert_eq!(CpuType::EpycTurin.sig(), 0x00B0_0F21);
            assert_eq!(CpuType::EpycTurin.sig(), cpu_sig(26, 2, 1));
            // Must NOT be the upstream placeholder.
            assert_ne!(CpuType::EpycTurin.sig(), cpu_sig(26, 0, 0));
        }

        /// The Genoa signature is unchanged (`cpu_sig(25, 17, 1)` =
        /// `0x00A10F11`) — the live §22 allowlist is signed over it.
        #[test]
        fn genoa_cpu_sig_unchanged() {
            use sev::measurement::vcpu_types::cpu_sig;
            assert_eq!(CpuType::EpycGenoa.sig(), 0x00A1_0F11);
            assert_eq!(CpuType::EpycGenoa.sig(), cpu_sig(25, 17, 1));
        }

        /// Turin is a first-class `CpuType`: sig→type, str, and u8
        /// discriminant all round-trip.
        #[test]
        fn turin_cpu_type_round_trips() {
            use std::convert::TryFrom;
            assert_eq!(
                CpuType::try_from(0x00B0_0F21_i32).unwrap(),
                CpuType::EpycTurin
            );
            assert_eq!(CpuType::try_from("EPYC-Turin").unwrap(), CpuType::EpycTurin);
            assert_eq!(format!("{}", CpuType::EpycTurin), "EPYC-Turin");
            assert_eq!(CpuType::try_from(15u8).unwrap(), CpuType::EpycTurin);
            assert_eq!(CpuType::try_from(16u8).unwrap(), CpuType::EpycTurinV1);
        }
    }
}

#[cfg(all(test, not(feature = "snp")))]
mod tests {
    use super::*;

    #[test]
    fn mock_fixed_returns_the_digest() {
        let d = [7u8; LAUNCH_DIGEST_LEN];
        let computer = MockLaunchDigest::fixed(d);
        // A trivial config — the mock ignores it.
        let cfg = test_config();
        assert_eq!(computer.compute(&cfg).unwrap(), d);
    }

    #[test]
    fn mock_failing_fails_closed() {
        let computer = MockLaunchDigest::failing();
        assert!(matches!(
            computer.compute(&test_config()),
            Err(MinerAgentError::LaunchDigest("sev-compute"))
        ));
    }

    #[test]
    fn sev_computer_without_snp_feature_is_disabled() {
        // The default build cannot compute a real digest — fail closed.
        assert!(matches!(
            SevLaunchDigest.compute(&test_config()),
            Err(MinerAgentError::LaunchDigest("feature-disabled"))
        ));
    }

    fn test_config() -> QemuConfig {
        use crate::lifecycle::cvm_handle::{DomainUuid, VmId};
        use std::path::PathBuf;
        QemuConfig {
            vm_id: VmId::new("t").unwrap(),
            domain_uuid: DomainUuid::parse("11111111-2222-4333-8444-555555555555").unwrap(),
            ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf.fd"),
            kernel_path: PathBuf::from("/var/lib/hippius-miner/vmlinuz"),
            initrd_path: PathBuf::from("/var/lib/hippius-miner/initrd"),
            cmdline: "quiet".to_string(),
            luks_disk_path: PathBuf::from("/var/lib/hippius-miner/d.img"),
            luks_disk_size_gb: 10,
            rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/rootfs.img"),
            rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/rootfs.verity"),
            state_disk_path: PathBuf::from("/var/lib/hippius-miner/state/t.raw"),
            data_disk_path: None,
            data_disk_size_gb: 0,
            cpu_count: 1,
            memory_mb: 1024,
            golden: false,
            cid: 3,
        }
    }
}
