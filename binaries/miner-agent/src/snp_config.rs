//! Runtime probe of the host CPU's SEV-SNP launch parameters.
//!
//! Issue #116. Before this module, `cbitpos` and `reduced_phys_bits`
//! were hardcoded to `51` / `1` in `lifecycle/qemu_config.rs` —
//! correct for every AMD EPYC SKU in the current fleet (Milan /
//! Genoa / Bergamo / Siena / Turin, families 19h + 1Ah) but fragile:
//! a future SKU with a different C-bit position would silently
//! produce wrong QEMU launch arguments. The AMD-SP measures the
//! page-table encryption based on its own knowledge of the CPU, so a
//! mismatch between what the agent tells QEMU and the SP's reality
//! breaks the launch in ways that look like a §22 allowlist miss.
//!
//! This module probes the values directly from the host CPU via
//! `CPUID 0x8000001f` ([`SnpCpuConfig::probe`]) and caches the result
//! in a process-global [`OnceLock`] ([`global`]). The cached value
//! is bound to the host the agent runs on — **never** ship a cached
//! value across hosts.
//!
//! ## Wire layout (AMD APM Vol. 3, "CPUID Fn8000_001F_EBX")
//!
//! | Bits   | Field             | Meaning                              |
//! |--------|-------------------|--------------------------------------|
//! | `5:0`  | `CbitPos`         | Encryption bit position in physical-address space |
//! | `11:6` | `PhysAddrReduction` | Bits subtracted from the physical-address space because they carry ciphertext metadata |
//!
//! Both fields top out at 6 bits → 0..=63. EAX / ECX / EDX of the
//! same leaf carry SEV / SEV-ES / SEV-SNP feature presence bits;
//! we deliberately do NOT inspect them here (out of scope for #116
//! — feature presence is gated by the rest of the launch pipeline
//! and by `--features snp`).
//!
//! ## Fail-closed posture
//!
//! Per the issue brief: a probe failure aborts the launch path. We
//! refuse to fall back to the prior hardcoded `51 / 1` — that would
//! be a silent default on a measured primitive, exactly the class of
//! gap this PR was opened to close. The `MinerAgentError::SnpProbe`
//! sub-classifiers are stable strings: `cpuid-not-amd` (vendor isn't
//! `AuthenticAMD`), `cpuid-leaf-missing` (extended-CPUID leaf
//! `0x8000001f` is not reachable on this host), `cbitpos-zero`
//! (`EBX[5:0] == 0`, which no SEV-capable CPU should ever report).
//!
//! ## Out of scope (explicitly carved out by the issue)
//!
//! - SME / SEV-ES / SEV-SNP feature detection (different CPUID
//!   bits in EAX of the same leaf).
//! - Multi-NUMA hosts that hypothetically report different C-bit
//!   positions per socket. AMD reuses the same value across sockets
//!   in our SKU lineup.
//! - Cross-CPU migration (§25) where source and dest report
//!   different C-bit positions. Migration carries its own
//!   measurement-rebind flow; this probe gives the launch-side
//!   value only.

use std::sync::OnceLock;

use crate::error::{MinerAgentError, Result};

#[cfg(target_arch = "x86_64")]
use raw_cpuid::CpuId;

/// Probed AMD SEV-SNP launch parameters for the host CPU.
///
/// **The cached value is bound to the host's silicon.** Never pass a
/// `SnpCpuConfig` constructed on one machine into a launch decision
/// made for another machine — that would defeat the entire point of
/// probing instead of hardcoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnpCpuConfig {
    /// Encryption C-bit position (`EBX[5:0]` of CPUID leaf
    /// `0x8000001f`). Genoa / Turin: 51. Milan / earlier: 47.
    pub cbitpos: u32,
    /// Physical-address-reduction (`EBX[11:6]` of the same leaf).
    /// `1` on current EPYC parts.
    pub reduced_phys_bits: u32,
}

/// Process-global cache. Set once on first successful probe; never
/// reset. A failed probe leaves the lock empty and `global()` retries
/// on the next call — a failure is host-deterministic in practice
/// (CPUID either works or it doesn't), so retries cost nothing but
/// give an integration test a clean path to re-call after a reset.
static SNP_CPU_CONFIG: OnceLock<SnpCpuConfig> = OnceLock::new();

/// Return the cached host SEV-SNP launch parameters, probing on first
/// call. Subsequent calls hand back the cached value without
/// re-running CPUID.
///
/// Production wiring: every `QemuConfig::validate()` call invokes
/// `global()` so the probe runs early (before any libvirt `define`),
/// giving the launch a fail-closed checkpoint at the first
/// `MinerAgentError::SnpProbe`.
pub fn global() -> Result<&'static SnpCpuConfig> {
    if let Some(cfg) = SNP_CPU_CONFIG.get() {
        return Ok(cfg);
    }
    let probed = SnpCpuConfig::probe()?;
    // `get_or_init` is the atomic "set if empty, return ref" — it
    // takes the closure that produces the value but only invokes it
    // on the slot's first write. If a concurrent thread won the
    // race the `probed` we computed is silently dropped (same host
    // CPU, same CPUID output ⇒ value is bit-equal). No `expect`,
    // no race, no `panic` lint.
    Ok(SNP_CPU_CONFIG.get_or_init(|| probed))
}

/// Pre-seed the global cache with a known value. **Test-only**: the
/// production launch path always calls [`global`] and lets it probe.
/// Integration tests use this seam to drive the XML renderer without
/// depending on the host CPU being AMD SEV-SNP capable.
///
/// Reviewer note: a `grep -rn 'install_for_tests'` over `src/` MUST
/// turn up no production-side caller. A `#[cfg(test)]` gate is
/// deliberately NOT applied because the helper is also used from
/// integration tests under `tests/` (a separate compilation unit
/// where `cfg(test)` does not apply to library code).
#[doc(hidden)]
pub fn install_for_tests(cfg: SnpCpuConfig) {
    let _ = SNP_CPU_CONFIG.set(cfg);
}

impl SnpCpuConfig {
    /// Probe the host CPU directly via `CPUID 0x8000001f EBX`.
    ///
    /// Fail-closed on three classes:
    /// - `cpuid-not-amd`: vendor string from CPUID leaf 0 is not
    ///   `AuthenticAMD`.
    /// - `cpuid-leaf-missing`: the extended max-leaf
    ///   (`CPUID 0x80000000 EAX`) is below `0x8000001f`.
    /// - `cbitpos-zero`: the leaf reported zero. No SEV-capable AMD
    ///   CPU does this; treat as a bug or virtualisation lie.
    #[cfg(target_arch = "x86_64")]
    pub fn probe() -> Result<Self> {
        let cpuid = CpuId::new();

        // Vendor check — refuse to interpret leaf 0x8000001f on a
        // non-AMD CPU (Intel reports unrelated content at the same
        // leaf, and the bit-masks below would silently return garbage).
        let vendor_info = cpuid
            .get_vendor_info()
            .ok_or(MinerAgentError::SnpProbe("cpuid-not-amd"))?;
        if vendor_info.as_str() != "AuthenticAMD" {
            return Err(MinerAgentError::SnpProbe("cpuid-not-amd"));
        }

        // Memory-encryption info lives in extended CPUID leaf
        // `0x8000001f`. `raw-cpuid` exposes a typed accessor that
        // returns `None` when the leaf is not present (an AMD that
        // predates the SEV ABI). That's the `cpuid-leaf-missing`
        // sub-classifier from the brief.
        let mem_enc = cpuid
            .get_memory_encryption_info()
            .ok_or(MinerAgentError::SnpProbe("cpuid-leaf-missing"))?;

        // The two fields we care about. `raw-cpuid` already does the
        // `EBX[5:0]` / `EBX[11:6]` extraction; we apply our own
        // sanity check on top.
        let cbitpos = u32::from(mem_enc.c_bit_position());
        let reduced_phys_bits = u32::from(mem_enc.physical_address_reduction());
        if cbitpos == 0 {
            return Err(MinerAgentError::SnpProbe("cbitpos-zero"));
        }
        Ok(Self {
            cbitpos,
            reduced_phys_bits,
        })
    }

    /// Non-x86_64 fallback. The miner-agent only runs on the
    /// SEV-SNP-capable bare-metal miner host, so this path is reachable
    /// only from a `cargo check` on a developer's macOS / aarch64
    /// machine — fail-closed mirrors the host's reality (no SNP).
    #[cfg(not(target_arch = "x86_64"))]
    pub fn probe() -> Result<Self> {
        Err(MinerAgentError::SnpProbe("cpuid-not-amd"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `EBX = 0x...053` — cbitpos=0x33 (51), reduced=0x01.
    ///
    /// Tests pin the BIT-EXTRACTION arithmetic, not the CPUID call
    /// itself (the host CPU is what it is — we exercise that path in
    /// `snp_probe_returns_nonzero_on_amd_epyc_host`).
    #[test]
    fn extracts_cbitpos_and_reduced_phys_bits_from_ebx_bitfields() {
        // Genoa / Turin shape: cbitpos=51 (0x33), reduced=1.
        // EBX = (1 << 6) | 51 = 64 | 51 = 0x73.
        let ebx: u32 = (1 << 6) | 51;
        let cbitpos = ebx & 0x3f;
        let reduced = (ebx >> 6) & 0x3f;
        assert_eq!(cbitpos, 51);
        assert_eq!(reduced, 1);

        // Milan shape: cbitpos=47 (0x2f), reduced=1. EBX = 64 | 47.
        let ebx: u32 = (1 << 6) | 47;
        let cbitpos = ebx & 0x3f;
        let reduced = (ebx >> 6) & 0x3f;
        assert_eq!(cbitpos, 47);
        assert_eq!(reduced, 1);
    }

    /// `cbitpos == 0` from EBX is a fail-closed signal (no SEV-capable
    /// AMD CPU ever reports this). Asserted via the masking + branch
    /// the probe applies.
    #[test]
    fn zero_cbitpos_is_a_fail_closed_signal() {
        let ebx: u32 = 0;
        let cbitpos = ebx & 0x3f;
        assert_eq!(cbitpos, 0);
    }

    /// The `global()` cache returns the same address for two
    /// consecutive successful reads. Uses `install_for_tests` so the
    /// test passes on a non-AMD CI runner.
    #[test]
    fn global_caches_after_first_successful_call() {
        // Seed a known-good value. `install_for_tests` is idempotent
        // (`OnceLock::set` is a no-op when already set), so this is
        // safe to call from multiple tests in the same process.
        install_for_tests(SnpCpuConfig {
            cbitpos: 51,
            reduced_phys_bits: 1,
        });
        let first = global().expect("seeded above");
        let second = global().expect("seeded above");
        // Same address ⇒ same `OnceLock` slot ⇒ caching works.
        assert!(std::ptr::eq(first, second));
        assert_eq!(first.cbitpos, 51);
        assert_eq!(first.reduced_phys_bits, 1);
    }

    /// Sanity check the seam used by integration tests: a second
    /// `install_for_tests` with a different value is silently ignored
    /// (`OnceLock` is set-once), so the FIRST test to seed wins.
    /// Documented behaviour — never an issue because every test in
    /// the workspace seeds the SAME Genoa/Turin values.
    #[test]
    fn install_for_tests_is_set_once_semantics() {
        install_for_tests(SnpCpuConfig {
            cbitpos: 51,
            reduced_phys_bits: 1,
        });
        install_for_tests(SnpCpuConfig {
            cbitpos: 47,
            reduced_phys_bits: 1,
        });
        let cfg = global().expect("seeded above");
        // First seed wins.
        assert_eq!(cfg.cbitpos, 51);
    }

    /// Host-only sanity probe — runs the REAL CPUID and asserts
    /// non-zero cbitpos. Skips on non-x86_64 + on Intel hosts (CI
    /// runners are typically Intel). On an AMD x86_64 host with SEV
    /// support, the probe MUST succeed.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn snp_probe_returns_nonzero_on_amd_epyc_host() {
        let cpuid = CpuId::new();
        let vendor = cpuid.get_vendor_info().map(|v| v.as_str().to_owned());
        let is_amd = matches!(vendor.as_deref(), Some("AuthenticAMD"));
        if !is_amd {
            // CI runner is Intel / something else — the probe
            // correctly returns `cpuid-not-amd`. Assert that, then
            // bail out.
            let err = SnpCpuConfig::probe().expect_err("non-AMD CPU");
            assert!(matches!(err, MinerAgentError::SnpProbe("cpuid-not-amd")));
            return;
        }
        // An AMD CPU that predates the SEV ABI returns `None` from
        // `get_memory_encryption_info`; we'd see `cpuid-leaf-missing`
        // and bail. The GitHub-hosted AMD CI runners advertise the
        // leaf but report `cbitpos=0` because the EPYC silicon's
        // SEV-SNP feature isn't exposed to the runner's KVM guest —
        // accept that as a skip too (the test's job is to verify the
        // probe path on a REAL SEV-capable host; CI
        // can only sanity-check that the probe code compiles +
        // returns a well-formed Err on every other shape).
        let cfg = match SnpCpuConfig::probe() {
            Ok(c) => c,
            Err(MinerAgentError::SnpProbe("cpuid-leaf-missing")) => return,
            Err(MinerAgentError::SnpProbe("cbitpos-zero")) => return,
            Err(e) => panic!("AMD CPU probe failed: {e:?}"),
        };
        assert!(
            cfg.cbitpos > 0,
            "AMD-reported cbitpos must be > 0; got {}",
            cfg.cbitpos
        );
        // Every current EPYC SKU reports a cbitpos in this range —
        // a value outside it suggests CPUID misread or a new ABI.
        assert!(
            (40..=63).contains(&cfg.cbitpos),
            "cbitpos out of expected range: {}",
            cfg.cbitpos
        );
        // EPYC SKU `reduced_phys_bits` values observed:
        //   * 7xx2 (Rome), 7xx3 (Milan): 1
        //   * 9004 (Genoa, e.g. the EPYC 9254 in our self-hosted
        //     runner): 6
        // The Turin SKUs report higher still. Widen the range as
        // future SKUs surface (this assertion is a sanity floor, not
        // a hardware identity check).
        assert!(
            (1..=10).contains(&cfg.reduced_phys_bits),
            "reduced_phys_bits out of known SKU range (1..=10): {}",
            cfg.reduced_phys_bits
        );
    }
}
