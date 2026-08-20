//! Real `/dev/sev-guest` ioctl wrapper — PR-E1.2.
//!
//! Implements [`crate::stages::snp_report::SnpReportProvider`] on top
//! of the `sev` crate's `Firmware::get_report`. The unsafe ioctl call
//! itself lives inside the `sev` crate; this module is `safe` Rust
//! (workspace `unsafe_code = "forbid"` lint inherited unmodified).
//!
//! ## Why a target-gated module
//!
//! `/dev/sev-guest` only exists on Linux SEV-SNP guests (AMD x86_64).
//! Building `hippius-agent-initramfs` on a macOS dev host (or any
//! other target) MUST still succeed for `cargo check`/`cargo test`;
//! it's only `main.rs` that fails fast if it can't find the real
//! provider. The `cfg(all(target_os = "linux", target_arch =
//! "x86_64"))` gate around the entire module is what makes that
//! split clean — non-Linux builds simply do not see
//! [`SevGuestProvider`].
//!
//! ## What we wrap
//!
//! [`sev::firmware::guest::Firmware`] does the following internally:
//!
//! 1. `open("/dev/sev-guest", O_RDWR | O_CLOEXEC)` (the path is
//!    hardcoded in the crate — we don't parameterise it; PR-E1.1
//!    plumbed `Config::sev_guest_dev` as a placeholder, but the real
//!    kernel uapi pins `/dev/sev-guest`).
//! 2. Builds `struct snp_report_req { user_data, vmpl, rsvd }`.
//! 3. `ioctl(SNP_GET_REPORT, &snp_guest_request_ioctl { … })`.
//! 4. Parses the `snp_report_resp` header + returns the 1184-byte
//!    body as `Vec<u8>`.
//!
//! Every error path inside `sev` maps to [`AgentError::SnpDevice`]
//! with one of the closed-vocabulary classifiers in [`cat`]. We
//! deliberately do NOT carry the `sev` crate's error in the variant
//! — that would risk leaking guest-internal pointer values or other
//! debug context through the §20 `log_fatal` path.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use crate::pipeline::AgentError;
use crate::stages::snp_report::{ReportData, SnpReport, SnpReportProvider, SNP_REPORT_LEN};

/// Stable classifier strings for [`AgentError::SnpDevice`] when raised
/// from this module. Kept in one place so the PR-E1.5 audit sink can
/// map each value to a metric code without grep-ing the codebase.
pub(crate) mod cat {
    /// `Firmware::open("/dev/sev-guest")` failed — character device
    /// missing, permission denied, kernel module not loaded. On a
    /// real SEV-SNP guest under a measured UKI this is unreachable;
    /// at runtime it means the guest is not a CVM and §11 has
    /// already failed.
    pub(crate) const OPEN: &str = "open-failed";
    /// `SNP_GET_REPORT` ioctl returned an error (firmware error,
    /// VMM error, EIO …). We don't surface which — the closed
    /// vocabulary keeps logs static, and operators investigate via
    /// `dmesg` on the host.
    pub(crate) const IOCTL: &str = "ioctl-failed";
    /// `SNP_GET_REPORT` returned bytes that aren't `SNP_REPORT_LEN`
    /// long. This contradicts the AMD SEV-SNP ABI v1.55+; the only
    /// way to hit it is a kernel/firmware regression OR an mocked-
    /// up device tampering. Drop fail-closed.
    pub(crate) const SHORT: &str = "short-report";
}

/// Production [`SnpReportProvider`] backed by `/dev/sev-guest`.
///
/// Zero-sized — `Firmware::open()` doesn't take any configuration, so
/// neither does this. PR-E1.5's HA / multi-VM scenarios will not
/// change that (one /dev/sev-guest per VM by definition).
#[derive(Debug, Default)]
pub struct SevGuestProvider;

impl SevGuestProvider {
    /// Construct a provider. No-op today (no state); kept as a method
    /// so callers go through a single entry-point — the future PR
    /// that adds e.g. mlock-of-the-response-buffer can hook in here.
    pub fn new() -> Self {
        Self
    }
}

impl SnpReportProvider for SevGuestProvider {
    fn get_report(&self, report_data: ReportData) -> Result<SnpReport, AgentError> {
        use sev::firmware::guest::Firmware;

        let mut fw = Firmware::open().map_err(|_| AgentError::SnpDevice(cat::OPEN))?;
        // `message_version = None` → defaults to 1 (current). VMPL 0
        // matches the v1 Hippius CVM layout (no SVSM, no nested-VMPL
        // tenant — confirmed §11 measured boot + §23 Audit VM both
        // run at VMPL 0). The `sev` crate's `ReportReq::default()`
        // uses VMPL 1, so we pass `Some(0)` explicitly.
        let bytes = fw
            .get_report(None, Some(*report_data.as_bytes()), Some(0))
            .map_err(|_| AgentError::SnpDevice(cat::IOCTL))?;
        if bytes.len() != SNP_REPORT_LEN {
            return Err(AgentError::SnpDevice(cat::SHORT));
        }
        Ok(SnpReport(bytes))
    }
}

// No unit tests here: `Firmware::open()` requires a real SEV-SNP
// guest. The behavioural coverage lives in
// `crate::stages::snp_report::tests::*` (via `MockSnpReportProvider`)
// and the end-to-end smoke test runs inside a real CVM under PR-F2's
// measured UKI — outside `cargo test`. The compile-gate test in
// `tests/compile_gate.rs` does pin the type signature
// `fn(&SevGuestProvider, [u8; 64]) -> Result<SnpReport, AgentError>`
// via an `as fn(...)` cast so a future refactor cannot drop the
// trait impl unnoticed.
