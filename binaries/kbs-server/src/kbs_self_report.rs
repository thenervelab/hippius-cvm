//! KBS SNP **self**-report provider — §8 / #102 PR B.
//!
//! The KBS itself runs inside a kata-qemu-snp confidential guest, so it
//! has its own `/dev/sev-guest`. To authenticate to the
//! SNP-attestation-bound Vault broker it must produce a FRESH
//! attestation report per redeem whose `REPORT_DATA` binds the broker
//! challenge to the KBS auth key:
//!
//! ```text
//! REPORT_DATA = challenge_nonce(32) ‖ kbs_auth_pubkey(32)
//! ```
//!
//! [`broker_report_data`] pins that byte-exact layout (it MUST match
//! the broker's `redeem` check — see
//! `binaries/kbs-vault-broker/src/redeem.rs` and the wire-contract
//! docs in `hippius_types::vault_broker`). [`SelfReportProvider`] is
//! the seam: production wires [`SevGuestSelfReport`] (the real
//! `/dev/sev-guest` ioctl); tests wire [`MockSelfReport`].
//!
//! ## §20 secret / log discipline
//!
//! Every error from this module is a `KbsError::Vault` carrying one of
//! the closed-vocabulary classifiers in [`cat`] — the inner `sev`
//! crate error is deliberately dropped (it can carry guest-internal
//! debug context), mirroring
//! `binaries/agent-initramfs/src/stages/snp_ioctl.rs`.

use kbs_core::error::{KbsError, Result};

/// Stable closed-vocabulary classifiers for self-report failures.
/// Mirrors `agent-initramfs::stages::snp_ioctl::cat` — one place to
/// map each value to a metric code, never the inner `sev` error.
pub(crate) mod cat {
    /// `Firmware::open("/dev/sev-guest")` failed — device missing,
    /// permission denied, kernel module not loaded. The KBS pod is a
    /// kata-qemu-snp CVM, so at runtime this means the confidential
    /// runtime is broken (or the binary is running outside a CVM).
    pub(crate) const OPEN: &str = "self-report: open-failed";
    /// `SNP_GET_REPORT` ioctl returned an error (firmware error, VMM
    /// error, EIO …). Which one is NOT surfaced — operators
    /// investigate via `dmesg` on the host.
    pub(crate) const IOCTL: &str = "self-report: ioctl-failed";
    /// The returned report length is outside the AMD SEV-SNP ABI
    /// bounds (`hippius_types::vault_broker::{MIN,MAX}_SNP_REPORT_LEN`).
    /// Kernel/firmware regression or a mocked-up device — fail closed.
    pub(crate) const LEN: &str = "self-report: bad-length";
}

/// A fresh KBS self-report plus the endorsement-key cert chain the
/// host PSP returned alongside it.
#[derive(Debug, Clone, Default)]
pub struct SelfReport {
    /// Raw SNP attestation report bytes (1184 B on ABI v1.55).
    pub report: Vec<u8>,
    /// The VEK leaf certificate (DER) — the per-chip VCEK or
    /// host-loaded VLEK from the extended report's cert table. Empty
    /// when no extended report / cert table is available (the broker
    /// then falls back to its mounted VEK). §17 / #394.
    pub vek_der: Vec<u8>,
}

/// Seam for obtaining a fresh KBS SNP self-report bound to the given
/// 64-byte `REPORT_DATA`. Production: [`SevGuestSelfReport`]. Tests:
/// [`MockSelfReport`].
pub trait SelfReportProvider: Send + Sync {
    /// Return a fresh [`SelfReport`] whose `REPORT_DATA` field equals
    /// `report_data`, carrying the VEK cert chain when the host PSP
    /// provides one. Errors are `KbsError::Vault` with a [`cat`]
    /// classifier only.
    fn report_for(&self, report_data: &[u8; 64]) -> Result<SelfReport>;
}

/// Byte-exact `REPORT_DATA` layout for broker redemption (§8):
/// `nonce(32) ‖ auth_pubkey(32)`. The broker verifies the report's
/// `REPORT_DATA` against exactly this concatenation — any drift here
/// is a fail-closed 403 at the broker, never a silent widening.
pub fn broker_report_data(nonce: &[u8; 32], auth_pubkey: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(nonce);
    out[32..].copy_from_slice(auth_pubkey);
    out
}

/// Production [`SelfReportProvider`] backed by `/dev/sev-guest`.
///
/// Target-gated like `agent-initramfs::stages::snp_ioctl` — the
/// device only exists on Linux SEV-SNP guests (AMD x86_64); building
/// the crate on any other dev host must still succeed, and `wiring`
/// fails fast there if `vault.broker_url` is set.
///
/// Zero-sized — `Firmware::open()` takes no configuration.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Debug, Default)]
pub struct SevGuestSelfReport;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl SevGuestSelfReport {
    /// Construct a provider. No-op today (no state); single
    /// entry-point so future hardening (e.g. mlock of the response
    /// buffer) hooks in here.
    pub fn new() -> Self {
        Self
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl SelfReportProvider for SevGuestSelfReport {
    fn report_for(&self, report_data: &[u8; 64]) -> Result<SelfReport> {
        use hippius_types::vault_broker::{
            MAX_SNP_REPORT_LEN, MAX_VEK_DER_LEN, MIN_SNP_REPORT_LEN,
        };
        use sev::firmware::guest::Firmware;
        use sev::firmware::host::CertType;

        let mut fw = Firmware::open().map_err(|_| KbsError::Vault(cat::OPEN.into()))?;
        // `get_ext_report` returns the report AND the host PSP's cached
        // endorsement-key cert table (§17 / #394). VMPL 0 matches the
        // v1 Hippius CVM layout (no SVSM); `Some(0)` is explicit since
        // the `sev` crate defaults to VMPL 1. The VEK travels with the
        // report so the broker's chain always matches the report's
        // current TCB — no static per-host VEK staging.
        let (bytes, certs) = fw
            .get_ext_report(None, Some(*report_data), Some(0))
            .map_err(|_| KbsError::Vault(cat::IOCTL.into()))?;
        if bytes.len() < MIN_SNP_REPORT_LEN || bytes.len() > MAX_SNP_REPORT_LEN {
            return Err(KbsError::Vault(cat::LEN.into()));
        }
        // Extract the VEK leaf (VCEK or VLEK) from the cert table, if
        // the host populated one. Empty ⇒ the broker uses its mounted
        // VEK fallback. Oversized ⇒ drop it (defence-in-depth; the
        // broker re-caps anyway).
        let vek_der = certs
            .unwrap_or_default()
            .into_iter()
            .find(|c| matches!(c.cert_type, CertType::VCEK | CertType::VLEK))
            .map(|c| c.data().to_vec())
            .filter(|d| !d.is_empty() && d.len() <= MAX_VEK_DER_LEN)
            .unwrap_or_default();
        Ok(SelfReport {
            report: bytes,
            vek_der,
        })
    }
}

/// Test double: returns a canned `MIN_SNP_REPORT_LEN`-byte report with
/// the requested `report_data` copied into its first 64 bytes (NOT the
/// real ABI offset — tests only assert the binding round-trips), and
/// records every `report_data` it was asked for.
#[cfg(test)]
pub(crate) struct MockSelfReport {
    pub(crate) calls: std::sync::Mutex<Vec<[u8; 64]>>,
}

#[cfg(test)]
impl MockSelfReport {
    pub(crate) fn new() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[cfg(test)]
impl SelfReportProvider for MockSelfReport {
    fn report_for(&self, report_data: &[u8; 64]) -> Result<SelfReport> {
        self.calls
            .lock()
            .expect("mock mutex poisoned")
            .push(*report_data);
        let mut report = vec![0xA5u8; hippius_types::vault_broker::MIN_SNP_REPORT_LEN];
        report[..64].copy_from_slice(report_data);
        Ok(SelfReport {
            report,
            vek_der: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_report_data_is_nonce_then_pubkey_byte_exact() {
        let mut nonce = [0u8; 32];
        let mut pubkey = [0u8; 32];
        for i in 0..32 {
            nonce[i] = i as u8; // 0x00..0x1F
            pubkey[i] = 0x40 + i as u8; // 0x40..0x5F
        }
        let rd = broker_report_data(&nonce, &pubkey);
        assert_eq!(&rd[..32], &nonce);
        assert_eq!(&rd[32..], &pubkey);
        // Spot-check absolute positions — the layout is the §8 wire
        // contract, not an implementation detail.
        assert_eq!(rd[0], 0x00);
        assert_eq!(rd[31], 0x1F);
        assert_eq!(rd[32], 0x40);
        assert_eq!(rd[63], 0x5F);
    }

    #[test]
    fn mock_records_report_data_and_embeds_it() {
        let mock = MockSelfReport::new();
        let rd = broker_report_data(&[7u8; 32], &[9u8; 32]);
        let sr = mock.report_for(&rd).expect("mock never fails");
        assert_eq!(
            sr.report.len(),
            hippius_types::vault_broker::MIN_SNP_REPORT_LEN
        );
        assert_eq!(&sr.report[..64], &rd);
        assert_eq!(mock.calls.lock().expect("mutex").as_slice(), &[rd]);
    }
}
