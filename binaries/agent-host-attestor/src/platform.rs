//! Platform claims lifted from the attested SNP report.
//!
//! The liveness beacon self-declares the platform it runs on —
//! `chip_id`, `measurement`, the TCB triple, and the guest `policy`. To
//! keep those fields honest, [`PlatformClaims`] has **no public
//! constructor**: the only way to build one is [`PlatformClaims::from_report`],
//! which reads the fields at their fixed AMD SEV-SNP ABI offsets out of
//! the report the attestor just generated. A caller therefore cannot
//! hand the beacon builder free-form platform bytes — every beacon's
//! platform fields provably originate in the attested report.
//!
//! ## Field offsets (AMD SEV-SNP `ATTESTATION_REPORT`, 1184 bytes)
//!
//! Confirmed against the in-tree `vendor/sev` parser
//! (`firmware/guest/types/snp.rs`) and the sibling agents' `0x90`
//! measurement offset:
//!
//! | field          | offset  | size | encoding      |
//! |----------------|---------|------|---------------|
//! | `policy`       | `0x008` | 8    | u64 LE        |
//! | `current_tcb`  | `0x038` | 8    | u64 LE        |
//! | `measurement`  | `0x090` | 48   | raw bytes     |
//! | `reported_tcb` | `0x180` | 8    | u64 LE        |
//! | `chip_id`      | `0x1A0` | 64   | raw bytes     |
//! | `committed_tcb`| `0x1E0` | 8    | u64 LE        |
//!
//! Each TCB version is the opaque 8-byte little-endian value read as an
//! integer — exactly the form [`PlatformTcb`] documents.

use hippius_types::host_attestor::{PlatformTcb, CHIP_ID_LEN, MEASUREMENT_LEN};

use crate::error::{HostAttestorError, Result};
use crate::snp::SnpReport;

/// `POLICY` — guest policy bits.
const POLICY_OFFSET: usize = 0x008;
/// `CURRENT_TCB` (a.k.a. `PLATFORM_VERSION`).
const CURRENT_TCB_OFFSET: usize = 0x038;
/// `MEASUREMENT` — the 48-byte launch measurement.
const MEASUREMENT_OFFSET: usize = 0x090;
/// `REPORTED_TCB`.
const REPORTED_TCB_OFFSET: usize = 0x180;
/// `CHIP_ID` — the 64-byte per-CPU platform identity.
const CHIP_ID_OFFSET: usize = 0x1A0;
/// `COMMITTED_TCB`.
const COMMITTED_TCB_OFFSET: usize = 0x1E0;

/// The platform fields a [`crate::beacon_builder`] folds into every
/// beacon — lifted verbatim from the attested SNP report.
///
/// All fields are private and there is exactly one constructor
/// ([`Self::from_report`]), so a beacon cannot carry a platform identity
/// that did not come out of a real report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformClaims {
    chip_id: [u8; CHIP_ID_LEN],
    measurement: [u8; MEASUREMENT_LEN],
    tcb: PlatformTcb,
    policy: u64,
}

impl PlatformClaims {
    /// Parse the platform fields out of `report` at their fixed ABI
    /// offsets. Fails closed (`Snp("short-report")`) if the report is
    /// too short to carry them.
    pub fn from_report(report: &SnpReport) -> Result<Self> {
        let bytes = report.0.as_slice();
        let chip_id = read_array::<CHIP_ID_LEN>(bytes, CHIP_ID_OFFSET)?;
        let measurement = read_array::<MEASUREMENT_LEN>(bytes, MEASUREMENT_OFFSET)?;
        let policy = read_u64_le(bytes, POLICY_OFFSET)?;
        let tcb = PlatformTcb {
            reported: read_u64_le(bytes, REPORTED_TCB_OFFSET)?,
            committed: read_u64_le(bytes, COMMITTED_TCB_OFFSET)?,
            current: read_u64_le(bytes, CURRENT_TCB_OFFSET)?,
        };
        Ok(Self {
            chip_id,
            measurement,
            tcb,
            policy,
        })
    }

    /// The 64-byte platform `CHIP_ID`.
    pub fn chip_id(&self) -> [u8; CHIP_ID_LEN] {
        self.chip_id
    }

    /// The 48-byte launch `MEASUREMENT`.
    pub fn measurement(&self) -> [u8; MEASUREMENT_LEN] {
        self.measurement
    }

    /// The reported / committed / current TCB triple.
    pub fn tcb(&self) -> PlatformTcb {
        self.tcb
    }

    /// The guest `policy` bits.
    pub fn policy(&self) -> u64 {
        self.policy
    }
}

/// Read a fixed-size byte array at `offset`, or `Snp("short-report")`.
fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .and_then(|s| <[u8; N]>::try_from(s).ok())
        .ok_or(HostAttestorError::Snp("short-report"))
}

/// Read an 8-byte little-endian `u64` at `offset`, or `Snp("short-report")`.
fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64> {
    let arr = read_array::<8>(bytes, offset)?;
    Ok(u64::from_le_bytes(arr))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::snp::SNP_REPORT_LEN;

    /// A canned report with distinct, recognisable bytes at each field
    /// offset so the parser's placement is pinned exactly.
    fn planted_report() -> SnpReport {
        let mut b = vec![0u8; SNP_REPORT_LEN];
        b[POLICY_OFFSET..POLICY_OFFSET + 8].copy_from_slice(&0x0003_0000u64.to_le_bytes());
        b[CURRENT_TCB_OFFSET..CURRENT_TCB_OFFSET + 8]
            .copy_from_slice(&0x0708_0000_0000_000Bu64.to_le_bytes());
        b[REPORTED_TCB_OFFSET..REPORTED_TCB_OFFSET + 8]
            .copy_from_slice(&0x0708_0000_0000_000Cu64.to_le_bytes());
        b[COMMITTED_TCB_OFFSET..COMMITTED_TCB_OFFSET + 8]
            .copy_from_slice(&0x0708_0000_0000_000Au64.to_le_bytes());
        for (i, byte) in b
            .iter_mut()
            .skip(MEASUREMENT_OFFSET)
            .take(MEASUREMENT_LEN)
            .enumerate()
        {
            *byte = 0x40 | (i as u8);
        }
        for (i, byte) in b
            .iter_mut()
            .skip(CHIP_ID_OFFSET)
            .take(CHIP_ID_LEN)
            .enumerate()
        {
            *byte = 0x80 | (i as u8);
        }
        SnpReport(b)
    }

    #[test]
    fn from_report_lifts_every_field_at_its_offset() {
        let claims = PlatformClaims::from_report(&planted_report()).unwrap();
        assert_eq!(claims.policy(), 0x0003_0000);
        assert_eq!(claims.tcb().current, 0x0708_0000_0000_000B);
        assert_eq!(claims.tcb().reported, 0x0708_0000_0000_000C);
        assert_eq!(claims.tcb().committed, 0x0708_0000_0000_000A);
        assert_eq!(claims.measurement()[0], 0x40);
        assert_eq!(
            claims.measurement()[MEASUREMENT_LEN - 1],
            0x40 | (MEASUREMENT_LEN as u8 - 1)
        );
        assert_eq!(claims.chip_id()[0], 0x80);
        assert_eq!(
            claims.chip_id()[CHIP_ID_LEN - 1],
            0x80 | (CHIP_ID_LEN as u8 - 1)
        );
    }

    #[test]
    fn from_report_rejects_a_short_report() {
        // One byte short of the last field's end.
        let short = SnpReport(vec![0u8; CHIP_ID_OFFSET + 1]);
        assert!(matches!(
            PlatformClaims::from_report(&short),
            Err(HostAttestorError::Snp("short-report"))
        ));
    }
}
