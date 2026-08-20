//! KBS-measurement allowlist for the broker.
//!
//! The set of SEV-SNP launch measurements the broker will mint
//! capabilities for. v1 is a fixed set loaded at startup (operator
//! config / mounted artifact). The §22-style *signed* allowlist with a
//! monotonic high-water mark is a follow-up (analogous to
//! `kbs_core::allowlist::InstalledAllowlist`); the trait boundary
//! ([`crate::redeem::KbsMeasurementAllowlist`]) is the same so that
//! upgrade is drop-in.
//!
//! Empty set ⇒ accepts nothing ⇒ fail-closed (every redeem denied).

use std::collections::BTreeSet;

use crate::redeem::KbsMeasurementAllowlist;

pub struct FixedMeasurementAllowlist {
    measurements: BTreeSet<[u8; 48]>,
}

impl FixedMeasurementAllowlist {
    /// Build from a list of 48-byte measurements.
    pub fn new(measurements: impl IntoIterator<Item = [u8; 48]>) -> Self {
        Self {
            measurements: measurements.into_iter().collect(),
        }
    }

    /// Parse from lower-case 96-hex strings (the form the operator
    /// pins, identical to the §22 allowlist measurement encoding).
    /// Fails closed on any malformed entry.
    pub fn from_hex(entries: &[String]) -> Result<Self, String> {
        let mut set = BTreeSet::new();
        for (i, h) in entries.iter().enumerate() {
            let bytes =
                hex::decode(h.trim()).map_err(|e| format!("allowlist[{i}] not hex: {e}"))?;
            let arr: [u8; 48] = bytes.as_slice().try_into().map_err(|_| {
                format!(
                    "allowlist[{i}] must be 48 bytes (96 hex), got {} bytes",
                    bytes.len()
                )
            })?;
            set.insert(arr);
        }
        Ok(Self { measurements: set })
    }

    pub fn len(&self) -> usize {
        self.measurements.len()
    }
    pub fn is_empty(&self) -> bool {
        self.measurements.is_empty()
    }
}

impl KbsMeasurementAllowlist for FixedMeasurementAllowlist {
    fn accepts(&self, measurement: &[u8; 48]) -> bool {
        self.measurements.contains(measurement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_listed() {
        let a = FixedMeasurementAllowlist::new([[0xABu8; 48]]);
        assert!(a.accepts(&[0xAB; 48]));
        assert!(!a.accepts(&[0xCD; 48]));
    }

    #[test]
    fn empty_accepts_nothing() {
        let a = FixedMeasurementAllowlist::new([]);
        assert!(a.is_empty());
        assert!(!a.accepts(&[0u8; 48]));
    }

    #[test]
    fn from_hex_round_trips() {
        let m = "ab".repeat(48); // 96 hex chars = 48 bytes
        let a = FixedMeasurementAllowlist::from_hex(&[m]).unwrap();
        assert_eq!(a.len(), 1);
        assert!(a.accepts(&[0xAB; 48]));
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        assert!(FixedMeasurementAllowlist::from_hex(&["ab".repeat(10)]).is_err());
        assert!(FixedMeasurementAllowlist::from_hex(&["zz".repeat(48)]).is_err());
    }
}
