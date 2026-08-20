//! The tenant guest's honest self-assessment of served work.
//!
//! A §23 `ServedDeliveryReceipt` carries `observed_degradation_bps` —
//! the guest's HONEST report, in basis points (0 = full service,
//! 10_000 = none), of "less than full work served" over the interval.
//! Host-claimed inputs may only decrease/corroborate reward, never
//! raise it (§23), so this value is the guest's own measurement.
//!
//! PR-E2.2 ships the receipt loop against the [`ServedWorkSource`]
//! capability. The production source — reading local service-health
//! signals — is a later refinement; E2.2 uses [`StaticServedWorkSource`]
//! (a configured constant, default 0 = full service).

use hippius_types::served_receipt::DEGRADATION_MAX_BPS;

use crate::error::{Result, TelemetryError};

/// A source of the observed service-degradation for the current
/// interval, in basis points (`0..=DEGRADATION_MAX_BPS`).
pub trait ServedWorkSource {
    /// The degradation observed for the interval just ended. The value
    /// MUST be `<= DEGRADATION_MAX_BPS` — a receipt over a larger value
    /// is rejected at `canonical()` encode time (fail closed).
    fn observed_degradation_bps(&self) -> Result<u32>;
}

/// A [`ServedWorkSource`] returning a fixed, pre-validated value.
#[derive(Debug)]
pub struct StaticServedWorkSource {
    bps: u32,
}

impl StaticServedWorkSource {
    /// Build a source returning `bps` every interval.
    ///
    /// `bps` is range-checked HERE so a misconfiguration fails at
    /// startup, not silently every interval at receipt-encode time.
    pub fn new(bps: u32) -> Result<Self> {
        if bps > DEGRADATION_MAX_BPS {
            return Err(TelemetryError::Receipt("degradation-out-of-range"));
        }
        Ok(Self { bps })
    }
}

impl ServedWorkSource for StaticServedWorkSource {
    fn observed_degradation_bps(&self) -> Result<u32> {
        Ok(self.bps)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_the_full_in_range_span() {
        assert_eq!(
            StaticServedWorkSource::new(0)
                .unwrap()
                .observed_degradation_bps()
                .unwrap(),
            0
        );
        assert_eq!(
            StaticServedWorkSource::new(DEGRADATION_MAX_BPS)
                .unwrap()
                .observed_degradation_bps()
                .unwrap(),
            DEGRADATION_MAX_BPS
        );
    }

    #[test]
    fn new_rejects_out_of_range_degradation() {
        let err = StaticServedWorkSource::new(DEGRADATION_MAX_BPS + 1)
            .expect_err("a degradation over the max must be rejected at construction");
        assert_eq!(err.class(), "degradation-out-of-range");
    }
}
