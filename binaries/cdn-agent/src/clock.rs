//! Wall-clock helpers. Timestamps on the wire are RFC 3339 UTC.

use std::time::{SystemTime, UNIX_EPOCH};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::{CdnError, Result};

/// Seconds since the Unix epoch. A clock before 1970 is a broken guest;
/// it reads as 0 rather than panicking, and every freshness check then
/// fails closed.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse an RFC 3339 timestamp into Unix seconds.
pub fn parse_rfc3339(s: &str) -> Result<u64> {
    let t = OffsetDateTime::parse(s, &Rfc3339).map_err(|_| CdnError::Backend("bad-timestamp"))?;
    u64::try_from(t.unix_timestamp()).map_err(|_| CdnError::Backend("bad-timestamp"))
}

/// Render Unix seconds as RFC 3339 UTC.
pub fn format_rfc3339(secs: u64) -> String {
    i64::try_from(secs)
        .ok()
        .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_round_trips() {
        let t = parse_rfc3339("2026-10-20T10:00:00Z").unwrap();
        assert_eq!(t, 1_792_490_400);
        assert_eq!(format_rfc3339(t), "2026-10-20T10:00:00Z");
    }

    #[test]
    fn rejects_garbage_and_pre_epoch() {
        assert!(parse_rfc3339("yesterday").is_err());
        assert!(parse_rfc3339("1960-01-01T00:00:00Z").is_err());
    }
}
