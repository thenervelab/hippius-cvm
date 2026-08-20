//! Host metrics sampling for the §K heartbeat (PR-MA-6).
//!
//! [`HostMetrics`] is the coarse host snapshot folded into a
//! [`crate::heartbeat::MinerHeartbeat`]: the 1-minute load average and
//! the total / available RAM. [`MetricsSource`] is the seam — the
//! production [`ProcMetricsSource`] reads `/proc/loadavg` +
//! `/proc/meminfo`; the test [`MockMetricsSource`] returns a canned
//! snapshot so the builder is testable on any host.
//!
//! The numbers are a SOFT signal for vali's scheduler — a heartbeat is
//! still a valid liveness proof if a metric read fails; the builder
//! decides the failure policy. This module just reads `/proc`.

use crate::error::{MinerAgentError, Result};

/// A coarse host-state snapshot.
///
/// `cpu_load_1m_centi` is the 1-minute load average in centi-units
/// (load × 100, truncated) — an integer so it folds cleanly into the
/// canonical-CBOR heartbeat body. The memory figures are MiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostMetrics {
    /// 1-minute load average × 100.
    pub cpu_load_1m_centi: u32,
    /// Total host RAM, MiB.
    pub memory_total_mib: u32,
    /// Available host RAM, MiB.
    pub memory_available_mib: u32,
}

/// The seam the heartbeat builder samples through.
pub trait MetricsSource: Send + Sync {
    /// Sample the host. `Err(MinerAgentError::HeartbeatBuild("metrics"))`
    /// on a read / parse failure.
    fn sample(&self) -> Result<HostMetrics>;
}

/// Production [`MetricsSource`] — reads the Linux `/proc` filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcMetricsSource;

impl MetricsSource for ProcMetricsSource {
    fn sample(&self) -> Result<HostMetrics> {
        let loadavg = std::fs::read_to_string("/proc/loadavg")
            .map_err(|_| MinerAgentError::HeartbeatBuild("metrics"))?;
        let meminfo = std::fs::read_to_string("/proc/meminfo")
            .map_err(|_| MinerAgentError::HeartbeatBuild("metrics"))?;
        let cpu_load_1m_centi = parse_loadavg_centi(&loadavg)?;
        let (memory_total_mib, memory_available_mib) = parse_meminfo_mib(&meminfo)?;
        Ok(HostMetrics {
            cpu_load_1m_centi,
            memory_total_mib,
            memory_available_mib,
        })
    }
}

/// Parse the 1-minute load average from `/proc/loadavg` into centi-
/// units. The file's first whitespace-separated token is the 1m
/// average, e.g. `0.75 0.42 0.31 1/512 12345`.
fn parse_loadavg_centi(raw: &str) -> Result<u32> {
    let token = raw
        .split_whitespace()
        .next()
        .ok_or(MinerAgentError::HeartbeatBuild("metrics"))?;
    let load: f64 = token
        .parse()
        .map_err(|_| MinerAgentError::HeartbeatBuild("metrics"))?;
    if !load.is_finite() || load < 0.0 {
        return Err(MinerAgentError::HeartbeatBuild("metrics"));
    }
    // load × 100, saturating into u32 — a load above ~42M is absurd
    // and is simply clamped rather than failing the heartbeat.
    let centi = (load * 100.0).trunc();
    if centi >= f64::from(u32::MAX) {
        Ok(u32::MAX)
    } else {
        Ok(centi as u32)
    }
}

/// Parse `MemTotal` + `MemAvailable` (kibibytes) from `/proc/meminfo`
/// and convert to MiB. Both lines look like `MemTotal:  16331776 kB`.
fn parse_meminfo_mib(raw: &str) -> Result<(u32, u32)> {
    let mut total_kib: Option<u64> = None;
    let mut avail_kib: Option<u64> = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kib = Some(parse_kib(rest)?);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail_kib = Some(parse_kib(rest)?);
        }
    }
    let total = total_kib.ok_or(MinerAgentError::HeartbeatBuild("metrics"))?;
    let avail = avail_kib.ok_or(MinerAgentError::HeartbeatBuild("metrics"))?;
    Ok((kib_to_mib(total), kib_to_mib(avail)))
}

/// Parse the leading integer of a `/proc/meminfo` value line — the
/// kibibyte count, ignoring the trailing `kB` unit.
fn parse_kib(rest: &str) -> Result<u64> {
    let token = rest
        .split_whitespace()
        .next()
        .ok_or(MinerAgentError::HeartbeatBuild("metrics"))?;
    token
        .parse()
        .map_err(|_| MinerAgentError::HeartbeatBuild("metrics"))
}

/// Kibibytes → mebibytes, saturating into `u32`.
fn kib_to_mib(kib: u64) -> u32 {
    let mib = kib / 1024;
    u32::try_from(mib).unwrap_or(u32::MAX)
}

/// Test [`MetricsSource`] — returns a fixed snapshot. Lets the
/// heartbeat builder tests run on any host with no `/proc`.
#[derive(Debug, Clone, Copy)]
pub struct MockMetricsSource {
    metrics: HostMetrics,
    /// When `true`, [`sample`](MetricsSource::sample) fails — drives
    /// the builder's metric-failure policy test.
    fail: bool,
}

impl MockMetricsSource {
    /// A mock that returns `metrics` for every sample.
    pub fn new(metrics: HostMetrics) -> Self {
        Self {
            metrics,
            fail: false,
        }
    }

    /// A mock whose every `sample` fails.
    pub fn failing() -> Self {
        Self {
            metrics: HostMetrics {
                cpu_load_1m_centi: 0,
                memory_total_mib: 0,
                memory_available_mib: 0,
            },
            fail: true,
        }
    }
}

impl Default for MockMetricsSource {
    fn default() -> Self {
        Self::new(HostMetrics {
            cpu_load_1m_centi: 125,
            memory_total_mib: 32_768,
            memory_available_mib: 24_000,
        })
    }
}

impl MetricsSource for MockMetricsSource {
    fn sample(&self) -> Result<HostMetrics> {
        if self.fail {
            Err(MinerAgentError::HeartbeatBuild("metrics"))
        } else {
            Ok(self.metrics)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loadavg_parses_to_centi_units() {
        assert_eq!(
            parse_loadavg_centi("0.75 0.42 0.31 1/512 12345").unwrap(),
            75
        );
        assert_eq!(parse_loadavg_centi("3.50 1.0 1.0 2/9 9").unwrap(), 350);
        assert_eq!(parse_loadavg_centi("0.00 0.0 0.0 1/1 1").unwrap(), 0);
    }

    #[test]
    fn loadavg_rejects_garbage() {
        assert!(parse_loadavg_centi("").is_err());
        assert!(parse_loadavg_centi("not-a-number 0 0").is_err());
        assert!(parse_loadavg_centi("-1.0 0 0").is_err());
    }

    #[test]
    fn meminfo_parses_total_and_available() {
        let raw = "MemTotal:       16331776 kB\n\
                   MemFree:         1048576 kB\n\
                   MemAvailable:   12058624 kB\n";
        let (total, avail) = parse_meminfo_mib(raw).unwrap();
        assert_eq!(total, 16_331_776 / 1024);
        assert_eq!(avail, 12_058_624 / 1024);
    }

    #[test]
    fn meminfo_rejects_missing_fields() {
        // No MemAvailable line.
        assert!(parse_meminfo_mib("MemTotal: 100 kB\n").is_err());
    }

    #[test]
    fn mock_source_returns_its_snapshot() {
        let m = HostMetrics {
            cpu_load_1m_centi: 200,
            memory_total_mib: 1024,
            memory_available_mib: 512,
        };
        assert_eq!(MockMetricsSource::new(m).sample().unwrap(), m);
    }

    #[test]
    fn failing_mock_source_errors() {
        assert!(matches!(
            MockMetricsSource::failing().sample(),
            Err(MinerAgentError::HeartbeatBuild("metrics"))
        ));
    }
}
