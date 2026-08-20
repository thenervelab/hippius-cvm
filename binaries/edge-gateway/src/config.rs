//! Operator-facing config for the Edge Gateway (PR-H3, §10).
//!
//! Everything tunable from the runbook lives here:
//!
//! - [`RateLimitConfig`] — per-source token bucket (refill rate, burst).
//! - [`EdgeGatewayConfig::queue_capacity`] — bounded validate→forward
//!   queue depth. When the queue is full, validated envelopes are
//!   dropped at the wire (§10) — Edge does NOT respond to the source
//!   (opaque relay, §5.6).
//! - [`EdgeGatewayConfig::idle_horizon_secs`] — inactivity horizon
//!   after which a per-source bucket is GC'd. The default (1h) bounds
//!   the bucket map under the "spawn millions of fake source IPs"
//!   DoS vector.
//!
//! Source order, picked deliberately small:
//! 1. `EDGE_GATEWAY_CONFIG` env var set → read file as TOML.
//! 2. Otherwise → `Default::default()`.
//!
//! No CLI flags, no merged-overlays. Operator runbook lives in
//! one place (the TOML), the binary either uses it or runs on the
//! baked-in defaults.

use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

/// Env var the binary reads at startup. Absent ⇒ defaults. Empty ⇒
/// defaults (treat as if unset, so `EDGE_GATEWAY_CONFIG=` doesn't
/// accidentally feed `""` into the path code).
pub const CONFIG_ENV: &str = "EDGE_GATEWAY_CONFIG";

/// Token-bucket parameters per source IP. Defaults per the PR-H3 brief
/// (50 sustained, burst 100). Re-used by [`crate::rate_limit::PerSourceRateLimiter`].
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Sustained refill rate, tokens per second.
    #[serde(default = "default_refill_per_sec")]
    pub refill_per_sec: f64,
    /// Maximum bucket capacity (initial + cap). Burst tokens.
    #[serde(default = "default_burst")]
    pub burst: u32,
}

fn default_refill_per_sec() -> f64 {
    50.0
}
fn default_burst() -> u32 {
    100
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            refill_per_sec: default_refill_per_sec(),
            burst: default_burst(),
        }
    }
}

/// In-cluster forward endpoints (PR-H8). The miner-facing router
/// relays a validated envelope's body to one of these base URLs,
/// selected by [`crate::pipeline::MessageKind`]. The defaults are the
/// cluster-DNS names of the KBS and vali services; an operator can
/// override them (a staging cluster, a different namespace) via the
/// `[forward]` TOML table.
///
/// These are **base** URLs — [`crate::forward`] appends the fixed
/// inner-plane paths (`/v1/kbs/release`, the vali telemetry / lifecycle
/// ingress routes). There is NO mTLS on the forward leg: the Cilium
/// NetworkPolicy is the who-calls-who control (Edge egress is scoped
/// to the `kbs` + `vali` namespaces).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    /// Base URL of the in-cluster KBS server. `KbsRequest` envelopes
    /// are relayed here.
    #[serde(default = "default_kbs_endpoint")]
    pub kbs_endpoint: String,
    /// Base URL of the in-cluster vali service. `ServedReceipt`,
    /// `ServedAggregate`, and `StoppedAck` envelopes are relayed here.
    #[serde(default = "default_vali_endpoint")]
    pub vali_endpoint: String,
}

fn default_kbs_endpoint() -> String {
    "http://kbs-server.kbs.svc.cluster.local:8000".to_string()
}
fn default_vali_endpoint() -> String {
    "http://vali.vali.svc.cluster.local:8000".to_string()
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            kbs_endpoint: default_kbs_endpoint(),
            vali_endpoint: default_vali_endpoint(),
        }
    }
}

/// Top-level config. Loaded from TOML; missing fields fall back to
/// the `Default::default()` value via `#[serde(default = "...")]`,
/// so a partial TOML (only `[rate_limit]`, or only `queue_capacity`,
/// or empty `{}`) is accepted.
///
/// PR-H8 added the `[forward]` table; its `String` endpoint fields
/// mean the struct is no longer `Copy` (it was through PR-H7).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeGatewayConfig {
    /// Per-source rate limiter cfg.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// In-cluster forward endpoints (PR-H8).
    #[serde(default)]
    pub forward: ForwardConfig,

    /// Capacity of the bounded validate→forward queue.
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: usize,

    /// How long a per-source bucket may sit idle before GC drops it.
    /// Expressed in seconds in TOML so the file stays human-edit
    /// friendly; converted via [`Self::idle_horizon`] before use.
    #[serde(default = "default_idle_horizon_secs")]
    pub idle_horizon_secs: u64,

    /// Hard upper bound on the per-source bucket map. Codex review
    /// of PR-H3 flagged the unbounded-growth window: GC removes
    /// dormant entries every 4096 calls, but a unique-IP flood
    /// within the idle horizon could fill memory linearly before
    /// the first sweep. With `max_tracked_peers` set, the limiter
    /// evicts the **oldest-`last_seen`** bucket on insertion at
    /// cap — the bucket map can never exceed this size. Defaults
    /// to 65,536 (plenty for any legitimate vRack peer load, but
    /// hard-bounds memory at ~6 MiB of `Bucket` records).
    #[serde(default = "default_max_tracked_peers")]
    pub max_tracked_peers: usize,
}

fn default_queue_capacity() -> usize {
    1024
}
fn default_idle_horizon_secs() -> u64 {
    3600
}
fn default_max_tracked_peers() -> usize {
    65_536
}

impl Default for EdgeGatewayConfig {
    fn default() -> Self {
        Self {
            rate_limit: RateLimitConfig::default(),
            forward: ForwardConfig::default(),
            queue_capacity: default_queue_capacity(),
            idle_horizon_secs: default_idle_horizon_secs(),
            max_tracked_peers: default_max_tracked_peers(),
        }
    }
}

impl EdgeGatewayConfig {
    /// Convert the `u64` seconds to a `Duration` for the limiter.
    pub fn idle_horizon(&self) -> Duration {
        Duration::from_secs(self.idle_horizon_secs)
    }

    /// Parse a TOML string into a config and validate semantics. A
    /// successfully-returned `Self` is safe to feed straight into
    /// `bounded_queue` / `PerSourceRateLimiter` — no further range
    /// checks needed downstream.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let parsed: Self = toml::from_str(s).map_err(|_| ConfigError::Parse)?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Range-check the config. Catches the pathologies flagged by
    /// the PR-H3 reviewer pair: `queue_capacity = 0` panics
    /// `tokio::mpsc::channel`; `burst = 0` means no traffic ever
    /// passes; negative / non-finite `refill_per_sec` would corrupt
    /// the bucket math; `idle_horizon_secs = 0` evicts every bucket
    /// the moment GC fires; `max_tracked_peers = 0` makes the
    /// limiter unusable. All static-classifier errors.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.queue_capacity == 0 {
            return Err(ConfigError::Invalid("queue-capacity-zero"));
        }
        if self.idle_horizon_secs == 0 {
            return Err(ConfigError::Invalid("idle-horizon-zero"));
        }
        if self.max_tracked_peers == 0 {
            return Err(ConfigError::Invalid("max-tracked-peers-zero"));
        }
        if self.rate_limit.burst == 0 {
            return Err(ConfigError::Invalid("burst-zero"));
        }
        if !self.rate_limit.refill_per_sec.is_finite() || self.rate_limit.refill_per_sec < 0.0 {
            return Err(ConfigError::Invalid("refill-rate-invalid"));
        }
        // PR-H8: a blank forward endpoint would build a `reqwest`
        // request against an empty base URL — fail-closed at config
        // load rather than at the first relayed envelope.
        if self.forward.kbs_endpoint.trim().is_empty() {
            return Err(ConfigError::Invalid("kbs-endpoint-empty"));
        }
        if self.forward.vali_endpoint.trim().is_empty() {
            return Err(ConfigError::Invalid("vali-endpoint-empty"));
        }
        Ok(())
    }

    /// Load the config from the path in `EDGE_GATEWAY_CONFIG`. If the
    /// env var is unset or empty, returns `Default::default()` (which
    /// is by construction valid — defaults are sanity-checked by the
    /// `defaults_pass_validation` unit test below).
    pub fn load_from_env() -> Result<Self, ConfigError> {
        match std::env::var(CONFIG_ENV) {
            Ok(p) if !p.is_empty() => Self::load_from_path(Path::new(&p)),
            _ => Ok(Self::default()),
        }
    }

    fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|_| ConfigError::Read)?;
        Self::from_toml_str(&raw)
    }
}

/// Stable static-classifier errors. Same `&'static str`-only `Display`
/// discipline as [`crate::pipeline::EdgeError`] — production audit
/// (PR-H6) keys on these.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config-read")]
    Read,
    #[error("config-parse")]
    Parse,
    /// PR-H3 review: semantic validation. Inner `&'static str` is a
    /// stable category (see [`EdgeGatewayConfig::validate`]); the
    /// `Display` impl renders ONLY the outer class, not the inner
    /// string — same as `SchemaInvalid` in `EdgeError`.
    #[error("config-invalid")]
    Invalid(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_pr_h3_brief() {
        let c = EdgeGatewayConfig::default();
        assert!((c.rate_limit.refill_per_sec - 50.0).abs() < f64::EPSILON);
        assert_eq!(c.rate_limit.burst, 100);
        assert_eq!(c.queue_capacity, 1024);
        assert_eq!(c.idle_horizon_secs, 3600);
        assert_eq!(c.max_tracked_peers, 65_536);
        assert_eq!(c.idle_horizon(), Duration::from_secs(3600));
    }

    #[test]
    fn defaults_pass_validation() {
        EdgeGatewayConfig::default()
            .validate()
            .expect("default config must validate");
    }

    #[test]
    fn zero_queue_capacity_is_rejected() {
        // Codex flag: `queue_capacity = 0` panics `tokio::mpsc::channel`
        // at boot. Must fail config validation.
        let err = EdgeGatewayConfig::from_toml_str("queue_capacity = 0").unwrap_err();
        assert!(
            matches!(err, ConfigError::Invalid("queue-capacity-zero")),
            "got {err:?}"
        );
    }

    #[test]
    fn zero_burst_is_rejected() {
        let err = EdgeGatewayConfig::from_toml_str(
            r#"
            [rate_limit]
            refill_per_sec = 1.0
            burst = 0
            "#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::Invalid("burst-zero")),
            "got {err:?}"
        );
    }

    #[test]
    fn zero_idle_horizon_is_rejected() {
        let err = EdgeGatewayConfig::from_toml_str("idle_horizon_secs = 0").unwrap_err();
        assert!(
            matches!(err, ConfigError::Invalid("idle-horizon-zero")),
            "got {err:?}"
        );
    }

    #[test]
    fn zero_max_tracked_peers_is_rejected() {
        let err = EdgeGatewayConfig::from_toml_str("max_tracked_peers = 0").unwrap_err();
        assert!(
            matches!(err, ConfigError::Invalid("max-tracked-peers-zero")),
            "got {err:?}"
        );
    }

    #[test]
    fn negative_refill_rate_is_rejected() {
        let err = EdgeGatewayConfig::from_toml_str(
            r#"
            [rate_limit]
            refill_per_sec = -1.0
            burst = 1
            "#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::Invalid("refill-rate-invalid")),
            "got {err:?}"
        );
    }

    #[test]
    fn nan_refill_rate_is_rejected() {
        // Constructed in code, not TOML — TOML doesn't have a NaN
        // literal. Pin the validator independently so a future
        // alternative loader (env var, k8s configmap) can't sneak
        // NaN past.
        let mut c = EdgeGatewayConfig::default();
        c.rate_limit.refill_per_sec = f64::NAN;
        assert!(matches!(
            c.validate().unwrap_err(),
            ConfigError::Invalid("refill-rate-invalid")
        ));
    }

    #[test]
    fn config_invalid_display_is_static() {
        // PR-H3 reviewer pin: ConfigError::Invalid renders ONLY the
        // outer class, never the inner classifier — same as
        // `EdgeError::SchemaInvalid`.
        let err = ConfigError::Invalid("queue-capacity-zero");
        assert_eq!(err.to_string(), "config-invalid");
    }

    #[test]
    fn empty_toml_uses_defaults() {
        let c = EdgeGatewayConfig::from_toml_str("").unwrap();
        let d = EdgeGatewayConfig::default();
        assert_eq!(c.queue_capacity, d.queue_capacity);
        assert_eq!(c.rate_limit.burst, d.rate_limit.burst);
        assert_eq!(c.idle_horizon_secs, d.idle_horizon_secs);
    }

    #[test]
    fn partial_toml_only_rate_limit() {
        let c = EdgeGatewayConfig::from_toml_str(
            r#"
            [rate_limit]
            refill_per_sec = 10.0
            burst = 20
            "#,
        )
        .unwrap();
        assert!((c.rate_limit.refill_per_sec - 10.0).abs() < f64::EPSILON);
        assert_eq!(c.rate_limit.burst, 20);
        // Other fields fall back to default.
        assert_eq!(c.queue_capacity, 1024);
        assert_eq!(c.idle_horizon_secs, 3600);
    }

    #[test]
    fn full_toml_roundtrip() {
        let c = EdgeGatewayConfig::from_toml_str(
            r#"
            queue_capacity = 64
            idle_horizon_secs = 60

            [rate_limit]
            refill_per_sec = 1.5
            burst = 3
            "#,
        )
        .unwrap();
        assert_eq!(c.queue_capacity, 64);
        assert_eq!(c.idle_horizon_secs, 60);
        assert!((c.rate_limit.refill_per_sec - 1.5).abs() < f64::EPSILON);
        assert_eq!(c.rate_limit.burst, 3);
    }

    #[test]
    fn unknown_field_is_rejected() {
        // `deny_unknown_fields` prevents typo'd / leftover config
        // keys from being silently ignored. Catches drift between
        // the runbook and the binary at parse time.
        let err = EdgeGatewayConfig::from_toml_str("nonsense_key = 1").unwrap_err();
        assert!(matches!(err, ConfigError::Parse));
    }

    #[test]
    fn unknown_field_in_rate_limit_is_rejected() {
        let err = EdgeGatewayConfig::from_toml_str(
            r#"
            [rate_limit]
            refill_per_sec = 1.0
            burst = 1
            mystery = "x"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Parse));
    }

    #[test]
    fn malformed_toml_is_parse_error() {
        let err = EdgeGatewayConfig::from_toml_str("queue_capacity = ").unwrap_err();
        assert!(matches!(err, ConfigError::Parse));
        assert_eq!(err.to_string(), "config-parse");
    }

    #[test]
    fn forward_defaults_are_cluster_dns() {
        // PR-H8: absent a `[forward]` table, the endpoints fall back
        // to the in-cluster service DNS names.
        let c = EdgeGatewayConfig::default();
        assert_eq!(
            c.forward.kbs_endpoint,
            "http://kbs-server.kbs.svc.cluster.local:8000"
        );
        assert_eq!(
            c.forward.vali_endpoint,
            "http://vali.vali.svc.cluster.local:8000"
        );
    }

    #[test]
    fn forward_block_overrides_endpoints() {
        let c = EdgeGatewayConfig::from_toml_str(
            r#"
            [forward]
            kbs_endpoint = "http://kbs.staging:9000"
            vali_endpoint = "http://vali.staging:9000"
            "#,
        )
        .unwrap();
        assert_eq!(c.forward.kbs_endpoint, "http://kbs.staging:9000");
        assert_eq!(c.forward.vali_endpoint, "http://vali.staging:9000");
    }

    #[test]
    fn blank_forward_endpoint_is_rejected() {
        let err = EdgeGatewayConfig::from_toml_str(
            r#"
            [forward]
            kbs_endpoint = "  "
            "#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::Invalid("kbs-endpoint-empty")),
            "got {err:?}"
        );
    }
}
