//! Agent configuration, resolved from the measured kernel command line.
//!
//! Every value is read from a `HIPPIUS_*` environment variable (dev /
//! explicit override) or, failing that, a `hippius.*=` token in
//! `/proc/cmdline`. The kernel command line is folded into the SNP
//! launch measurement, so a cmdline-sourced value is measurement-
//! covered — the same precedence the initramfs agent uses for its KBS
//! URL. Absent / malformed ⇒ fail closed (no defaults for identity or
//! the pinned KBS key).

use ed25519_dalek::VerifyingKey;

use crate::challenge::Challenge;
use crate::error::{Result, TelemetryError};

/// Length of an Ed25519 public key.
const KBS_VK_LEN: usize = 32;

/// Length of a validator challenge nonce.
const VALIDATOR_NONCE_LEN: usize = 32;

/// Default seconds between receipts when `HIPPIUS_RECEIPT_INTERVAL_SECS`
/// is unset.
const DEFAULT_INTERVAL_SECS: u64 = 60;

/// Default receipt time-to-live (`expiry = period_end + ttl`) when
/// `HIPPIUS_RECEIPT_TTL_SECS` is unset.
const DEFAULT_TTL_SECS: u64 = 3_600;

/// Upper bound on `observed_degradation_bps` — mirrors
/// `hippius_types::served_receipt::DEGRADATION_MAX_BPS`.
const DEGRADATION_MAX_BPS: u32 = 10_000;

/// Default host-side vsock port the PR-E2.3 pusher dials when
/// `HIPPIUS_VSOCK_PORT` is unset. The host miner-agent's MA-4 vsock
/// listener binds this port; it is a control-plane contract constant,
/// overridable for staging.
const DEFAULT_VSOCK_PORT: u32 = 5000;

/// Resolved agent configuration.
pub struct Config {
    /// Compute node identity — the miner's 32-byte §23 `node_id` (the
    /// raw bytes of its 64-hex `chain_node_id`). vali keys the
    /// `UsageAccrual` ledger + owed readout by `hex(node_id)`, so this
    /// MUST be the raw identity bytes, not an ASCII rendering of the hex.
    pub node_id: Vec<u8>,
    /// VM identity.
    pub vm_id: String,

    // ── PR-E2.2 receipt loop ────────────────────────────────────────
    /// The L1 billable lease this VM serves — bound into every receipt.
    pub lease_id: String,
    /// The miner family this node belongs to (opaque id bytes).
    pub family_id: Vec<u8>,
    /// The resource tier this VM serves at (e.g. `std`, `high-mem`).
    pub resource_class: String,
    /// Seconds between receipts. Each receipt covers one such window.
    pub interval_secs: u64,
    /// Receipt time-to-live: `expiry = period_end + receipt_ttl_secs`.
    pub receipt_ttl_secs: u64,
    /// The honest self-reported service degradation, in basis points
    /// (0 = full service). A static value in E2.2 — a later refinement
    /// reads it from local health signals.
    pub observed_degradation_bps: u32,
    /// The validator challenge to bind receipts to, if one is
    /// provisioned. `None` ⇒ the loop runs idle. Production challenges
    /// arrive over the Edge channel in PR-E2.3; until then this is an
    /// operator-injected staging affordance.
    pub challenge: Option<Challenge>,

    // ── PR-E2.3 vsock pusher ────────────────────────────────────────
    /// Host-side vsock port the receipt pusher dials — the port the
    /// host miner-agent's MA-4 listener binds. The CID is always
    /// `VMADDR_CID_HOST`; only the port is configurable.
    pub vsock_port: u32,

    // ── §23 telemetry key derivation ────────────────────────────────
    /// tmpfs path the §7 lifecycle key was released to (the measured
    /// cmdline's `hippius.lifecycle_key_path`). The telemetry signing
    /// key is HKDF-derived from that lifecycle seed, so vali (which
    /// generated it) can verify the guest's receipts without a second
    /// key exchange. NEVER on the miner-backed disk — a `/run` tmpfs path.
    pub lifecycle_key_path: String,
}

impl Config {
    /// Resolve the configuration. Returns `Err` on the first missing
    /// or malformed value — there is no partial / default config.
    pub fn resolve() -> Result<Self> {
        let cmdline = read_cmdline();
        let node_id_hex = resolve(&cmdline, "HIPPIUS_NODE_ID", "hippius.node_id")
            .ok_or(TelemetryError::Config("node-id-missing"))?;
        let node_id = hex::decode(node_id_hex.trim())
            .map_err(|_| TelemetryError::Config("node-id-not-hex"))?;
        if node_id.is_empty() {
            return Err(TelemetryError::Config("node-id-empty"));
        }
        let vm_id = resolve(&cmdline, "HIPPIUS_VM_ID", "hippius.vm_id")
            .ok_or(TelemetryError::Config("vm-id-missing"))?;

        // §23 — the telemetry signing key is HKDF-derived from the §7
        // lifecycle key (see `establish`); the guest no longer performs
        // the old in-guest-generate + `/v1/kbs/telemetry-cert` exchange,
        // so `kbs_url` / `kbs_vk` / `kbs_kid` are no longer required.

        // ── PR-E2.2 receipt-loop configuration ──────────────────────
        // Identity fields — required, no defaults (a receipt without
        // them attests nothing meaningful).
        let lease_id = resolve(&cmdline, "HIPPIUS_LEASE_ID", "hippius.lease_id")
            .ok_or(TelemetryError::Config("lease-id-missing"))?;
        let resource_class = resolve(&cmdline, "HIPPIUS_RESOURCE_CLASS", "hippius.resource_class")
            .ok_or(TelemetryError::Config("resource-class-missing"))?;
        let family_id_hex = resolve(&cmdline, "HIPPIUS_FAMILY_ID", "hippius.family_id")
            .ok_or(TelemetryError::Config("family-id-missing"))?;
        let family_id = hex::decode(family_id_hex.trim())
            .map_err(|_| TelemetryError::Config("family-id-not-hex"))?;
        if family_id.is_empty() {
            return Err(TelemetryError::Config("family-id-empty"));
        }

        // Loop tuning — defaulted, overridable.
        let interval_secs = resolve_u64(
            &cmdline,
            "HIPPIUS_RECEIPT_INTERVAL_SECS",
            "hippius.receipt_interval_secs",
            DEFAULT_INTERVAL_SECS,
            "receipt-interval-not-u64",
        )?;
        if interval_secs == 0 {
            // A zero interval would spin the loop and produce a
            // non-advancing (zero-length) receipt window.
            return Err(TelemetryError::Config("receipt-interval-zero"));
        }
        let receipt_ttl_secs = resolve_u64(
            &cmdline,
            "HIPPIUS_RECEIPT_TTL_SECS",
            "hippius.receipt_ttl_secs",
            DEFAULT_TTL_SECS,
            "receipt-ttl-not-u64",
        )?;

        let observed_degradation_bps = resolve_u32(
            &cmdline,
            "HIPPIUS_OBSERVED_DEGRADATION_BPS",
            "hippius.observed_degradation_bps",
            0,
            "observed-degradation-not-u32",
        )?;
        if observed_degradation_bps > DEGRADATION_MAX_BPS {
            return Err(TelemetryError::Config("observed-degradation-out-of-range"));
        }

        // Optional validator challenge (all three values, or none).
        let challenge = resolve_challenge(&cmdline)?;

        // PR-E2.3 — host vsock port. Defaulted + overridable; a zero
        // port is not a valid vsock port and fails closed.
        let vsock_port = resolve_u32(
            &cmdline,
            "HIPPIUS_VSOCK_PORT",
            "hippius.vsock_port",
            DEFAULT_VSOCK_PORT,
            "vsock-port-not-u32",
        )?;
        if vsock_port == 0 {
            return Err(TelemetryError::Config("vsock-port-zero"));
        }

        // §23 — the lifecycle key path the telemetry key is derived from.
        // Same measured-cmdline token the lifecycle agent reads.
        let lifecycle_key_path = resolve(
            &cmdline,
            "HIPPIUS_LIFECYCLE_KEY_PATH",
            "hippius.lifecycle_key_path",
        )
        .ok_or(TelemetryError::Config("lifecycle-key-path-missing"))?;

        Ok(Config {
            node_id,
            vm_id,
            lease_id,
            family_id,
            resource_class,
            interval_secs,
            receipt_ttl_secs,
            observed_degradation_bps,
            challenge,
            vsock_port,
            lifecycle_key_path,
        })
    }
}

/// Resolve an optional `u64`, falling back to `default` when unset.
/// A present-but-unparseable value fails closed.
fn resolve_u64(
    cmdline: &str,
    env: &str,
    cmdline_key: &str,
    default: u64,
    err: &'static str,
) -> Result<u64> {
    match resolve(cmdline, env, cmdline_key) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse::<u64>()
            .map_err(|_| TelemetryError::Config(err)),
    }
}

/// Resolve an optional `u32`, falling back to `default` when unset.
/// A present-but-unparseable value fails closed.
fn resolve_u32(
    cmdline: &str,
    env: &str,
    cmdline_key: &str,
    default: u32,
    err: &'static str,
) -> Result<u32> {
    match resolve(cmdline, env, cmdline_key) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse::<u32>()
            .map_err(|_| TelemetryError::Config(err)),
    }
}

/// Resolve the optional validator challenge.
///
/// Either all three values (`validator_id`, `validator_nonce`, `epoch`)
/// are present — yielding `Some` — or none are — yielding `None`. A
/// PARTIAL set is a misconfiguration and fails closed: a receipt loop
/// must never run against a half-specified challenge.
fn resolve_challenge(cmdline: &str) -> Result<Option<Challenge>> {
    let validator_id = resolve(cmdline, "HIPPIUS_VALIDATOR_ID", "hippius.validator_id");
    let validator_nonce = resolve(
        cmdline,
        "HIPPIUS_VALIDATOR_NONCE",
        "hippius.validator_nonce",
    );
    let epoch = resolve(
        cmdline,
        "HIPPIUS_TELEMETRY_EPOCH",
        "hippius.telemetry_epoch",
    );
    match (validator_id, validator_nonce, epoch) {
        (None, None, None) => Ok(None),
        (Some(id_hex), Some(nonce_hex), Some(epoch_str)) => {
            let validator_id = hex::decode(id_hex.trim())
                .map_err(|_| TelemetryError::Config("validator-id-not-hex"))?;
            if validator_id.is_empty() {
                return Err(TelemetryError::Config("validator-id-empty"));
            }
            let nonce_bytes = hex::decode(nonce_hex.trim())
                .map_err(|_| TelemetryError::Config("validator-nonce-not-hex"))?;
            let validator_nonce: [u8; VALIDATOR_NONCE_LEN] = nonce_bytes
                .as_slice()
                .try_into()
                .map_err(|_| TelemetryError::Config("validator-nonce-length"))?;
            let epoch = epoch_str
                .trim()
                .parse::<u64>()
                .map_err(|_| TelemetryError::Config("telemetry-epoch-not-u64"))?;
            Ok(Some(Challenge {
                validator_id,
                validator_nonce,
                epoch,
            }))
        }
        // Any partial combination — fail closed.
        _ => Err(TelemetryError::Config("challenge-partial")),
    }
}

/// Decode the pinned KBS verifying key from a 64-hex-char string.
pub fn decode_kbs_vk(hex_str: &str) -> Result<VerifyingKey> {
    let bytes =
        hex::decode(hex_str.trim()).map_err(|_| TelemetryError::Config("kbs-vk-not-hex"))?;
    let arr: [u8; KBS_VK_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| TelemetryError::Config("kbs-vk-length"))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| TelemetryError::Config("kbs-vk-invalid"))
}

/// Read `/proc/cmdline`, or `""` if it cannot be read (a non-Linux dev
/// host). Callers fall back to env vars, so an empty cmdline is fine.
fn read_cmdline() -> String {
    std::fs::read_to_string("/proc/cmdline").unwrap_or_default()
}

/// Resolve one value: the `env` var first (non-empty), else the
/// `cmdline_key=` token in `cmdline`. An empty value counts as absent.
/// Pure (takes `cmdline`) so it is unit-testable without `/proc`.
pub fn resolve(cmdline: &str, env: &str, cmdline_key: &str) -> Option<String> {
    if let Ok(v) = std::env::var(env) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    let prefix = format!("{cmdline_key}=");
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix(&prefix))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn resolve_reads_the_cmdline_token() {
        let line = "ro quiet hippius.vm_id=vm-7 console=ttyS0";
        assert_eq!(
            resolve(line, "HIPPIUS_TEST_ABSENT_VM", "hippius.vm_id").as_deref(),
            Some("vm-7")
        );
        assert_eq!(
            resolve(
                "ro quiet console=ttyS0",
                "HIPPIUS_TEST_ABSENT_VM",
                "hippius.vm_id"
            ),
            None
        );
        // An empty cmdline value counts as absent.
        assert_eq!(
            resolve("hippius.vm_id=", "HIPPIUS_TEST_ABSENT_VM", "hippius.vm_id"),
            None
        );
    }

    #[test]
    fn decode_kbs_vk_accepts_a_valid_key_and_rejects_garbage() {
        // A valid Ed25519 point: the public key of seed [7; 32].
        let vk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let hex_str = hex::encode(vk.to_bytes());
        assert_eq!(decode_kbs_vk(&hex_str).unwrap().to_bytes(), vk.to_bytes());

        assert!(decode_kbs_vk("zznothex").is_err());
        assert!(decode_kbs_vk("00").is_err()); // wrong length
    }

    #[test]
    fn resolve_u64_defaults_when_absent_and_parses_when_present() {
        // Absent ⇒ default.
        assert_eq!(
            resolve_u64(
                "ro quiet",
                "HIPPIUS_TEST_ABSENT_U64",
                "hippius.iv",
                60,
                "iv-err"
            )
            .unwrap(),
            60
        );
        // Present ⇒ parsed.
        assert_eq!(
            resolve_u64(
                "hippius.iv=120",
                "HIPPIUS_TEST_ABSENT_U64",
                "hippius.iv",
                60,
                "iv-err"
            )
            .unwrap(),
            120
        );
        // Present but unparseable ⇒ fail closed with the given class.
        let err = resolve_u64(
            "hippius.iv=lots",
            "HIPPIUS_TEST_ABSENT_U64",
            "hippius.iv",
            60,
            "iv-err",
        )
        .expect_err("a non-numeric value must fail");
        assert_eq!(err.class(), "iv-err");
    }

    #[test]
    fn resolve_challenge_none_when_fully_absent() {
        assert!(resolve_challenge("ro quiet console=ttyS0")
            .unwrap()
            .is_none());
    }

    #[test]
    fn resolve_challenge_some_when_fully_present() {
        let nonce_hex = "01".repeat(32); // 32 bytes
        let line = format!(
            "hippius.validator_id=abcd hippius.validator_nonce={nonce_hex} \
             hippius.telemetry_epoch=12"
        );
        let ch = resolve_challenge(&line)
            .unwrap()
            .expect("all three values present ⇒ Some");
        assert_eq!(ch.validator_id, vec![0xab, 0xcd]);
        assert_eq!(ch.validator_nonce, [1u8; 32]);
        assert_eq!(ch.epoch, 12);
    }

    #[test]
    fn resolve_challenge_partial_fails_closed() {
        // Only validator_id — a half-specified challenge is a misconfig.
        let err = resolve_challenge("hippius.validator_id=abcd")
            .expect_err("a partial challenge must fail closed");
        assert_eq!(err.class(), "challenge-partial");
    }

    #[test]
    fn resolve_challenge_rejects_a_wrong_length_nonce() {
        let line =
            "hippius.validator_id=abcd hippius.validator_nonce=0011 hippius.telemetry_epoch=1";
        let err = resolve_challenge(line).expect_err("a 2-byte nonce is not 32 bytes");
        assert_eq!(err.class(), "validator-nonce-length");
    }
}
