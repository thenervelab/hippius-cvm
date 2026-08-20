//! Agent configuration, resolved from the measured kernel command line.
//!
//! Every value is read from a `HIPPIUS_*` environment variable (dev /
//! explicit override) or, failing that, a `hippius.*=` token in
//! `/proc/cmdline`. The kernel command line is folded into the SNP launch
//! measurement, so a cmdline-sourced value is measurement-covered — the
//! same precedence the sibling agents use. Absent / malformed ⇒ fail
//! closed (no defaults for identity or the replay domains).

use hippius_types::host_attestor::DIGEST_LEN;

use crate::error::{HostAttestorError, Result};

/// Default seconds between beacons when `HIPPIUS_BEACON_INTERVAL_SECS`
/// is unset.
const DEFAULT_INTERVAL_SECS: u64 = 60;

/// Default beacon window (`expiry = observed + window`) when
/// `HIPPIUS_BEACON_WINDOW_SECS` is unset — a beacon is valid for five
/// minutes, comfortably longer than the one-minute beat.
const DEFAULT_WINDOW_SECS: u64 = 300;

/// Default seconds between periodic **re-enrollments** when
/// `HIPPIUS_ENROLL_INTERVAL_SECS` is unset — hourly, matching the design's
/// "per boot + HOURLY" enrollment intent. The KBS-minted enrollment cert
/// (`SignedHostAttestorCert`) has a 2 h TTL, so re-enrolling every hour
/// re-mints a fresh cert comfortably before the old one expires and the
/// vali `HostAttestor` row would flip `attested` → `expired`.
const DEFAULT_ENROLL_INTERVAL_SECS: u64 = 3600;

/// Hard ceiling on the re-enroll interval. The KBS cert lives 2 h
/// (`HOST_ATTESTOR_CERT_TTL_SECS`); a re-enroll interval at or above the
/// TTL would let the cert lapse between refreshes, so any value above this
/// margin (90 min — comfortably under 2 h, leaving room for one missed
/// tick + the vsock round-trip) is rejected fail-closed. A per-boot
/// misconfiguration must not silently un-attest the host.
const MAX_ENROLL_INTERVAL_SECS: u64 = 5400;

// Compile-time invariants: the default re-enroll interval stays comfortably
// below the ceiling, which itself stays comfortably below the 2 h (7200 s)
// KBS cert TTL — so a fresh cert is always minted before the old one
// expires (even allowing for one missed tick + the vsock round-trip).
const _: () = assert!(DEFAULT_ENROLL_INTERVAL_SECS < MAX_ENROLL_INTERVAL_SECS);
const _: () = assert!(MAX_ENROLL_INTERVAL_SECS < 2 * 60 * 60);

/// Default host-side vsock port the enrollment + beacon pusher dials when
/// `HIPPIUS_VSOCK_PORT` is unset — the miner-agent's host-attestor
/// enroll/beacon UP-relay listener binds it (PR-10b-S2a). A frozen wire
/// constant, overridable for staging. Distinct from the tenant relay port
/// (`5000`) and the nonce-challenge port.
const DEFAULT_VSOCK_PORT: u32 = hippius_types::host_attestor_challenge::ENROLL_BEACON_PORT;

/// Default host-side vsock port the enrollment nonce-challenge client dials
/// when `HIPPIUS_CHALLENGE_VSOCK_PORT` is unset — the miner-agent's
/// host-attestor challenge listener binds it (PR-10). A frozen wire
/// constant, overridable for staging.
const DEFAULT_CHALLENGE_VSOCK_PORT: u32 = hippius_types::host_attestor_challenge::CHALLENGE_PORT;

/// The kernel's per-boot UUID — the natural `boot_id` source when none
/// is supplied via env / cmdline.
const KERNEL_BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// Resolved agent configuration.
///
/// ## No `node_id` here (PR-10b-S2a)
///
/// The host `node_id` is deliberately NOT resolved from the measured
/// kernel cmdline: a per-node cmdline token would fold into the SNP launch
/// measurement, giving each node a distinct measurement and breaking the
/// fleet-wide operator-pinned host-attestor measurement (must-have #1).
/// The `node_id` is delivered at runtime over the vali nonce-challenge
/// response ([`crate::challenge::HostChallenge`]) instead — vali stamps it
/// from the miner's authenticated mTLS peer identity.
pub struct Config {
    /// Opaque per-boot identifier — a fresh enrollment per boot so a
    /// stale enrollment cannot be replayed. Sourced from env / cmdline,
    /// else the kernel's per-boot UUID.
    pub boot_id: String,
    /// SHA-256 of the substrate compute-chain genesis hash — a beacon
    /// replay domain across forks.
    pub chain_genesis: [u8; DIGEST_LEN],
    /// Compute-pallet instance discriminator — a beacon replay domain
    /// across deployments of the same pallet on one chain.
    pub pallet_instance: [u8; DIGEST_LEN],
    /// Seconds between beacons.
    pub interval_secs: u64,
    /// Beacon window: `expiry = observed + window_secs`.
    pub window_secs: u64,
    /// Seconds between periodic re-enrollments — a fresh challenge → fresh
    /// SNP report → fresh KBS cert, keeping the vali row `attested` before
    /// the 2 h cert TTL lapses. Defaults to hourly (fleet-wide constant, so
    /// defaulting it keeps the measured cmdline — and thus the pinned
    /// measurement — unchanged). Comfortably below the cert TTL.
    pub enroll_interval_secs: u64,
    /// Host-side vsock port the pusher dials.
    pub vsock_port: u32,
    /// Host-side vsock port the enrollment nonce-challenge client dials
    /// (PR-10). The miner-agent's host-attestor challenge listener binds
    /// it; the fresh vali-minted enrollment nonce is pulled over it.
    pub challenge_vsock_port: u32,
}

impl Config {
    /// Resolve the configuration. Returns `Err` on the first missing or
    /// malformed value — there is no partial / default identity config.
    pub fn resolve() -> Result<Self> {
        let cmdline = read_cmdline();

        // NOTE: `node_id` is intentionally NOT resolved here — it arrives
        // over the vali challenge response (see the struct docs). Sourcing
        // it from the measured cmdline would break the fleet-pinned
        // measurement.
        let boot_id = resolve_boot_id(&cmdline)?;

        let chain_genesis = resolve_digest(
            &cmdline,
            "HIPPIUS_CHAIN_GENESIS",
            "hippius.chain_genesis",
            "chain-genesis",
        )?;
        let pallet_instance = resolve_digest(
            &cmdline,
            "HIPPIUS_PALLET_INSTANCE",
            "hippius.pallet_instance",
            "pallet-instance",
        )?;

        let interval_secs = resolve_u64(
            &cmdline,
            "HIPPIUS_BEACON_INTERVAL_SECS",
            "hippius.beacon_interval_secs",
            DEFAULT_INTERVAL_SECS,
            "beacon-interval-not-u64",
        )?;
        if interval_secs == 0 {
            return Err(HostAttestorError::Config("beacon-interval-zero"));
        }

        let window_secs = resolve_u64(
            &cmdline,
            "HIPPIUS_BEACON_WINDOW_SECS",
            "hippius.beacon_window_secs",
            DEFAULT_WINDOW_SECS,
            "beacon-window-not-u64",
        )?;
        if window_secs == 0 {
            return Err(HostAttestorError::Config("beacon-window-zero"));
        }

        let enroll_interval_secs = resolve_u64(
            &cmdline,
            "HIPPIUS_ENROLL_INTERVAL_SECS",
            "hippius.enroll_interval_secs",
            DEFAULT_ENROLL_INTERVAL_SECS,
            "enroll-interval-not-u64",
        )?;
        if enroll_interval_secs == 0 {
            return Err(HostAttestorError::Config("enroll-interval-zero"));
        }
        // Reject an interval that would let the 2 h cert TTL lapse between
        // refreshes — fail-closed rather than silently un-attest the host.
        if enroll_interval_secs > MAX_ENROLL_INTERVAL_SECS {
            return Err(HostAttestorError::Config("enroll-interval-too-long"));
        }

        let vsock_port = resolve_u32(
            &cmdline,
            "HIPPIUS_VSOCK_PORT",
            "hippius.vsock_port",
            DEFAULT_VSOCK_PORT,
            "vsock-port-not-u32",
        )?;
        if vsock_port == 0 {
            return Err(HostAttestorError::Config("vsock-port-zero"));
        }

        let challenge_vsock_port = resolve_u32(
            &cmdline,
            "HIPPIUS_CHALLENGE_VSOCK_PORT",
            "hippius.challenge_vsock_port",
            DEFAULT_CHALLENGE_VSOCK_PORT,
            "challenge-vsock-port-not-u32",
        )?;
        if challenge_vsock_port == 0 {
            return Err(HostAttestorError::Config("challenge-vsock-port-zero"));
        }

        Ok(Config {
            boot_id,
            chain_genesis,
            pallet_instance,
            interval_secs,
            window_secs,
            enroll_interval_secs,
            vsock_port,
            challenge_vsock_port,
        })
    }
}

/// Resolve the per-boot id: env / cmdline first, else the kernel's
/// per-boot UUID. Fails closed if neither yields a non-empty value.
fn resolve_boot_id(cmdline: &str) -> Result<String> {
    if let Some(id) = resolve(cmdline, "HIPPIUS_BOOT_ID", "hippius.boot_id") {
        return Ok(id);
    }
    let kernel = std::fs::read_to_string(KERNEL_BOOT_ID_PATH)
        .map_err(|_| HostAttestorError::Config("boot-id-missing"))?;
    let trimmed = kernel.trim();
    if trimmed.is_empty() {
        return Err(HostAttestorError::Config("boot-id-empty"));
    }
    Ok(trimmed.to_string())
}

/// Resolve a required 32-byte digest from a 64-hex-char value.
fn resolve_digest(
    cmdline: &str,
    env: &str,
    cmdline_key: &str,
    what: &'static str,
) -> Result<[u8; DIGEST_LEN]> {
    let hex_str = resolve(cmdline, env, cmdline_key).ok_or(match what {
        "chain-genesis" => HostAttestorError::Config("chain-genesis-missing"),
        _ => HostAttestorError::Config("pallet-instance-missing"),
    })?;
    let bytes = hex::decode(hex_str.trim()).map_err(|_| match what {
        "chain-genesis" => HostAttestorError::Config("chain-genesis-not-hex"),
        _ => HostAttestorError::Config("pallet-instance-not-hex"),
    })?;
    <[u8; DIGEST_LEN]>::try_from(bytes.as_slice()).map_err(|_| match what {
        "chain-genesis" => HostAttestorError::Config("chain-genesis-length"),
        _ => HostAttestorError::Config("pallet-instance-length"),
    })
}

/// Resolve an optional `u64`, falling back to `default` when unset. A
/// present-but-unparseable value fails closed.
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
            .map_err(|_| HostAttestorError::Config(err)),
    }
}

/// Resolve an optional `u32`, falling back to `default` when unset. A
/// present-but-unparseable value fails closed.
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
            .map_err(|_| HostAttestorError::Config(err)),
    }
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
        let line = "ro quiet hippius.node_id=abcd console=ttyS0";
        assert_eq!(
            resolve(line, "HIPPIUS_TEST_ABSENT_NODE", "hippius.node_id").as_deref(),
            Some("abcd")
        );
        assert_eq!(
            resolve("ro quiet", "HIPPIUS_TEST_ABSENT_NODE", "hippius.node_id"),
            None
        );
        assert_eq!(
            resolve(
                "hippius.node_id=",
                "HIPPIUS_TEST_ABSENT_NODE",
                "hippius.node_id"
            ),
            None
        );
    }

    #[test]
    fn resolve_digest_decodes_a_64_hex_value_and_rejects_garbage() {
        let hex_str = "11".repeat(32);
        let line = format!("hippius.chain_genesis={hex_str}");
        let d = resolve_digest(
            &line,
            "HIPPIUS_TEST_ABSENT_CG",
            "hippius.chain_genesis",
            "chain-genesis",
        )
        .unwrap();
        assert_eq!(d, [0x11u8; DIGEST_LEN]);

        // Missing.
        let err = resolve_digest(
            "ro quiet",
            "HIPPIUS_TEST_ABSENT_CG",
            "hippius.chain_genesis",
            "chain-genesis",
        )
        .expect_err("missing digest fails closed");
        assert_eq!(err.class(), "chain-genesis-missing");
        // Wrong length.
        let err = resolve_digest(
            "hippius.pallet_instance=00",
            "HIPPIUS_TEST_ABSENT_PI",
            "hippius.pallet_instance",
            "pallet-instance",
        )
        .expect_err("a 1-byte digest is not 32 bytes");
        assert_eq!(err.class(), "pallet-instance-length");
    }

    #[test]
    fn resolve_u64_defaults_and_parses_and_fails_closed() {
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
    fn enroll_interval_defaults_to_hourly() {
        // The default is what a production boot uses (no cmdline token → the
        // measured cmdline, and thus the pinned measurement, is unchanged).
        assert_eq!(DEFAULT_ENROLL_INTERVAL_SECS, 3600);
    }
}
