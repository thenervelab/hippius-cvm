//! Typed, fail-loud errors for the host attestor.
//!
//! Every variant is non-recoverable — the attestor aborts on the first
//! `Err`; there is no retry / no fallback (§7 fail-closed). In
//! particular there is **no** "derive a random key instead" path: a
//! derived-key failure propagates, because a random signer key would
//! silently break the stable per-boot host identity the enrollment +
//! beacon contract depends on.
//!
//! ## No key material in `Display`
//!
//! No variant carries the SNP derived key, the HKDF output, or the
//! Ed25519 signer key. The `&'static str` variants render a fixed tag;
//! [`HostAttestorError::class`] returns a pure-static string and is what
//! callers log, so no dynamic text ever reaches a log line (§20).

use thiserror::Error;

/// Result alias for the crate.
pub type Result<T> = std::result::Result<T, HostAttestorError>;

/// Anything that can abort host-attestor key establishment, enrollment,
/// or the beacon loop.
#[derive(Debug, Error)]
pub enum HostAttestorError {
    /// Fetching the stable SNP derived key from `/dev/sev-guest` failed
    /// — opening the device, or the `get_derived_key` ioctl. Carries a
    /// static classifier only; the underlying firmware error never
    /// reaches a log. **Never** falls back to a random key.
    #[error("derived-key: {0}")]
    DerivedKey(&'static str),

    /// Deriving the Ed25519 signer seed from the SNP derived key failed.
    #[error("keygen: {0}")]
    Keygen(&'static str),

    /// Mounting a pseudo-filesystem (`/proc`, `/sys`, `/dev`) at PID 1
    /// failed — the diskless host-attestor initrd ships none pre-mounted,
    /// and without them the agent cannot read `/proc/cmdline` / the
    /// kernel `boot_id` nor open `/dev/sev-guest`. Carries a static
    /// classifier (`proc-mount`, `dev-mkdir`, …) naming the offender.
    #[error("mount: {0}")]
    Mount(&'static str),

    /// Loading a required kernel module (`sev-guest` + its crypto/TSM
    /// deps, or the `vsock` transport stack) at PID 1 failed — the
    /// diskless attestor initrd bundles the `.ko` bytes but the Debian
    /// stock kernel ships them as loadable modules (`CONFIG_SEV_GUEST=m`,
    /// `CONFIG_VSOCKETS=m`), so without loading them `/dev/sev-guest`
    /// never appears and the challenge/enroll/beacon vsock cannot bind.
    /// Carries a static classifier (`sev-guest-modules-load-sev-guest`,
    /// `vsock-modules-read-vsock`, …) naming the offending step.
    #[error("module: {0}")]
    Module(&'static str),

    /// A required config value (node/boot id, chain-genesis /
    /// pallet-instance digest, vsock port) was missing or malformed.
    #[error("config: {0}")]
    Config(&'static str),

    /// Requesting the platform SNP attestation report from
    /// `/dev/sev-guest` failed, or the returned report was too short to
    /// carry the platform fields.
    #[error("snp: {0}")]
    Snp(&'static str),

    /// Drawing a fresh single-use nonce from the OS CSPRNG failed.
    #[error("nonce: {0}")]
    Nonce(&'static str),

    /// Building the once-per-boot [`HostEnrollment`](hippius_types::host_attestor::HostEnrollment)
    /// failed — assembling the report `REPORT_DATA` binding or encoding
    /// the enrollment. Carries a static classifier only.
    #[error("enroll: {0}")]
    Enroll(&'static str),

    /// Building or signing a periodic
    /// [`SignedHostBeacon`](hippius_types::host_attestor::SignedHostBeacon)
    /// failed. Carries a static classifier only — the underlying
    /// `canonical()` detail never reaches a log.
    #[error("beacon: {0}")]
    Beacon(&'static str),

    /// The vsock pusher hit an unrecoverable error — a connect / write /
    /// flush failure, a poisoned queue lock, or a thread it could not
    /// spawn. Static classifier only; the `io::Error` detail never
    /// reaches a log (§20).
    #[error("vsock: {0}")]
    Vsock(&'static str),

    /// The shutdown-signal handler could not be installed.
    #[error("shutdown: {0}")]
    Shutdown(&'static str),

    /// A canonical-CBOR encode error from `hippius-types`.
    #[error("schema: {0}")]
    Schema(#[from] hippius_types::HippiusTypesError),
}

impl HostAttestorError {
    /// A pure-static classifier for logging — never carries dynamic
    /// text, so a log line cannot leak a wrapped error's message.
    pub fn class(&self) -> &'static str {
        match self {
            HostAttestorError::DerivedKey(c) => c,
            HostAttestorError::Keygen(c) => c,
            HostAttestorError::Mount(c) => c,
            HostAttestorError::Module(c) => c,
            HostAttestorError::Config(c) => c,
            HostAttestorError::Snp(c) => c,
            HostAttestorError::Nonce(c) => c,
            HostAttestorError::Enroll(c) => c,
            HostAttestorError::Beacon(c) => c,
            HostAttestorError::Vsock(c) => c,
            HostAttestorError::Shutdown(c) => c,
            HostAttestorError::Schema(_) => "schema",
        }
    }
}
