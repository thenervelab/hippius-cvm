//! Typed, fail-loud errors.
//!
//! Every variant is non-recoverable — the agent aborts establishment
//! on the first `Err`, there is no retry / no fallback (§7 fail-closed).
//!
//! ## No key material in `Display`
//!
//! No variant carries the telemetry signer key or any derivative of
//! it. The classified `&'static str` variants render a fixed tag; the
//! wrapped `GuestError` / `HippiusTypesError` carry only field names,
//! lengths, and CBOR error text — never key bytes. [`TelemetryError::class`]
//! returns a pure-static string and is what `main` logs, so even those
//! wrapped messages never reach a log line.

use thiserror::Error;

/// Result alias for the crate.
pub type Result<T> = std::result::Result<T, TelemetryError>;

/// Anything that can abort telemetry-key establishment.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// A required config value (KBS URL, node/vm id, pinned KBS key)
    /// was missing or malformed.
    #[error("config: {0}")]
    Config(&'static str),

    /// The Ed25519 signer keypair could not be generated.
    #[error("keygen: {0}")]
    Keygen(&'static str),

    /// `/dev/sev-guest` attestation failed.
    #[error("snp: {0}")]
    Snp(&'static str),

    /// A KBS HTTP exchange failed (transport, status, or decode).
    #[error("kbs: {0}")]
    Kbs(&'static str),

    /// The KBS telemetry certificate failed verification.
    #[error("verify: {0}")]
    Verify(#[from] hippius_guest::GuestError),

    /// A canonical-CBOR encode/decode error from `hippius-types`.
    #[error("schema: {0}")]
    Schema(#[from] hippius_types::HippiusTypesError),

    /// The shutdown-signal wait could not be set up.
    #[error("shutdown: {0}")]
    Shutdown(&'static str),

    /// Building or signing a periodic `ServedDeliveryReceipt` failed
    /// (PR-E2.2 receipt loop). Carries a static classifier only — the
    /// underlying `canonical()` / signing detail never reaches a log.
    #[error("receipt: {0}")]
    Receipt(&'static str),

    /// The PR-E2.3 vsock pusher hit an unrecoverable error — a connect
    /// / write / flush failure, a poisoned queue lock, or a thread it
    /// could not spawn. Carries a static classifier only; the
    /// underlying `io::Error` detail never reaches a log (§20).
    #[error("vsock: {0}")]
    Vsock(&'static str),
}

impl TelemetryError {
    /// A pure-static classifier for logging — never carries dynamic
    /// text, so a log line cannot leak a wrapped error's message.
    pub fn class(&self) -> &'static str {
        match self {
            TelemetryError::Config(c) => c,
            TelemetryError::Keygen(c) => c,
            TelemetryError::Snp(c) => c,
            TelemetryError::Kbs(c) => c,
            TelemetryError::Verify(_) => "telemetry-cert-verify",
            TelemetryError::Schema(_) => "schema",
            TelemetryError::Shutdown(c) => c,
            TelemetryError::Receipt(c) => c,
            TelemetryError::Vsock(c) => c,
        }
    }
}
