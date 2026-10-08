//! Typed errors with static classifiers.
//!
//! No variant carries key material, a session token, a sealed blob or
//! an unsealed plaintext. Every `&'static str` is a fixed tag, and
//! [`CdnError::class`] is what the agent logs, so a log line cannot
//! leak dynamic text from a wrapped error.

use thiserror::Error;

/// Result alias for the crate.
pub type Result<T> = std::result::Result<T, CdnError>;

/// Anything the agent can fail on.
#[derive(Debug, Error)]
pub enum CdnError {
    /// The node config or the node identity file is missing or invalid.
    /// Always fatal at start (fail closed).
    #[error("config: {0}")]
    Config(&'static str),

    /// The lifecycle key, the fleet keyring or the node certificate is
    /// missing, malformed, or does not match this node.
    #[error("identity: {0}")]
    Identity(&'static str),

    /// A backend exchange failed at the transport or decode level.
    #[error("backend: {0}")]
    Backend(&'static str),

    /// The backend answered with a non-success status.
    #[error("backend status {0}")]
    BackendStatus(u16),

    /// The backend refused an ACME lease for a name it does not issue
    /// (`name-mismatch`): this node is baked for another domain.
    #[error("backend: lease name refused")]
    LeaseNameRefused,

    /// The backend answered an error status with `Retry-After`: wait at
    /// least that long before the next poll.
    #[error("backend status {status}, retry after {retry_after_s} s")]
    Throttled { status: u16, retry_after_s: u64 },

    /// The backend rejected the session (401): re-register.
    #[error("backend: unauthorized")]
    Unauthorized,

    /// A feed response failed validation or could not be applied.
    #[error("feed: {0}")]
    Feed(&'static str),

    /// A sealed blob could not be opened.
    #[error("unseal: {0}")]
    Unseal(&'static str),

    /// The OpenResty control socket refused or failed a push.
    #[error("control: {0}")]
    Control(&'static str),

    /// Metering: a bad record, or the counter file could not be written.
    #[error("counters: {0}")]
    Counters(&'static str),

    /// Usage report queueing or signing failed.
    #[error("usage: {0}")]
    Usage(&'static str),

    /// A local file operation failed.
    #[error("io: {0}")]
    Io(&'static str),

    /// `/dev/sev-guest` attestation failed.
    #[error("snp: {0}")]
    Snp(&'static str),

    /// An ACME exchange or a certificate key operation failed (I4).
    #[error("acme: {0}")]
    Acme(&'static str),

    /// The shutdown handler could not be installed.
    #[error("shutdown: {0}")]
    Shutdown(&'static str),
}

impl CdnError {
    /// A pure-static classifier for logging.
    pub fn class(&self) -> &'static str {
        match self {
            CdnError::Config(c)
            | CdnError::Identity(c)
            | CdnError::Backend(c)
            | CdnError::Feed(c)
            | CdnError::Unseal(c)
            | CdnError::Control(c)
            | CdnError::Counters(c)
            | CdnError::Usage(c)
            | CdnError::Io(c)
            | CdnError::Snp(c)
            | CdnError::Acme(c)
            | CdnError::Shutdown(c) => c,
            CdnError::BackendStatus(_) => "backend-status",
            CdnError::LeaseNameRefused => "lease-name-refused",
            CdnError::Throttled { .. } => "backend-throttled",
            CdnError::Unauthorized => "unauthorized",
        }
    }
}
