//! Broker error type.
//!
//! Mirrors the kbs-server closed-vocabulary discipline: every variant
//! maps to a stable HTTP status + a short reason; the inner `String`
//! carries a classifier, never a secret (the Vault token is never put
//! in an error).

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// Malformed request body / shape — HTTP 400.
    #[error("bad-request: {0}")]
    BadRequest(String),
    /// Challenge unknown / expired / spent / scope-mismatch — HTTP 401.
    #[error("challenge-rejected: {0}")]
    Challenge(String),
    /// SNP attestation verification / binding / allowlist / policy
    /// failure — HTTP 403 (fail-closed; no capability minted).
    #[error("attestation-rejected: {0}")]
    Attestation(String),
    /// Vault token-mint failed (transport / Vault error) — HTTP 502.
    #[error("vault-mint-failed: {0}")]
    VaultMint(String),
    /// Operator config / startup error.
    #[error("config: {0}")]
    Config(String),
}

impl BrokerError {
    /// Stable HTTP status for the transport layer.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Challenge(_) => 401,
            Self::Attestation(_) => 403,
            Self::VaultMint(_) => 502,
            Self::Config(_) => 500,
        }
    }
    /// Stable, secret-free reason tag for the response body + logs.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad-request",
            Self::Challenge(_) => "challenge-rejected",
            Self::Attestation(_) => "attestation-rejected",
            Self::VaultMint(_) => "vault-mint-failed",
            Self::Config(_) => "config",
        }
    }
}
