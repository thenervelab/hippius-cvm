//! Crate error type.
//!
//! The binary fails closed on ANY error: a config or wiring fault aborts
//! startup with a non-zero exit code so the orchestrator restarts the
//! pod, rather than ever running a half-wired KBS. Messages are operator-
//! facing and never carry secret material (the Vault token / signing-key
//! bytes are never formatted into an error).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Bad or missing configuration / required environment input.
    #[error("config: {0}")]
    Config(String),
    /// A dependency could not be wired (store open, allowlist install …).
    #[error("wiring: {0}")]
    Wiring(String),
    /// The HTTP server could not bind or serve.
    #[error("serve: {0}")]
    Serve(String),
}
