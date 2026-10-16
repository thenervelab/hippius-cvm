//! Errors, each with a static class (the result's per-target `error`
//! code, or the log line).

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProbeError {
    /// The request file is unusable.
    #[error("request-{0}")]
    Request(&'static str),
    /// A target could not be probed (its `error` code in the result).
    #[error("{0}")]
    Target(&'static str),
    /// The result could not be written.
    #[error("result-{0}")]
    Result(&'static str),
}

pub type Result<T> = std::result::Result<T, ProbeError>;
