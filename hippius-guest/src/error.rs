//! Typed, fail-loud errors. Every variant is non-recoverable from the
//! guest's perspective — the agent MUST refuse to mount the disk /
//! refuse to switch_root.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GuestError {
    #[error("signature: {0}")]
    Signature(String),
    #[error("response decode: {0}")]
    Decode(String),
    #[error("binding mismatch ({field}): expected={expected:?}, got={got:?}")]
    Binding {
        field: &'static str,
        expected: String,
        got: String,
    },
    #[error("HPKE unwrap: {0}")]
    Hpke(String),
    #[error("user-data digest mismatch (KBS-signed response vs recompute)")]
    DigestMismatch,
    #[error("schema: {0}")]
    Schema(String),
    #[error("stopped-ack: {0}")]
    StoppedAck(String),
}

pub type Result<T> = core::result::Result<T, GuestError>;
