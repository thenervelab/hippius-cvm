//! Crate error type.
//!
//! Every variant is fail-closed — there is no path that downgrades an
//! error into a partial success. No variant ever carries the §22 root
//! public key (defence-in-depth: the key must not reach logs even
//! though it is not secret).

use std::path::PathBuf;

/// Result alias for the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong fetching + verifying a UKI.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("write {path:?}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },

    /// `--hash` was not a 32-byte SHA-256 hex string.
    #[error("--hash: {0}")]
    HashArg(String),

    /// A recomputed hash did not match what was expected — fail closed.
    #[error("{context}: hash mismatch — expected {expected}, got {actual}")]
    HashMismatch {
        context: &'static str,
        expected: String,
        actual: String,
    },

    /// The compiled-in §22 root public key could not be parsed. The
    /// message is deliberately content-free — the key never reaches a
    /// log line.
    #[error("compiled-in §22 root public key is malformed")]
    RootKey,

    /// `provenance.cbor` failed to decode (canonical-CBOR / schema).
    #[error("provenance decode: {0}")]
    Cbor(#[from] hippius_types::HippiusTypesError),

    /// `provenance.cbor` failed §22 signature verification, or another
    /// error from the reused PR-F4 verification path.
    #[error("provenance verification: {0}")]
    Provenance(#[from] hippius_image_provenance::Error),

    /// The image store backend failed.
    #[error("image store: {0}")]
    Store(#[from] hippius_image_provenance::ImageStoreError),
}
