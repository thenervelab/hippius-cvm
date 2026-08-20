//! Crate error types.

use std::path::PathBuf;

/// Result alias for the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong building / signing / publishing a
/// provenance map. Every variant is fail-closed — there is no path
/// that downgrades an error into a partial success.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("read {path:?}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("write {path:?}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("measurement envelope {path:?} is not valid JSON: {source}")]
    MeasurementJson {
        path: PathBuf,
        source: serde_json::Error,
    },

    /// A measurement envelope parsed but is unusable for provenance —
    /// e.g. it is a `uki_sha384` placeholder, or an SNP field is
    /// absent. Provenance only describes production SNP images.
    #[error("measurement envelope: {0}")]
    Measurement(String),

    /// A hex field could not be decoded or had the wrong length.
    #[error("field {field}: {reason}")]
    Field { field: &'static str, reason: String },

    /// The artifact passed does not match the measured one.
    #[error("artifact mismatch: {0}")]
    ArtifactMismatch(String),

    /// Provenance wire-format (canonical-CBOR) encode/decode error.
    #[error("{0}")]
    Provenance(#[from] hippius_types::HippiusTypesError),

    /// Ed25519 key material could not be loaded. The message never
    /// echoes key bytes.
    #[error("signing/verifying key: {0}")]
    Key(String),

    /// Signature creation or verification failed.
    #[error("signature: {0}")]
    Signature(String),

    /// Object-store backend error.
    #[error("image store: {0}")]
    Store(#[from] ImageStoreError),
}

/// Errors from an [`crate::store::ImageStore`] backend.
#[derive(Debug, thiserror::Error)]
pub enum ImageStoreError {
    /// The backend is a deliberate stub — only the `HippiusS3ImageStore`
    /// `put` path uses this now (writes need SigV4 which is deferred).
    #[error("backend not wired: {0}")]
    NotWired(String),

    /// A `get` targeted a key that does not exist.
    #[error("object {key:?} not found")]
    NotFound { key: String },

    /// A `put` found a different object already stored at `key`.
    /// Content-addressed keys must map to exactly one byte string —
    /// a mismatch is corruption or a conflicting re-sign, never a
    /// silent overwrite.
    #[error("object {key:?} already exists with different content")]
    Conflict { key: String },

    /// HTTP / TLS / DNS failure talking to the backend.
    #[error("transport: {0}")]
    Transport(String),

    /// The backend returned an unexpected status / body.
    #[error("backend protocol: {0}")]
    Protocol(String),

    /// A `MemoryImageStore` mutex was poisoned by a panicking thread.
    #[error("in-memory store lock poisoned")]
    LockPoisoned,
}
