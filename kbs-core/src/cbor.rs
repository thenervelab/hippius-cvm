//! Deterministic CBOR (RFC 8949 §4.2.1) — single source of truth in
//! `hippius_types::cbor`. Re-exported here for backwards compatibility
//! with internal kbs-core call sites and tests.

pub use hippius_types::cbor::{assert_canonical, to_canonical_vec};
