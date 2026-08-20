//! `hippius-miner-uki-fetch` — miner-side UKI fetch + §22 verify.
//!
//! A miner operator runs this before booting a tenant VM. It pulls a
//! UKI and its `provenance.cbor` from the Hippius S3 image bucket,
//! verifies the §22 offline-allowlist-root Ed25519 signature on the
//! provenance, recomputes the UKI's SHA-256 and fails closed on any
//! mismatch, then atomically installs the verified image.
//!
//! PR-F5 adds **no** new provenance crypto — the canonical-CBOR wire
//! format ([`hippius_types::provenance`]), the `ImageStore` backends,
//! and the `verify_provenance` §22 verifier are all reused from PR-F4.
//! This crate contributes the fetch orchestration ([`fetch`]), the
//! compiled-in root-key anchor, and the crash-safe atomic install.

pub mod atomic;
pub mod error;
pub mod fetch;

pub use error::{Error, Result};
pub use fetch::{bundled_root_pubkey, fetch, FetchOutcome};
