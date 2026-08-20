//! `hippius-image-provenance` — §11/§22 signed image provenance.
//!
//! The Packer factory measures a UKI with `hippius-uki-measure`, then
//! runs this tool to **bind** that measurement to its build inputs and
//! publish the result:
//!
//! 1. [`measurement`] reads the `hippius-uki-measure` SNP JSON
//!    envelope (fail-closed: a default `uki_sha384` build is refused).
//! 2. [`build`] turns it into a [`hippius_types::provenance::ProvenanceMap`]
//!    — the launch digest mapped to the verity root, the
//!    kernel/initrd/cmdline/OVMF fingerprints, the pinned launch
//!    config, and the content-addressed S3 location.
//! 3. [`sign`] Ed25519-signs the canonical body with the §22 offline
//!    allowlist root key and produces a `provenance.cbor` envelope.
//! 4. [`store`] + [`publish`] push the artifact and its provenance to
//!    the Hippius S3 image bucket — idempotently (a re-run of an
//!    already-published content hash is a successful no-op).
//!
//! The signature format is the production format: PR-F4 ships a
//! committed **dev** §22 root key so the flow is exercised end-to-end,
//! but swapping in the real air-gapped root key is a key-file change,
//! no code change. The §22 contract (offline root, deterministic
//! format, fail-closed) is honoured today.

pub mod build;
pub mod error;
pub mod measurement;
pub mod publish;
pub mod sign;
pub mod store;

pub use error::{Error, ImageStoreError, Result};
