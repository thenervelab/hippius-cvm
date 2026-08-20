//! UKI image fetch + §22 verification — a thin wrapper over the
//! `miner-uki-fetch` library.
//!
//! `miner-uki-fetch::fetch` already implements the whole miner-side
//! pipeline: pull `provenance.cbor`, **verify the §22 offline-root
//! Ed25519 signature first and always** (it is never skipped — not on
//! the idempotency fast path, not on a cache hit), hash-gate the UKI,
//! reuse the content-addressed local cache, and atomically install the
//! verified image. This module does not re-implement any of that — it
//! would only risk diverging from the verified path. It adds:
//!
//! - holding the chosen [`ImageStore`] backend + cache directory;
//! - parsing the operator's `--hash` hex argument into the 32-byte
//!   form `fetch` expects;
//! - deriving the content-addressed install path under the staging
//!   directory.
//!
//! The "verify even on a cache hit" invariant the miner relies on is
//! therefore satisfied by construction: every `fetch_verified` call is
//! a `fetch` call, and `fetch` always verifies.
//!
//! NOTE: the production backend [`HippiusS3ImageStore`] is itself a
//! stub (image-provenance, blocked on issue #80) — until it is wired,
//! `fetch_verified` against real Hippius S3 fails closed with a
//! `not-wired` error. The in-memory backend exercises the full path.

use std::path::{Path, PathBuf};

use hippius_image_provenance::store::ImageStore;
use hippius_miner_uki_fetch::{fetch, FetchOutcome};

use crate::error::{MinerAgentError, Result};

/// Characters in a hex-encoded SHA-256.
const SHA256_HEX_LEN: usize = 64;

/// Bytes in a SHA-256 — the array width `miner-uki-fetch::fetch` wants.
const SHA256_LEN: usize = 32;

/// A UKI image cache + fetcher bound to one [`ImageStore`] backend.
pub struct ImageCache {
    store: Box<dyn ImageStore + Send + Sync>,
    cache_dir: PathBuf,
}

impl ImageCache {
    /// Bind a cache to `store`, creating `cache_dir` if needed.
    pub fn new(store: Box<dyn ImageStore + Send + Sync>, cache_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&cache_dir)?;
        Ok(Self { store, cache_dir })
    }

    /// Fetch + §22-verify the UKI whose SHA-256 is `hash_hex`,
    /// installing the verified image at `staging_dir/<hash>.uki`.
    ///
    /// Delegates to `miner-uki-fetch::fetch` — which verifies the §22
    /// provenance signature on **every** call, cache hit or not.
    /// Returns the [`FetchOutcome`] and the install path. Any failure
    /// (bad hash arg, store error, signature mismatch, hash mismatch)
    /// is fail-closed: nothing is installed.
    pub fn fetch_verified(
        &self,
        hash_hex: &str,
        staging_dir: &Path,
    ) -> Result<(FetchOutcome, PathBuf)> {
        let hash = parse_sha256_hex(hash_hex)?;
        std::fs::create_dir_all(staging_dir)?;
        // Content-addressed install name — canonical lowercase hex.
        let output = staging_dir.join(format!("{}.uki", hex::encode(hash)));
        let outcome = fetch(self.store.as_ref(), &hash, &output, Some(&self.cache_dir))?;
        Ok((outcome, output))
    }

    /// The content-addressed cache directory.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

/// Parse a hex SHA-256 string (upper- or lower-case, surrounding
/// whitespace tolerated) into the 32-byte array. Fail-closed on a
/// wrong length or a non-hex character.
pub fn parse_sha256_hex(s: &str) -> Result<[u8; SHA256_LEN]> {
    let s = s.trim();
    if s.len() != SHA256_HEX_LEN {
        return Err(MinerAgentError::HashArg("length"));
    }
    let decoded = hex::decode(s).map_err(|_| MinerAgentError::HashArg("hex"))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| MinerAgentError::HashArg("length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hippius_image_provenance::store::{HippiusS3ImageStore, MemoryImageStore};
    use tempfile::TempDir;

    const VALID_HASH: &str = "e6fec6b20e2a6848537e70c195e99dce63a09f6d17551845e6eda126be53adab";

    #[test]
    fn parse_sha256_hex_accepts_a_valid_digest() {
        assert!(parse_sha256_hex(VALID_HASH).is_ok());
    }

    #[test]
    fn parse_sha256_hex_tolerates_whitespace() {
        let padded = format!("  {VALID_HASH}\n");
        assert!(parse_sha256_hex(&padded).is_ok());
    }

    #[test]
    fn parse_sha256_hex_rejects_wrong_length() {
        assert!(matches!(
            parse_sha256_hex("abcd"),
            Err(MinerAgentError::HashArg("length"))
        ));
    }

    #[test]
    fn parse_sha256_hex_rejects_non_hex() {
        let bad: String = "z".repeat(64);
        assert!(matches!(
            parse_sha256_hex(&bad),
            Err(MinerAgentError::HashArg("hex"))
        ));
    }

    #[test]
    fn new_creates_the_cache_dir() {
        let tmp = TempDir::new().unwrap();
        let cache = tmp.path().join("nested/cache");
        assert!(!cache.exists());
        let _c = ImageCache::new(Box::new(MemoryImageStore::new()), cache.clone()).unwrap();
        assert!(cache.is_dir());
    }

    #[test]
    fn fetch_from_empty_store_fails_closed_and_installs_nothing() {
        let tmp = TempDir::new().unwrap();
        let staging = tmp.path().join("staging");
        let cache =
            ImageCache::new(Box::new(MemoryImageStore::new()), tmp.path().join("c")).unwrap();
        // An empty store has no provenance → the §22 fetch fails.
        assert!(cache.fetch_verified(VALID_HASH, &staging).is_err());
        let installed = staging.join(format!("{VALID_HASH}.uki"));
        assert!(!installed.exists(), "a failed fetch must install nothing");
    }

    #[test]
    fn fetch_against_the_s3_stub_fails_closed() {
        let tmp = TempDir::new().unwrap();
        // Use a deliberately-unreachable endpoint — the GET against it
        // returns a Transport error (DNS / TLS / connect failure),
        // which `fetch_verified` propagates. Same fail-closed outcome
        // as the original stub assertion, against the live-wired READ
        // path PR-F UKI build pins + publish added.
        let store = HippiusS3ImageStore::new(
            "hippius-compute-images",
            "https://hippius-s3-not-reachable.invalid",
        )
        .unwrap();
        let cache = ImageCache::new(Box::new(store), tmp.path().join("c")).unwrap();
        assert!(cache
            .fetch_verified(VALID_HASH, &tmp.path().join("staging"))
            .is_err());
    }
}
