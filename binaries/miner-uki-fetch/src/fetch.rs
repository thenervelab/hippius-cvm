//! The miner-side fetch + §22-verify + atomic-install pipeline.
//!
//! Flow:
//!
//! 1. **Provenance** — pull `provenance.cbor` from the image store,
//!    decode it (canonical-CBOR gated), and verify the §22 offline-
//!    allowlist-root Ed25519 signature. There is exactly **one**
//!    accepted signer — the compiled-in root key; no fallback. This
//!    runs first and is never skipped: the signature is the trust
//!    anchor binding the requested hash to a genuine measured image.
//! 2. **Idempotency** — once the provenance is verified, if `output`
//!    already holds a file with the requested hash, stop: the verified
//!    image is already installed.
//! 3. **Artifact** — take the UKI from the local content cache when it
//!    is present and hashes correctly, otherwise download it. Either
//!    way its SHA-256 is checked against the signed `artifact_sha256`
//!    — a mismatch fails closed.
//! 4. **Install** — write the verified bytes to `output` atomically,
//!    so a crash never leaves a partial image. The cache is populated
//!    the same way, best-effort.

use std::fs;
use std::path::Path;

use ed25519_dalek::VerifyingKey;
use hippius_image_provenance::build::{provenance_object_key, validate_artifact_key};
use hippius_image_provenance::sign::verify_provenance;
use hippius_image_provenance::store::ImageStore;
use hippius_types::provenance::{ProvenanceMap, SignedProvenance, SHA256_LEN};
use sha2::{Digest, Sha256};

use crate::atomic::atomic_write;
use crate::error::{Error, Result};

/// The §22 offline-allowlist root **public** key, compiled into the
/// binary. §22 mandates the root key be the one trust anchor not
/// itself loaded from disk/config/network at run time — so it is baked
/// in here at build time.
///
/// RA-N6: the anchor is **build-time overridable**. A production build
/// sets `HIPPIUS_PROVENANCE_ROOT_PUBKEY` (the 64-hex real air-gapped
/// root pubkey) and that value is baked in; only a dev/CI build (env
/// unset) falls back to the committed reproducible dev placeholder. The
/// `prod-root` feature turns the fallback into a hard **build failure**
/// (see the const-assert below) so a production image can NEVER silently
/// ship the dev key — closing the "hard-coded dev root, no override"
/// gap. Activation is gated on the §22 offline signing ceremony + the
/// #80 image-store wiring; until then the dev key is inert (the prod
/// `HippiusS3ImageStore` is a fail-closed stub).
///
/// The key is **public**, but the binary still never prints it
/// (defence in depth) — it exists only to feed `verify_strict`.
const ROOT_PUBKEY_HEX: &str = match option_env!("HIPPIUS_PROVENANCE_ROOT_PUBKEY") {
    Some(k) => k,
    None => include_str!("../../../packer/kbs-uki/keys/dev/provenance-root.dev.ed25519.pub"),
};

// A `prod-root` build refuses the dev-key fallback: fail the compile if
// the real root pubkey was not supplied. This runs at const-eval time,
// so a misconfigured production build never links.
#[cfg(feature = "prod-root")]
const _: () = assert!(
    option_env!("HIPPIUS_PROVENANCE_ROOT_PUBKEY").is_some(),
    "prod-root build requires the HIPPIUS_PROVENANCE_ROOT_PUBKEY env var (the real \
     air-gapped §22 root pubkey) — refusing to fall back to the committed dev placeholder",
);

/// Length of an Ed25519 public key. Distinct from a SHA-256 length —
/// they are both 32 bytes, but conflating the two constants is a
/// latent trap if either ever moves.
const ED25519_PUBKEY_LEN: usize = 32;

/// Parse the compiled-in §22 root public key. Fails closed (and
/// content-free) if the baked-in key is somehow malformed.
pub fn bundled_root_pubkey() -> Result<VerifyingKey> {
    let bytes = hex::decode(ROOT_PUBKEY_HEX.trim()).map_err(|_| Error::RootKey)?;
    let arr: [u8; ED25519_PUBKEY_LEN] = bytes.as_slice().try_into().map_err(|_| Error::RootKey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| Error::RootKey)
}

/// How a [`fetch`] call obtained the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchOutcome {
    /// `output` already held the requested, hash-matching image.
    AlreadyPresent,
    /// The UKI came from the local content-addressed cache.
    FetchedFromCache,
    /// The UKI was downloaded from the image store.
    FetchedFromStore,
}

/// Fetch, §22-verify, and atomically install the UKI whose SHA-256 is
/// `requested_sha256`.
pub fn fetch(
    store: &dyn ImageStore,
    requested_sha256: &[u8; SHA256_LEN],
    output: &Path,
    cache_dir: Option<&Path>,
) -> Result<FetchOutcome> {
    // 1. Pull + §22-verify the provenance — FIRST, always. The
    //    signature is the only thing binding the requested hash to a
    //    genuine measured image; the idempotency fast path below must
    //    never bypass it.
    let map = fetch_verified_provenance(store, requested_sha256)?;

    // 2. Idempotency — is the verified image already at `output`?
    if let Some(hash) = hash_if_readable(output) {
        if hash == *requested_sha256 {
            return Ok(FetchOutcome::AlreadyPresent);
        }
        // Present but wrong — the atomic write in step 4 replaces it.
    }

    // 3. Obtain the UKI binary — local content cache first, else store.
    let cache_path = cache_dir.map(|d| d.join(hex::encode(requested_sha256)));
    let (uki_bytes, from_cache) = obtain_uki(store, &map, requested_sha256, cache_path.as_deref())?;

    // 4. Populate the cache on a fresh download — best-effort: a cache
    //    write failure (e.g. a misconfigured cache dir) must not block
    //    installing the already-verified image at `output`.
    if !from_cache {
        if let (Some(dir), Some(cp)) = (cache_dir, &cache_path) {
            if let Err(e) = populate_cache(dir, cp, &uki_bytes) {
                eprintln!("miner-uki-fetch: warning: could not populate cache {cp:?}: {e}");
            }
        }
    }

    // 5. Atomically install the verified UKI at the operator's path.
    atomic_write(output, &uki_bytes)?;

    Ok(if from_cache {
        FetchOutcome::FetchedFromCache
    } else {
        FetchOutcome::FetchedFromStore
    })
}

/// Pull `provenance.cbor`, §22-verify it, and confirm it describes the
/// requested artifact.
fn fetch_verified_provenance(
    store: &dyn ImageStore,
    requested_sha256: &[u8; SHA256_LEN],
) -> Result<ProvenanceMap> {
    let root = bundled_root_pubkey()?;
    let provenance_key = provenance_object_key(requested_sha256);
    let raw = store.get(&provenance_key)?;

    // `SignedProvenance::decode` canonical-gates the outer envelope;
    // `verify_provenance` canonical-gates the inner body, pins the
    // in-body signer pubkey to the §22 root, then `verify_strict`s the
    // detached signature. One signer, no fallback.
    let signed = SignedProvenance::decode(&raw)?;
    let map = verify_provenance(&signed, &root)?;

    // The signed provenance MUST describe the artifact we asked for.
    if map.artifact_sha256 != *requested_sha256 {
        return Err(Error::HashMismatch {
            context: "provenance artifact_sha256",
            expected: hex::encode(requested_sha256),
            actual: hex::encode(map.artifact_sha256),
        });
    }
    // Defence in depth: the artifact key must be the content address.
    validate_artifact_key(&map.s3_key, &map.artifact_sha256)?;
    Ok(map)
}

/// Return the UKI bytes + whether they came from the cache. The bytes
/// are always hash-gated against `requested_sha256` before return.
fn obtain_uki(
    store: &dyn ImageStore,
    map: &ProvenanceMap,
    requested_sha256: &[u8; SHA256_LEN],
    cache_path: Option<&Path>,
) -> Result<(Vec<u8>, bool)> {
    // Cache hit only when the cached bytes hash to the requested
    // value. A stale / partial / poisoned / unreadable cache entry is
    // silently ignored here and overwritten by the fresh download
    // below — it is never trusted, never returned.
    if let Some(cp) = cache_path {
        if let Some((bytes, hash)) = read_and_hash(cp) {
            if hash == *requested_sha256 {
                return Ok((bytes, true));
            }
        }
    }

    // Download from the image store and hash-gate it. `s3_key` is the
    // signed, content-addressed key validated in `fetch_verified_provenance`.
    let bytes = store.get(&map.s3_key)?;
    let got = sha256(&bytes);
    if got != *requested_sha256 {
        return Err(Error::HashMismatch {
            context: "downloaded UKI",
            expected: hex::encode(requested_sha256),
            actual: hex::encode(got),
        });
    }
    Ok((bytes, false))
}

/// Write `bytes` into the content-addressed cache at `cache_path`,
/// creating `dir` if needed. Caller treats a failure as non-fatal.
fn populate_cache(dir: &Path, cache_path: &Path, bytes: &[u8]) -> Result<()> {
    fs::create_dir_all(dir).map_err(|source| Error::Write {
        path: dir.to_path_buf(),
        source,
    })?;
    atomic_write(cache_path, bytes)
}

fn sha256(bytes: &[u8]) -> [u8; SHA256_LEN] {
    Sha256::digest(bytes).into()
}

/// Read a file and hash it, returning `None` on **any** error —
/// missing, unreadable, or a directory. Used for the best-effort
/// output-idempotency and cache-hit checks: a candidate that cannot be
/// read+hashed is simply "not a hit", never an error.
fn read_and_hash(path: &Path) -> Option<(Vec<u8>, [u8; SHA256_LEN])> {
    let bytes = fs::read(path).ok()?;
    let hash = sha256(&bytes);
    Some((bytes, hash))
}

fn hash_if_readable(path: &Path) -> Option<[u8; SHA256_LEN]> {
    read_and_hash(path).map(|(_, hash)| hash)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The committed PR-F4 dev §22 root public key. Pinned so a wrong
    /// `include_str!` path — e.g. accidentally baking in the sibling
    /// private seed — changes the compiled-in key and trips this test.
    ///
    /// `cfg(not(prod-root))`: this pins the DEV key, so it must NOT run
    /// against a production build (RA-N6), which bakes in the real root
    /// via `HIPPIUS_PROVENANCE_ROOT_PUBKEY` and would legitimately fail
    /// this assertion.
    #[cfg(not(feature = "prod-root"))]
    const EXPECTED_DEV_ROOT_PUBKEY_HEX: &str =
        "e6fec6b20e2a6848537e70c195e99dce63a09f6d17551845e6eda126be53adab";

    #[cfg(not(feature = "prod-root"))]
    #[test]
    fn bundled_root_pubkey_is_the_committed_dev_root() {
        let key = bundled_root_pubkey().expect("compiled-in §22 root key must parse");
        // `assert!` with a static message, not `assert_eq!` — a
        // failure must not echo key material into a CI log, even
        // though this key is public (pubkey-hygiene discipline).
        assert!(
            hex::encode(key.to_bytes()) == EXPECTED_DEV_ROOT_PUBKEY_HEX,
            "compiled-in §22 root key is not the committed dev root — wrong include_str! path?"
        );
    }

    /// Mode-independent: whatever the anchor (dev fallback or a
    /// `HIPPIUS_PROVENANCE_ROOT_PUBKEY` override), it MUST parse to a
    /// valid Ed25519 verifying key — else every provenance verify would
    /// fail closed at run time. Guards a malformed build-time override.
    #[test]
    fn bundled_root_pubkey_parses() {
        bundled_root_pubkey().expect("compiled-in §22 root key must parse to a valid Ed25519 key");
    }

    #[test]
    fn sha256_is_the_standard_digest() {
        assert_eq!(sha256(b""), Sha256::digest(b"").as_slice());
    }
}
