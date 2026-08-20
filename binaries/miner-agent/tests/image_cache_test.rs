//! End-to-end tests for the image cache, driven against the committed
//! PR-F4 provenance vectors in `test_vectors/provenance/` — the real
//! `provenance.cbor` signed by the committed dev §22 root key, and the
//! real `artifact.bin`. The cache runs over `MemoryImageStore` (the
//! real, idempotent in-memory backend), so the §22 signature
//! verification, the canonical-CBOR decode, the hash gating, and the
//! content-addressed cache reuse are all exercised for real — the same
//! shape as the `miner-uki-fetch` KAT, one layer up through
//! `ImageCache`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use hippius_image_provenance::build::provenance_object_key;
use hippius_image_provenance::sign::verify_provenance;
use hippius_image_provenance::store::{ImageStore, MemoryImageStore};
use hippius_miner_agent::ImageCache;
use hippius_miner_uki_fetch::{bundled_root_pubkey, FetchOutcome};
use hippius_types::provenance::SignedProvenance;
use tempfile::TempDir;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_vectors/provenance")
}

/// The committed vectors plus the artifact's content address,
/// recovered by verifying the provenance under the bundled dev root.
struct Vectors {
    provenance_cbor: Vec<u8>,
    artifact: Vec<u8>,
    artifact_sha256: [u8; 32],
    artifact_hex: String,
    s3_key: String,
}

fn load_vectors() -> Vectors {
    let provenance_cbor = std::fs::read(vectors_dir().join("provenance.cbor")).unwrap();
    let artifact = std::fs::read(vectors_dir().join("artifact.bin")).unwrap();
    let signed = SignedProvenance::decode(&provenance_cbor).expect("decode provenance.cbor");
    let map = verify_provenance(&signed, &bundled_root_pubkey().unwrap())
        .expect("committed provenance.cbor must verify under the bundled dev §22 root");
    Vectors {
        artifact_hex: hex::encode(map.artifact_sha256),
        artifact_sha256: map.artifact_sha256,
        s3_key: map.s3_key,
        provenance_cbor,
        artifact,
    }
}

/// A `MemoryImageStore` holding the committed image at F4's keys.
fn populated_store(v: &Vectors) -> MemoryImageStore {
    let store = MemoryImageStore::new();
    store
        .put(
            &provenance_object_key(&v.artifact_sha256),
            &v.provenance_cbor,
        )
        .unwrap();
    store.put(&v.s3_key, &v.artifact).unwrap();
    store
}

#[test]
fn fetch_verified_installs_the_committed_uki() {
    let v = load_vectors();
    let tmp = TempDir::new().unwrap();
    let cache = ImageCache::new(Box::new(populated_store(&v)), tmp.path().join("cache")).unwrap();
    let staging = tmp.path().join("staging");

    let (outcome, path) = cache.fetch_verified(&v.artifact_hex, &staging).unwrap();
    assert_eq!(outcome, FetchOutcome::FetchedFromStore);
    assert_eq!(std::fs::read(&path).unwrap(), v.artifact);
}

#[test]
fn second_fetch_is_a_cache_hit() {
    let v = load_vectors();
    let tmp = TempDir::new().unwrap();
    let cache = ImageCache::new(Box::new(populated_store(&v)), tmp.path().join("cache")).unwrap();

    // First fetch populates the content-addressed cache.
    cache
        .fetch_verified(&v.artifact_hex, &tmp.path().join("s1"))
        .unwrap();
    // Second fetch, fresh staging dir → served from the cache.
    // `miner-uki-fetch::fetch` still verifies the §22 signature here.
    let (outcome, path) = cache
        .fetch_verified(&v.artifact_hex, &tmp.path().join("s2"))
        .unwrap();
    assert_eq!(outcome, FetchOutcome::FetchedFromCache);
    assert_eq!(std::fs::read(&path).unwrap(), v.artifact);
}

#[test]
fn already_installed_image_is_detected() {
    let v = load_vectors();
    let tmp = TempDir::new().unwrap();
    let cache = ImageCache::new(Box::new(populated_store(&v)), tmp.path().join("cache")).unwrap();
    let staging = tmp.path().join("staging");

    cache.fetch_verified(&v.artifact_hex, &staging).unwrap();
    let (outcome, _) = cache.fetch_verified(&v.artifact_hex, &staging).unwrap();
    assert_eq!(outcome, FetchOutcome::AlreadyPresent);
}

#[test]
fn tampered_provenance_signature_fails_closed() {
    let v = load_vectors();
    let tmp = TempDir::new().unwrap();
    let store = MemoryImageStore::new();
    let mut tampered = v.provenance_cbor.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff; // corrupt the last signature byte
    store
        .put(&provenance_object_key(&v.artifact_sha256), &tampered)
        .unwrap();
    store.put(&v.s3_key, &v.artifact).unwrap();
    let cache = ImageCache::new(Box::new(store), tmp.path().join("cache")).unwrap();
    let staging = tmp.path().join("staging");

    assert!(cache.fetch_verified(&v.artifact_hex, &staging).is_err());
    let installed = staging.join(format!("{}.uki", v.artifact_hex));
    assert!(!installed.exists(), "a rejected fetch installs nothing");
}

#[test]
fn tampered_uki_binary_fails_closed() {
    let v = load_vectors();
    let tmp = TempDir::new().unwrap();
    let store = MemoryImageStore::new();
    store
        .put(
            &provenance_object_key(&v.artifact_sha256),
            &v.provenance_cbor,
        )
        .unwrap();
    // Genuine provenance, but the stored UKI bytes are not the real one.
    store.put(&v.s3_key, b"not-the-real-uki-bytes").unwrap();
    let cache = ImageCache::new(Box::new(store), tmp.path().join("cache")).unwrap();

    assert!(cache
        .fetch_verified(&v.artifact_hex, &tmp.path().join("staging"))
        .is_err());
}
