//! Known-answer + fail-closed tests for the miner UKI fetch tool.
//!
//! Built entirely on the committed PR-F4 vectors in
//! `test_vectors/provenance/` — the real `provenance.cbor` signed by
//! the committed dev §22 root key, and the real `artifact.bin`. The
//! fetch path runs against `MemoryImageStore` (PR-F4's real, idempotent
//! in-memory backend — not a mock) populated at F4's content-addressed
//! keys, so the §22 signature verification, canonical-CBOR decode, and
//! hash gating are all exercised for real.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use hippius_image_provenance::build::provenance_object_key;
use hippius_image_provenance::sign::verify_provenance;
use hippius_image_provenance::store::{ImageStore, MemoryImageStore};
use hippius_miner_uki_fetch::{bundled_root_pubkey, fetch, FetchOutcome};
use hippius_types::provenance::SignedProvenance;
use tempfile::TempDir;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_vectors/provenance")
}

fn read_vector(name: &str) -> Vec<u8> {
    std::fs::read(vectors_dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// The committed PR-F4 vectors plus the artifact's content address,
/// recovered by verifying the provenance under the bundled dev root.
struct Vectors {
    provenance_cbor: Vec<u8>,
    artifact: Vec<u8>,
    artifact_sha256: [u8; 32],
    s3_key: String,
}

fn load_vectors() -> Vectors {
    let provenance_cbor = read_vector("provenance.cbor");
    let artifact = read_vector("artifact.bin");
    let signed = SignedProvenance::decode(&provenance_cbor).expect("decode provenance.cbor");
    let map = verify_provenance(&signed, &bundled_root_pubkey().unwrap())
        .expect("committed provenance.cbor must verify under the bundled dev §22 root");
    Vectors {
        provenance_cbor,
        artifact,
        artifact_sha256: map.artifact_sha256,
        s3_key: map.s3_key,
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
fn kat_fetch_installs_the_verified_uki() {
    let v = load_vectors();
    let store = populated_store(&v);
    let out_dir = TempDir::new().unwrap();
    let output = out_dir.path().join("kbs.uki");

    let outcome = fetch(&store, &v.artifact_sha256, &output, None).unwrap();
    assert_eq!(outcome, FetchOutcome::FetchedFromStore);
    assert_eq!(std::fs::read(&output).unwrap(), v.artifact);
}

#[test]
fn kat_fetch_is_idempotent() {
    let v = load_vectors();
    let store = populated_store(&v);
    let out_dir = TempDir::new().unwrap();
    let output = out_dir.path().join("kbs.uki");

    fetch(&store, &v.artifact_sha256, &output, None).unwrap();
    // Second run sees the verified image already in place → skip.
    let second = fetch(&store, &v.artifact_sha256, &output, None).unwrap();
    assert_eq!(second, FetchOutcome::AlreadyPresent);
    assert_eq!(std::fs::read(&output).unwrap(), v.artifact);
}

#[test]
fn kat_cache_is_reused_on_a_second_fetch() {
    let v = load_vectors();
    let store = populated_store(&v);
    let cache = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();
    let first = out_dir.path().join("a.uki");
    let second = out_dir.path().join("b.uki");

    // First fetch populates the content-addressed cache.
    assert_eq!(
        fetch(&store, &v.artifact_sha256, &first, Some(cache.path())).unwrap(),
        FetchOutcome::FetchedFromStore
    );
    // A fresh output path, same cache → served from the cache.
    assert_eq!(
        fetch(&store, &v.artifact_sha256, &second, Some(cache.path())).unwrap(),
        FetchOutcome::FetchedFromCache
    );
    assert_eq!(std::fs::read(&second).unwrap(), v.artifact);
}

#[test]
fn kat_rejects_a_tampered_provenance_signature() {
    let v = load_vectors();
    let store = MemoryImageStore::new();
    let mut tampered = v.provenance_cbor.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff; // corrupt the last signature byte
    store
        .put(&provenance_object_key(&v.artifact_sha256), &tampered)
        .unwrap();
    store.put(&v.s3_key, &v.artifact).unwrap();

    let out_dir = TempDir::new().unwrap();
    let output = out_dir.path().join("kbs.uki");
    assert!(fetch(&store, &v.artifact_sha256, &output, None).is_err());
    assert!(!output.exists(), "a rejected fetch must install nothing");
}

#[test]
fn kat_rejects_a_tampered_uki_binary() {
    let v = load_vectors();
    let store = MemoryImageStore::new();
    store
        .put(
            &provenance_object_key(&v.artifact_sha256),
            &v.provenance_cbor,
        )
        .unwrap();
    // The provenance is genuine; the stored UKI bytes are not.
    store.put(&v.s3_key, b"not-the-real-uki-bytes").unwrap();

    let out_dir = TempDir::new().unwrap();
    let output = out_dir.path().join("kbs.uki");
    assert!(fetch(&store, &v.artifact_sha256, &output, None).is_err());
    assert!(!output.exists());
}

#[test]
fn kat_rejects_an_absent_image() {
    // An empty store — the provenance GET fails closed.
    let v = load_vectors();
    let store = MemoryImageStore::new();
    let out_dir = TempDir::new().unwrap();
    let output = out_dir.path().join("kbs.uki");
    assert!(fetch(&store, &v.artifact_sha256, &output, None).is_err());
    assert!(!output.exists());
}

#[test]
fn kat_rejects_provenance_for_a_different_artifact() {
    // Ask for a hash the genuine provenance does not describe: the
    // provenance is stored under the *requested* key but its signed
    // `artifact_sha256` is something else → fail closed.
    let v = load_vectors();
    let store = MemoryImageStore::new();
    let mut wrong_hash = v.artifact_sha256;
    wrong_hash[0] ^= 0xff;
    store
        .put(&provenance_object_key(&wrong_hash), &v.provenance_cbor)
        .unwrap();
    store.put(&v.s3_key, &v.artifact).unwrap();

    let out_dir = TempDir::new().unwrap();
    let output = out_dir.path().join("kbs.uki");
    assert!(fetch(&store, &wrong_hash, &output, None).is_err());
    assert!(!output.exists());
}

#[test]
fn kat_idempotency_skip_still_requires_verifiable_provenance() {
    // An `output` already matching `--hash` must NOT be accepted when
    // the store holds no verifiable provenance for it — the §22 check
    // is never skipped, not even on the idempotency fast path.
    let v = load_vectors();
    let store = MemoryImageStore::new(); // empty — no provenance to verify
    let out_dir = TempDir::new().unwrap();
    let output = out_dir.path().join("kbs.uki");
    // Pre-place a file that genuinely hashes to the requested artifact.
    std::fs::write(&output, &v.artifact).unwrap();

    assert!(
        fetch(&store, &v.artifact_sha256, &output, None).is_err(),
        "a hash-matching output must not short-circuit the §22 verification"
    );
}

#[test]
fn kat_a_broken_cache_dir_does_not_block_the_install() {
    // The cache is an optimisation: a misconfigured `--cache-dir` must
    // not stop the verified image from being installed at `--output`.
    let v = load_vectors();
    let store = populated_store(&v);
    let out_dir = TempDir::new().unwrap();
    let output = out_dir.path().join("kbs.uki");
    // A cache "directory" that is actually a regular file — every
    // cache read + write against it fails.
    let bad_cache = out_dir.path().join("not-a-directory");
    std::fs::write(&bad_cache, b"i am a file, not a directory").unwrap();

    let outcome = fetch(&store, &v.artifact_sha256, &output, Some(&bad_cache)).unwrap();
    assert_eq!(outcome, FetchOutcome::FetchedFromStore);
    assert_eq!(std::fs::read(&output).unwrap(), v.artifact);
}
