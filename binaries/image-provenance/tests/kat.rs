//! Known-answer test for the §22 image-provenance signature.
//!
//! Freezes the signed `provenance.cbor` produced for the pinned input
//! tuple in `test_vectors/provenance/` under the committed dev §22
//! root key. A canonical-encoding change, a key-file edit, or a
//! fixture edit that shifts the signature fails CI loudly instead of
//! silently moving every production provenance signature.
//!
//! Regenerate deliberately — see `test_vectors/provenance/REGENERATE.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use hippius_image_provenance::build::{build_provenance, BuildInputs};
use hippius_image_provenance::measurement::MeasurementEnvelope;
use hippius_image_provenance::sign::{
    load_signing_key, load_verifying_key, public_key_bytes, sign_provenance, verify_provenance,
};
use hippius_types::provenance::SignedProvenance;

/// Pinned build timestamp — frozen so the KAT signature is stable.
/// (Ed25519 is deterministic, so a fixed key + fixed body ⇒ fixed sig.)
const KAT_BUILT_AT_UNIX: u64 = 1_700_000_000;

/// The §22 dev root key + the KAT vectors live at the repo root,
/// two levels above this crate's manifest dir.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn dev_seed_path() -> PathBuf {
    repo_root().join("packer/kbs-uki/keys/dev/provenance-root.dev.ed25519")
}

fn dev_pub_path() -> PathBuf {
    repo_root().join("packer/kbs-uki/keys/dev/provenance-root.dev.ed25519.pub")
}

fn vectors_dir() -> PathBuf {
    repo_root().join("test_vectors/provenance")
}

/// Build + sign the provenance for the pinned vector tuple. Uses the
/// committed dev signing key; never touches the wall clock.
fn build_and_sign() -> SignedProvenance {
    let sk = load_signing_key(&dev_seed_path()).expect("load dev signing key");
    let envelope = MeasurementEnvelope::load(&vectors_dir().join("measurement.json"))
        .expect("load measurement envelope");
    let artifact = std::fs::read(vectors_dir().join("artifact.bin")).expect("read artifact.bin");
    let map = build_provenance(&BuildInputs {
        envelope: &envelope,
        artifact_bytes: &artifact,
        s3_bucket: "hippius-compute-images",
        built_at_unix: KAT_BUILT_AT_UNIX,
        signer_pubkey: public_key_bytes(&sk),
    })
    .expect("build provenance map");
    sign_provenance(&sk, &map).expect("sign provenance")
}

#[test]
fn provenance_kat_matches_the_frozen_vector() {
    let produced = build_and_sign().encode().expect("encode signed provenance");
    let expected = std::fs::read(vectors_dir().join("provenance.cbor")).expect(
        "test_vectors/provenance/provenance.cbor missing — run \
         `cargo test -p hippius-image-provenance --test kat \
         regenerate_committed_vectors -- --ignored --exact`",
    );
    assert_eq!(
        produced, expected,
        "provenance signature changed — a canonical-encoding, key, or fixture edit shifted \
         the KAT. If intentional, regenerate per test_vectors/provenance/REGENERATE.md."
    );
}

#[test]
fn provenance_kat_verifies_under_the_committed_dev_pubkey() {
    let signed = build_and_sign();
    let root = load_verifying_key(&dev_pub_path()).expect("load dev pubkey");
    verify_provenance(&signed, &root)
        .expect("KAT provenance must verify under the committed dev §22 root pubkey");
}

#[test]
fn committed_dev_pubkey_matches_the_seed() {
    // The `.pub` file MUST be the public key of the committed seed —
    // otherwise `verify` against the operator-distributed pubkey would
    // silently diverge from what `sign` produced.
    let sk = load_signing_key(&dev_seed_path()).expect("load dev signing key");
    let root = load_verifying_key(&dev_pub_path()).expect("load dev pubkey");
    assert_eq!(
        public_key_bytes(&sk),
        root.to_bytes(),
        "provenance-root.dev.ed25519.pub is not the public key of provenance-root.dev.ed25519"
    );
}

/// Regeneration helper — `#[ignore]`d so it never runs in CI. Run it
/// deliberately to (re)write the committed dev pubkey + KAT vector
/// after an intentional change:
///
/// ```text
/// cargo test -p hippius-image-provenance --test kat \
///     regenerate_committed_vectors -- --ignored --exact
/// ```
#[test]
#[ignore]
fn regenerate_committed_vectors() {
    let sk = load_signing_key(&dev_seed_path()).expect("load dev signing key");
    std::fs::write(
        dev_pub_path(),
        format!("{}\n", hex::encode(public_key_bytes(&sk))),
    )
    .expect("write dev pubkey");
    std::fs::write(
        vectors_dir().join("provenance.cbor"),
        build_and_sign().encode().expect("encode signed provenance"),
    )
    .expect("write provenance.cbor");
    println!("regenerated: dev §22 root pubkey + test_vectors/provenance/provenance.cbor");
}
