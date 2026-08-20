//! Known-answer tests for the self-generated miner identity:
//! generate → persist → reload, the on-disk file modes, atomicity,
//! and the fail-closed parse paths.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use hippius_miner_agent::{MinerAgentError, MinerIdentity};
use tempfile::TempDir;

fn paths(dir: &TempDir) -> (PathBuf, PathBuf) {
    (
        dir.path().join("identity.key"),
        dir.path().join("identity.pub"),
    )
}

#[test]
fn generate_persist_reload_round_trips() {
    let dir = TempDir::new().unwrap();
    let (key, pubp) = paths(&dir);
    let id = MinerIdentity::generate().unwrap();
    id.persist(&key, &pubp).unwrap();
    let loaded = MinerIdentity::load(&key, &pubp).unwrap();
    assert_eq!(id.pubkey_hex(), loaded.pubkey_hex());
}

#[test]
fn reloaded_identity_signs_compatibly() {
    let dir = TempDir::new().unwrap();
    let (key, pubp) = paths(&dir);
    let id = MinerIdentity::generate().unwrap();
    id.persist(&key, &pubp).unwrap();
    let loaded = MinerIdentity::load(&key, &pubp).unwrap();
    let msg = b"miner served-receipt body";
    // A signature from the RELOADED key verifies under the ORIGINAL
    // key's public half — proof the same keypair survived the round trip.
    let sig = loaded.sign(msg);
    assert!(id.verifying_key().verify_strict(msg, &sig).is_ok());
}

#[test]
fn key_file_is_0400_pub_file_is_0444() {
    let dir = TempDir::new().unwrap();
    let (key, pubp) = paths(&dir);
    MinerIdentity::generate()
        .unwrap()
        .persist(&key, &pubp)
        .unwrap();
    let key_mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    let pub_mode = std::fs::metadata(&pubp).unwrap().permissions().mode() & 0o777;
    assert_eq!(key_mode, 0o400, "secret key must be owner-read-only");
    assert_eq!(pub_mode, 0o444, "public key is world-readable");
}

#[test]
fn key_file_holds_64_hex_chars() {
    let dir = TempDir::new().unwrap();
    let (key, pubp) = paths(&dir);
    MinerIdentity::generate()
        .unwrap()
        .persist(&key, &pubp)
        .unwrap();
    let raw = std::fs::read_to_string(&key).unwrap();
    assert_eq!(raw.trim().len(), 64);
    assert!(raw.trim().chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn persist_leaves_no_temp_files() {
    let dir = TempDir::new().unwrap();
    let (key, pubp) = paths(&dir);
    MinerIdentity::generate()
        .unwrap()
        .persist(&key, &pubp)
        .unwrap();
    // Exactly the two final files — the atomic temp must be renamed
    // away, never left behind.
    let count = std::fs::read_dir(dir.path()).unwrap().count();
    assert_eq!(count, 2, "atomic write must leave no temp file");
}

#[test]
fn persisting_the_same_identity_twice_is_byte_stable() {
    let dir = TempDir::new().unwrap();
    let (key, pubp) = paths(&dir);
    let id = MinerIdentity::generate().unwrap();
    id.persist(&key, &pubp).unwrap();
    let first = std::fs::read(&key).unwrap();
    id.persist(&key, &pubp).unwrap();
    let second = std::fs::read(&key).unwrap();
    assert_eq!(first, second);
}

#[test]
fn load_missing_key_is_identity_missing() {
    let dir = TempDir::new().unwrap();
    let (key, pubp) = paths(&dir);
    assert!(matches!(
        MinerIdentity::load(&key, &pubp),
        Err(MinerAgentError::IdentityMissing)
    ));
}

#[test]
fn load_rejects_a_tampered_pub_sidecar() {
    let dir = TempDir::new().unwrap();
    let (key, pubp) = paths(&dir);
    MinerIdentity::generate()
        .unwrap()
        .persist(&key, &pubp)
        .unwrap();
    // Overwrite the .pub with a different (valid-shape) public key.
    // The sidecar is persisted 0444 (read-only), so remove it first —
    // a real tamper would come from a writer with that capability.
    let other = MinerIdentity::generate().unwrap();
    std::fs::remove_file(&pubp).unwrap();
    std::fs::write(&pubp, other.pubkey_hex()).unwrap();
    assert!(matches!(
        MinerIdentity::load(&key, &pubp),
        Err(MinerAgentError::IdentityParse("pub-mismatch"))
    ));
}

#[test]
fn load_rejects_a_malformed_key_file() {
    let dir = TempDir::new().unwrap();
    let (key, pubp) = paths(&dir);
    std::fs::write(&key, "this-is-not-hex").unwrap();
    std::fs::write(&pubp, "00").unwrap();
    assert!(matches!(
        MinerIdentity::load(&key, &pubp),
        Err(MinerAgentError::IdentityParse(_))
    ));
}

#[test]
fn key_present_reflects_the_file() {
    let dir = TempDir::new().unwrap();
    let (key, pubp) = paths(&dir);
    assert!(!MinerIdentity::key_present(&key));
    MinerIdentity::generate()
        .unwrap()
        .persist(&key, &pubp)
        .unwrap();
    assert!(MinerIdentity::key_present(&key));
}
