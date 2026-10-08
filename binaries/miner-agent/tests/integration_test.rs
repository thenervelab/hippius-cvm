//! End-to-end CLI tests — drive the built `hippius-miner-agent`
//! binary as an operator would.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use tempfile::TempDir;

/// Path to the binary under test (Cargo sets this for integration tests).
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_hippius-miner-agent")
}

/// Run `init-identity --print-pubkey` and return (success, pubkey).
fn run_init(key: &str, pubp: &str, force: bool) -> (bool, String) {
    let mut args = vec![
        "init-identity",
        "--key-output",
        key,
        "--pub-output",
        pubp,
        "--print-pubkey",
    ];
    if force {
        args.push("--force");
    }
    let out = Command::new(bin()).args(&args).output().unwrap();
    let pubkey = String::from_utf8(out.stdout).unwrap().trim().to_string();
    (out.status.success(), pubkey)
}

#[test]
fn init_identity_prints_a_64_hex_pubkey_on_stdout() {
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("identity.key");
    let pubp = dir.path().join("identity.pub");
    let (ok, pubkey) = run_init(key.to_str().unwrap(), pubp.to_str().unwrap(), false);
    assert!(ok);
    assert_eq!(
        pubkey.len(),
        64,
        "pubkey is 64 hex chars, no 0x, no whitespace"
    );
    assert!(pubkey.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(key.exists() && pubp.exists());
}

#[test]
fn init_identity_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("identity.key");
    let pubp = dir.path().join("identity.pub");
    let k = key.to_str().unwrap();
    let p = pubp.to_str().unwrap();

    let (ok1, first) = run_init(k, p, false);
    let key_after_first = std::fs::read(&key).unwrap();
    let (ok2, second) = run_init(k, p, false);
    let key_after_second = std::fs::read(&key).unwrap();

    assert!(ok1 && ok2);
    // A second run is a no-op: same pubkey, byte-identical key file.
    assert_eq!(first, second);
    assert_eq!(key_after_first, key_after_second);
}

#[test]
fn init_identity_force_regenerates() {
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("identity.key");
    let pubp = dir.path().join("identity.pub");
    let k = key.to_str().unwrap();
    let p = pubp.to_str().unwrap();

    let (_, first) = run_init(k, p, false);
    let (ok, forced) = run_init(k, p, true);
    assert!(ok);
    assert_ne!(first, forced, "--force must mint a fresh identity");
}

#[test]
fn init_identity_key_file_is_0400() {
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("identity.key");
    let pubp = dir.path().join("identity.pub");
    let out = Command::new(bin())
        .args([
            "init-identity",
            "--key-output",
            key.to_str().unwrap(),
            "--pub-output",
            pubp.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o400);
}

#[test]
fn image_fetch_against_the_s3_stub_fails_closed() {
    // The Hippius S3 backend is a stub (issue #80) — `image-fetch`
    // against it must exit non-zero, never pretend success.
    let dir = TempDir::new().unwrap();
    let out = Command::new(bin())
        .args([
            "image-fetch",
            "--hash",
            "e6fec6b20e2a6848537e70c195e99dce63a09f6d17551845e6eda126be53adab",
            "--cache-dir",
            dir.path().join("cache").to_str().unwrap(),
            "--output",
            dir.path().join("staging").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn image_fetch_rejects_a_malformed_hash() {
    let dir = TempDir::new().unwrap();
    let out = Command::new(bin())
        .args([
            "image-fetch",
            "--hash",
            "too-short",
            "--cache-dir",
            dir.path().join("cache").to_str().unwrap(),
            "--output",
            dir.path().join("staging").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn no_subcommand_is_a_usage_error() {
    let out = Command::new(bin()).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn version_prints_the_crate_version_and_the_embedded_release_tag() {
    // Play 05 matches `versions.miner_agent` (the crate version) in this
    // line, and the auto-updater matches the parenthesised release tag.
    let out = Command::new(bin()).arg("--version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim_end(),
        format!(
            "hippius-miner-agent {} ({})",
            env!("CARGO_PKG_VERSION"),
            hippius_miner_agent::release::RELEASE_TAG
        )
    );
}
