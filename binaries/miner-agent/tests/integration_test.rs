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

/// The 200-byte `HIPPIUS::REGISTER::v1` challenge for the Ed25519 seed
/// `0x11 × 32` on mainnet (account `0x44 × 32`, block 1000, expiry 1100).
const REGISTER_CHALLENGE_SEED_11: &str = "0x484950504955533a3a52454749535445523a3a763100000028a6b54823f786c5dd8520ef7bdb0ee2639173815bfbb7719bcf58ef9eb5e1f944444444444444444444444444444444444444444444444444444444444444447576f054116b1dff9bf2538c8980809de003d3b8e049f925b50bc28ccf75e1345555555555555555555555555555555555555555555555555555555555555555e80300000000000066666666666666666666666666666666666666666666666666666666666666664c04000000000000";

#[test]
fn sign_coldkey_registration_signs_from_a_raw_keypair_and_leaves_it_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let keypair = dir.path().join("keypair.bin");
    std::fs::write(&keypair, [0x11u8; 32]).unwrap();
    std::fs::set_permissions(&keypair, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::metadata(&keypair).unwrap();

    let family = format!("0x{}", "aa".repeat(32));
    let child = format!("0x{}", "bb".repeat(32));
    let out = Command::new(bin())
        .args(["sign-coldkey-registration", "--keypair"])
        .arg(&keypair)
        .args(["--challenge", REGISTER_CHALLENGE_SEED_11])
        .args(["--family", &family, "--child", &child, "--nonce", "3"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        json["node_id"],
        "12D3KooWPqT2nMDSiXUSx5D7fasaxhxKigVhcqfkKqrLghCq9jxz"
    );
    assert_eq!(json["account"], format!("0x{}", "44".repeat(32)));
    assert_eq!(json["expires_at"], 1100);
    assert_eq!(json["arion"]["nonce"], 3);
    assert_eq!(json["arion"]["node_id"], json["public_key"]);
    // The seed never reaches stdout or stderr.
    let seed_hex = "11".repeat(32);
    assert!(!stdout.contains(&seed_hex));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(&seed_hex));

    // Read-only: bytes, mode and mtime unchanged.
    let after = std::fs::metadata(&keypair).unwrap();
    assert_eq!(std::fs::read(&keypair).unwrap(), [0x11u8; 32]);
    assert_eq!(after.permissions().mode(), before.permissions().mode());
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn sign_coldkey_registration_refuses_partial_arion_args_and_bad_keys() {
    let dir = tempfile::tempdir().unwrap();
    let keypair = dir.path().join("keypair.bin");
    std::fs::write(&keypair, [0x11u8; 32]).unwrap();
    let family = format!("0x{}", "aa".repeat(32));
    let run = |extra: &[&str]| {
        Command::new(bin())
            .args(["sign-coldkey-registration", "--keypair"])
            .arg(&keypair)
            .args(["--challenge", REGISTER_CHALLENGE_SEED_11])
            .args(extra)
            .output()
            .unwrap()
    };
    let out = run(&["--family", &family]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("registration-arg/arion-args-all-or-none")
    );

    // A hex identity.key is not an Arion keypair.
    std::fs::write(&keypair, "11".repeat(32)).unwrap();
    let out = run(&[]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("identity-parse/keypair-len"));
}
