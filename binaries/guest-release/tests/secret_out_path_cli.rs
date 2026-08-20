//! P9/#12 — end-to-end wiring of the tmpfs-only `*_out` path gate.
//!
//! `src/main.rs`'s unit tests pin `check_secret_out_path` itself; these
//! pin that `main` actually CALLS it, for each of the three
//! secret-bearing flags, BEFORE the release exchange starts.
//!
//! The discriminator is the exit code:
//!
//! - `EXIT_USAGE` (1) — the gate refused the path. Nothing was sent to
//!   the KBS, no key was unwrapped.
//! - `EXIT_RELEASE_FAILED` (3) — the gate PASSED and the run proceeded
//!   far enough to fail on the (deliberately bogus) ticket.
//!
//! So an accepted `/run/...` path must produce 3, never 1 — which is
//! what keeps this gate from silently bricking the live boot path.
//!
//! Every invocation points `--kbs-url` at a closed loopback port and
//! `--ticket` at a nonexistent file, so no test here touches the
//! network: the ticket load fails first.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_hippius-guest-release");
const EXIT_USAGE: i32 = 1;
const EXIT_RELEASE_FAILED: i32 = 3;

/// Run the binary with `--kbs-url`/`--ticket` stubs plus `extra`, and
/// return `(exit_code, stderr)`.
fn run(extra: &[&str]) -> (i32, String) {
    let out = Command::new(BIN)
        .args(["--kbs-url", "https://127.0.0.1:1"])
        .args(["--ticket", "/nonexistent/hippius-guest-release-test-ticket"])
        .args(extra)
        .output()
        .expect("spawn hippius-guest-release");
    (
        out.status.code().expect("exited with a code"),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn refuses_a_persistent_lifecycle_key_out_before_the_release() {
    let (code, stderr) = run(&["--lifecycle-key-out", "/hippius-state/lifecycle.key"]);
    assert_eq!(
        code, EXIT_USAGE,
        "a persistent --lifecycle-key-out must be refused as a usage \
         error, not run into the release exchange; stderr: {stderr}"
    );
    // The refusal must NAME the offending path (§20: the path, never
    // the key bytes) so the operator can fix the launch cmdline.
    assert!(
        stderr.contains("/hippius-state/lifecycle.key"),
        "refusal must name the offending path; stderr: {stderr}"
    );
    assert!(
        stderr.contains("--lifecycle-key-out"),
        "refusal must name the offending flag; stderr: {stderr}"
    );
}

#[test]
fn accepts_the_live_production_lifecycle_key_out() {
    // `/run/hippius/lifecycle.key` is what vali stamps into the
    // MEASURED cmdline today. If this ever returns EXIT_USAGE, every
    // tenant VM is unbootable.
    let (code, stderr) = run(&["--lifecycle-key-out", "/run/hippius/lifecycle.key"]);
    assert_eq!(
        code, EXIT_RELEASE_FAILED,
        "the live production path must PASS the gate and fail later on \
         the bogus ticket; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("/run/hippius/lifecycle.key"),
        "an accepted path must not be echoed as a refusal; stderr: {stderr}"
    );
}

#[test]
fn refuses_a_dot_dot_traversal_out_of_run() {
    let (code, stderr) = run(&["--lifecycle-key-out", "/run/../hippius-state/lifecycle.key"]);
    assert_eq!(code, EXIT_USAGE, "stderr: {stderr}");
    assert!(
        stderr.contains("/run/../hippius-state/lifecycle.key"),
        "stderr: {stderr}"
    );
}

#[test]
fn refuses_a_persistent_userdata_out() {
    let (code, stderr) = run(&["--userdata-out", "/var/lib/hippius/user-data"]);
    assert_eq!(code, EXIT_USAGE, "stderr: {stderr}");
    assert!(stderr.contains("/var/lib/hippius/user-data"), "{stderr}");
    assert!(stderr.contains("--userdata-out"), "{stderr}");
}

#[test]
fn accepts_the_live_production_userdata_out() {
    let (code, stderr) = run(&["--userdata-out", "/run/cloud-init/seed/user-data"]);
    assert_eq!(code, EXIT_RELEASE_FAILED, "stderr: {stderr}");
}

#[test]
fn refuses_a_persistent_volume_stamp_ctx_out() {
    let (code, stderr) = run(&["--volume-stamp-ctx-out", "/hippius-state/volume-stamp.ctx"]);
    assert_eq!(code, EXIT_USAGE, "stderr: {stderr}");
    assert!(
        stderr.contains("/hippius-state/volume-stamp.ctx"),
        "{stderr}"
    );
    assert!(stderr.contains("--volume-stamp-ctx-out"), "{stderr}");
}

#[test]
fn accepts_the_live_production_volume_stamp_ctx_out() {
    let (code, stderr) = run(&["--volume-stamp-ctx-out", "/run/hippius/volume-stamp.ctx"]);
    assert_eq!(code, EXIT_RELEASE_FAILED, "stderr: {stderr}");
}

#[test]
fn does_not_guard_the_deliberately_persistent_counter_files() {
    // `--last/--new-counter-file` point at the miner-provisioned state
    // disk BY DESIGN (a boot count, not a secret). Guarding them would
    // refuse every production boot — pin that they are NOT guarded.
    let (code, stderr) = run(&[
        "--last-counter-file",
        "/hippius-state/boot-counter",
        "--new-counter-file",
        "/hippius-state/boot-counter",
    ]);
    assert_eq!(
        code, EXIT_RELEASE_FAILED,
        "the state-disk counter paths must not be gated; stderr: {stderr}"
    );
}

#[test]
fn does_not_guard_the_non_secret_volume_stamp_expected_out() {
    // Mode 0644, one decimal integer, also on the wire in the clear.
    let (code, stderr) = run(&[
        "--volume-stamp-expected-out",
        "/hippius-state/volume-stamp.expected",
    ]);
    assert_eq!(code, EXIT_RELEASE_FAILED, "stderr: {stderr}");
}
