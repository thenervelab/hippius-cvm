//! `--integrity-wipe` wiring: a distinct mode that needs no `--kbs-url`,
//! refuses every release/confirm flag, and fails closed with
//! `EXIT_WIPE_FAILED` on a target it must not touch — before any write.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_hippius-guest-release");
/// clap's own usage-error code.
const EXIT_CLAP_USAGE: i32 = 2;
const EXIT_WIPE_FAILED: i32 = 4;

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn hippius-guest-release");
    (
        out.status.code().expect("exited with a code"),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn wipe_mode_needs_no_kbs_url_and_refuses_a_non_mapper_target() {
    let (code, stderr) = run(&["--integrity-wipe", "/dev/null"]);
    assert_eq!(code, EXIT_WIPE_FAILED, "{stderr}");
    assert!(stderr.contains("fail-closed: integrity-wipe"), "{stderr}");
    assert!(stderr.contains("/dev/mapper/"), "{stderr}");
}

#[test]
fn wipe_mode_refuses_a_missing_mapper_device() {
    let (code, stderr) = run(&["--integrity-wipe", "/dev/mapper/hippius-no-such-device"]);
    assert_eq!(code, EXIT_WIPE_FAILED, "{stderr}");
}

#[test]
fn wipe_mode_conflicts_with_every_other_mode() {
    for extra in [
        &["--kbs-url", "https://127.0.0.1:1"][..],
        &["--ticket", "/nonexistent"][..],
        &["--confirm-volume-stamp", "/run/x"][..],
        &["--volume-stamp-expected-out", "/run/x"][..],
    ] {
        let mut args = vec!["--integrity-wipe", "/dev/mapper/x"];
        args.extend_from_slice(extra);
        let (code, stderr) = run(&args);
        assert_eq!(code, EXIT_CLAP_USAGE, "{extra:?} accepted: {stderr}");
    }
}

#[test]
fn release_mode_still_requires_kbs_url() {
    let (code, stderr) = run(&["--ticket", "/nonexistent"]);
    assert_eq!(code, EXIT_CLAP_USAGE, "{stderr}");
    assert!(stderr.contains("--kbs-url"), "{stderr}");
}
