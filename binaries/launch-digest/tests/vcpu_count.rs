//! The vCPU count is part of the SEV-SNP launch measurement.
//!
//! The PSP folds one VMSA page per vCPU into the launch digest, so a
//! guest started with N-1 (or N+1) vCPUs carries another measurement than
//! the flavor's N. vali pins only the digest of the flavor's vCPU count
//! (computed by THIS binary, `orchestration.services.launch_digest`), and
//! the KBS releases the KEK only to a report whose measurement is both in
//! the ticket's `allowed_measurements` and in the §22 allowlist — so a
//! miner that shaves vCPUs off a VM gets no disk key and the VM does not
//! boot. This test pins the premise with the real binary over the
//! committed `test_vectors/snp/` inputs.

#![cfg(all(feature = "snp", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_vectors/snp")
}

fn digest(vcpus: u32, vcpu_type: &str) -> String {
    let v = vectors();
    let out = Command::new(env!("CARGO_BIN_EXE_hippius-launch-digest"))
        .arg("--ovmf")
        .arg(v.join("ovmf.bin"))
        .arg("--kernel")
        .arg(v.join("kernel.bin"))
        .arg("--initrd")
        .arg(v.join("initrd.bin"))
        .arg("--cmdline")
        .arg(v.join("cmdline"))
        .args(["--vcpus", &vcpus.to_string(), "--vcpu-type", vcpu_type])
        .output()
        .expect("run hippius-launch-digest");
    assert!(
        out.status.success(),
        "launch-digest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hex = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert_eq!(hex.len(), 96, "{hex}");
    hex
}

/// Every catalogue vCPU count (`hippius_types::flavor`) and its
/// neighbours: N and N-1 never share a digest, on every generation vali
/// measures for.
#[test]
fn every_vcpu_count_has_its_own_launch_digest() {
    for vcpu_type in ["EpycMilan", "EpycGenoa", "EpycTurin"] {
        let mut seen = BTreeSet::new();
        for n in [1u32, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33] {
            assert!(
                seen.insert(digest(n, vcpu_type)),
                "{vcpu_type}: {n} vCPUs collides with another count"
            );
        }
        for n in [2u32, 4, 8, 16, 32] {
            assert_ne!(
                digest(n, vcpu_type),
                digest(n - 1, vcpu_type),
                "{vcpu_type}: {n} vs {} vCPUs",
                n - 1
            );
        }
    }
}

#[test]
fn the_digest_is_deterministic_for_a_given_vcpu_count() {
    assert_eq!(digest(4, "EpycGenoa"), digest(4, "EpycGenoa"));
}
