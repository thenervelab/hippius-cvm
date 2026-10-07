//! SEV-SNP pre-flight launch-digest known-answer test (`--features
//! snp`, Linux-only).
//!
//! The miner-agent pre-computes the exact digest the KBS will
//! re-derive from the running guest's SNP attestation report. This
//! test asserts that digest is **byte-identical** to the §F PR-F3
//! allowlist measurement: it reuses `test_vectors/snp/` — the same
//! pinned tuple `hippius-uki-measure --features snp` measures — and
//! freezes the result against PR-F3's `EXPECTED_SNP_DIGEST`.
//!
//! Without `--features snp` the whole file compiles away (the `sev`
//! measurement crate is Linux-only); the digest path runs on the CI
//! `cargo test -p hippius-miner-agent --features snp` lane.

#![cfg(feature = "snp")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use hippius_miner_agent::vsock::MIN_GUEST_CID;
use hippius_miner_agent::{
    compute_launch_digest_for_generation, load_cmdline, DomainUuid, QemuConfig, VmId,
};
use sev::Generation;

/// Compute the digest for the pinned vector pretending the host is the
/// given generation. The production `compute_launch_digest` derives the
/// generation from the build host's CPUID, which on a non-SNP CI box is
/// not an SNP generation at all — so the KAT pins the generation explicitly
/// to stay reproducible everywhere.
fn digest_for(gen: Generation) -> [u8; 48] {
    compute_launch_digest_for_generation(&kat_config(), gen).unwrap()
}

/// Frozen in `binaries/uki-measure` (`EXPECTED_SNP_DIGEST`) and in
/// `test_vectors/snp/REGENERATE.md`. The miner-agent's pre-flight
/// digest MUST equal it — both are `snp_calc_launch_digest` over the
/// same `(ovmf, kernel, initrd, cmdline)` tuple with the same pinned
/// launch parameters.
const EXPECTED_SNP_DIGEST: &str =
    "b98f249b158891a3d1bd5e5e136be52daabf42f1c87571649f0186086d1f907b3debcbdfac7e52498555334f937ed794";

/// `test_vectors/snp/` — repo-root-relative to this crate.
fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_vectors/snp")
}

/// A config over the pinned SNP vector: 1 vCPU (the `sev` digest folds
/// vCPU count into the VMSA), the launch parameters pinned inside
/// `launch_digest` to the §F Makefile values.
fn kat_config() -> QemuConfig {
    let v = vectors_dir();
    QemuConfig {
        vm_id: VmId::new("kat").unwrap(),
        domain_uuid: DomainUuid::parse("00000000-0000-4000-8000-000000000000").unwrap(),
        ovmf_path: v.join("ovmf.bin"),
        kernel_path: v.join("kernel.bin"),
        initrd_path: v.join("initrd.bin"),
        cmdline: load_cmdline(&v.join("cmdline")).unwrap(),
        luks_disk_path: PathBuf::from("/var/lib/hippius-miner/kat.img"),
        luks_disk_size_gb: 10,
        rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/rootfs.img"),
        rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/rootfs.verity"),
        state_disk_path: PathBuf::from("/var/lib/hippius-miner/state/kat.raw"),
        data_disk_path: None,
        data_disk_size_gb: 0,
        cpu_count: 1,
        memory_mb: 2048,
        // The digest ignores the disk + golden mode; legacy default here.
        golden: false,
        // The SEV-SNP launch digest is CID-independent — the `<vsock>`
        // device is not a measured launch input.
        cid: MIN_GUEST_CID,
        net: None,
    }
}

#[test]
fn launch_digest_matches_pr_f3_known_answer() {
    // The frozen §F value is a GENOA digest — adding Turin must not move
    // it by a single byte (no regression for Genoa hosts / the live §22
    // allowlist).
    let digest = digest_for(Generation::Genoa);
    assert_eq!(
        hex::encode(digest),
        EXPECTED_SNP_DIGEST,
        "the pre-flight launch digest diverged from the §F PR-F3 \
         allowlist measurement — a `sev`-crate bump or a fixture / \
         launch-parameter change. If intentional, regenerate per \
         test_vectors/snp/REGENERATE.md and re-attest the §22 allowlist."
    );
}

#[test]
fn launch_digest_is_48_bytes() {
    let digest = digest_for(Generation::Genoa);
    assert_eq!(digest.len(), 48, "an SEV-SNP launch digest is 384 bits");
}

#[test]
fn launch_digest_is_deterministic() {
    let a = digest_for(Generation::Genoa);
    let b = digest_for(Generation::Genoa);
    assert_eq!(a, b);
}

#[test]
fn turin_digest_is_deterministic() {
    let a = digest_for(Generation::Turin);
    let b = digest_for(Generation::Turin);
    assert_eq!(a, b, "the Turin digest must be reproducible");
    assert_eq!(a.len(), 48);
}

#[test]
fn turin_digest_differs_from_genoa() {
    // The whole point: a Turin host folds a different cpu_sig into the
    // VMSA, so its launch digest is genuinely distinct from the Genoa
    // one — that is why a Genoa-computed ticket can never match a Turin
    // guest, and why this PR exists.
    let genoa = digest_for(Generation::Genoa);
    let turin = digest_for(Generation::Turin);
    assert_ne!(
        genoa, turin,
        "Genoa and Turin must produce distinct launch digests"
    );
}

#[test]
fn milan_digest_is_deterministic_and_distinct() {
    // A Milan host (EPYC 7543) folds cpu_sig(25, 1, 1) = 0x00A00F11 into
    // the VMSA — a digest reproducible across calls and distinct from
    // both the Genoa and the Turin one.
    let a = digest_for(Generation::Milan);
    let b = digest_for(Generation::Milan);
    assert_eq!(a, b, "the Milan digest must be reproducible");
    assert_ne!(a, digest_for(Generation::Genoa), "Milan vs Genoa");
    assert_ne!(a, digest_for(Generation::Turin), "Milan vs Turin");
}

// ── customer-held keys: the guardian recipe reproduces the digest ────

use hippius_miner_agent::lifecycle::launch_digest::{
    compute_launch_digest_from_recipe, compute_launch_recipe_for_generation,
};

/// The recipe the guardian relay serves, fed back through the digest
/// computation with the artifact files it names, reproduces EXACTLY the
/// launch digest the miner measured — for every generation. This is what
/// an honest miner owes the guardian.
#[test]
fn the_guardian_recipe_reproduces_the_launch_digest() {
    let v = vectors_dir();
    for (name, gen) in [
        ("genoa", Generation::Genoa),
        ("turin", Generation::Turin),
        ("milan", Generation::Milan),
    ] {
        let recipe = compute_launch_recipe_for_generation(&kat_config(), gen).unwrap();
        recipe.validate().unwrap();
        assert_eq!(recipe.cmdline, kat_config().cmdline, "the exact cmdline");
        assert_eq!(recipe.vcpus, 1);
        assert_eq!(recipe.guest_features, 1);
        let digest = compute_launch_digest_from_recipe(
            &recipe,
            &v.join("ovmf.bin"),
            &v.join("kernel.bin"),
            &v.join("initrd.bin"),
        )
        .unwrap();
        assert_eq!(digest, digest_for(gen), "{name}");
    }
    let genoa = compute_launch_recipe_for_generation(&kat_config(), Generation::Genoa).unwrap();
    assert_eq!(genoa.vcpu_type, "EpycGenoa");
    let digest = compute_launch_digest_from_recipe(
        &genoa,
        &v.join("ovmf.bin"),
        &v.join("kernel.bin"),
        &v.join("initrd.bin"),
    )
    .unwrap();
    assert_eq!(hex::encode(digest), EXPECTED_SNP_DIGEST);
}

/// Every recipe input is load-bearing: change one and the digest moves
/// (or the artifact no longer matches its named hash).
#[test]
fn a_tampered_recipe_does_not_reproduce_the_digest() {
    let v = vectors_dir();
    let (ovmf, kernel, initrd) = (
        v.join("ovmf.bin"),
        v.join("kernel.bin"),
        v.join("initrd.bin"),
    );
    let good = compute_launch_recipe_for_generation(&kat_config(), Generation::Genoa).unwrap();
    let expected = digest_for(Generation::Genoa);
    let recompute = |r: &hippius_types::guardian::LaunchRecipe| {
        compute_launch_digest_from_recipe(r, &ovmf, &kernel, &initrd)
    };

    let mut r = good.clone();
    r.cmdline.push_str(" x");
    assert_ne!(recompute(&r).unwrap(), expected, "cmdline");
    let mut r = good.clone();
    r.vcpus = 2;
    assert_ne!(recompute(&r).unwrap(), expected, "vcpus");
    let mut r = good.clone();
    r.vcpu_type = "EpycTurin".into();
    assert_ne!(recompute(&r).unwrap(), expected, "vcpu_type");
    let mut r = good.clone();
    r.guest_features = 0x3;
    assert!(
        recompute(&r).map_or(true, |d| d != expected),
        "guest_features"
    );
    let mut r = good.clone();
    r.vcpu_type = "PentiumII".into();
    assert!(recompute(&r).is_err(), "unknown vcpu model");
    for field in 0..3 {
        let mut r = good.clone();
        match field {
            0 => r.ovmf_sha384[0] ^= 1,
            1 => r.kernel_sha256[0] ^= 1,
            _ => r.initrd_sha256[0] ^= 1,
        }
        assert!(recompute(&r).is_err(), "artifact hash {field}");
    }
}
