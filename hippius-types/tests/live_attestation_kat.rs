//! Known-answer test for the §23 tenant-CVM live-attestation wire
//! format — the KBS-L0-signed proof a tenant guest was ALIVE.
//!
//! Freezes one committed vector in `test_vectors/live_attestation/`:
//!
//! - `signed_live_attestation.cbor` — the canonical-CBOR
//!   [`SignedLiveAttestation`] envelope for a pinned [`LiveAttestation`]
//!   signed with a FIXED test Ed25519 key. Ed25519 is deterministic, so
//!   a fixed key + fixed body yields byte-exact bytes.
//!
//! Two consumers depend on these exact bytes, and the vector is what
//! keeps them honest:
//!
//! - `binaries/ticket-validator`'s `verify-live-attestation` subcommand,
//! - vali's `apps.telemetry.vm_liveness` ingest, whose end-to-end test
//!   pipes THIS FILE through the real binary. That test is the only
//!   place the Rust→JSON→Python field contract is checked against real
//!   cryptography rather than a mock, so the vector must stay a real
//!   signed envelope, never a hand-written stub.
//!
//! A failure here is **drift** — fix the impl, never silently
//! regenerate. Regenerate deliberately per
//! `test_vectors/live_attestation/REGENERATE.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::{Signer, SigningKey};
use hippius_types::live_attestation::{
    components_health, BindingSource, GuestBinding, GuestComponents, GuestResources,
    LiveAttestation, SignedLiveAttestation, CHIP_ID_LEN, DIGEST_LEN,
    LIVE_ATTESTATION_SCHEMA_VERSION, LIVE_ATTESTATION_SCHEMA_VERSION_BOUND,
    LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS, LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES,
    MEASUREMENT_LEN, PUBKEY_LEN, REPORT_ID_LEN,
};
use std::path::PathBuf;

/// Pinned test KBS-L0 Ed25519 signing-key seed (synthetic, fixed).
/// vali's end-to-end test pins the matching PUBLIC key.
const KAT_SEED: [u8; 32] = [0x5Au8; 32];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn signed_vector_path() -> PathBuf {
    repo_root().join("test_vectors/live_attestation/signed_live_attestation.cbor")
}

/// The schema-v2 (guest-bound) vector.
fn signed_v2_vector_path() -> PathBuf {
    repo_root().join("test_vectors/live_attestation/signed_live_attestation_v2.cbor")
}

/// The schema-v3 (guest-bound + attested resources) vector.
fn signed_v3_vector_path() -> PathBuf {
    repo_root().join("test_vectors/live_attestation/signed_live_attestation_v3.cbor")
}

/// The schema-v4 (guest-bound + resources + guest components) vector.
fn signed_v4_vector_path() -> PathBuf {
    repo_root().join("test_vectors/live_attestation/signed_live_attestation_v4.cbor")
}

/// The pinned attestation — fixed inputs. DO NOT change without
/// regenerating the committed vector AND updating vali's fixture
/// expectations.
fn kat_attestation(signer: &SigningKey) -> LiveAttestation {
    LiveAttestation {
        components: None,
        schema_version: LIVE_ATTESTATION_SCHEMA_VERSION,
        chain_genesis: [0xAA; DIGEST_LEN],
        pallet_instance: [0xDD; DIGEST_LEN],
        vm_id: "tn-kat-live-1".into(),
        node_id: [0xBB; PUBKEY_LEN],
        attestation_seq: 7,
        epoch: 4242,
        observed_at_unix: 1_800_000_000,
        verified_at_unix: 1_800_000_005,
        snp_report_digest: [0x11; DIGEST_LEN],
        vcek_chain_digest: [0x22; DIGEST_LEN],
        measurement: [0x33; MEASUREMENT_LEN],
        prev_attestation_hash: [0x44; DIGEST_LEN],
        expiry_unix: 1_800_000_900,
        signer_pubkey: signer.verifying_key().to_bytes(),
        guest: None,
        resources: None,
    }
}

/// The pinned v2 attestation: the v1 KAT plus a release-time guest
/// binding. Same DO-NOT-CHANGE rule.
fn kat_attestation_v2(signer: &SigningKey) -> LiveAttestation {
    LiveAttestation {
        schema_version: LIVE_ATTESTATION_SCHEMA_VERSION_BOUND,
        guest: Some(GuestBinding {
            chip_id: [0x5E; CHIP_ID_LEN],
            report_id: [0x7A; REPORT_ID_LEN],
            source: BindingSource::Release,
        }),
        ..kat_attestation(signer)
    }
}

/// The pinned v3 attestation: the v2 KAT plus attested resources (a
/// `large`: 4 vCPU, 16 GiB announced). Same DO-NOT-CHANGE rule.
fn kat_attestation_v3(signer: &SigningKey) -> LiveAttestation {
    LiveAttestation {
        schema_version: LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES,
        resources: Some(GuestResources {
            vcpus_online: 4,
            mem_firmware_kib: 16_776_164,
            mem_total_kib: 15_337_812,
            mem_unaccepted_kib: 1024,
        }),
        ..kat_attestation_v2(signer)
    }
}

/// The pinned v4 attestation: the v3 KAT plus the guest components
/// release 2, epoch 1, every health check passing. Same DO-NOT-CHANGE
/// rule.
fn kat_attestation_v4(signer: &SigningKey) -> LiveAttestation {
    LiveAttestation {
        schema_version: LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS,
        components: Some(GuestComponents {
            release_version: 2,
            security_epoch: 1,
            health: components_health::ALL,
            instance: 0x1234_5678,
            unhealthy_ticks: 1,
        }),
        ..kat_attestation_v3(signer)
    }
}

fn sign(att: &LiveAttestation, sk: &SigningKey) -> Vec<u8> {
    let body = att.canonical().expect("encode KAT body");
    let sig = sk.sign(&body).to_bytes().to_vec();
    SignedLiveAttestation { body, sig }
        .encode()
        .expect("encode KAT envelope")
}

fn kat_signed_v2() -> Vec<u8> {
    let sk = SigningKey::from_bytes(&KAT_SEED);
    sign(&kat_attestation_v2(&sk), &sk)
}

fn kat_signed_v3() -> Vec<u8> {
    let sk = SigningKey::from_bytes(&KAT_SEED);
    sign(&kat_attestation_v3(&sk), &sk)
}

fn kat_signed_v4() -> Vec<u8> {
    let sk = SigningKey::from_bytes(&KAT_SEED);
    sign(&kat_attestation_v4(&sk), &sk)
}

fn kat_signed() -> Vec<u8> {
    let sk = SigningKey::from_bytes(&KAT_SEED);
    let body = kat_attestation(&sk).canonical().expect("encode KAT body");
    let sig = sk.sign(&body).to_bytes().to_vec();
    SignedLiveAttestation { body, sig }
        .encode()
        .expect("encode KAT envelope")
}

#[test]
fn signed_live_attestation_kat_matches_the_frozen_vector() {
    let produced = kat_signed();
    let expected = std::fs::read(signed_vector_path()).expect(
        "test_vectors/live_attestation/signed_live_attestation.cbor missing — run \
         `cargo test -p hippius-types --test live_attestation_kat \
         regenerate_committed_vectors -- --ignored --exact`",
    );
    assert_eq!(
        produced, expected,
        "signed live-attestation envelope changed — a canonical-encoding, \
         key, or fixture edit shifted the KAT. If intentional, regenerate \
         per test_vectors/live_attestation/REGENERATE.md AND re-check \
         vali's end-to-end ingest fixture."
    );
}

#[test]
fn frozen_vector_decodes_and_verifies_under_the_pinned_key() {
    let raw = std::fs::read(signed_vector_path()).expect("read the frozen vector");
    let signed = SignedLiveAttestation::decode(&raw).expect("decode the frozen envelope");
    let att = LiveAttestation::decode(&signed.body).expect("decode the frozen body");
    let sk = SigningKey::from_bytes(&KAT_SEED);
    assert_eq!(att, kat_attestation(&sk));
    let sig = ed25519_dalek::Signature::from_slice(&signed.sig).expect("sig is 64 bytes");
    sk.verifying_key()
        .verify_strict(&signed.body, &sig)
        .expect("the frozen KAT signature must verify under the test key");
}

#[test]
fn signed_live_attestation_v2_kat_matches_the_frozen_vector() {
    let expected = std::fs::read(signed_v2_vector_path())
        .expect("test_vectors/live_attestation/signed_live_attestation_v2.cbor missing");
    assert_eq!(
        kat_signed_v2(),
        expected,
        "signed v2 live-attestation envelope changed — see REGENERATE.md"
    );
    let signed = SignedLiveAttestation::decode(&expected).expect("decode the v2 envelope");
    let att = LiveAttestation::decode(&signed.body).expect("decode the v2 body");
    assert_eq!(att, kat_attestation_v2(&SigningKey::from_bytes(&KAT_SEED)));
}

#[test]
fn signed_live_attestation_v3_kat_matches_the_frozen_vector() {
    let expected = std::fs::read(signed_v3_vector_path())
        .expect("test_vectors/live_attestation/signed_live_attestation_v3.cbor missing");
    assert_eq!(
        kat_signed_v3(),
        expected,
        "signed v3 live-attestation envelope changed — see REGENERATE.md"
    );
    let signed = SignedLiveAttestation::decode(&expected).expect("decode the v3 envelope");
    let att = LiveAttestation::decode(&signed.body).expect("decode the v3 body");
    assert_eq!(att, kat_attestation_v3(&SigningKey::from_bytes(&KAT_SEED)));
}

#[test]
fn signed_live_attestation_v4_kat_matches_the_frozen_vector() {
    let expected = std::fs::read(signed_v4_vector_path())
        .expect("test_vectors/live_attestation/signed_live_attestation_v4.cbor missing");
    assert_eq!(
        kat_signed_v4(),
        expected,
        "signed v4 live-attestation envelope changed — see REGENERATE.md"
    );
    let signed = SignedLiveAttestation::decode(&expected).expect("decode the v4 envelope");
    let att = LiveAttestation::decode(&signed.body).expect("decode the v4 body");
    assert_eq!(att, kat_attestation_v4(&SigningKey::from_bytes(&KAT_SEED)));
}

/// The v4 validity matrix: components required, binding and resources
/// each optional; components never ride on v1–v3.
#[test]
fn v4_components_are_required_and_orthogonal() {
    let sk = SigningKey::from_bytes(&KAT_SEED);
    for (guest, resources) in [(true, true), (true, false), (false, true), (false, false)] {
        let mut att = kat_attestation_v4(&sk);
        if !guest {
            att.guest = None;
        }
        if !resources {
            att.resources = None;
        }
        let body = att.canonical().expect("a v4 shape encodes");
        assert_eq!(
            LiveAttestation::decode(&body).unwrap(),
            att,
            "{guest} {resources}"
        );
    }
    let bare = LiveAttestation {
        components: None,
        ..kat_attestation_v4(&sk)
    };
    assert!(bare.canonical().is_err(), "v4 must carry components");
    for version in [
        LIVE_ATTESTATION_SCHEMA_VERSION,
        LIVE_ATTESTATION_SCHEMA_VERSION_BOUND,
        LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES,
    ] {
        let mislabeled = LiveAttestation {
            schema_version: version,
            ..kat_attestation_v4(&sk)
        };
        assert!(
            mislabeled.canonical().is_err(),
            "v{version} must not carry components"
        );
    }
}

/// The largest v4 body the stack can produce fits the runtime's
/// `MaxLiveAttestationBody` (1024 bytes): every optional part present, a
/// 64-byte `vm_id` (vali's charset lock), counters and unix times up to
/// 2^32 (year 2106), a petabyte of RAM, every `u32` at its max.
#[test]
fn the_largest_v4_body_fits_the_runtime_bound() {
    let sk = SigningKey::from_bytes(&KAT_SEED);
    let big = u64::from(u32::MAX);
    let att = LiveAttestation {
        vm_id: "v".repeat(64),
        attestation_seq: big,
        epoch: big,
        observed_at_unix: big - 2,
        verified_at_unix: big - 1,
        expiry_unix: big,
        resources: Some(GuestResources {
            vcpus_online: u32::MAX,
            mem_firmware_kib: 1 << 40,
            mem_total_kib: 1 << 40,
            mem_unaccepted_kib: 1 << 40,
        }),
        components: Some(GuestComponents {
            release_version: u32::MAX,
            security_epoch: u32::MAX,
            health: u32::MAX,
            instance: u32::MAX,
            unhealthy_ticks: u32::MAX,
        }),
        guest: Some(GuestBinding {
            chip_id: [0xFF; CHIP_ID_LEN],
            report_id: [0xFF; REPORT_ID_LEN],
            source: BindingSource::FirstUse,
        }),
        ..kat_attestation_v4(&sk)
    };
    let body = att.canonical().unwrap();
    assert!(body.len() <= 1024, "v4 body is {} bytes", body.len());
}

/// A v3 body without a guest binding (a KBS whose binding mode is `off`)
/// is well-formed, and resources never ride on a v1/v2 version number.
#[test]
fn v3_resources_are_orthogonal_to_the_guest_binding() {
    let sk = SigningKey::from_bytes(&KAT_SEED);
    let unbound = LiveAttestation {
        guest: None,
        ..kat_attestation_v3(&sk)
    };
    let body = unbound.canonical().expect("unbound v3 encodes");
    assert_eq!(LiveAttestation::decode(&body).unwrap(), unbound);

    for version in [
        LIVE_ATTESTATION_SCHEMA_VERSION,
        LIVE_ATTESTATION_SCHEMA_VERSION_BOUND,
    ] {
        let mislabeled = LiveAttestation {
            schema_version: version,
            ..kat_attestation_v3(&sk)
        };
        assert!(
            mislabeled.canonical().is_err(),
            "v{version} must not carry resources"
        );
    }
    let empty = LiveAttestation {
        resources: None,
        ..kat_attestation_v3(&sk)
    };
    assert!(empty.canonical().is_err(), "v3 must carry resources");
    let zero_cpu = LiveAttestation {
        resources: Some(GuestResources {
            vcpus_online: 0,
            ..kat_attestation_v3(&sk).resources.unwrap()
        }),
        ..kat_attestation_v3(&sk)
    };
    assert!(
        zero_cpu.canonical().is_err(),
        "a guest always has one CPU online"
    );
}

/// Regeneration helper — `#[ignore]`d so it never runs in CI.
///
/// ```text
/// cargo test -p hippius-types --test live_attestation_kat \
///     regenerate_committed_vectors -- --ignored --exact
/// ```
#[test]
#[ignore]
fn regenerate_committed_vectors() {
    let signed = kat_signed();
    std::fs::create_dir_all(signed_vector_path().parent().unwrap())
        .expect("create test_vectors/live_attestation/");
    std::fs::write(signed_vector_path(), &signed).expect("write the frozen vector");
    std::fs::write(signed_v2_vector_path(), kat_signed_v2()).expect("write the frozen v2 vector");
    std::fs::write(signed_v3_vector_path(), kat_signed_v3()).expect("write the frozen v3 vector");
    std::fs::write(signed_v4_vector_path(), kat_signed_v4()).expect("write the frozen v4 vector");
    println!(
        "regenerated: test_vectors/live_attestation/signed_live_attestation.cbor ({} bytes); \
         pinned KBS L0 public key = {}",
        signed.len(),
        hex::encode(SigningKey::from_bytes(&KAT_SEED).verifying_key().to_bytes()),
    );
}
