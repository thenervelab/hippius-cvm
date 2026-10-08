//! Known-answer test for the §K miner heartbeat wire format (PR-MA-6).
//!
//! Freezes two committed vectors in `test_vectors/heartbeat/`:
//!
//! - `heartbeat_body.cbor` — the canonical-CBOR encoding of a pinned
//!   [`MinerHeartbeat`]. A fixed struct → a byte-exact body. Any
//!   canonical-encoding change in `hippius_types::heartbeat` shifts
//!   this and fails CI loudly.
//! - `signed_heartbeat.cbor` — the canonical-CBOR encoding of the
//!   [`SignedMinerHeartbeat`] envelope produced by signing that body
//!   with a FIXED test Ed25519 key. Ed25519 is deterministic, so a
//!   fixed key + fixed body yields a byte-exact signed envelope.
//!
//! A parallel implementation (TS / Python tooling, an audit tool)
//! MUST reproduce these exact bytes for the same inputs. A failure is
//! **drift** — fix the impl, never silently regenerate the vector.
//!
//! A second pair, `heartbeat_body_v3.cbor` / `signed_heartbeat_v3.cbor`,
//! freezes the `v3` capacity-declaration body the same way. The `v1`
//! vectors above are untouched by `v3` — adding a schema never moves
//! an older one. A third pair, `heartbeat_body_v4.cbor` /
//! `signed_heartbeat_v4.cbor`, freezes the `v4` disk-declaration body,
//! a fourth, `heartbeat_body_v5.cbor` / `signed_heartbeat_v5.cbor`,
//! the `v5` host-health body, and a fifth, `heartbeat_body_v6.cbor` /
//! `signed_heartbeat_v6.cbor`, the `v6` agent-version body.
//!
//! Regenerate deliberately — see `test_vectors/heartbeat/REGENERATE.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::{Signer, SigningKey};
use hippius_types::heartbeat::{
    CapacityDeclaration, DiskDeclaration, HostHealthDeclaration, MinerHeartbeat,
    SignedMinerHeartbeat, DOMAIN, SCHEMA_VERSION, SCHEMA_VERSION_AGENT_VERSION,
    SCHEMA_VERSION_CAPACITY, SCHEMA_VERSION_DISK, SCHEMA_VERSION_HOST_HEALTH,
};
use std::path::PathBuf;

// ── Pinned KAT input tuple ──────────────────────────────────────────

/// Pinned test Ed25519 signing-key seed (synthetic, fixed).
const KAT_SEED: [u8; 32] = [0x3Bu8; 32];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn body_vector_path() -> PathBuf {
    repo_root().join("test_vectors/heartbeat/heartbeat_body.cbor")
}

fn signed_vector_path() -> PathBuf {
    repo_root().join("test_vectors/heartbeat/signed_heartbeat.cbor")
}

fn v3_body_vector_path() -> PathBuf {
    repo_root().join("test_vectors/heartbeat/heartbeat_body_v3.cbor")
}

fn v3_signed_vector_path() -> PathBuf {
    repo_root().join("test_vectors/heartbeat/signed_heartbeat_v3.cbor")
}

fn v4_body_vector_path() -> PathBuf {
    repo_root().join("test_vectors/heartbeat/heartbeat_body_v4.cbor")
}

fn v4_signed_vector_path() -> PathBuf {
    repo_root().join("test_vectors/heartbeat/signed_heartbeat_v4.cbor")
}

fn v5_body_vector_path() -> PathBuf {
    repo_root().join("test_vectors/heartbeat/heartbeat_body_v5.cbor")
}

fn v5_signed_vector_path() -> PathBuf {
    repo_root().join("test_vectors/heartbeat/signed_heartbeat_v5.cbor")
}

fn v6_body_vector_path() -> PathBuf {
    repo_root().join("test_vectors/heartbeat/heartbeat_body_v6.cbor")
}

fn v6_signed_vector_path() -> PathBuf {
    repo_root().join("test_vectors/heartbeat/signed_heartbeat_v6.cbor")
}

/// The pinned heartbeat — fixed inputs. DO NOT change without bumping
/// `test_vectors` and regenerating the committed vectors.
fn kat_heartbeat() -> MinerHeartbeat {
    MinerHeartbeat {
        schema_version: SCHEMA_VERSION,
        miner_id: "miner-a".into(),
        timestamp_unix: 1_700_000_000,
        sequence: 42,
        vm_count_running: 3,
        vm_count_total: 5,
        cpu_load_1m_centi: 175,
        memory_total_mib: 262_144,
        memory_available_mib: 131_072,
        domain: DOMAIN.into(),
        // The KAT is the `v1` baseline — the flag is never present in a
        // `v1` body, so a `false` here leaves the frozen bytes unchanged.
        graceful_exit_requested: false,
        // `v3`-only fields — zero (absent) in a `v1` body.
        cvm_cpu_budget: 0,
        cvm_memory_mb_budget: 0,
        asid_capacity: 0,
        asid_used: 0,
        disk: DiskDeclaration::default(),
        host_health: HostHealthDeclaration::default(),
        agent_version: String::new(),
    }
}

/// The pinned `v3` heartbeat — the `v1` tuple plus fixed capacity
/// declarations (realistic Genoa ASID figures).
fn kat_heartbeat_v3() -> MinerHeartbeat {
    let hb = kat_heartbeat().with_capacity(CapacityDeclaration {
        cvm_cpu_budget: 44,
        cvm_memory_mb_budget: 120_000,
        asid_capacity: 99,
        asid_used: 2,
    });
    assert_eq!(hb.schema_version, SCHEMA_VERSION_CAPACITY);
    hb
}

/// The pinned `v4` heartbeat — the `v3` tuple plus fixed disk
/// declarations.
fn kat_heartbeat_v4() -> MinerHeartbeat {
    let hb = kat_heartbeat().with_disk(
        CapacityDeclaration {
            cvm_cpu_budget: 44,
            cvm_memory_mb_budget: 120_000,
            asid_capacity: 99,
            asid_used: 2,
        },
        DiskDeclaration {
            cvm_disk_gb_budget: 3_000,
            data_disk_total_gb: 3_500,
            data_disk_available_gb: 2_900,
            staging_disk_available_gb: 400,
        },
    );
    assert_eq!(hb.schema_version, SCHEMA_VERSION_DISK);
    hb
}

/// The pinned `v5` heartbeat — the `v4` tuple plus a fixed host-health
/// report (figures from a host whose ASID recycling broke).
fn kat_heartbeat_v5() -> MinerHeartbeat {
    let v4 = kat_heartbeat_v4();
    let hb = kat_heartbeat().with_host_health(
        CapacityDeclaration {
            cvm_cpu_budget: v4.cvm_cpu_budget,
            cvm_memory_mb_budget: v4.cvm_memory_mb_budget,
            asid_capacity: v4.asid_capacity,
            asid_used: v4.asid_used,
        },
        v4.disk,
        HostHealthDeclaration {
            snp_enabled: true,
            cpus_offline: 24,
            snp_launches_since_boot: 97,
            df_flush_failures: 3,
        },
    );
    assert_eq!(hb.schema_version, SCHEMA_VERSION_HOST_HEALTH);
    hb
}

/// The pinned `v6` heartbeat — the `v5` tuple plus a fixed agent release
/// tag.
fn kat_heartbeat_v6() -> MinerHeartbeat {
    let v5 = kat_heartbeat_v5();
    let hb = kat_heartbeat().with_agent_version(
        CapacityDeclaration {
            cvm_cpu_budget: v5.cvm_cpu_budget,
            cvm_memory_mb_budget: v5.cvm_memory_mb_budget,
            asid_capacity: v5.asid_capacity,
            asid_used: v5.asid_used,
        },
        v5.disk,
        v5.host_health,
        "v1.2.3".into(),
    );
    assert_eq!(hb.schema_version, SCHEMA_VERSION_AGENT_VERSION);
    hb
}

/// Sign the pinned body with the fixed test key — deterministic.
fn kat_signed() -> SignedMinerHeartbeat {
    sign(kat_heartbeat())
}

fn sign(hb: MinerHeartbeat) -> SignedMinerHeartbeat {
    let body = hb.canonical().expect("encode KAT body");
    let sk = SigningKey::from_bytes(&KAT_SEED);
    let sig = sk.sign(&body);
    SignedMinerHeartbeat {
        body,
        sig: sig.to_bytes().to_vec(),
    }
}

#[test]
fn heartbeat_body_kat_matches_the_frozen_vector() {
    let produced = kat_heartbeat().canonical().expect("encode KAT body");
    let expected = std::fs::read(body_vector_path()).expect(
        "test_vectors/heartbeat/heartbeat_body.cbor missing — run \
         `cargo test -p hippius-types --test heartbeat_kat \
         regenerate_committed_vectors -- --ignored --exact`",
    );
    assert_eq!(
        produced, expected,
        "heartbeat canonical-CBOR body changed — a canonical-encoding or \
         fixture edit shifted the KAT. If intentional, regenerate per \
         test_vectors/heartbeat/REGENERATE.md."
    );
}

#[test]
fn signed_heartbeat_kat_matches_the_frozen_vector() {
    let produced = kat_signed().canonical().expect("encode KAT envelope");
    let expected = std::fs::read(signed_vector_path()).expect(
        "test_vectors/heartbeat/signed_heartbeat.cbor missing — run \
         `cargo test -p hippius-types --test heartbeat_kat \
         regenerate_committed_vectors -- --ignored --exact`",
    );
    assert_eq!(
        produced, expected,
        "signed heartbeat envelope changed — a canonical-encoding, key, \
         or fixture edit shifted the KAT. If intentional, regenerate per \
         test_vectors/heartbeat/REGENERATE.md."
    );
}

#[test]
fn frozen_signed_vector_decodes_and_verifies() {
    // The committed envelope decodes to the pinned tuple and its
    // signature verifies under the fixed test key — independent of the
    // byte-exact check above (catches a fixture swap).
    let raw = std::fs::read(signed_vector_path()).expect("read signed_heartbeat.cbor");
    let signed: SignedMinerHeartbeat =
        ciborium::de::from_reader(raw.as_slice()).expect("decode the frozen envelope");
    assert_eq!(signed.body, kat_heartbeat().canonical().unwrap());
    let vk = SigningKey::from_bytes(&KAT_SEED).verifying_key();
    let sig = ed25519_dalek::Signature::from_slice(&signed.sig).expect("sig is 64 bytes");
    vk.verify_strict(&signed.body, &sig)
        .expect("the frozen KAT signature must verify under the test key");
}

#[test]
fn v3_heartbeat_body_kat_matches_the_frozen_vector() {
    let produced = kat_heartbeat_v3().canonical().expect("encode v3 KAT body");
    let expected = std::fs::read(v3_body_vector_path()).expect(
        "test_vectors/heartbeat/heartbeat_body_v3.cbor missing — run \
         `cargo test -p hippius-types --test heartbeat_kat \
         regenerate_v3_vectors -- --ignored --exact`",
    );
    assert_eq!(
        produced, expected,
        "v3 heartbeat canonical-CBOR body changed"
    );
}

#[test]
fn v3_signed_heartbeat_kat_matches_the_frozen_vector() {
    let produced = sign(kat_heartbeat_v3())
        .canonical()
        .expect("encode v3 KAT envelope");
    let expected = std::fs::read(v3_signed_vector_path())
        .expect("test_vectors/heartbeat/signed_heartbeat_v3.cbor missing");
    assert_eq!(produced, expected, "v3 signed heartbeat envelope changed");
}

#[test]
fn v3_frozen_signed_vector_decodes_and_verifies() {
    let raw = std::fs::read(v3_signed_vector_path()).expect("read signed_heartbeat_v3.cbor");
    let signed: SignedMinerHeartbeat =
        ciborium::de::from_reader(raw.as_slice()).expect("decode the frozen v3 envelope");
    assert_eq!(signed.body, kat_heartbeat_v3().canonical().unwrap());
    let vk = SigningKey::from_bytes(&KAT_SEED).verifying_key();
    let sig = ed25519_dalek::Signature::from_slice(&signed.sig).expect("sig is 64 bytes");
    vk.verify_strict(&signed.body, &sig)
        .expect("the frozen v3 KAT signature must verify under the test key");
}

#[test]
fn v4_heartbeat_body_kat_matches_the_frozen_vector() {
    let produced = kat_heartbeat_v4().canonical().expect("encode v4 KAT body");
    let expected = std::fs::read(v4_body_vector_path()).expect(
        "test_vectors/heartbeat/heartbeat_body_v4.cbor missing — run \
         `cargo test -p hippius-types --test heartbeat_kat \
         regenerate_v4_vectors -- --ignored --exact`",
    );
    assert_eq!(
        produced, expected,
        "v4 heartbeat canonical-CBOR body changed"
    );
}

#[test]
fn v4_signed_heartbeat_kat_matches_the_frozen_vector() {
    let produced = sign(kat_heartbeat_v4())
        .canonical()
        .expect("encode v4 KAT envelope");
    let expected = std::fs::read(v4_signed_vector_path())
        .expect("test_vectors/heartbeat/signed_heartbeat_v4.cbor missing");
    assert_eq!(produced, expected, "v4 signed heartbeat envelope changed");
}

#[test]
fn v4_frozen_signed_vector_decodes_and_verifies() {
    let raw = std::fs::read(v4_signed_vector_path()).expect("read signed_heartbeat_v4.cbor");
    let signed: SignedMinerHeartbeat =
        ciborium::de::from_reader(raw.as_slice()).expect("decode the frozen v4 envelope");
    assert_eq!(signed.body, kat_heartbeat_v4().canonical().unwrap());
    let vk = SigningKey::from_bytes(&KAT_SEED).verifying_key();
    let sig = ed25519_dalek::Signature::from_slice(&signed.sig).expect("sig is 64 bytes");
    vk.verify_strict(&signed.body, &sig)
        .expect("the frozen v4 KAT signature must verify under the test key");
}

#[test]
fn v5_heartbeat_body_kat_matches_the_frozen_vector() {
    let produced = kat_heartbeat_v5().canonical().expect("encode v5 KAT body");
    let expected = std::fs::read(v5_body_vector_path()).expect(
        "test_vectors/heartbeat/heartbeat_body_v5.cbor missing — run \
         `cargo test -p hippius-types --test heartbeat_kat \
         regenerate_v5_vectors -- --ignored --exact`",
    );
    assert_eq!(
        produced, expected,
        "v5 heartbeat canonical-CBOR body changed"
    );
}

#[test]
fn v5_signed_heartbeat_kat_matches_the_frozen_vector() {
    let produced = sign(kat_heartbeat_v5())
        .canonical()
        .expect("encode v5 KAT envelope");
    let expected = std::fs::read(v5_signed_vector_path())
        .expect("test_vectors/heartbeat/signed_heartbeat_v5.cbor missing");
    assert_eq!(produced, expected, "v5 signed heartbeat envelope changed");
}

#[test]
fn v5_frozen_signed_vector_decodes_and_verifies() {
    let raw = std::fs::read(v5_signed_vector_path()).expect("read signed_heartbeat_v5.cbor");
    let signed: SignedMinerHeartbeat =
        ciborium::de::from_reader(raw.as_slice()).expect("decode the frozen v5 envelope");
    assert_eq!(signed.body, kat_heartbeat_v5().canonical().unwrap());
    let vk = SigningKey::from_bytes(&KAT_SEED).verifying_key();
    let sig = ed25519_dalek::Signature::from_slice(&signed.sig).expect("sig is 64 bytes");
    vk.verify_strict(&signed.body, &sig)
        .expect("the frozen v5 KAT signature must verify under the test key");
}

#[test]
fn v6_heartbeat_body_kat_matches_the_frozen_vector() {
    let produced = kat_heartbeat_v6().canonical().expect("encode v6 KAT body");
    let expected = std::fs::read(v6_body_vector_path()).expect(
        "test_vectors/heartbeat/heartbeat_body_v6.cbor missing — run \
         `cargo test -p hippius-types --test heartbeat_kat \
         regenerate_v6_vectors -- --ignored --exact`",
    );
    assert_eq!(
        produced, expected,
        "v6 heartbeat canonical-CBOR body changed"
    );
}

#[test]
fn v6_signed_heartbeat_kat_matches_the_frozen_vector() {
    let produced = sign(kat_heartbeat_v6())
        .canonical()
        .expect("encode v6 KAT envelope");
    let expected = std::fs::read(v6_signed_vector_path())
        .expect("test_vectors/heartbeat/signed_heartbeat_v6.cbor missing");
    assert_eq!(produced, expected, "v6 signed heartbeat envelope changed");
}

#[test]
fn v6_frozen_signed_vector_decodes_and_verifies() {
    let raw = std::fs::read(v6_signed_vector_path()).expect("read signed_heartbeat_v6.cbor");
    let signed: SignedMinerHeartbeat =
        ciborium::de::from_reader(raw.as_slice()).expect("decode the frozen v6 envelope");
    assert_eq!(signed.body, kat_heartbeat_v6().canonical().unwrap());
    let vk = SigningKey::from_bytes(&KAT_SEED).verifying_key();
    let sig = ed25519_dalek::Signature::from_slice(&signed.sig).expect("sig is 64 bytes");
    vk.verify_strict(&signed.body, &sig)
        .expect("the frozen v6 KAT signature must verify under the test key");
}

/// `v6` regeneration helper — writes ONLY the `v6` pair.
///
/// ```text
/// cargo test -p hippius-types --test heartbeat_kat \
///     regenerate_v6_vectors -- --ignored --exact
/// ```
#[test]
#[ignore]
fn regenerate_v6_vectors() {
    let body = kat_heartbeat_v6().canonical().expect("encode v6 KAT body");
    let signed = sign(kat_heartbeat_v6())
        .canonical()
        .expect("encode v6 KAT envelope");
    std::fs::write(v6_body_vector_path(), &body).expect("write heartbeat_body_v6.cbor");
    std::fs::write(v6_signed_vector_path(), &signed).expect("write signed_heartbeat_v6.cbor");
}

/// `v5` regeneration helper — writes ONLY the `v5` pair.
///
/// ```text
/// cargo test -p hippius-types --test heartbeat_kat \
///     regenerate_v5_vectors -- --ignored --exact
/// ```
#[test]
#[ignore]
fn regenerate_v5_vectors() {
    let body = kat_heartbeat_v5().canonical().expect("encode v5 KAT body");
    let signed = sign(kat_heartbeat_v5())
        .canonical()
        .expect("encode v5 KAT envelope");
    std::fs::write(v5_body_vector_path(), &body).expect("write heartbeat_body_v5.cbor");
    std::fs::write(v5_signed_vector_path(), &signed).expect("write signed_heartbeat_v5.cbor");
}

/// `v4` regeneration helper — writes ONLY the `v4` pair.
///
/// ```text
/// cargo test -p hippius-types --test heartbeat_kat \
///     regenerate_v4_vectors -- --ignored --exact
/// ```
#[test]
#[ignore]
fn regenerate_v4_vectors() {
    let body = kat_heartbeat_v4().canonical().expect("encode v4 KAT body");
    let signed = sign(kat_heartbeat_v4())
        .canonical()
        .expect("encode v4 KAT envelope");
    std::fs::write(v4_body_vector_path(), &body).expect("write heartbeat_body_v4.cbor");
    std::fs::write(v4_signed_vector_path(), &signed).expect("write signed_heartbeat_v4.cbor");
}

/// `v3` regeneration helper — writes ONLY the `v3` pair, so a `v3`
/// change can never silently rewrite the frozen `v1` vectors.
///
/// ```text
/// cargo test -p hippius-types --test heartbeat_kat \
///     regenerate_v3_vectors -- --ignored --exact
/// ```
#[test]
#[ignore]
fn regenerate_v3_vectors() {
    let body = kat_heartbeat_v3().canonical().expect("encode v3 KAT body");
    let signed = sign(kat_heartbeat_v3())
        .canonical()
        .expect("encode v3 KAT envelope");
    std::fs::write(v3_body_vector_path(), &body).expect("write heartbeat_body_v3.cbor");
    std::fs::write(v3_signed_vector_path(), &signed).expect("write signed_heartbeat_v3.cbor");
}

/// Regeneration helper — `#[ignore]`d so it never runs in CI. Run it
/// deliberately to (re)write the committed KAT vectors after an
/// intentional change:
///
/// ```text
/// cargo test -p hippius-types --test heartbeat_kat \
///     regenerate_committed_vectors -- --ignored --exact
/// ```
#[test]
#[ignore]
fn regenerate_committed_vectors() {
    let body = kat_heartbeat().canonical().expect("encode KAT body");
    let signed = kat_signed().canonical().expect("encode KAT envelope");
    std::fs::write(body_vector_path(), &body).expect("write heartbeat_body.cbor");
    std::fs::write(signed_vector_path(), &signed).expect("write signed_heartbeat.cbor");
    println!(
        "regenerated: test_vectors/heartbeat/heartbeat_body.cbor ({} bytes), \
         signed_heartbeat.cbor ({} bytes)",
        body.len(),
        signed.len()
    );
}
