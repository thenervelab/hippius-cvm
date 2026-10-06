#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Cross-impl round-trip tests for `hippius-order-ticket-mint`.
//!
//! These exercise the binary the way the operator + the production
//! KBS will:
//!
//! 1. Run the binary with a controlled set of args (writing the
//!    output to a `tempfile`).
//! 2. Decode the COSE_Sign1 envelope back into
//!    `hippius_types::ticket::OrderTicket` via `serde` — confirms the
//!    canonical-CBOR body matches the schema the verifier deserialises
//!    against.
//! 3. Re-verify the envelope via `kbs_core::ticket::verify_order_ticket`
//!    using the same signing key we minted with — confirms the wire
//!    shape + signature semantics are byte-exact with the production
//!    verifier (the strongest cross-impl check available).
//! 4. Re-run the binary with identical inputs (deterministic ticket
//!    id + nonce + issue time + Ed25519) — confirms the output is
//!    bitwise-identical, so a re-mint is provably idempotent and a
//!    drifted future change surfaces here, not in prod.
//!
//! Also exercises a handful of fail-closed paths the verifier
//! catches but we want caught locally for operator UX.

use std::path::{Path, PathBuf};
use std::process::Command;

use ciborium::value::Value;
use coset::CborSerializable;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hippius_types::cbor::{assert_canonical, to_canonical_vec};
use hippius_types::ticket::OrderTicket;
use kbs_core::ticket::{verify_order_ticket, L1Keyring};

/// Static dev seed → matches the format the binary expects (32-byte
/// seed, hex-encoded on one line). Deterministic: identical inputs
/// always yield identical envelopes.
const DEV_SEED_HEX: &str = "960850208ac2502bd7bdf9873c1e8f19dfffeb1e9a9087981e559cea123a26e1";
const KID: &str = "l1-order-ticket-dev-v1";

/// Concrete `MEASUREMENT` matching `test_vectors/uki/tenant-measurement.json`
/// — the live tenant UKI's launch digest. Using the real value
/// keeps the tests close to the production trust path: a future drift
/// in the tenant UKI build would change this constant, and the test
/// would be the canary.
const MEASUREMENT_HEX: &str =
    "f89f6a20e1e985e483c0b25abbf9d157d7f3e2302baefbe90c5af00e880ccb5ff26f0fd06bc10f1fe99e8c17972fd928";

const USERDATA_DIGEST_HEX: &str =
    "1c066ae099887766554433221100ffeeddccbbaa99887766554433221100ffee";
const NONCE_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn binary_path() -> PathBuf {
    // `CARGO_BIN_EXE_<name>` is set by cargo for integration tests of
    // a crate that ships a `[[bin]]` target. Beats walking up to
    // `target/` by hand and survives `cargo test --release`.
    PathBuf::from(env!("CARGO_BIN_EXE_hippius-order-ticket-mint"))
}

fn write_signing_key(dir: &tempfile::TempDir) -> PathBuf {
    let path = dir.path().join("dev.ed25519");
    // Trailing newline mirrors the real
    // `packer/keys/dev/l1-order-ticket.dev.ed25519` file shape.
    std::fs::write(&path, format!("{DEV_SEED_HEX}\n")).unwrap();
    path
}

struct OneKey {
    kid: Vec<u8>,
    vk: VerifyingKey,
}
impl L1Keyring for OneKey {
    fn verifying_key(&self, kid: &[u8]) -> Option<VerifyingKey> {
        (kid == self.kid).then_some(self.vk)
    }
}

fn dev_keyring() -> OneKey {
    let seed: [u8; 32] = hex::decode(DEV_SEED_HEX).unwrap().try_into().unwrap();
    let sk = SigningKey::from_bytes(&seed);
    OneKey {
        kid: KID.as_bytes().to_vec(),
        vk: sk.verifying_key(),
    }
}

/// Mint with a fixed argv. Output is the raw COSE_Sign1 bytes the
/// binary wrote to `--out`.
fn mint_fixture(key_path: &Path, out: &Path) {
    mint_fixture_with(key_path, out, &[]);
}

/// [`mint_fixture`] plus `extra` argv (e.g. `--key-mode split`).
fn mint_fixture_with(key_path: &Path, out: &Path, extra: &[&str]) {
    let status = Command::new(binary_path())
        .args(extra)
        .args([
            "--signing-key",
            key_path.to_str().unwrap(),
            "--kid",
            KID,
            "--ticket-id",
            "tk-fixture-1",
            "--issue-time",
            "1000",
            "--expiry-seconds",
            "1000",
            "--nonce-hex",
            NONCE_HEX,
            "--tenant-id",
            "tenant-fixture",
            "--user-id",
            "user-fixture",
            "--vm-id",
            "vm-fixture",
            "--lease-id",
            "lease-fixture",
            "--vm-generation",
            "1",
            "--node-id",
            "miner-fixture",
            "--platform-id",
            "chip-fixture",
            "--allowed-measurement-hex",
            MEASUREMENT_HEX,
            "--userdata-vault-path",
            "secret/hippius-compute/tenants/vm-fixture/userdata",
            "--userdata-vault-version",
            "1",
            "--luks-vault-path",
            "secret/hippius-compute/tenants/vm-fixture/luks-kek",
            "--luks-vault-version",
            "1",
            "--allowed-userdata-digest-hex",
            USERDATA_DIGEST_HEX,
            "--flavor",
            "small",
            "--lifecycle-perm",
            "launch",
            "--out",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "mint failed: status={status:?}");
}

// ─── Round-trip cases ───────────────────────────────────────────────

#[test]
fn mint_round_trips_through_order_ticket_deserialize() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let out = dir.path().join("ticket.cose");
    mint_fixture(&key, &out);

    let cose_bytes = std::fs::read(&out).unwrap();
    let sign1 = coset::CoseSign1::from_slice(&cose_bytes).unwrap();
    let payload = sign1.payload.unwrap();
    assert_canonical(&payload).expect("payload must be canonical CBOR");
    let ticket: OrderTicket = ciborium::de::from_reader(payload.as_slice()).unwrap();
    assert_eq!(ticket.v, hippius_types::ticket::SCHEMA_V);
    assert_eq!(ticket.ticket_id, "tk-fixture-1");
    assert_eq!(ticket.tenant_id, "tenant-fixture");
    assert_eq!(ticket.vm_id, "vm-fixture");
    assert_eq!(ticket.node_id, "miner-fixture");
    assert_eq!(ticket.platform_id, "chip-fixture");
    assert_eq!(ticket.lease_id, "lease-fixture");
    assert_eq!(ticket.vm_generation, 1);
    assert_eq!(ticket.issue_time, 1000);
    assert_eq!(ticket.expiry, 2000);
    assert_eq!(ticket.allowed_measurements.len(), 1);
    assert_eq!(ticket.allowed_measurements[0].as_ref().len(), 48);
    assert_eq!(ticket.allowed_userdata_digest.as_ref().len(), 32);
    assert_eq!(ticket.nonce.as_ref().len(), 32);
    assert_eq!(ticket.userdata_vault_ref.version, 1);
    assert_eq!(ticket.luks_vault_ref.version, 1);
    assert_ne!(
        ticket.userdata_vault_ref.path, ticket.luks_vault_ref.path,
        "paths must differ — verifier rejects collisions"
    );
    assert_eq!(ticket.flavor.as_str(), "small");
    assert_eq!(ticket.lifecycle_perms, vec!["launch".to_string()]);
}

#[test]
fn mint_verifies_via_kbs_core() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let out = dir.path().join("ticket.cose");
    mint_fixture(&key, &out);

    let cose_bytes = std::fs::read(&out).unwrap();
    let keyring = dev_keyring();
    // `now_unix = 1500` is mid-window for the fixture (issue=1000,
    // expiry=2000) so the verifier's expiry + not-yet-valid gates
    // both pass.
    let (ticket, kid_out) = verify_order_ticket(&cose_bytes, &keyring, 1500)
        .expect("kbs-core must accept a fresh mint");
    assert_eq!(kid_out, KID.as_bytes());
    assert_eq!(ticket.vm_id, "vm-fixture");
}

#[test]
fn mint_is_deterministic_given_fixed_inputs() {
    // Ed25519 signatures are deterministic; canonical CBOR is
    // deterministic; identical inputs MUST therefore produce
    // bitwise-identical COSE_Sign1 envelopes. A drift here is a
    // wire-format regression — exactly the thing the conformance
    // vectors (§N) exist to catch.
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let out_a = dir.path().join("a.cose");
    let out_b = dir.path().join("b.cose");
    mint_fixture(&key, &out_a);
    mint_fixture(&key, &out_b);
    let a = std::fs::read(&out_a).unwrap();
    let b = std::fs::read(&out_b).unwrap();
    assert_eq!(
        a, b,
        "two mints with identical inputs must produce byte-identical envelopes"
    );
}

#[test]
fn body_is_canonical_cbor() {
    // Belt-and-suspenders: even if `to_canonical_vec` regresses, the
    // verifier's `assert_canonical(payload)` would catch it. Asserting
    // it here makes the failure mode "this test is the canary" rather
    // than "all KBS releases break".
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let out = dir.path().join("ticket.cose");
    mint_fixture(&key, &out);
    let cose_bytes = std::fs::read(&out).unwrap();
    let sign1 = coset::CoseSign1::from_slice(&cose_bytes).unwrap();
    let payload = sign1.payload.unwrap();
    let value: Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
    let recanon = to_canonical_vec(&value).unwrap();
    assert_eq!(
        recanon.as_slice(),
        payload.as_slice(),
        "minted body is not in canonical-CBOR shape"
    );
}

// ─── Fail-closed input validation ──────────────────────────────────

fn run_with_overrides<I, S>(extra_args: I, base_key: &Path) -> std::process::Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut cmd = Command::new(binary_path());
    cmd.args([
        "--signing-key",
        base_key.to_str().unwrap(),
        "--kid",
        KID,
        "--tenant-id",
        "t",
        "--user-id",
        "u",
        "--vm-id",
        "vm",
        "--lease-id",
        "l",
        "--node-id",
        "n",
        "--platform-id",
        "p",
        "--userdata-vault-path",
        "secret/a",
        "--userdata-vault-version",
        "1",
        "--luks-vault-path",
        "secret/b",
        "--luks-vault-version",
        "1",
        "--allowed-userdata-digest-hex",
        USERDATA_DIGEST_HEX,
        "--flavor",
        "small",
        "--lifecycle-perm",
        "launch",
    ]);
    cmd.args(extra_args);
    cmd.output().unwrap()
}

#[test]
fn measurement_must_be_48_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let out = run_with_overrides(["--allowed-measurement-hex", "deadbeef"], &key);
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("must decode to 48 bytes"),
        "stderr={stderr}"
    );
}

#[test]
fn nonce_must_be_32_bytes_when_supplied() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let out = run_with_overrides(
        [
            "--allowed-measurement-hex",
            MEASUREMENT_HEX,
            "--nonce-hex",
            "00112233",
        ],
        &key,
    );
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("must decode to 32 bytes"),
        "stderr={stderr}"
    );
}

#[test]
fn collision_between_vault_paths_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let mut cmd = Command::new(binary_path());
    cmd.args([
        "--signing-key",
        key.to_str().unwrap(),
        "--kid",
        KID,
        "--tenant-id",
        "t",
        "--user-id",
        "u",
        "--vm-id",
        "vm",
        "--lease-id",
        "l",
        "--node-id",
        "n",
        "--platform-id",
        "p",
        "--allowed-measurement-hex",
        MEASUREMENT_HEX,
        "--userdata-vault-path",
        "secret/same",
        "--userdata-vault-version",
        "1",
        "--luks-vault-path",
        "secret/same",
        "--luks-vault-version",
        "1",
        "--allowed-userdata-digest-hex",
        USERDATA_DIGEST_HEX,
        "--flavor",
        "small",
        "--lifecycle-perm",
        "launch",
    ]);
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("must differ"), "stderr={stderr}");
}

#[test]
fn vault_version_zero_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let mut cmd = Command::new(binary_path());
    cmd.args([
        "--signing-key",
        key.to_str().unwrap(),
        "--kid",
        KID,
        "--tenant-id",
        "t",
        "--user-id",
        "u",
        "--vm-id",
        "vm",
        "--lease-id",
        "l",
        "--node-id",
        "n",
        "--platform-id",
        "p",
        "--allowed-measurement-hex",
        MEASUREMENT_HEX,
        "--userdata-vault-path",
        "secret/a",
        "--userdata-vault-version",
        "0",
        "--luks-vault-path",
        "secret/b",
        "--luks-vault-version",
        "1",
        "--allowed-userdata-digest-hex",
        USERDATA_DIGEST_HEX,
        "--flavor",
        "small",
        "--lifecycle-perm",
        "launch",
    ]);
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(">= 1"), "stderr={stderr}");
}

#[test]
fn empty_kid_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let mut cmd = Command::new(binary_path());
    cmd.args([
        "--signing-key",
        key.to_str().unwrap(),
        "--kid",
        "",
        "--tenant-id",
        "t",
        "--user-id",
        "u",
        "--vm-id",
        "vm",
        "--lease-id",
        "l",
        "--node-id",
        "n",
        "--platform-id",
        "p",
        "--allowed-measurement-hex",
        MEASUREMENT_HEX,
        "--userdata-vault-path",
        "secret/a",
        "--userdata-vault-version",
        "1",
        "--luks-vault-path",
        "secret/b",
        "--luks-vault-version",
        "1",
        "--allowed-userdata-digest-hex",
        USERDATA_DIGEST_HEX,
        "--flavor",
        "small",
        "--lifecycle-perm",
        "launch",
    ]);
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--kid must not be empty"),
        "stderr={stderr}"
    );
}

#[test]
fn expired_ticket_is_rejected_by_verifier() {
    // The verifier (`kbs_core::ticket::verify_order_ticket`) rejects
    // any ticket whose `expiry <= now_unix`. We mint the fixture with
    // `issue=1000, expiry=2000`, then ask the verifier "is this
    // valid at now=2000?" — must be a clean reject. Catches a future
    // regression where the minter or the verifier flips a
    // half-open-vs-closed boundary on `expiry`.
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let out = dir.path().join("ticket.cose");
    mint_fixture(&key, &out);
    let cose_bytes = std::fs::read(&out).unwrap();
    let keyring = dev_keyring();
    let res = verify_order_ticket(&cose_bytes, &keyring, 2000);
    assert!(res.is_err(), "verifier accepted an expired ticket");
}

#[test]
fn signing_key_must_be_32_byte_hex() {
    // Two failure modes for `--signing-key` that the operator UX
    // depends on being clear:
    //   1. The file decodes cleanly as hex but to the wrong length.
    //   2. The file is not hex at all.
    // Both should exit 2 (input rejection) with a message naming the
    // signing key, NEVER printing the file contents (§20 — even a
    // wrong-length seed could leak partial key material).
    let dir = tempfile::tempdir().unwrap();
    // Case 1: 16 bytes of hex (wrong length, hex-valid). Built
    // programmatically (not as a hex string literal in source) to
    // sidestep the repo's gitleaks `generic-api-key` heuristic.
    let short_key = dir.path().join("short.ed25519");
    let short_hex: String = (0u8..16).map(|b| format!("{b:02x}")).collect();
    std::fs::write(&short_key, format!("{short_hex}\n")).unwrap();
    let out = run_with_overrides(["--allowed-measurement-hex", MEASUREMENT_HEX], &short_key);
    // `--signing-key` is parsed BEFORE clap finishes the rest, so
    // the result is `MintError::BadInput("signing key must decode to
    // exactly 32 bytes (got 16)")` ⇒ exit 2.
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("decode to exactly 32 bytes") || stderr.contains("must decode to"),
        "stderr={stderr}"
    );
    // The wrong-length seed bytes themselves must NOT be echoed.
    assert!(
        !stderr.contains(&short_hex),
        "stderr leaked seed bytes: {stderr}"
    );

    // Case 2: not hex at all.
    let garbage_key = dir.path().join("garbage.ed25519");
    std::fs::write(&garbage_key, "this is not hex\n").unwrap();
    let out = run_with_overrides(["--allowed-measurement-hex", MEASUREMENT_HEX], &garbage_key);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("signing key is not valid hex"),
        "stderr={stderr}"
    );
    // Strict §20 check: stderr must NOT contain the file contents,
    // NOT echo the offending character, and NOT include a position
    // marker (which the underlying `hex::FromHexError` would have
    // surfaced — confirming the generic-message refactor stuck).
    assert!(
        !stderr.contains("this is not hex"),
        "stderr leaked file contents: {stderr}"
    );
    assert!(
        !stderr.contains("Invalid character") && !stderr.contains("position"),
        "stderr leaked hex-crate diagnostic ({stderr}) — \
         should be a generic 'not valid hex' message per §20."
    );
}

#[test]
fn ticket_validator_subcommand_accepts_mint() {
    // The existing `binaries/ticket-validator` `verify-ticket`
    // subcommand is what vali shells out to at intake — confirming a
    // fresh mint passes through it keeps PR-G's intake path covered
    // without spinning vali up.
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let out = dir.path().join("ticket.cose");
    mint_fixture(&key, &out);
    let cose_bytes = std::fs::read(&out).unwrap();

    let validator = PathBuf::from(env!("CARGO_BIN_EXE_hippius-order-ticket-mint"))
        .parent()
        .unwrap()
        .join("hippius-ticket-validator");
    if !validator.exists() {
        // The validator binary is built when the workspace's other
        // crate is in the `cargo test` graph; in a `-p
        // hippius-order-ticket-mint` only run it won't be present.
        // Skip rather than fail — `cargo test` from the repo root
        // (and CI) always builds both.
        eprintln!("ticket-validator binary missing — skipping cross-subcommand test");
        return;
    }
    let mut child = std::process::Command::new(&validator)
        .arg("verify-ticket")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&cose_bytes)
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "validator rejected mint: status={:?}, stdout={stdout}, stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("\"tag\":\"ok\""),
        "validator stdout missing ok tag: {stdout}"
    );
}

// ─── Customer-held keys: `--key-mode` ───────────────────────────────

/// SHA-256 of the fixture envelope as minted BEFORE `--key-mode` existed.
/// An M0 mint (no `--key-mode`) must stay byte-identical to it: every M0
/// ticket vali mints goes through this binary, and the KBS / guest decode
/// an unchanged body.
const M0_FIXTURE_SHA256: &str = "486c710a747cd258aff1d135f391bf34cce3075c05302938eccfbd8609f2a2c8";

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn m0_mint_is_byte_identical_to_the_pre_key_mode_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let out = dir.path().join("m0.cose");
    mint_fixture(&key, &out);
    assert_eq!(sha256_hex(&std::fs::read(&out).unwrap()), M0_FIXTURE_SHA256);
}

#[test]
fn key_mode_split_and_customer_are_signed_into_the_ticket() {
    use hippius_types::guardian::KeyMode;
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    for (wire, mode) in [("split", KeyMode::Split), ("customer", KeyMode::Customer)] {
        let out = dir.path().join(format!("{wire}.cose"));
        mint_fixture_with(&key, &out, &["--key-mode", wire]);
        let cose_bytes = std::fs::read(&out).unwrap();
        // The production verifier accepts it and reads the mode back.
        let (ticket, _) = verify_order_ticket(&cose_bytes, &dev_keyring(), 1500)
            .expect("kbs-core must accept a key_mode mint");
        assert_eq!(ticket.key_mode, Some(mode));
        assert_eq!(ticket.key_mode(), mode);
        assert_ne!(sha256_hex(&cose_bytes), M0_FIXTURE_SHA256);
        let payload = coset::CoseSign1::from_slice(&cose_bytes)
            .unwrap()
            .payload
            .unwrap();
        assert_canonical(&payload).expect("payload must be canonical CBOR");
    }
}

#[test]
fn m0_mint_carries_no_key_mode_entry() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    let out = dir.path().join("m0.cose");
    mint_fixture(&key, &out);
    let cose_bytes = std::fs::read(&out).unwrap();
    let payload = coset::CoseSign1::from_slice(&cose_bytes)
        .unwrap()
        .payload
        .unwrap();
    let Value::Map(entries) = ciborium::de::from_reader::<Value, _>(payload.as_slice()).unwrap()
    else {
        panic!("ticket body is not a map");
    };
    assert!(!entries
        .iter()
        .any(|(k, _)| k == &Value::Text("key_mode".into())));
}

#[test]
fn key_mode_hippius_and_unknown_modes_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_signing_key(&dir);
    for bad in ["hippius", "Split", "", "m1"] {
        let out = run_with_overrides(
            [
                "--allowed-measurement-hex",
                MEASUREMENT_HEX,
                "--key-mode",
                bad,
            ],
            &key,
        );
        assert!(!out.status.success(), "--key-mode {bad:?} must be refused");
    }
}
