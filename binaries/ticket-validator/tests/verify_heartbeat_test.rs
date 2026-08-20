//! Integration tests for the `verify-heartbeat` subcommand (PR-Part4-A).
//!
//! These spawn the real `hippius-ticket-validator` binary, pipe a
//! `SignedMinerHeartbeat` envelope to its stdin, and assert on the
//! data-bearing JSON contract vali's heartbeat ingest gate (#127)
//! consumes:
//!
//! - accept → `{"ok":true,"body":{…ten decoded fields…}}`, exit `0`
//! - reject → `{"ok":false,"error_class":"<class>"}`, exit `0`
//! - bad `--vk-hex` → exit `2`, a stderr line, NO stdout JSON
//!
//! The happy path is a known-answer test against the committed
//! `test_vectors/heartbeat/signed_heartbeat.cbor` — the same frozen
//! envelope `hippius-types`' KAT pins — so a canonical-encoding or
//! fixture drift fails here too. The negative cases cover every member
//! of the closed `error_class` vocabulary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use hippius_types::cbor::to_canonical_vec;
use hippius_types::heartbeat::{
    MinerHeartbeat, SignedMinerHeartbeat, DOMAIN, SCHEMA_VERSION, SIGNATURE_LEN,
};

/// The pinned KAT signing-key seed — identical to
/// `hippius-types/tests/heartbeat_kat.rs::KAT_SEED`. The committed
/// `signed_heartbeat.cbor` is signed by this key.
const KAT_SEED: [u8; 32] = [0x3Bu8; 32];

/// Outcome of one `verify-heartbeat` invocation.
struct Run {
    exit: i32,
    stdout: String,
    stderr: String,
}

/// Spawn the binary with `--vk-hex <vk_hex>` and feed `input` on stdin.
fn run_verify_heartbeat(vk_hex: &str, input: &[u8]) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hippius-ticket-validator"))
        .arg("verify-heartbeat")
        .arg("--vk-hex")
        .arg(vk_hex)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hippius-ticket-validator");

    let mut stdin = child.stdin.take().expect("child stdin");
    // A reject path that caps the read (an over-cap envelope) may close
    // stdin before the whole write lands — a BrokenPipe here is benign;
    // the child's stdout + exit code are the real assertion surface.
    if let Err(e) = stdin.write_all(input) {
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::BrokenPipe,
            "unexpected stdin write error: {e}",
        );
    }
    drop(stdin);

    let out = child.wait_with_output().expect("wait for child");
    Run {
        exit: out.status.code().expect("child exited via signal, no code"),
        stdout: String::from_utf8(out.stdout).expect("stdout is not UTF-8"),
        stderr: String::from_utf8(out.stderr).expect("stderr is not UTF-8"),
    }
}

/// Repo root — the integration test's `CARGO_MANIFEST_DIR` is the
/// `binaries/ticket-validator` crate dir, two levels down.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The pinned KAT heartbeat — byte-identical to the tuple
/// `hippius-types/tests/heartbeat_kat.rs` freezes.
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
        graceful_exit_requested: false,
    }
}

/// Hex of a signing key's verifying key — the `--vk-hex` argument.
fn vk_hex(sk: &SigningKey) -> String {
    hex::encode(sk.verifying_key().to_bytes())
}

/// Sign `body` with `sk` and canonical-encode the `{body, sig}` envelope.
fn signed_envelope(body: Vec<u8>, sk: &SigningKey) -> Vec<u8> {
    let sig = sk.sign(&body);
    SignedMinerHeartbeat {
        body,
        sig: sig.to_bytes().to_vec(),
    }
    .canonical()
    .expect("encode signed envelope")
}

/// Canonical-encode a body from raw CBOR field pairs — used to build
/// bodies `MinerHeartbeat::canonical()` would refuse to produce (a
/// wrong `schema_version`, a wrong `domain`, an extra key, …).
fn forged_body(entries: Vec<(Value, Value)>) -> Vec<u8> {
    to_canonical_vec(&Value::Map(entries)).expect("encode forged body")
}

/// A ten-field heartbeat body as raw pairs, with `overrides` applied by
/// key. Keeps the negative tests to a single deviation each.
fn body_pairs(overrides: &[(&str, Value)]) -> Vec<(Value, Value)> {
    let mut fields: Vec<(Value, Value)> = vec![
        ("cpu_load_1m_centi", Value::Integer(0.into())),
        ("domain", Value::Text(DOMAIN.into())),
        ("memory_available_mib", Value::Integer(0.into())),
        ("memory_total_mib", Value::Integer(0.into())),
        ("miner_id", Value::Text("m".into())),
        ("schema_version", Value::Integer(SCHEMA_VERSION.into())),
        ("sequence", Value::Integer(1.into())),
        ("timestamp_unix", Value::Integer(1.into())),
        ("vm_count_running", Value::Integer(0.into())),
        ("vm_count_total", Value::Integer(0.into())),
    ]
    .into_iter()
    .map(|(k, v)| (Value::Text(k.into()), v))
    .collect();
    for (ok, ov) in overrides {
        for (k, v) in fields.iter_mut() {
            if matches!(k, Value::Text(s) if s == ok) {
                *v = ov.clone();
            }
        }
    }
    fields
}

/// Parse `stdout` as JSON and assert it is a clean reject carrying
/// exactly `expected_class`.
fn assert_reject(run: &Run, expected_class: &str) {
    assert_eq!(
        run.exit, 0,
        "reject must still exit 0; stderr: {}",
        run.stderr
    );
    let json: serde_json::Value = serde_json::from_str(&run.stdout).expect("stdout is not JSON");
    assert_eq!(json["ok"], serde_json::Value::Bool(false), "want ok:false");
    assert_eq!(
        json["error_class"],
        serde_json::Value::String(expected_class.into()),
        "wrong error_class",
    );
    // A reject NEVER echoes the body fields.
    assert!(json.get("body").is_none(), "reject leaked a body");
}

#[test]
fn happy_path_kat_returns_the_decoded_body() {
    // The committed frozen envelope `hippius-types`' KAT pins — a
    // canonical-encoding or fixture drift fails this test too.
    let envelope = std::fs::read(repo_root().join("test_vectors/heartbeat/signed_heartbeat.cbor"))
        .expect("read test_vectors/heartbeat/signed_heartbeat.cbor");
    let sk = SigningKey::from_bytes(&KAT_SEED);

    let run = run_verify_heartbeat(&vk_hex(&sk), &envelope);
    assert_eq!(run.exit, 0, "stderr: {}", run.stderr);

    let json: serde_json::Value = serde_json::from_str(&run.stdout).expect("stdout is not JSON");
    assert_eq!(json["ok"], serde_json::Value::Bool(true));
    let body = &json["body"];
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["domain"], DOMAIN);
    assert_eq!(body["miner_id"], "miner-a");
    assert_eq!(body["timestamp_unix"], 1_700_000_000_i64);
    assert_eq!(body["sequence"], 42);
    assert_eq!(body["vm_count_running"], 3);
    assert_eq!(body["vm_count_total"], 5);
    assert_eq!(body["cpu_load_1m_centi"], 175);
    assert_eq!(body["memory_total_mib"], 262_144);
    assert_eq!(body["memory_available_mib"], 131_072);
    // A v1 body never carries the flag — the JSON always emits it false.
    assert_eq!(body["graceful_exit_requested"], false);
}

/// A v2 graceful-exit heartbeat tuple — 11 fields, the flag true.
fn kat_graceful_exit_heartbeat() -> MinerHeartbeat {
    MinerHeartbeat::graceful_exit(
        "miner-a".into(),
        1_700_000_000,
        42,
        3,
        5,
        175,
        262_144,
        131_072,
    )
}

#[test]
fn v2_graceful_exit_heartbeat_verifies_and_echoes_the_flag() {
    // A real v2 graceful-exit heartbeat, signed and verified end-to-end
    // through the spawned binary: it verifies, schema_version is 2, and
    // the JSON body carries graceful_exit_requested:true for the Django
    // ingest gate to act on (transport (B)).
    let sk = SigningKey::from_bytes(&[0xC2u8; 32]);
    let envelope = signed_envelope(kat_graceful_exit_heartbeat().canonical().unwrap(), &sk);
    let run = run_verify_heartbeat(&vk_hex(&sk), &envelope);
    assert_eq!(run.exit, 0, "stderr: {}", run.stderr);

    let json: serde_json::Value = serde_json::from_str(&run.stdout).expect("stdout is not JSON");
    assert_eq!(json["ok"], serde_json::Value::Bool(true));
    let body = &json["body"];
    assert_eq!(body["schema_version"], 2);
    assert_eq!(body["miner_id"], "miner-a");
    assert_eq!(body["graceful_exit_requested"], true);
}

#[test]
fn v2_body_missing_the_flag_is_body_decode_failed() {
    // A schema_version 2 body with only the 10 v1 fields (the flag key
    // missing) fails the version-aware field-count gate.
    let sk = SigningKey::from_bytes(&[0xC3u8; 32]);
    let body = forged_body(body_pairs(&[("schema_version", Value::Integer(2.into()))]));
    let run = run_verify_heartbeat(&vk_hex(&sk), &signed_envelope(body, &sk));
    assert_reject(&run, "body_decode_failed");
}

#[test]
fn wrong_verifying_key_is_signature_invalid() {
    // The KAT envelope, verified against an unrelated key.
    let envelope = signed_envelope(
        kat_heartbeat().canonical().unwrap(),
        &SigningKey::from_bytes(&[0x11u8; 32]),
    );
    let pretender = SigningKey::from_bytes(&[0x22u8; 32]);
    let run = run_verify_heartbeat(&vk_hex(&pretender), &envelope);
    assert_reject(&run, "signature_invalid");
}

#[test]
fn tampered_body_is_rejected() {
    // Flip a body byte AFTER signing, then re-canonicalise the envelope
    // so the failure lands on the signature, not the envelope shape.
    let sk = SigningKey::from_bytes(&[0x33u8; 32]);
    let mut body = kat_heartbeat().canonical().unwrap();
    let sig = sk.sign(&body);
    let last = body.len() - 1;
    body[last] ^= 0xff;
    let envelope = SignedMinerHeartbeat {
        body,
        sig: sig.to_bytes().to_vec(),
    }
    .canonical()
    .unwrap();
    let run = run_verify_heartbeat(&vk_hex(&sk), &envelope);
    // A flipped body byte breaks the signature (and may also break the
    // inner canonical form) — either is a clean reject.
    assert_eq!(run.exit, 0, "stderr: {}", run.stderr);
    let json: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(json["ok"], serde_json::Value::Bool(false));
    let class = json["error_class"].as_str().unwrap();
    assert!(
        class == "signature_invalid" || class == "not_canonical_cbor",
        "got {class}",
    );
}

#[test]
fn non_canonical_envelope_is_rejected() {
    // Emit `{body, sig}` in non-canonical key order. The canonical
    // order is `sig` then `body` (the 3-char key's encoded form sorts
    // before the 4-char key's) — `body` then `sig` is non-canonical.
    let sk = SigningKey::from_bytes(&[0x44u8; 32]);
    let body = kat_heartbeat().canonical().unwrap();
    let sig = sk.sign(&body);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![
            (Value::Text("body".into()), Value::Bytes(body)),
            (
                Value::Text("sig".into()),
                Value::Bytes(sig.to_bytes().to_vec()),
            ),
        ]),
        &mut bytes,
    )
    .unwrap();
    let run = run_verify_heartbeat(&vk_hex(&sk), &bytes);
    assert_reject(&run, "not_canonical_cbor");
}

#[test]
fn canonical_but_wrong_shape_is_envelope_decode_failed() {
    // Canonical CBOR that is not a `{body, sig}` envelope.
    let bytes = to_canonical_vec(&Value::Integer(7.into())).unwrap();
    let sk = SigningKey::from_bytes(&[0x55u8; 32]);
    let run = run_verify_heartbeat(&vk_hex(&sk), &bytes);
    assert_reject(&run, "envelope_decode_failed");
}

#[test]
fn array_encoded_body_field_is_rejected() {
    // `serde_bytes` DOES decode a `body` carried as a CBOR array of
    // integers — that is NOT the canonical `{body: bstr, sig: bstr}`
    // shape. Even with a VALID signature over the real body bytes, the
    // strict-shape re-encode gate keeps it off the `ok:true` path and
    // rejects it `not_canonical_cbor`.
    let sk = SigningKey::from_bytes(&[0x5Au8; 32]);
    let body = kat_heartbeat().canonical().unwrap();
    let sig = sk.sign(&body);
    let buf = to_canonical_vec(&Value::Map(vec![
        (
            Value::Text("body".into()),
            Value::Array(body.iter().map(|b| Value::Integer((*b).into())).collect()),
        ),
        (
            Value::Text("sig".into()),
            Value::Bytes(sig.to_bytes().to_vec()),
        ),
    ]))
    .unwrap();
    let run = run_verify_heartbeat(&vk_hex(&sk), &buf);
    assert_reject(&run, "not_canonical_cbor");
}

#[test]
fn over_cap_envelope_is_body_too_large() {
    // A 5000-byte body → an envelope past the 4096-byte cap.
    let sk = SigningKey::from_bytes(&[0x66u8; 32]);
    let envelope = SignedMinerHeartbeat {
        body: vec![0u8; 5000],
        sig: vec![0u8; SIGNATURE_LEN],
    }
    .canonical()
    .unwrap();
    let run = run_verify_heartbeat(&vk_hex(&sk), &envelope);
    assert_reject(&run, "body_too_large");
}

#[test]
fn wrong_schema_version_is_rejected() {
    // Version 3 is unknown (neither v1 nor v2). A 10-field body matches
    // the v1-count branch, so it decodes cleanly and the failure lands
    // on the schema-version gate.
    let sk = SigningKey::from_bytes(&[0x77u8; 32]);
    let body = forged_body(body_pairs(&[("schema_version", Value::Integer(3.into()))]));
    let run = run_verify_heartbeat(&vk_hex(&sk), &signed_envelope(body, &sk));
    assert_reject(&run, "wrong_schema_version");
}

#[test]
fn wrong_domain_is_rejected() {
    let sk = SigningKey::from_bytes(&[0x88u8; 32]);
    let body = forged_body(body_pairs(&[(
        "domain",
        Value::Text("HIPPIUS_OTHER_V1".into()),
    )]));
    let run = run_verify_heartbeat(&vk_hex(&sk), &signed_envelope(body, &sk));
    assert_reject(&run, "wrong_domain");
}

#[test]
fn empty_miner_id_is_rejected() {
    let sk = SigningKey::from_bytes(&[0x99u8; 32]);
    let body = forged_body(body_pairs(&[("miner_id", Value::Text(String::new()))]));
    let run = run_verify_heartbeat(&vk_hex(&sk), &signed_envelope(body, &sk));
    assert_reject(&run, "miner_id_invalid");
}

#[test]
fn body_with_an_extra_key_is_body_decode_failed() {
    // Eleven fields — a smuggle attempt past the fixed ten-field schema.
    let sk = SigningKey::from_bytes(&[0xAAu8; 32]);
    let mut pairs = body_pairs(&[]);
    pairs.push((Value::Text("evil".into()), Value::Integer(0.into())));
    let run = run_verify_heartbeat(&vk_hex(&sk), &signed_envelope(forged_body(pairs), &sk));
    assert_reject(&run, "body_decode_failed");
}

#[test]
fn malformed_vk_hex_exits_2_with_no_json() {
    // `--vk-hex` is a CLI/operator argument, not envelope data — a
    // malformed value is a usage error: exit 2, a stderr line, and NO
    // JSON on stdout (the Django consumer parses stdout only).
    let run = run_verify_heartbeat("not-hex", b"ignored");
    assert_eq!(run.exit, 2, "want exit 2 on a bad --vk-hex");
    assert!(
        run.stdout.is_empty(),
        "no JSON on a usage error: {}",
        run.stdout
    );
    assert!(!run.stderr.is_empty(), "a usage error must explain itself");
}

#[test]
fn short_vk_hex_exits_2() {
    // Valid hex, but not 32 bytes — still a usage error.
    let run = run_verify_heartbeat("abcd", b"ignored");
    assert_eq!(run.exit, 2);
    assert!(run.stdout.is_empty());
    assert!(!run.stderr.is_empty());
}

#[test]
fn stdout_write_failure_exits_1() {
    // A broken stdout pipe is a stdin/stdout IO failure — it MUST exit 1
    // (the Django consumer maps that to HTTP 503), never a false 0. A
    // valid KAT envelope is fed so the failure is unambiguously the
    // stdout write, not a validation outcome. The stdout read end is
    // closed before the child finishes reading stdin, so by the time it
    // reaches the emit/flush the write fails deterministically — Rust
    // ignores SIGPIPE, so the child observes a `BrokenPipe` error.
    let envelope = std::fs::read(repo_root().join("test_vectors/heartbeat/signed_heartbeat.cbor"))
        .expect("read signed_heartbeat.cbor");
    let sk = SigningKey::from_bytes(&KAT_SEED);

    let mut child = Command::new(env!("CARGO_BIN_EXE_hippius-ticket-validator"))
        .arg("verify-heartbeat")
        .arg("--vk-hex")
        .arg(vk_hex(&sk))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn hippius-ticket-validator");

    // Close the read end of stdout NOW — before the child has finished
    // reading stdin, so its later write to stdout has no reader.
    drop(child.stdout.take());
    {
        let mut stdin = child.stdin.take().expect("child stdin");
        // The child still consumes stdin fully before it writes; a
        // BrokenPipe on this write would be unexpected (stdin is fine).
        stdin.write_all(&envelope).expect("write stdin");
    }

    let status = child.wait().expect("wait for child");
    assert_eq!(
        status.code(),
        Some(1),
        "a broken stdout pipe must exit 1, not 0",
    );
}
