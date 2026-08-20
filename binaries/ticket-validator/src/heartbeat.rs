//! `verify-heartbeat` subcommand — §K miner-heartbeat signature +
//! schema validation (PR-Part4-A).
//!
//! ## Why this is a NEW pattern — data-bearing output
//!
//! The `verify-edge-telemetry` / `verify-served-receipt` subcommands
//! (see [`crate::telemetry`]) return only `{"tag":"ok"}` — the broker
//! already holds the body, so success needs no echo. A heartbeat is
//! different: vali's heartbeat ingest gate (#127) must enforce the
//! `±300 s` timestamp anti-skew AND the monotonic `sequence` replay
//! defence, and it must do so WITHOUT decoding CBOR in Python (the
//! canonical wire format is single-sourced in Rust). So this
//! subcommand is **data-bearing**: a fully-valid heartbeat returns
//! the decoded body fields for the Django gate to act on.
//!
//! ## Wire contract — the stable JSON the Django consumer parses
//!
//! - stdin: the canonical-CBOR [`SignedMinerHeartbeat`] envelope.
//! - `--vk-hex`: the miner's 32-byte Ed25519 verifying key. vali
//!   resolves it from the registered `TelemetrySource` — it is NEVER
//!   read from the (untrusted) envelope.
//! - stdout, always one JSON object:
//!   - accept → `{"ok":true,"body":{schema_version,domain,miner_id,
//!     timestamp_unix,sequence,vm_count_running,vm_count_total,
//!     cpu_load_1m_centi,memory_total_mib,memory_available_mib,
//!     graceful_exit_requested}}` — `graceful_exit_requested` is the
//!     `v2` flag (always emitted; `false` for a `v1` body, which never
//!     carries the key).
//!   - reject → `{"ok":false,"error_class":"<class>"}`
//! - On a reject the body fields are **never** echoed — even a body
//!   that decoded cleanly but failed a later gate yields only the
//!   class. The fields appear in the output ONLY on full success.
//! - exit: `0` on any validation outcome (accept OR reject); `2` on a
//!   CLI usage error (a malformed `--vk-hex`) with a stderr line and
//!   NO JSON; `1` on a stdin/stdout IO failure.
//!
//! ## Gate order — fail-closed, defence-in-depth
//!
//! size cap → envelope canonical-CBOR → envelope decode → strict-shape
//! re-encode → Ed25519 `verify_strict` over `body` → body
//! canonical-CBOR → body decode → `schema_version` / `domain` /
//! `miner_id`. Each gate runs strictly before the next; the body fields
//! are read only after the signature is proven.
//!
//! The strict-shape gate re-encodes the decoded envelope and demands
//! byte-equality with the input: a canonical-CBOR check alone proves
//! only that the bytes are *some* deterministic value, not that they
//! are the `{body: bstr, sig: bstr}` shape — `serde_bytes` would also
//! accept a `body`/`sig` carried as a CBOR array of integers. The
//! canonical check on the inner `body` is run separately from the
//! envelope's: the body is a nested document, so a non-canonical inner
//! body cannot slip in behind a canonical envelope.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use ciborium::value::Value;
use ed25519_dalek::{Signature, VerifyingKey};
use hippius_types::cbor::assert_canonical;
use hippius_types::heartbeat::{
    SignedMinerHeartbeat, DOMAIN, MAX_MINER_ID_LEN, SCHEMA_VERSION, SCHEMA_VERSION_GRACEFUL_EXIT,
    SIGNATURE_LEN,
};
use serde::Serialize;

/// Exit code on a validation outcome — accept OR reject. The JSON
/// `{"ok":…}` envelope carries the verdict.
const EXIT_OK: u8 = 0;
/// Exit code on a stdin/stdout IO failure — no JSON was emitted.
const EXIT_INTERNAL: u8 = 1;
/// Exit code on a CLI usage error (a malformed `--vk-hex`). A stderr
/// line is emitted; NO JSON — the Django consumer parses stdout only.
const EXIT_USAGE: u8 = 2;

/// Hard cap on the `SignedMinerHeartbeat` envelope read from stdin. A
/// heartbeat is tiny (ten small fields + a 64-byte signature); a
/// larger blob is rejected BEFORE any CBOR decode (parser hardening).
const MAX_HEARTBEAT_BYTES: u64 = 4096;

/// A canonical `v1` `MinerHeartbeat` body is exactly this many CBOR-map
/// fields. A `v1` body with any extra or missing key is malformed.
const HEARTBEAT_FIELD_COUNT: usize = 10;

/// A canonical `v2` body carries one extra key
/// (`graceful_exit_requested`), so the expected count is one greater.
/// The version drives the count: see [`expected_field_count`].
const HEARTBEAT_FIELD_COUNT_V2: usize = HEARTBEAT_FIELD_COUNT + 1;

/// The exact CBOR-map field count a body of `schema_version` must carry
/// — 11 for `v2`, 10 for every other (incl. `v1`). The caller has
/// already decoded `schema_version` and gated it to {1, 2}, so a value
/// of 2 yields the `v2` count and anything else the `v1` count.
fn expected_field_count(schema_version: i128) -> usize {
    if schema_version == i128::from(SCHEMA_VERSION_GRACEFUL_EXIT) {
        HEARTBEAT_FIELD_COUNT_V2
    } else {
        HEARTBEAT_FIELD_COUNT
    }
}

/// Closed `error_class` vocabulary — `&'static str` literals only, so
/// no envelope byte can ever be interpolated into the output (the §K
/// no-leak discipline). Keep in sync with the Django consumer (#127).
mod error_class {
    /// The stdin envelope exceeded [`super::MAX_HEARTBEAT_BYTES`].
    pub const BODY_TOO_LARGE: &str = "body_too_large";
    /// The envelope — or the inner body — was not canonical CBOR, or
    /// the envelope did not match the one canonical `{body, sig}` shape.
    pub const NOT_CANONICAL_CBOR: &str = "not_canonical_cbor";
    /// The bytes did not decode as a `SignedMinerHeartbeat` envelope.
    pub const ENVELOPE_DECODE_FAILED: &str = "envelope_decode_failed";
    /// Ed25519 `verify_strict` of `body` against `--vk-hex` failed.
    pub const SIGNATURE_INVALID: &str = "signature_invalid";
    /// The signed body did not decode to the `MinerHeartbeat` shape.
    pub const BODY_DECODE_FAILED: &str = "body_decode_failed";
    /// `body.schema_version` was not [`super::SCHEMA_VERSION`].
    pub const WRONG_SCHEMA_VERSION: &str = "wrong_schema_version";
    /// `body.domain` was not [`super::DOMAIN`].
    pub const WRONG_DOMAIN: &str = "wrong_domain";
    /// `body.miner_id` was empty or longer than the registry cap.
    pub const MINER_ID_INVALID: &str = "miner_id_invalid";
}

#[derive(clap::Args)]
pub struct VerifyHeartbeatArgs {
    /// 32-byte hex Ed25519 verifying key of the miner. vali resolves
    /// this from the registered `TelemetrySource` — it is NEVER read
    /// from the (untrusted) envelope.
    #[arg(long)]
    vk_hex: String,
}

/// The decoded heartbeat body echoed on a successful validation.
///
/// A faithful, explicit mirror of `hippius_types::heartbeat::
/// MinerHeartbeat` (which carries no `serde` derive — its canonical
/// encoder is hand-built so every signer goes through it). This struct
/// is constructed only AFTER every gate passes, so a `Serialize` here
/// can never echo an unverified field.
#[derive(Serialize, Debug)]
struct HeartbeatBody {
    schema_version: u8,
    domain: String,
    miner_id: String,
    timestamp_unix: i64,
    sequence: u64,
    vm_count_running: u32,
    vm_count_total: u32,
    cpu_load_1m_centi: u32,
    memory_total_mib: u32,
    memory_available_mib: u32,
    /// The `v2` graceful-exit flag. A `v1` body never carries the key,
    /// so it is `false` there; a `v2` body decodes the real CBOR bool.
    /// Always emitted in the JSON output so the Django consumer parses
    /// one stable shape across both versions (it defaults the key to
    /// `false` if absent, so this is backward-compatible regardless).
    graceful_exit_requested: bool,
}

/// `verify-heartbeat` entry point.
pub fn run(args: VerifyHeartbeatArgs) -> ExitCode {
    // The verifying key is a CLI argument, not envelope data: a
    // malformed value is an operator/vali usage error — exit 2 with a
    // stderr line, and NO JSON (the consumer parses stdout only).
    let vk = match parse_vk(&args.vk_hex) {
        Ok(vk) => vk,
        Err(message) => {
            eprintln!("hippius-ticket-validator: verify-heartbeat: {message}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    // `take(MAX + 1)` so an over-cap envelope is detected (a read of
    // MAX+1) without ever buffering an unbounded stream.
    let mut buf = Vec::new();
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_HEARTBEAT_BYTES + 1)
        .read_to_end(&mut buf)
    {
        eprintln!("hippius-ticket-validator: verify-heartbeat: stdin read failed: {e}");
        return ExitCode::from(EXIT_INTERNAL);
    }

    emit(verify(&buf, &vk))
}

/// Serialize the validation outcome to stdout as the stable JSON
/// contract. A reject carries ONLY the closed-vocabulary class.
fn emit(outcome: Result<HeartbeatBody, &'static str>) -> ExitCode {
    let json = match outcome {
        Ok(body) => serde_json::json!({ "ok": true, "body": body }),
        Err(class) => serde_json::json!({ "ok": false, "error_class": class }),
    };
    // The JSON carries no trailing newline, so the `LineWriter` behind
    // `Stdout` would not flush it before the lock drops — and a
    // drop-time flush failure is silently swallowed. Flush explicitly
    // so a broken stdout pipe surfaces as an exit-1 IO failure, never a
    // false exit-0 the Django consumer would read as "no output".
    let mut stdout = io::stdout().lock();
    let written = serde_json::to_writer(&mut stdout, &json)
        .map_err(io::Error::from)
        .and_then(|()| stdout.flush());
    match written {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(e) => {
            eprintln!("hippius-ticket-validator: verify-heartbeat: stdout write failed: {e}");
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

/// Core validation. Returns the decoded body on full success, or a
/// closed-vocabulary `error_class` on the first failing gate. Visible
/// at module scope so the unit tests drive it without a child process.
fn verify(buf: &[u8], vk: &VerifyingKey) -> Result<HeartbeatBody, &'static str> {
    // 1. Size cap — BEFORE any decode.
    if buf.len() as u64 > MAX_HEARTBEAT_BYTES {
        return Err(error_class::BODY_TOO_LARGE);
    }
    // 2. Envelope canonical-CBOR — a cheap pre-filter, BEFORE the
    //    structural decode, so non-canonical bytes never reach the
    //    typed `deny_unknown_fields` decoder.
    if assert_canonical(buf).is_err() {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    // 3. Envelope decode (`SignedMinerHeartbeat` is `deny_unknown_fields`).
    let envelope: SignedMinerHeartbeat =
        ciborium::de::from_reader(buf).map_err(|_| error_class::ENVELOPE_DECODE_FAILED)?;
    // 4. Strict-shape gate. Gate 2 only proves `buf` is SOME
    //    deterministic CBOR value — NOT that it is the canonical
    //    `{body: bstr, sig: bstr}` shape. `serde_bytes` also decodes a
    //    `body`/`sig` carried as a CBOR array of integers (or behind a
    //    tag), so a wrong-shape envelope with an otherwise-valid
    //    signature would slip past. Re-encode the typed envelope —
    //    `SignedMinerHeartbeat::canonical()` always emits byte strings,
    //    sorted keys, no tags — and require byte-for-byte equality: a
    //    heartbeat envelope has exactly ONE valid wire encoding.
    let recanonical = envelope
        .canonical()
        // The only reachable error is a non-[`SIGNATURE_LEN`]-byte
        // `sig` field — a signature defect, classified as such.
        .map_err(|_| error_class::SIGNATURE_INVALID)?;
    if recanonical.as_slice() != buf {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    // 5. Ed25519 verify over the exact `body` bytes — BEFORE any body
    //    field is read. `verify_strict` also rejects non-canonical
    //    signature encodings + small-order keys. Gate 4's `canonical()`
    //    has already proven `sig` is exactly [`SIGNATURE_LEN`] bytes.
    let sig_bytes: [u8; SIGNATURE_LEN] = envelope
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| error_class::SIGNATURE_INVALID)?;
    let signature = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(&envelope.body, &signature)
        .map_err(|_| error_class::SIGNATURE_INVALID)?;
    // 6. Inner-body canonical-CBOR — checked SEPARATELY from the
    //    envelope: the body is a nested CBOR document carried as a byte
    //    string, so gate 4's outer-shape proof says nothing about it. A
    //    miner that signs a non-canonical body must not slip it past.
    if assert_canonical(&envelope.body).is_err() {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    // 7. Body decode — `MinerHeartbeat` carries no `Deserialize`, so
    //    the CBOR map is walked explicitly.
    let body = decode_body(&envelope.body)?;
    // 8. Schema / domain / miner_id gates. BOTH wire versions are
    //    accepted — `v1` (10 fields) and `v2` (11 fields, the
    //    graceful-exit flag). `decode_body` has already enforced the
    //    version-correct field count, so a `v2`-versioned body with the
    //    `v1` field count (or vice-versa) was rejected `body_decode_failed`
    //    before this point. Any version outside {1, 2} fails closed here.
    if body.schema_version != SCHEMA_VERSION && body.schema_version != SCHEMA_VERSION_GRACEFUL_EXIT
    {
        return Err(error_class::WRONG_SCHEMA_VERSION);
    }
    if body.domain != DOMAIN {
        return Err(error_class::WRONG_DOMAIN);
    }
    if body.miner_id.is_empty() || body.miner_id.len() > MAX_MINER_ID_LEN {
        return Err(error_class::MINER_ID_INVALID);
    }
    Ok(body)
}

/// Parse + validate the `--vk-hex` CLI argument into a verifying key.
/// `Err` carries an operator-facing message — `--vk-hex` is public key
/// material from vali, never envelope data, so echoing the decode
/// detail is leak-free.
fn parse_vk(vk_hex: &str) -> Result<VerifyingKey, String> {
    let bytes =
        hex::decode(vk_hex.trim()).map_err(|e| format!("--vk-hex is not valid hex: {e}"))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        format!(
            "--vk-hex must be 32 bytes / 64 hex chars (got {})",
            bytes.len()
        )
    })?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("--vk-hex is not a valid Ed25519 key: {e}"))
}

/// Decode the signed `body` bytes into a [`HeartbeatBody`].
///
/// The body is a canonical CBOR map whose field count is
/// VERSION-DEPENDENT: exactly [`HEARTBEAT_FIELD_COUNT`] for `v1`,
/// [`HEARTBEAT_FIELD_COUNT_V2`] for `v2`. The `schema_version` is read
/// FIRST (it is mandatory in either version), the expected count is
/// derived from it, and a body with any extra key (a smuggle attempt)
/// or a missing one is rejected `body_decode_failed`. The
/// `graceful_exit_requested` bool is read only for `v2` (it is not a
/// `v1` field) and defaults to `false` for `v1`. Every integer is
/// range-checked into its destination type.
fn decode_body(body: &[u8]) -> Result<HeartbeatBody, &'static str> {
    let value: Value =
        ciborium::de::from_reader(body).map_err(|_| error_class::BODY_DECODE_FAILED)?;
    let Value::Map(entries) = value else {
        return Err(error_class::BODY_DECODE_FAILED);
    };
    // The `schema_version` is mandatory in BOTH versions and selects the
    // expected field count — read it before the count gate so a `v2`
    // body (11 fields) is not rejected as an oversized `v1` body.
    let schema_version_raw = int_field(&entries, "schema_version")?;
    if entries.len() != expected_field_count(schema_version_raw) {
        return Err(error_class::BODY_DECODE_FAILED);
    }
    let schema_version =
        u8::try_from(schema_version_raw).map_err(|_| error_class::BODY_DECODE_FAILED)?;
    // The flag is a `v2`-only field. For `v1` it is absent ⇒ `false`;
    // for `v2` it MUST be present (the count gate above guarantees the
    // 11th key is there) and a CBOR bool.
    let graceful_exit_requested = if schema_version == SCHEMA_VERSION_GRACEFUL_EXIT {
        bool_field(&entries, "graceful_exit_requested")?
    } else {
        false
    };
    Ok(HeartbeatBody {
        schema_version,
        domain: text_field(&entries, "domain")?,
        miner_id: text_field(&entries, "miner_id")?,
        timestamp_unix: i64::try_from(int_field(&entries, "timestamp_unix")?)
            .map_err(|_| error_class::BODY_DECODE_FAILED)?,
        sequence: u64::try_from(int_field(&entries, "sequence")?)
            .map_err(|_| error_class::BODY_DECODE_FAILED)?,
        vm_count_running: u32_field(&entries, "vm_count_running")?,
        vm_count_total: u32_field(&entries, "vm_count_total")?,
        cpu_load_1m_centi: u32_field(&entries, "cpu_load_1m_centi")?,
        memory_total_mib: u32_field(&entries, "memory_total_mib")?,
        memory_available_mib: u32_field(&entries, "memory_available_mib")?,
        graceful_exit_requested,
    })
}

/// Find a field in a decoded CBOR map by its text key.
fn field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(k, v)| match k {
        Value::Text(name) if name == key => Some(v),
        _ => None,
    })
}

/// Extract a required CBOR text field.
fn text_field(entries: &[(Value, Value)], key: &str) -> Result<String, &'static str> {
    match field(entries, key) {
        Some(Value::Text(s)) => Ok(s.clone()),
        _ => Err(error_class::BODY_DECODE_FAILED),
    }
}

/// Extract a required CBOR integer field as `i128` (the widest type a
/// ciborium integer fits — the caller range-checks to the real type).
fn int_field(entries: &[(Value, Value)], key: &str) -> Result<i128, &'static str> {
    match field(entries, key) {
        Some(Value::Integer(i)) => Ok(i128::from(*i)),
        _ => Err(error_class::BODY_DECODE_FAILED),
    }
}

/// Extract a required CBOR integer field range-checked into `u32`.
fn u32_field(entries: &[(Value, Value)], key: &str) -> Result<u32, &'static str> {
    u32::try_from(int_field(entries, key)?).map_err(|_| error_class::BODY_DECODE_FAILED)
}

/// Extract a required CBOR bool field. A non-bool (or absent) value is
/// `body_decode_failed` — the `v2` `graceful_exit_requested` MUST be a
/// genuine CBOR bool, never an integer or string masquerading as one.
fn bool_field(entries: &[(Value, Value)], key: &str) -> Result<bool, &'static str> {
    match field(entries, key) {
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(error_class::BODY_DECODE_FAILED),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hippius_types::cbor::to_canonical_vec;
    use hippius_types::heartbeat::MinerHeartbeat;

    /// The pinned KAT heartbeat (mirrors `hippius-types`' KAT tuple).
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

    /// Sign `body` with `sk` and canonical-encode the `{body, sig}`
    /// envelope.
    fn signed_envelope(body: Vec<u8>, sk: &SigningKey) -> Vec<u8> {
        let sig = sk.sign(&body);
        SignedMinerHeartbeat {
            body,
            sig: sig.to_bytes().to_vec(),
        }
        .canonical()
        .unwrap()
    }

    /// A forged canonical body from raw field pairs — used to build
    /// bodies `MinerHeartbeat::canonical()` would refuse to produce
    /// (a wrong `schema_version`, a wrong `domain`, …).
    fn forged_body(entries: Vec<(Value, Value)>) -> Vec<u8> {
        to_canonical_vec(&Value::Map(entries)).unwrap()
    }

    #[test]
    fn happy_path_returns_the_decoded_body() {
        let sk = SigningKey::from_bytes(&[0x3Bu8; 32]);
        let envelope = signed_envelope(kat_heartbeat().canonical().unwrap(), &sk);
        let body = verify(&envelope, &sk.verifying_key()).unwrap();
        assert_eq!(body.schema_version, 1);
        assert_eq!(body.domain, DOMAIN);
        assert_eq!(body.miner_id, "miner-a");
        assert_eq!(body.timestamp_unix, 1_700_000_000);
        assert_eq!(body.sequence, 42);
        assert_eq!(body.vm_count_running, 3);
        assert_eq!(body.vm_count_total, 5);
        assert_eq!(body.cpu_load_1m_centi, 175);
        assert_eq!(body.memory_total_mib, 262_144);
        assert_eq!(body.memory_available_mib, 131_072);
        // A v1 body never carries the flag — it defaults to false.
        assert!(!body.graceful_exit_requested);
    }

    /// A v2 graceful-exit heartbeat tuple (11 fields, flag true).
    fn kat_graceful_exit() -> MinerHeartbeat {
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
    fn v2_graceful_exit_heartbeat_verifies_and_carries_the_flag() {
        // A valid v2 heartbeat: 11 fields, the flag is true. It verifies
        // and the decoded body echoes the flag for the Django gate.
        let sk = SigningKey::from_bytes(&[0x2Au8; 32]);
        let envelope = signed_envelope(kat_graceful_exit().canonical().unwrap(), &sk);
        let body = verify(&envelope, &sk.verifying_key()).unwrap();
        assert_eq!(body.schema_version, 2);
        assert_eq!(body.miner_id, "miner-a");
        assert!(body.graceful_exit_requested);
    }

    #[test]
    fn v2_heartbeat_with_flag_false_verifies() {
        // A v2-versioned heartbeat may legitimately carry the flag as
        // false (a normal heartbeat that happens to be v2). It verifies.
        let sk = SigningKey::from_bytes(&[0x2Bu8; 32]);
        let mut hb = kat_graceful_exit();
        hb.graceful_exit_requested = false;
        let envelope = signed_envelope(hb.canonical().unwrap(), &sk);
        let body = verify(&envelope, &sk.verifying_key()).unwrap();
        assert_eq!(body.schema_version, 2);
        assert!(!body.graceful_exit_requested);
    }

    #[test]
    fn v2_body_with_only_ten_fields_is_rejected() {
        // A body that claims schema_version 2 but carries only the 10
        // v1 fields (the flag key missing) fails the version-aware count
        // gate — it must NOT be silently treated as a v1 body.
        let sk = SigningKey::from_bytes(&[0x2Cu8; 32]);
        let body = forged_body(vec![
            (
                Value::Text("cpu_load_1m_centi".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("domain".into()), Value::Text(DOMAIN.into())),
            (
                Value::Text("memory_available_mib".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("memory_total_mib".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("miner_id".into()), Value::Text("m".into())),
            (
                Value::Text("schema_version".into()),
                Value::Integer(2.into()),
            ),
            (Value::Text("sequence".into()), Value::Integer(1.into())),
            (
                Value::Text("timestamp_unix".into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("vm_count_running".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("vm_count_total".into()),
                Value::Integer(0.into()),
            ),
        ]);
        let envelope = signed_envelope(body, &sk);
        assert_eq!(
            verify(&envelope, &sk.verifying_key()).unwrap_err(),
            error_class::BODY_DECODE_FAILED,
        );
    }

    #[test]
    fn v1_body_with_eleven_fields_is_rejected() {
        // The mirror case: a schema_version 1 body with the v2 flag key
        // present (11 fields) exceeds the v1 count of 10 — rejected. A v1
        // heartbeat can never carry the flag.
        let sk = SigningKey::from_bytes(&[0x2Du8; 32]);
        let body = forged_body(vec![
            (
                Value::Text("cpu_load_1m_centi".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("domain".into()), Value::Text(DOMAIN.into())),
            (
                Value::Text("graceful_exit_requested".into()),
                Value::Bool(true),
            ),
            (
                Value::Text("memory_available_mib".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("memory_total_mib".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("miner_id".into()), Value::Text("m".into())),
            (
                Value::Text("schema_version".into()),
                Value::Integer(1.into()),
            ),
            (Value::Text("sequence".into()), Value::Integer(1.into())),
            (
                Value::Text("timestamp_unix".into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("vm_count_running".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("vm_count_total".into()),
                Value::Integer(0.into()),
            ),
        ]);
        let envelope = signed_envelope(body, &sk);
        assert_eq!(
            verify(&envelope, &sk.verifying_key()).unwrap_err(),
            error_class::BODY_DECODE_FAILED,
        );
    }

    #[test]
    fn v2_body_with_non_bool_flag_is_rejected() {
        // The flag MUST be a genuine CBOR bool — an integer 1 in its
        // place (11 fields, so the count passes) is body_decode_failed.
        let sk = SigningKey::from_bytes(&[0x2Eu8; 32]);
        let body = forged_body(vec![
            (
                Value::Text("cpu_load_1m_centi".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("domain".into()), Value::Text(DOMAIN.into())),
            (
                Value::Text("graceful_exit_requested".into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("memory_available_mib".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("memory_total_mib".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("miner_id".into()), Value::Text("m".into())),
            (
                Value::Text("schema_version".into()),
                Value::Integer(2.into()),
            ),
            (Value::Text("sequence".into()), Value::Integer(1.into())),
            (
                Value::Text("timestamp_unix".into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("vm_count_running".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("vm_count_total".into()),
                Value::Integer(0.into()),
            ),
        ]);
        let envelope = signed_envelope(body, &sk);
        assert_eq!(
            verify(&envelope, &sk.verifying_key()).unwrap_err(),
            error_class::BODY_DECODE_FAILED,
        );
    }

    #[test]
    fn wrong_verifying_key_is_signature_invalid() {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let pretender = SigningKey::from_bytes(&[2u8; 32]);
        let envelope = signed_envelope(kat_heartbeat().canonical().unwrap(), &signer);
        assert_eq!(
            verify(&envelope, &pretender.verifying_key()).unwrap_err(),
            error_class::SIGNATURE_INVALID,
        );
    }

    #[test]
    fn tampered_body_is_rejected() {
        // Flip a byte of the body AFTER signing — re-canonicalise the
        // envelope so the canonical gate passes and the failure lands
        // squarely on the signature.
        let sk = SigningKey::from_bytes(&[3u8; 32]);
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
        let class = verify(&envelope, &sk.verifying_key()).unwrap_err();
        // A flipped body byte breaks the signature (and may also break
        // the inner canonical form).
        assert!(
            class == error_class::SIGNATURE_INVALID || class == error_class::NOT_CANONICAL_CBOR,
            "got {class}",
        );
    }

    #[test]
    fn non_canonical_envelope_is_rejected() {
        // Emit the `{body, sig}` map in NON-canonical key order. The
        // canonical order is `sig` then `body` — the 3-char key's
        // encoded form (`0x63…`) sorts before the 4-char key's
        // (`0x64…`) — so `body` then `sig` is non-canonical and the
        // envelope canonical gate must reject it before the decode.
        let sk = SigningKey::from_bytes(&[4u8; 32]);
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
        assert_eq!(
            verify(&bytes, &sk.verifying_key()).unwrap_err(),
            error_class::NOT_CANONICAL_CBOR,
        );
    }

    #[test]
    fn array_encoded_body_field_is_rejected() {
        // `serde_bytes` DOES decode a `body` carried as a CBOR array of
        // integers — verified: the typed decode succeeds, so this is the
        // exact path the strict-shape gate exists to close. The envelope
        // is otherwise a VALID signature over the real body bytes, yet
        // the gate-4 re-encode mismatch rejects it `not_canonical_cbor`.
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
        assert_eq!(
            verify(&buf, &sk.verifying_key()).unwrap_err(),
            error_class::NOT_CANONICAL_CBOR,
        );
    }

    #[test]
    fn canonical_but_wrong_shape_is_envelope_decode_failed() {
        // Canonical CBOR that is not a `{body, sig}` envelope.
        let bytes = to_canonical_vec(&Value::Integer(7.into())).unwrap();
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        assert_eq!(
            verify(&bytes, &sk.verifying_key()).unwrap_err(),
            error_class::ENVELOPE_DECODE_FAILED,
        );
    }

    #[test]
    fn wrong_schema_version_is_rejected() {
        // A validly-signed 10-field body whose `schema_version` is 3 —
        // an UNKNOWN version (neither v1 nor v2). 10 fields matches the
        // v1-count branch, so the body decodes cleanly and the failure
        // lands on the schema-version gate (not the count gate).
        let sk = SigningKey::from_bytes(&[6u8; 32]);
        let body = forged_body(vec![
            (
                Value::Text("cpu_load_1m_centi".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("domain".into()), Value::Text(DOMAIN.into())),
            (
                Value::Text("memory_available_mib".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("memory_total_mib".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("miner_id".into()), Value::Text("m".into())),
            (
                Value::Text("schema_version".into()),
                Value::Integer(3.into()),
            ),
            (Value::Text("sequence".into()), Value::Integer(1.into())),
            (
                Value::Text("timestamp_unix".into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("vm_count_running".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("vm_count_total".into()),
                Value::Integer(0.into()),
            ),
        ]);
        let envelope = signed_envelope(body, &sk);
        assert_eq!(
            verify(&envelope, &sk.verifying_key()).unwrap_err(),
            error_class::WRONG_SCHEMA_VERSION,
        );
    }

    #[test]
    fn wrong_domain_is_rejected() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let body = forged_body(vec![
            (
                Value::Text("cpu_load_1m_centi".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("domain".into()),
                Value::Text("HIPPIUS_OTHER_V1".into()),
            ),
            (
                Value::Text("memory_available_mib".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("memory_total_mib".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("miner_id".into()), Value::Text("m".into())),
            (
                Value::Text("schema_version".into()),
                Value::Integer(1.into()),
            ),
            (Value::Text("sequence".into()), Value::Integer(1.into())),
            (
                Value::Text("timestamp_unix".into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("vm_count_running".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("vm_count_total".into()),
                Value::Integer(0.into()),
            ),
        ]);
        let envelope = signed_envelope(body, &sk);
        assert_eq!(
            verify(&envelope, &sk.verifying_key()).unwrap_err(),
            error_class::WRONG_DOMAIN,
        );
    }

    #[test]
    fn empty_miner_id_is_rejected() {
        let sk = SigningKey::from_bytes(&[8u8; 32]);
        let body = forged_body(vec![
            (
                Value::Text("cpu_load_1m_centi".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("domain".into()), Value::Text(DOMAIN.into())),
            (
                Value::Text("memory_available_mib".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("memory_total_mib".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("miner_id".into()), Value::Text(String::new())),
            (
                Value::Text("schema_version".into()),
                Value::Integer(1.into()),
            ),
            (Value::Text("sequence".into()), Value::Integer(1.into())),
            (
                Value::Text("timestamp_unix".into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("vm_count_running".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("vm_count_total".into()),
                Value::Integer(0.into()),
            ),
        ]);
        let envelope = signed_envelope(body, &sk);
        assert_eq!(
            verify(&envelope, &sk.verifying_key()).unwrap_err(),
            error_class::MINER_ID_INVALID,
        );
    }

    #[test]
    fn body_with_an_extra_key_is_body_decode_failed() {
        // Eleven fields — a smuggle attempt past the fixed schema.
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let body = forged_body(vec![
            (
                Value::Text("cpu_load_1m_centi".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("domain".into()), Value::Text(DOMAIN.into())),
            (Value::Text("evil".into()), Value::Integer(0.into())),
            (
                Value::Text("memory_available_mib".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("memory_total_mib".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("miner_id".into()), Value::Text("m".into())),
            (
                Value::Text("schema_version".into()),
                Value::Integer(1.into()),
            ),
            (Value::Text("sequence".into()), Value::Integer(1.into())),
            (
                Value::Text("timestamp_unix".into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("vm_count_running".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("vm_count_total".into()),
                Value::Integer(0.into()),
            ),
        ]);
        let envelope = signed_envelope(body, &sk);
        assert_eq!(
            verify(&envelope, &sk.verifying_key()).unwrap_err(),
            error_class::BODY_DECODE_FAILED,
        );
    }

    #[test]
    fn over_cap_envelope_is_body_too_large() {
        let sk = SigningKey::from_bytes(&[10u8; 32]);
        // A 5000-byte `body` → an envelope past the 4096-byte cap.
        let envelope = SignedMinerHeartbeat {
            body: vec![0u8; 5000],
            sig: vec![0u8; SIGNATURE_LEN],
        }
        .canonical()
        .unwrap();
        assert!(envelope.len() as u64 > MAX_HEARTBEAT_BYTES);
        assert_eq!(
            verify(&envelope, &sk.verifying_key()).unwrap_err(),
            error_class::BODY_TOO_LARGE,
        );
    }

    #[test]
    fn parse_vk_rejects_malformed_arguments() {
        assert!(parse_vk("not-hex").is_err());
        assert!(parse_vk("abcd").is_err()); // 2 bytes, not 32
        assert!(parse_vk(&"00".repeat(32)).is_ok());
    }
}
