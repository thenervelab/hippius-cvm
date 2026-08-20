//! `verify-vm-progress` subcommand — miner guest-boot progress signature
//! and schema validation. Mirrors [`crate::graceful_exit`] (data-bearing
//! output): vali's endpoint must enforce the `±300 s` timestamp skew AND
//! read the `vm_id` + `milestone` to advance the VM's `boot_phase`
//! WITHOUT decoding CBOR in Python (the canonical wire format is
//! single-sourced in Rust), so a fully-valid report returns its decoded
//! body fields for the Django gate to act on.
//!
//! ## Wire contract (the stable JSON the Django consumer parses)
//!
//! - stdin: the canonical-CBOR [`SignedVmProgress`] envelope.
//! - `--vk-hex`: the miner's 32-byte Ed25519 verifying key — vali
//!   resolves it from the registered miner identity, NEVER from the
//!   (untrusted) envelope.
//! - stdout, one JSON object:
//!   - accept → `{"ok":true,"body":{schema_version,domain,miner_id,
//!     vm_id,milestone,timestamp_unix}}`
//!   - reject → `{"ok":false,"error_class":"<class>"}` (no body echoed).
//! - exit: `0` on any validation outcome; `2` on a malformed `--vk-hex`
//!   (stderr line, no JSON); `1` on a stdin/stdout IO failure.
//!
//! Gate order (fail-closed, identical to `verify-graceful-exit`): size
//! cap → envelope canonical-CBOR → envelope decode → strict-shape
//! re-encode → Ed25519 `verify_strict` over `body` → body canonical-CBOR
//! → body decode → schema/domain/miner_id/vm_id/milestone.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use ciborium::value::Value;
use ed25519_dalek::{Signature, VerifyingKey};
use hippius_types::cbor::assert_canonical;
use hippius_types::vm_progress::{
    SignedVmProgress, VmProgressMilestone, DOMAIN, MAX_MINER_ID_LEN, MAX_VM_ID_LEN, SCHEMA_VERSION,
    SIGNATURE_LEN,
};
use serde::Serialize;

const EXIT_OK: u8 = 0;
const EXIT_INTERNAL: u8 = 1;
const EXIT_USAGE: u8 = 2;

/// Hard cap on the envelope read from stdin — a vm-progress report is
/// tiny (six small fields + a 64-byte signature). Rejected BEFORE any
/// decode. Matches the `_MAX_VM_PROGRESS_BYTES` cap the Django consumer
/// enforces.
const MAX_REQUEST_BYTES: u64 = 4096;

/// A canonical `VmProgressReport` body is exactly this many fields.
const FIELD_COUNT: usize = 6;

/// Closed `error_class` vocabulary — `&'static str` only, so no envelope
/// byte is ever interpolated into the output. Keep in sync with the
/// Django consumer (`VM_PROGRESS_ERROR_CLASSES`).
mod error_class {
    pub const BODY_TOO_LARGE: &str = "body_too_large";
    pub const NOT_CANONICAL_CBOR: &str = "not_canonical_cbor";
    pub const ENVELOPE_DECODE_FAILED: &str = "envelope_decode_failed";
    pub const SIGNATURE_INVALID: &str = "signature_invalid";
    pub const BODY_DECODE_FAILED: &str = "body_decode_failed";
    pub const WRONG_SCHEMA_VERSION: &str = "wrong_schema_version";
    pub const WRONG_DOMAIN: &str = "wrong_domain";
    pub const MINER_ID_INVALID: &str = "miner_id_invalid";
    pub const VM_ID_INVALID: &str = "vm_id_invalid";
    pub const MILESTONE_INVALID: &str = "milestone_invalid";
}

#[derive(clap::Args)]
pub struct VerifyVmProgressArgs {
    /// 32-byte hex Ed25519 verifying key of the miner. vali resolves it
    /// from the registered identity — NEVER from the envelope.
    #[arg(long)]
    vk_hex: String,
}

/// The decoded body echoed on a successful validation. Constructed ONLY
/// after every gate passes, so `Serialize` can never echo an unverified
/// field.
#[derive(Serialize, Debug)]
struct VmProgressBody {
    schema_version: u8,
    domain: String,
    miner_id: String,
    vm_id: String,
    milestone: String,
    timestamp_unix: i64,
}

/// `verify-vm-progress` entry point.
pub fn run(args: VerifyVmProgressArgs) -> ExitCode {
    let vk = match parse_vk(&args.vk_hex) {
        Ok(vk) => vk,
        Err(message) => {
            eprintln!("hippius-ticket-validator: verify-vm-progress: {message}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let mut buf = Vec::new();
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut buf)
    {
        eprintln!("hippius-ticket-validator: verify-vm-progress: stdin read failed: {e}");
        return ExitCode::from(EXIT_INTERNAL);
    }

    emit(verify(&buf, &vk))
}

fn emit(outcome: Result<VmProgressBody, &'static str>) -> ExitCode {
    let json = match outcome {
        Ok(body) => serde_json::json!({ "ok": true, "body": body }),
        Err(class) => serde_json::json!({ "ok": false, "error_class": class }),
    };
    let mut stdout = io::stdout().lock();
    let written = serde_json::to_writer(&mut stdout, &json)
        .map_err(io::Error::from)
        .and_then(|()| stdout.flush());
    match written {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(e) => {
            eprintln!("hippius-ticket-validator: verify-vm-progress: stdout write failed: {e}");
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

/// Core validation — returns the decoded body on full success, or a
/// closed-vocabulary `error_class` on the first failing gate. Module-
/// scoped so the unit tests drive it without a child process.
fn verify(buf: &[u8], vk: &VerifyingKey) -> Result<VmProgressBody, &'static str> {
    if buf.len() as u64 > MAX_REQUEST_BYTES {
        return Err(error_class::BODY_TOO_LARGE);
    }
    if assert_canonical(buf).is_err() {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    let envelope: SignedVmProgress =
        ciborium::de::from_reader(buf).map_err(|_| error_class::ENVELOPE_DECODE_FAILED)?;
    // Strict-shape gate — re-encode the typed envelope and demand
    // byte-equality (a vm-progress envelope has exactly ONE valid wire
    // encoding; `serde_bytes` would otherwise accept array-encoded bytes).
    let recanonical = envelope
        .canonical()
        .map_err(|_| error_class::SIGNATURE_INVALID)?;
    if recanonical.as_slice() != buf {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    let sig_bytes: [u8; SIGNATURE_LEN] = envelope
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| error_class::SIGNATURE_INVALID)?;
    let signature = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(&envelope.body, &signature)
        .map_err(|_| error_class::SIGNATURE_INVALID)?;
    if assert_canonical(&envelope.body).is_err() {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    let body = decode_body(&envelope.body)?;
    if body.schema_version != SCHEMA_VERSION {
        return Err(error_class::WRONG_SCHEMA_VERSION);
    }
    if body.domain != DOMAIN {
        return Err(error_class::WRONG_DOMAIN);
    }
    if body.miner_id.is_empty() || body.miner_id.len() > MAX_MINER_ID_LEN {
        return Err(error_class::MINER_ID_INVALID);
    }
    if body.vm_id.is_empty() || body.vm_id.len() > MAX_VM_ID_LEN {
        return Err(error_class::VM_ID_INVALID);
    }
    if VmProgressMilestone::from_wire(&body.milestone).is_none() {
        return Err(error_class::MILESTONE_INVALID);
    }
    Ok(body)
}

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

/// Decode the signed `body` into a [`VmProgressBody`] — a canonical CBOR
/// map of exactly [`FIELD_COUNT`] fields; any extra/missing key is
/// rejected.
fn decode_body(body: &[u8]) -> Result<VmProgressBody, &'static str> {
    let value: Value =
        ciborium::de::from_reader(body).map_err(|_| error_class::BODY_DECODE_FAILED)?;
    let Value::Map(entries) = value else {
        return Err(error_class::BODY_DECODE_FAILED);
    };
    if entries.len() != FIELD_COUNT {
        return Err(error_class::BODY_DECODE_FAILED);
    }
    Ok(VmProgressBody {
        schema_version: u8::try_from(int_field(&entries, "schema_version")?)
            .map_err(|_| error_class::BODY_DECODE_FAILED)?,
        domain: text_field(&entries, "domain")?,
        miner_id: text_field(&entries, "miner_id")?,
        vm_id: text_field(&entries, "vm_id")?,
        milestone: text_field(&entries, "milestone")?,
        timestamp_unix: i64::try_from(int_field(&entries, "timestamp_unix")?)
            .map_err(|_| error_class::BODY_DECODE_FAILED)?,
    })
}

fn field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(k, v)| match k {
        Value::Text(name) if name == key => Some(v),
        _ => None,
    })
}

fn text_field(entries: &[(Value, Value)], key: &str) -> Result<String, &'static str> {
    match field(entries, key) {
        Some(Value::Text(s)) => Ok(s.clone()),
        _ => Err(error_class::BODY_DECODE_FAILED),
    }
}

fn int_field(entries: &[(Value, Value)], key: &str) -> Result<i128, &'static str> {
    match field(entries, key) {
        Some(Value::Integer(i)) => Ok(i128::from(*i)),
        _ => Err(error_class::BODY_DECODE_FAILED),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hippius_types::vm_progress::VmProgressReport;

    fn kat() -> VmProgressReport {
        VmProgressReport::new(
            "miner-a".into(),
            "vm-abc-123".into(),
            VmProgressMilestone::KekReleased,
            1_700_000_000,
        )
    }

    fn signed_envelope(body: Vec<u8>, sk: &SigningKey) -> Vec<u8> {
        let sig = sk.sign(&body);
        SignedVmProgress {
            body,
            sig: sig.to_bytes().to_vec(),
        }
        .canonical()
        .unwrap()
    }

    #[test]
    fn happy_path_returns_the_decoded_body() {
        let sk = SigningKey::from_bytes(&[0x3Bu8; 32]);
        let env = signed_envelope(kat().canonical().unwrap(), &sk);
        let body = verify(&env, &sk.verifying_key()).unwrap();
        assert_eq!(body.schema_version, 1);
        assert_eq!(body.domain, DOMAIN);
        assert_eq!(body.miner_id, "miner-a");
        assert_eq!(body.vm_id, "vm-abc-123");
        assert_eq!(body.milestone, "kek-released");
        assert_eq!(body.timestamp_unix, 1_700_000_000);
    }

    #[test]
    fn wrong_key_is_signature_invalid() {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let pretender = SigningKey::from_bytes(&[2u8; 32]);
        let env = signed_envelope(kat().canonical().unwrap(), &signer);
        assert_eq!(
            verify(&env, &pretender.verifying_key()).unwrap_err(),
            error_class::SIGNATURE_INVALID,
        );
    }

    #[test]
    fn tampered_body_is_rejected() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let mut body = kat().canonical().unwrap();
        let sig = sk.sign(&body);
        let last = body.len() - 1;
        body[last] ^= 0xff;
        let env = SignedVmProgress {
            body,
            sig: sig.to_bytes().to_vec(),
        }
        .canonical()
        .unwrap();
        let class = verify(&env, &sk.verifying_key()).unwrap_err();
        assert!(
            class == error_class::SIGNATURE_INVALID || class == error_class::NOT_CANONICAL_CBOR,
            "got {class}",
        );
    }

    #[test]
    fn each_milestone_wire_value_verifies() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        for (m, wire) in [
            (VmProgressMilestone::Booting, "booting"),
            (VmProgressMilestone::KekReleased, "kek-released"),
            (VmProgressMilestone::Running, "running"),
        ] {
            let report = VmProgressReport::new("m".into(), "vm-1".into(), m, 1_700_000_000);
            let env = signed_envelope(report.canonical().unwrap(), &sk);
            let body = verify(&env, &sk.verifying_key()).unwrap();
            assert_eq!(body.milestone, wire);
        }
    }

    #[test]
    fn over_cap_envelope_is_body_too_large() {
        let sk = SigningKey::from_bytes(&[10u8; 32]);
        let env = SignedVmProgress {
            body: vec![0u8; 5000],
            sig: vec![0u8; SIGNATURE_LEN],
        }
        .canonical()
        .unwrap();
        assert!(env.len() as u64 > MAX_REQUEST_BYTES);
        assert_eq!(
            verify(&env, &sk.verifying_key()).unwrap_err(),
            error_class::BODY_TOO_LARGE,
        );
    }

    #[test]
    fn parse_vk_rejects_malformed() {
        assert!(parse_vk("not-hex").is_err());
        assert!(parse_vk("abcd").is_err());
        assert!(parse_vk(&"00".repeat(32)).is_ok());
    }
}
