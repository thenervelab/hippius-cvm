//! `verify-edge-telemetry` / `verify-served-receipt` subcommands —
//! §9 telemetry-broker signature + schema validation (PR-G6).
//!
//! Both verify ONE signed telemetry payload. The canonical-CBOR
//! `body` arrives on stdin; the detached Ed25519 `sig` as
//! `--sig-hex`; the telemetry source's verifying key as `--vk-hex`
//! (the broker resolves it from its trusted source registry — the
//! key is NEVER taken from the envelope itself). Validation, in
//! order:
//!
//!   1. the body fits the size cap — bounded BEFORE any CBOR decode
//!      (parser hardening);
//!   2. the body is canonical CBOR (`assert_canonical`);
//!   3. `verify_strict(body, sig)` against `vk`;
//!   4. the body decodes as a CBOR map carrying the expected
//!      `domain` tag — the inner payload's schema-version anchor,
//!      and the replay-context separator (a signature from one
//!      scheme cannot be reinterpreted as another).
//!
//! The broker (vali Django) shells out here per ingested envelope;
//! it never decodes CBOR itself. The two subcommands differ ONLY in
//! the expected `domain`.
//!
//! Wire contract: stdout `{"tag":"ok"}` / `{"tag":"err",...}`;
//! exit `0` ok, `2` structured failure, `1` stdin/stdout IO failure.

use std::io::{self, Read};
use std::process::ExitCode;

use ciborium::value::Value;
use ed25519_dalek::{Signature, VerifyingKey};
use hippius_types::cbor::assert_canonical;
use hippius_types::served_receipt::RECEIPT_DOMAIN;
use serde::Serialize;

const EXIT_OK: u8 = 0;
const EXIT_STRUCTURED: u8 = 2;
const EXIT_INTERNAL: u8 = 1;

/// Hard cap on the signed body read from stdin. Telemetry envelopes
/// are small (counters + routing tags, or a fixed-shape receipt); a
/// body larger than this is rejected BEFORE any CBOR decode runs.
const MAX_BODY_BYTES: u64 = 64 * 1024;

/// §H Edge telemetry domain tag. MUST stay byte-identical to
/// `hippius_edge_gateway::wire::TELEMETRY_DOMAIN` — kept as a local
/// constant so this lightweight validator does not pull the whole
/// edge-gateway crate (tokio / rustls) in for a single `&str`.
const EDGE_TELEMETRY_DOMAIN: &str = "HIPPIUS_EDGE_TELEMETRY_V1";

/// Stable `category` vocabulary — keep in sync with the Django
/// consumer (`apps.telemetry.verifier`).
mod category {
    /// A hex argument (vk / sig) failed to decode or had the wrong
    /// length.
    pub const DECODE: &str = "decode";
    /// The signed body was not canonical CBOR.
    pub const NON_CANONICAL: &str = "non-canonical";
    /// Ed25519 verification of the body against the source key
    /// failed.
    pub const SIGNATURE: &str = "signature";
    /// The body did not decode as a CBOR map.
    pub const CBOR: &str = "cbor";
    /// The body carried the wrong / missing `domain` tag — an
    /// unknown schema or a cross-scheme replay attempt.
    pub const DOMAIN: &str = "domain";
}

#[derive(clap::Args)]
pub struct VerifyTelemetryArgs {
    /// 32-byte hex Ed25519 verifying key of the telemetry source.
    /// The broker resolves this from its trusted source registry —
    /// it is never read from the (untrusted) envelope.
    #[arg(long)]
    vk_hex: String,
    /// 64-byte hex detached Ed25519 signature over the stdin body.
    #[arg(long)]
    sig_hex: String,
}

/// stdout JSON envelope for `verify-edge-telemetry`. `Ok` is a unit
/// variant — the broker already holds the body + sig from the request,
/// so success needs no echo.
#[derive(Serialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
enum Output {
    Ok,
    Err {
        error: String,
        category: &'static str,
    },
}

/// The verified, parsed billing fields of a served-delivery receipt.
/// `verify-served-receipt` is a DATA-BEARING verifier (like
/// `verify-heartbeat`): on success it echoes the attested fields the
/// usage-metering consumer bills on, so vali never re-decodes the CBOR
/// body. Every field here is covered by the Ed25519 signature just
/// verified — the miner that relays the receipt cannot forge them.
#[derive(Debug, Serialize)]
struct ReceiptFields {
    vm_id: String,
    lease_id: String,
    node_id_hex: String,
    epoch: u64,
    resource_class: String,
    period_start: u64,
    period_end: u64,
    monotonic_seq: u64,
    observed_degradation_bps: u32,
}

/// stdout JSON envelope for `verify-served-receipt`. On `ok` the parsed
/// billing fields are flattened alongside the tag
/// (`{"tag":"ok","vm_id":…,"period_start":…}`).
#[derive(Serialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
enum ReceiptOutput {
    Ok(ReceiptFields),
    Err {
        error: String,
        category: &'static str,
    },
}

/// Entry point for `verify-edge-telemetry`.
pub fn run_edge_telemetry(args: VerifyTelemetryArgs) -> ExitCode {
    run(args, EDGE_TELEMETRY_DOMAIN)
}

/// Entry point for `verify-served-receipt` — verifies the signature +
/// domain, then emits the attested billing fields for the usage meter.
pub fn run_served_receipt(args: VerifyTelemetryArgs) -> ExitCode {
    let body = match read_capped_stdin() {
        Ok(b) => b,
        Err(code) => return code,
    };
    let output =
        match verify(&body, &args, RECEIPT_DOMAIN).and_then(|()| extract_receipt_fields(&body)) {
            Ok(fields) => ReceiptOutput::Ok(fields),
            Err((category, error)) => ReceiptOutput::Err { error, category },
        };
    let exit = match &output {
        ReceiptOutput::Ok(_) => EXIT_OK,
        ReceiptOutput::Err { .. } => EXIT_STRUCTURED,
    };
    match serde_json::to_writer(io::stdout().lock(), &output) {
        Ok(()) => ExitCode::from(exit),
        Err(e) => {
            eprintln!("hippius-ticket-validator: stdout write failed: {e}");
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

/// Read the signed body from stdin under the size cap. `Err` carries the
/// process exit code for an IO failure (matches [`run`]'s handling).
fn read_capped_stdin() -> Result<Vec<u8>, ExitCode> {
    let mut body = Vec::new();
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut body)
    {
        eprintln!("hippius-ticket-validator: stdin read failed: {e}");
        return Err(ExitCode::from(EXIT_INTERNAL));
    }
    Ok(body)
}

fn run(args: VerifyTelemetryArgs, expected_domain: &str) -> ExitCode {
    let mut body = Vec::new();
    // `take(MAX + 1)` so an over-cap body is detected (read of
    // MAX+1) without ever buffering an unbounded stream.
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut body)
    {
        eprintln!("hippius-ticket-validator: stdin read failed: {e}");
        return ExitCode::from(EXIT_INTERNAL);
    }
    let output = match verify(&body, &args, expected_domain) {
        Ok(()) => Output::Ok,
        Err((category, error)) => Output::Err { error, category },
    };
    let exit = match &output {
        Output::Ok => EXIT_OK,
        Output::Err { .. } => EXIT_STRUCTURED,
    };
    match serde_json::to_writer(io::stdout().lock(), &output) {
        Ok(()) => ExitCode::from(exit),
        Err(e) => {
            eprintln!("hippius-ticket-validator: stdout write failed: {e}");
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

/// Core verification. Returns `(category, message)` on a structured
/// failure. Visible at module scope so the unit tests drive it
/// without spawning a child process.
fn verify(
    body: &[u8],
    args: &VerifyTelemetryArgs,
    expected_domain: &str,
) -> Result<(), (&'static str, String)> {
    if body.len() as u64 > MAX_BODY_BYTES {
        return Err((
            category::DECODE,
            format!("body exceeds {MAX_BODY_BYTES} bytes"),
        ));
    }
    if body.is_empty() {
        return Err((category::DECODE, "empty body".to_string()));
    }
    let vk = decode_vk(&args.vk_hex)?;
    let sig = decode_sig(&args.sig_hex)?;

    // Canonical-CBOR gate BEFORE the structural decode — a
    // non-canonical wrapper is rejected without trusting the decoder
    // with a malformed shape.
    assert_canonical(body).map_err(|e| (category::NON_CANONICAL, format!("body: {e}")))?;

    // Ed25519 over the exact body bytes — `verify_strict` rejects
    // non-canonical signature encodings + small-order keys.
    vk.verify_strict(body, &sig)
        .map_err(|_| (category::SIGNATURE, "ed25519 verify failed".to_string()))?;

    // The `domain` tag is the inner schema-version anchor + the
    // replay-context separator. An unknown / absent domain is
    // fail-closed.
    let domain = extract_domain(body)?;
    if domain != expected_domain {
        return Err((
            category::DOMAIN,
            format!(
                "domain mismatch: got {:?}, want {expected_domain:?}",
                truncate(&domain),
            ),
        ));
    }
    Ok(())
}

fn decode_vk(vk_hex: &str) -> Result<VerifyingKey, (&'static str, String)> {
    let bytes =
        hex::decode(vk_hex.trim()).map_err(|e| (category::DECODE, format!("vk_hex: {e}")))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        (
            category::DECODE,
            format!("vk must be 32 bytes (got {})", bytes.len()),
        )
    })?;
    VerifyingKey::from_bytes(&arr).map_err(|e| (category::DECODE, format!("vk parse: {e}")))
}

fn decode_sig(sig_hex: &str) -> Result<Signature, (&'static str, String)> {
    let bytes =
        hex::decode(sig_hex.trim()).map_err(|e| (category::DECODE, format!("sig_hex: {e}")))?;
    if bytes.len() != 64 {
        return Err((
            category::DECODE,
            format!("sig must be 64 bytes (got {})", bytes.len()),
        ));
    }
    Signature::from_slice(&bytes).map_err(|e| (category::DECODE, format!("sig parse: {e}")))
}

/// Decode the body's CBOR map and pull out the `domain` text field.
fn extract_domain(body: &[u8]) -> Result<String, (&'static str, String)> {
    let value: Value = ciborium::de::from_reader(body)
        .map_err(|e| (category::CBOR, format!("body decode: {e}")))?;
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err((category::CBOR, "body is not a CBOR map".to_string())),
    };
    for (key, val) in entries {
        if let Value::Text(name) = key {
            if name == "domain" {
                return match val {
                    Value::Text(domain) => Ok(domain),
                    _ => Err((
                        category::DOMAIN,
                        "domain field is not a text value".to_string(),
                    )),
                };
            }
        }
    }
    Err((category::DOMAIN, "body has no domain field".to_string()))
}

/// Decode a verified served-receipt body into its billing fields. The
/// signature + canonical form + domain were already checked by
/// [`verify`], so this is a pure structural extraction (a missing /
/// mistyped field is a `cbor` failure, fail-closed).
fn extract_receipt_fields(body: &[u8]) -> Result<ReceiptFields, (&'static str, String)> {
    let value: Value = ciborium::de::from_reader(body)
        .map_err(|e| (category::CBOR, format!("body decode: {e}")))?;
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err((category::CBOR, "body is not a CBOR map".to_string())),
    };

    let mut vm_id: Option<String> = None;
    let mut lease_id: Option<String> = None;
    let mut node_id: Option<Vec<u8>> = None;
    let mut resource_class: Option<String> = None;
    let mut epoch: Option<u64> = None;
    let mut period_start: Option<u64> = None;
    let mut period_end: Option<u64> = None;
    let mut monotonic_seq: Option<u64> = None;
    let mut degradation: Option<u64> = None;

    for (key, val) in entries {
        let name = match key {
            Value::Text(n) => n,
            _ => continue,
        };
        match name.as_str() {
            "vm_id" => vm_id = as_text(val),
            "lease_id" => lease_id = as_text(val),
            "resource_class" => resource_class = as_text(val),
            "node_id" => node_id = as_bytes(val),
            "epoch" => epoch = as_u64(val),
            "period_start" => period_start = as_u64(val),
            "period_end" => period_end = as_u64(val),
            "monotonic_seq" => monotonic_seq = as_u64(val),
            "observed_degradation_bps" => degradation = as_u64(val),
            _ => {}
        }
    }

    let period_start = require(period_start, "period_start")?;
    let period_end = require(period_end, "period_end")?;
    // The signer's `canonical()` already enforces this, but a hostile
    // producer that hand-rolls a body could not have passed the sig
    // check; still, fail closed rather than accrue a negative interval.
    if period_end < period_start {
        return Err((category::CBOR, "period_end < period_start".to_string()));
    }
    let degradation = require(degradation, "observed_degradation_bps")?;
    let degradation = u32::try_from(degradation).map_err(|_| {
        (
            category::CBOR,
            "observed_degradation_bps too large".to_string(),
        )
    })?;

    Ok(ReceiptFields {
        vm_id: require(vm_id, "vm_id")?,
        lease_id: require(lease_id, "lease_id")?,
        node_id_hex: hex::encode(require(node_id, "node_id")?),
        epoch: require(epoch, "epoch")?,
        resource_class: require(resource_class, "resource_class")?,
        period_start,
        period_end,
        monotonic_seq: require(monotonic_seq, "monotonic_seq")?,
        observed_degradation_bps: degradation,
    })
}

fn as_text(v: Value) -> Option<String> {
    match v {
        Value::Text(s) => Some(s),
        _ => None,
    }
}

fn as_bytes(v: Value) -> Option<Vec<u8>> {
    match v {
        Value::Bytes(b) => Some(b),
        _ => None,
    }
}

fn as_u64(v: Value) -> Option<u64> {
    match v {
        Value::Integer(i) => u64::try_from(i).ok(),
        _ => None,
    }
}

fn require<T>(opt: Option<T>, field: &str) -> Result<T, (&'static str, String)> {
    opt.ok_or_else(|| (category::CBOR, format!("missing/invalid {field}")))
}

/// Cap an envelope-supplied string before it lands in an error line.
/// The `domain` is attacker-influenced UTF-8 text — truncate on a
/// char boundary so a multibyte sequence straddling the limit cannot
/// panic the slice (which would surface as exit `1` → 503, evading a
/// poison strike).
fn truncate(s: &str) -> &str {
    const LIMIT: usize = 64;
    if s.len() <= LIMIT {
        return s;
    }
    let mut end = LIMIT;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hippius_types::cbor::to_canonical_vec;

    /// Build a canonical-CBOR body — a map with the given `domain`.
    fn body_with_domain(domain: &str) -> Vec<u8> {
        let value = Value::Map(vec![
            (Value::Text("counter".into()), Value::Integer(7.into())),
            (Value::Text("domain".into()), Value::Text(domain.into())),
        ]);
        to_canonical_vec(&value).unwrap()
    }

    fn args(vk: &VerifyingKey, sig: &Signature) -> VerifyTelemetryArgs {
        VerifyTelemetryArgs {
            vk_hex: hex::encode(vk.to_bytes()),
            sig_hex: hex::encode(sig.to_bytes()),
        }
    }

    #[test]
    fn happy_path_verifies() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let body = body_with_domain(EDGE_TELEMETRY_DOMAIN);
        let sig = sk.sign(&body);
        verify(
            &body,
            &args(&sk.verifying_key(), &sig),
            EDGE_TELEMETRY_DOMAIN,
        )
        .unwrap();
    }

    #[test]
    fn served_receipt_domain_verifies() {
        let sk = SigningKey::from_bytes(&[12u8; 32]);
        let body = body_with_domain(RECEIPT_DOMAIN);
        let sig = sk.sign(&body);
        verify(&body, &args(&sk.verifying_key(), &sig), RECEIPT_DOMAIN).unwrap();
    }

    #[test]
    fn served_receipt_extracts_billing_fields() {
        use hippius_types::served_receipt::ServedDeliveryReceipt;
        let sk = SigningKey::from_bytes(&[13u8; 32]);
        let nonce = [7u8; 32];
        let receipt = ServedDeliveryReceipt {
            validator_id: b"val-1",
            validator_nonce: &nonce,
            epoch: 42,
            vm_id: "vm-abc",
            lease_id: "lease-9",
            family_id: b"fam",
            node_id: &[0xab; 32],
            resource_class: "small",
            monotonic_seq: 5,
            observed_degradation_bps: 250,
            period_start: 1000,
            period_end: 1060,
            expiry: 2000,
        };
        let body = receipt.canonical().unwrap();
        let sig = sk.sign(&body);
        // The signature + domain verify …
        verify(&body, &args(&sk.verifying_key(), &sig), RECEIPT_DOMAIN).unwrap();
        // … and the billing fields extract byte-for-byte.
        let f = extract_receipt_fields(&body).unwrap();
        assert_eq!(f.vm_id, "vm-abc");
        assert_eq!(f.lease_id, "lease-9");
        assert_eq!(f.node_id_hex, hex::encode([0xab; 32]));
        assert_eq!(f.epoch, 42);
        assert_eq!(f.resource_class, "small");
        assert_eq!(f.period_start, 1000);
        assert_eq!(f.period_end, 1060);
        assert_eq!(f.monotonic_seq, 5);
        assert_eq!(f.observed_degradation_bps, 250);
    }

    #[test]
    fn extract_receipt_fields_rejects_a_non_receipt_body() {
        // A well-formed edge-telemetry body (counter + domain only) has
        // none of the receipt fields → fail-closed cbor error.
        let body = body_with_domain(RECEIPT_DOMAIN);
        let (cat, _) = extract_receipt_fields(&body).unwrap_err();
        assert_eq!(cat, category::CBOR);
    }

    #[test]
    fn wrong_signing_key_is_signature_failure() {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let pretender = SigningKey::from_bytes(&[2u8; 32]);
        let body = body_with_domain(EDGE_TELEMETRY_DOMAIN);
        let sig = signer.sign(&body);
        let (cat, _) = verify(
            &body,
            &args(&pretender.verifying_key(), &sig),
            EDGE_TELEMETRY_DOMAIN,
        )
        .unwrap_err();
        assert_eq!(cat, category::SIGNATURE);
    }

    #[test]
    fn tampered_body_is_rejected() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let body = body_with_domain(EDGE_TELEMETRY_DOMAIN);
        let sig = sk.sign(&body);
        let mut tampered = body.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        let (cat, _) = verify(
            &tampered,
            &args(&sk.verifying_key(), &sig),
            EDGE_TELEMETRY_DOMAIN,
        )
        .unwrap_err();
        // A flipped byte breaks either the canonical form or the sig.
        assert!(cat == category::SIGNATURE || cat == category::NON_CANONICAL);
    }

    #[test]
    fn wrong_domain_is_rejected() {
        let sk = SigningKey::from_bytes(&[4u8; 32]);
        // A validly-signed receipt body fed to the edge-telemetry
        // verifier — the signature is fine, the domain is not.
        let body = body_with_domain(RECEIPT_DOMAIN);
        let sig = sk.sign(&body);
        let (cat, _) = verify(
            &body,
            &args(&sk.verifying_key(), &sig),
            EDGE_TELEMETRY_DOMAIN,
        )
        .unwrap_err();
        assert_eq!(cat, category::DOMAIN);
    }

    #[test]
    fn missing_domain_field_is_rejected() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let value = Value::Map(vec![(
            Value::Text("counter".into()),
            Value::Integer(1.into()),
        )]);
        let body = to_canonical_vec(&value).unwrap();
        let sig = sk.sign(&body);
        let (cat, _) = verify(
            &body,
            &args(&sk.verifying_key(), &sig),
            EDGE_TELEMETRY_DOMAIN,
        )
        .unwrap_err();
        assert_eq!(cat, category::DOMAIN);
    }

    #[test]
    fn non_canonical_body_is_rejected() {
        // A map with keys in non-canonical order — canonical CBOR
        // sorts map keys shortest-first, so `"a"` must precede
        // `"bb"`; emitting `bb` then `a` in insertion order fails
        // the canonical gate.
        let mut bytes = Vec::new();
        let value = Value::Map(vec![
            (Value::Text("bb".into()), Value::Integer(0.into())),
            (Value::Text("a".into()), Value::Integer(0.into())),
        ]);
        ciborium::ser::into_writer(&value, &mut bytes).unwrap();
        let sk = SigningKey::from_bytes(&[6u8; 32]);
        let sig = sk.sign(&bytes);
        let (cat, _) = verify(
            &bytes,
            &args(&sk.verifying_key(), &sig),
            EDGE_TELEMETRY_DOMAIN,
        )
        .unwrap_err();
        assert_eq!(cat, category::NON_CANONICAL);
    }

    #[test]
    fn empty_body_is_rejected() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let sig = sk.sign(b"");
        let (cat, _) =
            verify(b"", &args(&sk.verifying_key(), &sig), EDGE_TELEMETRY_DOMAIN).unwrap_err();
        assert_eq!(cat, category::DECODE);
    }

    #[test]
    fn over_cap_body_is_rejected() {
        let sk = SigningKey::from_bytes(&[8u8; 32]);
        let body = vec![0u8; (MAX_BODY_BYTES + 1) as usize];
        let sig = sk.sign(&body);
        let (cat, _) = verify(
            &body,
            &args(&sk.verifying_key(), &sig),
            EDGE_TELEMETRY_DOMAIN,
        )
        .unwrap_err();
        assert_eq!(cat, category::DECODE);
    }

    #[test]
    fn multibyte_wrong_domain_does_not_panic() {
        // A signed body whose `domain` is a long multibyte string
        // fed to the wrong verifier — the error line truncates the
        // attacker-supplied domain; truncation must not panic on a
        // char boundary straddling the 64-byte limit.
        let sk = SigningKey::from_bytes(&[10u8; 32]);
        let domain = "é".repeat(60); // 120 bytes — boundary at 64 splits a char.
        let body = body_with_domain(&domain);
        let sig = sk.sign(&body);
        let (cat, _) = verify(
            &body,
            &args(&sk.verifying_key(), &sig),
            EDGE_TELEMETRY_DOMAIN,
        )
        .unwrap_err();
        assert_eq!(cat, category::DOMAIN);
    }

    #[test]
    fn bad_hex_args_are_decode_failures() {
        let body = body_with_domain(EDGE_TELEMETRY_DOMAIN);
        let bad = VerifyTelemetryArgs {
            vk_hex: "not-hex".into(),
            sig_hex: "00".repeat(64),
        };
        assert_eq!(
            verify(&body, &bad, EDGE_TELEMETRY_DOMAIN).unwrap_err().0,
            category::DECODE,
        );
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let short_sig = VerifyTelemetryArgs {
            vk_hex: hex::encode(sk.verifying_key().to_bytes()),
            sig_hex: "abcd".into(),
        };
        assert_eq!(
            verify(&body, &short_sig, EDGE_TELEMETRY_DOMAIN)
                .unwrap_err()
                .0,
            category::DECODE,
        );
    }
}
