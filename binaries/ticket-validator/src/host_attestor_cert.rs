//! `verify-host-attestor-cert` subcommand — blackbox host-attestor L0
//! enrollment-cert decode + (optional) KBS-L0-signature verification
//! (blackbox host-attestor chantier PR-8). Data-bearing, mirroring
//! [`crate::host_beacon`]: vali's cert-ingest gate must read the
//! KBS-attested `chip_id` / `measurement` / `node_id` / `attestor_pubkey`
//! WITHOUT decoding CBOR in Python.
//!
//! ## The `--vk-hex` seam (KBS L0 trust anchor)
//!
//! The [`SignedHostAttestorCert`] is signed by the **KBS L0 key**. vali
//! does not universally hold that public key today (it relays other
//! L0-signed artifacts to tenants for offline re-verification rather than
//! verifying them itself). So `--vk-hex` is OPTIONAL:
//!
//! - PRESENT → the Ed25519 signature over the cert body is
//!   `verify_strict`-checked against it; the JSON carries
//!   `"verified":true`.
//! - ABSENT  → the cert is only structurally decoded + schema-validated
//!   (canonical CBOR, field lengths, non-empty `node_id`, non-zero
//!   `expiry`); the JSON carries `"verified":false`.
//!
//! The Django consumer maps `verified:true` → `HostAttestor` status
//! `attested` (subject to its own on-chain-active gate) and
//! `verified:false` → `pending`. This is the honest "KBS-L0-pubkey not
//! wired in vali" seam surfaced as data, never faked.
//!
//! ## Wire contract (the stable JSON the Django consumer parses)
//!
//! - stdin: the canonical-CBOR [`SignedHostAttestorCert`] envelope.
//! - `--vk-hex` (optional): 32-byte hex Ed25519 KBS L0 verifying key.
//! - stdout, one JSON object:
//!   - accept → `{"ok":true,"verified":<bool>,"body":{…}}`.
//!   - reject → `{"ok":false,"error_class":"<class>"}` (no body echoed).
//! - exit: `0` on any validation outcome; `2` on a malformed `--vk-hex`
//!   (stderr line, no JSON); `1` on a stdin/stdout IO failure.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use ed25519_dalek::{Signature, VerifyingKey};
use hippius_types::cbor::assert_canonical;
use hippius_types::host_attestor::{HostAttestorCert, SignedHostAttestorCert};
use serde::Serialize;

const EXIT_OK: u8 = 0;
const EXIT_INTERNAL: u8 = 1;
const EXIT_USAGE: u8 = 2;

/// Hard cap on the envelope read from stdin — an enrollment cert is small
/// (fixed byte fields + a 64-byte signature; ~350 bytes on the wire).
/// Matches the `_MAX_HOST_CERT_BYTES` cap the Django consumer enforces.
const MAX_REQUEST_BYTES: u64 = 4096;

/// Closed `error_class` vocabulary — `&'static str` only. Keep in sync
/// with the Django consumer (`HOST_ATTESTOR_CERT_ERROR_CLASSES`).
mod error_class {
    pub const BODY_TOO_LARGE: &str = "body_too_large";
    pub const NOT_CANONICAL_CBOR: &str = "not_canonical_cbor";
    pub const ENVELOPE_DECODE_FAILED: &str = "envelope_decode_failed";
    pub const SIGNATURE_INVALID: &str = "signature_invalid";
    pub const BODY_DECODE_FAILED: &str = "body_decode_failed";
}

#[derive(clap::Args)]
pub struct VerifyHostAttestorCertArgs {
    /// Optional 32-byte hex Ed25519 KBS L0 verifying key. When set, the
    /// cert signature is verified against it (`verified:true`); when
    /// omitted, the cert is decode-only (`verified:false`) — the KBS-L0-
    /// pubkey-not-wired seam.
    #[arg(long)]
    vk_hex: Option<String>,
}

/// The decoded body echoed on a successful validation. All byte fields
/// are hex so the JSON is ASCII-safe.
#[derive(Serialize, Debug)]
struct HostCertBody {
    schema_version: u16,
    node_id: String,
    chip_id_hex: String,
    attestor_pubkey_hex: String,
    measurement_hex: String,
    tcb: u64,
    nonce_hex: String,
    expiry_unix: u64,
}

/// `verify-host-attestor-cert` entry point.
pub fn run(args: VerifyHostAttestorCertArgs) -> ExitCode {
    let vk = match args.vk_hex.as_deref() {
        None => None,
        Some(hexed) => match parse_vk(hexed) {
            Ok(vk) => Some(vk),
            Err(message) => {
                eprintln!("hippius-ticket-validator: verify-host-attestor-cert: {message}");
                return ExitCode::from(EXIT_USAGE);
            }
        },
    };

    let mut buf = Vec::new();
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut buf)
    {
        eprintln!("hippius-ticket-validator: verify-host-attestor-cert: stdin read failed: {e}");
        return ExitCode::from(EXIT_INTERNAL);
    }

    emit(verify(&buf, vk.as_ref()))
}

fn emit(outcome: Result<(bool, HostCertBody), &'static str>) -> ExitCode {
    let json = match outcome {
        Ok((verified, body)) => {
            serde_json::json!({ "ok": true, "verified": verified, "body": body })
        }
        Err(class) => serde_json::json!({ "ok": false, "error_class": class }),
    };
    let mut stdout = io::stdout().lock();
    let written = serde_json::to_writer(&mut stdout, &json)
        .map_err(io::Error::from)
        .and_then(|()| stdout.flush());
    match written {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(e) => {
            eprintln!(
                "hippius-ticket-validator: verify-host-attestor-cert: stdout write failed: {e}"
            );
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

/// Core validation — returns `(verified, body)` on success (`verified`
/// echoes whether the KBS L0 signature was checked), or a closed-
/// vocabulary `error_class` on the first failing gate.
fn verify(buf: &[u8], vk: Option<&VerifyingKey>) -> Result<(bool, HostCertBody), &'static str> {
    if buf.len() as u64 > MAX_REQUEST_BYTES {
        return Err(error_class::BODY_TOO_LARGE);
    }
    if assert_canonical(buf).is_err() {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    let envelope =
        SignedHostAttestorCert::decode(buf).map_err(|_| error_class::ENVELOPE_DECODE_FAILED)?;
    // Strict-shape gate — re-encode + demand byte-equality.
    let recanonical = envelope
        .encode()
        .map_err(|_| error_class::SIGNATURE_INVALID)?;
    if recanonical.as_slice() != buf {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    let verified = match vk {
        Some(vk) => {
            let signature = Signature::from_bytes(&envelope.sig);
            vk.verify_strict(&envelope.body, &signature)
                .map_err(|_| error_class::SIGNATURE_INVALID)?;
            true
        }
        None => false,
    };
    // The typed decoder asserts canonical body, cert domain, known
    // schema_version, and `validate()` (non-empty node_id, non-zero
    // expiry). A failure of any is a body-decode reject.
    let cert =
        HostAttestorCert::decode(&envelope.body).map_err(|_| error_class::BODY_DECODE_FAILED)?;
    Ok((
        verified,
        HostCertBody {
            schema_version: cert.schema_version,
            node_id: cert.node_id,
            chip_id_hex: hex::encode(cert.chip_id),
            attestor_pubkey_hex: hex::encode(cert.attestor_pubkey),
            measurement_hex: hex::encode(cert.measurement),
            tcb: cert.tcb,
            nonce_hex: hex::encode(cert.nonce),
            expiry_unix: cert.expiry_unix,
        },
    ))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hippius_types::host_attestor::{CHIP_ID_LEN, DIGEST_LEN, MEASUREMENT_LEN, PUBKEY_LEN};

    fn kat_cert() -> HostAttestorCert {
        HostAttestorCert {
            schema_version: 1,
            node_id: "node-host-1".into(),
            chip_id: [0x33; CHIP_ID_LEN],
            attestor_pubkey: [0x22; PUBKEY_LEN],
            measurement: [0x44; MEASUREMENT_LEN],
            tcb: 0x0708_0000_0000_000B,
            nonce: [0x11; DIGEST_LEN],
            expiry_unix: 1_800_000_900,
        }
    }

    fn signed_envelope(body: Vec<u8>, sk: &SigningKey) -> Vec<u8> {
        let sig = sk.sign(&body);
        SignedHostAttestorCert {
            body,
            sig: sig.to_bytes(),
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn verified_path_when_vk_matches() {
        let sk = SigningKey::from_bytes(&[0x5Au8; 32]);
        let env = signed_envelope(kat_cert().canonical().unwrap(), &sk);
        let (verified, body) = verify(&env, Some(&sk.verifying_key())).unwrap();
        assert!(verified);
        assert_eq!(body.node_id, "node-host-1");
        assert_eq!(body.chip_id_hex, "33".repeat(CHIP_ID_LEN));
        assert_eq!(body.attestor_pubkey_hex, "22".repeat(PUBKEY_LEN));
        assert_eq!(body.measurement_hex, "44".repeat(MEASUREMENT_LEN));
        assert_eq!(body.tcb, 0x0708_0000_0000_000B);
        assert_eq!(body.expiry_unix, 1_800_000_900);
    }

    #[test]
    fn decode_only_when_vk_absent() {
        let sk = SigningKey::from_bytes(&[0x5Au8; 32]);
        let env = signed_envelope(kat_cert().canonical().unwrap(), &sk);
        let (verified, body) = verify(&env, None).unwrap();
        assert!(!verified);
        assert_eq!(body.node_id, "node-host-1");
    }

    #[test]
    fn wrong_vk_is_signature_invalid() {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let pretender = SigningKey::from_bytes(&[2u8; 32]);
        let env = signed_envelope(kat_cert().canonical().unwrap(), &signer);
        assert_eq!(
            verify(&env, Some(&pretender.verifying_key())).unwrap_err(),
            error_class::SIGNATURE_INVALID,
        );
    }

    #[test]
    fn tampered_body_with_vk_is_rejected() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let mut body = kat_cert().canonical().unwrap();
        let sig = sk.sign(&body);
        let last = body.len() - 1;
        body[last] ^= 0xff;
        let env = SignedHostAttestorCert {
            body,
            sig: sig.to_bytes(),
        }
        .encode()
        .unwrap();
        let class = verify(&env, Some(&sk.verifying_key())).unwrap_err();
        assert!(
            class == error_class::SIGNATURE_INVALID || class == error_class::NOT_CANONICAL_CBOR,
            "got {class}",
        );
    }

    #[test]
    fn garbage_is_rejected() {
        let class = verify(b"not-cbor", None).unwrap_err();
        assert!(
            class == error_class::NOT_CANONICAL_CBOR
                || class == error_class::ENVELOPE_DECODE_FAILED,
            "got {class}",
        );
    }

    #[test]
    fn parse_vk_rejects_malformed() {
        assert!(parse_vk("not-hex").is_err());
        assert!(parse_vk("abcd").is_err());
        assert!(parse_vk(&"00".repeat(32)).is_ok());
    }
}
