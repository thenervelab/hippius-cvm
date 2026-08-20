//! `verify-host-beacon` subcommand — blackbox host-attestor liveness
//! beacon signature + schema validation (blackbox host-attestor chantier
//! PR-8). Mirrors [`crate::vm_progress`] (data-bearing output): vali's
//! host-attestor ingest gate must enforce monotonic `seq` + expiry AND
//! read the attested `chip_id` / `measurement` / `node_id` WITHOUT
//! decoding CBOR in Python (the canonical wire format is single-sourced
//! in Rust), so a fully-valid beacon returns its decoded body fields for
//! the Django gate to act on.
//!
//! ## Wire contract (the stable JSON the Django consumer parses)
//!
//! - stdin: the canonical-CBOR [`SignedHostBeacon`] envelope.
//! - `--vk-hex`: the **certified** attestor Ed25519 verifying key — vali
//!   passes the `signer_pubkey` the KBS L0 enrollment cert pinned for
//!   this host (stored on the `HostAttestor` row), NEVER the beacon's own
//!   self-declared `signer_pubkey`.
//! - stdout, one JSON object:
//!   - accept → `{"ok":true,"body":{…}}` (chip_id_hex, measurement_hex,
//!     node_id, boot_id, seq, observed_at_unix, policy, nonce_hex,
//!     expiry_unix, signer_pubkey_hex, schema_version).
//!   - reject → `{"ok":false,"error_class":"<class>"}` (no body echoed).
//! - exit: `0` on any validation outcome; `2` on a malformed `--vk-hex`
//!   (stderr line, no JSON); `1` on a stdin/stdout IO failure.
//!
//! Gate order (fail-closed, identical to `verify-vm-progress`): size cap
//! → envelope canonical-CBOR → envelope decode → strict-shape re-encode
//! → Ed25519 `verify_strict` over `body` (against the certified key) →
//! body canonical-CBOR + schema/domain (enforced by the typed decoder).

use std::io::{self, Read, Write};
use std::process::ExitCode;

use ed25519_dalek::{Signature, VerifyingKey};
use hippius_types::cbor::assert_canonical;
use hippius_types::host_attestor::{HostAliveBeacon, SignedHostBeacon};
use serde::Serialize;

const EXIT_OK: u8 = 0;
const EXIT_INTERNAL: u8 = 1;
const EXIT_USAGE: u8 = 2;

/// Hard cap on the envelope read from stdin — a host beacon is small (a
/// handful of fixed byte fields + a 64-byte signature; ~600 bytes on the
/// wire). Rejected BEFORE any decode. Matches the
/// `_MAX_HOST_BEACON_BYTES` cap the Django consumer enforces.
const MAX_REQUEST_BYTES: u64 = 4096;

/// Closed `error_class` vocabulary — `&'static str` only, so no envelope
/// byte is ever interpolated into the output. Keep in sync with the
/// Django consumer (`HOST_BEACON_ERROR_CLASSES`).
mod error_class {
    pub const BODY_TOO_LARGE: &str = "body_too_large";
    pub const NOT_CANONICAL_CBOR: &str = "not_canonical_cbor";
    pub const ENVELOPE_DECODE_FAILED: &str = "envelope_decode_failed";
    pub const SIGNATURE_INVALID: &str = "signature_invalid";
    pub const BODY_DECODE_FAILED: &str = "body_decode_failed";
}

#[derive(clap::Args)]
pub struct VerifyHostBeaconArgs {
    /// 32-byte hex Ed25519 verifying key — the KBS-certified attestor
    /// `signer_pubkey` for this host. vali reads it from the stored
    /// `HostAttestor` row, NEVER from the (untrusted) beacon envelope.
    #[arg(long)]
    vk_hex: String,
}

/// The decoded body echoed on a successful validation. Constructed ONLY
/// after every gate passes, so `Serialize` can never echo an unverified
/// field. All byte fields are hex so the JSON is ASCII-safe.
#[derive(Serialize, Debug)]
struct HostBeaconBody {
    schema_version: u16,
    chip_id_hex: String,
    measurement_hex: String,
    node_id: String,
    boot_id: String,
    seq: u64,
    observed_at_unix: u64,
    policy: u64,
    nonce_hex: String,
    signer_pubkey_hex: String,
    expiry_unix: u64,
}

/// `verify-host-beacon` entry point.
pub fn run(args: VerifyHostBeaconArgs) -> ExitCode {
    let vk = match parse_vk(&args.vk_hex) {
        Ok(vk) => vk,
        Err(message) => {
            eprintln!("hippius-ticket-validator: verify-host-beacon: {message}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let mut buf = Vec::new();
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut buf)
    {
        eprintln!("hippius-ticket-validator: verify-host-beacon: stdin read failed: {e}");
        return ExitCode::from(EXIT_INTERNAL);
    }

    emit(verify(&buf, &vk))
}

fn emit(outcome: Result<HostBeaconBody, &'static str>) -> ExitCode {
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
            eprintln!("hippius-ticket-validator: verify-host-beacon: stdout write failed: {e}");
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

/// Core validation — returns the decoded body on full success, or a
/// closed-vocabulary `error_class` on the first failing gate. Module-
/// scoped so the unit tests drive it without a child process.
fn verify(buf: &[u8], vk: &VerifyingKey) -> Result<HostBeaconBody, &'static str> {
    if buf.len() as u64 > MAX_REQUEST_BYTES {
        return Err(error_class::BODY_TOO_LARGE);
    }
    if assert_canonical(buf).is_err() {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    let envelope =
        SignedHostBeacon::decode(buf).map_err(|_| error_class::ENVELOPE_DECODE_FAILED)?;
    // Strict-shape gate — re-encode the typed envelope and demand
    // byte-equality (there is exactly ONE valid wire encoding).
    let recanonical = envelope
        .encode()
        .map_err(|_| error_class::SIGNATURE_INVALID)?;
    if recanonical.as_slice() != buf {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    let signature = Signature::from_bytes(&envelope.sig);
    // Verify against the CERTIFIED key vali supplied — a beacon signed by
    // any other key (incl. the beacon's own self-declared signer_pubkey)
    // fails closed here.
    vk.verify_strict(&envelope.body, &signature)
        .map_err(|_| error_class::SIGNATURE_INVALID)?;
    // The typed decoder asserts the body is canonical CBOR, carries the
    // beacon domain, the known schema_version, and passes `validate()`
    // (seq > 0, expiry strictly after observed_at, …). Any of those
    // failing is a body-decode reject.
    let beacon =
        HostAliveBeacon::decode(&envelope.body).map_err(|_| error_class::BODY_DECODE_FAILED)?;
    Ok(HostBeaconBody {
        schema_version: beacon.schema_version,
        chip_id_hex: hex::encode(beacon.chip_id),
        measurement_hex: hex::encode(beacon.measurement),
        node_id: beacon.node_id,
        boot_id: beacon.boot_id,
        seq: beacon.seq,
        observed_at_unix: beacon.observed_at_unix,
        policy: beacon.policy,
        nonce_hex: hex::encode(beacon.nonce),
        signer_pubkey_hex: hex::encode(beacon.signer_pubkey),
        expiry_unix: beacon.expiry_unix,
    })
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
    use hippius_types::host_attestor::{
        PlatformTcb, CHIP_ID_LEN, DIGEST_LEN, MEASUREMENT_LEN, PUBKEY_LEN, SIGNATURE_LEN,
    };

    fn kat_beacon(signer_pk: [u8; PUBKEY_LEN]) -> HostAliveBeacon {
        HostAliveBeacon {
            schema_version: 1,
            chain_genesis: [0xAA; DIGEST_LEN],
            pallet_instance: [0xDD; DIGEST_LEN],
            chip_id: [0x33; CHIP_ID_LEN],
            measurement: [0x44; MEASUREMENT_LEN],
            node_id: "node-host-1".into(),
            boot_id: "boot-abc".into(),
            seq: 7,
            observed_at_unix: 1_800_000_000,
            platform_tcb: PlatformTcb {
                reported: 0x0708_0000_0000_000B,
                committed: 0x0708_0000_0000_000A,
                current: 0x0708_0000_0000_000B,
            },
            policy: 0x30000,
            nonce: [0x11; DIGEST_LEN],
            signer_pubkey: signer_pk,
            expiry_unix: 1_800_000_900,
        }
    }

    fn signed_envelope(body: Vec<u8>, sk: &SigningKey) -> Vec<u8> {
        let sig = sk.sign(&body);
        SignedHostBeacon {
            body,
            sig: sig.to_bytes(),
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn happy_path_returns_the_decoded_body() {
        let sk = SigningKey::from_bytes(&[0x3Bu8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let env = signed_envelope(kat_beacon(pk).canonical().unwrap(), &sk);
        let body = verify(&env, &sk.verifying_key()).unwrap();
        assert_eq!(body.schema_version, 1);
        assert_eq!(body.node_id, "node-host-1");
        assert_eq!(body.boot_id, "boot-abc");
        assert_eq!(body.seq, 7);
        assert_eq!(body.chip_id_hex, "33".repeat(CHIP_ID_LEN));
        assert_eq!(body.measurement_hex, "44".repeat(MEASUREMENT_LEN));
        assert_eq!(body.signer_pubkey_hex, hex::encode(pk));
        assert_eq!(body.expiry_unix, 1_800_000_900);
    }

    #[test]
    fn wrong_key_is_signature_invalid() {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let pretender = SigningKey::from_bytes(&[2u8; 32]);
        let env = signed_envelope(
            kat_beacon(signer.verifying_key().to_bytes())
                .canonical()
                .unwrap(),
            &signer,
        );
        assert_eq!(
            verify(&env, &pretender.verifying_key()).unwrap_err(),
            error_class::SIGNATURE_INVALID,
        );
    }

    #[test]
    fn tampered_body_is_rejected() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let mut body = kat_beacon(sk.verifying_key().to_bytes())
            .canonical()
            .unwrap();
        let sig = sk.sign(&body);
        let last = body.len() - 1;
        body[last] ^= 0xff;
        let env = SignedHostBeacon {
            body,
            sig: sig.to_bytes(),
        }
        .encode()
        .unwrap();
        let class = verify(&env, &sk.verifying_key()).unwrap_err();
        assert!(
            class == error_class::SIGNATURE_INVALID || class == error_class::NOT_CANONICAL_CBOR,
            "got {class}",
        );
    }

    #[test]
    fn over_cap_envelope_is_body_too_large() {
        let sk = SigningKey::from_bytes(&[10u8; 32]);
        let env = SignedHostBeacon {
            body: vec![0u8; 5000],
            sig: [0u8; SIGNATURE_LEN],
        }
        .encode()
        .unwrap();
        assert!(env.len() as u64 > MAX_REQUEST_BYTES);
        assert_eq!(
            verify(&env, &sk.verifying_key()).unwrap_err(),
            error_class::BODY_TOO_LARGE,
        );
    }

    #[test]
    fn garbage_is_rejected() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let class = verify(b"not-cbor", &sk.verifying_key()).unwrap_err();
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
