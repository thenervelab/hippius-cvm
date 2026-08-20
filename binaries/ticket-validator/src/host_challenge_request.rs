//! `verify-host-challenge-request` subcommand — blackbox host-attestor
//! nonce-challenge request decode (blackbox host-attestor chantier PR-10).
//!
//! vali's nonce authority mints a fresh single-use enrollment nonce bound
//! to `{node_id, signer_pubkey}`. The `node_id` comes from the Edge-stamped
//! mTLS peer identity (never the body); the `signer_pubkey` comes from this
//! guest-authored request. This subcommand decodes the hostile-origin
//! [`HostChallengeRequest`] CBOR WITHOUT decoding CBOR in Python, mirroring
//! [`crate::host_attestor_cert`].
//!
//! Decode-only — the request carries no signature (it is transported over
//! the miner's mTLS leg; vali binds the minted nonce to the surfaced pk).
//!
//! ## Wire contract (the stable JSON the Django consumer parses)
//!
//! - stdin: the canonical-CBOR [`HostChallengeRequest`] body.
//! - stdout, one JSON object:
//!   - accept → `{"ok":true,"body":{"schema_version":…,"signer_pubkey_hex":…}}`.
//!   - reject → `{"ok":false,"error_class":"<class>"}` (no body echoed).
//! - exit: `0` on any validation outcome; `1` on a stdin/stdout IO failure.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use hippius_types::cbor::assert_canonical;
use hippius_types::host_attestor_challenge::HostChallengeRequest;
use serde::Serialize;

const EXIT_OK: u8 = 0;
const EXIT_INTERNAL: u8 = 1;

/// Hard cap on the request read from stdin — a challenge request is tiny
/// (a 32-byte key + a version int; ~50 bytes). Matches the challenge
/// frame cap `hippius_types::host_attestor_challenge::MAX_CHALLENGE_FRAME_BYTES`.
const MAX_REQUEST_BYTES: u64 = 4096;

/// Closed `error_class` vocabulary — a subset of the shared host-attestor
/// vocabulary the Django consumer accepts (`HOST_ATTESTOR_ERROR_CLASSES`).
mod error_class {
    pub const BODY_TOO_LARGE: &str = "body_too_large";
    pub const NOT_CANONICAL_CBOR: &str = "not_canonical_cbor";
    pub const BODY_DECODE_FAILED: &str = "body_decode_failed";
}

/// The decoded body echoed on a successful validation.
#[derive(Serialize, Debug)]
struct ChallengeRequestBody {
    schema_version: u16,
    signer_pubkey_hex: String,
}

/// `verify-host-challenge-request` entry point.
pub fn run() -> ExitCode {
    let mut buf = Vec::new();
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut buf)
    {
        eprintln!(
            "hippius-ticket-validator: verify-host-challenge-request: stdin read failed: {e}"
        );
        return ExitCode::from(EXIT_INTERNAL);
    }
    emit(verify(&buf))
}

fn emit(outcome: Result<ChallengeRequestBody, &'static str>) -> ExitCode {
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
            eprintln!(
                "hippius-ticket-validator: verify-host-challenge-request: stdout write failed: {e}"
            );
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

/// Core validation — returns the decoded body on success, or a closed-
/// vocabulary `error_class` on the first failing gate.
fn verify(buf: &[u8]) -> Result<ChallengeRequestBody, &'static str> {
    if buf.len() as u64 > MAX_REQUEST_BYTES {
        return Err(error_class::BODY_TOO_LARGE);
    }
    if assert_canonical(buf).is_err() {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    // The typed decoder asserts canonical body, known schema_version, and
    // the fixed 32-byte `signer_pubkey` length. Any failure is a
    // body-decode reject.
    let req = HostChallengeRequest::decode(buf).map_err(|_| error_class::BODY_DECODE_FAILED)?;
    Ok(ChallengeRequestBody {
        schema_version: req.schema_version,
        signer_pubkey_hex: hex::encode(req.signer_pubkey),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hippius_types::host_attestor_challenge::PUBKEY_LEN;

    #[test]
    fn decodes_a_well_formed_request() {
        let body = HostChallengeRequest::new([0x22; PUBKEY_LEN])
            .canonical()
            .unwrap();
        let out = verify(&body).unwrap();
        assert_eq!(out.schema_version, 1);
        assert_eq!(out.signer_pubkey_hex, "22".repeat(PUBKEY_LEN));
    }

    #[test]
    fn garbage_is_rejected() {
        let class = verify(b"not-cbor").unwrap_err();
        assert!(
            class == error_class::NOT_CANONICAL_CBOR || class == error_class::BODY_DECODE_FAILED,
            "got {class}",
        );
    }

    #[test]
    fn oversize_is_rejected() {
        let class = verify(&vec![0u8; (MAX_REQUEST_BYTES + 1) as usize]).unwrap_err();
        assert_eq!(class, error_class::BODY_TOO_LARGE);
    }
}
