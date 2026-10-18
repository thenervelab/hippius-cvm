//! `verify-host-inventory` subcommand — the miner host inventory (§18.10)
//! signature + schema validation. Data-bearing like [`crate::graceful_exit`]:
//! vali enforces the `±300 s` skew, the monotonic `sequence` and the
//! per-section merge WITHOUT decoding CBOR in Python, so a fully-valid
//! report returns its whole decoded body.
//!
//! ## Wire contract (the stable JSON the Django consumer parses)
//!
//! - stdin: the canonical-CBOR [`SignedHostInventory`] envelope.
//! - `--vk-hex`: the miner's 32-byte Ed25519 verifying key — vali resolves
//!   it from the registered miner identity, NEVER from the envelope.
//! - stdout, one JSON object:
//!   - accept → `{"ok":true,"body":<HostInventory as JSON>,
//!     "section_digests":{"<section>":"<sha256 hex>",…}}` — one digest per
//!     section the report carries: SHA-256 of that section's canonical
//!     CBOR, so "did this section change" has one definition;
//!   - reject → `{"ok":false,"error_class":"<class>","detail":"<reason>"}`
//!     — `detail` is the crate's closed `host-inventory-*` vocabulary, no
//!     envelope byte is echoed.
//! - exit: `0` on any validation outcome; `2` on a malformed `--vk-hex`
//!   (stderr line, no JSON); `1` on a stdin/stdout IO failure.
//!
//! Gate order (fail-closed): size cap → envelope (canonical, typed,
//! re-encoded byte for byte) → Ed25519 `verify_strict` over `body` → body
//! (canonical, typed, every bound, re-encoded byte for byte).

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use ciborium::value::Value;
use ed25519_dalek::{Signature, VerifyingKey};
use hippius_host_inventory::{
    HostInventory, SignedHostInventory, MAX_ENVELOPE_BYTES, SIGNATURE_LEN,
};
use hippius_types::cbor::to_canonical_vec;
use serde::Serialize;
use sha2::{Digest, Sha256};

const EXIT_OK: u8 = 0;
const EXIT_INTERNAL: u8 = 1;
const EXIT_USAGE: u8 = 2;

/// Closed `error_class` vocabulary — keep in sync with
/// `HOST_INVENTORY_ERROR_CLASSES` in `vali/apps/telemetry/verifier.py`.
mod error_class {
    pub const BODY_TOO_LARGE: &str = "body_too_large";
    pub const NOT_CANONICAL_CBOR: &str = "not_canonical_cbor";
    pub const ENVELOPE_DECODE_FAILED: &str = "envelope_decode_failed";
    pub const SIGNATURE_INVALID: &str = "signature_invalid";
    pub const BODY_DECODE_FAILED: &str = "body_decode_failed";
    pub const WRONG_SCHEMA_VERSION: &str = "wrong_schema_version";
    pub const WRONG_DOMAIN: &str = "wrong_domain";
    pub const MINER_ID_INVALID: &str = "miner_id_invalid";
    /// Decoded, but a bound, charset, order or completeness rule failed.
    pub const BODY_INVALID: &str = "body_invalid";
    /// The verifier itself failed (re-encoding an accepted section): not
    /// the miner's fault, vali answers 503.
    pub const INTERNAL: &str = "internal";
}

#[derive(clap::Args)]
pub struct VerifyHostInventoryArgs {
    /// 32-byte hex Ed25519 verifying key of the miner. vali resolves it
    /// from the registered identity — NEVER from the envelope.
    #[arg(long)]
    vk_hex: String,
}

/// A refusal: the class vali acts on and the crate's reason.
#[derive(Debug, PartialEq, Eq)]
struct Reject {
    class: &'static str,
    detail: &'static str,
}

/// Built ONLY after every gate passes.
#[derive(Serialize, Debug)]
struct Accepted {
    body: HostInventory,
    section_digests: BTreeMap<&'static str, String>,
}

/// `verify-host-inventory` entry point.
pub fn run(args: VerifyHostInventoryArgs) -> ExitCode {
    let vk = match parse_vk(&args.vk_hex) {
        Ok(vk) => vk,
        Err(message) => {
            eprintln!("hippius-ticket-validator: verify-host-inventory: {message}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let mut buf = Vec::new();
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_ENVELOPE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
    {
        eprintln!("hippius-ticket-validator: verify-host-inventory: stdin read failed: {e}");
        return ExitCode::from(EXIT_INTERNAL);
    }
    emit(verify(&buf, &vk))
}

fn emit(outcome: Result<Accepted, Reject>) -> ExitCode {
    let json = match outcome {
        Ok(a) => serde_json::json!({
            "ok": true,
            "body": a.body,
            "section_digests": a.section_digests,
        }),
        Err(r) => serde_json::json!({ "ok": false, "error_class": r.class, "detail": r.detail }),
    };
    let mut stdout = io::stdout().lock();
    let written = serde_json::to_writer(&mut stdout, &json)
        .map_err(io::Error::from)
        .and_then(|()| stdout.flush());
    match written {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(e) => {
            eprintln!("hippius-ticket-validator: verify-host-inventory: stdout write failed: {e}");
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

/// The class vali acts on for a crate reason.
fn class_of(detail: &'static str) -> &'static str {
    match detail {
        "host-inventory-too-large" => error_class::BODY_TOO_LARGE,
        "host-inventory-not-canonical" => error_class::NOT_CANONICAL_CBOR,
        "host-inventory-envelope-decode" => error_class::ENVELOPE_DECODE_FAILED,
        "host-inventory-signature-length" => error_class::SIGNATURE_INVALID,
        "host-inventory-body-decode" => error_class::BODY_DECODE_FAILED,
        "host-inventory-schema-version" => error_class::WRONG_SCHEMA_VERSION,
        "host-inventory-domain" => error_class::WRONG_DOMAIN,
        "host-inventory-miner-id" => error_class::MINER_ID_INVALID,
        _ => error_class::BODY_INVALID,
    }
}

fn reject(detail: &'static str) -> Reject {
    Reject {
        class: class_of(detail),
        detail,
    }
}

/// Core validation — module-scoped so the unit tests drive it without a
/// child process.
fn verify(buf: &[u8], vk: &VerifyingKey) -> Result<Accepted, Reject> {
    if buf.len() > MAX_ENVELOPE_BYTES {
        return Err(reject("host-inventory-too-large"));
    }
    let envelope = SignedHostInventory::decode(buf).map_err(reject)?;
    let sig_bytes: [u8; SIGNATURE_LEN] = envelope
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| reject("host-inventory-signature-length"))?;
    vk.verify_strict(&envelope.body, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| Reject {
            class: error_class::SIGNATURE_INVALID,
            detail: "host-inventory-signature",
        })?;
    let body = HostInventory::decode(&envelope.body).map_err(reject)?;
    let section_digests = section_digests(&body)?;
    Ok(Accepted {
        body,
        section_digests,
    })
}

/// SHA-256 of each present section's canonical CBOR.
fn section_digests(body: &HostInventory) -> Result<BTreeMap<&'static str, String>, Reject> {
    let s = &body.sections;
    let digests = [
        ("system", digest(&s.system)?),
        ("cpu", digest(&s.cpu)?),
        ("memory", digest(&s.memory)?),
        ("storage", digest(&s.storage)?),
        ("network", digest(&s.network)?),
        ("pci", digest(&s.pci)?),
        ("sensors", digest(&s.sensors)?),
        ("software", digest(&s.software)?),
    ];
    Ok(digests
        .into_iter()
        .filter_map(|(name, d)| d.map(|d| (name, d)))
        .collect())
}

fn digest<T: Serialize>(section: &Option<T>) -> Result<Option<String>, Reject> {
    let Some(section) = section else {
        return Ok(None);
    };
    let bytes = Value::serialized(section)
        .ok()
        .and_then(|v| to_canonical_vec(&v).ok())
        .ok_or(Reject {
            class: error_class::INTERNAL,
            detail: "host-inventory-encode",
        })?;
    Ok(Some(hex::encode(Sha256::digest(bytes))))
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
    use std::path::PathBuf;

    fn vector(name: &str) -> Vec<u8> {
        std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../test_vectors/host_inventory")
                .join(name),
        )
        .unwrap()
    }

    fn kat_vk() -> VerifyingKey {
        let hex = String::from_utf8(vector("kat_vk.hex")).unwrap();
        parse_vk(&hex).unwrap()
    }

    fn envelope(body: Vec<u8>, sig: Vec<u8>) -> Vec<u8> {
        SignedHostInventory { body, sig }.canonical().unwrap()
    }

    #[test]
    fn the_frozen_vectors_verify_and_echo_their_body() {
        for (env, body, sections) in [
            (
                "signed_host_inventory_full.cbor",
                "host_inventory_body_full.cbor",
                8,
            ),
            (
                "signed_host_inventory_counters.cbor",
                "host_inventory_body_counters.cbor",
                4,
            ),
        ] {
            let a = verify(&vector(env), &kat_vk()).unwrap();
            assert_eq!(a.body, HostInventory::decode(&vector(body)).unwrap());
            assert_eq!(a.section_digests.len(), sections, "{env}");
            assert!(a.section_digests.values().all(|d| d.len() == 64));
        }
    }

    #[test]
    fn a_section_digest_is_the_sha256_of_its_canonical_cbor() {
        let a = verify(&vector("signed_host_inventory_full.cbor"), &kat_vk()).unwrap();
        let cpu = Value::serialized(a.body.sections.cpu.as_ref().unwrap()).unwrap();
        let want = hex::encode(Sha256::digest(to_canonical_vec(&cpu).unwrap()));
        assert_eq!(a.section_digests["cpu"], want);
        // The full and counters reports share their sensors section.
        let c = verify(&vector("signed_host_inventory_counters.cbor"), &kat_vk()).unwrap();
        assert_eq!(
            a.body.sections.sensors == c.body.sections.sensors,
            a.section_digests["sensors"] == c.section_digests["sensors"],
        );
    }

    #[test]
    fn another_key_is_signature_invalid() {
        let other = VerifyingKey::from_bytes(
            &ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let r = verify(&vector("signed_host_inventory_full.cbor"), &other).unwrap_err();
        assert_eq!(r.class, error_class::SIGNATURE_INVALID);
    }

    #[test]
    fn a_tampered_body_is_refused() {
        let env = SignedHostInventory::decode(&vector("signed_host_inventory_full.cbor")).unwrap();
        let mut body = env.body.clone();
        let last = body.len() - 1;
        body[last] ^= 0x01;
        let r = verify(&envelope(body, env.sig), &kat_vk()).unwrap_err();
        assert_eq!(r.class, error_class::SIGNATURE_INVALID);
    }

    #[test]
    fn rejects_are_classed_from_the_crate_reason() {
        assert_eq!(
            verify(&vec![0u8; MAX_ENVELOPE_BYTES + 1], &kat_vk())
                .unwrap_err()
                .class,
            error_class::BODY_TOO_LARGE
        );
        assert_eq!(
            verify(&[0xa0], &kat_vk()).unwrap_err().class,
            error_class::ENVELOPE_DECODE_FAILED
        );
        assert_eq!(
            verify(b"\xff\xff", &kat_vk()).unwrap_err().class,
            error_class::NOT_CANONICAL_CBOR
        );
        assert_eq!(class_of("host-inventory-domain"), error_class::WRONG_DOMAIN);
        assert_eq!(
            class_of("host-inventory-schema-version"),
            error_class::WRONG_SCHEMA_VERSION
        );
        assert_eq!(class_of("host-inventory-device"), error_class::BODY_INVALID);
    }

    #[test]
    fn a_signed_body_breaking_a_rule_is_body_invalid() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let sign = |body: Vec<u8>| {
            let sig = sk.sign(&body).to_bytes().to_vec();
            verify(&envelope(body, sig), &sk.verifying_key()).unwrap_err()
        };
        // `{}` is canonical CBOR but no HostInventory.
        assert_eq!(sign(vec![0xa0]).class, error_class::BODY_DECODE_FAILED);
        // A `full` report missing a section: well-formed, but invalid.
        let mut full = HostInventory::decode(&vector("host_inventory_body_full.cbor")).unwrap();
        full.sections.sensors = None;
        let bytes = to_canonical_vec(&Value::serialized(&full).unwrap()).unwrap();
        let r = sign(bytes);
        assert_eq!(r.class, error_class::BODY_INVALID);
        assert_eq!(r.detail, "host-inventory-full-incomplete");
    }
}
