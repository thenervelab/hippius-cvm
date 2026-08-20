//! Signed telemetry wire types (PR-H6, §9 / §15).
//!
//! ## Why these live here, not in `hippius-types`
//!
//! `hippius-types` is the SHARED schema crate — every `SignedX` type
//! there is consumed by the guest, the KBS, AND the Validator. The
//! Edge telemetry envelope is consumed by exactly two parties
//! (Sentinel + the Validator, both of which already trust the Edge
//! pubkey), and putting it in the shared crate would pollute that
//! schema with an Edge-internal concern. So it is **local to the Edge
//! crate** — same reasoning as `stages::wire::KbsReleaseRequest`.
//!
//! ## Opacity (§5.6) — what is NOT in the envelope
//!
//! The envelope carries **counters + routing metadata only** — peer
//! identity, direction, kind, byte *counts*, a shed flag. It NEVER
//! carries body bytes, decoded inner fields, or anything derived from
//! the relayed payload. Edge is an opaque relay; its telemetry
//! describes the *shape* of traffic, never its content. The type has
//! no field that could hold a payload, so a future change that tried
//! to log inner bytes would have to add one — a visible diff.
//!
//! ## Signing
//!
//! [`EdgeTelemetryEnvelope::to_canonical`] produces deterministic
//! CBOR (RFC 8949 §4.2.1, via `hippius_types::cbor`). The Edge signs
//! that byte string with its boot-generated Ed25519 key
//! ([`crate::signer::EdgeSigner`]); the pair travels as
//! [`SignedEdgeTelemetry`]. A `domain` tag inside the signed body
//! separates this signature context from every other signed payload
//! in the stack (same discipline as `RELEASE_DOMAIN` / the
//! `kbs-core` audit domain).

use crate::pipeline::{Direction, MessageKind};
use ciborium::value::Value;
use ed25519_dalek::{Signature, VerifyingKey};
use hippius_types::cbor::{assert_canonical, to_canonical_vec};
use serde::{Deserialize, Serialize};

/// Domain tag bound into every signed telemetry body. Replay-context
/// separation: an Edge telemetry signature cannot be reinterpreted as
/// any other signed payload, and vice versa.
pub const TELEMETRY_DOMAIN: &str = "HIPPIUS_EDGE_TELEMETRY_V1";

/// One relay transaction, as observed by the Edge.
///
/// Built by [`crate::telemetry::TelemetryRecorder`] once per
/// [`crate::relay_once`] call. Every field is a counter or a routing
/// tag — see the module docs on opacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeTelemetryEnvelope {
    /// Always [`TELEMETRY_DOMAIN`] — signature-context separation.
    pub domain: String,
    /// Unix seconds the Edge observed the transaction.
    pub timestamp: u64,
    /// Monotonic per-instance counter. Sourced from the audit log
    /// sequence number, so it is strictly increasing in log order and
    /// continues (does not reset) across a process restart on the
    /// same instance.
    pub counter: u64,
    /// mTLS-derived peer identity (PR-H4) — the SAN URI / DNS / CN the
    /// connecting peer's leaf cert presented. NOT read from the wire
    /// body (§5.6).
    pub peer_id: String,
    /// Diode direction of the transaction.
    pub direction: Direction,
    /// Declared wire kind of the transaction.
    pub message_kind: MessageKind,
    /// Bytes received from the source for this transaction.
    pub bytes_in: u64,
    /// Bytes that egress across the diode. For an opaque relay this
    /// equals `bytes_in` when the transaction is relayed (the body is
    /// passed through verbatim) and `0` when it is shed.
    pub bytes_out: u64,
    /// Whether the transaction was dropped (rate-limited, queue-full,
    /// schema-invalid, …) rather than relayed.
    pub shed: bool,
    /// Static classifier for the shed, when `shed` is true; `None`
    /// for a relayed transaction. Drawn from the closed `EdgeError`
    /// classifier vocabulary — never caller-built text.
    pub shed_reason: Option<String>,
}

impl EdgeTelemetryEnvelope {
    /// Encode to canonical (deterministic) CBOR — the exact byte
    /// string the Edge signs and Sentinel / the Validator verify.
    pub fn to_canonical(&self) -> Result<Vec<u8>, TelemetryWireError> {
        let value = Value::serialized(self).map_err(|_| TelemetryWireError::Encode)?;
        to_canonical_vec(&value).map_err(|_| TelemetryWireError::Encode)
    }

    /// Decode from a canonical-CBOR body. Enforces canonical encoding
    /// AND `deny_unknown_fields` — a non-canonical or extra-field body
    /// is rejected.
    pub fn from_canonical(body: &[u8]) -> Result<Self, TelemetryWireError> {
        assert_canonical(body).map_err(|_| TelemetryWireError::NonCanonical)?;
        ciborium::de::from_reader(body).map_err(|_| TelemetryWireError::Decode)
    }
}

/// An [`EdgeTelemetryEnvelope`] plus the Edge's detached Ed25519
/// signature over its canonical body. Mirrors the `{body, sig}` shape
/// of the `hippius-types` `SignedX` wrappers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEdgeTelemetry {
    /// Canonical-CBOR [`EdgeTelemetryEnvelope`]. Opaque bytes from the
    /// signature's perspective — verifiers re-decode it.
    pub body: Vec<u8>,
    /// Ed25519 signature (64 bytes) over `body`.
    pub sig: Vec<u8>,
}

/// Stable static-classifier errors for the telemetry wire layer. Same
/// `&'static str`-only `Display` discipline as `EdgeError`.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryWireError {
    /// Canonical-CBOR encoding of an envelope failed.
    #[error("telemetry-encode")]
    Encode,
    /// A telemetry body did not decode as a well-formed envelope.
    #[error("telemetry-decode")]
    Decode,
    /// A telemetry body was not canonical CBOR.
    #[error("telemetry-non-canonical")]
    NonCanonical,
    /// The Ed25519 signature was malformed or did not verify.
    #[error("telemetry-sig")]
    Sig,
    /// The decoded body carried the wrong (or no) domain tag.
    #[error("telemetry-domain")]
    Domain,
}

impl TelemetryWireError {
    /// Static classifier for the audit / diagnostic sink.
    pub fn class(&self) -> &'static str {
        match self {
            TelemetryWireError::Encode => "telemetry-encode",
            TelemetryWireError::Decode => "telemetry-decode",
            TelemetryWireError::NonCanonical => "telemetry-non-canonical",
            TelemetryWireError::Sig => "telemetry-sig",
            TelemetryWireError::Domain => "telemetry-domain",
        }
    }
}

/// Verify a [`SignedEdgeTelemetry`] against the Edge's public key and
/// return the decoded envelope.
///
/// This is the operation Sentinel and the Validator run after fetching
/// the Edge pubkey from `/v1/edge/pubkey`. It is exercised by the
/// PR-H6 integration test. Checks, in order: the body is canonical
/// CBOR, the signature is well-formed and verifies (`verify_strict`),
/// the body decodes as an envelope, and the domain tag is correct.
pub fn verify_signed_telemetry(
    verifying_key: &VerifyingKey,
    signed: &SignedEdgeTelemetry,
) -> Result<EdgeTelemetryEnvelope, TelemetryWireError> {
    assert_canonical(&signed.body).map_err(|_| TelemetryWireError::NonCanonical)?;
    let sig = Signature::from_slice(&signed.sig).map_err(|_| TelemetryWireError::Sig)?;
    verifying_key
        .verify_strict(&signed.body, &sig)
        .map_err(|_| TelemetryWireError::Sig)?;
    let envelope: EdgeTelemetryEnvelope = ciborium::de::from_reader(signed.body.as_slice())
        .map_err(|_| TelemetryWireError::Decode)?;
    if envelope.domain != TELEMETRY_DOMAIN {
        return Err(TelemetryWireError::Domain);
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample() -> EdgeTelemetryEnvelope {
        EdgeTelemetryEnvelope {
            domain: TELEMETRY_DOMAIN.to_string(),
            timestamp: 1_700_000_000,
            counter: 7,
            peer_id: "hippius-miner:abc".to_string(),
            direction: Direction::MinerToInner,
            message_kind: MessageKind::ServedReceipt,
            bytes_in: 256,
            bytes_out: 256,
            shed: false,
            shed_reason: None,
        }
    }

    #[test]
    fn canonical_roundtrips() {
        let env = sample();
        let body = env.to_canonical().unwrap();
        let decoded = EdgeTelemetryEnvelope::from_canonical(&body).unwrap();
        assert_eq!(env, decoded);
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        // Two encodes of the same envelope must be byte-identical —
        // the signature is over these bytes.
        let env = sample();
        assert_eq!(env.to_canonical().unwrap(), env.to_canonical().unwrap());
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let env = sample();
        let body = env.to_canonical().unwrap();
        let signed = SignedEdgeTelemetry {
            body: body.clone(),
            sig: sk.sign(&body).to_bytes().to_vec(),
        };
        let got = verify_signed_telemetry(&sk.verifying_key(), &signed).unwrap();
        assert_eq!(got, env);
    }

    #[test]
    fn tampered_body_fails_verification() {
        let sk = SigningKey::from_bytes(&[4u8; 32]);
        let env = sample();
        let body = env.to_canonical().unwrap();
        let mut signed = SignedEdgeTelemetry {
            body,
            sig: sk.sign(&env.to_canonical().unwrap()).to_bytes().to_vec(),
        };
        signed.body[0] ^= 0xff;
        let err = verify_signed_telemetry(&sk.verifying_key(), &signed).unwrap_err();
        // A flipped first byte breaks canonical form before the sig
        // check is even reached.
        assert!(matches!(
            err,
            TelemetryWireError::Sig | TelemetryWireError::NonCanonical
        ));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let other = SigningKey::from_bytes(&[6u8; 32]);
        let body = sample().to_canonical().unwrap();
        let signed = SignedEdgeTelemetry {
            body: body.clone(),
            sig: sk.sign(&body).to_bytes().to_vec(),
        };
        assert!(matches!(
            verify_signed_telemetry(&other.verifying_key(), &signed).unwrap_err(),
            TelemetryWireError::Sig
        ));
    }

    #[test]
    fn wrong_domain_is_rejected() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut env = sample();
        env.domain = "NOT_THE_TELEMETRY_DOMAIN".to_string();
        let body = env.to_canonical().unwrap();
        let signed = SignedEdgeTelemetry {
            body: body.clone(),
            sig: sk.sign(&body).to_bytes().to_vec(),
        };
        assert!(matches!(
            verify_signed_telemetry(&sk.verifying_key(), &signed).unwrap_err(),
            TelemetryWireError::Domain
        ));
    }

    #[test]
    fn shed_envelope_roundtrips_with_reason() {
        let mut env = sample();
        env.shed = true;
        env.bytes_out = 0;
        env.shed_reason = Some("rate-limited".to_string());
        let body = env.to_canonical().unwrap();
        assert_eq!(EdgeTelemetryEnvelope::from_canonical(&body).unwrap(), env);
    }

    #[test]
    fn wire_error_class_is_stable() {
        for (e, c) in [
            (TelemetryWireError::Encode, "telemetry-encode"),
            (TelemetryWireError::Decode, "telemetry-decode"),
            (TelemetryWireError::NonCanonical, "telemetry-non-canonical"),
            (TelemetryWireError::Sig, "telemetry-sig"),
            (TelemetryWireError::Domain, "telemetry-domain"),
        ] {
            assert_eq!(e.class(), c);
            assert_eq!(e.to_string(), c);
        }
    }
}
