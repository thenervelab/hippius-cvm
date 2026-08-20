//! Stage 2 — wire-gate. PR-H2: canonical-CBOR + **typed schema**.
//!
//! The §10 invariant: every byte crossing the diode passes through a
//! deterministic-CBOR check AND a `deny_unknown_fields` typed decode
//! BEFORE the inner consumer sees it. Malformed bytes are dropped
//! at the wire — the relay NEVER forwards them.
//!
//! ## Typestate enforcement (PR-H1 baseline, still load-bearing)
//!
//! This stage is the **only** place that produces a
//! [`ValidatedEnvelope`]. [`crate::stages::forward::forward`]
//! accepts ONLY `ValidatedEnvelope`; the constructor is
//! `pub(crate)` and called only from here. A future PR cannot call
//! `forward` on raw bytes — the type system rejects it at compile
//! time.
//!
//! ## What PR-H2 adds on top of the canonical-CBOR check
//!
//! Three checks, in order, fail-closed on each:
//!
//! 1. **canonical-CBOR** — `hippius_types::cbor::assert_canonical`
//!    rejects unsorted maps, duplicate keys, indefinite-length
//!    items, non-minimal integer encodings.
//! 2. **direction vs kind** — `MessageKind::expected_direction(kind)`
//!    must equal the envelope's `Direction`. A Miner that posts a
//!    `KbsResponse`-shaped body is injecting; drop.
//! 3. **typed decode** — ciborium deserialises into the local
//!    [`crate::stages::wire::KbsReleaseRequest`] /
//!    [`crate::stages::wire::SignedEnvelope`] mirror with
//!    `deny_unknown_fields`. We do NOT decode into the hippius-types
//!    `SignedResponse` / `SignedStoppedAck` / `SignedServedDeliveryReceipt`
//!    / `SignedServedDeliveryAggregate` structs — those are
//!    round-trippable across the guest / KBS / Validator and do not
//!    carry `deny_unknown_fields`, so a Miner could smuggle an extra
//!    field past the gate by going through them. The decoded value
//!    is **dropped immediately** — Edge does NOT retain or surface
//!    any typed view of the body (§5.6 opacity).
//!
//! On success: `ValidatedEnvelope` (opaque), forwarded by-value.
//! On any failure: structured [`EdgeError`] with a stable category
//! string for the audit log.

use crate::pipeline::{EdgeError, MessageKind};
use crate::stages::envelope::{RawEnvelope, ValidatedEnvelope};
use crate::stages::wire::{
    HostChallengeRequest, KbsReleaseRequest, SignedEnvelope, HOST_ATTESTOR_PUBKEY_LEN,
    KBS_NONCE_LEN,
};
use hippius_types::cbor::assert_canonical;

/// Stable classifier strings for `EdgeError::SchemaInvalid`. Kept in
/// one place so the audit log (PR-H6) can map each value to a
/// metric code without grep-ing the codebase.
pub(crate) mod cat {
    /// Caller's declared `MessageKind` doesn't match the envelope's
    /// `Direction`. Drop — a Miner that posts a KBS-response shape
    /// is injecting; an Inner that posts a Miner-request shape is
    /// a misconfigured worker.
    pub(crate) const DIRECTION_MISMATCH: &str = "direction-mismatch";
    /// CBOR-into-typed-struct decode failed. Includes missing
    /// required field, wrong field type, presence of an unknown
    /// field (`deny_unknown_fields`).
    pub(crate) const DECODE: &str = "decode";
    /// A byte-typed field was the wrong length (currently only
    /// `kbs_nonce`, pinned at 32 bytes by §20).
    pub(crate) const BYTE_LENGTH: &str = "byte-length";
}

/// Wire gate. Consumes `env` and returns a [`ValidatedEnvelope`] on
/// success — the only path to producing one.
pub fn validate(env: RawEnvelope) -> Result<ValidatedEnvelope, EdgeError> {
    // (1) Canonical-CBOR. Empty-body fail-closed here so the
    //     deny_unknown_fields decode doesn't see `[]` and crash on
    //     a less-obvious code path.
    let body = env.body_bytes();
    if body.is_empty() {
        return Err(EdgeError::NonCanonical("empty-body"));
    }
    assert_canonical(body)?;

    // (2) Direction vs kind. Every kind has exactly one allowed
    //     direction (see `MessageKind::expected_direction`); a
    //     mismatch is either injection or a misconfigured peer.
    if env.kind().expected_direction() != env.direction() {
        return Err(EdgeError::SchemaInvalid(cat::DIRECTION_MISMATCH));
    }

    // (3) Typed decode per kind. The decoded value is dropped at end
    //     of arm — Edge never retains a typed view (§5.6 opacity).
    match env.kind() {
        MessageKind::KbsRequest => {
            let parsed: KbsReleaseRequest = ciborium::de::from_reader(body)
                .map_err(|_| EdgeError::SchemaInvalid(cat::DECODE))?;
            if parsed.kbs_nonce.len() != KBS_NONCE_LEN {
                return Err(EdgeError::SchemaInvalid(cat::BYTE_LENGTH));
            }
            // `cose_ticket` and `snp_report` are length-checked
            // downstream by kbs-core (which has the COSE / SEV
            // verifiers). Edge does not second-guess.
        }
        // Every signed-X kind shares the `{body, sig}` wrapper —
        // `SignedResponse` / `SignedStoppedAck` /
        // `SignedServedDeliveryReceipt` / `SignedServedDeliveryAggregate`
        // / `SignedMinerHeartbeat` (PR-MA-6). We decode via the local
        // `SignedEnvelope` (deny_unknown_fields) rather than the
        // hippius-types structs, which are round-trippable and DO NOT
        // all carry `deny_unknown_fields` — routing through those would
        // let a Miner smuggle an `extra` field past the gate. `kind` is
        // preserved as the audit / routing tag in the resulting
        // `ValidatedEnvelope`.
        // The host-attestor liveness beacon (PR-10b-S2a) is a
        // `SignedHostBeacon` — the same `{body, sig}` wrapper as the other
        // signed telemetry kinds, so it decodes through the same
        // `deny_unknown_fields` mirror. The inner beacon body is opaque to
        // Edge (vali verifies the Ed25519 signature).
        MessageKind::KbsResponse
        | MessageKind::StoppedAck
        | MessageKind::ServedReceipt
        | MessageKind::ServedAggregate
        | MessageKind::Heartbeat
        | MessageKind::GracefulExit
        | MessageKind::VmProgress
        | MessageKind::HostAttestorBeacon
        // The tenant-CVM live attestation (§23) is a KBS-L0-signed
        // `{body, sig}` envelope like the rest — Edge checks the shape
        // only; vali verifies the L0 signature against its pinned key.
        | MessageKind::VmLiveAttestation => {
            let _: SignedEnvelope = ciborium::de::from_reader(body)
                .map_err(|_| EdgeError::SchemaInvalid(cat::DECODE))?;
        }
        // PR-10b-S2a — the host-attestor enrollment. Unlike the signed
        // kinds this is a multi-field `HostEnrollment`, so decode it with
        // the FROZEN PR-1 hostile-origin parser (which itself rejects
        // non-canonical / unknown-field / wrong-length CBOR incl. the
        // 1184-byte SNP report). The decoded value is dropped immediately —
        // Edge relays the bytes opaquely; the KBS orchestration re-decodes
        // downstream (§5.6). Reuses `HostAttestorSchema` errors, so no new
        // `HippiusTypesError` variant.
        MessageKind::HostAttestorEnroll => {
            hippius_types::host_attestor::HostEnrollment::decode(body)
                .map_err(|_| EdgeError::SchemaInvalid(cat::DECODE))?;
        }
        // PR-10 — the host-attestor nonce-challenge request is NOT a
        // `{body, sig}` envelope; it is a `{schema_version, signer_pubkey}`
        // shape. Pin the shape + the 32-byte key length; the bytes are
        // relayed opaquely to vali (which mints the nonce bound to the
        // mTLS-stamped node_id + this pk).
        MessageKind::HostAttestorChallenge => {
            let parsed: HostChallengeRequest = ciborium::de::from_reader(body)
                .map_err(|_| EdgeError::SchemaInvalid(cat::DECODE))?;
            if parsed.signer_pubkey.len() != HOST_ATTESTOR_PUBKEY_LEN {
                return Err(EdgeError::SchemaInvalid(cat::BYTE_LENGTH));
            }
        }
    }

    Ok(ValidatedEnvelope::from_validated(env))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mtls::PeerId;
    use crate::pipeline::Direction;
    use ciborium::value::Value;
    use hippius_types::cbor::to_canonical_vec;

    /// Peer identity the wire-gate tests attribute envelopes to.
    /// `validate` does NOT key on `peer` (rate-limiting lives in
    /// `relay_once`, not here), so any concrete identity is fine —
    /// we just need *something* for the `RawEnvelope::from_wire`
    /// constructor.
    fn peer() -> PeerId {
        PeerId::new("test-peer")
    }

    /// Build a canonical-CBOR encoding of a `KbsReleaseRequest`.
    /// Used by multiple tests; isolated here for clarity.
    fn canonical_kbs_request_body(nonce_len: usize) -> Vec<u8> {
        let v = Value::Map(vec![
            (
                Value::Text("cose_ticket".into()),
                Value::Bytes(vec![1u8; 4]),
            ),
            (
                Value::Text("kbs_nonce".into()),
                Value::Bytes(vec![2u8; nonce_len]),
            ),
            (Value::Text("snp_report".into()), Value::Bytes(vec![3u8; 4])),
        ]);
        to_canonical_vec(&v).unwrap()
    }

    fn canonical_signed_envelope(body_len: usize, sig_len: usize) -> Vec<u8> {
        let v = Value::Map(vec![
            (
                Value::Text("body".into()),
                Value::Bytes(vec![0u8; body_len]),
            ),
            (Value::Text("sig".into()), Value::Bytes(vec![0u8; sig_len])),
        ]);
        to_canonical_vec(&v).unwrap()
    }

    // ─── canonical-CBOR layer (PR-H1, still works) ─────────────────

    #[test]
    fn empty_body_is_dropped_before_typed_decode() {
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::KbsRequest,
            peer(),
            Vec::new(),
        );
        let err = validate(env).unwrap_err();
        assert!(matches!(err, EdgeError::NonCanonical("empty-body")));
    }

    #[test]
    fn unsorted_map_is_dropped_at_canonical_gate() {
        // Non-canonical (unsorted) → must trip BEFORE the typed
        // decode would have caught the missing fields.
        let v = Value::Map(vec![
            (Value::Text("snp_report".into()), Value::Bytes(vec![1])),
            (Value::Text("cose_ticket".into()), Value::Bytes(vec![1])),
            (Value::Text("kbs_nonce".into()), Value::Bytes(vec![0u8; 32])),
        ]);
        let mut noncanon = Vec::new();
        ciborium::ser::into_writer(&v, &mut noncanon).unwrap();
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::KbsRequest,
            peer(),
            noncanon,
        );
        let err = validate(env).unwrap_err();
        assert!(
            matches!(err, EdgeError::HippiusTypes(_)),
            "canonical-CBOR check must run first, got {err:?}"
        );
    }

    // ─── direction-vs-kind enforcement ────────────────────────────

    #[test]
    fn miner_posting_kbs_response_shape_is_dropped() {
        // KBS-response shape with wrong direction (Miner→Inner instead
        // of Inner→Miner) — Miner trying to inject server-side
        // bytes. Drop at the direction gate, NOT at the decode step.
        let body = canonical_signed_envelope(8, 64);
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::KbsResponse,
            peer(),
            body,
        );
        let err = validate(env).unwrap_err();
        assert!(matches!(
            err,
            EdgeError::SchemaInvalid(cat::DIRECTION_MISMATCH)
        ));
    }

    #[test]
    fn inner_posting_kbs_request_shape_is_dropped() {
        let body = canonical_kbs_request_body(32);
        let env = RawEnvelope::from_wire(
            Direction::InnerToMiner,
            MessageKind::KbsRequest,
            peer(),
            body,
        );
        let err = validate(env).unwrap_err();
        assert!(matches!(
            err,
            EdgeError::SchemaInvalid(cat::DIRECTION_MISMATCH)
        ));
    }

    // ─── typed decode: KbsRequest happy + sad ─────────────────────

    #[test]
    fn kbs_request_happy_path() {
        let body = canonical_kbs_request_body(32);
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::KbsRequest,
            peer(),
            body,
        );
        let validated = validate(env).unwrap();
        assert_eq!(validated.kind(), MessageKind::KbsRequest);
    }

    #[test]
    fn kbs_request_with_short_nonce_is_dropped() {
        let body = canonical_kbs_request_body(16); // §20: must be 32
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::KbsRequest,
            peer(),
            body,
        );
        let err = validate(env).unwrap_err();
        assert!(matches!(err, EdgeError::SchemaInvalid(cat::BYTE_LENGTH)));
    }

    #[test]
    fn kbs_request_with_extra_unknown_field_is_dropped() {
        // `deny_unknown_fields` MUST trip — a Miner that smuggles an
        // extra field could be probing for KBS parser bugs.
        let v = Value::Map(vec![
            (
                Value::Text("cose_ticket".into()),
                Value::Bytes(vec![1u8; 4]),
            ),
            (Value::Text("extra".into()), Value::Integer(0.into())),
            (Value::Text("kbs_nonce".into()), Value::Bytes(vec![2u8; 32])),
            (Value::Text("snp_report".into()), Value::Bytes(vec![3u8; 4])),
        ]);
        let body = to_canonical_vec(&v).unwrap();
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::KbsRequest,
            peer(),
            body,
        );
        let err = validate(env).unwrap_err();
        assert!(matches!(err, EdgeError::SchemaInvalid(cat::DECODE)));
    }

    #[test]
    fn kbs_request_with_missing_field_is_dropped() {
        // Drop the `snp_report` field entirely.
        let v = Value::Map(vec![
            (
                Value::Text("cose_ticket".into()),
                Value::Bytes(vec![1u8; 4]),
            ),
            (Value::Text("kbs_nonce".into()), Value::Bytes(vec![2u8; 32])),
        ]);
        let body = to_canonical_vec(&v).unwrap();
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::KbsRequest,
            peer(),
            body,
        );
        let err = validate(env).unwrap_err();
        assert!(matches!(err, EdgeError::SchemaInvalid(cat::DECODE)));
    }

    #[test]
    fn kbs_request_with_wrong_type_is_dropped() {
        // `cose_ticket` as a text string instead of bytes.
        let v = Value::Map(vec![
            (
                Value::Text("cose_ticket".into()),
                Value::Text("not bytes".into()),
            ),
            (Value::Text("kbs_nonce".into()), Value::Bytes(vec![2u8; 32])),
            (Value::Text("snp_report".into()), Value::Bytes(vec![3u8; 4])),
        ]);
        let body = to_canonical_vec(&v).unwrap();
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::KbsRequest,
            peer(),
            body,
        );
        let err = validate(env).unwrap_err();
        assert!(matches!(err, EdgeError::SchemaInvalid(cat::DECODE)));
    }

    // ─── typed decode: each other kind happy path ─────────────────

    #[test]
    fn kbs_response_happy_path() {
        let body = canonical_signed_envelope(16, 64);
        let env = RawEnvelope::from_wire(
            Direction::InnerToMiner,
            MessageKind::KbsResponse,
            peer(),
            body,
        );
        let validated = validate(env).unwrap();
        assert_eq!(validated.kind(), MessageKind::KbsResponse);
    }

    #[test]
    fn stopped_ack_happy_path() {
        // SignedStoppedAck has the same {body, sig} shape as
        // SignedResponse — different MessageKind tag, same wrapper.
        let body = canonical_signed_envelope(64, 64);
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::StoppedAck,
            peer(),
            body,
        );
        let validated = validate(env).unwrap();
        assert_eq!(validated.kind(), MessageKind::StoppedAck);
    }

    #[test]
    fn served_receipt_happy_path() {
        let body = canonical_signed_envelope(64, 64);
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::ServedReceipt,
            peer(),
            body,
        );
        let validated = validate(env).unwrap();
        assert_eq!(validated.kind(), MessageKind::ServedReceipt);
    }

    /// Build a canonical-CBOR `HostChallengeRequest` body with a
    /// `pubkey_len`-byte `signer_pubkey` (PR-10).
    fn canonical_host_challenge_body(pubkey_len: usize) -> Vec<u8> {
        let v = Value::Map(vec![
            (
                Value::Text("schema_version".into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("signer_pubkey".into()),
                Value::Bytes(vec![0x22; pubkey_len]),
            ),
        ]);
        to_canonical_vec(&v).unwrap()
    }

    #[test]
    fn host_attestor_challenge_happy_path() {
        let body = canonical_host_challenge_body(HOST_ATTESTOR_PUBKEY_LEN);
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::HostAttestorChallenge,
            peer(),
            body,
        );
        let validated = validate(env).unwrap();
        assert_eq!(validated.kind(), MessageKind::HostAttestorChallenge);
    }

    #[test]
    fn host_attestor_challenge_short_pubkey_is_byte_length_reject() {
        let body = canonical_host_challenge_body(HOST_ATTESTOR_PUBKEY_LEN - 1);
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::HostAttestorChallenge,
            peer(),
            body,
        );
        let err = validate(env).unwrap_err();
        assert!(matches!(err, EdgeError::SchemaInvalid(cat::BYTE_LENGTH)));
    }

    #[test]
    fn host_attestor_challenge_wrong_direction_is_rejected() {
        // A host-attestor challenge is Miner→Inner only.
        let body = canonical_host_challenge_body(HOST_ATTESTOR_PUBKEY_LEN);
        let env = RawEnvelope::from_wire(
            Direction::InnerToMiner,
            MessageKind::HostAttestorChallenge,
            peer(),
            body,
        );
        let err = validate(env).unwrap_err();
        assert!(matches!(
            err,
            EdgeError::SchemaInvalid(cat::DIRECTION_MISMATCH)
        ));
    }

    #[test]
    fn host_attestor_beacon_happy_path() {
        // A SignedHostBeacon is a `{body, sig}` envelope — same wrapper as
        // the other signed telemetry kinds.
        let body = canonical_signed_envelope(64, 64);
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::HostAttestorBeacon,
            peer(),
            body,
        );
        let validated = validate(env).unwrap();
        assert_eq!(validated.kind(), MessageKind::HostAttestorBeacon);
    }

    #[test]
    fn host_attestor_enroll_happy_path() {
        // A full valid HostEnrollment (1184-byte SNP report + fields) must
        // pass the frozen PR-1 decoder the wire gate runs.
        let enrollment = hippius_types::host_attestor::HostEnrollment {
            schema_version: hippius_types::host_attestor::HOST_ATTESTOR_SCHEMA_VERSION,
            snp_report: [0x5A; hippius_types::host_attestor::SNP_REPORT_LEN],
            signer_pubkey: [0x22; hippius_types::host_attestor::PUBKEY_LEN],
            node_id: "node-host-1".into(),
            boot_id: "boot-abc".into(),
            issued_at_unix: 1_800_000_000,
        };
        let body = enrollment.canonical().unwrap();
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::HostAttestorEnroll,
            peer(),
            body,
        );
        let validated = validate(env).unwrap();
        assert_eq!(validated.kind(), MessageKind::HostAttestorEnroll);
    }

    #[test]
    fn host_attestor_enroll_malformed_is_dropped() {
        // A `{body, sig}` shape is NOT a valid HostEnrollment — the frozen
        // decoder rejects it (missing fields) → schema-invalid.
        let body = canonical_signed_envelope(64, 64);
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::HostAttestorEnroll,
            peer(),
            body,
        );
        let err = validate(env).unwrap_err();
        assert!(matches!(err, EdgeError::SchemaInvalid(cat::DECODE)));
    }

    #[test]
    fn host_attestor_enroll_wrong_direction_is_rejected() {
        let enrollment = hippius_types::host_attestor::HostEnrollment {
            schema_version: hippius_types::host_attestor::HOST_ATTESTOR_SCHEMA_VERSION,
            snp_report: [0x5A; hippius_types::host_attestor::SNP_REPORT_LEN],
            signer_pubkey: [0x22; hippius_types::host_attestor::PUBKEY_LEN],
            node_id: "node-host-1".into(),
            boot_id: "boot-abc".into(),
            issued_at_unix: 1_800_000_000,
        };
        let body = enrollment.canonical().unwrap();
        let env = RawEnvelope::from_wire(
            Direction::InnerToMiner,
            MessageKind::HostAttestorEnroll,
            peer(),
            body,
        );
        let err = validate(env).unwrap_err();
        assert!(matches!(
            err,
            EdgeError::SchemaInvalid(cat::DIRECTION_MISMATCH)
        ));
    }

    #[test]
    fn heartbeat_happy_path() {
        // SignedMinerHeartbeat (PR-MA-6) has the same {body, sig} shape
        // as the other signed-X kinds — different MessageKind tag.
        let body = canonical_signed_envelope(64, 64);
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::Heartbeat,
            peer(),
            body,
        );
        let validated = validate(env).unwrap();
        assert_eq!(validated.kind(), MessageKind::Heartbeat);
    }

    #[test]
    fn graceful_exit_happy_path() {
        // SignedGracefulExit has the same {body, sig} shape as the other
        // signed-X kinds — different MessageKind tag.
        let body = canonical_signed_envelope(64, 64);
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::GracefulExit,
            peer(),
            body,
        );
        let validated = validate(env).unwrap();
        assert_eq!(validated.kind(), MessageKind::GracefulExit);
    }

    #[test]
    fn served_aggregate_happy_path() {
        let body = canonical_signed_envelope(64, 64);
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::ServedAggregate,
            peer(),
            body,
        );
        let validated = validate(env).unwrap();
        assert_eq!(validated.kind(), MessageKind::ServedAggregate);
    }

    // ─── decode failure for the SignedX shapes (covers all four) ──

    #[test]
    fn signed_envelope_extra_field_is_dropped() {
        // §10 / PR-H2 deny_unknown_fields: a Miner that posts a
        // {body, sig, extra} envelope would deserialise cleanly into
        // the round-trippable hippius-types `SignedX` struct (which
        // doesn't carry `deny_unknown_fields`). Routing through the
        // local `SignedEnvelope` mirror MUST reject it. Covers all
        // four SignedX kinds in one sweep.
        let v = Value::Map(vec![
            (Value::Text("body".into()), Value::Bytes(vec![0u8; 16])),
            (Value::Text("extra".into()), Value::Integer(0.into())),
            (Value::Text("sig".into()), Value::Bytes(vec![0u8; 64])),
        ]);
        let body = to_canonical_vec(&v).unwrap();
        for (dir, kind) in [
            (Direction::InnerToMiner, MessageKind::KbsResponse),
            (Direction::MinerToInner, MessageKind::StoppedAck),
            (Direction::MinerToInner, MessageKind::ServedReceipt),
            (Direction::MinerToInner, MessageKind::ServedAggregate),
            (Direction::MinerToInner, MessageKind::Heartbeat),
            (Direction::MinerToInner, MessageKind::GracefulExit),
        ] {
            let env = RawEnvelope::from_wire(dir, kind, peer(), body.clone());
            let err = validate(env).unwrap_err();
            assert!(
                matches!(err, EdgeError::SchemaInvalid(cat::DECODE)),
                "kind={kind:?} got {err:?}"
            );
        }
    }

    #[test]
    fn signed_envelope_missing_sig_is_dropped() {
        // {body: bytes} with no `sig` field — fails the SignedResponse
        // / SignedStoppedAck / SignedServedDeliveryReceipt /
        // SignedServedDeliveryAggregate decode equally.
        let v = Value::Map(vec![(
            Value::Text("body".into()),
            Value::Bytes(vec![0u8; 16]),
        )]);
        let body = to_canonical_vec(&v).unwrap();
        for (dir, kind) in [
            (Direction::InnerToMiner, MessageKind::KbsResponse),
            (Direction::MinerToInner, MessageKind::StoppedAck),
            (Direction::MinerToInner, MessageKind::ServedReceipt),
            (Direction::MinerToInner, MessageKind::ServedAggregate),
            (Direction::MinerToInner, MessageKind::Heartbeat),
            (Direction::MinerToInner, MessageKind::GracefulExit),
        ] {
            let env = RawEnvelope::from_wire(dir, kind, peer(), body.clone());
            let err = validate(env).unwrap_err();
            assert!(
                matches!(err, EdgeError::SchemaInvalid(cat::DECODE)),
                "kind={kind:?} got {err:?}"
            );
        }
    }

    #[test]
    fn garbage_non_cbor_bytes_are_dropped() {
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::KbsRequest,
            peer(),
            vec![0xff, 0xff, 0xff],
        );
        assert!(validate(env).is_err());
    }
}
