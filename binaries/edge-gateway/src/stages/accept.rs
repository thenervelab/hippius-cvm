//! Stage 1 — accept an envelope on the inbound interface.
//!
//! ## PR-H4 split
//!
//! - This module (the mock) constructs a deterministic canonical-
//!   CBOR envelope for a given `(direction, kind, peer)` triple —
//!   used by the unit + integration tests in this crate. No TCP, no
//!   handshake, no real frames. Production now also takes the
//!   `peer: PeerId` as input from the caller (the mTLS handshake
//!   produces it).
//! - [`crate::mtls::MtlsAcceptor::accept`] is the **real** accept
//!   path. It owns a `tokio_rustls::TlsAcceptor`, drives the
//!   handshake on an inbound `TcpStream`, and returns the
//!   `(PeerId, TlsStream)` the caller can read a frame from. PR-H5
//!   wires the production `TcpListener` accept loop around it.
//!
//! The mock body shape **matches `kind`** so the wire gate accepts
//! it. Tests use the mock path; production goes through `MtlsAcceptor`
//! (PR-H5 will close that loop).

use crate::mtls::PeerId;
use crate::pipeline::{Direction, EdgeError, MessageKind};
use crate::stages::envelope::RawEnvelope;
use ciborium::value::Value;
use hippius_types::cbor::to_canonical_vec;

/// Mock-accept one envelope of `kind` on `direction`, attributing it
/// to source `peer`.
///
/// The returned `RawEnvelope` is canonical-CBOR AND parses cleanly
/// against `kind`'s typed schema by construction — used by the
/// integration test sweep that exercises one of each shape through
/// the wire gate.
///
/// The map deliberately does NOT echo the direction or peer tag —
/// keeping out-of-band [`Direction`] + handshake-derived `peer` as
/// the single source of routing truth (the relay won't be tempted
/// to read routing data out of the wire body, which would re-
/// introduce a §5.6 plaintext-inspection path).
pub async fn accept(
    direction: Direction,
    kind: MessageKind,
    peer: PeerId,
) -> Result<RawEnvelope, EdgeError> {
    let body = mock_body(kind)?;
    Ok(RawEnvelope::from_wire(direction, kind, peer, body))
}

/// Build a canonical-CBOR body whose shape matches `kind`. Each arm
/// constructs exactly the fields the corresponding typed decode in
/// [`crate::stages::validate`] expects — anything else would defeat
/// the integration test's "happy path round-trips" guarantee.
fn mock_body(kind: MessageKind) -> Result<Vec<u8>, EdgeError> {
    let value = match kind {
        MessageKind::KbsRequest => Value::Map(vec![
            // Map keys ordered lexicographically (canonical-CBOR).
            (
                Value::Text("cose_ticket".into()),
                Value::Bytes(vec![0xAA; 16]),
            ),
            (
                Value::Text("kbs_nonce".into()),
                // §20: must be exactly 32 bytes.
                Value::Bytes(vec![0xBB; 32]),
            ),
            (
                Value::Text("snp_report".into()),
                Value::Bytes(vec![0xCC; 64]),
            ),
        ]),
        // Every signed-X envelope shares the {body, sig} shape — the
        // typed decode validates field names + byte-types only, not
        // the contents (which are opaque to Edge).
        // The host-attestor beacon (PR-10b-S2a) is also a `{body, sig}`
        // signed envelope.
        MessageKind::KbsResponse
        | MessageKind::StoppedAck
        | MessageKind::ServedReceipt
        | MessageKind::ServedAggregate
        | MessageKind::Heartbeat
        | MessageKind::GracefulExit
        | MessageKind::VmProgress
        | MessageKind::HostAttestorBeacon
        | MessageKind::VmLiveAttestation => Value::Map(vec![
            (Value::Text("body".into()), Value::Bytes(vec![0xDD; 32])),
            (Value::Text("sig".into()), Value::Bytes(vec![0xEE; 64])),
        ]),
        // PR-10 — the host-attestor nonce-challenge request shape:
        // `{schema_version, signer_pubkey}` with a 32-byte key.
        MessageKind::HostAttestorChallenge => Value::Map(vec![
            (
                Value::Text("schema_version".into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("signer_pubkey".into()),
                Value::Bytes(vec![0x22; 32]),
            ),
        ]),
        // PR-10b-S2a — the host-attestor enrollment: a full valid
        // `HostEnrollment` so the frozen PR-1 decoder in `validate` accepts
        // it (the mock is the integration test's canonical-CBOR ground
        // truth). Built via the wire type so it stays in lockstep.
        MessageKind::HostAttestorEnroll => {
            let enrollment = hippius_types::host_attestor::HostEnrollment {
                schema_version: hippius_types::host_attestor::HOST_ATTESTOR_SCHEMA_VERSION,
                snp_report: [0x5A; hippius_types::host_attestor::SNP_REPORT_LEN],
                signer_pubkey: [0x22; hippius_types::host_attestor::PUBKEY_LEN],
                node_id: "node-host-1".into(),
                boot_id: "boot-abc".into(),
                issued_at_unix: 1_800_000_000,
            };
            return enrollment.canonical().map_err(EdgeError::HippiusTypes);
        }
    };
    to_canonical_vec(&value).map_err(EdgeError::HippiusTypes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stages::validate::validate;

    fn test_peer() -> PeerId {
        PeerId::new("test-peer")
    }

    #[tokio::test]
    async fn mock_envelope_has_requested_direction_kind_and_peer() {
        let p = test_peer();
        let env = accept(Direction::MinerToInner, MessageKind::KbsRequest, p.clone())
            .await
            .unwrap();
        assert_eq!(env.direction(), Direction::MinerToInner);
        assert_eq!(env.kind(), MessageKind::KbsRequest);
        assert_eq!(env.peer(), &p);
        assert!(env.body_len() > 0);
    }

    #[tokio::test]
    async fn mock_envelope_passes_the_wire_gate() {
        // Every `MessageKind` must round-trip through `validate` —
        // the mock body is the integration test's source of canonical-
        // CBOR-AND-typed-shape ground truth.
        let p = test_peer();
        for (direction, kind) in [
            (Direction::MinerToInner, MessageKind::KbsRequest),
            (Direction::InnerToMiner, MessageKind::KbsResponse),
            (Direction::MinerToInner, MessageKind::StoppedAck),
            (Direction::MinerToInner, MessageKind::ServedReceipt),
            (Direction::MinerToInner, MessageKind::ServedAggregate),
            (Direction::MinerToInner, MessageKind::Heartbeat),
        ] {
            let env = accept(direction, kind, p.clone()).await.unwrap();
            let validated = validate(env).expect("mock body must pass the wire gate");
            assert_eq!(validated.direction(), direction);
            assert_eq!(validated.kind(), kind);
            assert_eq!(validated.peer(), &p);
        }
    }
}
