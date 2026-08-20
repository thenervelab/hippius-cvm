//! The host→miner-agent vsock frame format.
//!
//! Each message is one frame: a 4-byte big-endian `u32` length, then
//! that many bytes of a CBOR `GuestFrame` map `{kind, body}` — the same
//! wire shape the sibling telemetry agent uses, so the host miner-agent's
//! vsock reader can demux both agents on one listener by `kind`:
//!
//! - [`ENROLL_KIND`] (`"host-enroll"`) — `body` is the canonical CBOR of
//!   a [`HostEnrollment`], sent ONCE per boot (and re-sent on each
//!   reconnect);
//! - [`BEACON_KIND`] (`"host-beacon"`) — `body` is the canonical CBOR of
//!   a [`SignedHostBeacon`] envelope, sent every beat.
//!
//! Fire-and-forget — no per-frame ack; vali's ingest (PR-8) dedupes by
//! content, so an at-least-once resend after a reconnect is safe.
//!
//! Nothing here logs a body or any derivative — only the caller's static
//! error classes (§20).

use hippius_types::host_attestor::{HostEnrollment, SignedHostBeacon};

use crate::error::{HostAttestorError, Result};

/// `kind` for a once-per-boot enrollment frame.
pub const ENROLL_KIND: &str = "host-enroll";

/// `kind` for a periodic liveness-beacon frame.
pub const BEACON_KIND: &str = "host-beacon";

/// Upper bound on one encoded frame. The enrollment (~1.3 KiB, dominated
/// by the 1184-byte SNP report) and a beacon (a few hundred bytes) sit
/// well under this; the cap only trips on a corrupt message.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

/// Encode the once-per-boot enrollment as a length-prefixed
/// `{kind: "host-enroll", body: <enrollment canonical CBOR>}` frame.
pub fn encode_enroll_frame(enrollment: &HostEnrollment) -> Result<Vec<u8>> {
    let body = enrollment
        .canonical()
        .map_err(|_| HostAttestorError::Vsock("enroll-encode"))?;
    frame(ENROLL_KIND, body)
}

/// Encode one signed beacon as a length-prefixed
/// `{kind: "host-beacon", body: <signed-beacon canonical CBOR>}` frame.
pub fn encode_beacon_frame(beacon: &SignedHostBeacon) -> Result<Vec<u8>> {
    let body = beacon
        .encode()
        .map_err(|_| HostAttestorError::Vsock("beacon-encode"))?;
    frame(BEACON_KIND, body)
}

/// Wrap `inner` in the `GuestFrame` CBOR map + length prefix.
fn frame(kind: &str, inner: Vec<u8>) -> Result<Vec<u8>> {
    let value = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("kind".to_string()),
            ciborium::value::Value::Text(kind.to_string()),
        ),
        (
            ciborium::value::Value::Text("body".to_string()),
            ciborium::value::Value::Bytes(inner),
        ),
    ]);
    let mut body = Vec::new();
    ciborium::into_writer(&value, &mut body)
        .map_err(|_| HostAttestorError::Vsock("frame-encode"))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(HostAttestorError::Vsock("frame-too-large"));
    }
    // Checked above: `body.len() <= MAX_FRAME_BYTES` ⇒ far below
    // `u32::MAX`, so the cast cannot truncate.
    let len = body.len() as u32;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hippius_types::host_attestor::{
        HostEnrollment, SignedHostBeacon, HOST_ATTESTOR_SCHEMA_VERSION, PUBKEY_LEN, SIGNATURE_LEN,
        SNP_REPORT_LEN,
    };

    fn enrollment() -> HostEnrollment {
        HostEnrollment {
            schema_version: HOST_ATTESTOR_SCHEMA_VERSION,
            snp_report: [0x5A; SNP_REPORT_LEN],
            signer_pubkey: [0x22; PUBKEY_LEN],
            node_id: "node-host-1".into(),
            boot_id: "boot-abc".into(),
            issued_at_unix: 1_800_000_000,
        }
    }

    /// Split a length-prefixed frame into (kind, inner-body).
    fn parse(frame: &[u8]) -> (String, Vec<u8>) {
        let declared = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(declared, frame.len() - 4);
        let value: ciborium::value::Value =
            ciborium::de::from_reader(&frame[4..]).expect("GuestFrame CBOR map");
        let ciborium::value::Value::Map(entries) = value else {
            panic!("frame body is not a CBOR map");
        };
        let mut kind = None;
        let mut inner = None;
        for (k, v) in &entries {
            match k.as_text() {
                Some("kind") => kind = v.as_text().map(str::to_string),
                Some("body") => inner = v.as_bytes().cloned(),
                _ => panic!("unexpected GuestFrame field"),
            }
        }
        (kind.expect("kind"), inner.expect("body"))
    }

    #[test]
    fn enroll_frame_is_a_length_prefixed_guest_frame() {
        let e = enrollment();
        let (kind, inner) = parse(&encode_enroll_frame(&e).unwrap());
        assert_eq!(kind, ENROLL_KIND);
        // The inner bytes are exactly the enrollment's canonical CBOR.
        assert_eq!(inner, e.canonical().unwrap());
        assert_eq!(HostEnrollment::decode(&inner).unwrap(), e);
    }

    #[test]
    fn beacon_frame_is_a_length_prefixed_guest_frame() {
        let signed = SignedHostBeacon {
            body: vec![7u8; 24],
            sig: [0xAB; SIGNATURE_LEN],
        };
        let (kind, inner) = parse(&encode_beacon_frame(&signed).unwrap());
        assert_eq!(kind, BEACON_KIND);
        assert_eq!(inner, signed.encode().unwrap());
        assert_eq!(SignedHostBeacon::decode(&inner).unwrap(), signed);
    }

    #[test]
    fn oversize_frame_is_refused() {
        // A signed beacon with an absurd body clears the cap.
        let signed = SignedHostBeacon {
            body: vec![0u8; MAX_FRAME_BYTES + 1],
            sig: [0u8; SIGNATURE_LEN],
        };
        let err = encode_beacon_frame(&signed).expect_err("an oversize frame must be refused");
        assert_eq!(err.class(), "frame-too-large");
    }
}
