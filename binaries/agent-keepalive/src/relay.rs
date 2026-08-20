//! Push the KBS-signed live attestation out to vali (§23 uptime
//! coverage).
//!
//! A keepalive tick already ends with a `SignedLiveAttestation` in the
//! guest's hands: proof, rooted in AMD silicon, that THIS CVM was alive
//! at that instant. That proof is only worth something once vali has
//! it — it is what makes the VM's served receipts creditable at all
//! when the uptime-liveness gate is armed. This module is the last hop.
//!
//! ```text
//! agent-keepalive (in the SEV-SNP CVM)
//!      │  AF_VSOCK, CID = VMADDR_CID_HOST
//!      ▼
//! miner-agent (host)  ──HTTP──▶ Edge /v1/edge/vm-live-attestation
//!      ▼
//! vali POST /v1/telemetry/vm-liveness   (verifies the KBS L0 signature)
//! ```
//!
//! ## The relay carries no trust
//!
//! The miner-agent and the Edge relay these bytes opaquely and vali
//! verifies the KBS L0 signature against its own pinned key. A miner
//! cannot mint an attestation (only a KBS that has just verified a
//! fresh SNP report from inside a live guest can) and cannot edit one
//! (the signature covers every field). It CAN drop them — and doing so
//! only costs the miner its own uptime credit, which is the incentive
//! that makes a dumb relay safe here.
//!
//! ## Failure posture: never fail the tick
//!
//! The attestation is already minted and durably archived KBS-side when
//! this runs. A vsock hiccup must not turn a successful keepalive into
//! a failed tick — a push failure is logged with a static classifier
//! and the next tick simply pushes a fresh attestation. Nothing is
//! queued: attestations are periodic and short-lived (they carry an
//! `expiry_unix`), so a stale one is worth less than the next one.
//!
//! ## Frame format (the MA-4 contract)
//!
//! One 4-byte big-endian `u32` length, then the CBOR of the
//! miner-agent's `GuestFrame` shape: a map `{kind:
//! "vm-live-attestation", body: <SignedLiveAttestation::encode bytes>}`.
//! `kind` is the kebab-case rendering of
//! `miner_agent::EnvelopeKind::VmLiveAttestation`; the decoder there is
//! `#[serde(deny_unknown_fields)]`, so the map carries exactly these
//! two keys. Identical discipline to the tenant-telemetry receipt
//! pusher.

use std::io::Write;

/// `VMADDR_CID_HOST` — the well-known vsock context id of the host the
/// SEV-SNP guest runs on, where the miner-agent's listener lives.
pub const VSOCK_HOST_CID: u32 = 2;

/// The `kind` tag the miner-agent routes on. MUST stay byte-identical
/// to the kebab-case serde rendering of
/// `hippius_miner_agent::EnvelopeKind::VmLiveAttestation` — a drift
/// here is silently-dropped coverage, which once the gate is armed is
/// silently-lost reward.
pub const FRAME_KIND: &str = "vm-live-attestation";

/// Upper bound on one encoded frame. A `SignedLiveAttestation` is under
/// a kilobyte; the cap only trips on a corrupt payload. Sized under the
/// Edge's own envelope cap so a frame this side accepts also clears the
/// next hop.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

/// Closed-vocabulary push errors — `&'static str` classifiers only, so
/// a log line can never splice in attestation bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayError {
    /// The frame could not be CBOR-encoded, or exceeded the cap.
    Encode,
    /// The vsock connection or write failed.
    Io,
}

impl RelayError {
    pub fn class(&self) -> &'static str {
        match self {
            RelayError::Encode => "relay-encode",
            RelayError::Io => "relay-io",
        }
    }
}

/// Encode one signed live attestation as a length-prefixed
/// `GuestFrame` CBOR frame.
pub fn encode_frame(signed_live_attestation: &[u8]) -> Result<Vec<u8>, RelayError> {
    let frame_value = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("kind".to_string()),
            ciborium::value::Value::Text(FRAME_KIND.to_string()),
        ),
        (
            ciborium::value::Value::Text("body".to_string()),
            ciborium::value::Value::Bytes(signed_live_attestation.to_vec()),
        ),
    ]);
    let mut body = Vec::new();
    ciborium::into_writer(&frame_value, &mut body).map_err(|_| RelayError::Encode)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(RelayError::Encode);
    }
    // Checked above ⇒ far below `u32::MAX`; the cast cannot truncate.
    let len = body.len() as u32;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Where a tick's attestation goes. A trait so the tick is testable
/// without a host-side vsock listener.
pub trait AttestationSink {
    /// Push one canonical-CBOR `SignedLiveAttestation`. Best-effort:
    /// the caller logs a failure and moves on (see the module doc).
    fn push(&self, signed_live_attestation: &[u8]) -> Result<(), RelayError>;
}

/// Discards the attestation. The default when no `--relay` is
/// configured, and the shape a deployment runs in while the operator is
/// still on step 2 of the arming sequence.
pub struct NullSink;

impl AttestationSink for NullSink {
    fn push(&self, _signed_live_attestation: &[u8]) -> Result<(), RelayError> {
        Ok(())
    }
}

/// Production sink: one short-lived AF_VSOCK connection per push.
///
/// Per-push connect rather than a held socket: keepalive ticks are
/// minutes apart, so a persistent connection would spend its whole life
/// idle and would need its own reconnect state machine. Connect-write-
/// close has no state to get wrong.
#[cfg(target_os = "linux")]
pub struct VsockSink {
    pub host_cid: u32,
    pub port: u32,
}

#[cfg(target_os = "linux")]
impl AttestationSink for VsockSink {
    fn push(&self, signed_live_attestation: &[u8]) -> Result<(), RelayError> {
        let frame = encode_frame(signed_live_attestation)?;
        let addr = vsock::VsockAddr::new(self.host_cid, self.port);
        let mut stream = vsock::VsockStream::connect(&addr).map_err(|_| RelayError::Io)?;
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .map_err(|_| RelayError::Io)?;
        stream.write_all(&frame).map_err(|_| RelayError::Io)?;
        stream.flush().map_err(|_| RelayError::Io)?;
        Ok(())
    }
}

/// A sink that writes frames into any `Write` — used by the tests, and
/// the shape the vsock sink degenerates to.
pub struct WriterSink<W: Write>(pub std::cell::RefCell<W>);

impl<W: Write> AttestationSink for WriterSink<W> {
    fn push(&self, signed_live_attestation: &[u8]) -> Result<(), RelayError> {
        let frame = encode_frame(signed_live_attestation)?;
        let mut w = self.0.borrow_mut();
        w.write_all(&frame).map_err(|_| RelayError::Io)?;
        w.flush().map_err(|_| RelayError::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_frame(frame: &[u8]) -> (String, Vec<u8>) {
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - 4, "length prefix must cover the body");
        let v: ciborium::value::Value =
            ciborium::de::from_reader(&frame[4..]).expect("frame body is CBOR");
        let entries = match v {
            ciborium::value::Value::Map(e) => e,
            _ => panic!("frame is not a map"),
        };
        assert_eq!(entries.len(), 2, "exactly {{kind, body}} — no extra keys");
        let mut kind = None;
        let mut body = None;
        for (k, val) in entries {
            match (k, val) {
                (ciborium::value::Value::Text(n), ciborium::value::Value::Text(t))
                    if n == "kind" =>
                {
                    kind = Some(t)
                }
                (ciborium::value::Value::Text(n), ciborium::value::Value::Bytes(b))
                    if n == "body" =>
                {
                    body = Some(b)
                }
                _ => panic!("unexpected frame entry"),
            }
        }
        (kind.expect("kind"), body.expect("body"))
    }

    #[test]
    fn frame_carries_the_kind_the_miner_agent_routes_on() {
        // A drift in this string is silently-dropped coverage.
        let frame = encode_frame(b"signed-live-attestation-bytes").unwrap();
        let (kind, body) = decode_frame(&frame);
        assert_eq!(kind, "vm-live-attestation");
        assert_eq!(body, b"signed-live-attestation-bytes");
    }

    #[test]
    fn frame_body_is_carried_verbatim() {
        // The guest must not re-encode what the KBS signed — one
        // altered byte and vali's L0 signature check fails.
        let payload: Vec<u8> = (0u8..=255).collect();
        let frame = encode_frame(&payload).unwrap();
        let (_, body) = decode_frame(&frame);
        assert_eq!(body, payload);
    }

    #[test]
    fn oversize_payload_is_refused_not_truncated() {
        let huge = vec![0u8; MAX_FRAME_BYTES + 1];
        assert_eq!(encode_frame(&huge).unwrap_err(), RelayError::Encode);
    }

    #[test]
    fn writer_sink_emits_one_frame_per_push() {
        let sink = WriterSink(std::cell::RefCell::new(Vec::new()));
        sink.push(b"a").unwrap();
        sink.push(b"bb").unwrap();
        let buf = sink.0.into_inner();
        let first_len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        let (k1, b1) = decode_frame(&buf[..4 + first_len]);
        assert_eq!(k1, FRAME_KIND);
        assert_eq!(b1, b"a");
        let (k2, b2) = decode_frame(&buf[4 + first_len..]);
        assert_eq!(k2, FRAME_KIND);
        assert_eq!(b2, b"bb");
    }

    #[test]
    fn a_failing_sink_reports_io_not_encode() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("nope"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = WriterSink(std::cell::RefCell::new(Broken));
        assert_eq!(sink.push(b"x").unwrap_err(), RelayError::Io);
    }

    #[test]
    fn null_sink_never_fails() {
        assert!(NullSink.push(b"anything").is_ok());
    }
}
