//! Length-prefixed CBOR framing for the guest-CVM ↔ miner-agent
//! AF_VSOCK relay (MA-4).
//!
//! ## Wire format
//!
//! `u32` big-endian length prefix + a CBOR body. The body decodes
//! into one fixed-shape [`GuestFrame`] — `{kind, body}`. Identical
//! framing to the edge-gateway HA peer link
//! (`ha::peer_link::{read,write}_beat`, PR-H3/H5): the reader rejects
//! a zero or over-cap length **before** allocating the body buffer, so
//! a hostile or buggy guest cannot drive an unbounded allocation.
//!
//! ## Size cap + recursion guard, ordered before decode
//!
//! Two guards run before any structural CBOR parsing:
//!
//! 1. **Size cap** — the `u32` length is checked against `max_frame`
//!    ([`MAX_VSOCK_FRAME`] in production) before the body `Vec` is
//!    allocated.
//! 2. **Recursion guard** — the body is decoded **straight into the
//!    typed [`GuestFrame`]**, never into a `ciborium::Value`. A
//!    deeply-nested hostile CBOR document is therefore rejected at the
//!    first level whose major type does not match the struct field
//!    (`kind` is a small enum, `body` a byte string — both leaves), so
//!    the decoder never descends an attacker-controlled nesting depth
//!    and cannot be driven to a stack overflow.
//!
//! ## What the frame does NOT carry
//!
//! There is no `vm_id` field. The relayed CVM's identity is derived
//! from the **connection's AF_VSOCK context id** — a value the
//! miner-agent itself assigned at launch (`vsock::peer::CidAllocator`)
//! — never from anything the guest declares. A hostile guest cannot
//! forge another tenant's identity by lying in a frame field, because
//! there is no such field to lie in.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::edge_client::EnvelopeKind;

/// Production cap on one guest frame — 64 KiB. A KBS release request
/// (COSE ticket + SNP report + nonce) is a few KiB; 64 KiB is generous
/// head-room while still bounding a single hostile allocation hard.
pub const MAX_VSOCK_FRAME: usize = 64 * 1024;

/// One message a tenant guest CVM relays through the miner-agent.
///
/// `kind` routes the frame (the miner-agent forwards it to the Edge as
/// an envelope of that kind); `body` is the already-signed inner
/// payload and is **opaque** to the miner-agent — exactly the §5.6
/// opacity the Edge gateway keeps, one hop earlier. The miner-agent
/// never decodes `body`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestFrame {
    /// Which `Miner → Inner` envelope kind this frame carries.
    pub kind: EnvelopeKind,
    /// The opaque, guest-signed payload bytes. Never decoded here.
    pub body: ByteBuf,
}

impl GuestFrame {
    /// Construct a frame for `kind` carrying `body`.
    pub fn new(kind: EnvelopeKind, body: Vec<u8>) -> Self {
        Self {
            kind,
            body: ByteBuf::from(body),
        }
    }
}

/// Stable static-classifier errors for the vsock frame codec. Same
/// `&'static str`-only `Display` discipline as the crate's
/// [`crate::error::MinerAgentError`] — a framing failure can never
/// echo a body byte into a log line.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The peer closed the connection cleanly between frames — the
    /// normal end of a relay session, not an error condition.
    #[error("vsock-frame/eof")]
    Eof,
    /// The length prefix named a frame larger than the cap — rejected
    /// before any body buffer was allocated.
    #[error("vsock-frame/oversize")]
    Oversize,
    /// The length prefix was zero — a frame carries at least the CBOR
    /// map header, so zero is malformed.
    #[error("vsock-frame/zero-length")]
    ZeroLength,
    /// The body was not a well-formed [`GuestFrame`] — bad CBOR, a
    /// wrong field type, a missing or unknown field.
    #[error("vsock-frame/decode")]
    Decode,
    /// A [`GuestFrame`] could not be CBOR-encoded, or exceeded the
    /// `u32` length prefix.
    #[error("vsock-frame/encode")]
    Encode,
    /// A transport read/write failed (not a clean EOF).
    #[error("vsock-frame/io")]
    Io,
}

impl FrameError {
    /// The static classifier — identical to the `Display` impl. For
    /// the relay's structured log lines.
    pub fn class(&self) -> &'static str {
        match self {
            FrameError::Eof => "vsock-frame/eof",
            FrameError::Oversize => "vsock-frame/oversize",
            FrameError::ZeroLength => "vsock-frame/zero-length",
            FrameError::Decode => "vsock-frame/decode",
            FrameError::Encode => "vsock-frame/encode",
            FrameError::Io => "vsock-frame/io",
        }
    }
}

/// Read + decode one length-prefixed [`GuestFrame`].
///
/// Generic over [`AsyncRead`] so the codec — and its known-answer
/// tests — run on any host with `tokio::io::duplex`; only the real
/// `VsockListener` bind is Linux-only. A zero or `> max_frame` length
/// is rejected before the body buffer is allocated. A clean hang-up
/// between frames surfaces as [`FrameError::Eof`].
pub async fn read_frame<R>(reader: &mut R, max_frame: usize) -> Result<GuestFrame, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        // No bytes (or a partial prefix) before the peer closed — the
        // ordinary end of a session. Distinguished from a mid-body
        // failure so the relay loop can stop quietly, not log an error.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Eof),
        Err(_) => return Err(FrameError::Io),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    // Size cap BEFORE any allocation — a hostile length cannot drive
    // an unbounded `Vec`.
    if len == 0 {
        return Err(FrameError::ZeroLength);
    }
    if len > max_frame {
        return Err(FrameError::Oversize);
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| FrameError::Io)?;
    // Decode straight into the typed struct — never `ciborium::Value`
    // — so a deeply-nested document is rejected at the first wrong
    // major type rather than recursed (see the module docs).
    ciborium::de::from_reader(body.as_slice()).map_err(|_| FrameError::Decode)
}

/// Encode + write one [`GuestFrame`] as a length-prefixed CBOR frame.
///
/// Generic over [`AsyncWrite`] for the same cross-platform-test
/// reason as [`read_frame`].
pub async fn write_frame<W>(writer: &mut W, frame: &GuestFrame) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
{
    let mut body = Vec::new();
    ciborium::ser::into_writer(frame, &mut body).map_err(|_| FrameError::Encode)?;
    let len = u32::try_from(body.len()).map_err(|_| FrameError::Encode)?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|_| FrameError::Io)?;
    writer.write_all(&body).await.map_err(|_| FrameError::Io)?;
    writer.flush().await.map_err(|_| FrameError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let sent = GuestFrame::new(EnvelopeKind::KbsRequest, vec![7u8; 256]);
        write_frame(&mut a, &sent).await.unwrap();
        let got = read_frame(&mut b, MAX_VSOCK_FRAME).await.unwrap();
        assert_eq!(got, sent);
    }

    #[tokio::test]
    async fn every_kind_round_trips() {
        for kind in [
            EnvelopeKind::KbsRequest,
            EnvelopeKind::StoppedAck,
            EnvelopeKind::ServedReceipt,
            EnvelopeKind::ServedAggregate,
            EnvelopeKind::VmLiveAttestation,
        ] {
            let (mut a, mut b) = tokio::io::duplex(4096);
            let sent = GuestFrame::new(kind, vec![1u8; 8]);
            write_frame(&mut a, &sent).await.unwrap();
            assert_eq!(read_frame(&mut b, MAX_VSOCK_FRAME).await.unwrap(), sent);
        }
    }

    #[tokio::test]
    async fn oversize_length_is_rejected_before_allocation() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        assert!(matches!(
            read_frame(&mut b, 4096).await,
            Err(FrameError::Oversize)
        ));
    }

    #[tokio::test]
    async fn zero_length_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&0u32.to_be_bytes()).await.unwrap();
        assert!(matches!(
            read_frame(&mut b, 4096).await,
            Err(FrameError::ZeroLength)
        ));
    }

    #[tokio::test]
    async fn clean_hangup_surfaces_eof() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(matches!(
            read_frame(&mut b, 4096).await,
            Err(FrameError::Eof)
        ));
    }

    #[tokio::test]
    async fn garbage_body_fails_decode_not_panic() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let junk = [0xffu8, 0xff, 0xff];
        a.write_all(&(junk.len() as u32).to_be_bytes())
            .await
            .unwrap();
        a.write_all(&junk).await.unwrap();
        assert!(matches!(
            read_frame(&mut b, 4096).await,
            Err(FrameError::Decode)
        ));
    }

    #[tokio::test]
    async fn deeply_nested_cbor_is_rejected_not_recursed() {
        // A 4096-deep nested CBOR array. The typed decode targets a
        // struct — `deserialize_struct` expects a map, so ciborium
        // rejects the array header on the FIRST byte, never descending
        // the nesting (and its own 256-deep recursion limit is the
        // backstop for any path that would). The body fits a 128 KiB
        // duplex so the whole frame is written before the read.
        let (mut a, mut b) = tokio::io::duplex(128 * 1024);
        let mut nested = vec![0x9fu8; 4096]; // 4096 × indefinite-array start
        nested.resize(8192, 0xffu8); // append 4096 × break
        a.write_all(&(nested.len() as u32).to_be_bytes())
            .await
            .unwrap();
        a.write_all(&nested).await.unwrap();
        drop(a);
        assert!(matches!(
            read_frame(&mut b, MAX_VSOCK_FRAME).await,
            Err(FrameError::Decode)
        ));
    }

    #[tokio::test]
    async fn unknown_field_in_frame_is_rejected() {
        // `deny_unknown_fields`: a guest that smuggles an extra key
        // gets the frame dropped, not silently accepted.
        let mut body = Vec::new();
        let v = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("kind".into()),
                ciborium::value::Value::Text("kbs-request".into()),
            ),
            (
                ciborium::value::Value::Text("body".into()),
                ciborium::value::Value::Bytes(vec![1, 2, 3]),
            ),
            (
                ciborium::value::Value::Text("extra".into()),
                ciborium::value::Value::Integer(0.into()),
            ),
        ]);
        ciborium::ser::into_writer(&v, &mut body).unwrap();
        let (mut a, mut b) = tokio::io::duplex(4096);
        a.write_all(&(body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        a.write_all(&body).await.unwrap();
        assert!(matches!(
            read_frame(&mut b, MAX_VSOCK_FRAME).await,
            Err(FrameError::Decode)
        ));
    }

    #[test]
    fn frame_error_class_matches_display() {
        for e in [
            FrameError::Eof,
            FrameError::Oversize,
            FrameError::ZeroLength,
            FrameError::Decode,
            FrameError::Encode,
            FrameError::Io,
        ] {
            assert_eq!(e.class(), e.to_string());
        }
    }
}
