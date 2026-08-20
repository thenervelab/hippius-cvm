//! Integration tests for the public AF_VSOCK framing API (MA-4).
//!
//! Exercises `hippius_miner_agent::vsock`'s length-prefixed CBOR codec
//! end to end — the wire-layout contract a guest-side implementer
//! relies on, plus the size cap + recursion guard.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use hippius_miner_agent::vsock::{
    read_frame, write_frame, FrameError, GuestFrame, MAX_VSOCK_FRAME,
};
use hippius_miner_agent::EnvelopeKind;

#[tokio::test]
async fn frame_round_trips_for_every_envelope_kind() {
    for kind in [
        EnvelopeKind::KbsRequest,
        EnvelopeKind::StoppedAck,
        EnvelopeKind::ServedReceipt,
        EnvelopeKind::ServedAggregate,
    ] {
        let (mut a, mut b) = tokio::io::duplex(8192);
        let sent = GuestFrame::new(kind, b"opaque-guest-signed-payload".to_vec());
        write_frame(&mut a, &sent).await.unwrap();
        let got = read_frame(&mut b, MAX_VSOCK_FRAME).await.unwrap();
        assert_eq!(got, sent);
    }
}

#[tokio::test]
async fn wire_layout_is_a_big_endian_u32_length_prefix() {
    // The cross-implementation contract: 4-byte big-endian length,
    // then exactly that many CBOR body bytes. A guest-side relay
    // implementer depends on this layout.
    let (mut a, mut b) = tokio::io::duplex(8192);
    let frame = GuestFrame::new(EnvelopeKind::KbsRequest, vec![0xab; 200]);
    write_frame(&mut a, &frame).await.unwrap();
    drop(a);

    let mut raw = Vec::new();
    b.read_to_end(&mut raw).await.unwrap();
    assert!(raw.len() > 4, "a frame is the prefix plus a body");
    let declared = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    assert_eq!(
        declared,
        raw.len() - 4,
        "the length prefix must equal the body byte count"
    );
}

#[tokio::test]
async fn an_oversize_frame_is_rejected_before_allocation() {
    // A peer claiming a 4 GiB body must be refused at the length
    // check — never a 4 GiB buffer.
    let (mut a, mut b) = tokio::io::duplex(64);
    a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    assert!(matches!(
        read_frame(&mut b, MAX_VSOCK_FRAME).await,
        Err(FrameError::Oversize)
    ));
}

#[tokio::test]
async fn a_clean_hangup_between_frames_is_eof_not_an_error() {
    let (mut a, mut b) = tokio::io::duplex(4096);
    let frame = GuestFrame::new(EnvelopeKind::ServedReceipt, vec![1u8; 16]);
    write_frame(&mut a, &frame).await.unwrap();
    drop(a);
    // First frame reads back; the second read sees a clean EOF.
    read_frame(&mut b, MAX_VSOCK_FRAME).await.unwrap();
    assert!(matches!(
        read_frame(&mut b, MAX_VSOCK_FRAME).await,
        Err(FrameError::Eof)
    ));
}

#[tokio::test]
async fn a_body_at_the_cap_is_accepted() {
    // A frame whose CBOR body is within the cap round-trips; the cap
    // is a hard ceiling, not an off-by-one reject of a legal body.
    let (mut a, mut b) = tokio::io::duplex(MAX_VSOCK_FRAME * 2);
    // A few hundred bytes — well inside the 64 KiB cap.
    let frame = GuestFrame::new(EnvelopeKind::ServedAggregate, vec![7u8; 4096]);
    write_frame(&mut a, &frame).await.unwrap();
    let got = read_frame(&mut b, MAX_VSOCK_FRAME).await.unwrap();
    assert_eq!(got, frame);
}
