//! The guest-CVM → Edge relay loop (MA-4).
//!
//! Once a guest connection has been resolved to a tenant [`GuestPeer`]
//! (the connection's AF_VSOCK context id mapped back to a `VmId` —
//! `vsock::peer`), [`relay_guest_frames`] drains length-prefixed
//! [`GuestFrame`]s off it and forwards each to the Edge gateway as an
//! envelope of the frame's declared kind.
//!
//! ## Opaque relay
//!
//! The miner-agent is, for guest traffic, an opaque relay one hop
//! before the Edge: it routes on the frame `kind` and never decodes
//! the `body`. Nothing derived from a frame body is ever logged — a
//! relay log line carries the tenant `vm_id`, the envelope `kind`, and
//! a static outcome class, never a payload byte.
//!
//! ## Edge forward (MA-3, wired)
//!
//! [`crate::edge_client::EdgeClient::send_envelope`] POSTs the opaque
//! frame body to the Edge over the miner→Edge mTLS transport. A forward
//! failure (transport / non-2xx) is logged + counted, never fatal — the
//! guest's at-least-once buffer retries and one wedged relay must not
//! kill the session.

use std::time::Duration;

use tokio::io::AsyncRead;
use tokio_util::sync::CancellationToken;

use crate::edge_client::EdgeClient;

use super::frame::{read_frame, FrameError, GuestFrame};
use super::peer::GuestPeer;

/// Why a relay loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayOutcome {
    /// The guest closed the connection cleanly between frames.
    Closed,
    /// No frame arrived within the idle timeout — the connection is
    /// dropped so a silent guest cannot park a handler task.
    IdleTimeout,
    /// A shutdown was signalled — the loop stopped draining.
    Cancelled,
    /// A frame was malformed (the static [`FrameError`] class).
    FrameError(&'static str),
}

/// The result of one relay session — frame counters plus the reason
/// the loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayReport {
    /// Frames successfully decoded off the connection.
    pub frames_read: u64,
    /// Frames the Edge gateway accepted (`send_envelope` returned
    /// `Ok`). `0` when the Edge send fails (dead endpoint / non-2xx).
    pub frames_forwarded: u64,
    /// Why the loop stopped.
    pub outcome: RelayOutcome,
}

/// Drain [`GuestFrame`]s off `reader` and forward each to the Edge.
///
/// Generic over [`AsyncRead`] so the loop runs against
/// `tokio::io::duplex` in tests and a real `VsockStream` in
/// production. Returns when the guest hangs up, a frame is malformed,
/// the idle timeout elapses, or `cancel` fires.
pub async fn relay_guest_frames<R>(
    reader: &mut R,
    peer: &GuestPeer,
    edge: &EdgeClient,
    max_frame: usize,
    idle_timeout: Duration,
    cancel: &CancellationToken,
) -> RelayReport
where
    R: AsyncRead + Unpin,
{
    let mut frames_read = 0u64;
    let mut frames_forwarded = 0u64;
    loop {
        let frame = tokio::select! {
            // Shutdown — stop draining, leave the rest for the peer to
            // resend after it reconnects to the restarted agent.
            _ = cancel.cancelled() => {
                return RelayReport {
                    frames_read,
                    frames_forwarded,
                    outcome: RelayOutcome::Cancelled,
                };
            }
            // A frame, an error, or the idle deadline.
            read = tokio::time::timeout(idle_timeout, read_frame(reader, max_frame)) => {
                match read {
                    Err(_elapsed) => {
                        return RelayReport {
                            frames_read,
                            frames_forwarded,
                            outcome: RelayOutcome::IdleTimeout,
                        };
                    }
                    Ok(Ok(frame)) => frame,
                    // A clean hang-up is the ordinary end of a session.
                    Ok(Err(FrameError::Eof)) => {
                        return RelayReport {
                            frames_read,
                            frames_forwarded,
                            outcome: RelayOutcome::Closed,
                        };
                    }
                    // Any other framing fault drops the connection.
                    Ok(Err(err)) => {
                        log_relay(peer, "frame-error", err.class());
                        return RelayReport {
                            frames_read,
                            frames_forwarded,
                            outcome: RelayOutcome::FrameError(err.class()),
                        };
                    }
                }
            }
        };
        frames_read += 1;
        forward(peer, edge, &frame, &mut frames_forwarded).await;
    }
}

/// Forward one frame to the Edge over mTLS, logging the outcome class.
///
/// A failure is logged + counted, not fatal — the guest's at-least-once
/// buffer retries, and one wedged relay must not kill the session.
async fn forward(peer: &GuestPeer, edge: &EdgeClient, frame: &GuestFrame, forwarded: &mut u64) {
    match edge.send_envelope(frame.kind, &frame.body).await {
        Ok(()) => {
            *forwarded += 1;
            log_relay(peer, &format!("forward-{:?}", frame.kind), "ok");
        }
        Err(err) => {
            // `MinerAgentError`'s Display is a static classifier — no
            // body byte, no path is echoed.
            log_relay(peer, &format!("forward-{:?}", frame.kind), &err_class(&err));
        }
    }
}

/// The static classifier of a forward error, for the relay log line.
fn err_class(err: &crate::error::MinerAgentError) -> String {
    err.to_string()
}

/// Emit a relay log line — tenant id + a static event/class pair.
/// Never a body byte (§5.6 opacity).
fn log_relay(peer: &GuestPeer, event: &str, class: &str) {
    eprintln!(
        "hippius-miner-agent: vsock-relay: vm={} cid={} {event}={class}",
        peer.vm_id, peer.cid
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    use crate::edge_client::EnvelopeKind;
    use crate::lifecycle::VmId;
    use crate::vsock::frame::{write_frame, MAX_VSOCK_FRAME};

    fn edge() -> EdgeClient {
        EdgeClient::insecure_for_tests("http://127.0.0.1:1".to_string())
    }

    fn peer() -> GuestPeer {
        GuestPeer {
            cid: 7,
            vm_id: VmId::new("tenant-relay-1").unwrap(),
        }
    }

    #[tokio::test]
    async fn relays_every_frame_then_stops_on_clean_eof() {
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        // Write three frames, then close the writer.
        for _ in 0..3 {
            write_frame(
                &mut writer,
                &GuestFrame::new(EnvelopeKind::KbsRequest, vec![1u8; 32]),
            )
            .await
            .unwrap();
        }
        drop(writer);

        let cancel = CancellationToken::new();
        let report = relay_guest_frames(
            &mut reader,
            &peer(),
            &edge(),
            MAX_VSOCK_FRAME,
            Duration::from_secs(5),
            &cancel,
        )
        .await;
        assert_eq!(report.frames_read, 3);
        // The dead 127.0.0.1:1 endpoint refuses — nothing forwards.
        assert_eq!(report.frames_forwarded, 0);
        assert_eq!(report.outcome, RelayOutcome::Closed);
    }

    #[tokio::test]
    async fn malformed_frame_drops_the_connection() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        // A valid frame, then garbage.
        write_frame(
            &mut writer,
            &GuestFrame::new(EnvelopeKind::ServedReceipt, vec![9u8; 4]),
        )
        .await
        .unwrap();
        writer.write_all(&3u32.to_be_bytes()).await.unwrap();
        writer.write_all(&[0xff, 0xff, 0xff]).await.unwrap();
        drop(writer);

        let cancel = CancellationToken::new();
        let report = relay_guest_frames(
            &mut reader,
            &peer(),
            &edge(),
            MAX_VSOCK_FRAME,
            Duration::from_secs(5),
            &cancel,
        )
        .await;
        assert_eq!(report.frames_read, 1);
        assert!(matches!(report.outcome, RelayOutcome::FrameError(_)));
    }

    #[tokio::test]
    async fn a_frame_cut_mid_body_is_dropped_not_forwarded() {
        // A guest write interrupted mid-frame: the length prefix
        // promises 64 bytes, only 10 arrive before the connection
        // closes. The truncated frame must never be decoded or reach
        // `forward` — only the complete frame before it counts.
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        write_frame(
            &mut writer,
            &GuestFrame::new(EnvelopeKind::ServedReceipt, vec![9u8; 4]),
        )
        .await
        .unwrap();
        writer.write_all(&64u32.to_be_bytes()).await.unwrap();
        writer.write_all(&[0xa2; 10]).await.unwrap();
        drop(writer);

        let cancel = CancellationToken::new();
        let report = relay_guest_frames(
            &mut reader,
            &peer(),
            &edge(),
            MAX_VSOCK_FRAME,
            Duration::from_secs(5),
            &cancel,
        )
        .await;
        assert_eq!(report.frames_read, 1, "the truncated frame is not read");
        assert_eq!(report.outcome, RelayOutcome::FrameError("vsock-frame/io"));
    }

    #[tokio::test]
    async fn idle_connection_times_out() {
        // A peer that connects but never sends — the reader half is
        // held open, no frame ever arrives.
        let (_writer, mut reader) = tokio::io::duplex(64);
        let cancel = CancellationToken::new();
        let report = relay_guest_frames(
            &mut reader,
            &peer(),
            &edge(),
            MAX_VSOCK_FRAME,
            Duration::from_millis(20),
            &cancel,
        )
        .await;
        assert_eq!(report.frames_read, 0);
        assert_eq!(report.outcome, RelayOutcome::IdleTimeout);
    }

    #[tokio::test]
    async fn cancellation_stops_the_loop() {
        let (_writer, mut reader) = tokio::io::duplex(64);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let report = relay_guest_frames(
            &mut reader,
            &peer(),
            &edge(),
            MAX_VSOCK_FRAME,
            Duration::from_secs(5),
            &cancel,
        )
        .await;
        assert_eq!(report.outcome, RelayOutcome::Cancelled);
    }
}
