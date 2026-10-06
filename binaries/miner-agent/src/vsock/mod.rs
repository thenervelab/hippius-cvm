//! Guest-CVM ↔ miner-agent AF_VSOCK relay (MA-4).
//!
//! A tenant SEV-SNP CVM has no network of its own — it reaches the
//! control plane through the miner-agent. The transport is AF_VSOCK: a
//! virtio socket between the guest and the host, with no IP stack and
//! no exposure to the miner's untrusted network. Each CVM is launched
//! with a libvirt `<vsock>` device pinned to a context id the
//! miner-agent assigned ([`peer::CidAllocator`]); the guest connects
//! to the host on [`VSOCK_RELAY_PORT`], and the miner-agent maps the
//! connection's source CID back to the tenant `VmId`.
//!
//! ## Module layout
//!
//! - [`frame`] — length-prefixed CBOR framing (size cap + recursion
//!   guard before decode), generic over `AsyncRead`/`AsyncWrite` so
//!   the codec is cross-platform and unit-tested on any host;
//! - [`peer`] — the [`peer::CidAllocator`]: collision-free, idempotent
//!   CID assignment and the CID → `VmId` reverse map;
//! - [`per_cid`] — the per-guest cap on concurrent relay connections;
//! - [`relay`] — the per-connection drain loop that forwards each
//!   guest frame to the Edge gateway;
//! - this module — the AF_VSOCK accept loop ([`run_vsock_listener`],
//!   Linux-only) and the per-connection handler [`handle_guest_conn`]
//!   (generic, so it is exercised cross-platform).
//!
//! ## Cross-platform
//!
//! AF_VSOCK is a Linux facility — [`run_vsock_listener`] and the
//! `tokio-vsock` dependency are `cfg(target_os = "linux")`. Everything
//! else (framing, CID allocation, the relay loop, the connection
//! handler) is generic over `AsyncRead`, so `cargo test --workspace`
//! stays green on a macOS dev host.

pub mod frame;
pub mod guardian_relay;
pub mod host_challenge;
pub mod host_relay;
pub mod kbs_proxy;
pub mod peer;
pub mod per_cid;
pub mod relay;
pub mod ticket_push;
pub mod vm_progress;

use std::time::Duration;

// `Arc` is used only by the Linux-only `run_vsock_listener` signature
// + body; the cross-platform `handle_guest_conn` takes plain refs.
#[cfg(target_os = "linux")]
use std::sync::Arc;

use tokio::io::AsyncRead;
use tokio_util::sync::CancellationToken;

use crate::edge_client::EdgeClient;

pub use frame::{read_frame, write_frame, FrameError, GuestFrame, MAX_VSOCK_FRAME};
pub use kbs_proxy::{
    CustodyRelayGate, KbsBackend, KbsProxyOutcome, ProxyBackends, ReqwestKbsBackend,
};
pub use peer::{CidAllocator, CidOwner, GuestPeer, MAX_GUEST_CID, MIN_GUEST_CID};
pub use relay::{relay_guest_frames, RelayOutcome, RelayReport};
pub use vm_progress::{EdgeVmProgressSink, VmProgressSink};

/// AF_VSOCK port the miner-agent listens on for guest CVM connections.
/// The guest side dials `(VMADDR_CID_HOST, VSOCK_RELAY_PORT)`.
pub const VSOCK_RELAY_PORT: u32 = 5000;

/// How long a guest connection may sit without delivering a frame
/// before it is dropped — a connected-but-silent guest cannot park a
/// handler task indefinitely.
///
/// Kept well above the guest telemetry agent's receipt interval (60 s
/// by default). Guests baked before the pusher closed its own
/// connection after each push hold one connection open across
/// receipts; at a 60 s timeout the host's close raced every receipt —
/// a `connection-lost` in the guest every other receipt, and a frame
/// written in the instant before the reset reached the guest was lost
/// without either side noticing. Three intervals of slack keeps such a
/// connection alive while still bounding a silent one; how many silent
/// connections one guest can hold is bounded by [`MAX_CONNS_PER_GUEST`].
pub const VSOCK_IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// Maximum concurrent in-flight guest-connection handlers. A miner
/// hosts at most a few dozen CVMs; the cap stops a misbehaving guest
/// (or a CID-spoofing attempt) flooding the accept loop into task
/// exhaustion. A connection beyond the cap is shed at accept.
pub const MAX_INFLIGHT_GUEST_CONNS: usize = 256;

/// Maximum concurrent relay connections from ONE guest CID. Without it
/// a single hostile guest could hold every [`MAX_INFLIGHT_GUEST_CONNS`]
/// permit and lock its neighbours out of the relay. A well-behaved
/// guest holds at most two at once on this port (the telemetry pusher
/// and the keepalive), so four leaves headroom for a reconnect overlap.
pub const MAX_CONNS_PER_GUEST: usize = 4;

/// Handle one guest connection: resolve its CID, then relay its frames.
///
/// Generic over [`AsyncRead`] so it is exercised cross-platform with
/// `tokio::io::duplex`; the Linux listener passes a real `VsockStream`.
/// A connection whose source CID was never handed out by the allocator
/// is rejected without reading a byte — a guest cannot relay traffic
/// under an identity the miner-agent did not assign it.
pub async fn handle_guest_conn<S>(
    mut stream: S,
    src_cid: u32,
    allocator: &CidAllocator,
    edge: &EdgeClient,
    cancel: CancellationToken,
) where
    S: AsyncRead + Unpin,
{
    let peer = match allocator.owner_of(src_cid) {
        Ok(CidOwner::Verified(vm_id)) => GuestPeer {
            cid: src_cid,
            vm_id,
        },
        // Held on a re-adoption record the live domain XML has not yet
        // confirmed: the guest behind this CID may not be that VM, so its
        // frames must not be attributed to it. The guest reconnects; once
        // the CID is verified the relay resumes.
        Ok(CidOwner::Unverified(_)) => {
            log_listener("rejected", "cid-unverified");
            return;
        }
        // A CID with no tracked CVM — a guest that is not a tenant the
        // miner-agent launched, or a stale connection after a stop.
        Ok(CidOwner::Unknown) => {
            log_listener("rejected", "unknown-cid");
            return;
        }
        // The allocator lock was poisoned — fail closed.
        Err(_) => {
            log_listener("rejected", "cid-lookup");
            return;
        }
    };
    let report = relay::relay_guest_frames(
        &mut stream,
        &peer,
        edge,
        MAX_VSOCK_FRAME,
        VSOCK_IDLE_TIMEOUT,
        &cancel,
    )
    .await;
    eprintln!(
        "hippius-miner-agent: vsock-listener: session-end vm={} cid={} frames_read={} outcome={:?}",
        peer.vm_id, peer.cid, report.frames_read, report.outcome
    );
}

/// Static-class log line for a listener-lifecycle event.
fn log_listener(event: &'static str, class: &'static str) {
    eprintln!("hippius-miner-agent: vsock-listener: {event} {class}");
}

/// Run the AF_VSOCK accept loop until `cancel` fires (Linux only).
///
/// Mirrors the edge-gateway miner listener (PR-H7): each accepted
/// connection is handled on its own task tracked in a [`JoinSet`] —
/// not detached — so a shutdown drains in-flight relays; concurrency
/// is capped by a [`Semaphore`]. A bind failure is logged and the
/// relay is simply absent for this process — non-fatal, the orders
/// server (the agent's command channel) is the priority and runs
/// regardless.
///
/// [`JoinSet`]: tokio::task::JoinSet
/// [`Semaphore`]: tokio::sync::Semaphore
#[cfg(target_os = "linux")]
pub async fn run_vsock_listener(
    allocator: Arc<CidAllocator>,
    edge: Arc<EdgeClient>,
    cancel: CancellationToken,
) {
    use tokio::task::JoinSet;
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    // Bind for connections from any guest CID on the relay port.
    let addr = VsockAddr::new(VMADDR_CID_ANY, VSOCK_RELAY_PORT);
    let listener = match VsockListener::bind(addr) {
        Ok(listener) => listener,
        Err(_) => {
            log_listener("bind-error", "vsock-bind");
            return;
        }
    };
    log_listener("up", "vsock");

    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_GUEST_CONNS));
    let per_guest = per_cid::PerCidLimiter::new(MAX_CONNS_PER_GUEST);
    let mut conns: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                log_listener("shutdown", "vsock");
                break;
            }
            accepted = listener.accept() => {
                let (stream, addr) = match accepted {
                    Ok(pair) => pair,
                    // Transient accept error — back off so fd pressure
                    // cannot hot-spin the task.
                    Err(_) => {
                        log_listener("accept-error", "vsock");
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                let src_cid = addr.cid();
                // Per-guest share first, so a guest at its cap never
                // touches the global semaphore its neighbours rely on.
                let guest_permit = match per_guest.try_acquire(src_cid) {
                    Some(permit) => permit,
                    None => {
                        log_listener("rejected", "per-guest-cap");
                        drop(stream);
                        continue;
                    }
                };
                // Concurrency cap — shed beyond it without a handshake.
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        log_listener("rejected", "at-capacity");
                        drop(stream);
                        continue;
                    }
                };
                let allocator = Arc::clone(&allocator);
                let edge = Arc::clone(&edge);
                let cancel = cancel.clone();
                conns.spawn(async move {
                    let _permit = permit;
                    let _guest_permit = guest_permit;
                    handle_guest_conn(stream, src_cid, &allocator, &edge, cancel).await;
                });
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
    // Drain in-flight relays — each is idle-timeout-bounded and the
    // cancel token is already tripped, so this terminates.
    while conns.join_next().await.is_some() {}
    log_listener("drained", "vsock");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::edge_client::EnvelopeKind;
    use crate::lifecycle::VmId;
    use crate::vsock::frame::write_frame;

    fn edge() -> Arc<EdgeClient> {
        Arc::new(EdgeClient::insecure_for_tests(
            "http://127.0.0.1:1".to_string(),
        ))
    }

    #[tokio::test]
    async fn unknown_cid_is_rejected_without_reading() {
        // The allocator knows nothing about CID 42 — the handler must
        // reject the connection rather than relay it.
        let allocator = Arc::new(CidAllocator::new());
        let (mut writer, reader) = tokio::io::duplex(4096);
        // Even if the guest writes a frame, an unknown CID never relays.
        write_frame(
            &mut writer,
            &GuestFrame::new(EnvelopeKind::KbsRequest, vec![1u8; 8]),
        )
        .await
        .unwrap();
        handle_guest_conn(reader, 42, &allocator, &edge(), CancellationToken::new()).await;
        // No panic, no relay — the connection was dropped at CID check.
    }

    #[tokio::test]
    async fn known_cid_relays_the_session() {
        let allocator = Arc::new(CidAllocator::new());
        let vm = VmId::new("tenant-conn-1").unwrap();
        let cid = allocator.allocate(&vm).unwrap();
        // Known = created: a fresh allocation is not an identity until then.
        assert!(allocator.mark_verified(&vm, cid).unwrap());

        let (mut writer, reader) = tokio::io::duplex(8192);
        write_frame(
            &mut writer,
            &GuestFrame::new(EnvelopeKind::ServedReceipt, vec![3u8; 16]),
        )
        .await
        .unwrap();
        drop(writer);
        // Resolves CID → vm_id and drains the one frame to clean EOF.
        handle_guest_conn(reader, cid, &allocator, &edge(), CancellationToken::new()).await;
    }
}
