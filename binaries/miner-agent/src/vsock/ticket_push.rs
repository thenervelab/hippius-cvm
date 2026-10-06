//! Host→guest vsock push of the L1-minted `OrderTicket` COSE envelope.
//!
//! Counterpart to `binaries/agent-initramfs/src/stages/ticket_vsock.rs`
//! on the guest side. The protocol constants
//! ([`hippius_types::ticket_vsock`]) are shared so the two crates
//! cannot drift on the port number, the length-frame cap, or the
//! boot-race timeouts.
//!
//! ## Why a runtime push (not a measured surface)
//!
//! Kernel cmdline and any `-fw_cfg` blob both fold into the §22
//! `launch_digest` — per-launch ticket bytes there would explode the
//! allowlist (one entry per launch, untenable at marketplace scale).
//! Vsock is a runtime channel; the AMD SP never sees these bytes.
//!
//! ## Wire format (one-shot per connection)
//!
//! - `u32` BE length prefix (matches the existing guest→host relay
//!   framing in [`crate::vsock::frame`]).
//! - That many raw COSE_Sign1 bytes (already canonical CBOR with the
//!   L1 signature — forwarded byte-for-byte; the agent never decodes).
//! - Sender closes after writing. The guest reads one frame and closes.
//!
//! ## Boot-race handling
//!
//! The miner-agent reaches `Running` the moment libvirt reports the
//! domain has started; the guest's `/init` (= agent-initramfs PID 1)
//! then needs ~1–3 s before its vsock listener is ready (kernel boot,
//! initramfs mount, vsock listen prep).
//! The push retries `connect(2)` on `ECONNREFUSED` with a small
//! back-off until the
//! [`hippius_types::ticket_vsock::PUSH_TIMEOUT_SECS`] budget runs out,
//! then fails closed with `MinerAgentError::TicketDelivery("connect-timeout")`.

use std::time::Duration;

use async_trait::async_trait;
use hippius_types::ticket_vsock::{MAX_TICKET_BYTES, PUSH_TIMEOUT_SECS};
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, Instant};

use crate::error::{MinerAgentError, Result};

/// Host→guest ticket push, injected through [`crate::orders::OrderState`]
/// so the integration tests can swap in a [`MockTicketPusher`] (no real
/// vsock connect required). Production wires [`VsockTicketPusher`].
#[async_trait]
pub trait TicketPusher: Send + Sync {
    /// Push `cose` to the guest at AF_VSOCK `(cid, port)`. The contract
    /// (empty / oversize guards + boot-race retry + the `&'static str`
    /// failure classes) is shared by both impls — the mock simply
    /// short-circuits the network bits.
    async fn push(&self, cid: u32, port: u32, cose: &[u8]) -> Result<()>;

    /// [`Self::push`], but only while `still_owner()` holds — checked
    /// before the first connect, before every boot-race reconnect, and
    /// once more before a single ticket byte is written. A `false` fails
    /// closed with `TicketDelivery("cid-not-owned")`.
    ///
    /// A CID names whichever guest holds it NOW, not the VM the ticket
    /// was minted for: the moment that VM is stopped its CID is free, and
    /// the next launch gets it. A push that keeps (re)connecting past that
    /// point lands in the NEW tenant's initramfs listener, which consumes
    /// the foreign ticket, gets a KBS 403, and never retries — the new VM
    /// is bricked and another tenant's signed ticket leaked into it
    /// (observed live 2026-09-24 on every CID reuse). Callers pass a
    /// guard that re-resolves "does this CID still belong to the VM whose
    /// ticket this is".
    ///
    /// The default only checks once up front — right for impls with no
    /// connect loop (the mock).
    async fn push_guarded(
        &self,
        cid: u32,
        port: u32,
        cose: &[u8],
        still_owner: &(dyn Fn() -> bool + Send + Sync),
    ) -> Result<()> {
        if !still_owner() {
            return Err(MinerAgentError::TicketDelivery("cid-not-owned"));
        }
        self.push(cid, port, cose).await
    }
}

/// Production [`TicketPusher`] — real AF_VSOCK `connect(2)` + framed
/// write. Linux only at the syscall layer; non-Linux dev builds still
/// run the empty / oversize guards so the misuse path is symmetric.
#[derive(Debug, Default, Clone, Copy)]
pub struct VsockTicketPusher;

impl VsockTicketPusher {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TicketPusher for VsockTicketPusher {
    async fn push(&self, cid: u32, port: u32, cose: &[u8]) -> Result<()> {
        push_ticket(cid, port, cose).await
    }

    async fn push_guarded(
        &self,
        cid: u32,
        port: u32,
        cose: &[u8],
        still_owner: &(dyn Fn() -> bool + Send + Sync),
    ) -> Result<()> {
        push_ticket_guarded(cid, port, cose, still_owner).await
    }
}

/// Test [`TicketPusher`] — short-circuits the network bits but keeps
/// the empty / oversize guards so integration tests still exercise
/// the producer-side preconditions. A successful push returns Ok;
/// a follow-up needs configurability, add an enum field.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockTicketPusher;

impl MockTicketPusher {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TicketPusher for MockTicketPusher {
    async fn push(&self, _cid: u32, _port: u32, cose: &[u8]) -> Result<()> {
        if cose.is_empty() {
            return Err(MinerAgentError::TicketDelivery("empty"));
        }
        if cose.len() > MAX_TICKET_BYTES {
            return Err(MinerAgentError::TicketDelivery("oversize"));
        }
        Ok(())
    }
}

/// Back-off between `connect(2)` attempts while the guest listener is
/// not yet ready. Small enough that the median launch sees the
/// listener on the first or second attempt; large enough that a
/// pathological boot does not spin the host CPU.
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Push the COSE-encoded OrderTicket to the guest at `(cid, port)`.
///
/// `cid` is the AF_VSOCK context id the lifecycle's `CidAllocator`
/// assigned to this VM at launch ([`crate::vsock::peer::CidAllocator`]);
/// `port` is the protocol-fixed [`hippius_types::ticket_vsock::PORT`]
/// (kept as a parameter so the unit tests on `tokio::io::duplex` can
/// drive the wire format without binding a real AF_VSOCK socket).
///
/// Fails closed on:
/// - `empty` — `cose` is empty (producer bug, see
///   [`crate::error::MinerAgentError::TicketDelivery`]);
/// - `oversize` — `cose.len() > MAX_TICKET_BYTES` (bounded so the
///   guest's frame guard can never see a length the cap would reject);
/// - `connect-timeout` — the guest never accepted within
///   `PUSH_TIMEOUT_SECS`;
/// - `write-failed` — the framed write erred mid-stream.
pub async fn push_ticket(cid: u32, port: u32, cose: &[u8]) -> Result<()> {
    push_ticket_guarded(cid, port, cose, &|| true).await
}

/// [`push_ticket`] gated on `still_owner` — see
/// [`TicketPusher::push_guarded`]. The guard runs before EVERY
/// `connect(2)` of the boot-race loop (which can spin for
/// `PUSH_TIMEOUT_SECS`, long enough for the CID to change hands) and
/// again between connect and write, so a push that outlives its VM
/// fails closed instead of reaching the CID's next owner.
#[cfg(target_os = "linux")]
pub async fn push_ticket_guarded(
    cid: u32,
    port: u32,
    cose: &[u8],
    still_owner: &(dyn Fn() -> bool + Send + Sync),
) -> Result<()> {
    use tokio_vsock::{VsockAddr, VsockStream};

    // Producer-side preconditions checked BEFORE any network I/O.
    if cose.is_empty() {
        return Err(MinerAgentError::TicketDelivery("empty"));
    }
    if cose.len() > MAX_TICKET_BYTES {
        return Err(MinerAgentError::TicketDelivery("oversize"));
    }

    let addr = VsockAddr::new(cid, port);
    deliver_guarded(
        || VsockStream::connect(addr),
        Duration::from_secs(PUSH_TIMEOUT_SECS),
        cose,
        still_owner,
    )
    .await
}

/// The transport-generic half of [`push_ticket_guarded`]: the boot-race
/// connect loop, the ownership re-checks, and the one-shot framed write.
/// Generic over the connector so the tests drive this exact sequence over
/// `tokio::io::duplex` (no AF_VSOCK on a CI runner).
///
/// `still_owner` is checked before every connect AND once more after the
/// connect succeeds — a connect is the moment the CID's CURRENT owner
/// answers, so ownership has to be re-proved between it and the write.
pub(crate) async fn deliver_guarded<S, F, Fut>(
    mut connect: F,
    budget: Duration,
    cose: &[u8],
    still_owner: &(dyn Fn() -> bool + Send + Sync),
) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<S>>,
{
    // Boot-race: retry connect until the deadline expires.
    let deadline = Instant::now() + budget;
    let mut stream = loop {
        if !still_owner() {
            return Err(MinerAgentError::TicketDelivery("cid-not-owned"));
        }
        match connect().await {
            Ok(s) => break s,
            Err(_) if Instant::now() < deadline => {
                sleep(CONNECT_RETRY_INTERVAL).await;
                continue;
            }
            Err(_) => return Err(MinerAgentError::TicketDelivery("connect-timeout")),
        }
    };
    if !still_owner() {
        return Err(MinerAgentError::TicketDelivery("cid-not-owned"));
    }

    // Framed write. `cose.len()` is bounded above to `MAX_TICKET_BYTES`
    // (≤ 8 KiB), so the `u32` cast can never truncate.
    let len = u32::try_from(cose.len()).map_err(|_| MinerAgentError::TicketDelivery("oversize"))?;
    write_framed(&mut stream, len, cose)
        .await
        .map_err(|_| MinerAgentError::TicketDelivery("write-failed"))?;
    // Drive the AsyncWrite shutdown (sends FIN) explicitly via the
    // trait — `VsockStream` ALSO carries an inherent `shutdown` taking
    // a `std::net::Shutdown`, and method resolution would pick that
    // instead. The half-close gives the guest's `read_exact` a clean
    // EOF after the body, matching the one-shot wire shape.
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
    Ok(())
}

/// Non-Linux dev hosts have no AF_VSOCK — the production push is a
/// no-op there (the dispatch path tolerates it; the live wire-up only
/// runs on a Linux miner).
#[cfg(not(target_os = "linux"))]
pub async fn push_ticket_guarded(
    _cid: u32,
    _port: u32,
    cose: &[u8],
    still_owner: &(dyn Fn() -> bool + Send + Sync),
) -> Result<()> {
    if !still_owner() {
        return Err(MinerAgentError::TicketDelivery("cid-not-owned"));
    }
    if cose.is_empty() {
        return Err(MinerAgentError::TicketDelivery("empty"));
    }
    if cose.len() > MAX_TICKET_BYTES {
        return Err(MinerAgentError::TicketDelivery("oversize"));
    }
    Ok(())
}

/// Generic framed write — `u32` BE length + body — extracted so the
/// unit tests can drive it through `tokio::io::duplex` without binding
/// AF_VSOCK. `len` is the caller-computed body length (bounded against
/// `MAX_TICKET_BYTES` BEFORE call so a hostile cast cannot reach here).
pub(crate) async fn write_framed<W>(writer: &mut W, len: u32, body: &[u8]) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// The wire shape is unambiguous: a single `u32` BE length prefix,
    /// then exactly that many bytes, then the writer closes. The
    /// guest's read_exact pulls the whole body in one call.
    #[tokio::test]
    async fn write_framed_emits_be_length_then_body() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let body = b"the-cose-ticket-bytes";
        write_framed(&mut a, body.len() as u32, body).await.unwrap();
        drop(a);

        let mut len_buf = [0u8; 4];
        b.read_exact(&mut len_buf).await.unwrap();
        assert_eq!(u32::from_be_bytes(len_buf) as usize, body.len());
        let mut got = vec![0u8; body.len()];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn push_ticket_rejects_empty_cose_before_any_io() {
        // No AF_VSOCK is touched — the empty guard runs first.
        let err = push_ticket(3, 0x4849, &[]).await.unwrap_err();
        assert!(matches!(err, MinerAgentError::TicketDelivery("empty")));
    }

    #[tokio::test]
    async fn push_ticket_rejects_oversize_cose_before_any_io() {
        let payload = vec![0u8; MAX_TICKET_BYTES + 1];
        let err = push_ticket(3, 0x4849, &payload).await.unwrap_err();
        assert!(matches!(err, MinerAgentError::TicketDelivery("oversize")));
    }

    /// The CID changes hands WHILE the push is connecting: the connect
    /// reaches the new owner's listener, so the ticket must not be
    /// written. The post-connect re-check is the only thing between the
    /// two — the pre-connect check had already passed.
    #[tokio::test]
    async fn ownership_lost_during_connect_writes_nothing() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let owned = Arc::new(AtomicBool::new(true));
        let (a, mut b) = tokio::io::duplex(4096);
        let mut a = Some(a);
        let flip = Arc::clone(&owned);
        let guard_owned = Arc::clone(&owned);
        let err = deliver_guarded(
            move || {
                flip.store(false, Ordering::SeqCst);
                let stream = a.take();
                async move { stream.ok_or_else(|| std::io::Error::other("reconnect")) }
            },
            Duration::from_secs(1),
            b"stale-ticket",
            &move || guard_owned.load(Ordering::SeqCst),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::TicketDelivery("cid-not-owned")
        ));
        let mut got = Vec::new();
        b.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty(), "a ticket byte reached the CID's new owner");
    }

    #[tokio::test]
    async fn an_owned_cid_gets_the_framed_ticket() {
        let (a, mut b) = tokio::io::duplex(4096);
        let mut a = Some(a);
        deliver_guarded(
            move || {
                let stream = a.take();
                async move { stream.ok_or_else(|| std::io::Error::other("reconnect")) }
            },
            Duration::from_secs(1),
            b"own-ticket",
            &|| true,
        )
        .await
        .unwrap();
        let mut got = Vec::new();
        b.read_to_end(&mut got).await.unwrap();
        assert_eq!(&got[4..], b"own-ticket");
    }
}
