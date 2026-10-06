//! Stage 1.b — accept the host-pushed COSE OrderTicket over AF_VSOCK.
//!
//! Counterpart to the producer in
//! `binaries/miner-agent/src/vsock/ticket_push.rs`. The protocol
//! constants ([`hippius_types::ticket_vsock`]) — port, length cap,
//! accept timeout — are shared so the two crates cannot drift.
//!
//! ## Why a runtime channel
//!
//! The OrderTicket carries per-launch tenant bindings (`vm_id`,
//! `tenant_id`, `lease_id`, `vm_generation`). It MUST NOT ride the
//! kernel cmdline or any `-fw_cfg` blob: those are folded into the
//! §22 `launch_digest`, so per-launch ticket bytes there would
//! explode the allowlist. Vsock is measurement-neutral.
//!
//! ## Wire format (one-shot per connection)
//!
//! - `u32` BE length prefix (matches the existing relay framing in
//!   `binaries/miner-agent/src/vsock/frame.rs` — same endian, same
//!   size-cap-before-allocation discipline).
//! - That many raw COSE_Sign1 bytes (already canonical CBOR with
//!   the L1 signature — `ticket::Ticket::from_cose` decodes).
//! - Host closes after writing; we read one frame and close.
//!
//! ## §20 logging discipline
//!
//! All error classes are compile-time `&'static str` literals
//! (enforced crate-wide by `tests/no_seed_logging.rs`). Sub-classes:
//! `bind` / `listen` / `accept-timeout` / `accept-failed` /
//! `read-length` / `oversize` / `read-body` / `wrong-source`.

#![allow(dead_code)] // `read_framed` is exercised by unit tests on a duplex stream; the
                     // `recv_ticket` entry point uses it via the real VsockListener path.

use std::io::Read;
use std::time::Duration;

use hippius_types::ticket_vsock::{ACCEPT_TIMEOUT_SECS, MAX_TICKET_BYTES};

use crate::pipeline::AgentError;

/// AF_VSOCK CID `2` is the host (the source the miner-agent connects
/// from). A connection from any other CID is suspicious enough to
/// refuse, even though the host's vsock routing should make it
/// impossible in practice. Belt-and-braces. Matches the §H peer-pin
/// discipline applied at other trust boundaries.
const EXPECTED_HOST_CID: u32 = 2;

/// Receive one host-pushed COSE OrderTicket on `(VMADDR_CID_ANY, port)`.
///
/// Blocks until either a connection arrives + a framed body is read,
/// or [`ACCEPT_TIMEOUT_SECS`] elapses. Returns the raw COSE bytes —
/// no decode — so the caller stays single-source for the
/// `Ticket::from_cose` parsing path (and so a test can drive this
/// function with arbitrary bytes).
///
/// Fail-classes are static, see the module docs.
#[cfg(target_os = "linux")]
pub fn recv_ticket(port: u32) -> Result<Vec<u8>, AgentError> {
    use std::io::ErrorKind;
    use std::time::Instant;
    use vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    let addr = VsockAddr::new(VMADDR_CID_ANY, port);
    let listener = VsockListener::bind(&addr).map_err(|_| AgentError::Ticket("vsock-bind"))?;

    // Real timeout enforcement: `vsock::VsockListener::accept` blocks
    // forever in blocking mode (`set_read_timeout` only affects an
    // ACCEPTED stream, not the listener's `accept(2)` itself — review
    // r1 P2). Use non-blocking + a sleep-poll loop bounded by
    // `ACCEPT_TIMEOUT_SECS` so a host that never connects (crashed
    // miner-agent, mis-allocated CID, dispatch aborted before push)
    // fails closed inside the budget rather than hanging the
    // initramfs.
    listener
        .set_nonblocking(true)
        .map_err(|_| AgentError::Ticket("vsock-listen"))?;
    let deadline = Instant::now() + Duration::from_secs(ACCEPT_TIMEOUT_SECS);
    let (mut stream, peer) = loop {
        match listener.accept() {
            Ok(pair) => break pair,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(AgentError::Ticket("vsock-accept-timeout"));
                }
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(_) => return Err(AgentError::Ticket("vsock-accept-failed")),
        }
    };

    // Mirror the host peer-pin discipline: refuse anything that did
    // not come from AF_VSOCK CID 2 (the host). The host's kernel
    // makes a non-CID-2 source infeasible in practice, but this is
    // belt-and-braces — same pattern as the §H peer-pin elsewhere.
    if peer.cid() != EXPECTED_HOST_CID {
        return Err(AgentError::Ticket("vsock-wrong-source"));
    }

    // The accepted stream is non-blocking by inheritance — switch it
    // BACK to blocking and pin a read timeout so `read_framed`'s
    // `read_exact` does not spin on `WouldBlock` and does not hang
    // either.
    stream
        .set_nonblocking(false)
        .map_err(|_| AgentError::Ticket("vsock-listen"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(ACCEPT_TIMEOUT_SECS)))
        .map_err(|_| AgentError::Ticket("vsock-listen"))?;

    read_framed(&mut stream)
}

/// Sleep slice between non-blocking `accept` polls. Small enough that
/// the median launch sees the host's first `connect` on the first or
/// second poll; large enough that a slow boot does not spin the CPU.
#[cfg(target_os = "linux")]
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Non-Linux dev hosts have no AF_VSOCK — return a static error so
/// the pipeline fails closed (the dev path uses a file-backed ticket
/// loader rather than this one; see `ticket::load`).
#[cfg(not(target_os = "linux"))]
pub fn recv_ticket(_port: u32) -> Result<Vec<u8>, AgentError> {
    Err(AgentError::Ticket("vsock-bind"))
}

/// Generic framed read — `u32` BE length + body — extracted so unit
/// tests can drive it through any `Read` impl (cursor / pipe).
pub(crate) fn read_framed<R: Read>(reader: &mut R) -> Result<Vec<u8>, AgentError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .map_err(|_| AgentError::Ticket("vsock-read-length"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    // Size cap BEFORE allocation — a hostile length cannot drive an
    // unbounded `Vec`. Same ordered-guard discipline as
    // `binaries/miner-agent/src/vsock/frame.rs::read_frame`.
    if len == 0 {
        return Err(AgentError::Ticket("vsock-read-length"));
    }
    if len > MAX_TICKET_BYTES {
        return Err(AgentError::Ticket("vsock-oversize"));
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .map_err(|_| AgentError::Ticket("vsock-read-body"))?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_framed_returns_the_body_bytes() {
        let body = b"the-cose-ticket-bytes-go-here";
        let mut wire = Vec::new();
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(body);
        let mut cur = Cursor::new(wire);
        let got = read_framed(&mut cur).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_framed_rejects_zero_length() {
        let mut cur = Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(matches!(
            read_framed(&mut cur),
            Err(AgentError::Ticket("vsock-read-length"))
        ));
    }

    #[test]
    fn read_framed_rejects_oversize_before_allocation() {
        // A length one byte over the cap. We never allocate the body —
        // the guard rejects on the length alone.
        let oversize = (MAX_TICKET_BYTES as u32 + 1).to_be_bytes();
        let mut cur = Cursor::new(oversize.to_vec());
        assert!(matches!(
            read_framed(&mut cur),
            Err(AgentError::Ticket("vsock-oversize"))
        ));
    }

    #[test]
    fn read_framed_rejects_truncated_body() {
        // Length says 10 bytes, body delivers 3.
        let mut wire = Vec::new();
        wire.extend_from_slice(&10u32.to_be_bytes());
        wire.extend_from_slice(&[1, 2, 3]);
        let mut cur = Cursor::new(wire);
        assert!(matches!(
            read_framed(&mut cur),
            Err(AgentError::Ticket("vsock-read-body"))
        ));
    }
}
