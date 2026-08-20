//! The host-attestor **nonce-challenge** client (blackbox host-attestor
//! chantier PR-10).
//!
//! Before enrolling, the attestor pulls a **vali-chosen, single-use,
//! freshness-bounded** nonce for `REPORT_DATA[0..32]`. It dials the host
//! miner-agent on
//! [`hippius_types::host_attestor_challenge::CHALLENGE_PORT`], sends a
//! [`HostChallengeRequest`] carrying its signer public key, and reads back
//! a [`HostChallengeResponse`] carrying the minted nonce (the miner relays
//! the request up to vali via the Edge and the nonce back down — see
//! `binaries/miner-agent/src/vsock/host_challenge.rs`).
//!
//! ## Fail-closed
//!
//! A guest-generated enrollment nonce is exactly the replay hole PR-10
//! closes, so there is **no local fallback**: if the fresh nonce cannot be
//! fetched (no channel / bad response / timeout) this returns an error and
//! the caller fails the enrollment (the process exits non-zero). The
//! transport is one request → one response per connection, `u32`-big-endian
//! length-prefixed canonical CBOR — the same framing as
//! [`crate::vsock_pusher`].
//!
//! Synchronous (no tokio) to match the rest of the agent. The core
//! [`fetch_nonce_over`] is generic over any [`Read`] + [`Write`] stream so
//! it is unit-tested without a real vsock.

use std::io::{Read, Write};

use hippius_types::host_attestor_challenge::{
    HostChallengeRequest, HostChallengeResponse, MAX_CHALLENGE_FRAME_BYTES, NONCE_LEN, PUBKEY_LEN,
};

use crate::error::{HostAttestorError, Result};

/// The vali-minted enrollment challenge the guest pulls before enrolling:
/// the single-use `nonce` (→ `REPORT_DATA[0..32]`) AND the `node_id` vali
/// stamped from the miner's mTLS peer identity (PR-10b-S2a wire
/// amendment). The guest CANNOT read its `node_id` from the measured
/// cmdline (that would make the measurement per-node), so it receives it
/// here and uses it for BOTH the enrollment `node_id` and the
/// `REPORT_DATA[32..64]` binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostChallenge {
    /// The vali-minted single-use enrollment nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The vali-stamped host `node_id` (from the miner's mTLS peer
    /// identity — never a guest/miner body-declared value).
    pub node_id: String,
}

/// Fetch one fresh vali-minted challenge over an already-connected
/// `stream`.
///
/// Writes the length-prefixed canonical-CBOR [`HostChallengeRequest`] for
/// `signer_pubkey`, then reads the length-prefixed
/// [`HostChallengeResponse`] and returns its `{nonce, node_id}`. Fails
/// closed on any I/O / framing / decode error — never a locally-generated
/// value.
pub fn fetch_challenge_over<S: Read + Write>(
    stream: &mut S,
    signer_pubkey: &[u8; PUBKEY_LEN],
) -> Result<HostChallenge> {
    let request = HostChallengeRequest::new(*signer_pubkey)
        .canonical()
        .map_err(|_| HostAttestorError::Nonce("challenge-encode"))?;
    write_framed(stream, &request)?;

    let body = read_framed(stream, MAX_CHALLENGE_FRAME_BYTES)?;
    let response = HostChallengeResponse::decode(&body)
        .map_err(|_| HostAttestorError::Nonce("challenge-decode"))?;
    Ok(HostChallenge {
        nonce: response.nonce,
        node_id: response.node_id,
    })
}

/// Dial the host miner-agent's challenge listener and fetch one fresh
/// challenge (nonce + node_id). Linux-only — `AF_VSOCK` is a Linux socket
/// family.
#[cfg(target_os = "linux")]
pub fn fetch_challenge_vsock(
    cid: u32,
    port: u32,
    signer_pubkey: &[u8; PUBKEY_LEN],
) -> Result<HostChallenge> {
    use std::time::Duration;

    use hippius_types::host_attestor_challenge::CHALLENGE_TIMEOUT_SECS;

    let timeout = Duration::from_secs(CHALLENGE_TIMEOUT_SECS);
    let stream = vsock::VsockStream::connect_with_cid_port(cid, port)
        .map_err(|_| HostAttestorError::Nonce("challenge-connect"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| HostAttestorError::Nonce("challenge-set-timeout"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| HostAttestorError::Nonce("challenge-set-timeout"))?;
    let mut stream = stream;
    fetch_challenge_over(&mut stream, signer_pubkey)
}

/// Write a `u32`-big-endian length prefix + `body`, then flush.
fn write_framed<W: Write>(writer: &mut W, body: &[u8]) -> Result<()> {
    let len =
        u32::try_from(body.len()).map_err(|_| HostAttestorError::Nonce("challenge-oversize"))?;
    writer
        .write_all(&len.to_be_bytes())
        .map_err(|_| HostAttestorError::Nonce("challenge-write"))?;
    writer
        .write_all(body)
        .map_err(|_| HostAttestorError::Nonce("challenge-write"))?;
    writer
        .flush()
        .map_err(|_| HostAttestorError::Nonce("challenge-flush"))?;
    Ok(())
}

/// Read a `u32`-big-endian length prefix + that many bytes (capped).
fn read_framed<R: Read>(reader: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .map_err(|_| HostAttestorError::Nonce("challenge-read-length"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > max {
        return Err(HostAttestorError::Nonce("challenge-length"));
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .map_err(|_| HostAttestorError::Nonce("challenge-read-body"))?;
    Ok(body)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A stream whose reads drain a canned response and whose writes are
    /// captured — enough for `fetch_nonce_over`'s write-then-read shape.
    struct MockStream {
        to_read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.to_read.read(buf)
        }
    }
    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn fetches_the_minted_nonce_and_node_id_and_sends_the_pubkey() {
        let nonce = [0x11u8; NONCE_LEN];
        let response = HostChallengeResponse::new(nonce, "node-host-7".into(), 1_800_000_900)
            .canonical()
            .unwrap();
        let mut stream = MockStream {
            to_read: Cursor::new(framed(&response)),
            written: Vec::new(),
        };
        let pk = [0x22u8; PUBKEY_LEN];
        let got = fetch_challenge_over(&mut stream, &pk).unwrap();
        assert_eq!(got.nonce, nonce);
        // The node_id rides the response — the guest uses it for enrollment
        // (never sourced from the measured cmdline).
        assert_eq!(got.node_id, "node-host-7");

        // The request we sent is a well-formed HostChallengeRequest for pk.
        let sent_len = u32::from_be_bytes(stream.written[..4].try_into().unwrap()) as usize;
        let sent = &stream.written[4..4 + sent_len];
        let req = HostChallengeRequest::decode(sent).unwrap();
        assert_eq!(req.signer_pubkey, pk);
    }

    #[test]
    fn rejects_a_non_response_body() {
        let mut stream = MockStream {
            to_read: Cursor::new(framed(b"not-cbor")),
            written: Vec::new(),
        };
        let err = fetch_challenge_over(&mut stream, &[0x22; PUBKEY_LEN]).unwrap_err();
        assert_eq!(err.class(), "challenge-decode");
    }

    #[test]
    fn rejects_a_truncated_frame() {
        // A length prefix promising more than the body → read-body fails.
        let mut bytes = 100u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 4]);
        let mut stream = MockStream {
            to_read: Cursor::new(bytes),
            written: Vec::new(),
        };
        assert!(fetch_challenge_over(&mut stream, &[0x22; PUBKEY_LEN]).is_err());
    }

    #[test]
    fn rejects_an_oversize_length_prefix() {
        let bytes = ((MAX_CHALLENGE_FRAME_BYTES + 1) as u32)
            .to_be_bytes()
            .to_vec();
        let mut stream = MockStream {
            to_read: Cursor::new(bytes),
            written: Vec::new(),
        };
        assert!(fetch_challenge_over(&mut stream, &[0x22; PUBKEY_LEN]).is_err());
    }
}
