//! Host-attestor **nonce-challenge** vsock listener (blackbox host-attestor
//! chantier PR-10).
//!
//! The blackbox host-attestor (a diskless SNP Infra CVM) must fold a
//! **vali-chosen, single-use** nonce into its enrollment `REPORT_DATA` — a
//! guest-generated nonce would let a paused / migrated VM replay a
//! pre-generated enrollment report. This listener is the miner-side of the
//! fresh-nonce channel.
//!
//! ## Guest-initiated pull (mirrors [`super::kbs_proxy`])
//!
//! The attestor guest *dials* the host on
//! [`hippius_types::host_attestor_challenge::CHALLENGE_PORT`] and sends a
//! [`HostChallengeRequest`] `{signer_pubkey}`. The miner-agent relays it
//! UP to the Edge (`/v1/edge/host-attestor-challenge`) over its mTLS leg —
//! the Edge stamps the miner's `x-hippius-peer-id` so vali binds the nonce
//! to the miner's `node_id` (never a body-declared one). vali mints the
//! nonce and returns it; the miner encodes a [`HostChallengeResponse`] and
//! writes it back down the SAME connection.
//!
//! The miner never chooses the nonce and never persists it — it is a pure
//! relay + wire-translator (vali's JSON `{nonce_hex, expiry_unix}` → the
//! guest's canonical-CBOR response). vali is the sole nonce authority.
//!
//! ## No CID gate (by design)
//!
//! Unlike the KBS proxy (which releases tenant secrets and so gates on the
//! CID the agent assigned) this listener issues only a *nonce*, which is
//! worthless to anyone but the measured attestor guest: the nonce is bound
//! to a `signer_pubkey` that only a genuine SNP host-attestor report (at
//! the allowlisted host-attestor measurement) can carry into `REPORT_DATA`.
//! So a connection from any CID is accepted and forwarded; the src CID is
//! logged for ops. (Once the diskless Infra CVM is given a CID — PR-13 —
//! this can be tightened to that CID.)
//!
//! ## Ships inert
//!
//! The listener is spawned only when `[host_attestor].enabled` is true
//! (default false) AND the miner has an Edge client — so a default deploy
//! never binds this port.

use hippius_types::host_attestor_challenge::{
    HostChallengeResponse, MAX_CHALLENGE_FRAME_BYTES, NONCE_LEN,
};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::edge_client::{EdgeClient, EnvelopeKind};

/// vali's JSON challenge response body (relayed verbatim through the Edge).
/// `#[serde(deny_unknown_fields)]` so a drifted vali shape is caught.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValiChallengeResponse {
    /// The vali-minted single-use nonce, hex (64 chars ⇒ 32 bytes).
    nonce_hex: String,
    /// The host `node_id` vali stamped from the miner's mTLS peer identity
    /// (PR-10b-S2a wire amendment) — surfaced to the guest so it never
    /// needs its node_id on the measured cmdline. The nonce is bound to it.
    node_id: String,
    /// Hard expiry, Unix seconds.
    expiry_unix: u64,
}

/// The outcome of serving one challenge connection — a static-class log
/// line (never echoes request/response bytes, §20).
#[derive(Debug, PartialEq, Eq)]
pub enum HostChallengeOutcome {
    /// The vali-minted nonce was delivered to the guest.
    Delivered,
    /// Dropped before/at delivery; carries a static class.
    Refused(&'static str),
}

/// Serve one guest challenge connection: read the request, relay it up to
/// vali via the Edge, translate the minted-nonce response into the guest's
/// canonical-CBOR wire, and write it back.
///
/// Generic over the stream so it is exercised cross-platform with
/// `tokio::io::duplex`; the Linux listener passes a real `VsockStream`.
pub async fn handle_host_challenge_conn<S>(mut stream: S, edge: &EdgeClient) -> HostChallengeOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // (1) Read the guest's framed `HostChallengeRequest` (opaque bytes —
    //     the Edge wire gate does the typed decode). Relayed verbatim.
    let request = match read_framed(&mut stream, MAX_CHALLENGE_FRAME_BYTES).await {
        Ok(bytes) => bytes,
        Err(class) => return HostChallengeOutcome::Refused(class),
    };

    // (2) Relay UP to the Edge → vali. The miner's mTLS identity is the
    //     authentication; vali binds the nonce to the stamped node_id.
    let vali_body = match edge
        .send_envelope_for_response(EnvelopeKind::HostAttestorChallenge, &request)
        .await
    {
        Ok(body) => body,
        // Transport / non-2xx — the guest retries (its enrollment is
        // fail-closed on a missing nonce).
        Err(_) => return HostChallengeOutcome::Refused("edge-relay"),
    };

    // (3) Translate vali's JSON `{nonce_hex, expiry_unix}` into the
    //     guest's canonical-CBOR `HostChallengeResponse`.
    let response = match build_challenge_response(&vali_body) {
        Ok(bytes) => bytes,
        Err(class) => return HostChallengeOutcome::Refused(class),
    };

    // (4) Write it back down the same connection.
    match write_framed(&mut stream, &response).await {
        Ok(()) => {
            let _ = stream.shutdown().await;
            HostChallengeOutcome::Delivered
        }
        Err(class) => HostChallengeOutcome::Refused(class),
    }
}

/// Parse vali's JSON challenge response and re-encode it as the guest's
/// canonical-CBOR [`HostChallengeResponse`]. Pure (no I/O) — the unit of
/// the translation logic's tests.
fn build_challenge_response(vali_body: &[u8]) -> Result<Vec<u8>, &'static str> {
    let parsed: ValiChallengeResponse =
        serde_json::from_slice(vali_body).map_err(|_| "vali-json")?;
    let nonce_bytes = hex::decode(parsed.nonce_hex.trim()).map_err(|_| "nonce-hex")?;
    let nonce: [u8; NONCE_LEN] = nonce_bytes.as_slice().try_into().map_err(|_| "nonce-len")?;
    // The node_id is relayed straight through from vali's stamped identity
    // (the miner never chooses it — it is the miner's OWN mTLS peer-id).
    HostChallengeResponse::new(nonce, parsed.node_id, parsed.expiry_unix)
        .canonical()
        .map_err(|_| "response-encode")
}

/// Log a challenge-listener outcome — static classes only (§20).
fn log_challenge(cid: u32, outcome: &HostChallengeOutcome) {
    match outcome {
        HostChallengeOutcome::Delivered => {
            eprintln!("hippius-miner-agent: host-attestor-challenge: cid={cid} delivered");
        }
        HostChallengeOutcome::Refused(class) => {
            eprintln!("hippius-miner-agent: host-attestor-challenge: cid={cid} refused {class}");
        }
    }
}

async fn read_framed<R>(reader: &mut R, max: usize) -> Result<Vec<u8>, &'static str>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|_| "read-length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > max {
        return Err("length");
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| "read-body")?;
    Ok(body)
}

async fn write_framed<W>(writer: &mut W, body: &[u8]) -> Result<(), &'static str>
where
    W: AsyncWrite + Unpin,
{
    let len = u32::try_from(body.len()).map_err(|_| "oversize")?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|_| "write-length")?;
    writer.write_all(body).await.map_err(|_| "write-body")?;
    writer.flush().await.map_err(|_| "flush")?;
    Ok(())
}

/// Bind the host-attestor challenge vsock port and serve guest
/// connections until cancelled (Linux only). Mirrors
/// [`super::kbs_proxy::run_kbs_proxy_listener`] (concurrency cap,
/// transient-accept backoff) but WITHOUT a CID gate — see the module doc.
#[cfg(target_os = "linux")]
pub async fn run_host_challenge_listener(
    edge: std::sync::Arc<EdgeClient>,
    cancel: tokio_util::sync::CancellationToken,
) {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::task::JoinSet;
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    let addr = VsockAddr::new(
        VMADDR_CID_ANY,
        hippius_types::host_attestor_challenge::CHALLENGE_PORT,
    );
    let listener = match VsockListener::bind(addr) {
        Ok(l) => l,
        Err(_) => {
            eprintln!("hippius-miner-agent: host-attestor-challenge: bind-error");
            return;
        }
    };
    eprintln!("hippius-miner-agent: host-attestor-challenge: up");

    let permits = Arc::new(tokio::sync::Semaphore::new(super::MAX_INFLIGHT_GUEST_CONNS));
    let mut conns: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                eprintln!("hippius-miner-agent: host-attestor-challenge: shutdown");
                break;
            }
            accepted = listener.accept() => {
                let (stream, addr) = match accepted {
                    Ok(pair) => pair,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => { drop(stream); continue; }
                };
                let src_cid = addr.cid();
                let edge = Arc::clone(&edge);
                conns.spawn(async move {
                    let _permit = permit;
                    let outcome = handle_host_challenge_conn(stream, edge.as_ref()).await;
                    log_challenge(src_cid, &outcome);
                });
            }
        }
        while conns.try_join_next().is_some() {}
    }
    conns.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hippius_types::host_attestor_challenge::HostChallengeRequest;
    use std::sync::Arc;

    fn edge() -> Arc<EdgeClient> {
        Arc::new(EdgeClient::insecure_for_tests(
            "http://127.0.0.1:1".to_string(),
        ))
    }

    #[test]
    fn build_challenge_response_round_trips_a_vali_json() {
        let nonce_hex = "11".repeat(NONCE_LEN);
        let body = format!(
            r#"{{"nonce_hex":"{nonce_hex}","node_id":"node-host-9","expiry_unix":1800000900}}"#
        );
        let cbor = build_challenge_response(body.as_bytes()).unwrap();
        let resp = HostChallengeResponse::decode(&cbor).unwrap();
        assert_eq!(resp.nonce, [0x11; NONCE_LEN]);
        // The node_id is relayed straight through to the guest (PR-10b-S2a).
        assert_eq!(resp.node_id, "node-host-9");
        assert_eq!(resp.expiry_unix, 1_800_000_900);
    }

    #[test]
    fn build_challenge_response_rejects_bad_json() {
        assert_eq!(
            build_challenge_response(b"not-json").unwrap_err(),
            "vali-json"
        );
    }

    #[test]
    fn build_challenge_response_rejects_unknown_field() {
        let nonce_hex = "11".repeat(NONCE_LEN);
        let body =
            format!(r#"{{"nonce_hex":"{nonce_hex}","node_id":"n","expiry_unix":1,"rogue":2}}"#);
        assert_eq!(
            build_challenge_response(body.as_bytes()).unwrap_err(),
            "vali-json"
        );
    }

    #[test]
    fn build_challenge_response_rejects_missing_node_id() {
        // A pre-amendment vali (no node_id) is a drifted shape — dropped.
        let nonce_hex = "11".repeat(NONCE_LEN);
        let body = format!(r#"{{"nonce_hex":"{nonce_hex}","expiry_unix":1800000900}}"#);
        assert_eq!(
            build_challenge_response(body.as_bytes()).unwrap_err(),
            "vali-json"
        );
    }

    #[test]
    fn build_challenge_response_rejects_bad_nonce_len() {
        let body = r#"{"nonce_hex":"1111","node_id":"n","expiry_unix":1800000900}"#;
        assert_eq!(
            build_challenge_response(body.as_bytes()).unwrap_err(),
            "nonce-len"
        );
    }

    #[test]
    fn build_challenge_response_rejects_zero_expiry() {
        // HostChallengeResponse::canonical rejects a zero expiry.
        let nonce_hex = "11".repeat(NONCE_LEN);
        let body = format!(r#"{{"nonce_hex":"{nonce_hex}","node_id":"n","expiry_unix":0}}"#);
        assert_eq!(
            build_challenge_response(body.as_bytes()).unwrap_err(),
            "response-encode"
        );
    }

    #[tokio::test]
    async fn dead_edge_refuses_after_reading_the_request() {
        let req = HostChallengeRequest::new([0x22; 32]).canonical().unwrap();
        let (mut client, server) = tokio::io::duplex(4096);
        // Guest writes a framed request.
        write_framed(&mut client, &req).await.unwrap();
        // The handler reads it, tries to relay to a dead Edge, and refuses.
        let outcome = handle_host_challenge_conn(server, edge().as_ref()).await;
        assert_eq!(outcome, HostChallengeOutcome::Refused("edge-relay"));
    }

    #[tokio::test]
    async fn a_truncated_frame_is_refused() {
        let (mut client, server) = tokio::io::duplex(4096);
        // A length prefix promising more than is sent → read-body fails.
        client.write_all(&100u32.to_be_bytes()).await.unwrap();
        client.write_all(&[0u8; 4]).await.unwrap();
        drop(client);
        let outcome = handle_host_challenge_conn(server, edge().as_ref()).await;
        assert_eq!(outcome, HostChallengeOutcome::Refused("read-body"));
    }
}
