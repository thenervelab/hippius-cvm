//! Host-attestor **enroll + beacon** UP-relay vsock listener (blackbox
//! host-attestor chantier PR-10b-S2a).
//!
//! This is the mirror-image of the PR-10 challenge relay
//! ([`super::host_challenge`]): where that carried a nonce DOWN, this
//! carries the attestor's enrollment + liveness beacons UP.
//!
//! ## Guest push (fire-and-forget)
//!
//! The blackbox host-attestor guest ([`agent-host-attestor`]'s
//! `vsock_pusher`) dials the host on
//! [`hippius_types::host_attestor_challenge::ENROLL_BEACON_PORT`] and
//! streams length-prefixed CBOR `GuestFrame{kind, body}` frames on one
//! long-lived connection:
//!
//! - `kind = "host-enroll"` — `body` is the once-per-boot
//!   [`HostEnrollment`] (canonical CBOR), sent as a preamble on every
//!   fresh connection;
//! - `kind = "host-beacon"` — `body` is a [`SignedHostBeacon`] envelope,
//!   sent every beat.
//!
//! The pusher is fire-and-forget: it writes frames and never reads an
//! ack (vali dedupes by content downstream, so an at-least-once resend
//! after a reconnect is safe).
//!
//! ## The miner is a DUMB relay
//!
//! This listener reads each frame and relays its **opaque** `body`
//! bytes UP to the Edge as the matching envelope kind
//! ([`EnvelopeKind::HostAttestorEnroll`] / [`EnvelopeKind::HostAttestorBeacon`])
//! over the miner's mTLS leg. It NEVER decodes the enrollment / beacon
//! body — the Edge orchestrates the KBS mint + the vali cert / beacon
//! ingest, and vali/KBS are the verifiers (§5.6 opacity, one hop
//! earlier than the Edge). A relay failure never fabricates success.
//!
//! ## At-least-once posture
//!
//! - An **enroll** relay failure closes the connection, so the guest's
//!   pusher reconnects and re-sends the enrollment preamble (at-least-once
//!   for the once-per-boot enrollment — the cert path must not be silently
//!   dropped).
//! - A **beacon** relay failure is logged and the loop continues: beacons
//!   are periodic and best-effort (liveness is a stream, not a
//!   transaction), so one lost beat must not force an (expensive) re-enroll.
//!
//! ## No CID gate (by design)
//!
//! Like [`super::host_challenge`], the relayed bytes are worthless to
//! anyone but the measured attestor guest: an enrollment is an AMD-signed
//! SNP report and a beacon is signed by the enrolled key, both re-verified
//! downstream. So a connection from any CID is accepted; the src CID is
//! logged for ops.
//!
//! ## Ships inert
//!
//! Spawned only when `[host_attestor].enabled` is true (default false) AND
//! the miner has an Edge client — so a default deploy never binds this
//! port.

use serde::Deserialize;
use serde_bytes::ByteBuf;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::edge_client::{EdgeClient, EnvelopeKind};
use crate::error::MinerAgentError;

/// The relay-failure sub-class of a beacon drop, for the log line — the
/// `edge-relay/{class}` sub-classifier (`transport` = the mTLS POST never
/// landed; `rejected` = the Edge/vali answered non-2xx). A non-relay error
/// is `other`. A compile-time `&'static str` — never echoes a body or URL.
fn relay_drop_class(err: &MinerAgentError) -> &'static str {
    match err {
        MinerAgentError::EdgeRelay(class) => class,
        _ => "other",
    }
}

/// Hard cap on one enroll/beacon frame — 64 KiB. An enrollment
/// (~1.3 KiB, dominated by the 1184-byte SNP report) and a beacon (a few
/// hundred bytes) sit far below this; the cap only trips on a corrupt or
/// hostile frame, and bounds a single allocation before any decode.
pub const MAX_HOST_RELAY_FRAME: usize = 64 * 1024;

/// The `kind` tag of a host-attestor guest frame. Kebab-case matches the
/// strings the guest pusher writes (`"host-enroll"` / `"host-beacon"`), so
/// an unknown / mistyped kind fails the typed decode and the frame is
/// dropped — the miner never guesses a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum HostRelayKind {
    HostEnroll,
    HostBeacon,
}

impl HostRelayKind {
    /// The Edge envelope kind this guest-frame kind relays as.
    fn envelope_kind(self) -> EnvelopeKind {
        match self {
            HostRelayKind::HostEnroll => EnvelopeKind::HostAttestorEnroll,
            HostRelayKind::HostBeacon => EnvelopeKind::HostAttestorBeacon,
        }
    }
}

/// One host-attestor guest frame — `{kind, body}`. `deny_unknown_fields`
/// so a drifted / hostile frame is dropped. `body` is **opaque** to the
/// miner — never decoded, only relayed. Decoded straight into this typed
/// struct (never a `ciborium::Value`), so a deeply-nested hostile CBOR
/// document is rejected at the first wrong major type, not recursed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRelayFrame {
    kind: HostRelayKind,
    body: ByteBuf,
}

/// The outcome of serving one guest relay connection — a static-class log
/// line (never echoes body bytes, §20).
#[derive(Debug, PartialEq, Eq)]
pub enum HostRelayOutcome {
    /// The peer closed cleanly after `frames_relayed` frames were relayed
    /// UP.
    Closed { frames_relayed: u64 },
    /// The connection was ended early; carries a static class. Any frames
    /// relayed before the failure still egressed (at-least-once).
    Ended(&'static str),
}

/// Serve one guest relay connection: read frames in a loop and relay each
/// opaque `body` UP to the Edge as its matching envelope kind, until the
/// peer closes, a decode fails, an enroll relay fails, or `cancel` fires.
///
/// Generic over the stream so it is exercised cross-platform with a
/// TCP/`tokio::io::duplex` stand-in; the Linux listener passes a real
/// `VsockStream`.
pub async fn handle_host_relay_conn<S>(
    mut stream: S,
    edge: &EdgeClient,
    cancel: tokio_util::sync::CancellationToken,
) -> HostRelayOutcome
where
    S: AsyncRead + Unpin,
{
    let mut frames_relayed: u64 = 0;
    loop {
        let frame = tokio::select! {
            _ = cancel.cancelled() => return HostRelayOutcome::Ended("cancelled"),
            read = read_host_frame(&mut stream, MAX_HOST_RELAY_FRAME) => match read {
                Ok(Some(frame)) => frame,
                // Clean EOF between frames — the ordinary end of a session.
                Ok(None) => return HostRelayOutcome::Closed { frames_relayed },
                Err(class) => return HostRelayOutcome::Ended(class),
            },
        };

        let kind = frame.kind;
        match edge
            .send_envelope(kind.envelope_kind(), frame.body.as_ref())
            .await
        {
            Ok(()) => frames_relayed += 1,
            Err(e) => match kind {
                // An enroll must be at-least-once: close so the guest
                // reconnects and re-sends the enrollment preamble. Never
                // fabricate success.
                HostRelayKind::HostEnroll => return HostRelayOutcome::Ended("enroll-relay"),
                // A beacon is periodic + best-effort: log the lost beat and
                // keep serving (do not force an expensive re-enroll). Surface
                // the relay sub-class — `transport` (the mTLS POST never
                // landed) vs `rejected` (the Edge/vali answered non-2xx, e.g.
                // a monotonic-`seq` refusal while a freshly-rebooted attestor
                // re-baselines) — so a persistent drop is not misdiagnosed as
                // an unreachable Edge (§20: static class only, never a body).
                HostRelayKind::HostBeacon => {
                    eprintln!(
                        "hippius-miner-agent: host-attestor-relay: beacon-relay-dropped (edge {})",
                        relay_drop_class(&e)
                    );
                }
            },
        }
    }
}

/// Read one length-prefixed CBOR [`HostRelayFrame`]. Returns `Ok(None)`
/// on a clean hang-up between frames (the normal end of a session),
/// `Err(class)` on a framing / decode failure. A zero or over-`max`
/// length is rejected before any body buffer is allocated.
async fn read_host_frame<R>(
    reader: &mut R,
    max: usize,
) -> Result<Option<HostRelayFrame>, &'static str>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        // No bytes (or a partial prefix) before close — a clean session end.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err("read-length"),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err("zero-length");
    }
    if len > max {
        return Err("oversize");
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| "read-body")?;
    // Decode straight into the typed struct (never `ciborium::Value`) so a
    // deeply-nested hostile document is rejected at the first wrong major
    // type, not recursed.
    let frame: HostRelayFrame = ciborium::de::from_reader(body.as_slice()).map_err(|_| "decode")?;
    Ok(Some(frame))
}

/// Log a relay-listener outcome — static classes only (§20).
fn log_relay(cid: u32, outcome: &HostRelayOutcome) {
    match outcome {
        HostRelayOutcome::Closed { frames_relayed } => {
            eprintln!(
                "hippius-miner-agent: host-attestor-relay: cid={cid} closed frames_relayed={frames_relayed}"
            );
        }
        HostRelayOutcome::Ended(class) => {
            eprintln!("hippius-miner-agent: host-attestor-relay: cid={cid} ended {class}");
        }
    }
}

/// Bind the host-attestor enroll/beacon UP-relay vsock port and serve
/// guest connections until cancelled (Linux only). Mirrors
/// [`super::host_challenge::run_host_challenge_listener`] (concurrency
/// cap, transient-accept backoff, drain-on-cancel).
#[cfg(target_os = "linux")]
pub async fn run_host_relay_listener(
    edge: std::sync::Arc<EdgeClient>,
    cancel: tokio_util::sync::CancellationToken,
) {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::task::JoinSet;
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    let addr = VsockAddr::new(
        VMADDR_CID_ANY,
        hippius_types::host_attestor_challenge::ENROLL_BEACON_PORT,
    );
    let listener = match VsockListener::bind(addr) {
        Ok(l) => l,
        Err(_) => {
            eprintln!("hippius-miner-agent: host-attestor-relay: bind-error");
            return;
        }
    };
    eprintln!("hippius-miner-agent: host-attestor-relay: up");

    let permits = Arc::new(tokio::sync::Semaphore::new(super::MAX_INFLIGHT_GUEST_CONNS));
    let mut conns: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                eprintln!("hippius-miner-agent: host-attestor-relay: shutdown");
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
                let cancel = cancel.clone();
                conns.spawn(async move {
                    let _permit = permit;
                    let outcome = handle_host_relay_conn(stream, edge.as_ref(), cancel).await;
                    log_relay(src_cid, &outcome);
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
    use hippius_types::host_attestor::{SignedHostBeacon, SIGNATURE_LEN};
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio_util::sync::CancellationToken;

    fn edge() -> Arc<EdgeClient> {
        Arc::new(EdgeClient::insecure_for_tests(
            "http://127.0.0.1:1".to_string(),
        ))
    }

    /// Encode a `GuestFrame{kind, body}` the way the guest pusher does:
    /// a length-prefixed CBOR map with a text `kind` + byte-string `body`.
    fn guest_frame(kind: &str, body: &[u8]) -> Vec<u8> {
        let value = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("body".to_string()),
                ciborium::value::Value::Bytes(body.to_vec()),
            ),
            (
                ciborium::value::Value::Text("kind".to_string()),
                ciborium::value::Value::Text(kind.to_string()),
            ),
        ]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&value, &mut cbor).unwrap();
        let mut out = (cbor.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&cbor);
        out
    }

    #[tokio::test]
    async fn read_frame_parses_enroll_and_beacon_kinds() {
        // Both known kinds decode into the typed frame; the body is the
        // opaque bytes verbatim.
        for (kind_str, expect) in [
            ("host-enroll", HostRelayKind::HostEnroll),
            ("host-beacon", HostRelayKind::HostBeacon),
        ] {
            let frame_bytes = guest_frame(kind_str, &[9u8; 40]);
            let mut cursor = std::io::Cursor::new(frame_bytes);
            let frame = read_host_frame(&mut cursor, MAX_HOST_RELAY_FRAME)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(frame.kind, expect);
            assert_eq!(frame.body.as_ref(), &[9u8; 40]);
        }
    }

    #[tokio::test]
    async fn read_frame_rejects_an_unknown_kind() {
        let frame_bytes = guest_frame("host-mystery", &[1u8; 4]);
        let mut cursor = std::io::Cursor::new(frame_bytes);
        assert_eq!(
            read_host_frame(&mut cursor, MAX_HOST_RELAY_FRAME)
                .await
                .unwrap_err(),
            "decode"
        );
    }

    #[tokio::test]
    async fn read_frame_rejects_an_oversize_length() {
        let mut bytes = ((MAX_HOST_RELAY_FRAME + 1) as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 8]);
        let mut cursor = std::io::Cursor::new(bytes);
        assert_eq!(
            read_host_frame(&mut cursor, MAX_HOST_RELAY_FRAME)
                .await
                .unwrap_err(),
            "oversize"
        );
    }

    #[tokio::test]
    async fn clean_close_after_frames_is_reported() {
        // A guest that writes an enroll + a beacon then hangs up: the
        // handler tries to relay each to a dead Edge. The FIRST is an
        // enroll → relay fails → the connection ends `enroll-relay`
        // (at-least-once: the guest will reconnect + re-enroll).
        let (mut client, server) = tokio::io::duplex(8192);
        let enroll = guest_frame("host-enroll", &[0x5A; 32]);
        client.write_all(&enroll).await.unwrap();
        client.flush().await.unwrap();
        drop(client);
        let outcome =
            handle_host_relay_conn(server, edge().as_ref(), CancellationToken::new()).await;
        assert_eq!(outcome, HostRelayOutcome::Ended("enroll-relay"));
    }

    #[tokio::test]
    async fn a_beacon_relay_failure_keeps_serving_until_eof() {
        // A stream of beacons to a dead Edge: each relay fails but the
        // handler keeps reading (best-effort liveness), and reports a
        // clean close at EOF. `frames_relayed` is 0 (all relays failed) —
        // never fabricated as success.
        let signed = SignedHostBeacon {
            body: vec![7u8; 24],
            sig: [0xAB; SIGNATURE_LEN],
        };
        let beacon_body = signed.encode().unwrap();
        let (mut client, server) = tokio::io::duplex(8192);
        client
            .write_all(&guest_frame("host-beacon", &beacon_body))
            .await
            .unwrap();
        client
            .write_all(&guest_frame("host-beacon", &beacon_body))
            .await
            .unwrap();
        client.flush().await.unwrap();
        drop(client);
        let outcome =
            handle_host_relay_conn(server, edge().as_ref(), CancellationToken::new()).await;
        assert_eq!(outcome, HostRelayOutcome::Closed { frames_relayed: 0 });
    }

    #[tokio::test]
    async fn a_truncated_frame_ends_the_connection() {
        let (mut client, server) = tokio::io::duplex(4096);
        // A length prefix promising more than is sent → read-body fails.
        client.write_all(&100u32.to_be_bytes()).await.unwrap();
        client.write_all(&[0u8; 4]).await.unwrap();
        drop(client);
        let outcome =
            handle_host_relay_conn(server, edge().as_ref(), CancellationToken::new()).await;
        assert_eq!(outcome, HostRelayOutcome::Ended("read-body"));
    }

    #[tokio::test]
    async fn an_immediate_close_is_a_clean_zero_frame_session() {
        let (client, server) = tokio::io::duplex(64);
        drop(client);
        let outcome =
            handle_host_relay_conn(server, edge().as_ref(), CancellationToken::new()).await;
        assert_eq!(outcome, HostRelayOutcome::Closed { frames_relayed: 0 });
    }
}
