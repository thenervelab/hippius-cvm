//! Edge gateway client (MA-3).
//!
//! Relays a guest-signed envelope (today: a tenant `ServedDeliveryReceipt`)
//! to the Edge gateway over the SAME miner→Edge mTLS transport the §K
//! heartbeat uses ([`crate::heartbeat::build_edge_mtls_client`]): a
//! `reqwest` client whose client identity IS the miner node key
//! (permissionless, no operator CA) and whose CA pins the Edge server.
//!
//! The miner authenticates at the transport layer (mTLS peer identity —
//! the Edge stamps `x-hippius-peer-id` from it). The relayed body is
//! **opaque** — it is the guest's own Ed25519-signed CBOR; the miner
//! never decodes it and never re-signs it (vali verifies the guest
//! signature, so the untrusted miner cannot forge a receipt).

use serde::{Deserialize, Serialize};

use crate::config::EdgeSection;
use crate::error::{MinerAgentError, Result};
use crate::heartbeat::build_edge_mtls_client;
use crate::identity::MinerIdentity;

/// The envelope kinds a miner sends *to* the Edge gateway — the
/// `Miner → Inner` direction.
///
/// Each maps to a `hippius-types` signed payload. The enum is kept local
/// to the miner-agent so it does not take a dependency on the
/// `hippius-edge-gateway` binary crate for one enum.
///
/// `Serialize`/`Deserialize` (kebab-case) so the MA-4 vsock relay can
/// carry it as the `kind` tag of a [`crate::vsock::frame::GuestFrame`]
/// — the guest declares which kind it is relaying, the miner-agent
/// routes on it without ever decoding the opaque body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvelopeKind {
    /// A KBS release request relayed from a tenant guest.
    KbsRequest,
    /// A lifecycle end-of-life acknowledgement.
    StoppedAck,
    /// A signed tenant served-delivery receipt.
    ServedReceipt,
    /// An Audit-VM-cosigned served-delivery aggregate.
    ServedAggregate,
    /// A signed miner graceful-exit request (`SignedGracefulExit`). Posted
    /// to the Edge `/v1/edge/graceful-exit` route over mTLS, exactly like
    /// a heartbeat — the Edge relays it opaquely to vali.
    GracefulExit,
    /// A blackbox host-attestor nonce-challenge request
    /// (`HostChallengeRequest`) relayed on the attestor guest's behalf
    /// (PR-10). Unlike every other kind this is a REQUEST/RESPONSE: the
    /// vali-minted nonce comes back in the response body (see
    /// [`EdgeClient::send_envelope_for_response`]).
    HostAttestorChallenge,
    /// A blackbox host-attestor once-per-boot enrollment (`HostEnrollment`)
    /// relayed UP on the attestor guest's behalf (PR-10b-S2a). The Edge
    /// orchestrates the KBS mint + the vali cert-ingest; the miner is a
    /// dumb relay (never decodes the body). Fire-and-forget.
    HostAttestorEnroll,
    /// A blackbox host-attestor liveness beacon (`SignedHostBeacon`)
    /// relayed UP on the attestor guest's behalf (PR-10b-S2a). The Edge
    /// forwards it to vali's host-attestor heartbeat ingest, stamping the
    /// miner's mTLS peer identity. Fire-and-forget.
    HostAttestorBeacon,
    /// A KBS-L0-signed tenant-CVM live attestation
    /// (`SignedLiveAttestation`) relayed UP on the tenant guest's behalf
    /// (§23 uptime coverage). The guest obtained it from KBS
    /// `/v1/attest/keepalive` by answering a single-use nonce with a
    /// fresh SNP report; the Edge forwards it to vali's uptime-coverage
    /// ingest. Fire-and-forget, and the miner is a DUMB relay: it cannot
    /// mint one of these (only a KBS that just verified a live guest's
    /// SNP report can) and cannot edit one (the L0 signature covers
    /// every field). Relaying it is the miner's own interest — without
    /// it, once the gate is armed, its VM's uptime is not creditable.
    VmLiveAttestation,
    /// The miner's own signed host inventory (`SignedHostInventory`,
    /// §18.10), posted by the inventory poster, which acts on the reply's
    /// status ([`EdgeClient::post_for_reply`]). Host-plane: never
    /// guest-relayable.
    HostInventory,
}

impl EnvelopeKind {
    /// Whether a tenant guest may relay this kind through the vsock relay
    /// ([`crate::vsock::relay`]): an ALLOWLIST of the guest-plane kinds,
    /// so a kind added later is refused until listed here. Senders in
    /// the guest code today: `served-receipt` (agent-tenant-telemetry),
    /// `vm-live-attestation` (agent-keepalive). `kbs-request`,
    /// `stopped-ack` and `served-aggregate` are guest-plane kinds kept
    /// for a guest that frames them (no current guest does: the KBS
    /// exchange and the stopped-ack ride the HTTP vsock proxy).
    ///
    /// Every host-plane kind is refused: the miner's own graceful exit
    /// and host inventory, the host-attestor kinds (their own vsock
    /// listener). A guest cannot forge them (vali verifies the miner or
    /// attestor key), but it could replay one or spend the miner's
    /// per-hour budget at vali.
    pub fn guest_relayable(self) -> bool {
        matches!(
            self,
            EnvelopeKind::KbsRequest
                | EnvelopeKind::StoppedAck
                | EnvelopeKind::ServedReceipt
                | EnvelopeKind::ServedAggregate
                | EnvelopeKind::VmLiveAttestation
        )
    }

    /// The Edge route a miner POSTs this envelope kind to (over mTLS).
    pub fn edge_route(self) -> &'static str {
        match self {
            EnvelopeKind::KbsRequest => "/v1/edge/kbs-request",
            EnvelopeKind::StoppedAck => "/v1/edge/stopped-ack",
            EnvelopeKind::ServedReceipt => "/v1/edge/served-receipt",
            EnvelopeKind::ServedAggregate => "/v1/edge/served-aggregate",
            EnvelopeKind::GracefulExit => "/v1/edge/graceful-exit",
            EnvelopeKind::HostAttestorChallenge => "/v1/edge/host-attestor-challenge",
            EnvelopeKind::HostAttestorEnroll => "/v1/edge/host-attestor-enroll",
            EnvelopeKind::HostAttestorBeacon => "/v1/edge/host-attestor-beacon",
            EnvelopeKind::VmLiveAttestation => "/v1/edge/vm-live-attestation",
            EnvelopeKind::HostInventory => "/v1/edge/host-inventory",
        }
    }
}

/// What the Edge answered a [`EdgeClient::post_for_reply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeReply {
    pub status: u16,
    /// `Retry-After`, seconds (only the Edge's own `429` carries one).
    pub retry_after: Option<u64>,
}

/// Content type of every relayed envelope body — canonical CBOR, the
/// same the heartbeat POSTs (the Edge relays it verbatim).
const RELAY_CONTENT_TYPE: &str = "application/cbor";

/// Cap on the host-attestor challenge response body the Edge relays back
/// (PR-10). vali returns a tiny JSON `{nonce_hex, expiry_unix}`; this
/// bounds a hostile upstream read.
const MAX_CHALLENGE_RESPONSE_BYTES: usize = 4 * 1024;

/// Client for the Edge gateway — a pre-built miner→Edge mTLS `reqwest`
/// client.
pub struct EdgeClient {
    endpoint: String,
    client: reqwest::Client,
}

impl EdgeClient {
    /// Build the Edge client from the `[edge]` config + the miner
    /// identity (the mTLS client cert). Fails closed on a bad CA / cert
    /// / key — the same builder the heartbeat pusher uses.
    pub fn connect(edge: &EdgeSection, identity: &MinerIdentity) -> Result<Self> {
        let client = build_edge_mtls_client(edge, identity)?;
        Ok(Self {
            endpoint: edge.endpoint.clone(),
            client,
        })
    }

    /// The Edge gateway endpoint this client targets.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Test-only: a plain (non-mTLS) client pointing at `endpoint`. Real
    /// relays use [`connect`]. The vsock-relay tests use this to exercise
    /// the drain loop without standing up an mTLS Edge — a send to a dead
    /// endpoint fails `EdgeRelay("transport")`, which the relay logs +
    /// counts, exactly the path under test.
    #[doc(hidden)]
    pub fn insecure_for_tests(endpoint: String) -> Self {
        // A short connect timeout so a send to a dead/unroutable endpoint
        // fails fast in every environment (a relay test must never hang on
        // a network round-trip).
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(200))
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap_or_default();
        Self { endpoint, client }
    }

    /// Relay `body` to the Edge as an envelope of `kind` over mTLS.
    ///
    /// `body` is posted verbatim (opaque CBOR) with `application/cbor`;
    /// the miner's mTLS identity is the authentication. Returns
    /// [`MinerAgentError::EdgeRelay`] on a transport failure or a non-2xx
    /// Edge response — the caller (the vsock relay) logs + counts it and
    /// the guest's at-least-once buffer retries.
    pub async fn send_envelope(&self, kind: EnvelopeKind, body: &[u8]) -> Result<()> {
        let url = self.envelope_url(kind);
        let resp = self
            .client
            .post(&url)
            .header("content-type", RELAY_CONTENT_TYPE)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| MinerAgentError::EdgeRelay("transport"))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(MinerAgentError::EdgeRelay("rejected"))
        }
    }

    /// Relay `body` to the Edge as an envelope of `kind` over mTLS and
    /// return the Edge's response body on a 2xx (PR-10, host-attestor
    /// nonce challenge).
    ///
    /// Unlike [`send_envelope`](Self::send_envelope) this is a
    /// REQUEST/RESPONSE: the vali-minted nonce is relayed back through the
    /// Edge verbatim in the response body. The body is capped at
    /// [`MAX_CHALLENGE_RESPONSE_BYTES`] so a hostile upstream cannot force
    /// an unbounded read. A transport failure or non-2xx status is
    /// [`MinerAgentError::EdgeRelay`].
    pub async fn send_envelope_for_response(
        &self,
        kind: EnvelopeKind,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let url = self.envelope_url(kind);
        let resp = self
            .client
            .post(&url)
            .header("content-type", RELAY_CONTENT_TYPE)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| MinerAgentError::EdgeRelay("transport"))?;
        if !resp.status().is_success() {
            return Err(MinerAgentError::EdgeRelay("rejected"));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|_| MinerAgentError::EdgeRelay("response-read"))?;
        if bytes.len() > MAX_CHALLENGE_RESPONSE_BYTES {
            return Err(MinerAgentError::EdgeRelay("response-too-large"));
        }
        Ok(bytes.to_vec())
    }

    /// POST `body` as an envelope of `kind` and return the reply's status
    /// and `Retry-After` (seconds). The reply body is not read at all:
    /// the Edge relays no upstream error body (a vali refusal is a bare
    /// `502`), and a 2xx carries nothing the poster needs. `Err` only for
    /// a transport failure (no reply).
    pub async fn post_for_reply(&self, kind: EnvelopeKind, body: &[u8]) -> Result<EdgeReply> {
        let url = self.envelope_url(kind);
        let resp = self
            .client
            .post(&url)
            .header("content-type", RELAY_CONTENT_TYPE)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| MinerAgentError::EdgeRelay("transport"))?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        Ok(EdgeReply {
            status,
            retry_after,
        })
    }

    /// The absolute URL an envelope of `kind` is POSTed to.
    fn envelope_url(&self, kind: EnvelopeKind) -> String {
        format!(
            "{}{}",
            self.endpoint.trim_end_matches('/'),
            kind.edge_route()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_routes_map_each_kind_to_its_path() {
        assert_eq!(
            EnvelopeKind::ServedReceipt.edge_route(),
            "/v1/edge/served-receipt"
        );
        assert_eq!(
            EnvelopeKind::KbsRequest.edge_route(),
            "/v1/edge/kbs-request"
        );
        assert_eq!(
            EnvelopeKind::StoppedAck.edge_route(),
            "/v1/edge/stopped-ack"
        );
        assert_eq!(
            EnvelopeKind::ServedAggregate.edge_route(),
            "/v1/edge/served-aggregate"
        );
        assert_eq!(
            EnvelopeKind::GracefulExit.edge_route(),
            "/v1/edge/graceful-exit"
        );
        assert_eq!(
            EnvelopeKind::HostAttestorChallenge.edge_route(),
            "/v1/edge/host-attestor-challenge"
        );
        assert_eq!(
            EnvelopeKind::HostAttestorEnroll.edge_route(),
            "/v1/edge/host-attestor-enroll"
        );
        assert_eq!(
            EnvelopeKind::HostAttestorBeacon.edge_route(),
            "/v1/edge/host-attestor-beacon"
        );
        // §23 uptime coverage — the route the Edge listens on. A rename
        // on either side silently starves the coverage meter, which once
        // armed stops reward accrual, so it is pinned here.
        assert_eq!(
            EnvelopeKind::VmLiveAttestation.edge_route(),
            "/v1/edge/vm-live-attestation"
        );
        // The Edge's `/v1/edge/host-inventory` relay (miner_router.rs).
        assert_eq!(
            EnvelopeKind::HostInventory.edge_route(),
            "/v1/edge/host-inventory"
        );
    }

    /// The relay allowlist: the guest-plane kinds pass, every host-plane
    /// kind is refused.
    #[test]
    fn only_guest_kinds_are_relayable() {
        for kind in [
            EnvelopeKind::KbsRequest,
            EnvelopeKind::StoppedAck,
            EnvelopeKind::ServedReceipt,
            EnvelopeKind::ServedAggregate,
            EnvelopeKind::VmLiveAttestation,
        ] {
            assert!(kind.guest_relayable(), "{kind:?}");
        }
        for kind in [
            EnvelopeKind::GracefulExit,
            EnvelopeKind::HostInventory,
            EnvelopeKind::HostAttestorChallenge,
            EnvelopeKind::HostAttestorEnroll,
            EnvelopeKind::HostAttestorBeacon,
        ] {
            assert!(!kind.guest_relayable(), "{kind:?}");
        }
    }

    #[tokio::test]
    async fn post_for_reply_reads_the_status_and_retry_after_only() {
        let (endpoint, seen) = test_http::serve(vec![
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\ncontent-length: 0\r\n\r\n",
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: soon\r\ncontent-length: 0\r\n\r\n",
            "HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n",
            // A large body is never read: the reply returns at once.
            "HTTP/1.1 200 OK\r\ncontent-length: 10000000\r\n\r\npartial",
        ])
        .await;
        let edge = EdgeClient::insecure_for_tests(endpoint);
        let mut got = Vec::new();
        for _ in 0..4 {
            let r = edge
                .post_for_reply(EnvelopeKind::HostInventory, b"x")
                .await
                .unwrap();
            got.push((r.status, r.retry_after));
        }
        assert_eq!(
            got,
            [(429, Some(120)), (429, None), (502, None), (200, None)]
        );
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["POST /v1/edge/host-inventory"; 4]
        );
        // No reply at all: a transport error.
        let dead = EdgeClient::insecure_for_tests("http://127.0.0.1:1".to_string());
        assert!(dead
            .post_for_reply(EnvelopeKind::HostInventory, b"x")
            .await
            .is_err());
    }

    /// The host's own graceful exit still goes out through the Edge
    /// client, whatever the guest relay refuses (`request-graceful-exit`
    /// builds its URL from the same `edge_route`).
    #[tokio::test]
    async fn the_hosts_graceful_exit_still_posts() {
        let (endpoint, seen) =
            test_http::serve(vec!["HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"]).await;
        let edge = EdgeClient::insecure_for_tests(endpoint);
        edge.send_envelope(EnvelopeKind::GracefulExit, b"signed")
            .await
            .unwrap();
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["POST /v1/edge/graceful-exit"]
        );
    }

    /// The guest declares the frame kind as a kebab-case CBOR string —
    /// pinned so the guest agent and the miner-agent cannot drift.
    #[test]
    fn vm_live_attestation_serialises_kebab_case() {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&EnvelopeKind::VmLiveAttestation, &mut buf).unwrap();
        let v: ciborium::value::Value = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(
            v,
            ciborium::value::Value::Text("vm-live-attestation".into())
        );
    }

    /// The URL joins the endpoint + route with no double slash, whether
    /// or not the endpoint carries a trailing `/`.
    #[test]
    fn envelope_url_joins_endpoint_and_route() {
        let mk = |endpoint: &str| EdgeClient {
            endpoint: endpoint.to_string(),
            // A default client is enough to exercise URL building — no
            // request is sent.
            client: reqwest::Client::new(),
        };
        assert_eq!(
            mk("https://edge.hippius.network:443").envelope_url(EnvelopeKind::ServedReceipt),
            "https://edge.hippius.network:443/v1/edge/served-receipt"
        );
        assert_eq!(
            mk("https://edge.hippius.network:443/").envelope_url(EnvelopeKind::ServedReceipt),
            "https://edge.hippius.network:443/v1/edge/served-receipt"
        );
    }
}

/// A loopback HTTP/1.1 server answering each connection with the next
/// canned response, recording each request line (tests only).
#[cfg(test)]
pub(crate) mod test_http {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serve `responses` in order on `127.0.0.1:<ephemeral>`; returns the
    /// endpoint and the request lines seen (`METHOD /path`).
    pub(crate) async fn serve(responses: Vec<&'static str>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            for response in responses {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // The head, then the body by its content-length.
                let head_end = loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break None;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(i + 4);
                    }
                };
                let Some(head_end) = head_end else { continue };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        if k.eq_ignore_ascii_case("content-length") {
                            v.trim().parse().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + len {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let line = head.lines().next().unwrap_or("").to_string();
                let request = line
                    .rsplit_once(' ')
                    .map_or(line.clone(), |(r, _)| r.to_string());
                log.lock().unwrap().push(request);
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        (format!("http://{addr}"), seen)
    }
}
