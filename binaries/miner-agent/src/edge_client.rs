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
}

impl EnvelopeKind {
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
        }
    }
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
