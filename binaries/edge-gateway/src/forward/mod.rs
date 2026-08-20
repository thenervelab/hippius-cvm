//! In-cluster forward — the vRack-side egress of the §9 relay
//! (PR-H8, §H phase 2).
//!
//! PR-H7 brought up the miner-facing `:443` mTLS listener but
//! terminated each connection after the handshake — there was no
//! written wire frame and no forward egress. PR-H8 layers the
//! envelope protocol (see [`crate::listeners::miner_router`]) over
//! that listener and this module is its other half: the client that
//! relays a validated envelope's body bytes onward to the inner
//! control plane.
//!
//! ## Opaque byte relay (§5.6)
//!
//! Forward is an **opaque byte relay**. The [`crate::listeners`]
//! router validated the envelope *shell* (canonical-CBOR, direction,
//! `deny_unknown_fields` typed decode) — that is the §10 wire gate.
//! This module then re-emits the **exact body bytes** of the
//! [`ValidatedEnvelope`] verbatim; it never re-encodes, never
//! decodes the inner KBS / telemetry protocol, never inspects the
//! payload. The destination is selected by the envelope's
//! [`MessageKind`](crate::pipeline::MessageKind) — i.e. by the URL
//! route the miner posted to — not by reading the body.
//!
//! ## No mTLS on the forward leg
//!
//! The miner-facing leg is mTLS (hostile L3). The forward leg runs
//! inside the trusted vRack / cluster network: who-may-call-whom is
//! enforced by the Cilium NetworkPolicy (Edge egress is allowed only
//! to the `kbs` and `vali` namespaces — see
//! `deploy/gitops/apps/edge-gateway/templates/networkpolicy.yaml`),
//! not by a second mTLS handshake. The [`ReqwestForwardClient`] still
//! pins **TLS 1.3** and `rustls` (no native-tls) so an in-cluster
//! `https://` endpoint negotiates a modern transport.
//!
//! ## Trait seam
//!
//! [`ForwardClient`] is the seam the router depends on. Production is
//! [`ReqwestForwardClient`]; tests inject [`MockForwardClient`],
//! which records every call and returns a canned [`ForwardResponse`]
//! — keeping the router tests off the network.

pub mod kbs_forward;
pub mod miner_forward;
pub mod vali_forward;

pub use kbs_forward::ReqwestForwardClient;
pub use miner_forward::{
    MinerForward, MinerForwardError, MinerForwardResponse, MockMinerForward, OrderKind,
    RecordedMinerForward, RecordedStatusForward, ReqwestMinerForward, MAX_MINER_ORDER_BODY,
    MAX_MINER_RESPONSE_BYTES,
};

use crate::stages::envelope::ValidatedEnvelope;
use async_trait::async_trait;

/// Hard upper bound on a relayed envelope body, in bytes.
///
/// PR-H8 introduces this cap: PR-H3's containment was per-source rate
/// limiting + a bounded validate→forward queue — neither bounds a
/// *single* body's size. The miner-facing axum router applies this
/// value via [`axum::extract::DefaultBodyLimit`] **before** any CBOR
/// decode, so a hostile oversized body is rejected (`413`) at the
/// HTTP layer without ever reaching the recursion-bounded canonical-
/// CBOR parser. `256 KiB` matches `agent-initramfs`'s
/// `MAX_RESPONSE_BYTES` — a `Signed*` envelope is a few KiB, so the
/// cap is generous for legitimate traffic yet bounds a hostile
/// allocation.
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;

/// The upstream's response to a forwarded envelope.
///
/// `body` is relayed back to the miner **verbatim** by the router
/// (`content-type: application/cbor`) — Edge does not decode it. For
/// a Miner→Inner kind the body is usually empty (telemetry ingest
/// acknowledgements), but for a `KbsRequest` it carries the signed
/// (HPKE-wrapped) KBS release response, opaque to Edge (§5.6).
#[derive(Debug, Clone)]
pub struct ForwardResponse {
    /// Upstream HTTP status code.
    pub status: u16,
    /// Upstream response body bytes — relayed to the miner verbatim.
    pub body: Vec<u8>,
}

/// Static-classifier error from a forward attempt. Same
/// `&'static str`-only `Display` discipline as
/// [`crate::pipeline::EdgeError`] — the inner classifier is drawn
/// from a closed vocabulary, never caller-built text, and the
/// `Display` renders only the outer class so a forward failure
/// cannot leak a URL / header / body into a log line.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    /// The HTTP client could not be built (bad TLS config, etc.).
    /// Boot-time only — surfaced so `main` can fail-closed.
    #[error("forward-client-build")]
    ClientBuild,
    /// The request did not reach the upstream, or no response was
    /// received: DNS, connect, TLS, or timeout. Distinct from an
    /// upstream that answered with a non-2xx status (that is a
    /// successful [`ForwardResponse`] the router maps to `502`).
    #[error("forward-transport")]
    Transport,
    /// The upstream response body exceeded [`MAX_ENVELOPE_BYTES`].
    /// Rejected outright rather than relayed truncated.
    #[error("forward-response-too-large")]
    ResponseTooLarge,
    /// Reading the upstream response body failed mid-stream.
    #[error("forward-response-read")]
    ResponseRead,
    /// A served-delivery receipt could not be split into its
    /// `{body_hex, sig_hex, vm_id}` for the vali JSON ingest — the body
    /// was already typed-decoded at the wire gate, so this is a
    /// should-not-happen internal fault, surfaced fail-closed.
    #[error("forward-receipt-encode")]
    ReceiptEncode,
    /// The host-attestor enrollment orchestration (PR-10b-S2a) could not
    /// build/parse a hop: re-decoding the `HostEnrollment` (already gated
    /// upstream), extracting the `REPORT_DATA` nonce, encoding the KBS
    /// `{enrollment, nonce}` request, or decoding the KBS
    /// `{signed_cert}` response. Surfaced fail-closed — never a fabricated
    /// cert into vali.
    #[error("forward-host-enroll")]
    HostEnroll,
}

impl ForwardError {
    /// Static classifier — identical to the `Display` impl. Named
    /// contract for the telemetry / diagnostic sinks.
    pub fn class(&self) -> &'static str {
        match self {
            ForwardError::ClientBuild => "forward-client-build",
            ForwardError::Transport => "forward-transport",
            ForwardError::ResponseTooLarge => "forward-response-too-large",
            ForwardError::ResponseRead => "forward-response-read",
            ForwardError::ReceiptEncode => "forward-receipt-encode",
            ForwardError::HostEnroll => "forward-host-enroll",
        }
    }
}

/// Forwards a validated envelope's body to the correct inner-plane
/// endpoint, selected by [`MessageKind`](crate::pipeline::MessageKind).
///
/// Every method is an **opaque byte relay**: it ships
/// [`ValidatedEnvelope::body`](crate::stages::envelope::ValidatedEnvelope)
/// verbatim and returns the upstream's [`ForwardResponse`] for the
/// router to relay back to the miner. A method is only called by the
/// route locked to its `MessageKind`, so the routing-correctness
/// invariant ("`KbsRequest` route forwards to the KBS, never to
/// vali") is enforced one layer up, in the router.
///
/// `#[async_trait]` so the router can hold a `dyn ForwardClient` —
/// the production [`ReqwestForwardClient`] and the test
/// [`MockForwardClient`] are both dispatched through the same
/// trait object.
#[async_trait]
pub trait ForwardClient: Send + Sync {
    /// Relay a `KbsRequest` body to the KBS release endpoint.
    async fn forward_kbs_request(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError>;

    /// Relay a `ServedReceipt` body to the vali telemetry broker.
    async fn forward_served_receipt(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError>;

    /// Relay a `ServedAggregate` body to the vali telemetry broker.
    async fn forward_served_aggregate(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError>;

    /// Relay a `StoppedAck` body to the vali lifecycle endpoint.
    async fn forward_stopped_ack(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError>;

    /// Relay a `Heartbeat` body to the vali telemetry ingest (PR-MA-6).
    async fn forward_heartbeat(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError>;

    /// Relay a `GracefulExit` body to the vali graceful-exit ingest.
    /// Stamps the connection's mTLS `PeerId` like
    /// [`forward_heartbeat`](Self::forward_heartbeat) so vali resolves
    /// the miner from the relay metadata, never from the opaque body.
    async fn forward_graceful_exit(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError>;

    /// Relay a `VmProgress` body to the vali boot-progress ingest.
    /// Stamps the connection's mTLS `PeerId` like
    /// [`forward_heartbeat`](Self::forward_heartbeat) so vali resolves
    /// the miner from the relay metadata, never from the opaque body.
    async fn forward_vm_progress(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError>;

    /// Relay a `HostAttestorChallenge` body to the vali nonce authority
    /// (PR-10). Stamps the connection's mTLS `PeerId` like
    /// [`forward_heartbeat`](Self::forward_heartbeat) so vali binds the
    /// minted single-use nonce to the relay-metadata `node_id` + the
    /// request's `signer_pubkey`, never a body-declared node. The minted
    /// nonce comes back in the response body and is relayed down verbatim.
    async fn forward_host_attestor_challenge(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError>;

    /// ORCHESTRATE a `HostAttestorEnroll` (PR-10b-S2a). Unlike every other
    /// method this is a **two-hop mint**, not a single opaque relay: the
    /// Edge decodes the `HostEnrollment` in Rust, extracts the vali-minted
    /// nonce from `REPORT_DATA[0..32]`, calls the KBS enroll endpoint, and
    /// on a minted `SignedHostAttestorCert` forwards it to vali's cert
    /// ingest (stamping the mTLS `PeerId`). Fail-closed at every hop: a KBS
    /// 4xx/5xx is surfaced WITHOUT calling vali (the returned
    /// [`ForwardResponse`] carries the KBS status, which the router maps to
    /// `502`); a vali reject is surfaced verbatim — never a retry into a
    /// false-attested state.
    async fn forward_host_attestor_enroll(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError>;

    /// Relay a `HostAttestorBeacon` body to vali's host-attestor heartbeat
    /// ingest (PR-10b-S2a). Stamps the connection's mTLS `PeerId` like
    /// [`forward_heartbeat`](Self::forward_heartbeat) so vali resolves the
    /// host `node_id` from the relay metadata, never from the opaque
    /// `SignedHostBeacon` body.
    async fn forward_host_attestor_beacon(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError>;

    /// Relay a `VmLiveAttestation` body to the vali uptime-coverage
    /// ingest (§23).
    ///
    /// No peer-id stamp and no bearer token, unlike every other vali
    /// relay here: the body is signed by the KBS L0 key and vali
    /// verifies it against its own pinned copy, so the relay carries no
    /// authority at all. A miner cannot mint one (only a KBS that just
    /// verified a fresh SNP report from inside the guest can) and cannot
    /// edit one (the L0 signature covers every field).
    async fn forward_vm_live_attestation(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError>;
}

/// A [`ForwardClient`] for tests. Records every forwarded body + the
/// method it was routed through, and returns a canned response (or a
/// canned [`ForwardError`]). Keeps the router tests off the network
/// while still exercising the routing-by-kind logic.
///
/// Unconditionally compiled (not `#[cfg(test)]`) so the separate-
/// crate integration tests in `tests/` — which do not see the lib's
/// `cfg(test)` items — can drive the production router against it.
pub use mock::{MockForwardClient, RecordedForward};

mod mock {
    use super::*;
    use crate::pipeline::MessageKind;
    use std::sync::Mutex;

    /// One recorded forward call: the routed kind + the body bytes
    /// the client was handed (so a test can assert the byte-relay was
    /// verbatim).
    #[derive(Debug, Clone)]
    pub struct RecordedForward {
        /// Which `forward_*` method the router invoked.
        pub kind: MessageKind,
        /// The body bytes passed through — should equal the
        /// envelope's body the miner posted.
        pub body: Vec<u8>,
    }

    /// Canned-response forward client for tests.
    pub struct MockForwardClient {
        /// What every `forward_*` call returns: `Ok` canned response
        /// or `Err` canned classifier.
        outcome: Mutex<Result<ForwardResponse, ForwardError>>,
        /// Every call, in order — drives the routing-correctness
        /// assertions.
        calls: Mutex<Vec<RecordedForward>>,
        /// Artificial delay before each `forward_*` call answers.
        /// `None` ⇒ answer immediately. Lets a test prove a SLOW
        /// forward is still relayed + audited (never cut short by a
        /// request timeout).
        delay: Option<std::time::Duration>,
    }

    impl MockForwardClient {
        /// A mock that returns `status` + `body` for every call.
        pub fn with_response(status: u16, body: Vec<u8>) -> Self {
            Self {
                outcome: Mutex::new(Ok(ForwardResponse { status, body })),
                calls: Mutex::new(Vec::new()),
                delay: None,
            }
        }

        /// A mock that waits `delay` before answering `status` + `body`
        /// — drives the "a slow forward is still relayed + audited,
        /// never cut into an un-audited 408" router test.
        pub fn with_delayed_response(
            status: u16,
            body: Vec<u8>,
            delay: std::time::Duration,
        ) -> Self {
            Self {
                outcome: Mutex::new(Ok(ForwardResponse { status, body })),
                calls: Mutex::new(Vec::new()),
                delay: Some(delay),
            }
        }

        /// A mock whose every `forward_*` call fails with `err` —
        /// drives the "forward transport failure → `502`" router test.
        pub fn with_error(err: ForwardError) -> Self {
            Self {
                outcome: Mutex::new(Err(err)),
                calls: Mutex::new(Vec::new()),
                delay: None,
            }
        }

        /// Every forward call recorded so far, in order. A poisoned
        /// lock (a panic in another call) yields the inner `Vec`
        /// anyway — the mock has no `&'static str` discipline to
        /// uphold and `unwrap`/`expect` are denied crate-wide outside
        /// `cfg(test)`, so it recovers rather than re-panicking.
        pub fn calls(&self) -> Vec<RecordedForward> {
            match self.calls.lock() {
                Ok(g) => g.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }

        /// Apply the configured `delay` (if any), record the call, and
        /// return the canned outcome. `async` so a test can prove the
        /// router does NOT cut a slow forward short.
        async fn delay_record_and_answer(
            &self,
            kind: MessageKind,
            env: &ValidatedEnvelope,
        ) -> Result<ForwardResponse, ForwardError> {
            if let Some(d) = self.delay {
                tokio::time::sleep(d).await;
            }
            let record = RecordedForward {
                kind,
                body: env.body_bytes().to_vec(),
            };
            match self.calls.lock() {
                Ok(mut g) => g.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            let outcome = match self.outcome.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            match &*outcome {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(match e {
                    ForwardError::ClientBuild => ForwardError::ClientBuild,
                    ForwardError::Transport => ForwardError::Transport,
                    ForwardError::ResponseTooLarge => ForwardError::ResponseTooLarge,
                    ForwardError::ResponseRead => ForwardError::ResponseRead,
                    ForwardError::ReceiptEncode => ForwardError::ReceiptEncode,
                    ForwardError::HostEnroll => ForwardError::HostEnroll,
                }),
            }
        }
    }

    #[async_trait]
    impl ForwardClient for MockForwardClient {
        async fn forward_kbs_request(
            &self,
            env: &ValidatedEnvelope,
        ) -> Result<ForwardResponse, ForwardError> {
            self.delay_record_and_answer(MessageKind::KbsRequest, env)
                .await
        }

        async fn forward_served_receipt(
            &self,
            env: &ValidatedEnvelope,
        ) -> Result<ForwardResponse, ForwardError> {
            self.delay_record_and_answer(MessageKind::ServedReceipt, env)
                .await
        }

        async fn forward_served_aggregate(
            &self,
            env: &ValidatedEnvelope,
        ) -> Result<ForwardResponse, ForwardError> {
            self.delay_record_and_answer(MessageKind::ServedAggregate, env)
                .await
        }

        async fn forward_stopped_ack(
            &self,
            env: &ValidatedEnvelope,
        ) -> Result<ForwardResponse, ForwardError> {
            self.delay_record_and_answer(MessageKind::StoppedAck, env)
                .await
        }

        async fn forward_heartbeat(
            &self,
            env: &ValidatedEnvelope,
        ) -> Result<ForwardResponse, ForwardError> {
            self.delay_record_and_answer(MessageKind::Heartbeat, env)
                .await
        }

        async fn forward_graceful_exit(
            &self,
            env: &ValidatedEnvelope,
        ) -> Result<ForwardResponse, ForwardError> {
            self.delay_record_and_answer(MessageKind::GracefulExit, env)
                .await
        }

        async fn forward_vm_progress(
            &self,
            env: &ValidatedEnvelope,
        ) -> Result<ForwardResponse, ForwardError> {
            self.delay_record_and_answer(MessageKind::VmProgress, env)
                .await
        }

        async fn forward_host_attestor_challenge(
            &self,
            env: &ValidatedEnvelope,
        ) -> Result<ForwardResponse, ForwardError> {
            self.delay_record_and_answer(MessageKind::HostAttestorChallenge, env)
                .await
        }

        async fn forward_host_attestor_enroll(
            &self,
            env: &ValidatedEnvelope,
        ) -> Result<ForwardResponse, ForwardError> {
            self.delay_record_and_answer(MessageKind::HostAttestorEnroll, env)
                .await
        }

        async fn forward_host_attestor_beacon(
            &self,
            env: &ValidatedEnvelope,
        ) -> Result<ForwardResponse, ForwardError> {
            self.delay_record_and_answer(MessageKind::HostAttestorBeacon, env)
                .await
        }

        async fn forward_vm_live_attestation(
            &self,
            env: &ValidatedEnvelope,
        ) -> Result<ForwardResponse, ForwardError> {
            self.delay_record_and_answer(MessageKind::VmLiveAttestation, env)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_error_display_is_static_and_matches_class() {
        for err in [
            ForwardError::ClientBuild,
            ForwardError::Transport,
            ForwardError::ResponseTooLarge,
            ForwardError::ResponseRead,
        ] {
            assert_eq!(err.class(), err.to_string());
        }
    }

    #[test]
    fn max_envelope_bytes_is_256_kib() {
        // Pinned so a reviewer can grep the cap; matches the
        // `agent-initramfs` KBS-response cap.
        assert_eq!(MAX_ENVELOPE_BYTES, 256 * 1024);
    }
}
