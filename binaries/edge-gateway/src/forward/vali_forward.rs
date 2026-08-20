//! vali-side forward route constants (PR-H8, §H phase 2).
//!
//! The [`ReqwestForwardClient`](super::ReqwestForwardClient) is the
//! shared transport; this module pins the **inner-plane paths** the
//! three vali-bound `MessageKind`s relay to, plus the
//! spec-vs-reality reconciliation for each choice.
//!
//! ## Route reconciliation (verified against the `vali` Django app)
//!
//! The PR-H8 brief said "ServedReceipt + ServedAggregate → vali
//! `/v1/telemetry/ingest`; StoppedAck → the real vali lifecycle
//! route." Reading `vali/apps/telemetry/urls.py`,
//! `vali/apps/telemetry/views.py`, `vali/apps/lifecycle/urls.py`,
//! and `vali/apps/lifecycle/views.py`:
//!
//! - **`/v1/telemetry/ingest`** is the §9 pull-only telemetry-broker
//!   ingress (`TelemetryIngestView`). It is the single real ingest
//!   route, so `ServedReceipt` AND `ServedAggregate` both relay
//!   here — consistent with the brief.
//!
//! - **StoppedAck** has no dedicated ingest route. vali verifies a
//!   stopped-ack inside `POST /v1/vm/<vm_id>/transition`
//!   (`VmTransitionView`), which needs a `vm_id` *path parameter*.
//!   The Edge is an **opaque relay** (§5.6): it routes by URL and
//!   relays the envelope shell — it does NOT decode the inner
//!   `SignedStoppedAck` body, so it cannot extract a `vm_id` to
//!   build that path. Forwarding to `/v1/vm/<vm_id>/transition` is
//!   therefore structurally impossible without breaking opacity.
//!   Per the brief's fallback ("`/v1/telemetry/ingest` if lifecycle
//!   has no ingress route"), `StoppedAck` relays to the telemetry
//!   broker too — it is the only vali route that accepts an opaque
//!   POST body without a decoded path/field. The broker's
//!   `EnvelopeKind` discriminates kinds itself; a vali-side PR can
//!   add a `stopped_ack` kind without any Edge change.
//!
//! ## Cross-service shape gap — closed for `Heartbeat` (PR-Part4-B)
//!
//! `TelemetryIngestView` expects a **JSON** body (`{schema_version,
//! source, source_id, kind, body_hex, sig_hex}`) for the
//! `ServedReceipt` / `ServedAggregate` / `StoppedAck` kinds. The Edge
//! relays the CBOR body verbatim with `content-type: application/cbor`
//! — the LOCKED opaque-relay invariant: Edge must not decode the inner
//! protocol to synthesise vali's JSON wrapper (doing so would
//! re-introduce the §5.6 plaintext-inspection path PR-H1 structurally
//! forbids). Bridging the CBOR-envelope ↔ JSON-wrapper shapes for
//! those three kinds is still a pending vali-side change; until then a
//! forwarded envelope of those kinds draws a vali `400`, which the
//! router maps to a miner-facing `502` and audits as a
//! `ForwardFailed`-class transaction.
//!
//! For **`Heartbeat`** the gap is **closed**: PR-Part4-B teaches
//! `TelemetryIngestView` to accept a raw canonical-CBOR
//! `SignedMinerHeartbeat` under `content-type: application/cbor`. vali
//! cannot read the `miner_id` from that opaque body, so it cannot pick
//! the miner's registered verifying key on its own — therefore
//! [`forward_heartbeat`](super::ReqwestForwardClient::forward_heartbeat)
//! attaches the connection's mTLS [`PeerId`](crate::mtls::PeerId) as
//! the [`HEARTBEAT_PEER_ID_HEADER`] HTTP header. The `PeerId` is the
//! CA-issued identity the miner already proved at the mTLS handshake
//! (auditable, never secret) — relaying it as relay metadata does NOT
//! decode the inner protocol, so the §5.6 opacity invariant holds. The
//! Ed25519 signature on the body remains the actual trust gate vali
//! enforces; the header only selects which registered key to check
//! against.

/// vali §9 telemetry-broker ingest path — `ServedReceipt`,
/// `ServedAggregate`, and `StoppedAck` relay here. Appended to the
/// configured vali base URL.
pub const TELEMETRY_INGEST_PATH: &str = "/v1/telemetry/ingest";

/// vali path a `StoppedAck` relays to. See the module-level route
/// reconciliation: lifecycle's `/v1/vm/<vm_id>/transition` needs a
/// decoded `vm_id` the opaque relay cannot supply, so a stopped-ack
/// goes to the kind-discriminating telemetry broker like the other
/// Miner→Inner telemetry kinds.
pub const STOPPED_ACK_PATH: &str = TELEMETRY_INGEST_PATH;

/// vali path a `Heartbeat` (PR-MA-6) relays to — the §9 telemetry
/// broker ingest. The Edge stays an opaque byte relay: it POSTs the
/// raw canonical-CBOR `SignedMinerHeartbeat` verbatim under
/// `content-type: application/cbor` and never decodes it. vali (PR-
/// Part4-B) treats a `application/cbor` POST here as a heartbeat and
/// resolves the miner from the [`HEARTBEAT_PEER_ID_HEADER`] header.
pub const HEARTBEAT_INGEST_PATH: &str = TELEMETRY_INGEST_PATH;

/// vali path a `GracefulExit` relays to — a **dedicated** handler,
/// distinct from the §9 telemetry-broker ingest. Unlike a heartbeat
/// (which enqueues a telemetry envelope) a graceful-exit drives a
/// quarantine + auto-migration, so vali exposes its own view here. The
/// Edge stays an opaque byte relay: it POSTs the raw canonical-CBOR
/// `SignedGracefulExit` verbatim under `content-type: application/cbor`,
/// never decodes it, and stamps the connection's mTLS
/// [`HEARTBEAT_PEER_ID_HEADER`] so vali resolves the miner from the
/// relay metadata (the `miner_id` is not readable from the opaque body —
/// §5.6). The Ed25519 signature on the body remains vali's trust gate.
pub const GRACEFUL_EXIT_INGEST_PATH: &str = "/v1/telemetry/graceful-exit";

/// vali path a `VmProgress` relays to — a **dedicated** handler for the
/// display-only guest-boot milestone. Like the graceful-exit relay it
/// POSTs the raw canonical-CBOR `SignedVmProgress` verbatim under
/// `content-type: application/cbor`, never decodes it, and stamps the
/// connection's mTLS [`HEARTBEAT_PEER_ID_HEADER`] so vali resolves the
/// miner from the relay metadata (the `miner_id` is not readable from the
/// opaque body — §5.6). The Ed25519 signature on the body remains vali's
/// trust gate; vali advances the VM's `boot_phase` display field.
pub const VM_PROGRESS_INGEST_PATH: &str = "/v1/telemetry/vm-progress";

/// vali path a `HostAttestorChallenge` relays to (PR-10). vali is the
/// nonce authority: it mints a fresh single-use enrollment nonce bound to
/// the mTLS-stamped `node_id` + the request's `signer_pubkey`, and returns
/// it in the response body (relayed back down to the miner verbatim). The
/// Edge POSTs the raw canonical-CBOR `HostChallengeRequest` under
/// `content-type: application/cbor`, never decodes it, and stamps the
/// connection's mTLS [`HEARTBEAT_PEER_ID_HEADER`] so vali binds the nonce
/// to the relay-metadata `node_id` (never a body-declared one — §5.6).
pub const HOST_ATTESTOR_CHALLENGE_INGEST_PATH: &str = "/v1/telemetry/host-attestor/challenge";

/// vali path a host-attestor **cert** relays to (PR-10b-S2a, PR-8). After
/// the Edge orchestrates the KBS mint of a `SignedHostAttestorCert`, it
/// POSTs the raw canonical-CBOR cert here. The KBS L0 signature is the
/// credential (no bearer token); vali upserts the `HostAttestor` row keyed
/// by the AMD-signed `chip_id`. The Edge still stamps the connection's
/// mTLS [`HEARTBEAT_PEER_ID_HEADER`] as relay metadata (auditable, never a
/// body-declared node).
pub const HOST_ATTESTOR_CERT_INGEST_PATH: &str = "/v1/telemetry/host-attestor/cert";

/// vali path a host-attestor **beacon** relays to (PR-10b-S2a, PR-8). The
/// Edge POSTs the raw canonical-CBOR `SignedHostBeacon` verbatim under
/// `content-type: application/cbor`, never decodes it, and stamps the
/// connection's mTLS [`HEARTBEAT_PEER_ID_HEADER`] — vali resolves the host
/// `node_id` from it (never the opaque beacon body — §5.6) and verifies
/// the Ed25519 signature against the CERTIFIED key with a monotonic-`seq`
/// replay gate.
pub const HOST_ATTESTOR_BEACON_INGEST_PATH: &str = "/v1/telemetry/host-attestor/heartbeat";

/// vali path a tenant-CVM **live attestation** relays to (§23 uptime
/// coverage). The Edge POSTs the raw canonical-CBOR
/// `SignedLiveAttestation` verbatim under `content-type:
/// application/cbor` and never decodes it.
///
/// No peer-id stamp and no bearer token: the body is signed by the KBS
/// L0 key, which vali verifies against its own pinned copy. The relaying
/// miner cannot alter one field of what it carries, and cannot mint one
/// — the artifact exists only because the KBS verified a fresh SNP
/// report from inside a live CVM.
pub const VM_LIVENESS_INGEST_PATH: &str = "/v1/telemetry/vm-liveness";

/// HTTP header [`forward_heartbeat`](super::ReqwestForwardClient::forward_heartbeat)
/// stamps with the connection's mTLS [`PeerId`](crate::mtls::PeerId).
///
/// vali reads it to resolve which registered miner's verifying key to
/// verify the opaque `SignedMinerHeartbeat` against — it cannot read
/// the `miner_id` from the CBOR body without decoding it (§5.6). The
/// `PeerId` is a CA-issued, auditable, non-secret identity; carrying
/// it as relay metadata does not breach opacity. See the module-level
/// "Cross-service shape gap" note.
pub const HEARTBEAT_PEER_ID_HEADER: &str = "x-hippius-peer-id";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_paths_are_stable() {
        assert_eq!(TELEMETRY_INGEST_PATH, "/v1/telemetry/ingest");
        // StoppedAck + Heartbeat share the broker ingress — see docs.
        assert_eq!(STOPPED_ACK_PATH, TELEMETRY_INGEST_PATH);
        assert_eq!(HEARTBEAT_INGEST_PATH, TELEMETRY_INGEST_PATH);
    }

    #[test]
    fn graceful_exit_path_is_dedicated_and_stable() {
        // A graceful-exit drives a quarantine, not a telemetry enqueue —
        // it has its OWN vali handler, NOT the broker ingest. Pinned so a
        // rename on either side surfaces here.
        assert_eq!(GRACEFUL_EXIT_INGEST_PATH, "/v1/telemetry/graceful-exit");
        assert_ne!(GRACEFUL_EXIT_INGEST_PATH, TELEMETRY_INGEST_PATH);
    }

    #[test]
    fn vm_progress_path_is_dedicated_and_stable() {
        // A vm-progress report advances a display field, not a telemetry
        // enqueue — its own vali handler, pinned so a rename surfaces here.
        assert_eq!(VM_PROGRESS_INGEST_PATH, "/v1/telemetry/vm-progress");
        assert_ne!(VM_PROGRESS_INGEST_PATH, TELEMETRY_INGEST_PATH);
    }

    #[test]
    fn host_attestor_paths_are_dedicated_and_stable() {
        // The cert + beacon ingests are dedicated host-attestor handlers,
        // pinned so a rename on either side surfaces here.
        assert_eq!(
            HOST_ATTESTOR_CERT_INGEST_PATH,
            "/v1/telemetry/host-attestor/cert"
        );
        assert_eq!(
            HOST_ATTESTOR_BEACON_INGEST_PATH,
            "/v1/telemetry/host-attestor/heartbeat"
        );
        assert_ne!(HOST_ATTESTOR_CERT_INGEST_PATH, TELEMETRY_INGEST_PATH);
        assert_ne!(HOST_ATTESTOR_BEACON_INGEST_PATH, TELEMETRY_INGEST_PATH);
    }

    #[test]
    fn vm_liveness_path_is_dedicated_and_stable() {
        // The uptime-coverage ingest is its OWN vali handler (a
        // KBS-L0-signed artifact, not a broker enqueue), pinned so a
        // rename on either side surfaces here rather than silently
        // starving the coverage meter — which, once armed, would stop
        // reward accrual.
        assert_eq!(VM_LIVENESS_INGEST_PATH, "/v1/telemetry/vm-liveness");
        assert_ne!(VM_LIVENESS_INGEST_PATH, TELEMETRY_INGEST_PATH);
        assert_ne!(VM_LIVENESS_INGEST_PATH, HOST_ATTESTOR_BEACON_INGEST_PATH);
    }

    #[test]
    fn heartbeat_peer_id_header_is_stable() {
        // vali (PR-Part4-B) reads this exact header name to resolve the
        // miner — a rename on either side silently breaks heartbeat
        // ingest, so the spelling is pinned here.
        assert_eq!(HEARTBEAT_PEER_ID_HEADER, "x-hippius-peer-id");
    }
}
