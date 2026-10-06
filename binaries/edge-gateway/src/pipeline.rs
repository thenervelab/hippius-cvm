//! Relay-loop orchestration.
//!
//! Each [`relay_once`] call executes one iteration of the §9 diode
//! loop:
//!
//! 1. **accept** — receive bytes on one of the two interfaces
//!    (PR-H4 wires the real `tokio::net::TcpListener` + mTLS;
//!    PR-H1..H3 return a canned canonical-CBOR envelope).
//! 2. **rate_limit** (PR-H3) — per-source token bucket. If the
//!    source IP has exhausted its bucket, the envelope is dropped
//!    AT THE WIRE — no validate cost, no forward cost. The shed is
//!    attributed to the source IP for the `edge_gw_shed_total`
//!    metric.
//! 3. **validate_canonical** — RFC 8949 §4.2.1 canonical-CBOR check
//!    AND per-`MessageKind` `deny_unknown_fields` decode against
//!    the pinned `hippius-types` schema. Any non-canonical /
//!    wrong-shape input is dropped (§10). Returns
//!    [`stages::envelope::ValidatedEnvelope`] on success — the
//!    only path to producing one.
//! 4. **enqueue** (PR-H3) — bounded `mpsc` queue between this task
//!    and the long-running forward worker. If the queue is full,
//!    the validated envelope is dropped (§10 "bounded queues
//!    before anything reaches inner"). The shed is attributed to
//!    the source IP.
//! 5. **forward** — pass the envelope to the destination interface.
//!    Accepts ONLY `ValidatedEnvelope`, so the validate-before-
//!    forward order is enforced at compile time (typestate;
//!    `forward(RawEnvelope)` does not type-check).
//! 6. **log** — structured static-string classifier; never bytes.
//!
//! ## Error logging discipline
//!
//! Every variant of [`EdgeError`] has a `Display` that is a
//! `&'static str` — there is no `{0}` interpolation that could
//! splice in a `hippius-types` decode message or any caller-built
//! string. The binary logs via [`EdgeError::class`] for clarity,
//! but even an accidental `eprintln!("{err}")` in a future PR
//! would not leak plaintext.

use crate::mtls::PeerId;
use crate::queue::{BoundedSink, SendOutcome};
use crate::rate_limit::PerSourceRateLimiter;
use crate::stages::{accept, log, validate};
use crate::telemetry::{TelemetryEvent, TelemetrySink};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stage tag used by [`EdgeError::Todo`] and by structured logs.
/// Stable string forms ship via [`Stage::as_class_str`] so the §20
/// logging discipline (static classifiers only) is preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// `accept` — receive an envelope on one of the two interfaces.
    Accept,
    /// `rate_limit` — PR-H3 per-source token bucket.
    RateLimit,
    /// `validate_canonical` — RFC 8949 §4.2.1 canonical-CBOR gate.
    ValidateCanonical,
    /// `enqueue` — PR-H3 bounded validate→forward queue.
    Enqueue,
    /// `forward` — pass the envelope across the diode.
    Forward,
}

impl Stage {
    pub fn as_class_str(self) -> &'static str {
        match self {
            Stage::Accept => "accept",
            Stage::RateLimit => "rate-limit",
            Stage::ValidateCanonical => "validate-canonical",
            Stage::Enqueue => "enqueue",
            Stage::Forward => "forward",
        }
    }
}

/// Canonical §9/§10 stage order. Documentation: the *actual* ordering
/// guarantee for `validate → forward` is the typestate barrier
/// ([`stages::envelope::ValidatedEnvelope`]); the limit/enqueue
/// ordering relative to that is enforced by `relay_once`'s body
/// (rate-limit fails before validate; enqueue fails after validate).
/// This constant is the human-readable map and the source of truth
/// for the `section_9_order_*` integration tests.
pub const SECTION_9_ORDER: [Stage; 5] = [
    Stage::Accept,
    Stage::RateLimit,
    Stage::ValidateCanonical,
    Stage::Enqueue,
    Stage::Forward,
];

/// Diode direction. §9: control flows inner → miner (signed); telemetry
/// flows miner → inner via a queue the inner side **pulls** from.
///
/// `Serialize`/`Deserialize` (kebab-case, matching [`Direction::as_class_str`])
/// so PR-H6's [`crate::wire::EdgeTelemetryEnvelope`] can carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    /// Miner → Edge → (inner pull-broker). Telemetry, attestation
    /// requests proxied to the KBS, etc.
    MinerToInner,
    /// (Inner control plane) → Edge → miner. Signed control
    /// envelopes only — Edge does not author them.
    InnerToMiner,
}

impl Direction {
    pub fn as_class_str(self) -> &'static str {
        match self {
            Direction::MinerToInner => "miner-to-inner",
            Direction::InnerToMiner => "inner-to-miner",
        }
    }
}

/// Wire-format tag for the envelope body. PR-H2 introduces this so
/// the validate stage can type-check the inner CBOR against the
/// right `hippius-types` schema; `forward` still treats the bytes
/// as opaque (§5.6).
///
/// Each kind is locked to a single [`Direction`] — a Miner that
/// sends a `KbsResponse`-shaped message (Inner→Miner schema) is an
/// injection attempt and gets dropped at validate.
///
/// `Serialize`/`Deserialize` (kebab-case, matching [`MessageKind::as_class_str`])
/// so PR-H6's [`crate::wire::EdgeTelemetryEnvelope`] can carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MessageKind {
    /// `Miner → Inner`. Wraps `{cose_ticket, snp_report, kbs_nonce}`
    /// (see `kbs_transport::wire::ReleaseRequestBody`). Edge validates
    /// the 3-field wrapper shape; the COSE_Sign1 signature on
    /// `cose_ticket` is opaque to Edge (verified by the KBS).
    KbsRequest,
    /// `Inner → Miner`. `hippius_types::release::SignedResponse` =
    /// `{body, sig}`. Both fields are opaque to Edge — the body is
    /// canonical-CBOR of the signed `KbsResponse`, but Edge has no
    /// pinned KBS verifying key (§5.6 / §22).
    KbsResponse,
    /// `Miner → Inner`. `hippius_types::stopped::SignedStoppedAck` —
    /// the §24/§25 EOL acknowledgement. Vali's `apps.lifecycle`
    /// verifies the signature; Edge only checks the envelope shape.
    StoppedAck,
    /// `Miner → Inner`. `hippius_types::served_receipt::
    /// SignedServedDeliveryReceipt` — per-VM compute-served telemetry
    /// signed by the tenant guest.
    ServedReceipt,
    /// `Miner → Inner`. `hippius_types::audit_vm::
    /// SignedServedDeliveryAggregate` — the Audit-VM-cosigned
    /// aggregate (§23).
    ServedAggregate,
    /// `Miner → Inner`. `hippius_types::heartbeat::SignedMinerHeartbeat`
    /// — the §K periodic miner liveness heartbeat (PR-MA-6). Vali's
    /// telemetry ingest verifies the miner-identity signature; Edge
    /// only checks the `{body, sig}` envelope shape.
    Heartbeat,
    /// `Miner → Inner`. `hippius_types::graceful_exit::SignedGracefulExit`
    /// — the signed miner graceful-exit request. Like `Heartbeat`, vali
    /// verifies the miner-identity Ed25519 signature and resolves the
    /// miner from the mTLS
    /// [`HEARTBEAT_PEER_ID_HEADER`](crate::forward::vali_forward::HEARTBEAT_PEER_ID_HEADER);
    /// Edge only checks the `{body, sig}` envelope shape.
    GracefulExit,
    /// `Miner → Inner`. `hippius_types::vm_progress::SignedVmProgress`
    /// — a display-only guest-boot progress milestone (booting /
    /// kek-released / running) the miner-agent emits after a launch is
    /// accepted. Like `Heartbeat`, vali verifies the miner-identity
    /// Ed25519 signature and resolves the miner from the mTLS
    /// [`HEARTBEAT_PEER_ID_HEADER`](crate::forward::vali_forward::HEARTBEAT_PEER_ID_HEADER);
    /// Edge only checks the `{body, sig}` envelope shape.
    VmProgress,
    /// `Miner → Inner`. `hippius_types::host_attestor_challenge::
    /// HostChallengeRequest` — a blackbox host-attestor asking vali to
    /// mint a fresh single-use enrollment nonce (PR-10). Unlike the
    /// signed telemetry kinds this is a `{schema_version, signer_pubkey}`
    /// request, not a `{body, sig}` envelope; Edge validates that shape
    /// (with the 32-byte pubkey length) and relays it. vali binds the
    /// minted nonce to the mTLS-stamped `node_id` + this `signer_pubkey`;
    /// the minted nonce is relayed back down verbatim.
    HostAttestorChallenge,
    /// `Miner → Inner`. `hippius_types::host_attestor::HostEnrollment` — a
    /// blackbox host-attestor's once-per-boot enrollment, relayed UP
    /// (PR-10b-S2a). The Edge decodes the (opaque-to-the-miner) enrollment
    /// in Rust, extracts the vali-minted nonce from `REPORT_DATA[0..32]`,
    /// ORCHESTRATES the KBS mint (`POST /v1/kbs/host-attestor/enroll`), and
    /// on a minted `SignedHostAttestorCert` forwards it to vali's cert
    /// ingest — fail-closed at every hop (a KBS 4xx never reaches vali).
    HostAttestorEnroll,
    /// `Miner → Inner`. `hippius_types::host_attestor::SignedHostBeacon` — a
    /// blackbox host-attestor liveness beacon, relayed UP (PR-10b-S2a). A
    /// `{body, sig}` envelope like the other signed telemetry kinds; the
    /// Edge forwards it to vali's host-attestor heartbeat ingest, stamping
    /// the miner's mTLS `x-hippius-peer-id` (vali resolves the host from
    /// it, never a body-declared node — §5.6).
    HostAttestorBeacon,
    /// `Miner → Inner`. `hippius_types::live_attestation::
    /// SignedLiveAttestation` — the KBS-L0-signed proof a tenant CVM
    /// was ALIVE (§23 uptime coverage). Minted by the KBS only after it
    /// verified a fresh SNP report from inside the guest, so the
    /// relaying miner can neither forge nor edit it; Edge relays the
    /// bytes verbatim and vali verifies the L0 signature.
    VmLiveAttestation,
}

impl MessageKind {
    /// The single direction every kind is allowed to travel in. Any
    /// (direction, kind) pair that disagrees is rejected at validate.
    pub fn expected_direction(self) -> Direction {
        match self {
            MessageKind::KbsRequest
            | MessageKind::StoppedAck
            | MessageKind::ServedReceipt
            | MessageKind::ServedAggregate
            | MessageKind::Heartbeat
            | MessageKind::GracefulExit
            | MessageKind::VmProgress
            | MessageKind::HostAttestorChallenge
            | MessageKind::HostAttestorEnroll
            | MessageKind::HostAttestorBeacon
            | MessageKind::VmLiveAttestation => Direction::MinerToInner,
            MessageKind::KbsResponse => Direction::InnerToMiner,
        }
    }

    pub fn as_class_str(self) -> &'static str {
        match self {
            MessageKind::KbsRequest => "kbs-request",
            MessageKind::KbsResponse => "kbs-response",
            MessageKind::StoppedAck => "stopped-ack",
            MessageKind::ServedReceipt => "served-receipt",
            MessageKind::ServedAggregate => "served-aggregate",
            MessageKind::Heartbeat => "heartbeat",
            MessageKind::GracefulExit => "graceful-exit",
            MessageKind::VmProgress => "vm-progress",
            MessageKind::HostAttestorChallenge => "host-attestor-challenge",
            MessageKind::HostAttestorEnroll => "host-attestor-enroll",
            MessageKind::HostAttestorBeacon => "host-attestor-beacon",
            MessageKind::VmLiveAttestation => "vm-live-attestation",
        }
    }
}

#[derive(Debug, Error)]
pub enum EdgeError {
    /// PR-H1 sentinel: the named stage has no real implementation
    /// yet. PR-H2..H6 replace each `Todo` return with a real one.
    ///
    /// The `Display` is a static class string — no `{0:?}` of the
    /// `Stage` variant, so even an accidental `eprintln!("{err}")`
    /// could not splice in caller-built text. Use [`Self::class`]
    /// or pattern-match the variant if you need the stage tag.
    #[error("stage-not-implemented")]
    Todo(Stage),

    /// The wire bytes were not canonical CBOR (§10 schema gate).
    /// Display is a static class string — the `&'static str`
    /// payload is kept for internal pattern-matching but is NOT
    /// formatted into the rendered error.
    #[error("non-canonical-cbor")]
    NonCanonical(&'static str),

    /// `hippius-types` reported a decode error during the
    /// canonical-CBOR check. The inner error is retained for
    /// debugging via `Debug`, but the `Display` impl emits only a
    /// static class string — there is no path from this variant to
    /// a logged decode message.
    #[error("hippius-types-decode")]
    HippiusTypes(#[from] hippius_types::HippiusTypesError),

    /// PR-H2: canonical-CBOR passed but the typed decode against the
    /// declared `MessageKind` failed (wrong direction, missing
    /// field, unknown field, byte-length / range violation). The
    /// inner `&'static str` is a stable classifier pulled from a
    /// closed vocabulary (`direction-mismatch`, `decode`, …); the
    /// `Display` impl is static so even an accidental `eprintln!
    /// ("{err}")` cannot leak bytes.
    #[error("schema-invalid")]
    SchemaInvalid(&'static str),

    /// PR-H3: the per-source token bucket was empty when this
    /// envelope arrived. The accept-side caller drops the bytes
    /// (`RawEnvelope`'s drop deallocates) and bumps the shed
    /// counter. The source gets no signal it was rate-limited —
    /// §10 "drop at the wire", opaque relay.
    #[error("rate-limited")]
    RateLimited,

    /// PR-H3: validate succeeded but the bounded validate→forward
    /// queue was at capacity. Same handling: shed counter bumps,
    /// envelope is dropped, no response.
    #[error("queue-full")]
    QueueFull,

    /// PR-H3: the bounded queue's consumer (the forward worker) is
    /// gone — RX half dropped, presumably because the worker task
    /// crashed. Process-level fail-closed: the relay has lost its
    /// inner side and must exit so PR-H5's HA peer can take over.
    /// Distinct from `QueueFull` because the audit response is
    /// different (process exit vs. counter bump).
    #[error("forward-worker-gone")]
    WorkerGone,

    /// PR-H4: the mTLS termination failed — handshake aborted,
    /// peer presented no cert / unknown CA / revoked cert / cert
    /// without a usable identity carrier, OR the [`crate::mtls::CrlStore`]
    /// is currently unhealthy. The inner `&'static str` is a stable
    /// classifier (`handshake`, `crl-unhealthy`, `no-peer-cert`,
    /// `peer-id`); the `Display` impl renders ONLY the outer class,
    /// same `&'static str` discipline as the other variants.
    #[error("mtls-failed")]
    MtlsFailed(&'static str),
}

impl EdgeError {
    /// Static classifier identical to the `Display` impl above.
    /// Retained as a named contract for the [`log`] module and
    /// PR-H6 audit envelope.
    pub fn class(&self) -> &'static str {
        match self {
            EdgeError::Todo(_) => "stage-not-implemented",
            EdgeError::NonCanonical(_) => "non-canonical-cbor",
            EdgeError::HippiusTypes(_) => "hippius-types-decode",
            EdgeError::SchemaInvalid(_) => "schema-invalid",
            EdgeError::RateLimited => "rate-limited",
            EdgeError::QueueFull => "queue-full",
            EdgeError::WorkerGone => "forward-worker-gone",
            EdgeError::MtlsFailed(_) => "mtls-failed",
        }
    }
}

/// Run one iteration of the §9/§10 diode loop in `direction` for an
/// inbound message tagged as `kind`, attributed to source `peer`.
/// PR-H4 swaps the PR-H3 socket-IP `peer` for an mTLS-derived
/// [`PeerId`]: the rate-limit bucket key is now the cryptographic
/// identity the peer presented at handshake (stable across NAT,
/// stable across 90-day cert rotation per §B Q11).
///
/// `Ok(())` means the envelope is in the bounded queue — the
/// forward worker drains it asynchronously. A `Err(QueueFull)` /
/// `Err(RateLimited)` is a *normal* shed (counter bumped, log
/// emitted); a `Err(WorkerGone)` is a process-level fail-closed.
///
/// PR-H6: every call emits exactly ONE signed telemetry record via
/// `telemetry` — relayed or shed. The record carries counters +
/// routing tags only (peer, direction, kind, byte counts, shed
/// flag/reason); it never carries body bytes (§5.6 opacity). The
/// emission is best-effort: a telemetry / audit failure is logged by
/// the sink, never surfaced into this function's `Result`.
pub async fn relay_once(
    direction: Direction,
    kind: MessageKind,
    peer: PeerId,
    limiter: &PerSourceRateLimiter,
    sink: &BoundedSink,
    telemetry: &dyn TelemetrySink,
) -> Result<(), EdgeError> {
    let raw = accept::accept(direction, kind, peer.clone()).await?;
    // Captured before the wire gate consumes `raw`, so it is
    // available to the telemetry record on every outcome below.
    let bytes_in = raw.body_len() as u64;

    // One telemetry record per transaction (PR-H6). The closure is
    // invoked exactly once on every path — relayed or shed — so the
    // §15 "every transaction is audited" invariant holds structurally.
    let emit = |bytes_out: u64, shed: bool, shed_reason: Option<&'static str>| {
        telemetry.record(TelemetryEvent {
            peer: peer.clone(),
            direction,
            message_kind: kind,
            bytes_in,
            bytes_out,
            shed,
            shed_reason,
        });
    };

    // PR-H3 rate-limit BEFORE validate. Saves the CBOR + typed
    // decode cost on shed traffic (the cheap-to-attack DoS path),
    // and means a malformed-bytes flood from a single source ALSO
    // gets shed by the limiter rather than burning validate cycles.
    // `try_acquire` bumps the per-peer shed counter internally on
    // false — no double-attribution downstream. PR-H4: key is the
    // mTLS-derived `PeerId`, not the socket IP.
    //
    // Review nit on PR-H3 v1: the "accepted" log used to fire BEFORE
    // this check, doubling log volume under a flood. Moved here so
    // shed envelopes log exactly once ("rate-limited") instead of
    // twice ("accepted" + "rate-limited").
    if !limiter.try_acquire(&peer) {
        log::log_shed(direction, &peer, "rate-limited");
        // `raw` drops here — bytes deallocate, no forward.
        drop(raw);
        emit(0, true, Some("rate-limited"));
        return Err(EdgeError::RateLimited);
    }
    log::log_raw(&raw, "accepted");

    // Wire gate. Consumes `raw` and yields a `ValidatedEnvelope`
    // (typestate barrier — only path to producing one). A future
    // PR cannot call `forward(raw)` without first going through
    // this stage; the type system rejects it at compile time.
    let validated = match validate::validate(raw) {
        Ok(v) => v,
        Err(err) => {
            // Schema-invalid / non-canonical / typed-decode failure —
            // a shed at the wire gate. Attribute it with the error's
            // own static classifier (`schema-invalid`, … — never
            // caller text).
            emit(0, true, Some(err.class()));
            return Err(err);
        }
    };
    log::log_validated(&validated, "validated");

    // PR-H3 bounded queue. `try_send` is non-blocking; on Full we
    // shed (counter + log + drop the returned envelope). Worker-gone
    // is a distinct fail-closed outcome (the process exits — PR-H5
    // active/active means miners just re-resolve onto the sister).
    match sink.try_send(validated) {
        SendOutcome::Enqueued => {
            // Relayed: an opaque relay egresses the body verbatim, so
            // bytes_out == bytes_in.
            emit(bytes_in, false, None);
            Ok(())
        }
        SendOutcome::QueueFull(env) => {
            limiter.note_shed(&peer);
            log::log_validated(&env, "queue-full");
            emit(0, true, Some("queue-full"));
            Err(EdgeError::QueueFull)
        }
        SendOutcome::WorkerGone => {
            log::log_shed(direction, &peer, "forward-worker-gone");
            emit(0, true, Some("forward-worker-gone"));
            Err(EdgeError::WorkerGone)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_9_order_lists_five_stages_in_canonical_order() {
        // PR-H3 expanded the stage list from 3 → 5 with the addition
        // of `RateLimit` (after Accept, before ValidateCanonical) and
        // `Enqueue` (after ValidateCanonical, before Forward). The
        // canonical order is the source of truth for the integration-
        // test `section_9_order_matches_pinned_const` test in
        // `tests/pipeline.rs`.
        assert_eq!(SECTION_9_ORDER.len(), 5);
        assert_eq!(SECTION_9_ORDER[0], Stage::Accept);
        assert_eq!(SECTION_9_ORDER[1], Stage::RateLimit);
        assert_eq!(SECTION_9_ORDER[2], Stage::ValidateCanonical);
        assert_eq!(SECTION_9_ORDER[3], Stage::Enqueue);
        assert_eq!(SECTION_9_ORDER[4], Stage::Forward);
    }

    #[test]
    fn edge_error_display_is_static_and_matches_class() {
        // Display MUST equal `class()` byte-for-byte — that's the
        // contract that lets us drop the class()-vs-Display split
        // in PR-H6's audit sink without re-checking each call site.
        // Pins every variant (including `HippiusTypes`, whose inner
        // `HippiusTypesError::Cbor(String)` DOES interpolate a
        // runtime string — the outer thiserror MUST NOT include
        // `{0}` or that runtime string would leak via `Display`).
        for err in [
            EdgeError::Todo(Stage::Forward),
            EdgeError::NonCanonical("empty-body"),
            EdgeError::SchemaInvalid("any-classifier"),
            EdgeError::HippiusTypes(hippius_types::HippiusTypesError::Cbor(
                "synthetic decode message".into(),
            )),
            EdgeError::RateLimited,
            EdgeError::QueueFull,
            EdgeError::WorkerGone,
            EdgeError::MtlsFailed("handshake"),
        ] {
            assert_eq!(err.class(), err.to_string());
        }
    }

    #[test]
    fn stage_class_strings_are_stable() {
        assert_eq!(Stage::Accept.as_class_str(), "accept");
        assert_eq!(Stage::RateLimit.as_class_str(), "rate-limit");
        assert_eq!(
            Stage::ValidateCanonical.as_class_str(),
            "validate-canonical"
        );
        assert_eq!(Stage::Enqueue.as_class_str(), "enqueue");
        assert_eq!(Stage::Forward.as_class_str(), "forward");
    }

    #[test]
    fn direction_class_strings_are_stable() {
        assert_eq!(Direction::MinerToInner.as_class_str(), "miner-to-inner");
        assert_eq!(Direction::InnerToMiner.as_class_str(), "inner-to-miner");
    }
}
