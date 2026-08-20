//! Telemetry emission — sign every relay transaction, chain it into
//! the audit log (PR-H6, §9 / §15).
//!
//! [`crate::relay_once`] calls [`TelemetrySink::record`] exactly once
//! per transaction — relayed or shed. The production [`TelemetryRecorder`]
//! builds an [`EdgeTelemetryEnvelope`], signs it with the boot-generated
//! [`EdgeSigner`], and appends the [`SignedEdgeTelemetry`] to the
//! hash-chained [`EdgeAuditSink`]. The `counter` field of the envelope
//! is the audit sequence number — a single monotonic value, assigned
//! once under the audit `Mutex`.
//!
//! ## Best-effort, never fail-the-relay
//!
//! `record` returns nothing. An audit-write failure is logged with a
//! static classifier and dropped — it does NOT propagate into the
//! relay path. This mirrors `kbs-core::audit`'s `AuditSink::record`
//! contract: a full disk must not start denying miner traffic. The
//! §15 completeness guarantee is enforced out-of-band (Sentinel
//! pulling `/v1/edge/audit/verify`), not by failing relays.
//!
//! ## Blocking I/O — deferred, documented
//!
//! [`TelemetryRecorder::record`] performs synchronous file I/O (the
//! audit append + its fsyncs) on the async relay path. Under
//! `main.rs`'s current-thread runtime that briefly stalls every other
//! task for the write. This is acceptable ONLY because the accept
//! stage is still the PR-H1 in-memory mock — there is no real miner
//! traffic to stall. The PR-H6 review pass flagged this as a MINOR;
//! the proper fix (a `spawn_blocking` writer or a batched channel)
//! belongs WITH the PR that replaces the mock accept path, so it can
//! be sized against real throughput rather than guessed at against a
//! mock. `kbs-core::audit` — the pattern mirrored here — is likewise
//! synchronous; the chain invariants are identical.

use crate::audit::{AuditError, EdgeAuditSink};
use crate::mtls::PeerId;
use crate::pipeline::{Direction, MessageKind};
use crate::signer::EdgeSigner;
use crate::wire::{EdgeTelemetryEnvelope, SignedEdgeTelemetry, TELEMETRY_DOMAIN};
use std::sync::Arc;

/// One relay transaction's telemetry-relevant facts, handed to
/// [`TelemetrySink::record`] by [`crate::relay_once`].
///
/// Every field is a counter or a routing tag — NEVER a body byte or a
/// decoded inner field (§5.6 opacity). `shed_reason` is a `&'static str`
/// drawn from the closed `EdgeError` classifier vocabulary.
#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    /// mTLS-derived peer identity of the transaction's source.
    pub peer: PeerId,
    /// Diode direction.
    pub direction: Direction,
    /// Declared wire kind.
    pub message_kind: MessageKind,
    /// Bytes received from the source.
    pub bytes_in: u64,
    /// Bytes egressing the diode (`== bytes_in` when relayed, `0`
    /// when shed — an opaque relay does not transform the body).
    pub bytes_out: u64,
    /// Whether the transaction was shed rather than relayed.
    pub shed: bool,
    /// Static shed classifier when `shed`; `None` when relayed.
    pub shed_reason: Option<&'static str>,
}

/// Sink for relay telemetry. [`crate::relay_once`] depends on this
/// trait, not on the concrete [`TelemetryRecorder`], so the relay path
/// stays decoupled from the signing + audit machinery and is testable
/// with [`NoopTelemetry`].
pub trait TelemetrySink {
    /// Record one relay transaction. Best-effort — see the module
    /// docs: an audit-write failure is logged, never propagated.
    fn record(&self, event: TelemetryEvent);
}

/// A [`TelemetrySink`] that discards everything. For tests + any
/// caller of [`crate::relay_once`] that is not the production relay
/// (the unit / integration tests that exercise the pipeline without
/// asserting on telemetry).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopTelemetry;

impl TelemetrySink for NoopTelemetry {
    fn record(&self, _event: TelemetryEvent) {}
}

/// Production telemetry sink: sign + hash-chain every transaction.
///
/// Holds `Arc`s to the [`EdgeSigner`] and [`EdgeAuditSink`] — both are
/// also shared with the `/v1/edge/*` HTTP server, which reads the
/// pubkey + audit head from the same instances.
pub struct TelemetryRecorder {
    signer: Arc<EdgeSigner>,
    audit: Arc<EdgeAuditSink>,
}

impl TelemetryRecorder {
    /// Build a recorder over a shared signer + audit sink.
    pub fn new(signer: Arc<EdgeSigner>, audit: Arc<EdgeAuditSink>) -> Self {
        Self { signer, audit }
    }
}

impl TelemetrySink for TelemetryRecorder {
    fn record(&self, event: TelemetryEvent) {
        let timestamp = now_unix();
        // The build closure runs UNDER the audit `Mutex` (see
        // `EdgeAuditSink::append`): `seq` is the about-to-be-assigned
        // sequence number, which becomes the envelope's `counter`.
        let result = self.audit.append(|seq| {
            let envelope = EdgeTelemetryEnvelope {
                domain: TELEMETRY_DOMAIN.to_string(),
                timestamp,
                counter: seq,
                peer_id: event.peer.as_str().to_string(),
                direction: event.direction,
                message_kind: event.message_kind,
                bytes_in: event.bytes_in,
                bytes_out: event.bytes_out,
                shed: event.shed,
                shed_reason: event.shed_reason.map(str::to_string),
            };
            let body = envelope.to_canonical().map_err(|_| AuditError::Encode)?;
            let sig = self.signer.sign(&body).to_vec();
            Ok(SignedEdgeTelemetry { body, sig })
        });
        if let Err(e) = result {
            log_telemetry_error(e.class());
        }
    }
}

/// Current Unix time in seconds. A clock before the epoch (impossible
/// on a sane host) folds to 0 rather than panicking.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Static-string-only emitter for telemetry anomalies. Same `&'static
/// str` discipline as `revocation::log_crl_error` — `class` is a
/// closed-vocabulary classifier, never caller-built text.
fn log_telemetry_error(class: &'static str) {
    eprintln!("hippius-edge-gateway: anomaly: telemetry: {class}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn event(shed: bool) -> TelemetryEvent {
        TelemetryEvent {
            peer: PeerId::new("hippius-miner:test"),
            direction: Direction::MinerToInner,
            message_kind: MessageKind::ServedReceipt,
            bytes_in: 128,
            bytes_out: if shed { 0 } else { 128 },
            shed,
            shed_reason: if shed { Some("rate-limited") } else { None },
        }
    }

    #[test]
    fn noop_sink_records_nothing() {
        // Pinned: the test sink really is inert.
        let n = NoopTelemetry;
        n.record(event(false));
        n.record(event(true));
    }

    #[test]
    fn recorder_appends_one_chained_record_per_call() {
        let td = TempDir::new().unwrap();
        let signer = Arc::new(EdgeSigner::generate());
        let audit = Arc::new(EdgeAuditSink::open(td.path()).unwrap());
        let recorder = TelemetryRecorder::new(Arc::clone(&signer), Arc::clone(&audit));

        recorder.record(event(false));
        recorder.record(event(true));
        recorder.record(event(false));

        // One chained, internally-consistent record per call. The
        // full "extract the signed envelope back out + verify the
        // signature + check the counters" round-trip lives in
        // `tests/telemetry_integration.rs`.
        let verified = audit.verify().unwrap();
        assert_eq!(verified.records, 3);
        assert_eq!(audit.record_count(), 3);
    }
}
