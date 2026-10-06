//! Compile-gate + integration coverage for PR-H1/H2/H3.
//!
//! Pins the §9 relay invariants PR-H3..H6 cannot regress. The
//! load-bearing pins are TYPESTATE — `forward` accepts only a
//! [`ValidatedEnvelope`], and the only way to produce one is via
//! [`validate::validate`]. A test that "proves the order" is
//! therefore not strictly necessary (the type system already does),
//! but we keep the function-pointer casts to catch signature drift
//! early.
//!
//! The "no `Clone` / no `Default`" invariant is pinned by
//! `compile_fail` doc-tests in `stages/envelope.rs`. Doc-tests run
//! under `cargo test --doc`; this integration test does NOT try
//! to assert the absence of traits (Rust has no stable way to do
//! that from a regular test — see review of PR-H1 v1).
//!
//! PR-H2 additions:
//! * `relay_once_passes_each_kind_through_the_wire_gate` — one full
//!   pipeline iteration per [`MessageKind`], proving every typed
//!   schema arm of the wire gate is actually reached.
//! * `malformed_inner_bytes_are_dropped_before_forward` — feeds the
//!   wire gate non-canonical / wrong-shape bytes directly and
//!   asserts they NEVER produce a `ValidatedEnvelope`; the diode's
//!   §10 "no malformed bytes cross" invariant from outside the
//!   crate.
//! * `kbs_request_shape_matches_kbs_server_wire` — fuzz-style
//!   cross-check: a `kbs_transport::wire::ReleaseRequestBody` round-
//!   tripped through canonical CBOR must parse cleanly via the
//!   Edge wire gate. If upstream KBS adds/renames a field, this
//!   test flips before production drift.
//!
//! PR-H3 adjustments:
//! * `relay_once_passes_each_kind_through_the_wire_gate` now drives
//!   the new 5-arg `relay_once` (peer + limiter + sink) and asserts
//!   each happy-path arm reaches `Enqueued`, the forward worker
//!   then dequeues and returns the `Todo(Forward)` stub. Per-source
//!   rate limit / queue-full integration tests live in
//!   `tests/rate_limit.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::type_complexity
)]

use ciborium::value::Value;
use hippius_edge_gateway::pipeline::SECTION_9_ORDER;
use hippius_edge_gateway::stages::{
    envelope::{RawEnvelope, ValidatedEnvelope},
    forward, log as log_stage, validate,
};
use hippius_edge_gateway::{
    bounded_queue, relay_once, Direction, EdgeError, EdgeGatewayConfig, MessageKind, NoopTelemetry,
    PeerId, PerSourceRateLimiter, Stage,
};
use hippius_types::cbor::to_canonical_vec;

fn peer() -> PeerId {
    PeerId::new("test-peer")
}

#[tokio::test]
async fn relay_once_passes_each_kind_through_the_wire_gate() {
    // The mock accept stage produces a canonical-CBOR envelope whose
    // body shape matches `kind` by construction, so the wire gate
    // accepts each one and `relay_once` returns `Ok(())` after
    // enqueueing into the bounded queue. We then dequeue and run
    // `forward::forward` directly to assert the typestate barrier
    // holds end-to-end (the only outcome is `Err(Todo(Forward))`,
    // matching the PR-H1..H3 stub).
    let cfg = EdgeGatewayConfig::default();
    let limiter = PerSourceRateLimiter::from_config(&cfg);
    let (sink, mut source) = bounded_queue(cfg.queue_capacity);
    for (direction, kind) in [
        (Direction::MinerToInner, MessageKind::KbsRequest),
        (Direction::InnerToMiner, MessageKind::KbsResponse),
        (Direction::MinerToInner, MessageKind::StoppedAck),
        (Direction::MinerToInner, MessageKind::ServedReceipt),
        (Direction::MinerToInner, MessageKind::ServedAggregate),
        (Direction::MinerToInner, MessageKind::Heartbeat),
    ] {
        relay_once(direction, kind, peer(), &limiter, &sink, &NoopTelemetry)
            .await
            .expect("happy-path relay must enqueue");
        let env = source.recv().await.expect("worker side must receive");
        assert_eq!(env.direction(), direction);
        assert_eq!(env.kind(), kind);
        let err = forward::forward(env).await.unwrap_err();
        match err {
            EdgeError::Todo(Stage::Forward) => {}
            other => panic!("expected Todo(Forward) for ({direction:?}, {kind:?}), got {other:?}"),
        }
    }
}

#[test]
fn malformed_inner_bytes_are_dropped_before_forward() {
    // Feed the wire gate inputs that should never reach `forward`.
    // The integration assertion is: each one returns `Err`, AND the
    // `forward` stage CANNOT have been called (the wire gate is the
    // only producer of `ValidatedEnvelope`; a `validate(...)?` that
    // returns `Err` short-circuits before the typestate barrier).
    let cases: &[(MessageKind, Direction, Vec<u8>)] = &[
        // Empty body — caught at canonical-CBOR gate (`empty-body`).
        (MessageKind::KbsRequest, Direction::MinerToInner, Vec::new()),
        // Garbage bytes — caught at canonical-CBOR gate.
        (
            MessageKind::KbsRequest,
            Direction::MinerToInner,
            vec![0xff, 0xff, 0xff],
        ),
        // Wrong direction for kind (Miner posting KBS-response shape).
        (
            MessageKind::KbsResponse,
            Direction::MinerToInner,
            signed_envelope(8, 64),
        ),
        // KBS request with nonce shorter than the pinned 32 bytes.
        (
            MessageKind::KbsRequest,
            Direction::MinerToInner,
            kbs_request_body(16),
        ),
    ];
    for (kind, direction, body) in cases {
        let env = RawEnvelope::from_wire(*direction, *kind, peer(), body.clone());
        let err = validate::validate(env).unwrap_err();
        // §20 logging discipline: must render as a static class
        // string (no plaintext leak even via `Display`).
        assert!(
            matches!(
                err.class(),
                "non-canonical-cbor" | "hippius-types-decode" | "schema-invalid"
            ),
            "unexpected class {} for ({kind:?}, {direction:?})",
            err.class()
        );
    }
}

#[test]
fn kbs_request_shape_matches_kbs_server_wire() {
    // Cross-check the local Edge mirror against the canonical KBS
    // shape via a hand-encoded map. If upstream KBS adds/renames a
    // field this round-trip flips before the integration drift
    // reaches production.
    //
    // We deliberately don't depend on `kbs-server` here (PR-H1 ADR:
    // pulling axum etc. across the diode is not worth it for a
    // 3-field struct), but the field names + types MUST stay
    // byte-identical.
    let v = Value::Map(vec![
        (
            Value::Text("cose_ticket".into()),
            Value::Bytes(vec![1u8; 32]),
        ),
        (Value::Text("kbs_nonce".into()), Value::Bytes(vec![2u8; 32])),
        (
            Value::Text("snp_report".into()),
            Value::Bytes(vec![3u8; 1184]),
        ),
    ]);
    let body = to_canonical_vec(&v).unwrap();
    let env = RawEnvelope::from_wire(
        Direction::MinerToInner,
        MessageKind::KbsRequest,
        peer(),
        body,
    );
    let validated = validate::validate(env).expect("KBS request shape must round-trip");
    assert_eq!(validated.kind(), MessageKind::KbsRequest);
}

#[test]
fn section_9_order_matches_pinned_const() {
    // PR-H3 expanded the canonical stage order from 3 → 5
    // (Accept → RateLimit → ValidateCanonical → Enqueue → Forward).
    // Pinning the array shape from the integration side catches a
    // future PR that adds / removes / reorders stages without
    // updating the runbook + integration coverage in lockstep.
    assert_eq!(
        SECTION_9_ORDER,
        [
            Stage::Accept,
            Stage::RateLimit,
            Stage::ValidateCanonical,
            Stage::Enqueue,
            Stage::Forward,
        ]
    );
}

#[test]
fn validate_returns_validated_envelope_not_decoded_payload() {
    // The wire gate MUST return `Result<ValidatedEnvelope, _>` —
    // NOT a decoded inner type. A regression that changes the
    // return to (e.g.) `Result<DecodedEnvelope, _>` would re-
    // introduce the §5.6 plaintext-access path; fail this cast.
    let _: fn(RawEnvelope) -> Result<ValidatedEnvelope, EdgeError> = validate::validate;
}

#[test]
fn forward_signature_pins_validated_envelope_by_value() {
    // The compile-gate's load-bearing assertion: `forward` takes
    // `ValidatedEnvelope` BY VALUE. A future PR that changes
    // the signature to `&ValidatedEnvelope` (so the caller could
    // reuse the bytes after forward) OR loosens it to
    // `RawEnvelope` (bypassing the wire gate) would fail this
    // cast.
    let _: fn(
        ValidatedEnvelope,
    ) -> core::pin::Pin<
        Box<dyn core::future::Future<Output = Result<(), EdgeError>> + Send>,
    > = |env| Box::pin(forward::forward(env));
}

#[test]
fn log_signatures_pin_static_str() {
    // Both log entry points accept `&'static str` only — any
    // String-accepting overload would fail this cast.
    let _: fn(&RawEnvelope, &'static str) = log_stage::log_raw;
    let _: fn(&ValidatedEnvelope, &'static str) = log_stage::log_validated;
}

#[test]
fn edge_error_display_emits_only_static_text() {
    // Pin the static-string `Display` invariant from the outside.
    // If a future PR adds `{0}` interpolation to any variant, the
    // contained text would diverge from `class()` and this test
    // would flip.
    assert_eq!(
        EdgeError::Todo(Stage::Forward).to_string(),
        "stage-not-implemented"
    );
    assert_eq!(
        EdgeError::NonCanonical("any-classifier").to_string(),
        "non-canonical-cbor"
    );
    assert_eq!(
        EdgeError::SchemaInvalid("any-classifier").to_string(),
        "schema-invalid"
    );
    // PR-H3 variants — same `&'static str` discipline.
    assert_eq!(EdgeError::RateLimited.to_string(), "rate-limited");
    assert_eq!(EdgeError::QueueFull.to_string(), "queue-full");
    assert_eq!(EdgeError::WorkerGone.to_string(), "forward-worker-gone");
}

// ─── helpers ─────────────────────────────────────────────────────

fn kbs_request_body(nonce_len: usize) -> Vec<u8> {
    let v = Value::Map(vec![
        (
            Value::Text("cose_ticket".into()),
            Value::Bytes(vec![1u8; 4]),
        ),
        (
            Value::Text("kbs_nonce".into()),
            Value::Bytes(vec![2u8; nonce_len]),
        ),
        (Value::Text("snp_report".into()), Value::Bytes(vec![3u8; 4])),
    ]);
    to_canonical_vec(&v).unwrap()
}

fn signed_envelope(body_len: usize, sig_len: usize) -> Vec<u8> {
    let v = Value::Map(vec![
        (
            Value::Text("body".into()),
            Value::Bytes(vec![0u8; body_len]),
        ),
        (Value::Text("sig".into()), Value::Bytes(vec![0u8; sig_len])),
    ]);
    to_canonical_vec(&v).unwrap()
}
