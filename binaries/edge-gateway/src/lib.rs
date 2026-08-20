//! # hippius-edge-gateway — library surface
//!
//! Production entry point is the `hippius-edge-gateway` binary
//! (`src/main.rs`). This `lib.rs` re-exports the pipeline + types so
//! integration tests can drive the relay without needing a real TCP
//! socket, mTLS termination, or a NetBird mesh peer.
//!
//! Spec of record: `ARCHITECTURE.md` §5 (invariants — Edge is an
//! application relay, NOT an IP router), §9 (diode telemetry
//! directionality + pull-only inner side), §10 (compromise
//! containment), §17.8 (sequenced plan).
//!
//! ## What the Edge does
//!
//! Bridge the **untrusted** miner-facing NetBird side (hostile L3) to
//! the **internal** vRack side (trusted L2). Per §5.4 the relay is
//! userspace-only — `ip_forward=0` at the kernel level prevents
//! accidental routing. The userspace process enforces:
//!
//! 1. **Authentication** (PR-H4): per-peer short-lived mTLS on both
//!    interfaces; revocation via cert lifetime + CRL/OCSP.
//! 2. **Diode directionality** (§9): control flows inner → Edge →
//!    miner; telemetry flows miner → Edge → queue (pull-only inner).
//! 3. **Opacity** (§5.6): Edge **never decrypts** secrets. KBS↔guest
//!    responses are HPKE-wrapped to the guest ephemeral key; Edge
//!    sees ciphertext only. Encoded in the type system: the wire
//!    gate returns [`stages::envelope::ValidatedEnvelope`], never a
//!    decoded inner type.
//! 4. **Wire gate at the boundary** (§10): every byte that reaches
//!    an inner consumer first passes through
//!    [`stages::validate::validate`]. Enforced by the typestate:
//!    [`stages::forward::forward`] accepts only `ValidatedEnvelope`,
//!    and the only constructor for that type is `pub(crate)` and
//!    called only from `validate`.
//! 5. **Rate limits + bounded queues** (§10, PR-H3) before anything
//!    crosses to inner.
//!
//! ## Skeleton scope (PR-H1/H2)
//!
//! The `forward` stage in [`stages::forward`] returns
//! [`pipeline::EdgeError::Todo`]. The `accept` stage in
//! [`stages::accept`] is a deterministic in-memory mock — there is
//! NO TCP socket, no `tokio::net::TcpListener`, no NetBird, no vRack
//! networking. The wire-gate stage is real and load-bearing:
//!
//! - PR-H1: canonical-CBOR via
//!   [`hippius_types::cbor::assert_canonical`], producing the
//!   `ValidatedEnvelope` typestate.
//! - PR-H2: + per-[`MessageKind`] `deny_unknown_fields` decode
//!   against the pinned `hippius-types` schema (or the local
//!   `stages::wire::KbsReleaseRequest` mirror), + direction-vs-
//!   kind enforcement. The decoded value is dropped at end of arm —
//!   Edge never retains a typed view (§5.6 opacity).
//!
//! ## Containment invariants this skeleton structurally pins
//!
//! - **Typestate before forward.** `RawEnvelope` → `validate` →
//!   `ValidatedEnvelope` → `forward`. A future PR cannot bypass the
//!   wire gate without changing `pub(crate)` to `pub` on
//!   `ValidatedEnvelope::from_validated` — a visible diff.
//! - **No public body bytes.** `body_bytes` / `into_body` are
//!   `pub(crate)`. Typed-decode code lives inside the crate; it
//!   can't read the bytes from outside.
//! - **No `Clone` / no `Default`.** Compile-fail doc-tests on both
//!   `RawEnvelope` and `ValidatedEnvelope` enforce.
//! - **No `Display` plaintext.** Every `EdgeError` variant renders
//!   to a `&'static str` — `eprintln!("{err}")` is safe.
//! - **`log_envelope` accepts `&'static str` only.** Caller-built
//!   `String` outcomes are a compile error.

#![deny(rust_2018_idioms, unreachable_pub)]
// Stage unit tests + integration tests use unwrap/panic — workspace
// denies these in library code. Same opt-in as `hippius-guest`.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod audit;
pub mod config;
pub mod edge_api;
pub mod forward;
pub mod ha;
pub mod listeners;
pub mod miner_listener;
pub mod mtls;
pub mod order_signing;
pub mod pipeline;
pub mod queue;
pub mod rate_limit;
pub mod signer;
pub mod stages;
pub mod telemetry;
pub mod wire;

pub use audit::{AuditError, EdgeAuditSink};
pub use config::{EdgeGatewayConfig, ForwardConfig, RateLimitConfig};
pub use edge_api::EdgeApiServer;
pub use forward::{
    ForwardClient, ForwardError, ForwardResponse, MinerForward, MinerForwardError,
    MinerForwardResponse, MockForwardClient, MockMinerForward, OrderKind, RecordedForward,
    RecordedMinerForward, RecordedStatusForward, ReqwestForwardClient, ReqwestMinerForward,
    MAX_ENVELOPE_BYTES, MAX_MINER_ORDER_BODY, MAX_MINER_RESPONSE_BYTES,
};
pub use ha::{
    HaConfig, HaError, HaHandle, HaNode, HaTiming, HealthMonitor, LocalShedSource, Metrics,
    PeerState,
};
pub use listeners::{
    build_inner_router, build_router, run_inner_listener, run_lifecycle_listener, InnerRouterState,
    LifecycleForward, MinerRouterState, ReqwestLifecycleForward, INNER_LISTENER_PORT,
    LIFECYCLE_LISTENER_PORT, ORDER_KIND_HEADER, TARGET_ADDR_HEADER,
};
pub use miner_listener::{run_miner_listener, MINER_LISTENER_PORT};
pub use mtls::{CertPaths, CertStoreError, MtlsAcceptor, MtlsRuntime, PeerId};
pub use order_signing::{OrderSigner, OrderSigningError};
pub use pipeline::{relay_once, Direction, EdgeError, MessageKind, Stage};
pub use queue::{bounded_queue, BoundedSink, BoundedSource, SendOutcome};
pub use rate_limit::PerSourceRateLimiter;
pub use signer::EdgeSigner;
pub use stages::envelope::{RawEnvelope, ValidatedEnvelope};
pub use telemetry::{NoopTelemetry, TelemetryEvent, TelemetryRecorder, TelemetrySink};
pub use wire::{EdgeTelemetryEnvelope, SignedEdgeTelemetry, TelemetryWireError};
