//! # kbs-transport — Hippius Confidential Compute KBS HTTP transport
//!
//! (Formerly the crate `kbs-server`; renamed to disambiguate from the
//! deployed binary crate `hippius-kbs-server` in `binaries/kbs-server`,
//! which depends on this transport library.)
//!
//! Spec: `ARCHITECTURE.md` §7 (release contract), §13/§17 (production
//! wiring + DoS posture), §21 (end-to-end flow).
//!
//! The KBS itself ([`kbs_core`]) is pure-logic. This crate is the thinnest
//! possible HTTP front door that an Edge gateway can OPAQUELY relay to —
//! the protocol is end-to-end signed (COSE_Sign1 ticket) and encrypted
//! (HPKE wrap bound to the attested guest key), so the transport adds no
//! trust assumptions of its own.
//!
//! Wire format: deterministic CBOR (`application/cbor`) on both request
//! and response paths, to match the rest of the protocol. The transport
//! enforces a hard body-size cap so a hostile peer cannot exhaust memory
//! before the release pipeline can fail closed.

// Tests use unwrap/expect/panic; the workspace denies them in library code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod admin_handler;
pub mod handlers;
pub mod rate_limit;
pub mod router;
pub mod service;
pub mod wire;

pub use admin_handler::{build_admin_router, AdminState, PeerCertInfo};
pub use handlers::AppState;
pub use rate_limit::{NonceRateLimiter, RateConfig};
pub use router::build_router;
pub use service::{DefaultKbsService, KbsService};
pub use wire::{CONTENT_TYPE_CBOR, MAX_REQUEST_BYTES, NONCE_LEN};
