//! Miner-facing listener wiring (PR-H8, §H phase 2).
//!
//! PR-H7's [`crate::miner_listener`] brought up the authenticated
//! `:443` front door — a `TcpListener` whose every connection is
//! driven through the mTLS handshake — but terminated each connection
//! after the handshake because the miner↔Edge wire frame had no
//! written spec.
//!
//! PR-H8 is that spec, **locked to HTTP/2 over the existing mTLS
//! stream**: a miner posts a typed `Signed*` envelope (canonical-CBOR
//! body, `content-type: application/cbor`) to a `MessageKind`-specific
//! URL route. [`miner_router`] is the [`axum`] router that serves
//! those routes; [`crate::miner_listener`] now drives the router over
//! each accepted [`tokio_rustls`] stream instead of closing it.
//!
//! This sub-tree exists so the router — a sizeable, dependency-heavy
//! module — is not crammed into the lean PR-H7 `miner_listener.rs`.

pub mod inner_listener;
pub mod inner_router;
pub mod lifecycle_listener;
pub mod lifecycle_router;
pub mod miner_router;
pub mod relay_router;

pub use inner_listener::{run_inner_listener, INNER_LISTENER_PORT};
pub use inner_router::{
    build_inner_router, InnerRouterState, ORDER_KIND_HEADER, TARGET_ADDR_HEADER,
};
pub use lifecycle_listener::{run_lifecycle_listener, LIFECYCLE_LISTENER_PORT};
pub use lifecycle_router::{
    build_lifecycle_router, LifecycleForward, LifecycleRouterState, ReqwestLifecycleForward,
    MAX_LIFECYCLE_BODY,
};
pub use miner_router::{build_router, MinerRouterState};
pub use relay_router::{RelayRouterState, MAX_RELAY_BODY};
