//! `hippius-agent-keepalive` library surface (issue #322 Phase B).
//!
//! The binary entry-point lives in `main.rs`; this lib exposes the
//! KBS client + the per-tick orchestration so they're individually
//! testable on a non-SNP dev host.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod client;
pub mod components;
pub mod relay;
pub mod resources;
pub mod tick;
