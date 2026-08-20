//! Library half of `hippius-kbs-admin-client`.
//!
//! The crate is primarily a subprocess binary (see `main.rs`); this lib
//! target exists so the mTLS policy + `rustls::ClientConfig` builder can
//! be driven from an integration test that runs the REAL KBS admin
//! listener (`binaries/kbs-server/tests/admin_mtls_client_interop.rs`).
//! Interop between the two halves of a mutual-TLS gate is exactly the
//! thing a mock cannot prove.

// Same allowance the other Hippius crates carry: `unwrap` is fine in a
// test (a panic IS the failure report), forbidden in shipped code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod mtls;
