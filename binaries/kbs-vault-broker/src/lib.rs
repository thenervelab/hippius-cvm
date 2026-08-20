//! `hippius-kbs-vault-broker` — SNP-attestation-bound Vault broker (#102).
//!
//! The KBS (a kata-snp confidential guest) authenticates to this broker
//! before reading a LUKS KEK from Vault. The broker holds the only
//! privileged Vault credential; it mints a **per-VM-scoped, short-TTL**
//! Vault token ONLY after verifying the KBS's own SEV-SNP
//! self-attestation:
//!
//! - the report verifies against the AMD chain (built-in ARK/ASK +
//!   the platform VEK),
//! - `REPORT_DATA == fresh_challenge_nonce ‖ KBS_auth_pubkey`,
//! - the KBS measurement is allowlisted,
//! - TCB ≥ floor + launch-policy bits.
//!
//! A breached non-CC host has no enclave ⇒ no valid SNP report ⇒ no
//! capability. There is no reusable fleet token.
//!
//! ## This crate (PR A — the tested security core)
//!
//! - [`redeem`] — the gate decision (pure, trait-driven, fully tested).
//! - [`challenge`] — single-use CSPRNG challenge store.
//! - [`allowlist`] — the KBS-measurement allowlist.
//! - [`error`] — the closed-vocabulary error → HTTP status mapping.
//!
//! The HTTP/TLS transport, the concrete AMD-chain verifier wiring, and
//! the real Vault `token create` client land in the follow-up PR that
//! turns this library into the deployable binary. The wire protocol the
//! KBS client speaks is `hippius_types::vault_broker`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod allowlist;
pub mod challenge;
pub mod config;
pub mod error;
pub mod handlers;
pub mod redeem;
pub mod tls;
pub mod vault_auth;
pub mod vault_client;
pub mod verifier;
