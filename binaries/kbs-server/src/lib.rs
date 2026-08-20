//! # `hippius-kbs-server` — Tier-0 KBS production binary (§D)
//!
//! Spec of record: `ARCHITECTURE.md` §7 (release contract), §8
//! (CVM-KBS, attestation-bound Vault), §17 (production wiring), §22
//! (offline allowlist). This crate is the *entrypoint* — it wires the
//! [`kbs_core`] release pipeline and the [`kbs_server`] axum transport
//! into a runnable process. The binary itself ([`main`](../main.rs)) is
//! a thin shell over these modules.
//!
//! ## What is real
//!
//! - TOML config — every struct `deny_unknown_fields`, fail-closed load.
//! - Durable file-backed stores (release / VM-state / KBS-nonce) and the
//!   hash-chained [`kbs_core::audit::FileAuditSink`] — opened, and the
//!   audit log locked, BEFORE the HTTP listener binds.
//! - The §22 signed measurement allowlist (COSE_Sign1 wire format).
//! - The `kbs-server` transport (`/healthz`, `/v1/kbs/{nonce,release}`)
//!   plus a `/readyz` probe, and SIGTERM/SIGINT graceful shutdown.
//!
//! ## Production attestation
//!
//! [`attest::RuntimeAttestationVerifier`] wires
//! [`kbs_core::snp_real::RealSnpVerifier`] — ABI-correct SNP report
//! parsing, `MaskedChipId` refusal, TCB rollback rejection — and selects
//! one of two cryptographic chain verifiers from operator config:
//!
//! - `[snp]` absent ⇒ [`attest::UnconfiguredChainVerifier`], a deny-
//!   closed `ChainVerifier`; every release fails closed at the chain step
//!   with an explicit `UNCONFIGURED_CHAIN_MSG` classifier.
//! - `[snp]` present + `vek_pem_path` mounted ⇒
//!   [`kbs_core::snp_real::SevChainVerifier`] anchored to the binary-
//!   built-in AMD ARK (Milan or Genoa per `[snp].generation`) + the
//!   matching built-in ASK + the operator-mounted VEK. Turin is gated
//!   on `RealSnpVerifier` widening `SUPPORTED_REPORT_VERSION` past v2.
//!
//! Production-grade per-CHIP_ID VEK fetch + cache against AMD KDS is the
//! `§17` follow-up; until that lands an operator stages the VEK PEM
//! manually for the deploy under test.
//!
//! ## What is still a transitional MVP (see `README.md`)
//!
//! - [`vault_mvp::StaticTokenVaultKv`] — a `VAULT_TOKEN`-authenticated
//!   KV-v2 client, standing in for the locked SNP-attestation-bound
//!   Vault broker (§8). The MVP Vault step is structurally unreachable
//!   in this build: [`wiring`] pairs it with `kbs_measurement_ok: |_|
//!   false` + `min_tcb: u64::MAX`, so any release that somehow passed
//!   the SNP gate would still fail closed at the Vault step.

// Tests use unwrap/expect/panic; the workspace denies them in non-test code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod admin_tls;
pub mod attest;
pub mod config;
pub mod error;
pub mod hwm;
pub mod kbs_self_report;
pub mod l1_keyring;
pub mod remote_broker_auth;
pub mod server;
pub mod vault_mvp;
pub mod wiring;
