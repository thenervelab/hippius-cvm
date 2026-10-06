//! # kbs-core — Hippius Confidential Compute Tier-0 Key Broker Service
//!
//! Spec of record: `ARCHITECTURE.md` (§4 split, §6 OrderTicket, §7 release
//! contract, §8 CVM-KBS + attestation-bound Vault, §20 crypto profile,
//! §21 end-to-end flow, §24 unified VM lifecycle).
//!
//! This crate is the *only* component that touches plaintext secrets and
//! is meant to run inside the attested SEV-SNP Confidential VM (§8). It is
//! deny-by-default: every code path fails closed (`KbsError`).
//!
//! Fully implemented & tested here: OrderTicket COSE/CBOR verification,
//! deterministic-CBOR enforcement, `REPORT_DATA` layouts, the §7 contract
//! logic over a verified report, HPKE wrap + signed response, the unified
//! lifecycle guard, anti-replay, and the release orchestration with
//! commit-before-emit. Infrastructure boundaries that need external systems
//! — the AMD cert-chain/signature verification ([`snp::AttestationVerifier`])
//! and the Vault SNP-attestation auth + KV client ([`vault`]) — are typed
//! trait seams with reference implementations; their production wiring is
//! the §17 next step.

// Tests use unwrap/expect/panic; the workspace denies them in library code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod admin;
pub mod admin_audit;
pub mod allowlist;
pub mod audit;
pub mod audit_journal;
pub mod audit_read;
pub mod audit_vm_cert;
pub mod boot_counter;
pub mod cbor;
pub mod crypto;
pub mod custody;
pub mod error;
pub mod evidence;
pub mod host_attestor;
pub mod keepalive;
pub mod keepalive_binding;
pub mod lifecycle;
pub mod live_attestation;
pub mod persist;
pub mod release;
pub mod replay;
pub mod report_data;
pub mod rollback;
pub mod snp;
pub mod snp_real;
pub mod ticket;
pub mod vault;
pub mod volume_stamp;

pub use error::{KbsError, Result};
