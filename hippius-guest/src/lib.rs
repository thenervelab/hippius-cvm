//! # hippius-guest — guest-side §6/§7/§19/§20/§24 protocol
//!
//! Spec of record: `ARCHITECTURE.md` §6 OrderTicket, §7 release contract,
//! §19 sealed-secrets contract, §20 deterministic CBOR + HPKE binding,
//! §24/§25 lifecycle.
//!
//! This crate is the protocol half that runs INSIDE the attested guest
//! VM. It does NOT touch /dev/sev-guest, /dev/mapper/*, NoCloud paths,
//! or switch_root — those belong to the initramfs agent binary that
//! orchestrates this library. The guarantees provided here are:
//!
//! 1. [`release::verify_and_unwrap_release`] takes a `SignedResponse`
//!    from the KBS and the guest's own X25519 secret, and returns the
//!    LUKS + user-data plaintext ONLY IF every binding holds:
//!    - Ed25519 signature by the trusted KBS pubkey,
//!    - response.vm_id / ticket_id / tenant_id / vm_generation match
//!      the guest's expected values (i.e., the values it advertised in
//!      its attestation),
//!    - response.measurement matches the guest's own measurement,
//!    - response.kbs_kid is one the guest accepts,
//!    - response.kbs_nonce equals the nonce the guest folded into
//!      `REPORT_DATA[0..32]`,
//!    - HPKE unwrap succeeds for both secrets bound to the canonical
//!      [`ReleaseContext`] re-derived field-by-field on this side,
//!    - SHA-256 over the user-data plaintext (`hippius_types::digest::
//!      userdata_digest` preimage) equals `response.allowed_userdata_
//!      digest`, constant-time compared (§19: the guest has no L1 key
//!      so it MUST compare against the KBS-signed response, not the
//!      ticket).
//!
//! 2. [`lifecycle::sign_stopped_ack`] / [`lifecycle::verify_stopped_ack`]
//!    produce / verify the §24/§25 end-of-life acknowledgement the
//!    orchestrator requires before committing destroy or activating a
//!    migration destination.
//!
//! Deny-by-default: any failure returns `Err(GuestError)` — the agent
//! must fail closed (refuse to switch_root, refuse to ack the
//! migration).

// Tests use unwrap/expect/panic; the workspace denies them in library code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod audit_vm;
pub mod audit_vm_cert;
pub mod error;
pub mod guardian;
pub mod lifecycle;
pub mod release;
pub mod served_receipt;
pub mod telemetry;
pub mod telemetry_key;

pub use audit_vm::{sign_aggregate, verify_aggregate};
pub use audit_vm_cert::verify_cert;
pub use error::{GuestError, Result};
pub use guardian::{
    open_guardian_reply, verify_stamp_ack, GuardianRelease, GuardianReply, GuardianStamp,
};
pub use lifecycle::{sign_stopped_ack, verify_stopped_ack};
pub use release::{
    verify_and_unwrap_release, verify_and_unwrap_release_attested,
    verify_and_unwrap_release_for_mode, AttestedStampProtocol, ExpectedRelease, UnwrappedSecrets,
};
pub use served_receipt::{
    sign_served_receipt, verify_receipt_in_aggregate_window, verify_served_receipt,
};
pub use telemetry::{verify_telemetry_cert, ExpectedTelemetryCert};
