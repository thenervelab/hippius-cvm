//! Local wire shapes Edge schema-validates against.
//!
//! Edge needs **defence-in-depth** `deny_unknown_fields` on every
//! shape it decodes — the hippius-types `SignedX` structs
//! (`SignedResponse`, `SignedStoppedAck`, `SignedServedDeliveryReceipt`,
//! `SignedServedDeliveryAggregate`) do NOT carry `deny_unknown_fields`
//! because they're general-purpose round-trippable types used by the
//! guest, KBS, and Validator. If we decoded directly into those, a
//! Miner could smuggle an `extra` field past the wire gate (since
//! serde would silently ignore it).
//!
//! So this module ships two `pub(crate)` deserialise-only mirrors
//! that DO carry `deny_unknown_fields`:
//!
//! - [`KbsReleaseRequest`] mirrors `kbs_transport::wire::ReleaseRequestBody`.
//!   Pulling `kbs-server` itself across the diode would bring `axum`
//!   and every server dep — not worth it for a 3-field struct.
//! - [`SignedEnvelope`] mirrors the shared `{body, sig}` shape of all
//!   four `Signed*` hippius-types wrappers. Edge only checks the
//!   wrapper has exactly these two byte-string fields; the inner
//!   `body` is opaque (§5.6 — Edge has no pinned verifying keys).
//!
//! The integration test `kbs_request_shape_matches_kbs_server_wire`
//! in `tests/pipeline.rs` flags drift from the upstream KBS shape.

use serde::Deserialize;
use serde_bytes::ByteBuf;

/// `POST /v1/kbs/release` request body — Miner→Inner shape.
///
/// All three fields are byte-strings; Edge validates the wrapper
/// has exactly these three keys with the right CBOR types. The
/// inner `cose_ticket` (COSE_Sign1 / EdDSA), `snp_report` (AMD SEV
/// blob), and `kbs_nonce` (32-byte random) are opaque to Edge —
/// verified downstream by the KBS, not here.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KbsReleaseRequest {
    // `cose_ticket` and `snp_report` are present so `deny_unknown_fields`
    // catches their absence AND so the wire decode pins their CBOR
    // major type (byte-string vs. text-string vs. int). Edge doesn't
    // need their VALUES — the COSE / SEV verifiers run inside the
    // KBS — hence `#[allow(dead_code)]` on the two fields.
    #[allow(dead_code)]
    pub cose_ticket: ByteBuf,
    #[allow(dead_code)]
    pub snp_report: ByteBuf,
    pub kbs_nonce: ByteBuf,
}

/// `{body, sig}` shape shared by every `Signed*` hippius-types
/// wrapper Edge relays. `deny_unknown_fields` blocks extra-key
/// smuggling that the round-trippable hippius-types structs would
/// otherwise accept. Edge does NOT verify `sig` (no pinned key —
/// §5.6 / §22); downstream consumers do.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedEnvelope {
    #[allow(dead_code)]
    pub body: ByteBuf,
    #[allow(dead_code)]
    pub sig: ByteBuf,
}

/// Pinned size of `kbs_nonce` (§20: 32 random bytes). Anything
/// other than 32 is a malformed request — drop at the wire.
pub(crate) const KBS_NONCE_LEN: usize = 32;

/// `HostChallengeRequest` — Miner→Inner shape (PR-10). A blackbox
/// host-attestor asks vali to mint a fresh single-use enrollment nonce
/// bound to `signer_pubkey`. `deny_unknown_fields` blocks extra-key
/// smuggling; Edge pins the CBOR major types (an int version + a
/// byte-string key) and the 32-byte key length, then relays the bytes
/// opaquely (the `node_id` is stamped from the mTLS peer, never a body).
///
/// Mirrors `hippius_types::host_attestor_challenge::HostChallengeRequest`;
/// decoded via this local mirror rather than the hippius-types struct to
/// keep the wire gate self-contained + `deny_unknown_fields`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostChallengeRequest {
    #[allow(dead_code)]
    pub schema_version: u16,
    pub signer_pubkey: ByteBuf,
}

/// Pinned size of the host-attestor `signer_pubkey` (Ed25519 = 32
/// bytes). Anything else is a malformed request — drop at the wire.
pub(crate) const HOST_ATTESTOR_PUBKEY_LEN: usize = 32;
