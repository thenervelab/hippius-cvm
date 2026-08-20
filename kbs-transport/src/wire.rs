//! HTTP wire format for the KBS transport (ARCHITECTURE.md §7/§17/§20).
//!
//! Both request and response bodies are deterministic CBOR — same encoding
//! discipline as the OrderTicket and the signed release response, so the
//! transport never re-encodes ambiguity in.

use hippius_types::cbor::assert_canonical;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// Hard upper bound on a single request body. The expected payload (one
/// COSE_Sign1 ticket ~ 1 KiB + one SNP report ~ 1.2 KiB + 32-byte nonce)
/// is well under 16 KiB; the cap is set generously above that so an
/// attacker can't burn memory before the release pipeline fails closed.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// The single content-type the KBS accepts and emits.
pub const CONTENT_TYPE_CBOR: &str = "application/cbor";

/// Length of a KBS-minted nonce (folded into `REPORT_DATA[0..32]`, §20).
pub const NONCE_LEN: usize = 32;

/// `POST /v1/kbs/nonce` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceResponse {
    /// Fresh 32-byte nonce minted by [`crate::KbsService::issue_nonce`].
    pub nonce: ByteBuf,
}

/// `POST /v1/kbs/release` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRequestBody {
    /// COSE_Sign1 over deterministic-CBOR OrderTicket (§6).
    pub cose_ticket: ByteBuf,
    /// Raw AMD SEV-SNP attestation report (verified inside kbs-core, §7).
    pub snp_report: ByteBuf,
    /// 32-byte KBS-minted nonce (must equal `REPORT_DATA[0..32]`, §7/§20).
    pub kbs_nonce: ByteBuf,
    /// Phase 2A of audit follow-up Codex #2 — anti-rollback for
    /// valid-old-ciphertext replay. The guest's reported value of
    /// "the boot counter I expect this release to advance to". On
    /// first boot, `Some(1)`. On subsequent boots, the guest reads
    /// the previous KBS-issued value from durable storage (Phase 2B
    /// chooses the storage location) and submits `prev + 1`.
    ///
    /// `#[serde(default)]` so a pre-Phase-2A guest that omits the
    /// field still decodes (`None` → release-path short-circuits
    /// the check). KBS-side enforcement is gated by the same
    /// Option, with the field ALWAYS echoed back in
    /// `KbsResponse::boot_counter` for the next boot to compare
    /// against.
    #[serde(default)]
    pub submitted_boot_counter: Option<u64>,
}

/// `POST /v1/kbs/volume-stamp/confirm` request body.
///
/// Sent by the guest AFTER it has durably written the stamp into its
/// encrypted overlay, and it is the ONLY thing that advances
/// `kbs-core::volume_stamp`. Deliberately tiny: no attestation, because
/// attestation would not help — the golden launch measurement is SHARED
/// across same-distro tenants, so a miner running its own golden VM can
/// produce a valid report and already holds the public COSE ticket it
/// relays. The authenticator is `token`, HPKE-sealed to the attested
/// guest in the release that issued it, which no other party can read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeStampConfirmBody {
    /// Stable tenant VM id (the same value the §20 release used).
    pub vm_id: String,
    /// The stamp value being confirmed. Must be exactly
    /// `stored + 1` or the CAS refuses it.
    pub value: u64,
    /// The 32-byte single-use authenticator the guest unwrapped from
    /// `KbsResponse::volume_stamp_token`.
    pub token: ByteBuf,
}

/// `POST /v1/kbs/volume-stamp/confirm` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeStampConfirmResponse {
    /// The stamp now stored for this VM.
    pub confirmed: u64,
}

/// `POST /v1/attest/keepalive` request body (issue #322 Phase B).
///
/// The in-VM guest agent gathers a fresh SNP report, the miner-agent
/// asserts the running VM's `node_id`, and the request is POSTed to
/// the KBS. Same nonce store as the release flow — the guest gets a
/// nonce from `/v1/kbs/nonce` and folds it into `REPORT_DATA[0..32]`
/// before issuing the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeepaliveRequestBody {
    /// Stable tenant VM id (same value the §K heartbeat + §20 release
    /// used).
    pub vm_id: String,
    /// 32 bytes — the miner's persistent Ed25519 node identity the
    /// signed body should credit. The KBS does NOT verify this binding
    /// itself (the §22 chain + measurement pin the booted UKI; the
    /// `node_id` is operator-asserted), but it IS copied into the
    /// signed body so the on-chain pallet credits the right miner.
    pub node_id: ByteBuf,
    /// Raw AMD SEV-SNP attestation report (verified inside kbs-core).
    pub snp_report: ByteBuf,
    /// 32-byte KBS-minted nonce. MUST equal `REPORT_DATA[0..32]`.
    pub kbs_nonce: ByteBuf,
    /// The compute-pallet epoch the resulting attestation should fall
    /// into — caller-asserted (typically the latest observed
    /// `CurrentEpoch::get()`). The pallet rejects on mismatch with
    /// its current epoch, so a stale value just denies; KBS itself
    /// does not enforce the value against any chain state.
    pub epoch: u64,
    /// Hard expiry for the signed body, Unix seconds. The pallet
    /// rejects `expiry_unix <= now_unix` on submission, so callers
    /// pick a value generous enough to absorb network + batch
    /// latency (e.g. `now + 600`).
    pub expiry_unix: u64,
}

/// `POST /v1/attest/keepalive` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeepaliveResponseBody {
    /// `hippius_types::live_attestation::SignedLiveAttestation::encode`
    /// bytes — the validator forwards these verbatim to the pallet.
    pub signed_live_attestation: ByteBuf,
}

/// `POST /v1/kbs/host-attestor/enroll` request body (blackbox
/// host-attestor chantier — PR-10b-S2b).
///
/// The S2a relay (miner-agent → Edge) forwards the guest's once-per-boot
/// [`HostEnrollment`](hippius_types::host_attestor::HostEnrollment)
/// together with the vali-minted single-use `nonce` that guest folded
/// into `REPORT_DATA[0..32]` (delivered over the PR-10 challenge
/// channel). The KBS re-verifies the platform SNP report against AMD's
/// root, requires the measurement to be host-attestor class, and
/// recomputes `REPORT_DATA` from `nonce` + the enrollment's
/// `signer_pubkey`/`node_id` — so a wrong `nonce` (or a lying relay)
/// just fails the byte-match and mints nothing.
///
/// The KBS does NOT check the nonce's freshness/single-use — that is
/// vali's job at cert-ingest (PR-8 / PR-10). It only needs the value to
/// reproduce the AMD-signed `REPORT_DATA` binding. The `enrollment` is
/// carried as opaque canonical-CBOR bytes and decoded with the frozen
/// PR-1 [`HostEnrollment::decode`](hippius_types::host_attestor::HostEnrollment::decode)
/// hostile-origin parser, so this envelope never re-implements the
/// enrollment schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEnrollRequestBody {
    /// Canonical CBOR of a
    /// [`HostEnrollment`](hippius_types::host_attestor::HostEnrollment)
    /// (decoded + validated in Rust via the frozen PR-1 decoder).
    pub enrollment: ByteBuf,
    /// The 32-byte vali-minted single-use nonce the guest folded into
    /// `REPORT_DATA[0..32]`. MUST equal that binding or the enroll is
    /// rejected. Not treated as fresh/single-use here (vali's job).
    pub nonce: ByteBuf,
}

/// `POST /v1/kbs/host-attestor/enroll` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEnrollResponseBody {
    /// `hippius_types::host_attestor::SignedHostAttestorCert::encode`
    /// bytes — the vali `/v1/telemetry/host-attestor/cert` endpoint
    /// (PR-8) verifies these against the KBS L0 verifying key.
    pub signed_cert: ByteBuf,
}

/// Decode a deterministic-CBOR body into `T`. Rejects non-canonical input
/// (§20) so a malicious peer can't smuggle equivalent-but-ambiguous bytes.
pub fn decode_canonical<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    assert_canonical(bytes).map_err(|e| format!("non-canonical CBOR: {e}"))?;
    ciborium::de::from_reader(bytes).map_err(|e| format!("CBOR decode: {e}"))
}

/// Encode `T` as deterministic CBOR.
///
/// ciborium's serde encoder emits struct fields in declaration order,
/// which is NOT canonical (RFC 8949 §4.2.1 demands sort by encoded-key
/// bytes — "sig" precedes "body" because the shorter text string sorts
/// first). We round-trip through a `Value` tree so the canonicalize step
/// produces stable bytes regardless of how the source struct is laid
/// out. The cost is two short CBOR passes; safe for our small response
/// types.
pub fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut interim = Vec::new();
    ciborium::ser::into_writer(value, &mut interim)
        .map_err(|e| format!("CBOR encode (interim): {e}"))?;
    let val: ciborium::value::Value = ciborium::de::from_reader(interim.as_slice())
        .map_err(|e| format!("CBOR decode for canonicalize: {e}"))?;
    hippius_types::cbor::to_canonical_vec(&val).map_err(|e| format!("CBOR canonicalize: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hippius_types::cbor::to_canonical_vec;

    #[test]
    fn release_body_round_trips() {
        let body = ReleaseRequestBody {
            cose_ticket: ByteBuf::from(vec![1, 2, 3]),
            snp_report: ByteBuf::from(vec![4, 5, 6]),
            kbs_nonce: ByteBuf::from(vec![7u8; 32]),
            submitted_boot_counter: None,
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&body, &mut bytes).unwrap();
        // ciborium's serde encoder emits map fields in struct order;
        // assert_canonical requires sorted-by-key map entries. Build the
        // canonical bytes via `to_canonical_vec` over a CBOR Value tree
        // and use those for the wire test.
        let v = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("cose_ticket".into()),
                ciborium::value::Value::Bytes(vec![1, 2, 3]),
            ),
            (
                ciborium::value::Value::Text("kbs_nonce".into()),
                ciborium::value::Value::Bytes(vec![7u8; 32]),
            ),
            (
                ciborium::value::Value::Text("snp_report".into()),
                ciborium::value::Value::Bytes(vec![4, 5, 6]),
            ),
        ]);
        let canonical = to_canonical_vec(&v).unwrap();
        let decoded: ReleaseRequestBody = decode_canonical(&canonical).unwrap();
        assert_eq!(decoded.cose_ticket.as_ref(), &[1u8, 2, 3]);
        assert_eq!(decoded.snp_report.as_ref(), &[4u8, 5, 6]);
        assert_eq!(decoded.kbs_nonce.len(), 32);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let v = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("cose_ticket".into()),
                ciborium::value::Value::Bytes(vec![1]),
            ),
            (
                ciborium::value::Value::Text("extra".into()),
                ciborium::value::Value::Integer(0.into()),
            ),
            (
                ciborium::value::Value::Text("kbs_nonce".into()),
                ciborium::value::Value::Bytes(vec![7u8; 32]),
            ),
            (
                ciborium::value::Value::Text("snp_report".into()),
                ciborium::value::Value::Bytes(vec![4]),
            ),
        ]);
        let canonical = to_canonical_vec(&v).unwrap();
        let r: Result<ReleaseRequestBody, _> = decode_canonical(&canonical);
        assert!(r.is_err());
    }

    #[test]
    fn non_canonical_bytes_are_rejected() {
        // Unsorted keys ⇒ non-canonical CBOR map.
        let v = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("snp_report".into()),
                ciborium::value::Value::Bytes(vec![1]),
            ),
            (
                ciborium::value::Value::Text("cose_ticket".into()),
                ciborium::value::Value::Bytes(vec![1]),
            ),
            (
                ciborium::value::Value::Text("kbs_nonce".into()),
                ciborium::value::Value::Bytes(vec![7u8; 32]),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&v, &mut bytes).unwrap();
        let r: Result<ReleaseRequestBody, _> = decode_canonical(&bytes);
        assert!(r.is_err());
    }

    /// Phase 2A of audit follow-up Codex #2 — a pre-Phase-2A guest
    /// that omits `submitted_boot_counter` must still decode (the
    /// field is `Option<u64>` with `#[serde(default)]`, so absence
    /// → `None` short-circuits the KBS boot-counter CAS). A pre-
    /// counter request body has the SAME three fields as before;
    /// decode MUST succeed and the counter field MUST be `None`.
    #[test]
    fn release_body_decodes_without_boot_counter_field() {
        let v = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("cose_ticket".into()),
                ciborium::value::Value::Bytes(vec![1, 2, 3]),
            ),
            (
                ciborium::value::Value::Text("kbs_nonce".into()),
                ciborium::value::Value::Bytes(vec![7u8; 32]),
            ),
            (
                ciborium::value::Value::Text("snp_report".into()),
                ciborium::value::Value::Bytes(vec![4, 5, 6]),
            ),
        ]);
        let canonical = to_canonical_vec(&v).unwrap();
        let decoded: ReleaseRequestBody = decode_canonical(&canonical).unwrap();
        assert_eq!(decoded.submitted_boot_counter, None);
    }

    #[test]
    fn host_enroll_body_round_trips() {
        let body = HostEnrollRequestBody {
            enrollment: ByteBuf::from(vec![1, 2, 3, 4]),
            nonce: ByteBuf::from(vec![9u8; 32]),
        };
        let v = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("enrollment".into()),
                ciborium::value::Value::Bytes(vec![1, 2, 3, 4]),
            ),
            (
                ciborium::value::Value::Text("nonce".into()),
                ciborium::value::Value::Bytes(vec![9u8; 32]),
            ),
        ]);
        let canonical = to_canonical_vec(&v).unwrap();
        let decoded: HostEnrollRequestBody = decode_canonical(&canonical).unwrap();
        assert_eq!(decoded.enrollment.as_ref(), body.enrollment.as_ref());
        assert_eq!(decoded.nonce.len(), 32);
    }

    #[test]
    fn host_enroll_body_rejects_unknown_field() {
        let v = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("enrollment".into()),
                ciborium::value::Value::Bytes(vec![1]),
            ),
            (
                ciborium::value::Value::Text("nonce".into()),
                ciborium::value::Value::Bytes(vec![9u8; 32]),
            ),
            (
                ciborium::value::Value::Text("rogue".into()),
                ciborium::value::Value::Integer(0.into()),
            ),
        ]);
        let canonical = to_canonical_vec(&v).unwrap();
        let r: Result<HostEnrollRequestBody, _> = decode_canonical(&canonical);
        assert!(r.is_err());
    }

    /// Phase 2A guest sets `Some(n)`; decode round-trips the value
    /// so the handler can forward it to `KbsService::process_release`.
    #[test]
    fn release_body_decodes_with_boot_counter_some() {
        let v = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("cose_ticket".into()),
                ciborium::value::Value::Bytes(vec![1, 2, 3]),
            ),
            (
                ciborium::value::Value::Text("kbs_nonce".into()),
                ciborium::value::Value::Bytes(vec![7u8; 32]),
            ),
            (
                ciborium::value::Value::Text("snp_report".into()),
                ciborium::value::Value::Bytes(vec![4, 5, 6]),
            ),
            (
                ciborium::value::Value::Text("submitted_boot_counter".into()),
                ciborium::value::Value::Integer(42.into()),
            ),
        ]);
        let canonical = to_canonical_vec(&v).unwrap();
        let decoded: ReleaseRequestBody = decode_canonical(&canonical).unwrap();
        assert_eq!(decoded.submitted_boot_counter, Some(42));
    }
}
