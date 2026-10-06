//! Exact SEV-SNP `REPORT_DATA` layouts (ARCHITECTURE.md §20).

#[allow(unused_imports)]
// per-module slice of the alloc prelude — not every module needs every item
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::cbor::to_canonical_vec;
use crate::{HippiusTypesError, Result};
use ciborium::value::Value;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

pub const REPORT_DATA_LEN: usize = 64;
pub const AUDIT_VM_DOMAIN: &[u8] = b"HIPPIUS_AUDIT_VM_V1";

/// Domain tag for the §23 tenant telemetry-signer `REPORT_DATA`
/// binding. Distinct from every other signed/hashed domain in the
/// stack so a hash bound under one scheme cannot be reused as another.
pub const TENANT_TELEMETRY_DOMAIN: &str = "HIPPIUS_TENANT_TELEMETRY_V1";

/// Domain tag for the §322 live-attestation `REPORT_DATA` binding.
/// Distinct from `LIVE_ATTESTATION_DOMAIN` (used by the on-chain
/// signed body) and every other domain in the stack — a report
/// minted under a release / telemetry / audit-vm binding cannot
/// replay as a live-attestation report.
pub const LIVE_ATTESTATION_REPORT_DOMAIN: &str = "HIPPIUS_LIVE_ATTESTATION_REPORT_V1";

/// Domain tag for a live-attestation report that also binds the guest's
/// resources ([`live_attestation_with_resources`]). Its own tag, so a
/// v1 preimage (domain + vm_id) and a resources preimage can never hash
/// to each other.
pub const LIVE_ATTESTATION_RESOURCES_REPORT_DOMAIN: &str =
    "HIPPIUS_LIVE_ATTESTATION_RESOURCES_REPORT_V1";

/// Domain tag for a live-attestation report that binds the guest
/// components release and its health
/// ([`live_attestation_with_components`]) — and, when the guest also
/// attests them, its resources. Its own tag: no other preimage can hash
/// to one of these.
pub const LIVE_ATTESTATION_COMPONENTS_REPORT_DOMAIN: &str =
    "HIPPIUS_LIVE_ATTESTATION_COMPONENTS_REPORT_V1";

/// Domain tag for the blackbox **host-attestor enrollment**
/// `REPORT_DATA` binding (see [`crate::host_attestor`]). The host
/// attestor runs on the bare-metal SEV-SNP host — outside any tenant
/// CVM — and enrols with the KBS by folding this binding into its
/// platform SNP report. Distinct from every other `REPORT_DATA`
/// domain in the stack: a tenant / telemetry / audit-vm /
/// live-attestation report can never replay as a host-attestor
/// enrollment, and vice-versa.
pub const HOST_ATTESTOR_REPORT_DOMAIN: &str = "HIPPIUS_HOST_ATTESTOR_REPORT_V1";

/// Domain tag for the **custody bind** `REPORT_DATA` binding (see
/// [`crate::custody`]). Distinct from every other `REPORT_DATA` domain:
/// a release / telemetry / live-attestation / host-attestor report can
/// never replay as a custody bind, and vice versa.
pub const CUSTODY_BIND_REPORT_DOMAIN: &str = "HIPPIUS_CUSTODY_BIND_REPORT_V1";

/// Domain tag for the **key-guardian release** `REPORT_DATA` binding (see
/// [`crate::guardian`]). Distinct from every other `REPORT_DATA` domain.
pub const GUARDIAN_REPORT_DOMAIN: &str = "HIPPIUS_GUARDIAN_REPORT_V1";

/// Expected `REPORT_DATA` for a tenant guest.
pub fn tenant(nonce: &[u8; 32], guest_x25519_pub: &[u8; 32]) -> [u8; REPORT_DATA_LEN] {
    let mut out = [0u8; REPORT_DATA_LEN];
    out[0..32].copy_from_slice(nonce);
    out[32..64].copy_from_slice(guest_x25519_pub);
    out
}

/// Domain tag of the **stamp protocol v2** tenant-release `REPORT_DATA`
/// binding ([`tenant_stamp_v2`]). Distinct from every other domain in the
/// stack.
pub const TENANT_RELEASE_STAMP_V2_REPORT_DOMAIN: &str = "HIPPIUS_TENANT_RELEASE_STAMP_V2_REPORT";

/// The first half of a stamp-protocol-v2 tenant `REPORT_DATA`:
/// `SHA-256(TENANT_RELEASE_STAMP_V2_REPORT_DOMAIN ‖ nonce)`.
pub fn tenant_stamp_v2_nonce_binding(nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TENANT_RELEASE_STAMP_V2_REPORT_DOMAIN.as_bytes());
    h.update(nonce);
    h.finalize().into()
}

/// Expected `REPORT_DATA` for a tenant guest that speaks **stamp protocol
/// v2** (a timeline-bound volume stamp — `kbs_core::volume_stamp`):
/// `[0..32] = SHA-256(TENANT_RELEASE_STAMP_V2_REPORT_DOMAIN ‖ nonce)`,
/// `[32..64] = guest X25519 pub` (unchanged, still the HPKE recipient).
///
/// This IS the guest's claim to speak v2, and the only one the KBS
/// accepts: `REPORT_DATA` is signed by the PSP inside the SNP report, so
/// a miner can neither add the claim to an older guest's report nor strip
/// it from a v2 guest's — every other part of the release request is
/// relayed by the miner and could be. A v1 report (`[0..32] = nonce`, see
/// [`tenant`]) can never be read as v2: that would need
/// `SHA-256(domain ‖ nonce) == nonce`.
pub fn tenant_stamp_v2(nonce: &[u8; 32], guest_x25519_pub: &[u8; 32]) -> [u8; REPORT_DATA_LEN] {
    let mut out = [0u8; REPORT_DATA_LEN];
    out[0..32].copy_from_slice(&tenant_stamp_v2_nonce_binding(nonce));
    out[32..64].copy_from_slice(guest_x25519_pub);
    out
}

/// Expected `REPORT_DATA` for the per-node Audit VM (§23). The
/// Ed25519 pubkey doesn't fit the X25519 layout, so we bind a SHA-256
/// over the pubkey, the domain, the `node_id` and the `platform_id` —
/// with each variable-length field length-prefixed (exact framing
/// below; do NOT hand-roll a plain `‖` concat — it will not match).
///
/// Each **variable-length** field (`audit_vm_ed25519_pub`, `node_id`,
/// `platform_id`) is `u32`-big-endian **length-prefixed** before it is
/// hashed, so the binding is **injective**: a plain concatenation of
/// three variable-length fields is ambiguous — `node_id=b"ab",
/// platform_id=b"c"` and `node_id=b"a", platform_id=b"bc"` would hash
/// identically — which would let an attested guest later be certified
/// for a *different* identity split. `AUDIT_VM_DOMAIN` is a fixed
/// constant so it carries no prefix. This refines the informal §20 `‖`
/// notation; a digest mismatch with a plain-concat verifier is a bug,
/// not a compatibility concern (this is the only producer).
pub fn audit_vm(
    nonce: &[u8; 32],
    audit_vm_ed25519_pub: &[u8],
    node_id: &[u8],
    platform_id: &[u8],
) -> [u8; REPORT_DATA_LEN] {
    let mut h = Sha256::new();
    h.update((audit_vm_ed25519_pub.len() as u32).to_be_bytes());
    h.update(audit_vm_ed25519_pub);
    h.update(AUDIT_VM_DOMAIN);
    h.update((node_id.len() as u32).to_be_bytes());
    h.update(node_id);
    h.update((platform_id.len() as u32).to_be_bytes());
    h.update(platform_id);
    let digest = h.finalize();
    let mut out = [0u8; REPORT_DATA_LEN];
    out[0..32].copy_from_slice(nonce);
    out[32..64].copy_from_slice(&digest);
    out
}

/// Expected `REPORT_DATA` for the §23 tenant telemetry-signer key.
///
/// The telemetry signer is **Ed25519** — like the Audit VM (§20) it
/// does not fit the tenant `[32:64] = X25519` layout, so `[32:64]` is
/// a SHA-256 binding instead. The preimage is a **canonical-CBOR map**
/// (RFC 8949 §4.2.1, sorted keys) carrying the domain tag, the signer
/// public key, and the `(node_id, vm_id)` identity. A CBOR map is
/// self-delimiting, so the variable-length `node_id` / `vm_id` cannot
/// be confused for one another — no concatenation-collision surface
/// (the plain-concat `audit_vm` layout above predates this helper).
///
/// The guest generates the Ed25519 signer keypair, folds this
/// `REPORT_DATA` into its SNP report, and the KBS recomputes the
/// identical 64 bytes before issuing the telemetry certificate — both
/// sides MUST call this one function.
pub fn tenant_telemetry(
    nonce: &[u8; 32],
    telemetry_signer_pubkey: &[u8; 32],
    node_id: &[u8],
    vm_id: &str,
) -> Result<[u8; REPORT_DATA_LEN]> {
    // Source key order is cosmetic — `to_canonical_vec` re-sorts to the
    // RFC 8949 §4.2.1 canonical order.
    let preimage = to_canonical_vec(&Value::Map(vec![
        (
            Value::Text("domain".into()),
            Value::Text(TENANT_TELEMETRY_DOMAIN.into()),
        ),
        (
            Value::Text("node_id".into()),
            Value::Bytes(node_id.to_vec()),
        ),
        (
            Value::Text("signer_pubkey".into()),
            Value::Bytes(telemetry_signer_pubkey.to_vec()),
        ),
        (Value::Text("vm_id".into()), Value::Text(vm_id.into())),
    ]))
    .map_err(|e| HippiusTypesError::Cbor(format!("tenant_telemetry preimage: {e}")))?;
    let digest = Sha256::digest(&preimage);
    let mut out = [0u8; REPORT_DATA_LEN];
    out[0..32].copy_from_slice(nonce);
    out[32..64].copy_from_slice(&digest);
    Ok(out)
}

/// Expected `REPORT_DATA` for a §322 live-attestation keepalive
/// report. The KBS issues a single-use nonce (same
/// [`crate::live_attestation`] flow as release), the in-VM guest
/// agent issues `SNP_GET_REPORT` with this `REPORT_DATA`, and the
/// KBS recomputes the same 64 bytes to verify before signing the
/// on-chain attestation.
///
/// `REPORT_DATA[0..32]` is the KBS-minted nonce (single-use, TTL-
/// bounded); `REPORT_DATA[32..64]` is a SHA-256 over a canonical-
/// CBOR map binding the `LIVE_ATTESTATION_REPORT_DOMAIN` tag + the
/// `vm_id`. Self-delimiting preimage (no concat-collision surface
/// like the legacy `audit_vm` layout). Same shape as
/// [`tenant_telemetry`].
pub fn live_attestation(nonce: &[u8; 32], vm_id: &str) -> Result<[u8; REPORT_DATA_LEN]> {
    let preimage = to_canonical_vec(&Value::Map(vec![
        (
            Value::Text("domain".into()),
            Value::Text(LIVE_ATTESTATION_REPORT_DOMAIN.into()),
        ),
        (Value::Text("vm_id".into()), Value::Text(vm_id.into())),
    ]))
    .map_err(|e| HippiusTypesError::Cbor(format!("live_attestation preimage: {e}")))?;
    let digest = Sha256::digest(&preimage);
    let mut out = [0u8; REPORT_DATA_LEN];
    out[0..32].copy_from_slice(nonce);
    out[32..64].copy_from_slice(&digest);
    Ok(out)
}

/// Expected `REPORT_DATA` for a live-attestation keepalive that also
/// attests the guest's resources (live-attestation schema v3).
///
/// Same layout as [`live_attestation`] — `nonce ‖ SHA-256(canonical-CBOR
/// map)` — with the map binding
/// [`LIVE_ATTESTATION_RESOURCES_REPORT_DOMAIN`], the `vm_id` and the four
/// [`crate::live_attestation::GuestResources`] values. The guest builds it
/// from what it read, the KBS rebuilds it from the values the request
/// carries: any value changed in transit breaks the byte-equality the KBS
/// checks against the PSP-signed report.
pub fn live_attestation_with_resources(
    nonce: &[u8; 32],
    vm_id: &str,
    resources: &crate::live_attestation::GuestResources,
) -> Result<[u8; REPORT_DATA_LEN]> {
    let preimage = to_canonical_vec(&Value::Map(vec![
        (
            Value::Text("domain".into()),
            Value::Text(LIVE_ATTESTATION_RESOURCES_REPORT_DOMAIN.into()),
        ),
        (
            Value::Text("mem_firmware_kib".into()),
            Value::Integer(resources.mem_firmware_kib.into()),
        ),
        (
            Value::Text("mem_total_kib".into()),
            Value::Integer(resources.mem_total_kib.into()),
        ),
        (
            Value::Text("mem_unaccepted_kib".into()),
            Value::Integer(resources.mem_unaccepted_kib.into()),
        ),
        (
            Value::Text("vcpus_online".into()),
            Value::Integer(resources.vcpus_online.into()),
        ),
        (Value::Text("vm_id".into()), Value::Text(vm_id.into())),
    ]))
    .map_err(|e| {
        HippiusTypesError::Cbor(format!("live_attestation_with_resources preimage: {e}"))
    })?;
    let digest = Sha256::digest(&preimage);
    let mut out = [0u8; REPORT_DATA_LEN];
    out[0..32].copy_from_slice(nonce);
    out[32..64].copy_from_slice(&digest);
    Ok(out)
}

/// Expected `REPORT_DATA` for a live-attestation keepalive that attests
/// the guest components release and its health (live-attestation schema
/// v4), and optionally its resources.
///
/// `nonce ‖ SHA-256(canonical-CBOR map)`; the map binds
/// [`LIVE_ATTESTATION_COMPONENTS_REPORT_DOMAIN`], the `vm_id`, the five
/// [`crate::live_attestation::GuestComponents`] values and — all four or
/// none — the [`crate::live_attestation::GuestResources`] values (a
/// canonical map tells the two shapes apart). The guest builds it from
/// what it read, the KBS rebuilds it from the request: a value changed or
/// dropped in transit breaks the byte-equality with the PSP-signed report.
pub fn live_attestation_with_components(
    nonce: &[u8; 32],
    vm_id: &str,
    components: &crate::live_attestation::GuestComponents,
    resources: Option<&crate::live_attestation::GuestResources>,
) -> Result<[u8; REPORT_DATA_LEN]> {
    let mut entries = vec![
        (
            Value::Text("components_health".into()),
            Value::Integer(components.health.into()),
        ),
        (
            Value::Text("components_instance".into()),
            Value::Integer(components.instance.into()),
        ),
        (
            Value::Text("components_release_version".into()),
            Value::Integer(components.release_version.into()),
        ),
        (
            Value::Text("components_security_epoch".into()),
            Value::Integer(components.security_epoch.into()),
        ),
        (
            Value::Text("components_unhealthy_ticks".into()),
            Value::Integer(components.unhealthy_ticks.into()),
        ),
        (
            Value::Text("domain".into()),
            Value::Text(LIVE_ATTESTATION_COMPONENTS_REPORT_DOMAIN.into()),
        ),
        (Value::Text("vm_id".into()), Value::Text(vm_id.into())),
    ];
    if let Some(r) = resources {
        entries.extend([
            (
                Value::Text("mem_firmware_kib".into()),
                Value::Integer(r.mem_firmware_kib.into()),
            ),
            (
                Value::Text("mem_total_kib".into()),
                Value::Integer(r.mem_total_kib.into()),
            ),
            (
                Value::Text("mem_unaccepted_kib".into()),
                Value::Integer(r.mem_unaccepted_kib.into()),
            ),
            (
                Value::Text("vcpus_online".into()),
                Value::Integer(r.vcpus_online.into()),
            ),
        ]);
    }
    let preimage = to_canonical_vec(&Value::Map(entries)).map_err(|e| {
        HippiusTypesError::Cbor(format!("live_attestation_with_components preimage: {e}"))
    })?;
    let digest = Sha256::digest(&preimage);
    let mut out = [0u8; REPORT_DATA_LEN];
    out[0..32].copy_from_slice(nonce);
    out[32..64].copy_from_slice(&digest);
    Ok(out)
}

/// Expected `REPORT_DATA` for a blackbox **host-attestor enrollment**
/// (see [`crate::host_attestor::HostEnrollment`]). The attestor's
/// Ed25519 signer key does not fit the tenant `[32:64] = X25519`
/// layout, so `[32:64]` is a SHA-256 binding instead.
///
/// `REPORT_DATA[0..32]` is a vali-minted single-use nonce.
/// `REPORT_DATA[32..64]` is a SHA-256 over a **canonical-CBOR map**
/// (RFC 8949 §4.2.1, sorted keys) binding the
/// [`HOST_ATTESTOR_REPORT_DOMAIN`] tag, the persistent `node_id`, and
/// the attestor's `attestor_pubkey`. A CBOR map is self-delimiting, so
/// the variable-length `node_id` cannot be confused for the pubkey —
/// no concatenation-collision surface (unlike the legacy `audit_vm`
/// plain-concat layout above). Same anti-concat shape as
/// [`tenant_telemetry`] / [`live_attestation`].
///
/// The attestor generates the Ed25519 signer keypair, folds this
/// `REPORT_DATA` into its platform SNP report, and the KBS recomputes
/// the identical 64 bytes before issuing the L0 enrollment cert —
/// both sides MUST call this one function.
pub fn host_attestor(
    nonce: &[u8; 32],
    attestor_pubkey: &[u8; 32],
    node_id: &str,
) -> Result<[u8; REPORT_DATA_LEN]> {
    // Source key order is cosmetic — `to_canonical_vec` re-sorts to the
    // RFC 8949 §4.2.1 canonical order.
    let preimage = to_canonical_vec(&Value::Map(vec![
        (
            Value::Text("attestor_pubkey".into()),
            Value::Bytes(attestor_pubkey.to_vec()),
        ),
        (
            Value::Text("domain".into()),
            Value::Text(HOST_ATTESTOR_REPORT_DOMAIN.into()),
        ),
        (Value::Text("node_id".into()), Value::Text(node_id.into())),
    ]))
    .map_err(|e| HippiusTypesError::Cbor(format!("host_attestor preimage: {e}")))?;
    let digest = Sha256::digest(&preimage);
    let mut out = [0u8; REPORT_DATA_LEN];
    out[0..32].copy_from_slice(nonce);
    out[32..64].copy_from_slice(&digest);
    Ok(out)
}

/// Expected `REPORT_DATA` for a **custody bind** (see
/// [`crate::custody::CustodyBindBody`]).
///
/// All 64 bytes are `SHA-512` over a canonical-CBOR map binding
/// [`CUSTODY_BIND_REPORT_DOMAIN`], the KBS-minted single-use `nonce`, the
/// `vm_id`, the VM `generation`, the boot counter of this boot and the
/// per-boot Ed25519 `lease_pub`. That is what makes the lease key the KBS
/// registers the one the ATTESTED guest generated: a relay that swaps
/// `lease_pub` in the request breaks this byte-match, and it cannot
/// re-sign the report.
///
/// **Why the nonce is hashed rather than placed raw in `[0..32]`** (the
/// layout every other binding uses): the §21 release verifier takes
/// `REPORT_DATA[0..32]` as its nonce and `[32..64]` as the guest's X25519
/// key WITHOUT any domain check. A `nonce ‖ digest` bind report would
/// therefore also be a valid release report, and a relay withholding a
/// bind could post it to `/v1/kbs/release` with `N+1` — no key disclosed
/// (the KEK would be sealed to a hash, not a key), but the KBS would spend
/// the nonce and commit a boot counter the running guest never reached,
/// planting a phantom boot that makes the next custody verdict
/// `Superseded`. With the nonce inside the hash, `[0..32]` is never an
/// issued nonce, so every nonce-prefixed verifier (release, keepalive,
/// host-attestor) refuses a custody report, and a report minted for any
/// of them cannot match this digest.
///
/// The report alone does not name the VM (the golden launch measurement
/// is shared across same-distro tenants), which is why the bind is ALSO
/// signed by the VM's lifecycle key; this binding only ties the key to
/// the attested launch. Verifiers compare all 64 bytes (constant time)
/// against this function's output — never a raw-nonce prefix.
pub fn custody_bind(
    nonce: &[u8; 32],
    vm_id: &str,
    generation: u64,
    boot_counter: u64,
    lease_pub: &[u8; 32],
) -> Result<[u8; REPORT_DATA_LEN]> {
    let preimage = to_canonical_vec(&Value::Map(vec![
        (
            Value::Text("boot_counter".into()),
            Value::Integer(boot_counter.into()),
        ),
        (
            Value::Text("domain".into()),
            Value::Text(CUSTODY_BIND_REPORT_DOMAIN.into()),
        ),
        (
            Value::Text("generation".into()),
            Value::Integer(generation.into()),
        ),
        (
            Value::Text("lease_pub".into()),
            Value::Bytes(lease_pub.to_vec()),
        ),
        (Value::Text("nonce".into()), Value::Bytes(nonce.to_vec())),
        (Value::Text("vm_id".into()), Value::Text(vm_id.into())),
    ]))
    .map_err(|e| HippiusTypesError::Cbor(format!("custody_bind preimage: {e}")))?;
    let mut out = [0u8; REPORT_DATA_LEN];
    out.copy_from_slice(&Sha512::digest(&preimage));
    Ok(out)
}

/// Expected `REPORT_DATA` for a **key-guardian release** (see
/// [`crate::guardian::GuardianReleaseRequest`]):
///
/// ```text
/// [0..32]  = SHA-256(GUARDIAN_REPORT_DOMAIN ‖ nonce ‖ u16be(len vm_id) ‖ vm_id
///                    ‖ u32be(share_c_version, 0 = absent))
/// [32..64] = guest_pub   (fresh X25519 key the share is sealed to)
/// ```
///
/// `nonce` is the guardian-issued single-use nonce. The domain and the
/// nonce are fixed-length and `vm_id` is length-prefixed, so the preimage
/// is injective.
///
/// **Why `[0..32]` is a hash and not the raw nonce** (the custody-bind
/// lesson, see [`custody_bind`]): the KBS release verifier reads
/// `REPORT_DATA[0..32]` as its nonce and `[32..64]` as the guest X25519
/// key with no domain check. With the guardian nonce hashed, `[0..32]`
/// is never a value the KBS issued, so a relay cannot post a guardian
/// report to `/v1/kbs/release` to spend a KBS release (and bump the
/// unconfirmed-release count) behind the guest's back. The other way
/// round, a KBS report (`kbs_nonce ‖ key`) never equals this hash, so it
/// cannot be replayed to the guardian. The key stays raw in `[32..64]`
/// because that is what the guardian seals to.
///
/// `vm_id` is in the report so a guardian answer is bound to the VM the
/// ATTESTED guest believes it is (read from its measured cmdline), not
/// only to the `vm_id` field of the untrusted request.
///
/// `share_c_version` (the request field: the version in the volume's
/// LUKS2 token, `None` on first boot) is in the report because the relay
/// could otherwise turn a first-boot `None` into `Some(old)` and have the
/// guardian seal a retired share the guest — which accepts any version
/// when it named none — would format a new volume with. Versions are
/// `>= 1`, so `0` encodes "absent" unambiguously.
pub fn guardian(
    nonce: &[u8; 32],
    vm_id: &str,
    guest_pub: &[u8; 32],
    share_c_version: Option<u32>,
) -> Result<[u8; REPORT_DATA_LEN]> {
    if share_c_version == Some(0) {
        return Err(HippiusTypesError::GuardianSchema(
            "share_c_version must be >= 1".into(),
        ));
    }
    // Same bounds as every guardian wire type (`guardian::MAX_VM_ID_LEN`),
    // so a report can never bind a vm_id the protocol would refuse.
    if vm_id.is_empty() || vm_id.len() > crate::guardian::MAX_VM_ID_LEN {
        return Err(HippiusTypesError::GuardianSchema(
            "vm_id length out of bounds".into(),
        ));
    }
    let len = u16::try_from(vm_id.len())
        .map_err(|_| HippiusTypesError::GuardianSchema("vm_id too long for u16 framing".into()))?;
    let mut h = Sha256::new();
    h.update(GUARDIAN_REPORT_DOMAIN.as_bytes());
    h.update(nonce);
    h.update(len.to_be_bytes());
    h.update(vm_id.as_bytes());
    h.update(share_c_version.unwrap_or(0).to_be_bytes());
    let mut out = [0u8; REPORT_DATA_LEN];
    out[0..32].copy_from_slice(&h.finalize());
    out[32..64].copy_from_slice(guest_pub);
    Ok(out)
}

/// Constant-time equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_layout_is_exact() {
        let rd = tenant(&[1u8; 32], &[2u8; 32]);
        assert_eq!(&rd[0..32], &[1u8; 32]);
        assert_eq!(&rd[32..64], &[2u8; 32]);
    }

    #[test]
    fn audit_vm_layout_binds_node_and_platform() {
        let a = audit_vm(&[1u8; 32], &[9u8; 32], b"node-1", b"chip-1");
        let b = audit_vm(&[1u8; 32], &[9u8; 32], b"node-2", b"chip-1");
        assert!(!ct_eq(&a, &b));
        assert!(ct_eq(
            &a,
            &audit_vm(&[1u8; 32], &[9u8; 32], b"node-1", b"chip-1")
        ));
    }

    #[test]
    fn audit_vm_binding_is_injective_across_field_splits() {
        // Without length-prefixing, `node_id="ab" + platform_id="c"`
        // and `node_id="a" + platform_id="bc"` would concatenate to the
        // same bytes and hash identically. The length prefixes must
        // keep the two distinct.
        let a = audit_vm(&[1u8; 32], &[9u8; 32], b"ab", b"c");
        let b = audit_vm(&[1u8; 32], &[9u8; 32], b"a", b"bc");
        assert!(!ct_eq(&a, &b));
        // Same for an ambiguous pubkey / node_id split.
        let c = audit_vm(&[1u8; 32], b"xy", b"z", b"p");
        let d = audit_vm(&[1u8; 32], b"x", b"yz", b"p");
        assert!(!ct_eq(&c, &d));
    }

    #[test]
    fn tenant_stamp_v2_hashes_the_nonce_and_keeps_the_guest_key() {
        let nonce = [0x11; 32];
        let pk = [0x22; 32];
        let rd = tenant_stamp_v2(&nonce, &pk);
        let mut h = Sha256::new();
        h.update(b"HIPPIUS_TENANT_RELEASE_STAMP_V2_REPORT");
        h.update(nonce);
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(&rd[0..32], &want);
        assert_eq!(&rd[32..64], &pk);
        // Never the v1 layout, for any nonce.
        assert_ne!(rd, tenant(&nonce, &pk));
        assert_ne!(&rd[0..32], &nonce);
    }

    #[test]
    fn the_stamp_v2_domain_is_distinct_from_every_report_data_domain() {
        for other in [
            core::str::from_utf8(AUDIT_VM_DOMAIN).unwrap(),
            TENANT_TELEMETRY_DOMAIN,
            LIVE_ATTESTATION_REPORT_DOMAIN,
            LIVE_ATTESTATION_RESOURCES_REPORT_DOMAIN,
            HOST_ATTESTOR_REPORT_DOMAIN,
            CUSTODY_BIND_REPORT_DOMAIN,
            GUARDIAN_REPORT_DOMAIN,
        ] {
            assert_ne!(TENANT_RELEASE_STAMP_V2_REPORT_DOMAIN, other);
        }
    }

    #[test]
    fn ct_eq_rejects_length_mismatch() {
        assert!(!ct_eq(&[0u8; 3], &[0u8; 4]));
    }

    #[test]
    fn tenant_telemetry_places_nonce_then_digest() {
        let rd = tenant_telemetry(&[0x11; 32], &[0x22; 32], b"node-1", "vm-1").unwrap();
        assert_eq!(rd.len(), 64);
        assert_eq!(&rd[0..32], &[0x11; 32], "REPORT_DATA[0..32] = nonce");
        // [32..64] is the SHA-256 binding — not the raw pubkey.
        assert_ne!(&rd[32..64], &[0x22; 32]);
    }

    #[test]
    fn tenant_telemetry_binds_every_field() {
        let base = tenant_telemetry(&[1; 32], &[2; 32], b"node-1", "vm-1").unwrap();
        // Each input change ⇒ a different binding.
        assert_ne!(
            base,
            tenant_telemetry(&[9; 32], &[2; 32], b"node-1", "vm-1").unwrap()
        );
        assert_ne!(
            base,
            tenant_telemetry(&[1; 32], &[9; 32], b"node-1", "vm-1").unwrap()
        );
        assert_ne!(
            base,
            tenant_telemetry(&[1; 32], &[2; 32], b"node-2", "vm-1").unwrap()
        );
        assert_ne!(
            base,
            tenant_telemetry(&[1; 32], &[2; 32], b"node-1", "vm-2").unwrap()
        );
    }

    #[test]
    fn tenant_telemetry_node_vm_boundary_is_unambiguous() {
        // The canonical-CBOR-map preimage is self-delimiting, so a
        // plain-concatenation collision — (node="ab", vm="c") vs
        // (node="a", vm="bc") — cannot happen.
        let a = tenant_telemetry(&[0; 32], &[0; 32], b"ab", "c").unwrap();
        let b = tenant_telemetry(&[0; 32], &[0; 32], b"a", "bc").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tenant_telemetry_is_deterministic() {
        let a = tenant_telemetry(&[7; 32], &[8; 32], b"node-x", "vm-x").unwrap();
        let b = tenant_telemetry(&[7; 32], &[8; 32], b"node-x", "vm-x").unwrap();
        assert_eq!(a, b);
    }

    /// Known-answer vector — frozen so a canonical-CBOR encoding change
    /// or a domain-tag edit (which would silently shift every tenant
    /// telemetry attestation) fails CI loudly. Inputs: `nonce = [0x11;
    /// 32]`, `signer_pubkey = [0x22; 32]`, `node_id = b"node-kat-1"`,
    /// `vm_id = "vm-kat-1"`.
    #[test]
    fn tenant_telemetry_known_answer() {
        let rd = tenant_telemetry(&[0x11; 32], &[0x22; 32], b"node-kat-1", "vm-kat-1").unwrap();
        let mut hex = String::new();
        for b in rd {
            hex.push_str(&format!("{b:02x}"));
        }
        assert_eq!(
            hex,
            "1111111111111111111111111111111111111111111111111111111111111111\
             08230cc2052e7b4824aaaa966671bb125f0376322c94a71b7cbd3eddb66ba746"
        );
    }

    // --- §322 live attestation ---

    #[test]
    fn live_attestation_places_nonce_then_digest() {
        let rd = live_attestation(&[0xAA; 32], "vm-keepalive-1").unwrap();
        assert_eq!(rd.len(), 64);
        assert_eq!(&rd[0..32], &[0xAA; 32], "REPORT_DATA[0..32] = nonce");
        assert_ne!(&rd[32..64], &[0u8; 32]);
    }

    #[test]
    fn live_attestation_binds_nonce_and_vm_id() {
        let base = live_attestation(&[1; 32], "vm-A").unwrap();
        assert_ne!(base, live_attestation(&[9; 32], "vm-A").unwrap());
        assert_ne!(base, live_attestation(&[1; 32], "vm-B").unwrap());
    }

    #[test]
    fn live_attestation_with_resources_binds_every_value() {
        use crate::live_attestation::GuestResources;
        let r = GuestResources {
            vcpus_online: 4,
            mem_firmware_kib: 16 * 1024 * 1024,
            mem_total_kib: 15 * 1024 * 1024,
            mem_unaccepted_kib: 0,
        };
        let base = live_attestation_with_resources(&[1; 32], "vm-A", &r).unwrap();
        assert_eq!(&base[0..32], &[1u8; 32]);
        for other in [
            GuestResources {
                vcpus_online: 3,
                ..r
            },
            GuestResources {
                mem_firmware_kib: r.mem_firmware_kib - 1,
                ..r
            },
            GuestResources {
                mem_total_kib: r.mem_total_kib - 1,
                ..r
            },
            GuestResources {
                mem_unaccepted_kib: 1,
                ..r
            },
        ] {
            assert_ne!(
                base,
                live_attestation_with_resources(&[1; 32], "vm-A", &other).unwrap()
            );
        }
        assert_ne!(
            base,
            live_attestation_with_resources(&[1; 32], "vm-B", &r).unwrap()
        );
        assert_ne!(
            base,
            live_attestation_with_resources(&[2; 32], "vm-A", &r).unwrap()
        );
        // Never the resource-less layout for the same (nonce, vm_id).
        assert_ne!(base, live_attestation(&[1; 32], "vm-A").unwrap());
    }

    #[test]
    fn live_attestation_is_deterministic() {
        let a = live_attestation(&[7; 32], "vm-x").unwrap();
        let b = live_attestation(&[7; 32], "vm-x").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn live_attestation_distinct_from_tenant_telemetry() {
        // Different domain tags ⇒ different `[32..64]` even when
        // every other input is identical. Locks the cross-domain
        // separation: a tenant-telemetry SNP report cannot replay
        // as a live-attestation report.
        let lk = live_attestation(&[0; 32], "vm-1").unwrap();
        let tt = tenant_telemetry(&[0; 32], &[0; 32], b"", "vm-1").unwrap();
        assert_ne!(&lk[32..64], &tt[32..64]);
    }

    // --- blackbox host-attestor enrollment ---

    #[test]
    fn host_attestor_places_nonce_then_digest() {
        let rd = host_attestor(&[0xCC; 32], &[0xDD; 32], "node-host-1").unwrap();
        assert_eq!(rd.len(), 64);
        assert_eq!(&rd[0..32], &[0xCC; 32], "REPORT_DATA[0..32] = nonce");
        // [32..64] is the SHA-256 binding — not the raw pubkey.
        assert_ne!(&rd[32..64], &[0xDD; 32]);
    }

    #[test]
    fn host_attestor_binds_every_field() {
        let base = host_attestor(&[1; 32], &[2; 32], "node-1").unwrap();
        assert_ne!(base, host_attestor(&[9; 32], &[2; 32], "node-1").unwrap());
        assert_ne!(base, host_attestor(&[1; 32], &[9; 32], "node-1").unwrap());
        assert_ne!(base, host_attestor(&[1; 32], &[2; 32], "node-2").unwrap());
    }

    #[test]
    fn host_attestor_is_deterministic() {
        let a = host_attestor(&[7; 32], &[8; 32], "node-x").unwrap();
        let b = host_attestor(&[7; 32], &[8; 32], "node-x").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn host_attestor_pubkey_node_boundary_is_unambiguous() {
        // The canonical-CBOR-map preimage is self-delimiting, so a
        // plain-concatenation collision cannot happen: even though the
        // pubkey is a fixed 32 bytes here, the self-delimiting map keeps
        // the domain / node_id / pubkey framing injective. Distinct
        // node_id ⇒ distinct binding.
        let a = host_attestor(&[0; 32], &[0; 32], "ab").unwrap();
        let b = host_attestor(&[0; 32], &[0; 32], "abx").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn host_attestor_distinct_from_every_other_report_domain() {
        // A host-attestor enrollment report must NOT collide with any
        // other `REPORT_DATA` binding under identical inputs — locks
        // cross-domain replay resistance for the whole family.
        let nonce = [0u8; 32];
        let pk = [0u8; 32];
        let ha = host_attestor(&nonce, &pk, "vm-1").unwrap();
        // vs tenant (raw x25519 layout)
        assert_ne!(&ha[32..64], &tenant(&nonce, &pk)[32..64]);
        // vs tenant_telemetry (same anti-concat map, different domain)
        let tt = tenant_telemetry(&nonce, &pk, b"vm-1", "vm-1").unwrap();
        assert_ne!(&ha[32..64], &tt[32..64]);
        // vs live_attestation
        let la = live_attestation(&nonce, "vm-1").unwrap();
        assert_ne!(&ha[32..64], &la[32..64]);
        // vs audit_vm (legacy plain-concat)
        let av = audit_vm(&nonce, &pk, b"vm-1", b"vm-1");
        assert_ne!(&ha[32..64], &av[32..64]);
    }

    // --- custody bind ---

    #[test]
    fn custody_bind_binds_every_field() {
        let base = custody_bind(&[1; 32], "vm-1", 3, 7, &[2; 32]).unwrap();
        assert_ne!(
            base,
            custody_bind(&[9; 32], "vm-1", 3, 7, &[2; 32]).unwrap()
        );
        assert_ne!(
            base,
            custody_bind(&[1; 32], "vm-2", 3, 7, &[2; 32]).unwrap()
        );
        assert_ne!(
            base,
            custody_bind(&[1; 32], "vm-1", 4, 7, &[2; 32]).unwrap()
        );
        assert_ne!(
            base,
            custody_bind(&[1; 32], "vm-1", 3, 8, &[2; 32]).unwrap()
        );
        assert_ne!(
            base,
            custody_bind(&[1; 32], "vm-1", 3, 7, &[9; 32]).unwrap()
        );
    }

    #[test]
    fn custody_bind_never_carries_the_raw_nonce_where_release_looks_for_it() {
        // The §21 release verifier reads REPORT_DATA[0..32] as its nonce
        // with no domain check. A custody report must never put the
        // issued nonce there, or it doubles as a release report.
        let nonce = [0x5a; 32];
        let rd = custody_bind(&nonce, "vm-1", 3, 7, &[2; 32]).unwrap();
        assert_ne!(&rd[0..32], &nonce);
        assert_ne!(&rd[32..64], &nonce);
    }

    #[test]
    fn custody_bind_is_distinct_from_every_other_report_domain() {
        let nonce = [0u8; 32];
        let pk = [0u8; 32];
        let cb = custody_bind(&nonce, "vm-1", 0, 0, &pk).unwrap();
        assert_ne!(cb, tenant(&nonce, &pk));
        assert_ne!(cb, tenant_telemetry(&nonce, &pk, b"vm-1", "vm-1").unwrap());
        assert_ne!(cb, live_attestation(&nonce, "vm-1").unwrap());
        assert_ne!(cb, host_attestor(&nonce, &pk, "vm-1").unwrap());
        assert_ne!(cb, audit_vm(&nonce, &pk, b"vm-1", b"vm-1"));
    }

    /// Known-answer vector — the guest daemon and the KBS must compute
    /// these 64 bytes identically, so the encoding is frozen here. Inputs:
    /// `nonce = [0x11; 32]`, `vm_id = "vm-kat-custody-1"`, `generation =
    /// 3`, `boot_counter = 7`, `lease_pub = [0x22; 32]`.
    #[test]
    fn custody_bind_known_answer() {
        let rd = custody_bind(&[0x11; 32], "vm-kat-custody-1", 3, 7, &[0x22; 32]).unwrap();
        let mut hex = String::new();
        for b in rd {
            hex.push_str(&format!("{b:02x}"));
        }
        assert_eq!(
            hex,
            "69d4076066a39865810a900eca48f248984c958a3232927e96765ac4457fa936\
             97e379fa81b4b75662f3baf58918d923a1eeba379b2538f6ee973e41faba9384"
        );
    }

    // --- key guardian ---

    #[test]
    fn guardian_differs_from_tenant_for_the_same_inputs() {
        let nonce = [0x33; 32];
        let pk = [0x44; 32];
        let g = guardian(&nonce, "vm-1", &pk, None).unwrap();
        let t = tenant(&nonce, &pk);
        assert_ne!(g, t);
        // Precisely: the raw nonce is never where the KBS verifier reads
        // one, and the key is where the guardian seals to.
        assert_ne!(&g[0..32], &nonce);
        assert_eq!(&g[32..64], &pk);
    }

    #[test]
    fn guardian_binds_every_field() {
        let base = guardian(&[1; 32], "vm-1", &[2; 32], None).unwrap();
        assert_ne!(base, guardian(&[9; 32], "vm-1", &[2; 32], None).unwrap());
        assert_ne!(base, guardian(&[1; 32], "vm-2", &[2; 32], None).unwrap());
        assert_ne!(base, guardian(&[1; 32], "vm-1", &[9; 32], None).unwrap());
        assert_eq!(base, guardian(&[1; 32], "vm-1", &[2; 32], None).unwrap());
    }

    #[test]
    fn guardian_is_distinct_from_every_other_report_domain() {
        let nonce = [0u8; 32];
        let pk = [0u8; 32];
        let g = guardian(&nonce, "vm-1", &pk, None).unwrap();
        assert_ne!(g, tenant(&nonce, &pk));
        assert_ne!(g, tenant_telemetry(&nonce, &pk, b"vm-1", "vm-1").unwrap());
        assert_ne!(g, live_attestation(&nonce, "vm-1").unwrap());
        assert_ne!(g, host_attestor(&nonce, &pk, "vm-1").unwrap());
        assert_ne!(g, custody_bind(&nonce, "vm-1", 0, 0, &pk).unwrap());
        assert_ne!(g, audit_vm(&nonce, &pk, b"vm-1", b"vm-1"));
    }

    #[test]
    fn guardian_applies_the_wire_vm_id_bounds() {
        let max = crate::guardian::MAX_VM_ID_LEN;
        assert!(guardian(&[0; 32], "", &[0; 32], None).is_err());
        assert!(guardian(&[0; 32], "v", &[0; 32], None).is_ok());
        assert!(guardian(&[0; 32], &"v".repeat(max), &[0; 32], None).is_ok());
        assert!(guardian(&[0; 32], &"v".repeat(max + 1), &[0; 32], None).is_err());
        let huge = "v".repeat(usize::from(u16::MAX) + 1);
        assert!(guardian(&[0; 32], &huge, &[0; 32], None).is_err());
    }

    #[test]
    fn guardian_binds_share_c_version() {
        let none = guardian(&[1; 32], "vm-1", &[2; 32], None).unwrap();
        let v1 = guardian(&[1; 32], "vm-1", &[2; 32], Some(1)).unwrap();
        let v2 = guardian(&[1; 32], "vm-1", &[2; 32], Some(2)).unwrap();
        // First boot (None) must not be re-spellable as an old version.
        assert_ne!(none, v1);
        assert_ne!(v1, v2);
        assert!(guardian(&[1; 32], "vm-1", &[2; 32], Some(0)).is_err());
    }

    /// Known-answer vectors, computed independently (Python `hashlib`):
    /// `sha256(b"HIPPIUS_GUARDIAN_REPORT_V1" + b"\x11"*32 + b"\x00\x0f" +
    /// b"vm-kat-guard-01" + v.to_bytes(4, "big")) ‖ b"\x22"*32` for
    /// `v = 0` (absent) and `v = 7`. The guest and the guardian must
    /// compute these 64 bytes identically.
    #[test]
    fn guardian_known_answer() {
        let hex = |rd: [u8; REPORT_DATA_LEN]| -> String {
            rd.iter().map(|b| format!("{b:02x}")).collect()
        };
        let pk_hex = "2222222222222222222222222222222222222222222222222222222222222222";
        let none = guardian(&[0x11; 32], "vm-kat-guard-01", &[0x22; 32], None).unwrap();
        assert_eq!(
            hex(none),
            format!("aeea2e93cfb330a3e5d4dda80afa2e2d5cb5b44f9e13c95fa04fb6f9c2dca749{pk_hex}")
        );
        let v7 = guardian(&[0x11; 32], "vm-kat-guard-01", &[0x22; 32], Some(7)).unwrap();
        assert_eq!(
            hex(v7),
            format!("494bf0a9e6fb87d8c94be07b37c166c988102a2e9eec947e1c4924ba15733ed8{pk_hex}")
        );
    }

    /// Known-answer vector — frozen so a canonical-CBOR encoding change
    /// or a domain-tag edit (which would silently shift every
    /// host-attestor enrollment) fails CI loudly. Inputs: `nonce =
    /// [0x11; 32]`, `attestor_pubkey = [0x22; 32]`, `node_id =
    /// "node-kat-host-1"`.
    #[test]
    fn host_attestor_known_answer() {
        let rd = host_attestor(&[0x11; 32], &[0x22; 32], "node-kat-host-1").unwrap();
        let mut hex = String::new();
        for b in rd {
            hex.push_str(&format!("{b:02x}"));
        }
        assert_eq!(
            hex,
            "1111111111111111111111111111111111111111111111111111111111111111\
             93cedb148ceb5d9374427010590680168f4de8d03530110bf68207264473aa0e"
        );
    }
}
