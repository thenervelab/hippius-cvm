//! Audit-VM certificate verification, guest side (ARCHITECTURE.md
//! §22/§23).
//!
//! Runs **inside** the attested Audit VM. After first-boot attestation
//! the KBS returns a [`SignedAuditVmCert`] (issued by
//! `kbs_core::audit_vm_cert::issue_cert`, signed with the §22 offline
//! root). [`verify_cert`] is the guest's single trust gate over it:
//! everything downstream (§23 liveness, `ServedDeliveryAggregate`
//! co-signatures) is gated on a cert that passed here.
//!
//! Fail-closed on every error — a bad signature, a §22 root that is not
//! the pinned one, a cert minted for a different Audit-VM key, or a
//! validity window that does not cover "now". There is no
//! "try-another-cert" path: the Audit VM has exactly one identity and
//! one cert.

use crate::error::{GuestError, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use hippius_types::audit_vm_cert::{AuditVmCert, SignedAuditVmCert};

/// Verify a KBS-issued Audit-VM certificate, guest side.
///
/// - `signed` — the `{body, sig}` envelope received from the KBS.
/// - `expected_audit_vm_pubkey` — the Audit VM's own Ed25519 public
///   key (the one it bound into `REPORT_DATA` at first attestation).
///   The cert MUST be for this exact key.
/// - `expected_node_id` / `expected_platform_id` — the node + platform
///   identity the Audit VM put into its own `REPORT_DATA` and cert
///   request. The cert MUST bind the key to **exactly** this identity:
///   a §22-signed cert is a statement about a `{key, node, platform}`
///   triple, so the consumer verifies all three, not just the key — a
///   cert that bound this key to a *different* node/platform must be
///   rejected (§23 platform-binding).
/// - `expected_root` — the §22 offline allowlist root verifying key,
///   pinned into the measured Audit-VM image. The cert's signature
///   MUST verify under this key, and the cert's self-declared
///   `signer_pubkey` MUST equal it.
/// - `now_unix` — the guest's current time; the cert's validity window
///   MUST cover it.
///
/// On success returns the decoded [`AuditVmCert`]. Every failure path
/// is a fail-closed `Err`.
pub fn verify_cert(
    signed: &SignedAuditVmCert,
    expected_audit_vm_pubkey: &[u8; 32],
    expected_node_id: &[u8],
    expected_platform_id: &[u8],
    expected_root: &VerifyingKey,
    now_unix: u64,
) -> Result<AuditVmCert> {
    // 1. Authenticate the body bytes against the PINNED §22 root before
    //    trusting a single field inside them. `verify_strict` rejects
    //    the known malleable / small-order edge cases.
    let sig = Signature::from_slice(&signed.sig)
        .map_err(|e| GuestError::Signature(format!("cert sig decode: {e}")))?;
    expected_root
        .verify_strict(&signed.body, &sig)
        .map_err(|e| GuestError::Signature(format!("cert sig invalid: {e}")))?;

    // 2. The body is authentic-from-our-root — now parse it. `decode`
    //    is itself fail-closed (canonical gate, domain tag, schema,
    //    field validation).
    let cert = AuditVmCert::decode(&signed.body)
        .map_err(|e| GuestError::Schema(format!("cert decode: {e}")))?;

    // 3. The cert's self-declared signer MUST be the root we just
    //    verified against — a mismatch means a malformed / confused
    //    cert even though the signature checked out.
    if cert.signer_pubkey != expected_root.to_bytes() {
        return Err(GuestError::Schema(
            "cert signer_pubkey does not match the pinned §22 root".into(),
        ));
    }

    // 4. The cert MUST bind THIS Audit VM's whole identity triple —
    //    key, node, platform. A cert minted for another node's Audit
    //    VM (or for this key under a different node/platform) must
    //    never authorise this one.
    if &cert.audit_vm_pubkey != expected_audit_vm_pubkey {
        return Err(GuestError::Schema(
            "cert audit_vm_pubkey does not match this Audit VM's key".into(),
        ));
    }
    if cert.node_id != expected_node_id {
        return Err(GuestError::Schema(
            "cert node_id does not match this Audit VM's node".into(),
        ));
    }
    if cert.platform_id != expected_platform_id {
        return Err(GuestError::Schema(
            "cert platform_id does not match this Audit VM's platform".into(),
        ));
    }

    // 5. The validity window MUST cover now. An expired (or not-yet-
    //    valid) cert is rejected — fail-closed, no grace period.
    if !cert.covers(now_unix) {
        return Err(GuestError::Schema(format!(
            "cert validity window [{}, {}] does not cover now={now_unix}",
            cert.not_before, cert.not_after
        )));
    }

    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hippius_types::audit_vm_cert::{AuditVmCert, AUDIT_VM_CERT_SCHEMA_VERSION};

    const NODE: &[u8] = b"node-1";
    const PLATFORM: &[u8] = b"chip-1";

    /// Mint a `SignedAuditVmCert` the way `kbs_core::issue_cert` does —
    /// duplicated here so the guest crate's test does not depend on
    /// kbs-core (the issue side is a separate trust domain). `node_id`
    /// / `platform_id` are parameters so a test can mint a mismatched
    /// cert.
    fn mint_full(
        root: &SigningKey,
        audit_vm_pubkey: [u8; 32],
        node_id: &[u8],
        platform_id: &[u8],
        not_before: u64,
        not_after: u64,
    ) -> SignedAuditVmCert {
        let cert = AuditVmCert {
            schema_version: AUDIT_VM_CERT_SCHEMA_VERSION,
            audit_vm_pubkey,
            node_id: node_id.to_vec(),
            platform_id: platform_id.to_vec(),
            not_before,
            not_after,
            signer_pubkey: root.verifying_key().to_bytes(),
        };
        let body = cert.canonical().unwrap();
        let sig = root.sign(&body);
        SignedAuditVmCert {
            body,
            sig: sig.to_bytes().to_vec(),
        }
    }

    /// The common case — a cert for the pinned NODE / PLATFORM.
    fn mint(
        root: &SigningKey,
        audit_vm_pubkey: [u8; 32],
        not_before: u64,
        not_after: u64,
    ) -> SignedAuditVmCert {
        mint_full(root, audit_vm_pubkey, NODE, PLATFORM, not_before, not_after)
    }

    fn root() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// `verify_cert` with the pinned NODE / PLATFORM and a `now` in the
    /// usual `[1_000, 2_000]` test window.
    fn verify(
        signed: &SignedAuditVmCert,
        avk: &[u8; 32],
        root: &SigningKey,
        now: u64,
    ) -> Result<AuditVmCert> {
        verify_cert(signed, avk, NODE, PLATFORM, &root.verifying_key(), now)
    }

    #[test]
    fn a_valid_cert_verifies() {
        let root = root();
        let avk = [0x42u8; 32];
        let signed = mint(&root, avk, 1_000, 2_000);
        let cert = verify(&signed, &avk, &root, 1_500).unwrap();
        assert_eq!(cert.audit_vm_pubkey, avk);
    }

    #[test]
    fn a_cert_signed_by_a_different_root_is_rejected() {
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let avk = [0x42u8; 32];
        let signed = mint(&attacker, avk, 1_000, 2_000);
        // Verifying against the pinned real root must fail.
        assert!(verify(&signed, &avk, &root(), 1_500).is_err());
    }

    #[test]
    fn a_cert_for_a_different_audit_vm_key_is_rejected() {
        let root = root();
        let signed = mint(&root, [0x42u8; 32], 1_000, 2_000);
        // Our key is different from the one the cert was minted for.
        assert!(verify(&signed, &[0x99u8; 32], &root, 1_500).is_err());
    }

    #[test]
    fn a_cert_for_a_different_node_or_platform_is_rejected() {
        let root = root();
        let avk = [0x42u8; 32];
        // §22-signed, for our key + window — but a different node_id.
        let wrong_node = mint_full(&root, avk, b"other-node", PLATFORM, 1_000, 2_000);
        assert!(verify(&wrong_node, &avk, &root, 1_500).is_err());
        // … and a different platform_id.
        let wrong_plat = mint_full(&root, avk, NODE, b"other-chip", 1_000, 2_000);
        assert!(verify(&wrong_plat, &avk, &root, 1_500).is_err());
    }

    #[test]
    fn an_expired_or_not_yet_valid_cert_is_rejected() {
        let root = root();
        let avk = [0x42u8; 32];
        let signed = mint(&root, avk, 1_000, 2_000);
        // Before the window / after the window.
        assert!(verify(&signed, &avk, &root, 999).is_err());
        assert!(verify(&signed, &avk, &root, 2_001).is_err());
        // Both bounds are inclusive.
        assert!(verify(&signed, &avk, &root, 1_000).is_ok());
        assert!(verify(&signed, &avk, &root, 2_000).is_ok());
    }

    #[test]
    fn a_tampered_body_is_rejected() {
        let root = root();
        let avk = [0x42u8; 32];
        let mut signed = mint(&root, avk, 1_000, 2_000);
        signed.body[10] ^= 0xff;
        assert!(verify(&signed, &avk, &root, 1_500).is_err());
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let root = root();
        let avk = [0x42u8; 32];
        let mut signed = mint(&root, avk, 1_000, 2_000);
        signed.sig[0] ^= 0xff;
        assert!(verify(&signed, &avk, &root, 1_500).is_err());
    }
}
