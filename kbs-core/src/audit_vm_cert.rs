//! KBS issuance of the Audit-VM certificate (ARCHITECTURE.md §22/§23).
//!
//! After the §7 attestation checks pass for an Audit-VM first-boot
//! request, the KBS issues a certificate binding the Audit-VM's Ed25519
//! public key to its node identity + a validity window, signed with the
//! **§22 offline allowlist root key**. The wire format
//! ([`AuditVmCert`] / [`SignedAuditVmCert`]) lives in `hippius-types`;
//! this module owns only the **signing** half — the verify half is
//! `hippius_guest::audit_vm_cert::verify_cert`, which runs inside the
//! attested Audit VM.
//!
//! ## Trust-root note (§22)
//!
//! The §22 root key is held air-gapped / in an HSM; production wires
//! that key in out-of-band. [`issue_cert`] takes the [`SigningKey`] as
//! a parameter rather than reaching for a global so the air-gap
//! boundary stays explicit and tests can drive it with a committed dev
//! key. The same root key signs image-provenance maps (§11) — but the
//! **distinct domain tag** baked into each signed body
//! ([`hippius_types::audit_vm_cert::AUDIT_VM_CERT_DOMAIN`] vs
//! `PROVENANCE_DOMAIN`) means a signature minted for one can never
//! verify as the other.

use crate::error::Result;
use ed25519_dalek::{Signer, SigningKey};
use hippius_types::audit_vm_cert::{AuditVmCert, SignedAuditVmCert, AUDIT_VM_CERT_SCHEMA_VERSION};

/// Issue a §22-root-signed Audit-VM certificate.
///
/// `root_sk` is the §22 offline allowlist root key. `audit_vm_pubkey`
/// is the Ed25519 key the Audit VM bound into `REPORT_DATA[32..64]` at
/// first attestation. `not_before` / `not_after` are the validity
/// window in Unix seconds.
///
/// # Security — caller contract (Critical)
///
/// `issue_cert` is a pure signing primitive: it performs **no
/// attestation verification whatsoever**. It signs *exactly* the
/// `{audit_vm_pubkey, node_id, platform_id}` triple it is handed.
///
/// The caller MUST, BEFORE calling this, run the full §7 / §21
/// attestation path on the SNP report — in particular it MUST
/// recompute the §20 `audit_vm` `REPORT_DATA[32..64]` binding by
/// calling [`hippius_types::report_data::audit_vm`] (the single source
/// of truth for that preimage — note its fields are length-prefixed,
/// so a hand-rolled `pubkey ‖ domain ‖ node_id ‖ platform_id` concat
/// will NOT match) and constant-time compare it to `REPORT_DATA[32..64]`
/// of the *verified* report, so the `{audit_vm_pubkey, node_id,
/// platform_id}` triple passed here is the one a genuine SEV-SNP guest
/// attested. Otherwise `issue_cert` will happily certify an unattested
/// / attacker-chosen key. **It MUST NOT be exposed on any HTTP route
/// until that §7 recompute gates it** — that wiring is a separate §E3
/// / KBS-server PR; PR-E3.1 ships only the signing primitive + the
/// agent's consume-side `verify_cert`.
///
/// Fails closed if the cert body would be semantically invalid (empty
/// `node_id` / `platform_id`, an inverted window) — `canonical()` runs
/// `validate()`, so an un-encodable cert is never signed.
pub fn issue_cert(
    root_sk: &SigningKey,
    audit_vm_pubkey: &[u8; 32],
    node_id: &[u8],
    platform_id: &[u8],
    not_before: u64,
    not_after: u64,
) -> Result<SignedAuditVmCert> {
    let cert = AuditVmCert {
        schema_version: AUDIT_VM_CERT_SCHEMA_VERSION,
        audit_vm_pubkey: *audit_vm_pubkey,
        node_id: node_id.to_vec(),
        platform_id: platform_id.to_vec(),
        not_before,
        not_after,
        // Self-certifying: bind the signing root's public key INTO the
        // body, so a verifier can confirm which root produced the
        // signature before trusting it.
        signer_pubkey: root_sk.verifying_key().to_bytes(),
    };
    let body = cert.canonical()?;
    let sig = root_sk.sign(&body);
    Ok(SignedAuditVmCert {
        body,
        sig: sig.to_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use hippius_types::audit_vm_cert::AUDIT_VM_CERT_DOMAIN;

    fn root() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    #[test]
    fn issue_cert_produces_a_root_verifiable_signature() {
        let root = root();
        let signed = issue_cert(&root, &[9u8; 32], b"node-1", b"chip-1", 1_000, 2_000).unwrap();
        // The §22 root's signature over the exact body verifies.
        let sig = ed25519_dalek::Signature::from_slice(&signed.sig).unwrap();
        root.verifying_key().verify(&signed.body, &sig).unwrap();
        // The body decodes back to the inputs.
        let cert = AuditVmCert::decode(&signed.body).unwrap();
        assert_eq!(cert.audit_vm_pubkey, [9u8; 32]);
        assert_eq!(cert.node_id, b"node-1");
        assert_eq!(cert.platform_id, b"chip-1");
        assert_eq!(cert.not_before, 1_000);
        assert_eq!(cert.not_after, 2_000);
        assert_eq!(cert.signer_pubkey, root.verifying_key().to_bytes());
    }

    #[test]
    fn issue_cert_signs_the_audit_vm_cert_domain() {
        let signed = issue_cert(&root(), &[1u8; 32], b"n", b"p", 10, 20).unwrap();
        let body: ciborium::value::Value =
            ciborium::de::from_reader(signed.body.as_slice()).unwrap();
        let ciborium::value::Value::Map(entries) = body else {
            panic!("cert body is not a map");
        };
        let domain = entries.iter().find_map(|(k, v)| match (k, v) {
            (ciborium::value::Value::Text(t), ciborium::value::Value::Text(d)) if t == "domain" => {
                Some(d.clone())
            }
            _ => None,
        });
        assert_eq!(domain.as_deref(), Some(AUDIT_VM_CERT_DOMAIN));
    }

    #[test]
    fn issue_cert_fails_closed_on_an_inverted_window() {
        // `canonical()` runs `validate()` — an un-encodable cert is
        // never signed.
        assert!(issue_cert(&root(), &[0u8; 32], b"n", b"p", 2_000, 1_000).is_err());
    }

    #[test]
    fn issue_cert_fails_closed_on_empty_identity() {
        assert!(issue_cert(&root(), &[0u8; 32], b"", b"p", 10, 20).is_err());
        assert!(issue_cert(&root(), &[0u8; 32], b"n", b"", 10, 20).is_err());
    }
}
