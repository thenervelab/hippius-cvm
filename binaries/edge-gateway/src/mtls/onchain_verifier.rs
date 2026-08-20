//! Permissionless on-chain miner-auth: the self-signed client-cert
//! verifier + the identity binding it relies on.
//!
//! This is the §-permissionless replacement for the operator-CA
//! `WebPkiClientVerifier` (`docs/design/permissionless-miner-auth.md`).
//! A miner presents a **self-signed** TLS client cert minted from its
//! Ed25519 node identity (`miner-agent`'s
//! `MinerIdentity::self_signed_client_pem`). There is no CA to chain
//! to; trust comes from the **chain**, enforced in two halves:
//!
//! 1. [`SelfSignedClientVerifier`] — accepts any self-signed client
//!    cert at the TLS layer (transport encryption only) and verifies
//!    the handshake `CertificateVerify` signature, so the peer is
//!    proven to hold the cert's private key. It does NOT validate a
//!    chain-to-CA (there is none) and does NOT consult the registry.
//! 2. [`bound_node_id_from_leaf`] — run post-handshake by
//!    [`super::MtlsAcceptor::accept`]: it extracts the node_id from the
//!    cert's SAN, **binds it to the cert's public key**, and the
//!    acceptor then gates that node_id on the live on-chain
//!    registered+`Active` set ([`super::registry::RegistryStore`]).
//!
//! ## Why the SAN↔key binding is load-bearing
//!
//! The node_id IS the miner's Ed25519 public key. Without binding the
//! SAN `hippius-node:<node_id>` to the cert's *actual* public key, a
//! peer could self-sign a cert with **its own** key but stamp a
//! **victim's** node_id in the SAN. TLS would prove it holds its own
//! key (true) and the registry check would pass (the victim is
//! registered) — impersonation. Requiring `SAN node_id == cert SPKI
//! Ed25519 key` closes that: proving possession of the cert key then
//! proves possession of exactly the claimed identity.

use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// The SAN URI scheme the miner-agent stamps its node identity under
/// (`URI:hippius-node:<node_id_hex>`). MUST match
/// `MinerIdentity::node_uri` on the agent side.
pub const NODE_URI_SCHEME: &str = "hippius-node:";

/// Failure extracting / binding the node identity from a leaf cert.
/// All variants are fail-closed: the acceptor drops the connection.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    /// Leaf DER did not parse as an X.509 certificate.
    #[error("identity-parse")]
    Parse,
    /// No SAN URI carrying the `hippius-node:` scheme.
    #[error("identity-no-san")]
    NoSan,
    /// The SAN URI's node_id was not 32 bytes of hex.
    #[error("identity-bad-san")]
    BadSan,
    /// The cert's public key is not a 32-byte Ed25519 key.
    #[error("identity-not-ed25519")]
    NotEd25519,
    /// The SAN node_id does not equal the cert's public key — a
    /// possible impersonation attempt (see the module docs).
    #[error("identity-mismatch")]
    Mismatch,
    /// The leaf carries more than one SAN URI. A legitimate miner cert
    /// has EXACTLY one (`hippius-node:<own-key>`). A second URI is a
    /// smuggled decoy: the attribution extractor
    /// ([`super::peer_id::extract_from_leaf`]) returns the FIRST SAN URI
    /// of any scheme, so a self-signed miner could set a victim's id as
    /// a decoy first URI (spoofing telemetry/heartbeat attribution)
    /// while binding its OWN key via a second `hippius-node:` URI to
    /// pass the registry gate. Reject the ambiguity outright (audit H9).
    #[error("identity-multiple-uris")]
    MultipleUris,
}

/// Extract the node_id from a leaf cert's SAN AND verify it equals the
/// cert's Ed25519 public key. Returns the 32-byte node_id on success.
///
/// This is the trust-binding step: the returned node_id is safe to
/// gate on the registry ONLY because it is proven equal to the key
/// the TLS handshake proves possession of.
pub fn bound_node_id_from_leaf(leaf_der: &[u8]) -> Result<[u8; 32], IdentityError> {
    let (_, cert) = X509Certificate::from_der(leaf_der).map_err(|_| IdentityError::Parse)?;

    // (1) The node_id claimed in the SAN URI `hippius-node:<hex>`.
    let san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .ok_or(IdentityError::NoSan)?;
    //
    // Count EVERY SAN URI (any scheme), not just the first
    // `hippius-node:` one: a legit cert has exactly one URI, so a second
    // is a smuggled decoy that the attribution extractor would return
    // instead of this key-bound id (audit H9). We do NOT `break` after
    // finding the node URI — we must see the whole SAN set to detect it.
    let mut uri_count = 0usize;
    let mut claimed: Option<[u8; 32]> = None;
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name {
            uri_count += 1;
            if let Some(hex_id) = uri.strip_prefix(NODE_URI_SCHEME) {
                let bytes = hex::decode(hex_id).map_err(|_| IdentityError::BadSan)?;
                if bytes.len() != 32 {
                    return Err(IdentityError::BadSan);
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                // Keep the FIRST node URI; a second URI (of any scheme)
                // trips the ambiguity guard below regardless.
                if claimed.is_none() {
                    claimed = Some(id);
                }
            }
        }
    }
    if uri_count > 1 {
        return Err(IdentityError::MultipleUris);
    }
    let claimed = claimed.ok_or(IdentityError::NoSan)?;

    // (2) The cert's actual public key. For Ed25519 (RFC 8410) the
    //     SubjectPublicKeyInfo's subjectPublicKey BIT STRING is the
    //     raw 32-byte key — so a 32-byte length is itself the Ed25519
    //     check (RSA/EC keys are DER structures far longer than 32 B).
    let spki = cert.public_key().subject_public_key.data.as_ref();
    if spki.len() != 32 {
        return Err(IdentityError::NotEd25519);
    }

    // (3) The binding: SAN node_id MUST equal the cert key.
    if spki != claimed {
        return Err(IdentityError::Mismatch);
    }
    Ok(claimed)
}

/// A rustls [`ClientCertVerifier`] that accepts **self-signed** client
/// certs (no CA), verifying only that the peer proves possession of
/// the cert's private key. On-chain admission is enforced separately,
/// post-handshake, in [`super::MtlsAcceptor::accept`].
#[derive(Debug)]
pub struct SelfSignedClientVerifier {
    provider: Arc<CryptoProvider>,
    supported: Vec<SignatureScheme>,
    /// We advertise no CA subject hints — there is no CA, and a miner
    /// selects its self-signed cert unconditionally.
    no_hints: Vec<DistinguishedName>,
}

impl SelfSignedClientVerifier {
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        let supported = provider
            .signature_verification_algorithms
            .supported_schemes();
        Self {
            provider,
            supported,
            no_hints: Vec::new(),
        }
    }
}

impl ClientCertVerifier for SelfSignedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.no_hints
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        // Accept any self-signed client cert at the transport layer.
        // We deliberately do NOT validate a chain-to-CA (there is no
        // CA). The SAN↔key binding + the on-chain registered+Active
        // gate are enforced post-handshake by the acceptor — see the
        // module docs and `MtlsAcceptor::accept`.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // The Edge pins TLS 1.3 at the config level, so this path is
        // never taken; implemented for trait completeness.
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // Proves the peer holds the private key for the leaf cert —
        // the possession half of the identity proof.
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.clone()
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Mint a self-signed Ed25519 client cert with SAN
    /// `hippius-node:<node_id>` where node_id is the cert's own key.
    /// Mirrors `MinerIdentity::self_signed_client_pem`. Returns
    /// `(leaf_der, node_id)`.
    fn mint_identity_cert() -> (Vec<u8>, [u8; 32]) {
        use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, Ia5String, KeyPair, SanType};
        // Ed25519 keypair.
        let kp = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        // The node_id is the raw 32-byte public key.
        let spki_der = kp.public_key_der();
        // SPKI Ed25519: the last 32 bytes are the raw key.
        let node_id_vec = spki_der[spki_der.len() - 32..].to_vec();
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&node_id_vec);

        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let uri =
            Ia5String::try_from(format!("{NODE_URI_SCHEME}{}", hex::encode(node_id))).unwrap();
        params.subject_alt_names.push(SanType::URI(uri));
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        let cert = params.self_signed(&kp).unwrap();
        (cert.der().to_vec(), node_id)
    }

    #[test]
    fn binding_accepts_a_well_formed_identity_cert() {
        let (leaf, node_id) = mint_identity_cert();
        assert_eq!(bound_node_id_from_leaf(&leaf).unwrap(), node_id);
    }

    #[test]
    fn binding_rejects_a_san_that_does_not_match_the_key() {
        // Mint a cert whose key is real but whose SAN claims a
        // DIFFERENT node_id — the impersonation attempt the binding
        // must catch.
        use rcgen::{CertificateParams, Ia5String, KeyPair, SanType};
        let kp = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let victim = [0x11u8; 32]; // not this cert's key
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let uri = Ia5String::try_from(format!("{NODE_URI_SCHEME}{}", hex::encode(victim))).unwrap();
        params.subject_alt_names.push(SanType::URI(uri));
        let cert = params.self_signed(&kp).unwrap();
        assert_eq!(
            bound_node_id_from_leaf(cert.der()).unwrap_err(),
            IdentityError::Mismatch
        );
    }

    #[test]
    fn binding_rejects_a_cert_with_no_node_uri_san() {
        use rcgen::{CertificateParams, KeyPair};
        let kp = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        // DNS SAN only — no hippius-node URI.
        let params = CertificateParams::new(vec!["miner.example".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        assert_eq!(
            bound_node_id_from_leaf(cert.der()).unwrap_err(),
            IdentityError::NoSan
        );
    }

    #[test]
    fn binding_rejects_garbage_der() {
        assert_eq!(
            bound_node_id_from_leaf(&[0u8; 16]).unwrap_err(),
            IdentityError::Parse
        );
    }

    /// H9: a miner binds its OWN key via a `hippius-node:` URI (so the
    /// registry gate passes) but smuggles a DECOY first URI of a
    /// different scheme carrying a victim's id. `extract_from_leaf`
    /// would return the decoy as the attribution PeerId — so the binding
    /// must reject the multi-URI cert outright.
    #[test]
    fn binding_rejects_decoy_first_uri_of_another_scheme() {
        use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, Ia5String, KeyPair, SanType};
        let kp = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let spki_der = kp.public_key_der();
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&spki_der[spki_der.len() - 32..]);

        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        // Decoy FIRST (different scheme, a victim's id) — what
        // extract_from_leaf would attribute to.
        let decoy = Ia5String::try_from("hippius-miner:VICTIM".to_string()).unwrap();
        params.subject_alt_names.push(SanType::URI(decoy));
        // Real, key-bound identity SECOND.
        let real =
            Ia5String::try_from(format!("{NODE_URI_SCHEME}{}", hex::encode(node_id))).unwrap();
        params.subject_alt_names.push(SanType::URI(real));
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        let cert = params.self_signed(&kp).unwrap();
        assert_eq!(
            bound_node_id_from_leaf(cert.der()).unwrap_err(),
            IdentityError::MultipleUris
        );
    }

    /// H9 variant: two `hippius-node:` URIs (victim first, own key
    /// second). Even though the own-key URI would match, the ambiguity
    /// guard rejects before any single URI is trusted.
    #[test]
    fn binding_rejects_two_hippius_node_uris() {
        use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, Ia5String, KeyPair, SanType};
        let kp = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let spki_der = kp.public_key_der();
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&spki_der[spki_der.len() - 32..]);

        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let victim = [0x11u8; 32];
        let decoy =
            Ia5String::try_from(format!("{NODE_URI_SCHEME}{}", hex::encode(victim))).unwrap();
        params.subject_alt_names.push(SanType::URI(decoy));
        let real =
            Ia5String::try_from(format!("{NODE_URI_SCHEME}{}", hex::encode(node_id))).unwrap();
        params.subject_alt_names.push(SanType::URI(real));
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        let cert = params.self_signed(&kp).unwrap();
        assert_eq!(
            bound_node_id_from_leaf(cert.der()).unwrap_err(),
            IdentityError::MultipleUris
        );
    }
}
