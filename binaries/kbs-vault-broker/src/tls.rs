//! DEV-ONLY insecure TLS config for the Vault client.
//!
//! Mirrors `binaries/kbs-server/src/vault_mvp.rs::dev_insecure_tls_config`
//! — accepts ANY server certificate so the broker can talk to the
//! self-signed dev Tier-0 Vault without baking its CA. Gated behind
//! `vault.dev_skip_tls_verify` + the fail-closed `dev_environment` +
//! non-public-endpoint refusal in `config::Config::validate` (audit H7).
//! Production mounts the real Vault CA and leaves the flag off.

/// Build a rustls `ClientConfig` that accepts every server cert.
/// DEV-ONLY (see module docs).
pub fn dev_insecure_tls_config() -> ureq::rustls::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use ureq::rustls;

    #[derive(Debug)]
    struct AcceptAnyCert;

    impl ServerCertVerifier for AcceptAnyCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyCert))
        .with_no_client_auth()
}

/// Production TLS: a rustls `ClientConfig` that pins EXACTLY the
/// certificate(s) in `ca_pem` (the operator-mounted Vault cert).
///
/// The Tier-0 Vault presents a self-signed cert marked `CA:TRUE` as
/// its TLS leaf. rustls/webpki strictly refuse a CA cert as an
/// end-entity (`CaUsedAsEndEntity`), so the normal `with_root_certificates`
/// path can't verify it. Instead we pin the exact cert: the presented
/// leaf DER must byte-equal a mounted cert, AND the handshake
/// signature is verified for real against that cert's key (the
/// `verify_tls1*_signature` hooks call rustls's crypto provider, NOT
/// an accept-all). An attacker replaying the public cert without the
/// Vault private key fails the signature check. This is exactly
/// certificate pinning of a self-signed endpoint.
pub fn ca_pinned_tls_config(ca_pem: &[u8]) -> Result<ureq::rustls::ClientConfig, String> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use std::sync::Arc;
    use ureq::rustls;

    let pinned: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(ca_pem))
            .map(|r| r.map(|d| d.into_owned()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| format!("Vault CA PEM parse: {e}"))?;
    if pinned.is_empty() {
        return Err("Vault CA bundle contained no certificates".to_string());
    }
    // ureq does not install a PROCESS-default CryptoProvider; it uses
    // its compiled-in `ring` provider (the same one `builder()` below
    // selects). Use it directly for the verifier's signature checks so
    // the algorithms match the config's provider.
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    #[derive(Debug)]
    struct PinnedVerifier {
        pinned: Vec<CertificateDer<'static>>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    }
    impl ServerCertVerifier for PinnedVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            if self
                .pinned
                .iter()
                .any(|c| c.as_ref() == end_entity.as_ref())
            {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General(
                    "server cert does not match the pinned Vault cert".into(),
                ))
            }
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
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
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pinned, provider }))
        .with_no_client_auth())
}
