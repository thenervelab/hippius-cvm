//! Certificate keys and PKCS#10 requests for ACME (CDN plan I4).
//!
//! The certificate key is ECDSA P-256 (spec §8.4), generated in RAM with
//! `ring` and never written anywhere: it leaves the agent only sealed to
//! the fleet key. The request is encoded by hand (a few fixed DER
//! structures) rather than through a CSR crate, so no shared dependency
//! gains a feature (see Cargo.toml).
//!
//! The request has an empty subject and one subjectAltName extension with
//! the order's DNS names; ACME CAs take the names from there.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use zeroize::Zeroizing;

use crate::error::{CdnError, Result};

/// The PEM label (kept out of a literal header so secret scanners do not
/// take the code for a key).
const PKCS8_LABEL: &str = "PRIVATE KEY";
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

/// A fresh certificate key: PKCS#8 DER, wiped on drop.
pub struct CertKey {
    pkcs8: Zeroizing<Vec<u8>>,
    pair: EcdsaKeyPair,
}

impl CertKey {
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| CdnError::Acme("cert-key-generate"))?;
        let pkcs8 = Zeroizing::new(doc.as_ref().to_vec());
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng)
            .map_err(|_| CdnError::Acme("cert-key-load"))?;
        Ok(Self { pkcs8, pair })
    }

    /// The key as a `PRIVATE KEY` PEM: what is sealed to the fleet key and
    /// what OpenResty serves with.
    pub fn pkcs8_pem(&self) -> Zeroizing<String> {
        let b64 = Zeroizing::new(B64.encode(self.pkcs8.as_slice()));
        let mut pem = Zeroizing::new(String::with_capacity(b64.len() + 80));
        pem.push_str(&format!("-----BEGIN {PKCS8_LABEL}-----\n"));
        for line in b64.as_bytes().chunks(64) {
            // Base64 output is ASCII.
            pem.push_str(std::str::from_utf8(line).unwrap_or_default());
            pem.push('\n');
        }
        pem.push_str(&format!("-----END {PKCS8_LABEL}-----\n"));
        pem
    }

    /// The DER SubjectPublicKeyInfo.
    pub fn spki_der(&self) -> Vec<u8> {
        spki(self.pair.public_key().as_ref())
    }

    /// A DER PKCS#10 request for `names`.
    pub fn csr_der(&self, names: &[&str]) -> Result<Vec<u8>> {
        if names.is_empty() {
            return Err(CdnError::Acme("csr-no-names"));
        }
        let mut general_names = Vec::new();
        for n in names {
            if n.is_empty() || !n.is_ascii() {
                return Err(CdnError::Acme("csr-bad-name"));
            }
            // dNSName: [2] IMPLICIT IA5String.
            general_names.extend(tlv(0x82, n.as_bytes()));
        }
        let san = tlv(0x30, &general_names);
        let extension = tlv(
            0x30,
            &[tlv(0x06, OID_SUBJECT_ALT_NAME), tlv(0x04, &san)].concat(),
        );
        let extensions = tlv(0x30, &extension);
        let attribute = tlv(
            0x30,
            &[tlv(0x06, OID_EXTENSION_REQUEST), tlv(0x31, &extensions)].concat(),
        );
        let info = tlv(
            0x30,
            &[
                tlv(0x02, &[0x00]), // version 0
                tlv(0x30, &[]),     // empty subject
                self.spki_der(),
                tlv(0xa0, &attribute), // [0] attributes
            ]
            .concat(),
        );
        let rng = SystemRandom::new();
        let sig = self
            .pair
            .sign(&rng, &info)
            .map_err(|_| CdnError::Acme("csr-sign"))?;
        let mut bits = vec![0x00];
        bits.extend_from_slice(sig.as_ref());
        Ok(tlv(
            0x30,
            &[
                info,
                tlv(0x30, &tlv(0x06, OID_ECDSA_SHA256)),
                tlv(0x03, &bits),
            ]
            .concat(),
        ))
    }
}

/// SubjectPublicKeyInfo of an uncompressed P-256 point.
fn spki(point: &[u8]) -> Vec<u8> {
    let alg = tlv(
        0x30,
        &[tlv(0x06, OID_EC_PUBLIC_KEY), tlv(0x06, OID_PRIME256V1)].concat(),
    );
    let mut bits = vec![0x00];
    bits.extend_from_slice(point);
    tlv(0x30, &[alg, tlv(0x03, &bits)].concat())
}

/// One DER tag-length-value.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
    use x509_parser::certification_request::X509CertificationRequest;
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::FromDer;

    #[test]
    fn lengths_use_the_short_and_long_forms() {
        assert_eq!(tlv(0x04, &[1, 2]), vec![0x04, 2, 1, 2]);
        let long = tlv(0x04, &[0u8; 200]);
        assert_eq!(&long[..3], &[0x04, 0x81, 200]);
        let longer = tlv(0x04, &vec![0u8; 300]);
        assert_eq!(&longer[..4], &[0x04, 0x82, 0x01, 0x2c]);
    }

    #[test]
    fn the_request_parses_names_the_hosts_and_verifies() {
        let key = CertKey::generate().unwrap();
        let der = key
            .csr_der(&["*.cdn.example.test", "www.example.test"])
            .unwrap();
        let (rest, csr) = X509CertificationRequest::from_der(&der).unwrap();
        assert!(rest.is_empty());
        let info = &csr.certification_request_info;
        assert_eq!(info.subject_pki.raw, key.spki_der().as_slice());
        let mut names = Vec::new();
        for ext in csr.requested_extensions().unwrap() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for g in &san.general_names {
                    if let GeneralName::DNSName(d) = g {
                        names.push(d.to_string());
                    }
                }
            }
        }
        assert_eq!(names, vec!["*.cdn.example.test", "www.example.test"]);
        // The signature covers the request info with the certificate key.
        let point = &info.subject_pki.subject_public_key.data;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point.as_ref())
            .verify(info.raw, &csr.signature_value.data)
            .unwrap();
    }

    #[test]
    fn the_pem_reloads_as_the_same_key() {
        let key = CertKey::generate().unwrap();
        let pem = key.pkcs8_pem();
        assert!(pem.starts_with(&format!("-----BEGIN {PKCS8_LABEL}-----\n")));
        let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        assert_eq!(block.contents, key.pkcs8.as_slice());
        let rng = SystemRandom::new();
        let again =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &block.contents, &rng)
                .unwrap();
        assert_eq!(again.public_key().as_ref(), key.pair.public_key().as_ref());
    }

    #[test]
    fn empty_or_non_ascii_names_are_refused() {
        let key = CertKey::generate().unwrap();
        assert!(key.csr_der(&[]).is_err());
        assert!(key.csr_der(&[""]).is_err());
        assert!(key.csr_der(&["bücher.example"]).is_err());
    }
}
