//! Served certificates: unseal and push to OpenResty's shared memory.
//!
//! Each feed certificate is a public chain plus its private key sealed
//! to a fleet key version. The agent opens the key in RAM, checks the
//! chain's leaf against the hostname and the clock, and pushes the whole
//! store as one document over the control socket. The cleartext key is
//! never written to disk, and the serialised document wipes on drop.
//!
//! A certificate that fails (unknown fleet version, tampered blob,
//! expired or mismatched leaf) is skipped and reported by class; the
//! rest of the store still loads.

use std::collections::BTreeMap;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::extensions::GeneralName;
use zeroize::Zeroizing;

use crate::clock::parse_rfc3339;
use crate::error::{CdnError, Result};
use crate::feed::FeedState;
use crate::hostname::san_covers;
use crate::unseal::FleetKeyring;
use crate::wire::SealedCert;

const MAX_KEY_PEM_LEN: usize = 16 * 1024;

/// The built store.
pub struct CertStore {
    /// The JSON document for `PUT /v1/certs`. Contains cleartext keys.
    pub body: Zeroizing<Vec<u8>>,
    pub loaded: usize,
    /// `(hostname_id, class)` of every skipped certificate.
    pub skipped: Vec<(String, &'static str)>,
    /// SHA-256 of the fleet wildcard leaf's SPKI, when it loaded. This
    /// is what the attestation report binds.
    pub default_spki_sha256: Option<[u8; 32]>,
}

#[derive(Serialize)]
struct Entry<'a> {
    chain_pem: &'a str,
    key_pem: &'a str,
    not_after: u64,
}

#[derive(Serialize)]
struct Doc<'a> {
    default: Option<&'a str>,
    certs: BTreeMap<&'a str, Entry<'a>>,
}

struct Opened<'a> {
    cert: &'a SealedCert,
    key_pem: Zeroizing<String>,
    not_after: u64,
    spki_sha256: [u8; 32],
}

/// Build the store from `state` (see module docs).
pub fn build(
    state: &FeedState,
    keyring: &FleetKeyring,
    fleet_wildcard: &str,
    now: u64,
) -> Result<CertStore> {
    let mut opened: BTreeMap<&str, Opened<'_>> = BTreeMap::new();
    let mut skipped = Vec::new();
    for cert in state.certs.values() {
        match open_one(cert, keyring, now) {
            Ok(o) => {
                // Two certificates for one hostname: keep the later expiry.
                let replace = opened
                    .get(cert.hostname.as_str())
                    .is_none_or(|prev| o.not_after > prev.not_after);
                if replace {
                    opened.insert(cert.hostname.as_str(), o);
                }
            }
            Err(e) => skipped.push((cert.hostname_id.clone(), e.class())),
        }
    }

    let default_spki_sha256 = opened.get(fleet_wildcard).map(|o| o.spki_sha256);
    let capacity: usize = opened
        .values()
        .map(|o| o.cert.cert_chain_pem.len() + o.key_pem.len() + o.cert.hostname.len() + 128)
        .sum::<usize>()
        + 64;
    let doc = Doc {
        default: default_spki_sha256.map(|_| fleet_wildcard),
        certs: opened
            .iter()
            .map(|(host, o)| {
                (
                    *host,
                    Entry {
                        chain_pem: &o.cert.cert_chain_pem,
                        key_pem: o.key_pem.as_str(),
                        not_after: o.not_after,
                    },
                )
            })
            .collect(),
    };
    // Pre-size so serialisation does not reallocate and leave copies of
    // key material in freed buffers.
    // JSON escaping grows a PEM by under 2x (newlines); x6 covers any
    // byte escaped as \u00XX.
    let mut body: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(capacity * 6));
    serde_json::to_writer(&mut *body, &doc).map_err(|_| CdnError::Unseal("certstore-encode"))?;
    Ok(CertStore {
        loaded: opened.len(),
        body,
        skipped,
        default_spki_sha256,
    })
}

fn open_one<'a>(cert: &'a SealedCert, keyring: &FleetKeyring, now: u64) -> Result<Opened<'a>> {
    let declared_not_after = parse_rfc3339(&cert.not_after)?;
    let leaf = check_leaf(&cert.cert_chain_pem, &cert.hostname, now)?;
    let leaf_not_after = leaf.not_after;
    if declared_not_after != leaf_not_after {
        return Err(CdnError::Unseal("cert-not-after-mismatch"));
    }
    let plain = keyring.open_b64(cert.fleet_key_version, &cert.sealed_blob_b64)?;
    if plain.len() > MAX_KEY_PEM_LEN {
        return Err(CdnError::Unseal("cert-key-too-large"));
    }
    let key_pem = Zeroizing::new(
        std::str::from_utf8(&plain)
            .map_err(|_| CdnError::Unseal("cert-key-not-pem"))?
            .to_owned(),
    );
    // The key must be the leaf's: otherwise TLS fails for the host, and
    // for the fleet wildcard the attestation would bind a key that never
    // was inside this CVM.
    if key_spki(&key_pem)? != leaf.spki_der {
        return Err(CdnError::Unseal("cert-key-mismatch"));
    }
    Ok(Opened {
        cert,
        key_pem,
        not_after: leaf_not_after,
        spki_sha256: Sha256::digest(&leaf.spki_der).into(),
    })
}

/// The DER SubjectPublicKeyInfo of a PEM private key (PKCS#8, SEC1 or
/// PKCS#1; RSA, ECDSA P-256/P-384 or Ed25519).
fn key_spki(key_pem: &str) -> Result<Vec<u8>> {
    let (_, block) = x509_parser::pem::parse_x509_pem(key_pem.as_bytes())
        .map_err(|_| CdnError::Unseal("cert-key-not-pem"))?;
    let label = block.label.clone();
    let der = Zeroizing::new(block.contents);
    let key = match label.as_str() {
        "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.as_slice())),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der.as_slice())),
        "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der.as_slice())),
        _ => return Err(CdnError::Unseal("cert-key-not-pem")),
    };
    let signer = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|_| CdnError::Unseal("cert-key-unsupported"))?;
    let spki = signer
        .public_key()
        .ok_or(CdnError::Unseal("cert-key-unsupported"))?;
    Ok(spki.as_ref().to_vec())
}

pub(crate) struct Leaf {
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
    pub(crate) spki_der: Vec<u8>,
    /// The leaf's dNSName SANs, lower-cased.
    pub(crate) dns_names: Vec<String>,
}

/// Parse the chain's first certificate, require it valid at `now` and
/// a dNSName SAN covering `hostname`.
pub(crate) fn check_leaf(chain_pem: &str, hostname: &str, now: u64) -> Result<Leaf> {
    let (_, block) = x509_parser::pem::parse_x509_pem(chain_pem.as_bytes())
        .map_err(|_| CdnError::Unseal("cert-chain-pem"))?;
    if block.label != "CERTIFICATE" {
        return Err(CdnError::Unseal("cert-chain-pem"));
    }
    let (_, leaf) = x509_parser::parse_x509_certificate(&block.contents)
        .map_err(|_| CdnError::Unseal("cert-chain-der"))?;
    let not_before = leaf.validity().not_before.timestamp();
    let not_after = u64::try_from(leaf.validity().not_after.timestamp())
        .map_err(|_| CdnError::Unseal("cert-validity"))?;
    if i64::try_from(now).map_or(true, |n| not_before > n) || not_after <= now {
        return Err(CdnError::Unseal("cert-expired"));
    }
    let san = leaf
        .subject_alternative_name()
        .map_err(|_| CdnError::Unseal("cert-san"))?
        .ok_or(CdnError::Unseal("cert-san"))?;
    let covered = san.value.general_names.iter().any(|g| match g {
        GeneralName::DNSName(d) => san_covers(d, hostname),
        _ => false,
    });
    if !covered {
        return Err(CdnError::Unseal("cert-hostname-mismatch"));
    }
    let dns_names = san
        .value
        .general_names
        .iter()
        .filter_map(|g| match g {
            GeneralName::DNSName(d) => Some(d.to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    Ok(Leaf {
        not_before: u64::try_from(not_before).unwrap_or(0),
        not_after,
        spki_der: leaf.public_key().raw.to_vec(),
        dns_names,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;
    use crate::unseal::seal_to;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    /// A P-256 certificate for `names`, its key sealed to `public`.
    pub(crate) fn sealed_cert(
        hostname_id: &str,
        hostname: &str,
        names: &[&str],
        public: &[u8; 32],
        version: u32,
        days: i64,
    ) -> SealedCert {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params =
            rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        let now = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .unwrap();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(days);
        let not_after = crate::clock::format_rfc3339(
            u64::try_from(params.not_after.unix_timestamp()).unwrap_or(0),
        );
        let cert = params.self_signed(&kp).unwrap();
        SealedCert {
            hostname_id: hostname_id.into(),
            hostname: hostname.into(),
            cert_chain_pem: cert.pem(),
            fleet_key_version: version,
            sealed_blob_b64: B64.encode(seal_to(public, kp.serialize_pem().as_bytes()).unwrap()),
            not_after,
        }
    }

    /// A feed certificate from an issued chain and its key PEM, sealed to
    /// the test fleet key 1 (the issuer tests' keyring).
    pub(crate) fn sealed_from(
        chain: &str,
        key_pem: &[u8],
        hostname_id: &str,
        hostname: &str,
    ) -> SealedCert {
        let (_, block) = x509_parser::pem::parse_x509_pem(chain.as_bytes()).unwrap();
        let (_, leaf) = x509_parser::parse_x509_certificate(&block.contents).unwrap();
        let not_after = crate::clock::format_rfc3339(
            u64::try_from(leaf.validity().not_after.timestamp()).unwrap(),
        );
        let public = FleetKeyring::from_secrets([(1, [9u8; 32])])
            .public_key(1)
            .unwrap();
        SealedCert {
            hostname_id: hostname_id.into(),
            hostname: hostname.into(),
            cert_chain_pem: chain.into(),
            fleet_key_version: 1,
            sealed_blob_b64: B64.encode(seal_to(&public, key_pem).unwrap()),
            not_after,
        }
    }

    fn state_with(certs: Vec<SealedCert>) -> FeedState {
        let mut s = FeedState::default();
        for c in certs {
            s.certs.insert(c.hostname_id.clone(), c);
        }
        s
    }

    #[test]
    fn loads_good_certs_and_skips_bad_ones() {
        let ring = FleetKeyring::from_secrets([(1, [9u8; 32])]);
        let pk = ring.public_key(1).unwrap();
        let other = FleetKeyring::from_secrets([(1, [8u8; 32])])
            .public_key(1)
            .unwrap();
        let mut swapped = sealed_cert("h7", "f.example.com", &["f.example.com"], &pk, 1, 30);
        swapped.sealed_blob_b64 =
            sealed_cert("hx", "f.example.com", &["f.example.com"], &pk, 1, 30).sealed_blob_b64;
        let mut tampered = sealed_cert("h5", "t.example.com", &["t.example.com"], &pk, 1, 30);
        tampered.not_after = "2099-01-01T00:00:00Z".into();
        let state = state_with(vec![
            sealed_cert(
                "fleet",
                "*.cdn.hippius.com",
                &["*.cdn.hippius.com"],
                &pk,
                1,
                30,
            ),
            sealed_cert("h1", "img.example.com", &["*.example.com"], &pk, 1, 30),
            sealed_cert("h2", "a.example.com", &["b.example.com"], &pk, 1, 30),
            sealed_cert("h3", "c.example.com", &["c.example.com"], &other, 1, 30),
            sealed_cert("h4", "d.example.com", &["d.example.com"], &pk, 2, 30),
            sealed_cert("h6", "e.example.com", &["e.example.com"], &pk, 1, -1),
            tampered,
            swapped,
        ]);
        let store = build(&state, &ring, "*.cdn.hippius.com", crate::clock::unix_now()).unwrap();
        assert_eq!(store.loaded, 2);
        let mut skipped = store.skipped.clone();
        skipped.sort();
        assert_eq!(
            skipped,
            vec![
                ("h2".to_string(), "cert-hostname-mismatch"),
                ("h3".to_string(), "open-failed"),
                ("h4".to_string(), "fleet-version-not-held"),
                ("h5".to_string(), "cert-not-after-mismatch"),
                ("h6".to_string(), "cert-expired"),
                ("h7".to_string(), "cert-key-mismatch"),
            ]
        );
        assert!(store.default_spki_sha256.is_some());
        let doc: serde_json::Value = serde_json::from_slice(&store.body).unwrap();
        assert_eq!(doc["default"], "*.cdn.hippius.com");
        assert!(doc["certs"]["img.example.com"]["key_pem"]
            .as_str()
            .unwrap()
            .contains("PRIVATE KEY"));
        assert!(doc["certs"].get("a.example.com").is_none());
    }

    #[test]
    fn no_wildcard_means_no_default() {
        let ring = FleetKeyring::from_secrets([(1, [9u8; 32])]);
        let pk = ring.public_key(1).unwrap();
        let state = state_with(vec![sealed_cert(
            "h1",
            "x.example.com",
            &["x.example.com"],
            &pk,
            1,
            30,
        )]);
        let store = build(&state, &ring, "*.cdn.hippius.com", crate::clock::unix_now()).unwrap();
        assert!(store.default_spki_sha256.is_none());
        let doc: serde_json::Value = serde_json::from_slice(&store.body).unwrap();
        assert!(doc["default"].is_null());
    }
}
