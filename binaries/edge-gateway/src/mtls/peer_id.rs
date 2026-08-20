//! `PeerId` — the rate-limit + audit key, derived from the peer's
//! mTLS leaf certificate.
//!
//! PR-H3 keyed every per-source counter on the raw socket
//! [`std::net::IpAddr`]. Codex review of PR-H3 v2 flagged the obvious
//! NAT gap: a NetBird peer behind CGNAT shares an apparent source IP
//! with every other peer on the same exit node, so "one bad peer
//! gets the whole NAT range rate-limited" is the unintended outcome.
//! PR-H4 switches the key to the **cryptographic identity** the peer
//! presented at handshake — extracted from the leaf cert via
//! [`extract_from_leaf`].
//!
//! ## Extraction order (most specific → least)
//!
//! 1. `subjectAltName: URI` — the spec'd identity carrier. Operators
//!    that mint per-miner certs the §17.7 way set
//!    `URI:hippius-miner:<peer-uuid>` in the SAN.
//! 2. `subjectAltName: DNS` — for the legacy "DNS name = peer name"
//!    pattern (the §H Ansible playbook uses this as a fallback while
//!    the URI scheme rolls out).
//! 3. `Subject CN` — last-ditch fallback for any cert that lacks SAN
//!    entries. CN is deprecated for hostname matching but is still
//!    a stable identity for opaque relays (the KBS / Vali never
//!    consume `PeerId` content; only Edge does, only as a HashMap
//!    key).
//!
//! ## What `PeerId` is NOT
//!
//! - **Not the cert fingerprint.** Switching key material on rotation
//!   (§B Q11: 90-day cadence) would otherwise reset the rate-limit
//!   bucket every 90 days for every peer. The SAN URI / DNS name is
//!   stable across rotation; the fingerprint is not.
//! - **Not the IP.** The whole point of the move.
//! - **Not user-controlled plaintext from the body.** §5.6 opacity
//!   forbids reading routing/identity info from the wire body; the
//!   only on-wire input here is the X.509 leaf the CA already
//!   issued, which Edge has already validated via
//!   [`crate::mtls::cert_store`] before we get to extraction.

use std::sync::Arc;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::OID_X509_COMMON_NAME;
use x509_parser::prelude::*;

/// Stable per-peer identity for rate-limit + audit attribution.
///
/// Constructed only by [`PeerId::new`] (test mocks + main-loop
/// fallback) or [`extract_from_leaf`] (the mTLS production path).
/// `Arc<str>` so cloning is a single refcount bump — the rate-limit
/// hot path calls `.clone()` on every `try_acquire` insert.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PeerId(Arc<str>);

impl PeerId {
    /// Build a `PeerId` from a borrowed string. The only call sites
    /// are (a) unit tests that mock a peer identity without going
    /// through a real handshake, and (b) the
    /// [`extract_from_leaf`] extractor below. Production code that
    /// has a `&CertificateDer` MUST go through `extract_from_leaf` —
    /// constructing one from arbitrary bytes would defeat the
    /// CA-issued-only invariant.
    ///
    /// Named `new` rather than `from_str` to avoid colliding with
    /// `std::str::FromStr::from_str` (clippy::should_implement_trait):
    /// `PeerId` can't return `Result` so the trait shape would lie
    /// about the failure mode.
    pub fn new(s: &str) -> Self {
        Self(Arc::from(s))
    }

    /// Borrow the underlying string. Stable for the `Display` impl +
    /// audit log emission; the runtime cost is one pointer read.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for PeerId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Static-classifier error from [`extract_from_leaf`]. Same
/// `&'static str`-only `Display` discipline as `EdgeError` — the
/// inner variant tag is the only thing the audit sink ever sees.
#[derive(Debug, thiserror::Error)]
pub enum PeerIdError {
    /// Leaf DER did not parse as an X.509 certificate. In production
    /// rustls would have rejected the handshake before we got here;
    /// this is the belt-and-braces second check.
    #[error("peer-id-cert-parse")]
    CertParse,
    /// No SAN URI, no SAN DNS, no Subject CN. The cert is structurally
    /// valid but lacks any identity carrier — the operator that
    /// minted it skipped both the SAN and a CN. Fail-closed: refuse
    /// the connection rather than rate-limit-keying on the empty
    /// string (which would collapse all such peers into one bucket).
    #[error("peer-id-missing")]
    Missing,
}

/// Extract the per-peer identity from the **already-CA-validated**
/// leaf certificate. The caller (rustls handshake completion in
/// [`crate::mtls::cert_store`]) guarantees the cert chains back to
/// the configured CA — extraction here is identity reading, not
/// trust establishment.
pub fn extract_from_leaf(leaf_der: &[u8]) -> Result<PeerId, PeerIdError> {
    let (_, parsed) = X509Certificate::from_der(leaf_der).map_err(|_| PeerIdError::CertParse)?;

    // (1) SAN URI — the canonical identity carrier per the §17.7
    //     Ansible playbook.
    if let Ok(Some(san)) = parsed.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::URI(uri) = name {
                return Ok(PeerId::new(uri));
            }
        }
        // (2) SAN DNS — legacy fallback.
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                return Ok(PeerId::new(dns));
            }
        }
    }

    // (3) Subject CN — last-ditch.
    for attr in parsed.subject().iter_attributes() {
        if attr.attr_type() == &OID_X509_COMMON_NAME {
            if let Ok(s) = attr.attr_value().as_str() {
                if !s.is_empty() {
                    return Ok(PeerId::new(s));
                }
            }
        }
    }

    Err(PeerIdError::Missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_roundtrips() {
        let p = PeerId::new("hippius-miner:abc");
        assert_eq!(p.as_str(), "hippius-miner:abc");
        assert_eq!(p.to_string(), "hippius-miner:abc");
    }

    #[test]
    fn equality_and_hash() {
        // Pins the HashMap-key contract: two `from_str`-built PeerIds
        // with the same content compare equal and hash equal, so the
        // rate-limit bucket map looks up correctly across `.clone()`.
        use std::collections::HashMap;
        let a = PeerId::new("peer-1");
        let b = PeerId::new("peer-1");
        assert_eq!(a, b);
        let mut m: HashMap<PeerId, u32> = HashMap::new();
        m.insert(a, 7);
        assert_eq!(m.get(&b).copied(), Some(7));
    }

    #[test]
    fn extract_from_bogus_bytes_fails_parse() {
        let err = extract_from_leaf(b"not-a-cert").unwrap_err();
        assert!(matches!(err, PeerIdError::CertParse));
        // Static-classifier display contract.
        assert_eq!(err.to_string(), "peer-id-cert-parse");
    }

    #[test]
    fn peer_id_error_display_is_static() {
        // The `Display` is the audit classifier — any future variant
        // that interpolates user data via `{0}` would break the
        // `&'static str`-only invariant.
        assert_eq!(PeerIdError::CertParse.to_string(), "peer-id-cert-parse");
        assert_eq!(PeerIdError::Missing.to_string(), "peer-id-missing");
    }
}
