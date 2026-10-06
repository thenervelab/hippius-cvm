//! A validated SPIFFE ID — the only shape an admin client identity may
//! take.
//!
//! The admin listener authorizes a peer by the URI SANs of its
//! CA-verified leaf, compared exactly against an allowlist of these.
//! Parsing the allowlist entries strictly (per the SPIFFE ID spec) is
//! what makes the comparison meaningful: a config entry that is really a
//! DNS name or a CN (`vali`, `vali.hippius.svc`) can never be written, so
//! no URI SAN can ever be matched against a non-URI identity.
//!
//! The grammar also guarantees the audit encoding is unambiguous: a
//! SPIFFE ID can contain neither `,` nor whitespace, so the
//! comma-joined list [`crate::PeerCertInfo::audit_identity`] writes into
//! `peer_san` splits back into exactly the IDs that were authorized.

use serde::{Deserialize, Serialize};

/// `spiffe://` — lowercase only; the scheme is case-sensitive here on
/// purpose (the comparison against URI SANs is exact).
const SCHEME: &str = "spiffe://";

/// SPIFFE ID spec §2.3: a SPIFFE ID is at most 2048 bytes.
const MAX_LEN: usize = 2048;

/// SPIFFE ID spec §2.1: a trust domain is at most 255 bytes.
const MAX_TRUST_DOMAIN_LEN: usize = 255;

/// Why a string is not a SPIFFE ID. Every `Display` is a fixed token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SpiffeIdError {
    /// Does not start with the (lowercase) `spiffe://` scheme.
    #[error("spiffe-id: scheme must be spiffe://")]
    Scheme,
    /// Longer than 2048 bytes, or a trust domain longer than 255.
    #[error("spiffe-id: too long")]
    TooLong,
    /// Empty trust domain, or one with a character outside `[a-z0-9._-]`
    /// (this also excludes userinfo, ports and uppercase).
    #[error("spiffe-id: invalid trust domain")]
    TrustDomain,
    /// An empty segment (`//`, trailing `/`), a `.`/`..` segment, or a
    /// character outside `[A-Za-z0-9._-]` (this also excludes query,
    /// fragment, percent-encoding, `,` and whitespace).
    #[error("spiffe-id: invalid path")]
    Path,
}

/// A SPIFFE ID (`spiffe://<trust-domain>[/<segment>...]`), validated on
/// construction. Ordered by its string so a list of them sorts
/// deterministically for the audit row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SpiffeId(String);

impl SpiffeId {
    /// Parse `s` strictly. No normalisation: `s` must already be the
    /// canonical form, because the admin gate compares it byte-for-byte
    /// with a certificate's URI SAN.
    pub fn parse(s: &str) -> Result<Self, SpiffeIdError> {
        if s.len() > MAX_LEN {
            return Err(SpiffeIdError::TooLong);
        }
        let rest = s.strip_prefix(SCHEME).ok_or(SpiffeIdError::Scheme)?;
        let (trust_domain, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        if trust_domain.len() > MAX_TRUST_DOMAIN_LEN {
            return Err(SpiffeIdError::TooLong);
        }
        if trust_domain.is_empty() || !trust_domain.bytes().all(is_trust_domain_byte) {
            return Err(SpiffeIdError::TrustDomain);
        }
        if !path.is_empty() {
            // `path` starts with '/', so the first split item is "".
            for segment in path.split('/').skip(1) {
                if segment.is_empty()
                    || segment == "."
                    || segment == ".."
                    || !segment.bytes().all(is_path_byte)
                {
                    return Err(SpiffeIdError::Path);
                }
            }
        }
        Ok(Self(s.to_string()))
    }

    /// The canonical string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_trust_domain_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
}

fn is_path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
}

impl TryFrom<String> for SpiffeId {
    type Error = SpiffeIdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<SpiffeId> for String {
    fn from(id: SpiffeId) -> Self {
        id.0
    }
}

impl std::fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_ids() {
        for ok in [
            "spiffe://hippius.network/vali",
            "spiffe://hippius.network/operator",
            "spiffe://hippius.network",
            "spiffe://td-1_x.y/a/B.c-d_e",
        ] {
            assert_eq!(SpiffeId::parse(ok).unwrap().as_str(), ok);
        }
    }

    #[test]
    fn rejects_every_non_spiffe_shape_with_its_reason() {
        use SpiffeIdError::*;
        for (bad, why) in [
            ("", Scheme),
            ("vali", Scheme),
            ("vali.hippius.svc", Scheme),
            ("https://hippius.network/vali", Scheme),
            ("SPIFFE://hippius.network/vali", Scheme),
            (" spiffe://hippius.network/vali", Scheme),
            ("spiffe:/hippius.network/vali", Scheme),
            ("spiffe://", TrustDomain),
            ("spiffe:///vali", TrustDomain),
            ("spiffe://Hippius.network/vali", TrustDomain),
            ("spiffe://user@hippius.network/vali", TrustDomain),
            ("spiffe://hippius.network:443/vali", TrustDomain),
            ("spiffe://hippius.network/vali/", Path),
            ("spiffe://hippius.network//vali", Path),
            ("spiffe://hippius.network/./vali", Path),
            ("spiffe://hippius.network/../vali", Path),
            ("spiffe://hippius.network/vali?x=1", Path),
            ("spiffe://hippius.network/vali#f", Path),
            ("spiffe://hippius.network/va%6Ci", Path),
            (
                "spiffe://hippius.network/vali,spiffe://hippius.network/x",
                Path,
            ),
            ("spiffe://hippius.network/vali ", Path),
        ] {
            assert_eq!(SpiffeId::parse(bad), Err(why), "{bad:?}");
        }
    }

    #[test]
    fn enforces_the_spec_length_limits() {
        let long_td = format!("spiffe://{}/vali", "a".repeat(256));
        assert_eq!(SpiffeId::parse(&long_td), Err(SpiffeIdError::TooLong));
        let ok_td = format!("spiffe://{}/vali", "a".repeat(255));
        assert!(SpiffeId::parse(&ok_td).is_ok());
        let long = format!("spiffe://hippius.network/{}", "a".repeat(MAX_LEN));
        assert_eq!(SpiffeId::parse(&long), Err(SpiffeIdError::TooLong));
    }

    #[test]
    fn deserialization_goes_through_the_parser() {
        let ok: SpiffeId = serde_json::from_str("\"spiffe://hippius.network/vali\"").unwrap();
        assert_eq!(ok.as_str(), "spiffe://hippius.network/vali");
        assert!(serde_json::from_str::<SpiffeId>("\"vali.hippius.svc\"").is_err());
    }
}
