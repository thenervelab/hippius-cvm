//! Extension points for the later CDN PRs.
//!
//! - **I4 (ACME)** is [`crate::issuer::Issuer`], driven from the feed
//!   loop one exchange at a time.
//! - **I5 (log shipping)** implements [`FeedListener`] for the zones'
//!   opt-in log settings and taps request records through
//!   [`RecordSink`].
//! - **I6 (HTTP origins)** replaces [`S3OnlyPolicy`] with an
//!   [`OriginPolicy`] that admits `http`/`https` origins behind the SSRF
//!   guard.

use crate::counters::RequestRecord;
use crate::feed::FeedState;
use crate::unseal::FleetKeyring;
use crate::wire::Origin;

/// Decides whether a zone's origin may be served. A refused zone is
/// pushed to OpenResty with `serving = false` and the refusal class, so
/// it answers without contacting anything.
pub trait OriginPolicy: Send + Sync {
    fn admit(&self, origin: &Origin) -> std::result::Result<(), &'static str>;
}

/// The private-beta policy: Hippius S3 only (spec §16 decision 4).
///
/// The S3 endpoint is not taken from the feed: OpenResty signs to the
/// endpoint baked into the measured image, so a feed entry cannot point a
/// node at an arbitrary host. Only `bucket`, `prefix` and `region` are
/// accepted.
#[derive(Debug, Default, Clone, Copy)]
pub struct S3OnlyPolicy;

impl OriginPolicy for S3OnlyPolicy {
    fn admit(&self, origin: &Origin) -> std::result::Result<(), &'static str> {
        if origin.kind != "s3" {
            return Err("origin-kind-not-supported");
        }
        for (k, v) in &origin.params {
            match (k.as_str(), v.as_str()) {
                ("bucket", Some(b)) if is_valid_bucket(b) => {}
                ("prefix", Some(p)) if is_valid_prefix(p) => {}
                ("region", Some(r))
                    if r.len() <= 32
                        && r.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') => {}
                _ => return Err("s3-origin-param-invalid"),
            }
        }
        if !origin.params.contains_key("bucket") {
            return Err("s3-origin-no-bucket");
        }
        Ok(())
    }
}

/// An object-key prefix: relative, no `..` segment, and none of the
/// characters that would change the request URL OpenResty builds
/// (`?`, `#`, `%`, `\\`).
fn is_valid_prefix(p: &str) -> bool {
    p.len() <= 1024
        && !p.starts_with('/')
        // Directory-aligned: "site" would also reach "site-private/...".
        && (p.is_empty() || p.ends_with('/'))
        && p.bytes()
            .all(|c| c.is_ascii_graphic() && !b"?#%\\".contains(&c))
        && !p.split('/').any(|seg| seg == ".." || seg == ".")
}

/// S3 bucket naming: 3-63 chars of lower-case letters, digits, `-`, `.`,
/// starting and ending alphanumeric.
fn is_valid_bucket(b: &str) -> bool {
    (3..=63).contains(&b.len())
        && b.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
        && b.bytes().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && b.bytes().last().is_some_and(|c| c.is_ascii_alphanumeric())
}

/// Called on the feed thread after a revision is applied and pushed.
/// Implementations must not block for long: the feed long-poll waits.
pub trait FeedListener: Send {
    fn on_applied(&mut self, state: &FeedState, keyring: &FleetKeyring);
}

/// Receives every metering record after it is counted.
pub trait RecordSink: Send + Sync {
    fn on_record(&self, record: &RequestRecord);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn origin(v: serde_json::Value) -> Origin {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn s3_only() {
        let p = S3OnlyPolicy;
        assert!(p
            .admit(&origin(
                serde_json::json!({"type": "s3", "bucket": "media", "prefix": "a/"})
            ))
            .is_ok());
        let refused = [
            (
                serde_json::json!({"type": "http", "host": "example.com"}),
                "origin-kind-not-supported",
            ),
            (serde_json::json!({"type": "s3"}), "s3-origin-no-bucket"),
            (
                serde_json::json!({"type": "s3", "bucket": "Media"}),
                "s3-origin-param-invalid",
            ),
            (
                serde_json::json!({"type": "s3", "bucket": "ok-bucket", "endpoint": "http://169.254.169.254"}),
                "s3-origin-param-invalid",
            ),
            (
                serde_json::json!({"type": "s3", "bucket": 7}),
                "s3-origin-param-invalid",
            ),
            (
                serde_json::json!({"type": "s3", "bucket": "media", "prefix": "../other/"}),
                "s3-origin-param-invalid",
            ),
            (
                serde_json::json!({"type": "s3", "bucket": "media", "prefix": "a/?x=1"}),
                "s3-origin-param-invalid",
            ),
            (
                serde_json::json!({"type": "s3", "bucket": "media", "prefix": "/abs/"}),
                "s3-origin-param-invalid",
            ),
            (
                serde_json::json!({"type": "s3", "bucket": "media", "prefix": "site"}),
                "s3-origin-param-invalid",
            ),
            (
                serde_json::json!({"type": "s3", "bucket": "media", "prefix": "a/%2e%2e/"}),
                "s3-origin-param-invalid",
            ),
        ];
        for (v, want) in refused {
            assert_eq!(p.admit(&origin(v)).unwrap_err(), want);
        }
    }
}
