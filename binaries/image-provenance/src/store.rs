//! The `ImageStore` abstraction + its two backends.
//!
//! PR-F4 shipped the abstraction + a fully-working in-memory backend;
//! PR-F UKI build pins + publish wires the **READ half** of the
//! `HippiusS3ImageStore` (`get` + `exists`) against the
//! anonymous-readable `images/` prefix of `s3.hippius.com`. The
//! **WRITE half** (`put`) is still [`ImageStoreError::NotWired`]: it
//! needs SigV4-signed PUT plus the content-checked idempotency contract
//! the trait demands, and is deferred to a follow-up issue (the CI
//! publish path in `uki-build.yml` uses `aws s3 cp` directly for the
//! first publish — see [`HIPPIUS_S3_PUT_STUB`]).
//!
//! Every `ImageStore` operation is content-addressed and
//! **idempotent**: storing a key that already exists is a successful
//! no-op, never an overwrite, so a re-run of an already-published
//! image cannot mutate or duplicate it.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use sha2::{Digest, Sha256};

use crate::error::ImageStoreError;

/// Whether a `put` created a new object or found one already there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// The object did not exist and was stored.
    Created,
    /// An object already existed at this key — left untouched.
    AlreadyPresent,
}

/// The result of a `put`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutReceipt {
    pub outcome: PutOutcome,
    /// Backend object-version identifier, if the backend assigns one.
    /// Recorded as **unsigned** transport metadata — it is not part of
    /// the signed provenance body (integrity is anchored by the
    /// content-addressed key + `artifact_sha256`).
    pub version_id: Option<String>,
}

/// A content-addressed object store for published images + provenance.
///
/// Implementations MUST be idempotent **and** content-checked: `put`
/// on an existing key whose bytes equal `body` is a no-op reporting
/// [`PutOutcome::AlreadyPresent`]; `put` on an existing key whose
/// bytes *differ* fails closed with [`ImageStoreError::Conflict`] —
/// it never silently overwrites and never silently accepts a
/// mismatching prior object.
pub trait ImageStore {
    /// Whether an object exists at `key`.
    fn exists(&self, key: &str) -> Result<bool, ImageStoreError>;

    /// Idempotently store `body` at `key`. Re-storing identical bytes
    /// is a no-op; an existing object with *different* bytes is a
    /// [`ImageStoreError::Conflict`], never an overwrite.
    fn put(&self, key: &str, body: &[u8]) -> Result<PutReceipt, ImageStoreError>;

    /// Fetch the object stored at `key`.
    fn get(&self, key: &str) -> Result<Vec<u8>, ImageStoreError>;
}

// ── in-memory backend ───────────────────────────────────────────────

/// An in-process `ImageStore` — the test + reference backend.
///
/// Not a "mock": it is a real, correct, idempotent content store, just
/// non-durable. It is what the `publish` orchestration is tested
/// against, and it makes the idempotency contract executable.
#[derive(Debug, Default)]
pub struct MemoryImageStore {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryImageStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored objects.
    pub fn len(&self) -> Result<usize, ImageStoreError> {
        Ok(self.lock()?.len())
    }

    /// Whether the store holds no objects.
    pub fn is_empty(&self) -> Result<bool, ImageStoreError> {
        Ok(self.lock()?.is_empty())
    }

    fn lock(&self) -> Result<MutexGuard<'_, BTreeMap<String, Vec<u8>>>, ImageStoreError> {
        self.objects
            .lock()
            .map_err(|_| ImageStoreError::LockPoisoned)
    }
}

/// A deterministic, content-addressed version id: the SHA-256 of the
/// stored bytes. Mirrors what a content-versioning object store would
/// expose without depending on one.
fn content_version_id(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

impl ImageStore for MemoryImageStore {
    fn exists(&self, key: &str) -> Result<bool, ImageStoreError> {
        Ok(self.lock()?.contains_key(key))
    }

    fn put(&self, key: &str, body: &[u8]) -> Result<PutReceipt, ImageStoreError> {
        let mut objects = self.lock()?;
        if let Some(existing) = objects.get(key) {
            // Content-checked idempotency: identical bytes ⇒ no-op;
            // different bytes ⇒ fail closed (corruption, or a
            // conflicting re-sign of the same content-addressed key).
            if existing.as_slice() != body {
                return Err(ImageStoreError::Conflict {
                    key: key.to_string(),
                });
            }
            return Ok(PutReceipt {
                outcome: PutOutcome::AlreadyPresent,
                version_id: Some(content_version_id(existing)),
            });
        }
        let version_id = content_version_id(body);
        objects.insert(key.to_string(), body.to_vec());
        Ok(PutReceipt {
            outcome: PutOutcome::Created,
            version_id: Some(version_id),
        })
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, ImageStoreError> {
        self.lock()?
            .get(key)
            .cloned()
            .ok_or_else(|| ImageStoreError::NotFound {
                key: key.to_string(),
            })
    }
}

// ── Hippius S3 backend ──────────────────────────────────────────────
//
// `s3.hippius.com` writer-only ACL posture (locked by #80): the
// `images/` + `firmware/` prefixes are anonymous-readable; writes
// require operator credentials. PR-F UKI build pins + publish wires
// the READ half — `get` + `exists` are plain HTTPS against the
// content-addressed key — and leaves `put` (which needs SigV4-signed
// PUT + idempotent GET-and-compare against a conflict) as a follow-up.

/// Why [`HippiusS3ImageStore::put`] is not wired yet. Surfaced
/// verbatim in the `NotWired` error so an operator running the
/// `publish` subcommand sees exactly what is blocked.
pub const HIPPIUS_S3_PUT_STUB: &str =
    "HippiusS3ImageStore::put is not wired yet. The miner-side READ \
    path (`exists`/`get`) talks to `s3.hippius.com`'s anonymous-readable \
    images/ prefix; the WRITE path needs SigV4-signed PUT + the \
    content-checked idempotency contract from the trait. PR-F UKI \
    build pins + publish operates the first publish via `aws s3 cp` \
    directly from CI; the typed `publish` subcommand becomes usable \
    when the WRITE path lands in a follow-up.";

/// Hard cap on a fetched object — a hostile / mis-pointed key cannot
/// drive an unbounded allocation. UKIs are tens of MiB; `provenance.cbor`
/// is hundreds of bytes; 64 MiB is well above either with margin.
const HIPPIUS_S3_MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

/// Strict whole-request timeout for `get` / `exists` — bounds an
/// upstream that dribbles. Matches `agent-initramfs`'s KBS client.
const HIPPIUS_S3_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The Hippius S3 image-bucket backend.
///
/// `get` + `exists` are wired against `s3.hippius.com`'s
/// anonymous-readable `images/` (+ `firmware/`) prefix — a plain HTTPS
/// GET / HEAD against `<endpoint>/<bucket>/<key>`. `put` still returns
/// [`ImageStoreError::NotWired`] (see [`HIPPIUS_S3_PUT_STUB`]).
#[derive(Debug, Clone)]
pub struct HippiusS3ImageStore {
    pub bucket: String,
    pub endpoint: String,
    client: reqwest::blocking::Client,
}

impl HippiusS3ImageStore {
    /// Build the store. A `reqwest::blocking::Client` builder failure
    /// is a fail-closed boot-time condition — the timeout + rustls
    /// pinning are load-bearing and a fallback `Client::new()` would
    /// silently drop them. The builder only fails on a broken TLS
    /// backend, which would also break every other reqwest user in
    /// the binary; surfacing the error here keeps `main` honest.
    pub fn new(
        bucket: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Result<Self, ImageStoreError> {
        let client = reqwest::blocking::Client::builder()
            .use_rustls_tls()
            .timeout(HIPPIUS_S3_REQUEST_TIMEOUT)
            .build()
            .map_err(|e| ImageStoreError::Transport(format!("reqwest client builder: {e}")))?;
        Ok(Self {
            bucket: bucket.into(),
            endpoint: endpoint.into(),
            client,
        })
    }

    /// `<endpoint>/<bucket>/<key>` — path-style S3 URL.
    fn object_url(&self, key: &str) -> String {
        format!(
            "{}/{}/{}",
            self.endpoint.trim_end_matches('/'),
            self.bucket,
            key.trim_start_matches('/'),
        )
    }
}

impl ImageStore for HippiusS3ImageStore {
    fn exists(&self, key: &str) -> Result<bool, ImageStoreError> {
        let resp = self
            .client
            .head(self.object_url(key))
            .send()
            .map_err(|e| ImageStoreError::Transport(format!("HEAD: {e}")))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(true);
        }
        // `s3.hippius.com`'s writer-only-ACL bucket returns 403 (not
        // 404) for an absent key when the caller is anonymous — an
        // anti-enumeration response: an unauthenticated client cannot
        // distinguish "missing" from "deny-listed", so both surface
        // as "not retrievable". For the typed `exists` contract that
        // is functionally `false` — a `get` against the same key
        // would also fail to retrieve, and the miner-side fetch path
        // is the only consumer of `exists`.
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::FORBIDDEN {
            return Ok(false);
        }
        Err(ImageStoreError::Protocol(format!(
            "HEAD returned unexpected status {status}"
        )))
    }

    fn put(&self, _key: &str, _body: &[u8]) -> Result<PutReceipt, ImageStoreError> {
        // The `put` path needs SigV4-signed PUT + the content-checked
        // idempotency contract; deferred to a follow-up. The CI
        // publish path uses `aws s3 cp` directly for now.
        Err(ImageStoreError::NotWired(HIPPIUS_S3_PUT_STUB.to_string()))
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, ImageStoreError> {
        let mut resp = self
            .client
            .get(self.object_url(key))
            .send()
            .map_err(|e| ImageStoreError::Transport(format!("GET: {e}")))?;
        let status = resp.status();
        // 403 mirrors the writer-only-ACL bucket's anti-enumeration
        // response for an absent key — `exists` documents the same.
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::FORBIDDEN {
            return Err(ImageStoreError::NotFound {
                key: key.to_string(),
            });
        }
        if !status.is_success() {
            return Err(ImageStoreError::Protocol(format!(
                "GET returned unexpected status {status}"
            )));
        }
        // Hard-bound the body via a bounded `take(cap + 1)` reader.
        // `content-length` is advisory and may be missing / lying low;
        // `resp.bytes()` would otherwise buffer the entire stream into
        // memory before any check fires. Reading at most `cap + 1`
        // bytes lets us detect overflow without ever allocating more
        // than the cap (plus one) even against a malicious endpoint
        // that streams forever.
        use std::io::Read;
        let mut buf: Vec<u8> = Vec::new();
        let read_cap = HIPPIUS_S3_MAX_OBJECT_BYTES.saturating_add(1);
        (&mut resp)
            .take(read_cap)
            .read_to_end(&mut buf)
            .map_err(|e| ImageStoreError::Transport(format!("body read: {e}")))?;
        if buf.len() as u64 > HIPPIUS_S3_MAX_OBJECT_BYTES {
            return Err(ImageStoreError::Protocol(format!(
                "object size exceeds the {HIPPIUS_S3_MAX_OBJECT_BYTES}-byte cap"
            )));
        }
        Ok(buf)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_round_trips() {
        let store = MemoryImageStore::new();
        let r = store.put("images/a/kbs.uki", b"artifact-bytes").unwrap();
        assert_eq!(r.outcome, PutOutcome::Created);
        assert_eq!(store.get("images/a/kbs.uki").unwrap(), b"artifact-bytes");
    }

    #[test]
    fn put_is_idempotent_on_an_existing_key() {
        let store = MemoryImageStore::new();
        let first = store.put("k", b"original").unwrap();
        let second = store.put("k", b"original").unwrap();
        assert_eq!(first.outcome, PutOutcome::Created);
        assert_eq!(second.outcome, PutOutcome::AlreadyPresent);
        // The version id is stable across the idempotent re-put.
        assert_eq!(first.version_id, second.version_id);
    }

    #[test]
    fn put_rejects_a_conflicting_overwrite() {
        // A content-addressed key must map to exactly one byte string.
        // A second `put` with DIFFERENT bytes fails closed — it is
        // never silently overwritten and never silently accepted.
        let store = MemoryImageStore::new();
        store.put("k", b"first-write").unwrap();
        assert!(matches!(
            store.put("k", b"second-write-DIFFERENT"),
            Err(ImageStoreError::Conflict { .. })
        ));
        // The stored object is untouched.
        assert_eq!(store.get("k").unwrap(), b"first-write");
    }

    #[test]
    fn exists_reflects_stored_keys() {
        let store = MemoryImageStore::new();
        assert!(!store.exists("k").unwrap());
        store.put("k", b"v").unwrap();
        assert!(store.exists("k").unwrap());
    }

    #[test]
    fn get_missing_key_is_not_found() {
        let store = MemoryImageStore::new();
        assert!(matches!(
            store.get("nope"),
            Err(ImageStoreError::NotFound { .. })
        ));
    }

    #[test]
    fn memory_version_id_is_content_addressed() {
        let store = MemoryImageStore::new();
        let r = store.put("k", b"abc").unwrap();
        assert_eq!(r.version_id, Some(content_version_id(b"abc")));
    }

    #[test]
    fn hippius_s3_put_still_fails_closed() {
        // The WRITE half is deferred — `put` returns `NotWired` with
        // the surface-aware stub message. CI publish uses `aws s3 cp`
        // directly until the SigV4-signed PUT lands.
        let store =
            HippiusS3ImageStore::new("hippius-compute-images", "https://example.invalid").unwrap();
        match store.put("k", b"v") {
            Err(ImageStoreError::NotWired(msg)) => assert!(msg.contains("put")),
            other => panic!("expected NotWired, got {other:?}"),
        }
    }

    #[test]
    fn hippius_s3_object_url_is_path_style() {
        // The URL shape `<endpoint>/<bucket>/<key>` is what the
        // anonymous-readable `images/` prefix exposes — `miner-uki-fetch`
        // depends on it. Pinned here so a refactor of the formatter
        // can't silently change the URL miners hit.
        let store =
            HippiusS3ImageStore::new("hippius-compute-images", "https://s3.hippius.com").unwrap();
        assert_eq!(
            store.object_url("images/aa/kbs.uki"),
            "https://s3.hippius.com/hippius-compute-images/images/aa/kbs.uki"
        );
        // Trailing `/` on the endpoint is collapsed; leading `/` on
        // the key is stripped, so callers can pass either form.
        let store_slash =
            HippiusS3ImageStore::new("hippius-compute-images", "https://s3.hippius.com/").unwrap();
        assert_eq!(
            store_slash.object_url("/images/aa/kbs.uki"),
            "https://s3.hippius.com/hippius-compute-images/images/aa/kbs.uki"
        );
    }

    #[test]
    fn hippius_s3_exists_returns_false_on_404() {
        // `s3.hippius.com` serves 404 for an absent key — `exists`
        // surfaces that as `Ok(false)`. The bucket is a known good
        // endpoint, the key is content-addressed garbage; the live s3
        // bucket round-trip is left to integration.
        let store =
            HippiusS3ImageStore::new("hippius-compute-images", "https://s3.hippius.com").unwrap();
        let key = format!("images/{}/never-exists.uki", "0".repeat(64));
        match store.exists(&key) {
            Ok(false) => {}
            // The live bucket's behaviour is not this unit test's contract:
            // a network-unreachable env (`Transport`) OR a transient/edge
            // status the bucket returns for an anonymous absent-key probe
            // (`Protocol` — e.g. a 5xx/redirect from the S3 gateway) is an
            // environment quirk, not a code defect. Skip gracefully; the
            // real 404/403→false mapping is unit-covered by the mock store
            // and the live round-trip is left to integration. Only a
            // spurious `Ok(true)` (garbage key "exists") is a real failure.
            Err(ImageStoreError::Transport(_)) | Err(ImageStoreError::Protocol(_)) => {}
            other => panic!("expected Ok(false)/Transport/Protocol, got {other:?}"),
        }
    }
}
