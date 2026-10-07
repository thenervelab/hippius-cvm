//! The backend client (CDN plan §C).
//!
//! Blocking `reqwest` over rustls, like the other guest agents.
//! Transport posture:
//! - `https` only, TLS ≥ 1.2, certificate verification always on;
//! - roots: the built-in web roots, or **only** the configured bundle;
//! - redirects are never followed, so a bearer token cannot be replayed
//!   to another host;
//! - every response body is read through a hard size cap.
//!
//! Authentication (§C.0): the node routes sit behind Cloudflare, so there
//! is no TLS client certificate. Every request made with a session carries
//! the bearer token and, unless `[backend] request_signatures = false`, a
//! per-request Ed25519 signature with the node key ([`crate::reqsign`]),
//! timestamped on the backend's clock. Every response, errors included,
//! updates that clock. A 401 `node-signature-stale` is retried once with
//! a fresh timestamp; any other 401 drops the session.
//!
//! Only the backend's error `code` is ever logged, after sanitising.

use std::io::Read;
use std::time::Duration;

use reqwest::blocking::{Client, Request, RequestBuilder};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, ETAG, IF_NONE_MATCH};
use reqwest::redirect::Policy;
use reqwest::{Certificate, StatusCode};
use serde::de::DeserializeOwned;

use crate::config::{signed_host, BackendConfig, BackendUrl};
use crate::error::{CdnError, Result};
use crate::reqsign::{fingerprint, NodeAuth, ServerClock, CODE_STALE};
use crate::wire::{
    self, AcmeLeaseRequest, AcmeLeaseResponse, CertUpload, ChallengeRequest, ChallengeResponse,
    Dns01Request, Dns01Response, ErrorBody, FeedResponse, NodeCertResponse, RegisterRequest,
    RegisterResponse,
};

/// Cap on small JSON responses.
const MAX_SMALL_BODY: u64 = 256 * 1024;
/// Cap on a feed response (a 10k-zone snapshot is about 20 MB).
const MAX_FEED_BODY: u64 = 256 * 1024 * 1024;
/// Longest `Retry-After` honoured (seconds); a larger value is clamped.
pub const MAX_RETRY_AFTER_S: u64 = 900;
/// Cap on an `ETag` value echoed back.
const MAX_ETAG_LEN: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Result of one feed long-poll.
#[derive(Debug)]
pub enum FeedPoll {
    Updated {
        resp: Box<FeedResponse>,
        etag: Option<String>,
    },
    /// Nothing changed. `retry_after` is the server's `Retry-After`.
    NotModified { retry_after: Option<u64> },
}

/// A configured backend client. Cheap to clone; clones share the server
/// clock.
#[derive(Clone)]
pub struct BackendClient {
    base: BackendUrl,
    http: Client,
    request_timeout: Duration,
    feed_timeout: Duration,
    clock: ServerClock,
}

impl BackendClient {
    pub fn new(cfg: &BackendConfig) -> Result<Self> {
        let mut b = Client::builder()
            .use_rustls_tls()
            .https_only(!cfg!(test))
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .redirect(Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent(concat!("hippius-cdn-agent/", env!("CARGO_PKG_VERSION")));
        if let Some(path) = &cfg.ca_bundle {
            let pem = std::fs::read(path).map_err(|_| CdnError::Config("ca-bundle-read"))?;
            let roots = Certificate::from_pem_bundle(&pem)
                .map_err(|_| CdnError::Config("ca-bundle-parse"))?;
            if roots.is_empty() {
                return Err(CdnError::Config("ca-bundle-empty"));
            }
            b = b.tls_built_in_root_certs(false);
            for root in roots {
                b = b.add_root_certificate(root);
            }
        }
        let http = b.build().map_err(|_| CdnError::Backend("client-build"))?;
        Ok(Self {
            base: cfg.url.clone(),
            http,
            request_timeout: Duration::from_secs(cfg.request_timeout_s),
            feed_timeout: Duration::from_secs(cfg.request_timeout_s + cfg.feed_poll_s),
            clock: ServerClock::default(),
        })
    }

    /// The backend's current time, as last learned from a response (the
    /// guest clock is the miner's).
    pub fn server_now(&self) -> u64 {
        self.clock.now()
    }

    /// Bootstrap: fetch this node's (public) certificate.
    pub fn node_cert(&self, vm_id: &str) -> Result<String> {
        let mut url = self.base.join(wire::PATH_NODE_CERT)?;
        url.query_pairs_mut().append_pair("vm_id", vm_id);
        let r: NodeCertResponse = self.json(self.http.get(url), None)?;
        Ok(r.cert_pem)
    }

    pub fn challenge(&self, vm_id: &str) -> Result<ChallengeResponse> {
        let url = self.base.join(wire::PATH_REGISTER_CHALLENGE)?;
        self.json(
            json_body(self.http.post(url), &ChallengeRequest { vm_id })?,
            None,
        )
    }

    pub fn register(&self, req: &RegisterRequest<'_>) -> Result<RegisterResponse> {
        let url = self.base.join(wire::PATH_REGISTER)?;
        self.json(json_body(self.http.post(url), req)?, None)
    }

    /// Long-poll the feed. `since = None` asks for a snapshot.
    pub fn feed(
        &self,
        auth: &NodeAuth<'_>,
        since: Option<u64>,
        etag: Option<&str>,
    ) -> Result<FeedPoll> {
        let mut url = self.base.join(wire::PATH_FEED)?;
        if let Some(rev) = since {
            url.query_pairs_mut().append_pair("since", &rev.to_string());
        }
        let mut req = self.http.get(url).timeout(self.feed_timeout);
        if let Some(tag) = etag {
            req = req.header(IF_NONE_MATCH, tag);
        }
        let (status, headers, body) = self.send(req, Some(auth), MAX_FEED_BODY)?;
        match status {
            StatusCode::NOT_MODIFIED => Ok(FeedPoll::NotModified {
                retry_after: retry_after_of(&headers),
            }),
            s if s.is_success() => {
                let resp: FeedResponse =
                    serde_json::from_slice(&body).map_err(|_| CdnError::Backend("feed-decode"))?;
                Ok(FeedPoll::Updated {
                    resp: Box::new(resp),
                    etag: etag_of(&headers),
                })
            }
            s => Err(match (status_error(s, &body), retry_after_of(&headers)) {
                (CdnError::BackendStatus(status), Some(retry_after_s)) => CdnError::Throttled {
                    status,
                    retry_after_s,
                },
                (e, _) => e,
            }),
        }
    }

    /// Post one usage report: `body` exactly as signed.
    pub fn post_usage(&self, auth: &NodeAuth<'_>, body: &[u8], signature_b64: &str) -> Result<()> {
        let url = self.base.join(wire::PATH_USAGE)?;
        let req = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(wire::HEADER_NODE, auth.node_id)
            .header(wire::HEADER_SIGNATURE, signature_b64)
            .body(body.to_vec());
        self.empty(req, Some(auth))
    }

    /// I4: upload a sealed certificate key and its public chain.
    pub fn upload_cert(&self, auth: &NodeAuth<'_>, upload: &CertUpload<'_>) -> Result<()> {
        let url = self.base.join(wire::PATH_CERTS)?;
        self.empty(json_body(self.http.post(url), upload)?, Some(auth))
    }

    /// I4: take the issuance lease for a hostname.
    pub fn acme_lease(&self, auth: &NodeAuth<'_>, hostname_id: &str) -> Result<AcmeLeaseResponse> {
        let url = self.base.join(wire::PATH_ACME_LEASE)?;
        self.json(
            json_body(self.http.post(url), &AcmeLeaseRequest { hostname_id })?,
            Some(auth),
        )
    }

    /// I4: ask the backend to write a DNS-01 TXT value.
    pub fn acme_dns01(&self, auth: &NodeAuth<'_>, req: &Dns01Request<'_>) -> Result<Dns01Response> {
        let url = self.base.join(wire::PATH_ACME_DNS01)?;
        self.json(json_body(self.http.post(url), req)?, Some(auth))
    }

    fn json<T: DeserializeOwned>(
        &self,
        req: RequestBuilder,
        auth: Option<&NodeAuth<'_>>,
    ) -> Result<T> {
        let (status, _, body) =
            self.send(req.timeout(self.request_timeout), auth, MAX_SMALL_BODY)?;
        if !status.is_success() {
            return Err(status_error(status, &body));
        }
        serde_json::from_slice(&body).map_err(|_| CdnError::Backend("decode"))
    }

    fn empty(&self, req: RequestBuilder, auth: Option<&NodeAuth<'_>>) -> Result<()> {
        let (status, _, body) =
            self.send(req.timeout(self.request_timeout), auth, MAX_SMALL_BODY)?;
        if status.is_success() {
            Ok(())
        } else {
            Err(status_error(status, &body))
        }
    }

    /// Send `req`, authenticated with `auth` when given. A signed request
    /// refused as stale is re-signed and sent once more: the response
    /// that refused it carried the server's time.
    fn send(
        &self,
        req: RequestBuilder,
        auth: Option<&NodeAuth<'_>>,
        max: u64,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
        let request = req
            .build()
            .map_err(|_| CdnError::Backend("request-build"))?;
        let Some(auth) = auth else {
            return self.execute(request, max);
        };
        let retry = if auth.sign { request.try_clone() } else { None };
        let first = self.execute(self.authenticate(request, auth)?, max)?;
        match retry {
            Some(again)
                if first.0 == StatusCode::UNAUTHORIZED
                    && error_code(&first.2).as_deref() == Some(CODE_STALE) =>
            {
                eprintln!(
                    "hippius-cdn-agent: request signature stale, clock resynced, retrying once"
                );
                self.execute(self.authenticate(again, auth)?, max)
            }
            _ => Ok(first),
        }
    }

    /// Add the bearer token and, when signing, the §C.0 headers.
    fn authenticate(&self, mut request: Request, auth: &NodeAuth<'_>) -> Result<Request> {
        let mut bearer = HeaderValue::from_str(&format!("Bearer {}", auth.token.expose()))
            .map_err(|_| CdnError::Backend("token-not-header-safe"))?;
        bearer.set_sensitive(true);
        request.headers_mut().insert(AUTHORIZATION, bearer);
        if !auth.sign {
            return Ok(request);
        }
        let url = request.url();
        let host = signed_host(url);
        let path_and_query = match url.query() {
            Some(q) if !q.is_empty() => format!("{}?{q}", url.path()),
            _ => url.path().to_string(),
        };
        let body = match request.body() {
            None => &[][..],
            Some(b) => b.as_bytes().ok_or(CdnError::Backend("body-not-signable"))?,
        };
        let method = request.method().as_str();
        let ts = self
            .clock
            .timestamp_for(fingerprint(method, &host, &path_and_query, body));
        let headers = auth.headers(method, &host, &path_and_query, ts, body);
        for (name, value) in headers {
            let value =
                HeaderValue::from_str(&value).map_err(|_| CdnError::Backend("signature-header"))?;
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| CdnError::Backend("signature-header"))?;
            request.headers_mut().insert(name, value);
        }
        Ok(request)
    }

    fn execute(&self, request: Request, max: u64) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
        let resp = self.http.execute(request).map_err(|e| {
            if e.is_timeout() {
                CdnError::Backend("timeout")
            } else if e.is_connect() {
                CdnError::Backend("connect")
            } else {
                CdnError::Backend("transport")
            }
        })?;
        let status = resp.status();
        let headers = resp.headers().clone();
        self.clock.observe(&headers);
        let mut body = Vec::new();
        resp.take(max + 1)
            .read_to_end(&mut body)
            .map_err(|_| CdnError::Backend("body-read"))?;
        if body.len() as u64 > max {
            return Err(CdnError::Backend("body-too-large"));
        }
        Ok((status, headers, body))
    }
}

/// Serialise `body` as the JSON request body.
fn json_body<T: serde::Serialize>(req: RequestBuilder, body: &T) -> Result<RequestBuilder> {
    let bytes = serde_json::to_vec(body).map_err(|_| CdnError::Backend("request-encode"))?;
    Ok(req
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(bytes))
}

fn etag_of(headers: &HeaderMap) -> Option<String> {
    headers
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= MAX_ETAG_LEN && v.bytes().all(|b| b.is_ascii_graphic()))
        .map(str::to_string)
}

/// `Retry-After` in delta-seconds (the HTTP-date form is ignored),
/// clamped to [`MAX_RETRY_AFTER_S`].
fn retry_after_of(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|s| s.min(MAX_RETRY_AFTER_S))
}

/// The backend's error `code`, sanitised.
fn error_code(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<ErrorBody>(body).ok().map(|e| {
        e.code
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            .take(64)
            .collect()
    })
}

fn status_error(status: StatusCode, body: &[u8]) -> CdnError {
    if status.is_redirection() {
        return CdnError::Backend("redirect-refused");
    }
    if let Some(code) = error_code(body) {
        eprintln!(
            "hippius-cdn-agent: backend status {} code {code}",
            status.as_u16()
        );
    }
    if status == StatusCode::UNAUTHORIZED {
        CdnError::Unauthorized
    } else {
        CdnError::BackendStatus(status.as_u16())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::identity::NodeKey;
    use crate::reqsign::{request_message, CODE_INVALID, HEADER_SERVER_TIME};
    use crate::test_support::{MockBackend, Reply};
    use crate::wire::SessionToken;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn cfg(mock: &MockBackend) -> BackendConfig {
        BackendConfig {
            url: BackendUrl::loopback_for_tests(mock.addr()),
            ca_bundle: None,
            request_signatures: true,
            request_timeout_s: 5,
            feed_poll_s: 1,
        }
    }

    fn key() -> NodeKey {
        NodeKey::derive(&[7u8; 32])
    }

    fn auth<'a>(tok: &'a SessionToken, key: &'a NodeKey, sign: bool) -> NodeAuth<'a> {
        NodeAuth {
            token: tok,
            session_id: "sess-1",
            node_id: "cdn-fr-7k2m",
            key,
            sign,
        }
    }

    /// Verify the §C.0 signature of a request the mock received.
    fn verify_signed(mock: &MockBackend, req: &crate::test_support::Request, key: &NodeKey) -> u64 {
        let ts: u64 = req
            .header("x-hippius-node-timestamp")
            .unwrap()
            .parse()
            .unwrap();
        let sig = B64
            .decode(req.header("x-hippius-node-signature").unwrap())
            .unwrap();
        let msg = request_message(
            "cdn-fr-7k2m",
            &req.method,
            &mock.addr().to_string(),
            &req.target,
            ts,
            &req.body,
            "sess-1",
        );
        VerifyingKey::from_bytes(&key.public_bytes())
            .unwrap()
            .verify(&msg, &Signature::from_slice(&sig).unwrap())
            .unwrap();
        ts
    }

    #[test]
    fn feed_sends_since_bearer_and_etag_and_reads_304() {
        let mock = MockBackend::start(|req| {
            if req.header("if-none-match") == Some("\"7\"") {
                Reply::status(304)
            } else {
                Reply::json(200, r#"{"revision":7,"mode":"snapshot","self":{}}"#)
                    .with_header("ETag", "\"7\"")
            }
        });
        let c = BackendClient::new(&cfg(&mock)).unwrap();
        let tok = SessionToken::for_tests("tok-1");
        let k = key();
        let tok = auth(&tok, &k, true);
        let FeedPoll::Updated { resp, etag } = c.feed(&tok, None, None).unwrap() else {
            panic!("expected update")
        };
        assert_eq!(resp.revision, 7);
        assert_eq!(etag.as_deref(), Some("\"7\""));
        assert!(matches!(
            c.feed(&tok, Some(7), etag.as_deref()).unwrap(),
            FeedPoll::NotModified { retry_after: None }
        ));
        let reqs = mock.requests();
        assert_eq!(reqs[0].target, "/api/cdn/node/feed/");
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[1].target, "/api/cdn/node/feed/?since=7");
        assert_eq!(reqs[1].header("authorization"), Some("Bearer tok-1"));
    }

    #[test]
    fn statuses_map_to_typed_errors_and_redirects_are_not_followed() {
        let mock = MockBackend::start(|req| match req.target.as_str() {
            t if t.starts_with("/api/cdn/node/cert/") => {
                Reply::status(302).with_header("Location", "http://evil.example/")
            }
            "/api/cdn/node/register/challenge/" => {
                Reply::json(401, r#"{"code":"session-expired"}"#)
            }
            _ => Reply::json(503, r#"{"code":"maintenance","detail":"x"}"#),
        });
        let c = BackendClient::new(&cfg(&mock)).unwrap();
        assert_eq!(c.node_cert("vm").unwrap_err().class(), "redirect-refused");
        assert!(matches!(
            c.challenge("vm").unwrap_err(),
            CdnError::Unauthorized
        ));
        let tok = SessionToken::for_tests("t");
        let k = key();
        let tok = auth(&tok, &k, true);
        assert!(matches!(
            c.feed(&tok, None, None).unwrap_err(),
            CdnError::BackendStatus(503)
        ));
        assert_eq!(
            mock.requests().len(),
            3,
            "no request to the redirect target"
        );
    }

    #[test]
    fn retry_after_is_read_from_304_and_errors() {
        let mock = MockBackend::start(|req| match req.target.as_str() {
            "/api/cdn/node/feed/?since=1" => Reply::status(304).with_header("Retry-After", "12"),
            "/api/cdn/node/feed/?since=2" => {
                Reply::json(503, r#"{"code":"busy"}"#).with_header("Retry-After", "99999")
            }
            "/api/cdn/node/feed/?since=3" => {
                Reply::status(304).with_header("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")
            }
            _ => Reply::json(503, "{}"),
        });
        let c = BackendClient::new(&cfg(&mock)).unwrap();
        let tok = SessionToken::for_tests("t");
        let k = key();
        let tok = auth(&tok, &k, true);
        assert!(matches!(
            c.feed(&tok, Some(1), None).unwrap(),
            FeedPoll::NotModified {
                retry_after: Some(12)
            }
        ));
        assert!(matches!(
            c.feed(&tok, Some(2), None).unwrap_err(),
            CdnError::Throttled {
                status: 503,
                retry_after_s: MAX_RETRY_AFTER_S
            }
        ));
        assert!(matches!(
            c.feed(&tok, Some(3), None).unwrap(),
            FeedPoll::NotModified { retry_after: None }
        ));
        assert!(matches!(
            c.feed(&tok, Some(4), None).unwrap_err(),
            CdnError::BackendStatus(503)
        ));
    }

    #[test]
    fn oversized_bodies_are_refused() {
        let big = format!(
            "{{\"cert_pem\":\"{}\"}}",
            "a".repeat(MAX_SMALL_BODY as usize)
        );
        let mock = MockBackend::start(move |_| Reply::json(200, &big));
        let c = BackendClient::new(&cfg(&mock)).unwrap();
        assert_eq!(c.node_cert("vm").unwrap_err().class(), "body-too-large");
    }

    #[test]
    fn session_requests_are_signed_on_the_server_clock() {
        let mock = MockBackend::start(|_| {
            Reply::status(304).with_header(HEADER_SERVER_TIME, "1900000000")
        });
        let c = BackendClient::new(&cfg(&mock)).unwrap();
        let tok = SessionToken::for_tests("tok-1");
        let k = key();
        // Bootstrap calls are not signed, but teach the client the clock.
        let _ = c.node_cert("vm");
        let unsigned = &mock.requests()[0];
        assert!(unsigned.header("x-hippius-node-signature").is_none());
        assert!(unsigned.header("authorization").is_none());
        c.feed(&auth(&tok, &k, true), Some(9), None).unwrap();
        c.feed(&auth(&tok, &k, true), Some(9), None).unwrap();
        let reqs = mock.requests();
        assert_eq!(reqs[1].header("authorization"), Some("Bearer tok-1"));
        let t1 = verify_signed(&mock, &reqs[1], &k);
        let t2 = verify_signed(&mock, &reqs[2], &k);
        assert!(
            (1_900_000_000..1_900_000_030).contains(&t1),
            "server-relative: {t1}"
        );
        assert!(t2 > t1, "two requests never share a timestamp");
        assert_eq!(reqs[1].target, "/api/cdn/node/feed/?since=9");
    }

    #[test]
    fn post_bodies_are_covered_by_the_signature() {
        let mock = MockBackend::start(|_| Reply::json(200, r#"{"lease_id":"l","expires_at":"x"}"#));
        let c = BackendClient::new(&cfg(&mock)).unwrap();
        let tok = SessionToken::for_tests("t");
        let k = key();
        c.acme_lease(&auth(&tok, &k, true), "h42").unwrap();
        let req = &mock.requests()[0];
        assert_eq!(req.json()["hostname_id"], "h42");
        verify_signed(&mock, req, &k);
    }

    #[test]
    fn signatures_off_sends_the_bearer_only() {
        let mock = MockBackend::start(|_| Reply::status(304));
        let c = BackendClient::new(&cfg(&mock)).unwrap();
        let tok = SessionToken::for_tests("t");
        let k = key();
        c.feed(&auth(&tok, &k, false), None, None).unwrap();
        let req = &mock.requests()[0];
        assert_eq!(req.header("authorization"), Some("Bearer t"));
        assert!(req.header("x-hippius-node-signature").is_none());
        assert!(req.header("x-hippius-node-timestamp").is_none());
    }

    #[test]
    fn a_stale_signature_resyncs_and_retries_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&calls);
        let mock = MockBackend::start(move |_| match c2.fetch_add(1, Ordering::SeqCst) {
            0 => Reply::json(401, r#"{"code":"node-signature-stale"}"#)
                .with_header(HEADER_SERVER_TIME, "2000000000"),
            _ => Reply::status(304).with_header(HEADER_SERVER_TIME, "2000000001"),
        });
        let c = BackendClient::new(&cfg(&mock)).unwrap();
        let tok = SessionToken::for_tests("t");
        let k = key();
        assert!(matches!(
            c.feed(&auth(&tok, &k, true), Some(1), None).unwrap(),
            FeedPoll::NotModified { .. }
        ));
        let reqs = mock.requests();
        assert_eq!(reqs.len(), 2);
        let first = verify_signed(&mock, &reqs[0], &k);
        let second = verify_signed(&mock, &reqs[1], &k);
        assert!(first < 1_999_000_000, "the guest clock before the resync");
        assert!((2_000_000_000..2_000_000_030).contains(&second));
    }

    #[test]
    fn stale_twice_or_invalid_is_not_retried_further() {
        let mock = MockBackend::start(|req| {
            if req.target.contains("since=1") {
                Reply::json(401, r#"{"code":"node-signature-stale"}"#)
            } else {
                Reply::json(401, &format!(r#"{{"code":"{CODE_INVALID}"}}"#))
            }
        });
        let c = BackendClient::new(&cfg(&mock)).unwrap();
        let tok = SessionToken::for_tests("t");
        let k = key();
        assert!(matches!(
            c.feed(&auth(&tok, &k, true), Some(1), None).unwrap_err(),
            CdnError::Unauthorized
        ));
        assert_eq!(mock.requests().len(), 2, "one retry only");
        assert!(matches!(
            c.feed(&auth(&tok, &k, true), Some(2), None).unwrap_err(),
            CdnError::Unauthorized
        ));
        assert_eq!(mock.requests().len(), 3, "invalid: no retry");
    }

    #[test]
    fn production_urls_must_be_https() {
        assert!(BackendUrl::parse("http://127.0.0.1:1/").is_err());
    }
}
