//! Per-request node signatures (backend contract §C.0).
//!
//! The node routes stay behind Cloudflare on the public API hostname, so
//! the backend never sees a TLS client certificate. Instead every request
//! made with a session carries
//!
//! ```text
//! X-Hippius-Node-Timestamp: <unix seconds, server-relative>
//! X-Hippius-Node-Signature: <base64 Ed25519 with the node key>
//! ```
//!
//! over the lines of [`request_message`], joined by `\n`.
//!
//! The guest clock belongs to the miner, so the timestamp is never the
//! local clock: [`ServerClock`] keeps the offset to the backend's clock,
//! learned from `X-Hippius-Server-Time` (or `Date`) on every response,
//! errors included. The backend refuses a replayed signed request, so two
//! requests are never signed with the same timestamp.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use reqwest::header::{HeaderMap, DATE};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;

use crate::clock::unix_now;
use crate::identity::NodeKey;
use crate::wire::SessionToken;

pub const DOMAIN: &str = "HIPPIUS_CDN_NODE_REQ_V1";
pub const HEADER_SIGNATURE: &str = "X-Hippius-Node-Signature";
pub const HEADER_TIMESTAMP: &str = "X-Hippius-Node-Timestamp";
pub const HEADER_SERVER_TIME: &str = "X-Hippius-Server-Time";
/// The `session_id` signed when the backend returned none (its interim
/// token has no session).
pub const NO_SESSION_ID: &str = "-";
/// 401 codes of §C.0.
pub const CODE_STALE: &str = "node-signature-stale";
pub const CODE_INVALID: &str = "node-signature-invalid";
/// Longest `session_id` accepted from the backend.
const MAX_SESSION_ID_LEN: usize = 128;

/// The signed message: domain, node id, method, host, path and query as
/// sent, timestamp, hex SHA-256 of the body, session id.
pub fn request_message(
    node_id: &str,
    method: &str,
    host: &str,
    path_and_query: &str,
    timestamp: u64,
    body: &[u8],
    session_id: &str,
) -> Vec<u8> {
    let body_hash = hex::encode(Sha256::digest(body));
    let ts = timestamp.to_string();
    [
        DOMAIN,
        node_id,
        &method.to_ascii_uppercase(),
        host,
        path_and_query,
        &ts,
        &body_hash,
        session_id,
    ]
    .join("\n")
    .into_bytes()
}

/// A session id is opaque, but it is one line of the signed message: no
/// whitespace or control characters.
pub fn valid_session_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_SESSION_ID_LEN && s.bytes().all(|b| b.is_ascii_graphic())
}

/// What an authenticated request is made with.
pub struct NodeAuth<'a> {
    pub token: &'a SessionToken,
    pub session_id: &'a str,
    pub node_id: &'a str,
    pub key: &'a NodeKey,
    /// `[backend] request_signatures`; off sends the bearer token only.
    pub sign: bool,
}

impl NodeAuth<'_> {
    /// The two headers for one request.
    pub fn headers(
        &self,
        method: &str,
        host: &str,
        path_and_query: &str,
        timestamp: u64,
        body: &[u8],
    ) -> [(&'static str, String); 2] {
        let msg = request_message(
            self.node_id,
            method,
            host,
            path_and_query,
            timestamp,
            body,
            self.session_id,
        );
        [
            (HEADER_TIMESTAMP, timestamp.to_string()),
            (HEADER_SIGNATURE, B64.encode(self.key.sign(&msg))),
        ]
    }
}

/// The backend's clock, as seen from this guest. Shared by every clone of
/// a client.
///
/// Anchored on the monotonic clock, not the wall clock: the guest's wall
/// clock is the miner's and steps (NTP `makestep`, or on purpose), while
/// `Instant` does not. Before the first response carried a time, the wall
/// clock is all there is.
#[derive(Clone, Default)]
pub struct ServerClock(Arc<Mutex<ClockState>>);

#[derive(Default)]
struct ClockState {
    /// The last server time seen, and when.
    anchor: Option<(u64, Instant)>,
    /// An `X-Hippius-Server-Time` was seen: `Date` is no longer used.
    authoritative: bool,
    /// (timestamp, request fingerprint) signed in the backend's replay
    /// window, so an identical request is never signed twice in a second.
    signed: Vec<(u64, [u8; 32])>,
}

/// The backend remembers a signed request for 120 s; keep a little more.
const REPLAY_WINDOW_S: u64 = 130;

impl ServerClock {
    /// Learn the server's time from a response's headers, if they carry
    /// one.
    pub fn observe(&self, headers: &HeaderMap) {
        self.observe_at(headers, Instant::now());
    }

    fn observe_at(&self, headers: &HeaderMap, at: Instant) {
        let Ok(mut s) = self.0.lock() else {
            return;
        };
        let explicit = explicit_server_time(headers);
        let time = match explicit {
            Some(t) => Some(t),
            None if !s.authoritative => date_time(headers),
            None => None,
        };
        if let Some(t) = time {
            s.anchor = Some((t, at));
            s.authoritative |= explicit.is_some();
        }
    }

    /// The backend's current time.
    pub fn now(&self) -> u64 {
        self.now_at(Instant::now(), unix_now())
    }

    /// `Instant` may stand still while the VM is paused (a stop, a §25
    /// migration): the clock then lags, and the first request's stale 401
    /// carries the server time that resyncs it.
    fn now_at(&self, at: Instant, wall: u64) -> u64 {
        let anchor = self.0.lock().ok().and_then(|s| s.anchor);
        match anchor {
            Some((t, then)) => t.saturating_add(at.saturating_duration_since(then).as_secs()),
            None => wall,
        }
    }

    /// A timestamp to sign the request `fingerprint` with: the backend's
    /// current second. The backend refuses a replayed message, so when
    /// this very request was already signed at that second, wait for the
    /// next one rather than run ahead of the server's clock.
    pub fn timestamp_for(&self, fingerprint: [u8; 32]) -> u64 {
        loop {
            let ts = self.now();
            if self.claim(ts, fingerprint) {
                return ts;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Record `(ts, fingerprint)` unless it was already signed.
    fn claim(&self, ts: u64, fingerprint: [u8; 32]) -> bool {
        let Ok(mut s) = self.0.lock() else {
            return true;
        };
        s.signed.retain(|(t, _)| {
            t.saturating_add(REPLAY_WINDOW_S) >= ts && *t <= ts.saturating_add(REPLAY_WINDOW_S)
        });
        if s.signed.contains(&(ts, fingerprint)) {
            return false;
        }
        s.signed.push((ts, fingerprint));
        true
    }
}

/// What makes two signed requests the same message, timestamp aside.
pub fn fingerprint(method: &str, host: &str, path_and_query: &str, body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [
        method.as_bytes(),
        host.as_bytes(),
        path_and_query.as_bytes(),
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.update(Sha256::digest(body));
    h.finalize().into()
}

/// `X-Hippius-Server-Time` (unix seconds).
fn explicit_server_time(headers: &HeaderMap) -> Option<u64> {
    let v = headers.get(HEADER_SERVER_TIME)?.to_str().ok()?.trim();
    if v.is_empty() || v.len() > 12 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

/// The HTTP `Date`.
fn date_time(headers: &HeaderMap) -> Option<u64> {
    let date = headers.get(DATE)?.to_str().ok()?;
    let t = OffsetDateTime::parse(date.trim(), &Rfc2822).ok()?;
    u64::try_from(t.unix_timestamp()).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use reqwest::header::HeaderValue;

    #[derive(serde::Deserialize)]
    struct Vectors {
        lifecycle_seed_hex: String,
        node_public_hex: String,
        cases: Vec<Case>,
    }

    #[derive(serde::Deserialize)]
    struct Case {
        name: String,
        node_id: String,
        method: String,
        host: String,
        path_and_query: String,
        timestamp: u64,
        body_hex: String,
        session_id: String,
        message_hex: String,
        signature_b64: String,
    }

    #[test]
    fn golden_vectors_match_the_backend() {
        let raw = include_str!("../../../test_vectors/cdn/node_req_v1.json");
        let v: Vectors = serde_json::from_str(raw).unwrap();
        let seed: [u8; 32] = hex::decode(&v.lifecycle_seed_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let key = NodeKey::derive(&seed);
        assert_eq!(hex::encode(key.public_bytes()), v.node_public_hex);
        let vk = VerifyingKey::from_bytes(&key.public_bytes()).unwrap();
        assert!(v.cases.len() >= 4);
        for c in &v.cases {
            let body = hex::decode(&c.body_hex).unwrap();
            let msg = request_message(
                &c.node_id,
                &c.method,
                &c.host,
                &c.path_and_query,
                c.timestamp,
                &body,
                &c.session_id,
            );
            assert_eq!(hex::encode(&msg), c.message_hex, "{}: message", c.name);
            let token = SessionToken::for_tests("unused");
            let auth = NodeAuth {
                token: &token,
                session_id: &c.session_id,
                node_id: &c.node_id,
                key: &key,
                sign: true,
            };
            let [(_, ts), (_, sig)] =
                auth.headers(&c.method, &c.host, &c.path_and_query, c.timestamp, &body);
            assert_eq!(ts, c.timestamp.to_string());
            assert_eq!(sig, c.signature_b64, "{}: signature", c.name);
            let sig = Signature::from_slice(&B64.decode(&sig).unwrap()).unwrap();
            vk.verify(&msg, &sig).unwrap();
        }
    }

    #[test]
    fn method_is_upper_cased_and_empty_body_hashes_empty() {
        let m = String::from_utf8(request_message("n", "get", "h", "/p", 5, b"", "-")).unwrap();
        assert_eq!(
            m,
            "HIPPIUS_CDN_NODE_REQ_V1\nn\nGET\nh\n/p\n5\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n-"
        );
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn server_time_wins_and_date_is_a_fallback_until_then() {
        let t0 = Instant::now();
        let c = ServerClock::default();
        assert_eq!(c.now_at(t0, 1000), 1000, "nothing seen: the wall clock");
        // Date alone (1445412480 = 2015-10-21T07:28:00Z).
        c.observe_at(&headers(&[("date", "Wed, 21 Oct 2015 07:28:00 GMT")]), t0);
        assert_eq!(c.now_at(t0, 1), 1_445_412_480);
        c.observe_at(&headers(&[(HEADER_SERVER_TIME, "1600")]), t0);
        assert_eq!(c.now_at(t0, 1), 1600);
        // Once X-Hippius-Server-Time was seen, a Date (e.g. an edge error
        // page) no longer moves the clock; garbage never does.
        c.observe_at(&headers(&[("date", "Wed, 21 Oct 2015 07:28:00 GMT")]), t0);
        c.observe_at(&headers(&[(HEADER_SERVER_TIME, "12x")]), t0);
        assert_eq!(c.now_at(t0, 1), 1600);
    }

    #[test]
    fn the_clock_runs_on_the_monotonic_clock_not_the_wall() {
        let t0 = Instant::now();
        let c = ServerClock::default();
        c.observe_at(&headers(&[(HEADER_SERVER_TIME, "2000")]), t0);
        // The wall clock is ignored once anchored, however it steps.
        assert_eq!(c.now_at(t0 + Duration::from_secs(30), 5), 2030);
        assert_eq!(c.now_at(t0 + Duration::from_secs(30), 99_999_999), 2030);
    }

    #[test]
    fn identical_requests_never_share_a_second_and_others_do() {
        let c = ServerClock::default();
        let a = fingerprint("GET", "h", "/feed/?since=1", b"");
        let b = fingerprint("POST", "h", "/usage/", b"{}");
        assert!(c.claim(100, a));
        assert!(c.claim(100, b), "a different request may share the second");
        assert!(!c.claim(100, a), "the same request may not");
        assert!(c.claim(101, a));
        // A clock corrected backwards inside the replay window still
        // refuses a pair already signed.
        assert!(!c.claim(100, a));
        // Outside it, the record is gone.
        assert!(c.claim(100 + REPLAY_WINDOW_S + 2, a));
        assert!(c.claim(100, a), "pruned once far out of the window");
    }

    #[test]
    fn a_burst_of_distinct_requests_stays_on_the_server_second() {
        let c = ServerClock::default();
        c.observe(&headers(&[(HEADER_SERVER_TIME, "3000")]));
        for i in 0..200u32 {
            let ts = c.timestamp_for(fingerprint("POST", "h", "/usage/", &i.to_be_bytes()));
            assert!((3000..3005).contains(&ts), "request {i} signed at {ts}");
        }
    }

    #[test]
    fn an_identical_request_waits_for_the_next_second() {
        let c = ServerClock::default();
        c.observe(&headers(&[(HEADER_SERVER_TIME, "4000")]));
        let fp = fingerprint("GET", "h", "/feed/?since=3", b"");
        let started = Instant::now();
        let t1 = c.timestamp_for(fp);
        let t2 = c.timestamp_for(fp);
        assert_eq!(t2, t1 + 1);
        assert!(started.elapsed() < Duration::from_millis(1600));
    }

    #[test]
    fn fingerprints_separate_the_fields() {
        assert_ne!(
            fingerprint("GET", "ab", "/c", b""),
            fingerprint("GET", "a", "b/c", b"")
        );
        assert_ne!(
            fingerprint("GET", "h", "/p", b"x"),
            fingerprint("GET", "h", "/p", b"")
        );
    }

    #[test]
    fn session_ids_must_be_one_printable_token() {
        assert!(valid_session_id("s_1-ab.C"));
        assert!(valid_session_id(NO_SESSION_ID));
        assert!(!valid_session_id(""));
        assert!(!valid_session_id("a b"));
        assert!(!valid_session_id("a\nb"));
        assert!(!valid_session_id(&"x".repeat(129)));
    }
}
