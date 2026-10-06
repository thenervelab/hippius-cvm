//! Stage 3 + Stage 5 — KBS HTTP client (PR-E1.3, §7 / §17 / §20 / §21).
//!
//! Two `POST` endpoints on the `kbs-server` Rust core, reached over
//! Guardian → Edge GW (NetBird mesh) → vRack:
//!
//! - `POST /v1/kbs/nonce`   → a fresh single-use 32-byte nonce.
//! - `POST /v1/kbs/release` → `{cose_ticket, snp_report, kbs_nonce}`
//!   in; a signed+wrapped [`SignedResponse`] (HTTP 200) or a signed
//!   `SignedDenial` (HTTP 403) out.
//!
//! ## No retry, fail-closed — by design
//!
//! There is **no retry at the HTTP layer**. The §7 release-once
//! primitive is keyed by `(ticket_id, KBS_nonce)`: the SNP report the
//! guest just generated is bound to *this* nonce, and the nonce is
//! single-use. A retry would have to re-attest with a fresh nonce —
//! that is the *agent loop*'s job, not the transport's. So:
//!
//! - **Timeout** (connect > 5 s, or whole request > 30 s) ⇒ `Err`.
//!   The agent aborts; PID 1 returning non-zero panics the kernel —
//!   no shell, no busy-retry (§20).
//! - **A KBS denial** (HTTP 403) ⇒ [`AgentError::KbsDenial`], which is
//!   **terminal**. The KBS evaluated the ticket + attestation and said
//!   no; re-asking cannot change the answer. The agent aborts and the
//!   VM powers off — there is no "try another KBS", because the ticket
//!   is nonce-bound to this single exchange.
//!
//! ## Opacity
//!
//! The transport is **opaque** to Guardian / Edge — they never see
//! plaintext (the secrets are HPKE-wrapped end-to-end to the guest's
//! ephemeral key, unwrapped only by [`crate::stages::verify`]). This
//! client therefore logs nothing but static error classes — no URL
//! query echo, no response-body dump, no header dump.
//!
//! TLS is `rustls` (an initramfs has no system OpenSSL). The KBS
//! response's authenticity does NOT rest on the TLS layer — it rests
//! on the Ed25519 signature the guest verifies in
//! [`hippius_guest::verify_and_unwrap_release`]. TLS here is transport
//! confidentiality + integrity only.

use crate::pipeline::AgentError;
use crate::stages::snp_report::SnpReport;
use ciborium::value::Value;
use hippius_types::cbor::{assert_canonical, to_canonical_vec};
use hippius_types::release::SignedResponse;
use std::io::Read;
use std::time::Duration;

/// Content-Type the KBS accepts and emits — deterministic CBOR.
const CONTENT_TYPE_CBOR: &str = "application/cbor";

/// Strict connect timeout. A peer that completes the TCP+TLS handshake
/// slower than this is treated as unreachable — bounds a slow-loris on
/// connection setup.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Strict whole-request timeout (send + server work + response read).
/// Bounds a slow-loris that dribbles the response body.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard cap on a KBS response body. A `SignedResponse` is a few KiB;
/// the cap is generous but bounds a hostile/buggy KBS from driving an
/// unbounded allocation. A response OVER the cap is rejected outright
/// (not truncated) — see [`HttpClient::post_cbor`].
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

/// Env var the agent reads the KBS base URL from (dev / override).
pub const ENV_KBS_URL: &str = "HIPPIUS_KBS_URL";

/// `/proc/cmdline` key the agent reads the KBS base URL from in
/// production — `hippius.kbs_url=https://…`.
pub const CMDLINE_KBS_URL_KEY: &str = "hippius.kbs_url";

/// A fresh KBS-minted nonce (§20: 32 bytes, single-use, short TTL).
/// Non-secret — it ends up in `REPORT_DATA[0..32]`, published in the
/// SNP attestation report.
#[derive(Debug, Clone, Copy)]
pub struct KbsNonce(pub [u8; 32]);

/// A raw HTTP response: status code + body bytes. The status drives
/// the release / denial branch; the body is opaque CBOR.
///
/// No `Debug` — the body is a wire blob; a stray `dbg!()` should not
/// dump it (it is signed/wrapped, not plaintext, but the §20 posture
/// is to keep wire material out of logs regardless).
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body bytes (already bounded by [`MAX_RESPONSE_BYTES`]).
    pub body: Vec<u8>,
}

/// Minimal HTTP transport the KBS client runs over.
///
/// Production is [`ReqwestHttpClient`]; tests inject a mock that
/// returns canned (validly-signed) responses — see
/// `tests/kbs_integration.rs`. The trait is the seam that keeps the
/// integration tests off the network.
pub trait HttpClient {
    /// `POST` `body` to `url` with `Content-Type: application/cbor`.
    /// An `Err` is a transport failure (DNS / connect / TLS / timeout
    /// / oversized response) — never a non-2xx status, which is
    /// surfaced in [`HttpResponse::status`].
    fn post_cbor(&self, url: &str, body: &[u8]) -> Result<HttpResponse, AgentError>;
}

/// Production [`HttpClient`] — a `reqwest` blocking client with strict
/// timeouts and `rustls` TLS.
pub struct ReqwestHttpClient {
    client: reqwest::blocking::Client,
}

impl ReqwestHttpClient {
    /// Build the client with the §20 strict timeouts. No proxy, no
    /// redirect-following (the KBS URL is exact), `rustls` TLS.
    pub fn new() -> Result<Self, AgentError> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| AgentError::Kbs("http-client-build"))?;
        Ok(Self { client })
    }
}

impl HttpClient for ReqwestHttpClient {
    fn post_cbor(&self, url: &str, body: &[u8]) -> Result<HttpResponse, AgentError> {
        let response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .body(body.to_vec())
            .send()
            .map_err(|e| classify_reqwest_error(&e))?;
        let status = response.status().as_u16();
        let body = read_bounded(response)?;
        Ok(HttpResponse { status, body })
    }
}

/// Read a response body, hard-bounded by [`MAX_RESPONSE_BYTES`].
///
/// Reads ONE byte past the cap: if that byte materialises the body is
/// over-cap and is rejected outright (`response-too-large`) rather
/// than silently truncated into something that would later fail the
/// CBOR decode with a misleading class. The caller's request timeout
/// separately bounds a slow dribble.
fn read_bounded<R: Read>(reader: R) -> Result<Vec<u8>, AgentError> {
    let mut buf = Vec::new();
    reader
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|_| AgentError::Kbs("response-read"))?;
    if buf.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(AgentError::Kbs("response-too-large"));
    }
    Ok(buf)
}

/// Map a `reqwest` error to a static-classified [`AgentError::Kbs`].
/// The inner `&'static str` is a closed-vocabulary tag for internal
/// triage; `AgentError::Kbs`'s `Display` renders only `"kbs-failed"`,
/// so no URL / header / body context can leak through a log line.
fn classify_reqwest_error(e: &reqwest::Error) -> AgentError {
    if e.is_timeout() {
        AgentError::Kbs("timeout")
    } else if e.is_connect() {
        AgentError::Kbs("connect")
    } else {
        AgentError::Kbs("transport")
    }
}

/// Resolve the KBS base URL: the `HIPPIUS_KBS_URL` env var first (dev
/// / explicit override), then the `hippius.kbs_url=` token in
/// `/proc/cmdline` (production — baked into the measured UKI's kernel
/// command line, §20). Absent both ⇒ `Err`.
pub fn resolve_kbs_url() -> Result<String, AgentError> {
    if let Ok(url) = std::env::var(ENV_KBS_URL) {
        if !url.is_empty() {
            return Ok(url);
        }
    }
    let cmdline =
        std::fs::read_to_string("/proc/cmdline").map_err(|_| AgentError::Kbs("cmdline-read"))?;
    kbs_url_from_cmdline(&cmdline).ok_or(AgentError::Kbs("kbs-url-missing"))
}

/// Extract `hippius.kbs_url=<value>` from a `/proc/cmdline` string.
/// Pulled out so it is unit-testable without `/proc`.
pub fn kbs_url_from_cmdline(cmdline: &str) -> Option<String> {
    let prefix = format!("{CMDLINE_KBS_URL_KEY}=");
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix(&prefix))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Join a base URL and an absolute path, collapsing a doubled `/`.
fn join_url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// `POST /v1/kbs/nonce` — fetch a fresh single-use nonce.
///
/// The nonce endpoint takes no request body. The response is a
/// canonical-CBOR `{nonce: bstr}` map; the nonce MUST be exactly 32
/// bytes (§20) or the call fails closed.
pub fn fetch_nonce(http: &dyn HttpClient, base_url: &str) -> Result<KbsNonce, AgentError> {
    let url = join_url(base_url, "/v1/kbs/nonce");
    let response = http.post_cbor(&url, &[])?;
    if response.status != 200 {
        return Err(AgentError::Kbs("nonce-http-status"));
    }
    decode_nonce(&response.body)
}

/// Decode a canonical-CBOR nonce response into a [`KbsNonce`].
fn decode_nonce(body: &[u8]) -> Result<KbsNonce, AgentError> {
    assert_canonical(body).map_err(|_| AgentError::Kbs("nonce-non-canonical"))?;
    let value: Value =
        ciborium::de::from_reader(body).map_err(|_| AgentError::Kbs("nonce-decode"))?;
    let Value::Map(entries) = value else {
        return Err(AgentError::Kbs("nonce-decode"));
    };
    for (k, v) in entries {
        if matches!(&k, Value::Text(t) if t == "nonce") {
            let Value::Bytes(bytes) = v else {
                return Err(AgentError::Kbs("nonce-decode"));
            };
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| AgentError::Kbs("nonce-length"))?;
            return Ok(KbsNonce(arr));
        }
    }
    Err(AgentError::Kbs("nonce-decode"))
}

/// `POST /v1/kbs/release` — ship `{cose_ticket, snp_report, kbs_nonce}`
/// and receive a signed release response.
///
/// `cose_ticket` is the raw COSE_Sign1 bytes (this client never decodes
/// or verifies the ticket — the KBS verifies, §7). All three inputs are
/// required by §21 step 7. Returns:
/// - `Ok(SignedResponse)` on HTTP 200 — to be handed straight to
///   [`crate::stages::verify::verify_and_unwrap`] (this client does
///   NOT verify the signature — that is the §6/§7/§19/§20 gate's job).
/// - `Err(AgentError::KbsDenial)` on HTTP 403 — terminal (see module
///   docs). The signed denial body is not decoded: the agent has no
///   action to take on it but abort.
/// - `Err(AgentError::Kbs(_))` on any other status or a decode failure.
pub fn release(
    http: &dyn HttpClient,
    base_url: &str,
    cose_ticket: &[u8],
    nonce: &KbsNonce,
    report: &SnpReport,
    submitted_boot_counter: Option<u64>,
) -> Result<SignedResponse, AgentError> {
    let body = encode_release_request(cose_ticket, &report.0, &nonce.0, submitted_boot_counter)?;
    let url = join_url(base_url, "/v1/kbs/release");
    let response = http.post_cbor(&url, &body)?;
    match response.status {
        200 => decode_signed_response(&response.body),
        403 => Err(AgentError::KbsDenial),
        _ => Err(AgentError::Kbs("release-http-status")),
    }
}

/// Build the canonical-CBOR `ReleaseRequestBody`. Emits a 3-field map
/// `{cose_ticket, kbs_nonce, snp_report}` when `submitted_boot_counter`
/// is `None` (matches the pre-Phase-2A wire shape that older KBS
/// peers still parse with `#[serde(default)]`), or a 4-field map with
/// `submitted_boot_counter` included when `Some`. `to_canonical_vec`
/// sorts the keys to RFC 8949 §4.2.1 order, matching what
/// `kbs-server`'s `decode_canonical` expects.
fn encode_release_request(
    cose_ticket: &[u8],
    snp_report: &[u8],
    kbs_nonce: &[u8; 32],
    submitted_boot_counter: Option<u64>,
) -> Result<Vec<u8>, AgentError> {
    let mut entries = vec![
        (
            Value::Text("cose_ticket".into()),
            Value::Bytes(cose_ticket.to_vec()),
        ),
        (
            Value::Text("kbs_nonce".into()),
            Value::Bytes(kbs_nonce.to_vec()),
        ),
        (
            Value::Text("snp_report".into()),
            Value::Bytes(snp_report.to_vec()),
        ),
    ];
    if let Some(counter) = submitted_boot_counter {
        // Phase 2A — include the counter ONLY when the guest opts
        // in. Sending `None` over the wire (encoded as a CBOR null)
        // would round-trip to `Some(0)` via the `Option<u64>` serde
        // path on some older runtimes; omitting the field entirely
        // is the unambiguous "not present" signal.
        entries.push((
            Value::Text("submitted_boot_counter".into()),
            Value::Integer(counter.into()),
        ));
    }
    let value = Value::Map(entries);
    to_canonical_vec(&value).map_err(|_| AgentError::Kbs("request-encode"))
}

/// Decode a canonical-CBOR `SignedResponse` from a 200 body.
fn decode_signed_response(body: &[u8]) -> Result<SignedResponse, AgentError> {
    assert_canonical(body).map_err(|_| AgentError::Kbs("response-non-canonical"))?;
    ciborium::de::from_reader(body).map_err(|_| AgentError::Kbs("response-decode"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A canned-response [`HttpClient`] for the transport-branching
    /// unit tests. Records the last URL + body it was POSTed.
    struct CannedHttp {
        status: u16,
        body: Vec<u8>,
        last_url: RefCell<Option<String>>,
        last_body: RefCell<Option<Vec<u8>>>,
    }

    impl CannedHttp {
        fn new(status: u16, body: Vec<u8>) -> Self {
            Self {
                status,
                body,
                last_url: RefCell::new(None),
                last_body: RefCell::new(None),
            }
        }
    }

    impl HttpClient for CannedHttp {
        fn post_cbor(&self, url: &str, body: &[u8]) -> Result<HttpResponse, AgentError> {
            *self.last_url.borrow_mut() = Some(url.to_string());
            *self.last_body.borrow_mut() = Some(body.to_vec());
            Ok(HttpResponse {
                status: self.status,
                body: self.body.clone(),
            })
        }
    }

    fn canonical_nonce_body(nonce: &[u8]) -> Vec<u8> {
        to_canonical_vec(&Value::Map(vec![(
            Value::Text("nonce".into()),
            Value::Bytes(nonce.to_vec()),
        )]))
        .unwrap()
    }

    #[test]
    fn join_url_collapses_double_slash() {
        assert_eq!(
            join_url("https://kbs.internal/", "/v1/kbs/release"),
            "https://kbs.internal/v1/kbs/release"
        );
        assert_eq!(
            join_url("https://kbs.internal", "/v1/kbs/nonce"),
            "https://kbs.internal/v1/kbs/nonce"
        );
    }

    #[test]
    fn kbs_url_from_cmdline_extracts_the_token() {
        let line = "ro quiet hippius.kbs_url=https://kbs.vrack:8443 console=ttyS0";
        assert_eq!(
            kbs_url_from_cmdline(line).as_deref(),
            Some("https://kbs.vrack:8443")
        );
        assert_eq!(kbs_url_from_cmdline("ro quiet console=ttyS0"), None);
        // An empty value is treated as absent.
        assert_eq!(kbs_url_from_cmdline("hippius.kbs_url="), None);
    }

    #[test]
    fn fetch_nonce_decodes_a_32_byte_nonce() {
        let http = CannedHttp::new(200, canonical_nonce_body(&[0xABu8; 32]));
        let nonce = fetch_nonce(&http, "https://kbs.internal").unwrap();
        assert_eq!(nonce.0, [0xABu8; 32]);
        // The nonce endpoint is POSTed with no body.
        assert_eq!(http.last_body.borrow().as_deref(), Some(&[][..]));
        assert_eq!(
            http.last_url.borrow().as_deref(),
            Some("https://kbs.internal/v1/kbs/nonce")
        );
    }

    #[test]
    fn fetch_nonce_rejects_a_wrong_length_nonce() {
        let http = CannedHttp::new(200, canonical_nonce_body(&[0u8; 16]));
        assert!(matches!(
            fetch_nonce(&http, "https://kbs.internal"),
            Err(AgentError::Kbs("nonce-length"))
        ));
    }

    #[test]
    fn fetch_nonce_rejects_a_non_200_status() {
        let http = CannedHttp::new(500, Vec::new());
        assert!(matches!(
            fetch_nonce(&http, "https://kbs.internal"),
            Err(AgentError::Kbs("nonce-http-status"))
        ));
    }

    #[test]
    fn release_maps_403_to_a_terminal_denial() {
        // A 403 is a KBS denial — terminal, no retry. The denial body
        // is intentionally not decoded.
        let http = CannedHttp::new(403, b"signed-denial-bytes".to_vec());
        let report = SnpReport(vec![0u8; crate::stages::snp_report::SNP_REPORT_LEN]);
        assert!(matches!(
            release(
                &http,
                "https://kbs.internal",
                &[1, 2, 3],
                &KbsNonce([0u8; 32]),
                &report,
                None,
            ),
            Err(AgentError::KbsDenial)
        ));
    }

    #[test]
    fn release_maps_unexpected_status_to_a_kbs_error() {
        let http = CannedHttp::new(503, Vec::new());
        let report = SnpReport(vec![0u8; crate::stages::snp_report::SNP_REPORT_LEN]);
        assert!(matches!(
            release(
                &http,
                "https://kbs.internal",
                &[1, 2, 3],
                &KbsNonce([0u8; 32]),
                &report,
                None,
            ),
            Err(AgentError::Kbs("release-http-status"))
        ));
    }

    #[test]
    fn read_bounded_accepts_a_body_at_the_cap() {
        let body = vec![0u8; 4096];
        assert_eq!(read_bounded(&body[..]).unwrap().len(), 4096);
    }

    #[test]
    fn read_bounded_rejects_an_over_cap_body() {
        // One byte past the cap → rejected outright, not truncated.
        let oversized = vec![0u8; (MAX_RESPONSE_BYTES + 1) as usize];
        assert!(matches!(
            read_bounded(&oversized[..]),
            Err(AgentError::Kbs("response-too-large"))
        ));
    }

    #[test]
    fn encoded_release_request_is_canonical_and_round_trips() {
        let body = encode_release_request(&[1, 2, 3], &[4, 5, 6], &[7u8; 32], None).unwrap();
        assert_canonical(&body).expect("request body must be canonical CBOR");
        let value: Value = ciborium::de::from_reader(body.as_slice()).unwrap();
        let Value::Map(entries) = value else {
            panic!("request body is not a map");
        };
        // The 3 §21-step-7 fields, all present.
        let keys: Vec<&str> = entries
            .iter()
            .filter_map(|(k, _)| match k {
                Value::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert!(keys.contains(&"cose_ticket"));
        assert!(keys.contains(&"snp_report"));
        assert!(keys.contains(&"kbs_nonce"));
        // `None` means the counter field is OMITTED — same wire as
        // pre-Phase-2A guests, see Review audit #2.
        assert!(!keys.contains(&"submitted_boot_counter"));
        assert_eq!(keys.len(), 3);
    }

    /// Phase 2A — when the guest opts in by passing `Some(n)`, the
    /// counter field MUST appear in the encoded request body. The
    /// canonical-CBOR encoder sorts the keys, so the new field shows
    /// up exactly once in the right position.
    #[test]
    fn encoded_release_request_with_counter_includes_field() {
        let body = encode_release_request(&[1, 2, 3], &[4, 5, 6], &[7u8; 32], Some(42)).unwrap();
        assert_canonical(&body).expect("request body must be canonical CBOR");
        let value: Value = ciborium::de::from_reader(body.as_slice()).unwrap();
        let Value::Map(entries) = value else {
            panic!("request body is not a map");
        };
        let keys: Vec<&str> = entries
            .iter()
            .filter_map(|(k, _)| match k {
                Value::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert!(keys.contains(&"submitted_boot_counter"));
        assert_eq!(keys.len(), 4);
        // Extract the counter value and pin it.
        let counter = entries
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Text(t), Value::Integer(i)) if t == "submitted_boot_counter" => {
                    let n: u64 = (*i).try_into().ok()?;
                    Some(n)
                }
                _ => None,
            })
            .expect("counter field is an integer");
        assert_eq!(counter, 42);
    }
}
