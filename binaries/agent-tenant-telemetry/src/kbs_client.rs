//! KBS HTTP client for the §23 telemetry-key certification flow.
//!
//! Mirrors the initramfs agent's KBS client (`reqwest` + `rustls`,
//! strict connect/request timeouts, hard-bounded response body, **no
//! retry**, fail-closed, opaque logging — only static error classes).
//! A shared `kbs-http` crate is a deliberate future refactor; for
//! PR-E2.1 the client is duplicated rather than churning the closed
//! E1 sub-track.
//!
//! Two endpoints:
//! - `POST /v1/kbs/nonce` → a fresh single-use 32-byte nonce.
//! - `POST /v1/kbs/telemetry-cert` → `{kbs_nonce, node_id,
//!   signer_pubkey, snp_report, vm_id}` in; a [`SignedTelemetryCert`]
//!   out (HTTP 200), or a terminal denial (HTTP 403).
//!
//! No retry: the SNP report is bound to a single-use nonce, so a retry
//! would have to re-attest with a fresh one — that is a future agent-
//! loop concern, not the transport's. Any failure aborts establishment.

use std::io::Read;
use std::time::Duration;

use ciborium::value::Value;
use hippius_types::cbor::{assert_canonical, to_canonical_vec};
use hippius_types::telemetry_cert::SignedTelemetryCert;

use crate::error::{Result, TelemetryError};
use crate::snp::SnpReport;

/// Content-Type the KBS speaks — deterministic CBOR.
const CONTENT_TYPE_CBOR: &str = "application/cbor";

/// Strict connect timeout — bounds slow-loris on connection setup.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Strict whole-request timeout — bounds a dribbled response.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard cap on a KBS response body. A `SignedTelemetryCert` is a few
/// hundred bytes; the cap is generous but bounds a hostile/buggy KBS.
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

/// A fresh KBS-minted nonce (§20: 32 bytes, single-use). Non-secret —
/// it lands in `REPORT_DATA[0..32]`, published in the attestation.
#[derive(Debug, Clone, Copy)]
pub struct KbsNonce(pub [u8; 32]);

/// A raw HTTP response: status + body. No `Debug` — the body is wire
/// material and is kept out of logs by discipline.
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Minimal HTTP transport the KBS client runs over. Production:
/// [`ReqwestHttpClient`]; tests inject a canned client.
pub trait HttpClient {
    /// `POST` `body` to `url` as `application/cbor`. `Err` is a
    /// transport failure — never a non-2xx status (that is in
    /// [`HttpResponse::status`]).
    fn post_cbor(&self, url: &str, body: &[u8]) -> Result<HttpResponse>;
}

/// Production [`HttpClient`] — `reqwest` blocking + `rustls` TLS, with
/// the §20 strict timeouts. The KBS response's authenticity rests on
/// the KBS Ed25519 signature the guest verifies, not on TLS.
pub struct ReqwestHttpClient {
    client: reqwest::blocking::Client,
}

impl ReqwestHttpClient {
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| TelemetryError::Kbs("http-client-build"))?;
        Ok(Self { client })
    }
}

impl HttpClient for ReqwestHttpClient {
    fn post_cbor(&self, url: &str, body: &[u8]) -> Result<HttpResponse> {
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

/// Read a response body, hard-bounded by [`MAX_RESPONSE_BYTES`]. Reads
/// one byte past the cap so an over-cap body is rejected outright,
/// never silently truncated.
fn read_bounded<R: Read>(reader: R) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|_| TelemetryError::Kbs("response-read"))?;
    if buf.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(TelemetryError::Kbs("response-too-large"));
    }
    Ok(buf)
}

/// Map a `reqwest` error to a static-classified [`TelemetryError::Kbs`]
/// — no URL / header / body context can leak through.
fn classify_reqwest_error(e: &reqwest::Error) -> TelemetryError {
    if e.is_timeout() {
        TelemetryError::Kbs("timeout")
    } else if e.is_connect() {
        TelemetryError::Kbs("connect")
    } else {
        TelemetryError::Kbs("transport")
    }
}

/// Join a base URL and an absolute path, collapsing a doubled `/`.
fn join_url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// `POST /v1/kbs/nonce` — fetch a fresh single-use nonce.
pub fn fetch_nonce(http: &dyn HttpClient, base_url: &str) -> Result<KbsNonce> {
    let url = join_url(base_url, "/v1/kbs/nonce");
    let response = http.post_cbor(&url, &[])?;
    if response.status != 200 {
        return Err(TelemetryError::Kbs("nonce-http-status"));
    }
    decode_nonce(&response.body)
}

/// Decode a canonical-CBOR `{nonce: bstr}` response into a [`KbsNonce`].
///
/// The response schema is **exactly** a one-field `{nonce}` map — any
/// extra key is rejected fail-closed (strict KBS wire-schema hygiene).
fn decode_nonce(body: &[u8]) -> Result<KbsNonce> {
    assert_canonical(body).map_err(|_| TelemetryError::Kbs("nonce-non-canonical"))?;
    let value: Value =
        ciborium::de::from_reader(body).map_err(|_| TelemetryError::Kbs("nonce-decode"))?;
    let Value::Map(entries) = value else {
        return Err(TelemetryError::Kbs("nonce-decode"));
    };
    // Exactly one entry, `nonce` → a byte string. 0 / 2+ entries, a
    // non-text key, or a non-bytes value all fail the pattern.
    let [(Value::Text(key), Value::Bytes(bytes))] = entries.as_slice() else {
        return Err(TelemetryError::Kbs("nonce-decode"));
    };
    if key != "nonce" {
        return Err(TelemetryError::Kbs("nonce-decode"));
    }
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| TelemetryError::Kbs("nonce-length"))?;
    Ok(KbsNonce(arr))
}

/// `POST /v1/kbs/telemetry-cert` — attest the guest-generated signer
/// public key and obtain the KBS-signed [`SignedTelemetryCert`].
///
/// - `Ok(SignedTelemetryCert)` on HTTP 200 — handed to
///   [`hippius_guest::verify_telemetry_cert`] (this client does NOT
///   verify the signature).
/// - `Err(TelemetryError::Kbs("cert-denied"))` on HTTP 403 — terminal.
/// - `Err` on any other status / decode failure.
pub fn request_telemetry_cert(
    http: &dyn HttpClient,
    base_url: &str,
    nonce: &KbsNonce,
    signer_pubkey: &[u8; 32],
    node_id: &[u8],
    vm_id: &str,
    report: &SnpReport,
) -> Result<SignedTelemetryCert> {
    let body = encode_cert_request(&nonce.0, node_id, signer_pubkey, &report.0, vm_id)?;
    let url = join_url(base_url, "/v1/kbs/telemetry-cert");
    let response = http.post_cbor(&url, &body)?;
    match response.status {
        200 => decode_signed_cert(&response.body),
        403 => Err(TelemetryError::Kbs("cert-denied")),
        _ => Err(TelemetryError::Kbs("cert-http-status")),
    }
}

/// Build the canonical-CBOR telemetry-cert request body — a 5-field
/// map. `to_canonical_vec` sorts the keys to RFC 8949 §4.2.1 order.
fn encode_cert_request(
    kbs_nonce: &[u8; 32],
    node_id: &[u8],
    signer_pubkey: &[u8; 32],
    snp_report: &[u8],
    vm_id: &str,
) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::Text("kbs_nonce".into()),
            Value::Bytes(kbs_nonce.to_vec()),
        ),
        (
            Value::Text("node_id".into()),
            Value::Bytes(node_id.to_vec()),
        ),
        (
            Value::Text("signer_pubkey".into()),
            Value::Bytes(signer_pubkey.to_vec()),
        ),
        (
            Value::Text("snp_report".into()),
            Value::Bytes(snp_report.to_vec()),
        ),
        (Value::Text("vm_id".into()), Value::Text(vm_id.into())),
    ]);
    to_canonical_vec(&value).map_err(|_| TelemetryError::Kbs("request-encode"))
}

/// Decode a canonical-CBOR [`SignedTelemetryCert`] from a 200 body.
fn decode_signed_cert(body: &[u8]) -> Result<SignedTelemetryCert> {
    assert_canonical(body).map_err(|_| TelemetryError::Kbs("cert-non-canonical"))?;
    ciborium::de::from_reader(body).map_err(|_| TelemetryError::Kbs("cert-decode"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A canned-response [`HttpClient`] — records the last POST.
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
        fn post_cbor(&self, url: &str, body: &[u8]) -> Result<HttpResponse> {
            *self.last_url.borrow_mut() = Some(url.to_string());
            *self.last_body.borrow_mut() = Some(body.to_vec());
            Ok(HttpResponse {
                status: self.status,
                body: self.body.clone(),
            })
        }
    }

    fn nonce_body(nonce: &[u8]) -> Vec<u8> {
        to_canonical_vec(&Value::Map(vec![(
            Value::Text("nonce".into()),
            Value::Bytes(nonce.to_vec()),
        )]))
        .unwrap()
    }

    #[test]
    fn join_url_collapses_double_slash() {
        assert_eq!(
            join_url("https://kbs/", "/v1/kbs/telemetry-cert"),
            "https://kbs/v1/kbs/telemetry-cert"
        );
        assert_eq!(
            join_url("https://kbs", "/v1/kbs/nonce"),
            "https://kbs/v1/kbs/nonce"
        );
    }

    #[test]
    fn fetch_nonce_decodes_a_32_byte_nonce() {
        let http = CannedHttp::new(200, nonce_body(&[0xABu8; 32]));
        let nonce = fetch_nonce(&http, "https://kbs").unwrap();
        assert_eq!(nonce.0, [0xABu8; 32]);
        assert_eq!(http.last_body.borrow().as_deref(), Some(&[][..]));
    }

    #[test]
    fn fetch_nonce_rejects_a_wrong_length_nonce() {
        let http = CannedHttp::new(200, nonce_body(&[0u8; 16]));
        assert!(matches!(
            fetch_nonce(&http, "https://kbs"),
            Err(TelemetryError::Kbs("nonce-length"))
        ));
    }

    #[test]
    fn fetch_nonce_rejects_a_nonce_response_with_extra_fields() {
        // The nonce schema is exactly `{nonce}` — an extra key is a
        // malformed response and must be rejected fail-closed.
        let body = to_canonical_vec(&Value::Map(vec![
            (Value::Text("extra".into()), Value::Integer(1.into())),
            (Value::Text("nonce".into()), Value::Bytes(vec![0xABu8; 32])),
        ]))
        .unwrap();
        let http = CannedHttp::new(200, body);
        assert!(fetch_nonce(&http, "https://kbs").is_err());
    }

    #[test]
    fn fetch_nonce_rejects_a_non_200_status() {
        let http = CannedHttp::new(500, Vec::new());
        assert!(matches!(
            fetch_nonce(&http, "https://kbs"),
            Err(TelemetryError::Kbs("nonce-http-status"))
        ));
    }

    #[test]
    fn cert_request_body_is_canonical_with_five_fields() {
        let body =
            encode_cert_request(&[1u8; 32], b"node-1", &[2u8; 32], &[3, 4, 5], "vm-1").unwrap();
        assert_canonical(&body).expect("request body must be canonical CBOR");
        let value: Value = ciborium::de::from_reader(body.as_slice()).unwrap();
        let Value::Map(entries) = value else {
            panic!("not a map");
        };
        let keys: Vec<&str> = entries
            .iter()
            .filter_map(|(k, _)| match k {
                Value::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(keys.len(), 5);
        for want in [
            "kbs_nonce",
            "node_id",
            "signer_pubkey",
            "snp_report",
            "vm_id",
        ] {
            assert!(keys.contains(&want), "missing field {want}");
        }
    }

    #[test]
    fn request_telemetry_cert_maps_403_to_a_terminal_denial() {
        let http = CannedHttp::new(403, b"denial".to_vec());
        let report = SnpReport(vec![0u8; crate::snp::SNP_REPORT_LEN]);
        assert!(matches!(
            request_telemetry_cert(
                &http,
                "https://kbs",
                &KbsNonce([0u8; 32]),
                &[0u8; 32],
                b"node-1",
                "vm-1",
                &report,
            ),
            Err(TelemetryError::Kbs("cert-denied"))
        ));
    }

    #[test]
    fn request_telemetry_cert_maps_unexpected_status_to_an_error() {
        let http = CannedHttp::new(503, Vec::new());
        let report = SnpReport(vec![0u8; crate::snp::SNP_REPORT_LEN]);
        assert!(matches!(
            request_telemetry_cert(
                &http,
                "https://kbs",
                &KbsNonce([0u8; 32]),
                &[0u8; 32],
                b"node-1",
                "vm-1",
                &report,
            ),
            Err(TelemetryError::Kbs("cert-http-status"))
        ));
    }

    #[test]
    fn read_bounded_rejects_an_over_cap_body() {
        let oversized = vec![0u8; (MAX_RESPONSE_BYTES + 1) as usize];
        assert!(matches!(
            read_bounded(&oversized[..]),
            Err(TelemetryError::Kbs("response-too-large"))
        ));
    }
}
