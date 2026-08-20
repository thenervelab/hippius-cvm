//! KBS HTTP client used by the keepalive agent.
//!
//! Two operations:
//! - `fetch_nonce` — POST `/v1/kbs/nonce`, decode `NonceResponse`.
//! - `post_keepalive` — POST `/v1/attest/keepalive`, decode
//!   `KeepaliveResponseBody`.
//!
//! ## Two transports, selected by the URL scheme
//!
//! A production tenant CVM has **no route to the KBS**: it reaches it
//! through the host miner-agent's AF_VSOCK proxy, addressed as
//! `vsock://2:19266` on the measured cmdline (`hippius.kbs_url`). An
//! `https://` client alone would therefore fail on every real boot
//! while every https-based test passed — the same asymmetry that has
//! bitten the release + volume-stamp paths here before. So `KbsClient`
//! dispatches on the scheme exactly like the §21 release path does,
//! reusing that path's `VsockHttpClient` rather than re-deriving the
//! framing:
//!
//! - `vsock://CID:PORT` → the miner-agent KBS proxy (production);
//! - anything else → a direct `reqwest` HTTPS client (dev / staging).
//!
//! Both KBS paths the agent uses (`/v1/kbs/nonce`,
//! `/v1/attest/keepalive`) are in
//! [`hippius_types::kbs_vsock::ALLOWED_PATHS`], which the guest checks
//! before emitting a frame and the host re-checks before forwarding.
//!
//! Both use canonical CBOR on the wire (same discipline as the
//! release path). Errors are mapped to a small closed-vocabulary
//! enum so the per-tick log line never interpolates an inner library
//! message — the keepalive flow runs forever; one classifier per
//! failure class is enough to drive an operator alert without
//! flooding the journal.

use hippius_agent_initramfs::stages::kbs_client::HttpClient;
use hippius_agent_initramfs::stages::kbs_vsock_client::{is_vsock_url, VsockHttpClient};
use hippius_types::cbor::{assert_canonical, to_canonical_vec};
use hippius_types::kbs_vsock::{KBS_KEEPALIVE_PATH, KBS_NONCE_PATH};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::time::Duration;
use thiserror::Error;

/// Closed-vocabulary error class. `Debug`/`Display` derived from
/// `thiserror` — call sites log `{:?}` to get the variant name (a
/// short `&'static str` classifier) without ever leaking inner
/// transport / decode messages.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("kbs-connect")]
    Connect,
    #[error("kbs-status")]
    Status,
    #[error("kbs-body")]
    Body,
    #[error("kbs-encode")]
    Encode,
    #[error("kbs-decode")]
    Decode,
    #[error("kbs-noncanon")]
    NonCanonical,
}

/// Same wire shape as `kbs_transport::wire::NonceResponse`. Duplicated
/// locally so this binary doesn't drag `kbs-server` (axum + tower-
/// http + …) into the guest image.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NonceResponse {
    nonce: ByteBuf,
}

/// Mirror of `kbs_transport::wire::KeepaliveRequestBody`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeepaliveRequestBody<'a> {
    vm_id: &'a str,
    node_id: ByteBuf,
    snp_report: ByteBuf,
    kbs_nonce: ByteBuf,
    epoch: u64,
    expiry_unix: u64,
}

/// Mirror of `kbs_transport::wire::KeepaliveResponseBody`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeepaliveResponseBody {
    /// `hippius_types::live_attestation::SignedLiveAttestation::encode`
    /// bytes the validator forwards verbatim to the pallet.
    pub signed_live_attestation: ByteBuf,
}

/// The wire transport one `KbsClient` speaks.
enum Transport {
    /// Direct HTTPS (dev / staging). One `reqwest::blocking::Client`
    /// reused across every tick — connection pooling amortizes the TLS
    /// handshake cost in the steady state.
    Https(reqwest::blocking::Client),
    /// AF_VSOCK relay through the host miner-agent's KBS proxy — what a
    /// production tenant CVM uses (`hippius.kbs_url=vsock://2:19266`).
    /// Stateless: one short-lived connection per request.
    Vsock(VsockHttpClient),
}

/// Transport handle.
pub struct KbsClient {
    base_url: String,
    transport: Transport,
}

impl KbsClient {
    /// Build a client pointing at `base_url`. `base_url` MUST NOT
    /// have a trailing slash (the routes start with `/v1/...`); a
    /// trailing slash is tolerated at runtime via a `trim_end_matches`.
    ///
    /// The scheme picks the transport: `vsock://CID:PORT` relays through
    /// the host miner-agent's KBS proxy (production), anything else goes
    /// straight out over HTTPS (dev / staging).
    pub fn new(base_url: impl Into<String>) -> Result<Self, ClientError> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let transport = if is_vsock_url(&base_url) {
            Transport::Vsock(VsockHttpClient::new())
        } else {
            Transport::Https(
                reqwest::blocking::Client::builder()
                    .connect_timeout(Duration::from_secs(5))
                    .timeout(Duration::from_secs(30))
                    .build()
                    .map_err(|_| ClientError::Connect)?,
            )
        };
        Ok(Self {
            base_url,
            transport,
        })
    }

    /// `true` iff this client relays through the host vsock proxy.
    /// Exposed so a caller (and the tests) can assert WHICH transport a
    /// URL selected — an https client built for a `vsock://` production
    /// URL would fail every tick with a generic `kbs-connect`.
    pub fn is_vsock(&self) -> bool {
        matches!(self.transport, Transport::Vsock(_))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// POST `body` as `application/cbor` to `path` and return the
    /// response body, mapping a non-2xx status to [`ClientError::Status`].
    /// One place, so both operations get identical transport dispatch +
    /// status handling.
    fn post_cbor(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, ClientError> {
        let url = self.url(path);
        match &self.transport {
            Transport::Https(http) => {
                let resp = http
                    .post(&url)
                    .header("content-type", "application/cbor")
                    .body(body)
                    .send()
                    .map_err(|_| ClientError::Connect)?;
                if !resp.status().is_success() {
                    return Err(ClientError::Status);
                }
                Ok(resp.bytes().map_err(|_| ClientError::Body)?.to_vec())
            }
            Transport::Vsock(vsock) => {
                // `post_cbor` errors here are transport failures (the
                // guest-side allow-list check, the dial, the framing);
                // a KBS 4xx/5xx comes back as a non-2xx `status`.
                let resp = vsock
                    .post_cbor(&url, &body)
                    .map_err(|_| ClientError::Connect)?;
                if !(200..300).contains(&resp.status) {
                    return Err(ClientError::Status);
                }
                Ok(resp.body)
            }
        }
    }

    /// `POST /v1/kbs/nonce` — same endpoint the release path uses.
    /// Returns the 32-byte nonce the guest folds into
    /// `REPORT_DATA[0..32]`.
    pub fn fetch_nonce(&self) -> Result<[u8; 32], ClientError> {
        let bytes = self.post_cbor(KBS_NONCE_PATH, Vec::new())?;
        assert_canonical(&bytes).map_err(|_| ClientError::NonCanonical)?;
        let body: NonceResponse =
            ciborium::de::from_reader(bytes.as_slice()).map_err(|_| ClientError::Decode)?;
        let nonce_bytes = body.nonce.to_vec();
        let arr: [u8; 32] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ClientError::Decode)?;
        Ok(arr)
    }

    /// `POST /v1/attest/keepalive` — verify-and-sign one live
    /// attestation. Returns the `SignedLiveAttestation::encode`
    /// bytes the validator (or KBS sink) ships on-chain.
    pub fn post_keepalive(
        &self,
        vm_id: &str,
        node_id: &[u8; 32],
        snp_report: &[u8],
        kbs_nonce: &[u8; 32],
        epoch: u64,
        expiry_unix: u64,
    ) -> Result<Vec<u8>, ClientError> {
        let body = KeepaliveRequestBody {
            vm_id,
            node_id: ByteBuf::from(node_id.to_vec()),
            snp_report: ByteBuf::from(snp_report.to_vec()),
            kbs_nonce: ByteBuf::from(kbs_nonce.to_vec()),
            epoch,
            expiry_unix,
        };
        let encoded = encode_canonical(&body)?;
        let bytes = self.post_cbor(KBS_KEEPALIVE_PATH, encoded)?;
        assert_canonical(&bytes).map_err(|_| ClientError::NonCanonical)?;
        let parsed: KeepaliveResponseBody =
            ciborium::de::from_reader(bytes.as_slice()).map_err(|_| ClientError::Decode)?;
        Ok(parsed.signed_live_attestation.to_vec())
    }
}

/// Canonical-CBOR encode helper. Same round-trip-through-Value
/// discipline as `kbs_transport::wire::encode_cbor`: ciborium's serde
/// encoder emits fields in declaration order, so we encode to a
/// `Value` first then re-emit with the canonical sort.
fn encode_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, ClientError> {
    let mut interim = Vec::new();
    ciborium::ser::into_writer(value, &mut interim).map_err(|_| ClientError::Encode)?;
    let val: ciborium::value::Value =
        ciborium::de::from_reader(interim.as_slice()).map_err(|_| ClientError::Encode)?;
    to_canonical_vec(&val).map_err(|_| ClientError::Encode)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The production tenant CVM has no route to the KBS: `hippius.kbs_url`
    /// is `vsock://2:19266` and the request must go through the host
    /// miner-agent's proxy. A client that built an HTTPS transport for that
    /// URL would fail EVERY tick with a generic `kbs-connect` — no
    /// `VmLiveAttestation` would ever land — while every https-based test
    /// kept passing. This pins the dispatch.
    #[test]
    fn a_vsock_url_selects_the_vsock_transport() {
        let c = KbsClient::new("vsock://2:19266").expect("client builds");
        assert!(c.is_vsock(), "vsock:// must not build an HTTPS client");
    }

    #[test]
    fn an_https_url_selects_the_https_transport() {
        let c = KbsClient::new("https://kbs.hippius.network").expect("client builds");
        assert!(!c.is_vsock(), "https:// must not build a vsock client");
    }

    /// Both KBS endpoints the agent calls must compose onto the base URL
    /// as `vsock://CID:PORT/v1/...` — the shape `parse_vsock_url` splits
    /// into an authority + an allow-listed path.
    #[test]
    fn urls_compose_onto_a_vsock_base() {
        let c = KbsClient::new("vsock://2:19266/").expect("client builds");
        assert_eq!(c.url(KBS_NONCE_PATH), "vsock://2:19266/v1/kbs/nonce");
        assert_eq!(
            c.url(KBS_KEEPALIVE_PATH),
            "vsock://2:19266/v1/attest/keepalive"
        );
    }

    /// Both paths the keepalive agent posts to must be forwardable by the
    /// proxy. The guest refuses to even emit a frame for a path outside
    /// the list (`vsock-path-forbidden`), so an omission here is a
    /// fail-closed production outage that no https test can see.
    #[test]
    fn both_keepalive_paths_are_proxy_forwardable() {
        assert!(hippius_types::kbs_vsock::is_allowed_path(KBS_NONCE_PATH));
        assert!(hippius_types::kbs_vsock::is_allowed_path(
            KBS_KEEPALIVE_PATH
        ));
    }

    /// The paths are the KBS's real routes — a drift here is a 404 the
    /// agent reports as an opaque `kbs-status`.
    #[test]
    fn the_paths_are_the_kbs_routes() {
        assert_eq!(KBS_NONCE_PATH, "/v1/kbs/nonce");
        assert_eq!(KBS_KEEPALIVE_PATH, "/v1/attest/keepalive");
    }
}
