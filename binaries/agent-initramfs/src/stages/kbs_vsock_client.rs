//! Guest-side [`HttpClient`] that relays the §21 KBS exchange over
//! **AF_VSOCK** to the miner-agent, instead of reaching the KBS over
//! the network.
//!
//! The tenant CVM has no route to the in-cluster KBS (a mesh-only
//! cluster address) —
//! routing its traffic through the host's NetBird mesh is fragile and
//! broke in practice. Instead the guest dials the miner-agent on the
//! host (`vsock://2:PORT`) and the agent proxies the two KBS POSTs
//! (`/v1/kbs/nonce`, `/v1/kbs/release`) to the real KBS over the host's
//! network. The guest needs no DNS, no route, no mesh — only the vsock
//! channel it already uses for the OrderTicket.
//!
//! This implements the SAME [`HttpClient`] trait the network path uses,
//! so `kbs_client::fetch_nonce` / `release` are unchanged — only the
//! transport flips, selected by the `--kbs-url` scheme.

use std::io::{Read, Write};

use hippius_types::guardian::{
    is_guardian_allowed_path, GUARDIAN_MAX_REQUEST_BYTES, GUARDIAN_MAX_RESPONSE_BYTES,
    GUARDIAN_RECIPE_PATH, GUARDIAN_VSOCK_PORT,
};
use hippius_types::kbs_vsock::{
    is_allowed_path, KbsProxyRequest, KbsProxyResponse, MAX_RESPONSE_BYTES,
};
use serde_bytes::ByteBuf;

use super::kbs_client::{HttpClient, HttpResponse};
use crate::pipeline::AgentError;

/// `true` iff `url` selects the vsock transport (`vsock://CID:PORT`).
pub fn is_vsock_url(url: &str) -> bool {
    url.starts_with("vsock://")
}

/// Parsed `vsock://<cid>:<port>` authority. `path` is taken per-request
/// from the full URL (`vsock://cid:port/v1/kbs/nonce`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsockTarget {
    pub cid: u32,
    pub port: u32,
}

/// Split `vsock://<cid>:<port>/<path>` into the target authority and
/// the path. `cid` may be empty (`vsock://:port/...`) → defaults to the
/// host CID. A missing/empty path is rejected.
pub fn parse_vsock_url(url: &str) -> Result<(VsockTarget, String), AgentError> {
    let rest = url
        .strip_prefix("vsock://")
        .ok_or(AgentError::Kbs("vsock-url-scheme"))?;
    // Authority is up to the first '/'; the remainder (incl. the '/')
    // is the path.
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if path.is_empty() {
        return Err(AgentError::Kbs("vsock-url-path"));
    }
    let (cid_s, port_s) = authority
        .rsplit_once(':')
        .ok_or(AgentError::Kbs("vsock-url-authority"))?;
    let cid = if cid_s.is_empty() {
        hippius_types::kbs_vsock::HOST_CID
    } else {
        cid_s
            .parse()
            .map_err(|_| AgentError::Kbs("vsock-url-cid"))?
    };
    let port: u32 = port_s
        .parse()
        .map_err(|_| AgentError::Kbs("vsock-url-port"))?;
    Ok((VsockTarget { cid, port }, path.to_string()))
}

/// Guest-side KBS transport over AF_VSOCK. Stateless: each `post_cbor`
/// opens one short-lived connection (one request → one response), so a
/// boot-race or a dropped link is just a retry at the `kbs_client`
/// layer, exactly like the HTTP path.
pub struct VsockHttpClient;

impl VsockHttpClient {
    pub fn new() -> Self {
        Self
    }
}

impl Default for VsockHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for VsockHttpClient {
    fn post_cbor(&self, url: &str, body: &[u8]) -> Result<HttpResponse, AgentError> {
        let (target, path) = parse_vsock_url(url)?;
        // Defence-in-depth: the host enforces this too, but refuse to
        // even emit a frame for a non-KBS path (no SSRF carrier).
        if !is_allowed_path(&path) {
            return Err(AgentError::Kbs("vsock-path-forbidden"));
        }
        let req = KbsProxyRequest {
            path,
            body: ByteBuf::from(body.to_vec()),
        };
        let mut frame = Vec::new();
        ciborium::ser::into_writer(&req, &mut frame)
            .map_err(|_| AgentError::Kbs("vsock-encode"))?;
        let resp = vsock_exchange(target, &frame)?;
        let resp: KbsProxyResponse =
            ciborium::de::from_reader(&resp[..]).map_err(|_| AgentError::Kbs("vsock-decode"))?;
        Ok(HttpResponse {
            status: resp.status,
            body: resp.body.into_vec(),
        })
    }
}

/// Guest-side transport for the customer-held-keys **guardian relay**
/// (`vsock://2:`[`GUARDIAN_VSOCK_PORT`]). Same framing and one-exchange-
/// per-connection discipline as [`VsockHttpClient`]; the only difference
/// is the closed path list — the guardian paths plus the relay-local
/// recipe path, never a KBS path (and the KBS client never emits a
/// guardian one), so neither relay can be asked to carry the other's
/// traffic.
pub struct GuardianVsockClient;

impl GuardianVsockClient {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GuardianVsockClient {
    fn default() -> Self {
        Self::new()
    }
}

/// The guardian relay's base URL: the host CID on [`GUARDIAN_VSOCK_PORT`].
pub fn guardian_relay_url() -> String {
    format!(
        "vsock://{}:{}",
        hippius_types::kbs_vsock::HOST_CID,
        GUARDIAN_VSOCK_PORT
    )
}

impl HttpClient for GuardianVsockClient {
    fn post_cbor(&self, url: &str, body: &[u8]) -> Result<HttpResponse, AgentError> {
        let (target, path) = parse_vsock_url(url)?;
        if !(is_guardian_allowed_path(&path) || path == GUARDIAN_RECIPE_PATH) {
            return Err(AgentError::Guardian("vsock-path-forbidden"));
        }
        if body.len() > GUARDIAN_MAX_REQUEST_BYTES {
            return Err(AgentError::Guardian("vsock-req-oversize"));
        }
        let req = KbsProxyRequest {
            path,
            body: ByteBuf::from(body.to_vec()),
        };
        let mut frame = Vec::new();
        ciborium::ser::into_writer(&req, &mut frame)
            .map_err(|_| AgentError::Guardian("vsock-encode"))?;
        decode_guardian_reply(&vsock_exchange(target, &frame)?)
    }
}

/// Decode the relay's `{status, body}` frame, refusing a body over the
/// guardian response cap (the relay caps it too; the guest does not
/// rely on that).
fn decode_guardian_reply(frame: &[u8]) -> Result<HttpResponse, AgentError> {
    let resp: KbsProxyResponse =
        ciborium::de::from_reader(frame).map_err(|_| AgentError::Guardian("vsock-decode"))?;
    if resp.body.len() > GUARDIAN_MAX_RESPONSE_BYTES {
        return Err(AgentError::Guardian("vsock-resp-oversize"));
    }
    Ok(HttpResponse {
        status: resp.status,
        body: resp.body.into_vec(),
    })
}

/// Frame a request, write it, read the framed response. The real
/// AF_VSOCK round-trip (Linux only). `u32` BE length prefix + CBOR, the
/// same framing as the ticket / Edge-relay paths.
#[cfg(target_os = "linux")]
fn vsock_exchange(target: VsockTarget, frame: &[u8]) -> Result<Vec<u8>, AgentError> {
    use std::time::Duration;
    use vsock::{VsockAddr, VsockStream};

    let timeout = Duration::from_secs(hippius_types::kbs_vsock::PROXY_TIMEOUT_SECS);
    let addr = VsockAddr::new(target.cid, target.port);
    let mut stream = VsockStream::connect(&addr).map_err(|_| AgentError::Kbs("vsock-connect"))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| AgentError::Kbs("vsock-timeout-set"))?;

    let len = u32::try_from(frame.len()).map_err(|_| AgentError::Kbs("vsock-req-oversize"))?;
    stream
        .write_all(&len.to_be_bytes())
        .and_then(|()| stream.write_all(frame))
        .and_then(|()| stream.flush())
        .map_err(|_| AgentError::Kbs("vsock-write"))?;
    // Half-close the write side so the host sees EOF after the request.
    let _ = stream.shutdown(std::net::Shutdown::Write);

    read_framed(&mut stream)
}

/// Non-Linux stub so the crate still builds on a macOS dev host (the
/// initramfs binaries are Linux-only at runtime).
#[cfg(not(target_os = "linux"))]
fn vsock_exchange(_target: VsockTarget, _frame: &[u8]) -> Result<Vec<u8>, AgentError> {
    Err(AgentError::Kbs("vsock-unsupported-platform"))
}

/// Read a `u32` BE length-prefixed body, size-capped before allocation.
/// Mirrors `ticket_vsock::read_framed` / `miner-agent vsock::frame`.
fn read_framed<R: Read>(reader: &mut R) -> Result<Vec<u8>, AgentError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .map_err(|_| AgentError::Kbs("vsock-read-length"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_RESPONSE_BYTES {
        return Err(AgentError::Kbs("vsock-resp-length"));
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .map_err(|_| AgentError::Kbs("vsock-read-body"))?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_vsock_url_detects_scheme() {
        assert!(is_vsock_url("vsock://2:19266/v1/kbs/nonce"));
        assert!(!is_vsock_url("https://kbs.hippius.network"));
    }

    #[test]
    fn parse_splits_authority_and_path() {
        let (t, p) = parse_vsock_url("vsock://2:19266/v1/kbs/release").unwrap();
        assert_eq!(
            t,
            VsockTarget {
                cid: 2,
                port: 19266
            }
        );
        assert_eq!(p, "/v1/kbs/release");
    }

    #[test]
    fn parse_defaults_empty_cid_to_host() {
        let (t, p) = parse_vsock_url("vsock://:5000/v1/kbs/nonce").unwrap();
        assert_eq!(t.cid, hippius_types::kbs_vsock::HOST_CID);
        assert_eq!(t.port, 5000);
        assert_eq!(p, "/v1/kbs/nonce");
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse_vsock_url("https://x/y").is_err()); // wrong scheme
        assert!(parse_vsock_url("vsock://2:5000").is_err()); // no path
        assert!(parse_vsock_url("vsock://noport/v1/kbs/nonce").is_err()); // no :port
        assert!(parse_vsock_url("vsock://2:notaport/v1/kbs/nonce").is_err()); // bad port
    }

    #[test]
    fn read_framed_round_trips() {
        let body = b"a-kbs-proxy-response";
        let mut wire = Vec::new();
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(body);
        let mut cur = std::io::Cursor::new(wire);
        assert_eq!(read_framed(&mut cur).unwrap(), body);
    }

    #[test]
    fn read_framed_rejects_zero_and_oversize() {
        let mut zero = std::io::Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(read_framed(&mut zero).is_err());
        let huge = (MAX_RESPONSE_BYTES as u32 + 1).to_be_bytes().to_vec();
        let mut cur = std::io::Cursor::new(huge);
        assert!(read_framed(&mut cur).is_err());
    }

    #[test]
    fn guardian_client_refuses_every_non_guardian_path() {
        let c = GuardianVsockClient::new();
        for path in [
            "/v1/kbs/nonce",
            "/v1/kbs/release",
            "/v1/guardian/nonce?x=1",
            "/v1/guardian",
            "/v1/admin/allowlist/reload",
        ] {
            let err = c.post_cbor(&format!("vsock://2:19271{path}"), &[]);
            assert!(
                matches!(err, Err(AgentError::Guardian("vsock-path-forbidden"))),
                "{path}"
            );
        }
        // And the KBS client never carries a guardian path.
        let kbs = VsockHttpClient::new();
        for path in ["/v1/guardian/nonce", GUARDIAN_RECIPE_PATH] {
            let err = kbs.post_cbor(&format!("vsock://2:19266{path}"), &[]);
            assert!(matches!(err, Err(AgentError::Kbs("vsock-path-forbidden"))));
        }
    }

    #[test]
    fn guardian_client_refuses_an_oversize_body_before_connecting() {
        let c = GuardianVsockClient::new();
        let err = c.post_cbor(
            "vsock://2:19271/v1/guardian/release",
            &vec![0; GUARDIAN_MAX_REQUEST_BYTES + 1],
        );
        assert!(matches!(
            err,
            Err(AgentError::Guardian("vsock-req-oversize"))
        ));
    }

    #[test]
    fn guardian_client_passes_every_guardian_path_and_a_full_size_body_to_the_socket() {
        // No relay listens in a test, so getting as far as the connect
        // (a transport error, not a refusal) is what "allowed" means.
        let c = GuardianVsockClient::new();
        for path in [
            GUARDIAN_RECIPE_PATH,
            "/v1/guardian/nonce",
            "/v1/guardian/release",
            "/v1/guardian/stamp/confirm",
        ] {
            let err = c.post_cbor(&format!("vsock://2:19271{path}"), &[1]);
            assert!(
                matches!(err, Err(AgentError::Kbs(_))),
                "{path}: {:?}",
                err.err()
            );
        }
        let err = c.post_cbor(
            "vsock://2:19271/v1/guardian/release",
            &vec![0; GUARDIAN_MAX_REQUEST_BYTES],
        );
        assert!(matches!(err, Err(AgentError::Kbs(_))), "{:?}", err.err());
    }

    #[test]
    fn guardian_reply_is_capped_at_the_guardian_response_limit() {
        let frame = |len: usize| {
            let mut out = Vec::new();
            ciborium::ser::into_writer(
                &KbsProxyResponse {
                    status: 200,
                    body: ByteBuf::from(vec![7u8; len]),
                },
                &mut out,
            )
            .unwrap();
            out
        };
        let ok = decode_guardian_reply(&frame(GUARDIAN_MAX_RESPONSE_BYTES)).unwrap();
        assert_eq!(
            (ok.status, ok.body.len()),
            (200, GUARDIAN_MAX_RESPONSE_BYTES)
        );
        assert!(matches!(
            decode_guardian_reply(&frame(GUARDIAN_MAX_RESPONSE_BYTES + 1)),
            Err(AgentError::Guardian("vsock-resp-oversize"))
        ));
        assert!(matches!(
            decode_guardian_reply(b"not cbor"),
            Err(AgentError::Guardian("vsock-decode"))
        ));
    }

    #[test]
    fn guardian_relay_url_is_the_host_on_the_guardian_port() {
        assert_eq!(guardian_relay_url(), "vsock://2:19271");
        let (t, _) =
            parse_vsock_url(&format!("{}/v1/guardian/nonce", guardian_relay_url())).unwrap();
        assert_eq!(t.cid, 2);
        assert_eq!(t.port, GUARDIAN_VSOCK_PORT);
    }

    #[test]
    fn post_cbor_refuses_forbidden_path() {
        // An SSRF attempt never opens a connection.
        let c = VsockHttpClient::new();
        let err = c.post_cbor("vsock://2:5000/v1/admin/allowlist/reload", &[]);
        assert!(matches!(err, Err(AgentError::Kbs("vsock-path-forbidden"))));
    }
}
