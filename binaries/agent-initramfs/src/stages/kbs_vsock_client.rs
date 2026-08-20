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
    fn post_cbor_refuses_forbidden_path() {
        // An SSRF attempt never opens a connection.
        let c = VsockHttpClient::new();
        let err = c.post_cbor("vsock://2:5000/v1/admin/allowlist/reload", &[]);
        assert!(matches!(err, Err(AgentError::Kbs("vsock-path-forbidden"))));
    }
}
