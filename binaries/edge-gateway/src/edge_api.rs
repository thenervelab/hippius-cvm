//! Read-only Edge HTTP API — `/v1/edge/pubkey` + `/v1/edge/audit/verify`
//! (PR-H6, §15).
//!
//! Two endpoints, both `GET`, both read-only, both consumed by
//! Sentinel and the Validator:
//!
//! - **`/v1/edge/pubkey`** — the Edge's boot-generated Ed25519 public
//!   key. A verifier fetches it once, then checks every
//!   [`crate::wire::SignedEdgeTelemetry`] against it. Only the PUBLIC
//!   half is ever served — [`EdgeSigner`] has no path to the secret.
//!
//! - **`/v1/edge/audit/verify`** — walks + chain-verifies the audit
//!   log on every scrape ([`EdgeAuditSink::verify`]) and returns the
//!   verified head hash + record count. A `200` means the chain
//!   checked out; a tampered log (or an I/O error) returns `500` with
//!   a static error classifier, so even a plain HTTP health check
//!   treats it as a hard failure. The verify walk is run on a
//!   blocking thread so a scrape never stalls the relay path.
//!
//! Hand-rolled HTTP/1.1, same slim-dependency posture as
//! `ha::balance_metric` — a JSON body that small does not justify a
//! framework. `Connection: close` on every response, a read timeout,
//! and a one-shot accumulating read of the request line so a
//! fragmented request is classified correctly rather than 404'd.

use crate::audit::EdgeAuditSink;
use crate::signer::EdgeSigner;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Fixed TCP port the Edge API binds. Distinct from the HA peer-link
/// (9443) and HA `/metrics` (9464) ports.
pub const EDGE_API_PORT: u16 = 9465;

/// How long a connection may take to deliver its request line.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest request prefix buffered — the request line is tiny, this
/// just bounds the per-connection buffer.
const REQUEST_CAP: usize = 1024;

/// The Edge API HTTP server.
///
/// Bound separately from started so a caller (the integration test)
/// can read back an OS-assigned port. Production binds the fixed
/// [`EDGE_API_PORT`].
pub struct EdgeApiServer {
    listener: TcpListener,
    addr: SocketAddr,
}

impl EdgeApiServer {
    /// Bind the API listener. `addr`'s port may be `0` for an
    /// OS-assigned ephemeral port — read it back via [`Self::local_addr`].
    /// Returns a static classifier on failure.
    pub async fn bind(addr: SocketAddr) -> Result<Self, &'static str> {
        let listener = TcpListener::bind(addr).await.map_err(|_| "edge-api-bind")?;
        let addr = listener.local_addr().map_err(|_| "edge-api-bind")?;
        Ok(Self { listener, addr })
    }

    /// The address the API listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Serve the API forever. One short-lived task per connection,
    /// every response `Connection: close`. Consumes `self` — spawn it.
    pub async fn run(self, signer: Arc<EdgeSigner>, audit: Arc<EdgeAuditSink>) {
        loop {
            let stream = match self.listener.accept().await {
                Ok((stream, _)) => stream,
                // Transient accept error — back off so a hard failure
                // (fd exhaustion) does not hot-spin the task.
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            let signer = Arc::clone(&signer);
            let audit = Arc::clone(&audit);
            tokio::spawn(async move {
                // A failed connection is dropped silently.
                let _ = serve_one(stream, &signer, audit).await;
            });
        }
    }
}

/// Handle one connection: classify the request line, answer.
async fn serve_one(
    mut stream: TcpStream,
    signer: &EdgeSigner,
    audit: Arc<EdgeAuditSink>,
) -> std::io::Result<()> {
    // Accumulate until the request line is complete (`\r\n`), the cap
    // is hit, or the peer closes — so a fragmented read is classified
    // correctly rather than spuriously 404'd.
    let mut buf = [0u8; REQUEST_CAP];
    let mut len = 0usize;
    while !buf[..len].windows(2).any(|w| w == b"\r\n") && len < buf.len() {
        let n = match tokio::time::timeout(REQUEST_TIMEOUT, stream.read(&mut buf[len..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            // Timeout or read error → drop the connection unanswered.
            _ => return Ok(()),
        };
        len += n;
    }
    let request = &buf[..len];

    let response = if request.starts_with(b"GET /v1/edge/pubkey ") {
        json_ok(&format!(
            "{{\"algorithm\":\"ed25519\",\"public_key\":\"{}\"}}",
            hex::encode(signer.public_key_bytes()),
        ))
    } else if request.starts_with(b"GET /v1/edge/audit/verify ") {
        // Walk + chain-verify the log on every scrape — the endpoint
        // is named `verify`, so it must actually verify, not serve a
        // cached in-memory head/count (which would still report OK
        // after on-disk tampering). The walk is synchronous file I/O,
        // so it runs on a blocking thread: a scrape must never stall
        // the relay path or, on the current-thread runtime, every
        // other task.
        match tokio::task::spawn_blocking(move || audit.verify()).await {
            Ok(Ok(v)) => json_ok(&format!(
                "{{\"verified\":true,\"head\":\"{}\",\"record_count\":{}}}",
                hex::encode(v.head),
                v.records,
            )),
            // Chain verification failed (tamper) or an I/O error —
            // surface it as 5xx so Sentinel flags this Edge hard.
            Ok(Err(e)) => json_error(e.class()),
            Err(_) => json_error("audit-verify-task"),
        }
    } else {
        not_found()
    };

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Render a `200 OK` HTTP/1.1 response with a JSON body.
fn json_ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len(),
    )
}

/// Render a `404 Not Found` HTTP/1.1 response.
fn not_found() -> String {
    "HTTP/1.1 404 Not Found\r\n\
     Content-Length: 0\r\n\
     Connection: close\r\n\
     \r\n"
        .to_string()
}

/// Render a `500` response carrying a static error classifier — the
/// `/v1/edge/audit/verify` failure path. A 5xx (not a 200 with a flag)
/// so a plain HTTP health check, not just a JSON-parsing scraper,
/// treats a tamper-detected audit log as a hard failure.
fn json_error(class: &str) -> String {
    let body = format!("{{\"verified\":false,\"error\":\"{class}\"}}");
    format!(
        "HTTP/1.1 500 Internal Server Error\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_ok_carries_length_and_close() {
        let r = json_ok("{\"k\":1}");
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(r.contains("Content-Type: application/json\r\n"));
        assert!(r.contains("Content-Length: 7\r\n"));
        assert!(r.contains("Connection: close\r\n"));
        assert!(r.ends_with("{\"k\":1}"));
    }

    #[test]
    fn not_found_is_well_formed() {
        let r = not_found();
        assert!(r.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(r.contains("Content-Length: 0\r\n"));
        assert!(r.ends_with("\r\n\r\n"));
    }
}
