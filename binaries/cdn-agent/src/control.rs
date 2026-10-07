//! The local control interface to OpenResty.
//!
//! OpenResty serves a `content_by_lua` location on a Unix stream socket
//! (`/run/cdn/ctl.sock`) and nowhere else. The agent is the client: each
//! push is one `PUT` of a complete JSON document, which OpenResty stores
//! in shared dictionaries. Every document is a full replacement, so a
//! push is idempotent and a lost push is repaired by the next one.
//!
//! | Path | Body | Secret? |
//! |---|---|---|
//! | [`PATH_CONFIG`] | zones, hostnames, purge generations, blocks, ACME HTTP-01, peers | no |
//! | [`PATH_SECRETS`] | unsealed zone secrets | **yes** |
//! | [`PATH_CERTS`] | certificate chains and unsealed keys | **yes** |
//! | [`PATH_HEALTH`] | readiness bits for `/__hippius/health` | no |
//! | [`PATH_ATTESTATION`] | SNP report for `/.well-known/hippius-attestation` | no |
//!
//! Status contract: `2xx` stored; `409` means OpenResty's shared memory
//! is empty (it restarted) and the agent must re-push everything; any
//! other status is an error the agent retries.
//!
//! Secret bodies cross a local socket into the OpenResty worker's
//! memory and are never written to disk by either side.

use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{CdnError, Result};

pub const PATH_CONFIG: &str = "/v1/config";
pub const PATH_SECRETS: &str = "/v1/secrets";
pub const PATH_CERTS: &str = "/v1/certs";
pub const PATH_HEALTH: &str = "/v1/health";
pub const PATH_ATTESTATION: &str = "/v1/attestation";

/// Class of the error a `409` maps to.
pub const RESYNC_REQUIRED: &str = "resync-required";

/// A sink for control documents. A trait so the agent loops can be
/// tested without OpenResty.
pub trait ControlChannel: Send + Sync {
    fn put(&self, path: &str, body: &[u8]) -> Result<()>;
}

/// HTTP/1.1 over the OpenResty control socket.
#[derive(Debug, Clone)]
pub struct UnixControl {
    socket: PathBuf,
    owner_uid: Option<u32>,
    timeout: Duration,
}

impl UnixControl {
    /// With `owner_uid`, every push first checks that the socket path is
    /// a socket (not a symlink) owned by that uid.
    pub fn new(socket: PathBuf, owner_uid: Option<u32>, timeout: Duration) -> Self {
        Self {
            socket,
            owner_uid,
            timeout,
        }
    }

    fn check_owner(&self) -> Result<()> {
        let Some(uid) = self.owner_uid else {
            return Ok(());
        };
        let meta = std::fs::symlink_metadata(&self.socket)
            .map_err(|_| CdnError::Control("connect-failed"))?;
        if !meta.file_type().is_socket() || meta.uid() != uid {
            return Err(CdnError::Control("socket-owner-mismatch"));
        }
        Ok(())
    }
}

impl ControlChannel for UnixControl {
    fn put(&self, path: &str, body: &[u8]) -> Result<()> {
        self.check_owner()?;
        let mut s =
            UnixStream::connect(&self.socket).map_err(|_| CdnError::Control("connect-failed"))?;
        s.set_read_timeout(Some(self.timeout))
            .and_then(|_| s.set_write_timeout(Some(self.timeout)))
            .map_err(|_| CdnError::Control("socket-timeout-setup"))?;
        let head = format!(
            "PUT {path} HTTP/1.1\r\nHost: cdn-agent\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        s.write_all(head.as_bytes())
            .and_then(|_| s.write_all(body))
            .and_then(|_| s.flush())
            .map_err(|_| CdnError::Control("write-failed"))?;
        match read_status(&mut s)? {
            200..=299 => Ok(()),
            409 => Err(CdnError::Control(RESYNC_REQUIRED)),
            _ => Err(CdnError::Control("rejected")),
        }
    }
}

/// Read the status code from `HTTP/1.x NNN ...\r\n`.
fn read_status(s: &mut UnixStream) -> Result<u16> {
    let mut buf = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n") {
        if buf.len() >= 256 {
            return Err(CdnError::Control("status-line-too-long"));
        }
        match s.read(&mut byte) {
            Ok(0) => return Err(CdnError::Control("closed-before-status")),
            Ok(_) => buf.push(byte[0]),
            Err(_) => return Err(CdnError::Control("read-failed")),
        }
    }
    let line = std::str::from_utf8(&buf).map_err(|_| CdnError::Control("status-line"))?;
    let mut parts = line.split(' ');
    match (parts.next(), parts.next()) {
        (Some(v), Some(code)) if v.starts_with("HTTP/1.") => code
            .trim()
            .parse()
            .map_err(|_| CdnError::Control("status-line")),
        _ => Err(CdnError::Control("status-line")),
    }
}

/// Records every push (tests).
#[cfg(test)]
#[derive(Default)]
pub struct RecordingControl {
    pub pushes: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    pub fail_with: std::sync::Mutex<Option<&'static str>>,
}

#[cfg(test)]
impl RecordingControl {
    pub fn last(&self, path: &str) -> Option<serde_json::Value> {
        let pushes = self.pushes.lock().ok()?;
        pushes
            .iter()
            .rev()
            .find(|(p, _)| p == path)
            .and_then(|(_, b)| serde_json::from_slice(b).ok())
    }

    pub fn count(&self, path: &str) -> usize {
        self.pushes
            .lock()
            .map(|p| p.iter().filter(|(q, _)| q == path).count())
            .unwrap_or(0)
    }
}

#[cfg(test)]
impl ControlChannel for RecordingControl {
    fn put(&self, path: &str, body: &[u8]) -> Result<()> {
        if let Some(class) = *self
            .fail_with
            .lock()
            .map_err(|_| CdnError::Control("lock"))?
        {
            return Err(CdnError::Control(class));
        }
        self.pushes
            .lock()
            .map_err(|_| CdnError::Control("lock"))?
            .push((path.to_string(), body.to_vec()));
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::os::unix::net::UnixListener;

    /// One-shot control server: answers `status`, returns the request.
    fn serve_once(
        path: PathBuf,
        status: &'static str,
    ) -> std::thread::JoinHandle<(String, Vec<u8>)> {
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut r = std::io::BufReader::new(s.try_clone().unwrap());
            let mut request_line = String::new();
            r.read_line(&mut request_line).unwrap();
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                r.read_line(&mut h).unwrap();
                if h == "\r\n" {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body).unwrap();
            let mut w = s;
            write!(w, "HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").unwrap();
            (request_line, body)
        })
    }

    #[test]
    fn put_sends_the_document_and_reads_the_status() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ctl.sock");
        let server = serve_once(sock.clone(), "204 No Content");
        let ctl = UnixControl::new(sock, None, Duration::from_secs(5));
        ctl.put(PATH_CONFIG, br#"{"revision":1}"#).unwrap();
        let (line, body) = server.join().unwrap();
        assert_eq!(line, "PUT /v1/config HTTP/1.1\r\n");
        assert_eq!(body, br#"{"revision":1}"#);
    }

    #[test]
    fn conflict_means_resync_and_other_statuses_fail() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("a.sock");
        let server = serve_once(sock.clone(), "409 Conflict");
        let ctl = UnixControl::new(sock, None, Duration::from_secs(5));
        assert_eq!(
            ctl.put(PATH_HEALTH, b"{}").unwrap_err().class(),
            RESYNC_REQUIRED
        );
        server.join().unwrap();

        let sock = dir.path().join("b.sock");
        let server = serve_once(sock.clone(), "500 Internal");
        let ctl = UnixControl::new(sock, None, Duration::from_secs(5));
        assert_eq!(ctl.put(PATH_HEALTH, b"{}").unwrap_err().class(), "rejected");
        server.join().unwrap();

        let ctl = UnixControl::new(dir.path().join("absent.sock"), None, Duration::from_secs(1));
        assert_eq!(
            ctl.put(PATH_HEALTH, b"{}").unwrap_err().class(),
            "connect-failed"
        );

        // An owner check refuses a socket bound by another uid, or a plain file.
        let sock = dir.path().join("c.sock");
        let server = serve_once(sock.clone(), "204 No Content");
        let mine = std::fs::metadata(&sock).unwrap().uid();
        let ctl = UnixControl::new(
            sock.clone(),
            Some(mine.wrapping_add(1)),
            Duration::from_secs(1),
        );
        assert_eq!(
            ctl.put(PATH_HEALTH, b"{}").unwrap_err().class(),
            "socket-owner-mismatch"
        );
        let file = dir.path().join("plain");
        std::fs::write(&file, b"").unwrap();
        let ctl = UnixControl::new(file, Some(mine), Duration::from_secs(1));
        assert_eq!(
            ctl.put(PATH_HEALTH, b"{}").unwrap_err().class(),
            "socket-owner-mismatch"
        );
        let ctl = UnixControl::new(sock, Some(mine), Duration::from_secs(5));
        ctl.put(PATH_HEALTH, b"{}").unwrap();
        server.join().unwrap();
    }
}
