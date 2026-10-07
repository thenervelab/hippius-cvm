//! Usage reports: the on-disk queue and the signed upload (spec §9.2).
//!
//! A report is a checkpoint of cumulative totals, so the newest report
//! of an epoch supersedes the older ones for billing totals. The queue
//! is still sent oldest-first (it keeps the 5-minute buckets accurate),
//! and when it overflows the **oldest** reports are dropped: their
//! traffic is carried by the newer totals.
//!
//! Each body is serialised once, stored, and sent byte-for-byte; the
//! detached Ed25519 signature covers `wire::usage_message(body)`.

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::backend::BackendClient;
use crate::clock::unix_now;
use crate::error::{CdnError, Result};
use crate::identity::NodeKey;
use crate::persist;
use crate::reqsign::NodeAuth;
use crate::wire::{self, UsageReport};

/// 24 h of 60 s reports.
pub const DEFAULT_MAX_QUEUED: usize = 1_440;
/// The queue shares the cache volume: past this many bytes the oldest
/// reports go first (the newest always stays).
const MAX_QUEUE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_REPORT_LEN: u64 = 64 * 1024 * 1024;

/// Unsent reports, one file each, named so that lexical order is
/// creation order.
pub struct UsageQueue {
    dir: PathBuf,
    max: usize,
    counter: u64,
}

/// What a flush did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Flushed {
    pub sent: usize,
    /// Permanently refused by the backend (4xx other than 401/429).
    pub refused: usize,
}

impl UsageQueue {
    pub fn open(dir: PathBuf, max: usize) -> Result<Self> {
        persist::ensure_private_dir(&dir)?;
        Ok(Self {
            dir,
            max,
            counter: 0,
        })
    }

    /// Serialise and store `report`, then drop the oldest past `max`.
    pub fn enqueue(&mut self, report: &UsageReport) -> Result<()> {
        let epoch_ok = report.counter_epoch.len() == 32
            && report.counter_epoch.bytes().all(|b| b.is_ascii_hexdigit());
        if !epoch_ok {
            return Err(CdnError::Usage("bad-epoch"));
        }
        let body = serde_json::to_vec(report).map_err(|_| CdnError::Usage("encode"))?;
        if body.len() as u64 > MAX_REPORT_LEN {
            return Err(CdnError::Usage("report-too-large"));
        }
        self.counter += 1;
        let name = format!(
            "{:020}-{:06}-{}-{:020}.json",
            unix_now(),
            self.counter % 1_000_000,
            report.counter_epoch,
            report.seq
        );
        persist::atomic_write(&self.dir.join(name), &body)?;
        self.prune()
    }

    /// Drop the oldest reports past `max` files or `MAX_QUEUE_BYTES`.
    fn prune(&self) -> Result<()> {
        let pending = self.pending()?;
        let mut keep_bytes: u64 = 0;
        let mut kept = 0usize;
        // Walk newest first; everything past the budget is removed.
        for path in pending.iter().rev() {
            let len = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let over = kept >= self.max || (kept > 0 && keep_bytes + len > MAX_QUEUE_BYTES);
            if over {
                let _ = fs::remove_file(path);
            } else {
                kept += 1;
                keep_bytes += len;
            }
        }
        Ok(())
    }

    /// Queued report files, oldest first.
    pub fn pending(&self) -> Result<Vec<PathBuf>> {
        let mut files: Vec<PathBuf> = fs::read_dir(&self.dir)
            .map_err(|_| CdnError::Usage("queue-read"))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort();
        Ok(files)
    }

    /// Send queued reports oldest-first until one fails. A transport
    /// error, a 5xx, a 429 or a 401 stops the flush (and is returned)
    /// with the report kept; a 4xx that will never succeed drops it.
    pub fn flush(&self, client: &BackendClient, auth: &NodeAuth<'_>) -> Result<Flushed> {
        let mut out = Flushed::default();
        for path in self.pending()? {
            let body = match persist::read_optional(&path, MAX_REPORT_LEN) {
                Ok(Some(b)) => b,
                Ok(None) => continue,
                Err(e) => {
                    eprintln!(
                        "hippius-cdn-agent: unreadable usage report dropped ({})",
                        e.class()
                    );
                    let _ = fs::remove_file(&path);
                    continue;
                }
            };
            let sig = sign(&body, auth.key);
            match client.post_usage(auth, &body, &sig) {
                Ok(()) => {
                    remove(&path)?;
                    out.sent += 1;
                }
                Err(CdnError::BackendStatus(code)) if is_permanent(code) => {
                    eprintln!("hippius-cdn-agent: usage report refused ({code}), dropped");
                    remove(&path)?;
                    out.refused += 1;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

/// 4xx statuses retrying cannot fix. 409 is the backend's "already have
/// this seq".
fn is_permanent(code: u16) -> bool {
    (400..500).contains(&code) && code != 401 && code != 408 && code != 429
}

/// Remove a sent report. Already gone (pruned meanwhile) is fine.
fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CdnError::Usage("queue-remove")),
    }
}

/// Base64 detached signature over `wire::usage_message(body)`.
pub fn sign(body: &[u8], key: &NodeKey) -> String {
    B64.encode(key.sign(&wire::usage_message(body)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::{BackendConfig, BackendUrl};
    use crate::counters::Counters;
    use crate::test_support::{MockBackend, Reply};
    use crate::wire::SessionToken;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn report(seq: u64) -> UsageReport {
        let mut c = Counters::fresh();
        for _ in 0..seq {
            let dir = tempfile::tempdir().unwrap();
            c.checkpoint(&dir.path().join("c"), "n", "t".into(), 0, "db")
                .unwrap();
        }
        c.final_report("cdn-fr-1", "2026-10-20T10:00:00Z".into(), 3, "dbip-2026-10")
    }

    fn client(mock: &MockBackend) -> BackendClient {
        BackendClient::new(&BackendConfig {
            url: BackendUrl::loopback_for_tests(mock.addr()),
            ca_bundle: None,
            request_signatures: true,
            request_timeout_s: 5,
            feed_poll_s: 1,
        })
        .unwrap()
    }

    fn auth<'a>(tok: &'a SessionToken, key: &'a NodeKey, node_id: &'a str) -> NodeAuth<'a> {
        NodeAuth {
            token: tok,
            session_id: "sess-1",
            node_id,
            key,
            sign: true,
        }
    }

    #[test]
    fn signature_covers_the_exact_body_bytes() {
        let key = NodeKey::derive(&[1u8; 32]);
        let mock = MockBackend::start(|_| Reply::status(204));
        let dir = tempfile::tempdir().unwrap();
        let mut q = UsageQueue::open(dir.path().join("q"), 10).unwrap();
        q.enqueue(&report(1)).unwrap();
        let tok = SessionToken::for_tests("t");
        let f = q
            .flush(&client(&mock), &auth(&tok, &key, "cdn-fr-1"))
            .unwrap();
        assert_eq!(
            f,
            Flushed {
                sent: 1,
                refused: 0
            }
        );
        assert!(q.pending().unwrap().is_empty());

        let req = &mock.requests()[0];
        assert_eq!(req.target, "/api/cdn/node/usage/");
        assert_eq!(req.method, "POST");
        assert_eq!(req.header("x-hippius-cdn-node"), Some("cdn-fr-1"));
        let sig: [u8; 64] = B64
            .decode(req.header("x-hippius-cdn-signature").unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let vk = VerifyingKey::from_bytes(&key.public_bytes()).unwrap();
        vk.verify(
            &wire::usage_message(&req.body),
            &Signature::from_bytes(&sig),
        )
        .unwrap();
        // The request signature (§C.0) covers the same bytes.
        assert!(req.header("x-hippius-node-signature").is_some());
        assert!(req.header("x-hippius-node-timestamp").is_some());
        // One flipped byte breaks it.
        let mut tampered = req.body.clone();
        tampered[1] ^= 1;
        assert!(vk
            .verify(
                &wire::usage_message(&tampered),
                &Signature::from_bytes(&sig)
            )
            .is_err());
        let body: UsageReport = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body.seq, 2);
        assert_eq!(body.applied_revision, 3);
    }

    #[test]
    fn failures_keep_reports_in_order_and_permanent_refusals_drop() {
        let key = NodeKey::derive(&[1u8; 32]);
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&calls);
        // 1st: 503 (stop), then: 409 (drop), then 204.
        let mock = MockBackend::start(move |_| match c2.fetch_add(1, Ordering::SeqCst) {
            0 => Reply::status(503),
            1 => Reply::json(409, r#"{"code":"seq-replay"}"#),
            _ => Reply::status(204),
        });
        let dir = tempfile::tempdir().unwrap();
        let mut q = UsageQueue::open(dir.path().join("q"), 10).unwrap();
        q.enqueue(&report(1)).unwrap();
        q.enqueue(&report(2)).unwrap();
        let tok = SessionToken::for_tests("t");
        let c = client(&mock);
        assert!(matches!(
            q.flush(&c, &auth(&tok, &key, "n")).unwrap_err(),
            CdnError::BackendStatus(503)
        ));
        assert_eq!(q.pending().unwrap().len(), 2);
        let f = q.flush(&c, &auth(&tok, &key, "n")).unwrap();
        assert_eq!(
            f,
            Flushed {
                sent: 1,
                refused: 1
            }
        );
        // Oldest first: the first two posts carried seq 2, then seq 2 again
        // (refused as replay), then seq 3.
        let seqs: Vec<u64> = mock
            .requests()
            .iter()
            .map(|r| serde_json::from_slice::<UsageReport>(&r.body).unwrap().seq)
            .collect();
        assert_eq!(seqs, vec![2, 2, 3]);
    }

    #[test]
    fn overflow_drops_the_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let mut q = UsageQueue::open(dir.path().join("q"), 3).unwrap();
        for seq in 0..5 {
            q.enqueue(&report(seq)).unwrap();
        }
        let left: Vec<u64> = q
            .pending()
            .unwrap()
            .iter()
            .map(|p| {
                serde_json::from_slice::<UsageReport>(&fs::read(p).unwrap())
                    .unwrap()
                    .seq
            })
            .collect();
        assert_eq!(left, vec![3, 4, 5]);
    }
}
