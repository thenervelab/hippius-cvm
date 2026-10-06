//! Durable, hash-chained audit log for §15.
//!
//! `release::process_release` calls `AuditSink::record` on every
//! decision. The reference in-memory sink (used in tests) is fine for
//! development, but production needs an **append-only, tamper-evident**
//! sink so an operator can detect post-hoc log mutation.
//!
//! `FileAuditSink` stores records as newline-delimited canonical-CBOR
//! lines in a single file (`{dir}/audit.log`). Each record commits the
//! SHA-256 of the PREVIOUS record's bytes — a hash chain. A
//! corresponding `head.sha256` file stores the latest record hash so
//! a reader can verify the tail without reading the entire log.
//!
//! **Authority hierarchy:** `audit.log` is THE source of truth —
//! `head.sha256` is a denormalised tail cache. On open we WALK THE LOG
//! and compute the real tail; `head.sha256` is repaired if it
//! disagrees. A crash between log fsync and head rename therefore
//! cannot leave a stale head that derails the next append.
//!
//! **Cross-process safety:** every operation that touches the chain
//! holds an exclusive advisory lock on `audit.lock` (POSIX flock via
//! `std::fs::File::lock`). Two `FileAuditSink::open(dir)` calls in
//! different processes serialize on this lock; the second blocks until
//! the first drops. Append-only fsync alone doesn't serialize the
//! read-modify-write of `prev_hash`/`seq`, so the file lock is the
//! actual safety primitive — `O_APPEND` is just one ingredient.
//!
//! **Tamper detection caveat:** an operator with write access to the
//! filesystem can still rebuild a perfectly-consistent parallel log.
//! The chain raises the bar from "silent overwrite" to "must rewrite
//! the entire tail AND the head pointer". For real authenticity-
//! against-host-breach (§15 Tier-0 grade), an external attestation
//! root MUST sign over `(record_count, head)` periodically. This
//! module is the substrate that root will sign over.

use crate::audit_journal::{self, ChainFiles, Walk};
use crate::audit_read::{self, AuditPage, LogIndex};
use crate::error::{KbsError, Result};
use crate::release::AuditSink;
use ciborium::value::Value;
use hippius_types::cbor::to_canonical_vec;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Domain tag — distinct from every other signed payload in the stack
/// so a record body cannot replay into any other signature context.
pub const AUDIT_DOMAIN: &str = "HIPPIUS_KBS_AUDIT_V1";

const LOG_FILENAME: &str = "audit.log";
const HEAD_FILENAME: &str = "head.sha256";
const LOCK_FILENAME: &str = "audit.lock";
const FILES: ChainFiles = ChainFiles {
    label: "audit",
    log: LOG_FILENAME,
    head: HEAD_FILENAME,
};

/// Durable file-backed sink with a single-file append-only log + hash
/// chain + cross-process advisory lock.
pub struct FileAuditSink {
    dir: PathBuf,
    /// Held for the FileAuditSink lifetime via `File::lock_exclusive` —
    /// drops the lock on `Drop`. Cross-process invariant.
    _lock: File,
    /// In-process serialization of multi-step writes. Cross-process
    /// callers serialize via the file lock above.
    state: Mutex<HeadState>,
}

#[derive(Debug, Clone)]
struct HeadState {
    /// Previous record's SHA-256, or all-zeros if the chain is fresh.
    prev_hash: [u8; 32],
    /// Next sequence number to issue (== record count so far).
    next_seq: u64,
    /// Byte index of `audit.log` for the read route
    /// (`crate::audit_read`).
    index: LogIndex,
}

impl FileAuditSink {
    /// Open / create the log directory. Takes the directory's
    /// exclusive advisory lock for the lifetime of `Self`. ALWAYS walks
    /// `audit.log` to derive the true tail — `head.sha256` is treated
    /// as a cache and repaired on disagreement.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        Self::open_at(dir, unix_now())
    }

    /// [`Self::open`] with the clock of an `audit-truncated` record chained
    /// at open (tests and the shared wire fixture pin it).
    pub fn open_at(dir: impl Into<PathBuf>, now_unix: u64) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)
            .map_err(|e| KbsError::Vault(format!("audit create_dir_all: {e}")))?;
        // Acquire the exclusive lock. `lock_exclusive` blocks until
        // any other holder drops the file's open handle.
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join(LOCK_FILENAME))
            .map_err(|e| KbsError::Vault(format!("audit lock open: {e}")))?;
        lock.lock()
            .map_err(|e| KbsError::Vault(format!("audit lock acquire: {e}")))?;

        // Walk the log to compute the real tail. Journal semantics — see
        // `crate::audit_journal`: a torn trailing record is truncated (and
        // an `audit-truncated` record chained in its place), a stale head is
        // repaired; only a state no crash produces refuses.
        let opened = audit_journal::open_recover(&dir, FILES, walk_bytes, |prev, seq, torn| {
            let reason = torn.marker_reason(seq);
            Self::build_record(prev, seq, false, None, None, &reason, now_unix)
        })?;
        Ok(Self {
            dir,
            _lock: lock,
            state: Mutex::new(HeadState {
                prev_hash: opened.head,
                next_seq: opened.records,
                index: opened.index,
            }),
        })
    }

    /// Build the canonical-CBOR body of a single audit record. Schema
    /// is pinned for §N conformance — keys sorted by encoded bytes.
    fn build_record(
        prev_hash: &[u8; 32],
        seq: u64,
        granted: bool,
        ticket_id: Option<&str>,
        vm_id: Option<&str>,
        reason: &str,
        now_unix: u64,
    ) -> Result<Vec<u8>> {
        let v = Value::Map(vec![
            (
                Value::Text("domain".into()),
                Value::Text(AUDIT_DOMAIN.into()),
            ),
            (Value::Text("granted".into()), Value::Bool(granted)),
            (
                Value::Text("now_unix".into()),
                Value::Integer(now_unix.into()),
            ),
            (
                Value::Text("prev_hash".into()),
                Value::Bytes(prev_hash.to_vec()),
            ),
            (Value::Text("reason".into()), Value::Text(reason.into())),
            (Value::Text("seq".into()), Value::Integer(seq.into())),
            (
                Value::Text("ticket_id".into()),
                Value::Text(ticket_id.unwrap_or("").into()),
            ),
            (
                Value::Text("vm_id".into()),
                Value::Text(vm_id.unwrap_or("").into()),
            ),
        ]);
        to_canonical_vec(&v).map_err(|e| KbsError::Vault(format!("audit encode: {e}")))
    }

    /// Append a record + update `head.sha256` atomically. Returns the
    /// new record's SHA-256.
    pub fn append(
        &self,
        granted: bool,
        ticket_id: Option<&str>,
        vm_id: Option<&str>,
        reason: &str,
        now_unix: u64,
    ) -> Result<[u8; 32]> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| KbsError::Vault("audit lock poisoned".into()))?;
        let seq = g.next_seq;
        let body = Self::build_record(
            &g.prev_hash,
            seq,
            granted,
            ticket_id,
            vm_id,
            reason,
            now_unix,
        )?;
        let mut h = [0u8; 32];
        h.copy_from_slice(Sha256::digest(&body).as_slice());

        // Append the line. Format `<seq>:<hex_body>:<hex_hash>\n`.
        let line = format!("{seq}:{}:{}\n", hex::encode(&body), hex::encode(h));
        let offset = audit_journal::append_line(&self.dir, FILES, g.index.end(), line.as_bytes())?;

        // Update head pointer via atomic rename.
        // The record is durable from here: advance the chain state BEFORE
        // the head cache, so a failed head write cannot leave a persisted
        // record outside the index (and the next append re-using its seq).
        g.prev_hash = h;
        g.next_seq = seq.saturating_add(1);
        g.index.push(offset, line.len() as u64, h);

        // Head pointer: a cache, repaired from the log at every open.
        audit_journal::write_head_atomic(&self.dir, FILES, &h)?;
        Ok(h)
    }

    /// One page of the persisted chain for `GET /v1/admin/audit`: records
    /// after `after_seq` (from `seq=0` when `None`), at most `limit`
    /// (clamped to `1..=ADMIN_AUDIT_PAGE_MAX`). Read-only — see
    /// `crate::audit_read`. The mutex is held only to cut the snapshot,
    /// so a release never waits on the disk read.
    pub fn read_page(&self, after_seq: Option<u64>, limit: u32) -> Result<AuditPage> {
        let snap = {
            let g = self
                .state
                .lock()
                .map_err(|_| KbsError::Vault("audit lock poisoned".into()))?;
            g.index.snapshot(g.prev_hash, after_seq, limit)
        };
        audit_read::read_snapshot(&self.dir.join(LOG_FILENAME), snap)
    }

    /// Read all records back, recompute the chain, return the
    /// recomputed head hash. The chain MUST match what's on disk at
    /// `head.sha256` for the log to be considered untampered.
    pub fn verify(&self) -> Result<VerifiedAudit> {
        walk_log(&self.dir).and_then(|v| {
            let head_path = self.dir.join(HEAD_FILENAME);
            match fs::read(&head_path) {
                Ok(bytes) => {
                    if bytes != v.head {
                        return Err(KbsError::Vault(
                            "audit head.sha256 disagrees with computed tail".into(),
                        ));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if v.records > 0 {
                        return Err(KbsError::Vault(
                            "audit head.sha256 missing while log has records (tamper)".into(),
                        ));
                    }
                }
                Err(e) => return Err(KbsError::Vault(format!("audit head read: {e}"))),
            }
            Ok(v)
        })
    }
}

/// Result of [`FileAuditSink::verify`].
#[derive(Debug, Clone, Copy)]
pub struct VerifiedAudit {
    pub records: u64,
    pub head: [u8; 32],
}

/// Read + decode + chain-check the log file. Returns the records
/// count and the computed tail hash. Does NOT touch `head.sha256`. Strict:
/// a torn tail is an error here (open has already truncated any).
fn walk_log(dir: &std::path::Path) -> Result<VerifiedAudit> {
    let bytes = match fs::read(dir.join(LOG_FILENAME)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(KbsError::Vault(format!("audit walk read: {e}"))),
    };
    let w = walk_bytes(&bytes, None).map_err(|e| KbsError::Vault(format!("audit: {e}")))?;
    if let Some(t) = w.torn {
        return Err(KbsError::Vault(format!(
            "audit: torn tail at byte {}: {}",
            t.offset, t.why
        )));
    }
    Ok(VerifiedAudit {
        records: w.records,
        head: w.head,
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn walk_bytes(bytes: &[u8], head_probe: Option<[u8; 32]>) -> std::result::Result<Walk, String> {
    audit_journal::walk(bytes, head_probe, check_body)
}

/// A self-consistent release record at chain position `(seq, prev)`:
/// strict schema, the domain tag, its own `seq`, and its `prev_hash`.
fn check_body(body: &[u8], seq: u64, prev: &[u8; 32]) -> std::result::Result<(), String> {
    let decoded = decode_strict(body).ok_or_else(|| "invalid schema".to_string())?;
    if decoded.domain != AUDIT_DOMAIN {
        return Err("wrong domain".into());
    }
    if decoded.seq != seq {
        return Err(format!("body seq {} != line seq {seq}", decoded.seq));
    }
    if decoded.prev_hash != *prev {
        return Err("chain broken (prev_hash != expected)".into());
    }
    Ok(())
}

#[derive(Debug)]
struct AuditRecord {
    domain: String,
    prev_hash: [u8; 32],
    seq: u64,
}

/// Strict decoder: returns Some only if the CBOR matches the record
/// schema exactly — every required field present, correct types, no
/// extra fields. The canonical-encoding requirement is enforced
/// SEPARATELY by `assert_canonical` (which also rejects duplicate
/// keys at the encoder level on the producer side).
fn decode_strict(body: &[u8]) -> Option<AuditRecord> {
    let v: Value = ciborium::de::from_reader(body).ok()?;
    let Value::Map(entries) = v else { return None };
    let mut domain = None;
    let mut granted = None;
    let mut now_unix = None;
    let mut prev_hash = None;
    let mut reason = None;
    let mut seq = None;
    let mut ticket_id = None;
    let mut vm_id = None;
    for (k, val) in entries {
        let Value::Text(t) = k else { return None };
        match t.as_str() {
            "domain" => {
                if domain.is_some() {
                    return None;
                }
                let Value::Text(s) = val else { return None };
                domain = Some(s);
            }
            "granted" => {
                if granted.is_some() {
                    return None;
                }
                let Value::Bool(b) = val else { return None };
                granted = Some(b);
            }
            "now_unix" => {
                if now_unix.is_some() {
                    return None;
                }
                let Value::Integer(i) = val else {
                    return None;
                };
                let u: u64 = i.try_into().ok()?;
                now_unix = Some(u);
            }
            "prev_hash" => {
                if prev_hash.is_some() {
                    return None;
                }
                let Value::Bytes(b) = val else { return None };
                if b.len() != 32 {
                    return None;
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                prev_hash = Some(out);
            }
            "reason" => {
                if reason.is_some() {
                    return None;
                }
                let Value::Text(s) = val else { return None };
                reason = Some(s);
            }
            "seq" => {
                if seq.is_some() {
                    return None;
                }
                let Value::Integer(i) = val else {
                    return None;
                };
                let u: u64 = i.try_into().ok()?;
                seq = Some(u);
            }
            "ticket_id" => {
                if ticket_id.is_some() {
                    return None;
                }
                let Value::Text(s) = val else { return None };
                ticket_id = Some(s);
            }
            "vm_id" => {
                if vm_id.is_some() {
                    return None;
                }
                let Value::Text(s) = val else { return None };
                vm_id = Some(s);
            }
            _ => return None, // unknown field
        }
    }
    Some(AuditRecord {
        domain: domain?,
        prev_hash: prev_hash?,
        seq: seq?,
    })
    .filter(|_| {
        granted.is_some()
            && now_unix.is_some()
            && reason.is_some()
            && ticket_id.is_some()
            && vm_id.is_some()
    })
}

impl AuditSink for FileAuditSink {
    fn record(&self, granted: bool, ticket_id: Option<&str>, vm_id: Option<&str>, reason: &str) {
        // `AuditSink::record` is best-effort: must not fail the
        // release pipeline. We route the error to stderr via a locked
        // handle (eprintln! would also work but acquires the lock per
        // write and is documented as panicking on stderr fail in some
        // std versions; this form is more explicit).
        if let Err(e) = self.append(granted, ticket_id, vm_id, reason, unix_now()) {
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "kbs-core::audit: failed to append record: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn empty_log_verifies_as_zero_records() {
        let td = TempDir::new().unwrap();
        let s = FileAuditSink::open(td.path()).unwrap();
        let v = s.verify().unwrap();
        assert_eq!(v.records, 0);
        assert_eq!(v.head, [0u8; 32]);
    }

    #[test]
    fn appended_records_chain_correctly() {
        let td = TempDir::new().unwrap();
        let s = FileAuditSink::open(td.path()).unwrap();
        s.append(true, Some("tk-1"), Some("abc"), "released", 1_000)
            .unwrap();
        s.append(false, Some("tk-2"), Some("abc"), "expired", 1_010)
            .unwrap();
        s.append(true, Some("tk-3"), Some("xyz"), "released", 1_020)
            .unwrap();
        let v = s.verify().unwrap();
        assert_eq!(v.records, 3);
    }

    #[test]
    fn reopen_picks_up_the_chain() {
        let td = TempDir::new().unwrap();
        {
            let s = FileAuditSink::open(td.path()).unwrap();
            s.append(true, Some("tk-a"), Some("vm-a"), "released", 1_000)
                .unwrap();
        }
        let s2 = FileAuditSink::open(td.path()).unwrap();
        s2.append(true, Some("tk-b"), Some("vm-b"), "released", 2_000)
            .unwrap();
        let v = s2.verify().unwrap();
        assert_eq!(v.records, 2);
    }

    #[test]
    fn tampered_body_detected() {
        let td = TempDir::new().unwrap();
        let s = FileAuditSink::open(td.path()).unwrap();
        s.append(true, Some("tk"), Some("vm"), "released", 1_000)
            .unwrap();
        s.append(true, Some("tk2"), Some("vm"), "released", 1_010)
            .unwrap();
        let log_path = td.path().join(LOG_FILENAME);
        let mut content = fs::read_to_string(&log_path).unwrap();
        let idx = content.find("0:").unwrap() + 2;
        let mut bytes = content.into_bytes();
        bytes[idx] = if bytes[idx] == b'a' { b'b' } else { b'a' };
        content = String::from_utf8(bytes).unwrap();
        fs::write(&log_path, content).unwrap();
        assert!(s.verify().is_err());
    }

    #[test]
    fn tampered_chain_broken_detected() {
        let td = TempDir::new().unwrap();
        let s = FileAuditSink::open(td.path()).unwrap();
        s.append(true, Some("tk1"), Some("vm"), "r1", 1_000)
            .unwrap();
        s.append(true, Some("tk2"), Some("vm"), "r2", 1_010)
            .unwrap();
        let log_path = td.path().join(LOG_FILENAME);
        let content = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let mut new_content = String::new();
        new_content.push_str(lines[1]);
        new_content.push('\n');
        new_content.push_str(lines[0]);
        new_content.push('\n');
        fs::write(&log_path, new_content).unwrap();
        assert!(s.verify().is_err());
    }

    #[test]
    fn audit_sink_trait_record_writes_to_disk() {
        let td = TempDir::new().unwrap();
        let s = FileAuditSink::open(td.path()).unwrap();
        let sink: &dyn AuditSink = &s;
        sink.record(true, Some("tk-trait"), Some("vm"), "ok");
        let v = s.verify().unwrap();
        assert_eq!(v.records, 1);
    }

    /// Review round-1 H1: an attacker who removes the entire log file
    /// while head.sha256 still references records MUST be caught.
    #[test]
    fn log_deletion_with_stale_head_is_tamper() {
        let td = TempDir::new().unwrap();
        let s = FileAuditSink::open(td.path()).unwrap();
        s.append(true, Some("tk"), Some("vm"), "released", 1_000)
            .unwrap();
        // Drop the sink so the lock releases (we want the file lock free
        // so an attacker process could in principle do this — though
        // here we just simulate the on-disk state).
        drop(s);
        // Attacker: delete the log file, leave head.sha256.
        fs::remove_file(td.path().join(LOG_FILENAME)).unwrap();
        // Reopen — the open path itself catches this.
        let r = FileAuditSink::open(td.path());
        assert!(r.is_err(), "expected open to detect log-deletion tamper");
    }

    /// Review round-1 H1 variant: log truncated to empty with a stale
    /// non-zero head must be caught.
    #[test]
    fn empty_log_with_stale_head_is_tamper() {
        let td = TempDir::new().unwrap();
        let s = FileAuditSink::open(td.path()).unwrap();
        s.append(true, Some("tk"), Some("vm"), "released", 1_000)
            .unwrap();
        drop(s);
        fs::write(td.path().join(LOG_FILENAME), b"").unwrap();
        assert!(FileAuditSink::open(td.path()).is_err());
    }

    /// Review round-1 H3: open() repairs head.sha256 if the log is
    /// ahead. Simulates "log fsync happened, head rename did not".
    #[test]
    fn open_repairs_stale_head_against_log() {
        let td = TempDir::new().unwrap();
        let s = FileAuditSink::open(td.path()).unwrap();
        s.append(true, Some("tk"), Some("vm"), "released", 1_000)
            .unwrap();
        drop(s);
        // Tamper head to zero (simulates pre-rename crash).
        fs::write(td.path().join(HEAD_FILENAME), [0u8; 32]).unwrap();
        // Reopen — should repair head from the log.
        let s2 = FileAuditSink::open(td.path()).unwrap();
        // verify() passes only if head was repaired.
        let v = s2.verify().unwrap();
        assert_eq!(v.records, 1);
    }

    /// Review round-1 H2: cross-process lock prevents two
    /// simultaneous sinks. Spawn a thread that tries to open while we
    /// hold the lock; it must block. We use try_lock instead of lock
    /// in the test to keep determinism.
    #[test]
    fn cross_process_lock_excludes_second_opener() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;
        let td = TempDir::new().unwrap();
        let s = FileAuditSink::open(td.path()).unwrap();
        let dir = td.path().to_path_buf();
        let (tx, rx) = mpsc::channel();
        let h = thread::spawn(move || {
            // Try to acquire the lock with a short bounded wait.
            // Without the cross-process lock this would succeed.
            let lock = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(dir.join(LOCK_FILENAME))
                .unwrap();
            let _ = tx.send(lock.try_lock().is_ok());
        });
        let acquired = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(!acquired, "second opener acquired the lock — race window");
        drop(s);
        h.join().unwrap();
    }

    struct Release;

    impl crate::audit_journal::crash_tests::Harness for Release {
        const FILES: ChainFiles = FILES;
        type Sink = FileAuditSink;
        fn open(dir: &std::path::Path) -> Result<FileAuditSink> {
            FileAuditSink::open(dir)
        }
        fn append(s: &FileAuditSink, i: u64) -> [u8; 32] {
            s.append(
                true,
                Some(&format!("tk-{i}")),
                Some("vm"),
                "released",
                1_000 + i,
            )
            .unwrap()
        }
        fn records(s: &FileAuditSink) -> u64 {
            s.state.lock().unwrap().next_seq
        }
        fn page(s: &FileAuditSink) -> Vec<(u64, [u8; 32])> {
            let p = s.read_page(None, 500).unwrap();
            p.entries.iter().map(|e| (e.seq, e.sha256)).collect()
        }
        fn marker_reason(s: &FileAuditSink, seq: u64) -> Option<String> {
            let p = s.read_page(seq.checked_sub(1), 1).unwrap();
            let e = p.entries.into_iter().find(|e| e.seq == seq)?;
            let v: Value = ciborium::de::from_reader(e.body.as_slice()).unwrap();
            let Value::Map(m) = v else { return None };
            let get = |k: &str| {
                m.iter()
                    .find(|(kk, _)| kk.as_text() == Some(k))
                    .map(|(_, v)| v.clone())
            };
            let reason = get("reason")?.into_text().ok()?;
            let is_marker = reason.starts_with(crate::audit_journal::AUDIT_TRUNCATED)
                && get("granted") == Some(Value::Bool(false))
                && get("ticket_id") == Some(Value::Text(String::new()))
                && get("vm_id") == Some(Value::Text(String::new()));
            is_marker.then_some(reason)
        }
    }

    #[test]
    fn every_append_crash_point_starts_and_keeps_chaining() {
        crate::audit_journal::crash_tests::every_crash_point_starts::<Release>();
    }

    #[test]
    fn torn_tail_variants_start() {
        crate::audit_journal::crash_tests::torn_tail_variants_start::<Release>();
    }

    #[test]
    fn a_crash_inside_the_recovery_is_recovered() {
        crate::audit_journal::crash_tests::recovery_is_crash_safe::<Release>();
    }

    #[test]
    fn real_inconsistency_refuses_to_start() {
        crate::audit_journal::crash_tests::real_inconsistency_refuses::<Release>();
    }

    #[test]
    fn hooked_append_crash_points_start() {
        crate::audit_journal::crash_tests::hooked_append_crash_points::<Release>();
    }

    #[test]
    fn hooked_recovery_crash_points_start() {
        crate::audit_journal::crash_tests::hooked_recovery_crash_points::<Release>();
    }

    #[test]
    fn a_failed_head_write_leaves_no_temp() {
        crate::audit_journal::crash_tests::failed_head_write_leaves_no_temp::<Release>();
    }

    #[test]
    fn a_failed_append_is_cut_by_the_next() {
        crate::audit_journal::crash_tests::failed_append_is_cut_at_the_next::<Release>();
    }

    /// Review round-1 M1: verify() rejects a record whose body decodes
    /// to a wrong domain.
    #[test]
    fn wrong_domain_in_body_rejected() {
        let td = TempDir::new().unwrap();
        let s = FileAuditSink::open(td.path()).unwrap();
        s.append(true, Some("tk"), Some("vm"), "ok", 100).unwrap();
        // Forge a record with a different domain string but otherwise
        // canonical CBOR + matching SHA. Replace the existing line.
        let prev_hash = [0u8; 32];
        let v = Value::Map(vec![
            (
                Value::Text("domain".into()),
                Value::Text("NOT_THE_AUDIT_DOMAIN".into()),
            ),
            (Value::Text("granted".into()), Value::Bool(true)),
            (Value::Text("now_unix".into()), Value::Integer(100.into())),
            (
                Value::Text("prev_hash".into()),
                Value::Bytes(prev_hash.to_vec()),
            ),
            (Value::Text("reason".into()), Value::Text("ok".into())),
            (Value::Text("seq".into()), Value::Integer(0.into())),
            (Value::Text("ticket_id".into()), Value::Text("tk".into())),
            (Value::Text("vm_id".into()), Value::Text("vm".into())),
        ]);
        let body = to_canonical_vec(&v).unwrap();
        let mut h = [0u8; 32];
        h.copy_from_slice(Sha256::digest(&body).as_slice());
        let line = format!("0:{}:{}\n", hex::encode(&body), hex::encode(h));
        fs::write(td.path().join(LOG_FILENAME), line).unwrap();
        // Also need to repair head to point at this fake record so the
        // head-mismatch check doesn't short-circuit.
        fs::write(td.path().join(HEAD_FILENAME), h).unwrap();
        drop(s);
        // open() itself walks the log and rejects the wrong-domain
        // record before returning — this is the desired behavior.
        assert!(
            FileAuditSink::open(td.path()).is_err(),
            "wrong domain must be rejected at open"
        );
    }
}
