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

use crate::error::{KbsError, Result};
use crate::release::AuditSink;
use ciborium::value::Value;
use hippius_types::cbor::{assert_canonical, to_canonical_vec};
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
}

impl FileAuditSink {
    /// Open / create the log directory. Takes the directory's
    /// exclusive advisory lock for the lifetime of `Self`. ALWAYS walks
    /// `audit.log` to derive the true tail — `head.sha256` is treated
    /// as a cache and repaired on disagreement.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
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

        // Walk the log to compute the real tail. If the log is
        // absent, the chain is fresh (prev_hash = 0). `head.sha256` is
        // repaired if it doesn't agree.
        let verified = walk_log(&dir)?;
        let head_path = dir.join(HEAD_FILENAME);
        match fs::read(&head_path) {
            Ok(bytes) if bytes == verified.head => {}
            Ok(bytes) if bytes.is_empty() && verified.records == 0 => {}
            Ok(_) => {
                // Stale or empty/zero head + records present (or vice
                // versa) — repair to match the log.
                write_head_atomic(&dir, &verified.head)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if verified.records > 0 {
                    write_head_atomic(&dir, &verified.head)?;
                }
            }
            Err(e) => return Err(KbsError::Vault(format!("audit head read: {e}"))),
        }
        // Also clean up any stale temp head from a crashed prior run.
        let _ = fs::remove_file(dir.join(format!("{HEAD_FILENAME}.tmp")));
        Ok(Self {
            dir,
            _lock: lock,
            state: Mutex::new(HeadState {
                prev_hash: verified.head,
                next_seq: verified.records,
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
        let log_path = self.dir.join(LOG_FILENAME);
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| KbsError::Vault(format!("audit open: {e}")))?;
        let line = format!("{seq}:{}:{}\n", hex::encode(&body), hex::encode(h));
        f.write_all(line.as_bytes())
            .map_err(|e| KbsError::Vault(format!("audit write: {e}")))?;
        f.sync_all()
            .map_err(|e| KbsError::Vault(format!("audit fsync: {e}")))?;

        // Update head pointer via atomic rename.
        write_head_atomic(&self.dir, &h)?;

        g.prev_hash = h;
        g.next_seq = seq.saturating_add(1);
        Ok(h)
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
/// count and the computed tail hash. Does NOT touch `head.sha256` —
/// the caller decides whether to reconcile.
fn walk_log(dir: &std::path::Path) -> Result<VerifiedAudit> {
    let log_path = dir.join(LOG_FILENAME);
    let head_path = dir.join(HEAD_FILENAME);
    let bytes = match fs::read(&log_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Log missing. If head exists with a non-zero hash, the
            // log was deleted out from under us — tamper.
            match fs::read(&head_path) {
                Ok(h) if h.iter().all(|b| *b == 0) => {}
                Ok(h) if h.is_empty() => {}
                Ok(_) => {
                    return Err(KbsError::Vault(
                        "audit log missing but head.sha256 references records (tamper)".into(),
                    ))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(KbsError::Vault(format!("audit head probe: {e}"))),
            }
            return Ok(VerifiedAudit {
                records: 0,
                head: [0u8; 32],
            });
        }
        Err(e) => return Err(KbsError::Vault(format!("audit walk read: {e}"))),
    };
    if bytes.is_empty() {
        // Empty log file. Head must be absent or zero.
        match fs::read(&head_path) {
            Ok(h) if h.iter().all(|b| *b == 0) => {}
            Ok(h) if h.is_empty() => {}
            Ok(_) => {
                return Err(KbsError::Vault(
                    "audit log empty but head.sha256 references records (tamper)".into(),
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(KbsError::Vault(format!("audit head probe: {e}"))),
        }
        return Ok(VerifiedAudit {
            records: 0,
            head: [0u8; 32],
        });
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| KbsError::Vault(format!("audit log not utf8: {e}")))?;
    let mut expected_prev = [0u8; 32];
    let mut records = 0u64;
    let mut last_hash = [0u8; 32];
    for (lineno, raw) in text.lines().enumerate() {
        let mut parts = raw.splitn(3, ':');
        let seq_str = parts
            .next()
            .ok_or_else(|| KbsError::Vault(format!("audit line {lineno}: missing seq")))?;
        let body_hex = parts
            .next()
            .ok_or_else(|| KbsError::Vault(format!("audit line {lineno}: missing body")))?;
        let hash_hex = parts
            .next()
            .ok_or_else(|| KbsError::Vault(format!("audit line {lineno}: missing hash")))?;
        let line_seq: u64 = seq_str
            .parse()
            .map_err(|_| KbsError::Vault(format!("audit line {lineno}: bad seq")))?;
        if line_seq != records {
            return Err(KbsError::Vault(format!(
                "audit line {lineno}: seq {line_seq} != expected {records}"
            )));
        }
        let body = hex::decode(body_hex)
            .map_err(|_| KbsError::Vault(format!("audit line {lineno}: bad body hex")))?;
        // Strict: canonical CBOR + correct domain + matching seq +
        // matching prev_hash, ALL enforced before we accept the line.
        assert_canonical(&body)
            .map_err(|e| KbsError::Vault(format!("audit line {lineno}: non-canonical: {e}")))?;
        let decoded = decode_strict(&body)
            .ok_or_else(|| KbsError::Vault(format!("audit line {lineno}: invalid schema")))?;
        if decoded.domain != AUDIT_DOMAIN {
            return Err(KbsError::Vault(format!(
                "audit line {lineno}: wrong domain"
            )));
        }
        if decoded.seq != line_seq {
            return Err(KbsError::Vault(format!(
                "audit line {lineno}: body seq {} != line seq {}",
                decoded.seq, line_seq
            )));
        }
        let mut recomputed = [0u8; 32];
        recomputed.copy_from_slice(Sha256::digest(&body).as_slice());
        let on_disk: Vec<u8> = hex::decode(hash_hex)
            .map_err(|_| KbsError::Vault(format!("audit line {lineno}: bad hash hex")))?;
        if on_disk != recomputed {
            return Err(KbsError::Vault(format!(
                "audit line {lineno}: hash mismatch — body tampered"
            )));
        }
        if decoded.prev_hash != expected_prev {
            return Err(KbsError::Vault(format!(
                "audit line {lineno}: chain broken (prev_hash != expected)"
            )));
        }
        expected_prev = recomputed;
        last_hash = recomputed;
        records += 1;
    }
    Ok(VerifiedAudit {
        records,
        head: last_hash,
    })
}

/// Atomic-rename write of `head.sha256`. Uses a unique-name temp so
/// stale `.tmp` from a previous crash doesn't block this write.
fn write_head_atomic(dir: &std::path::Path, h: &[u8; 32]) -> Result<()> {
    use rand::RngCore;
    let head_path = dir.join(HEAD_FILENAME);
    let mut rand_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
    let tmp = dir.join(format!("{HEAD_FILENAME}.tmp.{}", hex::encode(rand_bytes)));
    let mut hf = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .map_err(|e| KbsError::Vault(format!("audit head temp open: {e}")))?;
    hf.write_all(h)
        .map_err(|e| KbsError::Vault(format!("audit head write: {e}")))?;
    hf.sync_all()
        .map_err(|e| KbsError::Vault(format!("audit head fsync: {e}")))?;
    drop(hf);
    fs::rename(&tmp, &head_path).map_err(|e| KbsError::Vault(format!("audit head rename: {e}")))?;
    let dirf = File::open(dir).map_err(|e| KbsError::Vault(format!("audit dir open: {e}")))?;
    dirf.sync_all()
        .map_err(|e| KbsError::Vault(format!("audit dir fsync: {e}")))?;
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Err(e) = self.append(granted, ticket_id, vm_id, reason, now) {
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

    /// Codex round-1 H1: an attacker who removes the entire log file
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

    /// Codex round-1 H1 variant: log truncated to empty with a stale
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

    /// Codex round-1 H3: open() repairs head.sha256 if the log is
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

    /// Codex round-1 H2: cross-process lock prevents two
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

    /// Codex round-1 M1: verify() rejects a record whose body decodes
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
