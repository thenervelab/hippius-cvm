//! Durable, hash-chained audit log for KBS ADMIN operations
//! (§24/§25 lifecycle pre-registration + future Phase B ops).
//!
//! ## Why a separate chain
//!
//! The release audit log (`audit.log`, see `crate::audit`) records
//! every §7 release decision. Its schema is pinned and `deny_unknown_
//! fields`-shaped — adding a new variant to its `AuditRecord` shape
//! breaks the canonical-CBOR encoding of every prior record and the
//! sentinel verifier (`sentinel/tools/kbs_audit.py`).
//!
//! Admin operations have a different shape (op discriminator, peer
//! cert SAN/serial, body sha256, status code, applied bool — none of
//! which the release schema carries). Adding them inline would either
//! (a) break the release chain or (b) require a discriminated
//! supertype that complicates the existing verifier.
//!
//! Instead, this module ships a PARALLEL chain at
//! `{dir}/admin.log` + `{dir}/admin.head.sha256` with its own
//! `admin.lock` and its own domain tag `HIPPIUS_KBS_ADMIN_V1`. The
//! existing release chain stays byte-for-byte unchanged.
//!
//! ## Schema (canonical CBOR map, RFC 8949 §4.2.1 sorted keys)
//!
//! ```text
//! {
//!   "applied":     <bool>,
//!   "body_sha256": <bstr 32>,
//!   "domain":      "HIPPIUS_KBS_ADMIN_V1",
//!   "now_unix":    <u64>,
//!   "op":          "register-vm" | …,
//!   "peer_san":    <text> (empty string when no client cert),
//!   "peer_serial": <text> (empty string when no client cert),
//!   "prev_hash":   <bstr 32>,
//!   "reason":      <text> (empty string when status==200),
//!   "seq":         <u64>,
//!   "status_code": <u16>,
//!   "ticket_id":   <text> (empty string when ticket-decode failed),
//!   "url_vm_id":   <text> (URL path component, always populated),
//!   "vm_id":       <text> (empty string when ticket-decode failed),
//! }
//! ```
//!
//! Both `peer_san` / `peer_serial` empty-strings are deliberate: every
//! field is always present, so the canonical-CBOR encoding has a
//! fixed shape regardless of the operation outcome. A pre-parse 4xx
//! still produces a record with `ticket_id=""`/`vm_id=""` but a
//! populated `url_vm_id` for attribution.

use crate::error::{KbsError, Result};
use ciborium::value::Value;
use hippius_types::cbor::{assert_canonical, to_canonical_vec};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Domain tag. Distinct from `audit::AUDIT_DOMAIN` so admin records
/// cannot replay as release records and vice-versa.
pub const ADMIN_AUDIT_DOMAIN: &str = "HIPPIUS_KBS_ADMIN_V1";

const LOG_FILENAME: &str = "admin.log";
const HEAD_FILENAME: &str = "admin.head.sha256";
const LOCK_FILENAME: &str = "admin.lock";

/// Outcome of a single admin operation, as recorded on disk.
#[derive(Debug, Clone)]
pub struct AdminAuditRecord<'a> {
    /// Always populated. Op discriminator string ("register-vm", etc.)
    /// — matches `hippius_types::admin::AdminOp::path_segment`.
    pub op: &'a str,
    /// The `vm_id` path segment as it appeared in the request URL.
    /// Always present even on pre-parse failures.
    pub url_vm_id: &'a str,
    /// Extracted from the verified ticket. Empty when ticket-decode
    /// failed.
    pub ticket_id: Option<&'a str>,
    /// Extracted from the verified ticket. Empty when ticket-decode
    /// failed.
    pub vm_id: Option<&'a str>,
    /// `true` when the operation mutated state, `false` otherwise
    /// (idempotent hit, 4xx).
    pub applied: bool,
    /// HTTP status code returned to the client.
    pub status_code: u16,
    /// Short subclass string ("ticket-decode", "state-divergent",
    /// "rate-limited", …). Empty when `status_code == 200`.
    pub reason: Option<&'a str>,
    /// Client cert subject (SAN URI), or `None` when no client cert
    /// was presented (the listener should already 401 in that case,
    /// but we still record the attempt for §13 attribution).
    pub peer_san: Option<&'a str>,
    /// Client cert serial number, hex. Same conditions as
    /// `peer_san`.
    pub peer_serial: Option<&'a str>,
    /// SHA-256 of the request body bytes. Pairs with the
    /// idempotency-store key for cross-referencing.
    pub body_sha256: &'a [u8; 32],
}

/// Durable, hash-chained sink. Mirrors `crate::audit::FileAuditSink`
/// structurally but writes to a separate file + head + lock.
pub struct FileAdminAuditSink {
    dir: PathBuf,
    _lock: File,
    state: Mutex<HeadState>,
}

#[derive(Debug, Clone)]
struct HeadState {
    prev_hash: [u8; 32],
    next_seq: u64,
}

impl FileAdminAuditSink {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)
            .map_err(|e| KbsError::Vault(format!("admin-audit create_dir_all: {e}")))?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join(LOCK_FILENAME))
            .map_err(|e| KbsError::Vault(format!("admin-audit lock open: {e}")))?;
        lock.lock()
            .map_err(|e| KbsError::Vault(format!("admin-audit lock acquire: {e}")))?;

        let verified = walk_log(&dir)?;
        let head_path = dir.join(HEAD_FILENAME);
        match fs::read(&head_path) {
            Ok(bytes) if bytes == verified.head => {}
            Ok(bytes) if bytes.is_empty() && verified.records == 0 => {}
            Ok(_) => write_head_atomic(&dir, &verified.head)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if verified.records > 0 {
                    write_head_atomic(&dir, &verified.head)?;
                }
            }
            Err(e) => return Err(KbsError::Vault(format!("admin-audit head read: {e}"))),
        }
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

    fn build_record(
        prev_hash: &[u8; 32],
        seq: u64,
        r: &AdminAuditRecord,
        now_unix: u64,
    ) -> Result<Vec<u8>> {
        let v = Value::Map(vec![
            (Value::Text("applied".into()), Value::Bool(r.applied)),
            (
                Value::Text("body_sha256".into()),
                Value::Bytes(r.body_sha256.to_vec()),
            ),
            (
                Value::Text("domain".into()),
                Value::Text(ADMIN_AUDIT_DOMAIN.into()),
            ),
            (
                Value::Text("now_unix".into()),
                Value::Integer(now_unix.into()),
            ),
            (Value::Text("op".into()), Value::Text(r.op.into())),
            (
                Value::Text("peer_san".into()),
                Value::Text(r.peer_san.unwrap_or("").into()),
            ),
            (
                Value::Text("peer_serial".into()),
                Value::Text(r.peer_serial.unwrap_or("").into()),
            ),
            (
                Value::Text("prev_hash".into()),
                Value::Bytes(prev_hash.to_vec()),
            ),
            (
                Value::Text("reason".into()),
                Value::Text(r.reason.unwrap_or("").into()),
            ),
            (Value::Text("seq".into()), Value::Integer(seq.into())),
            (
                Value::Text("status_code".into()),
                Value::Integer(u64::from(r.status_code).into()),
            ),
            (
                Value::Text("ticket_id".into()),
                Value::Text(r.ticket_id.unwrap_or("").into()),
            ),
            (
                Value::Text("url_vm_id".into()),
                Value::Text(r.url_vm_id.into()),
            ),
            (
                Value::Text("vm_id".into()),
                Value::Text(r.vm_id.unwrap_or("").into()),
            ),
        ]);
        to_canonical_vec(&v).map_err(|e| KbsError::Vault(format!("admin-audit encode: {e}")))
    }

    /// Append a record + update `admin.head.sha256` atomically.
    pub fn append(&self, r: &AdminAuditRecord, now_unix: u64) -> Result<[u8; 32]> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| KbsError::Vault("admin-audit lock poisoned".into()))?;
        let seq = g.next_seq;
        let body = Self::build_record(&g.prev_hash, seq, r, now_unix)?;
        let mut h = [0u8; 32];
        h.copy_from_slice(Sha256::digest(&body).as_slice());

        let log_path = self.dir.join(LOG_FILENAME);
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| KbsError::Vault(format!("admin-audit open: {e}")))?;
        let line = format!("{seq}:{}:{}\n", hex::encode(&body), hex::encode(h));
        f.write_all(line.as_bytes())
            .map_err(|e| KbsError::Vault(format!("admin-audit write: {e}")))?;
        f.sync_all()
            .map_err(|e| KbsError::Vault(format!("admin-audit fsync: {e}")))?;

        write_head_atomic(&self.dir, &h)?;

        g.prev_hash = h;
        g.next_seq = seq.saturating_add(1);
        Ok(h)
    }

    /// Re-walk the log on disk. Returns the recomputed head + record
    /// count — same shape as `crate::audit::VerifiedAudit` for
    /// compatibility with future sentinel tooling.
    pub fn verify(&self) -> Result<VerifiedAdminAudit> {
        walk_log(&self.dir)
    }
}

/// Result of [`FileAdminAuditSink::verify`].
#[derive(Debug, Clone)]
pub struct VerifiedAdminAudit {
    pub head: [u8; 32],
    pub records: u64,
}

fn walk_log(dir: &Path) -> Result<VerifiedAdminAudit> {
    let path = dir.join(LOG_FILENAME);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VerifiedAdminAudit {
                head: [0u8; 32],
                records: 0,
            });
        }
        Err(e) => return Err(KbsError::Vault(format!("admin-audit log read: {e}"))),
    };

    let mut head = [0u8; 32];
    let mut count: u64 = 0;
    for (line_idx, line) in bytes.split(|b| *b == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let s = std::str::from_utf8(line)
            .map_err(|_| KbsError::Vault(format!("admin-audit line {line_idx} non-utf8")))?;
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(KbsError::Vault(format!(
                "admin-audit line {line_idx} malformed (expected seq:body:hash)"
            )));
        }
        let seq: u64 = parts[0]
            .parse()
            .map_err(|_| KbsError::Vault(format!("admin-audit line {line_idx} bad seq")))?;
        if seq != count {
            return Err(KbsError::Vault(format!(
                "admin-audit line {line_idx} seq gap (got {seq}, want {count})"
            )));
        }
        let body = hex::decode(parts[1])
            .map_err(|_| KbsError::Vault(format!("admin-audit line {line_idx} bad body hex")))?;
        assert_canonical(&body).map_err(|e| {
            KbsError::Vault(format!(
                "admin-audit line {line_idx} non-canonical body: {e}"
            ))
        })?;
        let expected_hash = hex::decode(parts[2])
            .map_err(|_| KbsError::Vault(format!("admin-audit line {line_idx} bad hash hex")))?;
        if expected_hash.len() != 32 {
            return Err(KbsError::Vault(format!(
                "admin-audit line {line_idx} hash not 32 bytes"
            )));
        }
        let actual = Sha256::digest(&body);
        if actual.as_slice() != expected_hash {
            return Err(KbsError::Vault(format!(
                "admin-audit line {line_idx} hash mismatch (chain broken)"
            )));
        }
        head.copy_from_slice(&expected_hash);
        count = count.saturating_add(1);
    }
    Ok(VerifiedAdminAudit {
        head,
        records: count,
    })
}

fn write_head_atomic(dir: &Path, h: &[u8; 32]) -> Result<()> {
    let tmp = dir.join(format!("{HEAD_FILENAME}.tmp"));
    let final_ = dir.join(HEAD_FILENAME);
    fs::write(&tmp, h).map_err(|e| KbsError::Vault(format!("admin-audit head tmp write: {e}")))?;
    fs::rename(&tmp, &final_)
        .map_err(|e| KbsError::Vault(format!("admin-audit head rename: {e}")))?;
    if let Some(parent) = final_.parent() {
        let f = File::open(parent)
            .map_err(|e| KbsError::Vault(format!("admin-audit dir open: {e}")))?;
        let _ = f.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn rec<'a>(op: &'a str, vm: &'a str, applied: bool, status: u16) -> AdminAuditRecord<'a> {
        let bs = Box::leak(Box::new([0xab; 32]));
        AdminAuditRecord {
            op,
            url_vm_id: vm,
            ticket_id: Some("tk-1"),
            vm_id: Some(vm),
            applied,
            status_code: status,
            reason: if status == 200 { None } else { Some("test") },
            peer_san: Some("spiffe://hippius.network/vali"),
            peer_serial: Some("0a1b2c"),
            body_sha256: bs,
        }
    }

    #[test]
    fn empty_dir_opens_and_head_is_zero() {
        let td = TempDir::new().unwrap();
        let s = FileAdminAuditSink::open(td.path()).unwrap();
        let v = s.verify().unwrap();
        assert_eq!(v.head, [0u8; 32]);
        assert_eq!(v.records, 0);
    }

    #[test]
    fn appended_records_chain_correctly() {
        let td = TempDir::new().unwrap();
        let s = FileAdminAuditSink::open(td.path()).unwrap();
        let h1 = s
            .append(&rec("register-vm", "vm-1", true, 200), 1000)
            .unwrap();
        let h2 = s
            .append(&rec("register-vm", "vm-2", false, 409), 1001)
            .unwrap();
        assert_ne!(h1, h2);
        let v = s.verify().unwrap();
        assert_eq!(v.records, 2);
        assert_eq!(v.head, h2);
    }

    #[test]
    fn reopen_reads_existing_chain() {
        let td = TempDir::new().unwrap();
        {
            let s = FileAdminAuditSink::open(td.path()).unwrap();
            s.append(&rec("register-vm", "vm-1", true, 200), 1000)
                .unwrap();
            s.append(&rec("register-vm", "vm-2", true, 200), 1001)
                .unwrap();
        }
        let s2 = FileAdminAuditSink::open(td.path()).unwrap();
        let v = s2.verify().unwrap();
        assert_eq!(v.records, 2);
    }

    #[test]
    fn corrupted_log_fails_walk() {
        let td = TempDir::new().unwrap();
        let s = FileAdminAuditSink::open(td.path()).unwrap();
        s.append(&rec("register-vm", "vm-1", true, 200), 1000)
            .unwrap();
        drop(s);
        // Corrupt the log.
        let log = td.path().join(LOG_FILENAME);
        let mut bytes = fs::read(&log).unwrap();
        // Flip a byte in the body hex region.
        bytes[12] ^= 0x01;
        fs::write(&log, bytes).unwrap();
        // Re-open walks the log and surfaces the broken chain.
        assert!(FileAdminAuditSink::open(td.path()).is_err());
    }

    #[test]
    fn domain_is_stable() {
        // Pin: any change to the domain string is a §22-affecting
        // policy change. Audit log readers (sentinel) hard-code it.
        assert_eq!(ADMIN_AUDIT_DOMAIN, "HIPPIUS_KBS_ADMIN_V1");
    }
}
