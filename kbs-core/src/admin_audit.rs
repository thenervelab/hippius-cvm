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
//!   "reason":      <text> (empty string when status==200, except a register-vm of a
//!                  customer-held-keys VM: "key-mode:split" / "key-mode:customer"),
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

use crate::audit_journal::{self, ChainFiles, Walk, AUDIT_TRUNCATED};
use crate::audit_read::{self, AuditPage, LogIndex};
use crate::error::{KbsError, Result};
use ciborium::value::Value;
use hippius_types::cbor::to_canonical_vec;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Domain tag. Distinct from `audit::AUDIT_DOMAIN` so admin records
/// cannot replay as release records and vice-versa.
pub const ADMIN_AUDIT_DOMAIN: &str = "HIPPIUS_KBS_ADMIN_V1";

const LOG_FILENAME: &str = "admin.log";
const HEAD_FILENAME: &str = "admin.head.sha256";
const LOCK_FILENAME: &str = "admin.lock";
const FILES: ChainFiles = ChainFiles {
    label: "admin-audit",
    log: LOG_FILENAME,
    head: HEAD_FILENAME,
};

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
    /// "rate-limited", …). Empty when `status_code == 200` — except a
    /// successful register-vm of an M1/M2 VM, which names the pinned key
    /// mode (`crate::admin::record_admin_register_outcome`).
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
    /// Byte index of `admin.log` for the read route
    /// (`crate::audit_read`).
    index: LogIndex,
}

impl FileAdminAuditSink {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        Self::open_at(dir, now())
    }

    /// [`Self::open`] with the clock of an `audit-truncated` record chained
    /// at open (tests and the shared wire fixture pin it).
    pub fn open_at(dir: impl Into<PathBuf>, now_unix: u64) -> Result<Self> {
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

        // Journal semantics — see `crate::audit_journal`: a torn trailing
        // record is truncated (and an `audit-truncated` record chained in its
        // place); only a state no crash produces refuses.
        let opened = audit_journal::open_recover(&dir, FILES, walk_bytes, |prev, seq, torn| {
            let reason = torn.marker_reason(seq);
            let dropped_sha256 = torn.sha256();
            let marker = truncation_record(&reason, &dropped_sha256);
            Self::build_record(prev, seq, &marker, now_unix)
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

        let line = format!("{seq}:{}:{}\n", hex::encode(&body), hex::encode(h));
        let offset = audit_journal::append_line(&self.dir, FILES, g.index.end(), line.as_bytes())?;

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
    /// `crate::audit_read`. The mutex is held only to cut the snapshot.
    pub fn read_page(&self, after_seq: Option<u64>, limit: u32) -> Result<AuditPage> {
        let snap = {
            let g = self
                .state
                .lock()
                .map_err(|_| KbsError::Vault("admin-audit lock poisoned".into()))?;
            g.index.snapshot(g.prev_hash, after_seq, limit)
        };
        audit_read::read_snapshot(&self.dir.join(LOG_FILENAME), snap)
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

/// Strict re-walk: a torn tail is an error here (open has already
/// truncated any).
fn walk_log(dir: &Path) -> Result<VerifiedAdminAudit> {
    let bytes = match fs::read(dir.join(LOG_FILENAME)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(KbsError::Vault(format!("admin-audit log read: {e}"))),
    };
    let w = walk_bytes(&bytes, None).map_err(|e| KbsError::Vault(format!("admin-audit: {e}")))?;
    if let Some(t) = w.torn {
        return Err(KbsError::Vault(format!(
            "admin-audit: torn tail at byte {}: {}",
            t.offset, t.why
        )));
    }
    Ok(VerifiedAdminAudit {
        head: w.head,
        records: w.records,
    })
}

fn walk_bytes(bytes: &[u8], head_probe: Option<[u8; 32]>) -> std::result::Result<Walk, String> {
    audit_journal::walk(bytes, head_probe, check_body)
}

/// A self-consistent admin record at chain position `(seq, prev)`: the
/// domain tag, its own `seq`, and its `prev_hash` must all match.
fn check_body(body: &[u8], seq: u64, prev: &[u8; 32]) -> std::result::Result<(), String> {
    let v: Value = ciborium::de::from_reader(body).map_err(|_| "body is not CBOR".to_string())?;
    let Value::Map(entries) = v else {
        return Err("body is not a map".into());
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
            .map(|(_, v)| v)
    };
    match field("domain") {
        Some(Value::Text(d)) if d == ADMIN_AUDIT_DOMAIN => {}
        _ => return Err("wrong domain".into()),
    }
    match field("seq") {
        Some(Value::Integer(i)) if u64::try_from(*i).ok() == Some(seq) => {}
        _ => return Err(format!("body seq is not {seq}")),
    }
    match field("prev_hash") {
        Some(Value::Bytes(b)) if b.as_slice() == prev.as_slice() => Ok(()),
        _ => Err("prev_hash is not the previous record's hash (chain broken)".into()),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The `audit-truncated` record chained in place of a truncated torn
/// tail (`crate::audit_journal`): `op="audit-truncated"`, the marker
/// `reason`, and the full sha256 of the dropped bytes as `body_sha256`.
fn truncation_record<'a>(reason: &'a str, dropped_sha256: &'a [u8; 32]) -> AdminAuditRecord<'a> {
    AdminAuditRecord {
        op: AUDIT_TRUNCATED,
        url_vm_id: "",
        ticket_id: None,
        vm_id: None,
        applied: false,
        status_code: 0,
        reason: Some(reason),
        peer_san: None,
        peer_serial: None,
        body_sha256: dropped_sha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_journal::crash_tests::Harness;
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
    fn a_corrupted_middle_record_refuses_to_start() {
        let td = TempDir::new().unwrap();
        let s = FileAdminAuditSink::open(td.path()).unwrap();
        s.append(&rec("register-vm", "vm-1", true, 200), 1000)
            .unwrap();
        s.append(&rec("register-vm", "vm-2", true, 200), 1001)
            .unwrap();
        drop(s);
        // Flip a byte in record 0's body hex: a record follows it.
        let log = td.path().join(LOG_FILENAME);
        let mut bytes = fs::read(&log).unwrap();
        bytes[12] ^= 0x01;
        fs::write(&log, bytes).unwrap();
        assert!(FileAdminAuditSink::open(td.path()).is_err());
    }

    struct Admin;

    impl crate::audit_journal::crash_tests::Harness for Admin {
        const FILES: ChainFiles = FILES;
        type Sink = FileAdminAuditSink;
        fn open(dir: &Path) -> Result<FileAdminAuditSink> {
            FileAdminAuditSink::open(dir)
        }
        fn append(s: &FileAdminAuditSink, i: u64) -> [u8; 32] {
            let vm = format!("vm-{i}");
            s.append(&rec("register-vm", &vm, true, 200), 1_000 + i)
                .unwrap()
        }
        fn records(s: &FileAdminAuditSink) -> u64 {
            s.state.lock().unwrap().next_seq
        }
        fn page(s: &FileAdminAuditSink) -> Vec<(u64, [u8; 32])> {
            let p = s.read_page(None, 500).unwrap();
            p.entries.iter().map(|e| (e.seq, e.sha256)).collect()
        }
        fn marker_reason(s: &FileAdminAuditSink, seq: u64) -> Option<String> {
            let p = s.read_page(seq.checked_sub(1), 1).unwrap();
            let e = p.entries.into_iter().find(|e| e.seq == seq)?;
            let v: Value = ciborium::de::from_reader(e.body.as_slice()).unwrap();
            let Value::Map(m) = v else { return None };
            let get = |k: &str| {
                m.iter()
                    .find(|(kk, _)| kk.as_text() == Some(k))
                    .map(|(_, v)| v.clone())
            };
            if get("op")? != Value::Text(AUDIT_TRUNCATED.into()) {
                return None;
            }
            assert_eq!(get("applied"), Some(Value::Bool(false)));
            assert_eq!(get("status_code"), Some(Value::Integer(0.into())));
            get("reason")?.into_text().ok()
        }
    }

    #[test]
    fn every_append_crash_point_starts_and_keeps_chaining() {
        crate::audit_journal::crash_tests::every_crash_point_starts::<Admin>();
    }

    #[test]
    fn torn_tail_variants_start() {
        crate::audit_journal::crash_tests::torn_tail_variants_start::<Admin>();
    }

    #[test]
    fn a_crash_inside_the_recovery_is_recovered() {
        crate::audit_journal::crash_tests::recovery_is_crash_safe::<Admin>();
    }

    #[test]
    fn real_inconsistency_refuses_to_start() {
        crate::audit_journal::crash_tests::real_inconsistency_refuses::<Admin>();
    }

    #[test]
    fn hooked_append_crash_points_start() {
        crate::audit_journal::crash_tests::hooked_append_crash_points::<Admin>();
    }

    #[test]
    fn hooked_recovery_crash_points_start() {
        crate::audit_journal::crash_tests::hooked_recovery_crash_points::<Admin>();
    }

    #[test]
    fn a_failed_head_write_leaves_no_temp() {
        crate::audit_journal::crash_tests::failed_head_write_leaves_no_temp::<Admin>();
    }

    #[test]
    fn a_failed_append_is_cut_by_the_next() {
        crate::audit_journal::crash_tests::failed_append_is_cut_at_the_next::<Admin>();
    }

    #[test]
    fn the_admin_marker_carries_the_full_sha256_of_the_dropped_bytes() {
        let td = TempDir::new().unwrap();
        crate::audit_journal::crash_tests::chain::<Admin>(td.path(), 1);
        let torn = b"1:00ff";
        let mut f = OpenOptions::new()
            .append(true)
            .open(td.path().join(LOG_FILENAME))
            .unwrap();
        std::io::Write::write_all(&mut f, torn).unwrap();
        drop(f);
        let s = FileAdminAuditSink::open(td.path()).unwrap();
        let e = s.read_page(Some(0), 1).unwrap().entries.remove(0);
        let v: Value = ciborium::de::from_reader(e.body.as_slice()).unwrap();
        let Value::Map(m) = v else { panic!() };
        let bs = m
            .iter()
            .find(|(k, _)| k.as_text() == Some("body_sha256"))
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(bs, Value::Bytes(Sha256::digest(torn).to_vec()));
        let reason = Admin::marker_reason(&s, 1).unwrap();
        assert_eq!(
            reason,
            format!(
                "audit-truncated:seq=1:len=6:sha256={}",
                &hex::encode(Sha256::digest(torn))[..16]
            )
        );
    }

    #[test]
    fn a_deleted_or_emptied_log_under_a_live_head_is_refused() {
        for emptied in [false, true] {
            let td = TempDir::new().unwrap();
            let s = FileAdminAuditSink::open(td.path()).unwrap();
            s.append(&rec("register-vm", "vm-1", true, 200), 1000)
                .unwrap();
            drop(s);
            let log = td.path().join(LOG_FILENAME);
            if emptied {
                fs::write(&log, b"").unwrap();
            } else {
                fs::remove_file(&log).unwrap();
            }
            assert!(
                FileAdminAuditSink::open(td.path()).is_err(),
                "emptied={emptied}: a cut chain must not reopen as a fresh one"
            );
        }
        // A fresh dir (no head, or a zero head) still opens.
        let td = TempDir::new().unwrap();
        fs::write(td.path().join(HEAD_FILENAME), [0u8; 32]).unwrap();
        assert!(FileAdminAuditSink::open(td.path()).is_ok());
    }

    #[test]
    fn domain_is_stable() {
        // Pin: any change to the domain string is a §22-affecting
        // policy change. Audit log readers (sentinel) hard-code it.
        assert_eq!(ADMIN_AUDIT_DOMAIN, "HIPPIUS_KBS_ADMIN_V1");
    }
}
