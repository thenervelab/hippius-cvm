//! Read side of the KBS hash-chained audit logs — the release chain
//! (`crate::audit`, `audit.log`) and the admin chain
//! (`crate::admin_audit`, `admin.log`).
//!
//! ## Why
//!
//! Both chains live on an emptyDir inside the Kata SEV-SNP CVM: the host
//! cannot read them and a KBS restart wipes them. `GET /v1/admin/audit`
//! (mTLS admin listener) serves them page by page so vali can pull them
//! out and keep them. The page carries the EXACT persisted records — the
//! reader re-verifies the chain; the KBS vouching for itself would prove
//! nothing.
//!
//! ## Read-only by construction
//!
//! A page is cut from a snapshot taken under the sink's in-process mutex
//! (record count, head, and the byte offsets of the requested records),
//! then the bytes are read with the mutex RELEASED — a release never
//! waits on a reader. Every record in the snapshot's byte range was
//! written and fsynced before the snapshot, and the log is append-only,
//! so the range is stable. Nothing here writes a file, advances a
//! counter, or appends an audit record.
//!
//! ## Why a read is not audited
//!
//! Same rule as the other admin reads (`…/evidence`, `…/volume-stamp`,
//! `…/config`): the chains record state CHANGES. Auditing this route in
//! particular would feed itself — every poll would append a record that
//! the next poll fetches and whose fetch appends another — so an idle
//! KBS polled by vali would grow its emptyDir forever.

use crate::error::{KbsError, Result};
use ciborium::value::Value;
use hippius_types::admin::{AdminAuditEntry, AdminAuditPageResponse, ADMIN_AUDIT_PAGE_MAX};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Byte budget of one page. The record cap bounds the COUNT; an admin
/// record carries request-derived strings (the URL `vm_id`), so the count
/// alone does not bound what a page allocates. A page stops at the last
/// whole record under this budget — always at least one record, so a
/// reader still advances past an oversized one.
pub const MAX_AUDIT_PAGE_BYTES: u64 = 4 * 1024 * 1024;

/// Which chain a page is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLogKind {
    /// `crate::admin_audit` — lifecycle/admin operations.
    Admin,
    /// `crate::audit` — every §7 release decision.
    Release,
}

impl AuditLogKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Release => "release",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "release" => Some(Self::Release),
            _ => None,
        }
    }
}

/// Byte index of an audit log: where each record's line starts, where
/// the file ends, and the chain's genesis hash. Maintained by the sink
/// under its mutex (built at open from the verified walk, extended on
/// every append).
#[derive(Debug, Clone, Default)]
pub(crate) struct LogIndex {
    /// `offsets[seq]` = byte offset of record `seq`'s line.
    offsets: Vec<u64>,
    /// File length after the last indexed record.
    end: u64,
    /// `sha256` of record 0.
    genesis: Option<[u8; 32]>,
}

impl LogIndex {
    /// Index built from the verified log bytes: `line_starts[i]` is the
    /// offset of record `i`, `genesis` the hash of record 0 if any.
    pub(crate) fn from_walk(line_starts: Vec<u64>, end: u64, genesis: Option<[u8; 32]>) -> Self {
        Self {
            offsets: line_starts,
            end,
            genesis,
        }
    }

    /// Record one appended line.
    pub(crate) fn push(&mut self, offset: u64, line_len: u64, hash: [u8; 32]) {
        if self.offsets.is_empty() {
            self.genesis = Some(hash);
        }
        self.offsets.push(offset);
        self.end = offset.saturating_add(line_len);
    }

    pub(crate) fn len(&self) -> u64 {
        self.offsets.len() as u64
    }

    /// File length after the last indexed record.
    pub(crate) fn end(&self) -> u64 {
        self.end
    }

    /// Move the indexed end (a terminator appended at open).
    pub(crate) fn set_end(&mut self, end: u64) {
        self.end = end;
    }

    /// Cut a page snapshot: which seqs, which bytes. Pure.
    pub(crate) fn snapshot(
        &self,
        head: [u8; 32],
        after_seq: Option<u64>,
        limit: u32,
    ) -> PageSnapshot {
        let count = self.len();
        let start = after_seq.map_or(0, |s| s.saturating_add(1));
        let limit = u64::from(limit.clamp(1, ADMIN_AUDIT_PAGE_MAX));
        let mut stop = start.saturating_add(limit).min(count);
        let range = if start < stop {
            // Every index here is ≤ count ≤ usize::MAX (the Vec holds them).
            let end_of = |seq_excl: u64| {
                if seq_excl == count {
                    self.end
                } else {
                    self.offsets[seq_excl as usize]
                }
            };
            let from = self.offsets[start as usize];
            // Shrink to the byte budget, keeping at least one record.
            let mut k = start + 1;
            while k < stop && end_of(k + 1).saturating_sub(from) <= MAX_AUDIT_PAGE_BYTES {
                k += 1;
            }
            stop = k;
            Some((start, stop, from, end_of(stop)))
        } else {
            None
        };
        PageSnapshot {
            genesis: self.genesis,
            head_seq: count.checked_sub(1),
            head,
            range,
        }
    }
}

/// What a page covers, cut under the sink's mutex.
#[derive(Debug, Clone)]
pub(crate) struct PageSnapshot {
    genesis: Option<[u8; 32]>,
    head_seq: Option<u64>,
    head: [u8; 32],
    /// `(first_seq, end_seq_exclusive, first_byte, end_byte_exclusive)`.
    range: Option<(u64, u64, u64, u64)>,
}

/// One persisted record, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPageEntry {
    pub seq: u64,
    /// The canonical-CBOR body exactly as stored.
    pub body: Vec<u8>,
    /// The hash stored next to it (NOT recomputed).
    pub sha256: [u8; 32],
    /// The `prev_hash` field decoded out of `body`.
    pub prev_hash: [u8; 32],
}

/// A page of one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPage {
    pub genesis: Option<[u8; 32]>,
    pub head_seq: Option<u64>,
    pub head: [u8; 32],
    pub entries: Vec<AuditPageEntry>,
}

impl AuditPage {
    /// The `GET /v1/admin/audit` 200 body.
    pub fn to_wire(&self, log: AuditLogKind) -> AdminAuditPageResponse {
        AdminAuditPageResponse {
            v: 1,
            log: log.as_str().to_string(),
            genesis_hash_hex: self.genesis.map(hex::encode),
            head_seq: self.head_seq,
            head_hash_hex: hex::encode(self.head),
            entries: self
                .entries
                .iter()
                .map(|e| AdminAuditEntry {
                    seq: e.seq,
                    body_cbor_hex: hex::encode(&e.body),
                    sha256_hex: hex::encode(e.sha256),
                    prev_hash_hex: hex::encode(e.prev_hash),
                })
                .collect(),
        }
    }
}

fn corrupt(what: &str) -> KbsError {
    KbsError::Vault(format!("audit-read: {what}"))
}

/// Read the snapshot's byte range of `log_path` and parse it. Fails
/// loudly — never skips — on anything that is not exactly the records
/// the snapshot named, in order.
pub(crate) fn read_snapshot(log_path: &Path, snap: PageSnapshot) -> Result<AuditPage> {
    let mut entries = Vec::new();
    if let Some((first_seq, end_seq, from, to)) = snap.range {
        let len = usize::try_from(to.saturating_sub(from))
            .map_err(|_| corrupt("page byte range overflows usize"))?;
        let mut buf = vec![0u8; len];
        let mut f = File::open(log_path).map_err(|e| corrupt(&format!("open: {e}")))?;
        f.seek(SeekFrom::Start(from))
            .map_err(|e| corrupt(&format!("seek: {e}")))?;
        f.read_exact(&mut buf)
            .map_err(|e| corrupt(&format!("read: {e}")))?;

        let mut expected = first_seq;
        for line in buf.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            if expected >= end_seq {
                return Err(corrupt("more records in range than indexed"));
            }
            let entry = parse_line(line, expected)?;
            entries.push(entry);
            expected = expected.saturating_add(1);
        }
        if expected != end_seq {
            return Err(corrupt(&format!(
                "range held {} records, index says {}",
                expected - first_seq,
                end_seq - first_seq
            )));
        }
    }
    Ok(AuditPage {
        genesis: snap.genesis,
        head_seq: snap.head_seq,
        head: snap.head,
        entries,
    })
}

fn parse_line(line: &[u8], expected_seq: u64) -> Result<AuditPageEntry> {
    // The release walker (`str::lines`) accepts a CRLF terminator; serve
    // exactly what it accepted.
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let s = std::str::from_utf8(line).map_err(|_| corrupt("line is not utf-8"))?;
    let mut parts = s.splitn(3, ':');
    let (Some(seq_s), Some(body_hex), Some(hash_hex)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(corrupt("line is not seq:body:hash"));
    };
    let seq: u64 = seq_s.parse().map_err(|_| corrupt("bad seq"))?;
    if seq != expected_seq {
        return Err(corrupt(&format!(
            "seq {seq} where the index expects {expected_seq}"
        )));
    }
    let body = hex::decode(body_hex).map_err(|_| corrupt("bad body hex"))?;
    let hash_v = hex::decode(hash_hex).map_err(|_| corrupt("bad hash hex"))?;
    let sha256: [u8; 32] = hash_v
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("hash is not 32 bytes"))?;
    let prev_hash = body_prev_hash(&body)
        .ok_or_else(|| corrupt(&format!("record {seq} carries no 32-byte prev_hash")))?;
    Ok(AuditPageEntry {
        seq,
        body,
        sha256,
        prev_hash,
    })
}

/// The `prev_hash` field of a record body (both chains name it so).
fn body_prev_hash(body: &[u8]) -> Option<[u8; 32]> {
    let v: Value = ciborium::de::from_reader(body).ok()?;
    let Value::Map(entries) = v else { return None };
    entries.into_iter().find_map(|(k, v)| match (k, v) {
        (Value::Text(k), Value::Bytes(b)) if k == "prev_hash" => b.as_slice().try_into().ok(),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_clamps_the_limit_and_handles_the_edges() {
        let mut ix = LogIndex::default();
        for i in 0..1000u64 {
            ix.push(i * 10, 10, [i as u8; 32]);
        }
        let s = ix.snapshot([7; 32], None, 10_000);
        assert_eq!(s.range, Some((0, 500, 0, 5000)));
        assert_eq!(s.head_seq, Some(999));
        assert_eq!(s.genesis, Some([0; 32]));
        let s = ix.snapshot([7; 32], Some(997), 500);
        assert_eq!(s.range, Some((998, 1000, 9980, 10_000)));
        assert!(ix.snapshot([7; 32], Some(999), 5).range.is_none());
        assert!(ix.snapshot([7; 32], Some(u64::MAX), 5).range.is_none());
        let s = ix.snapshot([7; 32], Some(1), 0);
        assert_eq!(s.range, Some((2, 3, 20, 30)), "limit 0 is clamped up to 1");
        let empty = LogIndex::default().snapshot([0; 32], None, 5);
        assert!(empty.range.is_none());
        assert_eq!(empty.head_seq, None);
        assert_eq!(empty.genesis, None);
    }

    use crate::admin_audit::{AdminAuditRecord, FileAdminAuditSink};
    use crate::audit::FileAuditSink;
    use sha2::{Digest, Sha256};
    use std::fs;
    use tempfile::TempDir;

    /// `(seq, body_hex, hash_hex)` of every line on disk — the ground truth
    /// a page must reproduce byte for byte.
    fn disk_lines(path: &Path) -> Vec<(u64, String, String)> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| {
                let mut p = l.splitn(3, ':');
                (
                    p.next().unwrap().parse().unwrap(),
                    p.next().unwrap().to_string(),
                    p.next().unwrap().to_string(),
                )
            })
            .collect()
    }

    fn release_sink(td: &TempDir, n: u64) -> FileAuditSink {
        let s = FileAuditSink::open(td.path()).unwrap();
        for i in 0..n {
            let reason = if i % 2 == 0 {
                "released"
            } else {
                "ticket_expired"
            };
            s.append(
                i % 2 == 0,
                Some(&format!("tk-{i}")),
                Some("vm-a"),
                reason,
                1_000 + i,
            )
            .unwrap();
        }
        s
    }

    fn assert_page_is_disk(page: &AuditPage, disk: &[(u64, String, String)]) {
        for e in &page.entries {
            let (seq, body_hex, hash_hex) = &disk[e.seq as usize];
            assert_eq!(e.seq, *seq);
            assert_eq!(
                hex::encode(&e.body),
                *body_hex,
                "body must be the stored bytes"
            );
            assert_eq!(
                hex::encode(e.sha256),
                *hash_hex,
                "hash must be the stored hash"
            );
            let expected_prev = if e.seq == 0 {
                "00".repeat(32)
            } else {
                disk[e.seq as usize - 1].2.clone()
            };
            assert_eq!(hex::encode(e.prev_hash), expected_prev);
        }
    }

    #[test]
    fn release_page_returns_the_exact_persisted_records() {
        let td = TempDir::new().unwrap();
        let s = release_sink(&td, 5);
        let disk = disk_lines(&td.path().join("audit.log"));
        let page = s.read_page(None, 500).unwrap();
        assert_eq!(page.entries.len(), 5);
        assert_page_is_disk(&page, &disk);
        assert_eq!(page.head_seq, Some(4));
        assert_eq!(hex::encode(page.head), disk[4].2);
        assert_eq!(page.genesis.map(hex::encode), Some(disk[0].2.clone()));
        // The stored hash IS sha256(body) on an honest log.
        let e = &page.entries[3];
        assert_eq!(Sha256::digest(&e.body).as_slice(), e.sha256);
    }

    #[test]
    fn pages_tile_the_log_without_gap_or_overlap() {
        let td = TempDir::new().unwrap();
        let s = release_sink(&td, 7);
        let disk = disk_lines(&td.path().join("audit.log"));
        let mut seen = Vec::new();
        let mut after = None;
        loop {
            let page = s.read_page(after, 3).unwrap();
            assert!(page.entries.len() <= 3);
            if page.entries.is_empty() {
                break;
            }
            assert_page_is_disk(&page, &disk);
            after = page.entries.last().map(|e| e.seq);
            seen.extend(page.entries.iter().map(|e| e.seq));
        }
        assert_eq!(seen, (0..7).collect::<Vec<_>>());
    }

    #[test]
    fn the_cap_holds_whatever_the_limit() {
        let td = TempDir::new().unwrap();
        let s = release_sink(&td, u64::from(ADMIN_AUDIT_PAGE_MAX) + 3);
        let page = s.read_page(None, u32::MAX).unwrap();
        assert_eq!(page.entries.len(), ADMIN_AUDIT_PAGE_MAX as usize);
        let rest = s
            .read_page(Some(u64::from(ADMIN_AUDIT_PAGE_MAX) - 1), u32::MAX)
            .unwrap();
        assert_eq!(rest.entries.len(), 3);
        assert_eq!(rest.entries[0].seq, u64::from(ADMIN_AUDIT_PAGE_MAX));
    }

    #[test]
    fn reading_mutates_nothing_and_appends_keep_the_index_current() {
        let td = TempDir::new().unwrap();
        let s = release_sink(&td, 3);
        let log = td.path().join("audit.log");
        let head = td.path().join("head.sha256");
        let (log0, head0) = (fs::read(&log).unwrap(), fs::read(&head).unwrap());
        for _ in 0..3 {
            s.read_page(None, 500).unwrap();
            s.read_page(Some(1), 1).unwrap();
        }
        assert_eq!(fs::read(&log).unwrap(), log0, "a read wrote the log");
        assert_eq!(fs::read(&head).unwrap(), head0, "a read moved the head");
        assert_eq!(s.verify().unwrap().records, 3);
        // An append after reads lands at seq 3 and is served.
        s.append(true, Some("tk-z"), Some("vm-z"), "released", 9_999)
            .unwrap();
        let page = s.read_page(Some(2), 500).unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_page_is_disk(&page, &disk_lines(&log));
    }

    #[test]
    fn a_reopened_sink_serves_the_records_of_its_previous_life() {
        let td = TempDir::new().unwrap();
        drop(release_sink(&td, 4));
        let s = FileAuditSink::open(td.path()).unwrap();
        s.append(true, Some("tk-4"), Some("vm-a"), "released", 5_000)
            .unwrap();
        let page = s.read_page(None, 500).unwrap();
        assert_eq!(page.entries.len(), 5);
        assert_page_is_disk(&page, &disk_lines(&td.path().join("audit.log")));
    }

    #[test]
    fn an_empty_log_has_no_genesis_and_no_head() {
        let td = TempDir::new().unwrap();
        let s = FileAuditSink::open(td.path()).unwrap();
        let page = s.read_page(None, 10).unwrap();
        assert_eq!(page.genesis, None);
        assert_eq!(page.head_seq, None);
        assert_eq!(page.head, [0; 32]);
        assert!(page.entries.is_empty());
    }

    #[test]
    fn a_log_rewritten_under_the_sink_is_refused_not_skipped() {
        let td = TempDir::new().unwrap();
        let s = release_sink(&td, 3);
        let log = td.path().join("audit.log");
        // Drop line 1: the index still names three records.
        let lines: Vec<String> = fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        fs::write(&log, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(s.read_page(None, 500).is_err());
    }

    #[test]
    fn a_same_length_record_with_the_wrong_seq_is_refused_not_skipped() {
        let td = TempDir::new().unwrap();
        let s = release_sink(&td, 3);
        let log = td.path().join("audit.log");
        let text = fs::read_to_string(&log).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        // Same byte length, so the snapshot's range still reads cleanly:
        // only the per-line seq check can catch it.
        lines[1].replace_range(0..1, "7");
        fs::write(&log, lines.join("\n") + "\n").unwrap();
        assert!(s.read_page(None, 500).is_err());
        assert!(s.read_page(Some(0), 1).is_err());
        // Pages that do not cover the bad record still serve.
        assert_eq!(s.read_page(Some(1), 500).unwrap().entries.len(), 1);
    }

    #[test]
    fn a_record_blanked_in_place_is_refused_not_dropped() {
        // Overwrite the last record with newlines of the same length: the
        // range reads cleanly and every remaining line parses — only the
        // record count can tell a record went missing.
        let td = TempDir::new().unwrap();
        let s = release_sink(&td, 3);
        let log = td.path().join("audit.log");
        let text = fs::read_to_string(&log).unwrap();
        let cut = text[..text.len() - 1].rfind('\n').unwrap() + 1;
        let blanked = format!("{}{}", &text[..cut], "\n".repeat(text.len() - cut));
        fs::write(&log, blanked).unwrap();
        assert!(s.read_page(None, 500).is_err());
        assert!(s.read_page(Some(1), 500).is_err());
    }

    #[test]
    fn a_page_stops_at_the_byte_budget_but_always_advances() {
        let mut ix = LogIndex::default();
        let big = MAX_AUDIT_PAGE_BYTES / 3 + 1; // three do not fit, two do
        for i in 0..5u64 {
            ix.push(i * big, big, [1; 32]);
        }
        let s = ix.snapshot([0; 32], None, 500);
        assert_eq!(s.range, Some((0, 2, 0, 2 * big)));
        let s = ix.snapshot([0; 32], Some(3), 500);
        assert_eq!(s.range, Some((4, 5, 4 * big, 5 * big)));
        // A single record over the budget is still served, alone.
        let mut huge = LogIndex::default();
        huge.push(0, MAX_AUDIT_PAGE_BYTES * 2, [1; 32]);
        huge.push(MAX_AUDIT_PAGE_BYTES * 2, 10, [2; 32]);
        let s = huge.snapshot([0; 32], None, 500);
        assert_eq!(s.range, Some((0, 1, 0, MAX_AUDIT_PAGE_BYTES * 2)));
    }

    #[test]
    fn a_crlf_log_the_walker_accepts_is_served() {
        let td = TempDir::new().unwrap();
        drop(release_sink(&td, 2));
        let log = td.path().join("audit.log");
        let crlf = fs::read_to_string(&log).unwrap().replace('\n', "\r\n");
        fs::write(&log, crlf).unwrap();
        let s = FileAuditSink::open(td.path()).unwrap();
        let page = s.read_page(None, 500).unwrap();
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[1].prev_hash, page.entries[0].sha256);
    }

    #[test]
    fn a_record_persisted_without_its_newline_is_terminated_at_open() {
        let td = TempDir::new().unwrap();
        drop(release_sink(&td, 2));
        let log = td.path().join("audit.log");
        let mut bytes = fs::read(&log).unwrap();
        assert_eq!(bytes.pop(), Some(b'\n'));
        fs::write(&log, &bytes).unwrap();
        // Reopen repairs the terminator; the next append is its own line.
        let s = FileAuditSink::open(td.path()).unwrap();
        s.append(true, Some("tk-2"), Some("vm-a"), "released", 3_000)
            .unwrap();
        assert_eq!(s.read_page(None, 500).unwrap().entries.len(), 3);
        drop(s);
        let s = FileAuditSink::open(td.path()).expect("the chain still opens");
        assert_eq!(s.verify().unwrap().records, 3);
        // Same for the admin chain.
        let td = TempDir::new().unwrap();
        let a = FileAdminAuditSink::open(td.path()).unwrap();
        let b = [0u8; 32];
        let rec = AdminAuditRecord {
            op: "register-vm",
            url_vm_id: "vm",
            ticket_id: None,
            vm_id: None,
            applied: true,
            status_code: 200,
            reason: None,
            peer_san: None,
            peer_serial: None,
            body_sha256: &b,
        };
        a.append(&rec, 1).unwrap();
        drop(a);
        let log = td.path().join("admin.log");
        let mut bytes = fs::read(&log).unwrap();
        bytes.pop();
        fs::write(&log, &bytes).unwrap();
        let a = FileAdminAuditSink::open(td.path()).unwrap();
        a.append(&rec, 2).unwrap();
        drop(a);
        let a = FileAdminAuditSink::open(td.path()).unwrap();
        assert_eq!(a.verify().unwrap().records, 2);
        assert_eq!(a.read_page(None, 500).unwrap().entries.len(), 2);
    }

    #[test]
    fn a_failed_head_write_leaves_the_durable_record_indexed() {
        let td = TempDir::new().unwrap();
        let s = release_sink(&td, 1);
        // Make the head rename fail: its target is now a non-empty dir.
        let head = td.path().join("head.sha256");
        fs::remove_file(&head).unwrap();
        fs::create_dir(&head).unwrap();
        fs::write(head.join("x"), b"x").unwrap();
        assert!(s
            .append(true, Some("tk-1"), Some("vm-a"), "released", 2_000)
            .is_err());
        // The record is on disk AND served; the next append is seq 2.
        assert_eq!(s.read_page(None, 500).unwrap().entries.len(), 2);
        fs::remove_dir_all(&head).unwrap();
        s.append(true, Some("tk-2"), Some("vm-a"), "released", 3_000)
            .unwrap();
        let page = s.read_page(None, 500).unwrap();
        assert_eq!(
            page.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        drop(s);
        assert_eq!(
            FileAuditSink::open(td.path())
                .unwrap()
                .verify()
                .unwrap()
                .records,
            3
        );
    }

    #[test]
    fn admin_page_returns_the_exact_persisted_records() {
        let td = TempDir::new().unwrap();
        let s = FileAdminAuditSink::open(td.path()).unwrap();
        let body_sha = [0xab; 32];
        for (i, vm) in ["vm-1", "vm-2", "vm-3"].iter().enumerate() {
            s.append(
                &AdminAuditRecord {
                    op: "register-vm",
                    url_vm_id: vm,
                    ticket_id: Some("tk"),
                    vm_id: Some(vm),
                    applied: true,
                    status_code: 200,
                    reason: None,
                    peer_san: Some("spiffe://hippius.network/vali"),
                    peer_serial: Some("0a"),
                    body_sha256: &body_sha,
                },
                2_000 + i as u64,
            )
            .unwrap();
        }
        let disk = disk_lines(&td.path().join("admin.log"));
        let page = s.read_page(Some(0), 500).unwrap();
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].seq, 1);
        assert_page_is_disk(&page, &disk);
        assert_eq!(page.genesis.map(hex::encode), Some(disk[0].2.clone()));
        assert_eq!(page.head_seq, Some(2));
    }
}
