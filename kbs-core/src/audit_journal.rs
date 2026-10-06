//! Crash recovery shared by the two hash-chained audit logs — the
//! release chain (`crate::audit`, `audit.log` + `head.sha256`) and the
//! admin chain (`crate::admin_audit`, `admin.log` + `admin.head.sha256`).
//!
//! ## Why
//!
//! Both chains live on an `emptyDir` that SURVIVES a container restart
//! inside the same pod (OOM kill, liveness restart). A process that dies
//! in the middle of `append` leaves the directory in one of a handful of
//! states; refusing to start on any of them would take key release down
//! for the whole fleet until someone intervened by hand — worse than the
//! tamper the refusal guards against. So the logs have JOURNAL semantics:
//! a torn TRAILING record is truncated at open (and surfaced), and only a
//! state no crash can produce refuses.
//!
//! ## `append`, and every point a process can die in it
//!
//! `append` (`append_line` + the caller) runs, under the sink's mutex and
//! the directory's exclusive lock:
//!
//! 1. check the file ends where the index says (see "runtime" below);
//! 2. `write(2)` the whole line `seq:body_hex:hash_hex\n` (`O_APPEND`);
//! 3. `fsync` the log;
//! 4. advance the in-memory chain state + index;
//! 5. write the head: temp file, `fsync`, `rename`, `fsync` the dir.
//!
//! | process dies…                      | on disk                                   | open    |
//! |------------------------------------|-------------------------------------------|---------|
//! | before 2                           | N records, head = record N-1              | start   |
//! | during 2 (partial line)            | N records + a torn tail                   | truncate + marker, start |
//! | during 2, only the `\n` missing    | N+1 records, last unterminated, head N-1  | keep it, terminate, head repaired, start |
//! | after 2, before 3 / after 3, before 5 | N+1 records, head = record N-1 (1 behind) | head repaired, start |
//! | during 5 (temp written, not renamed) | same + a stale `*.tmp.*`                  | head repaired, temp removed, start |
//! | after 5                            | N+1 records, head = record N              | start   |
//!
//! Beyond a process kill (power loss under a lying disk, a torn page) the
//! same rule covers a complete-looking last line whose hash does not
//! verify, and a head ONE record ahead of the log (it names the hash of the
//! torn trailing record). Every recovery step at open is itself ordered so
//! a second crash in the middle of it is again one of these states: the
//! head is first pulled back to the verified tail, then the marker record
//! OVERWRITES the torn bytes in place (so a crash before the `set_len`
//! leaves marker + leftover garbage — a second torn tail, not a lost
//! marker), then the head moves to the marker.
//!
//! ## Torn vs broken — the one rule
//!
//! A line is SELF-CONSISTENT when it parses as `seq:body_hex:hash_hex`
//! and `sha256(body)` equals its stored hash. A torn write never produces
//! a self-consistent line that is wrong: it produces a prefix, or bytes
//! whose hash does not verify. So:
//!
//! - a trailing line that is NOT self-consistent is a torn tail →
//!   truncated;
//! - a self-consistent line that does not chain (wrong seq, wrong
//!   `prev_hash`, wrong domain, bad schema, non-canonical) is a BREAK →
//!   refuse, wherever it is;
//! - any bad line with a record after it (a break in the middle, a
//!   rewritten earlier record, a seq gap before the tail) → refuse;
//! - a head that is neither a record of the verified chain (0..N behind),
//!   nor the hash the torn tail claims (1 ahead — only a torn line whose
//!   seq field IS the next seq claims anything), is not explainable by
//!   one torn append → refuse. A head BEHIND the tail is never a
//!   refusal: the log is the authority and extends it (a head write that
//!   failed while the log append succeeded leaves exactly that).
//!
//! What this cannot tell apart: the head is an unauthenticated cache, so
//! someone who cuts records AND leaves a torn-looking line naming the old
//! head (or rewrites the head) passes as one torn append — never silently:
//! the marker and the ERROR line still record a truncation. Likewise,
//! someone rewriting the LAST record into
//! bytes that no longer hash looks exactly like a torn write. It is not
//! accepted silently — the dropped bytes are logged at ERROR and a marker
//! record is chained in their place (below), and a reader that already
//! held the original record sees a different record at that seq (vali:
//! an `equivocation` anomaly).
//!
//! ## How a truncation is surfaced — the `audit-truncated` marker record
//!
//! After truncating, open appends ONE synthetic record as the next chain
//! record, at the seq the torn record would have had, so the chain itself
//! carries the evidence (it survives the next restart and is read by the
//! same route as every record):
//!
//! - release chain: `granted=false`, `ticket_id=""`, `vm_id=""`,
//!   `reason="audit-truncated:seq=<N>:len=<L>:sha256=<16 hex>"`;
//! - admin chain: `op="audit-truncated"`, the same `reason`, `applied=false`,
//!   `status_code=0`, `body_sha256` = the full sha256 of the dropped bytes.
//!
//! vali (`apps/orchestration/kbs_audit.py`) records each one as a
//! `KbsAuditAnomaly` of kind `torn-tail-truncated` (WARNING — a crash, not
//! a tamper).
//!
//! ## Runtime: a failed append never glues the next one
//!
//! `AuditSink::record` is best-effort — a failed release-audit append does
//! not stop the release, and the process goes on appending. A write that
//! failed half-way (ENOSPC) or whose `fsync` failed leaves bytes past the
//! indexed end; appending after them would put a bad line in the MIDDLE,
//! which the next open must refuse. So every append first cuts the file
//! back to the indexed end (the sink holds the directory's exclusive lock:
//! those bytes can only be its own failed append).

use crate::audit_read::LogIndex;
use crate::error::{KbsError, Result};
use hippius_types::cbor::assert_canonical;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// `op` (admin) / `reason` prefix (both) of the marker record chained in
/// place of a truncated torn tail.
pub const AUDIT_TRUNCATED: &str = "audit-truncated";

/// Where the operator procedure for a refused audit dir lives.
pub const REFUSAL_RUNBOOK: &str =
    "deploy/gitops/apps/kbs/README.md § \"Audit log refused at start\"";

/// Crash-point hook: a test arms a named point and the code returns an
/// error there, leaving the files exactly as a process killed at that
/// point would (the caller then drops the sink and reopens). Inert
/// outside `cfg(test)`.
#[cfg(test)]
pub(crate) mod crash_hook {
    use std::cell::Cell;
    thread_local! {
        static ARMED: Cell<Option<&'static str>> = const { Cell::new(None) };
    }
    pub(crate) fn arm(at: &'static str) {
        ARMED.with(|c| c.set(Some(at)));
    }
    pub(crate) fn disarm() {
        ARMED.with(|c| c.set(None));
    }
    pub(crate) fn hit(at: &'static str) -> bool {
        ARMED.with(|c| c.get()) == Some(at)
    }
}

fn crash_point(at: &'static str) -> Result<()> {
    #[cfg(test)]
    if crash_hook::hit(at) {
        return Err(KbsError::Vault(format!("test crash at {at}")));
    }
    let _ = at;
    Ok(())
}

/// The file names of one chain.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChainFiles {
    /// Error/log prefix ("audit", "admin-audit").
    pub label: &'static str,
    pub log: &'static str,
    pub head: &'static str,
}

/// The trailing bytes a torn append left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TornTail {
    /// Byte offset of the torn line (== the verified end of the log).
    pub offset: u64,
    /// Everything from `offset` to EOF — what truncation drops.
    pub dropped: Vec<u8>,
    /// Why the line is not a record.
    pub why: String,
    /// Hashes the torn record could have had: its stored hash field (if
    /// it parses) and `sha256(body)` (if the body hex decodes). A head
    /// naming one of these is ONE record ahead, not a cut.
    pub claimed: Vec<[u8; 32]>,
}

impl TornTail {
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.dropped).into()
    }

    /// `reason` of the marker record for this truncation.
    pub fn marker_reason(&self, seq: u64) -> String {
        format!(
            "{AUDIT_TRUNCATED}:seq={seq}:len={}:sha256={}",
            self.dropped.len(),
            &hex::encode(self.sha256())[..16]
        )
    }
}

/// The verified prefix of a log.
#[derive(Debug, Clone)]
pub(crate) struct Walk {
    pub records: u64,
    /// Hash of the last verified record, zero when there is none.
    pub head: [u8; 32],
    pub index: LogIndex,
    pub torn: Option<TornTail>,
    /// The last verified record is not `\n`-terminated.
    pub unterminated: bool,
    /// Number of records the probed head names (`Some(0)` for a zero
    /// head), when the probe is a hash of the verified chain.
    pub probe_at: Option<u64>,
}

/// Walk a log's bytes. `check_body(body, seq, prev)` validates a
/// SELF-CONSISTENT record's body against the chain position it occupies
/// (schema, domain, body seq, `prev_hash`); its `Err` is a break.
///
/// `Err` = refuse to start (the message names the reason).
pub(crate) fn walk(
    bytes: &[u8],
    head_probe: Option<[u8; 32]>,
    mut check_body: impl FnMut(&[u8], u64, &[u8; 32]) -> std::result::Result<(), String>,
) -> std::result::Result<Walk, String> {
    let mut records = 0u64;
    let mut head = [0u8; 32];
    let mut offsets = Vec::new();
    let mut genesis = None;
    let mut unterminated = false;
    let mut probe_at = head_probe.filter(|p| *p == [0u8; 32]).map(|_| 0);
    let mut pos = 0usize;
    while pos < bytes.len() {
        let nl = bytes[pos..].iter().position(|b| *b == b'\n');
        let (raw, next) = match nl {
            Some(i) => (&bytes[pos..pos + i], pos + i + 1),
            None => (&bytes[pos..], bytes.len()),
        };
        if raw.is_empty() {
            pos = next;
            continue;
        }
        match check_line(raw, records, &head, &mut check_body) {
            Ok(h) => {
                if records == 0 {
                    genesis = Some(h);
                }
                offsets.push(pos as u64);
                records += 1;
                head = h;
                unterminated = nl.is_none();
                if head_probe == Some(h) {
                    probe_at = Some(records);
                }
            }
            Err(LineFault::Broken(why)) => {
                return Err(format!("record at seq {records} does not chain: {why}"));
            }
            Err(LineFault::Torn { why, claimed }) => {
                // Torn only if nothing but blank lines follows it.
                if bytes[next..].iter().any(|b| *b != b'\n') {
                    return Err(format!(
                        "record at seq {records} is not a record ({why}) and records follow it \
                         — a break in the middle of the chain, not a torn append"
                    ));
                }
                let offset = pos as u64;
                return Ok(Walk {
                    records,
                    head,
                    index: LogIndex::from_walk(offsets, offset, genesis),
                    torn: Some(TornTail {
                        offset,
                        dropped: bytes[pos..].to_vec(),
                        why,
                        claimed,
                    }),
                    unterminated: false,
                    probe_at,
                });
            }
        }
        pos = next;
    }
    // Trailing blank lines stay inside the indexed range; the reader skips
    // them.
    Ok(Walk {
        records,
        head,
        index: LogIndex::from_walk(offsets, bytes.len() as u64, genesis),
        torn: None,
        unterminated,
        probe_at,
    })
}

enum LineFault {
    /// Not a self-consistent record — what a torn write leaves.
    Torn { why: String, claimed: Vec<[u8; 32]> },
    /// Self-consistent but wrong for its chain position.
    Broken(String),
}

fn check_line(
    raw: &[u8],
    expected_seq: u64,
    expected_prev: &[u8; 32],
    check_body: &mut impl FnMut(&[u8], u64, &[u8; 32]) -> std::result::Result<(), String>,
) -> std::result::Result<[u8; 32], LineFault> {
    let torn = |why: &str, claimed: Vec<[u8; 32]>| LineFault::Torn {
        why: why.to_string(),
        claimed,
    };
    // A CRLF terminator is accepted (the reader serves exactly this).
    let line = raw.strip_suffix(b"\r").unwrap_or(raw);
    let mut parts = line.splitn(3, |b| *b == b':');
    let (Some(seq_b), Some(body_b), Some(hash_b)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(torn("not seq:body:hash", Vec::new()));
    };
    let body = hex::decode(body_b).ok();
    let stored: Option<[u8; 32]> = hex::decode(hash_b)
        .ok()
        .and_then(|v| v.as_slice().try_into().ok());
    // The hashes a head one ahead may name — only if the torn line says it
    // is the NEXT record: a torn line carrying another seq explains no head.
    let mut claimed = Vec::new();
    let names_next =
        std::str::from_utf8(seq_b).ok().and_then(|s| s.parse().ok()) == Some(expected_seq);
    if names_next {
        claimed.extend(stored);
        if let Some(b) = &body {
            claimed.push(Sha256::digest(b).into());
        }
    }
    let Some(body) = body else {
        return Err(torn("body is not hex", claimed));
    };
    let Some(stored) = stored else {
        return Err(torn("hash is not 32 bytes of hex", claimed));
    };
    let actual: [u8; 32] = Sha256::digest(&body).into();
    if actual != stored {
        return Err(torn("sha256(body) != stored hash", claimed));
    }
    // Self-consistent from here: anything wrong is a break.
    let seq: u64 = std::str::from_utf8(seq_b)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| LineFault::Broken("bad seq".into()))?;
    if seq != expected_seq {
        return Err(LineFault::Broken(format!(
            "seq gap (got {seq}, want {expected_seq})"
        )));
    }
    assert_canonical(&body).map_err(|e| LineFault::Broken(format!("non-canonical body: {e}")))?;
    // `expected_seq`, not the line's: the body's seq is checked on its own,
    // independently of the prefix check above.
    check_body(&body, expected_seq, expected_prev).map_err(LineFault::Broken)?;
    Ok(actual)
}

/// What the head file says relative to the walked log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeadVerdict {
    /// Head equals the verified tail (or is absent/empty on an empty log).
    Current,
    /// Absent or empty with records present — repair. A crash leaves this
    /// only before the FIRST head write; more records than one means head
    /// writes kept failing (or the head was removed): logged at ERROR.
    Missing,
    /// Names record `records - n` (0 = the zero hash) — repair.
    Behind(u64),
    /// Names the torn trailing record — repair.
    OneAhead,
}

/// Classify the head file. `Err` = refuse.
pub(crate) fn classify_head(
    head_file: Option<&[u8]>,
    walk: &Walk,
) -> std::result::Result<HeadVerdict, String> {
    let Some(h) = head_file.filter(|h| !h.is_empty()) else {
        return Ok(if walk.records == 0 {
            HeadVerdict::Current
        } else {
            HeadVerdict::Missing
        });
    };
    let h: [u8; 32] = h
        .try_into()
        .map_err(|_| format!("head file is {} bytes, not 32", h.len()))?;
    if h == walk.head {
        return Ok(HeadVerdict::Current);
    }
    if let Some(at) = walk.probe_at {
        return Ok(HeadVerdict::Behind(walk.records - at));
    }
    if walk.torn.as_ref().is_some_and(|t| t.claimed.contains(&h)) {
        return Ok(HeadVerdict::OneAhead);
    }
    Err(format!(
        "head {} is not a record of the log ({} verified records{}): the log lost more than \
         one torn append, or its tail was rewritten",
        &hex::encode(h)[..16],
        walk.records,
        if walk.torn.is_some() {
            ", then a torn tail that does not name it"
        } else {
            ""
        }
    ))
}

/// The refusal every open returns: one line naming the log, the reason
/// and the runbook.
pub(crate) fn refusal(files: ChainFiles, dir: &Path, why: &str) -> KbsError {
    KbsError::Vault(format!(
        "{label}: REFUSING TO START — {log} in {dir} is inconsistent in a way no crash \
         produces: {why}. Nothing was modified. Preserve the directory as evidence and \
         follow {REFUSAL_RUNBOOK}; never hand-edit the log.",
        label = files.label,
        log = files.log,
        dir = dir.display(),
    ))
}

/// Recovered chain state an opened sink starts from.
pub(crate) struct Opened {
    pub head: [u8; 32],
    pub records: u64,
    pub index: LogIndex,
}

/// Open-time recovery shared by both sinks. `walk_fn(bytes, probe)` is the
/// chain's walker; `build_marker(prev, seq, torn)` encodes the chain's
/// `audit-truncated` record body. The caller holds the directory lock.
pub(crate) fn open_recover(
    dir: &Path,
    files: ChainFiles,
    walk_fn: impl Fn(&[u8], Option<[u8; 32]>) -> std::result::Result<Walk, String>,
    build_marker: impl FnOnce(&[u8; 32], u64, &TornTail) -> Result<Vec<u8>>,
) -> Result<Opened> {
    let log_path = dir.join(files.log);
    let head_path = dir.join(files.head);
    let bytes = match fs::read(&log_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(KbsError::Vault(format!("{} log read: {e}", files.label))),
    };
    let head_file = match fs::read(&head_path) {
        Ok(h) => Some(h),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(KbsError::Vault(format!("{} head read: {e}", files.label))),
    };
    let probe = head_file
        .as_deref()
        .and_then(|h| <[u8; 32]>::try_from(h).ok());
    let walk = walk_fn(&bytes, probe).map_err(|why| refusal(files, dir, &why))?;
    let verdict =
        classify_head(head_file.as_deref(), &walk).map_err(|why| refusal(files, dir, &why))?;
    match verdict {
        HeadVerdict::Current => {}
        HeadVerdict::Missing if walk.records <= 1 => eprintln!(
            "WARN kbs-core::{}: no head over {} record(s) (a crash before the first head \
             write) — written",
            files.label, walk.records
        ),
        HeadVerdict::Missing => eprintln!(
            "ERROR kbs-core::{}: no head over {} records — head writes failed while log appends \
             succeeded, or the head was removed; rebuilt from the log (the log is the authority)",
            files.label, walk.records
        ),
        HeadVerdict::Behind(1) => eprintln!(
            "WARN kbs-core::{}: head was one record behind the log (a crash between the log \
             fsync and the head write) — repaired to seq {}",
            files.label,
            walk.records.saturating_sub(1)
        ),
        HeadVerdict::Behind(n) => eprintln!(
            "ERROR kbs-core::{}: head was {n} records behind the log (head writes failed while \
             log appends succeeded) — repaired to seq {}; the log is the authority",
            files.label,
            walk.records.saturating_sub(1)
        ),
        HeadVerdict::OneAhead => eprintln!(
            "ERROR kbs-core::{}: head was one record AHEAD of the verified log — it names the \
             torn trailing record; pulled back before the truncation",
            files.label
        ),
    }
    // Pull the head to the verified tail FIRST: a crash anywhere below
    // then leaves a head at most one behind — never one ahead of a log
    // whose torn tail is gone.
    let head_ok = head_file.as_deref() == Some(walk.head.as_slice())
        || (walk.records == 0 && head_file.as_deref().is_none_or(<[u8]>::is_empty));
    if !head_ok {
        write_head_atomic(dir, files, &walk.head)?;
    }
    crash_point("recover:after-head-pullback")?;
    let Walk {
        mut records,
        mut head,
        mut index,
        torn,
        unterminated,
        ..
    } = walk;
    if let Some(torn) = torn {
        let seq = records;
        eprintln!(
            "ERROR kbs-core::{label}: TORN TRAILING RECORD truncated at open: {log} seq={seq} \
             offset={off} len={len} sha256={sha} ({why}); an `{AUDIT_TRUNCATED}` record is \
             chained at seq {seq} in its place",
            label = files.label,
            log = files.log,
            off = torn.offset,
            len = torn.dropped.len(),
            sha = hex::encode(torn.sha256()),
            why = torn.why,
        );
        let body = build_marker(&head, seq, &torn)?;
        let h: [u8; 32] = Sha256::digest(&body).into();
        let line = format!("{seq}:{}:{}\n", hex::encode(&body), hex::encode(h));
        // Overwrite in place, THEN cut: a crash between the two leaves the
        // marker followed by leftover torn bytes — a new torn tail the next
        // open truncates behind the marker, never a lost marker.
        let io = |e: std::io::Error| KbsError::Vault(format!("{} truncate: {e}", files.label));
        let mut f = OpenOptions::new().write(true).open(&log_path).map_err(io)?;
        f.seek(SeekFrom::Start(torn.offset)).map_err(io)?;
        f.write_all(line.as_bytes()).map_err(io)?;
        crash_point("recover:between-overwrite-and-cut")?;
        f.set_len(torn.offset + line.len() as u64).map_err(io)?;
        f.sync_all().map_err(io)?;
        crash_point("recover:before-marker-head")?;
        index.push(torn.offset, line.len() as u64, h);
        records += 1;
        head = h;
        write_head_atomic(dir, files, &head)?;
    } else if unterminated {
        // A verified record persisted without its `\n`: it IS a record —
        // keep it, and terminate it so the next append is its own line.
        let io = |e: std::io::Error| KbsError::Vault(format!("{} terminator: {e}", files.label));
        let mut f = OpenOptions::new()
            .append(true)
            .open(&log_path)
            .map_err(io)?;
        f.write_all(b"\n").and_then(|()| f.sync_all()).map_err(io)?;
        index.set_end(bytes.len() as u64 + 1);
        eprintln!(
            "WARN kbs-core::{}: the last record (seq {}) was persisted without its newline — kept \
             and terminated",
            files.label,
            records.saturating_sub(1)
        );
    }
    remove_stale_head_temps(dir, files);
    Ok(Opened {
        head,
        records,
        index,
    })
}

/// Append one line at the indexed end of the log and `fsync` it. Returns
/// the line's offset. Bytes past `indexed_end` are this process's own
/// failed append (the caller holds the directory lock) — cut first, or the
/// new line would sit behind garbage in the middle of the chain.
pub(crate) fn append_line(
    dir: &Path,
    files: ChainFiles,
    indexed_end: u64,
    line: &[u8],
) -> Result<u64> {
    let label = files.label;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(files.log))
        .map_err(|e| KbsError::Vault(format!("{label} open: {e}")))?;
    let len = f
        .metadata()
        .map_err(|e| KbsError::Vault(format!("{label} stat: {e}")))?
        .len();
    if len > indexed_end {
        eprintln!(
            "ERROR kbs-core::{label}: {} bytes of a failed append past the indexed end ({}) \
             — cut before appending",
            len - indexed_end,
            indexed_end
        );
        f.set_len(indexed_end)
            .and_then(|()| f.sync_all())
            .map_err(|e| KbsError::Vault(format!("{label} cut failed append: {e}")))?;
    } else if len < indexed_end {
        return Err(KbsError::Vault(format!(
            "{label}: the log shrank under the sink ({len} < indexed {indexed_end}) — refusing \
             to append"
        )));
    }
    #[cfg(test)]
    if crash_hook::hit("append:partial-write") {
        f.write_all(&line[..line.len() / 2])
            .map_err(|e| KbsError::Vault(format!("{label} write: {e}")))?;
        return Err(KbsError::Vault("test crash at append:partial-write".into()));
    }
    f.write_all(line)
        .map_err(|e| KbsError::Vault(format!("{label} write: {e}")))?;
    crash_point("append:before-fsync")?;
    f.sync_all()
        .map_err(|e| KbsError::Vault(format!("{label} fsync: {e}")))?;
    Ok(indexed_end)
}

/// Atomic-rename write of the head. A unique temp name, so a stale temp
/// from a crashed run never blocks this write.
pub(crate) fn write_head_atomic(dir: &Path, files: ChainFiles, h: &[u8; 32]) -> Result<()> {
    use rand::RngCore;
    let label = files.label;
    let head_path = dir.join(files.head);
    let mut rand_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
    let tmp = dir.join(format!("{}.tmp.{}", files.head, hex::encode(rand_bytes)));
    let staged = (|| {
        let mut hf = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .map_err(|e| KbsError::Vault(format!("{label} head temp open: {e}")))?;
        hf.write_all(h)
            .map_err(|e| KbsError::Vault(format!("{label} head write: {e}")))?;
        hf.sync_all()
            .map_err(|e| KbsError::Vault(format!("{label} head fsync: {e}")))?;
        drop(hf);
        crash_point("head:before-rename")?;
        fs::rename(&tmp, &head_path)
            .map_err(|e| KbsError::Vault(format!("{label} head rename: {e}")))
    })();
    if let Err(e) = staged {
        // A failed (not crashed) head write must not leak its temp — under
        // ENOSPC every release append would leave one behind.
        #[cfg(test)]
        if crash_hook::hit("head:before-rename") {
            return Err(e); // a crash leaves the temp; open removes it
        }
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    let dirf = File::open(dir).map_err(|e| KbsError::Vault(format!("{label} dir open: {e}")))?;
    dirf.sync_all()
        .map_err(|e| KbsError::Vault(format!("{label} dir fsync: {e}")))?;
    Ok(())
}

/// Remove head temps a crash in the middle of `write_head_atomic` left.
fn remove_stale_head_temps(dir: &Path, files: ChainFiles) {
    let prefix = format!("{}.tmp", files.head);
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        if e.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = fs::remove_file(e.path());
        }
    }
}

#[cfg(test)]
pub(crate) mod crash_tests {
    //! On-disk crash states, built for both chains by the same harness.
    //! Each chain's test module drives `Harness` with its own sink.

    use super::*;

    /// One sink under test, seen only through the files it writes.
    pub(crate) trait Harness {
        const FILES: ChainFiles;
        type Sink;
        fn open(dir: &Path) -> Result<Self::Sink>;
        /// Append one ordinary record; returns its hash.
        fn append(s: &Self::Sink, i: u64) -> [u8; 32];
        fn records(s: &Self::Sink) -> u64;
        /// Records the read route serves (seq, hash).
        fn page(s: &Self::Sink) -> Vec<(u64, [u8; 32])>;
        /// Is the record at `seq` an `audit-truncated` marker, and its reason.
        fn marker_reason(s: &Self::Sink, seq: u64) -> Option<String>;
    }

    pub(crate) fn log(dir: &Path, h: ChainFiles) -> Vec<u8> {
        fs::read(dir.join(h.log)).unwrap_or_default()
    }

    pub(crate) fn head(dir: &Path, h: ChainFiles) -> Option<Vec<u8>> {
        fs::read(dir.join(h.head)).ok()
    }

    /// A dir holding `n` records, closed cleanly. Returns their hashes.
    pub(crate) fn chain<H: Harness>(dir: &Path, n: u64) -> Vec<[u8; 32]> {
        let s = H::open(dir).unwrap();
        (0..n).map(|i| H::append(&s, i)).collect()
    }

    /// The line the sink WOULD append next (seq `n`), captured by letting
    /// a scratch copy of the dir append it.
    pub(crate) fn next_line<H: Harness>(dir: &Path) -> (Vec<u8>, [u8; 32]) {
        let scratch = tempfile::TempDir::new().unwrap();
        for f in [H::FILES.log, H::FILES.head] {
            if let Ok(b) = fs::read(dir.join(f)) {
                fs::write(scratch.path().join(f), b).unwrap();
            }
        }
        let before = log(scratch.path(), H::FILES).len();
        let s = H::open(scratch.path()).unwrap();
        let h = H::append(&s, 999);
        drop(s);
        (log(scratch.path(), H::FILES)[before..].to_vec(), h)
    }

    fn append_raw(dir: &Path, h: ChainFiles, bytes: &[u8]) {
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(dir.join(h.log))
            .unwrap();
        f.write_all(bytes).unwrap();
    }

    /// Reopen after a crash state; assert it starts, holds `want` real
    /// records (plus a marker iff `marker`), and keeps chaining across two
    /// more appends and a clean reopen.
    fn assert_starts<H: Harness>(dir: &Path, want: u64, marker: bool, what: &str) {
        let s = H::open(dir).unwrap_or_else(|e| panic!("{what}: refused to start: {e}"));
        let total = want + u64::from(marker);
        assert_eq!(H::records(&s), total, "{what}: record count");
        match H::marker_reason(&s, want) {
            Some(r) => {
                assert!(marker, "{what}: unexpected marker {r}");
                assert!(
                    r.starts_with(&format!("{AUDIT_TRUNCATED}:seq={want}:len=")),
                    "{what}: {r}"
                );
            }
            None => assert!(!marker, "{what}: no marker at seq {want}"),
        }
        let h1 = H::append(&s, 100);
        let h2 = H::append(&s, 101);
        let page = H::page(&s);
        assert_eq!(page.len() as u64, total + 2, "{what}: served records");
        assert_eq!(page[page.len() - 1], (total + 1, h2), "{what}");
        assert_eq!(page[page.len() - 2], (total, h1), "{what}");
        assert_eq!(head(dir, H::FILES).as_deref(), Some(h2.as_slice()));
        drop(s);
        let s = H::open(dir).unwrap_or_else(|e| panic!("{what}: clean reopen refused: {e}"));
        assert_eq!(H::records(&s), total + 2, "{what}: after reopen");
        let temps = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .count();
        assert_eq!(temps, 0, "{what}: stale head temps left behind");
    }

    /// Every crash point of `append`, from a 3-record chain.
    pub(crate) fn every_crash_point_starts<H: Harness>() {
        let f = H::FILES;
        let fresh = |n| {
            let td = tempfile::TempDir::new().unwrap();
            let hashes = chain::<H>(td.path(), n);
            (td, hashes)
        };

        // Before the write: nothing happened.
        let (td, _) = fresh(3);
        assert_starts::<H>(td.path(), 3, false, "crash before write");

        // During the write: every proper prefix of the line, head untouched.
        let (td, _) = fresh(3);
        let (line, _) = next_line::<H>(td.path());
        for cut in [1, 2, line.len() / 2, line.len() - 30, line.len() - 2] {
            let td2 = tempfile::TempDir::new().unwrap();
            for name in [f.log, f.head] {
                fs::copy(td.path().join(name), td2.path().join(name)).unwrap();
            }
            append_raw(td2.path(), f, &line[..cut]);
            assert_starts::<H>(td2.path(), 3, true, &format!("partial write {cut}"));
        }

        // Partial write of the FIRST record: a torn tail and nothing else.
        let td = tempfile::TempDir::new().unwrap();
        let (line, _) = next_line::<H>(td.path());
        append_raw(td.path(), f, &line[..line.len() / 3]);
        assert_starts::<H>(td.path(), 0, true, "partial first record");

        // The whole line but its newline: a verified record — kept.
        let (td, _) = fresh(3);
        let (line, _) = next_line::<H>(td.path());
        append_raw(td.path(), f, &line[..line.len() - 1]);
        assert_starts::<H>(td.path(), 4, false, "newline missing");

        // After the write, before the fsync / after the fsync, before the
        // head write: the record is whole, the head one behind.
        let (td, hashes) = fresh(3);
        let (line, _) = next_line::<H>(td.path());
        append_raw(td.path(), f, &line);
        assert_eq!(head(td.path(), f).unwrap(), hashes[2]);
        assert_starts::<H>(td.path(), 4, false, "after fsync, before head");

        // During the head write: temp written (whole or partial), no rename.
        for partial in [false, true] {
            let (td, _) = fresh(3);
            let (line, h) = next_line::<H>(td.path());
            append_raw(td.path(), f, &line);
            let tmp = td.path().join(format!("{}.tmp.0011223344556677", f.head));
            fs::write(&tmp, if partial { &h[..7] } else { &h[..] }).unwrap();
            assert_starts::<H>(td.path(), 4, false, &format!("head temp partial={partial}"));
        }

        // After the head rename: clean.
        let (td, _) = fresh(4);
        assert_starts::<H>(td.path(), 4, false, "after head rename");
    }

    /// Torn tails beyond a process kill: a whole last line that does not
    /// hash, a head ONE ahead (naming the torn record), trailing blanks.
    pub(crate) fn torn_tail_variants_start<H: Harness>() {
        let f = H::FILES;
        // A complete last line whose body was garbled.
        let (td, hashes) = {
            let td = tempfile::TempDir::new().unwrap();
            let h = chain::<H>(td.path(), 3);
            (td, h)
        };
        let mut bytes = log(td.path(), f);
        let last = bytes[..bytes.len() - 1]
            .iter()
            .rposition(|b| *b == b'\n')
            .unwrap()
            + 1;
        let i = last + 8;
        bytes[i] = if bytes[i] == b'0' { b'1' } else { b'0' };
        fs::write(td.path().join(f.log), &bytes).unwrap();
        // The head still names the (now garbled) record 2: one AHEAD.
        assert_eq!(head(td.path(), f).unwrap(), hashes[2]);
        assert_starts::<H>(
            td.path(),
            2,
            true,
            "last line hash mismatch, head one ahead",
        );

        // Head one ahead of a torn line cut inside its hash field: the body
        // is whole, so sha256(body) still explains the head.
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 2);
        let (line, h) = next_line::<H>(td.path());
        append_raw(td.path(), f, &line[..line.len() - 10]);
        fs::write(td.path().join(f.head), h).unwrap();
        assert_starts::<H>(td.path(), 2, true, "head one ahead, hash field torn");

        // Torn garbage followed only by blank lines.
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 2);
        append_raw(td.path(), f, b"2:zz\n\n\n");
        assert_starts::<H>(td.path(), 2, true, "torn + blank lines");

        // Head zero / empty / absent over a real chain: behind, repaired.
        for head_bytes in [Some(vec![0u8; 32]), Some(Vec::new()), None] {
            let td = tempfile::TempDir::new().unwrap();
            chain::<H>(td.path(), 2);
            match &head_bytes {
                Some(b) => fs::write(td.path().join(f.head), b).unwrap(),
                None => fs::remove_file(td.path().join(f.head)).unwrap(),
            }
            assert_starts::<H>(td.path(), 2, false, &format!("head {head_bytes:?}"));
        }

        // Head two behind (two head writes failed): the log is the authority.
        let td = tempfile::TempDir::new().unwrap();
        let hashes = chain::<H>(td.path(), 4);
        fs::write(td.path().join(f.head), hashes[1]).unwrap();
        assert_starts::<H>(td.path(), 4, false, "head two behind");
    }

    /// A second crash in the middle of the open-time recovery itself.
    pub(crate) fn recovery_is_crash_safe<H: Harness>() {
        let f = H::FILES;
        // Crash after the marker overwrote the torn bytes but before the
        // cut: marker + leftover garbage. The first marker must survive.
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 2);
        let good = log(td.path(), f);
        let (line, _) = next_line::<H>(td.path());
        append_raw(td.path(), f, &line[..line.len() - 3]);
        drop(H::open(td.path()).unwrap()); // recovers: marker at seq 2
        let recovered = log(td.path(), f);
        let marker_line = recovered[good.len()..].to_vec();
        // Rebuild "overwritten, not yet cut": marker + the torn line's
        // leftover bytes past the marker's length (if any) — make sure
        // there are some by using a torn line longer than the marker.
        let mut state = good.clone();
        state.extend_from_slice(&marker_line);
        state.extend_from_slice(b"2:deadbeef-leftover");
        fs::write(td.path().join(f.log), &state).unwrap();
        let s = H::open(td.path()).unwrap();
        assert_eq!(H::records(&s), 4, "marker kept + a second marker");
        assert!(H::marker_reason(&s, 2).is_some());
        assert!(H::marker_reason(&s, 3).is_some());
        drop(s);

        // Crash after the head was pulled back, before the overwrite:
        // head = verified tail, torn tail still there.
        let td = tempfile::TempDir::new().unwrap();
        let hashes = chain::<H>(td.path(), 2);
        let (line, _) = next_line::<H>(td.path());
        append_raw(td.path(), f, &line[..20]);
        fs::write(td.path().join(f.head), hashes[1]).unwrap();
        assert_starts::<H>(td.path(), 2, true, "crash before overwrite");

        // Crash after the cut, before the head moved to the marker: the
        // head is one behind the marker.
        let td = tempfile::TempDir::new().unwrap();
        let hashes = chain::<H>(td.path(), 2);
        let (line, _) = next_line::<H>(td.path());
        append_raw(td.path(), f, &line[..20]);
        drop(H::open(td.path()).unwrap());
        fs::write(td.path().join(f.head), hashes[1]).unwrap();
        let s = H::open(td.path()).unwrap();
        assert_eq!(H::records(&s), 3);
        assert!(H::marker_reason(&s, 2).is_some());
    }

    /// States no crash produces: each refuses, and leaves the files as
    /// they were (evidence).
    pub(crate) fn real_inconsistency_refuses<H: Harness>() {
        let f = H::FILES;
        let refuses = |dir: &Path, what: &str| {
            let (log0, head0) = (log(dir, f), head(dir, f));
            let err = match H::open(dir) {
                Ok(_) => panic!("{what}: started"),
                Err(e) => e.to_string(),
            };
            assert!(err.contains("REFUSING TO START"), "{what}: {err}");
            assert!(err.contains(REFUSAL_RUNBOOK), "{what}: {err}");
            assert_eq!(log(dir, f), log0, "{what}: log modified");
            assert_eq!(head(dir, f), head0, "{what}: head modified");
        };
        // A break the WALK must refuse on its own: also with the head file
        // gone and with the head naming the log's last line — the head
        // (an unauthenticated cache) must not be what catches it.
        let walk_refuses = |dir: &Path, what: &str| {
            refuses(dir, what);
            let saved = head(dir, f).unwrap();
            fs::remove_file(dir.join(f.head)).unwrap();
            refuses(dir, &format!("{what}, head removed"));
            let text = log(dir, f);
            let last = text
                .split(|b| *b == b'\n')
                .rfind(|l| !l.is_empty())
                .unwrap();
            let hash = hex::decode(last.rsplit(|b| *b == b':').next().unwrap()).unwrap();
            fs::write(dir.join(f.head), hash).unwrap();
            refuses(dir, &format!("{what}, head = its last line"));
            fs::write(dir.join(f.head), saved).unwrap();
        };
        let lines = |dir: &Path| -> Vec<Vec<u8>> {
            log(dir, f)
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
                .map(<[u8]>::to_vec)
                .collect()
        };
        let write_lines = |dir: &Path, ls: &[Vec<u8>]| {
            let mut out = Vec::new();
            for l in ls {
                out.extend_from_slice(l);
                out.push(b'\n');
            }
            fs::write(dir.join(f.log), out).unwrap();
        };

        // A middle record garbled (not self-consistent), records after it.
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 4);
        let mut ls = lines(td.path());
        let i = ls[1].len() / 2;
        ls[1][i] = if ls[1][i] == b'0' { b'1' } else { b'0' };
        write_lines(td.path(), &ls);
        walk_refuses(td.path(), "middle record garbled");

        // A middle chain break: a self-consistent record whose prev_hash is
        // not its predecessor (record 1 from ANOTHER chain, re-sequenced
        // nowhere — same seq, different history).
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 4);
        let other = tempfile::TempDir::new().unwrap();
        let s = H::open(other.path()).unwrap();
        H::append(&s, 50);
        H::append(&s, 51);
        drop(s);
        let mut ls = lines(td.path());
        ls[1] = lines(other.path())[1].clone();
        write_lines(td.path(), &ls);
        walk_refuses(td.path(), "middle prev_hash break");

        // The same break at the TAIL: self-consistent, so not "torn".
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 2);
        let mut ls = lines(td.path());
        ls[1] = lines(other.path())[1].clone();
        write_lines(td.path(), &ls);
        walk_refuses(td.path(), "tail prev_hash break");

        // A rewrite of an earlier record, re-hashed (self-consistent): the
        // next record no longer chains onto it.
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 3);
        let mut ls = lines(td.path());
        ls[0] = lines(other.path())[0].clone();
        write_lines(td.path(), &ls);
        walk_refuses(td.path(), "earlier record rewritten");

        // A seq gap before the tail: a record removed from the middle.
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 4);
        let mut ls = lines(td.path());
        ls.remove(1);
        write_lines(td.path(), &ls);
        walk_refuses(td.path(), "seq gap");

        // A self-consistent record whose line seq prefix (outside the hash)
        // disagrees with its body: the reader would refuse to serve it.
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 3);
        let mut ls = lines(td.path());
        assert_eq!(ls[2][0], b'2');
        ls[2][0] = b'7';
        write_lines(td.path(), &ls);
        walk_refuses(td.path(), "line seq prefix rewritten");

        // Head two ahead: the last whole record removed AND a torn tail
        // that does not name the head.
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 4);
        let mut ls = lines(td.path());
        ls.truncate(2);
        write_lines(td.path(), &ls);
        refuses(td.path(), "head two ahead");
        append_raw(td.path(), f, b"2:0a1b");
        refuses(td.path(), "head two ahead + torn tail");

        // A torn tail that names ANOTHER seq explains no head: records 2
        // and 3 cut away, then a torn line carrying the old head's hash.
        let td = tempfile::TempDir::new().unwrap();
        let hashes = chain::<H>(td.path(), 4);
        let mut ls = lines(td.path());
        ls.truncate(2);
        write_lines(td.path(), &ls);
        append_raw(
            td.path(),
            f,
            format!("9:00:{}", hex::encode(hashes[3])).as_bytes(),
        );
        refuses(
            td.path(),
            "torn tail with a foreign seq under a head far ahead",
        );

        // Head one ahead with NO torn tail: a whole record removed cleanly —
        // no crash removes a fsynced line.
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 3);
        let mut ls = lines(td.path());
        ls.truncate(2);
        write_lines(td.path(), &ls);
        refuses(td.path(), "last record removed cleanly");

        // The last record rewritten self-consistently: chains, but the head
        // names the original.
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 1);
        fs::copy(other.path().join(f.log), td.path().join(f.log)).unwrap();
        let mut ls = lines(td.path());
        ls.truncate(1);
        write_lines(td.path(), &ls);
        refuses(td.path(), "only record replaced self-consistently");

        // A cut log under a live head (missing / emptied).
        for emptied in [false, true] {
            let td = tempfile::TempDir::new().unwrap();
            chain::<H>(td.path(), 2);
            if emptied {
                fs::write(td.path().join(f.log), b"").unwrap();
            } else {
                fs::remove_file(td.path().join(f.log)).unwrap();
            }
            refuses(td.path(), &format!("cut log emptied={emptied}"));
        }

        // A malformed head.
        let td = tempfile::TempDir::new().unwrap();
        chain::<H>(td.path(), 2);
        fs::write(td.path().join(f.head), b"short").unwrap();
        refuses(td.path(), "malformed head");
    }

    /// The same crash points driven through the real code by the hook: the
    /// sink errors at the point, is dropped (the process died), and the
    /// directory reopens. Then the same points WITHOUT dying: the process
    /// goes on appending (the release audit is best-effort).
    pub(crate) fn hooked_append_crash_points<H: Harness>() {
        use super::crash_hook;
        // (point, records after reopen) — the record survives iff it was
        // wholly written.
        for (point, survives) in [
            ("append:partial-write", false),
            ("append:before-fsync", true),
            ("head:before-rename", true),
        ] {
            // Dies.
            let td = tempfile::TempDir::new().unwrap();
            chain::<H>(td.path(), 2);
            let s = H::open(td.path()).unwrap();
            crash_hook::arm(point);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| H::append(&s, 7)));
            crash_hook::disarm();
            assert!(r.is_err(), "{point}: the hook did not fire");
            assert_eq!(H::records(&s), 2 + u64::from(point == "head:before-rename"));
            drop(s);
            let want = if survives { 3 } else { 2 };
            assert_starts::<H>(td.path(), want, !survives, &format!("{point}, died"));

            // Lives on.
            let td = tempfile::TempDir::new().unwrap();
            chain::<H>(td.path(), 2);
            let s = H::open(td.path()).unwrap();
            crash_hook::arm(point);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| H::append(&s, 7)));
            crash_hook::disarm();
            assert!(r.is_err(), "{point}: the hook did not fire");
            assert_eq!(H::records(&s), 2 + u64::from(point == "head:before-rename"));
            let h = H::append(&s, 8);
            let n = H::records(&s);
            assert_eq!(H::page(&s).last(), Some(&(n - 1, h)), "{point}, lived on");
            drop(s);
            let s = H::open(td.path())
                .unwrap_or_else(|e| panic!("{point}, lived on: reopen refused: {e}"));
            assert_eq!(H::records(&s), n, "{point}, lived on");
            assert!(H::marker_reason(&s, 2).is_none(), "{point}, lived on");
        }
    }

    /// A second crash inside the open-time recovery, at each of its points,
    /// for a torn tail whose head is ONE AHEAD (the hardest case: a head
    /// left naming the dropped record would refuse the next open).
    pub(crate) fn hooked_recovery_crash_points<H: Harness>() {
        use super::crash_hook;
        let f = H::FILES;
        for point in [
            "recover:after-head-pullback",
            "recover:between-overwrite-and-cut",
            "recover:before-marker-head",
            "head:before-rename",
        ] {
            let td = tempfile::TempDir::new().unwrap();
            chain::<H>(td.path(), 2);
            let (line, h) = next_line::<H>(td.path());
            // Long torn tail (longer than the marker line): 400 hex zeros
            // spliced into the body, so the body no longer hashes but the
            // stored hash — which the head names (one ahead) — is intact.
            let colon = line.iter().position(|b| *b == b':').unwrap() + 1;
            let mut torn = line[..colon].to_vec();
            torn.extend_from_slice(&[b'0'; 400]);
            torn.extend_from_slice(&line[colon..line.len() - 1]);
            append_raw(td.path(), f, &torn);
            fs::write(td.path().join(f.head), h).unwrap();
            crash_hook::arm(point);
            let r = H::open(td.path());
            crash_hook::disarm();
            match r {
                Err(e) => assert!(e.to_string().contains("test crash at"), "{point}: {e}"),
                Ok(_) => panic!("{point}: the hook did not fire"),
            }
            let s = H::open(td.path())
                .unwrap_or_else(|e| panic!("{point}: the recovery's own crash refused: {e}"));
            assert!(
                H::marker_reason(&s, 2).is_some(),
                "{point}: the truncation marker was lost"
            );
            drop(s);
            if point == "recover:between-overwrite-and-cut" {
                // The marker overwrote the head of the torn bytes; the rest
                // was a second torn tail, truncated behind a second marker.
                assert_starts::<H>(td.path(), 3, true, point);
            } else {
                assert_starts::<H>(td.path(), 2, true, point);
            }
        }
    }

    /// A head write that FAILS (the process lives on) removes its temp.
    pub(crate) fn failed_head_write_leaves_no_temp<H: Harness>() {
        let f = H::FILES;
        let td = tempfile::TempDir::new().unwrap();
        let s = H::open(td.path()).unwrap();
        H::append(&s, 0);
        // The rename target is now a non-empty directory: rename fails.
        let head_path = td.path().join(f.head);
        fs::remove_file(&head_path).unwrap();
        fs::create_dir(&head_path).unwrap();
        fs::write(head_path.join("x"), b"x").unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| H::append(&s, 1)));
        assert!(r.is_err());
        let temps: Vec<_> = fs::read_dir(td.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(temps.is_empty(), "leaked {temps:?}");
    }

    /// A failed append at runtime (partial write, failed fsync) does not
    /// poison the log: the next append cuts it and the chain reopens.
    pub(crate) fn failed_append_is_cut_at_the_next<H: Harness>() {
        let f = H::FILES;
        let td = tempfile::TempDir::new().unwrap();
        let s = H::open(td.path()).unwrap();
        H::append(&s, 0);
        H::append(&s, 1);
        // What a failed write / fsync leaves: bytes past the indexed end
        // (here a whole valid-looking line at seq 2 AND garbage).
        let (line, _) = next_line::<H>(td.path());
        append_raw(td.path(), f, &line);
        append_raw(td.path(), f, b"2:ab");
        let h = H::append(&s, 2);
        assert_eq!(H::records(&s), 3);
        assert_eq!(H::page(&s).last(), Some(&(2, h)));
        drop(s);
        let s = H::open(td.path()).expect("the chain reopens");
        assert_eq!(H::records(&s), 3);
        assert!(H::marker_reason(&s, 2).is_none());

        // A log that SHRANK under the sink is not "repaired" by appending
        // at the wrong offset: the append is refused and writes nothing.
        let bytes = log(td.path(), f);
        let cut = &bytes[..bytes.len() - 5];
        fs::write(td.path().join(f.log), cut).unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| H::append(&s, 3)));
        assert!(r.is_err(), "appended onto a shrunken log");
        assert_eq!(log(td.path(), f), cut);
        assert_eq!(H::records(&s), 3);
    }
}
