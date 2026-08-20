//! Durable, hash-chained telemetry audit log (PR-H6, §15).
//!
//! Every opaque-relay transaction emits a [`SignedEdgeTelemetry`]
//! envelope; this module is the **append-only, tamper-evident** sink
//! those envelopes land in. It is a deliberate, edge-local
//! re-implementation of the `kbs-core::audit::FileAuditSink` pattern —
//! the Edge does NOT depend on `kbs-core` (that would pull the whole
//! KBS / HPKE / SEV stack across the diode, exactly the coupling §5
//! forbids). The chain invariants are identical to `kbs-core`'s.
//!
//! ## On-disk shape
//!
//! Records are newline-delimited lines in `{dir}/audit.log`, each
//! `<seq>:<hex_record_body>:<hex_record_hash>`. The record body is
//! canonical CBOR `{domain, prev_hash, seq, sig, telemetry}` — it
//! commits the SHA-256 of the PREVIOUS record's body via `prev_hash`,
//! forming a hash chain. `{dir}/head.sha256` caches the latest record
//! hash so a reader can check the tail without the whole log.
//!
//! **Authority hierarchy:** `audit.log` is THE source of truth;
//! `head.sha256` is a denormalised cache. [`EdgeAuditSink::open`]
//! WALKS the log to derive the real tail and repairs `head.sha256` if
//! it disagrees — a crash between the log fsync and the head rename
//! cannot derail the next append.
//!
//! ## Concurrency (the §H reviewer focus)
//!
//! Identical model to `kbs-core::audit`:
//!
//! - **Cross-process:** an exclusive advisory lock on `audit.lock`
//!   (`std::fs::File::lock`) is held for the sink's whole lifetime.
//!   A second `EdgeAuditSink::open` in another process blocks.
//! - **In-process:** every [`EdgeAuditSink::append`] takes a `Mutex`
//!   for the WHOLE read-modify-write — read `prev_hash`/`seq`, build
//!   and sign the record, write the line, fsync, rename the head.
//!   Two concurrent `append` calls therefore serialize completely;
//!   the sequence numbers are strictly monotonic in log order and
//!   the chain can never interleave. `O_APPEND` alone does NOT
//!   serialize the `prev_hash` read-modify-write — the `Mutex` is
//!   the real primitive.
//!
//! ## Tamper detection caveat
//!
//! An attacker with filesystem write access can still rebuild a fully
//! consistent parallel log. The chain raises the bar from "silent
//! overwrite" to "rewrite the entire tail + the head pointer". The
//! §15 answer is external: Sentinel pulls `/v1/edge/audit/verify`
//! periodically and an external root signs over `(count, head)` — the
//! Edge signature on each envelope ([`crate::wire`]) is the
//! authenticity layer, this chain is the ordering/completeness layer.

use crate::wire::{EdgeTelemetryEnvelope, SignedEdgeTelemetry, TELEMETRY_DOMAIN};
use ciborium::value::Value;
use hippius_types::cbor::{assert_canonical, to_canonical_vec};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Domain tag for an audit record — distinct from [`crate::wire::TELEMETRY_DOMAIN`]
/// (the envelope inside) and from every other signed/hashed payload in
/// the stack.
pub const EDGE_AUDIT_DOMAIN: &str = "HIPPIUS_EDGE_AUDIT_V1";

const LOG_FILENAME: &str = "audit.log";
const HEAD_FILENAME: &str = "head.sha256";
const LOCK_FILENAME: &str = "audit.lock";

/// Stable static-classifier errors. Same `&'static str`-only `Display`
/// discipline as `EdgeError` — the diagnostic sink keys on these.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// A filesystem operation failed (create, open, read, write,
    /// fsync, rename).
    #[error("audit-io")]
    Io,
    /// The cross-process advisory lock could not be acquired.
    #[error("audit-lock")]
    Lock,
    /// Canonical-CBOR encoding of a record (or the telemetry envelope
    /// the caller's closure builds) failed.
    #[error("audit-encode")]
    Encode,
    /// The on-disk log failed chain verification — a broken link, a
    /// hash mismatch, a wrong domain, a non-monotone sequence, or a
    /// malformed line. ALL of these mean the log was tampered with
    /// (a log produced only by `append` always walks cleanly).
    #[error("audit-tamper")]
    Tamper,
    /// The in-process `Mutex` was poisoned by a prior panic.
    #[error("audit-poisoned")]
    Poisoned,
}

impl AuditError {
    /// Static classifier for the diagnostic sink.
    pub fn class(&self) -> &'static str {
        match self {
            AuditError::Io => "audit-io",
            AuditError::Lock => "audit-lock",
            AuditError::Encode => "audit-encode",
            AuditError::Tamper => "audit-tamper",
            AuditError::Poisoned => "audit-poisoned",
        }
    }
}

/// Result of walking the whole log — the record count and the tail
/// hash. Returned by [`EdgeAuditSink::verify`].
#[derive(Debug, Clone, Copy)]
pub struct VerifiedEdgeAudit {
    /// Number of records in the log.
    pub records: u64,
    /// SHA-256 of the last record's body (all-zero for an empty log).
    pub head: [u8; 32],
}

/// Durable file-backed sink: a single append-only log + a SHA-256
/// hash chain + a cross-process advisory lock.
pub struct EdgeAuditSink {
    dir: PathBuf,
    /// Held for the sink's lifetime — drops the advisory lock on
    /// `Drop`. The cross-process exclusivity primitive.
    _lock: File,
    /// In-process serialization of the multi-step append.
    state: Mutex<HeadState>,
}

#[derive(Debug, Clone, Copy)]
struct HeadState {
    /// Previous record's SHA-256, or all-zero for a fresh chain.
    prev_hash: [u8; 32],
    /// Next sequence number to issue == record count so far.
    next_seq: u64,
}

impl EdgeAuditSink {
    /// Open / create the audit directory and take its exclusive
    /// advisory lock for the lifetime of `Self`. ALWAYS walks
    /// `audit.log` to derive the true tail — and so detects any
    /// tampering that happened while the process was down — then
    /// repairs `head.sha256` if it is stale.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, AuditError> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|_| AuditError::Io)?;

        // Acquire the exclusive lock; blocks until any other holder
        // drops its handle.
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join(LOCK_FILENAME))
            .map_err(|_| AuditError::Io)?;
        lock.lock().map_err(|_| AuditError::Lock)?;

        // Walk the log → the real tail. Repair `head.sha256` if it
        // disagrees (or is missing while the log has records).
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
            Err(_) => return Err(AuditError::Io),
        }
        // Clean any stale temp head from a crashed prior run.
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

    /// Append one telemetry record.
    ///
    /// `build` is handed the sequence number this record will take and
    /// returns the [`SignedEdgeTelemetry`] to store. Running it under
    /// the append `Mutex` is what lets the telemetry envelope's
    /// `counter` field equal the audit `seq` — a single monotonic
    /// number, assigned once, with no window for a concurrent caller
    /// to interleave.
    ///
    /// Best-effort callers (the relay path) treat an `Err` as a
    /// logged anomaly, never as a reason to fail the relay.
    pub fn append<F>(&self, build: F) -> Result<(), AuditError>
    where
        F: FnOnce(u64) -> Result<SignedEdgeTelemetry, AuditError>,
    {
        let mut g = self.state.lock().map_err(|_| AuditError::Poisoned)?;
        let seq = g.next_seq;
        let signed = build(seq)?;
        let body = build_record(&g.prev_hash, seq, &signed)?;

        let mut hash = [0u8; 32];
        hash.copy_from_slice(Sha256::digest(&body).as_slice());

        // Append the line, fsync, then atomically update the head.
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(LOG_FILENAME))
            .map_err(|_| AuditError::Io)?;
        let line = format!("{seq}:{}:{}\n", hex::encode(&body), hex::encode(hash));
        f.write_all(line.as_bytes()).map_err(|_| AuditError::Io)?;
        f.sync_all().map_err(|_| AuditError::Io)?;
        write_head_atomic(&self.dir, &hash)?;

        g.prev_hash = hash;
        g.next_seq = seq.saturating_add(1);
        Ok(())
    }

    /// Current head hash — the SHA-256 of the most recent record's
    /// body (all-zero for an empty log). O(1): served straight from
    /// in-memory state. Sound because this process holds the
    /// exclusive lock and is the only writer.
    pub fn head(&self) -> [u8; 32] {
        self.state.lock().map(|g| g.prev_hash).unwrap_or([0u8; 32])
    }

    /// Number of records in the log. O(1), in-memory (see [`Self::head`]).
    pub fn record_count(&self) -> u64 {
        self.state.lock().map(|g| g.next_seq).unwrap_or(0)
    }

    /// Re-walk the log from disk, recompute the chain, and return the
    /// verified record count + tail hash. Errors with
    /// [`AuditError::Tamper`] if the chain does not check out — a
    /// broken hash link, a non-monotone `seq`, a wrong domain, or an
    /// embedded telemetry envelope whose signed `counter` does not
    /// match its chain position. This is the O(n) deep check: `open`
    /// runs it once at boot, `tests` run it for integrity, and the
    /// `/v1/edge/audit/verify` endpoint runs it per scrape.
    ///
    /// Like `kbs-core::audit::FileAuditSink::verify`, this does NOT
    /// hold the append `Mutex` — it is a point-in-time snapshot, so a
    /// `/v1/edge/audit/verify` scrape never stalls telemetry appends.
    pub fn verify(&self) -> Result<VerifiedEdgeAudit, AuditError> {
        let verified = walk_log(&self.dir)?;
        let head_path = self.dir.join(HEAD_FILENAME);
        match fs::read(&head_path) {
            Ok(bytes) => {
                // An empty `head.sha256` is a valid empty-log state —
                // `walk_log` / `open` both accept it, so `verify` must
                // too. Only a non-empty, mismatching head is tamper.
                let empty_ok = bytes.is_empty() && verified.records == 0;
                if !empty_ok && bytes != verified.head {
                    return Err(AuditError::Tamper);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if verified.records > 0 {
                    return Err(AuditError::Tamper);
                }
            }
            Err(_) => return Err(AuditError::Io),
        }
        Ok(verified)
    }
}

/// Build the canonical-CBOR body of one audit record. `to_canonical_vec`
/// sorts the map keys to the RFC 8949 §4.2.1 order, so the input
/// ordering here is irrelevant.
fn build_record(
    prev_hash: &[u8; 32],
    seq: u64,
    signed: &SignedEdgeTelemetry,
) -> Result<Vec<u8>, AuditError> {
    let v = Value::Map(vec![
        (
            Value::Text("domain".into()),
            Value::Text(EDGE_AUDIT_DOMAIN.into()),
        ),
        (
            Value::Text("prev_hash".into()),
            Value::Bytes(prev_hash.to_vec()),
        ),
        (Value::Text("seq".into()), Value::Integer(seq.into())),
        (Value::Text("sig".into()), Value::Bytes(signed.sig.clone())),
        (
            Value::Text("telemetry".into()),
            Value::Bytes(signed.body.clone()),
        ),
    ]);
    to_canonical_vec(&v).map_err(|_| AuditError::Encode)
}

/// Atomic-rename write of `head.sha256`, using a unique temp name so a
/// stale `.tmp` from a previous crash cannot block the write.
fn write_head_atomic(dir: &Path, h: &[u8; 32]) -> Result<(), AuditError> {
    // A unique suffix from the nanosecond clock — no `rand` dep, and a
    // collision would only mean falling back to a fresh `create_new`.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!("{HEAD_FILENAME}.tmp.{nonce}"));
    let mut hf = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .map_err(|_| AuditError::Io)?;
    hf.write_all(h).map_err(|_| AuditError::Io)?;
    hf.sync_all().map_err(|_| AuditError::Io)?;
    drop(hf);
    fs::rename(&tmp, dir.join(HEAD_FILENAME)).map_err(|_| AuditError::Io)?;
    let dirf = File::open(dir).map_err(|_| AuditError::Io)?;
    dirf.sync_all().map_err(|_| AuditError::Io)?;
    Ok(())
}

/// Read + decode + chain-check the whole log. Returns the record count
/// and the computed tail hash. Does NOT touch `head.sha256`.
fn walk_log(dir: &Path) -> Result<VerifiedEdgeAudit, AuditError> {
    let log_path = dir.join(LOG_FILENAME);
    let head_path = dir.join(HEAD_FILENAME);

    let bytes = match fs::read(&log_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Log absent. If the head references records, the log was
            // deleted out from under us — tamper.
            return match fs::read(&head_path) {
                Ok(h) if h.iter().all(|b| *b == 0) || h.is_empty() => Ok(VerifiedEdgeAudit {
                    records: 0,
                    head: [0u8; 32],
                }),
                Ok(_) => Err(AuditError::Tamper),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(VerifiedEdgeAudit {
                    records: 0,
                    head: [0u8; 32],
                }),
                Err(_) => Err(AuditError::Io),
            };
        }
        Err(_) => return Err(AuditError::Io),
    };
    if bytes.is_empty() {
        // Empty log file — head must be absent or all-zero.
        return match fs::read(&head_path) {
            Ok(h) if h.iter().all(|b| *b == 0) || h.is_empty() => Ok(VerifiedEdgeAudit {
                records: 0,
                head: [0u8; 32],
            }),
            Ok(_) => Err(AuditError::Tamper),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(VerifiedEdgeAudit {
                records: 0,
                head: [0u8; 32],
            }),
            Err(_) => Err(AuditError::Io),
        };
    }

    let text = std::str::from_utf8(&bytes).map_err(|_| AuditError::Tamper)?;
    let mut expected_prev = [0u8; 32];
    let mut records = 0u64;
    let mut last_hash = [0u8; 32];
    for raw in text.lines() {
        let mut parts = raw.splitn(3, ':');
        let seq_str = parts.next().ok_or(AuditError::Tamper)?;
        let body_hex = parts.next().ok_or(AuditError::Tamper)?;
        let hash_hex = parts.next().ok_or(AuditError::Tamper)?;

        let line_seq: u64 = seq_str.parse().map_err(|_| AuditError::Tamper)?;
        if line_seq != records {
            return Err(AuditError::Tamper);
        }
        let body = hex::decode(body_hex).map_err(|_| AuditError::Tamper)?;
        // Canonical encoding + strict schema, both enforced.
        assert_canonical(&body).map_err(|_| AuditError::Tamper)?;
        let decoded = decode_record(&body).ok_or(AuditError::Tamper)?;
        if decoded.domain != EDGE_AUDIT_DOMAIN {
            return Err(AuditError::Tamper);
        }
        if decoded.seq != line_seq {
            return Err(AuditError::Tamper);
        }
        if decoded.prev_hash != expected_prev {
            return Err(AuditError::Tamper);
        }
        // PR-H6 codex review: bind the SIGNED telemetry envelope to its
        // chain position. The envelope's `counter` lives inside the
        // Ed25519-signed body, so a record cannot be moved to a
        // different `seq` (reordered) without breaking either this
        // equality OR its signature. The envelope must also be a
        // well-formed, canonical, correctly-domained `EdgeTelemetryEnvelope`
        // — a rewritten log of garbage telemetry no longer "verifies".
        // Full SIGNATURE verification stays the consumer's job: the
        // Edge rotates its key every boot and cannot re-verify records
        // from prior boots (Sentinel keeps the per-boot pubkey history).
        let envelope = EdgeTelemetryEnvelope::from_canonical(&decoded.telemetry)
            .map_err(|_| AuditError::Tamper)?;
        if envelope.domain != TELEMETRY_DOMAIN || envelope.counter != line_seq {
            return Err(AuditError::Tamper);
        }

        let mut recomputed = [0u8; 32];
        recomputed.copy_from_slice(Sha256::digest(&body).as_slice());
        let on_disk = hex::decode(hash_hex).map_err(|_| AuditError::Tamper)?;
        if on_disk != recomputed {
            return Err(AuditError::Tamper);
        }

        expected_prev = recomputed;
        last_hash = recomputed;
        records += 1;
    }
    Ok(VerifiedEdgeAudit {
        records,
        head: last_hash,
    })
}

/// A decoded audit record: the chain-relevant fields plus the embedded
/// telemetry body, which `walk_log` re-decodes to bind the signed
/// `counter` to the chain `seq`.
struct AuditRecord {
    domain: String,
    prev_hash: [u8; 32],
    seq: u64,
    /// The canonical-CBOR `EdgeTelemetryEnvelope` body.
    telemetry: Vec<u8>,
}

/// Strict decoder: `Some` only if the CBOR matches the record schema
/// EXACTLY — every required field present with the right type, no
/// duplicate keys, no extra keys. `sig` is required to be a byte
/// string; `telemetry` is returned for `walk_log` to re-decode +
/// counter-check (full signature verification stays the consumer's
/// job — see `walk_log`).
fn decode_record(body: &[u8]) -> Option<AuditRecord> {
    let v: Value = ciborium::de::from_reader(body).ok()?;
    let Value::Map(entries) = v else { return None };
    let mut domain = None;
    let mut prev_hash = None;
    let mut seq = None;
    let mut sig = None;
    let mut telemetry = None;
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
            "prev_hash" => {
                if prev_hash.is_some() {
                    return None;
                }
                let Value::Bytes(b) = val else { return None };
                let arr: [u8; 32] = b.try_into().ok()?;
                prev_hash = Some(arr);
            }
            "seq" => {
                if seq.is_some() {
                    return None;
                }
                let Value::Integer(i) = val else { return None };
                seq = Some(u64::try_from(i).ok()?);
            }
            "sig" => {
                if sig.is_some() {
                    return None;
                }
                let Value::Bytes(b) = val else { return None };
                sig = Some(b);
            }
            "telemetry" => {
                if telemetry.is_some() {
                    return None;
                }
                let Value::Bytes(b) = val else { return None };
                telemetry = Some(b);
            }
            _ => return None, // unknown field
        }
    }
    // Every field must be present. `sig` is required but the chain
    // does not use it (the consumer verifies the signature).
    let _ = sig?;
    Some(AuditRecord {
        domain: domain?,
        prev_hash: prev_hash?,
        seq: seq?,
        telemetry: telemetry?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{Direction, MessageKind};
    use tempfile::TempDir;

    /// A `SignedEdgeTelemetry` whose body is a real, canonical
    /// `EdgeTelemetryEnvelope` with `counter == seq`. `walk_log`
    /// re-decodes + counter-checks the embedded envelope, so test
    /// records must be well-formed. The signature is a fixed stub —
    /// the audit CHAIN does not verify it (that is the consumer's job).
    fn signed_for(seq: u64) -> SignedEdgeTelemetry {
        let envelope = EdgeTelemetryEnvelope {
            domain: TELEMETRY_DOMAIN.to_string(),
            timestamp: 1_700_000_000 + seq,
            counter: seq,
            peer_id: format!("hippius-miner:{seq}"),
            direction: Direction::MinerToInner,
            message_kind: MessageKind::ServedReceipt,
            bytes_in: 100,
            bytes_out: 100,
            shed: false,
            shed_reason: None,
        };
        SignedEdgeTelemetry {
            body: envelope.to_canonical().unwrap(),
            sig: vec![0u8; 64],
        }
    }

    fn append_n(sink: &EdgeAuditSink, n: u8) {
        for _ in 0..n {
            sink.append(|seq| Ok(signed_for(seq))).unwrap();
        }
    }

    #[test]
    fn empty_log_verifies_as_zero_records() {
        let td = TempDir::new().unwrap();
        let s = EdgeAuditSink::open(td.path()).unwrap();
        let v = s.verify().unwrap();
        assert_eq!(v.records, 0);
        assert_eq!(v.head, [0u8; 32]);
        assert_eq!(s.record_count(), 0);
        assert_eq!(s.head(), [0u8; 32]);
    }

    #[test]
    fn appended_records_chain_and_count() {
        let td = TempDir::new().unwrap();
        let s = EdgeAuditSink::open(td.path()).unwrap();
        append_n(&s, 5);
        let v = s.verify().unwrap();
        assert_eq!(v.records, 5);
        assert_eq!(s.record_count(), 5);
        // In-memory head matches the walked head.
        assert_eq!(s.head(), v.head);
        assert_ne!(v.head, [0u8; 32]);
    }

    #[test]
    fn counter_seq_is_handed_to_the_build_closure_monotonically() {
        let td = TempDir::new().unwrap();
        let s = EdgeAuditSink::open(td.path()).unwrap();
        let mut seen = Vec::new();
        for _ in 0..4 {
            s.append(|seq| {
                seen.push(seq);
                Ok(signed_for(seq))
            })
            .unwrap();
        }
        assert_eq!(seen, vec![0, 1, 2, 3]);
    }

    #[test]
    fn reopen_picks_up_the_chain() {
        let td = TempDir::new().unwrap();
        {
            let s = EdgeAuditSink::open(td.path()).unwrap();
            append_n(&s, 3);
        }
        let s2 = EdgeAuditSink::open(td.path()).unwrap();
        append_n(&s2, 2);
        assert_eq!(s2.verify().unwrap().records, 5);
        assert_eq!(s2.record_count(), 5);
    }

    #[test]
    fn build_closure_error_aborts_the_append() {
        let td = TempDir::new().unwrap();
        let s = EdgeAuditSink::open(td.path()).unwrap();
        let err = s.append(|_seq| Err(AuditError::Encode)).unwrap_err();
        assert!(matches!(err, AuditError::Encode));
        // The failed append must not have advanced the chain.
        assert_eq!(s.record_count(), 0);
        assert_eq!(s.verify().unwrap().records, 0);
    }

    #[test]
    fn tampered_body_is_detected() {
        let td = TempDir::new().unwrap();
        let s = EdgeAuditSink::open(td.path()).unwrap();
        append_n(&s, 2);
        let log_path = td.path().join(LOG_FILENAME);
        let content = fs::read_to_string(&log_path).unwrap();
        let idx = content.find("0:").unwrap() + 2;
        let mut bytes = content.into_bytes();
        bytes[idx] = if bytes[idx] == b'a' { b'b' } else { b'a' };
        fs::write(&log_path, bytes).unwrap();
        assert!(matches!(s.verify(), Err(AuditError::Tamper)));
    }

    #[test]
    fn reordered_chain_is_detected() {
        let td = TempDir::new().unwrap();
        let s = EdgeAuditSink::open(td.path()).unwrap();
        append_n(&s, 2);
        let log_path = td.path().join(LOG_FILENAME);
        let content = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let reordered = format!("{}\n{}\n", lines[1], lines[0]);
        fs::write(&log_path, reordered).unwrap();
        assert!(matches!(s.verify(), Err(AuditError::Tamper)));
    }

    #[test]
    fn log_deletion_with_stale_head_is_tamper() {
        let td = TempDir::new().unwrap();
        let s = EdgeAuditSink::open(td.path()).unwrap();
        append_n(&s, 1);
        drop(s);
        fs::remove_file(td.path().join(LOG_FILENAME)).unwrap();
        // The open path itself detects the deletion.
        assert!(matches!(
            EdgeAuditSink::open(td.path()),
            Err(AuditError::Tamper)
        ));
    }

    #[test]
    fn open_repairs_a_stale_head() {
        let td = TempDir::new().unwrap();
        let s = EdgeAuditSink::open(td.path()).unwrap();
        append_n(&s, 1);
        drop(s);
        // Simulate a pre-rename crash: head zeroed.
        fs::write(td.path().join(HEAD_FILENAME), [0u8; 32]).unwrap();
        let s2 = EdgeAuditSink::open(td.path()).unwrap();
        // verify() passes only if open() repaired the head from the log.
        assert_eq!(s2.verify().unwrap().records, 1);
    }

    #[test]
    fn cross_process_lock_excludes_a_second_opener() {
        let td = TempDir::new().unwrap();
        let s = EdgeAuditSink::open(td.path()).unwrap();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(td.path().join(LOCK_FILENAME))
            .unwrap();
        // The first sink holds the lock — a try_lock must fail.
        assert!(lock.try_lock().is_err());
        drop(s);
    }

    #[test]
    fn error_class_is_stable() {
        for (e, c) in [
            (AuditError::Io, "audit-io"),
            (AuditError::Lock, "audit-lock"),
            (AuditError::Encode, "audit-encode"),
            (AuditError::Tamper, "audit-tamper"),
            (AuditError::Poisoned, "audit-poisoned"),
        ] {
            assert_eq!(e.class(), c);
            assert_eq!(e.to_string(), c);
        }
    }
}
