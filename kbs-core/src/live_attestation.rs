//! Per-VM live-attestation persistence + replay-chain state (issue
//! #322 — Phase B).
//!
//! Two traits, two best-effort vs durable contracts:
//!
//! - [`LiveAttestationStateStore`] is **durable** — it owns the per-
//!   `vm_id` monotonic seq + `prev_attestation_hash` chain that the
//!   on-chain pallet (`pallet-compute-scoring::submit_live_attestation`)
//!   enforces. A crash AFTER a `commit` MUST keep the chain advanced
//!   (a missed advance breaks the chain at the next keepalive, fail-
//!   closed). Mirrors `crate::replay::ReleaseStore` discipline.
//! - [`LiveAttestationSink`] is **best-effort** — it archives the
//!   signed body off-chain (the full canonical-CBOR bytes + sig) for
//!   forensic replay. A failure here does NOT propagate; the durable
//!   side effect is the chain advance already committed via the state
//!   store. Mirrors `crate::evidence::EvidenceSink` discipline.
//!
//! The on-chain signed body itself is `hippius_types::
//! live_attestation::SignedLiveAttestation` — this module persists +
//! produces it, but does NOT define the wire format. Same separation
//! as `crate::audit_vm_cert` (this crate signs; wire-format crate
//! owns the bytes).

use hippius_types::live_attestation::SignedLiveAttestation;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::error::{KbsError, Result};

/// Per-`vm_id` snapshot the keepalive flow needs BEFORE signing the
/// next attestation: the seq it must use (`prev_seq + 1`, or `1` for
/// the very first attestation) and the SHA-256 hash of the previous
/// body it must chain off (`[0; 32]` for the first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveAttestationChain {
    pub next_seq: u64,
    pub prev_attestation_hash: [u8; 32],
}

impl LiveAttestationChain {
    /// The genesis seed — what an unseen `vm_id` looks like.
    pub fn genesis() -> Self {
        Self {
            next_seq: 1,
            prev_attestation_hash: [0u8; 32],
        }
    }
}

/// Per-`vm_id` replay-chain state. Implementations MUST make the
/// `commit_then_advance` write atomic + durable: a crash AFTER the
/// call returns `Ok` MUST surface the new `(seq, body_hash)` on
/// every subsequent `get_chain` for the same `vm_id`. The test
/// in-memory impl ([`InMemoryLiveAttestationState`]) covers the
/// trait shape; production wires a file-backed impl with the same
/// atomic-rename discipline as `crate::persist::FileReleaseStore`
/// (deferred to a follow-up PR — KBS today has no other persistent
/// per-VM counter, so adding the production backend deserves its
/// own diff).
pub trait LiveAttestationStateStore: Send + Sync {
    /// Read the chain seed for `vm_id`. Returns
    /// [`LiveAttestationChain::genesis`] for a `vm_id` never seen
    /// before.
    fn get_chain(&self, vm_id: &str) -> Result<LiveAttestationChain>;

    /// Atomically advance the chain: confirm that the `vm_id`'s
    /// current chain matches `expected_chain` (compare-and-swap),
    /// then write `(new_seq, new_body_hash)` durably. Returns
    /// `KbsError::Replay` if the CAS fails (concurrent keepalive
    /// landed first).
    fn commit_then_advance(
        &self,
        vm_id: &str,
        expected_chain: LiveAttestationChain,
        new_seq: u64,
        new_body_hash: [u8; 32],
    ) -> Result<()>;
}

/// In-memory, non-durable reference implementation. Adequate for
/// tests + the KBS-server happy-path bring-up; a production
/// deployment MUST wire a file-backed impl so a crash doesn't
/// rewind the chain.
#[derive(Default)]
pub struct InMemoryLiveAttestationState {
    map: Mutex<HashMap<String, LiveAttestationChain>>,
}

impl LiveAttestationStateStore for InMemoryLiveAttestationState {
    fn get_chain(&self, vm_id: &str) -> Result<LiveAttestationChain> {
        let g = self.map.lock().map_err(|_| KbsError::Replay)?;
        Ok(g.get(vm_id)
            .copied()
            .unwrap_or_else(LiveAttestationChain::genesis))
    }

    fn commit_then_advance(
        &self,
        vm_id: &str,
        expected_chain: LiveAttestationChain,
        new_seq: u64,
        new_body_hash: [u8; 32],
    ) -> Result<()> {
        let mut g = self.map.lock().map_err(|_| KbsError::Replay)?;
        let cur = g
            .get(vm_id)
            .copied()
            .unwrap_or_else(LiveAttestationChain::genesis);
        if cur != expected_chain {
            return Err(KbsError::Replay);
        }
        if new_seq != expected_chain.next_seq {
            return Err(KbsError::Replay);
        }
        g.insert(
            vm_id.to_string(),
            LiveAttestationChain {
                next_seq: new_seq.saturating_add(1),
                prev_attestation_hash: new_body_hash,
            },
        );
        Ok(())
    }
}

/// Per-attestation off-chain archive. Best-effort: `record` returns
/// `()` deliberately so the keepalive path cannot accidentally
/// fail-closed on a transient write error. The durable side effect
/// of a granted keepalive is the [`LiveAttestationStateStore`]
/// commit + the (eventual) on-chain extrinsic; archiving is
/// additive forensic data the vali batcher reads to ship to the
/// chain (until the production sink lands, archive readers may be
/// the operator's own scrape jobs).
pub trait LiveAttestationSink: Send + Sync {
    /// Archive `signed`. Failures are implementation-internal —
    /// they MUST NOT propagate into the keepalive decision.
    fn record(&self, vm_id: &str, signed: &SignedLiveAttestation);
}

/// No-op sink — for ops that disable off-chain archival entirely.
pub struct NullLiveAttestationSink;
impl LiveAttestationSink for NullLiveAttestationSink {
    fn record(&self, _vm_id: &str, _signed: &SignedLiveAttestation) {}
}

/// Production filesystem-backed sink. Writes to
/// `{dir}/pending/{vm_id}/{body_hash_hex_first_16}.cbor` with atomic
/// rename + parent fsync. The follow-up vali batcher reads from
/// `pending/` and moves submitted files to `submitted/`.
///
/// **Best-effort, like [`crate::evidence::FileEvidenceSink`]**:
/// failures inside `record` are logged to stderr + dropped; the
/// durable side effect of a granted keepalive is the on-chain
/// extrinsic (when the batcher gets the file there) + the
/// already-advanced [`LiveAttestationStateStore`] chain — never
/// the disk write.
///
/// Filename uses the first 16 hex chars of `SHA-256(canonical body)`
/// — the live-attestation body is unique per `(vm_id,
/// attestation_seq)` (the seq itself is monotonic per VM, the
/// canonical body is identical to the on-chain `body_hash`
/// pre-image), so the filename is collision-resistant without
/// embedding the seq directly. A reader can re-derive the seq + the
/// rest of the metadata by parsing the file's CBOR.
pub struct FileLiveAttestationSink {
    dir: PathBuf,
    /// Serializes the per-`vm_id` `create_dir_all` in-process. The
    /// kernel's own `mkdir` atomicity covers cross-process callers.
    mkdirs: Mutex<()>,
}

impl FileLiveAttestationSink {
    /// Open / create the root directory + the `pending/` subdir.
    /// Idempotent across boots. Returns `Err` only on a structural
    /// problem (root dir cannot be created); never on a per-record
    /// write failure (those go through `record` which is infallible).
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(dir.join("pending"))
            .map_err(|e| KbsError::Vault(format!("live-attestation create_dir_all: {e}")))?;
        Ok(Self {
            dir,
            mkdirs: Mutex::new(()),
        })
    }

    /// The directory this sink writes into. Exposed for tests + the
    /// `kbs-server` startup log line.
    pub fn root(&self) -> &PathBuf {
        &self.dir
    }

    fn try_record(&self, vm_id: &str, signed: &SignedLiveAttestation) -> Result<()> {
        let envelope = signed
            .encode()
            .map_err(|e| KbsError::Vault(format!("live-attestation envelope encode: {e}")))?;

        // Filename = first 16 hex chars of SHA-256(canonical body).
        // The body is sized for the §322 schema (~360 B); hashing is
        // O(1) relative to the write itself.
        let body_hash = Sha256::digest(signed.body.as_slice());
        let stem = hex_first_n(&body_hash, 16);

        // Per-`vm_id` subdir under `pending/`. The `mkdirs` mutex
        // serializes concurrent same-VM create_dir_all in-process.
        let vm_dir = self.dir.join("pending").join(vm_id);
        {
            let _g = self
                .mkdirs
                .lock()
                .map_err(|_| KbsError::Vault("live-attestation mkdir mutex poisoned".into()))?;
            fs::create_dir_all(&vm_dir)
                .map_err(|e| KbsError::Vault(format!("live-attestation vm subdir: {e}")))?;
        }

        // Atomic write: tmp + fsync + rename + parent fsync. Same
        // discipline as `evidence::FileEvidenceSink`.
        let final_path = vm_dir.join(format!("{stem}.cbor"));
        let tmp_path = vm_dir.join(format!("{stem}.cbor.tmp"));

        {
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp_path)
                .map_err(|e| KbsError::Vault(format!("live-attestation tmp open: {e}")))?;
            f.write_all(&envelope)
                .map_err(|e| KbsError::Vault(format!("live-attestation write: {e}")))?;
            f.sync_all()
                .map_err(|e| KbsError::Vault(format!("live-attestation fsync: {e}")))?;
        }
        fs::rename(&tmp_path, &final_path)
            .map_err(|e| KbsError::Vault(format!("live-attestation rename: {e}")))?;
        let dirf = File::open(&vm_dir)
            .map_err(|e| KbsError::Vault(format!("live-attestation dir open: {e}")))?;
        dirf.sync_all()
            .map_err(|e| KbsError::Vault(format!("live-attestation dir fsync: {e}")))?;
        Ok(())
    }
}

fn hex_first_n(bytes: &[u8], n_chars: usize) -> String {
    let mut out = String::with_capacity(n_chars);
    let n_bytes = n_chars.div_ceil(2);
    for b in bytes.iter().take(n_bytes) {
        out.push_str(&format!("{b:02x}"));
    }
    out.truncate(n_chars);
    out
}

impl LiveAttestationSink for FileLiveAttestationSink {
    fn record(&self, vm_id: &str, signed: &SignedLiveAttestation) {
        if let Err(e) = self.try_record(vm_id, signed) {
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "kbs-core::live_attestation: failed to record: {e}");
        }
    }
}

/// In-memory recording sink — for tests.
#[derive(Default)]
pub struct MockLiveAttestationSink {
    records: Mutex<Vec<(String, SignedLiveAttestation)>>,
}

impl MockLiveAttestationSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.records.lock().map(|g| g.len()).unwrap_or(0)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn snapshot(&self) -> Vec<(String, SignedLiveAttestation)> {
        self.records.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl LiveAttestationSink for MockLiveAttestationSink {
    fn record(&self, vm_id: &str, signed: &SignedLiveAttestation) {
        if let Ok(mut g) = self.records.lock() {
            g.push((vm_id.to_string(), signed.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_chain_is_seq_one_zero_hash() {
        let g = LiveAttestationChain::genesis();
        assert_eq!(g.next_seq, 1);
        assert_eq!(g.prev_attestation_hash, [0u8; 32]);
    }

    #[test]
    fn in_memory_state_starts_at_genesis() {
        let s = InMemoryLiveAttestationState::default();
        let c = s.get_chain("vm-1").unwrap();
        assert_eq!(c, LiveAttestationChain::genesis());
    }

    #[test]
    fn in_memory_state_advances_under_cas() {
        let s = InMemoryLiveAttestationState::default();
        let expected = s.get_chain("vm-1").unwrap();
        s.commit_then_advance("vm-1", expected, 1, [0xAB; 32])
            .unwrap();
        let c = s.get_chain("vm-1").unwrap();
        assert_eq!(c.next_seq, 2);
        assert_eq!(c.prev_attestation_hash, [0xAB; 32]);
    }

    #[test]
    fn in_memory_state_rejects_stale_expected() {
        let s = InMemoryLiveAttestationState::default();
        let expected = s.get_chain("vm-1").unwrap();
        s.commit_then_advance("vm-1", expected, 1, [0xAB; 32])
            .unwrap();
        // Stale CAS (still pointing at genesis) must fail.
        let stale = LiveAttestationChain::genesis();
        assert!(matches!(
            s.commit_then_advance("vm-1", stale, 1, [0xCD; 32]),
            Err(KbsError::Replay)
        ));
    }

    #[test]
    fn in_memory_state_rejects_seq_skip() {
        let s = InMemoryLiveAttestationState::default();
        let expected = s.get_chain("vm-1").unwrap();
        // `new_seq = 2` but `expected.next_seq = 1` — a sequence
        // mismatch even though the CAS itself matches.
        assert!(matches!(
            s.commit_then_advance("vm-1", expected, 2, [0xAB; 32]),
            Err(KbsError::Replay)
        ));
    }

    #[test]
    fn in_memory_state_isolates_per_vm_chains() {
        let s = InMemoryLiveAttestationState::default();
        let g = LiveAttestationChain::genesis();
        s.commit_then_advance("vm-A", g, 1, [0x11; 32]).unwrap();
        // vm-B's chain MUST still be at genesis.
        assert_eq!(s.get_chain("vm-B").unwrap(), g);
        assert_ne!(s.get_chain("vm-A").unwrap(), g);
    }

    #[test]
    fn mock_sink_records_per_call() {
        let s = MockLiveAttestationSink::new();
        assert!(s.is_empty());
        let signed = SignedLiveAttestation {
            body: vec![0xAA; 8],
            sig: vec![0xBB; 64],
        };
        s.record("vm-1", &signed);
        s.record("vm-2", &signed);
        assert_eq!(s.len(), 2);
        let snap = s.snapshot();
        assert_eq!(snap[0].0, "vm-1");
        assert_eq!(snap[1].0, "vm-2");
    }

    #[test]
    fn null_sink_drops_silently() {
        let s = NullLiveAttestationSink;
        let signed = SignedLiveAttestation {
            body: vec![0xAA; 8],
            sig: vec![0xBB; 64],
        };
        s.record("vm-1", &signed); // does not panic
    }

    #[test]
    fn file_sink_writes_pending_subdir() {
        let tmp = tempfile::tempdir().unwrap();
        let sink = FileLiveAttestationSink::open(tmp.path()).unwrap();
        let signed = SignedLiveAttestation {
            body: vec![0xAA; 32],
            sig: vec![0xBB; 64],
        };
        sink.record("vm-test", &signed);

        let vm_dir = tmp.path().join("pending").join("vm-test");
        assert!(vm_dir.is_dir(), "vm subdir must be created");
        let entries: Vec<_> = std::fs::read_dir(&vm_dir).unwrap().collect();
        assert_eq!(entries.len(), 1, "exactly one file per record");

        let entry = entries[0].as_ref().unwrap();
        let name = entry.file_name().into_string().unwrap();
        assert!(name.ends_with(".cbor"));

        // File contents = encoded envelope.
        let bytes = std::fs::read(entry.path()).unwrap();
        let decoded = SignedLiveAttestation::decode(&bytes).unwrap();
        assert_eq!(decoded, signed);
    }

    #[test]
    fn file_sink_isolates_per_vm() {
        let tmp = tempfile::tempdir().unwrap();
        let sink = FileLiveAttestationSink::open(tmp.path()).unwrap();
        let signed_a = SignedLiveAttestation {
            body: vec![0x01; 16],
            sig: vec![0xBB; 64],
        };
        let signed_b = SignedLiveAttestation {
            body: vec![0x02; 16],
            sig: vec![0xCC; 64],
        };
        sink.record("vm-A", &signed_a);
        sink.record("vm-B", &signed_b);

        assert!(tmp.path().join("pending/vm-A").is_dir());
        assert!(tmp.path().join("pending/vm-B").is_dir());
        assert_eq!(
            std::fs::read_dir(tmp.path().join("pending/vm-A"))
                .unwrap()
                .count(),
            1
        );
        assert_eq!(
            std::fs::read_dir(tmp.path().join("pending/vm-B"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn file_sink_chains_multiple_attestations_per_vm() {
        let tmp = tempfile::tempdir().unwrap();
        let sink = FileLiveAttestationSink::open(tmp.path()).unwrap();
        for i in 0u8..3 {
            let signed = SignedLiveAttestation {
                body: vec![i; 32],
                sig: vec![0xBB; 64],
            };
            sink.record("vm-1", &signed);
        }
        let n = std::fs::read_dir(tmp.path().join("pending/vm-1"))
            .unwrap()
            .count();
        assert_eq!(n, 3, "3 distinct bodies ⇒ 3 distinct files");
    }
}
