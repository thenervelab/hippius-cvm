//! Per-release **evidence-bundle** persistence (issue #280 Phase 1).
//!
//! On every granted `release::process_release` call,
//! `EvidenceSink::record` archives a [`SignedEvidenceBundle`]: a
//! KBS-L0-signed envelope of the raw SNP report bytes, the VCEK chain
//! the verifier just used, the §22 allowlist epoch + manifest digest,
//! and the L1-signed OrderTicket — exactly enough public attestation
//! data for a future tenant verifier (issue #280 Phase 3) to re-check
//! the SEV-SNP chain of custody offline, against AMD's silicon root.
//!
//! ## Best-effort contract (§7 / §15)
//!
//! The audit log (`crate::audit`) is the **single fatal durable side
//! effect** of release. Evidence is additive auditing infrastructure:
//! [`EvidenceSink::record`] returns `()` deliberately so the release
//! path cannot accidentally fail-closed on a transient filesystem
//! error here. Implementation errors are logged via stderr (matching
//! the `crate::audit` convention at `kbs-core/src/audit.rs:511`) and
//! dropped — the release still returns `Ok(SignedResponse)` to the
//! tenant. A subsequent operator action (or PR-K14 metric / alert
//! after PR-K14b lands KBS `/metrics`) surfaces the loss.
//!
//! ## Layout
//!
//! [`FileEvidenceSink`] writes one CBOR file per release at
//! `{dir}/{vm_id}/{ticket_id}.cbor`. Ticket IDs are unique per release
//! (the replay store at `crate::replay::ReleaseStore` enforces
//! single-use), so there is no inter-release filename contention and
//! no seq counter is needed. Lookups by `(vm_id, ticket_id)` are
//! deterministic, lookups by `vm_id` enumerate the subdir.
//!
//! Per-release writes use the same atomic-write + dir-fsync discipline
//! as `crate::audit::write_head_atomic` — write to a tmp file, fsync,
//! rename into place, fsync the parent directory. Crash-safe: either
//! the final file is fully present or it is not, never half-written.

use crate::error::{KbsError, Result};
use hippius_types::evidence_bundle::SignedEvidenceBundle;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Per-release evidence-bundle archive sink.
///
/// **Best-effort by construction**: `record` takes `&SignedEvidenceBundle`
/// and returns `()`. An implementation that wants to surface a write
/// failure can `eprintln!` to its own log; failures MUST NOT escape
/// back into the release path (the audit record is what commits the
/// release fact durably).
pub trait EvidenceSink: Send + Sync {
    /// Archive `bundle`. Failures are implementation-internal — they
    /// do NOT propagate into the release decision.
    fn record(&self, bundle: &SignedEvidenceBundle);

    /// Read side: the MOST RECENT signed evidence bundle for `vm_id`
    /// (newest by file mtime), or `None` if no release has been
    /// recorded. Powers the tenant-facing attestation endpoint. The
    /// default is `Ok(None)` so write-only / disabled sinks need no
    /// override; [`FileEvidenceSink`] reads the per-VM subdir.
    fn latest_for_vm(&self, _vm_id: &str) -> Result<Option<SignedEvidenceBundle>> {
        Ok(None)
    }
}

/// Production filesystem-backed sink. Writes to
/// `{dir}/{vm_id}/{ticket_id}.cbor` with atomic rename + parent fsync.
///
/// No cross-process lock: filenames are keyed by `ticket_id` which is
/// unique per release, so concurrent releases of distinct tickets
/// never contend on the same file. The in-process `mkdirs` mutex
/// serializes the per-`vm_id` `create_dir_all` against itself (cheap
/// and only contended on the first release for a given VM).
pub struct FileEvidenceSink {
    dir: PathBuf,
    /// Serializes the per-`vm_id` `create_dir_all` in-process so
    /// concurrent releases for different VMs don't all stat the
    /// filesystem in parallel. Cross-process callers serialize via
    /// the kernel's own `mkdir` atomicity (idempotent).
    mkdirs: Mutex<()>,
}

impl FileEvidenceSink {
    /// Open / create the evidence root directory. Idempotent; safe to
    /// call on every KBS boot. Returns `Err` only on a structural
    /// problem (root dir cannot be created); never on a per-release
    /// write failure (those go through `record` which is infallible).
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)
            .map_err(|e| KbsError::Vault(format!("evidence create_dir_all: {e}")))?;
        Ok(Self {
            dir,
            mkdirs: Mutex::new(()),
        })
    }

    /// The directory this sink writes into. Exposed for tests and for
    /// the `kbs-server` startup log line.
    pub fn root(&self) -> &PathBuf {
        &self.dir
    }

    /// Read the newest `{dir}/{vm_id}/*.cbor` bundle. `vm_id` is
    /// charset-checked BEFORE the path join so a `../` cannot traverse
    /// out of the evidence root (defense-in-depth — the admin endpoint
    /// is mTLS-gated, but a path-safe read is cheap insurance).
    fn read_latest(&self, vm_id: &str) -> Result<Option<SignedEvidenceBundle>> {
        if vm_id.is_empty()
            || vm_id.len() > 256
            || !vm_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(KbsError::Vault("evidence: invalid vm_id".into()));
        }
        let vm_dir = self.dir.join(vm_id);
        let entries = match fs::read_dir(&vm_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(KbsError::Vault(format!("evidence read_dir: {e}"))),
        };
        // Pick the newest finalised `.cbor` (skip in-flight `.cbor.tmp`).
        let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
        for entry in entries {
            let entry = entry.map_err(|e| KbsError::Vault(format!("evidence entry: {e}")))?;
            let path = entry.path();
            let is_cbor = path.extension().and_then(|x| x.to_str()) == Some("cbor");
            if !is_cbor {
                continue;
            }
            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .map_err(|e| KbsError::Vault(format!("evidence mtime: {e}")))?;
            if newest.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true) {
                newest = Some((mtime, path));
            }
        }
        let Some((_, path)) = newest else {
            return Ok(None);
        };
        let bytes = fs::read(&path).map_err(|e| KbsError::Vault(format!("evidence read: {e}")))?;
        let bundle = SignedEvidenceBundle::decode(&bytes)
            .map_err(|e| KbsError::Vault(format!("evidence decode: {e}")))?;
        Ok(Some(bundle))
    }

    /// Internal try-record that surfaces errors to the caller — used
    /// by [`EvidenceSink::record`] to log + drop. Kept private so the
    /// release path can never accidentally call a fallible variant.
    fn try_record(&self, bundle: &SignedEvidenceBundle) -> Result<()> {
        // Decode the bundle body just enough to recover `vm_id` +
        // `ticket_id` for the filename. The body has already been
        // canonical-encoded by `EvidenceBundle::canonical` before
        // signing, so this round-trip is cheap and never fails on a
        // well-formed bundle. A malformed bundle is an in-process
        // bug, not a tenant-supplied input.
        let body = hippius_types::evidence_bundle::EvidenceBundle::decode(&bundle.body)
            .map_err(|e| KbsError::Vault(format!("evidence decode for path: {e}")))?;

        // Per-`vm_id` subdir — create_dir_all under the mkdirs mutex
        // so concurrent releases for the SAME vm don't all
        // stat-and-mkdir in parallel (no semantic race, just IO
        // amplification).
        let vm_dir = self.dir.join(&body.vm_id);
        {
            let _g = self
                .mkdirs
                .lock()
                .map_err(|_| KbsError::Vault("evidence mkdir mutex poisoned".into()))?;
            fs::create_dir_all(&vm_dir)
                .map_err(|e| KbsError::Vault(format!("evidence vm subdir: {e}")))?;
        }

        // Atomic write: tmp + fsync + rename + parent fsync. Same
        // discipline as `audit::write_head_atomic` (audit.rs:368-385).
        let final_path = vm_dir.join(format!("{}.cbor", body.ticket_id));
        let tmp_path = vm_dir.join(format!("{}.cbor.tmp", body.ticket_id));

        // Canonical envelope bytes — the `{body, sig}` map.
        let envelope = bundle
            .encode()
            .map_err(|e| KbsError::Vault(format!("evidence envelope encode: {e}")))?;

        {
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp_path)
                .map_err(|e| KbsError::Vault(format!("evidence tmp open: {e}")))?;
            f.write_all(&envelope)
                .map_err(|e| KbsError::Vault(format!("evidence write: {e}")))?;
            f.sync_all()
                .map_err(|e| KbsError::Vault(format!("evidence fsync: {e}")))?;
        }
        fs::rename(&tmp_path, &final_path)
            .map_err(|e| KbsError::Vault(format!("evidence rename: {e}")))?;
        let dirf =
            File::open(&vm_dir).map_err(|e| KbsError::Vault(format!("evidence dir open: {e}")))?;
        dirf.sync_all()
            .map_err(|e| KbsError::Vault(format!("evidence dir fsync: {e}")))?;
        Ok(())
    }
}

impl EvidenceSink for FileEvidenceSink {
    fn latest_for_vm(&self, vm_id: &str) -> Result<Option<SignedEvidenceBundle>> {
        self.read_latest(vm_id)
    }

    fn record(&self, bundle: &SignedEvidenceBundle) {
        if let Err(e) = self.try_record(bundle) {
            // Match `audit.rs:511` stderr convention so a future PR
            // (PR-K14b) can scrape both via the same log-handler. NO
            // bundle content is interpolated — only the structural
            // error class, which is bug-classifier text, never tenant
            // bytes.
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "kbs-core::evidence: failed to record bundle: {e}");
        }
    }
}

/// No-op sink — used when the operator has explicitly disabled
/// evidence persistence (KBS config `evidence.enabled = false`).
/// Releases still succeed; the audit log still commits the decision.
#[derive(Default)]
pub struct NullEvidenceSink;

impl EvidenceSink for NullEvidenceSink {
    fn record(&self, _bundle: &SignedEvidenceBundle) {
        // Deliberately empty — the audit log is the durable record
        // when evidence is disabled.
    }
}

/// In-memory capture sink — for unit + integration tests that want to
/// assert "exactly one bundle was recorded" without touching the
/// filesystem.
#[derive(Default)]
pub struct MockEvidenceSink {
    records: Mutex<Vec<SignedEvidenceBundle>>,
}

impl MockEvidenceSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of bundles recorded so far.
    pub fn len(&self) -> usize {
        self.records.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` iff no bundles have been recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot the recorded bundles. Returns clones — the sink keeps
    /// its own copies.
    pub fn snapshot(&self) -> Vec<SignedEvidenceBundle> {
        self.records.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl EvidenceSink for MockEvidenceSink {
    fn record(&self, bundle: &SignedEvidenceBundle) {
        if let Ok(mut g) = self.records.lock() {
            g.push(bundle.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hippius_types::evidence_bundle::{
        EvidenceBundle, EVIDENCE_BUNDLE_SCHEMA_VERSION, MEASUREMENT_LEN, MIN_SNP_REPORT_LEN,
        PUBKEY_LEN, SHA256_LEN,
    };

    fn sample_signed(vm_id: &str, ticket_id: &str, sk: &SigningKey) -> SignedEvidenceBundle {
        let signer_pubkey = sk.verifying_key().to_bytes();
        let bundle = EvidenceBundle {
            schema_version: EVIDENCE_BUNDLE_SCHEMA_VERSION,
            vm_id: vm_id.into(),
            tenant_id: "tenant-x".into(),
            ticket_id: ticket_id.into(),
            granted_at_unix: 1_780_000_000,
            measurement: [0x33; MEASUREMENT_LEN],
            allowlist_epoch: 1,
            allowlist_manifest_digest: [0x44; SHA256_LEN],
            snp_report_bytes: vec![0x55; MIN_SNP_REPORT_LEN],
            vcek_chain_pem: b"-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n".to_vec(),
            ticket_cose_bytes: b"cose-bytes".to_vec(),
            kbs_signer_pubkey: signer_pubkey,
        };
        // Note: not all 32 bytes of vk fit `[u8; PUBKEY_LEN]` — the
        // assertion is just `PUBKEY_LEN == 32`, which it is.
        assert_eq!(PUBKEY_LEN, 32);
        let body = bundle.canonical().unwrap();
        let sig = sk.sign(&body).to_bytes().to_vec();
        SignedEvidenceBundle { body, sig }
    }

    #[test]
    fn null_sink_records_nothing_and_does_not_panic() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let signed = sample_signed("vm-1", "tkt-1", &sk);
        let sink = NullEvidenceSink;
        sink.record(&signed);
    }

    #[test]
    fn mock_sink_captures_records_in_order() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let sink = MockEvidenceSink::new();
        assert!(sink.is_empty());
        sink.record(&sample_signed("vm-1", "tkt-1", &sk));
        sink.record(&sample_signed("vm-2", "tkt-2", &sk));
        assert_eq!(sink.len(), 2);
        let snap = sink.snapshot();
        // Round-trip the first record's body → EvidenceBundle and
        // check the vm_id, proving the captured bytes are real.
        let decoded = EvidenceBundle::decode(&snap[0].body).unwrap();
        assert_eq!(decoded.vm_id, "vm-1");
        assert_eq!(decoded.ticket_id, "tkt-1");
        let decoded = EvidenceBundle::decode(&snap[1].body).unwrap();
        assert_eq!(decoded.vm_id, "vm-2");
    }

    #[test]
    fn file_sink_writes_one_file_per_release_and_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let sink = FileEvidenceSink::open(tmp.path()).unwrap();
        let sk = SigningKey::from_bytes(&[1u8; 32]);

        sink.record(&sample_signed("vm-a", "ticket-001", &sk));
        sink.record(&sample_signed("vm-a", "ticket-002", &sk));
        sink.record(&sample_signed("vm-b", "ticket-003", &sk));

        let path_a1 = tmp.path().join("vm-a").join("ticket-001.cbor");
        let path_a2 = tmp.path().join("vm-a").join("ticket-002.cbor");
        let path_b3 = tmp.path().join("vm-b").join("ticket-003.cbor");
        assert!(path_a1.exists(), "missing {path_a1:?}");
        assert!(path_a2.exists(), "missing {path_a2:?}");
        assert!(path_b3.exists(), "missing {path_b3:?}");

        // Round-trip one bundle off disk → SignedEvidenceBundle →
        // EvidenceBundle, then verify the signature against the KBS
        // signing key. Proves the full archive → verifier path.
        let bytes = fs::read(&path_a1).unwrap();
        let signed = SignedEvidenceBundle::decode(&bytes).unwrap();
        let decoded = EvidenceBundle::decode(&signed.body).unwrap();
        assert_eq!(decoded.vm_id, "vm-a");
        assert_eq!(decoded.ticket_id, "ticket-001");
        assert_eq!(decoded.kbs_signer_pubkey, sk.verifying_key().to_bytes());

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&decoded.kbs_signer_pubkey).unwrap();
        let sig = Signature::from_slice(&signed.sig).unwrap();
        vk.verify(&signed.body, &sig).expect("KBS sig must verify");
    }

    #[test]
    fn latest_for_vm_returns_the_newest_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let sink = FileEvidenceSink::open(tmp.path()).unwrap();
        let sk = SigningKey::from_bytes(&[1u8; 32]);

        // Unknown VM → None (the attestation endpoint's 404).
        assert!(sink.latest_for_vm("vm-x").unwrap().is_none());

        sink.record(&sample_signed("vm-x", "ticket-001", &sk));
        // mtime resolution: sleep so the second write is strictly newer.
        std::thread::sleep(std::time::Duration::from_millis(10));
        sink.record(&sample_signed("vm-x", "ticket-002", &sk));

        let latest = sink.latest_for_vm("vm-x").unwrap().expect("a bundle");
        let body = EvidenceBundle::decode(&latest.body).unwrap();
        assert_eq!(body.ticket_id, "ticket-002", "newest release wins");

        // Path-traversal is refused before the join.
        assert!(sink.latest_for_vm("../etc").is_err());
        assert!(sink.latest_for_vm("").is_err());
    }

    #[test]
    fn file_sink_overwrites_a_duplicate_ticket_id_atomically() {
        // Per `crate::replay::ReleaseStore`, the same ticket_id can
        // never be granted twice. But defense-in-depth: if a buggy
        // caller passes the same ticket_id twice, the file sink does
        // not corrupt the existing file — it atomically replaces.
        let tmp = tempfile::tempdir().unwrap();
        let sink = FileEvidenceSink::open(tmp.path()).unwrap();
        let sk = SigningKey::from_bytes(&[1u8; 32]);

        sink.record(&sample_signed("vm-x", "tkt-1", &sk));
        // Build a bundle with a different sig (different sk) at the
        // same path — the rename must atomically replace.
        let sk2 = SigningKey::from_bytes(&[2u8; 32]);
        sink.record(&sample_signed("vm-x", "tkt-1", &sk2));

        let bytes = fs::read(tmp.path().join("vm-x").join("tkt-1.cbor")).unwrap();
        let signed = SignedEvidenceBundle::decode(&bytes).unwrap();
        let decoded = EvidenceBundle::decode(&signed.body).unwrap();
        // The most-recent write wins — its signer_pubkey is sk2's.
        assert_eq!(decoded.kbs_signer_pubkey, sk2.verifying_key().to_bytes());
    }
}
