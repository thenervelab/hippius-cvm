//! Durable persistence (ARCHITECTURE.md §7/§14/§24).
//!
//! The §7 anti-replay store, the unified §24 per-`vm_id` VM lifecycle
//! state, and the KBS-issued nonce single-use store all need to be
//! **durable** — a crash AFTER `commit` MUST leave the ticket/nonce/state
//! spent (else a replay window opens, §14). The kbs-core scaffold's
//! in-memory impls cover trait behaviour and unit tests; production
//! wires the file-backed implementations here (and ultimately the
//! Tier-0 storage backend — §22 high-water principle: anything safety-
//! critical lives in tamper-safe Tier-0, never on the vali FS).
//!
//! Atomicity contract: every write goes through [`atomic_write`] — a
//! `temp file in the same dir → fsync → rename` sequence. POSIX
//! guarantees that `rename` is atomic on the same filesystem (the
//! kernel publishes the new inode at the destination path in one step;
//! a crash either leaves the previous inode visible or the new one,
//! never a partial). The `fsync` before the rename forces the temp
//! file's data to durable storage so the post-rename name resolves to
//! actually-durable bytes.

use crate::error::{KbsError, Result};
use crate::lifecycle::{VmState, VmStateStore};
use crate::replay::{ReleaseKey, ReleaseStore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Guard that removes a path on drop unless `disarm()`-ed. Used to keep
/// half-written temp files from leaking on early returns.
struct TempPathGuard {
    path: Option<PathBuf>,
}
impl TempPathGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }
    fn disarm(mut self) {
        self.path = None;
    }
}
impl Drop for TempPathGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = fs::remove_file(p);
        }
    }
}

fn fresh_temp_name(target: &Path) -> String {
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("write");
    let pid = std::process::id();
    let mut rand_bytes = [0u8; 8];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
    format!("{name}.tmp.{pid}.{}", hex::encode(rand_bytes))
}

/// Ensure the directory entry of `path`'s parent is durable on disk.
/// `fsync` of a directory is required after rename/link to guarantee
/// the new entry survives a crash.
fn fsync_dir(parent: &Path) -> Result<()> {
    let dir =
        File::open(parent).map_err(|e| KbsError::Vault(format!("open dir for fsync: {e}")))?;
    dir.sync_all()
        .map_err(|e| KbsError::Vault(format!("dir fsync: {e}")))
}

/// Atomic *overwrite* of `path` (temp in the same dir → fsync → rename
/// → dir fsync). Use this for "replace this snapshot" semantics; it is
/// NOT safe for fail-on-exists markers (see [`atomic_create_new`]).
/// The temp file is removed via a drop guard if any step before rename
/// fails. Same-filesystem `rename` is atomic on POSIX.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| KbsError::Vault("path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|e| KbsError::Vault(format!("create_dir_all: {e}")))?;
    let tmp = parent.join(fresh_temp_name(path));
    let guard = TempPathGuard::new(tmp.clone());
    {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .map_err(|e| KbsError::Vault(format!("open temp: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| KbsError::Vault(format!("write temp: {e}")))?;
        f.sync_all()
            .map_err(|e| KbsError::Vault(format!("fsync temp: {e}")))?;
    }
    fs::rename(&tmp, path).map_err(|e| KbsError::Vault(format!("rename: {e}")))?;
    guard.disarm();
    fsync_dir(parent)?;
    Ok(())
}

/// Atomic *exclusive create* of `path` (`O_CREAT|O_EXCL`) followed by
/// data fsync and dir fsync. Returns `KbsError::Replay` if `path`
/// already exists — this is the cross-process race-safe primitive for
/// publishing a one-shot "spent" marker (cf. §7 release-once and
/// nonce single-use): two racing callers cannot both succeed because
/// only one `create_new(true)` wins. The other gets `AlreadyExists`,
/// which we map to `Replay`.
fn atomic_create_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| KbsError::Vault("path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|e| KbsError::Vault(format!("create_dir_all: {e}")))?;
    let mut f = match OpenOptions::new().create_new(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(KbsError::Replay),
        Err(e) => return Err(KbsError::Vault(format!("open exclusive: {e}"))),
    };
    f.write_all(bytes)
        .map_err(|e| KbsError::Vault(format!("write exclusive: {e}")))?;
    f.sync_all()
        .map_err(|e| KbsError::Vault(format!("fsync exclusive: {e}")))?;
    drop(f);
    fsync_dir(parent)?;
    Ok(())
}

// =================== Release store (durable §7) ====================

/// On-disk slot for `(ticket_id, KBS_nonce)`: file present + content
/// `"S"` = Spent. The Reserved phase is in-memory only (a crash before
/// commit MUST leave nothing on disk, so the ticket+nonce can be
/// retried via a fresh request — §14 minting recovery).
fn release_key_filename(key: &ReleaseKey) -> String {
    let mut h = Sha256::new();
    h.update((key.ticket_id.len() as u64).to_le_bytes());
    h.update(key.ticket_id.as_bytes());
    h.update((key.nonce.len() as u64).to_le_bytes());
    h.update(&key.nonce);
    format!("{}.spent", hex::encode(h.finalize()))
}

/// File-backed durable release-once store. Reservations are in-memory;
/// commits are durable (atomic file create). Once a `.spent` file
/// exists on disk for `(ticket_id, KBS_nonce)`, no further release
/// ever succeeds — crash-after-commit stays spent (§7/§14).
pub struct FileReleaseStore {
    dir: PathBuf,
    reserved: Mutex<std::collections::HashSet<ReleaseKey>>,
}

impl FileReleaseStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)
            .map_err(|e| KbsError::Vault(format!("create_dir_all {}: {e}", dir.display())))?;
        Ok(Self {
            dir,
            reserved: Mutex::new(Default::default()),
        })
    }
    fn spent_path(&self, key: &ReleaseKey) -> PathBuf {
        self.dir.join(release_key_filename(key))
    }
    fn is_spent_on_disk(&self, key: &ReleaseKey) -> bool {
        self.spent_path(key).exists()
    }
}

impl ReleaseStore for FileReleaseStore {
    fn reserve(&self, key: &ReleaseKey) -> Result<()> {
        let mut g = self.reserved.lock().map_err(|_| KbsError::Replay)?;
        if self.is_spent_on_disk(key) {
            return Err(KbsError::Replay);
        }
        if !g.insert(key.clone()) {
            return Err(KbsError::Replay);
        }
        Ok(())
    }

    fn commit(&self, key: &ReleaseKey) -> Result<()> {
        // Must have been reserved in this process.
        {
            let g = self.reserved.lock().map_err(|_| KbsError::Replay)?;
            if !g.contains(key) {
                return Err(KbsError::Replay);
            }
        }
        // Atomic exclusive create publishes the spent marker — fails on
        // existing path with `Replay` (race-safe across processes; an
        // overwriting `rename` would let two committers both win).
        atomic_create_new(&self.spent_path(key), b"S")?;
        if let Ok(mut g) = self.reserved.lock() {
            g.remove(key);
        }
        Ok(())
    }

    fn rollback(&self, key: &ReleaseKey) {
        if let Ok(mut g) = self.reserved.lock() {
            g.remove(key);
        }
    }
}

// =================== VM lifecycle store (durable §24) ====================

/// File-backed durable map of `vm_id → VmState`. Single-file JSON
/// snapshot; every write replaces the file atomically (small dataset
/// expected per KBS instance). The KBS reads (`get`); production
/// writers (vali orchestration) use [`put`] / [`cas`] for state
/// transitions (§24/§25). The trait `VmStateStore` exposes only `get`.
pub struct FileVmStateStore {
    path: PathBuf,
    cache: Mutex<HashMap<String, VmState>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum VmStateWire {
    Active {
        gen: u64,
        host: String,
        lease_id: String,
    },
    Migrating {
        old_gen: u64,
        new_gen: u64,
        source: String,
        dest: String,
        lease_id: String,
    },
    Decommissioning,
    Destroyed {
        gen: u64,
    },
}

impl From<VmState> for VmStateWire {
    fn from(s: VmState) -> Self {
        match s {
            VmState::Active {
                gen,
                host,
                lease_id,
            } => VmStateWire::Active {
                gen,
                host,
                lease_id,
            },
            VmState::Migrating {
                old_gen,
                new_gen,
                source,
                dest,
                lease_id,
            } => VmStateWire::Migrating {
                old_gen,
                new_gen,
                source,
                dest,
                lease_id,
            },
            VmState::Decommissioning => VmStateWire::Decommissioning,
            VmState::Destroyed { gen } => VmStateWire::Destroyed { gen },
        }
    }
}
impl From<VmStateWire> for VmState {
    fn from(s: VmStateWire) -> Self {
        match s {
            VmStateWire::Active {
                gen,
                host,
                lease_id,
            } => VmState::Active {
                gen,
                host,
                lease_id,
            },
            VmStateWire::Migrating {
                old_gen,
                new_gen,
                source,
                dest,
                lease_id,
            } => VmState::Migrating {
                old_gen,
                new_gen,
                source,
                dest,
                lease_id,
            },
            VmStateWire::Decommissioning => VmState::Decommissioning,
            VmStateWire::Destroyed { gen } => VmState::Destroyed { gen },
        }
    }
}

impl FileVmStateStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let cache = match fs::read(&path) {
            Ok(bytes) => {
                let wire: HashMap<String, VmStateWire> = serde_json::from_slice(&bytes)
                    .map_err(|e| KbsError::Vault(format!("vm-states decode: {e}")))?;
                wire.into_iter().map(|(k, v)| (k, v.into())).collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(KbsError::Vault(format!("vm-states read: {e}"))),
        };
        Ok(Self {
            path,
            cache: Mutex::new(cache),
        })
    }

    fn persist(&self, map: &HashMap<String, VmState>) -> Result<()> {
        let wire: HashMap<String, VmStateWire> = map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone().into()))
            .collect();
        let bytes = serde_json::to_vec(&wire)
            .map_err(|e| KbsError::Vault(format!("vm-states encode: {e}")))?;
        atomic_write(&self.path, &bytes)
    }

    /// Writer-side: set `vm_id`'s state unconditionally. Use only when
    /// the caller knows no concurrent transition matters (e.g., initial
    /// `Active`); state machine transitions should use [`cas`].
    pub fn put(&self, vm_id: &str, state: VmState) -> Result<()> {
        let mut g = self
            .cache
            .lock()
            .map_err(|_| KbsError::Lifecycle("vm-states lock poisoned".into()))?;
        // Stage-then-swap: persist the candidate FIRST. If persist fails,
        // the in-memory cache is left untouched so `get` cannot observe an
        // uncommitted state — `process_release` must never accept a
        // lifecycle transition that wasn't durably written.
        let mut staged = g.clone();
        staged.insert(vm_id.to_string(), state);
        self.persist(&staged)?;
        *g = staged;
        Ok(())
    }

    /// Atomic compare-and-set on `vm_id`'s state (the only safe primitive
    /// for §24/§25 transitions). `expected_now` is a predicate evaluated
    /// against the current state under the lock; on `true` the state is
    /// staged + durably persisted; only on persist `Ok` is the cache
    /// updated. **The predicate MUST NOT re-enter the store** (it would
    /// deadlock on the lock held here).
    pub fn cas(
        &self,
        vm_id: &str,
        expected_now: impl FnOnce(Option<&VmState>) -> bool,
        new_state: VmState,
    ) -> Result<()> {
        let mut g = self
            .cache
            .lock()
            .map_err(|_| KbsError::Lifecycle("vm-states lock poisoned".into()))?;
        if !expected_now(g.get(vm_id)) {
            return Err(KbsError::Lifecycle("CAS precondition failed".into()));
        }
        let mut staged = g.clone();
        staged.insert(vm_id.to_string(), new_state);
        self.persist(&staged)?;
        *g = staged;
        Ok(())
    }
}

impl VmStateStore for FileVmStateStore {
    fn get(&self, vm_id: &str) -> Result<VmState> {
        let g = self
            .cache
            .lock()
            .map_err(|_| KbsError::Lifecycle("vm-states lock poisoned".into()))?;
        g.get(vm_id)
            .cloned()
            .ok_or_else(|| KbsError::Lifecycle(format!("no state for vm_id={vm_id}")))
    }
}

// =================== KBS-nonce store (durable §7) ====================

/// Tracks the lifecycle of KBS-issued nonces (the freshness primitive
/// folded into `REPORT_DATA[0..32]`, §7/§20). A nonce is single-use AND
/// time-bounded: `issue` durably records `{nonce, issued_at}` so
/// `verify_unspent` can refuse any nonce we never minted or one whose
/// TTL has elapsed. `spend` is the atomic single-use commit.
pub trait KbsNonceStore {
    fn issue(&self, now_unix: u64) -> Result<[u8; 32]>;
    fn verify_unspent(&self, nonce: &[u8; 32], now_unix: u64) -> Result<()>;
    fn spend(&self, nonce: &[u8; 32], now_unix: u64) -> Result<()>;
    /// Best-effort reap of expired `.issued` (and matching `.spent`)
    /// markers. The default is a no-op so in-memory test stores stay
    /// trivial; file-backed implementations override it (§13 DoS
    /// resilience — unbounded `.issued` accumulation is the dominant
    /// failure mode for an untrusted-Edge KBS). Returns the count of
    /// `.issued` markers reaped. Safe to call concurrently with
    /// `issue`/`verify_unspent`/`spend` because GC removes `.issued`
    /// FIRST so a racing verifier sees "unknown nonce" → Replay.
    fn gc_expired(&self, _now_unix: u64) -> Result<usize> {
        Ok(0)
    }
}

/// File-backed nonce store. Per-nonce on-disk files:
/// `<hex>.issued` (with the issuance unix-seconds, 8 bytes LE) and
/// `<hex>.spent` (empty marker). Both are published via
/// [`atomic_create_new`] (`O_CREAT|O_EXCL`) so concurrent callers cannot
/// both succeed.
pub struct FileKbsNonceStore {
    dir: PathBuf,
    ttl_secs: u64,
}

impl FileKbsNonceStore {
    /// `ttl_secs` is the maximum age (issued_at + ttl ≥ now) accepted
    /// by `verify_unspent` and `spend` — §7 "short expiry".
    pub fn open(dir: impl Into<PathBuf>, ttl_secs: u64) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|e| KbsError::Vault(format!("create_dir_all: {e}")))?;
        Ok(Self { dir, ttl_secs })
    }
    fn issued_path(&self, nonce: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.issued", hex::encode(nonce)))
    }
    fn spent_path(&self, nonce: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.spent", hex::encode(nonce)))
    }

    fn issued_at(&self, nonce: &[u8; 32]) -> Result<Option<u64>> {
        match fs::read(self.issued_path(nonce)) {
            Ok(bytes) => {
                if bytes.len() != 8 {
                    return Err(KbsError::Vault("issued marker corrupt".into()));
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes);
                Ok(Some(u64::from_le_bytes(buf)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(KbsError::Vault(format!("read issued: {e}"))),
        }
    }

    fn expired(&self, issued_at: u64, now_unix: u64) -> bool {
        now_unix.saturating_sub(issued_at) > self.ttl_secs
    }

    /// Reap on-disk markers whose `.issued` timestamp is older than the
    /// TTL. Returns the number of `.issued` files removed.
    ///
    /// **Order matters.** `.issued` is the GATING record `verify_unspent`
    /// consults; `.spent` is only checked when `.issued` is still present
    /// AND not expired by the *caller's* `now_unix`. A concurrent
    /// verifier could carry an older `now_unix` than the GC (clock
    /// skew across processes, or the verifier captured `now` before the
    /// GC reached this entry); if we removed `.spent` first, that
    /// verifier would observe "issued, unexpired by my clock, no
    /// .spent" and accept a previously-spent nonce. So:
    ///
    /// 1. Remove `.issued` first and `fsync` the directory. Now any
    ///    verifier — regardless of clock — sees "unknown nonce" and
    ///    returns Replay (fail-closed).
    /// 2. Remove `.spent`. The leftover orphan after step 1 is benign
    ///    (no `.issued` ⇒ no `verify_unspent` Ok path).
    /// 3. `fsync` the directory once more so neither deletion can be
    ///    resurrected by a crash.
    pub fn gc_expired(&self, now_unix: u64) -> Result<usize> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(KbsError::Vault(format!("read_dir: {e}"))),
        };
        let mut targets: Vec<(PathBuf, PathBuf)> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| KbsError::Vault(format!("dirent: {e}")))?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(hex_part) = name.strip_suffix(".issued") else {
                continue;
            };
            // Read the timestamp; on any read error, leave the marker
            // alone — manual operator action is safer than silent GC of
            // unreadable state.
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if bytes.len() != 8 {
                continue;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes);
            let issued_at = u64::from_le_bytes(buf);
            if !self.expired(issued_at, now_unix) {
                continue;
            }
            let spent = self.dir.join(format!("{hex_part}.spent"));
            targets.push((path, spent));
        }
        if targets.is_empty() {
            return Ok(0);
        }
        // Pass 1: remove every `.issued` and durably fsync the directory
        // so no verifier (any clock) can observe a stale "issued + no
        // .spent" pair.
        let mut removed = 0usize;
        for (issued, _) in &targets {
            match fs::remove_file(issued) {
                Ok(()) => removed += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => continue,
            }
        }
        fsync_dir(&self.dir)?;
        // Pass 2: reap the now-orphan .spent markers. Failures here are
        // benign: the gating .issued is already gone.
        for (_, spent) in &targets {
            let _ = fs::remove_file(spent);
        }
        let _ = fsync_dir(&self.dir);
        Ok(removed)
    }
}

impl KbsNonceStore for FileKbsNonceStore {
    fn issue(&self, now_unix: u64) -> Result<[u8; 32]> {
        // OsRng collisions on 32 bytes are vanishingly unlikely; if one
        // does happen, `atomic_create_new` returns `Replay` and we
        // retry with fresh randomness up to a bounded number of times.
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        for _ in 0..4 {
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            match atomic_create_new(&self.issued_path(&nonce), &now_unix.to_le_bytes()) {
                Ok(()) => return Ok(nonce),
                Err(KbsError::Replay) => continue, // freak collision; retry
                Err(e) => return Err(e),
            }
        }
        Err(KbsError::Vault(
            "nonce issuance: persistent collisions".into(),
        ))
    }

    fn verify_unspent(&self, nonce: &[u8; 32], now_unix: u64) -> Result<()> {
        let issued_at = self.issued_at(nonce)?.ok_or(KbsError::Replay)?; // unknown nonce = treat as replay
        if self.expired(issued_at, now_unix) {
            return Err(KbsError::Replay);
        }
        if self.spent_path(nonce).exists() {
            return Err(KbsError::Replay);
        }
        Ok(())
    }

    fn spend(&self, nonce: &[u8; 32], now_unix: u64) -> Result<()> {
        // Re-verify under the same TTL/issued contract before committing
        // the spend marker.
        self.verify_unspent(nonce, now_unix)?;
        // Atomic exclusive create — `AlreadyExists` ⇒ `Replay` (a racing
        // caller already won).
        atomic_create_new(&self.spent_path(nonce), b"S")
    }

    /// Inherent [`Self::gc_expired`] is the implementation; the trait
    /// method delegates so production callers can use either path.
    fn gc_expired(&self, now_unix: u64) -> Result<usize> {
        FileKbsNonceStore::gc_expired(self, now_unix)
    }
}

// =================== Idempotency-key store (§14) ====================

/// Generic idempotency-key dedup store. The §14 retry primitive any L1
/// ↔ vali / vali ↔ KBS exchange should use: a client that doesn't get
/// an ACK retries the same logical operation with the same
/// `IdempotencyKey`; the server returns the IDENTICAL response the
/// first attempt produced, without re-running side effects.
///
/// Stored payload is a SHA-256 of the original canonical response
/// bytes — not the bytes themselves. The server retains the response
/// bytes in its own storage layer (Postgres for vali, the durable
/// stores already in this module for KBS); the dedup store just says
/// "yes I've seen this key, the response I emitted was THIS hash".
///
/// Why a hash and not the bytes? Two reasons:
/// 1. The response can be large (signed denials carry full reason
///    strings); the dedup store stays cheap O(1)-per-entry on disk.
/// 2. Two clients that supplied the same key MUST have produced the
///    same canonical request — if their re-derived response bytes
///    don't hash to the stored value, that's a bug or a tamper and we
///    fail closed.
pub trait IdempotencyStore {
    /// First-time path: record `(key, response_hash, now_unix)`.
    /// Returns `KbsError::Replay` if the key already exists (caller
    /// must use `recall` to retrieve the stored hash).
    fn record(&self, key: &IdempotencyKey, response_hash: &[u8; 32], now_unix: u64) -> Result<()>;

    /// Retry path: returns the previously-recorded hash if the key
    /// exists and isn't expired. None = key unknown (caller proceeds
    /// with first-time processing). The caller asserts the response it
    /// re-derives hashes to the returned value.
    fn recall(&self, key: &IdempotencyKey, now_unix: u64) -> Result<Option<[u8; 32]>>;
}

/// Idempotency key. The producer supplies an arbitrary bytestring
/// scoped to its own request semantics. We don't constrain length —
/// just hash it to a uniform on-disk filename. 32 bytes recommended
/// for collision-resistance (UUIDv7 + a domain tag works).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(pub Vec<u8>);

/// File-backed dedup store with per-key TTL. Each entry lives at
/// `{dir}/<hex(sha256(key))>.idem` and contains
/// `<8-byte-LE timestamp> || <32-byte response hash>` (40 bytes total).
/// Cross-process race-safe via `atomic_create_new` (`O_CREAT|O_EXCL`).
pub struct FileIdempotencyStore {
    dir: PathBuf,
    ttl_secs: u64,
}

impl FileIdempotencyStore {
    /// `ttl_secs` bounds how long a recorded entry is recallable. After
    /// expiry, `recall` returns `None` and a `record` for the same
    /// key succeeds anew. Tune to the longest plausible end-to-end
    /// retry window of the producer.
    pub fn open(dir: impl Into<PathBuf>, ttl_secs: u64) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)
            .map_err(|e| KbsError::Vault(format!("idem create_dir_all: {e}")))?;
        Ok(Self { dir, ttl_secs })
    }

    fn entry_path(&self, key: &IdempotencyKey) -> PathBuf {
        let h = Sha256::digest(&key.0);
        self.dir.join(format!("{}.idem", hex::encode(h)))
    }

    fn read_entry(&self, key: &IdempotencyKey) -> Result<Option<(u64, [u8; 32])>> {
        match fs::read(self.entry_path(key)) {
            Ok(bytes) if bytes.len() == 40 => {
                let mut ts = [0u8; 8];
                ts.copy_from_slice(&bytes[..8]);
                let mut h = [0u8; 32];
                h.copy_from_slice(&bytes[8..]);
                Ok(Some((u64::from_le_bytes(ts), h)))
            }
            Ok(_) => Err(KbsError::Vault("idem entry corrupt".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(KbsError::Vault(format!("idem read: {e}"))),
        }
    }

    fn expired(&self, recorded_at: u64, now_unix: u64) -> bool {
        now_unix.saturating_sub(recorded_at) > self.ttl_secs
    }

    /// GC scan: remove every entry past TTL. Same opportunistic pattern
    /// as [`FileKbsNonceStore::gc_expired`]. Returns count removed.
    pub fn gc_expired(&self, now_unix: u64) -> Result<usize> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(KbsError::Vault(format!("idem read_dir: {e}"))),
        };
        let mut removed = 0usize;
        for entry in entries {
            let entry = entry.map_err(|e| KbsError::Vault(format!("idem dirent: {e}")))?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.ends_with(".idem") {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            if bytes.len() != 40 {
                continue;
            }
            let mut ts = [0u8; 8];
            ts.copy_from_slice(&bytes[..8]);
            let recorded_at = u64::from_le_bytes(ts);
            if !self.expired(recorded_at, now_unix) {
                continue;
            }
            if fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        if removed > 0 {
            fsync_dir(&self.dir)?;
        }
        Ok(removed)
    }
}

impl IdempotencyStore for FileIdempotencyStore {
    fn record(&self, key: &IdempotencyKey, response_hash: &[u8; 32], now_unix: u64) -> Result<()> {
        // Body = 8-byte timestamp || 32-byte hash. atomic_create_new
        // is the O_CREAT|O_EXCL primitive that ensures cross-process
        // safety: two writers cannot both succeed.
        let mut body = Vec::with_capacity(40);
        body.extend_from_slice(&now_unix.to_le_bytes());
        body.extend_from_slice(response_hash);
        atomic_create_new(&self.entry_path(key), &body)
    }

    fn recall(&self, key: &IdempotencyKey, now_unix: u64) -> Result<Option<[u8; 32]>> {
        match self.read_entry(key)? {
            Some((recorded_at, hash)) if !self.expired(recorded_at, now_unix) => Ok(Some(hash)),
            Some(_) => Ok(None), // expired — recallable as if absent
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn k(ticket: &str, nonce: u8) -> ReleaseKey {
        ReleaseKey {
            ticket_id: ticket.into(),
            nonce: vec![nonce; 32],
        }
    }

    #[test]
    fn file_release_store_commit_is_durable() {
        let td = TempDir::new().unwrap();
        let key = k("tk-1", 1);
        {
            let s = FileReleaseStore::open(td.path()).unwrap();
            s.reserve(&key).unwrap();
            s.commit(&key).unwrap();
        }
        // Reopen — durably spent.
        let s2 = FileReleaseStore::open(td.path()).unwrap();
        assert!(s2.reserve(&key).is_err()); // already spent
    }

    #[test]
    fn file_release_store_rollback_does_not_persist() {
        let td = TempDir::new().unwrap();
        let key = k("tk-2", 2);
        let s = FileReleaseStore::open(td.path()).unwrap();
        s.reserve(&key).unwrap();
        s.rollback(&key);
        // After rollback the key is free.
        s.reserve(&key).unwrap();
        // No on-disk persistence yet.
        let s2 = FileReleaseStore::open(td.path()).unwrap();
        assert!(s2.reserve(&key).is_ok());
    }

    #[test]
    fn file_release_store_commit_without_reserve_denied() {
        let td = TempDir::new().unwrap();
        let s = FileReleaseStore::open(td.path()).unwrap();
        assert!(s.commit(&k("tk-3", 3)).is_err());
    }

    #[test]
    fn file_vm_state_store_round_trip_and_reopen() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("vms.json");
        {
            let s = FileVmStateStore::open(&path).unwrap();
            s.put(
                "abc",
                VmState::Active {
                    gen: 5,
                    host: "node-1".into(),
                    lease_id: "lease-1".into(),
                },
            )
            .unwrap();
        }
        let s2 = FileVmStateStore::open(&path).unwrap();
        let v = s2.get("abc").unwrap();
        assert!(
            matches!(v, VmState::Active { gen, ref host, ref lease_id } if gen == 5 && host == "node-1" && lease_id == "lease-1")
        );
    }

    #[test]
    fn file_vm_state_store_cas_enforces_precondition() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("vms.json");
        let s = FileVmStateStore::open(&path).unwrap();
        s.put(
            "abc",
            VmState::Active {
                gen: 5,
                host: "n1".into(),
                lease_id: "l".into(),
            },
        )
        .unwrap();
        // Fails: precondition asserts gen==99 but actual is 5.
        let res = s.cas(
            "abc",
            |cur| matches!(cur, Some(VmState::Active { gen, .. }) if *gen == 99),
            VmState::Decommissioning,
        );
        assert!(res.is_err());
        // Real transition: Active{5} → Migrating
        s.cas(
            "abc",
            |cur| matches!(cur, Some(VmState::Active { gen, .. }) if *gen == 5),
            VmState::Migrating {
                old_gen: 5,
                new_gen: 6,
                source: "n1".into(),
                dest: "n2".into(),
                lease_id: "l".into(),
            },
        )
        .unwrap();
        assert!(
            matches!(s.get("abc").unwrap(), VmState::Migrating { new_gen, .. } if new_gen == 6)
        );
    }

    #[test]
    fn file_kbs_nonce_store_durable_single_use() {
        let td = TempDir::new().unwrap();
        let now = 1_000_000_u64;
        let n1;
        let n2;
        {
            let s = FileKbsNonceStore::open(td.path(), 60).unwrap();
            n1 = s.issue(now).unwrap();
            n2 = s.issue(now).unwrap();
            assert_ne!(n1, n2); // fresh randomness
            s.verify_unspent(&n1, now).unwrap();
            s.spend(&n1, now).unwrap();
            assert!(s.verify_unspent(&n1, now).is_err());
            assert!(s.spend(&n1, now).is_err()); // no double-spend
        }
        // Reopen — spent stays spent.
        let s2 = FileKbsNonceStore::open(td.path(), 60).unwrap();
        assert!(s2.verify_unspent(&n1, now).is_err());
        s2.verify_unspent(&n2, now).unwrap(); // n2 was never spent
    }

    #[test]
    fn file_kbs_nonce_store_rejects_unissued_nonce() {
        let td = TempDir::new().unwrap();
        let s = FileKbsNonceStore::open(td.path(), 60).unwrap();
        // A nonce we never issued must NOT pass verify_unspent (§7
        // "KBS-issued" requirement — caller can't supply arbitrary
        // bytes and have them treated as fresh).
        let attacker = [0xAAu8; 32];
        assert!(s.verify_unspent(&attacker, 100).is_err());
        assert!(s.spend(&attacker, 100).is_err());
    }

    #[test]
    fn file_kbs_nonce_store_gc_expired_removes_only_expired_markers() {
        let td = TempDir::new().unwrap();
        let s = FileKbsNonceStore::open(td.path(), 30).unwrap();
        // Two nonces issued at t=100; one expires by t=200, the other at
        // t=120 we issue fresh so it survives a GC at t=140.
        let stale = s.issue(100).unwrap();
        // Spend the stale one so we exercise both .issued and .spent
        // removal.
        s.spend(&stale, 120).unwrap();
        // Fresh issued at t=120; with TTL=30 it expires at t=150.
        let fresh = s.issue(120).unwrap();
        // GC at t=140 ⇒ stale (issued 100, expired by 131) goes;
        // fresh (issued 120, still valid through 150) stays.
        let removed = s.gc_expired(140).unwrap();
        assert_eq!(removed, 1);
        // Stale marker gone from disk.
        assert!(s.verify_unspent(&stale, 140).is_err());
        assert!(!td
            .path()
            .join(format!("{}.issued", hex::encode(stale)))
            .exists());
        assert!(!td
            .path()
            .join(format!("{}.spent", hex::encode(stale)))
            .exists());
        // Fresh one is still verifiable.
        s.verify_unspent(&fresh, 140).unwrap();
    }

    #[test]
    fn file_kbs_nonce_store_gc_is_idempotent_on_empty_dir() {
        let td = TempDir::new().unwrap();
        let s = FileKbsNonceStore::open(td.path(), 30).unwrap();
        assert_eq!(s.gc_expired(1000).unwrap(), 0);
    }

    #[test]
    fn file_kbs_nonce_store_gc_removes_issued_before_spent() {
        // Regression guard: a concurrent verifier with a stale `now_unix`
        // must NEVER observe an expired nonce as "issued + unspent"
        // because GC removed `.spent` first. We inspect the disk after a
        // GC step: there must be no `.spent` orphan whose `.issued` is
        // still on disk. (We can't easily simulate concurrent partial
        // execution in a deterministic test; the asymmetric directory
        // state below is sufficient.)
        use std::fs;
        let td = TempDir::new().unwrap();
        let s = FileKbsNonceStore::open(td.path(), 30).unwrap();
        let n = s.issue(100).unwrap();
        s.spend(&n, 110).unwrap();
        // Both files exist now.
        let issued = td.path().join(format!("{}.issued", hex::encode(n)));
        let spent = td.path().join(format!("{}.spent", hex::encode(n)));
        assert!(issued.exists());
        assert!(spent.exists());
        // GC at t=200 (issued expired by 130).
        s.gc_expired(200).unwrap();
        // After GC, neither marker should remain. The IMPORTANT property
        // — `.issued` cannot persist past `.spent` removal — is what we
        // really care about; we assert it explicitly even though the
        // surface API verifies both are gone.
        assert!(!issued.exists(), ".issued must be removed by GC");
        assert!(!spent.exists(), ".spent must be removed by GC");
        // Even if a hypothetical orphan `.spent` were present (we
        // simulate that by writing one back), `verify_unspent` STILL
        // returns Err because `.issued` is gone.
        fs::write(&spent, b"S").unwrap();
        assert!(s.verify_unspent(&n, 50).is_err());
    }

    #[test]
    fn file_kbs_nonce_store_trait_gc_delegates_to_inherent() {
        let td = TempDir::new().unwrap();
        let s = FileKbsNonceStore::open(td.path(), 30).unwrap();
        let n = s.issue(100).unwrap();
        // Via &dyn trait, gc_expired must reap the same way.
        let dyn_s: &dyn KbsNonceStore = &s;
        assert_eq!(dyn_s.gc_expired(50).unwrap(), 0); // not yet expired
        assert_eq!(dyn_s.gc_expired(200).unwrap(), 1); // now expired
        assert!(dyn_s.verify_unspent(&n, 200).is_err());
    }

    #[test]
    fn file_kbs_nonce_store_rejects_expired_nonce() {
        let td = TempDir::new().unwrap();
        let s = FileKbsNonceStore::open(td.path(), 30).unwrap();
        let n = s.issue(100).unwrap();
        s.verify_unspent(&n, 120).unwrap(); // within TTL
        assert!(s.verify_unspent(&n, 200).is_err()); // > 100+30
        assert!(s.spend(&n, 200).is_err());
    }

    #[test]
    fn file_release_store_concurrent_commit_only_one_wins() {
        // Two FileReleaseStores over the SAME directory simulate two
        // KBS processes racing. Both reserve (in-memory, independently),
        // but only the first commit succeeds — the second hits the
        // `O_CREAT|O_EXCL` race-safe primitive and gets `Replay`.
        let td = TempDir::new().unwrap();
        let a = FileReleaseStore::open(td.path()).unwrap();
        let b = FileReleaseStore::open(td.path()).unwrap();
        let key = k("tk-cross", 7);
        a.reserve(&key).unwrap();
        b.reserve(&key).unwrap();
        a.commit(&key).unwrap();
        assert!(b.commit(&key).is_err()); // second loses
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("x.txt");
        atomic_write(&p, b"hello").unwrap();
        atomic_write(&p, b"world").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"world");
    }

    #[test]
    fn atomic_create_new_refuses_to_overwrite() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("once.txt");
        atomic_create_new(&p, b"first").unwrap();
        let e = atomic_create_new(&p, b"second").unwrap_err();
        assert!(matches!(e, KbsError::Replay));
        assert_eq!(std::fs::read(&p).unwrap(), b"first");
    }

    // =================== Idempotency-store tests (§14) ====================

    fn idk(s: &str) -> IdempotencyKey {
        IdempotencyKey(s.as_bytes().to_vec())
    }

    #[test]
    fn idempotency_first_record_then_recall_returns_hash() {
        let td = TempDir::new().unwrap();
        let s = FileIdempotencyStore::open(td.path(), 60).unwrap();
        let key = idk("req-abc-001");
        let h = [0xAAu8; 32];
        s.record(&key, &h, 1_000).unwrap();
        let recalled = s.recall(&key, 1_010).unwrap();
        assert_eq!(recalled, Some(h));
    }

    #[test]
    fn idempotency_unknown_key_returns_none() {
        let td = TempDir::new().unwrap();
        let s = FileIdempotencyStore::open(td.path(), 60).unwrap();
        let recalled = s.recall(&idk("never-recorded"), 1_000).unwrap();
        assert_eq!(recalled, None);
    }

    #[test]
    fn idempotency_record_twice_is_replay_error() {
        let td = TempDir::new().unwrap();
        let s = FileIdempotencyStore::open(td.path(), 60).unwrap();
        let key = idk("req-dup");
        s.record(&key, &[1u8; 32], 100).unwrap();
        // Re-recording the same key — caller should have used recall first.
        // Cross-process safety: O_CREAT|O_EXCL rejects the second writer.
        assert!(s.record(&key, &[2u8; 32], 110).is_err());
    }

    #[test]
    fn idempotency_recall_after_ttl_returns_none() {
        let td = TempDir::new().unwrap();
        let s = FileIdempotencyStore::open(td.path(), 30).unwrap();
        let key = idk("req-stale");
        s.record(&key, &[5u8; 32], 100).unwrap();
        // Within TTL — recallable.
        assert!(s.recall(&key, 120).unwrap().is_some());
        // Past TTL — treated as absent so client can record fresh.
        assert!(s.recall(&key, 200).unwrap().is_none());
    }

    #[test]
    fn idempotency_persists_across_reopen() {
        let td = TempDir::new().unwrap();
        let key = idk("req-durable");
        let h = [0x42u8; 32];
        {
            let s = FileIdempotencyStore::open(td.path(), 60).unwrap();
            s.record(&key, &h, 1_000).unwrap();
        }
        // Reopen — recall must return the same hash.
        let s2 = FileIdempotencyStore::open(td.path(), 60).unwrap();
        assert_eq!(s2.recall(&key, 1_010).unwrap(), Some(h));
    }

    #[test]
    fn idempotency_gc_removes_only_expired_entries() {
        let td = TempDir::new().unwrap();
        let s = FileIdempotencyStore::open(td.path(), 30).unwrap();
        s.record(&idk("stale-1"), &[1u8; 32], 100).unwrap();
        s.record(&idk("stale-2"), &[2u8; 32], 100).unwrap();
        // GC at t=200 with TTL=30 ⇒ both stale.
        s.record(&idk("fresh"), &[3u8; 32], 180).unwrap();
        let removed = s.gc_expired(200).unwrap();
        assert_eq!(removed, 2);
        // Fresh entry survives.
        assert!(s.recall(&idk("fresh"), 200).unwrap().is_some());
        // Stale entries are gone — a fresh record on the same key succeeds.
        s.record(&idk("stale-1"), &[9u8; 32], 200).unwrap();
    }

    #[test]
    fn idempotency_trait_recall_via_dyn() {
        // Exercise the &dyn IdempotencyStore call path so consumers
        // (vali Django bindings, future kbs-server retry layer) can
        // store this behind an Arc<dyn IdempotencyStore + Send + Sync>.
        let td = TempDir::new().unwrap();
        let s = FileIdempotencyStore::open(td.path(), 60).unwrap();
        let key = idk("req-via-dyn");
        let dyn_s: &dyn IdempotencyStore = &s;
        dyn_s.record(&key, &[7u8; 32], 100).unwrap();
        assert_eq!(dyn_s.recall(&key, 110).unwrap(), Some([7u8; 32]));
    }

    #[test]
    fn idempotency_key_hash_collision_resistant() {
        // Different keys with similar prefix MUST hash to different
        // filenames. SHA-256 gives this for free — sanity check.
        let td = TempDir::new().unwrap();
        let s = FileIdempotencyStore::open(td.path(), 60).unwrap();
        s.record(&idk("req-x"), &[1u8; 32], 100).unwrap();
        // A different key with overlapping bytes must NOT collide.
        s.record(&idk("req-x-2"), &[2u8; 32], 100).unwrap();
        assert_eq!(s.recall(&idk("req-x"), 100).unwrap(), Some([1u8; 32]));
        assert_eq!(s.recall(&idk("req-x-2"), 100).unwrap(), Some([2u8; 32]));
    }
}
