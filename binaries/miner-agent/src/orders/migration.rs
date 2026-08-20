//! §25 warm-migration **M1** — source-side quiesce + snapshot-to-S3.
//!
//! This is the **transport + disk-move** layer (Milestone 1). It does
//! the source half of a §25 warm migration:
//!
//! 1. **quiesce** — cleanly stop the source CVM's guest (via the
//!    existing [`CvmLifecycle::stop`] graceful path) so its writable
//!    LUKS2 + dm-integrity volume is crash-consistent and static.
//!    Idempotent: an already-stopped (or untracked) CVM is a no-op
//!    success.
//! 2. **snapshot** — copy that writable volume and stream it, **still
//!    encrypted on disk**, to a short-TTL presigned S3 PUT URL. The
//!    miner never decrypts: the data-disk key lives in the guest's SNP
//!    boundary, so the bytes the miner copies are ciphertext. Streamed
//!    chunk-by-chunk so a multi-GB volume never buffers in RAM.
//! 3. **status** — a `running` / `done` / `failed` poll the Edge relays
//!    back to vali's
//!    [`poll_snapshot`](vali/apps/orchestration/effects.py) (which
//!    expects exactly that JSON `{"status": …}` shape).
//!
//! ## What M1 deliberately does NOT do (deferred — clear TODOs below)
//!
//! - **Dest restore** (download + restore + boot the snapshot on the
//!   destination miner) — **M2**.
//! - **Signed stopped-ack fence** — M1 does a CLEAN STOP for quiesce,
//!   but does NOT produce or verify the guest's `SignedStoppedAck`
//!   (`crate::edge_client::EnvelopeKind::StoppedAck`). The split-brain
//!   fence that gates dest-activation on a cryptographically verified
//!   source-stopped proof is **M2**.
//! - **KBS dest re-activation at `new_gen`** — **M2**.
//! - **Dest artifact staging** — **M3**.
//!
//! Until those land (and a deploy), this source-side move is inert: it
//! uploads an encrypted snapshot that nothing can yet restore. M1
//! proves the source quiesce + snapshot + upload are correct.
//!
//! ## §20 secret discipline
//!
//! No secret byte touches a log line or an error. Every classifier is a
//! compile-time `&'static str`; the presigned URL, the disk path, and
//! the ciphertext are never interpolated.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{MinerAgentError, Result};
use crate::lifecycle::{CvmLifecycle, VmId};

/// The §25 inputs vali binds into the source guest's `stopped{}` ack and
/// hands to the source miner in the `migrate-quiesce` order.
///
/// Every field pins the ack to ONE migration event so vali's
/// `_verify_ack` can re-derive + check the Ed25519 signature against the
/// VM's pinned lifecycle vk:
///
/// - `vm_id` / `lease_id` — anti-replay across VMs + re-leasings.
/// - `source_gen` — the generation the SOURCE signs at (== the VM's
///   CURRENT generation, NOT `new_gen`). vali calls
///   `_verify_ack(vm_generation=job.source_gen)`; the source MUST sign at
///   this generation or verification fails closed. (SECURITY INVARIANT
///   #1 — never let the source sign at `new_gen`.)
/// - `eol_nonce` — vali's fresh, single-use 32-byte freshness nonce
///   (SECURITY INVARIANT #2). Consumed once per migration; vali clears it
///   on dest-activation so it can never be replayed.
///
/// The miner is an untrusted relay: it carries these to the guest's
/// signer + surfaces the resulting opaque ack. It cannot forge the ack
/// (only the guest's in-SNP lifecycle key signs it), and a wrong / stale
/// ack just makes vali reject it (fail-closed).
#[derive(Debug, Clone)]
pub struct SourceAckInputs {
    /// The VM being migrated.
    pub vm_id: String,
    /// The lease the ack binds to.
    pub lease_id: String,
    /// The generation the source signs at (the VM's current generation).
    pub source_gen: u64,
    /// vali's fresh single-use 32-byte EOL nonce, hex-encoded.
    pub eol_nonce_hex: String,
}

/// Wall-clock cap on a single snapshot upload. A multi-GB encrypted
/// volume over a 100 Mbit link is the worst case; 30 min is generous
/// while still bounding a stuck PUT so the migration state cannot hang
/// `running` forever. Mirrors the Edge's `PREFLIGHT_REQUEST_TIMEOUT`
/// budget for the analogous long-running miner work.
const UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Strict connect timeout for the S3 PUT — a peer slower than this to
/// complete TCP is treated as unreachable.
const UPLOAD_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The lifecycle phase of one VM's §25 M1 source-side migration.
///
/// The internal progression is `Quiescing → Snapshotting → Done`
/// (or `Failed` from any non-terminal phase). The status the Edge
/// relays back to vali collapses `Quiescing` + `Snapshotting` into the
/// single `running` value `poll_snapshot` expects — see
/// [`Self::as_status_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationPhase {
    /// The quiesce (clean stop) is in progress or done; the snapshot
    /// has not started.
    Quiescing,
    /// The snapshot copy + S3 upload is in progress.
    Snapshotting,
    /// §25 M2 DEST side — the destination is downloading the snapshot +
    /// restoring + booting the domain. Set on the DEST miner (the
    /// snapshot phases run on the SOURCE), so vali's dest-activation poll
    /// sees `running` until this completes. Like the snapshot upload, the
    /// restore far exceeds the order-relay timeout, so `migrate-activate`
    /// ACKs immediately and the work runs on a background task.
    Activating,
    /// The snapshot uploaded successfully — SOURCE leg. The source domain
    /// must stay STOPPED from here on (it is moving away), which the
    /// reboot-watcher relies on.
    Done,
    /// §25 M2 DEST — the restore + boot completed. Distinct from [`Done`]
    /// because the two legs need OPPOSITE reboot-watcher behaviour and a
    /// shared terminal state cannot express that: a source that reaches
    /// `Done` must never be restarted, while a destination that reaches
    /// `Activated` is a normal running tenant whose guest reboots must be
    /// honoured (SEV-SNP cannot warm-reset vCPUs, so every in-guest
    /// `reboot` arrives as a libvirt `Stopped` event and only the watcher
    /// brings it back). Collapsing both into `Done` left a migrated VM
    /// unable to survive its first reboot.
    ///
    /// Reports as `done` on the wire, so vali's dest-activation poll is
    /// unchanged.
    Activated,
    /// The quiesce / snapshot (source) or the dest restore + boot failed.
    /// Terminal; vali re-drives or abandons per its phase deadline.
    Failed,
}

impl MigrationPhase {
    /// The `{"status": …}` value the Edge relays to vali's
    /// `poll_snapshot`, which accepts exactly `running` / `done` /
    /// `failed`. The two in-progress internal phases both map to
    /// `running` (vali does not distinguish quiesce from snapshot —
    /// it only polls the snapshot's terminal outcome).
    pub fn as_status_str(self) -> &'static str {
        match self {
            MigrationPhase::Quiescing
            | MigrationPhase::Snapshotting
            | MigrationPhase::Activating => "running",
            MigrationPhase::Done | MigrationPhase::Activated => "done",
            MigrationPhase::Failed => "failed",
        }
    }
}

/// One VM's recorded migration state.
#[derive(Debug, Clone, Default)]
struct MigrationEntry {
    phase: Option<MigrationPhase>,
    /// The writable LUKS volume path, captured at quiesce time so a
    /// subsequent `stop` dropping the lifecycle handle does not lose
    /// the path the snapshot still needs.
    disk_path: Option<PathBuf>,
    /// §25 M2 — the guest-signed `SignedStoppedAck` (canonical-CBOR
    /// bytes) the SOURCE guest produced on its quiesce. Surfaced to
    /// vali's `poll_source_ack` (via the Edge `source-ack` relay) so vali
    /// can cryptographically verify the source generation is stopped
    /// BEFORE it activates the destination — the split-brain fence.
    ///
    /// The ack is OPAQUE to the miner: it is the guest's Ed25519
    /// signature over `(vm_id, lease_id, vm_generation, eol_nonce,
    /// now_unix)`, which only vali (holding the pinned lifecycle vk + the
    /// nonce) can verify. The miner is an untrusted relay — it cannot
    /// forge it, and surfacing a stale / wrong ack just makes vali's
    /// `_verify_ack` reject it (fail-closed, never advance).
    source_ack: Option<Vec<u8>>,
}

/// In-memory `vm_id → MigrationEntry` map.
///
/// Bounded only by the number of VMs a miner hosts (a handful); no
/// eviction is needed (unlike the order-idempotency store, which a
/// hostile peer can spray). A migration entry is created on the first
/// quiesce for a `vm_id` and overwritten on a re-drive.
///
/// The map is the source of truth for the status route AND the gate
/// that a snapshot was preceded by a quiesce (`not-quiesced` otherwise
/// — the source guest may still be writing).
#[derive(Default)]
pub struct MigrationStore {
    entries: Mutex<HashMap<VmId, MigrationEntry>>,
}

impl MigrationStore {
    /// An empty store.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Record `vm_id` entering `phase`, preserving any already-captured
    /// disk path + surfaced ack. A poisoned lock fails closed.
    fn set_phase(&self, vm_id: &VmId, phase: MigrationPhase) -> Result<()> {
        let mut map = self.lock()?;
        let entry = map.entry(vm_id.clone()).or_default();
        entry.phase = Some(phase);
        Ok(())
    }

    /// Record the writable disk path captured at quiesce time.
    fn set_disk_path(&self, vm_id: &VmId, path: Option<PathBuf>) -> Result<()> {
        let mut map = self.lock()?;
        let entry = map.entry(vm_id.clone()).or_default();
        // Only overwrite with a Some — a re-drive that re-quiesces an
        // already-stopped VM (whose handle is gone) must not clobber the
        // path captured on the first quiesce.
        if path.is_some() {
            entry.disk_path = path;
        }
        Ok(())
    }

    /// §25 M2 — record the guest-signed source `SignedStoppedAck` for
    /// `vm_id` (the canonical-CBOR bytes). Surfaced verbatim to vali's
    /// `poll_source_ack`. Overwrites any prior ack for the same vm_id (a
    /// re-driven quiesce signs a fresh ack). A poisoned lock fails closed.
    pub fn set_source_ack(&self, vm_id: &VmId, ack_cbor: Vec<u8>) -> Result<()> {
        let mut map = self.lock()?;
        let entry = map.entry(vm_id.clone()).or_default();
        entry.source_ack = Some(ack_cbor);
        Ok(())
    }

    /// §25 M2 — the surfaced source `SignedStoppedAck` for `vm_id`, or
    /// `None` if the guest has not produced + delivered one yet. The
    /// `source-ack` route maps `None` to a `404` (vali's `poll_source_ack`
    /// treats 404 as "not produced yet" and keeps waiting until the phase
    /// deadline — fail-closed, never advance without a verified ack).
    pub fn source_ack(&self, vm_id: &VmId) -> Option<Vec<u8>> {
        self.entries.lock().ok()?.get(vm_id)?.source_ack.clone()
    }

    /// The recorded phase of `vm_id`, or `None` if no migration has been
    /// started for it. The status route maps `None` to a `404`.
    pub fn phase(&self, vm_id: &VmId) -> Option<MigrationPhase> {
        self.entries.lock().ok()?.get(vm_id)?.phase
    }

    /// The disk path captured at quiesce time, if any.
    fn disk_path(&self, vm_id: &VmId) -> Result<Option<PathBuf>> {
        Ok(self.lock()?.get(vm_id).and_then(|e| e.disk_path.clone()))
    }

    /// §25 M1 — synchronously validate that a quiesce preceded the
    /// snapshot, capture the disk path, and move the phase to
    /// `Snapshotting`. Returns the writable disk path the caller then
    /// streams to S3 on a BACKGROUND task (see [`mark_snapshot_done`] /
    /// [`mark_snapshot_failed`]).
    ///
    /// Splitting the fast quiesce-check from the slow upload lets the
    /// `migrate-snapshot` order ACK immediately (so vali's
    /// `trigger_snapshot` does not block for the multi-GB upload, which
    /// far exceeds the order-relay timeout); vali then tracks the upload
    /// to completion via the `migration/{vm}/status` poll.
    pub fn begin_snapshot(&self, vm_id: &VmId) -> Result<PathBuf> {
        if self.phase(vm_id).is_none() {
            return Err(MinerAgentError::Migration("not-quiesced"));
        }
        let disk_path = match self.disk_path(vm_id)? {
            Some(p) => p,
            None => {
                let _ = self.set_phase(vm_id, MigrationPhase::Failed);
                return Err(MinerAgentError::Migration("disk-missing"));
            }
        };
        self.set_phase(vm_id, MigrationPhase::Snapshotting)?;
        Ok(disk_path)
    }

    /// §25 M1 — mark the background snapshot upload finished (the status
    /// poll then returns `done`).
    pub fn mark_snapshot_done(&self, vm_id: &VmId) -> Result<()> {
        self.set_phase(vm_id, MigrationPhase::Done)
    }

    /// §25 M1 — mark the background snapshot upload failed (the status
    /// poll then returns `failed`; vali fails the migration closed).
    pub fn mark_snapshot_failed(&self, vm_id: &VmId) {
        let _ = self.set_phase(vm_id, MigrationPhase::Failed);
    }

    /// §25 M2 DEST — synchronously enter `Activating` so the
    /// `migrate-activate` order can ACK immediately and the slow restore
    /// (multi-GB download + boot, far past the order-relay timeout) runs on
    /// a BACKGROUND task. vali's dest-activation poll then sees `running`
    /// until [`mark_activate_done`] / [`mark_activate_failed`]. Creates the
    /// DEST's migration entry (no prior quiesce on the dest — unlike the
    /// source snapshot, which requires one).
    pub fn begin_activate(&self, vm_id: &VmId) -> Result<()> {
        // This host must not be this VM's SOURCE. `Snapshotting`/`Done`
        // mean we quiesced and uploaded it — activating it here would put
        // a second live copy of the VM on the machine the fence just
        // fenced. vali already refuses a same-node migration
        // (`start_migration`'s `same-node`) and a miner rejects an order
        // not addressed to it (`order-wrong-miner`), so this is unreachable
        // today — but both of those are EXTERNAL to this store, and a
        // future local caller of `begin_activate` would re-arm the
        // split-brain with no compile-time or runtime signal. Make the
        // invariant local and self-enforcing instead.
        match self.phase(vm_id) {
            // Every phase only a SOURCE can be in. `Quiescing` belongs here
            // as much as the other two — `quiesce()` sets it as its very
            // first action, so it is the EARLIEST source marker, and
            // leaving it out left the hole this guard exists to close.
            Some(MigrationPhase::Quiescing)
            | Some(MigrationPhase::Snapshotting)
            | Some(MigrationPhase::Done) => Err(MinerAgentError::Migration("activate-on-source")),
            _ => self.set_phase(vm_id, MigrationPhase::Activating),
        }
    }

    /// Clear a SOURCE-leg entry once this host owns the VM again.
    ///
    /// After a migration fails, the documented recovery is to relaunch the
    /// intact source disk at `source_gen` (`_fail_migration`'s docstring),
    /// and reboot-recovery does the same for a VM that is merely down. But
    /// the store still holds `Done`, and the reboot-watcher suppresses
    /// restarts for it — so the relaunched VM would serve fine and then
    /// die silently on its first in-guest reboot, until the agent restarted
    /// and the in-memory store cleared. Exactly the dest-leg bug the
    /// `Activated` split fixes, on the other leg.
    ///
    /// Deliberately NOT an unconditional clear: the status route maps
    /// `None` to a 404, so wiping an entry mid-`Activating` would make
    /// vali's dest-activation poll see `no-migration` instead of
    /// `running`. Only the source's terminal `Done` is cleared.
    pub fn clear_completed_source(&self, vm_id: &VmId) {
        let Ok(mut map) = self.lock() else { return };
        if map.get(vm_id).and_then(|e| e.phase) == Some(MigrationPhase::Done) {
            map.remove(vm_id);
        }
    }

    /// §25 M2 DEST — mark the background restore + boot finished (the
    /// status poll then returns `done`; vali activates the dest Vm row).
    pub fn mark_activate_done(&self, vm_id: &VmId) -> Result<()> {
        self.set_phase(vm_id, MigrationPhase::Activated)
    }

    /// §25 M2 DEST — mark the background restore + boot failed (the status
    /// poll then returns `failed`; vali fails the migration closed — the
    /// dest is never activated, the split-brain fence holds).
    pub fn mark_activate_failed(&self, vm_id: &VmId) {
        let _ = self.set_phase(vm_id, MigrationPhase::Failed);
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<VmId, MigrationEntry>>> {
        self.entries
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)
    }
}

/// The seam the snapshot path PUTs the encrypted volume through.
///
/// Production is [`ReqwestSnapshotUploader`] (a real streaming HTTP
/// PUT to the presigned S3 URL); tests inject a mock so the migration
/// flow can be exercised without S3 or a real multi-GB disk.
#[async_trait]
pub trait SnapshotUploader: Send + Sync {
    /// Stream the file at `disk_path` to the presigned `put_url`. The
    /// bytes are ciphertext (LUKS2 + dm-integrity); the uploader never
    /// inspects or transforms them. MUST stream (not buffer the whole
    /// file) — production wraps a `tokio::fs::File` in a `ReaderStream`.
    async fn upload(&self, disk_path: &std::path::Path, put_url: &str) -> Result<()>;
}

/// Production [`SnapshotUploader`] — a streaming HTTP PUT.
pub struct ReqwestSnapshotUploader {
    client: reqwest::Client,
}

impl ReqwestSnapshotUploader {
    /// Build the client. `Err(Migration("upload-client"))` only on a
    /// `reqwest` builder failure (broken TLS backend).
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .connect_timeout(UPLOAD_CONNECT_TIMEOUT)
            .timeout(UPLOAD_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| MinerAgentError::Migration("upload-client"))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl SnapshotUploader for ReqwestSnapshotUploader {
    async fn upload(&self, disk_path: &std::path::Path, put_url: &str) -> Result<()> {
        use tokio_util::io::ReaderStream;

        // Open the encrypted volume for streaming. The file length is
        // read so we can stamp `content-length` (S3 requires it for a
        // non-chunked PUT); the bytes themselves are streamed off the
        // `ReaderStream` so the whole multi-GB volume never buffers.
        let file = tokio::fs::File::open(disk_path)
            .await
            .map_err(|_| MinerAgentError::Migration("disk-open"))?;
        let len = file
            .metadata()
            .await
            .map_err(|_| MinerAgentError::Migration("disk-open"))?
            .len();
        let body = reqwest::Body::wrap_stream(ReaderStream::new(file));

        let resp = self
            .client
            .put(put_url)
            .header(reqwest::header::CONTENT_LENGTH, len)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body)
            .send()
            .await
            .map_err(|_| MinerAgentError::Migration("upload-send"))?;

        if !resp.status().is_success() {
            return Err(MinerAgentError::Migration("upload-status"));
        }
        Ok(())
    }
}

/// The seam the dest-activation path streams the encrypted snapshot
/// down through (§25 M2).
///
/// Production is [`ReqwestSnapshotDownloader`] (a real streaming HTTP
/// GET from the presigned S3 URL → the dest disk); tests inject a mock
/// so the activation flow can be exercised without S3 or a real
/// multi-GB disk. The bytes are ciphertext (LUKS2 + dm-integrity); the
/// downloader never inspects or decrypts them.
#[async_trait]
pub trait SnapshotDownloader: Send + Sync {
    /// Stream the object at `get_url` and write it to `dest_path`. MUST
    /// stream (not buffer the whole object) — production writes chunks
    /// to a temp file then atomically renames into place, so a partial
    /// download never leaves a torn `{vm}.img` a launch could attach.
    async fn download(&self, get_url: &str, dest_path: &std::path::Path) -> Result<()>;
}

/// Production [`SnapshotDownloader`] — a streaming HTTP GET that writes
/// the ciphertext to a sibling temp file then atomically renames it
/// into `dest_path` (so a crash mid-download cannot leave a half-written
/// disk that the launch would attach + the guest would fail to unlock).
pub struct ReqwestSnapshotDownloader {
    client: reqwest::Client,
}

impl ReqwestSnapshotDownloader {
    /// Build the client. `Err(Migration("download-client"))` only on a
    /// `reqwest` builder failure (broken TLS backend).
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .connect_timeout(UPLOAD_CONNECT_TIMEOUT)
            .timeout(UPLOAD_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| MinerAgentError::Migration("download-client"))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl SnapshotDownloader for ReqwestSnapshotDownloader {
    async fn download(&self, get_url: &str, dest_path: &std::path::Path) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let parent = dest_path
            .parent()
            .ok_or(MinerAgentError::Migration("disk-path-invalid"))?;
        // A sibling temp file in the SAME directory so the final rename
        // is atomic (same filesystem). The `.part` suffix makes a
        // stranded temp obvious to an operator.
        let tmp_path = dest_path.with_extension("img.part");

        let resp = self
            .client
            .get(get_url)
            .send()
            .await
            .map_err(|_| MinerAgentError::Migration("download-send"))?;
        if !resp.status().is_success() {
            return Err(MinerAgentError::Migration("download-status"));
        }

        // Ensure the parent exists (the launch path validates the disk
        // is under MINER_ROOT; the dir should already exist on a staged
        // host, but create it best-effort so a fresh dest works).
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|_| MinerAgentError::Migration("download-write"))?;

        let mut file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(|_| MinerAgentError::Migration("download-write"))?;

        let mut stream = resp;
        loop {
            let chunk = stream
                .chunk()
                .await
                .map_err(|_| MinerAgentError::Migration("download-read"))?;
            match chunk {
                Some(bytes) => {
                    file.write_all(&bytes)
                        .await
                        .map_err(|_| MinerAgentError::Migration("download-write"))?;
                }
                None => break,
            }
        }
        // fsync the data + rename atomically into place.
        file.flush()
            .await
            .map_err(|_| MinerAgentError::Migration("download-write"))?;
        file.sync_all()
            .await
            .map_err(|_| MinerAgentError::Migration("download-write"))?;
        drop(file);
        tokio::fs::rename(&tmp_path, dest_path)
            .await
            .map_err(|_| MinerAgentError::Migration("download-write"))?;
        Ok(())
    }
}

/// The seam the §25 ack producer drives the running SOURCE guest's
/// `stopped{}` signer through — and pulls the resulting opaque
/// `SignedStoppedAck` bytes back.
///
/// ## Why a trait (the deferred-transport seam)
///
/// On a §25 quiesce the source guest must sign a `StoppedAck` bound to
/// the SOURCE generation + vali's fresh single-use nonce, as its FINAL
/// act while still running — BEFORE the miner stops it (a stopped guest
/// can no longer sign). The mechanism that hands the nonce to the live
/// guest, triggers its in-SNP signer, and reads the signed bytes back is
/// an AF_VSOCK round-trip into the measured guest (the dual of the
/// `ticket_push` channel). That live vsock byte-exchange CANNOT be
/// exercised from `cargo test` (it needs a booted SEV-SNP guest), so it
/// lives behind this trait: [`run_eol`]-style production wiring on one
/// side, a [`MockAckSigner`] on the other.
///
/// ## Fail-closed contract (SECURITY INVARIANT #3)
///
/// `sign` returns `Ok(Some(bytes))` ONLY when the guest produced a real
/// signed ack. It returns `Ok(None)` (the guest is unreachable / declined
/// / the channel is the not-yet-wired stub) WITHOUT failing the quiesce —
/// the quiesce still stops the guest so its disk is static for the
/// snapshot. A `None` ack is simply NOT surfaced to the `source-ack`
/// store, so vali's `poll_source_ack` returns `None`, the
/// `AwaitingSourceAck` phase times out, the source is §13-quarantined,
/// and **the destination is NEVER activated**. There is no path here that
/// fabricates an ack or advances the migration without a guest-signed one.
#[async_trait]
pub trait GuestStoppedAckSigner: Send + Sync {
    /// Drive the running guest for `vm_id` to sign a `StoppedAck` bound to
    /// `inputs`, returning the opaque canonical-CBOR `SignedStoppedAck`
    /// bytes the guest produced, or `None` if no ack could be obtained
    /// (fail-closed — the migration then times out, never advances).
    async fn sign(&self, vm_id: &VmId, inputs: &SourceAckInputs) -> Result<Option<Vec<u8>>>;
}

/// The production [`GuestStoppedAckSigner`] for the COLD-migration
/// shutdown-sign fence.
///
/// ## The locked design — COLD migration, guest signs from its baked cmdline
///
/// §25 is a COLD migration: the source guest is cleanly **shut down**, its
/// encrypted disk is snapshotted while static, and a fresh boot is brought
/// up on the destination. There is no live-RAM transfer (SEV-SNP encrypted
/// RAM makes that impractical). The split-brain fence is the guest's own
/// cryptographic stopped-ack — and the KEY SIMPLIFICATION of the locked
/// design is that the guest signs `(vm_id, lease_id, vm_generation, nonce)`
/// **ENTIRELY from its already-baked launch cmdline**:
///
/// - `hippius.vm_id` / `hippius.lease_id` / `hippius.vm_generation` /
///   `hippius.eol_nonce` are all measured cmdline tokens the guest reads at
///   shutdown (`agent-initramfs::main::eol_push_inputs`). NO fresh nonce
///   needs to be delivered to a RUNNING guest over vsock — the eliminated
///   dependency that previously blocked this producer.
/// - Per-migration replay protection comes from the **generation**, not a
///   fresh per-event nonce: each migration runs the source at a distinct
///   `source_gen`, and vali's KBS fence forever denies an already-migrated
///   generation (`kbs_core::lifecycle::check_releasable`). So the SAME baked
///   nonce signing at a NEW generation is not a replay.
///
/// This is precisely the §24 EOL signing path
/// (`agent-initramfs::stages::eol::run_eol`): sign the `StoppedAck` from the
/// baked cmdline → push it → `luksClose` → power off. For COLD migration the
/// power-off is DESIRED (the disk goes static for the snapshot), and the
/// teardown is **non-destructive on disk** — `luksClose` removes the
/// dm-crypt MAPPING, never the on-disk LUKS ciphertext (only §24's vali-side
/// `crypto_erase_kek` is destructive, and §25 deliberately SKIPS it). So §25
/// reuses the §24 guest EOL AS-IS; only vali's state machine differs (no
/// crypto-erase, re-mint at `new_gen`).
///
/// ## `inputs` is the binding to VERIFY against — not a fresh secret to push
///
/// `inputs` (vali's `source_gen` + `lease_id` + the VM's `eol_nonce`) is the
/// tuple vali's `_verify_ack` re-derives and checks the guest's Ed25519
/// signature against. The miner is an untrusted relay: it triggers the
/// guest's clean shutdown-sign, captures the OPAQUE signed bytes the guest
/// produces, and surfaces them — it can neither forge the ack (only the
/// guest's in-SNP lifecycle key signs it) nor weaken the fence (a wrong /
/// absent ack just makes vali fail closed and never activate the dest).
///
/// ## The one remaining gate — a BAKE (documented, not hacked)
///
/// Closing the guest-execution step end-to-end needs the measured tenant
/// image to carry the shutdown integration that invokes `hippius-agent-
/// initramfs eol` (a systemd shutdown unit / dracut shutdown hook — §F) AND
/// the baked `hippius.eol_nonce` cmdline token vali verifies against. Until
/// that bake ships, this production signer is **fail-closed**: it triggers
/// no fabricated ack, so vali's fence times out, the source is
/// §13-quarantined, and the destination is NEVER activated. It NEVER
/// fabricates an ack. The producer LOGIC around it (source_gen binding,
/// surfacing, fail-closed) is fully unit-tested via the mock; the
/// guest-execution is validated in a live §25 e2e on a real SNP guest once
/// the shutdown-hook bake lands.
#[derive(Debug, Default)]
pub struct EolShutdownAckSigner;

impl EolShutdownAckSigner {
    /// Construct the production signer.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl GuestStoppedAckSigner for EolShutdownAckSigner {
    async fn sign(&self, _vm_id: &VmId, _inputs: &SourceAckInputs) -> Result<Option<Vec<u8>>> {
        // The guest signs its stopped-ack from its baked cmdline during the
        // clean EOL shutdown the quiesce drives (the §24 `eol` path, reused
        // non-destructively). Capturing those opaque bytes needs the
        // shutdown-hook bake (see the struct docs) — until it ships this is
        // fail-closed: no ack surfaced, so the migration never advances the
        // destination without a guest-signed proof. It NEVER fabricates one.
        eprintln!(
            "hippius-miner-agent: migration: source-ack awaits the eol shutdown-hook bake (fail-closed)"
        );
        Ok(None)
    }
}

/// One measured boot artifact the dest stages from S3 before activation
/// (§25 M3). The dest fetches `url`, sha256-verifies the bytes against
/// `sha256_hex`, and writes them to the canonical dest path the
/// `migrate-activate` order already names (so the staged file lands
/// exactly where the libvirt domain build expects it).
///
/// Mirrors `tenant-preflight`'s [`crate::orders::types::PreflightArtifact`]
/// — same presigned-URL + pinned-sha contract, so a migrate-activate
/// stage is byte-identical to the launch-time stage the source did.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedArtifact {
    /// Short-TTL presigned S3 GET URL for the artifact bytes. A secret —
    /// never logged.
    pub url: String,
    /// Lower-case hex SHA-256 the fetched bytes MUST match.
    pub sha256_hex: String,
}

/// The §25 M3 dest staging bundle: presigned S3 GET URLs + pinned SHAs for
/// the measured boot artifacts the dest must have to boot at `new_gen`
/// with the SAME launch_digest the VM launched with.
///
/// `rootfs_data` / `rootfs_hash` are optional: a dm-verity rootfs split is
/// the common case, but a deployment may pre-stage the (large, immutable)
/// rootfs out-of-band and only stage the small per-tenant kernel/initrd
/// here. OVMF is likewise optional — it is the same operator-staged file
/// for every tenant (see `TenantPreflightOrder::ovmf_path`), so a
/// deployment that provisions it via the standard miner chain omits it.
///
/// Not `Debug`: the URLs are short-TTL secrets.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestStagingArtifacts {
    /// Pinned SEV-SNP-capable OVMF firmware (optional — see struct docs).
    #[serde(default)]
    pub ovmf: Option<StagedArtifact>,
    /// Guest kernel.
    pub kernel: StagedArtifact,
    /// Guest initrd.
    pub initrd: StagedArtifact,
    /// dm-verity rootfs data image (optional — see struct docs).
    #[serde(default)]
    pub rootfs_data: Option<StagedArtifact>,
    /// dm-verity rootfs hash tree (optional — see struct docs).
    #[serde(default)]
    pub rootfs_hash: Option<StagedArtifact>,
}

/// Rewrite every boot-artifact path this activate is going to STAGE so it
/// lands inside THIS VM's own staging dir, ignoring whatever path the
/// order named.
///
/// ## Why (P9/#16) — the live clobber this closes
///
/// `_launch_paths` on the vali side resolved `rootfs_data_path` /
/// `rootfs_hash_path` from the launch SPEC, whose default is the SHARED
/// `/var/lib/hippius-miner/rootfs.img` — and kernel/initrd fell back to
/// the equally shared `/var/lib/hippius-miner/tenant.vmlinuz`. So a §25
/// dest-activation wrote multi-GB verified bytes straight onto paths that
/// are NOT this VM's:
///
/// - on one host those four files exist as REAL files at the miner root,
///   and `/var/lib/hippius-miner/rootfs.img` is byte-identical to a
///   tenant's `staging/<vm_id>/rootfs.img` — a migration wrote them
///   there;
/// - on another host the SAME paths are SYMLINKS into
///   `staging/rootfs.img`, the shared legacy base. The identical order
///   would have followed the link and replaced the base image of every
///   legacy VM on the host, in place, under a running guest.
///
/// That is the "two miners silently diverge on what the rootfs means"
/// defect and the data-loss event in one. The fix is not to send better
/// paths (a fleet can always carry an older vali): the MINER owns its own
/// layout and never writes an artifact outside `staging/<vm_id>/`.
///
/// Only the artifacts we actually stage are rewritten. An order that
/// carries NO descriptor for an artifact means "it is pre-staged out of
/// band" — that path is left exactly as the order named it and is
/// existence-checked, unchanged, by the caller.
///
/// Measurement-neutral by construction: OVMF / kernel / initrd are folded
/// into the SNP launch digest by CONTENT, the cmdline is measured
/// verbatim and contains no host paths, and the golden base is bound by
/// the `dm-verity.root=` hash in that cmdline. Moving a file changes no
/// measured byte.
fn redirect_staged_paths_into_vm_dir(
    staging: &DestStagingArtifacts,
    order: &mut crate::orders::types::MigrateActivateOrder,
    dir: &std::path::Path,
) {
    use crate::lifecycle::preflight as pf;
    if staging.ovmf.is_some() {
        order.ovmf_path = dir.join(pf::ARTIFACT_OVMF);
    }
    order.kernel_path = dir.join(pf::ARTIFACT_KERNEL);
    order.initrd_path = dir.join(pf::ARTIFACT_INITRD);
    if staging.rootfs_data.is_some() {
        order.rootfs_data_path = dir.join(pf::ARTIFACT_ROOTFS_IMG);
    }
    if staging.rootfs_hash.is_some() {
        order.rootfs_hash_path = dir.join(pf::ARTIFACT_ROOTFS_VERITY);
    }
}

/// Fetch + sha256-verify + atomically stage every measured boot artifact
/// the `migrate-activate` order carries a descriptor for, writing each to
/// the canonical dest path the order names (so the domain build finds it).
///
/// Callers MUST have run [`redirect_staged_paths_into_vm_dir`] first, so
/// "the path the order names" is always inside this VM's own staging dir.
///
/// Fail-closed (SECURITY: a wrong artifact would change the SNP
/// measurement, and the KBS would refuse the KEK — but we reject earlier,
/// at the sha verify, so a mis-staged dest never even boots):
/// - a fetch / network error → `Migration("dest-artifact-fetch")`;
/// - a non-2xx status        → `Migration("dest-artifact-status")`;
/// - a sha256 mismatch       → `Migration("dest-artifact-sha-mismatch")`;
/// - a stage write error     → `Migration("dest-artifact-stage")`;
/// - a differing file already in place under a LIVE domain →
///   `Migration("dest-artifact-in-use")`.
async fn stage_dest_artifacts(
    staging: &DestStagingArtifacts,
    order: &crate::orders::types::MigrateActivateOrder,
    policy: crate::lifecycle::preflight::StagePolicy,
) -> Result<()> {
    if let Some(ovmf) = &staging.ovmf {
        fetch_verify_stage_artifact(ovmf, &order.ovmf_path, policy).await?;
    }
    fetch_verify_stage_artifact(&staging.kernel, &order.kernel_path, policy).await?;
    fetch_verify_stage_artifact(&staging.initrd, &order.initrd_path, policy).await?;
    if let Some(rootfs_data) = &staging.rootfs_data {
        fetch_verify_stage_artifact(rootfs_data, &order.rootfs_data_path, policy).await?;
    }
    if let Some(rootfs_hash) = &staging.rootfs_hash {
        fetch_verify_stage_artifact(rootfs_hash, &order.rootfs_hash_path, policy).await?;
    }
    Ok(())
}

/// Fetch one artifact, sha256-verify it, and atomically stage it to
/// `out_path` (write to a sibling `*.part`, fsync, rename). Mirrors
/// `lifecycle::preflight::fetch_verify_stage` — the launch-time staging
/// the source did — so a migrate-activate stage is byte-identical.
async fn fetch_verify_stage_artifact(
    artifact: &StagedArtifact,
    out_path: &std::path::Path,
    policy: crate::lifecycle::preflight::StagePolicy,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;

    let expected = parse_sha256_hex(&artifact.sha256_hex)
        .ok_or(MinerAgentError::Migration("dest-artifact-bad-sha"))?;

    // Stage-time content check — the same rule the launch preflight uses.
    // `stage_dest_artifacts` runs BEFORE this handler's live-domain check
    // (it has to: the existence gate depends on it), so without this a
    // re-driven activate re-downloads multi-GB artifacts straight over a
    // booted guest's dm-verity base. Identical bytes ⇒ no-op; differing
    // bytes under a live domain ⇒ fail closed.
    if out_path.exists() {
        if crate::lifecycle::preflight::file_sha256_matches(out_path, &expected) {
            return Ok(());
        }
        if policy == crate::lifecycle::preflight::StagePolicy::PinnedByLiveVm {
            return Err(MinerAgentError::Migration("dest-artifact-in-use"));
        }
    }

    let resp = reqwest::get(&artifact.url)
        .await
        .map_err(|_| MinerAgentError::Migration("dest-artifact-fetch"))?;
    if !resp.status().is_success() {
        return Err(MinerAgentError::Migration("dest-artifact-status"));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|_| MinerAgentError::Migration("dest-artifact-fetch"))?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    if hasher.finalize().as_slice() != expected.as_slice() {
        // SECURITY: a sha mismatch means the bytes are NOT the measured
        // artifact — reject before staging so the dest never boots a
        // measurement the KBS would (rightly) refuse the KEK for.
        return Err(MinerAgentError::Migration("dest-artifact-sha-mismatch"));
    }

    let parent = out_path
        .parent()
        .ok_or(MinerAgentError::Migration("dest-artifact-stage"))?;
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|_| MinerAgentError::Migration("dest-artifact-stage"))?;
    let partial = out_path.with_extension("part");
    let mut f = tokio::fs::File::create(&partial)
        .await
        .map_err(|_| MinerAgentError::Migration("dest-artifact-stage"))?;
    f.write_all(&bytes)
        .await
        .map_err(|_| MinerAgentError::Migration("dest-artifact-stage"))?;
    f.sync_all()
        .await
        .map_err(|_| MinerAgentError::Migration("dest-artifact-stage"))?;
    drop(f);
    tokio::fs::rename(&partial, out_path)
        .await
        .map_err(|_| MinerAgentError::Migration("dest-artifact-stage"))?;
    Ok(())
}

/// Parse a 64-char lower/upper hex SHA-256 into 32 bytes. Mirrors
/// `lifecycle::preflight::parse_sha256_hex`.
fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Sidecar path recording WHICH migration last restored this VM's
/// artifacts onto this host. Sits beside the boot disk. NOTE: nothing
/// currently sweeps it — §24 `destroy` unlinks only the luks/overlay
/// paths — so it leaks alongside the known `state/` orphans.
pub(crate) fn restore_marker_path(disk_path: &std::path::Path) -> std::path::PathBuf {
    let mut p = disk_path.as_os_str().to_owned();
    p.push(".restored-from");
    std::path::PathBuf::from(p)
}

/// Identity of the artifacts an activate order is asking us to restore:
/// the snapshot object's PATH, with the presigned query stripped.
///
/// The path is `migrations/{vm_id}/{job_id}.luks`, so it is unique per
/// MIGRATION JOB while being stable across re-presigns of the same job
/// (each presign carries a different signature + expiry in the query).
///
/// `new_gen` cannot serve here: it is `vm.generation + 1`, and the VM's
/// generation only advances on a SUCCESSFUL activation. A migration that
/// fails after restoring leaves the generation untouched, so the retry
/// carries the SAME `new_gen` — the marker would match, both downloads
/// would be skipped, and the retry would boot the failed attempt's stale
/// artifacts. `job_id` is regenerated per job, so the path is not.
fn artifact_identity(get_url: &str) -> &str {
    match get_url.split_once('?') {
        Some((path, _query)) => path,
        None => get_url,
    }
}

/// Read the artifact identity recorded by the last completed restore.
/// `None` on any error — a missing or unreadable marker means "we do not
/// know", and not-knowing must fall through to the live-domain check
/// rather than silently skip a needed restore.
async fn read_restore_marker(path: &std::path::Path) -> Option<String> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    Some(raw.trim().to_string())
}

/// Record the artifacts whose restore just completed, durably.
///
/// fsync'd because the marker is what stops a re-drive from re-pulling —
/// and while the LIVE-DOMAIN check below is the real guarantee against
/// overwriting a running guest, this is what prevents a needless multi-GB
/// re-download and, in the window after a dest guest has booted and
/// advanced its counter but before the domain is observed running, what
/// stops the counter being rewound. Best-effort: a failure costs a
/// redundant re-download, never a failed activation.
async fn write_restore_marker(path: &std::path::Path, identity: &str) {
    let write = async {
        let mut f = tokio::fs::File::create(path).await?;
        tokio::io::AsyncWriteExt::write_all(&mut f, identity.as_bytes()).await?;
        tokio::io::AsyncWriteExt::flush(&mut f).await?;
        f.sync_all().await
    };
    if let Err(e) = write.await {
        let _ = e;
        eprintln!(
            "hippius-miner-agent: migrate-activate: restore marker write failed \
             (a re-drive will re-download; a running domain is still never clobbered)"
        );
    }
}

/// Activate the DESTINATION CVM from a snapshot (§25 M2).
///
/// This is the destination half of a §25 warm migration. It is
/// dispatched by vali ONLY after vali has cryptographically verified the
/// source guest's signed `stopped{}` ack at the source generation AND
/// moved the KBS VmState to `Migrating{new_gen, dest}` (the fence). See
/// the [`crate::orders::types::MigrateActivateOrder`] docs for the full
/// ordering guarantee.
///
/// Steps:
/// 1. **fail closed if boot artifacts are not pre-staged** (OVMF /
///    kernel / initrd). M2 requires them on the dest already (M3 wires
///    the staging) — a missing one is `dest-artifacts-missing`, never a
///    half-provisioned boot.
/// 2. **download** the encrypted LUKS snapshot from `get_url` → write it
///    as the dest's `luks_disk_path` (atomic temp + rename). Skipped if
///    the disk is already present from a prior tick (idempotent).
/// 3. **recreate the libvirt domain** via the SAME launch path a fresh
///    launch uses, booting at the migration generation. The guest
///    re-attests at `new_gen`; the KBS — already at
///    `Migrating{new_gen, dest}` — releases the SAME rootfs KEK so the
///    dest unlocks the migrated disk.
///
/// Idempotent: an already-running CVM for this `vm_id` (a re-driven
/// activate) is a success no-op (`handle_launch` maps `AlreadyLaunched`
/// to ok); the disk download is skipped when the disk already exists.
///
/// The miner NEVER decrypts: it writes ciphertext to disk and boots the
/// guest, which unlocks inside its SNP boundary with the KBS-released
/// key. The split-brain invariant is enforced UPSTREAM (vali's verified
/// ack + the KBS fence) — this handler is the mechanical dest restore.
pub async fn activate_dest(
    lifecycle: &CvmLifecycle,
    downloader: &dyn SnapshotDownloader,
    pusher: &dyn crate::vsock::ticket_push::TicketPusher,
    mut order: crate::orders::types::MigrateActivateOrder,
) -> Result<String> {
    let vm_id = order.vm_id.clone();

    // Idempotent fast-path: if this VM is already running on the dest
    // (a re-driven activate), the launch path's `AlreadyLaunched` →
    // success handles it. We still must NOT re-download over a running
    // VM's disk — so the download below is gated on the disk's absence.

    // (0) §25 M3 — STAGE the measured boot artifacts from S3 onto the
    //     dest BEFORE the existence check. The dest must boot at `new_gen`
    //     with the SAME measured OVMF / kernel / initrd / rootfs the VM
    //     launched with — else the SNP launch_digest differs and the KBS
    //     refuses the KEK. Each artifact is fetched from its presigned S3
    //     URL, sha256-verified against the bake's pinned digest, and
    //     atomically staged to the order's canonical path. Fail-closed:
    //     a missing URL, a fetch error, or a sha mismatch surfaces
    //     `dest-artifacts-missing` / `dest-artifact-sha-mismatch` — never
    //     a half-staged boot.
    //
    //     P9/#16: every artifact we stage is FIRST redirected into this
    //     VM's own `staging/<vm_id>/` dir — the order's path hints are
    //     ignored for anything we write, so a stale/older vali that still
    //     names the SHARED `/var/lib/hippius-miner/rootfs.img` can no
    //     longer make us replace another tenant's base image (on some
    //     hosts that path is a SYMLINK into the shared legacy base).
    //     Staging is
    //     additionally content-checked and refuses to change bytes a LIVE
    //     domain boots from.
    if let Some(staging) = order.boot_artifacts.clone() {
        redirect_staged_paths_into_vm_dir(&staging, &mut order, &lifecycle.vm_staging_dir(&vm_id));
        let policy = match lifecycle.tenant_domain_liveness(&vm_id).await {
            crate::lifecycle::DomainLiveness::Down => {
                crate::lifecycle::preflight::StagePolicy::Replace
            }
            crate::lifecycle::DomainLiveness::Live | crate::lifecycle::DomainLiveness::Unknown => {
                crate::lifecycle::preflight::StagePolicy::PinnedByLiveVm
            }
        };
        stage_dest_artifacts(&staging, &order, policy).await?;
    }

    // GOLDEN mode is derived from the SNP-MEASURED cmdline (same as
    // `launch`), so a miner cannot spoof it. In golden mode the OS is the
    // SHARED read-only dm-verity base (rootfs.img/rootfs.verity) and the
    // writable `/dev/vda` is the per-VM overlay upper.
    let is_golden = crate::lifecycle::golden::is_golden_cmdline(&order.cmdline);

    // (1) Fail closed if a required boot artifact is still absent (the
    //     order carried no staging descriptor, or a stage left a gap).
    //     Booting without them would produce a broken domain. We check
    //     existence here, BEFORE the snapshot download, so a mis-staged
    //     dest fails fast without pulling a multi-GB disk. For GOLDEN the
    //     dest ALSO needs the shared dm-verity base (rootfs.img/rootfs.
    //     verity) present — the golden `launch` boots the root from it and
    //     never self-fetches it, so a cache-miss must fail here, not
    //     mid-verity at boot. (Both are PUBLIC integrity-only artifacts —
    //     the verity ROOT is measured in the cmdline, so a wrong base is
    //     caught by the SNP measurement / dm-verity, not by trust.)
    let mut required: Vec<&std::path::PathBuf> =
        vec![&order.ovmf_path, &order.kernel_path, &order.initrd_path];
    if is_golden {
        required.push(&order.rootfs_data_path);
        required.push(&order.rootfs_hash_path);
    }
    for artifact in required {
        if !artifact.exists() {
            return Err(MinerAgentError::Migration("dest-artifacts-missing"));
        }
    }

    // (2) Download the encrypted snapshot to the dest boot-disk path —
    //     unless it is already present (idempotent re-drive: the prior tick
    //     wrote it, or the VM is already running on it). A zero-byte or
    //     absent file triggers a (re)download; a present non-empty file
    //     is reused as the migrated ciphertext.
    //
    //     CRITICAL for GOLDEN: `launch` ignores `order.luks_disk_path` and
    //     boots the writable `/dev/vda` from its OWN derived overlay path
    //     (`golden::overlay_disk_path`). So the migrated ciphertext MUST be
    //     written THERE, or the launch's `ensure_overlay_disk` would create
    //     a BLANK overlay and the guest would boot empty (data loss) /
    //     `luksOpen` would fail. Writing it to the derived path makes
    //     `ensure_overlay_disk` find it already present and PRESERVE it
    //     (never reformat) → the guest unlocks the migrated data. Still
    //     ciphertext end-to-end (the miner never holds the key).
    let disk_path = if is_golden {
        lifecycle.golden_overlay_path(&vm_id)
    } else {
        order.luks_disk_path.clone()
    };
    if disk_path.as_os_str().is_empty() {
        return Err(MinerAgentError::Migration("disk-path-invalid"));
    }
    //     WHICH RESTORE IS THIS? A bare "the file is already here" test
    //     cannot tell a re-driven activate of THIS migration from a VM
    //     RETURNING to a host it previously lived on — and nothing ever
    //     deletes a departed VM's artifacts (§25 never destroys the
    //     source; §24's `destroy` unlinks only the luks/overlay paths, so
    //     `state/` accumulates orphans). On a migrate-back the stale local
    //     copies would be reused: the overlay silently reverts the tenant's
    //     disk to its pre-migration contents, and the counter is behind
    //     what the KBS holds.
    //
    //     So the skip is keyed on the ARTIFACTS this activate is for
    //     (`artifact_identity` — the snapshot object path, unique per
    //     migration job), not on mere presence:
    //       marker == this job's artifacts ⇒ already restored ⇒ skip;
    //       otherwise                      ⇒ a different residency or a
    //         retry ⇒ restore both, overwriting what this host kept.
    //
    //     Both artifacts share one marker deliberately. Restoring the
    //     counter but not the overlay would be WORSE than today: the guest
    //     would unlock a STALE disk instead of failing closed on the
    //     counter — silent data loss in place of a visible brick.
    //
    //     AND we never write over a domain that is LIVE on this host. The
    //     marker alone is not enough: `_guarded` on the vali side is
    //     explicitly "common-case dedup, NOT exactly-once", so a re-drive
    //     can arrive at any time — including after the dest guest booted,
    //     if the marker write had failed. Re-downloading then would rename
    //     a fresh file over the backing store of a RUNNING QEMU domain and
    //     rewind the counter the guest has already advanced. `activate_dest`
    //     must be idempotent unconditionally, not just while a file
    //     survives, so the live-domain check is the load-bearing guard and
    //     the marker is the optimisation on top of it. A migrate-back
    //     arrives when the VM is NOT running here, so this costs nothing
    //     there.
    let marker_path = restore_marker_path(&disk_path);
    let identity = artifact_identity(&order.get_url).to_string();
    let restored = read_restore_marker(&marker_path).await;
    let running = lifecycle
        .list_tenants()
        .await
        .map(|ts| ts.iter().any(|(id, _)| id == &vm_id))
        .unwrap_or(false);
    let already_restored = restored.as_deref() == Some(identity.as_str()) || running;
    if !already_restored {
        downloader.download(&order.get_url, &disk_path).await?;
    }

    // (2b) Restore the source's ANTI-ROLLBACK STATE DISK — before the
    //      launch, because `launch` calls `ensure_state_disk`, which
    //      formats a BLANK 1 MiB ext4 whenever the file is absent and
    //      returns the existing file untouched when it is present.
    //
    //      Without this the migrated guest boots with an empty
    //      `/hippius-state/boot-counter`, submits `1` to the KBS — which
    //      still holds the source's `stored = N` for the SAME vm_id — and
    //      `boot_counter::check_only` refuses (`submitted != stored + 1`)
    //      BEFORE any Vault read. The dest domain then runs, hung in
    //      initramfs, having never unlocked: a migration that reports
    //      success with a dead workload.
    //
    //      Same idempotency rule as the volume: skip when a non-empty file
    //      is already here (a re-driven activate, or the VM already
    //      running on it) so a re-drive never rewinds a counter the dest
    //      has since advanced. Empty URL ⇒ nothing was carried; fall
    //      through to `ensure_state_disk`'s blank disk (pre-fix behaviour).
    if !order.state_get_url.is_empty() && !already_restored {
        let state_path = lifecycle.state_disk_path(&vm_id);
        downloader
            .download(&order.state_get_url, &state_path)
            .await?;
        // The state disk has ONE legal size. Check it before the guest is
        // ever pointed at it: this file becomes /dev/vdd, and the guest's
        // ext4 driver parses it in the initramfs BEFORE the LUKS unlock.
        // The source host is untrusted, so without this the source chooses
        // a filesystem image that an honest host's guest then mounts.
        // A wrong size means the object is not our 1 MiB image — refuse
        // rather than attach it.
        //
        // This does NOT bound the transfer: an oversized object is still
        // written before being rejected. The volume leg has always been
        // unbounded and is the multi-GB one, so bounding only this leg
        // would not change the disk-fill picture — that is a separate,
        // pre-existing concern.
        let len = tokio::fs::metadata(&state_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        if len != crate::lifecycle::state_disk::STATE_DISK_BYTES {
            let _ = tokio::fs::remove_file(&state_path).await;
            return Err(MinerAgentError::Migration("state-disk-size"));
        }
    }
    // Record the restore — only after it succeeded, so a failure
    // mid-restore leaves the marker stale and the next tick re-pulls both
    // rather than booting a half-restored VM.
    //
    // Written whenever the marker does not already name these artifacts,
    // INCLUDING when the download was skipped because the domain is live.
    // That case is the tail of the very failure the live-domain guard
    // exists for: the marker write failed, the guest booted, and the
    // re-drive skipped on `running`. Leaving the marker absent there means
    // a LATER re-drive arriving while the domain happens to be down (guest
    // crash, or the reboot-watcher's restart window) would re-pull and
    // rewind the counter the guest already advanced — a 403 brick. The VM
    // demonstrably has these artifacts, so recording that is honest.
    if restored.as_deref() != Some(identity.as_str()) {
        write_restore_marker(&marker_path, &identity).await;
    }

    // (3) Recreate the domain via the SAME launch path. The migrated
    //     ciphertext is now at `luks_disk_path`; `handle_launch` attaches
    //     it (the launch path never overwrites an existing LUKS volume —
    //     it validates + attaches), boots the guest, and pushes the L1
    //     ticket over vsock. The guest re-attests at `new_gen` and the
    //     KBS releases the KEK to (new_gen, dest).
    let launch_order = order.into_launch_order();
    match crate::orders::handler::handle_launch(lifecycle, pusher, launch_order).await {
        Ok(class) => Ok(class),
        // The launch path's rejection is already a static-class HTTP
        // mapping; surface a migration-flavoured outcome so vali's audit
        // log distinguishes a dest-activation launch failure. We map the
        // launch rejection's class through, but anchor the family.
        Err(_rej) => {
            let _ = &vm_id; // vm_id captured for potential future logging.
            Err(MinerAgentError::Migration("dest-launch-failed"))
        }
    }
}

/// Quiesce the source CVM (§25 step 2) — **non-destructive**.
///
/// Cleanly stops the guest via [`CvmLifecycle::stop`] (graceful: ACPI
/// shutdown with a bounded force-destroy fallback) so its writable LUKS
/// volume is crash-consistent + static. Idempotent: a stop of an
/// already-gone CVM (`VmNotFound`) is success.
///
/// **The LUKS `{vm}.img` ciphertext MUST survive intact** for the
/// snapshot + restore. `lifecycle.stop` only stops the libvirt domain +
/// drops the in-process handle; it NEVER unlinks the disk (that is the
/// §24 `destroy` path, which §25 deliberately does NOT call). The guest's
/// own EOL teardown (`agent-initramfs::stages::eol::eol_teardown`) does
/// `luksClose` + `poweroff` — closing the dm-crypt MAPPING, never
/// erasing the on-disk ciphertext. So a §25 quiesce is crypto-preserving
/// where a §24 EOL is crypto-erasing.
///
/// The writable disk path is captured into the migration store BEFORE
/// the stop drops the lifecycle handle, so the subsequent snapshot can
/// still find the volume.
///
/// ## The source stopped-ack (the split-brain fence's source half)
///
/// On its quiesce the SOURCE guest signs a §25 `SignedStoppedAck`
/// (reusing the §24 `StoppedAck` machinery — same fields binding
/// `vm_id`, `lease_id`, `vm_generation`, the single-use `eol_nonce`).
/// The source miner SURFACES that ack to vali via
/// [`MigrationStore::set_source_ack`] →
/// `GET /v1/miner/migration/{vm_id}/source-ack`, which the Edge
/// `source-ack` relay proxies to vali's `poll_source_ack`. vali
/// cryptographically verifies it at the SOURCE generation BEFORE it
/// activates the destination — that verification (already merged on the
/// vali side, `_h_mig_awaiting_source_ack`) is the split-brain gate.
///
/// ## §25 M3 — the ack PRODUCER
///
/// `ack_inputs` carries vali's fresh single-use `eol_nonce` + the
/// `source_gen` the guest must sign at. The quiesce drives the
/// [`GuestStoppedAckSigner`] FIRST — while the guest is still running —
/// to obtain the guest-signed `SignedStoppedAck`, and surfaces it into the
/// `source-ack` store ([`MigrationStore::set_source_ack`]) so vali's
/// `poll_source_ack` can read + cryptographically verify it at
/// `source_gen` BEFORE activating the destination. Only THEN does it stop
/// the guest (so the LUKS volume is static for the snapshot).
///
/// **Ordering matters (and is the whole point of M3):** the signer runs
/// BEFORE the stop because a stopped guest can no longer sign. A failed /
/// absent ack does NOT abort the quiesce — the guest is still stopped so
/// the snapshot is crash-consistent — but no ack is surfaced, so vali
/// fences, times out, §13-quarantines the source, and **never activates
/// the destination** (SECURITY INVARIANT #3, fail-closed).
///
/// `ack_inputs` is `None` only on a pre-M3 caller (or a re-drive that
/// already surfaced the ack) — then this degrades to the plain M1 clean
/// stop with no producer step.
pub async fn quiesce(
    lifecycle: &CvmLifecycle,
    store: &MigrationStore,
    signer: &dyn GuestStoppedAckSigner,
    vm_id: &VmId,
    ack_inputs: Option<&SourceAckInputs>,
) -> Result<()> {
    store.set_phase(vm_id, MigrationPhase::Quiescing)?;
    // Capture the writable volume path while the handle still exists.
    let disk_path = lifecycle.luks_disk_path_for(vm_id);
    store.set_disk_path(vm_id, disk_path)?;

    // ── M3 PRODUCER: sign the source `stopped{}` ack BEFORE the stop ──
    // The guest must sign while it is still running. We surface the ack
    // BEFORE stopping so the ordering is unambiguous; a `None` (guest
    // unreachable / channel not-yet-wired) is fail-closed — we proceed to
    // the stop without surfacing an ack, and vali times out (never
    // activates the dest). We never fail the quiesce on a signing miss:
    // the disk must still be quiesced for the snapshot.
    if let Some(inputs) = ack_inputs {
        match signer.sign(vm_id, inputs).await {
            Ok(Some(ack_cbor)) if !ack_cbor.is_empty() => {
                // Surface the OPAQUE guest-signed ack for vali's poll +
                // verify. The miner never decodes or trusts it.
                store.set_source_ack(vm_id, ack_cbor)?;
            }
            Ok(_) => {
                // No ack produced — fail-closed. Logged as a static class
                // (no nonce / no secret); vali's fence handles the rest.
                eprintln!(
                    "hippius-miner-agent: migration: vm={} source-ack absent (fail-closed)",
                    vm_id.as_str()
                );
            }
            Err(_) => {
                // A signer transport error is also fail-closed — surface
                // nothing, proceed to the stop, let vali time out.
                eprintln!(
                    "hippius-miner-agent: migration: vm={} source-ack signer error (fail-closed)",
                    vm_id.as_str()
                );
            }
        }
    }

    // Graceful stop. An already-stopped / untracked CVM is success
    // (idempotent) — the desired end state (guest static) is met. This is
    // NON-DESTRUCTIVE: `stop` only stops the libvirt domain + drops the
    // handle; it NEVER unlinks the `{vm}.img` ciphertext (only §24
    // `destroy` does), so the snapshot still finds the volume intact
    // (SECURITY INVARIANT #4).
    match lifecycle.stop(vm_id, true).await {
        Ok(()) | Err(MinerAgentError::VmNotFound) => Ok(()),
        Err(_) => {
            // The guest may still be writing — fail closed so the
            // snapshot does not run against a live volume.
            let _ = store.set_phase(vm_id, MigrationPhase::Failed);
            Err(MinerAgentError::Migration("quiesce-stop"))
        }
    }
}

/// Snapshot the source CVM's writable volume + upload it (§25 M1
/// step 2). Drives the migration store `Snapshotting → Done`/`Failed`.
///
/// Requires a prior [`quiesce`] for this `vm_id` (the migration store
/// must hold an entry with a captured disk path) — otherwise the source
/// guest may still be writing, so the snapshot is refused
/// (`not-quiesced` / `disk-missing`).
///
/// The volume is streamed encrypted to `put_url` via the injected
/// [`SnapshotUploader`]; the miner never decrypts.
///
/// ⚠️ SUPERSEDED — **test-only**. Production goes through
/// [`crate::orders::handler::handle_migrate_snapshot`], which ACKs
/// immediately and uploads on a background task, and which ALSO carries
/// the per-VM anti-rollback state disk. This function does not, so a
/// migration driven through it would produce a destination that boots and
/// never unlocks. Kept because these tests are the coverage for
/// `MigrationStore`'s quiesce/upload transitions; `#[cfg(test)]` so it
/// cannot be wired back into a production path by mistake.
#[cfg(test)]
pub async fn snapshot(
    store: &MigrationStore,
    uploader: &dyn SnapshotUploader,
    vm_id: &VmId,
    put_url: &str,
) -> Result<()> {
    // The snapshot must follow a quiesce: no migration entry ⇒ the
    // source guest was never stopped for this migration.
    if store.phase(vm_id).is_none() {
        return Err(MinerAgentError::Migration("not-quiesced"));
    }
    let disk_path = match store.disk_path(vm_id)? {
        Some(p) => p,
        None => {
            let _ = store.set_phase(vm_id, MigrationPhase::Failed);
            return Err(MinerAgentError::Migration("disk-missing"));
        }
    };

    store.set_phase(vm_id, MigrationPhase::Snapshotting)?;
    match uploader.upload(&disk_path, put_url).await {
        Ok(()) => {
            store.set_phase(vm_id, MigrationPhase::Done)?;
            Ok(())
        }
        Err(e) => {
            let _ = store.set_phase(vm_id, MigrationPhase::Failed);
            Err(e)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn vid(s: &str) -> VmId {
        VmId::new(s).unwrap()
    }

    #[test]
    fn phase_maps_to_the_vali_status_vocabulary() {
        // vali's `poll_snapshot` accepts EXACTLY running / done / failed.
        assert_eq!(MigrationPhase::Quiescing.as_status_str(), "running");
        assert_eq!(MigrationPhase::Snapshotting.as_status_str(), "running");
        // §25 M2 dest — the async restore reads as `running` until terminal.
        assert_eq!(MigrationPhase::Activating.as_status_str(), "running");
        assert_eq!(MigrationPhase::Done.as_status_str(), "done");
        assert_eq!(MigrationPhase::Failed.as_status_str(), "failed");
    }

    #[test]
    fn dest_activation_phase_transitions_are_observable() {
        // The §25 M2 dest coordination: begin_activate (no prior quiesce
        // needed on the dest) → running; mark_activate_done → done;
        // mark_activate_failed → failed. This is what vali's dest-activation
        // poll reads on the DEST miner's status route.
        let store = MigrationStore::new();
        let vm = vid("dest-vm");
        assert_eq!(store.phase(&vm), None);
        store.begin_activate(&vm).unwrap();
        assert_eq!(store.phase(&vm).map(|p| p.as_status_str()), Some("running"));
        store.mark_activate_done(&vm).unwrap();
        assert_eq!(store.phase(&vm).map(|p| p.as_status_str()), Some("done"));

        let vm2 = vid("dest-vm-2");
        store.begin_activate(&vm2).unwrap();
        store.mark_activate_failed(&vm2);
        assert_eq!(store.phase(&vm2).map(|p| p.as_status_str()), Some("failed"));
    }

    #[test]
    fn store_starts_empty_and_records_phases() {
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        // No migration started ⇒ no phase (status route 404s).
        assert_eq!(store.phase(&vm), None);
        store.set_phase(&vm, MigrationPhase::Quiescing).unwrap();
        assert_eq!(store.phase(&vm), Some(MigrationPhase::Quiescing));
        store.set_phase(&vm, MigrationPhase::Snapshotting).unwrap();
        assert_eq!(store.phase(&vm), Some(MigrationPhase::Snapshotting));
        store.set_phase(&vm, MigrationPhase::Done).unwrap();
        assert_eq!(store.phase(&vm), Some(MigrationPhase::Done));
    }

    #[test]
    fn source_ack_starts_absent_then_round_trips() {
        // §25 M2 — the source-ack slot is empty until the guest's signed
        // ack is surfaced; vali's `poll_source_ack` 404s until then
        // (fail-closed: no ack ⇒ no dest activation).
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        assert!(store.source_ack(&vm).is_none());
        let ack = vec![0xde, 0xad, 0xbe, 0xef];
        store.set_source_ack(&vm, ack.clone()).unwrap();
        assert_eq!(store.source_ack(&vm), Some(ack));
        // A re-quiesce signs a fresh ack — the latest overwrites.
        let ack2 = vec![0x01, 0x02];
        store.set_source_ack(&vm, ack2.clone()).unwrap();
        assert_eq!(store.source_ack(&vm), Some(ack2));
    }

    #[test]
    fn source_ack_and_phase_coexist_on_one_entry() {
        // Surfacing the ack must not clobber the phase / disk path, and
        // vice versa — they share one `MigrationEntry`.
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        store.set_phase(&vm, MigrationPhase::Quiescing).unwrap();
        store
            .set_disk_path(&vm, Some(PathBuf::from("/var/lib/hippius-miner/d.img")))
            .unwrap();
        store.set_source_ack(&vm, vec![0xaa]).unwrap();
        assert_eq!(store.phase(&vm), Some(MigrationPhase::Quiescing));
        assert_eq!(
            store.disk_path(&vm).unwrap(),
            Some(PathBuf::from("/var/lib/hippius-miner/d.img"))
        );
        assert_eq!(store.source_ack(&vm), Some(vec![0xaa]));
    }

    #[test]
    fn set_disk_path_does_not_clobber_a_captured_path_with_none() {
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        store
            .set_disk_path(&vm, Some(PathBuf::from("/var/lib/hippius-miner/d.img")))
            .unwrap();
        // A re-quiesce after the handle is gone passes None — must NOT
        // erase the path captured on the first quiesce.
        store.set_disk_path(&vm, None).unwrap();
        assert_eq!(
            store.disk_path(&vm).unwrap(),
            Some(PathBuf::from("/var/lib/hippius-miner/d.img"))
        );
    }

    /// A [`SnapshotUploader`] that records the args + returns a canned
    /// outcome — keeps the snapshot flow tests off S3 and off a real
    /// multi-GB disk.
    struct MockUploader {
        calls: Mutex<Vec<(PathBuf, String)>>,
        fail: bool,
    }

    impl MockUploader {
        fn ok() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail: true,
            }
        }
        fn calls(&self) -> Vec<(PathBuf, String)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl SnapshotUploader for MockUploader {
        async fn upload(&self, disk_path: &std::path::Path, put_url: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push((disk_path.to_path_buf(), put_url.to_string()));
            if self.fail {
                Err(MinerAgentError::Migration("upload-send"))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn snapshot_refuses_without_a_prior_quiesce() {
        // No migration entry ⇒ the source guest was never quiesced; the
        // snapshot is refused so it never runs against a live volume.
        let store = MigrationStore::new();
        let uploader = MockUploader::ok();
        let err = snapshot(&store, &uploader, &vid("tenant-x"), "https://s3/put")
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Migration("not-quiesced")));
        assert!(uploader.calls().is_empty());
    }

    #[tokio::test]
    async fn snapshot_fails_when_no_disk_path_was_captured() {
        // A quiesce that recorded a phase but no disk path (the VM was
        // already gone before quiesce, so `luks_disk_path_for` was None)
        // cannot snapshot — fail closed `disk-missing`.
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        store.set_phase(&vm, MigrationPhase::Quiescing).unwrap();
        let uploader = MockUploader::ok();
        let err = snapshot(&store, &uploader, &vm, "https://s3/put")
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Migration("disk-missing")));
        assert_eq!(store.phase(&vm), Some(MigrationPhase::Failed));
    }

    #[tokio::test]
    async fn snapshot_streams_then_marks_done() {
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        // Simulate a completed quiesce: phase recorded + disk path captured.
        store.set_phase(&vm, MigrationPhase::Quiescing).unwrap();
        store
            .set_disk_path(&vm, Some(PathBuf::from("/var/lib/hippius-miner/d.img")))
            .unwrap();

        let uploader = MockUploader::ok();
        snapshot(&store, &uploader, &vm, "https://s3.example/put?sig=x")
            .await
            .unwrap();

        // The uploader saw the captured disk path + the presigned URL.
        let calls = uploader.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, PathBuf::from("/var/lib/hippius-miner/d.img"));
        assert_eq!(calls[0].1, "https://s3.example/put?sig=x");
        // Terminal state is Done → status route reports "done".
        assert_eq!(store.phase(&vm), Some(MigrationPhase::Done));
        assert_eq!(store.phase(&vm).unwrap().as_status_str(), "done");
    }

    #[tokio::test]
    async fn snapshot_upload_failure_marks_failed() {
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        store.set_phase(&vm, MigrationPhase::Quiescing).unwrap();
        store
            .set_disk_path(&vm, Some(PathBuf::from("/var/lib/hippius-miner/d.img")))
            .unwrap();

        let uploader = MockUploader::failing();
        let err = snapshot(&store, &uploader, &vm, "https://s3/put")
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Migration("upload-send")));
        assert_eq!(store.phase(&vm), Some(MigrationPhase::Failed));
        assert_eq!(store.phase(&vm).unwrap().as_status_str(), "failed");
    }

    #[test]
    fn begin_snapshot_refuses_without_a_prior_quiesce() {
        // The async snapshot path's fast gate: no migration entry ⇒
        // not-quiesced (vali sees it on the order response, no upload
        // spawned).
        let store = MigrationStore::new();
        let err = store.begin_snapshot(&vid("tenant-x")).unwrap_err();
        assert!(matches!(err, MinerAgentError::Migration("not-quiesced")));
    }

    #[test]
    fn begin_snapshot_captures_path_and_moves_to_snapshotting() {
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        store.set_phase(&vm, MigrationPhase::Quiescing).unwrap();
        store
            .set_disk_path(&vm, Some(PathBuf::from("/var/lib/hippius-miner/d.img")))
            .unwrap();
        let path = store.begin_snapshot(&vm).unwrap();
        assert_eq!(path, PathBuf::from("/var/lib/hippius-miner/d.img"));
        // Phase advanced to Snapshotting → status route reports "running".
        assert_eq!(store.phase(&vm), Some(MigrationPhase::Snapshotting));
        assert_eq!(store.phase(&vm).unwrap().as_status_str(), "running");
        // The background task then drives it to Done.
        store.mark_snapshot_done(&vm).unwrap();
        assert_eq!(store.phase(&vm).unwrap().as_status_str(), "done");
    }

    #[test]
    fn begin_snapshot_without_a_captured_disk_path_marks_failed() {
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        // A quiesce phase but no disk path captured (e.g. the lifecycle
        // handle was already gone) ⇒ disk-missing + Failed.
        store.set_phase(&vm, MigrationPhase::Quiescing).unwrap();
        let err = store.begin_snapshot(&vm).unwrap_err();
        assert!(matches!(err, MinerAgentError::Migration("disk-missing")));
        assert_eq!(store.phase(&vm), Some(MigrationPhase::Failed));
    }

    /// Count-based mock so the idempotency test can assert how many
    /// times the uploader ran across repeated snapshot calls.
    struct CountingUploader {
        count: AtomicUsize,
    }
    #[async_trait]
    impl SnapshotUploader for CountingUploader {
        async fn upload(&self, _disk_path: &std::path::Path, _put_url: &str) -> Result<()> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn snapshot_is_re_drivable_after_done() {
        // A second snapshot for the same vm_id (vali re-drive) runs again
        // and stays Done — the state machine tolerates a repeat (the
        // upload itself is idempotent: same object, same presigned URL).
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        store.set_phase(&vm, MigrationPhase::Quiescing).unwrap();
        store
            .set_disk_path(&vm, Some(PathBuf::from("/d.img")))
            .unwrap();
        let uploader = CountingUploader {
            count: AtomicUsize::new(0),
        };
        snapshot(&store, &uploader, &vm, "https://s3/put")
            .await
            .unwrap();
        snapshot(&store, &uploader, &vm, "https://s3/put")
            .await
            .unwrap();
        assert_eq!(uploader.count.load(Ordering::SeqCst), 2);
        assert_eq!(store.phase(&vm), Some(MigrationPhase::Done));
    }

    #[test]
    fn reqwest_uploader_builds() {
        assert!(ReqwestSnapshotUploader::new().is_ok());
    }

    #[test]
    fn reqwest_downloader_builds() {
        assert!(ReqwestSnapshotDownloader::new().is_ok());
    }

    // ── §25 M2 dest-activation tests ────────────────────────────────

    use crate::lifecycle::preflight::StagePolicy;
    use crate::lifecycle::{CvmLifecycle, MockLaunchDigest, MockLibvirtDriver};
    use crate::orders::types::MigrateActivateOrder;
    use crate::vsock::ticket_push::MockTicketPusher;
    use crate::HostResources;
    use serde_bytes::ByteBuf;
    use std::sync::Arc;

    /// A mock [`SnapshotDownloader`] that records calls and either writes
    /// a stand-in ciphertext file to `dest_path` or fails. Counts calls
    /// so the idempotent-skip test can assert the download ran zero times.
    struct MockDownloader {
        calls: Mutex<Vec<(String, PathBuf)>>,
        fail: bool,
    }
    impl MockDownloader {
        fn ok() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail: false,
            }
        }
        fn calls(&self) -> Vec<(String, PathBuf)> {
            self.calls.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl SnapshotDownloader for MockDownloader {
        async fn download(&self, get_url: &str, dest_path: &std::path::Path) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push((get_url.to_string(), dest_path.to_path_buf()));
            if self.fail {
                return Err(MinerAgentError::Migration("download-send"));
            }
            if let Some(parent) = dest_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // The state disk is size-checked on arrival, so the mock has
            // to produce a legally-sized image for that leg — otherwise
            // every happy-path test would trip the gate instead of
            // exercising it.
            if dest_path.extension().and_then(|e| e.to_str()) == Some("raw") {
                std::fs::write(
                    dest_path,
                    vec![0u8; crate::lifecycle::state_disk::STATE_DISK_BYTES as usize],
                )
                .unwrap();
            } else {
                std::fs::write(dest_path, b"luks-ciphertext").unwrap();
            }
            Ok(())
        }
    }

    fn test_lifecycle() -> CvmLifecycle {
        CvmLifecycle::new(
            Arc::new(MockLibvirtDriver::new()),
            Arc::new(MockLaunchDigest::fixed([0u8; 48])),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
        )
        .skip_state_disk_provision_for_tests()
    }

    /// A lifecycle whose miner root is `root`, so `vm_staging_dir` (where
    /// the §25 dest-activation now redirects every artifact it stages)
    /// resolves inside a tempdir instead of the real
    /// `/var/lib/hippius-miner`.
    fn test_lifecycle_rooted(root: &std::path::Path) -> CvmLifecycle {
        test_lifecycle().with_state_disk_root(root.to_path_buf())
    }

    /// Build a `migrate-activate` order whose boot artifacts point at
    /// `dir`. `make_artifacts` controls whether the OVMF/kernel/initrd
    /// files are actually created (so the fail-closed test can omit them).
    fn activate_order(
        dir: &std::path::Path,
        vm: &str,
        make_artifacts: bool,
    ) -> MigrateActivateOrder {
        let ovmf = dir.join("ovmf.fd");
        let kernel = dir.join("vmlinuz");
        let initrd = dir.join("initrd");
        if make_artifacts {
            std::fs::write(&ovmf, b"ovmf").unwrap();
            std::fs::write(&kernel, b"kernel").unwrap();
            std::fs::write(&initrd, b"initrd").unwrap();
        }
        MigrateActivateOrder {
            vm_id: vid(vm),
            get_url: "https://s3.example/snap?sig=x".to_string(),
            state_get_url: String::new(),
            new_gen: 6,
            ovmf_path: ovmf,
            kernel_path: kernel,
            initrd_path: initrd,
            cmdline: "ro hippius.vm_generation=6".to_string(),
            luks_disk_path: dir.join(format!("{vm}.img")),
            luks_disk_size_gb: 10,
            rootfs_data_path: dir.join("rootfs.img"),
            rootfs_hash_path: dir.join("rootfs.verity"),
            cpu_count: 2,
            memory_mb: 2048,
            cose_ticket: ByteBuf::new(),
            boot_artifacts: None,
        }
    }

    #[tokio::test]
    async fn dest_activate_fails_closed_when_boot_artifacts_absent() {
        // M2 requires OVMF/kernel/initrd pre-staged on the dest (M3 wires
        // staging). A missing one fails closed BEFORE the multi-GB
        // download — and the downloader is never even called.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle();
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        let order = activate_order(dir.path(), "tenant-x", /*make_artifacts=*/ false);

        let err = activate_dest(&lifecycle, &downloader, &pusher, order)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::Migration("dest-artifacts-missing")
        ));
        // Crucially: no snapshot was pulled for a mis-staged dest.
        assert!(downloader.calls().is_empty());
    }

    #[tokio::test]
    async fn dest_activate_downloads_the_snapshot_then_drives_the_launch() {
        // Happy-ordering: artifacts present ⇒ the snapshot is downloaded
        // to the dest LUKS path FIRST, then the launch path is driven.
        // The launch itself fences the tempdir path (outside MINER_ROOT)
        // and surfaces `dest-launch-failed` — which PROVES the launch was
        // attempted AFTER the download landed (the security-relevant
        // ordering: ciphertext on disk before any boot).
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle();
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        let order = activate_order(dir.path(), "tenant-x", true);
        let disk_path = order.luks_disk_path.clone();

        let outcome = activate_dest(&lifecycle, &downloader, &pusher, order).await;

        // The download ran exactly once and wrote the encrypted volume.
        let calls = downloader.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "https://s3.example/snap?sig=x");
        assert_eq!(calls[0].1, disk_path);
        assert!(disk_path.exists(), "the snapshot disk must be on the dest");
        // The launch was driven (and fenced by the MINER_ROOT path check
        // in this unit-test harness) — surfaced as `dest-launch-failed`.
        assert!(matches!(
            outcome,
            Err(MinerAgentError::Migration("dest-launch-failed"))
        ));
    }

    #[tokio::test]
    async fn dest_activate_restores_the_boot_counter_state_disk() {
        // THE §25 fix. The guest keeps its anti-rollback boot counter on
        // the per-VM state disk. `ensure_state_disk` formats a BLANK one
        // whenever the file is absent, so a dest that did not receive the
        // source's disk submits counter `1` while the KBS still holds the
        // source's `stored = N` for the SAME vm_id — refused before any
        // Vault read, and the migrated guest never unlocks.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle().with_state_disk_root(dir.path().to_path_buf());
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        let mut order = activate_order(dir.path(), "tenant-x", true);
        order.state_get_url = "https://s3.example/state?sig=y".to_string();
        let state_path = lifecycle.state_disk_path(&order.vm_id);

        let _ = activate_dest(&lifecycle, &downloader, &pusher, order).await;

        // BOTH artifacts were pulled, and the state disk landed at the
        // path `ensure_state_disk` consults — so the launch finds it
        // present and does NOT format a blank counter over it.
        let calls = downloader.calls();
        assert_eq!(calls.len(), 2, "volume + state disk");
        assert_eq!(calls[1].0, "https://s3.example/state?sig=y");
        assert_eq!(calls[1].1, state_path);
        assert!(
            state_path.exists(),
            "the migrated boot counter must be on the dest BEFORE the launch"
        );
    }

    #[tokio::test]
    async fn dest_activate_refuses_a_wrongly_sized_state_disk() {
        // The restored file becomes /dev/vdd, and the guest's ext4 driver
        // parses it in the initramfs BEFORE the LUKS unlock. The source
        // host is untrusted, so anything that is not our 1 MiB image is
        // refused rather than handed to the guest.
        struct ShortDownloader;
        #[async_trait]
        impl SnapshotDownloader for ShortDownloader {
            async fn download(&self, _url: &str, dest: &std::path::Path) -> Result<()> {
                if let Some(p) = dest.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                std::fs::write(dest, b"not-a-1MiB-ext4-image").unwrap();
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle().with_state_disk_root(dir.path().to_path_buf());
        let pusher = MockTicketPusher::new();
        let mut order = activate_order(dir.path(), "tenant-x", true);
        order.state_get_url = "https://s3.example/state?sig=y".to_string();
        let state_path = lifecycle.state_disk_path(&order.vm_id);

        let err = activate_dest(&lifecycle, &ShortDownloader, &pusher, order)
            .await
            .unwrap_err();

        assert!(matches!(err, MinerAgentError::Migration("state-disk-size")));
        assert!(
            !state_path.exists(),
            "the rejected image must not be left where the launch would attach it"
        );
    }

    #[tokio::test]
    async fn dest_activate_skips_the_state_disk_when_no_url_is_carried() {
        // Forward-compat: a vali predating the field (or a migration job
        // started before it) sends no `state_get_url`. The dest must still
        // activate — falling back to the pre-fix blank counter — rather
        // than fail closed on an absent URL.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle().with_state_disk_root(dir.path().to_path_buf());
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        let order = activate_order(dir.path(), "tenant-x", true);
        assert!(order.state_get_url.is_empty());

        let _ = activate_dest(&lifecycle, &downloader, &pusher, order).await;

        assert_eq!(downloader.calls().len(), 1, "volume only");
    }

    #[tokio::test]
    async fn dest_activate_never_rewinds_a_counter_this_migration_restored() {
        // Idempotent re-drive WITHIN one migration: vali re-dispatches
        // `migrate-activate` after a tick. Re-downloading the SOURCE's
        // counter over a dest disk the guest has since advanced would make
        // the next release submit a STALE value and be refused — bricking
        // the VM we just migrated. Keyed on the generation, so this holds
        // without also making a migrate-back reuse stale artifacts (see
        // `dest_activate_replaces_artifacts_left_by_an_earlier_residency`).
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle().with_state_disk_root(dir.path().to_path_buf());
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        let mut order = activate_order(dir.path(), "tenant-x", true);
        order.state_get_url = "https://s3.example/state?sig=y".to_string();
        let state_path = lifecycle.state_disk_path(&order.vm_id);
        std::fs::create_dir_all(state_path.parent().unwrap()).unwrap();
        std::fs::write(&state_path, b"already-advanced-on-the-dest").unwrap();
        std::fs::write(
            restore_marker_path(&order.luks_disk_path),
            artifact_identity(&order.get_url),
        )
        .unwrap();

        let _ = activate_dest(&lifecycle, &downloader, &pusher, order).await;

        assert!(
            !downloader
                .calls()
                .iter()
                .any(|(url, _)| url.contains("state")),
            "a counter restored by THIS migration must not be re-pulled"
        );
        assert_eq!(
            std::fs::read(&state_path).unwrap(),
            b"already-advanced-on-the-dest"
        );
    }

    #[tokio::test]
    async fn dest_activate_golden_downloads_to_the_overlay_path() {
        // GOLDEN: the golden `launch` ignores `order.luks_disk_path` and
        // boots /dev/vda from its OWN derived `golden::overlay_disk_path`.
        // So the migrated ciphertext MUST land THERE — else launch's
        // `ensure_overlay_disk` would create a BLANK overlay (data loss).
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle().with_state_disk_root(dir.path().to_path_buf());
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        let mut order = activate_order(dir.path(), "golden-mig", true);
        // Make it golden + stage the shared dm-verity base (existence check).
        order.cmdline = "ro dm-verity.root=abc123 hippius.vm_generation=6".to_string();
        std::fs::write(&order.rootfs_data_path, b"rootfs").unwrap();
        std::fs::write(&order.rootfs_hash_path, b"verity").unwrap();
        let expected = lifecycle.golden_overlay_path(&vid("golden-mig"));

        let _ = activate_dest(&lifecycle, &downloader, &pusher, order).await;

        let calls = downloader.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].1, expected,
            "golden snapshot must land at the derived overlay path"
        );
        assert_ne!(
            calls[0].1,
            dir.path().join("golden-mig.img"),
            "NOT the order's generic luks_disk_path"
        );
        assert!(
            expected.exists(),
            "the migrated overlay must be on the dest"
        );
    }

    #[tokio::test]
    async fn dest_activate_golden_fails_closed_without_the_dm_verity_base() {
        // GOLDEN needs the shared read-only dm-verity base (rootfs.img/
        // rootfs.verity) present — golden `launch` never self-fetches it.
        // A missing base fails closed BEFORE the multi-GB download.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle().with_state_disk_root(dir.path().to_path_buf());
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        let mut order = activate_order(dir.path(), "golden-mig", true); // ovmf/kernel/initrd present
        order.cmdline = "ro dm-verity.root=abc123".to_string();
        // rootfs base deliberately NOT created.

        let err = activate_dest(&lifecycle, &downloader, &pusher, order)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::Migration("dest-artifacts-missing")
        ));
        assert!(
            downloader.calls().is_empty(),
            "no download for a base-less golden dest"
        );
    }

    #[tokio::test]
    async fn dest_activate_skips_download_when_these_artifacts_were_restored() {
        // Idempotent re-drive: THIS migration already restored the disk
        // (the marker names this job's snapshot object) ⇒ the download is
        // NOT repeated, so a tick re-drive never clobbers a volume.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle();
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        let order = activate_order(dir.path(), "tenant-x", true);
        std::fs::write(&order.luks_disk_path, b"already-here").unwrap();
        std::fs::write(
            restore_marker_path(&order.luks_disk_path),
            artifact_identity(&order.get_url),
        )
        .unwrap();

        let _ = activate_dest(&lifecycle, &downloader, &pusher, order).await;
        assert!(
            downloader.calls().is_empty(),
            "a disk restored by THIS migration must not be re-downloaded"
        );
    }

    #[tokio::test]
    async fn dest_activate_never_overwrites_a_running_domain_even_without_a_marker() {
        // The marker is an optimisation; THIS is the guarantee. vali's
        // `_guarded` is documented as "common-case dedup, NOT
        // exactly-once", so a re-drive can land at any moment — including
        // after the dest guest has booted, if the marker write had failed
        // (ENOSPC/EACCES). Re-downloading then would rename a fresh file
        // over the backing store of a LIVE QEMU domain and rewind the
        // counter the guest already advanced: corruption of a running
        // tenant. So a live domain is never written over, marker or not.
        use crate::orders::LaunchOrder;
        crate::snp_config::install_for_tests(crate::snp_config::SnpCpuConfig {
            cbitpos: 51,
            reduced_phys_bits: 1,
        });
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle().with_state_disk_root(dir.path().to_path_buf());
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        let vm = vid("tenant-x");
        // Bring the VM UP on this host first.
        lifecycle
            .launch(LaunchOrder {
                vm_id: vm.clone(),
                ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf.fd"),
                kernel_path: PathBuf::from("/var/lib/hippius-miner/vmlinuz"),
                initrd_path: PathBuf::from("/var/lib/hippius-miner/initrd"),
                cmdline: "quiet".to_string(),
                luks_disk_path: PathBuf::from("/var/lib/hippius-miner/tenant-x.img"),
                luks_disk_size_gb: 10,
                data_disk_size_gb: 0,
                rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/rootfs.img"),
                rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/rootfs.verity"),
                cpu_count: 2,
                memory_mb: 2048,
                cose_ticket: ByteBuf::from(launch_cose_ticket()),
            })
            .await
            .expect("launch should succeed");

        let mut order = activate_order(dir.path(), "tenant-x", true);
        order.state_get_url = "https://s3.example/state?sig=y".to_string();
        // NO marker on disk — the write failed, or the agent restarted.
        assert!(!restore_marker_path(&order.luks_disk_path).exists());

        let _ = activate_dest(&lifecycle, &downloader, &pusher, order).await;

        assert!(
            downloader.calls().is_empty(),
            "a live domain's disks must never be re-downloaded over"
        );
    }

    #[tokio::test]
    async fn dest_activate_restores_again_for_a_retried_job_at_the_same_generation() {
        // `new_gen` is `vm.generation + 1`, and the generation only
        // advances on a SUCCESSFUL activation — `_fail_migration` leaves it
        // alone. So a migration that fails after restoring is retried with
        // the SAME `new_gen`. Keying the marker on the generation would
        // match, skip both downloads, and boot the failed attempt's stale
        // artifacts. Keying on the snapshot object (unique per job_id)
        // re-restores, which is what a retry must do.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle().with_state_disk_root(dir.path().to_path_buf());
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        let mut order = activate_order(dir.path(), "tenant-x", true);
        order.state_get_url = "https://s3.example/state?sig=y".to_string();
        // The FAILED attempt's leftovers, at the very same new_gen.
        std::fs::write(&order.luks_disk_path, b"stale-from-the-failed-attempt").unwrap();
        std::fs::write(
            restore_marker_path(&order.luks_disk_path),
            "migrations/tenant-x/the-FAILED-job.luks",
        )
        .unwrap();

        let _ = activate_dest(&lifecycle, &downloader, &pusher, order).await;

        assert_eq!(
            downloader.calls().len(),
            2,
            "a retry at the same generation must re-pull both artifacts"
        );
    }

    #[test]
    fn begin_activate_refuses_on_a_host_that_is_this_vms_source() {
        // The dest-only property of `Activated` rests on two EXTERNAL
        // gates (vali refuses a same-node migration; a miner rejects an
        // order not addressed to it). Make it local too, so a future
        // caller cannot re-arm the split-brain silently.
        for source_phase in [
            MigrationPhase::Quiescing,
            MigrationPhase::Snapshotting,
            MigrationPhase::Done,
        ] {
            let store = MigrationStore::new();
            let vm = vid("tenant-x");
            store.set_phase(&vm, source_phase).unwrap();
            let err = store.begin_activate(&vm).unwrap_err();
            assert!(
                matches!(err, MinerAgentError::Migration("activate-on-source")),
                "phase {source_phase:?} must refuse activation"
            );
            assert_eq!(store.phase(&vm), Some(source_phase), "phase must not move");
        }

        // A genuine dest (no entry) and an idempotent re-drive both pass.
        let dest = MigrationStore::new();
        let vm2 = vid("tenant-y");
        dest.begin_activate(&vm2).unwrap();
        dest.begin_activate(&vm2)
            .expect("a re-drive must stay idempotent");
        dest.mark_activate_done(&vm2).unwrap();
        dest.begin_activate(&vm2)
            .expect("a re-drive after success must stay idempotent");
    }

    #[test]
    fn clear_completed_source_only_touches_a_finished_source() {
        // After a failed migration the operator relaunches the intact
        // source disk (the documented recovery). The store still holds the
        // source's `Done`, and the reboot-watcher suppresses restarts for
        // it — so without this clear the relaunched VM serves fine and then
        // dies silently on its first in-guest reboot.
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        store.set_phase(&vm, MigrationPhase::Done).unwrap();
        store.clear_completed_source(&vm);
        assert_eq!(store.phase(&vm), None, "a finished source must be released");

        // But NOT mid-activation: the status route maps `None` to a 404,
        // so clearing here would make vali's dest poll see `no-migration`
        // instead of `running` and fail an in-flight migration.
        for keep in [
            MigrationPhase::Quiescing,
            MigrationPhase::Snapshotting,
            MigrationPhase::Activating,
            MigrationPhase::Activated,
            MigrationPhase::Failed,
        ] {
            let s = MigrationStore::new();
            let v = vid("tenant-z");
            s.set_phase(&v, keep).unwrap();
            s.clear_completed_source(&v);
            assert_eq!(s.phase(&v), Some(keep), "{keep:?} must be preserved");
        }
    }

    #[test]
    fn the_two_legs_have_distinct_terminal_phases_but_one_wire_status() {
        // The source and the destination need OPPOSITE reboot-watcher
        // behaviour after a migration: a source that finished uploading
        // must stay stopped forever (it is moving away), while a
        // destination that finished restoring is a normal running tenant
        // whose in-guest reboots must be honoured. A single shared `Done`
        // could not express that, and the watcher's "any phase ⇒ do not
        // restart" rule meant a migrated VM died on its first reboot.
        let store = MigrationStore::new();
        let vm = vid("tenant-x");

        // SOURCE leg: quiesce → snapshot → Done.
        store.set_phase(&vm, MigrationPhase::Quiescing).unwrap();
        store.mark_snapshot_done(&vm).unwrap();
        assert_eq!(store.phase(&vm), Some(MigrationPhase::Done));

        // DEST leg: begin_activate → Activated, NOT Done.
        let dest = MigrationStore::new();
        let vm2 = vid("tenant-y");
        dest.begin_activate(&vm2).unwrap();
        dest.mark_activate_done(&vm2).unwrap();
        assert_eq!(dest.phase(&vm2), Some(MigrationPhase::Activated));
        assert_ne!(dest.phase(&vm2), Some(MigrationPhase::Done));

        // But vali cannot tell the difference — both report `done`, so the
        // dest-activation poll's wire contract is unchanged.
        assert_eq!(MigrationPhase::Done.as_status_str(), "done");
        assert_eq!(MigrationPhase::Activated.as_status_str(), "done");
    }

    #[test]
    fn artifact_identity_strips_the_presigned_query() {
        // Two presigns of the SAME job differ only in the query (fresh
        // signature + expiry). They must compare equal, or every re-drive
        // would re-download; and two different jobs must not.
        let a = artifact_identity("https://s3/b/migrations/vm-1/job-A.luks?sig=1&exp=100");
        let b = artifact_identity("https://s3/b/migrations/vm-1/job-A.luks?sig=2&exp=999");
        assert_eq!(a, b);
        let c = artifact_identity("https://s3/b/migrations/vm-1/job-B.luks?sig=1");
        assert_ne!(a, c);
        // No query at all is still a usable identity.
        assert_eq!(
            artifact_identity("https://s3/b/migrations/vm-1/job-A.luks"),
            "https://s3/b/migrations/vm-1/job-A.luks"
        );
    }

    #[tokio::test]
    async fn dest_activate_replaces_artifacts_left_by_an_earlier_residency() {
        // MIGRATE-BACK. The VM lived on this host before, migrated away,
        // and is now coming home. Nothing ever deleted its old artifacts
        // (§25 never destroys the source; §24 unlinks only the luks and
        // overlay paths), so a bare "file already present" test would
        // reuse them: the tenant's disk would silently revert to its
        // pre-migration contents and the boot counter would sit behind the
        // KBS. The marker records a DIFFERENT generation, so both must be
        // re-pulled.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle().with_state_disk_root(dir.path().to_path_buf());
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        let mut order = activate_order(dir.path(), "tenant-x", true);
        order.state_get_url = "https://s3.example/state?sig=y".to_string();
        let state_path = lifecycle.state_disk_path(&order.vm_id);
        std::fs::create_dir_all(state_path.parent().unwrap()).unwrap();
        // Leftovers from the PREVIOUS residency, at an older generation.
        std::fs::write(&order.luks_disk_path, b"stale-overlay-from-last-time").unwrap();
        std::fs::write(&state_path, b"stale-counter").unwrap();
        // Marker from the PREVIOUS residency — a different job, so a
        // different snapshot object.
        std::fs::write(
            restore_marker_path(&order.luks_disk_path),
            "migrations/tenant-x/an-earlier-job.luks",
        )
        .unwrap();

        let _ = activate_dest(&lifecycle, &downloader, &pusher, order).await;

        let calls = downloader.calls();
        assert_eq!(calls.len(), 2, "both artifacts must be re-pulled");
        assert_ne!(
            std::fs::read(&state_path).unwrap(),
            b"stale-counter",
            "the stale counter must be replaced, not reused"
        );
    }

    #[tokio::test]
    async fn dest_activate_restores_when_the_marker_is_missing_or_foreign() {
        // Not knowing which artifacts produced these files must fall
        // toward re-restoring (a redundant download) rather than skipping
        // (a stale boot). Covers a first arrival, an interrupted restore
        // that never wrote the marker, and one naming a different job.
        for marker in [
            None,
            Some("migrations/tenant-x/some-other-job.luks"),
            Some(""),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let lifecycle = test_lifecycle();
            let downloader = MockDownloader::ok();
            let pusher = MockTicketPusher::new();
            let order = activate_order(dir.path(), "tenant-x", true);
            std::fs::write(&order.luks_disk_path, b"present-but-unattributed").unwrap();
            if let Some(m) = marker {
                std::fs::write(restore_marker_path(&order.luks_disk_path), m).unwrap();
            }

            let _ = activate_dest(&lifecycle, &downloader, &pusher, order).await;
            assert!(
                !downloader.calls().is_empty(),
                "an unattributable disk must be re-restored, not trusted (marker={marker:?})"
            );
        }
    }

    /// §25 quiesce is NON-destructive: it cleanly STOPS the source guest
    /// (so the LUKS volume is static for the snapshot) but NEVER unlinks
    /// the `{vm}.img` ciphertext. We launch a real CVM through the
    /// lifecycle, quiesce it, and assert: (a) the quiesce succeeded, (b)
    /// the VM is no longer tracked (stopped), and (c) the writable disk
    /// path was captured into the migration store for the snapshot.
    ///
    /// The disk-survival guarantee is STRUCTURAL: `quiesce` calls
    /// `lifecycle.stop(.., graceful=true)`, and `stop` only stops the
    /// libvirt domain + drops the handle — the ONLY method that unlinks
    /// the disk is `lifecycle.destroy` (the §24 path), which §25 quiesce
    /// never calls. This test pins that quiesce drives the stop path.
    #[tokio::test]
    async fn quiesce_stops_the_guest_non_destructively_and_captures_the_disk() {
        use crate::lifecycle::CvmPhase;
        use crate::orders::LaunchOrder;

        // `QemuConfig::validate` (in `launch`) probes the host SNP CPU
        // params; CI hosts aren't EPYC, so pre-seed (idempotent).
        crate::snp_config::install_for_tests(crate::snp_config::SnpCpuConfig {
            cbitpos: 51,
            reduced_phys_bits: 1,
        });
        let lifecycle = test_lifecycle();
        let store = MigrationStore::new();
        let vm = vid("tenant-nd");
        // A MINER_ROOT-shaped luks path passes `validate_luks_path`
        // without existing (string-prefix check; no canonicalize when the
        // path + parent are absent). The mock driver never reads it.
        let luks = PathBuf::from("/var/lib/hippius-miner/tenant-nd.img");
        let order = LaunchOrder {
            vm_id: vm.clone(),
            ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf.fd"),
            kernel_path: PathBuf::from("/var/lib/hippius-miner/vmlinuz"),
            initrd_path: PathBuf::from("/var/lib/hippius-miner/initrd"),
            cmdline: "quiet".to_string(),
            luks_disk_path: luks.clone(),
            luks_disk_size_gb: 10,
            data_disk_size_gb: 0,
            rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/rootfs.img"),
            rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/rootfs.verity"),
            cpu_count: 2,
            memory_mb: 2048,
            cose_ticket: ByteBuf::from(launch_cose_ticket()),
        };
        lifecycle
            .launch(order)
            .await
            .expect("launch should succeed");
        assert_eq!(lifecycle.query(&vm).await.unwrap(), CvmPhase::Running);

        // Quiesce — clean stop, NON-destructive. No producer inputs ⇒
        // the plain M1 clean stop (the signer is never consulted).
        let signer = MockAckSigner::producing(None);
        quiesce(&lifecycle, &store, &signer, &vm, None)
            .await
            .unwrap();
        // The signer was NOT consulted (no ack inputs were supplied).
        assert_eq!(signer.calls(), 0);

        // The guest is stopped (handle dropped) — the volume is static.
        assert!(matches!(
            lifecycle.query(&vm).await,
            Err(MinerAgentError::VmNotFound)
        ));
        // The writable disk path was captured for the snapshot — and it
        // is the SAME path the launch used (never unlinked).
        assert_eq!(store.disk_path(&vm).unwrap(), Some(luks));
        // The migration phase was recorded.
        assert_eq!(store.phase(&vm), Some(MigrationPhase::Quiescing));
    }

    /// A CoseSign1-shaped ticket carrying `flavor: "medium"` so the
    /// launch path's §317 flavor peek (cpu_count=2 ⇒ Medium) passes.
    fn launch_cose_ticket() -> Vec<u8> {
        use ciborium::value::Value;
        use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
        let payload = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(2.into())),
            (Value::Text("flavor".into()), Value::Text("medium".into())),
        ]);
        let mut payload_buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_buf).unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build();
        CoseSign1Builder::new()
            .protected(protected)
            .payload(payload_buf)
            .create_signature(b"", |_| vec![0u8; 64])
            .build()
            .to_vec()
            .unwrap()
    }

    #[tokio::test]
    async fn dest_activate_propagates_a_download_failure_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle();
        let downloader = MockDownloader {
            calls: Mutex::new(Vec::new()),
            fail: true,
        };
        let pusher = MockTicketPusher::new();
        let order = activate_order(dir.path(), "tenant-x", true);

        let err = activate_dest(&lifecycle, &downloader, &pusher, order)
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Migration("download-send")));
    }

    // ── §25 M3 — source ack PRODUCER tests ──────────────────────────

    /// A [`GuestStoppedAckSigner`] that records the inputs it was handed
    /// and returns a canned ack (or `None` for the fail-closed path).
    struct MockAckSigner {
        /// What `sign` returns.
        outcome: Result<Option<Vec<u8>>>,
        /// Records every `(vm_id, source_gen, eol_nonce_hex)` seen.
        seen: Mutex<Vec<(String, u64, String)>>,
    }
    impl MockAckSigner {
        /// A signer that returns `ack` (clones the bytes per call).
        fn producing(ack: Option<Vec<u8>>) -> Self {
            Self {
                outcome: Ok(ack),
                seen: Mutex::new(Vec::new()),
            }
        }
        /// A signer whose transport errors.
        fn erroring() -> Self {
            Self {
                outcome: Err(MinerAgentError::Migration("ack-signer")),
                seen: Mutex::new(Vec::new()),
            }
        }
        fn calls(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
        fn seen(&self) -> Vec<(String, u64, String)> {
            self.seen.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl GuestStoppedAckSigner for MockAckSigner {
        async fn sign(&self, vm_id: &VmId, inputs: &SourceAckInputs) -> Result<Option<Vec<u8>>> {
            self.seen.lock().unwrap().push((
                vm_id.as_str().to_owned(),
                inputs.source_gen,
                inputs.eol_nonce_hex.clone(),
            ));
            match &self.outcome {
                Ok(v) => Ok(v.clone()),
                Err(_) => Err(MinerAgentError::Migration("ack-signer")),
            }
        }
    }

    fn ack_inputs(source_gen: u64) -> SourceAckInputs {
        SourceAckInputs {
            vm_id: "tenant-x".to_string(),
            lease_id: "lease-1".to_string(),
            source_gen,
            // A fresh single-use nonce (32 bytes hex).
            eol_nonce_hex: hex::encode([0x22u8; 32]),
        }
    }

    /// The store needs a captured disk path so the quiesce can run its
    /// stop branch without a real lifecycle handle — pre-seed it the way
    /// a real quiesce would, then drive the producer against a stopped VM
    /// (`VmNotFound` ⇒ Ok).
    fn empty_lifecycle() -> CvmLifecycle {
        test_lifecycle()
    }

    #[tokio::test]
    async fn quiesce_surfaces_the_guest_signed_ack_bound_to_source_gen() {
        // The PRODUCER: with vali's nonce + source_gen, the quiesce drives
        // the signer FIRST (while the guest is up), surfaces the opaque
        // ack into the source-ack store for vali's poll, THEN stops.
        let lifecycle = empty_lifecycle();
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        let canned = vec![0xab, 0xcd, 0xef];
        let signer = MockAckSigner::producing(Some(canned.clone()));
        let inputs = ack_inputs(5);

        quiesce(&lifecycle, &store, &signer, &vm, Some(&inputs))
            .await
            .unwrap();

        // The signer was consulted with EXACTLY the source generation —
        // never new_gen (SECURITY INVARIANT #1).
        assert_eq!(signer.calls(), 1);
        let seen = signer.seen();
        assert_eq!(seen[0].0, "tenant-x");
        assert_eq!(seen[0].1, 5, "the source signs at source_gen, not new_gen");
        assert_eq!(seen[0].2, hex::encode([0x22u8; 32]), "vali's fresh nonce");
        // The opaque ack is surfaced for vali's `poll_source_ack`.
        assert_eq!(store.source_ack(&vm), Some(canned));
    }

    #[tokio::test]
    async fn quiesce_is_fail_closed_when_the_guest_produces_no_ack() {
        // SECURITY INVARIANT #3: a guest that does not sign (unreachable /
        // not-yet-wired) leaves the source-ack store EMPTY — vali polls
        // None, times out, quarantines the source, never activates the
        // dest. The quiesce itself still SUCCEEDS (the guest is stopped so
        // the snapshot is crash-consistent) — it just surfaces no ack.
        let lifecycle = empty_lifecycle();
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        let signer = MockAckSigner::producing(None);
        let inputs = ack_inputs(5);

        quiesce(&lifecycle, &store, &signer, &vm, Some(&inputs))
            .await
            .unwrap();

        assert_eq!(signer.calls(), 1, "the signer was consulted");
        // NO ack surfaced ⇒ vali's poll 404s ⇒ fail-closed fence.
        assert!(
            store.source_ack(&vm).is_none(),
            "no ack ⇒ the dest is never activated"
        );
    }

    #[tokio::test]
    async fn quiesce_is_fail_closed_when_the_signer_errors() {
        // A signer transport error is also fail-closed: no ack surfaced,
        // the quiesce still completes (guest stopped), vali times out.
        let lifecycle = empty_lifecycle();
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        let signer = MockAckSigner::erroring();
        let inputs = ack_inputs(5);

        quiesce(&lifecycle, &store, &signer, &vm, Some(&inputs))
            .await
            .unwrap();
        assert!(store.source_ack(&vm).is_none());
    }

    #[tokio::test]
    async fn quiesce_rejects_an_empty_ack_fail_closed() {
        // A signer that returns Some(empty) is treated as no ack — an
        // empty SignedStoppedAck can never verify, so we never surface it.
        let lifecycle = empty_lifecycle();
        let store = MigrationStore::new();
        let vm = vid("tenant-x");
        let signer = MockAckSigner::producing(Some(Vec::new()));
        quiesce(&lifecycle, &store, &signer, &vm, Some(&ack_inputs(5)))
            .await
            .unwrap();
        assert!(store.source_ack(&vm).is_none());
    }

    #[test]
    fn source_ack_inputs_requires_both_nonce_and_source_gen() {
        use crate::orders::types::MigrateQuiesceOrder;
        // A full set ⇒ producer inputs.
        let full = MigrateQuiesceOrder {
            vm_id: vid("tenant-x"),
            node_id: "node-src".to_string(),
            lease_id: "lease-1".to_string(),
            source_gen: 5,
            eol_nonce_hex: hex::encode([0x22u8; 32]),
        };
        assert!(full.source_ack_inputs().is_some());
        // A missing nonce ⇒ no producer step (fail-closed to clean stop).
        let no_nonce = MigrateQuiesceOrder {
            eol_nonce_hex: String::new(),
            ..full.clone()
        };
        assert!(no_nonce.source_ack_inputs().is_none());
        // A zero source_gen ⇒ no producer step (never sign at gen 0).
        let no_gen = MigrateQuiesceOrder {
            source_gen: 0,
            ..full.clone()
        };
        assert!(no_gen.source_ack_inputs().is_none());
    }

    #[tokio::test]
    async fn eol_shutdown_ack_signer_is_fail_closed_by_default() {
        // The production COLD-migration signer is fail-closed until the
        // guest shutdown-hook bake ships — it returns no ack, the SAFE
        // default (vali fences + times out, never activates the dest
        // without a real guest-signed ack). It NEVER fabricates one.
        let signer = EolShutdownAckSigner::new();
        let out = signer.sign(&vid("tenant-x"), &ack_inputs(5)).await.unwrap();
        assert!(
            out.is_none(),
            "fail-closed signer must produce no ack until the bake lands"
        );
    }

    // ── §25 M3 — dest artifact STAGING tests ────────────────────────

    /// Spawn a one-shot HTTP server that serves `body` for a single GET,
    /// returning its `http://127.0.0.1:port/` URL. Dependency-free (a raw
    /// TCP listener) so the staging fetch path is exercised without a new
    /// dev-dependency or a real S3.
    async fn serve_once(body: Vec<u8>, status_line: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Drain the request headers (best-effort).
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let header = format!(
                    "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.flush().await;
            }
        });
        format!("http://{addr}/")
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }

    #[tokio::test]
    async fn fetch_verify_stage_writes_the_artifact_on_a_sha_match() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tenant.vmlinuz");
        let body = b"measured-kernel-bytes".to_vec();
        let url = serve_once(body.clone(), "HTTP/1.1 200 OK").await;
        let artifact = StagedArtifact {
            url,
            sha256_hex: sha256_hex(&body),
        };
        fetch_verify_stage_artifact(&artifact, &out, StagePolicy::Replace)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), body);
        // No stranded `.part` temp file.
        assert!(!out.with_extension("part").exists());
    }

    #[tokio::test]
    async fn fetch_verify_stage_fails_closed_on_a_sha_mismatch() {
        // SECURITY: a sha mismatch means the bytes are NOT the measured
        // artifact — reject BEFORE staging so the dest never boots a
        // measurement the KBS would refuse the KEK for.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tenant.vmlinuz");
        let body = b"tampered-kernel".to_vec();
        let url = serve_once(body, "HTTP/1.1 200 OK").await;
        let artifact = StagedArtifact {
            url,
            // The sha of DIFFERENT bytes — a mismatch.
            sha256_hex: sha256_hex(b"the-real-kernel"),
        };
        let err = fetch_verify_stage_artifact(&artifact, &out, StagePolicy::Replace)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::Migration("dest-artifact-sha-mismatch")
        ));
        // Nothing was staged — not even a `.part`.
        assert!(!out.exists());
        assert!(!out.with_extension("part").exists());
    }

    #[tokio::test]
    async fn fetch_verify_stage_fails_closed_on_a_non_2xx_status() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tenant.vmlinuz");
        let url = serve_once(b"not found".to_vec(), "HTTP/1.1 404 Not Found").await;
        let artifact = StagedArtifact {
            url,
            sha256_hex: sha256_hex(b"whatever"),
        };
        let err = fetch_verify_stage_artifact(&artifact, &out, StagePolicy::Replace)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::Migration("dest-artifact-status")
        ));
        assert!(!out.exists());
    }

    #[tokio::test]
    async fn fetch_verify_stage_rejects_a_malformed_sha() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tenant.vmlinuz");
        let artifact = StagedArtifact {
            url: "http://127.0.0.1:1/".to_string(),
            sha256_hex: "not-a-sha".to_string(),
        };
        let err = fetch_verify_stage_artifact(&artifact, &out, StagePolicy::Replace)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::Migration("dest-artifact-bad-sha")
        ));
    }

    #[tokio::test]
    async fn dest_activate_stages_artifacts_before_the_existence_check() {
        // End-to-end of Part B: the order carries staging descriptors for
        // the kernel + initrd; the dest fetches + verifies + stages them,
        // so the existence check passes and the activation proceeds to the
        // download (which our temp-dir path then fences as
        // `dest-launch-failed`, proving staging ran first).
        //
        // P9/#16: the staged artifacts land in THIS VM's staging dir, not
        // at the paths the order named — see the redirect test below.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle_rooted(dir.path());
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        // Build an order whose artifacts do NOT yet exist on disk.
        let mut order = activate_order(dir.path(), "tenant-x", /*make_artifacts=*/ false);
        // OVMF the launch path measures is operator-staged out-of-band in
        // this harness — pre-create it so only kernel+initrd are staged.
        std::fs::write(&order.ovmf_path, b"ovmf").unwrap();
        let kernel_bytes = b"staged-kernel".to_vec();
        let initrd_bytes = b"staged-initrd".to_vec();
        order.boot_artifacts = Some(DestStagingArtifacts {
            ovmf: None,
            kernel: StagedArtifact {
                url: serve_once(kernel_bytes.clone(), "HTTP/1.1 200 OK").await,
                sha256_hex: sha256_hex(&kernel_bytes),
            },
            initrd: StagedArtifact {
                url: serve_once(initrd_bytes.clone(), "HTTP/1.1 200 OK").await,
                sha256_hex: sha256_hex(&initrd_bytes),
            },
            rootfs_data: None,
            rootfs_hash: None,
        });
        let vm_dir = lifecycle.vm_staging_dir(&order.vm_id);
        let kernel_path = vm_dir.join("tenant.vmlinuz");
        let initrd_path = vm_dir.join("tenant.initrd.img");

        let outcome = activate_dest(&lifecycle, &downloader, &pusher, order).await;

        // The measured artifacts were staged from S3 (so the existence
        // check passed and activation proceeded).
        assert_eq!(std::fs::read(&kernel_path).unwrap(), kernel_bytes);
        assert_eq!(std::fs::read(&initrd_path).unwrap(), initrd_bytes);
        // Activation proceeded past staging to the launch (fenced by the
        // unit-test MINER_ROOT check) — proving staging ran FIRST.
        assert!(matches!(
            outcome,
            Err(MinerAgentError::Migration("dest-launch-failed"))
        ));
    }

    // ── P9/#16: a §25 stage can never clobber a SHARED base image ─────
    //
    // Live evidence this closes (observed on a two-host fleet):
    //   host A — `/var/lib/hippius-miner/rootfs.img` was a REAL
    //     multi-hundred-MB file, byte-identical to a tenant's
    //     `staging/<vm_id>/rootfs.img`. A dest-activation put it there,
    //     because `_launch_paths` resolved `rootfs_data_path` from the
    //     SPEC (whose default is that shared path).
    //   host B — the SAME path is a SYMLINK to `staging/rootfs.img`, the
    //     shared legacy base. The identical order would have followed it
    //     and replaced every legacy VM's base image, in place.
    // Two miners, one spec, different content — and a data-loss event.

    #[tokio::test]
    async fn dest_staging_never_writes_outside_the_per_vm_dir() {
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle_rooted(dir.path());
        let mut order = activate_order(dir.path(), "tenant-x", false);
        // The SHARED, mutable paths a real (older-vali) order carries.
        order.ovmf_path = dir.path().join("ovmf.fd");
        order.kernel_path = dir.path().join("tenant.vmlinuz");
        order.initrd_path = dir.path().join("tenant.initrd.img");
        order.rootfs_data_path = dir.path().join("rootfs.img");
        order.rootfs_hash_path = dir.path().join("rootfs.verity");
        let shared_rootfs = order.rootfs_data_path.clone();
        let shared_verity = order.rootfs_hash_path.clone();
        let shared_ovmf = order.ovmf_path.clone();
        std::fs::write(&shared_rootfs, b"THE SHARED BASE OTHER VMS BOOT").unwrap();
        std::fs::write(&shared_verity, b"THE SHARED VERITY TREE").unwrap();
        std::fs::write(&shared_ovmf, b"THE SHARED OVMF").unwrap();

        let artifact = |body: &[u8]| StagedArtifact {
            url: "http://127.0.0.1:1/".to_string(),
            sha256_hex: sha256_hex(body),
        };
        let staging = DestStagingArtifacts {
            ovmf: Some(artifact(b"new-ovmf")),
            kernel: artifact(b"new-kernel"),
            initrd: artifact(b"new-initrd"),
            rootfs_data: Some(artifact(b"new-rootfs")),
            rootfs_hash: Some(artifact(b"new-verity")),
        };

        let vm_dir = lifecycle.vm_staging_dir(&order.vm_id);
        redirect_staged_paths_into_vm_dir(&staging, &mut order, &vm_dir);

        // Every destination is now under THIS VM's own dir…
        for p in [
            &order.ovmf_path,
            &order.kernel_path,
            &order.initrd_path,
            &order.rootfs_data_path,
            &order.rootfs_hash_path,
        ] {
            assert_eq!(
                p.parent().unwrap(),
                vm_dir,
                "a §25 stage destination escaped the per-VM staging dir: {p:?}"
            );
        }
        // …and the names match what the LAUNCH preflight stages, so §24's
        // reclaim (which sweeps that dir) finds them.
        assert_eq!(order.kernel_path, vm_dir.join("tenant.vmlinuz"));
        assert_eq!(order.initrd_path, vm_dir.join("tenant.initrd.img"));
        assert_eq!(order.rootfs_data_path, vm_dir.join("rootfs.img"));
        assert_eq!(order.rootfs_hash_path, vm_dir.join("rootfs.verity"));
        assert_eq!(order.ovmf_path, vm_dir.join("ovmf.fd"));

        // The shared artifacts are untouched — and, decisively, staging
        // them now cannot reach the shared paths at all.
        assert_eq!(
            std::fs::read(&shared_rootfs).unwrap(),
            b"THE SHARED BASE OTHER VMS BOOT"
        );
        assert_eq!(
            std::fs::read(&shared_verity).unwrap(),
            b"THE SHARED VERITY TREE"
        );
        assert_eq!(std::fs::read(&shared_ovmf).unwrap(), b"THE SHARED OVMF");
    }

    #[test]
    fn dest_staging_leaves_out_of_band_artifacts_where_the_order_named_them() {
        // An artifact with NO descriptor is pre-staged out of band (the
        // operator-provisioned OVMF is the live case). We do not write it,
        // so we must not move it either — the existence check would fail
        // and a perfectly good migration would break.
        let dir = tempfile::tempdir().unwrap();
        let mut order = activate_order(dir.path(), "tenant-x", false);
        let out_of_band_ovmf = dir.path().join("operator-staged-ovmf.fd");
        order.ovmf_path = out_of_band_ovmf.clone();
        let out_of_band_rootfs = dir.path().join("prestaged-rootfs.img");
        order.rootfs_data_path = out_of_band_rootfs.clone();

        let staging = DestStagingArtifacts {
            ovmf: None,
            kernel: StagedArtifact {
                url: "http://127.0.0.1:1/".to_string(),
                sha256_hex: sha256_hex(b"k"),
            },
            initrd: StagedArtifact {
                url: "http://127.0.0.1:1/".to_string(),
                sha256_hex: sha256_hex(b"i"),
            },
            rootfs_data: None,
            rootfs_hash: None,
        };
        redirect_staged_paths_into_vm_dir(&staging, &mut order, &dir.path().join("staging/vm"));

        assert_eq!(order.ovmf_path, out_of_band_ovmf);
        assert_eq!(order.rootfs_data_path, out_of_band_rootfs);
        // Only what we STAGE is redirected.
        assert_eq!(
            order.kernel_path,
            dir.path().join("staging/vm/tenant.vmlinuz")
        );
    }

    #[tokio::test]
    async fn dest_staging_refuses_to_rewrite_a_live_domains_artifacts() {
        // `stage_dest_artifacts` runs BEFORE this handler's live-domain
        // check (the existence gate depends on it), so a re-driven
        // activate used to re-download multi-GB artifacts straight over a
        // booted guest's dm-verity base.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("staging/vm/rootfs.img");
        std::fs::create_dir_all(out.parent().unwrap()).unwrap();
        std::fs::write(&out, b"the-base-the-running-guest-boots").unwrap();

        let replacement = b"a-different-base".to_vec();
        let artifact = StagedArtifact {
            url: serve_once(replacement.clone(), "HTTP/1.1 200 OK").await,
            sha256_hex: sha256_hex(&replacement),
        };
        let err = fetch_verify_stage_artifact(&artifact, &out, StagePolicy::PinnedByLiveVm)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::Migration("dest-artifact-in-use")
        ));
        assert_eq!(
            std::fs::read(&out).unwrap(),
            b"the-base-the-running-guest-boots"
        );
    }

    #[tokio::test]
    async fn dest_staging_is_a_no_op_when_the_artifact_is_already_correct() {
        // The legitimate re-drive: identical bytes. Must succeed WITHOUT a
        // re-download (the URL is unreachable, so success proves it) —
        // otherwise the live-domain refusal above would break every retry.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("staging/vm/rootfs.img");
        std::fs::create_dir_all(out.parent().unwrap()).unwrap();
        let body = b"exactly-the-artifact-this-order-names".to_vec();
        std::fs::write(&out, &body).unwrap();

        let artifact = StagedArtifact {
            url: "http://127.0.0.1:1/".to_string(),
            sha256_hex: sha256_hex(&body),
        };
        fetch_verify_stage_artifact(&artifact, &out, StagePolicy::PinnedByLiveVm)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), body);
    }

    #[tokio::test]
    async fn dest_activate_fails_closed_when_a_staged_artifact_sha_mismatches() {
        // A tampered staged artifact aborts the activation at the sha
        // verify — the dest never even downloads the snapshot.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = test_lifecycle();
        let downloader = MockDownloader::ok();
        let pusher = MockTicketPusher::new();
        let mut order = activate_order(dir.path(), "tenant-x", false);
        std::fs::write(&order.ovmf_path, b"ovmf").unwrap();
        let kernel_bytes = b"staged-kernel".to_vec();
        order.boot_artifacts = Some(DestStagingArtifacts {
            ovmf: None,
            kernel: StagedArtifact {
                url: serve_once(kernel_bytes, "HTTP/1.1 200 OK").await,
                sha256_hex: sha256_hex(b"DIFFERENT-bytes"),
            },
            initrd: StagedArtifact {
                url: "http://127.0.0.1:1/".to_string(),
                sha256_hex: sha256_hex(b"never-reached"),
            },
            rootfs_data: None,
            rootfs_hash: None,
        });

        let err = activate_dest(&lifecycle, &downloader, &pusher, order)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::Migration("dest-artifact-sha-mismatch")
        ));
        // The snapshot was NEVER pulled for a mis-staged dest.
        assert!(downloader.calls().is_empty());
    }
}
