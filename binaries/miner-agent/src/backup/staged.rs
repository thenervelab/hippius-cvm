//! Staged restores: rebuild a backup point NEXT TO a VM's live disks,
//! swap it in only when vali says so, and keep the original until the
//! restored guest has proven itself.
//!
//! The `restore` order has three ops, all keyed on vali's `restore_id`
//! (32 lower-case hex, one per restore attempt):
//!
//! - `stage` — download + verify + rebuild the chain into
//!   `<data_root>/backup/<vm>/restore/<id>/{overlay.img,state.raw}` on a
//!   background task, while the original keeps running. Never touches a
//!   live path. Idempotent per id; one staging per VM at a time.
//! - `abort` — put everything back: force the restored guest down if it
//!   is running (only a domain whose marker says `staged:<id>`), rename
//!   the retained `*.pre-restore-<id>` originals back over the live
//!   paths, drop the staging dir.
//! - `reclaim` — the restore held: delete the retained originals and the
//!   staging dir. Refused unless the live marker is `staged:<id>`, so it
//!   can never delete the only copy.
//!
//! The swap itself is `migrate-activate` with `staged_restore_id`
//! ([`swap_in`]): rename the live overlay and state disk aside to
//! `*.pre-restore-<id>`, move the staged files in, write the marker
//! `staged:<id>`, then the normal launch. Every step is a rename or a
//! re-copy of the 1 MiB state disk, fsynced, and every step is
//! re-entrant: a crash anywhere leaves a state the same swap (or an
//! abort) completes.
//!
//! Every path is derived from the VM id and the restore id alone —
//! nothing is ever globbed, and nothing outside the VM's own overlay,
//! state disk, marker and `backup/<vm>/restore/` dir is ever touched
//! (never a shared base image, rootfs or OVMF).
//!
//! The per-VM record `backup/<vm>/restore/status.json` survives an agent
//! restart: a staging interrupted by one is reported `failed`
//! (`agent-restart`), and vali re-sends `stage`.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::capture::SpaceLedger;
use super::restore::{self, FetchOpts, PieceFetcher, RestoreChain, Target};
use crate::error::{MinerAgentError, Result};
use crate::lifecycle::state_disk::STATE_DISK_BYTES;
use crate::lifecycle::{CvmLifecycle, DomainLiveness, VmId};
use crate::orders::migration::{restore_marker_path, MigrationPhase, MigrationStore};

/// The per-VM restore dir under `backup/<vm>/`.
pub const RESTORE_DIR_NAME: &str = "restore";

const STATUS_FILE: &str = "status.json";
const STATUS_TMP: &str = ".status.json.tmp";
const STAGED_OVERLAY: &str = "overlay.img";
const STAGED_STATE: &str = "state.raw";
const WORK_DIR: &str = "work";

/// How long an abort waits for a cancelled staging to stop writing.
const CANCEL_WAIT: Duration = Duration::from_secs(60);

/// Stagings in flight per host, across VMs: a staging is disk- and
/// network-bound, and the host's tenants share both.
pub const MAX_CONCURRENT_STAGINGS: usize = 2;

/// Wall-clock bound on one staging — the longest presigned-URL TTL vali
/// hands out. Past it the URLs are dead anyway.
const STAGE_TIMEOUT: Duration = Duration::from_secs(12 * 3600);

/// Serializes every restore file operation on this host: a stage's
/// start, an abort, a reclaim, a `migrate-activate` swap — and a staged
/// activation's entry into `Activating` — never interleave.
static RESTORE_OPS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Hold the restore lock (see [`RESTORE_OPS`]) — for a staged
/// `migrate-activate` entering `Activating`, so no abort or reclaim
/// checks the phase in between.
pub async fn restore_lock() -> tokio::sync::MutexGuard<'static, ()> {
    RESTORE_OPS.lock().await
}

/// A `restore_id`: exactly 32 lower-case hex characters.
pub fn check_restore_id(id: &str) -> Result<()> {
    if id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(MinerAgentError::Backup("restore-bad-id"))
    }
}

/// The overlay marker a swapped-in restore leaves: `staged:<id>`.
pub fn staged_marker(restore_id: &str) -> String {
    format!("staged:{restore_id}")
}

/// A `restore` order's op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RestoreOp {
    /// Download + rebuild into the staging dir.
    Stage,
    /// Undo the restore; keep the original.
    Abort,
    /// Keep the restore; delete the original.
    Reclaim,
}

/// Where a restore of a VM stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RestoreState {
    /// Downloading / rebuilding.
    Staging,
    /// Rebuilt and verified; ready to swap in (or already swapped —
    /// see [`RestoreStatus::swapped`]).
    Staged,
    /// The staging failed (`reason`); nothing live was touched.
    Failed,
    /// Aborted: the original is back, the staging is gone.
    Aborted,
    /// Reclaimed: the restore holds, the original is gone.
    Reclaimed,
}

/// The staged overlay's identity at the moment staging finished: proof,
/// at swap time, that a file currently named `overlay.img` (or currently
/// the live overlay) really is the one this record's chain rebuilt —
/// not the same path coincidentally repopulated by something else, or a
/// live overlay that never got swapped at all. A rename preserves the
/// inode, so this survives the swap's own `staged_overlay -> live_overlay`
/// move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct StagedOverlayStat {
    /// Inode number.
    ino: u64,
    /// Device id — an inode number alone is only unique per filesystem.
    dev: u64,
    /// Length in bytes.
    size: u64,
}

/// The persisted per-VM record (`backup/<vm>/restore/status.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    restore_id: String,
    op: RestoreOp,
    state: RestoreState,
    bytes_done: u64,
    bytes_total: u64,
    reason: Option<String>,
    /// The staged overlay's identity once staging reached `Staged`.
    /// `None` for a record an older agent wrote, or before staging
    /// finished — [`swap_in`] falls back to a weaker (but still safe)
    /// check for those. `serde(default)` so an older agent's on-disk
    /// record still parses across an upgrade.
    #[serde(default)]
    staged_overlay_stat: Option<StagedOverlayStat>,
}

impl StagedOverlayStat {
    /// Stat `path` (must exist) into a record identity.
    async fn of(path: &Path) -> Result<Self> {
        let m = tokio::fs::metadata(path)
            .await
            .map_err(|_| MinerAgentError::Backup("restore-stat"))?;
        Ok(Self {
            ino: m.ino(),
            dev: m.dev(),
            size: m.len(),
        })
    }
}

/// What `GET /v1/miner/restore/{vm_id}/status` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestoreStatus {
    /// The VM.
    pub vm_id: String,
    /// The latest restore of the VM this host knows of.
    pub restore_id: String,
    /// The last op applied to it.
    pub op: RestoreOp,
    /// Where it stands.
    pub state: RestoreState,
    /// Bytes downloaded so far (all of them once staged).
    pub bytes_done: u64,
    /// Bytes the chain downloads in all.
    pub bytes_total: u64,
    /// Why it failed (a static class), else `null`.
    pub reason: Option<String>,
    /// The live overlay's marker is `staged:<restore_id>`: the restored
    /// disks are the live ones.
    pub swapped: bool,
    /// A retained original (`*.pre-restore-<restore_id>`) is on disk.
    pub pre_restore_present: bool,
    /// The VM's domain is running on this host.
    pub domain_live: bool,
}

/// [`RestoreManager::peek`]'s answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peek {
    /// The latest restore's id.
    pub restore_id: String,
    /// Its persisted state.
    pub state: RestoreState,
    /// Its disks are the live ones.
    pub swapped: bool,
}

/// Why [`RestoreManager::status`] has no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusError {
    /// libvirt cannot be asked whether the domain runs; retry.
    Unavailable,
}

/// Every path one restore of one VM touches — derived from the VM's live
/// paths and the restore id, nothing else.
#[derive(Debug, Clone)]
pub struct RestorePaths {
    /// The golden overlay the domain boots (`overlay/<vm>.img`).
    pub live_overlay: PathBuf,
    /// The state disk (`state/<vm>.raw`).
    pub live_state: PathBuf,
    /// The overlay's `.restored-from` marker.
    pub marker: PathBuf,
    /// `<overlay>.pre-restore-<id>`.
    pub pre_overlay: PathBuf,
    /// `<state>.pre-restore-<id>`.
    pub pre_state: PathBuf,
    /// `<marker>.pre-restore-<id>` — the marker the original ran under.
    pub pre_marker: PathBuf,
    /// `backup/<vm>/restore` (holds the record).
    pub restore_root: PathBuf,
    /// `backup/<vm>/restore/<id>`.
    pub staging_dir: PathBuf,
    /// `backup/<vm>/restore/<id>/overlay.img`.
    pub staged_overlay: PathBuf,
    /// `backup/<vm>/restore/<id>/state.raw`.
    pub staged_state: PathBuf,
    /// `backup/<vm>/restore/<id>/work` — the rebuild's scratch dir.
    pub work_dir: PathBuf,
}

impl RestorePaths {
    /// The paths of restore `restore_id` (already validated) of the VM
    /// whose overlay, state disk and backup dir are given.
    pub fn new(
        live_overlay: &Path,
        live_state: &Path,
        vm_backup_dir: &Path,
        restore_id: &str,
    ) -> Self {
        let suffix = format!(".pre-restore-{restore_id}");
        let marker = restore_marker_path(live_overlay);
        let restore_root = vm_backup_dir.join(RESTORE_DIR_NAME);
        let staging_dir = restore_root.join(restore_id);
        Self {
            live_overlay: live_overlay.to_path_buf(),
            live_state: live_state.to_path_buf(),
            pre_overlay: restore::sibling(live_overlay, &suffix),
            pre_state: restore::sibling(live_state, &suffix),
            pre_marker: restore::sibling(&marker, &suffix),
            marker,
            staged_overlay: staging_dir.join(STAGED_OVERLAY),
            staged_state: staging_dir.join(STAGED_STATE),
            work_dir: staging_dir.join(WORK_DIR),
            staging_dir,
            restore_root,
        }
    }

    /// [`Self::new`] from the lifecycle's own roots.
    pub fn for_vm(lifecycle: &CvmLifecycle, vm_id: &VmId, restore_id: &str) -> Self {
        Self::new(
            &lifecycle.golden_overlay_path(vm_id),
            &lifecycle.state_disk_path(vm_id),
            &lifecycle.backup_dir(vm_id),
            restore_id,
        )
    }
}

/// The retained originals of the restore `vm_backup_dir`'s record names
/// (for the §24 reclaim): its `*.pre-restore-<id>` overlay, state disk
/// and marker. Empty when there is no (valid) record.
pub fn retained_files(
    vm_backup_dir: &Path,
    live_overlay: &Path,
    live_state: &Path,
) -> Vec<PathBuf> {
    let Some(rec) = read_record_sync(&vm_backup_dir.join(RESTORE_DIR_NAME)) else {
        return Vec::new();
    };
    let p = RestorePaths::new(live_overlay, live_state, vm_backup_dir, &rec.restore_id);
    vec![p.pre_overlay, p.pre_state, p.pre_marker]
}

fn parse_record(raw: &[u8]) -> Option<Record> {
    let rec: Record = serde_json::from_slice(raw).ok()?;
    check_restore_id(&rec.restore_id).ok()?;
    Some(rec)
}

fn read_record_sync(restore_root: &Path) -> Option<Record> {
    parse_record(&std::fs::read(restore_root.join(STATUS_FILE)).ok()?)
}

async fn read_record(restore_root: &Path) -> Option<Record> {
    parse_record(&tokio::fs::read(restore_root.join(STATUS_FILE)).await.ok()?)
}

/// Write the record durably (temp + fsync + rename + dir fsync).
async fn write_record(restore_root: &Path, rec: &Record) -> Result<()> {
    let io = |_| MinerAgentError::Backup("restore-record");
    tokio::fs::create_dir_all(restore_root).await.map_err(io)?;
    let body = serde_json::to_vec(rec).map_err(|_| MinerAgentError::Backup("restore-record"))?;
    let tmp = restore_root.join(STATUS_TMP);
    write_durable(&tmp, &body).await.map_err(io)?;
    tokio::fs::rename(&tmp, restore_root.join(STATUS_FILE))
        .await
        .map_err(io)?;
    restore::sync_dir(restore_root).await
}

async fn write_durable(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut f = tokio::fs::File::create(path).await?;
    f.write_all(body).await?;
    f.flush().await?;
    f.sync_all().await
}

/// The overlay marker's content, trimmed; `None` if absent/unreadable.
async fn read_marker(path: &Path) -> Option<String> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    Some(raw.trim().to_string())
}

/// Whether `path` names an entry (a dangling symlink counts).
async fn present(path: &Path) -> Result<bool> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(MinerAgentError::Backup("restore-stat")),
    }
}

async fn rename(from: &Path, to: &Path, class: &'static str) -> Result<()> {
    tokio::fs::rename(from, to)
        .await
        .map_err(|_| MinerAgentError::Backup(class))
}

/// Remove a file by its exact path; absent is success.
async fn remove_file(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(MinerAgentError::Backup("restore-remove")),
    }
}

/// Remove a staging dir by its exact path; absent is success. Refuses a
/// symlink (never deletes through one).
async fn remove_staging(dir: &Path) -> Result<()> {
    match tokio::fs::symlink_metadata(dir).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(MinerAgentError::Backup("restore-remove")),
        Ok(m) if m.file_type().is_symlink() => Err(MinerAgentError::Backup("restore-remove")),
        Ok(_) => tokio::fs::remove_dir_all(dir)
            .await
            .map_err(|_| MinerAgentError::Backup("restore-remove")),
    }
}

async fn sync_parent(path: &Path) -> Result<()> {
    match path.parent() {
        Some(dir) => restore::sync_dir(dir).await,
        None => Err(MinerAgentError::Backup("dir-sync")),
    }
}

#[cfg(test)]
thread_local! {
    /// Test hook: the step [`crash_point`] fails at (0 = never).
    pub(crate) static CRASH_AT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Test hook: simulate the agent dying right after step `n` of a swap or
/// an abort. A no-op outside tests.
#[cfg(test)]
fn crash_point(n: u32) -> Result<()> {
    if CRASH_AT.with(std::cell::Cell::get) == n {
        return Err(MinerAgentError::Backup("test-crash"));
    }
    Ok(())
}

#[cfg(not(test))]
#[inline]
fn crash_point(_n: u32) -> Result<()> {
    Ok(())
}

/// What [`swap_in`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapOutcome {
    /// The staged disks are now the live ones.
    Swapped,
    /// They already were (the marker says `staged:<id>`).
    AlreadySwapped,
}

/// `p.staged_overlay`, if present, must be `rec`'s staged overlay: same
/// (dev, ino) as staging recorded (a rename preserves both, so this
/// still holds after step (2) has moved it — callers only ask this
/// while it is still at its staged path). Identity, not size:
/// `expected_size` is the separate, existing authority on size. A
/// record with no recorded identity (an older agent) trusts presence
/// alone, same as before this check existed.
async fn staged_overlay_is(p: &RestorePaths, rec: &Record) -> Result<()> {
    let Some(want_stat) = rec.staged_overlay_stat else {
        return Ok(());
    };
    let m = tokio::fs::metadata(&p.staged_overlay)
        .await
        .map_err(|_| MinerAgentError::Migration("restore-stat"))?;
    if m.dev() != want_stat.dev || m.ino() != want_stat.ino {
        return Err(MinerAgentError::Migration("restore-staged-missing"));
    }
    Ok(())
}

/// Whether `p.live_overlay` already IS `rec`'s staged overlay — i.e.
/// step (2) already ran, this call or an earlier crashed one — proven
/// from the identity staging recorded (a rename preserves the inode),
/// not merely inferred from the staged overlay's absence: see the
/// module docs and [`swap_in`]'s BUG-1 history for why presence alone
/// is not enough. `expected_size`, when known, must also match.
///
/// For a record an older agent wrote (no inode): falls back to the
/// weaker but still safe proof that BOTH halves of steps (1)+(2) have
/// already run — the original's overlay AND its marker moved aside.
/// Anything less (staged merely absent, original untouched) is refused
/// rather than guessed at.
async fn overlay_already_swapped(
    p: &RestorePaths,
    rec: &Record,
    expected_size: Option<u64>,
) -> Result<bool> {
    let mig = |c: &'static str| move |_: MinerAgentError| MinerAgentError::Migration(c);
    match rec.staged_overlay_stat {
        Some(want_stat) => {
            if !present(&p.live_overlay)
                .await
                .map_err(mig("restore-stat"))?
            {
                return Ok(false);
            }
            let m = tokio::fs::metadata(&p.live_overlay)
                .await
                .map_err(|_| MinerAgentError::Migration("restore-stat"))?;
            if m.dev() != want_stat.dev || m.ino() != want_stat.ino {
                return Ok(false);
            }
            if let Some(want_len) = expected_size {
                if m.len() != want_len {
                    return Err(MinerAgentError::Migration("restore-size-mismatch"));
                }
            }
            Ok(true)
        }
        None => {
            let pre_overlay = present(&p.pre_overlay).await.map_err(mig("restore-stat"))?;
            let pre_marker = present(&p.pre_marker).await.map_err(mig("restore-stat"))?;
            Ok(pre_overlay && pre_marker)
        }
    }
}

/// Swap restore `restore_id`'s staged disks in (the `migrate-activate`
/// half). `domain_down` is awaited under the restore lock, right before
/// any rename, and must prove the domain DOWN (`restore-vm-live`
/// otherwise). `expected_size`, when known (the measured
/// `hippius.disk_gb=`), must be the staged overlay's size.
///
/// Re-entrant at every step; see the module docs. Errors are
/// `migration/…` classes (they surface on the activation's status).
pub async fn swap_in(
    p: &RestorePaths,
    restore_id: &str,
    expected_size: Option<u64>,
    domain_down: impl std::future::Future<Output = bool>,
) -> Result<SwapOutcome> {
    let _ops = RESTORE_OPS.lock().await;
    let want = staged_marker(restore_id);
    if read_marker(&p.marker).await.as_deref() == Some(want.as_str()) {
        return Ok(SwapOutcome::AlreadySwapped);
    }
    let rec = match read_record(&p.restore_root).await {
        Some(r) if r.restore_id == restore_id && r.state == RestoreState::Staged => r,
        _ => return Err(MinerAgentError::Migration("restore-not-staged")),
    };
    let mig = |c: &'static str| move |_: MinerAgentError| MinerAgentError::Migration(c);
    let swap_io = |_: std::io::Error| MinerAgentError::Migration("restore-swap-io");

    // Before step (1) touches anything: on a same-host restore, "the
    // staged overlay vanished before the move" and "the move already
    // happened, on a resend after a crash" both look like "staged
    // absent, live present" from file presence alone — and the wrong
    // read of that (treating it as already moved) launches the ORIGINAL
    // disk while still reporting `Swapped` (see the module docs). Prove
    // it instead, from the identity staging recorded — and, since
    // nothing but this single-flight `RESTORE_OPS` lock stands between
    // this check and step (2)'s own rename, [`overlay_already_swapped`]
    // is re-run FRESH at step (2)'s decision point below rather than
    // trusted from here: this upfront check only buys an early,
    // side-effect-free refusal for the common case.
    if present(&p.staged_overlay)
        .await
        .map_err(mig("restore-stat"))?
    {
        staged_overlay_is(p, &rec).await?;
    } else if !overlay_already_swapped(p, &rec, expected_size).await? {
        return Err(MinerAgentError::Migration("restore-staged-missing"));
    }

    if !domain_down.await {
        return Err(MinerAgentError::Migration("restore-vm-live"));
    }
    if let Some(want_len) = expected_size {
        if present(&p.staged_overlay)
            .await
            .map_err(mig("restore-stat"))?
        {
            let len = tokio::fs::metadata(&p.staged_overlay)
                .await
                .map(|m| m.len())
                .map_err(|_| MinerAgentError::Migration("restore-stat"))?;
            if len != want_len {
                return Err(MinerAgentError::Migration("restore-size-mismatch"));
            }
        }
    }
    let staged_state = tokio::fs::read(&p.staged_state)
        .await
        .map_err(|_| MinerAgentError::Migration("restore-staged-missing"))?;
    if staged_state.len() as u64 != STATE_DISK_BYTES {
        return Err(MinerAgentError::Migration("restore-staged-missing"));
    }

    // (1) Keep the marker the original ran under, so an abort puts it
    //     back. Both present means something wrote a marker mid-swap:
    //     refuse rather than guess which is the original's.
    if present(&p.marker).await.map_err(mig("restore-stat"))? {
        if present(&p.pre_marker).await.map_err(mig("restore-stat"))? {
            return Err(MinerAgentError::Migration("restore-swap-conflict"));
        }
        tokio::fs::rename(&p.marker, &p.pre_marker)
            .await
            .map_err(swap_io)?;
        sync_parent(&p.marker)
            .await
            .map_err(mig("restore-swap-io"))?;
        crash_point(1)?;
    }

    // (2) The overlay: the original aside, the staged one in. Gated on
    //     the staged file still being there — once it has moved, this
    //     step is done. Re-verified fresh right here (not from the
    //     upfront check above, which only covers the common case): the
    //     only thing between that check and here is step (1)'s own
    //     rename, but nothing stops an external actor from deleting the
    //     staged overlay in that window too, and this decision is where
    //     it actually matters.
    if present(&p.staged_overlay)
        .await
        .map_err(mig("restore-stat"))?
    {
        staged_overlay_is(p, &rec).await?;
        if present(&p.live_overlay)
            .await
            .map_err(mig("restore-stat"))?
        {
            if present(&p.pre_overlay).await.map_err(mig("restore-stat"))? {
                return Err(MinerAgentError::Migration("restore-swap-conflict"));
            }
            tokio::fs::rename(&p.live_overlay, &p.pre_overlay)
                .await
                .map_err(swap_io)?;
            // Durable before anything replaces the live name.
            sync_parent(&p.pre_overlay)
                .await
                .map_err(mig("restore-swap-io"))?;
            crash_point(2)?;
        }
        if let Some(dir) = p.live_overlay.parent() {
            tokio::fs::create_dir_all(dir)
                .await
                .map_err(|_| MinerAgentError::Migration("restore-swap-io"))?;
        }
        tokio::fs::rename(&p.staged_overlay, &p.live_overlay)
            .await
            .map_err(swap_io)?;
        sync_parent(&p.live_overlay)
            .await
            .map_err(mig("restore-swap-io"))?;
        restore::sync_dir(&p.staging_dir)
            .await
            .map_err(mig("restore-swap-io"))?;
        crash_point(3)?;
    } else if !overlay_already_swapped(p, &rec, expected_size).await? {
        return Err(MinerAgentError::Migration("restore-staged-missing"));
    }

    // (3) The state disk: the original aside (unless it already holds
    //     exactly the staged bytes — nothing to keep then), a COPY of the
    //     staged one in (the state root may be another filesystem, and
    //     the staged copy stays until reclaim/abort). Re-copying is
    //     harmless, so no gate is needed.
    if present(&p.live_state).await.map_err(mig("restore-stat"))?
        && !present(&p.pre_state).await.map_err(mig("restore-stat"))?
    {
        let live = tokio::fs::read(&p.live_state)
            .await
            .map_err(|_| MinerAgentError::Migration("restore-swap-io"))?;
        if live != staged_state {
            tokio::fs::rename(&p.live_state, &p.pre_state)
                .await
                .map_err(swap_io)?;
            sync_parent(&p.pre_state)
                .await
                .map_err(mig("restore-swap-io"))?;
            crash_point(4)?;
        }
    }
    if let Some(dir) = p.live_state.parent() {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|_| MinerAgentError::Migration("restore-swap-io"))?;
    }
    // `state.raw` is the boot-counter / anti-rollback disk the KBS checks
    // on every attestation — not a scratch file. Losing it bricks the VM
    // (no recovery: see the state-disk-is-a-SPOF discipline elsewhere in
    // this codebase), so it is written to a `.restore-part` sibling and
    // fsynced BEFORE the rename ever touches the live name, the same
    // write-durable-then-rename discipline every other file in this swap
    // uses — never a plain in-place overwrite of `p.live_state`.
    let part = restore::sibling(&p.live_state, ".restore-part");
    write_durable(&part, &staged_state)
        .await
        .map_err(|_| MinerAgentError::Migration("restore-swap-io"))?;
    tokio::fs::rename(&part, &p.live_state)
        .await
        .map_err(swap_io)?;
    sync_parent(&p.live_state)
        .await
        .map_err(mig("restore-swap-io"))?;
    crash_point(5)?;

    // (4) The marker last: from here on the swap is done.
    write_durable(&p.marker, want.as_bytes())
        .await
        .map_err(|_| MinerAgentError::Migration("restore-swap-io"))?;
    sync_parent(&p.marker)
        .await
        .map_err(mig("restore-swap-io"))?;
    Ok(SwapOutcome::Swapped)
}

/// Undo restore `restore_id` on disk: the marker first (so a reclaim can
/// no longer pass its check), then the retained originals back over the
/// live paths, then the staging dir. The caller has proven nothing runs
/// on the paths it renames. Re-entrant.
async fn abort_files(p: &RestorePaths, restore_id: &str) -> Result<()> {
    if present(&p.pre_marker).await? {
        rename(&p.pre_marker, &p.marker, "restore-abort-io").await?;
        sync_parent(&p.marker).await?;
        crash_point(11)?;
    } else if read_marker(&p.marker).await.as_deref() == Some(staged_marker(restore_id).as_str()) {
        remove_file(&p.marker).await?;
        sync_parent(&p.marker).await?;
        crash_point(11)?;
    }
    if present(&p.pre_overlay).await? {
        rename(&p.pre_overlay, &p.live_overlay, "restore-abort-io").await?;
        sync_parent(&p.live_overlay).await?;
        crash_point(12)?;
    }
    if present(&p.pre_state).await? {
        rename(&p.pre_state, &p.live_state, "restore-abort-io").await?;
        sync_parent(&p.live_state).await?;
        crash_point(13)?;
    }
    remove_staging(&p.staging_dir).await
}

/// Delete restore `restore_id`'s retained originals and staging dir —
/// only while the live marker says the restored disks are the live ones.
async fn reclaim_files(p: &RestorePaths, restore_id: &str) -> Result<()> {
    if read_marker(&p.marker).await.as_deref() != Some(staged_marker(restore_id).as_str()) {
        return Err(MinerAgentError::Backup("restore-reclaim-refused"));
    }
    remove_file(&p.pre_overlay).await?;
    remove_file(&p.pre_state).await?;
    remove_file(&p.pre_marker).await?;
    remove_staging(&p.staging_dir).await
}

/// A validated `stage` request.
///
/// Not `Debug`: the chain holds presigned URLs.
pub struct StageRequest {
    /// The VM.
    pub vm_id: VmId,
    /// vali's restore id.
    pub restore_id: String,
    /// The point to rebuild.
    pub chain: RestoreChain,
    /// The full's expected size (the VM's disk size).
    pub disk_bytes: u64,
    /// Parallel ranged GETs per piece.
    pub streams: usize,
}

/// A staging registered by [`RestoreManager::begin_stage`], to be run by
/// [`RestoreManager::run_stage`].
pub struct StageJob {
    vm_id: VmId,
    restore_id: String,
    paths: RestorePaths,
    chain: RestoreChain,
    disk_bytes: u64,
    bytes_total: u64,
    opts: FetchOpts,
    cancel: CancellationToken,
    done: tokio::sync::watch::Sender<bool>,
    ratchet: Arc<Ratchet>,
}

/// What [`RestoreManager::begin_stage`] decided.
pub enum StageStart {
    /// A new staging; run it.
    Started(Box<StageJob>),
    /// This restore is already staging.
    Staging,
    /// This restore is already staged.
    Staged,
}

struct Running {
    restore_id: String,
    cancel: CancellationToken,
    done: tokio::sync::watch::Receiver<bool>,
    progress: Arc<AtomicU64>,
    ratchet: Arc<Ratchet>,
}

/// A byte counter that only ever reports non-decreasing values. The
/// transfer layer's raw progress counter legitimately dips when a range
/// — or, without recorded part shas, a whole piece — is retried from
/// scratch (see `transfer::download_ranged`'s rollback): a failed
/// attempt takes its bytes back before trying again. A restore's
/// reported "Preparing N%" must never go backwards for that, so every
/// reader of the raw counter goes through [`Self::report`] instead of
/// loading it directly.
#[derive(Default)]
struct Ratchet(AtomicU64);

impl Ratchet {
    /// The highest value ever reported so far, updated to `raw` first if
    /// `raw` is higher.
    fn report(&self, raw: u64) -> u64 {
        self.0.fetch_max(raw, Ordering::Relaxed).max(raw)
    }
}

/// How often [`RestoreManager::run_stage`] persists live progress into
/// the durable record at the most, absent a bigger jump (see
/// [`DEFAULT_PERSIST_BYTES`]) — so a reader with no live process to ask
/// (or `status()` itself, should the in-memory map ever be unavailable)
/// still sees real motion on a large piece well before it finishes.
const DEFAULT_PERSIST_INTERVAL: Duration = Duration::from_secs(2);

/// How many more bytes land before [`RestoreManager::run_stage`]
/// persists progress early, without waiting for
/// [`DEFAULT_PERSIST_INTERVAL`].
const DEFAULT_PERSIST_BYTES: u64 = 256 << 20;

/// How often this loop itself wakes up to check whether `interval` or
/// `bytes` has been crossed — never coarser than `interval` (a test
/// passing a tiny `interval` still gets fine-grained wakeups).
const PERSIST_POLL: Duration = Duration::from_millis(200);

/// Runs beside a staging (see [`RestoreManager::run_stage`]): writes
/// `progress`'s current value into the durable record once at least
/// `interval` has passed, or sooner once `bytes` more have landed since
/// the last write — never more often than that, so a fast transfer does
/// not turn into an fsync storm. Reports through `ratchet`, so a value
/// dipping while a range or piece is retried from scratch never regresses
/// what was already persisted. Best-effort: a write failure here is
/// silently retried on the next tick and never fails the stage; the
/// caller aborts this task once the stage itself returns, before writing
/// the terminal record, so this never races it.
/// [`persist_progress`]'s inputs, bundled to keep the function's own
/// arg count sane.
struct PersistArgs {
    restore_root: PathBuf,
    restore_id: String,
    bytes_total: u64,
    progress: Arc<AtomicU64>,
    ratchet: Arc<Ratchet>,
    interval: Duration,
    bytes: u64,
    /// Cancelled to ask this loop to exit — checked only between
    /// iterations (a write already in flight when it fires is left to
    /// finish normally; see the call site in
    /// [`RestoreManager::run_stage`] for why that matters).
    stop: CancellationToken,
}

async fn persist_progress(args: PersistArgs) {
    let PersistArgs {
        restore_root,
        restore_id,
        bytes_total,
        progress,
        ratchet,
        interval,
        bytes,
        stop,
    } = args;
    let poll = interval.min(PERSIST_POLL).max(Duration::from_millis(1));
    let mut last_written = 0u64;
    let mut last_write_at = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep(poll) => {}
        }
        let done = ratchet
            .report(progress.load(Ordering::Relaxed))
            .min(bytes_total);
        if done <= last_written {
            continue;
        }
        if last_write_at.elapsed() < interval && done.saturating_sub(last_written) < bytes {
            continue;
        }
        let rec = Record {
            restore_id: restore_id.clone(),
            op: RestoreOp::Stage,
            state: RestoreState::Staging,
            bytes_done: done,
            bytes_total,
            reason: None,
            staged_overlay_stat: None,
        };
        if write_record(&restore_root, &rec).await.is_ok() {
            last_written = done;
            last_write_at = tokio::time::Instant::now();
        }
    }
}

/// Owns the staged restores of this host.
pub struct RestoreManager {
    fetcher: Arc<dyn PieceFetcher>,
    space: Arc<SpaceLedger>,
    headroom_bytes: u64,
    persist_interval: Duration,
    persist_bytes: u64,
    running: Mutex<HashMap<VmId, Running>>,
}

impl RestoreManager {
    /// Stage through `fetcher`, reserving in `space` (the ledger backups
    /// and chain restores share) with the standard headroom.
    pub fn new(fetcher: Arc<dyn PieceFetcher>, space: Arc<SpaceLedger>) -> Self {
        Self {
            fetcher,
            space,
            headroom_bytes: super::capture::SPACE_RESERVE_BYTES,
            persist_interval: DEFAULT_PERSIST_INTERVAL,
            persist_bytes: DEFAULT_PERSIST_BYTES,
            running: Mutex::new(HashMap::new()),
        }
    }

    /// Override the free-space headroom (tests).
    pub fn with_headroom(mut self, headroom_bytes: u64) -> Self {
        self.headroom_bytes = headroom_bytes;
        self
    }

    /// Override the progress-persistence cadence (tests).
    pub fn with_persist_cadence(mut self, interval: Duration, bytes: u64) -> Self {
        self.persist_interval = interval;
        self.persist_bytes = bytes;
        self
    }

    fn running_lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<VmId, Running>>> {
        self.running
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)
    }

    /// Cancel and await any restore staging in flight for `vm_id` —
    /// whichever restore it is, since a §24 `destroy` does not know or
    /// care which one. Mirrors [`Self::abort`]'s own cancellation step:
    /// run OUTSIDE the restore lock (the wait can be long — a qcow2
    /// apply runs to its end — and the lock is host-wide) and, critically,
    /// BEFORE anything on disk is reclaimed. Without this, `destroy`
    /// wiping `backup/<vm>/` races a still-running [`Self::run_stage`],
    /// which then recreates `backup/<vm>/restore/status.json` for a VM
    /// that no longer exists — a leak with no other cleanup path.
    ///
    /// A no-op if nothing is staging. `run_stage`'s own belt-and-braces
    /// check (it skips its terminal write once the VM's backup dir is
    /// gone) covers the residual race a caller that does not go through
    /// here would leave open.
    pub async fn cancel_staging(&self, vm_id: &VmId) -> Result<()> {
        let staging = self
            .running_lock()?
            .get(vm_id)
            .map(|r| (r.cancel.clone(), r.done.clone()));
        if let Some((cancel, mut done)) = staging {
            cancel.cancel();
            if tokio::time::timeout(CANCEL_WAIT, done.wait_for(|d| *d))
                .await
                .is_err()
            {
                return Err(MinerAgentError::Backup("restore-cancel-timeout"));
            }
        }
        Ok(())
    }

    /// Validate and register a staging; the caller spawns
    /// [`Self::run_stage`] for `Started`.
    ///
    /// Idempotent per id: staging or staged already ⇒ no new work. A
    /// different id while one is staging — or while an earlier restore
    /// still has a staged dir or retained originals on disk — is
    /// `restore-busy`: its files are only reachable through its own id,
    /// so it must be aborted or reclaimed first. An id already aborted or
    /// reclaimed is `restore-finished`.
    pub async fn begin_stage(
        &self,
        lifecycle: &CvmLifecycle,
        req: StageRequest,
    ) -> Result<StageStart> {
        check_restore_id(&req.restore_id)?;
        if req.chain.restore_id != req.restore_id {
            return Err(MinerAgentError::Backup("restore-id-mismatch"));
        }
        if req.disk_bytes == 0 {
            return Err(MinerAgentError::Backup("restore-disk-bytes"));
        }
        restore::check_chain(&req.chain, Some(req.disk_bytes))?;
        let _ops = RESTORE_OPS.lock().await;
        if let Some(r) = self.running_lock()?.get(&req.vm_id) {
            return if r.restore_id == req.restore_id {
                Ok(StageStart::Staging)
            } else {
                Err(MinerAgentError::Backup("restore-busy"))
            };
        }
        let paths = RestorePaths::for_vm(lifecycle, &req.vm_id, &req.restore_id);
        if let Some(rec) = read_record(&paths.restore_root).await {
            if rec.restore_id == req.restore_id {
                match rec.state {
                    RestoreState::Staged => return Ok(StageStart::Staged),
                    RestoreState::Aborted | RestoreState::Reclaimed => {
                        return Err(MinerAgentError::Backup("restore-finished"));
                    }
                    // A failed (or restart-interrupted) staging is redone.
                    RestoreState::Staging | RestoreState::Failed => {}
                }
            } else {
                let other = RestorePaths::for_vm(lifecycle, &req.vm_id, &rec.restore_id);
                let unfinished = matches!(rec.state, RestoreState::Staging | RestoreState::Staged)
                    || present(&other.pre_overlay).await?
                    || present(&other.pre_state).await?;
                if unfinished {
                    return Err(MinerAgentError::Backup("restore-busy"));
                }
                // A failed staging's leftovers go now, by their exact path.
                remove_staging(&other.staging_dir).await?;
            }
        }
        // Only genuinely new work counts against the host's bound (checked
        // under the restore lock, which every registration holds).
        if self.running_lock()?.len() >= MAX_CONCURRENT_STAGINGS {
            return Err(MinerAgentError::Backup("restore-host-busy"));
        }
        remove_staging(&paths.staging_dir).await?;
        tokio::fs::create_dir_all(&paths.restore_root)
            .await
            .map_err(|_| MinerAgentError::Backup("restore-dir"))?;
        // Early answer only; the rebuild reserves for real.
        drop(self.space.reserve(
            &paths.restore_root,
            restore::chain_peak_bytes(&req.chain),
            self.headroom_bytes,
        )?);
        let bytes_total = restore::chain_bytes(&req.chain);
        // The record first: a restart always finds one for a dir it made.
        write_record(
            &paths.restore_root,
            &Record {
                restore_id: req.restore_id.clone(),
                op: RestoreOp::Stage,
                state: RestoreState::Staging,
                bytes_done: 0,
                bytes_total,
                reason: None,
                staged_overlay_stat: None,
            },
        )
        .await?;
        let (done_tx, done_rx) = tokio::sync::watch::channel(false);
        let cancel = CancellationToken::new();
        let opts = FetchOpts {
            streams: req.streams.clamp(1, super::transfer::MAX_STREAMS),
            progress: Arc::default(),
            cancel: cancel.clone(),
        };
        let ratchet = Arc::new(Ratchet::default());
        self.running_lock()?.insert(
            req.vm_id.clone(),
            Running {
                restore_id: req.restore_id.clone(),
                cancel: cancel.clone(),
                done: done_rx,
                progress: Arc::clone(&opts.progress),
                ratchet: Arc::clone(&ratchet),
            },
        );
        Ok(StageStart::Started(Box::new(StageJob {
            vm_id: req.vm_id,
            restore_id: req.restore_id,
            paths,
            chain: req.chain,
            disk_bytes: req.disk_bytes,
            bytes_total,
            opts,
            cancel,
            done: done_tx,
            ratchet,
        })))
    }

    /// Run a staging registered by [`Self::begin_stage`] and record the
    /// outcome. A failure (or a cancel by `abort`) leaves no staged file.
    pub async fn run_stage(&self, job: Box<StageJob>) {
        let job = *job;
        // Cancellation (an abort, or the timeout below) is cooperative:
        // the rebuild stops between steps and returns only once nothing
        // of it writes any more, so the slot and the paths are free.
        let timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let timer = {
            let (cancel, timed_out) = (job.cancel.clone(), Arc::clone(&timed_out));
            tokio::spawn(async move {
                tokio::time::sleep(STAGE_TIMEOUT).await;
                timed_out.store(true, Ordering::Relaxed);
                cancel.cancel();
            })
        };
        // Live progress (`opts.progress`) is visible in-process the
        // instant it changes (`status()` reads it straight off the
        // `running` map), but a large piece can run for a long time with
        // no other observer of this process — persist it into the
        // durable record too, so `status.json` itself shows real motion
        // rather than sitting at the `bytes_done: 0` `begin_stage` wrote,
        // unchanged until the terminal write.
        //
        // Stopped cooperatively, not aborted: both this task and the
        // terminal write below call `write_record`, which is NOT safe to
        // run concurrently against itself (both writers share one
        // `.status.json.tmp`). `persist_stop.cancel()` only takes effect
        // the next time the loop's `select!` polls it — if a write is
        // already in flight it is left to finish normally — and awaiting
        // the `JoinHandle` (not `.abort()`, which only requests a stop at
        // the next await point and does not wait for it) proves the
        // persister has genuinely stopped issuing writes before the
        // terminal one below starts.
        let persist_stop = CancellationToken::new();
        let persister = tokio::spawn(persist_progress(PersistArgs {
            restore_root: job.paths.restore_root.clone(),
            restore_id: job.restore_id.clone(),
            bytes_total: job.bytes_total,
            progress: Arc::clone(&job.opts.progress),
            ratchet: Arc::clone(&job.ratchet),
            interval: self.persist_interval,
            bytes: self.persist_bytes,
            stop: persist_stop.clone(),
        }));
        let mut result = self.stage(&job).await;
        timer.abort();
        persist_stop.cancel();
        let _ = persister.await;
        if result.is_err() && timed_out.load(Ordering::Relaxed) {
            result = Err(MinerAgentError::Backup("restore-timeout"));
        }
        let _ = remove_staging(&job.paths.work_dir).await;
        // A successful rebuild's identity must be captured before the
        // record can say `Staged` — `swap_in`'s whole BUG-1 proof rests
        // on it. A stat failure here (the file we just installed
        // ourselves cannot be stat'd) is bizarre enough to fail loudly
        // as the stage itself failing, rather than silently falling back
        // to the weaker legacy-record guarantee.
        let mut staged_overlay_stat = None;
        if result.is_ok() {
            match StagedOverlayStat::of(&job.paths.staged_overlay).await {
                Ok(s) => staged_overlay_stat = Some(s),
                Err(e) => result = Err(e),
            }
        }
        let rec = match &result {
            Ok(()) => Record {
                restore_id: job.restore_id.clone(),
                op: RestoreOp::Stage,
                state: RestoreState::Staged,
                bytes_done: job.bytes_total,
                bytes_total: job.bytes_total,
                reason: None,
                staged_overlay_stat,
            },
            Err(e) => {
                let _ = remove_staging(&job.paths.staging_dir).await;
                Record {
                    restore_id: job.restore_id.clone(),
                    op: RestoreOp::Stage,
                    state: RestoreState::Failed,
                    bytes_done: job
                        .ratchet
                        .report(job.opts.progress.load(Ordering::Relaxed))
                        .min(job.bytes_total),
                    bytes_total: job.bytes_total,
                    reason: Some(error_class(e).to_string()),
                    staged_overlay_stat: None,
                }
            }
        };
        // Belt and braces: `destroy` cancels and awaits us before it
        // reclaims `backup/<vm>/` (see `cancel_staging`), so by the time
        // we get here that race is normally already closed. But this is
        // the last line of defence against a caller that raced past it
        // (or any future one that forgets to call in) — if the VM's
        // backup dir is gone, writing here would only recreate
        // `restore/status.json` for a VM nothing will ever read it back
        // for. Checked on both the success and the failure record: an
        // orphaned "staged" is just as much a leak as an orphaned
        // "failed".
        let footprint_gone = matches!(
            tokio::fs::symlink_metadata(&job.paths.restore_root).await,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
        );
        if footprint_gone {
            eprintln!(
                "hippius-miner-agent: restore: vm={} restore_id={} stage finished after its \
                 backup dir was reclaimed (likely a concurrent destroy) — dropping the record",
                job.vm_id.as_str(),
                job.restore_id
            );
        } else {
            if let Err(e) = write_record(&job.paths.restore_root, &rec).await {
                eprintln!(
                    "hippius-miner-agent: restore: vm={} record write failed: {e}",
                    job.vm_id.as_str()
                );
            }
            eprintln!(
                "hippius-miner-agent: restore: vm={} restore_id={} stage {}",
                job.vm_id.as_str(),
                job.restore_id,
                rec.reason.as_deref().unwrap_or("staged")
            );
        }
        if let Ok(mut map) = self.running.lock() {
            if map
                .get(&job.vm_id)
                .is_some_and(|r| r.restore_id == job.restore_id)
            {
                map.remove(&job.vm_id);
            }
        }
        let _ = job.done.send(true);
    }

    async fn stage(&self, job: &StageJob) -> Result<()> {
        tokio::fs::create_dir_all(&job.paths.staging_dir)
            .await
            .map_err(|_| MinerAgentError::Backup("restore-dir"))?;
        restore::rebuild(
            self.fetcher.as_ref(),
            &self.space,
            &job.chain,
            &Target {
                work_dir: &job.paths.work_dir,
                overlay_path: &job.paths.staged_overlay,
                state_path: &job.paths.staged_state,
            },
            Some(job.disk_bytes),
            self.headroom_bytes,
            &job.opts,
        )
        .await
    }

    /// `abort`: see the module docs. Refused (`restore-activating`) while
    /// a `migrate-activate` of the VM runs here, and (`restore-vm-live`)
    /// when a domain that is NOT this restore's runs over retained
    /// originals. With the original running and nothing swapped, only
    /// the staging goes. Idempotent.
    pub async fn abort(
        &self,
        lifecycle: &CvmLifecycle,
        migration: &MigrationStore,
        vm_id: &VmId,
        restore_id: &str,
    ) -> Result<()> {
        check_restore_id(restore_id)?;
        // Stop a staging of this restore first, WITHOUT the restore lock:
        // the wait can be long (a qcow2 apply runs to its end) and the
        // lock is host-wide — every activation enters `Activating` under
        // it. Harmless if the abort is refused below: a restore being
        // staged is neither activating nor reclaimed.
        let staging = self
            .running_lock()?
            .get(vm_id)
            .filter(|r| r.restore_id == restore_id)
            .map(|r| (r.cancel.clone(), r.done.clone()));
        if let Some((cancel, mut done)) = staging {
            cancel.cancel();
            match tokio::time::timeout(CANCEL_WAIT, done.wait_for(|d| *d)).await {
                Ok(_) => {}
                Err(_) => return Err(MinerAgentError::Backup("restore-cancel-timeout")),
            }
        }
        let _ops = RESTORE_OPS.lock().await;
        if migration.phase(vm_id) == Some(MigrationPhase::Activating) {
            return Err(MinerAgentError::Backup("restore-activating"));
        }
        let p = RestorePaths::for_vm(lifecycle, vm_id, restore_id);
        // A reclaimed restore is committed: its original is gone, and
        // "aborting" it would only take the good VM down.
        if read_record(&p.restore_root)
            .await
            .is_some_and(|r| r.restore_id == restore_id && r.state == RestoreState::Reclaimed)
        {
            return Err(MinerAgentError::Backup("restore-finished"));
        }
        // A stage re-sent while the lock was free starts a new staging:
        // refuse rather than rename under it.
        if self
            .running_lock()?
            .get(vm_id)
            .is_some_and(|r| r.restore_id == restore_id)
        {
            return Err(MinerAgentError::Backup("restore-busy"));
        }
        let ours =
            read_marker(&p.marker).await.as_deref() == Some(staged_marker(restore_id).as_str());
        let retained = present(&p.pre_overlay).await? || present(&p.pre_state).await?;
        // The record no longer names this restore: another one started,
        // which it only could once this one was settled. Its swapped-in
        // disks are then the VM's, committed — never taken down here.
        let current = read_record(&p.restore_root)
            .await
            .is_some_and(|r| r.restore_id == restore_id);
        if (ours || retained) && !current {
            return Err(MinerAgentError::Backup("restore-finished"));
        }
        match lifecycle.tenant_domain_liveness(vm_id).await {
            DomainLiveness::Down => {}
            DomainLiveness::Live | DomainLiveness::Unknown => {
                if ours {
                    lifecycle.force_stop_tenant(vm_id).await?;
                } else if retained {
                    return Err(MinerAgentError::Backup("restore-vm-live"));
                }
            }
        }
        abort_files(&p, restore_id).await?;
        self.record_terminal(&p, restore_id, RestoreOp::Abort, RestoreState::Aborted)
            .await
    }

    /// `reclaim`: see the module docs. Refused (`restore-activating`)
    /// while a `migrate-activate` of the VM runs here: the swap may be
    /// done but the restored guest not yet booted. Idempotent.
    pub async fn reclaim(
        &self,
        lifecycle: &CvmLifecycle,
        migration: &MigrationStore,
        vm_id: &VmId,
        restore_id: &str,
    ) -> Result<()> {
        check_restore_id(restore_id)?;
        let _ops = RESTORE_OPS.lock().await;
        if migration.phase(vm_id) == Some(MigrationPhase::Activating) {
            return Err(MinerAgentError::Backup("restore-activating"));
        }
        if self
            .running_lock()?
            .get(vm_id)
            .is_some_and(|r| r.restore_id == restore_id)
        {
            return Err(MinerAgentError::Backup("restore-reclaim-refused"));
        }
        let p = RestorePaths::for_vm(lifecycle, vm_id, restore_id);
        // The marker check first, then the intent, durably, then the
        // deletes: a crash in between leaves `reclaimed` (which an abort
        // refuses) and a re-sent reclaim finishes the deletes.
        if read_marker(&p.marker).await.as_deref() != Some(staged_marker(restore_id).as_str()) {
            return Err(MinerAgentError::Backup("restore-reclaim-refused"));
        }
        self.record_terminal(&p, restore_id, RestoreOp::Reclaim, RestoreState::Reclaimed)
            .await?;
        crash_point(21)?;
        reclaim_files(&p, restore_id).await
    }

    /// Record a terminal op — unless the record belongs to another
    /// restore, which it must keep describing.
    async fn record_terminal(
        &self,
        p: &RestorePaths,
        restore_id: &str,
        op: RestoreOp,
        state: RestoreState,
    ) -> Result<()> {
        let prev = read_record(&p.restore_root).await;
        if prev.as_ref().is_some_and(|r| r.restore_id != restore_id) {
            return Ok(());
        }
        let (bytes_done, bytes_total, staged_overlay_stat) = prev.map_or((0, 0, None), |r| {
            (r.bytes_done, r.bytes_total, r.staged_overlay_stat)
        });
        write_record(
            &p.restore_root,
            &Record {
                restore_id: restore_id.to_string(),
                op,
                state,
                bytes_done,
                bytes_total,
                reason: None,
                staged_overlay_stat,
            },
        )
        .await
    }

    /// The latest restore of `vm_id` as persisted, and whether it is the
    /// one swapped in — no libvirt, no manager state (the activation's
    /// quick check).
    pub async fn peek(lifecycle: &CvmLifecycle, vm_id: &VmId) -> Option<Peek> {
        let rec = read_record(&lifecycle.backup_dir(vm_id).join(RESTORE_DIR_NAME)).await?;
        let p = RestorePaths::for_vm(lifecycle, vm_id, &rec.restore_id);
        let swapped = read_marker(&p.marker).await.as_deref()
            == Some(staged_marker(&rec.restore_id).as_str());
        Some(Peek {
            restore_id: rec.restore_id,
            state: rec.state,
            swapped,
        })
    }

    /// The status route's answer; `Ok(None)` when nothing is known for
    /// the VM.
    pub async fn status(
        &self,
        lifecycle: &CvmLifecycle,
        vm_id: &VmId,
    ) -> std::result::Result<Option<RestoreStatus>, StatusError> {
        let root = lifecycle.backup_dir(vm_id).join(RESTORE_DIR_NAME);
        let Some(rec) = read_record(&root).await else {
            return Ok(None);
        };
        let live_progress = self.running.lock().ok().and_then(|m| {
            m.get(vm_id)
                .filter(|r| r.restore_id == rec.restore_id)
                .map(|r| r.ratchet.report(r.progress.load(Ordering::Relaxed)))
        });
        let p = RestorePaths::for_vm(lifecycle, vm_id, &rec.restore_id);
        let swapped = read_marker(&p.marker).await.as_deref()
            == Some(staged_marker(&rec.restore_id).as_str());
        let pre_restore_present = present(&p.pre_overlay).await.unwrap_or(true)
            || present(&p.pre_state).await.unwrap_or(true);
        let domain_live = match lifecycle.tenant_domain_liveness(vm_id).await {
            DomainLiveness::Live => true,
            DomainLiveness::Down => false,
            DomainLiveness::Unknown => return Err(StatusError::Unavailable),
        };
        Ok(Some(RestoreStatus {
            vm_id: vm_id.as_str().to_string(),
            restore_id: rec.restore_id,
            op: rec.op,
            state: rec.state,
            bytes_done: live_progress.unwrap_or(rec.bytes_done).min(rec.bytes_total),
            bytes_total: rec.bytes_total,
            reason: rec.reason,
            swapped,
            pre_restore_present,
            domain_live,
        }))
    }

    /// At agent start, before orders are served: a staging the previous
    /// process did not finish is recorded `failed` (`agent-restart`) and
    /// its partial staging dir removed; a staged restore's scratch dir
    /// goes. Nothing else is touched.
    pub async fn recover_on_startup(&self, backup_root: &Path) {
        let Ok(mut entries) = tokio::fs::read_dir(backup_root).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let vm_dir = entry.path();
            if vm_dir
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| VmId::new(n).ok())
                .is_none()
            {
                continue;
            }
            let root = vm_dir.join(RESTORE_DIR_NAME);
            let Some(mut rec) = read_record(&root).await else {
                continue;
            };
            let staging = root.join(&rec.restore_id);
            let _ = remove_staging(&staging.join(WORK_DIR)).await;
            if rec.state == RestoreState::Staging {
                let _ = remove_staging(&staging).await;
                rec.state = RestoreState::Failed;
                rec.reason = Some("agent-restart".to_string());
                if write_record(&root, &rec).await.is_err() {
                    eprintln!(
                        "hippius-miner-agent: restore: {} interrupted staging not recorded",
                        vm_dir.display()
                    );
                }
            }
        }
    }
}

/// Test helper: leave restore `restore_id` staged with these bytes, as a
/// completed `stage` would — including the staged overlay's identity, as
/// the current agent always records it.
#[cfg(test)]
pub(crate) async fn stage_for_tests(
    p: &RestorePaths,
    restore_id: &str,
    overlay: &[u8],
    state: &[u8],
) {
    std::fs::create_dir_all(&p.staging_dir).unwrap();
    std::fs::write(&p.staged_overlay, overlay).unwrap();
    std::fs::write(&p.staged_state, state).unwrap();
    let staged_overlay_stat = Some(StagedOverlayStat::of(&p.staged_overlay).await.unwrap());
    write_record(
        &p.restore_root,
        &Record {
            restore_id: restore_id.to_string(),
            op: RestoreOp::Stage,
            state: RestoreState::Staged,
            bytes_done: 1,
            bytes_total: 1,
            reason: None,
            staged_overlay_stat,
        },
    )
    .await
    .unwrap();
}

/// Test helper: [`stage_for_tests`], but as an older agent (before
/// [`StagedOverlayStat`] existed) would have left it — no inode
/// recorded. Exercises `swap_in`'s weaker fallback for a record an
/// upgrade finds already staged.
#[cfg(test)]
pub(crate) async fn stage_for_tests_legacy(
    p: &RestorePaths,
    restore_id: &str,
    overlay: &[u8],
    state: &[u8],
) {
    std::fs::create_dir_all(&p.staging_dir).unwrap();
    std::fs::write(&p.staged_overlay, overlay).unwrap();
    std::fs::write(&p.staged_state, state).unwrap();
    write_record(
        &p.restore_root,
        &Record {
            restore_id: restore_id.to_string(),
            op: RestoreOp::Stage,
            state: RestoreState::Staged,
            bytes_done: 1,
            bytes_total: 1,
            reason: None,
            staged_overlay_stat: None,
        },
    )
    .await
    .unwrap();
}

fn error_class(e: &MinerAgentError) -> &'static str {
    match e {
        MinerAgentError::Backup(c) | MinerAgentError::Migration(c) => c,
        MinerAgentError::LockPoisoned => "lock-poisoned",
        _ => "internal",
    }
}

#[cfg(test)]
mod tests;
