//! The QMP side of a backup run: copy the running overlay (full) or the
//! clusters written since a parent point (incremental) into a local temp
//! image, point-in-time consistent, without pausing the guest.
//!
//! Sequence (both kinds):
//!
//! 1. release anything a previous, interrupted run left in QEMU (its
//!    in-flight marker); refuse to start if that fails;
//! 2. find the overlay's `file` node (`libvirt-N-storage`) and its
//!    bitmaps in `query-named-block-nodes`;
//! 3. prune our bitmaps down to {parent};
//! 4. reserve the space (see [`SpaceLedger`]);
//! 5. create the temp target (raw sized to the source, or a backing-less
//!    qcow2), open it read-write twice — once `O_DIRECT` for QEMU, once
//!    buffered for the upload — and **unlink it at once** — from here on
//!    the only references are descriptors, so a crash can never strand a
//!    multi-GB file on disk;
//! 6. `add-fd` QEMU's descriptor and `blockdev-add` the target on
//!    `/dev/fdset/<id>` with `cache.direct` (see [`super::qmp`] for why
//!    by fd);
//! 7. ONE `transaction`: add this run's bitmap + start the copy (full, or
//!    `sync=bitmap` over the parent's bitmap with `bitmap-mode=never`),
//!    capped at the configured speed;
//! 8. poll `query-jobs` until the job concludes, riding out a monitor
//!    that stops answering for a while;
//! 9. ALWAYS release: cancel (and wait) if still running, dismiss,
//!    `blockdev-del` the target, `remove-fd` the fdset. A run that did
//!    not succeed also drops its own new bitmap.
//!
//! ## Bitmaps are restore points
//!
//! `hippius-bk-<run_id>` means "dirty since run `run_id`'s point in time".
//! It is created atomically with that run's copy and is NEVER cleared by
//! a job (`bitmap-mode=never`): an incremental copies what its parent's
//! bitmap marks and leaves it intact. So nothing is lost when a run fails
//! after QEMU finished — the upload, vali's CompleteMultipart, an agent
//! restart: the next run names the same (last committed) parent and its
//! delta covers everything since. Old points are pruned at the start of
//! the next run, which names the one to keep.
//!
//! The bitmaps are in memory (`persistent: false`) and die with QEMU;
//! that is intended — a reboot invalidates every backup anyway (see the
//! design doc), and a missing parent tells vali to take a full.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::image_tool::ImageTool;
use super::qmp::{self, QmpTransport, SourceNode, TargetFormat};
use crate::error::{MinerAgentError, Result};
use crate::lifecycle::DomainId;

/// Headroom the space guard keeps free on the work dir's filesystem on
/// top of every reserved target, so a backup can never push the host to
/// ENOSPC under the running guests.
pub const SPACE_RESERVE_BYTES: u64 = 4 << 30;

/// Name of the in-flight marker inside a VM's work dir. Present while a
/// capture may hold QEMU resources; removed only once they are released.
pub const INFLIGHT_MARKER: &str = "inflight.json";

/// How long a release waits for a cancelled job to conclude.
const CANCEL_WAIT: Duration = Duration::from_secs(60);

/// `O_DIRECT` needs offsets and lengths aligned to the logical block
/// size (512 or 4096). A raw target the size of the source is written
/// with direct I/O only when that size is a multiple of the larger one:
/// QEMU pads an unaligned tail write up to a whole block, which would
/// grow the file past the disk size. Overlays are whole GiB, so in
/// practice always.
const DIRECT_IO_ALIGN: u64 = 4096;

/// Consecutive `query-jobs` polls that may hit a stalled monitor (see
/// [`is_transient`]) before the run gives up. One stall costs up to the
/// 60 s virsh timeout, so this rides out ~10 min of silence.
const MAX_TRANSIENT_POLLS: u32 = 10;

/// Which backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackupKind {
    /// The whole overlay; starts a chain.
    Full,
    /// The clusters written since the parent point.
    Incremental,
}

impl BackupKind {
    fn target_format(self) -> TargetFormat {
        match self {
            BackupKind::Full => TargetFormat::Raw,
            BackupKind::Incremental => TargetFormat::Qcow2,
        }
    }
}

/// The bitmap name of run `run_id`'s point (charset-validated by the
/// caller).
pub fn bitmap_name(run_id: &str) -> String {
    format!("{}{run_id}", qmp::BITMAP_PREFIX)
}

/// Host-wide byte reservations for backup targets, restore stagings and
/// §25 snapshot downloads.
///
/// `statvfs` alone cannot keep two concurrent writers from both counting
/// the same free blocks, and a sparse `set_len` allocates nothing up
/// front. Each writer reserves its worst case here, atomically against
/// the others, and holds the reservation until its file is gone (or
/// fully written into place).
///
/// Production uses [`SpaceLedger::host`]: its counter is the one the
/// per-VM disk creates are admitted under
/// ([`crate::lifecycle::disk_space`]), and its free space is net of the
/// unwritten tail of every per-VM disk — so a backup cannot take bytes
/// promised to a live guest, nor a launch bytes a backup holds. The
/// [`Default`] ledger is an isolated one over raw `statvfs` (tests).
#[derive(Debug)]
pub struct SpaceLedger {
    /// `Some`: this ledger's own counter. `None`: the host counter.
    own: Option<Mutex<u64>>,
    /// Whose per-VM disks' tails come off the free space (`None`: none).
    miner_root: Option<PathBuf>,
}

impl Default for SpaceLedger {
    fn default() -> Self {
        Self {
            own: Some(Mutex::new(0)),
            miner_root: None,
        }
    }
}

impl SpaceLedger {
    /// The host ledger over the per-VM disks under `miner_root`
    /// (`[storage] data_disk_root`).
    pub fn host(miner_root: impl Into<PathBuf>) -> Self {
        Self {
            own: None,
            miner_root: Some(miner_root.into()),
        }
    }

    fn counter(&self) -> MutexGuard<'_, u64> {
        match &self.own {
            Some(own) => own
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            None => crate::lifecycle::disk_space::create_lock(),
        }
    }

    /// Bytes still free on `dir`'s filesystem with `reserved` held.
    fn unreserved(&self, dir: &Path, reserved: u64) -> Result<u64> {
        match &self.miner_root {
            Some(root) => crate::lifecycle::disk_space::headroom_bytes(reserved, root, dir)
                .map_err(MinerAgentError::Backup),
            None => Ok(free_bytes(dir)?.saturating_sub(reserved)),
        }
    }

    /// Reserve `need` bytes on `dir`'s filesystem, keeping `headroom`
    /// free on top of every reservation.
    pub fn reserve(&self, dir: &Path, need: u64, headroom: u64) -> Result<SpaceGuard<'_>> {
        self.take(dir, need, headroom)?;
        Ok(SpaceGuard {
            ledger: self,
            bytes: need,
        })
    }

    fn grow(&self, dir: &Path, extra: u64, headroom: u64) -> Result<()> {
        // The free space already excludes what this run's target has
        // written so far, which its reservation also counts: conservative.
        self.take(dir, extra, headroom)
    }

    fn take(&self, dir: &Path, need: u64, headroom: u64) -> Result<()> {
        let mut reserved = self.counter();
        let free = self.unreserved(dir, *reserved)?;
        if free < need.saturating_add(headroom) {
            return Err(MinerAgentError::Backup("insufficient-space"));
        }
        *reserved = reserved.saturating_add(need);
        Ok(())
    }

    /// Bytes currently reserved.
    pub fn reserved(&self) -> u64 {
        *self.counter()
    }
}

/// A live reservation; released on drop.
#[derive(Debug)]
pub struct SpaceGuard<'a> {
    ledger: &'a SpaceLedger,
    bytes: u64,
}

impl SpaceGuard<'_> {
    /// Raise this reservation to `total` bytes (no-op if already there).
    pub fn grow_to(&mut self, dir: &Path, total: u64, headroom: u64) -> Result<()> {
        if total > self.bytes {
            self.ledger.grow(dir, total - self.bytes, headroom)?;
            self.bytes = total;
        }
        Ok(())
    }

    /// Keep the bytes reserved for the rest of the agent's life: QEMU
    /// may still hold (and grow) the target, so the space is not ours to
    /// hand out again. A restart re-derives free space from scratch.
    pub fn strand(mut self) {
        self.bytes = 0;
    }
}

impl Drop for SpaceGuard<'_> {
    fn drop(&mut self) {
        let mut reserved = self.ledger.counter();
        *reserved = reserved.saturating_sub(self.bytes);
    }
}

/// What one capture needs.
pub struct CaptureRequest<'a> {
    /// The running domain.
    pub domain: &'a DomainId,
    /// The overlay's path as libvirt opened it (the `/dev/vda` source).
    pub source_path: &'a Path,
    /// This VM's work dir (`<root>/backup/<vm_id>`).
    pub work_dir: &'a Path,
    /// Full or incremental.
    pub kind: BackupKind,
    /// This run's bitmap ([`bitmap_name`] of its run id).
    pub new_bitmap: &'a str,
    /// The parent point's bitmap: what an incremental copies; for a full,
    /// the one old point to keep (so the current chain survives a failed
    /// full). Every other bitmap of ours is pruned.
    pub parent_bitmap: Option<&'a str>,
    /// Bytes to keep free on top of all reservations
    /// ([`SPACE_RESERVE_BYTES`] in production).
    pub headroom_bytes: u64,
    /// Cap on this job's copy, bytes/s (`0`: uncapped) — its share of
    /// the host budget ([`super::job_speed`]).
    pub speed_bytes_per_sec: u64,
}

/// Poll cadence + overall bound on the QEMU job.
#[derive(Debug, Clone, Copy)]
pub struct JobTiming {
    /// Delay between `query-jobs` polls.
    pub poll: Duration,
    /// Give up (and cancel) after this long.
    pub timeout: Duration,
}

impl Default for JobTiming {
    fn default() -> Self {
        Self {
            poll: Duration::from_millis(500),
            timeout: Duration::from_secs(6 * 3600),
        }
    }
}

/// A finished capture — an unlinked temp image, held open, and the space
/// reservation that covers it.
#[derive(Debug)]
pub struct Captured<'a> {
    /// The image (raw for a full, qcow2 for an incremental), offset 0.
    pub file: std::fs::File,
    /// Its length in bytes — what gets uploaded.
    pub len: u64,
    /// The source's virtual size.
    pub virtual_size: u64,
    /// Held until the image is dropped (`None` if stranded because QEMU
    /// kept a reference to the target).
    pub space: Option<SpaceGuard<'a>>,
}

/// What restart cleanup needs to know about an interrupted capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InflightMarker {
    /// The run's own point bitmap while its copy has not completed —
    /// never a valid point, so recovery drops it. `None` once the copy
    /// completed: the run may since have been committed, and its point
    /// must survive a late release.
    pub new_bitmap: Option<String>,
    /// The overlay path (to find the node the bitmap lives on).
    pub source_path: PathBuf,
}

/// Look up the source node for `source_path`.
pub async fn source_node(
    qmp: &dyn QmpTransport,
    domain: &DomainId,
    source_path: &Path,
) -> Result<SourceNode> {
    let nodes = qmp
        .execute(domain, &qmp::query_named_block_nodes(), None)
        .await?;
    qmp::find_file_node(&nodes, source_path).ok_or(MinerAgentError::Backup("source-node-missing"))
}

/// Free bytes on the filesystem holding `dir`.
pub fn free_bytes(dir: &Path) -> Result<u64> {
    let st = nix::sys::statvfs::statvfs(dir).map_err(|_| MinerAgentError::Backup("statvfs"))?;
    #[allow(clippy::useless_conversion)]
    let avail = u64::try_from(st.blocks_available()).unwrap_or(0);
    #[allow(clippy::useless_conversion)]
    let frsize = u64::try_from(st.fragment_size()).unwrap_or(0);
    Ok(avail.saturating_mul(frsize))
}

/// Bytes the target will need at most.
///
/// Full: the whole virtual size (the overlay is LUKS ciphertext end to
/// end — nothing is sparse). Incremental: the parent's dirty bytes, plus
/// [`WRITE_SLACK_BYTES`] (capped at the disk) for what the guest dirties
/// before the transaction, plus qcow2 metadata (one 8-byte L2 entry per
/// 64 KiB cluster is `size/8192`, doubled for refcounts, plus slack).
/// The slack is not trusted as a bound: right after the transaction the
/// parent's count is re-read and the reservation grown to match (or the
/// job cancelled). A `sync=bitmap` job copies only what was dirty at its
/// start.
pub fn space_needed(kind: BackupKind, virtual_size: u64, dirty: u64) -> u64 {
    match kind {
        BackupKind::Full => virtual_size,
        BackupKind::Incremental => dirty
            .saturating_add(WRITE_SLACK_BYTES.min(virtual_size))
            .saturating_add(virtual_size / 4096)
            .saturating_add(16 << 20),
    }
}

/// See [`space_needed`].
pub const WRITE_SLACK_BYTES: u64 = 1 << 30;

/// Run one capture. Whatever happens, the QEMU resources it set up are
/// released (or left recorded in the in-flight marker for the next run
/// or the next agent start to release).
pub async fn capture<'l>(
    qmp: &dyn QmpTransport,
    img: &dyn ImageTool,
    ledger: &'l SpaceLedger,
    req: &CaptureRequest<'_>,
    timing: JobTiming,
) -> Result<Captured<'l>> {
    tokio::fs::create_dir_all(req.work_dir)
        .await
        .map_err(|_| MinerAgentError::Backup("work-dir"))?;
    if let Some(stale) = read_marker(req.work_dir).await {
        if !recover_interrupted(qmp, req.domain, &stale).await {
            return Err(MinerAgentError::Backup("previous-run-unreleased"));
        }
        remove_marker(req.work_dir).await;
    }

    let node = source_node(qmp, req.domain, req.source_path).await?;
    if node.bitmap(req.new_bitmap).is_some() {
        // This run already took its point (a replayed order after an
        // agent restart). Re-taking it would prune and replace a point
        // vali may have committed.
        return Err(MinerAgentError::Backup("run-exists"));
    }
    let dirty = match (req.kind, req.parent_bitmap) {
        (BackupKind::Full, _) => 0,
        (BackupKind::Incremental, None) => return Err(MinerAgentError::Backup("parent-missing")),
        (BackupKind::Incremental, Some(parent)) => {
            node.bitmap(parent)
                .ok_or(MinerAgentError::Backup("bitmap-missing"))?
                .count
        }
    };
    prune_bitmaps(qmp, req.domain, &node, req.parent_bitmap).await?;

    let mut space = ledger.reserve(
        req.work_dir,
        space_needed(req.kind, node.virtual_size, dirty),
        req.headroom_bytes,
    )?;
    let (file, qemu_target) = create_unlinked_target(img, req, node.virtual_size).await?;

    let mut marker = InflightMarker {
        new_bitmap: Some(req.new_bitmap.to_string()),
        source_path: req.source_path.to_path_buf(),
    };
    write_marker(req.work_dir, &marker).await?;

    let outcome = run_job(qmp, req, &node, qemu_target, timing, &mut space).await;
    if outcome.is_ok() {
        // The point is real now; a late release must not drop it.
        marker.new_bitmap = None;
        write_marker(req.work_dir, &marker).await?;
    }
    let mut clean = release_resources(qmp, req.domain, timing.poll).await;
    if outcome.is_err() {
        // Not a valid point: whether or not QEMU finished, nothing of it
        // was delivered.
        clean &= drop_bitmap(qmp, req.domain, &node.node_name, req.new_bitmap).await;
    }
    if clean {
        remove_marker(req.work_dir).await;
    } else {
        eprintln!(
            "hippius-miner-agent: backup: QEMU still holds backup resources; the next run retries the release"
        );
    }
    let space = if clean {
        Some(space)
    } else {
        space.strand();
        None
    };
    outcome?;

    let len = file
        .metadata()
        .map_err(|_| MinerAgentError::Backup("target-stat"))?
        .len();
    Ok(Captured {
        file,
        len,
        virtual_size: node.virtual_size,
        space,
    })
}

/// Whether bitmap `bitmap` is on the overlay node now.
pub async fn bitmap_present(
    qmp: &dyn QmpTransport,
    domain: &DomainId,
    source_path: &Path,
    bitmap: &str,
) -> Result<bool> {
    Ok(source_node(qmp, domain, source_path)
        .await?
        .bitmap(bitmap)
        .is_some())
}

/// Drop every `hippius-bk-*` bitmap on the node except `keep`.
async fn prune_bitmaps(
    qmp: &dyn QmpTransport,
    domain: &DomainId,
    node: &SourceNode,
    keep: Option<&str>,
) -> Result<()> {
    for b in &node.bitmaps {
        if b.name.starts_with(qmp::BITMAP_PREFIX) && Some(b.name.as_str()) != keep {
            qmp.execute(domain, &qmp::bitmap_remove(&node.node_name, &b.name), None)
                .await?;
        }
    }
    Ok(())
}

/// The descriptor QEMU writes the target through, and whether it is
/// `O_DIRECT` (the target node's `cache.direct` must say the same).
struct QemuTarget {
    file: std::fs::File,
    direct: bool,
}

/// Create the target and return two descriptors on it: the agent's own
/// (buffered — the upload reads it with arbitrary buffers) and QEMU's.
///
/// QEMU's is a SEPARATE open, `O_DIRECT`: the copy then bypasses the page
/// cache instead of filling the host's dirty memory with the whole disk
/// (#1246). Separate, not a dup: status flags belong to the open file,
/// and QEMU `F_SETFL`s the fdset member it dups. Where direct I/O is not
/// possible (an unaligned size, a filesystem refusing `O_DIRECT`) QEMU
/// gets a buffered descriptor and the run still works, only slower.
async fn create_unlinked_target(
    img: &dyn ImageTool,
    req: &CaptureRequest<'_>,
    virtual_size: u64,
) -> Result<(std::fs::File, QemuTarget)> {
    let path = req.work_dir.join(match req.kind {
        BackupKind::Full => "target.raw",
        BackupKind::Incremental => "target.qcow2",
    });
    // A leftover from a crash before the unlink below.
    let _ = tokio::fs::remove_file(&path).await;
    let opened = async {
        let file = match req.kind {
            BackupKind::Full => {
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .map_err(|_| MinerAgentError::Backup("target-create"))?;
                f.set_len(virtual_size)
                    .map_err(|_| MinerAgentError::Backup("target-create"))?;
                f
            }
            BackupKind::Incremental => {
                img.create_qcow2(&path, virtual_size).await?;
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| MinerAgentError::Backup("target-create"))?
            }
        };
        // A qcow2 target's length is QEMU's business (cluster-aligned
        // anyway); a raw one must stay exactly the disk size.
        let want_direct =
            req.kind == BackupKind::Incremental || virtual_size.is_multiple_of(DIRECT_IO_ALIGN);
        let qemu = open_for_qemu(&path, want_direct)?;
        Ok((file, qemu))
    }
    .await;
    // Unlink whatever happened: success keeps the open descriptors.
    let _ = tokio::fs::remove_file(&path).await;
    opened
}

/// Open `path` read-write for QEMU, `O_DIRECT` when `want_direct` and the
/// filesystem allows it.
fn open_for_qemu(path: &Path, want_direct: bool) -> Result<QemuTarget> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true);
    if want_direct {
        match opts
            .clone()
            .custom_flags(nix::fcntl::OFlag::O_DIRECT.bits())
            .open(path)
        {
            Ok(file) => return Ok(QemuTarget { file, direct: true }),
            // EINVAL: this filesystem does not do O_DIRECT.
            Err(e) if e.raw_os_error() == Some(nix::libc::EINVAL) => {}
            Err(_) => return Err(MinerAgentError::Backup("target-create")),
        }
    }
    eprintln!(
        "hippius-miner-agent: backup: direct I/O unavailable for the target; QEMU writes it through the page cache"
    );
    let file = opts
        .open(path)
        .map_err(|_| MinerAgentError::Backup("target-create"))?;
    Ok(QemuTarget {
        file,
        direct: false,
    })
}

async fn run_job(
    qmp: &dyn QmpTransport,
    req: &CaptureRequest<'_>,
    node: &SourceNode,
    target: QemuTarget,
    timing: JobTiming,
    space: &mut SpaceGuard<'_>,
) -> Result<()> {
    let ret = qmp
        .execute(req.domain, &qmp::add_fd(), Some(target.file))
        .await?;
    let fdset = qmp::parse_add_fd(&ret)?;
    qmp.execute(
        req.domain,
        &qmp::blockdev_add_target(req.kind.target_format(), fdset, target.direct),
        None,
    )
    .await?;
    let speed = req.speed_bytes_per_sec;
    let tx = match (req.kind, req.parent_bitmap) {
        (BackupKind::Full, _) => qmp::transaction_full(&node.node_name, req.new_bitmap, speed),
        (BackupKind::Incremental, Some(parent)) => {
            qmp::transaction_incremental(&node.node_name, parent, req.new_bitmap, speed)
        }
        (BackupKind::Incremental, None) => return Err(MinerAgentError::Backup("parent-missing")),
    };
    // A transaction that timed out may still have started the job: the
    // monitor is serialised, so the polls below see its outcome, and a
    // job that is not there means it never started.
    let mut absent = "job-vanished";
    match qmp.execute(req.domain, &tx, None).await {
        Ok(_) => {}
        Err(MinerAgentError::Backup("qmp-timeout")) => {
            eprintln!(
                "hippius-miner-agent: backup: domain={} transaction timed out; polling for the job",
                req.domain.as_str()
            );
            absent = "qmp-timeout";
        }
        Err(e) => return Err(e),
    }
    if let (BackupKind::Incremental, Some(parent)) = (req.kind, req.parent_bitmap) {
        // The copy set is now fixed; the parent's count has only grown
        // since, so it bounds what the job will write. Asked while the
        // job copies (or while libvirt still waits on a timed-out
        // transaction), so it rides out a stall like the polls do.
        let now = source_node_riding_stalls(qmp, req.domain, req.source_path, timing).await?;
        let dirty = now
            .bitmap(parent)
            .ok_or(MinerAgentError::Backup("bitmap-missing"))?
            .count;
        space.grow_to(
            req.work_dir,
            space_needed(req.kind, node.virtual_size, dirty),
            req.headroom_bytes,
        )?;
    }

    let job = wait_concluded(qmp, req.domain, timing, absent).await?;
    if job.failed {
        return Err(MinerAgentError::Backup("job-failed"));
    }
    Ok(())
}

/// Poll until the job concludes. Past the deadline: `job-timeout` (the
/// release cancels it). No job is error `absent`: after a confirmed
/// start it vanished — we never dismiss it, so something else did.
///
/// A monitor that does not answer ([`is_transient`]) is polled again, up
/// to [`MAX_TRANSIENT_POLLS`] times in a row: under a saturating copy
/// QEMU's monitor can go quiet for a minute while the job runs fine
/// (#1246), and failing the run there throws the copy away.
async fn wait_concluded(
    qmp: &dyn QmpTransport,
    domain: &DomainId,
    timing: JobTiming,
    absent: &'static str,
) -> Result<qmp::JobInfo> {
    let deadline = tokio::time::Instant::now() + timing.timeout;
    let mut stalls = 0;
    loop {
        match qmp.execute(domain, &qmp::query_jobs(), None).await {
            Ok(jobs) => {
                stalls = 0;
                let job =
                    qmp::find_job(&jobs, qmp::JOB_ID).ok_or(MinerAgentError::Backup(absent))?;
                if job.status == "concluded" {
                    return Ok(job);
                }
            }
            Err(e) if is_transient(&e) && stalls < MAX_TRANSIENT_POLLS => {
                stalls += 1;
                eprintln!(
                    "hippius-miner-agent: backup: domain={} query-jobs failed ({e}), {stalls}/{MAX_TRANSIENT_POLLS} in a row; still polling",
                    domain.as_str(),
                );
            }
            Err(e) => return Err(e),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(MinerAgentError::Backup("job-timeout"));
        }
        tokio::time::sleep(timing.poll).await;
    }
}

/// [`source_node`], retried on a stalled monitor up to
/// [`MAX_TRANSIENT_POLLS`] times in a row and within the job bound.
async fn source_node_riding_stalls(
    qmp: &dyn QmpTransport,
    domain: &DomainId,
    source_path: &Path,
    timing: JobTiming,
) -> Result<SourceNode> {
    let deadline = tokio::time::Instant::now() + timing.timeout;
    let mut stalls = 0;
    loop {
        match source_node(qmp, domain, source_path).await {
            Err(e)
                if is_transient(&e)
                    && stalls < MAX_TRANSIENT_POLLS
                    && tokio::time::Instant::now() < deadline =>
            {
                stalls += 1;
                eprintln!(
                    "hippius-miner-agent: backup: domain={} query-named-block-nodes failed ({e}), {stalls}/{MAX_TRANSIENT_POLLS} in a row; retrying",
                    domain.as_str(),
                );
                tokio::time::sleep(timing.poll).await;
            }
            other => return other,
        }
    }
}

/// A QMP failure that says the monitor (or libvirt's per-domain job lock
/// in front of it) is busy, not that anything went wrong in QEMU: virsh
/// timed out (`qmp-timeout`), or answered nothing but an error on stderr
/// (`qmp-virsh` — "cannot acquire state change lock" when another caller
/// holds the domain). A QMP `error` reply or a gone domain is not.
fn is_transient(e: &MinerAgentError) -> bool {
    matches!(e, MinerAgentError::Backup("qmp-timeout" | "qmp-virsh"))
}

/// Release every backup resource of ours in the domain, found by QUERY
/// rather than from what this process remembers sending (a reply lost
/// after QEMU acted must not leak anything): the job — cancelled and
/// WAITED for, since a running job can be neither dismissed nor have its
/// target deleted under it — then the target node, then our fdsets.
/// `true` iff all of it is gone (a domain that is gone took it along).
async fn release_resources(qmp: &dyn QmpTransport, domain: &DomainId, poll: Duration) -> bool {
    match finish_job(qmp, domain, poll).await {
        Ok(()) => {}
        Err(Gone) => return true,
        Err(Stuck) => return false,
    }
    let nodes = match qmp
        .execute(domain, &qmp::query_named_block_nodes(), None)
        .await
    {
        Ok(n) => n,
        Err(e) => return is_gone(&e),
    };
    if qmp::has_node(&nodes, qmp::TARGET_NODE) {
        if let Err(e) = qmp
            .execute(domain, &qmp::blockdev_del(qmp::TARGET_NODE), None)
            .await
        {
            return is_gone(&e);
        }
    }
    match qmp.execute(domain, &qmp::query_fdsets(), None).await {
        Ok(sets) => {
            let mut clean = true;
            for id in qmp::our_fdsets(&sets) {
                clean &= qmp.execute(domain, &qmp::remove_fd(id), None).await.is_ok();
            }
            clean
        }
        Err(e) => is_gone(&e),
    }
}

/// Outcome of bringing our job to `concluded` and dismissing it.
enum JobEnd {
    /// The domain is gone.
    Gone,
    /// The job would not conclude, or could not be dismissed.
    Stuck,
}
use JobEnd::{Gone, Stuck};

/// Cancel our job if it is still running, wait (bounded) for it to
/// conclude, dismiss it. No job at all is success. Transient QMP errors
/// are retried until the deadline, and the cancel is re-sent on every
/// poll until the job concludes (it is idempotent).
async fn finish_job(
    qmp: &dyn QmpTransport,
    domain: &DomainId,
    poll: Duration,
) -> std::result::Result<(), JobEnd> {
    let deadline = tokio::time::Instant::now() + CANCEL_WAIT;
    loop {
        match qmp.execute(domain, &qmp::query_jobs(), None).await {
            Err(e) if is_gone(&e) => return Err(Gone),
            Err(_) => {}
            Ok(jobs) => match qmp::find_job(&jobs, qmp::JOB_ID) {
                None => return Ok(()),
                Some(j) if j.status == "concluded" => {
                    match qmp
                        .execute(domain, &qmp::job_dismiss(qmp::JOB_ID), None)
                        .await
                    {
                        Ok(_) => return Ok(()),
                        Err(e) if is_gone(&e) => return Err(Gone),
                        Err(_) => {}
                    }
                }
                Some(_) => {
                    let _ = qmp
                        .execute(domain, &qmp::job_cancel(qmp::JOB_ID), None)
                        .await;
                }
            },
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Stuck);
        }
        tokio::time::sleep(poll).await;
    }
}

fn is_gone(e: &MinerAgentError) -> bool {
    matches!(e, MinerAgentError::Backup(c) if *c == qmp::NO_DOMAIN)
}

/// Drop one bitmap if present. `true` iff it is gone afterwards.
async fn drop_bitmap(qmp: &dyn QmpTransport, domain: &DomainId, node: &str, name: &str) -> bool {
    let nodes = match qmp
        .execute(domain, &qmp::query_named_block_nodes(), None)
        .await
    {
        Ok(n) => n,
        Err(e) => return is_gone(&e),
    };
    let present = nodes.as_array().is_some_and(|ns| {
        ns.iter().any(|n| {
            n.get("node-name").and_then(|v| v.as_str()) == Some(node)
                && n.get("dirty-bitmaps")
                    .and_then(|b| b.as_array())
                    .is_some_and(|bs| {
                        bs.iter()
                            .any(|b| b.get("name").and_then(|v| v.as_str()) == Some(name))
                    })
        })
    });
    if !present {
        return true;
    }
    match qmp
        .execute(domain, &qmp::bitmap_remove(node, name), None)
        .await
    {
        Ok(_) => true,
        Err(e) => is_gone(&e),
    }
}

/// Drop run point `bitmap` from the overlay node (a run that failed after
/// its capture must not be usable as a parent). `true` iff it is gone.
pub async fn discard_point(
    qmp: &dyn QmpTransport,
    domain: &DomainId,
    source_path: &Path,
    bitmap: &str,
) -> bool {
    match source_node(qmp, domain, source_path).await {
        Ok(node) => drop_bitmap(qmp, domain, &node.node_name, bitmap).await,
        // No overlay node ⇒ no bitmap on it.
        Err(MinerAgentError::Backup("source-node-missing")) => true,
        Err(e) => is_gone(&e),
    }
}

/// Release whatever an interrupted capture left inside QEMU (agent crash
/// or restart mid-run): the job, the target node, our fdsets, and — if
/// its copy never completed — the run's own point bitmap. `true` iff all
/// of it is gone.
pub async fn recover_interrupted(
    qmp: &dyn QmpTransport,
    domain: &DomainId,
    marker: &InflightMarker,
) -> bool {
    if !release_resources(qmp, domain, Duration::from_millis(500)).await {
        return false;
    }
    match &marker.new_bitmap {
        Some(bitmap) => discard_point(qmp, domain, &marker.source_path, bitmap).await,
        None => true,
    }
}

async fn write_marker(work_dir: &Path, marker: &InflightMarker) -> Result<()> {
    let body = serde_json::to_vec(marker).map_err(|_| MinerAgentError::Backup("marker"))?;
    let path = work_dir.join(INFLIGHT_MARKER);
    let tmp = work_dir.join(".inflight.json.tmp");
    let write = async {
        let mut f = tokio::fs::File::create(&tmp).await?;
        tokio::io::AsyncWriteExt::write_all(&mut f, &body).await?;
        f.sync_all().await?;
        tokio::fs::rename(&tmp, &path).await
    };
    write.await.map_err(|_| MinerAgentError::Backup("marker"))
}

async fn remove_marker(work_dir: &Path) {
    let _ = tokio::fs::remove_file(work_dir.join(INFLIGHT_MARKER)).await;
}

/// Read a VM work dir's in-flight marker, if any.
pub async fn read_marker(work_dir: &Path) -> Option<InflightMarker> {
    let raw = tokio::fs::read(work_dir.join(INFLIGHT_MARKER)).await.ok()?;
    serde_json::from_slice(&raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::qmp::mock::MockQmp;
    use async_trait::async_trait;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    struct FakeImg;

    #[async_trait]
    impl ImageTool for FakeImg {
        async fn create_qcow2(&self, path: &Path, _size: u64) -> Result<()> {
            std::fs::write(path, b"QFI\xfbfake").map_err(|_| MinerAgentError::Backup("x"))
        }
    }

    const OVERLAY: &str = "/var/lib/hippius-miner/overlay/vm-a.img";

    /// A QEMU stand-in with real state: bitmaps, one job, the target
    /// node, fdsets. The job concludes after `polls` queries (with
    /// `fail` as its outcome); `job-cancel` concludes it at once, unless
    /// `stuck`. The next `stalls` `query-jobs` fail as a busy monitor
    /// would; `tx_timeout` makes the `transaction` reply time out, after
    /// starting the job unless `tx_lost`. Once a job exists, the next
    /// `node_stalls` `query-named-block-nodes` fail the same way.
    #[derive(Default)]
    struct Qemu {
        bitmaps: Vec<String>,
        job: Option<(String, bool)>,
        polls_left: usize,
        fail: bool,
        stuck: bool,
        target: bool,
        fdsets: Vec<i64>,
        stalls: usize,
        tx_timeout: bool,
        tx_lost: bool,
        node_stalls: usize,
    }

    fn qemu(bitmaps: &[&str], polls: usize, fail: bool) -> (Arc<MockQmp>, Arc<Mutex<Qemu>>) {
        let st = Arc::new(Mutex::new(Qemu {
            bitmaps: bitmaps.iter().map(|s| s.to_string()).collect(),
            polls_left: polls,
            fail,
            ..Qemu::default()
        }));
        let s = Arc::clone(&st);
        let mock = MockQmp::new(move |c: &Value| {
            let mut q = s.lock().unwrap();
            let args = &c["arguments"];
            match c["execute"].as_str().unwrap() {
                "query-named-block-nodes" => {
                    if q.job.is_some() && q.node_stalls > 0 {
                        q.node_stalls -= 1;
                        return Err(MinerAgentError::Backup("qmp-virsh"));
                    }
                    let bms: Vec<Value> = q
                        .bitmaps
                        .iter()
                        .map(|n| json!({"name": n, "count": 65536}))
                        .collect();
                    let mut nodes = vec![json!({"node-name": "libvirt-1-storage", "drv": "file",
                        "file": OVERLAY, "image": {"virtual-size": 1048576u64},
                        "dirty-bitmaps": bms})];
                    if q.target {
                        nodes.push(json!({"node-name": qmp::TARGET_NODE, "drv": "file",
                            "file": "/dev/fdset/7", "image": {"virtual-size": 1048576u64}}));
                    }
                    Ok(json!(nodes))
                }
                "add-fd" => {
                    q.fdsets.push(7);
                    Ok(json!({"fdset-id": 7, "fd": 40}))
                }
                "blockdev-add" => {
                    q.target = true;
                    Ok(json!({}))
                }
                "blockdev-del" => {
                    if q.job.as_ref().is_some_and(|(s, _)| s != "concluded") {
                        return Err(MinerAgentError::Backup("qmp-error"));
                    }
                    q.target = false;
                    Ok(json!({}))
                }
                "remove-fd" => {
                    let id = args["fdset-id"].as_i64().unwrap();
                    q.fdsets.retain(|f| *f != id);
                    Ok(json!({}))
                }
                "transaction" => {
                    if q.tx_lost {
                        return Err(MinerAgentError::Backup("qmp-timeout"));
                    }
                    let a = &args["actions"];
                    let name = a[0]["data"]["name"].as_str().unwrap().to_string();
                    if let Some(parent) = a[1]["data"]["bitmap"].as_str() {
                        assert_eq!(a[1]["data"]["bitmap-mode"], "never");
                        if !q.bitmaps.iter().any(|b| b == parent) {
                            return Err(MinerAgentError::Backup("qmp-error"));
                        }
                    }
                    q.bitmaps.push(name);
                    q.job = Some(("running".into(), false));
                    if q.tx_timeout {
                        return Err(MinerAgentError::Backup("qmp-timeout"));
                    }
                    Ok(json!({}))
                }
                "block-dirty-bitmap-remove" => {
                    let name = args["name"].as_str().unwrap().to_string();
                    q.bitmaps.retain(|b| *b != name);
                    Ok(json!({}))
                }
                "query-jobs" => {
                    if q.stalls > 0 {
                        q.stalls -= 1;
                        // Both faces of #1246: virsh timing out, and
                        // libvirt refusing the domain's job lock.
                        let class = if q.stalls.is_multiple_of(2) {
                            "qmp-timeout"
                        } else {
                            "qmp-virsh"
                        };
                        return Err(MinerAgentError::Backup(class));
                    }
                    if let Some((status, _)) = q.job.clone() {
                        if status == "running" {
                            if q.polls_left <= 1 {
                                let f = q.fail;
                                q.job = Some(("concluded".into(), f));
                            } else {
                                q.polls_left -= 1;
                            }
                        }
                    }
                    Ok(match &q.job {
                        Some((status, failed)) => {
                            let mut j = json!({"id": qmp::JOB_ID, "status": status});
                            if *failed {
                                j["error"] = json!("Input/output error");
                            }
                            json!([j])
                        }
                        None => json!([]),
                    })
                }
                "job-cancel" => {
                    if !q.stuck {
                        q.job = Some(("concluded".into(), true));
                    }
                    Ok(json!({}))
                }
                "job-dismiss" => {
                    match &q.job {
                        Some((s, _)) if s == "concluded" => q.job = None,
                        _ => return Err(MinerAgentError::Backup("qmp-error")),
                    }
                    Ok(json!({}))
                }
                "query-fdsets" => Ok(json!(q
                    .fdsets
                    .iter()
                    .map(|id| json!({"fdset-id": id, "fds": [{"fd": 40, "opaque": qmp::FDSET_OPAQUE}]}))
                    .collect::<Vec<_>>())),
                _ => Ok(json!({})),
            }
        });
        (Arc::new(mock), st)
    }

    fn fast() -> JobTiming {
        JobTiming {
            poll: Duration::from_millis(1),
            timeout: Duration::from_secs(5),
        }
    }

    fn domain() -> DomainId {
        DomainId::new("hippius-tenant-vm-a").unwrap()
    }

    fn req<'a>(
        d: &'a DomainId,
        dir: &'a Path,
        kind: BackupKind,
        new: &'a str,
        parent: Option<&'a str>,
    ) -> CaptureRequest<'a> {
        CaptureRequest {
            domain: d,
            source_path: Path::new(OVERLAY),
            work_dir: dir,
            kind,
            new_bitmap: new,
            parent_bitmap: parent,
            headroom_bytes: 0,
            speed_bytes_per_sec: 192 << 20,
        }
    }

    fn assert_released(q: &Qemu, dir: &Path) {
        assert!(q.job.is_none(), "job dismissed");
        assert!(!q.target, "target node deleted");
        assert!(q.fdsets.is_empty(), "fdset removed");
        assert_eq!(
            std::fs::read_dir(dir).unwrap().count(),
            0,
            "no file, no marker"
        );
    }

    #[tokio::test]
    async fn full_runs_one_transaction_prunes_and_releases_everything() {
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&["hippius-bk-old", "hippius-bk-keep"], 3, false);
        let d = domain();
        let ledger = SpaceLedger::default();
        let r = req(
            &d,
            dir.path(),
            BackupKind::Full,
            "hippius-bk-r1",
            Some("hippius-bk-keep"),
        );
        let got = capture(m.as_ref(), &FakeImg, &ledger, &r, fast())
            .await
            .unwrap();
        assert_eq!(got.len, 1_048_576);
        assert_eq!(got.virtual_size, 1_048_576);
        assert_eq!(ledger.reserved(), 1_048_576, "held while the image lives");
        drop(got);
        assert_eq!(ledger.reserved(), 0);
        let ex = m.executed();
        let pos = |name: &str| ex.iter().position(|c| c == name).unwrap();
        assert_eq!(ex[0], "query-named-block-nodes");
        assert!(pos("block-dirty-bitmap-remove") < pos("add-fd"), "{ex:?}");
        assert!(pos("add-fd") < pos("blockdev-add"), "{ex:?}");
        assert!(pos("blockdev-add") < pos("transaction"), "{ex:?}");
        assert!(pos("transaction") < pos("job-dismiss"), "{ex:?}");
        assert!(pos("job-dismiss") < pos("blockdev-del"), "{ex:?}");
        assert!(pos("blockdev-del") < pos("remove-fd"), "{ex:?}");
        assert!(!ex.contains(&"job-cancel".to_string()));
        let calls = m.calls.lock().unwrap();
        assert!(calls
            .iter()
            .all(|(_, c, fd)| *fd == (c["execute"] == "add-fd")));
        assert!(calls.iter().all(|(dom, _, _)| dom == "hippius-tenant-vm-a"));
        drop(calls);
        let q = q.lock().unwrap();
        assert_eq!(q.bitmaps, ["hippius-bk-keep", "hippius-bk-r1"]);
        assert_released(&q, dir.path());
    }

    #[tokio::test]
    async fn incremental_reads_the_parent_and_leaves_it_intact() {
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&["hippius-bk-r1", "hippius-bk-stale"], 2, false);
        let d = domain();
        let ledger = SpaceLedger::default();
        let r = req(
            &d,
            dir.path(),
            BackupKind::Incremental,
            "hippius-bk-r2",
            Some("hippius-bk-r1"),
        );
        let got = capture(m.as_ref(), &FakeImg, &ledger, &r, fast())
            .await
            .unwrap();
        assert_eq!(got.len, 8); // the fake qcow2 bytes
        let calls = m.calls.lock().unwrap();
        let add = calls
            .iter()
            .find(|(_, c, _)| c["execute"] == "blockdev-add")
            .unwrap();
        assert_eq!(add.1["arguments"]["driver"], "qcow2");
        assert_eq!(add.1["arguments"]["file"]["filename"], "/dev/fdset/7");
        drop(calls);
        let q = q.lock().unwrap();
        // The parent survives (a failed upload of r2 can retry from r1);
        // the stale point is pruned; r2 is the new point.
        assert_eq!(q.bitmaps, ["hippius-bk-r1", "hippius-bk-r2"]);
        assert_released(&q, dir.path());
    }

    #[tokio::test]
    async fn a_failed_job_drops_only_its_own_new_bitmap() {
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&["hippius-bk-r1"], 1, true);
        let d = domain();
        let ledger = SpaceLedger::default();
        let r = req(
            &d,
            dir.path(),
            BackupKind::Incremental,
            "hippius-bk-r2",
            Some("hippius-bk-r1"),
        );
        let err = capture(m.as_ref(), &FakeImg, &ledger, &r, fast())
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("job-failed")));
        let q = q.lock().unwrap();
        assert_eq!(q.bitmaps, ["hippius-bk-r1"]);
        assert_released(&q, dir.path());
        assert_eq!(ledger.reserved(), 0);
    }

    #[tokio::test]
    async fn incremental_needs_its_parent() {
        let dir = tempfile::tempdir().unwrap();
        let (m, _) = qemu(&["hippius-bk-other"], 1, false);
        let d = domain();
        let ledger = SpaceLedger::default();
        let r = req(
            &d,
            dir.path(),
            BackupKind::Incremental,
            "hippius-bk-r2",
            Some("hippius-bk-r1"),
        );
        let err = capture(m.as_ref(), &FakeImg, &ledger, &r, fast())
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("bitmap-missing")));
        assert_eq!(m.executed(), ["query-named-block-nodes"]);
        let r = req(
            &d,
            dir.path(),
            BackupKind::Incremental,
            "hippius-bk-r2",
            None,
        );
        let err = capture(m.as_ref(), &FakeImg, &ledger, &r, fast())
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("parent-missing")));
    }

    #[tokio::test]
    async fn a_timed_out_job_is_cancelled_waited_for_and_released() {
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&["hippius-bk-r1"], usize::MAX, false);
        let d = domain();
        let ledger = SpaceLedger::default();
        let r = req(
            &d,
            dir.path(),
            BackupKind::Incremental,
            "hippius-bk-r2",
            Some("hippius-bk-r1"),
        );
        let timing = JobTiming {
            poll: Duration::from_millis(1),
            timeout: Duration::from_millis(5),
        };
        let err = capture(m.as_ref(), &FakeImg, &ledger, &r, timing)
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("job-timeout")));
        let ex = m.executed();
        let cancel = ex.iter().position(|c| c == "job-cancel").unwrap();
        let dismiss = ex.iter().position(|c| c == "job-dismiss").unwrap();
        let del = ex.iter().position(|c| c == "blockdev-del").unwrap();
        assert!(cancel < dismiss && dismiss < del, "{ex:?}");
        let q = q.lock().unwrap();
        assert_eq!(
            q.bitmaps,
            ["hippius-bk-r1"],
            "ambiguous run ⇒ its point is dropped"
        );
        assert_released(&q, dir.path());
    }

    #[tokio::test]
    async fn a_job_that_will_not_cancel_keeps_the_marker_and_blocks_the_next_run() {
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&["hippius-bk-r1"], usize::MAX, false);
        q.lock().unwrap().stuck = true;
        let d = domain();
        let ledger = SpaceLedger::default();
        let timing = JobTiming {
            poll: Duration::from_millis(1),
            timeout: Duration::from_millis(5),
        };
        let r = req(
            &d,
            dir.path(),
            BackupKind::Incremental,
            "hippius-bk-r2",
            Some("hippius-bk-r1"),
        );
        // CANCEL_WAIT is a minute in production; run the real bound under
        // paused time.
        tokio::time::pause();
        let err = capture(m.as_ref(), &FakeImg, &ledger, &r, timing)
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("job-timeout")));
        assert!(read_marker(dir.path()).await.is_some(), "marker kept");
        assert!(
            q.lock().unwrap().target,
            "never deleted under a running job"
        );

        let r3 = req(
            &d,
            dir.path(),
            BackupKind::Incremental,
            "hippius-bk-r3",
            Some("hippius-bk-r1"),
        );
        let err = capture(m.as_ref(), &FakeImg, &ledger, &r3, timing)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::Backup("previous-run-unreleased")
        ));

        // Once QEMU lets go, the next run cleans up and proceeds.
        {
            let mut q = q.lock().unwrap();
            q.stuck = false;
            q.polls_left = 1;
        }
        tokio::time::resume();
        capture(m.as_ref(), &FakeImg, &ledger, &r3, fast())
            .await
            .unwrap();
        let q = q.lock().unwrap();
        assert_eq!(q.bitmaps, ["hippius-bk-r1", "hippius-bk-r3"]);
        assert!(!q.target && q.fdsets.is_empty() && q.job.is_none());
    }

    #[tokio::test]
    async fn space_is_reserved_across_concurrent_captures() {
        let dir = tempfile::tempdir().unwrap();
        let free = free_bytes(dir.path()).unwrap();
        let ledger = SpaceLedger::default();
        let g = ledger.reserve(dir.path(), free / 2, 0).unwrap();
        assert!(matches!(
            ledger.reserve(dir.path(), free / 2 + (free / 4), 0),
            Err(MinerAgentError::Backup("insufficient-space"))
        ));
        drop(g);
        ledger.reserve(dir.path(), free / 2, 0).unwrap();
        assert_eq!(space_needed(BackupKind::Full, 100, 7), 100);
        assert_eq!(
            space_needed(BackupKind::Incremental, 1 << 40, 1 << 20),
            (1 << 20) + WRITE_SLACK_BYTES + (1 << 28) + (16 << 20)
        );
        assert_eq!(
            space_needed(BackupKind::Incremental, 1 << 20, 0),
            (1 << 20) + (1 << 8) + (16 << 20),
            "the write slack is capped at the disk size"
        );
    }

    #[tokio::test]
    async fn space_guard_refuses_before_touching_qemu_resources() {
        let dir = tempfile::tempdir().unwrap();
        let huge = u64::MAX / 2;
        let m = MockQmp::new(move |c: &Value| match c["execute"].as_str().unwrap() {
            "query-named-block-nodes" => Ok(json!([{"node-name": "n", "drv": "file",
                "file": OVERLAY, "image": {"virtual-size": huge}}])),
            _ => Ok(json!({})),
        });
        let d = domain();
        let ledger = SpaceLedger::default();
        let r = req(&d, dir.path(), BackupKind::Full, "hippius-bk-r1", None);
        let err = capture(&m, &FakeImg, &ledger, &r, fast())
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("insufficient-space")));
        assert_eq!(m.executed(), ["query-named-block-nodes"]);
    }

    #[tokio::test]
    async fn restart_recovery_releases_a_stranded_run() {
        let (m, q) = qemu(&["hippius-bk-r1", "hippius-bk-r2"], usize::MAX, false);
        {
            let mut q = q.lock().unwrap();
            q.job = Some(("running".into(), false));
            q.target = true;
            q.fdsets = vec![7];
        }
        let marker = InflightMarker {
            new_bitmap: Some("hippius-bk-r2".into()),
            source_path: OVERLAY.into(),
        };
        assert!(recover_interrupted(m.as_ref(), &domain(), &marker).await);
        let q = q.lock().unwrap();
        // The interrupted run's point is gone, its parent kept.
        assert_eq!(q.bitmaps, ["hippius-bk-r1"]);
        assert!(!q.target && q.fdsets.is_empty() && q.job.is_none());
    }

    #[tokio::test]
    async fn recovery_of_a_gone_domain_is_clean() {
        let m = MockQmp::new(|_| Err(MinerAgentError::Backup(qmp::NO_DOMAIN)));
        let marker = InflightMarker {
            new_bitmap: Some("hippius-bk-r2".into()),
            source_path: OVERLAY.into(),
        };
        assert!(recover_interrupted(&m, &domain(), &marker).await);
    }

    #[tokio::test]
    async fn a_completed_run_whose_release_is_late_keeps_its_point() {
        // The copy finished (and vali may commit it) but QEMU would not
        // let go of the target. The next run's recovery must release the
        // resources WITHOUT dropping the completed run's point.
        let (m, q) = qemu(&["hippius-bk-r1", "hippius-bk-r2"], usize::MAX, false);
        {
            let mut q = q.lock().unwrap();
            q.target = true;
            q.fdsets = vec![7];
        }
        let marker = InflightMarker {
            new_bitmap: None,
            source_path: OVERLAY.into(),
        };
        assert!(recover_interrupted(m.as_ref(), &domain(), &marker).await);
        let q = q.lock().unwrap();
        assert_eq!(q.bitmaps, ["hippius-bk-r1", "hippius-bk-r2"]);
        assert!(!q.target && q.fdsets.is_empty());
    }

    #[tokio::test]
    async fn a_replayed_run_never_retakes_its_point() {
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&["hippius-bk-r1", "hippius-bk-r2"], 1, false);
        let d = domain();
        let ledger = SpaceLedger::default();
        let r = req(
            &d,
            dir.path(),
            BackupKind::Incremental,
            "hippius-bk-r2",
            Some("hippius-bk-r1"),
        );
        let err = capture(m.as_ref(), &FakeImg, &ledger, &r, fast())
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("run-exists")));
        assert_eq!(
            q.lock().unwrap().bitmaps,
            ["hippius-bk-r1", "hippius-bk-r2"]
        );
        assert_eq!(m.executed(), ["query-named-block-nodes"]);
    }

    #[tokio::test]
    async fn a_stuck_release_strands_the_space_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&["hippius-bk-r1"], usize::MAX, false);
        q.lock().unwrap().stuck = true;
        let d = domain();
        let ledger = SpaceLedger::default();
        let timing = JobTiming {
            poll: Duration::from_millis(1),
            timeout: Duration::from_millis(5),
        };
        let r = req(
            &d,
            dir.path(),
            BackupKind::Incremental,
            "hippius-bk-r2",
            Some("hippius-bk-r1"),
        );
        tokio::time::pause();
        let _ = capture(m.as_ref(), &FakeImg, &ledger, &r, timing)
            .await
            .unwrap_err();
        assert!(ledger.reserved() > 0, "QEMU may still grow the target");
    }

    /// Whether `dir`'s filesystem takes `O_DIRECT` (tmpfs before 6.6
    /// does not; the capture then falls back to a buffered target).
    fn fs_does_direct_io(dir: &Path) -> bool {
        use std::os::unix::fs::OpenOptionsExt;
        let p = dir.join("probe");
        let ok = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .custom_flags(nix::fcntl::OFlag::O_DIRECT.bits())
            .open(&p)
            .is_ok();
        let _ = std::fs::remove_file(&p);
        ok
    }

    fn getfl(f: &std::fs::File) -> nix::fcntl::OFlag {
        nix::fcntl::OFlag::from_bits_truncate(
            nix::fcntl::fcntl(f, nix::fcntl::FcntlArg::F_GETFL).unwrap(),
        )
    }

    #[tokio::test]
    async fn qemu_writes_the_target_o_direct_and_the_copy_is_capped() {
        use nix::fcntl::OFlag;
        let dir = tempfile::tempdir().unwrap();
        let direct = fs_does_direct_io(dir.path());
        let (m, q) = qemu(&[], 1, false);
        let d = domain();
        let ledger = SpaceLedger::default();
        let r = req(&d, dir.path(), BackupKind::Full, "hippius-bk-r1", None);
        let got = capture(m.as_ref(), &FakeImg, &ledger, &r, fast())
            .await
            .unwrap();
        // QEMU's descriptor: read-write, O_DIRECT, and `cache.direct`
        // saying the same — QEMU matches the two when it opens the fdset.
        let flags = m.fd_flags.lock().unwrap().clone();
        assert_eq!(flags.len(), 1);
        assert!(flags[0].contains(OFlag::O_RDWR));
        assert_eq!(flags[0].contains(OFlag::O_DIRECT), direct);
        let calls = m.calls.lock().unwrap();
        let find = |name: &str| {
            calls
                .iter()
                .find(|(_, c, _)| c["execute"] == name)
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(find("blockdev-add")["arguments"]["cache"]["direct"], direct);
        assert_eq!(
            find("transaction")["arguments"]["actions"][1]["data"]["speed"],
            192 << 20
        );
        drop(calls);
        // The agent's own descriptor stays buffered: the upload reads it
        // with buffers of any alignment.
        assert!(!getfl(&got.file).contains(OFlag::O_DIRECT));
        assert_eq!(got.len, 1_048_576);
        drop(got);
        assert_released(&q.lock().unwrap(), dir.path());
    }

    #[tokio::test]
    async fn an_unaligned_raw_target_is_written_through_the_page_cache() {
        let dir = tempfile::tempdir().unwrap();
        let direct = fs_does_direct_io(dir.path());
        let d = domain();
        let r = req(&d, dir.path(), BackupKind::Full, "hippius-bk-r1", None);
        let (file, qemu) = create_unlinked_target(&FakeImg, &r, (1 << 20) + 512)
            .await
            .unwrap();
        assert!(!qemu.direct);
        assert!(!getfl(&qemu.file).contains(nix::fcntl::OFlag::O_DIRECT));
        assert_eq!(file.metadata().unwrap().len(), (1 << 20) + 512);
        let (_, qemu) = create_unlinked_target(&FakeImg, &r, 1 << 20).await.unwrap();
        assert_eq!(qemu.direct, direct);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn a_stalled_monitor_during_the_copy_is_ridden_out() {
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&[], 3, false);
        q.lock().unwrap().stalls = MAX_TRANSIENT_POLLS as usize;
        let d = domain();
        let ledger = SpaceLedger::default();
        let r = req(&d, dir.path(), BackupKind::Full, "hippius-bk-r1", None);
        capture(m.as_ref(), &FakeImg, &ledger, &r, fast())
            .await
            .unwrap();
        let q = q.lock().unwrap();
        assert_eq!(q.bitmaps, ["hippius-bk-r1"]);
        assert_released(&q, dir.path());
    }

    #[tokio::test]
    async fn a_job_that_failed_behind_a_stall_still_fails_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&["hippius-bk-r1"], 2, true);
        q.lock().unwrap().stalls = 3;
        let d = domain();
        let ledger = SpaceLedger::default();
        let r = req(
            &d,
            dir.path(),
            BackupKind::Incremental,
            "hippius-bk-r2",
            Some("hippius-bk-r1"),
        );
        let err = capture(m.as_ref(), &FakeImg, &ledger, &r, fast())
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("job-failed")));
        let q = q.lock().unwrap();
        assert_eq!(q.bitmaps, ["hippius-bk-r1"]);
        assert_released(&q, dir.path());
    }

    #[tokio::test]
    async fn polling_gives_up_only_on_a_run_of_stalls_or_a_real_error() {
        let d = domain();
        // Silent for good: fails after the bound, with the stall's class.
        let m = MockQmp::new(|_| Err(MinerAgentError::Backup("qmp-virsh")));
        let err = wait_concluded(&m, &d, fast(), "job-vanished")
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("qmp-virsh")));
        assert_eq!(m.executed().len(), MAX_TRANSIENT_POLLS as usize + 1);

        // A QMP error reply is not a stall.
        let m = MockQmp::new(|_| Err(MinerAgentError::Backup("qmp-error")));
        let err = wait_concluded(&m, &d, fast(), "job-vanished")
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("qmp-error")));
        assert_eq!(m.executed().len(), 1);

        // Stalls broken up by answers never add up: twice the bound in
        // total, two in a row at most.
        let n = std::sync::atomic::AtomicUsize::new(0);
        let total = 3 * MAX_TRANSIENT_POLLS as usize;
        let m = MockQmp::new(move |_| {
            let i = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            match i {
                i if i >= total => Ok(json!([{"id": qmp::JOB_ID, "status": "concluded"}])),
                i if i % 3 == 0 => Ok(json!([{"id": qmp::JOB_ID, "status": "running"}])),
                _ => Err(MinerAgentError::Backup("qmp-timeout")),
            }
        });
        let job = wait_concluded(&m, &d, fast(), "job-vanished")
            .await
            .unwrap();
        assert!(!job.failed);
    }

    #[tokio::test]
    async fn a_transaction_that_timed_out_is_polled_to_its_outcome() {
        // QEMU started the job; only the reply was lost.
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&[], 2, false);
        q.lock().unwrap().tx_timeout = true;
        let d = domain();
        let ledger = SpaceLedger::default();
        let r = req(&d, dir.path(), BackupKind::Full, "hippius-bk-r1", None);
        capture(m.as_ref(), &FakeImg, &ledger, &r, fast())
            .await
            .unwrap();
        assert_released(&q.lock().unwrap(), dir.path());

        // No job behind the timeout: the run fails as the timeout, and
        // the release still clears the target and the fdset by query.
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&[], 2, false);
        q.lock().unwrap().tx_lost = true;
        let err = capture(
            m.as_ref(),
            &FakeImg,
            &ledger,
            &req(&d, dir.path(), BackupKind::Full, "hippius-bk-r1", None),
            fast(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("qmp-timeout")));
        let q = q.lock().unwrap();
        assert!(q.bitmaps.is_empty());
        assert_released(&q, dir.path());
    }

    fn incremental<'a>(d: &'a DomainId, dir: &'a Path) -> CaptureRequest<'a> {
        req(
            d,
            dir,
            BackupKind::Incremental,
            "hippius-bk-r2",
            Some("hippius-bk-r1"),
        )
    }

    #[tokio::test]
    async fn an_incremental_whose_transaction_timed_out_rides_out_the_job_lock() {
        // libvirt holds the domain's job lock until QEMU answers the
        // timed-out transaction: the space re-read after it stalls too.
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&["hippius-bk-r1"], 2, false);
        {
            let mut q = q.lock().unwrap();
            q.tx_timeout = true;
            q.node_stalls = 3;
        }
        let d = domain();
        let ledger = SpaceLedger::default();
        capture(
            m.as_ref(),
            &FakeImg,
            &ledger,
            &incremental(&d, dir.path()),
            fast(),
        )
        .await
        .unwrap();
        let q = q.lock().unwrap();
        assert_eq!(q.bitmaps, ["hippius-bk-r1", "hippius-bk-r2"]);
        assert_released(&q, dir.path());
    }

    #[tokio::test]
    async fn the_incremental_space_re_read_rides_out_a_stall_up_to_the_bound() {
        let d = domain();
        let ledger = SpaceLedger::default();
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&["hippius-bk-r1"], 2, false);
        q.lock().unwrap().node_stalls = MAX_TRANSIENT_POLLS as usize;
        capture(
            m.as_ref(),
            &FakeImg,
            &ledger,
            &incremental(&d, dir.path()),
            fast(),
        )
        .await
        .unwrap();
        assert_released(&q.lock().unwrap(), dir.path());

        // One stall past the bound fails the run — and releases it.
        let dir = tempfile::tempdir().unwrap();
        let (m, q) = qemu(&["hippius-bk-r1"], usize::MAX, false);
        q.lock().unwrap().node_stalls = MAX_TRANSIENT_POLLS as usize + 1;
        let err = capture(
            m.as_ref(),
            &FakeImg,
            &ledger,
            &incremental(&d, dir.path()),
            fast(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("qmp-virsh")));
        let q = q.lock().unwrap();
        assert_eq!(q.bitmaps, ["hippius-bk-r1"]);
        assert_released(&q, dir.path());
    }

    #[tokio::test]
    async fn marker_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let m = InflightMarker {
            new_bitmap: Some("hippius-bk-r1".into()),
            source_path: OVERLAY.into(),
        };
        write_marker(dir.path(), &m).await.unwrap();
        assert_eq!(read_marker(dir.path()).await.unwrap(), m);
        remove_marker(dir.path()).await;
        assert!(read_marker(dir.path()).await.is_none());
    }

    // ── the host ledger (one account with the per-VM disk creates) ──

    /// A sparse per-VM disk under `root` promising all but `leave` bytes
    /// of the filesystem's free space.
    fn promise_all_but(root: &Path, leave: u64) {
        let free = free_bytes(root).unwrap();
        let dir = crate::lifecycle::data_disk::data_dir(root);
        std::fs::create_dir_all(&dir).unwrap();
        let f = std::fs::File::create(dir.join("filler.img")).unwrap();
        f.set_len(free.saturating_sub(leave)).unwrap();
    }

    #[test]
    fn the_host_ledger_cannot_take_bytes_promised_to_a_live_disk() {
        let tmp = tempfile::TempDir::new().unwrap();
        promise_all_but(tmp.path(), 512 << 20);
        let err = SpaceLedger::host(tmp.path())
            .reserve(tmp.path(), 1 << 30, 0)
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("insufficient-space")));
        // The raw-`statvfs` ledger sees the space the sparse disk has not
        // written yet — the double count the host ledger exists to stop.
        assert!(SpaceLedger::default()
            .reserve(tmp.path(), 1 << 30, 0)
            .is_ok());
    }

    #[test]
    fn a_host_reservation_is_the_counter_every_disk_create_reads() {
        let _tight = crate::lifecycle::disk_space::tight_tests();
        let tmp = tempfile::TempDir::new().unwrap();
        // 1.5 GiB of real headroom; a backup holds 1 GiB of it.
        promise_all_but(tmp.path(), 3 << 29);
        let host = SpaceLedger::host(tmp.path());
        let held = host.reserve(tmp.path(), 1 << 30, 0).expect("fits");
        assert!(*crate::lifecycle::disk_space::create_lock() >= 1 << 30);
        let vm = crate::lifecycle::VmId::new("tenant-behind-a-backup").unwrap();
        assert!(matches!(
            crate::lifecycle::data_disk::ensure_data_disk_bytes(tmp.path(), &vm, 1 << 30),
            Err(MinerAgentError::DataDisk("insufficient-space"))
        ));
        assert!(matches!(
            crate::lifecycle::golden::ensure_overlay_disk_bytes(tmp.path(), &vm, 1 << 30),
            Err(MinerAgentError::OverlayDisk("insufficient-space"))
        ));
        drop(held);
        crate::lifecycle::data_disk::ensure_data_disk_bytes(tmp.path(), &vm, 1 << 30)
            .expect("fits once the backup's reservation is released");
    }

    #[tokio::test]
    async fn a_full_backup_is_refused_the_space_a_live_disk_was_promised() {
        let dir = tempfile::tempdir().unwrap();
        promise_all_but(dir.path(), 0);
        let (m, _q) = qemu(&[], 3, false);
        let d = domain();
        let ledger = SpaceLedger::host(dir.path());
        let r = req(&d, dir.path(), BackupKind::Full, "hippius-bk-r1", None);
        let err = capture(m.as_ref(), &FakeImg, &ledger, &r, fast())
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("insufficient-space")));
        assert_eq!(ledger.reserved(), 0, "nothing held after a refusal");
    }

    #[test]
    fn isolated_ledgers_do_not_share_a_counter() {
        let tmp = tempfile::TempDir::new().unwrap();
        let a = SpaceLedger::default();
        let _held = a.reserve(tmp.path(), 4096, 0).unwrap();
        assert_eq!(a.reserved(), 4096);
        assert_eq!(SpaceLedger::default().reserved(), 0);
    }
}
