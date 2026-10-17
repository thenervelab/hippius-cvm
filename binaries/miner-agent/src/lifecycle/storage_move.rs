//! Live storage move: a running golden VM's OS disk (the overlay,
//! `/dev/vda`) moves from one storage pool of this host to another with no
//! downtime — libvirt block copy into a pre-created file, pivot, then the
//! persistent definition rewritten (the disk-tier live storage move).
//!
//! ## Phases, journaled
//!
//! `<state_root>/moves/<vm>.json` is written atomically BEFORE each
//! transition, so a crash anywhere resumes ([`CvmLifecycle::resume_moves`]):
//!
//! | phase | the VM runs on | the persistent XML | a failure… |
//! |---|---|---|---|
//! | `prepared`  | src | src | aborts: dst deleted |
//! | `copying`   | src (mirrored) | src | aborts: job aborted, dst deleted |
//! | `pivoting`  | src or dst | src | dst if libvirt pivoted, else aborts |
//! | `pivoted`   | dst | src → **redefine** | retried, NEVER back to src |
//! | `redefined` | dst | dst | src kept until vali `release`s it |
//! | `done`      | dst | dst | n/a |
//!
//! The source stays authoritative until the pivot; after it, only forward.
//! A guest stop / reboot during the copy kills the mirror (QEMU exits): the
//! reboot watcher asks [`CvmLifecycle::settle_move_before_restart`] first,
//! which aborts the copy (the VM restarts on src) or redefines to dst (the
//! VM restarts on dst, never on the stale src). While a move is before
//! `redefined`, a launch, a backup and a §25 quiesce of the VM are refused
//! (`vm-storage-move-in-progress`); a destroy aborts it.
//!
//! One move per host. The destination is admitted like a launch's pool
//! (active, OS disks, bound), and must hold the disk within its budget and
//! its free space before anything is created.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{adopt, golden, vm_pool, CvmLifecycle, CvmPhase, DomainId, DomainLiveness, VmId};
use crate::error::{MinerAgentError, Result};
use crate::orders::{MoveAction, MoveVmStorageOrder};

/// Under the agent's state root.
pub const MOVES_DIR: &str = "moves";

/// The disk a move copies.
const DISK: &str = "vda";

/// Polls for a late block job before a `prepared` move's copy is deleted.
const PREPARED_JOB_GRACE_ROUNDS: usize = 3;

/// A move's phase (module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MovePhase {
    Prepared,
    Copying,
    Pivoting,
    Pivoted,
    Redefined,
    Done,
    Aborted,
    Failed,
}

impl MovePhase {
    /// Before the persistent definition names dst: the VM's other
    /// operations must wait.
    pub fn blocks_vm(self) -> bool {
        matches!(
            self,
            Self::Prepared | Self::Copying | Self::Pivoting | Self::Pivoted
        )
    }

    /// Holds the host's one move (both copies exist).
    pub fn is_active(self) -> bool {
        self.blocks_vm() || self == Self::Redefined
    }
}

/// One move, as journaled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveJournal {
    pub move_id: String,
    pub vm_id: String,
    pub src_pool: String,
    pub dst_pool: String,
    /// The overlay file the VM ran on, and the one it moves to.
    pub src: PathBuf,
    pub dst: PathBuf,
    pub dst_root: PathBuf,
    pub bytes_total: u64,
    pub bandwidth_mib_s: u32,
    pub phase: MovePhase,
    /// Set on `aborted` / `failed`.
    pub code: Option<String>,
    pub started_at: u64,
    pub updated_at: u64,
}

/// What the order route answers (`status`, and every other action).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MoveStatus {
    pub move_id: String,
    pub vm_id: String,
    pub phase: MovePhase,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub src_pool: String,
    pub dst_pool: String,
    pub started_at: u64,
    pub updated_at: u64,
    pub code: Option<String>,
}

/// In-process state of the moves.
#[derive(Debug)]
pub struct MoveRuntime {
    /// VMs whose move a driver task runs.
    driving: Mutex<HashSet<VmId>>,
    /// How often a driver polls libvirt.
    poll: Mutex<Duration>,
    /// Serializes the start/cancel/release/settle decisions of the host.
    ops: tokio::sync::Mutex<()>,
}

impl Default for MoveRuntime {
    fn default() -> Self {
        Self {
            driving: Mutex::new(HashSet::new()),
            poll: Mutex::new(Duration::from_secs(2)),
            ops: tokio::sync::Mutex::new(()),
        }
    }
}

fn moves_dir(state_root: &Path) -> PathBuf {
    state_root.join(MOVES_DIR)
}

fn journal_path(state_root: &Path, vm_id: &VmId) -> PathBuf {
    moves_dir(state_root).join(format!("{}.json", vm_id.as_str()))
}

fn dest_xml_path(state_root: &Path, vm_id: &VmId) -> PathBuf {
    moves_dir(state_root).join(format!("{}.dest.xml", vm_id.as_str()))
}

/// `vm_id`'s journal (`Ok(None)`: none).
pub fn read_journal(state_root: &Path, vm_id: &VmId) -> Result<Option<MoveJournal>> {
    match std::fs::read(journal_path(state_root, vm_id)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| MinerAgentError::StorageMove("move-journal-unreadable")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(MinerAgentError::StorageMove("move-journal-unreadable")),
    }
}

fn write_journal(state_root: &Path, journal: &MoveJournal) -> Result<()> {
    use std::io::Write;
    let fail = |_| MinerAgentError::StorageMove("move-journal-unwritable");
    let dir = moves_dir(state_root);
    std::fs::create_dir_all(&dir).map_err(fail)?;
    let vm = VmId::new(&journal.vm_id)?;
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|_| MinerAgentError::StorageMove("move-journal-unwritable"))?;
    let mut tmp = tempfile::NamedTempFile::new_in(&dir).map_err(fail)?;
    tmp.write_all(&bytes).map_err(fail)?;
    tmp.as_file().sync_all().map_err(fail)?;
    tmp.persist(journal_path(state_root, &vm))
        .map_err(|_| MinerAgentError::StorageMove("move-journal-unwritable"))?;
    std::fs::File::open(&dir)
        .and_then(|d| d.sync_all())
        .map_err(fail)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn domain_of(vm_id: &VmId) -> Result<DomainId> {
    DomainId::new(&format!(
        "{}{}",
        super::TENANT_DOMAIN_PREFIX,
        vm_id.as_str()
    ))
}

/// The disk XML `virsh blockcopy --xml` reads: the destination file, as
/// the domain's own vda is rendered (raw, no host cache).
fn dest_disk_xml(dst: &Path) -> Result<String> {
    let path = dst
        .to_str()
        .filter(|p| !p.contains(['\'', '<', '>', '&', '"']))
        .ok_or(MinerAgentError::StorageMove("move-pool-unknown"))?;
    Ok(format!(
        "<disk type='file' device='disk'>\n  <driver name='qemu' type='raw' cache='none'/>\n  \
         <source file='{path}'/>\n</disk>\n"
    ))
}

impl MoveJournal {
    /// A stop mid-pivot: which copy holds the guest's last writes is not
    /// known. Both copies are kept and the VM is held until an operator
    /// decides.
    fn pivot_unknown(&self) -> bool {
        self.phase == MovePhase::Failed && self.code.as_deref() == Some("move-pivot-unknown")
    }

    /// The VM's other operations must wait ([`MovePhase::blocks_vm`], or a
    /// pivot whose outcome is unknown).
    pub fn blocks_vm(&self) -> bool {
        self.phase.blocks_vm() || self.pivot_unknown()
    }

    /// Holds the host's one move.
    pub fn is_active(&self) -> bool {
        self.phase.is_active() || self.pivot_unknown()
    }
}

/// Every journal on this host, and how many could not be read (a move
/// nobody can read still holds the host: callers refuse new moves).
fn all_journals(state_root: &Path) -> (Vec<MoveJournal>, usize) {
    let entries = match std::fs::read_dir(moves_dir(state_root)) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Vec::new(), 0),
        Err(_) => return (Vec::new(), 1),
    };
    let (mut out, mut unreadable) = (Vec::new(), 0);
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(vm) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
            continue;
        };
        match VmId::new(vm).map(|vm| read_journal(state_root, &vm)) {
            Ok(Ok(Some(journal))) => out.push(journal),
            Ok(Ok(None)) => {}
            _ => {
                eprintln!(
                    "hippius-miner-agent: storage-move: journal {} unreadable — the host takes \
                     no move until an operator looks at it",
                    entry.path().display()
                );
                unreadable += 1;
            }
        }
    }
    (out, unreadable)
}

/// A libvirt call of a move, bounded: a hung virsh must not hold the
/// host's move lock (and every restart and destroy behind it) forever.
async fn bounded<T>(fut: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(60), fut)
        .await
        .unwrap_or(Err(MinerAgentError::StorageMove("move-libvirt-timeout")))
}

/// The GiB a move holds on each of its pools (both copies exist until the
/// source is released): `(pool root, GiB)`.
fn held_gb(journal: &MoveJournal) -> Vec<(PathBuf, u64)> {
    let gb = journal.bytes_total.div_ceil(1 << 30);
    let src_root = journal
        .src
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf);
    let both = || {
        let mut v = vec![(journal.dst_root.clone(), gb)];
        v.extend(src_root.clone().map(|r| (r, gb)));
        v
    };
    match journal.phase {
        // The VM is accounted on src (its handle): dst is the extra copy.
        MovePhase::Prepared | MovePhase::Copying => vec![(journal.dst_root.clone(), gb)],
        // Between the pivot and the redefine (or when it is unknown) the
        // handle may name either copy: both are counted (over, never under).
        MovePhase::Pivoting | MovePhase::Pivoted => both(),
        MovePhase::Failed if journal.pivot_unknown() => both(),
        // Accounted on dst now: src is the extra copy.
        MovePhase::Redefined => src_root.map(|r| vec![(r, gb)]).unwrap_or_default(),
        _ => Vec::new(),
    }
}

impl CvmLifecycle {
    /// How often a move driver polls libvirt (tests shorten it).
    pub fn with_move_poll(self, poll: Duration) -> Self {
        if let Ok(mut p) = self.moves.poll.lock() {
            *p = poll;
        }
        self
    }

    fn move_poll(&self) -> Duration {
        self.moves
            .poll
            .lock()
            .map(|p| *p)
            .unwrap_or(Duration::from_secs(2))
    }

    /// The host's move lock, for a §24 destroy of a VM that has a move
    /// journal (any phase; an unreadable one too): held from start to end.
    pub async fn move_ops_for(&self, vm_id: &VmId) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        if matches!(read_journal(&self.state_disk_root, vm_id), Ok(None)) {
            return None;
        }
        Some(self.moves.ops.lock().await)
    }

    /// Refuse an operation on `vm_id` while its move has not yet made the
    /// persistent definition name the destination.
    pub fn check_no_move(&self, vm_id: &VmId) -> Result<()> {
        match read_journal(&self.state_disk_root, vm_id)? {
            Some(j) if j.blocks_vm() => {
                Err(MinerAgentError::StorageMove("vm-storage-move-in-progress"))
            }
            _ => Ok(()),
        }
    }

    /// The VM's journal is this move: a re-sent `start` answers it before
    /// any other check.
    pub fn is_journaled_move(&self, vm_id: &VmId, move_id: &str) -> bool {
        matches!(
            read_journal(&self.state_disk_root, vm_id),
            Ok(Some(j)) if j.move_id == move_id
        )
    }

    /// The GiB live moves hold on the pool at `root` beyond what the VMs'
    /// handles account (the second copy).
    pub fn move_held_gb(&self, root: &Path) -> u64 {
        all_journals(&self.state_disk_root)
            .0
            .iter()
            .flat_map(held_gb)
            .filter(|(r, _)| r == root)
            .map(|(_, gb)| gb)
            .sum()
    }

    /// The `move-vm-storage` order.
    pub async fn storage_move(self: &Arc<Self>, order: &MoveVmStorageOrder) -> Result<MoveStatus> {
        match order.action {
            MoveAction::Start => self.start_move(order).await,
            MoveAction::Status => self.move_status(&order.vm_id, &order.move_id).await,
            MoveAction::Cancel => self.cancel_move(&order.vm_id, &order.move_id).await,
            MoveAction::Release => self.release_move(&order.vm_id, &order.move_id).await,
        }
    }

    async fn start_move(self: &Arc<Self>, order: &MoveVmStorageOrder) -> Result<MoveStatus> {
        let vm_id = &order.vm_id;
        let (Some(target), Some(source), Some(bandwidth)) = (
            order.target_pool.as_deref(),
            order.expected_source_pool.as_deref(),
            order.bandwidth_mib_s,
        ) else {
            return Err(MinerAgentError::StorageMove("move-start-field-missing"));
        };
        let _ops = self.moves.ops.lock().await;
        // Idempotent on `move_id`.
        if let Some(j) = read_journal(&self.state_disk_root, vm_id)? {
            if j.move_id == order.move_id {
                if j.phase.blocks_vm() {
                    self.spawn_driver(vm_id);
                }
                return self.status_of(&j).await;
            }
        }
        // A start that waited past its validity (behind the move lock, or
        // in transit) never begins a copy: vali may have given it up.
        if now_unix() > order.not_after_unix {
            return Err(MinerAgentError::StorageMove("move-order-expired"));
        }
        let (journals, unreadable) = all_journals(&self.state_disk_root);
        if unreadable > 0 || journals.iter().any(MoveJournal::is_active) {
            return Err(MinerAgentError::StorageMove("move-busy"));
        }
        // The VM: tracked, running, golden (a raw overlay), on the pool
        // vali believes.
        let src = {
            let handles = self.lock_handles()?;
            let handle = handles
                .get(vm_id)
                .ok_or(MinerAgentError::StorageMove("move-vm-not-found"))?;
            if handle.phase != CvmPhase::Running {
                return Err(MinerAgentError::StorageMove("move-domain-not-running"));
            }
            handle.luks_disk_path.clone()
        };
        if self.tenant_domain_liveness(vm_id).await != DomainLiveness::Live {
            return Err(MinerAgentError::StorageMove("move-domain-not-running"));
        }
        let src_root = golden::overlay_root(&src, vm_id)
            .ok_or(MinerAgentError::StorageMove("move-not-golden"))?;
        let domain = domain_of(vm_id)?;
        let live = bounded(self.driver.domain_xml(&domain)).await?;
        if super::libvirt_driver::vda_driver_type(&live).as_deref() != Some("raw")
            || adopt::writable_disk_path(&live).as_deref() != Some(src.as_path())
        {
            return Err(MinerAgentError::StorageMove("move-not-golden"));
        }
        let pools = self.pools.pools();
        let src_pool = pools
            .iter()
            .find(|p| p.path == src_root)
            .map(|p| p.id.clone())
            .ok_or(MinerAgentError::StorageMove("move-source-mismatch"))?;
        if src_pool != source {
            return Err(MinerAgentError::StorageMove("move-source-mismatch"));
        }
        let pool = pools
            .get(target)
            .ok_or(MinerAgentError::StorageMove("move-pool-unknown"))?;
        if pool.path == src_root {
            return Err(MinerAgentError::StorageMove("move-same-pool"));
        }
        if pool.draining {
            return Err(MinerAgentError::StorageMove("move-pool-not-active"));
        }
        if !pool.os_disks {
            return Err(MinerAgentError::StorageMove("move-pool-no-os-disks"));
        }
        if !pool.is_default() && self.admit_pool(pool).is_err() {
            return Err(MinerAgentError::StorageMove("move-pool-unavailable"));
        }
        let bytes_total = std::fs::metadata(&src)
            .map_err(|_| MinerAgentError::StorageMove("move-not-golden"))?
            .len();
        let gb = u32::try_from(bytes_total.div_ceil(1 << 30))
            .map_err(|_| MinerAgentError::StorageMove("move-pool-insufficient-space"))?;
        // Both copies count while moving: the target's budget must hold it.
        if self.check_pool_disk_budget(pool, gb).is_err() {
            return Err(MinerAgentError::StorageMove("move-pool-insufficient-space"));
        }
        let dst = golden::overlay_disk_path(&pool.path, vm_id);
        match dst.try_exists() {
            Ok(false) => {}
            // Not ours (no journal names it): never overwritten.
            Ok(true) => return Err(MinerAgentError::StorageMove("move-dst-exists")),
            Err(_) => return Err(MinerAgentError::StorageMove("move-pool-unavailable")),
        }
        let now = now_unix();
        let mut journal = MoveJournal {
            move_id: order.move_id.clone(),
            vm_id: vm_id.as_str().to_string(),
            src_pool,
            dst_pool: pool.id.clone(),
            src: src.clone(),
            dst: dst.clone(),
            dst_root: pool.path.clone(),
            bytes_total,
            bandwidth_mib_s: bandwidth,
            phase: MovePhase::Prepared,
            code: None,
            started_at: now,
            updated_at: now,
        };
        drop(pools);
        // The journal before the file: a crash in between leaves a journal
        // the resume aborts (deleting whatever was created), never a file
        // nobody knows.
        write_journal(&self.state_disk_root, &journal)?;
        let (root, id) = (journal.dst_root.clone(), vm_id.clone());
        let created = tokio::task::spawn_blocking(move || {
            golden::ensure_overlay_disk_bytes(&root, &id, bytes_total)
        })
        .await
        .unwrap_or(Err(MinerAgentError::OverlayDisk("join")));
        if let Err(err) = created {
            let code = match err {
                MinerAgentError::OverlayDisk("insufficient-space") => {
                    "move-pool-insufficient-space"
                }
                _ => "move-dst-create-failed",
            };
            if self.finish_abort(&mut journal, code).await.is_err() {
                // The driver settles the copy (never left `prepared`
                // without one).
                self.spawn_driver(vm_id);
            }
            return Err(MinerAgentError::StorageMove(code));
        }
        let xml_path = dest_xml_path(&self.state_disk_root, vm_id);
        let written = dest_disk_xml(&dst).and_then(|xml| {
            std::fs::write(&xml_path, xml)
                .map_err(|_| MinerAgentError::StorageMove("move-journal-unwritable"))
        });
        if written.is_err() {
            // No job started: the copy is nobody's.
            if self
                .finish_abort(&mut journal, "move-dst-create-failed")
                .await
                .is_err()
            {
                self.spawn_driver(vm_id);
            }
            return Err(MinerAgentError::StorageMove("move-dst-create-failed"));
        }
        if bounded(
            self.driver
                .blockcopy_start(&domain, DISK, &xml_path, bandwidth),
        )
        .await
        .is_err()
        {
            // The job may have started anyway (a timeout): the driver
            // aborts it from `prepared`, deleting the copy only once it is
            // provably unused.
            self.spawn_driver(vm_id);
            return Err(MinerAgentError::StorageMove("move-job-failed"));
        }
        if let Err(err) = self.advance(&mut journal, MovePhase::Copying) {
            // A job runs that the journal does not say: the driver aborts
            // it from `prepared`.
            self.spawn_driver(vm_id);
            return Err(err);
        }
        eprintln!(
            "hippius-miner-agent: storage-move: vm={vm_id} {} → {} ({} bytes, {} MiB/s) copying",
            journal.src_pool, journal.dst_pool, journal.bytes_total, bandwidth
        );
        self.spawn_driver(vm_id);
        self.status_of(&journal).await
    }

    async fn move_status(&self, vm_id: &VmId, move_id: &str) -> Result<MoveStatus> {
        let journal = self.journal_of(vm_id, move_id)?;
        self.status_of(&journal).await
    }

    async fn cancel_move(self: &Arc<Self>, vm_id: &VmId, move_id: &str) -> Result<MoveStatus> {
        let _ops = self.moves.ops.lock().await;
        let mut journal = self.journal_of(vm_id, move_id)?;
        match journal.phase {
            MovePhase::Prepared | MovePhase::Copying => {
                self.abort_move(&mut journal, "move-aborted-operator")
                    .await?;
            }
            MovePhase::Aborted => {}
            MovePhase::Failed if !journal.pivot_unknown() => {}
            _ => return Err(MinerAgentError::StorageMove("move-past-pivot")),
        }
        self.status_of(&journal).await
    }

    async fn release_move(&self, vm_id: &VmId, move_id: &str) -> Result<MoveStatus> {
        let _ops = self.moves.ops.lock().await;
        let mut journal = self.journal_of(vm_id, move_id)?;
        match journal.phase {
            MovePhase::Redefined => {}
            MovePhase::Done => return self.status_of(&journal).await,
            _ => return Err(MinerAgentError::StorageMove("move-not-releasable")),
        }
        self.release_src(&mut journal).await?;
        self.status_of(&journal).await
    }

    /// Delete a redefined move's source and journal it `done`. The VM runs
    /// from dst and boots from dst: the source copy is now only stale
    /// ciphertext — unless the VM came back onto that very path since:
    /// checked, never assumed.
    async fn release_src(&self, journal: &mut MoveJournal) -> Result<()> {
        let vm_id = VmId::new(&journal.vm_id)?;
        if self.named_by_vm(&vm_id, &journal.src).await? {
            return Err(MinerAgentError::StorageMove("move-release-in-use"));
        }
        let marker = crate::orders::migration::restore_marker_path(&journal.src);
        for path in [&journal.src, &marker] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(MinerAgentError::StorageMove("move-release-failed")),
            }
        }
        self.advance(journal, MovePhase::Done)?;
        eprintln!(
            "hippius-miner-agent: storage-move: vm={} source released, done",
            journal.vm_id
        );
        Ok(())
    }

    /// §25 quiesce: the VM leaves with the disk it runs on (dst), so a
    /// redefined move's source is released now — nothing may later land
    /// on its path before a late `release` deletes it. A move before its
    /// redefine, or held (`move-pivot-unknown`), refuses the departure.
    pub async fn release_before_departure(&self, vm_id: &VmId) -> Result<()> {
        if read_journal(&self.state_disk_root, vm_id)?.is_none() {
            return Ok(());
        }
        let _ops = self.moves.ops.lock().await;
        let Some(mut journal) = read_journal(&self.state_disk_root, vm_id)? else {
            return Ok(());
        };
        match journal.phase {
            MovePhase::Redefined => self.release_src(&mut journal).await,
            _ if journal.is_active() => {
                Err(MinerAgentError::StorageMove("vm-storage-move-in-progress"))
            }
            _ => Ok(()),
        }
    }

    /// A §25 arrival (or an in-place restore) is refused while the VM has
    /// a copy in flight or a held pivot here: a mirror may still write the
    /// files it would land on. (A redefined move onto whose source it lands
    /// is closed after: [`Self::close_superseded_move`].)
    pub fn check_arrival_clear(&self, vm_id: &VmId) -> Result<()> {
        match read_journal(&self.state_disk_root, vm_id)? {
            Some(j) if j.blocks_vm() => {
                Err(MinerAgentError::StorageMove("vm-storage-move-in-progress"))
            }
            _ => Ok(()),
        }
    }

    /// Whether `path` is a disk the VM still uses: its pool record, its
    /// handle, its live definition or its persistent definition names it.
    /// `Err` when that cannot be said (an unreadable record, a libvirt that
    /// does not answer, a definition without a readable vda).
    ///
    /// INVARIANT: nothing in this module deletes a file this answers `true`
    /// or `Err` for — dst on an abort, src on a release.
    async fn named_by_vm(&self, vm_id: &VmId, path: &Path) -> Result<bool> {
        let unknown = || MinerAgentError::StorageMove("move-libvirt-unknown");
        match vm_pool::read(&self.state_disk_root, vm_id) {
            Ok(Some(record)) if golden::overlay_disk_path(&record.root, vm_id) == path => {
                return Ok(true);
            }
            Ok(_) => {}
            Err(vm_pool::Unreadable) => {
                return Err(MinerAgentError::StorageMove("move-pool-record-unreadable"));
            }
        }
        if self
            .lock_handles()?
            .get(vm_id)
            .is_some_and(|h| h.luks_disk_path == path)
        {
            return Ok(true);
        }
        let domain = domain_of(vm_id)?;
        match self.tenant_domain_liveness(vm_id).await {
            DomainLiveness::Live => match self.live_vda(&domain).await? {
                Some(vda) if vda == path => return Ok(true),
                Some(_) => {}
                None => return Err(unknown()),
            },
            DomainLiveness::Down => {}
            DomainLiveness::Unknown => return Err(unknown()),
        }
        match bounded(self.driver.domain_xml_inactive(&domain)).await {
            Ok(xml) => match adopt::writable_disk_path(&xml) {
                Some(vda) if vda == path => return Ok(true),
                Some(_) => {}
                None => return Err(unknown()),
            },
            Err(_) => {
                let list = bounded(self.driver.list_domains())
                    .await
                    .map_err(|_| unknown())?;
                if list.iter().any(|(id, _)| id == &domain) {
                    return Err(unknown());
                }
            }
        }
        Ok(false)
    }

    /// A launch or an arrival puts the VM's disk under `root`. A move whose
    /// source is that very path is over: it is closed (`done`,
    /// `move-superseded`, nothing deleted) so a late `release` finds
    /// nothing to delete. A copy in flight, or a held pivot, refuses it.
    pub async fn close_superseded_move(&self, vm_id: &VmId, root: &Path) -> Result<()> {
        // Only a move still holding a source (or the VM) concerns a launch:
        // the host lock is not taken for an old `done`/`aborted` journal.
        if let Ok(journal) = read_journal(&self.state_disk_root, vm_id) {
            if !journal.is_some_and(|j| j.blocks_vm() || j.phase == MovePhase::Redefined) {
                return Ok(());
            }
        }
        let _ops = self.moves.ops.lock().await;
        let Some(mut journal) = read_journal(&self.state_disk_root, vm_id)? else {
            return Ok(());
        };
        if journal.blocks_vm() {
            return Err(MinerAgentError::StorageMove("vm-storage-move-in-progress"));
        }
        if journal.phase == MovePhase::Redefined
            && golden::overlay_disk_path(root, vm_id) == journal.src
        {
            journal.code = Some("move-superseded".to_string());
            self.advance(&mut journal, MovePhase::Done)?;
            eprintln!(
                "hippius-miner-agent: storage-move: vm={vm_id} is back on {}: its move is \
                 closed, nothing released",
                journal.src.display()
            );
        }
        Ok(())
    }

    fn journal_of(&self, vm_id: &VmId, move_id: &str) -> Result<MoveJournal> {
        read_journal(&self.state_disk_root, vm_id)?
            .filter(|j| j.move_id == move_id)
            .ok_or(MinerAgentError::StorageMove("move-not-found"))
    }

    async fn status_of(&self, journal: &MoveJournal) -> Result<MoveStatus> {
        // Progress is best effort: a status never fails on libvirt.
        let bytes_done = match journal.phase {
            MovePhase::Copying | MovePhase::Pivoting => {
                let job = match domain_of(&VmId::new(&journal.vm_id)?) {
                    Ok(domain) => bounded(self.driver.blockjob_info(&domain, DISK))
                        .await
                        .ok()
                        .flatten(),
                    Err(_) => None,
                };
                job.map_or(0, |j| {
                    if j.end == 0 {
                        0
                    } else {
                        journal.bytes_total.saturating_mul(j.cur) / j.end
                    }
                })
            }
            MovePhase::Pivoted | MovePhase::Redefined | MovePhase::Done => journal.bytes_total,
            _ => 0,
        };
        Ok(MoveStatus {
            move_id: journal.move_id.clone(),
            vm_id: journal.vm_id.clone(),
            phase: journal.phase,
            bytes_total: journal.bytes_total,
            bytes_done,
            src_pool: journal.src_pool.clone(),
            dst_pool: journal.dst_pool.clone(),
            started_at: journal.started_at,
            updated_at: journal.updated_at,
            code: journal.code.clone(),
        })
    }

    fn advance(&self, journal: &mut MoveJournal, phase: MovePhase) -> Result<()> {
        journal.phase = phase;
        journal.updated_at = now_unix();
        write_journal(&self.state_disk_root, journal)
    }

    /// The live vda's file. `Err` when libvirt can't say — never read as
    /// "not on dst".
    async fn live_vda(&self, domain: &DomainId) -> Result<Option<PathBuf>> {
        let xml = bounded(self.driver.domain_xml(domain))
            .await
            .map_err(|_| MinerAgentError::StorageMove("move-libvirt-unknown"))?;
        Ok(adopt::writable_disk_path(&xml))
    }

    /// Abort a move whose VM still runs (or ran) on src: abort the job,
    /// then delete dst — only on positive evidence that nothing uses it:
    /// no job, and the live vda IS src (or no QEMU at all). If libvirt
    /// pivoted, the VM is on dst: nothing is deleted, the move goes on.
    /// Anything unknown leaves everything as it is (`Err`, retried).
    async fn abort_move(&self, journal: &mut MoveJournal, code: &'static str) -> Result<()> {
        let vm_id = VmId::new(&journal.vm_id)?;
        let domain = domain_of(&vm_id)?;
        let unknown = || MinerAgentError::StorageMove("move-abort-failed");
        match self.tenant_domain_liveness(&vm_id).await {
            DomainLiveness::Live => {
                if journal.phase == MovePhase::Prepared {
                    // A start whose answer was lost (a timeout) may still
                    // register its job: watch for it before the copy goes.
                    for _ in 0..PREPARED_JOB_GRACE_ROUNDS {
                        if bounded(self.driver.blockjob_info(&domain, DISK))
                            .await
                            .map_err(|_| unknown())?
                            .is_some()
                        {
                            bounded(self.driver.blockjob_abort(&domain, DISK))
                                .await
                                .map_err(|_| unknown())?;
                        }
                        tokio::time::sleep(self.move_poll()).await;
                    }
                }
                bounded(self.driver.blockjob_abort(&domain, DISK))
                    .await
                    .map_err(|_| unknown())?;
                if bounded(self.driver.blockjob_info(&domain, DISK))
                    .await
                    .map_err(|_| unknown())?
                    .is_some()
                {
                    // Still copying into dst: not deleted under it.
                    return Err(unknown());
                }
                match self.live_vda(&domain).await? {
                    Some(vda) if vda == journal.dst => {
                        // libvirt pivoted after all.
                        self.advance(journal, MovePhase::Pivoted)?;
                        return Ok(());
                    }
                    Some(vda) if vda == journal.src => {}
                    _ => return Err(unknown()),
                }
            }
            // A stop mid-pivot: libvirt may have pivoted before QEMU
            // exited — decided from the definition, else held.
            DomainLiveness::Down if journal.phase == MovePhase::Pivoting => {
                return self.resolve_stopped_pivot(journal).await;
            }
            // No QEMU: nothing writes either copy.
            DomainLiveness::Down => {}
            DomainLiveness::Unknown => return Err(unknown()),
        }
        self.finish_abort(journal, code).await
    }

    /// The copy is unused (no job, the VM not on it): delete dst, journal
    /// `aborted:<code>`.
    async fn finish_abort(&self, journal: &mut MoveJournal, code: &'static str) -> Result<()> {
        let vm_id = VmId::new(&journal.vm_id)?;
        let domain = domain_of(&vm_id)?;
        // A job libvirt registered late (a start that timed out) would
        // mirror into the deleted file: never under a running job.
        if self.tenant_domain_liveness(&vm_id).await == DomainLiveness::Live
            && bounded(self.driver.blockjob_info(&domain, DISK))
                .await
                .map_err(|_| MinerAgentError::StorageMove("move-job-unknown"))?
                .is_some()
        {
            return Err(MinerAgentError::StorageMove("move-job-present"));
        }
        if self.named_by_vm(&vm_id, &journal.dst).await? {
            // The VM uses the copy after all (a pivot libvirt completed
            // late): never deleted — the move goes on from where it runs.
            return self.dst_in_use(journal, &domain).await;
        }
        match std::fs::remove_file(&journal.dst) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(MinerAgentError::StorageMove("move-abort-failed")),
        }
        if let Ok(vm) = VmId::new(&journal.vm_id) {
            let _ = std::fs::remove_file(dest_xml_path(&self.state_disk_root, &vm));
        }
        journal.code = Some(code.to_string());
        self.advance(journal, MovePhase::Aborted)?;
        eprintln!(
            "hippius-miner-agent: storage-move: vm={} aborted ({code}), still on {}",
            journal.vm_id, journal.src_pool
        );
        Ok(())
    }

    /// An abort found the VM's records naming dst. A definition (live or
    /// persistent) naming it: libvirt pivoted, the move goes on — pivoted,
    /// then redefined. Only the agent's own records naming it (a handle, a
    /// pool record): which copy is current is unknown — held for an
    /// operator (`move-pivot-unknown`), both copies kept.
    async fn dst_in_use(&self, journal: &mut MoveJournal, domain: &DomainId) -> Result<()> {
        let names_dst =
            |xml: &str| adopt::writable_disk_path(xml).as_deref() == Some(journal.dst.as_path());
        // A read error is no answer: retried, never taken for "not dst".
        let unknown = || MinerAgentError::StorageMove("move-libvirt-unknown");
        let live = match self
            .tenant_domain_liveness(&VmId::new(&journal.vm_id)?)
            .await
        {
            DomainLiveness::Live => bounded(self.driver.domain_xml(domain))
                .await
                .map(|xml| names_dst(&xml))
                .map_err(|_| unknown())?,
            DomainLiveness::Down => false,
            DomainLiveness::Unknown => return Err(unknown()),
        };
        let inactive = match bounded(self.driver.domain_xml_inactive(domain)).await {
            Ok(xml) => names_dst(&xml),
            Err(_) => {
                let list = bounded(self.driver.list_domains())
                    .await
                    .map_err(|_| unknown())?;
                if list.iter().any(|(id, _)| id == domain) {
                    return Err(unknown());
                }
                false
            }
        };
        if live || inactive {
            self.advance(journal, MovePhase::Pivoted)?;
            return self.redefine(journal).await;
        }
        journal.code = Some("move-pivot-unknown".to_string());
        self.advance(journal, MovePhase::Failed)?;
        eprintln!(
            "hippius-miner-agent: storage-move: vm={} records name the copy {} though no \
             definition does — held, both copies kept",
            journal.vm_id,
            journal.dst.display()
        );
        Ok(())
    }

    /// Make the persistent definition (and the agent's records) name dst.
    /// Idempotent; on failure the move stays `pivoted` and is retried. A
    /// domain no longer defined (stopped since: its next launch renders
    /// vda from the pool record) needs only the records.
    async fn redefine(&self, journal: &mut MoveJournal) -> Result<()> {
        let vm_id = VmId::new(&journal.vm_id)?;
        let domain = domain_of(&vm_id)?;
        let fail = || MinerAgentError::StorageMove("move-redefine-failed");
        let inactive = match bounded(self.driver.domain_xml_inactive(&domain)).await {
            Ok(xml) => Some(xml),
            Err(_) => {
                let list = bounded(self.driver.list_domains())
                    .await
                    .map_err(|_| fail())?;
                if list.iter().any(|(id, _)| id == &domain) {
                    return Err(fail());
                }
                None
            }
        };
        if let Some(inactive) = inactive {
            if adopt::writable_disk_path(&inactive).as_deref() != Some(journal.dst.as_path()) {
                let xml = super::libvirt_driver::replace_vda_source(&inactive, &journal.dst)
                    .ok_or_else(fail)?;
                bounded(self.driver.define_domain(&xml))
                    .await
                    .map_err(|_| fail())?;
                let check = bounded(self.driver.domain_xml_inactive(&domain))
                    .await
                    .map_err(|_| fail())?;
                if adopt::writable_disk_path(&check).as_deref() != Some(journal.dst.as_path()) {
                    return Err(fail());
                }
            }
        }
        // A §25 restore marker follows the overlay it describes.
        let src_marker = crate::orders::migration::restore_marker_path(&journal.src);
        if src_marker.exists() {
            let dst_marker = crate::orders::migration::restore_marker_path(&journal.dst);
            std::fs::copy(&src_marker, &dst_marker).map_err(|_| fail())?;
        }
        // Everything that finds the VM's disks: its pool record, its
        // handle, its re-adoption snapshot.
        vm_pool::write(
            &self.state_disk_root,
            &vm_id,
            &vm_pool::VmPoolRecord {
                pool_id: journal.dst_pool.clone(),
                root: journal.dst_root.clone(),
                ran: true,
            },
        )
        .map_err(|_| fail())?;
        let snapshot = {
            let mut handles = self.lock_handles()?;
            handles.get_mut(&vm_id).map(|h| {
                h.luks_disk_path = journal.dst.clone();
                h.clone()
            })
        };
        if let Some(handle) = snapshot {
            if let Err(err) = adopt::persist(&self.state_disk_root, &handle) {
                eprintln!(
                    "hippius-miner-agent: storage-move: vm={vm_id} snapshot not persisted: {err}"
                );
            }
        }
        let _ = std::fs::remove_file(dest_xml_path(&self.state_disk_root, &vm_id));
        self.advance(journal, MovePhase::Redefined)?;
        eprintln!(
            "hippius-miner-agent: storage-move: vm={vm_id} on {} (redefined); source kept until \
             released",
            journal.dst_pool
        );
        Ok(())
    }

    fn spawn_driver(self: &Arc<Self>, vm_id: &VmId) {
        let Ok(mut driving) = self.moves.driving.lock() else {
            return;
        };
        if !driving.insert(vm_id.clone()) {
            return;
        }
        drop(driving);
        let this = Arc::clone(self);
        let vm = vm_id.clone();
        tokio::spawn(async move {
            this.drive(&vm).await;
            if let Ok(mut driving) = this.moves.driving.lock() {
                driving.remove(&vm);
            }
        });
    }

    /// Run one move to `redefined` (or an abort): poll, pivot when the
    /// mirror is ready, redefine. An unreadable journal is retried, never
    /// a reason to stop driving a job that runs.
    async fn drive(&self, vm_id: &VmId) {
        loop {
            tokio::time::sleep(self.move_poll()).await;
            let _ops = self.moves.ops.lock().await;
            let mut journal = match read_journal(&self.state_disk_root, vm_id) {
                Ok(Some(j)) if j.phase.blocks_vm() => j,
                Ok(_) => return,
                Err(err) => {
                    eprintln!("hippius-miner-agent: storage-move: vm={vm_id} journal: {err}");
                    continue;
                }
            };
            if let Err(err) = self.step(&mut journal).await {
                eprintln!("hippius-miner-agent: storage-move: vm={vm_id} step: {err} (retried)");
            }
        }
    }

    /// One step of a move that blocks its VM. Every branch acts only on
    /// what libvirt positively says; an unknown answer waits a tick.
    async fn step(&self, journal: &mut MoveJournal) -> Result<()> {
        let vm_id = VmId::new(&journal.vm_id)?;
        let domain = domain_of(&vm_id)?;
        match journal.phase {
            // The start never reached a recorded copy (a crash, a timeout).
            MovePhase::Prepared => self.abort_move(journal, "move-aborted-agent-restart").await,
            MovePhase::Copying => {
                match self.tenant_domain_liveness(&vm_id).await {
                    DomainLiveness::Live => {}
                    // QEMU exited: the mirror died with it, nothing runs on
                    // dst (the persistent definition is still src).
                    DomainLiveness::Down => {
                        return self.finish_abort(journal, "move-aborted-guest-stop").await;
                    }
                    DomainLiveness::Unknown => return Ok(()),
                }
                let info = bounded(self.driver.blockjob_info(&domain, DISK))
                    .await
                    .map_err(|_| MinerAgentError::StorageMove("move-job-unknown"))?;
                match info {
                    Some(info) if info.ready => self.pivot(journal, &domain).await,
                    Some(_) => Ok(()),
                    None => match self.live_vda(&domain).await? {
                        Some(vda) if vda == journal.dst => {
                            self.advance(journal, MovePhase::Pivoted)?;
                            self.redefine(journal).await
                        }
                        // The job died (libvirtd restart, an error); the VM
                        // provably runs on src.
                        Some(vda) if vda == journal.src => {
                            self.finish_abort(journal, "move-job-failed").await
                        }
                        _ => Err(MinerAgentError::StorageMove("move-libvirt-unknown")),
                    },
                }
            }
            MovePhase::Pivoting => {
                match self.tenant_domain_liveness(&vm_id).await {
                    DomainLiveness::Live => {}
                    DomainLiveness::Down => return self.resolve_stopped_pivot(journal).await,
                    DomainLiveness::Unknown => return Ok(()),
                }
                match self.live_vda(&domain).await? {
                    Some(vda) if vda == journal.dst => {
                        self.advance(journal, MovePhase::Pivoted)?;
                        self.redefine(journal).await
                    }
                    Some(vda) if vda == journal.src => {
                        match bounded(self.driver.blockjob_info(&domain, DISK)).await? {
                            Some(_) => self.pivot(journal, &domain).await,
                            None => self.finish_abort(journal, "move-pivot-failed").await,
                        }
                    }
                    _ => Err(MinerAgentError::StorageMove("move-libvirt-unknown")),
                }
            }
            MovePhase::Pivoted => self.redefine(journal).await,
            _ => Ok(()),
        }
    }

    /// Pivot: a pivot libvirt confirmed is authoritative (the VM is on
    /// dst, whatever a later read says); one it refused leaves the VM on
    /// src, mirrored, and the move backs out.
    async fn pivot(&self, journal: &mut MoveJournal, domain: &DomainId) -> Result<()> {
        self.advance(journal, MovePhase::Pivoting)?;
        match bounded(self.driver.blockjob_pivot(domain, DISK)).await {
            Ok(()) => {
                self.advance(journal, MovePhase::Pivoted)?;
                return self.redefine(journal).await;
            }
            // libvirtd may still complete a pivot whose answer timed out:
            // the outcome is unknown, so the move stays `pivoting` and the
            // next step reads it off libvirt (the live vda and the job; the
            // persistent definition if the guest stopped). Never backed out.
            Err(MinerAgentError::StorageMove("move-libvirt-timeout")) => {
                return Err(MinerAgentError::StorageMove("move-pivot-unknown-outcome"));
            }
            // A refusal: libvirt says it did not pivot.
            Err(_) => {}
        }
        match self.live_vda(domain).await? {
            Some(vda) if vda == journal.dst => {
                self.advance(journal, MovePhase::Pivoted)?;
                self.redefine(journal).await
            }
            // Still `pivoting` in the journal while it backs out: libvirt
            // may yet complete a pivot that timed out, and a `pivoting` move
            // whose VM stops is held, never restarted on a guess.
            Some(vda) if vda == journal.src => self.abort_move(journal, "move-pivot-failed").await,
            // Unknown: stays `pivoting`, looked at again.
            _ => Err(MinerAgentError::StorageMove("move-libvirt-unknown")),
        }
    }

    /// The domain stopped mid-pivot. If the persistent definition already
    /// names dst (libvirt updated it), the move completes; else which copy
    /// holds the last writes is unknown: both are kept, the VM is held
    /// (`move-pivot-unknown`) for an operator.
    async fn resolve_stopped_pivot(&self, journal: &mut MoveJournal) -> Result<()> {
        let domain = domain_of(&VmId::new(&journal.vm_id)?)?;
        if let Ok(inactive) = bounded(self.driver.domain_xml_inactive(&domain)).await {
            if adopt::writable_disk_path(&inactive).as_deref() == Some(journal.dst.as_path()) {
                self.advance(journal, MovePhase::Pivoted)?;
                return self.redefine(journal).await;
            }
        }
        journal.code = Some("move-pivot-unknown".to_string());
        self.advance(journal, MovePhase::Failed)?;
        eprintln!(
            "hippius-miner-agent: storage-move: vm={} stopped mid-pivot — held, both copies kept \
             ({} / {}); an operator decides which one boots",
            journal.vm_id,
            journal.src.display(),
            journal.dst.display()
        );
        Ok(())
    }

    /// Before the reboot watcher (or anything else) starts the VM's domain
    /// from its persistent definition: a copy in flight is aborted (QEMU
    /// exited, so the mirror is gone: the VM restarts on src), a pivoted
    /// move is redefined first (the VM restarts on dst, never on the stale
    /// src). `Err`: do not start it.
    pub async fn settle_move_before_restart(&self, vm_id: &VmId) -> Result<()> {
        // Most restarts have no move: no wait on the move lock.
        if !read_journal(&self.state_disk_root, vm_id)?.is_some_and(|j| j.blocks_vm()) {
            return Ok(());
        }
        let _ops = self.moves.ops.lock().await;
        let Some(mut journal) = read_journal(&self.state_disk_root, vm_id)? else {
            return Ok(());
        };
        match journal.phase {
            MovePhase::Prepared | MovePhase::Copying => {
                self.finish_abort(&mut journal, "move-aborted-guest-stop")
                    .await?
            }
            MovePhase::Pivoting => self.resolve_stopped_pivot(&mut journal).await?,
            MovePhase::Pivoted => self.redefine(&mut journal).await?,
            _ => {}
        }
        // Whatever settled it, a held pivot is never restarted on a guess.
        if journal.pivot_unknown() {
            return Err(MinerAgentError::StorageMove("move-pivot-unknown"));
        }
        Ok(())
    }

    /// §24 destroy of a VM with a move: stop the copy first (the destroy
    /// then reclaims both overlays, every pool's). The journal stays until
    /// the destroy succeeded ([`Self::forget_move`]): a destroy that fails
    /// later still has it to restart the VM on the right copy. The caller
    /// holds the move lock for the whole destroy ([`Self::move_ops`]): no
    /// driver step redefines or re-journals the VM under it.
    pub async fn abort_move_for_destroy(&self, vm_id: &VmId) -> Result<()> {
        match read_journal(&self.state_disk_root, vm_id) {
            Ok(Some(j)) if j.blocks_vm() => {}
            Ok(_) => return Ok(()),
            Err(_) => {
                // A §24 is never blocked by a journal nobody can read: stop
                // whatever copy runs, best effort, and go on.
                eprintln!(
                    "hippius-miner-agent: storage-move: vm={vm_id} journal unreadable at \
                     destroy — best-effort job abort"
                );
                if let Ok(domain) = domain_of(vm_id) {
                    let _ = bounded(self.driver.blockjob_abort(&domain, DISK)).await;
                }
                return Ok(());
            }
        }
        let domain = domain_of(vm_id)?;
        if self.tenant_domain_liveness(vm_id).await == DomainLiveness::Live {
            let fail = || MinerAgentError::StorageMove("move-abort-failed");
            bounded(self.driver.blockjob_abort(&domain, DISK))
                .await
                .map_err(|_| fail())?;
            if bounded(self.driver.blockjob_info(&domain, DISK))
                .await
                .map_err(|_| fail())?
                .is_some()
            {
                return Err(fail());
            }
        }
        Ok(())
    }

    /// The VM is destroyed: its move is over.
    pub fn forget_move(&self, vm_id: &VmId) {
        let _ = std::fs::remove_file(dest_xml_path(&self.state_disk_root, vm_id));
        if let Err(e) = std::fs::remove_file(journal_path(&self.state_disk_root, vm_id)) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "hippius-miner-agent: storage-move: vm={vm_id} journal not removed after the \
                     destroy"
                );
            }
        }
    }

    /// At startup, after re-adoption: pick up every move a previous agent
    /// left before `redefined` (its libvirt job survives an agent restart).
    pub async fn resume_moves(self: &Arc<Self>) -> Result<usize> {
        let (journals, _unreadable) = all_journals(&self.state_disk_root);
        let mut resumed = 0;
        for journal in journals {
            if !journal.phase.blocks_vm() {
                continue;
            }
            let vm = VmId::new(&journal.vm_id)?;
            eprintln!(
                "hippius-miner-agent: storage-move: vm={vm} resuming at {:?}",
                journal.phase
            );
            self.spawn_driver(&vm);
            resumed += 1;
        }
        Ok(resumed)
    }
}

#[cfg(test)]
mod tests;
