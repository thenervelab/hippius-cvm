//! Live VM backups to S3, and the chain restore behind failover.
//!
//! A `backup` order copies a RUNNING golden VM's overlay — whole (full)
//! or the clusters written since a parent point (incremental) — without
//! pausing the guest, and uploads it with the anti-rollback state disk
//! through presigned URLs. vali tracks chains, commits uploads and
//! decides what is restorable; the miner reports what it took: sizes,
//! per-part ETags + sha256, the boot counter the state disk holds, and
//! whether the run's point bitmap is in QEMU (i.e. whether it can be a
//! parent).
//!
//! - [`qmp`] — QMP command builders/parsers and the virsh transport;
//! - [`capture`] — the QEMU job (point bitmaps, `blockdev-backup`,
//!   fd-passed temp target, release);
//! - [`transfer`] — presigned multipart PUT / size-capped verified GET;
//! - [`state`] — the state-disk copy and its boot counter;
//! - [`restore`] — full + incrementals ⇒ overlay (`migrate-activate`
//!   chain mode), applied by [`qcow2`], never by `qemu-img`;
//! - [`staged`] — the `restore` order: stage a point beside the live
//!   disks, swap it in on `migrate-activate`, abort or reclaim;
//! - [`image_tool`] — `qemu-img create` for the incremental target.
//!
//! One backup per VM at a time. Every temp file is unlinked as soon as
//! it is open, and a run that dies with the agent is released from QEMU
//! at the next start ([`BackupManager::recover_on_startup`]) or, failing
//! that, before the VM's next run.

pub mod capture;
pub mod image_tool;
#[cfg(test)]
mod live_tests;
pub mod qcow2;
pub mod qmp;
pub mod restore;
pub mod staged;
pub mod state;
pub mod transfer;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::error::{MinerAgentError, Result};
use crate::lifecycle::{CvmLifecycle, DomainId, DomainLiveness, VmId};
pub use capture::BackupKind;
use capture::JobTiming;
use image_tool::ImageTool;
use qmp::QmpTransport;
use transfer::{PieceReceipt, Transfer};

/// Upper bound on a `run_id`.
const ID_MAX_LEN: usize = 64;

/// Concurrent uploads per host: a backup is disk- and network-bound,
/// and the host's tenants share both.
const MAX_CONCURRENT_RUNS: usize = 2;

/// Default HOST budget for backup copies, bytes/s. A full reads the
/// overlay and writes the target on the same host storage the tenants
/// use; uncapped, QEMU 10.2 on a Genoa host read ~830 MB/s and its monitor
/// stopped answering for up to a minute (#1246). 384 MiB/s is about half
/// that. Each job gets `384 / MAX_CONCURRENT_RUNS` = 192 MiB/s
/// ([`job_speed`]), which copies the largest disk we sell (160 GiB) in
/// ~14 min — far inside the 6 h job bound ([`JobTiming`]) and vali's run
/// timeout, which also has to cover the upload.
pub const DEFAULT_HOST_SPEED_BYTES_PER_SEC: u64 = 384 << 20;

/// Lowest per-job cap [`job_speed`] hands out, whatever the budget.
const MIN_JOB_SPEED_BYTES_PER_SEC: u64 = 1 << 20;

/// One job's `blockdev-backup` speed out of the host budget `host`: an
/// equal share of every run slot, so concurrent runs together never pass
/// the budget. Static on purpose — re-balancing a running job would
/// mean `block-job-set-speed` on a monitor that may be stalled mid-copy
/// (#1246). `0` stays `0` (uncapped); a share is never below 1 MiB/s.
pub fn job_speed(host: u64) -> u64 {
    if host == 0 {
        return 0;
    }
    (host / MAX_CONCURRENT_RUNS as u64).max(MIN_JOB_SPEED_BYTES_PER_SEC)
}

/// A validated backup request (the miner-side view of the order).
///
/// Not `Debug`: it holds presigned URLs.
pub struct BackupRequest {
    /// The VM.
    pub vm_id: VmId,
    /// vali's id for this run; names the run's point bitmap.
    pub run_id: String,
    /// The last COMMITTED run of the chain: what an incremental copies
    /// from; for a full, the one old point to keep. Every other point is
    /// pruned.
    pub parent_run_id: Option<String>,
    /// Full or incremental.
    pub kind: BackupKind,
    /// Multipart part size.
    pub part_size: u64,
    /// Presigned `UploadPart` URLs for the disk piece, part 1 first.
    pub disk_part_urls: Vec<String>,
    /// Presigned PUT for the state disk.
    pub state_put_url: String,
}

/// Validate an id vali chose: `[a-z0-9-]{1,64}`. A run id becomes part
/// of a QEMU bitmap name.
pub fn check_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > ID_MAX_LEN
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(MinerAgentError::Backup("bad-id"));
    }
    Ok(())
}

/// A run's phase as `GET …/backup/<vm>/status` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RunPhase {
    /// In progress.
    Running,
    /// Uploaded; the report is complete.
    Done,
    /// Failed; `error` says where.
    Failed,
}

/// The status of a VM's latest run.
#[derive(Debug, Clone, Serialize)]
pub struct RunStatus {
    /// vali's run id.
    pub run_id: String,
    /// The parent point the run was taken against.
    pub parent_run_id: Option<String>,
    /// Full or incremental.
    pub kind: BackupKind,
    /// Phase.
    pub status: RunPhase,
    /// Static failure class.
    pub error: Option<&'static str>,
    /// This run's point bitmap is in QEMU after the run (`None` if
    /// unknown): whether the run can be the parent of an incremental.
    /// Always `false` for a failed run.
    pub bitmap_present: Option<bool>,
    /// Boot counter in the state disk copy (`None` if the guest never
    /// completed a release, or it could not be read).
    pub boot_counter: Option<u64>,
    /// The overlay's virtual size.
    pub virtual_size: Option<u64>,
    /// The disk piece — raw image (full) or qcow2 (incremental).
    pub disk: Option<PieceReceipt>,
    /// The state disk piece.
    pub state: Option<PieceReceipt>,
}

impl RunStatus {
    fn started(req: &BackupRequest) -> Self {
        Self {
            run_id: req.run_id.clone(),
            parent_run_id: req.parent_run_id.clone(),
            kind: req.kind,
            status: RunPhase::Running,
            error: None,
            bitmap_present: None,
            boot_counter: None,
            virtual_size: None,
            disk: None,
            state: None,
        }
    }
}

/// What `GET …/backup/<vm>/status` returns: the latest run plus what
/// is true of the VM right now, so vali can see a reboot between runs.
#[derive(Debug, Clone, Serialize)]
pub struct BackupStatus {
    /// The VM.
    pub vm_id: String,
    /// Read at poll time.
    pub live: LiveState,
    /// The latest run since the agent started, if any.
    pub run: Option<RunStatus>,
}

/// The VM's backup-relevant state at poll time.
#[derive(Debug, Clone, Serialize)]
pub struct LiveState {
    /// The boot counter the state disk holds now (`None`: no committed
    /// release yet, or the disk is unreadable).
    pub boot_counter: Option<u64>,
    /// Run ids whose point bitmap is on the overlay node now — the
    /// points an incremental can be taken against. Empty when the
    /// domain is not running (bitmaps die with QEMU).
    pub point_run_ids: Vec<String>,
}

/// Why [`BackupManager::live_status`] has no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveStatusError {
    /// This host has no domain for the VM.
    NoDomain,
    /// libvirt or QMP could not be asked; retry.
    Unavailable,
}

/// Owns the backup runs of this host.
pub struct BackupManager {
    qmp: Arc<dyn QmpTransport>,
    img: Arc<dyn ImageTool>,
    transfer: Arc<Transfer>,
    runs: Mutex<HashMap<VmId, RunStatus>>,
    slots: tokio::sync::Semaphore,
    space: Arc<capture::SpaceLedger>,
    timing: JobTiming,
    /// Per-job cap ([`job_speed`] of the host budget).
    job_speed_bytes_per_sec: u64,
}

impl BackupManager {
    /// A manager over the given tools.
    pub fn new(
        qmp: Arc<dyn QmpTransport>,
        img: Arc<dyn ImageTool>,
        transfer: Arc<Transfer>,
    ) -> Self {
        Self {
            qmp,
            img,
            transfer,
            runs: Mutex::new(HashMap::new()),
            slots: tokio::sync::Semaphore::new(MAX_CONCURRENT_RUNS),
            space: Arc::default(),
            timing: JobTiming::default(),
            job_speed_bytes_per_sec: job_speed(DEFAULT_HOST_SPEED_BYTES_PER_SEC),
        }
    }

    /// Override the QEMU job poll cadence / bound (tests).
    pub fn with_timing(mut self, timing: JobTiming) -> Self {
        self.timing = timing;
        self
    }

    /// Cap all copies on this host at `bytes_per_sec` together (`0`:
    /// uncapped) — the agent config's `[backup].host_speed_bytes_per_sec`.
    pub fn with_host_speed(mut self, bytes_per_sec: u64) -> Self {
        self.job_speed_bytes_per_sec = job_speed(bytes_per_sec);
        self
    }

    /// Reserve in `space` — production passes [`capture::SpaceLedger::host`],
    /// the ledger the per-VM disk creates are admitted under. The default
    /// is an isolated ledger (tests).
    pub fn with_space_ledger(mut self, space: Arc<capture::SpaceLedger>) -> Self {
        self.space = space;
        self
    }

    /// The host-wide space ledger — share it with the chain restorer.
    pub fn space_ledger(&self) -> Arc<capture::SpaceLedger> {
        Arc::clone(&self.space)
    }

    /// The latest run of `vm_id`, if any since the agent started.
    pub fn status(&self, vm_id: &VmId) -> Option<RunStatus> {
        self.runs.lock().ok()?.get(vm_id).cloned()
    }

    /// The status route's answer. Cheap: one `virsh list`, one QMP
    /// query when the domain runs, one 1 MiB read + `debugfs`.
    ///
    /// No QMP while a run of the VM is in flight: the query would queue
    /// on the domain's libvirt job lock behind the run's own commands and
    /// make the run's next one fail "cannot acquire state change lock"
    /// (#1246). The points are then the run's parent — the one point the
    /// run keeps; its own is not a point until it is done.
    pub async fn live_status(
        &self,
        lifecycle: &CvmLifecycle,
        vm_id: &VmId,
    ) -> std::result::Result<BackupStatus, LiveStatusError> {
        match lifecycle.tenant_domain_defined(vm_id).await {
            None => return Err(LiveStatusError::Unavailable),
            Some(false) => return Err(LiveStatusError::NoDomain),
            Some(true) => {}
        }
        let run = self.status(vm_id);
        let point_run_ids = match lifecycle.tenant_domain_liveness(vm_id).await {
            DomainLiveness::Down => Vec::new(),
            DomainLiveness::Unknown => return Err(LiveStatusError::Unavailable),
            DomainLiveness::Live => match &run {
                Some(r) if r.status == RunPhase::Running => {
                    r.parent_run_id.iter().cloned().collect()
                }
                _ => self.live_points(lifecycle, vm_id).await?,
            },
        };
        let boot_counter = match state::read_state_disk(&lifecycle.state_disk_path(vm_id)).await {
            Ok(img) => state::boot_counter(&img, &lifecycle.backup_root()).await,
            Err(_) => None,
        };
        Ok(BackupStatus {
            vm_id: vm_id.as_str().to_string(),
            live: LiveState {
                boot_counter,
                point_run_ids,
            },
            run,
        })
    }

    /// The run ids of the points on the running VM's overlay node (QMP).
    async fn live_points(
        &self,
        lifecycle: &CvmLifecycle,
        vm_id: &VmId,
    ) -> std::result::Result<Vec<String>, LiveStatusError> {
        let domain = tenant_domain(vm_id).map_err(|_| LiveStatusError::Unavailable)?;
        let overlay = lifecycle.golden_overlay_path(vm_id);
        match capture::source_node(self.qmp.as_ref(), &domain, &overlay).await {
            Ok(node) => Ok(point_ids(&node)),
            // A running non-golden VM has no overlay node: no points.
            Err(MinerAgentError::Backup("source-node-missing")) => Ok(Vec::new()),
            Err(_) => Err(LiveStatusError::Unavailable),
        }
    }

    /// Validate and register a run; the caller spawns [`Self::run`].
    ///
    /// Idempotent on `run_id`: the same run again is `Ok(false)` (already
    /// accepted, nothing to spawn). Another run while one is in flight is
    /// `backup-in-flight`.
    pub fn begin(&self, req: &BackupRequest) -> Result<bool> {
        check_id(&req.run_id)?;
        if let Some(p) = &req.parent_run_id {
            check_id(p)?;
            if *p == req.run_id {
                return Err(MinerAgentError::Backup("bad-id"));
            }
        }
        if req.kind == BackupKind::Incremental && req.parent_run_id.is_none() {
            return Err(MinerAgentError::Backup("parent-missing"));
        }
        transfer::check_part_size(req.part_size)?;
        if req.disk_part_urls.is_empty() || req.state_put_url.is_empty() {
            return Err(MinerAgentError::Backup("missing-urls"));
        }
        let mut runs = self
            .runs
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?;
        if let Some(cur) = runs.get(&req.vm_id) {
            if cur.run_id == req.run_id {
                return Ok(false);
            }
            if cur.status == RunPhase::Running {
                return Err(MinerAgentError::Backup("backup-in-flight"));
            }
        }
        runs.insert(req.vm_id.clone(), RunStatus::started(req));
        Ok(true)
    }

    /// Execute a run registered by [`Self::begin`], recording the outcome.
    pub async fn run(&self, lifecycle: &CvmLifecycle, req: BackupRequest) {
        let outcome = self.execute(lifecycle, &req).await;
        if let Ok(mut runs) = self.runs.lock() {
            if let Some(st) = runs.get_mut(&req.vm_id) {
                if st.run_id == req.run_id {
                    match outcome {
                        Ok(report) => {
                            st.status = RunPhase::Done;
                            st.bitmap_present = report.bitmap_present;
                            st.boot_counter = report.boot_counter;
                            st.virtual_size = Some(report.virtual_size);
                            st.disk = Some(report.disk);
                            st.state = Some(report.state);
                        }
                        Err(e) => {
                            st.status = RunPhase::Failed;
                            st.error = Some(error_class(&e));
                            st.bitmap_present = e.1;
                        }
                    }
                }
            }
        }
    }

    async fn execute(
        &self,
        lifecycle: &CvmLifecycle,
        req: &BackupRequest,
    ) -> std::result::Result<Report, RunError> {
        let domain = tenant_domain(&req.vm_id).map_err(|e| RunError(e, None))?;
        let overlay = lifecycle.golden_overlay_path(&req.vm_id);
        let bitmap = capture::bitmap_name(&req.run_id);
        let parent = req.parent_run_id.as_deref().map(capture::bitmap_name);
        let mut point_created = false;
        let result = self
            .execute_inner(
                lifecycle,
                req,
                &domain,
                &overlay,
                &bitmap,
                parent.as_deref(),
                &mut point_created,
            )
            .await;
        match result {
            Ok(r) => Ok(r),
            // This attempt's capture made the point, then a later step
            // failed: nothing may build on it.
            Err(e) if point_created => {
                let gone =
                    capture::discard_point(self.qmp.as_ref(), &domain, &overlay, &bitmap).await;
                Err(RunError(e, gone.then_some(false)))
            }
            // The capture failed or never ran — it already dropped any
            // point it made, and a point it refused to touch
            // (`run-exists`) is not ours to drop. Report what is there.
            Err(e) => {
                let present =
                    capture::bitmap_present(self.qmp.as_ref(), &domain, &overlay, &bitmap)
                        .await
                        .ok();
                Err(RunError(e, present))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_inner(
        &self,
        lifecycle: &CvmLifecycle,
        req: &BackupRequest,
        domain: &DomainId,
        overlay: &Path,
        bitmap: &str,
        parent: Option<&str>,
        point_created: &mut bool,
    ) -> Result<Report> {
        let _slot = self
            .slots
            .acquire()
            .await
            .map_err(|_| MinerAgentError::Backup("shutting-down"))?;
        // Checked after the (possibly long) wait for a slot.
        if lifecycle.tenant_domain_liveness(&req.vm_id).await != DomainLiveness::Live {
            return Err(MinerAgentError::Backup("vm-not-running"));
        }
        let work_dir = lifecycle.backup_dir(&req.vm_id);
        let state_path = lifecycle.state_disk_path(&req.vm_id);

        // The guest writes its counter only while booting. Reading the
        // state disk on both sides of the capture and requiring the same
        // bytes proves no boot (and no torn counter write) happened in
        // between — the counter reported belongs to the overlay copied.
        let state_img = state::read_state_disk(&state_path).await?;
        let captured = capture::capture(
            self.qmp.as_ref(),
            self.img.as_ref(),
            self.space.as_ref(),
            &capture::CaptureRequest {
                domain,
                source_path: overlay,
                work_dir: &work_dir,
                kind: req.kind,
                new_bitmap: bitmap,
                parent_bitmap: parent,
                headroom_bytes: capture::SPACE_RESERVE_BYTES,
                speed_bytes_per_sec: self.job_speed_bytes_per_sec,
            },
            self.timing,
        )
        .await?;
        *point_created = true;
        if state::read_state_disk(&state_path).await? != state_img {
            return Err(MinerAgentError::Backup("state-changed"));
        }

        let boot_counter = state::boot_counter(&state_img, &work_dir).await;
        let disk = self
            .transfer
            .upload_parts(
                &captured.file,
                captured.len,
                req.part_size,
                &req.disk_part_urls,
            )
            .await?;
        let virtual_size = captured.virtual_size;
        drop(captured);
        let state = self
            .transfer
            .put_small(&req.state_put_url, state_img)
            .await?;
        let bitmap_present = capture::bitmap_present(self.qmp.as_ref(), domain, overlay, bitmap)
            .await
            .ok();
        Ok(Report {
            bitmap_present,
            boot_counter,
            virtual_size,
            disk,
            state,
        })
    }

    /// Clean up after runs the previous agent process did not finish:
    /// release their QEMU resources (job, target node, fdsets, the
    /// run's own point bitmap) and empty every VM work dir. A marker
    /// whose release did not complete is KEPT, so the VM's next run
    /// retries the release before starting. The staged-restore dir
    /// (`restore/`) is not a backup's to empty — [`staged`] recovers it.
    /// Call once at startup, before orders are served.
    pub async fn recover_on_startup(&self, backup_root: &Path) {
        let Ok(mut entries) = tokio::fs::read_dir(backup_root).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let dir = entry.path();
            let Some(vm) = dir
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| VmId::new(n).ok())
            else {
                continue;
            };
            let mut keep_marker = false;
            if let Some(marker) = capture::read_marker(&dir).await {
                if let Ok(domain) = tenant_domain(&vm) {
                    eprintln!(
                        "hippius-miner-agent: backup: vm={} releasing an interrupted run",
                        vm.as_str()
                    );
                    keep_marker =
                        !capture::recover_interrupted(self.qmp.as_ref(), &domain, &marker).await;
                    if keep_marker {
                        eprintln!(
                            "hippius-miner-agent: backup: vm={} release incomplete; the next run retries it",
                            vm.as_str()
                        );
                    }
                }
            }
            empty_dir(&dir, keep_marker).await;
        }
    }
}

/// A successful run's report.
struct Report {
    bitmap_present: Option<bool>,
    boot_counter: Option<u64>,
    virtual_size: u64,
    disk: PieceReceipt,
    state: PieceReceipt,
}

/// A failed run: the error and the bitmap presence observed afterwards.
struct RunError(MinerAgentError, Option<bool>);

fn error_class(e: &RunError) -> &'static str {
    match &e.0 {
        MinerAgentError::Backup(c) => c,
        MinerAgentError::LockPoisoned => "lock-poisoned",
        _ => "internal",
    }
}

/// The run ids of our point bitmaps on `node`, sorted.
fn point_ids(node: &qmp::SourceNode) -> Vec<String> {
    let mut ids: Vec<String> = node
        .bitmaps
        .iter()
        .filter_map(|b| b.name.strip_prefix(qmp::BITMAP_PREFIX))
        .map(str::to_string)
        .collect();
    ids.sort();
    ids
}

/// The libvirt domain of tenant `vm_id` (`hippius-tenant-<vm_id>`).
fn tenant_domain(vm_id: &VmId) -> Result<DomainId> {
    DomainId::new(&format!("hippius-tenant-{}", vm_id.as_str()))
}

async fn empty_dir(dir: &Path, keep_marker: bool) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    while let Ok(Some(e)) = entries.next_entry().await {
        let p: PathBuf = e.path();
        if keep_marker && e.file_name() == capture::INFLIGHT_MARKER {
            continue;
        }
        if e.file_name() == staged::RESTORE_DIR_NAME {
            continue;
        }
        let is_dir = e.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
        let _ = if is_dir {
            tokio::fs::remove_dir_all(&p).await
        } else {
            tokio::fs::remove_file(&p).await
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(run: &str) -> BackupRequest {
        BackupRequest {
            vm_id: VmId::new("vm-a").unwrap(),
            run_id: run.into(),
            parent_run_id: None,
            kind: BackupKind::Full,
            part_size: transfer::MIN_PART_SIZE,
            disk_part_urls: vec!["http://x/1".into()],
            state_put_url: "http://x/s".into(),
        }
    }

    fn manager() -> BackupManager {
        let qmp = Arc::new(qmp::mock::MockQmp::new(|_| Ok(serde_json::json!({}))));
        BackupManager::new(
            qmp,
            Arc::new(image_tool::QemuImg::default()),
            Arc::new(Transfer::new().unwrap()),
        )
    }

    #[test]
    fn ids_are_charset_checked() {
        check_id("c-1").unwrap();
        assert!(check_id("").is_err());
        assert!(check_id("C1").is_err());
        assert!(check_id("a/b").is_err());
        assert!(check_id(&"a".repeat(65)).is_err());
    }

    #[test]
    fn one_run_per_vm_and_idempotent_on_run_id() {
        let m = manager();
        assert!(m.begin(&req("r1")).unwrap());
        assert!(!m.begin(&req("r1")).unwrap(), "same run is a no-op");
        assert!(matches!(
            m.begin(&req("r2")),
            Err(MinerAgentError::Backup("backup-in-flight"))
        ));
        m.runs
            .lock()
            .unwrap()
            .get_mut(&VmId::new("vm-a").unwrap())
            .unwrap()
            .status = RunPhase::Failed;
        assert!(
            m.begin(&req("r2")).unwrap(),
            "a new run after the last ended"
        );
        assert_eq!(m.status(&VmId::new("vm-a").unwrap()).unwrap().run_id, "r2");
    }

    #[test]
    fn bad_requests_are_refused() {
        let m = manager();
        let mut r = req("r1");
        r.part_size = 1;
        assert!(matches!(
            m.begin(&r),
            Err(MinerAgentError::Backup("part-size"))
        ));
        let mut r = req("r1");
        r.parent_run_id = Some("Bad".into());
        assert!(m.begin(&r).is_err());
        let mut r = req("r1");
        r.parent_run_id = Some("r1".into());
        assert!(m.begin(&r).is_err(), "a run cannot be its own parent");
        let mut r = req("r1");
        r.kind = BackupKind::Incremental;
        assert!(matches!(
            m.begin(&r),
            Err(MinerAgentError::Backup("parent-missing"))
        ));
        let mut r = req("r1");
        r.state_put_url.clear();
        assert!(matches!(
            m.begin(&r),
            Err(MinerAgentError::Backup("missing-urls"))
        ));
    }

    #[tokio::test]
    async fn a_replayed_run_keeps_the_point_it_refused_to_retake() {
        use crate::lifecycle::{DomainState, MockLaunchDigest, MockLibvirtDriver};
        let root = tempfile::tempdir().unwrap();
        let driver = Arc::new(MockLibvirtDriver::new());
        driver.seed_domain(
            DomainId::new("hippius-tenant-vm-a").unwrap(),
            DomainState::Running,
        );
        let lifecycle = CvmLifecycle::new(
            driver,
            Arc::new(MockLaunchDigest::failing()),
            crate::lifecycle::HostResources {
                total_cpus: 1,
                total_memory_mb: 1,
                total_disk_gb: 0,
            },
        )
        .with_state_disk_root(root.path().to_path_buf());
        let vm = VmId::new("vm-a").unwrap();
        let state = lifecycle.state_disk_path(&vm);
        std::fs::create_dir_all(state.parent().unwrap()).unwrap();
        std::fs::write(&state, vec![0u8; 1 << 20]).unwrap();
        let overlay = lifecycle.golden_overlay_path(&vm);
        let ov = overlay.to_str().unwrap().to_string();
        let qmp = Arc::new(qmp::mock::MockQmp::new(move |c| {
            Ok(match c["execute"].as_str().unwrap() {
                "query-named-block-nodes" => serde_json::json!([{
                    "node-name": "libvirt-1-storage", "drv": "file", "file": ov,
                    "image": {"virtual-size": 1048576u64},
                    "dirty-bitmaps": [{"name": "hippius-bk-r1", "count": 0},
                                      {"name": "hippius-bk-r2", "count": 0}]}]),
                _ => serde_json::json!({}),
            })
        }));
        let m = BackupManager::new(
            qmp.clone(),
            Arc::new(image_tool::QemuImg::default()),
            Arc::new(Transfer::new().unwrap()),
        );
        let mut r = req("r2");
        r.kind = BackupKind::Incremental;
        r.parent_run_id = Some("r1".into());
        assert!(m.begin(&r).unwrap());
        m.run(&lifecycle, r).await;
        let st = m.status(&vm).unwrap();
        assert_eq!(st.status, RunPhase::Failed);
        assert_eq!(st.error, Some("run-exists"));
        assert_eq!(st.bitmap_present, Some(true));
        assert!(
            !qmp.executed()
                .iter()
                .any(|c| c == "block-dirty-bitmap-remove"),
            "the committed point is not ours to drop"
        );
    }

    #[tokio::test]
    async fn live_status_reports_points_and_no_domain() {
        use crate::lifecycle::{DomainState, MockLaunchDigest, MockLibvirtDriver};
        let root = tempfile::tempdir().unwrap();
        let driver = Arc::new(MockLibvirtDriver::new());
        driver.seed_domain(
            DomainId::new("hippius-tenant-vm-a").unwrap(),
            DomainState::Running,
        );
        let lifecycle = CvmLifecycle::new(
            driver,
            Arc::new(MockLaunchDigest::failing()),
            crate::lifecycle::HostResources {
                total_cpus: 1,
                total_memory_mb: 1,
                total_disk_gb: 0,
            },
        )
        .with_state_disk_root(root.path().to_path_buf());
        let vm = VmId::new("vm-a").unwrap();
        let ov = lifecycle
            .golden_overlay_path(&vm)
            .to_str()
            .unwrap()
            .to_string();
        let qmp = Arc::new(qmp::mock::MockQmp::new(move |_| {
            Ok(serde_json::json!([{
                "node-name": "libvirt-1-storage", "drv": "file", "file": ov,
                "image": {"virtual-size": 1048576u64},
                "dirty-bitmaps": [{"name": "hippius-bk-r7", "count": 0},
                                  {"name": "not-ours", "count": 0},
                                  {"name": "hippius-bk-r5", "count": 0}]}]))
        }));
        let m = BackupManager::new(
            qmp,
            Arc::new(image_tool::QemuImg::default()),
            Arc::new(Transfer::new().unwrap()),
        );
        let st = m.live_status(&lifecycle, &vm).await.unwrap();
        let v = serde_json::to_value(&st).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"vm_id": "vm-a",
                "live": {"boot_counter": null, "point_run_ids": ["r5", "r7"]},
                "run": null})
        );
        assert_eq!(
            m.live_status(&lifecycle, &VmId::new("vm-b").unwrap())
                .await
                .unwrap_err(),
            LiveStatusError::NoDomain
        );
    }

    #[tokio::test]
    async fn live_status_leaves_qmp_alone_while_a_run_is_in_flight() {
        use crate::lifecycle::{DomainState, MockLaunchDigest, MockLibvirtDriver};
        let root = tempfile::tempdir().unwrap();
        let driver = Arc::new(MockLibvirtDriver::new());
        driver.seed_domain(
            DomainId::new("hippius-tenant-vm-a").unwrap(),
            DomainState::Running,
        );
        let lifecycle = CvmLifecycle::new(
            driver,
            Arc::new(MockLaunchDigest::failing()),
            crate::lifecycle::HostResources {
                total_cpus: 1,
                total_memory_mb: 1,
                total_disk_gb: 0,
            },
        )
        .with_state_disk_root(root.path().to_path_buf());
        let vm = VmId::new("vm-a").unwrap();
        let qmp = Arc::new(qmp::mock::MockQmp::new(|_| {
            Ok(serde_json::json!([{
                "node-name": "libvirt-1-storage", "drv": "file", "file": "/elsewhere",
                "image": {"virtual-size": 1048576u64}}]))
        }));
        let m = BackupManager::new(
            qmp.clone(),
            Arc::new(image_tool::QemuImg::default()),
            Arc::new(Transfer::new().unwrap()),
        );
        let mut r = req("r2");
        r.kind = BackupKind::Incremental;
        r.parent_run_id = Some("r1".into());
        assert!(m.begin(&r).unwrap());
        let st = m.live_status(&lifecycle, &vm).await.unwrap();
        assert!(qmp.executed().is_empty(), "no QMP during a run");
        assert_eq!(st.live.point_run_ids, ["r1"]);
        assert_eq!(st.run.unwrap().status, RunPhase::Running);

        // Once the run is over, the points are read from QEMU again.
        m.runs.lock().unwrap().get_mut(&vm).unwrap().status = RunPhase::Done;
        let st = m.live_status(&lifecycle, &vm).await.unwrap();
        assert_eq!(qmp.executed(), ["query-named-block-nodes"]);
        assert!(st.live.point_run_ids.is_empty());
    }

    #[test]
    fn the_host_budget_is_split_across_the_run_slots() {
        assert_eq!(job_speed(DEFAULT_HOST_SPEED_BYTES_PER_SEC), 192 << 20);
        assert_eq!(
            job_speed(1000 << 20),
            (1000 << 20) / MAX_CONCURRENT_RUNS as u64
        );
        assert_eq!(job_speed(0), 0, "uncapped stays uncapped");
        assert_eq!(job_speed(1), MIN_JOB_SPEED_BYTES_PER_SEC, "floor");
    }

    #[tokio::test]
    async fn concurrent_runs_each_get_their_share_of_the_host_budget() {
        use crate::lifecycle::{DomainState, MockLaunchDigest, MockLibvirtDriver};
        let root = tempfile::tempdir().unwrap();
        let driver = Arc::new(MockLibvirtDriver::new());
        let vms = [VmId::new("vm-a").unwrap(), VmId::new("vm-b").unwrap()];
        for vm in &vms {
            driver.seed_domain(tenant_domain(vm).unwrap(), DomainState::Running);
        }
        let lifecycle = CvmLifecycle::new(
            driver,
            Arc::new(MockLaunchDigest::failing()),
            crate::lifecycle::HostResources {
                total_cpus: 1,
                total_memory_mb: 1,
                total_disk_gb: 0,
            },
        )
        .with_state_disk_root(root.path().to_path_buf());
        let mut nodes = Vec::new();
        for (i, vm) in vms.iter().enumerate() {
            let state = lifecycle.state_disk_path(vm);
            std::fs::create_dir_all(state.parent().unwrap()).unwrap();
            std::fs::write(&state, vec![0u8; 1 << 20]).unwrap();
            nodes.push(serde_json::json!({
                "node-name": format!("libvirt-{i}-storage"), "drv": "file",
                "file": lifecycle.golden_overlay_path(vm).to_str().unwrap(),
                "image": {"virtual-size": 1048576u64}}));
        }
        let nodes = serde_json::Value::Array(nodes);
        // Everything up to the transaction succeeds; the transaction is
        // refused, which ends both runs right after their speed is seen.
        let qmp = Arc::new(qmp::mock::MockQmp::new(move |c| {
            match c["execute"].as_str().unwrap() {
                "query-named-block-nodes" => Ok(nodes.clone()),
                "add-fd" => Ok(serde_json::json!({"fdset-id": 1})),
                "transaction" => Err(MinerAgentError::Backup("qmp-error")),
                "query-jobs" | "query-fdsets" => Ok(serde_json::json!([])),
                _ => Ok(serde_json::json!({})),
            }
        }));
        let m = BackupManager::new(
            qmp.clone(),
            Arc::new(image_tool::QemuImg::default()),
            Arc::new(Transfer::new().unwrap()),
        )
        .with_host_speed(100 << 20);
        let (mut a, mut b) = (req("r1"), req("r2"));
        a.vm_id = vms[0].clone();
        b.vm_id = vms[1].clone();
        assert!(m.begin(&a).unwrap() && m.begin(&b).unwrap());
        tokio::join!(m.run(&lifecycle, a), m.run(&lifecycle, b));
        let speeds: Vec<serde_json::Value> = qmp
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, c, _)| c["execute"] == "transaction")
            .map(|(_, c, _)| c["arguments"]["actions"][1]["data"]["speed"].clone())
            .collect();
        assert_eq!(
            speeds,
            [serde_json::json!(50 << 20), serde_json::json!(50 << 20)]
        );

        // An uncapped host sends no speed at all.
        let m = BackupManager::new(
            qmp.clone(),
            Arc::new(image_tool::QemuImg::default()),
            Arc::new(Transfer::new().unwrap()),
        )
        .with_host_speed(0);
        let mut c = req("r3");
        c.vm_id = vms[0].clone();
        assert!(m.begin(&c).unwrap());
        m.run(&lifecycle, c).await;
        let calls = qmp.calls.lock().unwrap();
        let last = calls
            .iter()
            .rev()
            .find(|(_, c, _)| c["execute"] == "transaction")
            .unwrap();
        assert!(last.1["arguments"]["actions"][1]["data"]
            .get("speed")
            .is_none());
    }

    #[tokio::test]
    async fn startup_recovery_empties_work_dirs_and_releases_qemu() {
        let root = tempfile::tempdir().unwrap();
        let vm_dir = root.path().join("vm-a");
        std::fs::create_dir_all(vm_dir.join("chain-restore")).unwrap();
        std::fs::write(vm_dir.join("target.raw"), b"x").unwrap();
        std::fs::write(
            vm_dir.join(capture::INFLIGHT_MARKER),
            serde_json::to_vec(&capture::InflightMarker {
                new_bitmap: Some("hippius-bk-r2".into()),
                source_path: "/o/vm-a.img".into(),
            })
            .unwrap(),
        )
        .unwrap();
        std::fs::create_dir_all(root.path().join("NOT-A-VM")).unwrap();
        // A staged restore survives: it is not backup scratch.
        std::fs::create_dir_all(vm_dir.join("restore/abc")).unwrap();
        std::fs::write(vm_dir.join("restore/status.json"), b"{}").unwrap();
        let qmp = Arc::new(qmp::mock::MockQmp::new(|c| {
            Ok(match c["execute"].as_str().unwrap() {
                "query-fdsets" => {
                    serde_json::json!([{"fdset-id": 3, "fds": [{"fd": 9, "opaque": qmp::FDSET_OPAQUE}]}])
                }
                "query-jobs" | "query-named-block-nodes" => serde_json::json!([]),
                _ => serde_json::json!({}),
            })
        }));
        let m = BackupManager::new(
            qmp.clone(),
            Arc::new(image_tool::QemuImg::default()),
            Arc::new(Transfer::new().unwrap()),
        );
        m.recover_on_startup(root.path()).await;
        let left: Vec<_> = std::fs::read_dir(&vm_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["restore"]);
        assert!(vm_dir.join("restore/abc").exists());
        let calls = qmp.calls.lock().unwrap();
        assert!(calls.iter().all(|(d, _, _)| d == "hippius-tenant-vm-a"));
        assert!(calls
            .iter()
            .any(|(_, c, _)| c["execute"] == "remove-fd" && c["arguments"]["fdset-id"] == 3));
    }
}
