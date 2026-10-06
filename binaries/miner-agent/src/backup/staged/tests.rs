//! Staged-restore claims, each with its own test:
//!
//! - staging never touches a live file (success or failure);
//! - one restore per VM, idempotent per id; finished ids stay finished;
//! - the swap is correct and re-entrant after a crash at every step;
//! - abort puts the original back byte-identical, after a crash at every
//!   swap step and at every abort step;
//! - abort destroys only this restore's domain, refuses to rename under a
//!   foreign live one, and leaves a running original alone;
//! - reclaim never deletes the only copy;
//! - a restart turns an interrupted staging into `failed`;
//! - the status route's shape.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use super::super::qcow2::testimg;
use super::super::restore::{ChainPiece, FetchOpts, PieceFetcher, RestoreChain};
use super::*;
use crate::lifecycle::{DomainId, DomainState, HostResources, MockLaunchDigest, MockLibvirtDriver};

const RID: &str = "0123456789abcdef0123456789abcdef";
const RID2: &str = "fedcba9876543210fedcba9876543210";
const CS: usize = 1 << 16;
const FULL: u64 = 16 * CS as u64;
const ORIGINAL_OVERLAY: &[u8] = b"the original overlay";
const ORIGINAL_MARKER: &str = "chain:job-0:https://s3/earlier";

/// Serves pieces from memory; enforces size + sha like the real fetcher.
/// With a gate, every fetch first waits for a permit (a staging held
/// open).
struct MemFetcher {
    objs: HashMap<String, Vec<u8>>,
    gate: Option<Arc<tokio::sync::Semaphore>>,
}

#[async_trait]
impl PieceFetcher for MemFetcher {
    async fn fetch(&self, piece: &ChainPiece, dest: &Path, opts: &FetchOpts) -> Result<()> {
        if let Some(g) = &self.gate {
            g.acquire().await.unwrap().forget();
        }
        let body = self
            .objs
            .get(&piece.url)
            .ok_or(MinerAgentError::Backup("get-status"))?;
        if hex::encode(Sha256::digest(body)) != piece.sha256_hex {
            return Err(MinerAgentError::Backup("sha-mismatch"));
        }
        tokio::fs::write(dest, body).await.unwrap();
        opts.progress
            .fetch_add(body.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

fn piece(url: &str, body: &[u8]) -> ChainPiece {
    ChainPiece {
        url: url.into(),
        sha256_hex: hex::encode(Sha256::digest(body)),
        size: body.len() as u64,
        part_size: 0,
        part_sha256_hex: Vec::new(),
    }
}

struct Env {
    _dir: tempfile::TempDir,
    driver: Arc<MockLibvirtDriver>,
    lifecycle: CvmLifecycle,
    vm: VmId,
    objs: HashMap<String, Vec<u8>>,
    migration: MigrationStore,
}

impl Env {
    /// A VM with a live overlay, state disk and marker; data and state on
    /// separate roots (the state disk is copied, not renamed, in).
    fn new() -> Self {
        Self::build(true)
    }

    /// A VM with NO live overlay, state disk or marker — the destination
    /// of a restore to a host that never ran this VM before (nothing to
    /// keep, nothing to rename aside).
    fn new_other_host() -> Self {
        Self::build(false)
    }

    fn build(with_original: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(MockLibvirtDriver::new());
        let lifecycle = CvmLifecycle::new(
            driver.clone(),
            Arc::new(MockLaunchDigest::failing()),
            HostResources {
                total_cpus: 1,
                total_memory_mb: 1,
                total_disk_gb: 0,
            },
        )
        .with_storage_roots(dir.path().join("data"), dir.path().join("statefs"));
        let vm = VmId::new("vm-r").unwrap();
        let p = RestorePaths::for_vm(&lifecycle, &vm, RID);
        std::fs::create_dir_all(p.live_overlay.parent().unwrap()).unwrap();
        std::fs::create_dir_all(p.live_state.parent().unwrap()).unwrap();
        if with_original {
            std::fs::write(&p.live_overlay, ORIGINAL_OVERLAY).unwrap();
            std::fs::write(&p.live_state, original_state()).unwrap();
            std::fs::write(&p.marker, ORIGINAL_MARKER).unwrap();
        }
        let mut objs = HashMap::new();
        objs.insert("u/full".to_string(), vec![0u8; FULL as usize]);
        objs.insert(
            "u/inc".to_string(),
            testimg::build(FULL, &[(1, Some(0x42))]),
        );
        objs.insert("u/state".to_string(), staged_state());
        Self {
            _dir: dir,
            driver,
            lifecycle,
            vm,
            objs,
            migration: MigrationStore::new(),
        }
    }

    fn paths(&self, rid: &str) -> RestorePaths {
        RestorePaths::for_vm(&self.lifecycle, &self.vm, rid)
    }

    fn chain(&self, rid: &str) -> RestoreChain {
        RestoreChain {
            restore_id: rid.into(),
            full: piece("u/full", &self.objs["u/full"]),
            incrementals: vec![piece("u/inc", &self.objs["u/inc"])],
            state: piece("u/state", &self.objs["u/state"]),
        }
    }

    fn manager(&self, gate: Option<Arc<tokio::sync::Semaphore>>) -> RestoreManager {
        RestoreManager::new(
            Arc::new(MemFetcher {
                objs: self.objs.clone(),
                gate,
            }),
            Arc::default(),
        )
        .with_headroom(0)
    }

    fn req(&self, rid: &str) -> StageRequest {
        StageRequest {
            vm_id: self.vm.clone(),
            restore_id: rid.into(),
            chain: self.chain(rid),
            disk_bytes: FULL,
            streams: 8,
        }
    }

    /// Stage `rid` to completion.
    async fn stage(&self, m: &RestoreManager, rid: &str) {
        match m.begin_stage(&self.lifecycle, self.req(rid)).await.unwrap() {
            StageStart::Started(job) => m.run_stage(job).await,
            _ => panic!("expected a new staging"),
        }
        let st = RestoreManager::peek(&self.lifecycle, &self.vm)
            .await
            .unwrap();
        assert_eq!(st.state, RestoreState::Staged);
    }

    fn domain(&self) -> DomainId {
        DomainId::new("hippius-tenant-vm-r").unwrap()
    }

    /// The live files, byte for byte (`None` = absent).
    fn live(&self) -> [Option<Vec<u8>>; 3] {
        let p = self.paths(RID);
        [
            std::fs::read(&p.live_overlay).ok(),
            std::fs::read(&p.live_state).ok(),
            std::fs::read(&p.marker).ok(),
        ]
    }

    fn original_live(&self) -> [Option<Vec<u8>>; 3] {
        [
            Some(ORIGINAL_OVERLAY.to_vec()),
            Some(original_state()),
            Some(ORIGINAL_MARKER.as_bytes().to_vec()),
        ]
    }
}

fn original_state() -> Vec<u8> {
    vec![7u8; STATE_DISK_BYTES as usize]
}

fn staged_state() -> Vec<u8> {
    vec![9u8; STATE_DISK_BYTES as usize]
}

/// What the chain rebuilds to: zeros with cluster 1 = 0x42.
fn rebuilt_overlay() -> Vec<u8> {
    let mut v = vec![0u8; FULL as usize];
    v[CS..2 * CS].fill(0x42);
    v
}

fn assert_backup(err: MinerAgentError, class: &str) {
    assert!(
        matches!(err, MinerAgentError::Backup(c) if c == class),
        "want backup/{class}, got {err:?}"
    );
}

fn set_crash(n: u32) {
    CRASH_AT.with(|c| c.set(n));
}

#[tokio::test]
async fn staging_builds_beside_the_live_disks_and_never_touches_them() {
    let env = Env::new();
    let m = env.manager(None);
    let before = env.live();
    env.stage(&m, RID).await;
    let p = env.paths(RID);
    assert_eq!(std::fs::read(&p.staged_overlay).unwrap(), rebuilt_overlay());
    assert_eq!(std::fs::read(&p.staged_state).unwrap(), staged_state());
    assert!(!p.work_dir.exists(), "the scratch dir goes");
    assert_eq!(env.live(), before, "no live file changed");
    assert!(!p.pre_overlay.exists() && !p.pre_state.exists());
    let st = m.status(&env.lifecycle, &env.vm).await.unwrap().unwrap();
    assert_eq!(st.bytes_done, st.bytes_total);
    assert_eq!(
        st.bytes_total,
        FULL + env.objs["u/inc"].len() as u64 + STATE_DISK_BYTES
    );
}

#[tokio::test]
async fn a_failed_staging_leaves_the_live_disks_and_no_staged_file() {
    let mut env = Env::new();
    env.objs.insert("u/inc".into(), b"corrupt".to_vec());
    let m = env.manager(None);
    let before = env.live();
    let mut req = env.req(RID);
    // The order carried the real sha; the store serves other bytes.
    req.chain.incrementals[0] = piece("u/inc", &testimg::build(FULL, &[(1, Some(0x42))]));
    let StageStart::Started(job) = m.begin_stage(&env.lifecycle, req).await.unwrap() else {
        panic!("expected a new staging");
    };
    m.run_stage(job).await;
    let st = m.status(&env.lifecycle, &env.vm).await.unwrap().unwrap();
    assert_eq!(st.state, RestoreState::Failed);
    assert_eq!(st.reason.as_deref(), Some("sha-mismatch"));
    assert!(!env.paths(RID).staging_dir.exists());
    assert_eq!(env.live(), before);
}

#[tokio::test]
async fn one_restore_per_vm_idempotent_per_id() {
    let env = Env::new();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let m = Arc::new(env.manager(Some(gate.clone())));
    let StageStart::Started(job) = m.begin_stage(&env.lifecycle, env.req(RID)).await.unwrap()
    else {
        panic!("expected a new staging");
    };
    assert!(matches!(
        m.begin_stage(&env.lifecycle, env.req(RID)).await.unwrap(),
        StageStart::Staging
    ));
    assert_backup(
        m.begin_stage(&env.lifecycle, env.req(RID2))
            .await
            .err()
            .unwrap(),
        "restore-busy",
    );
    gate.add_permits(100);
    m.run_stage(job).await;
    assert!(matches!(
        m.begin_stage(&env.lifecycle, env.req(RID)).await.unwrap(),
        StageStart::Staged
    ));
    // A staged restore still owns files only its id reaches.
    assert_backup(
        m.begin_stage(&env.lifecycle, env.req(RID2))
            .await
            .err()
            .unwrap(),
        "restore-busy",
    );
    m.abort(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap();
    assert_backup(
        m.begin_stage(&env.lifecycle, env.req(RID))
            .await
            .err()
            .unwrap(),
        "restore-finished",
    );
    assert!(matches!(
        m.begin_stage(&env.lifecycle, env.req(RID2)).await.unwrap(),
        StageStart::Started(_)
    ));
}

#[tokio::test]
async fn a_new_restore_waits_for_the_last_ones_retained_originals() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    swap_in(&env.paths(RID), RID, None, async { true })
        .await
        .unwrap();
    // Swapped, not reclaimed: the originals are only reachable via RID.
    assert_backup(
        m.begin_stage(&env.lifecycle, env.req(RID2))
            .await
            .err()
            .unwrap(),
        "restore-busy",
    );
    m.reclaim(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap();
    assert!(matches!(
        m.begin_stage(&env.lifecycle, env.req(RID2)).await.unwrap(),
        StageStart::Started(_)
    ));
}

#[tokio::test]
async fn staging_refuses_a_chain_for_another_restore() {
    let env = Env::new();
    let m = env.manager(None);
    let mut req = env.req(RID);
    req.chain.restore_id = RID2.into();
    assert_backup(
        m.begin_stage(&env.lifecycle, req).await.err().unwrap(),
        "restore-id-mismatch",
    );
    let mut req = env.req("NOT-AN-ID");
    req.chain.restore_id = "NOT-AN-ID".into();
    assert_backup(
        m.begin_stage(&env.lifecycle, req).await.err().unwrap(),
        "restore-bad-id",
    );
    let mut req = env.req(RID);
    req.disk_bytes = FULL * 2;
    assert_backup(
        m.begin_stage(&env.lifecycle, req).await.err().unwrap(),
        "full-size-mismatch",
    );
    assert!(RestoreManager::peek(&env.lifecycle, &env.vm)
        .await
        .is_none());
}

/// Assert the swapped state: restored disks live, originals retained.
fn assert_swapped(env: &Env) {
    let p = env.paths(RID);
    assert_eq!(std::fs::read(&p.live_overlay).unwrap(), rebuilt_overlay());
    assert_eq!(std::fs::read(&p.live_state).unwrap(), staged_state());
    assert_eq!(
        std::fs::read_to_string(&p.marker).unwrap(),
        staged_marker(RID)
    );
    assert_eq!(std::fs::read(&p.pre_overlay).unwrap(), ORIGINAL_OVERLAY);
    assert_eq!(std::fs::read(&p.pre_state).unwrap(), original_state());
    assert_eq!(
        std::fs::read_to_string(&p.pre_marker).unwrap(),
        ORIGINAL_MARKER
    );
}

#[tokio::test]
async fn the_swap_completes_after_a_crash_at_every_step() {
    for crash in [0u32, 1, 2, 3, 4, 5] {
        let env = Env::new();
        let m = env.manager(None);
        env.stage(&m, RID).await;
        set_crash(crash);
        let first = swap_in(&env.paths(RID), RID, Some(FULL), async { true }).await;
        set_crash(0);
        if crash == 0 {
            assert_eq!(first.unwrap(), SwapOutcome::Swapped);
        } else {
            assert_backup(first.unwrap_err(), "test-crash");
            assert_eq!(
                swap_in(&env.paths(RID), RID, Some(FULL), async { true })
                    .await
                    .unwrap(),
                SwapOutcome::Swapped,
                "crash={crash}"
            );
        }
        assert_swapped(&env);
        assert_eq!(
            swap_in(&env.paths(RID), RID, Some(FULL), async { true })
                .await
                .unwrap(),
            SwapOutcome::AlreadySwapped
        );
        assert_swapped(&env);
    }
}

/// The live repro: staging reached `staged`, then (this test: a
/// `remove_file`, live: something else) the staged overlay vanished from
/// disk before `migrate-activate` ran, on the SAME host as the original.
/// Before the inode-identity check, `swap_in` read "staged absent, live
/// present" as "step (2) already moved it" — the `else if
/// !present(live_overlay)` branch only ever errored when the live
/// overlay was ALSO gone — and happily renamed the state disk, wrote the
/// `staged:<id>` marker and returned `Swapped`, launching the ORIGINAL
/// disk while vali's done-gate reported the job `done`. It must instead
/// refuse before touching anything.
#[tokio::test]
async fn same_host_swap_refuses_when_the_staged_overlay_vanished_before_the_move() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    let p = env.paths(RID);
    std::fs::remove_file(&p.staged_overlay).unwrap();
    let before = env.live();
    let err = swap_in(&p, RID, Some(FULL), async { true })
        .await
        .unwrap_err();
    assert!(
        matches!(err, MinerAgentError::Migration("restore-staged-missing")),
        "{err:?}"
    );
    assert_eq!(
        env.live(),
        before,
        "the original overlay, state disk and marker are untouched"
    );
    assert_eq!(env.live(), env.original_live());
    assert!(
        !p.pre_overlay.exists() && !p.pre_state.exists() && !p.pre_marker.exists(),
        "a refused swap must rename nothing — no pre-restore files appear"
    );
    // Mutation check (see the fix's PR description): reverting the
    // inode-identity guard makes exactly this assertion fail — the old
    // code returns `Swapped` here instead of refusing.
}

/// Mirrors [`the_swap_completes_after_a_crash_at_every_step`] on a host
/// that never ran this VM before: nothing to rename aside, so steps (1)
/// and (2)'s "move the original aside" halves never run, but the swap
/// still completes and is still re-entrant at the steps that do apply
/// (staged overlay -> live, and the state disk write).
#[tokio::test]
async fn other_host_swap_completes_and_resumes_after_a_crash_at_every_step() {
    for crash in [0u32, 1, 2, 3, 4, 5] {
        let env = Env::new_other_host();
        let m = env.manager(None);
        env.stage(&m, RID).await;
        let p = env.paths(RID);
        set_crash(crash);
        let first = swap_in(&p, RID, Some(FULL), async { true }).await;
        set_crash(0);
        match first {
            Ok(outcome) => assert_eq!(outcome, SwapOutcome::Swapped, "crash={crash}"),
            Err(e) => {
                assert_backup(e, "test-crash");
                assert_eq!(
                    swap_in(&p, RID, Some(FULL), async { true }).await.unwrap(),
                    SwapOutcome::Swapped,
                    "crash={crash}"
                );
            }
        }
        assert_eq!(std::fs::read(&p.live_overlay).unwrap(), rebuilt_overlay());
        assert_eq!(std::fs::read(&p.live_state).unwrap(), staged_state());
        assert_eq!(
            std::fs::read_to_string(&p.marker).unwrap(),
            staged_marker(RID)
        );
        assert!(
            !p.pre_overlay.exists() && !p.pre_state.exists() && !p.pre_marker.exists(),
            "no original ever existed to retain — crash={crash}"
        );
        assert_eq!(
            swap_in(&p, RID, Some(FULL), async { true }).await.unwrap(),
            SwapOutcome::AlreadySwapped,
            "crash={crash}"
        );
    }
}

/// The same crash matrix as [`the_swap_completes_after_a_crash_at_every_step`],
/// but for a record an OLDER agent wrote (no [`StagedOverlayStat`]):
/// `swap_in`'s weaker fallback (both the original's overlay AND its
/// marker already moved aside) must still resume correctly across an
/// upgrade.
#[tokio::test]
async fn legacy_record_without_inode_still_resumes_after_a_crash() {
    for crash in [0u32, 1, 2, 3, 4, 5] {
        let env = Env::new();
        let p = env.paths(RID);
        stage_for_tests_legacy(&p, RID, &rebuilt_overlay(), &staged_state()).await;
        set_crash(crash);
        let first = swap_in(&p, RID, Some(FULL), async { true }).await;
        set_crash(0);
        if crash == 0 {
            assert_eq!(first.unwrap(), SwapOutcome::Swapped);
        } else {
            assert_backup(first.unwrap_err(), "test-crash");
            assert_eq!(
                swap_in(&p, RID, Some(FULL), async { true }).await.unwrap(),
                SwapOutcome::Swapped,
                "crash={crash}"
            );
        }
        assert_swapped(&env);
        assert_eq!(
            swap_in(&p, RID, Some(FULL), async { true }).await.unwrap(),
            SwapOutcome::AlreadySwapped
        );
    }
}

/// The same live bug, for a record an older agent left with no inode
/// recorded: without the `pre_overlay`+`pre_marker` fallback check, a
/// legacy record is just as exposed to "staged absent, live present"
/// being misread as "already moved".
#[tokio::test]
async fn legacy_record_without_inode_also_refuses_when_staged_vanished() {
    let env = Env::new();
    let p = env.paths(RID);
    stage_for_tests_legacy(&p, RID, &rebuilt_overlay(), &staged_state()).await;
    std::fs::remove_file(&p.staged_overlay).unwrap();
    let before = env.live();
    let err = swap_in(&p, RID, Some(FULL), async { true })
        .await
        .unwrap_err();
    assert!(
        matches!(err, MinerAgentError::Migration("restore-staged-missing")),
        "{err:?}"
    );
    assert_eq!(env.live(), before);
    assert_eq!(env.live(), env.original_live());
    assert!(!p.pre_overlay.exists() && !p.pre_state.exists() && !p.pre_marker.exists());
}

#[tokio::test]
async fn abort_restores_the_original_byte_identical_from_any_crash() {
    for swap_crash in [0u32, 1, 2, 3, 4, 5] {
        for abort_crash in [0u32, 11, 12, 13] {
            let env = Env::new();
            let m = env.manager(None);
            env.stage(&m, RID).await;
            set_crash(swap_crash);
            let _ = swap_in(&env.paths(RID), RID, None, async { true }).await;
            set_crash(abort_crash);
            let first = m.abort(&env.lifecycle, &env.migration, &env.vm, RID).await;
            set_crash(0);
            if first.is_err() {
                m.abort(&env.lifecycle, &env.migration, &env.vm, RID)
                    .await
                    .unwrap();
            }
            assert_eq!(
                env.live(),
                env.original_live(),
                "swap_crash={swap_crash} abort_crash={abort_crash}"
            );
            let p = env.paths(RID);
            assert!(!p.pre_overlay.exists() && !p.pre_state.exists() && !p.pre_marker.exists());
            assert!(!p.staging_dir.exists());
            let st = m.status(&env.lifecycle, &env.vm).await.unwrap().unwrap();
            assert_eq!((st.op, st.state), (RestoreOp::Abort, RestoreState::Aborted));
            // Idempotent.
            m.abort(&env.lifecycle, &env.migration, &env.vm, RID)
                .await
                .unwrap();
            assert_eq!(env.live(), env.original_live());
        }
    }
}

#[tokio::test]
async fn abort_forces_this_restores_domain_down_first() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    swap_in(&env.paths(RID), RID, None, async { true })
        .await
        .unwrap();
    // The restored guest booted (untracked: an agent restart since).
    env.driver.seed_domain(env.domain(), DomainState::Running);
    m.abort(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap();
    assert_eq!(
        env.lifecycle.tenant_domain_liveness(&env.vm).await,
        DomainLiveness::Down
    );
    assert_eq!(env.live(), env.original_live());
}

#[tokio::test]
async fn abort_never_renames_under_a_foreign_live_domain() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    // A swap died after moving the original aside; something then booted
    // the domain (not from this restore's marker).
    set_crash(2);
    let _ = swap_in(&env.paths(RID), RID, None, async { true }).await;
    set_crash(0);
    env.driver.seed_domain(env.domain(), DomainState::Running);
    let before = env.live();
    let err = m
        .abort(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap_err();
    assert_backup(err, "restore-vm-live");
    assert_eq!(env.live(), before, "nothing renamed");
    assert!(env.paths(RID).pre_overlay.exists());
    assert_eq!(
        env.lifecycle.tenant_domain_liveness(&env.vm).await,
        DomainLiveness::Live,
        "a foreign domain is never stopped"
    );
}

#[tokio::test]
async fn abort_while_the_original_runs_only_drops_the_staging() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    env.driver.seed_domain(env.domain(), DomainState::Running);
    m.abort(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap();
    assert_eq!(
        env.lifecycle.tenant_domain_liveness(&env.vm).await,
        DomainLiveness::Live,
        "the running original is left alone"
    );
    assert_eq!(env.live(), env.original_live());
    assert!(!env.paths(RID).staging_dir.exists());
}

#[tokio::test]
async fn abort_is_refused_while_an_activation_runs() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    assert!(env.migration.begin_activate(&env.vm).unwrap());
    let err = m
        .abort(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap_err();
    assert_backup(err, "restore-activating");
    assert!(env.paths(RID).staged_overlay.exists());
}

#[tokio::test]
async fn abort_cancels_a_staging_in_flight() {
    let env = Env::new();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let m = Arc::new(env.manager(Some(gate)));
    let StageStart::Started(job) = m.begin_stage(&env.lifecycle, env.req(RID)).await.unwrap()
    else {
        panic!("expected a new staging");
    };
    let runner = {
        let m = Arc::clone(&m);
        tokio::spawn(async move { m.run_stage(job).await })
    };
    tokio::task::yield_now().await;
    m.abort(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap();
    runner.await.unwrap();
    let st = m.status(&env.lifecycle, &env.vm).await.unwrap().unwrap();
    assert_eq!(st.state, RestoreState::Aborted);
    assert!(!env.paths(RID).staging_dir.exists());
    assert_eq!(env.live(), env.original_live());
}

#[tokio::test]
async fn reclaim_never_deletes_the_only_copy() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    let p = env.paths(RID);
    // Staged, not swapped: the live disks are the only copy of the VM.
    assert_backup(
        m.reclaim(&env.lifecycle, &env.migration, &env.vm, RID)
            .await
            .unwrap_err(),
        "restore-reclaim-refused",
    );
    assert_eq!(env.live(), env.original_live());
    assert!(p.staged_overlay.exists());
    // A swap that died before its marker: the originals aside are the
    // only copy of the original.
    set_crash(5);
    let _ = swap_in(&p, RID, None, async { true }).await;
    set_crash(0);
    assert_backup(
        m.reclaim(&env.lifecycle, &env.migration, &env.vm, RID)
            .await
            .unwrap_err(),
        "restore-reclaim-refused",
    );
    assert_eq!(std::fs::read(&p.pre_overlay).unwrap(), ORIGINAL_OVERLAY);
    assert_eq!(std::fs::read(&p.pre_state).unwrap(), original_state());
    // Swapped: the originals go, the restored disks stay.
    swap_in(&p, RID, None, async { true }).await.unwrap();
    m.reclaim(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap();
    assert!(!p.pre_overlay.exists() && !p.pre_state.exists() && !p.pre_marker.exists());
    assert!(!p.staging_dir.exists());
    assert_eq!(std::fs::read(&p.live_overlay).unwrap(), rebuilt_overlay());
    assert_eq!(std::fs::read(&p.live_state).unwrap(), staged_state());
    m.reclaim(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap();
    let st = m.status(&env.lifecycle, &env.vm).await.unwrap().unwrap();
    assert_eq!(
        (st.op, st.state),
        (RestoreOp::Reclaim, RestoreState::Reclaimed)
    );
}

#[tokio::test]
async fn reclaim_is_refused_after_an_abort() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    swap_in(&env.paths(RID), RID, None, async { true })
        .await
        .unwrap();
    m.abort(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap();
    assert_backup(
        m.reclaim(&env.lifecycle, &env.migration, &env.vm, RID)
            .await
            .unwrap_err(),
        "restore-reclaim-refused",
    );
    assert_eq!(env.live(), env.original_live());
}

#[tokio::test]
async fn the_swap_refuses_anything_but_this_staged_restore() {
    let env = Env::new();
    let p = env.paths(RID);
    let err = swap_in(&p, RID, None, async { true }).await.unwrap_err();
    assert!(matches!(
        err,
        MinerAgentError::Migration("restore-not-staged")
    ));
    let m = env.manager(None);
    env.stage(&m, RID).await;
    let err = swap_in(&env.paths(RID2), RID2, None, async { true })
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        MinerAgentError::Migration("restore-not-staged")
    ));
    let err = swap_in(&p, RID, Some(FULL * 2), async { true })
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        MinerAgentError::Migration("restore-size-mismatch")
    ));
    assert_eq!(env.live(), env.original_live(), "nothing moved");
    assert!(p.staged_overlay.exists());
}

#[tokio::test]
async fn a_restart_fails_an_interrupted_staging_and_keeps_a_staged_one() {
    let env = Env::new();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let m = env.manager(Some(gate));
    let StageStart::Started(_job) = m.begin_stage(&env.lifecycle, env.req(RID)).await.unwrap()
    else {
        panic!("expected a new staging");
    };
    std::fs::create_dir_all(env.paths(RID).work_dir.clone()).unwrap();
    std::fs::write(env.paths(RID).work_dir.join("overlay.img"), b"partial").unwrap();
    // The process dies; a new one starts.
    let fresh = env.manager(None);
    fresh.recover_on_startup(&env.lifecycle.backup_root()).await;
    let st = fresh
        .status(&env.lifecycle, &env.vm)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(st.state, RestoreState::Failed);
    assert_eq!(st.reason.as_deref(), Some("agent-restart"));
    assert!(!env.paths(RID).staging_dir.exists());
    // vali re-sends stage: it runs again.
    env.stage(&fresh, RID).await;
    fresh.recover_on_startup(&env.lifecycle.backup_root()).await;
    let st = fresh
        .status(&env.lifecycle, &env.vm)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(st.state, RestoreState::Staged);
    assert!(env.paths(RID).staged_overlay.exists());
}

#[tokio::test]
async fn the_status_has_the_contract_shape() {
    let env = Env::new();
    let m = env.manager(None);
    assert_eq!(m.status(&env.lifecycle, &env.vm).await.unwrap(), None);
    env.stage(&m, RID).await;
    swap_in(&env.paths(RID), RID, None, async { true })
        .await
        .unwrap();
    env.driver.seed_domain(env.domain(), DomainState::Running);
    let st = m.status(&env.lifecycle, &env.vm).await.unwrap().unwrap();
    let total = st.bytes_total;
    assert_eq!(
        serde_json::to_value(&st).unwrap(),
        serde_json::json!({
            "vm_id": "vm-r", "restore_id": RID, "op": "stage", "state": "staged",
            "bytes_done": total, "bytes_total": total, "reason": null,
            "swapped": true, "pre_restore_present": true, "domain_live": true,
        })
    );
}

#[test]
fn restore_ids_are_32_lower_hex() {
    check_restore_id(RID).unwrap();
    for bad in [
        "",
        "0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdef0",
        "0123456789abcdef0123456789abcdeg",
        "../../../../../../../../etc/pwd0",
    ] {
        assert!(check_restore_id(bad).is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn the_decommission_footprint_names_the_retained_originals_exactly() {
    let env = Env::new();
    let m = env.manager(None);
    let dir = env.lifecycle.backup_dir(&env.vm);
    let ov = env.lifecycle.golden_overlay_path(&env.vm);
    let stp = env.lifecycle.state_disk_path(&env.vm);
    assert!(retained_files(&dir, &ov, &stp).is_empty());
    env.stage(&m, RID).await;
    let p = env.paths(RID);
    assert_eq!(
        retained_files(&dir, &ov, &stp),
        vec![p.pre_overlay, p.pre_state, p.pre_marker]
    );
}

#[tokio::test]
async fn a_decommission_reclaims_the_retained_originals_too() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    swap_in(&env.paths(RID), RID, None, async { true })
        .await
        .unwrap();
    let p = env.paths(RID);
    env.lifecycle.destroy(&env.vm, Some(&m)).await.unwrap();
    for f in [&p.pre_overlay, &p.pre_state, &p.pre_marker, &p.live_overlay] {
        assert!(!f.exists(), "{} left behind", f.display());
    }
    assert!(!p.restore_root.exists());
}

#[tokio::test]
async fn a_destroy_cancels_an_in_flight_staging_before_reclaiming_it() {
    // The leak this guards: `destroy` used to reclaim `backup/<vm>/`
    // without a care for a staging still writing into
    // `backup/<vm>/restore/<rid>/` — the still-running `run_stage` would
    // then recreate `restore/status.json` for a VM that no longer
    // exists, forever (nothing else ever revisits a destroyed VM's
    // backup dir). `destroy` must cancel and await the staging first.
    let env = Env::new();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let m = Arc::new(env.manager(Some(gate)));
    let StageStart::Started(job) = m.begin_stage(&env.lifecycle, env.req(RID)).await.unwrap()
    else {
        panic!("expected a new staging");
    };
    assert!(env.lifecycle.backup_dir(&env.vm).exists(), "precondition");
    let runner = {
        let m = Arc::clone(&m);
        tokio::spawn(async move { m.run_stage(job).await })
    };
    // Let the staging actually start (block on the gate mid-fetch) before
    // destroy races it — a stage not yet even begun would prove nothing.
    tokio::task::yield_now().await;

    // `destroy` itself must not hang waiting on a staging that only a
    // gate release can unblock: it cancels the staging cooperatively
    // rather than waiting for the fetch to finish.
    tokio::time::timeout(
        Duration::from_secs(5),
        env.lifecycle.destroy(&env.vm, Some(m.as_ref())),
    )
    .await
    .expect("destroy must not block on an in-flight staging")
    .expect("destroy must succeed");

    // By the time `destroy` returned, the cancelled `run_stage` must
    // already have finished — its own await inside `destroy` blocks on
    // exactly that — so this must not need a timeout to pass.
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("run_stage must have finished by the time destroy returns")
        .unwrap();

    assert!(
        !env.lifecycle.backup_dir(&env.vm).exists(),
        "a destroy concurrent with an in-progress stage must leave no backup/<vm> footprint"
    );
}

#[tokio::test]
async fn the_swap_never_overwrites_a_retained_original() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    let p = env.paths(RID);
    // Retained originals already on disk (however they got there) while
    // live disks exist too: renaming live over them would destroy them.
    std::fs::write(&p.pre_overlay, b"retained overlay").unwrap();
    let err = swap_in(&p, RID, None, async { true }).await.unwrap_err();
    assert!(matches!(
        err,
        MinerAgentError::Migration("restore-swap-conflict")
    ));
    assert_eq!(std::fs::read(&p.pre_overlay).unwrap(), b"retained overlay");
    assert_eq!(std::fs::read(&p.live_overlay).unwrap(), ORIGINAL_OVERLAY);

    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    let p = env.paths(RID);
    std::fs::write(&p.pre_state, b"retained state").unwrap();
    swap_in(&p, RID, None, async { true }).await.unwrap();
    assert_eq!(std::fs::read(&p.pre_state).unwrap(), b"retained state");
}

#[tokio::test]
async fn a_real_ranged_staging_over_http_heals_a_bad_part() {
    use super::super::transfer::{test_server, Transfer, MIN_PART_SIZE};
    let store = test_server::Store::default();
    let base = test_server::start(store.clone()).await;
    let full: Vec<u8> = (0..(MIN_PART_SIZE * 2 + 4321))
        .map(|i| (i * 31 % 253) as u8)
        .collect();
    let state = staged_state();
    store
        .objects
        .lock()
        .unwrap()
        .insert("full".into(), full.clone());
    store
        .objects
        .lock()
        .unwrap()
        .insert("state".into(), state.clone());
    // The middle part comes back corrupt once.
    store
        .corrupt
        .lock()
        .unwrap()
        .insert(("full".into(), MIN_PART_SIZE), 1);
    let mut full_piece = piece(&format!("{base}/full"), &full);
    full_piece.part_size = MIN_PART_SIZE;
    full_piece.part_sha256_hex = full
        .chunks(MIN_PART_SIZE as usize)
        .map(|c| hex::encode(Sha256::digest(c)))
        .collect();
    let env = Env::new();
    let m =
        RestoreManager::new(Arc::new(Transfer::new().unwrap()), Arc::default()).with_headroom(0);
    let req = StageRequest {
        vm_id: env.vm.clone(),
        restore_id: RID.into(),
        chain: RestoreChain {
            restore_id: RID.into(),
            full: full_piece,
            incrementals: Vec::new(),
            state: piece(&format!("{base}/state"), &state),
        },
        disk_bytes: full.len() as u64,
        streams: 3,
    };
    let StageStart::Started(job) = m.begin_stage(&env.lifecycle, req).await.unwrap() else {
        panic!("expected a new staging");
    };
    m.run_stage(job).await;
    let st = m.status(&env.lifecycle, &env.vm).await.unwrap().unwrap();
    assert_eq!(st.state, RestoreState::Staged, "{:?}", st.reason);
    assert_eq!(st.bytes_done, full.len() as u64 + STATE_DISK_BYTES);
    assert_eq!(std::fs::read(env.paths(RID).staged_overlay).unwrap(), full);
    assert_eq!(std::fs::read(env.paths(RID).staged_state).unwrap(), state);
    assert_eq!(env.live(), env.original_live());
    let gets = store.gets.lock().unwrap();
    assert_eq!(
        gets.iter().filter(|(k, _)| k == "full").count(),
        4,
        "three ranges + one retry"
    );
}

#[tokio::test]
async fn a_reclaimed_restore_cannot_be_aborted() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    let p = env.paths(RID);
    swap_in(&p, RID, None, async { true }).await.unwrap();
    m.reclaim(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap();
    env.driver.seed_domain(env.domain(), DomainState::Running);
    assert_backup(
        m.abort(&env.lifecycle, &env.migration, &env.vm, RID)
            .await
            .unwrap_err(),
        "restore-finished",
    );
    assert_eq!(
        env.lifecycle.tenant_domain_liveness(&env.vm).await,
        DomainLiveness::Live,
        "the committed VM keeps running"
    );
    assert_eq!(
        std::fs::read_to_string(&p.marker).unwrap(),
        staged_marker(RID)
    );
}

#[tokio::test]
async fn reclaim_is_refused_while_an_activation_runs() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    let p = env.paths(RID);
    swap_in(&p, RID, None, async { true }).await.unwrap();
    assert!(env.migration.begin_activate(&env.vm).unwrap());
    assert_backup(
        m.reclaim(&env.lifecycle, &env.migration, &env.vm, RID)
            .await
            .unwrap_err(),
        "restore-activating",
    );
    assert_eq!(std::fs::read(&p.pre_overlay).unwrap(), ORIGINAL_OVERLAY);
}

#[tokio::test]
async fn the_swap_rechecks_the_domain_under_its_lock() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    let p = env.paths(RID);
    let err = swap_in(&p, RID, None, async { false }).await.unwrap_err();
    assert!(matches!(err, MinerAgentError::Migration("restore-vm-live")));
    assert_eq!(env.live(), env.original_live(), "nothing moved");
    assert!(p.staged_overlay.exists());
}

#[tokio::test]
async fn stagings_are_bounded_per_host() {
    // Three fetches' worth: one staging runs to completion first.
    let gate = Arc::new(tokio::sync::Semaphore::new(3));
    let env = Env::new();
    let m = env.manager(Some(gate));
    env.stage(&m, RID).await;
    let mut jobs = Vec::new();
    for (i, rid) in [RID, RID2].iter().enumerate() {
        let mut req = env.req(rid);
        req.vm_id = VmId::new(&format!("vm-{i}")).unwrap();
        match m.begin_stage(&env.lifecycle, req).await.unwrap() {
            StageStart::Started(job) => jobs.push(job),
            _ => panic!("expected a new staging"),
        }
    }
    let mut req = env.req(RID);
    req.vm_id = VmId::new("vm-third").unwrap();
    assert_backup(
        m.begin_stage(&env.lifecycle, req).await.err().unwrap(),
        "restore-host-busy",
    );
    // An already-staged restore still answers staged: no new work.
    assert!(matches!(
        m.begin_stage(&env.lifecycle, env.req(RID)).await.unwrap(),
        StageStart::Staged
    ));
}

#[tokio::test]
async fn a_superseded_restore_is_never_aborted() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    let p = env.paths(RID);
    swap_in(&p, RID, None, async { true }).await.unwrap();
    m.reclaim(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap();
    // The next restore of the VM starts; a delayed abort of the first
    // arrives while the committed VM runs.
    assert!(matches!(
        m.begin_stage(&env.lifecycle, env.req(RID2)).await.unwrap(),
        StageStart::Started(_)
    ));
    env.driver.seed_domain(env.domain(), DomainState::Running);
    assert_backup(
        m.abort(&env.lifecycle, &env.migration, &env.vm, RID)
            .await
            .unwrap_err(),
        "restore-finished",
    );
    assert_eq!(
        env.lifecycle.tenant_domain_liveness(&env.vm).await,
        DomainLiveness::Live
    );
    assert_eq!(
        std::fs::read_to_string(&p.marker).unwrap(),
        staged_marker(RID)
    );
}

#[tokio::test]
async fn a_reclaim_that_died_midway_is_never_aborted_and_finishes_on_resend() {
    let env = Env::new();
    let m = env.manager(None);
    env.stage(&m, RID).await;
    let p = env.paths(RID);
    swap_in(&p, RID, None, async { true }).await.unwrap();
    set_crash(21);
    let first = m
        .reclaim(&env.lifecycle, &env.migration, &env.vm, RID)
        .await;
    set_crash(0);
    assert_backup(first.unwrap_err(), "test-crash");
    assert!(p.pre_overlay.exists(), "died before deleting");
    assert_backup(
        m.abort(&env.lifecycle, &env.migration, &env.vm, RID)
            .await
            .unwrap_err(),
        "restore-finished",
    );
    assert_eq!(std::fs::read(&p.live_overlay).unwrap(), rebuilt_overlay());
    m.reclaim(&env.lifecycle, &env.migration, &env.vm, RID)
        .await
        .unwrap();
    assert!(!p.pre_overlay.exists() && !p.pre_state.exists());
}

#[test]
fn ratchet_never_reports_less_than_its_high_water_mark() {
    let r = Ratchet::default();
    assert_eq!(r.report(0), 0);
    assert_eq!(r.report(10), 10);
    assert_eq!(r.report(3), 10, "a dip must not regress what was reported");
    assert_eq!(r.report(15), 15);
    assert_eq!(r.report(15), 15);
}

/// The live bug: a 40 GiB ranged download's `bytes_done` sat at 0 the
/// whole way through. Drives a real multi-range HTTP staging (one range
/// corrupted once, forcing the transfer layer's own progress rollback
/// mid-flight) through a slowed-down test server and polls both
/// [`RestoreManager::status`] and the durable record on disk while it
/// runs: both must show real, non-decreasing motion well before the
/// piece finishes, not just a jump from 0 to done at the very end.
#[tokio::test]
async fn ranged_staging_progress_rises_across_pieces_and_never_regresses() {
    use super::super::transfer::{test_server, Transfer, MIN_PART_SIZE};
    let store = test_server::Store::default();
    let base = test_server::start(store.clone()).await;
    let full: Vec<u8> = (0..(MIN_PART_SIZE * 3))
        .map(|i| (i * 31 % 253) as u8)
        .collect();
    let state = staged_state();
    store
        .objects
        .lock()
        .unwrap()
        .insert("full".into(), full.clone());
    store
        .objects
        .lock()
        .unwrap()
        .insert("state".into(), state.clone());
    // Slow enough that polling at 5ms reliably samples mid-flight values
    // without making the test itself slow.
    *store.get_delay.lock().unwrap() = Duration::from_millis(25);
    // One range comes back corrupt once: its failed attempt rolls the
    // RAW transfer-layer counter back mid-download — exactly the dip the
    // ratchet must hide from anything reading `bytes_done`.
    store
        .corrupt
        .lock()
        .unwrap()
        .insert(("full".into(), MIN_PART_SIZE), 1);

    let mut full_piece = piece(&format!("{base}/full"), &full);
    full_piece.part_size = MIN_PART_SIZE;
    full_piece.part_sha256_hex = full
        .chunks(MIN_PART_SIZE as usize)
        .map(|c| hex::encode(Sha256::digest(c)))
        .collect();

    let env = Env::new();
    let m = Arc::new(
        RestoreManager::new(Arc::new(Transfer::new().unwrap()), Arc::default())
            .with_headroom(0)
            .with_persist_cadence(Duration::from_millis(15), 1),
    );
    let req = StageRequest {
        vm_id: env.vm.clone(),
        restore_id: RID.into(),
        chain: RestoreChain {
            restore_id: RID.into(),
            full: full_piece,
            incrementals: Vec::new(),
            state: piece(&format!("{base}/state"), &state),
        },
        disk_bytes: full.len() as u64,
        streams: 2,
    };
    let StageStart::Started(job) = m.begin_stage(&env.lifecycle, req).await.unwrap() else {
        panic!("expected a new staging");
    };
    let runner = {
        let m = Arc::clone(&m);
        tokio::spawn(async move { m.run_stage(job).await })
    };

    let total = full.len() as u64 + STATE_DISK_BYTES;
    let restore_root = env.paths(RID).restore_root;
    let mut live_seen = Vec::new();
    let mut disk_seen = Vec::new();
    for _ in 0..4000 {
        let st = m.status(&env.lifecycle, &env.vm).await.unwrap();
        let staging = st
            .as_ref()
            .is_some_and(|s| s.state == RestoreState::Staging);
        if let Some(st) = st {
            live_seen.push(st.bytes_done);
        }
        if let Some(rec) = read_record(&restore_root).await {
            disk_seen.push(rec.bytes_done);
        }
        if !staging {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    runner.await.unwrap();

    assert!(
        live_seen.iter().any(|&b| b > 0 && b < total),
        "status() must show a real mid-flight value, not jump 0 -> done: {live_seen:?}"
    );
    assert!(
        live_seen.windows(2).all(|w| w[1] >= w[0]),
        "status() must never regress despite the mid-flight rollback: {live_seen:?}"
    );
    assert!(
        disk_seen.iter().any(|&b| b > 0 && b < total),
        "the persisted record must show motion too, not sit at 0 the whole time: {disk_seen:?}"
    );
    assert!(
        disk_seen.windows(2).all(|w| w[1] >= w[0]),
        "the persisted record must never regress either: {disk_seen:?}"
    );

    let final_status = m.status(&env.lifecycle, &env.vm).await.unwrap().unwrap();
    assert_eq!(
        final_status.state,
        RestoreState::Staged,
        "{:?}",
        final_status.reason
    );
    assert_eq!(final_status.bytes_done, total);
    assert_eq!(std::fs::read(env.paths(RID).staged_overlay).unwrap(), full);
}
